# AZexec - Azure Resource Manager (ARM) Functions
# Multi-subscription enumeration for Azure resources (VMs, Storage, KeyVault, Network, etc.)
# These functions use Az PowerShell modules, not Microsoft Graph

# ============================================
# REUSABLE MULTI-SUBSCRIPTION HELPER FUNCTIONS
# ============================================

<#
.SYNOPSIS
    Initialize Azure RM modules required for ARM-based commands.
.DESCRIPTION
    Checks for and installs required Az PowerShell modules (Az.Accounts, Az.Compute, 
    Az.Resources, Az.Storage, Az.KeyVault, Az.Network).
.PARAMETER RequiredModules
    Array of module names to check and install.
#>
function Initialize-AzureRMModules {
    param(
        [Parameter(Mandatory = $true)]
        [string[]]$RequiredModules
    )
    
    Write-ColorOutput -Message "[*] Checking required Az PowerShell modules..." -Color "Yellow"
    
    $modulesToInstall = @()
    
    foreach ($module in $RequiredModules) {
        if (-not (Get-Module -ListAvailable -Name $module)) {
            $modulesToInstall += $module
        }
    }
    
    if ($modulesToInstall.Count -gt 0) {
        Write-ColorOutput -Message "[!] Missing modules: $($modulesToInstall -join ', ')" -Color "Yellow"
        Write-ColorOutput -Message "[*] Installing missing modules..." -Color "Yellow"
        
        foreach ($module in $modulesToInstall) {
            try {
                Write-ColorOutput -Message "    [*] Installing $module..." -Color "Gray"
                Install-Module $module -Scope CurrentUser -Force -AllowClobber -ErrorAction Stop -Repository PSGallery
                Write-ColorOutput -Message "    [+] $module installed successfully" -Color "Green"
            } catch {
                Write-ColorOutput -Message "    [!] Failed to install $module" -Color "Red"
                Write-ColorOutput -Message "    [!] Error: $($_.Exception.Message)" -Color "Red"
                Write-ColorOutput -Message "`n[*] Please install manually using:" -Color "Yellow"
                Write-ColorOutput -Message "    Install-Module $module -Scope CurrentUser -Force" -Color "Gray"
                Write-ColorOutput -Message "`n[*] Or install the full Az module:" -Color "Yellow"
                Write-ColorOutput -Message "    Install-Module Az -Scope CurrentUser -Force`n" -Color "Gray"
                return $false
            }
        }
        Write-ColorOutput -Message "[+] All required modules installed successfully" -Color "Green"
    } else {
        Write-ColorOutput -Message "[+] All required Az modules are already installed" -Color "Green"
    }
    
    # Import modules
    Write-ColorOutput -Message "[*] Importing Az modules..." -Color "Yellow"
    try {
        foreach ($module in $RequiredModules) {
            Import-Module $module -ErrorAction Stop
        }
        Write-ColorOutput -Message "[+] Az modules imported successfully`n" -Color "Green"
        return $true
    } catch {
        Write-ColorOutput -Message "[!] Failed to import Az modules" -Color "Red"
        Write-ColorOutput -Message "[!] Error: $($_.Exception.Message)" -Color "Red"
        return $false
    }
}

<#
.SYNOPSIS
    Connect to Azure and return the current context.
.DESCRIPTION
    Checks for existing Azure authentication and prompts for login if needed.
.OUTPUTS
    Returns the Azure context if successful, $null otherwise.
#>
function Connect-AzureRM {
    try {
        $azContext = Get-AzContext -ErrorAction Stop
        
        if (-not $azContext) {
            Write-ColorOutput -Message "[!] Not authenticated to Azure" -Color "Red"
            Write-ColorOutput -Message "[*] Attempting authentication..." -Color "Yellow"
            Write-ColorOutput -Message "[*] Note: You may see warnings about tenants requiring MFA - these are informational only`n" -Color "Cyan"
            
            Connect-AzAccount -ErrorAction Stop -WarningAction SilentlyContinue | Out-Null
            $azContext = Get-AzContext
        }
        
        if ($azContext) {
            Write-ColorOutput -Message "[+] Authenticated as: $($azContext.Account.Id)" -Color "Green"
            Write-ColorOutput -Message "[+] Current Subscription: $($azContext.Subscription.Name) ($($azContext.Subscription.Id))" -Color "Green"
            
            # Check user's RBAC roles (informational only)
            Write-ColorOutput -Message "[*] Checking Azure RBAC permissions (informational)..." -Color "Yellow"
            try {
                $roleAssignments = Get-AzRoleAssignment -SignInName $azContext.Account.Id -ErrorAction SilentlyContinue -WarningAction SilentlyContinue
                
                if ($roleAssignments -and $roleAssignments.Count -gt 0) {
                    $relevantRoles = $roleAssignments | Where-Object { 
                        $_.RoleDefinitionName -match "Reader|Contributor|Owner|Storage|Key Vault|Network|Virtual Machine" 
                    }
                    
                    if ($relevantRoles.Count -gt 0) {
                        Write-ColorOutput -Message "[+] Direct RBAC role assignments found:" -Color "Green"
                        $roleGroups = $relevantRoles | Group-Object RoleDefinitionName
                        foreach ($group in $roleGroups) {
                            $scopeInfo = $group.Group | ForEach-Object {
                                if ($_.Scope -match "/subscriptions/[^/]+$") { "Subscription" } 
                                elseif ($_.Scope -match "/resourceGroups/([^/]+)") { "RG: $($matches[1])" }
                                else { "Other" }
                            }
                            $uniqueScopes = ($scopeInfo | Select-Object -Unique) -join ", "
                            Write-ColorOutput -Message "    • $($group.Name) ($uniqueScopes)" -Color "Gray"
                        }
                    } else {
                        Write-ColorOutput -Message "[*] No direct resource roles found (you may have group-based or inherited permissions)" -Color "Cyan"
                    }
                } else {
                    Write-ColorOutput -Message "[*] No direct role assignments detected (you may have group-based or inherited permissions)" -Color "Cyan"
                }
                Write-ColorOutput -Message "[*] Proceeding with enumeration - actual permissions will be tested..." -Color "Cyan"
            } catch {
                Write-ColorOutput -Message "[*] Proceeding with enumeration..." -Color "Cyan"
            }
            
            Write-Host ""
            return $azContext
        }
    } catch {
        Write-ColorOutput -Message "[!] Failed to get Azure context: $($_.Exception.Message)" -Color "Red"
        Write-ColorOutput -Message "[*] Please authenticate using: Connect-AzAccount" -Color "Yellow"
        return $null
    }
    
    return $null
}

<#
.SYNOPSIS
    Get list of subscriptions to enumerate based on user input.
.DESCRIPTION
    Returns either a specific subscription or all enabled subscriptions the user has access to.
.PARAMETER SubscriptionId
    Optional specific subscription ID to target.
.PARAMETER CurrentContext
    The current Azure context.
.OUTPUTS
    Array of subscription objects to enumerate.
#>
function Get-SubscriptionsToEnumerate {
    param(
        [string]$SubscriptionId,
        [object]$CurrentContext
    )
    
    $subscriptionsToScan = @()
    
    if ($SubscriptionId) {
        # User specified a specific subscription
        try {
            $targetSub = Get-AzSubscription -SubscriptionId $SubscriptionId -ErrorAction Stop
            $subscriptionsToScan = @($targetSub)
            Write-ColorOutput -Message "[*] Target subscription: $($targetSub.Name) ($($targetSub.Id))`n" -Color "Cyan"
        } catch {
            Write-ColorOutput -Message "[!] Failed to find subscription: $SubscriptionId" -Color "Red"
            Write-ColorOutput -Message "[*] Error: $($_.Exception.Message)" -Color "Red"
            Write-ColorOutput -Message "`n[*] List available subscriptions:" -Color "Yellow"
            Write-ColorOutput -Message "    Get-AzSubscription | Format-Table Name, Id, State`n" -Color "Gray"
            return $null
        }
    } else {
        # Enumerate all accessible subscriptions
        try {
            $allSubs = Get-AzSubscription -ErrorAction Stop -WarningAction SilentlyContinue | Where-Object { $_.State -eq 'Enabled' }
            $subscriptionsToScan = @($allSubs)
            
            if ($subscriptionsToScan.Count -eq 0) {
                Write-ColorOutput -Message "[!] No enabled subscriptions found" -Color "Red"
                return $null
            }
            
            Write-ColorOutput -Message "[*] Found $($subscriptionsToScan.Count) enabled subscription(s):" -Color "Cyan"
            $currentSubId = $CurrentContext.Subscription.Id
            foreach ($sub in $subscriptionsToScan) {
                $isCurrent = if ($sub.Id -eq $currentSubId) { " [CURRENT]" } else { "" }
                $tenantInfo = if ($sub.TenantId) { " | Tenant: $($sub.TenantId)" } else { "" }
                Write-ColorOutput -Message "    • $($sub.Name)$isCurrent" -Color $(if ($sub.Id -eq $currentSubId) { "Green" } else { "Gray" })
                Write-ColorOutput -Message "      ID: $($sub.Id)$tenantInfo" -Color "DarkGray"
            }
            Write-ColorOutput -Message "`n[*] Will enumerate across all subscriptions (use -SubscriptionId to target specific subscription)`n" -Color "Yellow"
        } catch {
            Write-ColorOutput -Message "[!] Failed to retrieve subscriptions: $($_.Exception.Message)" -Color "Red"
            return $null
        }
    }
    
    return $subscriptionsToScan
}

<#
.SYNOPSIS
    Switch Azure context to a specific subscription.
.DESCRIPTION
    Safely switches the Azure context to the specified subscription with error handling.
.PARAMETER Subscription
    The subscription object to switch to.
.OUTPUTS
    Returns $true if successful, $false otherwise.
#>
function Set-SubscriptionContext {
    param(
        [Parameter(Mandatory = $true)]
        [object]$Subscription
    )
    
    Write-ColorOutput -Message "[*] --------------------------------------------------" -Color "Cyan"
    Write-ColorOutput -Message "[*] Subscription: $($Subscription.Name)" -Color "White"
    Write-ColorOutput -Message "[*] ID: $($Subscription.Id)" -Color "Gray"
    Write-ColorOutput -Message "[*] --------------------------------------------------`n" -Color "Cyan"
    
    try {
        if ($Subscription.TenantId) {
            Set-AzContext -SubscriptionId $Subscription.Id -TenantId $Subscription.TenantId -ErrorAction Stop -WarningAction SilentlyContinue | Out-Null
        } else {
            Set-AzContext -SubscriptionId $Subscription.Id -ErrorAction Stop -WarningAction SilentlyContinue | Out-Null
        }
    } catch {
        Write-ColorOutput -Message "[!] Failed to switch to subscription: $($Subscription.Name)" -Color "Red"
        Write-ColorOutput -Message "[*] Error: $($_.Exception.Message)" -Color "Red"
        
        if ($_.Exception.Message -like "*tenant*" -or $_.Exception.Message -like "*authentication*") {
            Write-ColorOutput -Message "[*] This subscription may be in a different tenant requiring separate authentication" -Color "Yellow"
            Write-ColorOutput -Message "[*] Tenant ID: $($Subscription.TenantId)" -Color "Yellow"
        }
        Write-ColorOutput -Message "[*] Skipping to next subscription...`n" -Color "Yellow"
        return $false
    }
    
    # Verify context switch was successful
    $currentContext = Get-AzContext -ErrorAction SilentlyContinue
    if (-not $currentContext -or $currentContext.Subscription.Id -ne $Subscription.Id) {
        Write-ColorOutput -Message "[!] Context switch verification failed for: $($Subscription.Name)" -Color "Red"
        Write-ColorOutput -Message "[*] Skipping to next subscription...`n" -Color "Yellow"
        return $false
    }
    
    return $true
}

<#
.SYNOPSIS
    Display multi-subscription enumeration summary.
.DESCRIPTION
    Shows a summary of the multi-subscription enumeration including statistics and helpful tips.
.PARAMETER SubscriptionsScanned
    Number of subscriptions scanned.
.PARAMETER TotalItems
    Total items found across all subscriptions.
.PARAMETER SuccessCount
    Number of successful operations.
.PARAMETER FailedCount
    Number of failed operations.
.PARAMETER ItemType
    Description of item type (e.g., "Storage Accounts", "Key Vaults").
.PARAMETER SubscriptionId
    If provided, indicates a specific subscription was targeted.
#>
function Show-MultiSubscriptionSummary {
    param(
        [int]$SubscriptionsScanned,
        [int]$TotalItems,
        [int]$SuccessCount = 0,
        [int]$FailedCount = 0,
        [string]$ItemType,
        [string]$SubscriptionId
    )
    
    Write-ColorOutput -Message "`n[*] ========================================" -Color "Cyan"
    Write-ColorOutput -Message "[*] MULTI-SUBSCRIPTION ENUMERATION SUMMARY" -Color "Cyan"
    Write-ColorOutput -Message "[*] ========================================`n" -Color "Cyan"
    
    Write-ColorOutput -Message "[*] Subscriptions Scanned: $SubscriptionsScanned" -Color "White"
    Write-ColorOutput -Message "[*] Total $ItemType Found: $TotalItems" -Color "White"
    
    if ($SuccessCount -gt 0) {
        Write-ColorOutput -Message "[*] Successful Operations: $SuccessCount" -Color "Green"
    }
    if ($FailedCount -gt 0) {
        Write-ColorOutput -Message "[*] Failed Operations: $FailedCount" -Color "Red"
    }
    
    # Multi-subscription tips
    if ($SubscriptionsScanned -gt 1 -and -not $SubscriptionId) {
        Write-ColorOutput -Message "`n[*] MULTI-SUBSCRIPTION SCAN:" -Color "Cyan"
        Write-ColorOutput -Message "    - Scanned $SubscriptionsScanned subscriptions automatically" -Color "Cyan"
        Write-ColorOutput -Message "    - Use -SubscriptionId to target a specific subscription" -Color "Cyan"
        Write-ColorOutput -Message "    - Export includes subscription information for each item" -Color "Cyan"
    }
}

<#
.SYNOPSIS
    Export enumeration results to file.
.DESCRIPTION
    Exports data to CSV, JSON, or HTML format based on file extension.
.PARAMETER Data
    The data to export.
.PARAMETER ExportPath
    The file path to export to.
.PARAMETER Title
    Title for HTML reports.
.PARAMETER Statistics
    Statistics hashtable for HTML reports.
.PARAMETER CommandName
    Command name for HTML reports.
.PARAMETER Description
    Description for HTML reports.
#>
function Export-EnumerationResults {
    param(
        [Parameter(Mandatory = $true)]
        [array]$Data,
        [Parameter(Mandatory = $true)]
        [string]$ExportPath,
        [string]$Title = "Azure Enumeration",
        [hashtable]$Statistics = @{},
        [string]$CommandName = "",
        [string]$Description = ""
    )
    
    if ($Data.Count -eq 0) {
        Write-ColorOutput -Message "`n[!] No data to export" -Color "Yellow"
        return $false
    }
    
    try {
        $extension = [System.IO.Path]::GetExtension($ExportPath).ToLower()
        
        switch ($extension) {
            ".csv" {
                $Data | Export-Csv -Path $ExportPath -NoTypeInformation -ErrorAction Stop
                Write-ColorOutput -Message "`n[+] Results exported to: $ExportPath" -Color "Green"
                return $true
            }
            ".json" {
                $Data | ConvertTo-Json -Depth 10 | Out-File -FilePath $ExportPath -ErrorAction Stop
                Write-ColorOutput -Message "`n[+] Results exported to: $ExportPath" -Color "Green"
                return $true
            }
            ".html" {
                $success = Export-HtmlReport -Data $Data -OutputPath $ExportPath -Title $Title -Statistics $Statistics -CommandName $CommandName -Description $Description
                if ($success) {
                    Write-ColorOutput -Message "`n[+] HTML report exported to: $ExportPath" -Color "Green"
                }
                return $success
            }
            default {
                Write-ColorOutput -Message "`n[!] Unsupported export format. Use .csv, .json, or .html" -Color "Red"
                return $false
            }
        }
    } catch {
        Write-ColorOutput -Message "`n[!] Failed to export results: $_" -Color "Red"
        return $false
    }
}


# ============================================
# STORAGE ACCOUNT ENUMERATION
# ============================================

<#
.SYNOPSIS
    Enumerate Azure Storage Accounts across subscriptions.
.DESCRIPTION
    Discovers storage accounts with security-relevant information including
    public access settings, encryption, network rules, and access keys.
#>
function Invoke-StorageEnumeration {
    param(
        [string]$ResourceGroup,
        [string]$SubscriptionId,
        [string]$ExportPath
    )
    
    Write-ColorOutput -Message "`n[*] AZX - Azure Storage Account Enumeration" -Color "Yellow"
    Write-ColorOutput -Message "[*] Command: storage-enum" -Color "Yellow"
    Write-ColorOutput -Message "[*] Discovering storage accounts with security configurations`n" -Color "Cyan"
    
    # Initialize required modules
    $requiredModules = @('Az.Accounts', 'Az.Resources', 'Az.Storage')
    if (-not (Initialize-AzureRMModules -RequiredModules $requiredModules)) {
        return
    }
    
    # Connect to Azure
    $azContext = Connect-AzureRM
    if (-not $azContext) { return }
    
    # Get subscriptions to enumerate
    $subscriptionsToScan = Get-SubscriptionsToEnumerate -SubscriptionId $SubscriptionId -CurrentContext $azContext
    if (-not $subscriptionsToScan) { return }
    
    # Global counters
    $exportData = @()
    $totalStorageAccounts = 0
    $publicAccessEnabled = 0
    $httpsOnlyDisabled = 0
    $blobPublicAccess = 0
    
    Write-ColorOutput -Message "[*] ========================================" -Color "Cyan"
    Write-ColorOutput -Message "[*] MULTI-SUBSCRIPTION STORAGE ENUMERATION" -Color "Cyan"
    Write-ColorOutput -Message "[*] ========================================`n" -Color "Cyan"
    
    # Loop through each subscription
    foreach ($subscription in $subscriptionsToScan) {
        if (-not (Set-SubscriptionContext -Subscription $subscription)) {
            continue
        }
        
        Write-ColorOutput -Message "[*] Retrieving Storage Accounts..." -Color "Yellow"
        
        try {
            $storageAccounts = @()
            if ($ResourceGroup) {
                $storageAccounts = @(Get-AzStorageAccount -ResourceGroupName $ResourceGroup -ErrorAction Stop)
                Write-ColorOutput -Message "[+] Retrieved $($storageAccounts.Count) storage account(s) from resource group: $ResourceGroup" -Color "Green"
            } else {
                $storageAccounts = @(Get-AzStorageAccount -ErrorAction Stop)
                Write-ColorOutput -Message "[+] Retrieved $($storageAccounts.Count) storage account(s) across all resource groups" -Color "Green"
            }
        } catch {
            $errorMessage = $_.Exception.Message
            if ($errorMessage -like "*AuthorizationFailed*") {
                Write-ColorOutput -Message "[!] Authorization failed for subscription: $($subscription.Name)" -Color "Red"
                Write-ColorOutput -Message "[*] Skipping to next subscription...`n" -Color "Yellow"
            } else {
                Write-ColorOutput -Message "[!] Error retrieving storage accounts: $errorMessage" -Color "Red"
            }
            continue
        }
        
        if ($storageAccounts.Count -eq 0) {
            Write-ColorOutput -Message "[*] No storage accounts found in this subscription`n" -Color "Yellow"
            continue
        }
        
        $totalStorageAccounts += $storageAccounts.Count
        
        foreach ($sa in $storageAccounts) {
            $saName = $sa.StorageAccountName
            $saRG = $sa.ResourceGroupName
            
            # Security checks
            $isHttpsOnly = $sa.EnableHttpsTrafficOnly
            $allowBlobPublicAccess = $sa.AllowBlobPublicAccess
            $minimumTlsVersion = $sa.MinimumTlsVersion
            $networkRuleDefaultAction = $sa.NetworkRuleSet.DefaultAction
            $allowSharedKeyAccess = $sa.AllowSharedKeyAccess
            
            # Track security issues
            if (-not $isHttpsOnly) { $httpsOnlyDisabled++ }
            if ($allowBlobPublicAccess -eq $true) { $blobPublicAccess++ }
            if ($networkRuleDefaultAction -eq "Allow") { $publicAccessEnabled++ }
            
            # Determine risk level
            $riskLevel = "LOW"
            $securityIssues = @()
            
            if ($allowBlobPublicAccess -eq $true) {
                $riskLevel = "HIGH"
                $securityIssues += "Blob Public Access Enabled"
            }
            if (-not $isHttpsOnly) {
                if ($riskLevel -ne "HIGH") { $riskLevel = "MEDIUM" }
                $securityIssues += "HTTPS Not Required"
            }
            if ($networkRuleDefaultAction -eq "Allow") {
                if ($riskLevel -ne "HIGH") { $riskLevel = "MEDIUM" }
                $securityIssues += "Network Default: Allow All"
            }
            if ($minimumTlsVersion -ne "TLS1_2") {
                $securityIssues += "TLS < 1.2"
            }
            if ($allowSharedKeyAccess -eq $true) {
                $securityIssues += "Shared Key Access Enabled"
            }
            
            $riskColor = switch ($riskLevel) {
                "HIGH" { "Red" }
                "MEDIUM" { "Yellow" }
                default { "Green" }
            }
            
            Write-ColorOutput -Message "[*] Storage Account: $saName" -Color "White"
            Write-ColorOutput -Message "    Resource Group: $saRG" -Color "Gray"
            Write-ColorOutput -Message "    Kind: $($sa.Kind) | SKU: $($sa.Sku.Name)" -Color "Gray"
            Write-ColorOutput -Message "    Location: $($sa.PrimaryLocation)" -Color "Gray"
            Write-ColorOutput -Message "    Risk Level: $riskLevel" -Color $riskColor
            
            if ($securityIssues.Count -gt 0) {
                Write-ColorOutput -Message "    Security Issues:" -Color "Yellow"
                foreach ($issue in $securityIssues) {
                    Write-ColorOutput -Message "      - $issue" -Color "Yellow"
                }
            }
            
            # Get endpoints
            $blobEndpoint = $sa.PrimaryEndpoints.Blob
            $fileEndpoint = $sa.PrimaryEndpoints.File
            $tableEndpoint = $sa.PrimaryEndpoints.Table
            $queueEndpoint = $sa.PrimaryEndpoints.Queue
            
            Write-ColorOutput -Message "    Endpoints:" -Color "Cyan"
            if ($blobEndpoint) { Write-ColorOutput -Message "      Blob: $blobEndpoint" -Color "DarkGray" }
            if ($fileEndpoint) { Write-ColorOutput -Message "      File: $fileEndpoint" -Color "DarkGray" }
            
            # Build export object
            $exportData += [PSCustomObject]@{
                Subscription = $subscription.Name
                SubscriptionId = $subscription.Id
                StorageAccountName = $saName
                ResourceGroup = $saRG
                Kind = $sa.Kind
                SkuName = $sa.Sku.Name
                Location = $sa.PrimaryLocation
                CreationTime = $sa.CreationTime
                RiskLevel = $riskLevel
                SecurityIssues = ($securityIssues -join "; ")
                HttpsOnly = $isHttpsOnly
                AllowBlobPublicAccess = $allowBlobPublicAccess
                MinimumTlsVersion = $minimumTlsVersion
                NetworkDefaultAction = $networkRuleDefaultAction
                AllowSharedKeyAccess = $allowSharedKeyAccess
                BlobEndpoint = $blobEndpoint
                FileEndpoint = $fileEndpoint
                TableEndpoint = $tableEndpoint
                QueueEndpoint = $queueEndpoint
            }
            
            Write-Host ""
        }
        
        Write-ColorOutput -Message "[*] Subscription enumeration complete`n" -Color "Green"
    }
    
    # Summary
    Show-MultiSubscriptionSummary -SubscriptionsScanned $subscriptionsToScan.Count -TotalItems $totalStorageAccounts -ItemType "Storage Accounts" -SubscriptionId $SubscriptionId
    
    Write-ColorOutput -Message "`n[*] SECURITY SUMMARY:" -Color "Yellow"
    Write-ColorOutput -Message "    Storage Accounts with Public Network Access: $publicAccessEnabled" -Color $(if ($publicAccessEnabled -gt 0) { "Red" } else { "Green" })
    Write-ColorOutput -Message "    Storage Accounts with Blob Public Access: $blobPublicAccess" -Color $(if ($blobPublicAccess -gt 0) { "Red" } else { "Green" })
    Write-ColorOutput -Message "    Storage Accounts without HTTPS-Only: $httpsOnlyDisabled" -Color $(if ($httpsOnlyDisabled -gt 0) { "Yellow" } else { "Green" })
    
    # Export if requested
    if ($ExportPath) {
        $stats = @{
            "Subscriptions Scanned" = $subscriptionsToScan.Count
            "Total Storage Accounts" = $totalStorageAccounts
            "Public Network Access" = $publicAccessEnabled
            "Blob Public Access" = $blobPublicAccess
            "HTTPS-Only Disabled" = $httpsOnlyDisabled
        }
        Export-EnumerationResults -Data $exportData -ExportPath $ExportPath -Title "Azure Storage Account Enumeration" -Statistics $stats -CommandName "storage-enum" -Description "Enumeration of Azure Storage Accounts with security configuration analysis"
    }
    
    # Helpful tips
    if ($blobPublicAccess -gt 0 -or $publicAccessEnabled -gt 0) {
        Write-ColorOutput -Message "`n[*] SECURITY RECOMMENDATIONS:" -Color "Cyan"
        Write-ColorOutput -Message "    - Review storage accounts with public blob access" -Color "Cyan"
        Write-ColorOutput -Message "    - Consider using Private Endpoints for sensitive data" -Color "Cyan"
        Write-ColorOutput -Message "    - Enable HTTPS-only traffic on all storage accounts" -Color "Cyan"
        Write-ColorOutput -Message "    - Disable shared key access and use Azure AD authentication" -Color "Cyan"
    }
    
    return $exportData
}


# ============================================
# KEY VAULT ENUMERATION
# ============================================

<#
.SYNOPSIS
    Enumerate Azure Key Vaults across subscriptions.
.DESCRIPTION
    Discovers Key Vaults with security-relevant information including
    access policies, network rules, soft delete, and purge protection.
#>
function Invoke-KeyVaultEnumeration {
    param(
        [string]$ResourceGroup,
        [string]$SubscriptionId,
        [string]$ExportPath
    )
    
    Write-ColorOutput -Message "`n[*] AZX - Azure Key Vault Enumeration" -Color "Yellow"
    Write-ColorOutput -Message "[*] Command: keyvault-enum" -Color "Yellow"
    Write-ColorOutput -Message "[*] Discovering Key Vaults with security configurations`n" -Color "Cyan"
    
    # Initialize required modules
    $requiredModules = @('Az.Accounts', 'Az.Resources', 'Az.KeyVault')
    if (-not (Initialize-AzureRMModules -RequiredModules $requiredModules)) {
        return
    }
    
    # Connect to Azure
    $azContext = Connect-AzureRM
    if (-not $azContext) { return }
    
    # Get subscriptions to enumerate
    $subscriptionsToScan = Get-SubscriptionsToEnumerate -SubscriptionId $SubscriptionId -CurrentContext $azContext
    if (-not $subscriptionsToScan) { return }
    
    # Global counters
    $exportData = @()
    $totalKeyVaults = 0
    $publicAccessEnabled = 0
    $softDeleteDisabled = 0
    $purgeProtectionDisabled = 0
    $rbacDisabled = 0
    
    Write-ColorOutput -Message "[*] ========================================" -Color "Cyan"
    Write-ColorOutput -Message "[*] MULTI-SUBSCRIPTION KEY VAULT ENUMERATION" -Color "Cyan"
    Write-ColorOutput -Message "[*] ========================================`n" -Color "Cyan"
    
    # Loop through each subscription
    foreach ($subscription in $subscriptionsToScan) {
        if (-not (Set-SubscriptionContext -Subscription $subscription)) {
            continue
        }
        
        Write-ColorOutput -Message "[*] Retrieving Key Vaults..." -Color "Yellow"
        
        try {
            $keyVaults = @()
            if ($ResourceGroup) {
                $keyVaults = @(Get-AzKeyVault -ResourceGroupName $ResourceGroup -ErrorAction Stop)
                Write-ColorOutput -Message "[+] Retrieved $($keyVaults.Count) Key Vault(s) from resource group: $ResourceGroup" -Color "Green"
            } else {
                $keyVaults = @(Get-AzKeyVault -ErrorAction Stop)
                Write-ColorOutput -Message "[+] Retrieved $($keyVaults.Count) Key Vault(s) across all resource groups" -Color "Green"
            }
        } catch {
            $errorMessage = $_.Exception.Message
            if ($errorMessage -like "*AuthorizationFailed*") {
                Write-ColorOutput -Message "[!] Authorization failed for subscription: $($subscription.Name)" -Color "Red"
                Write-ColorOutput -Message "[*] Skipping to next subscription...`n" -Color "Yellow"
            } else {
                Write-ColorOutput -Message "[!] Error retrieving Key Vaults: $errorMessage" -Color "Red"
            }
            continue
        }
        
        if ($keyVaults.Count -eq 0) {
            Write-ColorOutput -Message "[*] No Key Vaults found in this subscription`n" -Color "Yellow"
            continue
        }
        
        $totalKeyVaults += $keyVaults.Count
        
        foreach ($kv in $keyVaults) {
            $kvName = $kv.VaultName
            $kvRG = $kv.ResourceGroupName
            
            # Get detailed Key Vault info
            try {
                $kvDetails = Get-AzKeyVault -VaultName $kvName -ResourceGroupName $kvRG -ErrorAction Stop
            } catch {
                Write-ColorOutput -Message "[!] Failed to get details for Key Vault: $kvName" -Color "Red"
                continue
            }
            
            # Security checks
            $enableSoftDelete = $kvDetails.EnableSoftDelete
            $enablePurgeProtection = $kvDetails.EnablePurgeProtection
            $enableRbacAuthorization = $kvDetails.EnableRbacAuthorization
            $networkDefaultAction = $kvDetails.NetworkAcls.DefaultAction
            $publicNetworkAccess = $kvDetails.PublicNetworkAccess
            
            # Track security issues
            if (-not $enableSoftDelete) { $softDeleteDisabled++ }
            if (-not $enablePurgeProtection) { $purgeProtectionDisabled++ }
            if (-not $enableRbacAuthorization) { $rbacDisabled++ }
            if ($networkDefaultAction -eq "Allow" -or $publicNetworkAccess -eq "Enabled") { $publicAccessEnabled++ }
            
            # Access policies count
            $accessPolicyCount = ($kvDetails.AccessPolicies | Measure-Object).Count
            
            # Determine risk level
            $riskLevel = "LOW"
            $securityIssues = @()
            
            if ($networkDefaultAction -eq "Allow" -or $publicNetworkAccess -eq "Enabled") {
                $riskLevel = "MEDIUM"
                $securityIssues += "Public Network Access Enabled"
            }
            if (-not $enableSoftDelete) {
                if ($riskLevel -ne "HIGH") { $riskLevel = "MEDIUM" }
                $securityIssues += "Soft Delete Disabled"
            }
            if (-not $enablePurgeProtection) {
                $securityIssues += "Purge Protection Disabled"
            }
            if (-not $enableRbacAuthorization) {
                $securityIssues += "RBAC Authorization Disabled (using Access Policies)"
            }
            if ($accessPolicyCount -gt 10) {
                $securityIssues += "Many Access Policies ($accessPolicyCount)"
            }
            
            $riskColor = switch ($riskLevel) {
                "HIGH" { "Red" }
                "MEDIUM" { "Yellow" }
                default { "Green" }
            }
            
            Write-ColorOutput -Message "[*] Key Vault: $kvName" -Color "White"
            Write-ColorOutput -Message "    Resource Group: $kvRG" -Color "Gray"
            Write-ColorOutput -Message "    Location: $($kvDetails.Location)" -Color "Gray"
            Write-ColorOutput -Message "    Vault URI: $($kvDetails.VaultUri)" -Color "Cyan"
            Write-ColorOutput -Message "    Risk Level: $riskLevel" -Color $riskColor
            
            Write-ColorOutput -Message "    Security Settings:" -Color "Yellow"
            Write-ColorOutput -Message "      Soft Delete: $(if ($enableSoftDelete) { 'Enabled' } else { 'Disabled' })" -Color $(if ($enableSoftDelete) { "Green" } else { "Red" })
            Write-ColorOutput -Message "      Purge Protection: $(if ($enablePurgeProtection) { 'Enabled' } else { 'Disabled' })" -Color $(if ($enablePurgeProtection) { "Green" } else { "Yellow" })
            Write-ColorOutput -Message "      RBAC Authorization: $(if ($enableRbacAuthorization) { 'Enabled' } else { 'Disabled' })" -Color $(if ($enableRbacAuthorization) { "Green" } else { "Yellow" })
            Write-ColorOutput -Message "      Network Default Action: $networkDefaultAction" -Color $(if ($networkDefaultAction -eq "Deny") { "Green" } else { "Yellow" })
            Write-ColorOutput -Message "      Access Policies Count: $accessPolicyCount" -Color "Gray"
            
            if ($securityIssues.Count -gt 0) {
                Write-ColorOutput -Message "    Security Issues:" -Color "Yellow"
                foreach ($issue in $securityIssues) {
                    Write-ColorOutput -Message "      - $issue" -Color "Yellow"
                }
            }
            
            # Build export object
            $exportData += [PSCustomObject]@{
                Subscription = $subscription.Name
                SubscriptionId = $subscription.Id
                VaultName = $kvName
                ResourceGroup = $kvRG
                Location = $kvDetails.Location
                VaultUri = $kvDetails.VaultUri
                RiskLevel = $riskLevel
                SecurityIssues = ($securityIssues -join "; ")
                SoftDeleteEnabled = $enableSoftDelete
                PurgeProtectionEnabled = $enablePurgeProtection
                RbacAuthorizationEnabled = $enableRbacAuthorization
                NetworkDefaultAction = $networkDefaultAction
                PublicNetworkAccess = $publicNetworkAccess
                AccessPolicyCount = $accessPolicyCount
                SKU = $kvDetails.Sku
            }
            
            Write-Host ""
        }
        
        Write-ColorOutput -Message "[*] Subscription enumeration complete`n" -Color "Green"
    }
    
    # Summary
    Show-MultiSubscriptionSummary -SubscriptionsScanned $subscriptionsToScan.Count -TotalItems $totalKeyVaults -ItemType "Key Vaults" -SubscriptionId $SubscriptionId
    
    Write-ColorOutput -Message "`n[*] SECURITY SUMMARY:" -Color "Yellow"
    Write-ColorOutput -Message "    Key Vaults with Public Access: $publicAccessEnabled" -Color $(if ($publicAccessEnabled -gt 0) { "Yellow" } else { "Green" })
    Write-ColorOutput -Message "    Key Vaults without Soft Delete: $softDeleteDisabled" -Color $(if ($softDeleteDisabled -gt 0) { "Red" } else { "Green" })
    Write-ColorOutput -Message "    Key Vaults without Purge Protection: $purgeProtectionDisabled" -Color $(if ($purgeProtectionDisabled -gt 0) { "Yellow" } else { "Green" })
    Write-ColorOutput -Message "    Key Vaults using Access Policies (no RBAC): $rbacDisabled" -Color $(if ($rbacDisabled -gt 0) { "Yellow" } else { "Green" })
    
    # Export if requested
    if ($ExportPath) {
        $stats = @{
            "Subscriptions Scanned" = $subscriptionsToScan.Count
            "Total Key Vaults" = $totalKeyVaults
            "Public Access Enabled" = $publicAccessEnabled
            "Soft Delete Disabled" = $softDeleteDisabled
            "Purge Protection Disabled" = $purgeProtectionDisabled
            "RBAC Disabled" = $rbacDisabled
        }
        Export-EnumerationResults -Data $exportData -ExportPath $ExportPath -Title "Azure Key Vault Enumeration" -Statistics $stats -CommandName "keyvault-enum" -Description "Enumeration of Azure Key Vaults with security configuration analysis"
    }
    
    # Helpful tips
    Write-ColorOutput -Message "`n[*] SECURITY RECOMMENDATIONS:" -Color "Cyan"
    Write-ColorOutput -Message "    - Enable soft delete and purge protection on all Key Vaults" -Color "Cyan"
    Write-ColorOutput -Message "    - Use RBAC authorization instead of access policies" -Color "Cyan"
    Write-ColorOutput -Message "    - Restrict network access using Private Endpoints" -Color "Cyan"
    Write-ColorOutput -Message "    - Regularly audit access policies and RBAC assignments" -Color "Cyan"
    
    return $exportData
}


# ============================================
# NETWORK ENUMERATION
# ============================================

<#
.SYNOPSIS
    Enumerate Azure Network resources across subscriptions.
.DESCRIPTION
    Discovers Virtual Networks, NSGs, Public IPs, Load Balancers, and other
    network resources with security-relevant information.
#>
function Invoke-NetworkEnumeration {
    param(
        [string]$ResourceGroup,
        [string]$SubscriptionId,
        [string]$ExportPath
    )
    
    Write-ColorOutput -Message "`n[*] AZX - Azure Network Resource Enumeration" -Color "Yellow"
    Write-ColorOutput -Message "[*] Command: network-enum" -Color "Yellow"
    Write-ColorOutput -Message "[*] Discovering network resources with security configurations`n" -Color "Cyan"
    
    # Initialize required modules
    $requiredModules = @('Az.Accounts', 'Az.Resources', 'Az.Network')
    if (-not (Initialize-AzureRMModules -RequiredModules $requiredModules)) {
        return
    }
    
    # Connect to Azure
    $azContext = Connect-AzureRM
    if (-not $azContext) { return }
    
    # Get subscriptions to enumerate
    $subscriptionsToScan = Get-SubscriptionsToEnumerate -SubscriptionId $SubscriptionId -CurrentContext $azContext
    if (-not $subscriptionsToScan) { return }
    
    # Global counters
    $exportData = @()
    $totalVNets = 0
    $totalNSGs = 0
    $totalPublicIPs = 0
    $totalLoadBalancers = 0
    $openNSGRules = 0
    $unassociatedPublicIPs = 0
    
    Write-ColorOutput -Message "[*] ========================================" -Color "Cyan"
    Write-ColorOutput -Message "[*] MULTI-SUBSCRIPTION NETWORK ENUMERATION" -Color "Cyan"
    Write-ColorOutput -Message "[*] ========================================`n" -Color "Cyan"
    
    # Loop through each subscription
    foreach ($subscription in $subscriptionsToScan) {
        if (-not (Set-SubscriptionContext -Subscription $subscription)) {
            continue
        }
        
        # ==================
        # Virtual Networks
        # ==================
        Write-ColorOutput -Message "[*] Retrieving Virtual Networks..." -Color "Yellow"
        
        try {
            $vnets = @()
            if ($ResourceGroup) {
                $vnets = @(Get-AzVirtualNetwork -ResourceGroupName $ResourceGroup -ErrorAction Stop)
            } else {
                $vnets = @(Get-AzVirtualNetwork -ErrorAction Stop)
            }
            Write-ColorOutput -Message "[+] Retrieved $($vnets.Count) Virtual Network(s)" -Color "Green"
            $totalVNets += $vnets.Count
            
            foreach ($vnet in $vnets) {
                Write-ColorOutput -Message "    [*] VNet: $($vnet.Name)" -Color "White"
                Write-ColorOutput -Message "        Resource Group: $($vnet.ResourceGroupName)" -Color "Gray"
                Write-ColorOutput -Message "        Address Space: $($vnet.AddressSpace.AddressPrefixes -join ', ')" -Color "Cyan"
                Write-ColorOutput -Message "        Subnets: $($vnet.Subnets.Count)" -Color "Gray"
                
                # Check for peerings
                if ($vnet.VirtualNetworkPeerings.Count -gt 0) {
                    Write-ColorOutput -Message "        Peerings: $($vnet.VirtualNetworkPeerings.Count)" -Color "Yellow"
                }
                
                # Build export object for VNet
                $exportData += [PSCustomObject]@{
                    Subscription = $subscription.Name
                    SubscriptionId = $subscription.Id
                    ResourceType = "VirtualNetwork"
                    Name = $vnet.Name
                    ResourceGroup = $vnet.ResourceGroupName
                    Location = $vnet.Location
                    Details = "AddressSpace: $($vnet.AddressSpace.AddressPrefixes -join ', ') | Subnets: $($vnet.Subnets.Count)"
                    RiskLevel = "INFO"
                    SecurityIssues = ""
                }
            }
        } catch {
            Write-ColorOutput -Message "[!] Error retrieving VNets: $($_.Exception.Message)" -Color "Red"
        }
        
        # ==================
        # Network Security Groups
        # ==================
        Write-ColorOutput -Message "`n[*] Retrieving Network Security Groups..." -Color "Yellow"
        
        try {
            $nsgs = @()
            if ($ResourceGroup) {
                $nsgs = @(Get-AzNetworkSecurityGroup -ResourceGroupName $ResourceGroup -ErrorAction Stop)
            } else {
                $nsgs = @(Get-AzNetworkSecurityGroup -ErrorAction Stop)
            }
            Write-ColorOutput -Message "[+] Retrieved $($nsgs.Count) NSG(s)" -Color "Green"
            $totalNSGs += $nsgs.Count
            
            foreach ($nsg in $nsgs) {
                $nsgName = $nsg.Name
                $nsgRG = $nsg.ResourceGroupName
                
                # Check for risky inbound rules
                $riskyRules = @()
                $nsgSecurityIssues = @()
                
                foreach ($rule in $nsg.SecurityRules) {
                    if ($rule.Direction -eq "Inbound" -and $rule.Access -eq "Allow") {
                        # Check for any source (0.0.0.0/0 or *)
                        $isOpenSource = $rule.SourceAddressPrefix -eq "*" -or $rule.SourceAddressPrefix -eq "0.0.0.0/0" -or $rule.SourceAddressPrefix -eq "Internet"
                        
                        # Check for risky ports
                        $riskyPorts = @("22", "3389", "445", "135", "139", "1433", "3306", "5432", "27017", "*")
                        $isRiskyPort = $false
                        
                        foreach ($port in $riskyPorts) {
                            if ($rule.DestinationPortRange -eq $port -or $rule.DestinationPortRange -eq "*") {
                                $isRiskyPort = $true
                                break
                            }
                        }
                        
                        if ($isOpenSource -and $isRiskyPort) {
                            $riskyRules += "$($rule.Name) (Port: $($rule.DestinationPortRange))"
                            $openNSGRules++
                        }
                    }
                }
                
                $riskLevel = if ($riskyRules.Count -gt 0) { "HIGH" } else { "LOW" }
                if ($riskyRules.Count -gt 0) {
                    $nsgSecurityIssues += "Open Inbound Rules: $($riskyRules -join ', ')"
                }
                
                $riskColor = if ($riskLevel -eq "HIGH") { "Red" } else { "Green" }
                
                Write-ColorOutput -Message "    [*] NSG: $nsgName" -Color "White"
                Write-ColorOutput -Message "        Resource Group: $nsgRG" -Color "Gray"
                Write-ColorOutput -Message "        Rules Count: $($nsg.SecurityRules.Count)" -Color "Gray"
                Write-ColorOutput -Message "        Risk Level: $riskLevel" -Color $riskColor
                
                if ($riskyRules.Count -gt 0) {
                    Write-ColorOutput -Message "        [!] RISKY INBOUND RULES:" -Color "Red"
                    foreach ($rule in $riskyRules) {
                        Write-ColorOutput -Message "            - $rule" -Color "Red"
                    }
                }
                
                # Build export object for NSG
                $exportData += [PSCustomObject]@{
                    Subscription = $subscription.Name
                    SubscriptionId = $subscription.Id
                    ResourceType = "NetworkSecurityGroup"
                    Name = $nsgName
                    ResourceGroup = $nsgRG
                    Location = $nsg.Location
                    Details = "Rules: $($nsg.SecurityRules.Count) | Risky Rules: $($riskyRules.Count)"
                    RiskLevel = $riskLevel
                    SecurityIssues = ($nsgSecurityIssues -join "; ")
                }
            }
        } catch {
            Write-ColorOutput -Message "[!] Error retrieving NSGs: $($_.Exception.Message)" -Color "Red"
        }
        
        # ==================
        # Public IP Addresses
        # ==================
        Write-ColorOutput -Message "`n[*] Retrieving Public IP Addresses..." -Color "Yellow"
        
        try {
            $publicIPs = @()
            if ($ResourceGroup) {
                $publicIPs = @(Get-AzPublicIpAddress -ResourceGroupName $ResourceGroup -ErrorAction Stop)
            } else {
                $publicIPs = @(Get-AzPublicIpAddress -ErrorAction Stop)
            }
            Write-ColorOutput -Message "[+] Retrieved $($publicIPs.Count) Public IP(s)" -Color "Green"
            $totalPublicIPs += $publicIPs.Count
            
            foreach ($pip in $publicIPs) {
                $pipName = $pip.Name
                $pipRG = $pip.ResourceGroupName
                $ipAddress = $pip.IpAddress
                $isAssociated = $null -ne $pip.IpConfiguration
                
                if (-not $isAssociated) {
                    $unassociatedPublicIPs++
                }
                
                $riskLevel = if (-not $isAssociated) { "MEDIUM" } else { "INFO" }
                $securityIssues = if (-not $isAssociated) { "Unassociated Public IP (billable, potential misconfiguration)" } else { "" }
                
                $riskColor = switch ($riskLevel) {
                    "HIGH" { "Red" }
                    "MEDIUM" { "Yellow" }
                    default { "Cyan" }
                }
                
                Write-ColorOutput -Message "    [*] Public IP: $pipName" -Color "White"
                Write-ColorOutput -Message "        IP Address: $(if ($ipAddress) { $ipAddress } else { 'Not Allocated' })" -Color "Cyan"
                Write-ColorOutput -Message "        Associated: $(if ($isAssociated) { 'Yes' } else { 'No' })" -Color $(if ($isAssociated) { "Green" } else { "Yellow" })
                Write-ColorOutput -Message "        Allocation Method: $($pip.PublicIpAllocationMethod)" -Color "Gray"
                Write-ColorOutput -Message "        SKU: $($pip.Sku.Name)" -Color "Gray"
                
                # Build export object for Public IP
                $exportData += [PSCustomObject]@{
                    Subscription = $subscription.Name
                    SubscriptionId = $subscription.Id
                    ResourceType = "PublicIPAddress"
                    Name = $pipName
                    ResourceGroup = $pipRG
                    Location = $pip.Location
                    Details = "IP: $ipAddress | Allocation: $($pip.PublicIpAllocationMethod) | SKU: $($pip.Sku.Name)"
                    RiskLevel = $riskLevel
                    SecurityIssues = $securityIssues
                }
            }
        } catch {
            Write-ColorOutput -Message "[!] Error retrieving Public IPs: $($_.Exception.Message)" -Color "Red"
        }
        
        # ==================
        # Load Balancers
        # ==================
        Write-ColorOutput -Message "`n[*] Retrieving Load Balancers..." -Color "Yellow"
        
        try {
            $loadBalancers = @()
            if ($ResourceGroup) {
                $loadBalancers = @(Get-AzLoadBalancer -ResourceGroupName $ResourceGroup -ErrorAction Stop)
            } else {
                $loadBalancers = @(Get-AzLoadBalancer -ErrorAction Stop)
            }
            Write-ColorOutput -Message "[+] Retrieved $($loadBalancers.Count) Load Balancer(s)" -Color "Green"
            $totalLoadBalancers += $loadBalancers.Count
            
            foreach ($lb in $loadBalancers) {
                $lbName = $lb.Name
                $lbRG = $lb.ResourceGroupName
                
                Write-ColorOutput -Message "    [*] Load Balancer: $lbName" -Color "White"
                Write-ColorOutput -Message "        Resource Group: $lbRG" -Color "Gray"
                Write-ColorOutput -Message "        SKU: $($lb.Sku.Name)" -Color "Gray"
                Write-ColorOutput -Message "        Frontend IPs: $($lb.FrontendIpConfigurations.Count)" -Color "Gray"
                Write-ColorOutput -Message "        Backend Pools: $($lb.BackendAddressPools.Count)" -Color "Gray"
                Write-ColorOutput -Message "        Rules: $($lb.LoadBalancingRules.Count)" -Color "Gray"
                
                # Build export object for Load Balancer
                $exportData += [PSCustomObject]@{
                    Subscription = $subscription.Name
                    SubscriptionId = $subscription.Id
                    ResourceType = "LoadBalancer"
                    Name = $lbName
                    ResourceGroup = $lbRG
                    Location = $lb.Location
                    Details = "SKU: $($lb.Sku.Name) | Frontend IPs: $($lb.FrontendIpConfigurations.Count) | Backend Pools: $($lb.BackendAddressPools.Count)"
                    RiskLevel = "INFO"
                    SecurityIssues = ""
                }
            }
        } catch {
            Write-ColorOutput -Message "[!] Error retrieving Load Balancers: $($_.Exception.Message)" -Color "Red"
        }
        
        Write-ColorOutput -Message "`n[*] Subscription enumeration complete`n" -Color "Green"
    }
    
    # Summary
    Show-MultiSubscriptionSummary -SubscriptionsScanned $subscriptionsToScan.Count -TotalItems ($totalVNets + $totalNSGs + $totalPublicIPs + $totalLoadBalancers) -ItemType "Network Resources" -SubscriptionId $SubscriptionId
    
    Write-ColorOutput -Message "`n[*] RESOURCE BREAKDOWN:" -Color "Yellow"
    Write-ColorOutput -Message "    Virtual Networks: $totalVNets" -Color "Cyan"
    Write-ColorOutput -Message "    Network Security Groups: $totalNSGs" -Color "Cyan"
    Write-ColorOutput -Message "    Public IP Addresses: $totalPublicIPs" -Color "Cyan"
    Write-ColorOutput -Message "    Load Balancers: $totalLoadBalancers" -Color "Cyan"
    
    Write-ColorOutput -Message "`n[*] SECURITY SUMMARY:" -Color "Yellow"
    Write-ColorOutput -Message "    NSGs with Risky Inbound Rules: $openNSGRules" -Color $(if ($openNSGRules -gt 0) { "Red" } else { "Green" })
    Write-ColorOutput -Message "    Unassociated Public IPs: $unassociatedPublicIPs" -Color $(if ($unassociatedPublicIPs -gt 0) { "Yellow" } else { "Green" })
    
    # Export if requested
    if ($ExportPath) {
        $stats = @{
            "Subscriptions Scanned" = $subscriptionsToScan.Count
            "Virtual Networks" = $totalVNets
            "Network Security Groups" = $totalNSGs
            "Public IP Addresses" = $totalPublicIPs
            "Load Balancers" = $totalLoadBalancers
            "Risky NSG Rules (HIGH RISK)" = $openNSGRules
            "Unassociated Public IPs" = $unassociatedPublicIPs
        }
        Export-EnumerationResults -Data $exportData -ExportPath $ExportPath -Title "Azure Network Resource Enumeration" -Statistics $stats -CommandName "network-enum" -Description "Enumeration of Azure Network resources including VNets, NSGs, Public IPs, and Load Balancers"
    }
    
    # Helpful tips
    if ($openNSGRules -gt 0) {
        Write-ColorOutput -Message "`n[*] SECURITY RECOMMENDATIONS:" -Color "Cyan"
        Write-ColorOutput -Message "    - Review and restrict NSG rules allowing traffic from Any/Internet" -Color "Cyan"
        Write-ColorOutput -Message "    - Use Just-In-Time VM Access for management ports (22, 3389)" -Color "Cyan"
        Write-ColorOutput -Message "    - Consider using Azure Bastion instead of public IPs for VM access" -Color "Cyan"
        Write-ColorOutput -Message "    - Implement network segmentation using NSGs and ASGs" -Color "Cyan"
    }
    
    return $exportData
}

