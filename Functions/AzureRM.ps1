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
    $totalNICs = 0
    $openNSGRules = 0
    $unassociatedPublicIPs = 0
    $unattachedNICs = 0
    
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
        
        # ==================
        # Network Interfaces (NICs)
        # ==================
        Write-ColorOutput -Message "`n[*] Retrieving Network Interfaces..." -Color "Yellow"
        
        try {
            $nics = @()
            if ($ResourceGroup) {
                $nics = @(Get-AzNetworkInterface -ResourceGroupName $ResourceGroup -ErrorAction Stop)
            } else {
                $nics = @(Get-AzNetworkInterface -ErrorAction Stop)
            }
            Write-ColorOutput -Message "[+] Retrieved $($nics.Count) Network Interface(s)" -Color "Green"
            $totalNICs += $nics.Count
            
            foreach ($nic in $nics) {
                $nicName = $nic.Name
                $nicRG = $nic.ResourceGroupName
                $isAttached = $null -ne $nic.VirtualMachine
                
                if (-not $isAttached) {
                    $unattachedNICs++
                }
                
                # Get IP configurations
                $privateIPs = @()
                $publicIPs = @()
                $hasPublicIP = $false
                
                foreach ($ipConfig in $nic.IpConfigurations) {
                    $privateIP = $ipConfig.PrivateIpAddress
                    if ($privateIP) {
                        $privateIPs += $privateIP
                    }
                    
                    # Check for associated public IP
                    if ($ipConfig.PublicIpAddress) {
                        $hasPublicIP = $true
                        try {
                            $pubIPResource = Get-AzPublicIpAddress -ResourceGroupName $nicRG -Name ($ipConfig.PublicIpAddress.Id -split '/')[-1] -ErrorAction SilentlyContinue
                            if ($pubIPResource -and $pubIPResource.IpAddress) {
                                $publicIPs += $pubIPResource.IpAddress
                            }
                        } catch {
                            # Silently continue if we can't get the public IP details
                        }
                    }
                }
                
                # Get NSG association
                $nsgAssociated = $null -ne $nic.NetworkSecurityGroup
                $nsgName = if ($nsgAssociated) { 
                    ($nic.NetworkSecurityGroup.Id -split '/')[-1] 
                } else { 
                    "None" 
                }
                
                # Get VM association
                $vmName = if ($isAttached) { 
                    ($nic.VirtualMachine.Id -split '/')[-1] 
                } else { 
                    "Not Attached" 
                }
                
                # Determine risk level
                $securityIssues = @()
                $riskLevel = "INFO"
                
                if (-not $isAttached) {
                    $securityIssues += "Unattached NIC (billable, potential misconfiguration)"
                    $riskLevel = "MEDIUM"
                }
                
                if ($hasPublicIP -and -not $nsgAssociated) {
                    $securityIssues += "Public IP without NSG (HIGH RISK)"
                    $riskLevel = "HIGH"
                } elseif ($hasPublicIP) {
                    $securityIssues += "Has Public IP (verify NSG rules)"
                    if ($riskLevel -eq "INFO") {
                        $riskLevel = "MEDIUM"
                    }
                }
                
                if (-not $nsgAssociated -and $isAttached) {
                    $securityIssues += "No NSG associated (relies on subnet NSG)"
                    if ($riskLevel -eq "INFO") {
                        $riskLevel = "LOW"
                    }
                }
                
                # IP Forwarding enabled?
                if ($nic.EnableIPForwarding) {
                    $securityIssues += "IP Forwarding enabled (routing/firewall capability)"
                    if ($riskLevel -eq "INFO") {
                        $riskLevel = "MEDIUM"
                    }
                }
                
                # Accelerated Networking
                $acceleratedNetworking = if ($nic.EnableAcceleratedNetworking) { "Enabled" } else { "Disabled" }
                
                $riskColor = switch ($riskLevel) {
                    "HIGH" { "Red" }
                    "MEDIUM" { "Yellow" }
                    "LOW" { "Cyan" }
                    default { "White" }
                }
                
                Write-ColorOutput -Message "    [*] NIC: $nicName" -Color "White"
                Write-ColorOutput -Message "        Resource Group: $nicRG" -Color "Gray"
                Write-ColorOutput -Message "        Attached to VM: $vmName" -Color $(if ($isAttached) { "Green" } else { "Yellow" })
                Write-ColorOutput -Message "        Private IP(s): $(if ($privateIPs.Count -gt 0) { $privateIPs -join ', ' } else { 'None' })" -Color "Cyan"
                
                if ($publicIPs.Count -gt 0) {
                    Write-ColorOutput -Message "        Public IP(s): $($publicIPs -join ', ')" -Color "Yellow"
                } else {
                    Write-ColorOutput -Message "        Public IP(s): None" -Color "Gray"
                }
                
                Write-ColorOutput -Message "        NSG: $nsgName" -Color $(if ($nsgAssociated) { "Green" } else { "Gray" })
                Write-ColorOutput -Message "        IP Forwarding: $(if ($nic.EnableIPForwarding) { 'Enabled' } else { 'Disabled' })" -Color $(if ($nic.EnableIPForwarding) { "Yellow" } else { "Gray" })
                Write-ColorOutput -Message "        Accelerated Networking: $acceleratedNetworking" -Color "Gray"
                Write-ColorOutput -Message "        MAC Address: $(if ($nic.MacAddress) { $nic.MacAddress } else { 'Not Allocated' })" -Color "Gray"
                Write-ColorOutput -Message "        Risk Level: $riskLevel" -Color $riskColor
                
                if ($securityIssues.Count -gt 0) {
                    Write-ColorOutput -Message "        [!] SECURITY ISSUES:" -Color "Red"
                    foreach ($issue in $securityIssues) {
                        Write-ColorOutput -Message "            - $issue" -Color "Red"
                    }
                }
                
                # Build export object for NIC
                $exportData += [PSCustomObject]@{
                    Subscription = $subscription.Name
                    SubscriptionId = $subscription.Id
                    ResourceType = "NetworkInterface"
                    Name = $nicName
                    ResourceGroup = $nicRG
                    Location = $nic.Location
                    Details = "VM: $vmName | Private IPs: $($privateIPs -join ', ') | Public IPs: $(if ($publicIPs.Count -gt 0) { $publicIPs -join ', ' } else { 'None' }) | NSG: $nsgName | MAC: $(if ($nic.MacAddress) { $nic.MacAddress } else { 'N/A' })"
                    RiskLevel = $riskLevel
                    SecurityIssues = ($securityIssues -join "; ")
                }
            }
        } catch {
            Write-ColorOutput -Message "[!] Error retrieving Network Interfaces: $($_.Exception.Message)" -Color "Red"
        }
        
        Write-ColorOutput -Message "`n[*] Subscription enumeration complete`n" -Color "Green"
    }
    
    # Summary
    Show-MultiSubscriptionSummary -SubscriptionsScanned $subscriptionsToScan.Count -TotalItems ($totalVNets + $totalNSGs + $totalPublicIPs + $totalLoadBalancers + $totalNICs) -ItemType "Network Resources" -SubscriptionId $SubscriptionId
    
    Write-ColorOutput -Message "`n[*] RESOURCE BREAKDOWN:" -Color "Yellow"
    Write-ColorOutput -Message "    Virtual Networks: $totalVNets" -Color "Cyan"
    Write-ColorOutput -Message "    Network Security Groups: $totalNSGs" -Color "Cyan"
    Write-ColorOutput -Message "    Public IP Addresses: $totalPublicIPs" -Color "Cyan"
    Write-ColorOutput -Message "    Load Balancers: $totalLoadBalancers" -Color "Cyan"
    Write-ColorOutput -Message "    Network Interfaces: $totalNICs" -Color "Cyan"
    
    Write-ColorOutput -Message "`n[*] SECURITY SUMMARY:" -Color "Yellow"
    Write-ColorOutput -Message "    NSGs with Risky Inbound Rules: $openNSGRules" -Color $(if ($openNSGRules -gt 0) { "Red" } else { "Green" })
    Write-ColorOutput -Message "    Unassociated Public IPs: $unassociatedPublicIPs" -Color $(if ($unassociatedPublicIPs -gt 0) { "Yellow" } else { "Green" })
    Write-ColorOutput -Message "    Unattached Network Interfaces: $unattachedNICs" -Color $(if ($unattachedNICs -gt 0) { "Yellow" } else { "Green" })
    
    # Export if requested
    if ($ExportPath) {
        $stats = @{
            "Subscriptions Scanned" = $subscriptionsToScan.Count
            "Virtual Networks" = $totalVNets
            "Network Security Groups" = $totalNSGs
            "Public IP Addresses" = $totalPublicIPs
            "Load Balancers" = $totalLoadBalancers
            "Network Interfaces" = $totalNICs
            "Risky NSG Rules (HIGH RISK)" = $openNSGRules
            "Unassociated Public IPs" = $unassociatedPublicIPs
            "Unattached NICs" = $unattachedNICs
        }
        Export-EnumerationResults -Data $exportData -ExportPath $ExportPath -Title "Azure Network Resource Enumeration" -Statistics $stats -CommandName "network-enum" -Description "Enumeration of Azure Network resources including VNets, NSGs, Public IPs, Load Balancers, and Network Interfaces"
    }
    
    # Helpful tips
    if ($openNSGRules -gt 0 -or $unattachedNICs -gt 0) {
        Write-ColorOutput -Message "`n[*] SECURITY RECOMMENDATIONS:" -Color "Cyan"
        if ($openNSGRules -gt 0) {
            Write-ColorOutput -Message "    - Review and restrict NSG rules allowing traffic from Any/Internet" -Color "Cyan"
            Write-ColorOutput -Message "    - Use Just-In-Time VM Access for management ports (22, 3389)" -Color "Cyan"
            Write-ColorOutput -Message "    - Consider using Azure Bastion instead of public IPs for VM access" -Color "Cyan"
            Write-ColorOutput -Message "    - Implement network segmentation using NSGs and ASGs" -Color "Cyan"
        }
        if ($unattachedNICs -gt 0) {
            Write-ColorOutput -Message "    - Remove unattached network interfaces to reduce costs and attack surface" -Color "Cyan"
            Write-ColorOutput -Message "    - Unattached NICs with public IPs are billable and may be misconfigured" -Color "Cyan"
        }
    }
    
    return $exportData
}


# ============================================
# AZURE FILE SHARES ENUMERATION (--shares equivalent)
# ============================================

<#
.SYNOPSIS
    Enumerate Azure File Shares across Storage Accounts.
.DESCRIPTION
    The Azure equivalent of NetExec's --shares command. Discovers File Shares
    in Storage Accounts with access permission analysis. Shows which shares
    are accessible, their quotas, and access tier.
    
    NetExec equivalent: nxc smb 192.168.1.0/24 -u user -p 'PASSWORDHERE' --shares
    
    In Azure, "shares" are Azure File Shares in Storage Accounts. This command
    enumerates all file shares and their configurations, including:
    - Share name and quota
    - Access tier (Hot, Cool, Transaction Optimized)
    - Enabled protocols (SMB, NFS)
    - Access permissions (based on RBAC and storage account settings)
    - Share snapshots
    
    Security relevance:
    - File Shares may contain sensitive data
    - Misconfigured shares can expose data to unauthorized users
    - Public access settings on storage accounts affect share accessibility
#>
function Invoke-SharesEnumeration {
    param(
        [string]$ResourceGroup,
        [string]$SubscriptionId,
        [string]$ExportPath,
        [ValidateSet("all", "READ", "WRITE", "READ,WRITE")]
        [string]$SharesFilter = "all"
    )
    
    Write-ColorOutput -Message "`n[*] AZX - Azure File Shares Enumeration" -Color "Yellow"
    Write-ColorOutput -Message "[*] Command: shares-enum (Azure equivalent of nxc smb --shares)" -Color "Yellow"
    Write-ColorOutput -Message "[*] Discovering Azure File Shares with access permissions`n" -Color "Cyan"
    
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
    $totalFileShares = 0
    $sharesWithReadAccess = 0
    $sharesWithWriteAccess = 0
    $sharesWithPublicAccess = 0
    $smbShares = 0
    $nfsShares = 0
    
    Write-ColorOutput -Message "[*] ========================================" -Color "Cyan"
    Write-ColorOutput -Message "[*] AZURE FILE SHARES ENUMERATION" -Color "Cyan"
    Write-ColorOutput -Message "[*] (NetExec --shares equivalent)" -Color "Cyan"
    Write-ColorOutput -Message "[*] ========================================`n" -Color "Cyan"
    
    # Display filter information
    if ($SharesFilter -ne "all") {
        Write-ColorOutput -Message "[*] Filter: Only showing shares with $SharesFilter access`n" -Color "Yellow"
    }
    
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
            
            # Get storage account context for file share enumeration
            try {
                $saContext = $sa.Context
                if (-not $saContext) {
                    # Try to get context using keys (requires Storage Account Key Operator or higher)
                    try {
                        $saKeys = Get-AzStorageAccountKey -ResourceGroupName $saRG -Name $saName -ErrorAction Stop
                        $saContext = New-AzStorageContext -StorageAccountName $saName -StorageAccountKey $saKeys[0].Value -ErrorAction Stop
                    } catch {
                        # Try with OAuth token instead
                        try {
                            $saContext = New-AzStorageContext -StorageAccountName $saName -UseConnectedAccount -ErrorAction Stop
                        } catch {
                            Write-ColorOutput -Message "[!] Cannot access storage account: $saName (no key/OAuth access)" -Color "Yellow"
                            continue
                        }
                    }
                }
            } catch {
                Write-ColorOutput -Message "[!] Failed to get context for storage account: $saName" -Color "Yellow"
                continue
            }
            
            # Get file shares
            try {
                $fileShares = @(Get-AzStorageShare -Context $saContext -ErrorAction Stop)
            } catch {
                $errorMessage = $_.Exception.Message
                if ($errorMessage -like "*AuthorizationFailure*" -or $errorMessage -like "*AuthenticationFailed*") {
                    Write-ColorOutput -Message "[!] Access denied to file shares in: $saName" -Color "Yellow"
                } else {
                    Write-ColorOutput -Message "[!] Error retrieving file shares from $saName : $errorMessage" -Color "Yellow"
                }
                continue
            }
            
            if ($fileShares.Count -eq 0) {
                continue
            }
            
            # Storage account header (like netexec host header)
            $networkDefaultAction = $sa.NetworkRuleSet.DefaultAction
            $isPubliclyAccessible = ($networkDefaultAction -eq "Allow") -or ($sa.AllowBlobPublicAccess -eq $true)
            
            Write-ColorOutput -Message "`n[*] Storage Account: $saName" -Color "White"
            Write-ColorOutput -Message "    Resource Group: $saRG | Location: $($sa.PrimaryLocation)" -Color "Gray"
            Write-ColorOutput -Message "    Public Network Access: $(if ($isPubliclyAccessible) { 'Enabled' } else { 'Restricted' })" -Color $(if ($isPubliclyAccessible) { "Yellow" } else { "Green" })
            Write-ColorOutput -Message "    File Shares Found: $($fileShares.Count)" -Color "Cyan"
            
            foreach ($share in $fileShares) {
                $shareName = $share.Name
                $shareQuota = $share.Quota
                $shareLastModified = $share.LastModified
                
                # Get detailed share properties
                try {
                    $shareProperties = Get-AzStorageShare -Name $shareName -Context $saContext -ErrorAction Stop
                    $shareAccessTier = $shareProperties.ShareProperties.AccessTier
                    $shareEnabledProtocols = $shareProperties.ShareProperties.EnabledProtocols
                    $shareRootSquash = $shareProperties.ShareProperties.RootSquash
                } catch {
                    $shareAccessTier = "Unknown"
                    $shareEnabledProtocols = "SMB"
                    $shareRootSquash = "N/A"
                }
                
                # Determine access permissions based on RBAC and storage account settings
                # In Azure, READ = Storage Blob Data Reader / Storage File Data SMB Share Reader
                # WRITE = Storage Blob Data Contributor / Storage File Data SMB Share Contributor
                # For simplicity, we check if the current user can access the share
                $canRead = $true  # If we got here, we can at least list shares
                $canWrite = $false
                
                # Test write access by checking if we can get share metadata
                try {
                    # If we can access share properties, we likely have at least read access
                    # Write access would require Storage File Data SMB Share Contributor role
                    $shareAcl = Get-AzStorageShareStoredAccessPolicy -ShareName $shareName -Context $saContext -ErrorAction SilentlyContinue
                    if ($null -ne $shareAcl) {
                        $canWrite = $true
                    }
                } catch {
                    # Write access check failed - user likely has only read access
                }
                
                # Track access types
                if ($canRead) { $sharesWithReadAccess++ }
                if ($canWrite) { $sharesWithWriteAccess++ }
                if ($isPubliclyAccessible) { $sharesWithPublicAccess++ }
                
                # Track protocol types
                if ($shareEnabledProtocols -eq "SMB") { $smbShares++ }
                elseif ($shareEnabledProtocols -eq "NFS") { $nfsShares++ }
                
                # Build access string (netexec style)
                $accessString = ""
                if ($canRead -and $canWrite) {
                    $accessString = "READ,WRITE"
                } elseif ($canRead) {
                    $accessString = "READ"
                } elseif ($canWrite) {
                    $accessString = "WRITE"
                } else {
                    $accessString = "NO ACCESS"
                }
                
                # Apply filter if specified
                if ($SharesFilter -ne "all") {
                    if ($SharesFilter -eq "READ" -and -not ($canRead -and -not $canWrite)) { continue }
                    if ($SharesFilter -eq "WRITE" -and -not $canWrite) { continue }
                    if ($SharesFilter -eq "READ,WRITE" -and -not ($canRead -and $canWrite)) { continue }
                }
                
                $totalFileShares++
                
                # Determine color based on access level
                $accessColor = switch ($accessString) {
                    "READ,WRITE" { "Red" }
                    "WRITE" { "Yellow" }
                    "READ" { "Green" }
                    default { "DarkGray" }
                }
                
                # NetExec-style output for shares
                # Format: AZR    STORAGEACCOUNT   443    SHARENAME    [ACCESS]   Quota: XXX GB
                $azrPrefix = "AZR"
                $port = "443"
                
                Write-Host "        " -NoNewline
                Write-Host $azrPrefix -ForegroundColor "Magenta" -NoNewline
                Write-Host "         " -NoNewline
                Write-Host $saName.PadRight(25) -NoNewline
                Write-Host $port.PadRight(7) -NoNewline
                Write-Host $shareName.PadRight(30) -NoNewline
                Write-Host "[$accessString]".PadRight(15) -ForegroundColor $accessColor -NoNewline
                Write-Host "Quota: $($shareQuota)GB | Tier: $shareAccessTier | Protocol: $shareEnabledProtocols" -ForegroundColor "Gray"
                
                # Build export object
                $exportData += [PSCustomObject]@{
                    Subscription = $subscription.Name
                    SubscriptionId = $subscription.Id
                    StorageAccountName = $saName
                    ResourceGroup = $saRG
                    Location = $sa.PrimaryLocation
                    ShareName = $shareName
                    Access = $accessString
                    CanRead = $canRead
                    CanWrite = $canWrite
                    QuotaGB = $shareQuota
                    AccessTier = $shareAccessTier
                    EnabledProtocols = $shareEnabledProtocols
                    RootSquash = $shareRootSquash
                    LastModified = $shareLastModified
                    PublicNetworkAccess = $isPubliclyAccessible
                    StorageAccountKind = $sa.Kind
                    StorageAccountSku = $sa.Sku.Name
                }
            }
        }
        
        Write-ColorOutput -Message "`n[*] Subscription enumeration complete" -Color "Green"
    }
    
    # Summary (netexec style)
    Write-ColorOutput -Message "`n[*] ========================================" -Color "Cyan"
    Write-ColorOutput -Message "[*] SHARES ENUMERATION SUMMARY" -Color "Cyan"
    Write-ColorOutput -Message "[*] ========================================`n" -Color "Cyan"
    
    Write-ColorOutput -Message "[*] Subscriptions Scanned: $($subscriptionsToScan.Count)" -Color "White"
    Write-ColorOutput -Message "[*] Storage Accounts Scanned: $totalStorageAccounts" -Color "White"
    Write-ColorOutput -Message "[*] Total File Shares Found: $totalFileShares" -Color "White"
    
    Write-ColorOutput -Message "`n[*] ACCESS BREAKDOWN:" -Color "Yellow"
    Write-ColorOutput -Message "    Shares with READ access: $sharesWithReadAccess" -Color "Green"
    Write-ColorOutput -Message "    Shares with WRITE access: $sharesWithWriteAccess" -Color $(if ($sharesWithWriteAccess -gt 0) { "Red" } else { "Green" })
    Write-ColorOutput -Message "    Shares in publicly accessible storage: $sharesWithPublicAccess" -Color $(if ($sharesWithPublicAccess -gt 0) { "Red" } else { "Green" })
    
    Write-ColorOutput -Message "`n[*] PROTOCOL BREAKDOWN:" -Color "Yellow"
    Write-ColorOutput -Message "    SMB Shares: $smbShares" -Color "Cyan"
    Write-ColorOutput -Message "    NFS Shares: $nfsShares" -Color "Cyan"
    
    # Export if requested
    if ($ExportPath) {
        $stats = @{
            "Subscriptions Scanned" = $subscriptionsToScan.Count
            "Storage Accounts" = $totalStorageAccounts
            "Total File Shares" = $totalFileShares
            "READ Access" = $sharesWithReadAccess
            "WRITE Access (HIGH RISK)" = $sharesWithWriteAccess
            "Public Network Access" = $sharesWithPublicAccess
        }
        Export-EnumerationResults -Data $exportData -ExportPath $ExportPath -Title "Azure File Shares Enumeration" -Statistics $stats -CommandName "shares-enum" -Description "Azure equivalent of NetExec --shares command. Enumerates Azure File Shares with access permissions."
    }
    
    # Security recommendations
    if ($sharesWithWriteAccess -gt 0 -or $sharesWithPublicAccess -gt 0) {
        Write-ColorOutput -Message "`n[*] SECURITY RECOMMENDATIONS:" -Color "Cyan"
        if ($sharesWithWriteAccess -gt 0) {
            Write-ColorOutput -Message "    - Review shares with WRITE access - potential data exfiltration risk" -Color "Cyan"
            Write-ColorOutput -Message "    - Limit write permissions to minimum required users/groups" -Color "Cyan"
        }
        if ($sharesWithPublicAccess -gt 0) {
            Write-ColorOutput -Message "    - Shares in publicly accessible storage may be at risk" -Color "Cyan"
            Write-ColorOutput -Message "    - Consider enabling firewall rules to restrict access" -Color "Cyan"
            Write-ColorOutput -Message "    - Use Private Endpoints for sensitive file shares" -Color "Cyan"
        }
        Write-ColorOutput -Message "    - Enable Azure Defender for Storage for threat detection" -Color "Cyan"
    }
    
    # NetExec comparison help
    Write-ColorOutput -Message "`n[*] NETEXEC COMPARISON:" -Color "Yellow"
    Write-ColorOutput -Message "    NetExec: nxc smb 192.168.1.0/24 -u user -p 'PASS' --shares" -Color "Gray"
    Write-ColorOutput -Message "    AZexec:  .\azx.ps1 shares-enum" -Color "Gray"
    Write-ColorOutput -Message "`n    NetExec: nxc smb 192.168.1.0/24 -u user -p 'PASS' --shares READ,WRITE" -Color "Gray"
    Write-ColorOutput -Message "    AZexec:  .\azx.ps1 shares-enum -SharesFilter READ,WRITE" -Color "Gray"
    
    return $exportData
}


# ============================================
# AZURE MANAGED DISKS ENUMERATION
# ============================================

<#
.SYNOPSIS
    Enumerate Azure Managed Disks across subscriptions.
.DESCRIPTION
    Discovers Azure Managed Disks with security-relevant information including
    disk size, encryption status, attachment state, SKU, and network access settings.
    This is the Azure equivalent of NetExec's --disks command for SMB enumeration.
.PARAMETER ResourceGroup
    Optional resource group filter.
.PARAMETER SubscriptionId
    Optional subscription ID to target specific subscription.
.PARAMETER ExportPath
    Optional path to export results (CSV, JSON, or HTML).
#>
function Invoke-DisksEnumeration {
    param(
        [string]$ResourceGroup,
        [string]$SubscriptionId,
        [string]$ExportPath
    )
    
    Write-ColorOutput -Message "`n[*] AZX - Azure Managed Disks Enumeration" -Color "Yellow"
    Write-ColorOutput -Message "[*] Command: disks-enum" -Color "Yellow"
    Write-ColorOutput -Message "[*] Discovering managed disks with security configurations`n" -Color "Cyan"
    
    # Initialize required modules
    $requiredModules = @('Az.Accounts', 'Az.Resources', 'Az.Compute')
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
    $totalDisks = 0
    $attachedDisks = 0
    $unattachedDisks = 0
    $encryptedDisks = 0
    $unencryptedDisks = 0
    $publicNetworkAccessDisks = 0
    $osDiskCount = 0
    $dataDiskCount = 0
    $totalSizeGB = 0
    
    Write-ColorOutput -Message "[*] ========================================" -Color "Cyan"
    Write-ColorOutput -Message "[*] MULTI-SUBSCRIPTION DISK ENUMERATION" -Color "Cyan"
    Write-ColorOutput -Message "[*] ========================================`n" -Color "Cyan"
    
    # Loop through each subscription
    foreach ($subscription in $subscriptionsToScan) {
        if (-not (Set-SubscriptionContext -Subscription $subscription)) {
            continue
        }
        
        Write-ColorOutput -Message "[*] Retrieving Managed Disks..." -Color "Yellow"
        
        try {
            $disks = @()
            if ($ResourceGroup) {
                $disks = @(Get-AzDisk -ResourceGroupName $ResourceGroup -ErrorAction Stop)
                Write-ColorOutput -Message "[+] Retrieved $($disks.Count) disk(s) from resource group: $ResourceGroup" -Color "Green"
            } else {
                $disks = @(Get-AzDisk -ErrorAction Stop)
                Write-ColorOutput -Message "[+] Retrieved $($disks.Count) disk(s) across all resource groups" -Color "Green"
            }
        } catch {
            $errorMessage = $_.Exception.Message
            if ($errorMessage -like "*AuthorizationFailed*") {
                Write-ColorOutput -Message "[!] Authorization failed for subscription: $($subscription.Name)" -Color "Red"
                Write-ColorOutput -Message "[*] Skipping to next subscription...`n" -Color "Yellow"
            } else {
                Write-ColorOutput -Message "[!] Error retrieving disks: $errorMessage" -Color "Red"
            }
            continue
        }
        
        if ($disks.Count -eq 0) {
            Write-ColorOutput -Message "[*] No managed disks found in this subscription`n" -Color "Yellow"
            continue
        }
        
        $totalDisks += $disks.Count
        
        # Display disk information in netexec style
        Write-ColorOutput -Message "`n[*] Managed Disks Found: $($disks.Count)" -Color "Cyan"
        Write-ColorOutput -Message "[*] --------------------------------------------------`n" -Color "Cyan"
        
        # Header (netexec style)
        Write-Host "    " -NoNewline
        Write-Host "AZR".PadRight(8) -ForegroundColor "Magenta" -NoNewline
        Write-Host "DISK NAME".PadRight(40) -ForegroundColor "White" -NoNewline
        Write-Host "SIZE".PadRight(10) -ForegroundColor "White" -NoNewline
        Write-Host "TYPE".PadRight(12) -ForegroundColor "White" -NoNewline
        Write-Host "STATE".PadRight(15) -ForegroundColor "White" -NoNewline
        Write-Host "ENCRYPTION" -ForegroundColor "White"
        Write-Host "    " -NoNewline
        Write-Host ("-" * 100) -ForegroundColor "DarkGray"
        
        foreach ($disk in $disks) {
            $diskName = $disk.Name
            $diskRG = $disk.ResourceGroupName
            $diskLocation = $disk.Location
            $diskSizeGB = $disk.DiskSizeGB
            $diskSku = $disk.Sku.Name
            $diskState = $disk.DiskState
            $osType = $disk.OsType
            $diskType = if ($osType) { "OS Disk" } else { "Data Disk" }
            
            # Encryption settings
            $encryptionType = "None"
            $isEncrypted = $false
            if ($disk.Encryption) {
                if ($disk.Encryption.Type -eq "EncryptionAtRestWithPlatformKey") {
                    $encryptionType = "Platform-Managed"
                    $isEncrypted = $true
                } elseif ($disk.Encryption.Type -eq "EncryptionAtRestWithCustomerKey") {
                    $encryptionType = "Customer-Managed"
                    $isEncrypted = $true
                } elseif ($disk.Encryption.Type -eq "EncryptionAtRestWithPlatformAndCustomerKeys") {
                    $encryptionType = "Platform+Customer"
                    $isEncrypted = $true
                }
            } elseif ($disk.EncryptionSettingsCollection) {
                $encryptionType = "Legacy Encryption"
                $isEncrypted = $true
            }
            
            # Network access
            $networkAccessPolicy = $disk.NetworkAccessPolicy
            $publicNetworkAccess = $disk.PublicNetworkAccess
            $hasPublicAccess = ($publicNetworkAccess -eq "Enabled") -or ($networkAccessPolicy -eq "AllowAll")
            
            # Attachment state
            $isAttached = ($diskState -eq "Attached")
            $attachedTo = if ($disk.ManagedBy) { 
                $vmName = ($disk.ManagedBy -split '/')[-1]
                $vmName
            } else { 
                "Unattached" 
            }
            
            # Track statistics
            if ($isAttached) { $attachedDisks++ } else { $unattachedDisks++ }
            if ($isEncrypted) { $encryptedDisks++ } else { $unencryptedDisks++ }
            if ($hasPublicAccess) { $publicNetworkAccessDisks++ }
            if ($osType) { $osDiskCount++ } else { $dataDiskCount++ }
            $totalSizeGB += $diskSizeGB
            
            # Determine risk level
            $riskLevel = "LOW"
            $securityIssues = @()
            
            if (-not $isEncrypted) {
                $riskLevel = "HIGH"
                $securityIssues += "No Encryption"
            }
            if ($hasPublicAccess) {
                if ($riskLevel -ne "HIGH") { $riskLevel = "MEDIUM" }
                $securityIssues += "Public Network Access"
            }
            if (-not $isAttached) {
                $securityIssues += "Unattached"
            }
            
            # Color coding
            $stateColor = if ($isAttached) { "Green" } else { "Yellow" }
            $encryptionColor = if ($isEncrypted) { "Green" } else { "Red" }
            $riskColor = switch ($riskLevel) {
                "HIGH" { "Red" }
                "MEDIUM" { "Yellow" }
                default { "Green" }
            }
            
            # NetExec-style output
            Write-Host "    " -NoNewline
            Write-Host "AZR".PadRight(8) -ForegroundColor "Magenta" -NoNewline
            Write-Host $diskName.Substring(0, [Math]::Min(38, $diskName.Length)).PadRight(40) -NoNewline
            Write-Host "$($diskSizeGB)GB".PadRight(10) -NoNewline
            Write-Host $diskType.PadRight(12) -NoNewline
            Write-Host $diskState.PadRight(15) -ForegroundColor $stateColor -NoNewline
            Write-Host $encryptionType -ForegroundColor $encryptionColor
            
            # Additional details
            Write-Host "        " -NoNewline
            Write-Host "RG: $diskRG | Location: $diskLocation | SKU: $diskSku" -ForegroundColor "DarkGray"
            
            if ($isAttached) {
                Write-Host "        " -NoNewline
                Write-Host "Attached to: $attachedTo" -ForegroundColor "Gray"
            }
            
            if ($securityIssues.Count -gt 0) {
                Write-Host "        " -NoNewline
                Write-Host "[RISK: $riskLevel] " -ForegroundColor $riskColor -NoNewline
                Write-Host "$($securityIssues -join ', ')" -ForegroundColor "Gray"
            }
            
            if ($osType) {
                Write-Host "        " -NoNewline
                Write-Host "OS Type: $osType" -ForegroundColor "Cyan"
            }
            
            Write-Host ""
            
            # Build export object
            $exportData += [PSCustomObject]@{
                Subscription = $subscription.Name
                SubscriptionId = $subscription.Id
                DiskName = $diskName
                ResourceGroup = $diskRG
                Location = $diskLocation
                SizeGB = $diskSizeGB
                DiskType = $diskType
                OsType = $osType
                DiskState = $diskState
                IsAttached = $isAttached
                AttachedTo = $attachedTo
                SkuName = $diskSku
                SkuTier = $disk.Sku.Tier
                EncryptionType = $encryptionType
                IsEncrypted = $isEncrypted
                NetworkAccessPolicy = $networkAccessPolicy
                PublicNetworkAccess = $publicNetworkAccess
                HasPublicAccess = $hasPublicAccess
                RiskLevel = $riskLevel
                SecurityIssues = ($securityIssues -join '; ')
                CreationTime = $disk.TimeCreated
                DiskIOPSReadWrite = $disk.DiskIOPSReadWrite
                DiskMBpsReadWrite = $disk.DiskMBpsReadWrite
                Zones = ($disk.Zones -join ',')
            }
        }
        
        Write-ColorOutput -Message "[*] Subscription enumeration complete" -Color "Green"
    }
    
    # Summary (netexec style)
    Write-ColorOutput -Message "`n[*] ========================================" -Color "Cyan"
    Write-ColorOutput -Message "[*] DISKS ENUMERATION SUMMARY" -Color "Cyan"
    Write-ColorOutput -Message "[*] ========================================`n" -Color "Cyan"
    
    Write-ColorOutput -Message "[*] Subscriptions Scanned: $($subscriptionsToScan.Count)" -Color "White"
    Write-ColorOutput -Message "[*] Total Managed Disks Found: $totalDisks" -Color "White"
    Write-ColorOutput -Message "[*] Total Storage Capacity: $totalSizeGB GB" -Color "White"
    
    Write-ColorOutput -Message "`n[*] DISK TYPE BREAKDOWN:" -Color "Yellow"
    Write-ColorOutput -Message "    OS Disks: $osDiskCount" -Color "Cyan"
    Write-ColorOutput -Message "    Data Disks: $dataDiskCount" -Color "Cyan"
    
    Write-ColorOutput -Message "`n[*] ATTACHMENT STATE:" -Color "Yellow"
    Write-ColorOutput -Message "    Attached Disks: $attachedDisks" -Color "Green"
    Write-ColorOutput -Message "    Unattached Disks: $unattachedDisks" -Color $(if ($unattachedDisks -gt 0) { "Yellow" } else { "Green" })
    
    Write-ColorOutput -Message "`n[*] ENCRYPTION STATUS:" -Color "Yellow"
    Write-ColorOutput -Message "    Encrypted Disks: $encryptedDisks" -Color "Green"
    Write-ColorOutput -Message "    Unencrypted Disks: $unencryptedDisks" -Color $(if ($unencryptedDisks -gt 0) { "Red" } else { "Green" })
    
    Write-ColorOutput -Message "`n[*] NETWORK ACCESS:" -Color "Yellow"
    Write-ColorOutput -Message "    Public Network Access Enabled: $publicNetworkAccessDisks" -Color $(if ($publicNetworkAccessDisks -gt 0) { "Yellow" } else { "Green" })
    
    # Export if requested
    if ($ExportPath) {
        $stats = @{
            "Subscriptions Scanned" = $subscriptionsToScan.Count
            "Total Disks" = $totalDisks
            "Total Storage (GB)" = $totalSizeGB
            "OS Disks" = $osDiskCount
            "Data Disks" = $dataDiskCount
            "Attached Disks" = $attachedDisks
            "Unattached Disks (MEDIUM RISK)" = $unattachedDisks
            "Encrypted Disks" = $encryptedDisks
            "Unencrypted Disks (HIGH RISK)" = $unencryptedDisks
            "Public Network Access" = $publicNetworkAccessDisks
        }
        Export-EnumerationResults -Data $exportData -ExportPath $ExportPath -Title "Azure Managed Disks Enumeration" -Statistics $stats -CommandName "disks-enum" -Description "Azure equivalent of NetExec --disks command. Enumerates Azure Managed Disks with encryption and security configurations."
    }
    
    # Security recommendations
    if ($unencryptedDisks -gt 0 -or $unattachedDisks -gt 0 -or $publicNetworkAccessDisks -gt 0) {
        Write-ColorOutput -Message "`n[*] SECURITY RECOMMENDATIONS:" -Color "Cyan"
        if ($unencryptedDisks -gt 0) {
            Write-ColorOutput -Message "    - Enable encryption for all unencrypted disks (HIGH PRIORITY)" -Color "Cyan"
            Write-ColorOutput -Message "    - Use Azure Disk Encryption (ADE) or Server-Side Encryption (SSE)" -Color "Cyan"
            Write-ColorOutput -Message "    - Consider using Customer-Managed Keys for sensitive data" -Color "Cyan"
        }
        if ($unattachedDisks -gt 0) {
            Write-ColorOutput -Message "    - Review unattached disks - potential orphaned resources" -Color "Cyan"
            Write-ColorOutput -Message "    - Delete unused disks to reduce costs and attack surface" -Color "Cyan"
            Write-ColorOutput -Message "    - Unattached disks may contain sensitive data from deleted VMs" -Color "Cyan"
        }
        if ($publicNetworkAccessDisks -gt 0) {
            Write-ColorOutput -Message "    - Restrict public network access to disks" -Color "Cyan"
            Write-ColorOutput -Message "    - Use Private Endpoints for disk access" -Color "Cyan"
        }
        Write-ColorOutput -Message "    - Enable Azure Defender for Storage for threat detection" -Color "Cyan"
        Write-ColorOutput -Message "    - Implement disk backup and snapshot policies" -Color "Cyan"
    }
    
    # NetExec comparison help
    Write-ColorOutput -Message "`n[*] NETEXEC COMPARISON:" -Color "Yellow"
    Write-ColorOutput -Message "    NetExec: nxc smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --disks" -Color "Gray"
    Write-ColorOutput -Message "    AZexec:  .\azx.ps1 disks-enum" -Color "Gray"
    Write-ColorOutput -Message "`n    NetExec enumerates local/network disks on remote SMB hosts" -Color "Gray"
    Write-ColorOutput -Message "    AZexec enumerates Azure Managed Disks across subscriptions" -Color "Gray"
    
    return $exportData
}

# ============================================
# BITLOCKER ENUMERATION (NetExec --bitlocker equivalent)
# ============================================
function Invoke-BitLockerEnumeration {
    param(
        [string]$ResourceGroup,
        [string]$SubscriptionId,
        [ValidateSet("all", "running", "stopped")]
        [string]$VMFilter = "running",
        [string]$ExportPath
    )
    
    Write-ColorOutput -Message "`n[*] AZX - Azure BitLocker Enumeration" -Color "Yellow"
    Write-ColorOutput -Message "[*] Command: bitlocker-enum" -Color "Yellow"
    Write-ColorOutput -Message "[*] Enumerating BitLocker encryption status`n" -Color "Cyan"
    
    # ============================================
    # SECTION 1: INTUNE-MANAGED DEVICES (Graph API)
    # ============================================
    Write-ColorOutput -Message "[*] ========================================" -Color "Cyan"
    Write-ColorOutput -Message "[*] SECTION 1: INTUNE-MANAGED DEVICES" -Color "Cyan"
    Write-ColorOutput -Message "[*] ========================================`n" -Color "Cyan"
    
    $intuneDevicesFound = $false
    $intuneEncrypted = 0
    $intuneNotEncrypted = 0
    $intuneExportData = @()
    $notEncryptedDevices = @()
    
    try {
        # Check if Microsoft.Graph module is available
        if (Get-Module -ListAvailable -Name Microsoft.Graph.Authentication) {
            Import-Module Microsoft.Graph.Authentication -ErrorAction SilentlyContinue
            
            # Try to connect to Graph with Intune permissions
            Write-ColorOutput -Message "[*] Connecting to Microsoft Graph for Intune device data..." -Color "Yellow"
            Connect-MgGraph -Scopes "DeviceManagementManagedDevices.Read.All" -NoWelcome -ErrorAction Stop
            
            $context = Get-MgContext
            if ($context) {
                Write-ColorOutput -Message "[+] Connected to Graph as: $($context.Account)" -Color "Green"
                
                # Query Intune for Windows devices with encryption status
                $uri = "https://graph.microsoft.com/v1.0/deviceManagement/managedDevices?`$filter=operatingSystem eq 'Windows'&`$select=id,deviceName,azureADDeviceId,isEncrypted,complianceState,userPrincipalName,lastSyncDateTime"
                $intuneDevices = Invoke-MgGraphRequest -Uri $uri -Method GET -ErrorAction Stop
                
                if ($intuneDevices.value -and $intuneDevices.value.Count -gt 0) {
                    $intuneDevicesFound = $true
                    Write-ColorOutput -Message "[+] Found $($intuneDevices.value.Count) Windows devices in Intune`n" -Color "Green"
                    
                    foreach ($device in $intuneDevices.value) {
                        $deviceName = $device.deviceName
                        $isEncrypted = $device.isEncrypted
                        $compliance = $device.complianceState
                        $user = $device.userPrincipalName
                        $lastSync = $device.lastSyncDateTime
                        
                        # Determine color based on encryption status
                        if ($isEncrypted -eq $true) {
                            $color = "Green"
                            $status = "BitLocker ENABLED"
                            $intuneEncrypted++
                        } else {
                            $color = "Red"
                            $status = "NOT ENCRYPTED"
                            $intuneNotEncrypted++
                            $notEncryptedDevices += $deviceName
                        }
                        
                        # NetExec-style output
                        Write-Host "AZR".PadRight(12) -ForegroundColor "Cyan" -NoNewline
                        Write-Host $device.azureADDeviceId.Substring(0, [Math]::Min(14, $device.azureADDeviceId.Length)).PadRight(17) -NoNewline
                        Write-Host "443".PadRight(7) -NoNewline
                        Write-Host $deviceName.PadRight(35) -NoNewline
                        Write-Host "[*] " -ForegroundColor $color -NoNewline
                        Write-Host $status -ForegroundColor $color -NoNewline
                        Write-Host " | Compliance: $compliance" -ForegroundColor "Gray"
                        
                        # Collect for export
                        $intuneExportData += [PSCustomObject]@{
                            Source = "Intune"
                            DeviceName = $deviceName
                            AzureADDeviceId = $device.azureADDeviceId
                            IsEncrypted = $isEncrypted
                            ComplianceState = $compliance
                            UserPrincipalName = $user
                            LastSyncDateTime = $lastSync
                        }
                    }
                    
                    # Summary for Intune devices
                    Write-ColorOutput -Message "`n[*] Intune Device Summary:" -Color "Cyan"
                    Write-ColorOutput -Message "    Total Windows Devices: $($intuneDevices.value.Count)" -Color "White"
                    Write-ColorOutput -Message "    BitLocker Enabled: $intuneEncrypted" -Color "Green"
                    if ($intuneNotEncrypted -gt 0) {
                        Write-ColorOutput -Message "    NOT Encrypted: $intuneNotEncrypted" -Color "Red"
                        Write-ColorOutput -Message "`n[!] Devices without BitLocker:" -Color "Red"
                        foreach ($deviceName in $notEncryptedDevices) {
                            Write-ColorOutput -Message "    → $deviceName" -Color "Red"
                        }
                    }
                } else {
                    Write-ColorOutput -Message "[*] No Windows devices found in Intune" -Color "Yellow"
                }
            }
        } else {
            Write-ColorOutput -Message "[*] Microsoft.Graph module not available - skipping Intune enumeration" -Color "Yellow"
            Write-ColorOutput -Message "[*] Install with: Install-Module Microsoft.Graph -Scope CurrentUser" -Color "Gray"
        }
    } catch {
        Write-ColorOutput -Message "[!] Failed to query Intune devices: $($_.Exception.Message)" -Color "Yellow"
        Write-ColorOutput -Message "[*] This may require DeviceManagementManagedDevices.Read.All permission with admin consent" -Color "Gray"
    }
    
    # ============================================
    # SECTION 2: AZURE VMs (ARM API)
    # ============================================
    Write-ColorOutput -Message "`n[*] ========================================" -Color "Cyan"
    Write-ColorOutput -Message "[*] SECTION 2: AZURE VMs (via Run Command)" -Color "Cyan"
    Write-ColorOutput -Message "[*] ========================================`n" -Color "Cyan"
    
    # Initialize required modules
    $requiredModules = @('Az.Accounts', 'Az.Compute', 'Az.Resources')
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
    $totalVMs = 0
    $queriedVMs = 0
    $successfulQueries = 0
    $failedQueries = 0
    $windowsVMs = 0
    $encryptedVolumes = 0
    $unencryptedVolumes = 0
    $totalVolumes = 0
    
    Write-ColorOutput -Message "[*] ========================================" -Color "Cyan"
    Write-ColorOutput -Message "[*] MULTI-SUBSCRIPTION BITLOCKER ENUMERATION" -Color "Cyan"
    Write-ColorOutput -Message "[*] ========================================`n" -Color "Cyan"
    
    # Loop through each subscription
    foreach ($subscription in $subscriptionsToScan) {
        if (-not (Set-SubscriptionContext -Subscription $subscription)) {
            continue
        }
        
        Write-ColorOutput -Message "[*] Retrieving VMs..." -Color "Yellow"
        
        try {
            $vms = @()
            if ($ResourceGroup) {
                $vms = @(Get-AzVM -ResourceGroupName $ResourceGroup -Status -ErrorAction Stop)
                Write-ColorOutput -Message "[+] Retrieved $($vms.Count) VM(s) from resource group: $ResourceGroup" -Color "Green"
            } else {
                $vms = @(Get-AzVM -Status -ErrorAction Stop)
                Write-ColorOutput -Message "[+] Retrieved $($vms.Count) VM(s) across all resource groups" -Color "Green"
            }
        } catch {
            $errorMessage = $_.Exception.Message
            if ($errorMessage -like "*AuthorizationFailed*") {
                Write-ColorOutput -Message "[!] Authorization failed for subscription: $($subscription.Name)" -Color "Red"
                Write-ColorOutput -Message "[*] Skipping to next subscription...`n" -Color "Yellow"
            } else {
                Write-ColorOutput -Message "[!] Error retrieving VMs: $errorMessage" -Color "Red"
            }
            continue
        }
        
        # Filter by power state
        $filteredVMs = switch ($VMFilter) {
            "running" {
                $vms | Where-Object { $_.PowerState -eq "VM running" }
            }
            "stopped" {
                $vms | Where-Object { $_.PowerState -ne "VM running" }
            }
            default {
                $vms
            }
        }
        
        # Filter Windows VMs only (BitLocker is Windows-specific)
        $windowsVMsList = $filteredVMs | Where-Object { 
            $_.StorageProfile.OsDisk.OsType -eq "Windows" 
        }
        
        if ($windowsVMsList.Count -eq 0) {
            Write-ColorOutput -Message "[*] No Windows VMs found matching filter criteria in this subscription`n" -Color "Yellow"
            continue
        }
        
        $totalVMs += $windowsVMsList.Count
        $windowsVMs += $windowsVMsList.Count
        
        Write-ColorOutput -Message "`n[*] Windows VMs Found: $($windowsVMsList.Count)" -Color "Cyan"
        Write-ColorOutput -Message "[*] VM Filter: $VMFilter" -Color "Cyan"
        Write-ColorOutput -Message "[*] --------------------------------------------------`n" -Color "Cyan"
        
        foreach ($vm in $windowsVMsList) {
            $vmName = $vm.Name
            $vmRG = $vm.ResourceGroupName
            $vmLocation = $vm.Location
            $vmPowerState = $vm.PowerState
            $vmSize = $vm.HardwareProfile.VmSize
            
            Write-ColorOutput -Message "[*] Querying VM: $vmName ($vmPowerState)" -Color "Yellow"
            
            # Skip if VM is not running
            if ($vmPowerState -ne "VM running") {
                Write-ColorOutput -Message "    [!] VM is not running - skipping BitLocker query" -Color "DarkGray"
                Write-ColorOutput -Message "    [*] RG: $vmRG | Location: $vmLocation`n" -Color "DarkGray"
                continue
            }
            
            $queriedVMs++
            
            # PowerShell script to query BitLocker status
            $bitlockerScript = @'
# Query BitLocker status for all volumes
try {
    $volumes = Get-BitLockerVolume -ErrorAction Stop
    $results = @()
    
    foreach ($vol in $volumes) {
        $result = [PSCustomObject]@{
            MountPoint = $vol.MountPoint
            VolumeStatus = $vol.VolumeStatus
            EncryptionPercentage = $vol.EncryptionPercentage
            EncryptionMethod = if ($vol.EncryptionMethod) { $vol.EncryptionMethod.ToString() } else { "None" }
            ProtectionStatus = $vol.ProtectionStatus
            KeyProtector = if ($vol.KeyProtector.Count -gt 0) { 
                ($vol.KeyProtector | ForEach-Object { $_.KeyProtectorType }) -join ", " 
            } else { 
                "None" 
            }
            CapacityGB = [Math]::Round($vol.CapacityGB, 2)
            LockStatus = $vol.LockStatus
        }
        $results += $result
    }
    
    # Return as JSON
    $results | ConvertTo-Json -Compress
    
} catch {
    Write-Output "ERROR: $($_.Exception.Message)"
}
'@
            
            # Execute Run Command
            try {
                Write-ColorOutput -Message "    [*] Executing BitLocker query via VM Run Command..." -Color "Gray"
                
                $runResult = Invoke-AzVMRunCommand `
                    -ResourceGroupName $vmRG `
                    -VMName $vmName `
                    -CommandId 'RunPowerShellScript' `
                    -ScriptString $bitlockerScript `
                    -ErrorAction Stop
                
                $output = $runResult.Value[0].Message
                
                # Check for errors
                if ($output -like "ERROR:*") {
                    Write-ColorOutput -Message "    [!] Failed to query BitLocker: $($output -replace 'ERROR: ', '')" -Color "Red"
                    $failedQueries++
                    Write-ColorOutput -Message "    [*] This may indicate BitLocker is not available or the VM agent is not responding`n" -Color "Yellow"
                    continue
                }
                
                # Parse JSON output
                $volumes = $output | ConvertFrom-Json
                
                if (-not $volumes) {
                    Write-ColorOutput -Message "    [!] No volumes found or failed to parse output" -Color "Red"
                    $failedQueries++
                    continue
                }
                
                $successfulQueries++
                
                # NetExec-style output header
                Write-Host "    " -NoNewline
                Write-Host "AZR".PadRight(8) -ForegroundColor "Magenta" -NoNewline
                Write-Host $vmName.Substring(0, [Math]::Min(30, $vmName.Length)).PadRight(32) -NoNewline
                Write-Host "443".PadRight(7) -NoNewline
                Write-Host "Windows".PadRight(12) -NoNewline
                Write-Host "[*] " -ForegroundColor "Cyan" -NoNewline
                Write-Host "BitLocker Status" -ForegroundColor "White"
                
                # Display volume information
                foreach ($vol in $volumes) {
                    $totalVolumes++
                    $mountPoint = $vol.MountPoint
                    $volumeStatus = $vol.VolumeStatus
                    $encryptionPct = $vol.EncryptionPercentage
                    $encryptionMethod = $vol.EncryptionMethod
                    $protectionStatus = $vol.ProtectionStatus
                    $keyProtector = $vol.KeyProtector
                    $capacityGB = $vol.CapacityGB
                    $lockStatus = $vol.LockStatus
                    
                    # Determine if volume is encrypted
                    $isEncrypted = $volumeStatus -eq "FullyEncrypted" -or $encryptionPct -eq 100
                    $isProtected = $protectionStatus -eq "On"
                    
                    if ($isEncrypted) {
                        $encryptedVolumes++
                    } else {
                        $unencryptedVolumes++
                    }
                    
                    # Color coding based on encryption status
                    $statusColor = if ($isEncrypted -and $isProtected) { 
                        "Green" 
                    } elseif ($isEncrypted -and -not $isProtected) { 
                        "Yellow" 
                    } else { 
                        "Red" 
                    }
                    
                    # Display volume details (NetExec style)
                    Write-Host "        " -NoNewline
                    Write-Host "[$mountPoint]".PadRight(10) -NoNewline -ForegroundColor "Cyan"
                    Write-Host "Status: " -NoNewline
                    Write-Host $volumeStatus.PadRight(20) -NoNewline -ForegroundColor $statusColor
                    Write-Host "Encryption: " -NoNewline
                    Write-Host "$encryptionPct%".PadRight(8) -NoNewline -ForegroundColor $statusColor
                    Write-Host "Protection: " -NoNewline
                    Write-Host $protectionStatus -ForegroundColor $statusColor
                    
                    if ($isEncrypted) {
                        Write-Host "        " -NoNewline
                        Write-Host "    Method: $encryptionMethod | " -NoNewline -ForegroundColor "Gray"
                        Write-Host "Key Protector: $keyProtector | " -NoNewline -ForegroundColor "Gray"
                        Write-Host "Capacity: $($capacityGB)GB" -ForegroundColor "Gray"
                    }
                    
                    # Risk assessment
                    $riskLevel = "LOW"
                    $securityIssues = @()
                    
                    if (-not $isEncrypted) {
                        $riskLevel = "HIGH"
                        $securityIssues += "Volume not encrypted"
                    } elseif (-not $isProtected) {
                        $riskLevel = "MEDIUM"
                        $securityIssues += "BitLocker protection disabled"
                    }
                    
                    if ($lockStatus -eq "Unlocked" -and -not $isEncrypted) {
                        $securityIssues += "Unencrypted and unlocked"
                    }
                    
                    if ($securityIssues.Count -gt 0) {
                        $riskColor = switch ($riskLevel) {
                            "HIGH" { "Red" }
                            "MEDIUM" { "Yellow" }
                            default { "Green" }
                        }
                        Write-Host "        " -NoNewline
                        Write-Host "    [RISK: $riskLevel] " -NoNewline -ForegroundColor $riskColor
                        Write-Host "$($securityIssues -join ', ')" -ForegroundColor "Gray"
                    }
                    
                    # Build export object
                    $exportData += [PSCustomObject]@{
                        Subscription = $subscription.Name
                        SubscriptionId = $subscription.Id
                        ResourceGroup = $vmRG
                        VMName = $vmName
                        Location = $vmLocation
                        VMSize = $vmSize
                        PowerState = $vmPowerState
                        MountPoint = $mountPoint
                        VolumeStatus = $volumeStatus
                        EncryptionPercentage = $encryptionPct
                        EncryptionMethod = $encryptionMethod
                        ProtectionStatus = $protectionStatus
                        KeyProtector = $keyProtector
                        CapacityGB = $capacityGB
                        LockStatus = $lockStatus
                        IsEncrypted = $isEncrypted
                        IsProtected = $isProtected
                        RiskLevel = $riskLevel
                        SecurityIssues = $securityIssues -join '; '
                    }
                }
                
                Write-Host ""
                
            } catch {
                $failedQueries++
                Write-ColorOutput -Message "    [!] Failed to execute Run Command: $($_.Exception.Message)" -Color "Red"
                Write-ColorOutput -Message "    [*] Ensure VM has Azure VM Agent installed and you have proper permissions`n" -Color "Yellow"
            }
        }
    }
    
    # Summary statistics
    Write-ColorOutput -Message "`n[*] ========================================" -Color "Cyan"
    Write-ColorOutput -Message "[*] BITLOCKER ENUMERATION SUMMARY" -Color "Cyan"
    Write-ColorOutput -Message "[*] ========================================`n" -Color "Cyan"
    
    # Intune summary
    if ($intuneDevicesFound) {
        Write-ColorOutput -Message "[*] INTUNE-MANAGED DEVICES:" -Color "Yellow"
        Write-ColorOutput -Message "    Total Windows Devices: $($intuneEncrypted + $intuneNotEncrypted)" -Color "White"
        Write-ColorOutput -Message "    BitLocker Enabled: $intuneEncrypted" -Color "Green"
        Write-ColorOutput -Message "    NOT Encrypted: $intuneNotEncrypted" -Color $(if ($intuneNotEncrypted -gt 0) { "Red" } else { "Green" })
        if ($notEncryptedDevices.Count -gt 0) {
            Write-ColorOutput -Message "    Devices needing BitLocker:" -Color "Red"
            foreach ($deviceName in $notEncryptedDevices) {
                Write-ColorOutput -Message "        → $deviceName" -Color "Red"
            }
        }
        Write-ColorOutput -Message "" -Color "White"
    }
    
    # Azure VM summary
    Write-ColorOutput -Message "[*] AZURE VMs:" -Color "Yellow"
    Write-ColorOutput -Message "    Total Windows VMs: $totalVMs" -Color "White"
    Write-ColorOutput -Message "    VMs Queried: $queriedVMs" -Color "White"
    Write-ColorOutput -Message "    Successful Queries: $successfulQueries" -Color "Green"
    Write-ColorOutput -Message "    Failed Queries: $failedQueries" -Color $(if ($failedQueries -gt 0) { "Red" } else { "Green" })
    Write-ColorOutput -Message "    Total Volumes Found: $totalVolumes" -Color "White"
    Write-ColorOutput -Message "    Encrypted Volumes: $encryptedVolumes" -Color "Green"
    Write-ColorOutput -Message "    Unencrypted Volumes: $unencryptedVolumes" -Color $(if ($unencryptedVolumes -gt 0) { "Red" } else { "Green" })
    
    if ($totalVolumes -gt 0) {
        $encryptionRate = [Math]::Round(($encryptedVolumes / $totalVolumes) * 100, 2)
        Write-ColorOutput -Message "[*] Encryption Rate: $encryptionRate%" -Color $(if ($encryptionRate -eq 100) { "Green" } elseif ($encryptionRate -ge 80) { "Yellow" } else { "Red" })
    }
    
    # Export results if requested
    $allExportData = @()
    if ($intuneExportData.Count -gt 0) {
        $allExportData += $intuneExportData
    }
    if ($exportData.Count -gt 0) {
        $allExportData += $exportData
    }
    
    if ($ExportPath -and $allExportData.Count -gt 0) {
        $stats = [ordered]@{
            "Intune Devices - Encrypted" = $intuneEncrypted
            "Intune Devices - NOT Encrypted" = $intuneNotEncrypted
            "Azure VMs - Total" = $totalVMs
            "Azure VMs - Queried" = $queriedVMs
            "Azure VMs - Encrypted Volumes" = $encryptedVolumes
            "Azure VMs - Unencrypted Volumes (HIGH RISK)" = $unencryptedVolumes
        }
        Export-EnumerationResults -Data $allExportData -ExportPath $ExportPath -Title "BitLocker Enumeration (Intune + Azure VMs)" -Statistics $stats -CommandName "bitlocker-enum" -Description "Azure equivalent of NetExec -M bitlocker. Enumerates BitLocker encryption status on Intune-managed devices and Azure VMs."
    }
    
    # Security recommendations
    if ($unencryptedVolumes -gt 0 -or $intuneNotEncrypted -gt 0) {
        Write-ColorOutput -Message "`n[*] SECURITY RECOMMENDATIONS:" -Color "Cyan"
        if ($intuneNotEncrypted -gt 0) {
            Write-ColorOutput -Message "    INTUNE DEVICES:" -Color "Yellow"
            Write-ColorOutput -Message "    - Enable BitLocker on $intuneNotEncrypted unencrypted device(s) (HIGH PRIORITY)" -Color "Cyan"
            Write-ColorOutput -Message "    - Deploy BitLocker policy via Intune Endpoint Security" -Color "Cyan"
            Write-ColorOutput -Message "    - Store recovery keys in Azure AD (automatic with Intune)" -Color "Cyan"
            Write-ColorOutput -Message "    - Enable silent encryption for devices without TPM" -Color "Cyan"
        }
        if ($unencryptedVolumes -gt 0) {
            Write-ColorOutput -Message "    AZURE VMs:" -Color "Yellow"
            Write-ColorOutput -Message "    - Enable BitLocker on all unencrypted volumes (HIGH PRIORITY)" -Color "Cyan"
            Write-ColorOutput -Message "    - Use strong encryption methods (XTS-AES 256)" -Color "Cyan"
            Write-ColorOutput -Message "    - Store recovery keys in Azure Key Vault" -Color "Cyan"
            Write-ColorOutput -Message "    - Enable automatic BitLocker encryption via Azure Policy" -Color "Cyan"
            Write-ColorOutput -Message "    - Consider using Azure Disk Encryption (ADE) for VM disks" -Color "Cyan"
        }
        Write-ColorOutput -Message "    GENERAL:" -Color "Yellow"
        Write-ColorOutput -Message "    - Implement conditional access policies for encrypted devices only" -Color "Cyan"
    }
    
    # NetExec comparison help
    Write-ColorOutput -Message "`n[*] NETEXEC COMPARISON:" -Color "Yellow"
    Write-ColorOutput -Message "    NetExec: nxc smb 192.168.1.0/24 -u username -p password -M bitlocker" -Color "Gray"
    Write-ColorOutput -Message "    AZexec:  .\azx.ps1 bitlocker-enum" -Color "Gray"
    Write-ColorOutput -Message "`n    NetExec queries BitLocker status via SMB/WMI on remote Windows hosts" -Color "Gray"
    Write-ColorOutput -Message "    AZexec queries BitLocker status via Azure VM Run Command on Azure VMs" -Color "Gray"
    Write-ColorOutput -Message "`n[*] Additional Info:" -Color "Yellow"
    Write-ColorOutput -Message "    - BitLocker enumeration requires VMs to be in 'running' state" -Color "Gray"
    Write-ColorOutput -Message "    - Requires 'Virtual Machine Contributor' or 'VM Command Executor' role" -Color "Gray"
    Write-ColorOutput -Message "    - All queries are logged in Azure Activity Logs" -Color "Gray"
    
    return $exportData
}