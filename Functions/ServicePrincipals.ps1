# AZexec - Service Principal Discovery Functions
# These functions are loaded into the main script scope via dot-sourcing
function Format-ServicePrincipalDiscoveryOutput {
    param(
        [PSCustomObject]$ServicePrincipal,
        [array]$AppRoles,
        [array]$OAuth2Permissions,
        [array]$Owners,
        [array]$HighRiskPermissions = @()
    )
    
    # Service Principal display name
    $displayName = if ($ServicePrincipal.DisplayName) { $ServicePrincipal.DisplayName } else { "UNKNOWN" }
    
    # Truncate long names for column display
    $maxNameLength = 35
    $displayNameShort = if ($displayName.Length -gt $maxNameLength) {
        $displayName.Substring(0, $maxNameLength - 3) + "..."
    } else {
        $displayName
    }
    
    # Use first 15 chars of SPN ID for alignment
    $spnIdShort = if ($ServicePrincipal.Id) { 
        $ServicePrincipal.Id.Substring(0, [Math]::Min(15, $ServicePrincipal.Id.Length))
    } else { 
        "UNKNOWN-ID" 
    }
    
    # Service Principal Type
    $spnType = if ($ServicePrincipal.ServicePrincipalType) { $ServicePrincipal.ServicePrincipalType } else { "Application" }
    
    # App ID
    $appId = if ($ServicePrincipal.AppId) { $ServicePrincipal.AppId } else { "N/A" }
    
    # Account status
    $accountEnabled = if ($ServicePrincipal.AccountEnabled) { "Enabled" } else { "Disabled" }
    
    # Count credentials
    $passwordCreds = if ($ServicePrincipal.PasswordCredentials) { $ServicePrincipal.PasswordCredentials.Count } else { 0 }
    $certCreds = if ($ServicePrincipal.KeyCredentials) { $ServicePrincipal.KeyCredentials.Count } else { 0 }
    
    # Count permissions
    $appRoleCount = if ($AppRoles) { $AppRoles.Count } else { 0 }
    $oauth2PermCount = if ($OAuth2Permissions) { $OAuth2Permissions.Count } else { 0 }
    $ownerCount = if ($Owners) { $Owners.Count } else { 0 }
    
    # Check if this SPN has high-risk permissions
    $hasHighRiskPermissions = $false
    if ($HighRiskPermissions.Count -gt 0) {
        # Check OAuth2 permissions for high-risk permissions
        foreach ($perm in $OAuth2Permissions) {
            if ($perm.Scope) {
                $grantedScopes = $perm.Scope -split ' '
                $hasHighRisk = $grantedScopes | Where-Object { $_ -in $HighRiskPermissions }
                if ($hasHighRisk) {
                    $hasHighRiskPermissions = $true
                    break
                }
            }
        }
        
        # Check App Roles for high-risk permissions
        if (-not $hasHighRiskPermissions) {
            foreach ($role in $AppRoles) {
                if ($role.Value -in $HighRiskPermissions) {
                    $hasHighRiskPermissions = $true
                    break
                }
            }
        }
    }
    
    # Build main output line
    $output = "AZR".PadRight(12) + 
              $spnIdShort.PadRight(17) + 
              "443".PadRight(7) + 
              $displayNameShort.PadRight(38) + 
              "[*] (appId:$appId) (type:$spnType) (status:$accountEnabled) (pwdCreds:$passwordCreds) (certCreds:$certCreds) (appRoles:$appRoleCount) (delegated:$oauth2PermCount) (owners:$ownerCount)"
    
    # Color based on status and security posture
    $color = "Cyan"
    if ($hasHighRiskPermissions) {
        $color = "Red"  # High-risk permissions in red - highest priority
    } elseif ($accountEnabled -eq "Disabled") {
        $color = "DarkGray"  # Disabled SPNs in gray
    } elseif ($passwordCreds -gt 0 -and $certCreds -eq 0) {
        $color = "Yellow"  # Password-only credentials in yellow (security risk)
    } elseif ($appRoleCount -gt 0 -or $oauth2PermCount -gt 0) {
        $color = "Green"  # SPNs with permissions in green
    }
    
    Write-ColorOutput -Message $output -Color $color
    
    # Display app roles (application permissions)
    if ($AppRoles -and $AppRoles.Count -gt 0) {
        Write-ColorOutput -Message "    [+] Application Permissions (App Roles):" -Color "Cyan"
        foreach ($role in $AppRoles) {
            $roleName = if ($role.Value) { $role.Value } else { "Unknown" }
            $roleId = if ($role.Id) { $role.Id } else { "N/A" }
            $resource = if ($role.ResourceDisplayName) { $role.ResourceDisplayName } else { "Unknown Resource" }
            
            # Check if this is a high-risk permission
            $permColor = "DarkCyan"
            if ($HighRiskPermissions.Count -gt 0 -and $roleName -in $HighRiskPermissions) {
                $permColor = "Red"
            }
            
            Write-ColorOutput -Message "        [-] $resource : $roleName (ID: $roleId)" -Color $permColor
        }
    }
    
    # Display OAuth2 permissions (delegated permissions)
    if ($OAuth2Permissions -and $OAuth2Permissions.Count -gt 0) {
        Write-ColorOutput -Message "    [+] Delegated Permissions (OAuth2):" -Color "Cyan"
        foreach ($perm in $OAuth2Permissions) {
            $scope = if ($perm.Scope) { $perm.Scope } else { "Unknown" }
            $consentType = if ($perm.ConsentType) { $perm.ConsentType } else { "Unknown" }
            $resource = if ($perm.ResourceDisplayName) { $perm.ResourceDisplayName } else { "Unknown Resource" }
            
            # Check if any of the scopes are high-risk
            $permColor = "DarkCyan"
            if ($HighRiskPermissions.Count -gt 0 -and $scope) {
                $grantedScopes = $scope -split ' '
                $hasHighRisk = $grantedScopes | Where-Object { $_ -in $HighRiskPermissions }
                if ($hasHighRisk) {
                    $permColor = "Red"
                }
            }
            
            Write-ColorOutput -Message "        [-] $resource : $scope (ConsentType: $consentType)" -Color $permColor
        }
    }
    
    # Display owners
    if ($Owners -and $Owners.Count -gt 0) {
        Write-ColorOutput -Message "    [+] Owners:" -Color "Cyan"
        foreach ($owner in $Owners) {
            $ownerName = if ($owner.DisplayName) { $owner.DisplayName } else { "Unknown" }
            $ownerType = if ($owner.'@odata.type') { 
                $owner.'@odata.type' -replace '#microsoft.graph.', '' 
            } else { 
                "Unknown" 
            }
            $ownerUPN = if ($owner.UserPrincipalName) { " ($($owner.UserPrincipalName))" } else { "" }
            Write-ColorOutput -Message "        [-] $ownerName [$ownerType]$ownerUPN" -Color "DarkCyan"
        }
    }
    
    Write-ColorOutput -Message "" -Color "White"
}

# Main Service Principal Discovery function
function Invoke-ServicePrincipalDiscovery {
    param(
        [string]$ExportPath
    )
    
    Write-ColorOutput -Message "`n[*] AZX - Azure/Entra Service Principal Discovery" -Color "Yellow"
    Write-ColorOutput -Message "[*] Command: Service Principal Permission and Assignment Enumeration" -Color "Yellow"
    Write-ColorOutput -Message "[*] Discovers service principals with their permissions, roles, and ownership`n" -Color "Yellow"
    
    # Get context to display current user info
    $context = Get-MgContext
    if ($context) {
        Write-ColorOutput -Message "[*] Authenticated as: $($context.Account)" -Color "Cyan"
        Write-ColorOutput -Message "[*] Tenant: $($context.TenantId)`n" -Color "Cyan"
    }
    
    # Prepare export data
    $exportData = @()
    
    # ===== PHASE 1: ENUMERATE SERVICE PRINCIPALS =====
    Write-ColorOutput -Message "[*] ========================================" -Color "Cyan"
    Write-ColorOutput -Message "[*] PHASE 1: Service Principal Enumeration" -Color "Cyan"
    Write-ColorOutput -Message "[*] ========================================`n" -Color "Cyan"
    
    Write-ColorOutput -Message "[*] Retrieving service principals from Azure/Entra ID..." -Color "Yellow"
    Write-ColorOutput -Message "[*] This may take a while for large organizations...`n" -Color "Yellow"
    
    try {
        $allSPNs = Get-MgServicePrincipal -All -Property "id,displayName,appId,servicePrincipalType,passwordCredentials,keyCredentials,signInAudience,tags,accountEnabled,createdDateTime,appRoles,oauth2PermissionScopes" -ErrorAction Stop
        Write-ColorOutput -Message "[+] Retrieved $($allSPNs.Count) service principals`n" -Color "Green"
    } catch {
        Write-ColorOutput -Message "[!] Failed to retrieve service principals: $_" -Color "Red"
        Write-ColorOutput -Message "[!] Ensure you have Application.Read.All or Directory.Read.All permissions" -Color "Red"
        Write-ColorOutput -Message "[*] Guest users may have restricted access to service principal enumeration" -Color "Yellow"
        return
    }
    
    if ($allSPNs.Count -eq 0) {
        Write-ColorOutput -Message "[!] No service principals found or insufficient permissions`n" -Color "Red"
        return
    }
    
    # ===== PHASE 2: ENUMERATE PERMISSIONS =====
    Write-ColorOutput -Message "[*] ========================================" -Color "Cyan"
    Write-ColorOutput -Message "[*] PHASE 2: Permission Discovery" -Color "Cyan"
    Write-ColorOutput -Message "[*] ========================================`n" -Color "Cyan"
    
    Write-ColorOutput -Message "[*] Retrieving app role assignments (application permissions)..." -Color "Yellow"
    
    $appRoleAssignments = @{}
    try {
        # Get all app role assignments
        $allAppRoleAssignments = Invoke-MgGraphRequest -Uri "https://graph.microsoft.com/v1.0/servicePrincipals?`$expand=appRoleAssignedTo" -Method GET -ErrorAction Stop
        
        foreach ($spn in $allAppRoleAssignments.value) {
            if ($spn.appRoleAssignedTo -and $spn.appRoleAssignedTo.Count -gt 0) {
                $appRoleAssignments[$spn.id] = $spn.appRoleAssignedTo
            }
        }
        
        Write-ColorOutput -Message "[+] Retrieved app role assignments for $($appRoleAssignments.Count) service principals`n" -Color "Green"
    } catch {
        Write-ColorOutput -Message "[!] Failed to retrieve app role assignments: $_" -Color "Yellow"
        Write-ColorOutput -Message "[*] Continuing with limited permission data...`n" -Color "Yellow"
    }
    
    Write-ColorOutput -Message "[*] Retrieving OAuth2 permission grants (delegated permissions)..." -Color "Yellow"
    
    $oauth2Grants = @{}
    try {
        $allOAuth2Grants = Invoke-MgGraphRequest -Uri "https://graph.microsoft.com/v1.0/oauth2PermissionGrants" -Method GET -ErrorAction Stop
        
        foreach ($grant in $allOAuth2Grants.value) {
            $clientId = $grant.clientId
            if (-not $oauth2Grants.ContainsKey($clientId)) {
                $oauth2Grants[$clientId] = @()
            }
            $oauth2Grants[$clientId] += $grant
        }
        
        Write-ColorOutput -Message "[+] Retrieved OAuth2 permission grants for $($oauth2Grants.Count) service principals`n" -Color "Green"
    } catch {
        Write-ColorOutput -Message "[!] Failed to retrieve OAuth2 permission grants: $_" -Color "Yellow"
        Write-ColorOutput -Message "[*] Continuing with limited permission data...`n" -Color "Yellow"
    }
    
    # ===== PHASE 3: ENUMERATE OWNERS =====
    Write-ColorOutput -Message "[*] ========================================" -Color "Cyan"
    Write-ColorOutput -Message "[*] PHASE 3: Ownership Discovery" -Color "Cyan"
    Write-ColorOutput -Message "[*] ========================================`n" -Color "Cyan"
    
    Write-ColorOutput -Message "[*] Retrieving service principal owners..." -Color "Yellow"
    Write-ColorOutput -Message "[*] This may take a while...`n" -Color "Yellow"
    
    $ownershipData = @{}
    $ownersRetrieved = 0
    
    foreach ($spn in $allSPNs) {
        try {
            $owners = Get-MgServicePrincipalOwner -ServicePrincipalId $spn.Id -ErrorAction SilentlyContinue
            if ($owners -and $owners.Count -gt 0) {
                $ownershipData[$spn.Id] = $owners
                $ownersRetrieved++
            }
        } catch {
            # Silently continue if we can't get owners for this SPN
        }
    }
    
    Write-ColorOutput -Message "[+] Retrieved ownership data for $ownersRetrieved service principals`n" -Color "Green"
    
    # Define high-risk permissions for highlighting
    $highRiskPermissions = @(
        "RoleManagement.ReadWrite.Directory",
        "AppRoleAssignment.ReadWrite.All",
        "Application.ReadWrite.All",
        "Directory.ReadWrite.All"
    )
    
    # ===== PHASE 4: DISPLAY RESULTS =====
    Write-ColorOutput -Message "[*] ========================================" -Color "Cyan"
    Write-ColorOutput -Message "[*] PHASE 4: Service Principal Details" -Color "Cyan"
    Write-ColorOutput -Message "[*] ========================================`n" -Color "Cyan"
    
    Write-ColorOutput -Message "[*] Displaying $($allSPNs.Count) service principals with permissions`n" -Color "Green"
    
    # Enumerate service principals with their permissions
    foreach ($spn in $allSPNs) {
        # Get app roles for this SPN
        $spnAppRoles = @()
        if ($appRoleAssignments.ContainsKey($spn.Id)) {
            foreach ($assignment in $appRoleAssignments[$spn.Id]) {
                # Try to resolve the app role name
                $resourceSPN = $allSPNs | Where-Object { $_.Id -eq $assignment.resourceId } | Select-Object -First 1
                $appRoleName = "Unknown"
                if ($resourceSPN -and $resourceSPN.AppRoles) {
                    $matchingRole = $resourceSPN.AppRoles | Where-Object { $_.Id -eq $assignment.appRoleId } | Select-Object -First 1
                    if ($matchingRole) {
                        $appRoleName = $matchingRole.Value
                    }
                }
                
                $spnAppRoles += [PSCustomObject]@{
                    Id = $assignment.appRoleId
                    Value = $appRoleName
                    ResourceDisplayName = $assignment.resourceDisplayName
                }
            }
        }
        
        # Get OAuth2 permissions for this SPN
        $spnOAuth2Perms = @()
        if ($oauth2Grants.ContainsKey($spn.Id)) {
            foreach ($grant in $oauth2Grants[$spn.Id]) {
                # Try to resolve resource display name
                $resourceSPN = $allSPNs | Where-Object { $_.Id -eq $grant.resourceId } | Select-Object -First 1
                $resourceDisplayName = if ($resourceSPN) { $resourceSPN.DisplayName } else { "Unknown" }
                
                $spnOAuth2Perms += [PSCustomObject]@{
                    Scope = $grant.scope
                    ConsentType = $grant.consentType
                    ResourceDisplayName = $resourceDisplayName
                    ResourceId = $grant.resourceId
                }
            }
        }
        
        # Get owners for this SPN
        $spnOwners = @()
        if ($ownershipData.ContainsKey($spn.Id)) {
            $spnOwners = $ownershipData[$spn.Id]
        }
        
        # Format and display output
        Format-ServicePrincipalDiscoveryOutput -ServicePrincipal $spn -AppRoles $spnAppRoles -OAuth2Permissions $spnOAuth2Perms -Owners $spnOwners -HighRiskPermissions $highRiskPermissions
        
        # Collect for export
        if ($ExportPath) {
            $exportData += [PSCustomObject]@{
                ObjectId = $spn.Id
                AppId = $spn.AppId
                DisplayName = $spn.DisplayName
                ServicePrincipalType = $spn.ServicePrincipalType
                AccountEnabled = $spn.AccountEnabled
                SignInAudience = $spn.SignInAudience
                PasswordCredentials = $spn.PasswordCredentials.Count
                KeyCredentials = $spn.KeyCredentials.Count
                Tags = ($spn.Tags -join ";")
                CreatedDateTime = $spn.CreatedDateTime
                AppRoleCount = $spnAppRoles.Count
                AppRoles = ($spnAppRoles | ForEach-Object { "$($_.ResourceDisplayName):$($_.Value)" }) -join "; "
                OAuth2PermissionCount = $spnOAuth2Perms.Count
                OAuth2Permissions = ($spnOAuth2Perms | ForEach-Object { "$($_.ResourceDisplayName):$($_.Scope)" }) -join "; "
                OwnerCount = $spnOwners.Count
                Owners = ($spnOwners | ForEach-Object { $_.DisplayName }) -join "; "
            }
        }
    }
    
    # Calculate summary statistics
    $spnsWithPasswordCreds = ($allSPNs | Where-Object { $_.PasswordCredentials.Count -gt 0 }).Count
    $spnsWithCertCreds = ($allSPNs | Where-Object { $_.KeyCredentials.Count -gt 0 }).Count
    $enabledSPNs = ($allSPNs | Where-Object { $_.AccountEnabled -eq $true }).Count
    $managedIdentities = ($allSPNs | Where-Object { $_.ServicePrincipalType -eq "ManagedIdentity" }).Count
    $passwordOnlySPNs = ($allSPNs | Where-Object { $_.PasswordCredentials.Count -gt 0 -and $_.KeyCredentials.Count -eq 0 }).Count
    
    # Export if requested
    if ($ExportPath -and $exportData.Count -gt 0) {
        try {
            $extension = [System.IO.Path]::GetExtension($ExportPath).ToLower()
            
            if ($extension -eq ".csv") {
                $exportData | Export-Csv -Path $ExportPath -NoTypeInformation -Force
                Write-ColorOutput -Message "[+] Results exported to: $ExportPath" -Color "Green"
            } elseif ($extension -eq ".json") {
                $exportData | ConvertTo-Json -Depth 5 | Out-File -FilePath $ExportPath -Force
                Write-ColorOutput -Message "[+] Results exported to: $ExportPath" -Color "Green"
            } elseif ($extension -eq ".html") {
                $stats = [ordered]@{
                    "Total Service Principals" = $allSPNs.Count
                    "Enabled Service Principals" = $enabledSPNs
                    "Password-Only SPNs (HIGH RISK)" = $passwordOnlySPNs
                    "SPNs with Password Credentials" = $spnsWithPasswordCreds
                    "SPNs with Certificate Credentials" = $spnsWithCertCreds
                    "Managed Identities" = $managedIdentities
                    "SPNs with App Role Assignments" = $appRoleAssignments.Count
                    "SPNs with OAuth2 Permission Grants" = $oauth2Grants.Count
                    "SPNs with Owners" = $ownersRetrieved
                }
                
                $description = "Service principal discovery with detailed permissions, role assignments, and ownership information. Identifies high-risk permissions and password-only credentials."
                
                $success = Export-HtmlReport -Data $exportData -OutputPath $ExportPath -Title "Service Principal Discovery Report" -Statistics $stats -CommandName "sp-discovery" -Description $description
                
                if ($success) {
                    Write-ColorOutput -Message "[+] HTML report exported to: $ExportPath" -Color "Green"
                }
            } else {
                # Default to CSV
                $exportData | Export-Csv -Path $ExportPath -NoTypeInformation -Force
                Write-ColorOutput -Message "[+] Results exported to: $ExportPath" -Color "Green"
            }
        } catch {
            Write-ColorOutput -Message "[!] Failed to export results: $_" -Color "Red"
        }
    }
    
    # Display summary statistics
    Write-ColorOutput -Message "`n[*] ========================================" -Color "Cyan"
    Write-ColorOutput -Message "[*] Summary Statistics" -Color "Cyan"
    Write-ColorOutput -Message "[*] ========================================`n" -Color "Cyan"
    
    Write-ColorOutput -Message "[*] Service Principals:" -Color "Yellow"
    Write-ColorOutput -Message "    Total Service Principals: $($allSPNs.Count)" -Color "Cyan"
    Write-ColorOutput -Message "    Enabled Service Principals: $enabledSPNs" -Color "Cyan"
    Write-ColorOutput -Message "    SPNs with Password Credentials: $spnsWithPasswordCreds" -Color "Cyan"
    Write-ColorOutput -Message "    SPNs with Certificate Credentials: $spnsWithCertCreds" -Color "Cyan"
    Write-ColorOutput -Message "    Managed Identities: $managedIdentities" -Color "Cyan"
    
    Write-ColorOutput -Message "`n[*] Permissions:" -Color "Yellow"
    Write-ColorOutput -Message "    SPNs with App Role Assignments: $($appRoleAssignments.Count)" -Color "Cyan"
    Write-ColorOutput -Message "    SPNs with OAuth2 Permission Grants: $($oauth2Grants.Count)" -Color "Cyan"
    
    Write-ColorOutput -Message "`n[*] Ownership:" -Color "Yellow"
    Write-ColorOutput -Message "    SPNs with Owners: $ownersRetrieved" -Color "Cyan"
    
    # Security findings
    if ($passwordOnlySPNs -gt 0) {
        Write-ColorOutput -Message "`n[!] Security Warnings:" -Color "Yellow"
        Write-ColorOutput -Message "    [!] Found $passwordOnlySPNs service principals with password-only credentials" -Color "Yellow"
        Write-ColorOutput -Message "    [*] These are vulnerable to credential theft (similar to SMB without signing)" -Color "DarkGray"
        Write-ColorOutput -Message "    [*] Recommendation: Use certificate-based authentication instead" -Color "DarkGray"
    }
    
    # Identify high-risk permissions
    $highRiskPermissions = @(
        "RoleManagement.ReadWrite.Directory",
        "AppRoleAssignment.ReadWrite.All",
        "Application.ReadWrite.All",
        "Directory.ReadWrite.All"
    )
    
    $spnsWithHighRiskPerms = 0
    foreach ($spnId in $oauth2Grants.Keys) {
        foreach ($grant in $oauth2Grants[$spnId]) {
            $grantedScopes = $grant.scope -split ' '
            $hasHighRisk = $grantedScopes | Where-Object { $_ -in $highRiskPermissions }
            if ($hasHighRisk) {
                $spnsWithHighRiskPerms++
                break
            }
        }
    }
    
    if ($spnsWithHighRiskPerms -gt 0) {
        Write-ColorOutput -Message "    [!] Found $spnsWithHighRiskPerms service principals with high-risk permissions" -Color "Yellow"
        Write-ColorOutput -Message "    [*] These permissions can modify directory, roles, or applications" -Color "DarkGray"
        Write-ColorOutput -Message "    [*] Review these service principals for potential privilege escalation paths" -Color "DarkGray"
    }
    
    Write-ColorOutput -Message "`n[*] Service Principal discovery complete!" -Color "Green"
}

# Format user profile output like netexec
