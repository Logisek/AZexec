# AZexec - Application Enumeration Functions
# These functions are loaded into the main script scope via dot-sourcing
function Format-ApplicationOutput {
    param(
        [PSCustomObject]$Application,
        [string]$AppType = "Application",
        [array]$HighRiskPermissions = @()
    )
    
    # Application name
    $appName = if ($Application.DisplayName) { $Application.DisplayName } else { "UNKNOWN" }
    
    # Truncate long app names for column display
    $maxNameLength = 35
    $displayName = if ($appName.Length -gt $maxNameLength) {
        $appName.Substring(0, $maxNameLength - 3) + "..."
    } else {
        $appName
    }
    
    # Use app ID as "IP" equivalent (first 15 chars for alignment)
    $appIdShort = if ($Application.AppId) { 
        $Application.AppId.Substring(0, [Math]::Min(15, $Application.AppId.Length))
    } else { 
        "UNKNOWN-ID" 
    }
    
    # Credential status - check for password vs certificate credentials
    $credStatus = "None"
    $credCount = 0
    
    if ($Application.PasswordCredentials -and $Application.PasswordCredentials.Count -gt 0) {
        $credCount += $Application.PasswordCredentials.Count
        if ($Application.KeyCredentials -and $Application.KeyCredentials.Count -gt 0) {
            $credStatus = "Both"
        } else {
            $credStatus = "Password"
        }
    } elseif ($Application.KeyCredentials -and $Application.KeyCredentials.Count -gt 0) {
        $credCount += $Application.KeyCredentials.Count
        $credStatus = "Certificate"
    }
    
    # Sign-in audience
    $audience = if ($Application.SignInAudience) { 
        $Application.SignInAudience 
    } else { 
        "N/A" 
    }
    
    # Public client status (ROPC vulnerable)
    $isPublicClient = if ($Application.IsFallbackPublicClient -eq $true) {
        "True"
    } elseif ($Application.PublicClient -and $Application.PublicClient.RedirectUris.Count -gt 0) {
        "True"
    } else {
        "False"
    }
    
    # Check for high-risk permissions in requiredResourceAccess
    $hasHighRiskPermissions = $false
    if ($HighRiskPermissions.Count -gt 0 -and $Application.RequiredResourceAccess) {
        foreach ($resource in $Application.RequiredResourceAccess) {
            if ($resource.ResourceAppId -eq "00000003-0000-0000-c000-000000000000") {  # Microsoft Graph
                foreach ($access in $resource.ResourceAccess) {
                    # Get permission value/name from a common mapping
                    $permId = $access.Id
                    # Check common high-risk permission IDs
                    $highRiskPermIds = @(
                        "19dbc75e-c2e2-444c-a770-ec69d8559fc7",  # Directory.ReadWrite.All
                        "1bfefb4e-e0b5-418b-a88f-73c46d2cc8e9",  # Application.ReadWrite.All
                        "06b708a9-e830-4db3-a914-8e69da51d44f",  # AppRoleAssignment.ReadWrite.All
                        "9e3f62cf-ca93-4989-b6ce-bf83c28f9fe8"   # RoleManagement.ReadWrite.Directory
                    )
                    if ($permId -in $highRiskPermIds) {
                        $hasHighRiskPermissions = $true
                        break
                    }
                }
            }
            if ($hasHighRiskPermissions) {
                break
            }
        }
    }
    
    $output = "AZR".PadRight(12) + 
              $appIdShort.PadRight(17) + 
              "443".PadRight(7) + 
              $displayName.PadRight(38) + 
              "[*] (name:$appName) (type:$AppType) (creds:$credStatus [$credCount]) (audience:$audience) (publicClient:$isPublicClient)"
    
    # Color based on security posture
    $color = "Cyan"
    if ($hasHighRiskPermissions) {
        $color = "Red"  # High-risk permissions in red (highest priority)
    } elseif ($credStatus -eq "Password") {
        $color = "Yellow"  # Password-only credentials are weaker
    } elseif ($credStatus -eq "None") {
        $color = "DarkGray"  # No credentials
    } elseif ($isPublicClient -eq "True") {
        $color = "Yellow"  # Public client enabled (ROPC vulnerable)
    } else {
        $color = "Green"  # Certificate-based auth
    }
    
    Write-ColorOutput -Message $output -Color $color
}

# Main application enumeration function
function Invoke-ApplicationEnumeration {
    param(
        [string]$ExportPath
    )
    
    Write-ColorOutput -Message "`n[*] AZX - Azure/Entra Application Enumeration" -Color "Yellow"
    Write-ColorOutput -Message "[*] Command: Application and Service Principal Enumeration" -Color "Yellow"
    Write-ColorOutput -Message "[*] Lists registered applications and service principals`n" -Color "Yellow"
    
    # Get context to display current user info
    $context = Get-MgContext
    if ($context) {
        Write-ColorOutput -Message "[*] Authenticated as: $($context.Account)" -Color "Cyan"
        Write-ColorOutput -Message "[*] Tenant: $($context.TenantId)`n" -Color "Cyan"
    }
    
    # Prepare export data
    $exportData = @()
    
    # ===== PHASE 1: ENUMERATE APPLICATIONS =====
    Write-ColorOutput -Message "[*] ========================================" -Color "Cyan"
    Write-ColorOutput -Message "[*] PHASE 1: Application Registrations" -Color "Cyan"
    Write-ColorOutput -Message "[*] ========================================`n" -Color "Cyan"
    
    Write-ColorOutput -Message "[*] Retrieving application registrations from Azure/Entra ID..." -Color "Yellow"
    
    try {
        $allApps = Get-MgApplication -All -Property "id,displayName,appId,signInAudience,passwordCredentials,keyCredentials,isFallbackPublicClient,publicClient,requiredResourceAccess,web,createdDateTime" -ErrorAction Stop
        Write-ColorOutput -Message "[+] Retrieved $($allApps.Count) application registrations`n" -Color "Green"
    } catch {
        Write-ColorOutput -Message "[!] Failed to retrieve applications: $_" -Color "Red"
        Write-ColorOutput -Message "[!] Ensure you have Application.Read.All or Directory.Read.All permissions" -Color "Red"
        Write-ColorOutput -Message "[*] Guest users may have restricted access to application enumeration" -Color "Yellow"
        $allApps = @()
    }
    
    # Define high-risk permission IDs
    $highRiskPermissions = @(
        "19dbc75e-c2e2-444c-a770-ec69d8559fc7",  # Directory.ReadWrite.All
        "1bfefb4e-e0b5-418b-a88f-73c46d2cc8e9",  # Application.ReadWrite.All
        "06b708a9-e830-4db3-a914-8e69da51d44f",  # AppRoleAssignment.ReadWrite.All
        "9e3f62cf-ca93-4989-b6ce-bf83c28f9fe8"   # RoleManagement.ReadWrite.Directory
    )
    
    if ($allApps.Count -gt 0) {
        Write-ColorOutput -Message "[*] Displaying $($allApps.Count) application registrations`n" -Color "Green"
        
        # Enumerate applications
        foreach ($app in $allApps) {
            Format-ApplicationOutput -Application $app -AppType "App" -HighRiskPermissions $highRiskPermissions
            
            # Collect for export
            if ($ExportPath) {
                $exportData += [PSCustomObject]@{
                    Type                  = "Application"
                    ObjectId              = $app.Id
                    AppId                 = $app.AppId
                    DisplayName           = $app.DisplayName
                    SignInAudience        = $app.SignInAudience
                    IsFallbackPublicClient = $app.IsFallbackPublicClient
                    PasswordCredentials   = $app.PasswordCredentials.Count
                    KeyCredentials        = $app.KeyCredentials.Count
                    CreatedDateTime       = $app.CreatedDateTime
                    PublicClientRedirectUris = if ($app.PublicClient) { ($app.PublicClient.RedirectUris -join ";") } else { "" }
                    WebRedirectUris       = if ($app.Web) { ($app.Web.RedirectUris -join ";") } else { "" }
                }
            }
        }
    } else {
        Write-ColorOutput -Message "[!] No applications found or insufficient permissions`n" -Color "Red"
    }
    
    # ===== PHASE 2: ENUMERATE SERVICE PRINCIPALS =====
    Write-ColorOutput -Message "`n[*] ========================================" -Color "Cyan"
    Write-ColorOutput -Message "[*] PHASE 2: Service Principals" -Color "Cyan"
    Write-ColorOutput -Message "[*] ========================================`n" -Color "Cyan"
    
    Write-ColorOutput -Message "[*] Retrieving service principals from Azure/Entra ID..." -Color "Yellow"
    Write-ColorOutput -Message "[*] This may take a while for large organizations...`n" -Color "Yellow"
    
    try {
        $allSPNs = Get-MgServicePrincipal -All -Property "id,displayName,appId,servicePrincipalType,passwordCredentials,keyCredentials,signInAudience,tags,accountEnabled,createdDateTime" -ErrorAction Stop
        Write-ColorOutput -Message "[+] Retrieved $($allSPNs.Count) service principals`n" -Color "Green"
    } catch {
        Write-ColorOutput -Message "[!] Failed to retrieve service principals: $_" -Color "Red"
        Write-ColorOutput -Message "[!] Ensure you have Application.Read.All or Directory.Read.All permissions" -Color "Red"
        Write-ColorOutput -Message "[*] Guest users may have restricted access to service principal enumeration" -Color "Yellow"
        $allSPNs = @()
    }
    
    if ($allSPNs.Count -gt 0) {
        Write-ColorOutput -Message "[*] Displaying $($allSPNs.Count) service principals`n" -Color "Green"
        
        # Enumerate service principals
        foreach ($spn in $allSPNs) {
            Format-ApplicationOutput -Application $spn -AppType "SPN" -HighRiskPermissions $highRiskPermissions
            
            # Collect for export
            if ($ExportPath) {
                $exportData += [PSCustomObject]@{
                    Type                  = "ServicePrincipal"
                    ObjectId              = $spn.Id
                    AppId                 = $spn.AppId
                    DisplayName           = $spn.DisplayName
                    ServicePrincipalType  = $spn.ServicePrincipalType
                    AccountEnabled        = $spn.AccountEnabled
                    SignInAudience        = $spn.SignInAudience
                    PasswordCredentials   = $spn.PasswordCredentials.Count
                    KeyCredentials        = $spn.KeyCredentials.Count
                    Tags                  = ($spn.Tags -join ";")
                    CreatedDateTime       = $spn.CreatedDateTime
                    PublicClientRedirectUris = ""
                    WebRedirectUris       = ""
                }
            }
        }
    } else {
        Write-ColorOutput -Message "[!] No service principals found or insufficient permissions`n" -Color "Red"
    }
    
    # Calculate summary statistics
    $appsWithPasswordCreds = 0
    $appsWithCertCreds = 0
    $publicClientApps = 0
    if ($allApps.Count -gt 0) {
        $appsWithPasswordCreds = ($allApps | Where-Object { $_.PasswordCredentials.Count -gt 0 }).Count
        $appsWithCertCreds = ($allApps | Where-Object { $_.KeyCredentials.Count -gt 0 }).Count
        $publicClientApps = ($allApps | Where-Object { $_.IsFallbackPublicClient -eq $true -or ($_.PublicClient -and $_.PublicClient.RedirectUris.Count -gt 0) }).Count
    }
    
    $spnsWithPasswordCreds = 0
    $spnsWithCertCreds = 0
    $enabledSPNs = 0
    $managedIdentities = 0
    if ($allSPNs.Count -gt 0) {
        $spnsWithPasswordCreds = ($allSPNs | Where-Object { $_.PasswordCredentials.Count -gt 0 }).Count
        $spnsWithCertCreds = ($allSPNs | Where-Object { $_.KeyCredentials.Count -gt 0 }).Count
        $enabledSPNs = ($allSPNs | Where-Object { $_.AccountEnabled -eq $true }).Count
        $managedIdentities = ($allSPNs | Where-Object { $_.ServicePrincipalType -eq "ManagedIdentity" }).Count
    }
    
    # Export if requested
    if ($ExportPath -and $exportData.Count -gt 0) {
        try {
            $extension = [System.IO.Path]::GetExtension($ExportPath).ToLower()
            
            if ($extension -eq ".csv") {
                $exportData | Export-Csv -Path $ExportPath -NoTypeInformation -Force
                Write-ColorOutput -Message "`n[+] Results exported to: $ExportPath" -Color "Green"
            } elseif ($extension -eq ".json") {
                $exportData | ConvertTo-Json -Depth 5 | Out-File -FilePath $ExportPath -Force
                Write-ColorOutput -Message "`n[+] Results exported to: $ExportPath" -Color "Green"
            } elseif ($extension -eq ".html") {
                $stats = [ordered]@{
                    "Total Applications" = $allApps.Count
                    "Total Service Principals" = $allSPNs.Count
                    "Apps with Password Credentials" = $appsWithPasswordCreds
                    "Public Client Apps (ROPC-enabled)" = $publicClientApps
                    "SPNs with Password Credentials" = $spnsWithPasswordCreds
                    "Enabled Service Principals" = $enabledSPNs
                    "Managed Identities" = $managedIdentities
                }
                
                $description = "Application and service principal enumeration including credential types and security posture assessment."
                
                $success = Export-HtmlReport -Data $exportData -OutputPath $ExportPath -Title "Application Enumeration Report" -Statistics $stats -CommandName "apps" -Description $description
                
                if ($success) {
                    Write-ColorOutput -Message "`n[+] HTML report exported to: $ExportPath" -Color "Green"
                }
            } else {
                # Default to CSV
                $exportData | Export-Csv -Path $ExportPath -NoTypeInformation -Force
                Write-ColorOutput -Message "`n[+] Results exported to: $ExportPath" -Color "Green"
            }
        } catch {
            Write-ColorOutput -Message "`n[!] Failed to export results: $_" -Color "Red"
        }
    }
    
    # Display summary statistics
    Write-ColorOutput -Message "`n[*] ========================================" -Color "Cyan"
    Write-ColorOutput -Message "[*] Summary Statistics" -Color "Cyan"
    Write-ColorOutput -Message "[*] ========================================`n" -Color "Cyan"
    
    Write-ColorOutput -Message "[*] Applications:" -Color "Yellow"
    Write-ColorOutput -Message "    Total Registered Apps: $($allApps.Count)" -Color "Cyan"
    
    if ($allApps.Count -gt 0) {
        Write-ColorOutput -Message "    Apps with Password Credentials: $appsWithPasswordCreds" -Color "Cyan"
        Write-ColorOutput -Message "    Apps with Certificate Credentials: $appsWithCertCreds" -Color "Cyan"
        Write-ColorOutput -Message "    Public Client Apps (ROPC-enabled): $publicClientApps" -Color $(if ($publicClientApps -gt 0) { "Yellow" } else { "Cyan" })
    }
    
    Write-ColorOutput -Message "`n[*] Service Principals:" -Color "Yellow"
    Write-ColorOutput -Message "    Total Service Principals: $($allSPNs.Count)" -Color "Cyan"
    
    if ($allSPNs.Count -gt 0) {
        Write-ColorOutput -Message "    SPNs with Password Credentials: $spnsWithPasswordCreds" -Color "Cyan"
        Write-ColorOutput -Message "    SPNs with Certificate Credentials: $spnsWithCertCreds" -Color "Cyan"
        Write-ColorOutput -Message "    Enabled Service Principals: $enabledSPNs" -Color "Cyan"
        Write-ColorOutput -Message "    Managed Identities: $managedIdentities" -Color "Cyan"
    }
    
    # Security findings
    $totalPasswordOnly = 0
    if ($allApps.Count -gt 0) {
        $totalPasswordOnly += ($allApps | Where-Object { $_.PasswordCredentials.Count -gt 0 -and $_.KeyCredentials.Count -eq 0 }).Count
    }
    if ($allSPNs.Count -gt 0) {
        $totalPasswordOnly += ($allSPNs | Where-Object { $_.PasswordCredentials.Count -gt 0 -and $_.KeyCredentials.Count -eq 0 }).Count
    }
    
    if ($totalPasswordOnly -gt 0) {
        Write-ColorOutput -Message "`n[!] Security Warning:" -Color "Yellow"
        Write-ColorOutput -Message "    [!] Found $totalPasswordOnly applications/SPNs with password-only credentials" -Color "Yellow"
        Write-ColorOutput -Message "    [*] These are vulnerable to credential theft (similar to SMB without signing)" -Color "DarkGray"
        Write-ColorOutput -Message "    [*] Recommendation: Use certificate-based authentication instead" -Color "DarkGray"
    }
    
    # Check for high-risk permissions in applications
    $appsWithHighRiskPerms = 0
    $highRiskPermIds = @(
        "19dbc75e-c2e2-444c-a770-ec69d8559fc7",  # Directory.ReadWrite.All
        "1bfefb4e-e0b5-418b-a88f-73c46d2cc8e9",  # Application.ReadWrite.All
        "06b708a9-e830-4db3-a914-8e69da51d44f",  # AppRoleAssignment.ReadWrite.All
        "9e3f62cf-ca93-4989-b6ce-bf83c28f9fe8"   # RoleManagement.ReadWrite.Directory
    )
    
    foreach ($app in $allApps) {
        if ($app.RequiredResourceAccess) {
            foreach ($resource in $app.RequiredResourceAccess) {
                if ($resource.ResourceAppId -eq "00000003-0000-0000-c000-000000000000") {  # Microsoft Graph
                    foreach ($access in $resource.ResourceAccess) {
                        if ($access.Id -in $highRiskPermIds) {
                            $appsWithHighRiskPerms++
                            break
                        }
                    }
                }
            }
        }
    }
    
    if ($appsWithHighRiskPerms -gt 0) {
        if ($totalPasswordOnly -eq 0) {
            Write-ColorOutput -Message "`n[!] Security Warning:" -Color "Yellow"
        }
        Write-ColorOutput -Message "    [!] Found $appsWithHighRiskPerms applications requesting high-risk permissions" -Color "Yellow"
        Write-ColorOutput -Message "    [*] These permissions can modify directory, roles, or applications" -Color "DarkGray"
        Write-ColorOutput -Message "    [*] Review these applications for potential privilege escalation paths" -Color "DarkGray"
        Write-ColorOutput -Message "    [*] Use sp-discovery command for detailed permission analysis" -Color "DarkGray"
    }
    
    Write-ColorOutput -Message "`n[*] Application enumeration complete!" -Color "Green"
}

# Format role assignment output like netexec
