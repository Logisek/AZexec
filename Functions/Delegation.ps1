# AZexec - OAuth2 Delegation Enumeration Functions
# These functions are loaded into the main script scope via dot-sourcing
# Azure equivalent of NetExec's --delegate functionality

# Define dangerous permissions for risk assessment
$script:CriticalPermissions = @(
    "Directory.AccessAsUser.All",      # Full directory access as user (unconstrained delegation equivalent)
    "RoleManagement.ReadWrite.Directory", # Can assign any role
    "AppRoleAssignment.ReadWrite.All",    # Can grant any permission
    "Application.ReadWrite.All"           # Can modify any application
)

$script:HighRiskPermissions = @(
    "Mail.Send",                       # Send email as users
    "Mail.ReadWrite",                  # Full mailbox access
    "Mail.ReadWrite.All",              # All mailboxes
    "Files.ReadWrite.All",             # Access all files
    "Group.ReadWrite.All",             # Modify all groups
    "User.ReadWrite.All",              # Modify all users
    "Directory.ReadWrite.All",         # Directory write access
    "Sites.ReadWrite.All",             # SharePoint full access
    "Calendars.ReadWrite",             # Calendar access
    "Contacts.ReadWrite"               # Contacts access
)

$script:MediumRiskPermissions = @(
    "User.Read.All",                   # Read all user profiles
    "Group.Read.All",                  # Read all groups
    "Directory.Read.All",              # Read directory
    "Mail.Read",                       # Read mail
    "Files.Read.All",                  # Read all files
    "Sites.Read.All",                  # Read SharePoint
    "Calendars.Read",                  # Read calendars
    "AuditLog.Read.All"                # Read audit logs
)

function Get-PermissionRiskLevel {
    param(
        [string]$Permission,
        [string]$ConsentType
    )

    # AllPrincipals (admin consent) elevates risk
    $isAdminConsent = $ConsentType -eq "AllPrincipals"

    if ($Permission -in $script:CriticalPermissions) {
        return @{
            Level = "CRITICAL"
            Color = "Red"
            Priority = 1
        }
    }

    if ($Permission -in $script:HighRiskPermissions) {
        # Admin consent elevates HIGH to CRITICAL for some permissions
        if ($isAdminConsent -and $Permission -in @("Mail.Send", "Mail.ReadWrite", "Mail.ReadWrite.All")) {
            return @{
                Level = "CRITICAL"
                Color = "Red"
                Priority = 1
            }
        }
        return @{
            Level = "HIGH"
            Color = "Yellow"
            Priority = 2
        }
    }

    if ($Permission -in $script:MediumRiskPermissions) {
        return @{
            Level = "MEDIUM"
            Color = "Cyan"
            Priority = 3
        }
    }

    return @{
        Level = "LOW"
        Color = "Gray"
        Priority = 4
    }
}

function Format-DelegationOutput {
    param(
        [PSCustomObject]$Grant,
        [PSCustomObject]$ServicePrincipal,
        [string]$ResourceName,
        [array]$Scopes,
        [string]$ConsentType,
        [string]$OverallRiskLevel,
        [string]$RiskColor
    )

    # Build display name
    $displayName = if ($ServicePrincipal.DisplayName) { $ServicePrincipal.DisplayName } else { "UNKNOWN" }
    $maxNameLength = 35
    $displayNameShort = if ($displayName.Length -gt $maxNameLength) {
        $displayName.Substring(0, $maxNameLength - 3) + "..."
    } else {
        $displayName
    }

    # Use AppId for column (truncated)
    $appIdShort = if ($ServicePrincipal.AppId) {
        $ServicePrincipal.AppId.Substring(0, [Math]::Min(15, $ServicePrincipal.AppId.Length))
    } else {
        "UNKNOWN-ID"
    }

    # Build scope summary
    $scopeSummary = ($Scopes | Select-Object -First 3) -join ","
    if ($Scopes.Count -gt 3) {
        $scopeSummary += "..."
    }

    # Build main output line
    $consentLabel = if ($ConsentType -eq "AllPrincipals") { "AllPrincipals" } else { "Principal" }
    $output = "AZR".PadRight(12) +
              $appIdShort.PadRight(17) +
              "443".PadRight(7) +
              $displayNameShort.PadRight(38) +
              "[$([char]0x0021)] ${consentLabel}:$scopeSummary ($OverallRiskLevel)"

    Write-ColorOutput -Message $output -Color $RiskColor

    # Display detailed permission breakdown
    foreach ($scope in $Scopes) {
        $risk = Get-PermissionRiskLevel -Permission $scope -ConsentType $ConsentType
        $permColor = switch ($risk.Level) {
            "CRITICAL" { "Red" }
            "HIGH" { "Yellow" }
            "MEDIUM" { "Cyan" }
            default { "Gray" }
        }
        Write-ColorOutput -Message "    [$([char]0x002B)] $scope [$($risk.Level)]" -Color $permColor
    }

    # Add risk explanation for critical/high
    if ($OverallRiskLevel -eq "CRITICAL") {
        $criticalPerms = $Scopes | Where-Object { $_ -in $script:CriticalPermissions }
        foreach ($perm in $criticalPerms) {
            $explanation = switch ($perm) {
                "Directory.AccessAsUser.All" { "FULL DIRECTORY ACCESS as any user - Azure equivalent of unconstrained delegation" }
                "RoleManagement.ReadWrite.Directory" { "Can assign ANY directory role including Global Admin" }
                "AppRoleAssignment.ReadWrite.All" { "Can grant ANY permission to ANY application" }
                "Application.ReadWrite.All" { "Can modify ANY application including adding credentials" }
                default { "Critical permission - review immediately" }
            }
            Write-ColorOutput -Message "    [$([char]0x0021)] $explanation" -Color "Red"
        }
    }

    if ($ConsentType -eq "AllPrincipals") {
        Write-ColorOutput -Message "    [$([char]0x002B)] Resource: $ResourceName" -Color "DarkCyan"
        Write-ColorOutput -Message "    [$([char]0x002B)] Consent: Admin (tenant-wide impersonation)" -Color "DarkCyan"
    } else {
        Write-ColorOutput -Message "    [$([char]0x002B)] Resource: $ResourceName" -Color "DarkGray"
        Write-ColorOutput -Message "    [$([char]0x002B)] Consent: User (per-user consent)" -Color "DarkGray"
    }

    Write-ColorOutput -Message "" -Color "White"
}

function Analyze-OAuth2PermissionGrant {
    param(
        [PSCustomObject]$Grant,
        [hashtable]$SPLookup,
        [hashtable]$PermissionLookup
    )

    $clientId = $Grant.clientId
    $resourceId = $Grant.resourceId
    $consentType = $Grant.consentType
    $scopes = if ($Grant.scope) { $Grant.scope -split ' ' | Where-Object { $_ -ne '' } } else { @() }

    # Get client service principal
    $clientSP = $SPLookup[$clientId]
    if (-not $clientSP) {
        return $null
    }

    # Get resource service principal
    $resourceSP = $SPLookup[$resourceId]
    $resourceName = if ($resourceSP) { $resourceSP.DisplayName } else { "Unknown Resource" }

    # Calculate overall risk level
    $highestPriority = 5  # Start with lowest
    $overallRiskLevel = "LOW"
    $riskColor = "Gray"

    foreach ($scope in $scopes) {
        $risk = Get-PermissionRiskLevel -Permission $scope -ConsentType $consentType
        if ($risk.Priority -lt $highestPriority) {
            $highestPriority = $risk.Priority
            $overallRiskLevel = $risk.Level
            $riskColor = $risk.Color
        }
    }

    # Admin consent elevates risk level
    if ($consentType -eq "AllPrincipals" -and $overallRiskLevel -eq "LOW") {
        $overallRiskLevel = "MEDIUM"
        $riskColor = "Cyan"
    }

    return @{
        Grant = $Grant
        ClientSP = $clientSP
        ResourceName = $resourceName
        Scopes = $scopes
        ConsentType = $consentType
        OverallRiskLevel = $overallRiskLevel
        RiskColor = $riskColor
        RiskPriority = $highestPriority
    }
}

# Main Delegation Enumeration function
function Invoke-DelegationEnumeration {
    param(
        [string]$ExportPath
    )

    Write-ColorOutput -Message "`n[*] AZX - Azure OAuth2 Delegation Enumeration" -Color "Yellow"
    Write-ColorOutput -Message "[*] Command: OAuth2 Permission Grant Analysis (Impersonation Paths)" -Color "Yellow"
    Write-ColorOutput -Message "[*] Azure equivalent of NetExec's --delegate flag`n" -Color "Yellow"

    Write-ColorOutput -Message "[*] ========================================" -Color "Cyan"
    Write-ColorOutput -Message "[*] KERBEROS vs OAUTH2 DELEGATION CONCEPTS" -Color "Cyan"
    Write-ColorOutput -Message "[*] ========================================`n" -Color "Cyan"

    Write-ColorOutput -Message "[*] NetExec (Kerberos) -> AZexec (OAuth2) Mapping:" -Color "Yellow"
    Write-ColorOutput -Message "    RBCD (Resource-Based Constrained Delegation) -> Admin Consent (AllPrincipals)" -Color "DarkCyan"
    Write-ColorOutput -Message "    S4U2Self (Service for User to Self)          -> Delegated permissions with user context" -Color "DarkCyan"
    Write-ColorOutput -Message "    Constrained Delegation                       -> Specific scope grants to resources" -Color "DarkCyan"
    Write-ColorOutput -Message "    Unconstrained Delegation                     -> Directory.AccessAsUser.All`n" -Color "DarkCyan"

    # Get context to display current user info
    $context = Get-MgContext
    if ($context) {
        Write-ColorOutput -Message "[*] Authenticated as: $($context.Account)" -Color "Cyan"
        Write-ColorOutput -Message "[*] Tenant: $($context.TenantId)`n" -Color "Cyan"
    }

    # Prepare export data
    $exportData = @()

    # ===== PHASE 1: RETRIEVE SERVICE PRINCIPALS =====
    Write-ColorOutput -Message "[*] ========================================" -Color "Cyan"
    Write-ColorOutput -Message "[*] PHASE 1: Service Principal Discovery" -Color "Cyan"
    Write-ColorOutput -Message "[*] ========================================`n" -Color "Cyan"

    Write-ColorOutput -Message "[*] Retrieving service principals for permission resolution..." -Color "Yellow"

    $spLookup = @{}
    try {
        $allSPNs = Get-MgServicePrincipal -All -Property "id,displayName,appId,servicePrincipalType,oauth2PermissionScopes" -ErrorAction Stop
        foreach ($sp in $allSPNs) {
            $spLookup[$sp.Id] = $sp
        }
        Write-ColorOutput -Message "[+] Retrieved $($allSPNs.Count) service principals`n" -Color "Green"
    } catch {
        Write-ColorOutput -Message "[!] Failed to retrieve service principals: $_" -Color "Red"
        Write-ColorOutput -Message "[!] Ensure you have Application.Read.All or Directory.Read.All permissions" -Color "Red"
        return
    }

    # Get Microsoft Graph SP for permission name resolution
    $graphSP = $allSPNs | Where-Object { $_.AppId -eq "00000003-0000-0000-c000-000000000000" } | Select-Object -First 1
    $permissionLookup = @{}
    if ($graphSP -and $graphSP.Oauth2PermissionScopes) {
        foreach ($perm in $graphSP.Oauth2PermissionScopes) {
            $permissionLookup[$perm.Id] = $perm.Value
        }
        Write-ColorOutput -Message "[+] Loaded $($permissionLookup.Count) Microsoft Graph permission definitions`n" -Color "Green"
    }

    # ===== PHASE 2: RETRIEVE OAUTH2 PERMISSION GRANTS =====
    Write-ColorOutput -Message "[*] ========================================" -Color "Cyan"
    Write-ColorOutput -Message "[*] PHASE 2: OAuth2 Permission Grant Enumeration" -Color "Cyan"
    Write-ColorOutput -Message "[*] ========================================`n" -Color "Cyan"

    Write-ColorOutput -Message "[*] Retrieving OAuth2 permission grants (delegated permissions)..." -Color "Yellow"

    $allGrants = @()
    try {
        $grantsResponse = Invoke-MgGraphRequest -Uri "https://graph.microsoft.com/v1.0/oauth2PermissionGrants" -Method GET -ErrorAction Stop
        $allGrants = $grantsResponse.value

        # Handle pagination
        while ($grantsResponse.'@odata.nextLink') {
            $grantsResponse = Invoke-MgGraphRequest -Uri $grantsResponse.'@odata.nextLink' -Method GET -ErrorAction Stop
            $allGrants += $grantsResponse.value
        }

        Write-ColorOutput -Message "[+] Retrieved $($allGrants.Count) OAuth2 permission grants`n" -Color "Green"
    } catch {
        Write-ColorOutput -Message "[!] Failed to retrieve OAuth2 permission grants: $_" -Color "Yellow"
        Write-ColorOutput -Message "[*] Continuing with limited data...`n" -Color "Yellow"
    }

    if ($allGrants.Count -eq 0) {
        Write-ColorOutput -Message "[!] No OAuth2 permission grants found or insufficient permissions`n" -Color "Yellow"
        return
    }

    # Analyze all grants
    $analyzedGrants = @()
    foreach ($grant in $allGrants) {
        $analysis = Analyze-OAuth2PermissionGrant -Grant $grant -SPLookup $spLookup -PermissionLookup $permissionLookup
        if ($analysis) {
            $analyzedGrants += $analysis
        }
    }

    # Sort by risk level
    $analyzedGrants = $analyzedGrants | Sort-Object { $_.RiskPriority }

    # Separate admin consent vs user consent
    $adminConsentGrants = $analyzedGrants | Where-Object { $_.ConsentType -eq "AllPrincipals" }
    $userConsentGrants = $analyzedGrants | Where-Object { $_.ConsentType -ne "AllPrincipals" }

    # ===== PHASE 3: ADMIN CONSENT GRANTS (TENANT-WIDE IMPERSONATION) =====
    Write-ColorOutput -Message "[*] ========================================" -Color "Cyan"
    Write-ColorOutput -Message "[*] PHASE 3: Admin Consent Grants (Tenant-Wide Impersonation)" -Color "Cyan"
    Write-ColorOutput -Message "[*] ========================================`n" -Color "Cyan"

    if ($adminConsentGrants.Count -gt 0) {
        Write-ColorOutput -Message "[!] Admin consent grants allow apps to act on behalf of ALL users in the tenant" -Color "Yellow"
        Write-ColorOutput -Message "[!] This is the Azure equivalent of RBCD (Resource-Based Constrained Delegation)`n" -Color "Yellow"

        foreach ($analysis in $adminConsentGrants) {
            Format-DelegationOutput -Grant $analysis.Grant `
                -ServicePrincipal $analysis.ClientSP `
                -ResourceName $analysis.ResourceName `
                -Scopes $analysis.Scopes `
                -ConsentType $analysis.ConsentType `
                -OverallRiskLevel $analysis.OverallRiskLevel `
                -RiskColor $analysis.RiskColor

            # Collect for export
            if ($ExportPath) {
                $exportData += [PSCustomObject]@{
                    AppId = $analysis.ClientSP.AppId
                    DisplayName = $analysis.ClientSP.DisplayName
                    ServicePrincipalId = $analysis.ClientSP.Id
                    ServicePrincipalType = $analysis.ClientSP.ServicePrincipalType
                    ResourceName = $analysis.ResourceName
                    ConsentType = $analysis.ConsentType
                    Scopes = ($analysis.Scopes -join "; ")
                    RiskLevel = $analysis.OverallRiskLevel
                    GrantId = $analysis.Grant.id
                    PrincipalId = $analysis.Grant.principalId
                }
            }
        }
    } else {
        Write-ColorOutput -Message "[*] No admin consent grants found`n" -Color "Gray"
    }

    # ===== PHASE 4: USER CONSENT GRANTS (PER-USER IMPERSONATION) =====
    Write-ColorOutput -Message "[*] ========================================" -Color "Cyan"
    Write-ColorOutput -Message "[*] PHASE 4: User Consent Grants (Per-User Impersonation)" -Color "Cyan"
    Write-ColorOutput -Message "[*] ========================================`n" -Color "Cyan"

    if ($userConsentGrants.Count -gt 0) {
        Write-ColorOutput -Message "[*] User consent grants allow apps to act on behalf of specific users who consented" -Color "Yellow"
        Write-ColorOutput -Message "[*] Risk depends on which users have consented and what permissions were granted`n" -Color "Yellow"

        # Group by client app for cleaner output
        $groupedUserGrants = $userConsentGrants | Group-Object { $_.ClientSP.Id }

        foreach ($group in $groupedUserGrants) {
            $firstGrant = $group.Group[0]
            $userCount = $group.Count

            # Combine all unique scopes from all grants for this app
            $allScopes = ($group.Group | ForEach-Object { $_.Scopes }) | Select-Object -Unique

            # Recalculate overall risk with all scopes
            $highestPriority = 5
            $overallRiskLevel = "LOW"
            $riskColor = "Gray"
            foreach ($scope in $allScopes) {
                $risk = Get-PermissionRiskLevel -Permission $scope -ConsentType "Principal"
                if ($risk.Priority -lt $highestPriority) {
                    $highestPriority = $risk.Priority
                    $overallRiskLevel = $risk.Level
                    $riskColor = $risk.Color
                }
            }

            # Build display name
            $displayName = if ($firstGrant.ClientSP.DisplayName) { $firstGrant.ClientSP.DisplayName } else { "UNKNOWN" }
            $maxNameLength = 35
            $displayNameShort = if ($displayName.Length -gt $maxNameLength) {
                $displayName.Substring(0, $maxNameLength - 3) + "..."
            } else {
                $displayName
            }

            $appIdShort = if ($firstGrant.ClientSP.AppId) {
                $firstGrant.ClientSP.AppId.Substring(0, [Math]::Min(15, $firstGrant.ClientSP.AppId.Length))
            } else {
                "UNKNOWN-ID"
            }

            $scopeSummary = ($allScopes | Select-Object -First 3) -join ","
            if ($allScopes.Count -gt 3) {
                $scopeSummary += "..."
            }

            $output = "AZR".PadRight(12) +
                      $appIdShort.PadRight(17) +
                      "443".PadRight(7) +
                      $displayNameShort.PadRight(38) +
                      "[*] Principal:$scopeSummary ($overallRiskLevel)"

            Write-ColorOutput -Message $output -Color $riskColor
            Write-ColorOutput -Message "    [*] Per-user consent only ($userCount users)" -Color "DarkGray"

            foreach ($scope in $allScopes) {
                $risk = Get-PermissionRiskLevel -Permission $scope -ConsentType "Principal"
                $permColor = switch ($risk.Level) {
                    "CRITICAL" { "Red" }
                    "HIGH" { "Yellow" }
                    "MEDIUM" { "Cyan" }
                    default { "Gray" }
                }
                Write-ColorOutput -Message "    [$([char]0x002B)] $scope [$($risk.Level)]" -Color $permColor
            }

            Write-ColorOutput -Message "" -Color "White"

            # Collect for export (one entry per app with aggregated data)
            if ($ExportPath) {
                $exportData += [PSCustomObject]@{
                    AppId = $firstGrant.ClientSP.AppId
                    DisplayName = $firstGrant.ClientSP.DisplayName
                    ServicePrincipalId = $firstGrant.ClientSP.Id
                    ServicePrincipalType = $firstGrant.ClientSP.ServicePrincipalType
                    ResourceName = $firstGrant.ResourceName
                    ConsentType = "Principal"
                    Scopes = ($allScopes -join "; ")
                    RiskLevel = $overallRiskLevel
                    UserCount = $userCount
                    GrantIds = ($group.Group | ForEach-Object { $_.Grant.id }) -join "; "
                }
            }
        }
    } else {
        Write-ColorOutput -Message "[*] No user consent grants found`n" -Color "Gray"
    }

    # ===== PHASE 5: SUMMARY =====
    Write-ColorOutput -Message "[*] ========================================" -Color "Cyan"
    Write-ColorOutput -Message "[*] DELEGATION SUMMARY" -Color "Cyan"
    Write-ColorOutput -Message "[*] ========================================`n" -Color "Cyan"

    # Count by risk level
    $criticalCount = ($analyzedGrants | Where-Object { $_.OverallRiskLevel -eq "CRITICAL" }).Count
    $highCount = ($analyzedGrants | Where-Object { $_.OverallRiskLevel -eq "HIGH" }).Count
    $mediumCount = ($analyzedGrants | Where-Object { $_.OverallRiskLevel -eq "MEDIUM" }).Count
    $lowCount = ($analyzedGrants | Where-Object { $_.OverallRiskLevel -eq "LOW" }).Count

    # Unique apps with admin consent
    $adminConsentApps = ($adminConsentGrants | Select-Object -ExpandProperty ClientSP | Select-Object -ExpandProperty Id -Unique).Count

    if ($criticalCount -gt 0) {
        Write-ColorOutput -Message "    [$([char]0x0021)] CRITICAL IMPERSONATION APPS: $criticalCount" -Color "Red"
    }
    if ($highCount -gt 0) {
        Write-ColorOutput -Message "    [$([char]0x0021)] HIGH RISK IMPERSONATION APPS: $highCount" -Color "Yellow"
    }
    Write-ColorOutput -Message "    [*] MEDIUM RISK APPS: $mediumCount" -Color "Cyan"
    Write-ColorOutput -Message "    [*] LOW RISK APPS: $lowCount" -Color "Gray"
    Write-ColorOutput -Message "    [*] Total OAuth2 Grants: $($allGrants.Count)" -Color "White"
    Write-ColorOutput -Message "    [*] Admin Consent Grants: $($adminConsentGrants.Count) ($adminConsentApps unique apps)" -Color "White"
    Write-ColorOutput -Message "    [*] User Consent Grants: $($userConsentGrants.Count)" -Color "White"

    # Security recommendations
    if ($criticalCount -gt 0 -or $highCount -gt 0) {
        Write-ColorOutput -Message "`n[!] Security Recommendations:" -Color "Yellow"

        # Check for Directory.AccessAsUser.All specifically
        $directoryAccessApps = $adminConsentGrants | Where-Object {
            $_.Scopes -contains "Directory.AccessAsUser.All"
        }
        if ($directoryAccessApps.Count -gt 0) {
            Write-ColorOutput -Message "    [$([char]0x0021)] CRITICAL: $($directoryAccessApps.Count) apps with Directory.AccessAsUser.All" -Color "Red"
            Write-ColorOutput -Message "    [*] These apps can fully impersonate any user in the directory" -Color "DarkGray"
        }

        # Check for role management permissions
        $roleManagementApps = $adminConsentGrants | Where-Object {
            $_.Scopes -contains "RoleManagement.ReadWrite.Directory" -or
            $_.Scopes -contains "AppRoleAssignment.ReadWrite.All" -or
            $_.Scopes -contains "Application.ReadWrite.All"
        }
        if ($roleManagementApps.Count -gt 0) {
            Write-ColorOutput -Message "    [$([char]0x0021)] CRITICAL: $($roleManagementApps.Count) apps can modify roles/permissions" -Color "Red"
            Write-ColorOutput -Message "    [*] Review for privilege escalation paths" -Color "DarkGray"
        }

        # Check for mail permissions with admin consent
        $mailApps = $adminConsentGrants | Where-Object {
            $_.Scopes | Where-Object { $_ -like "Mail.*" }
        }
        if ($mailApps.Count -gt 0) {
            Write-ColorOutput -Message "    [$([char]0x0021)] HIGH: $($mailApps.Count) apps can send/read email as ANY user" -Color "Yellow"
            Write-ColorOutput -Message "    [*] Review necessity of Mail.Send and Mail.ReadWrite permissions" -Color "DarkGray"
        }

        # Check for file access permissions with admin consent
        $fileApps = $adminConsentGrants | Where-Object {
            $_.Scopes -contains "Files.ReadWrite.All" -or $_.Scopes -contains "Sites.ReadWrite.All"
        }
        if ($fileApps.Count -gt 0) {
            Write-ColorOutput -Message "    [$([char]0x0021)] HIGH: $($fileApps.Count) apps have tenant-wide file/SharePoint access" -Color "Yellow"
            Write-ColorOutput -Message "    [*] Review necessity of Files.ReadWrite.All and Sites.ReadWrite.All" -Color "DarkGray"
        }

        Write-ColorOutput -Message "    [*] Consider implementing app governance policies" -Color "DarkGray"
        Write-ColorOutput -Message "    [*] Review Azure AD admin consent workflow settings" -Color "DarkGray"
    }

    # Export if requested
    if ($ExportPath -and $exportData.Count -gt 0) {
        try {
            $extension = [System.IO.Path]::GetExtension($ExportPath).ToLower()

            if ($extension -eq ".csv") {
                $exportData | Export-Csv -Path $ExportPath -NoTypeInformation -Force
                Write-ColorOutput -Message "`n[+] Results exported to: $ExportPath" -Color "Green"
            } elseif ($extension -eq ".json") {
                $jsonExport = @{
                    Metadata = @{
                        Timestamp = (Get-Date -Format "yyyy-MM-ddTHH:mm:ssZ")
                        TenantId = $context.TenantId
                        AuthenticatedUser = $context.Account
                        TotalGrants = $allGrants.Count
                        AdminConsentGrants = $adminConsentGrants.Count
                        UserConsentGrants = $userConsentGrants.Count
                    }
                    Summary = @{
                        CriticalRiskApps = $criticalCount
                        HighRiskApps = $highCount
                        MediumRiskApps = $mediumCount
                        LowRiskApps = $lowCount
                    }
                    Grants = $exportData
                }
                $jsonExport | ConvertTo-Json -Depth 5 | Out-File -FilePath $ExportPath -Force
                Write-ColorOutput -Message "`n[+] Results exported to: $ExportPath" -Color "Green"
            } elseif ($extension -eq ".html") {
                $stats = [ordered]@{
                    "Total OAuth2 Grants" = $allGrants.Count
                    "Admin Consent Grants" = $adminConsentGrants.Count
                    "User Consent Grants" = $userConsentGrants.Count
                    "CRITICAL Risk Apps" = $criticalCount
                    "HIGH Risk Apps" = $highCount
                    "MEDIUM Risk Apps" = $mediumCount
                    "LOW Risk Apps" = $lowCount
                }

                $description = "OAuth2 delegation enumeration identifying applications with delegated permissions that can act on behalf of users. This is the Azure equivalent of Kerberos delegation analysis."

                $success = Export-HtmlReport -Data $exportData -OutputPath $ExportPath -Title "OAuth2 Delegation Analysis Report" -Statistics $stats -CommandName "delegation-enum" -Description $description

                if ($success) {
                    Write-ColorOutput -Message "`n[+] HTML report exported to: $ExportPath" -Color "Green"
                }
            } else {
                # Default to CSV
                $exportData | Export-Csv -Path $ExportPath -NoTypeInformation -Force
                Write-ColorOutput -Message "`n[+] Results exported to: $ExportPath" -Color "Green"
            }
        } catch {
            Write-ColorOutput -Message "[!] Failed to export results: $_" -Color "Red"
        }
    }

    Write-ColorOutput -Message "`n[*] Delegation enumeration complete!" -Color "Green"
}
