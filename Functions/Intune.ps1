# AZexec - Intune/Endpoint Manager Functions
# These functions are loaded into the main script scope via dot-sourcing
# Azure equivalent of NetExec's sccm-recon6 module

function Format-IntuneOutput {
    param(
        [string]$Category,
        [string]$ItemName,
        [string]$Details,
        [string]$Color = "Cyan"
    )

    # Truncate long item names for column display
    $maxNameLength = 35
    $displayName = if ($ItemName.Length -gt $maxNameLength) {
        $ItemName.Substring(0, $maxNameLength - 3) + "..."
    } else {
        $ItemName
    }

    # Build output line in NetExec style
    $output = "AZR".PadRight(12) +
              "INTUNE".PadRight(17) +
              "443".PadRight(7) +
              $displayName.PadRight(38) +
              $Details

    Write-ColorOutput -Message $output -Color $Color
}

function Get-IntuneEnrollmentConfigurations {
    param()

    $results = @()

    try {
        # Query device enrollment configurations
        $uri = "https://graph.microsoft.com/beta/deviceManagement/deviceEnrollmentConfigurations"
        $response = Invoke-MgGraphRequest -Uri $uri -Method GET -ErrorAction Stop

        if ($response.value) {
            foreach ($config in $response.value) {
                $configType = switch ($config.'@odata.type') {
                    "#microsoft.graph.deviceEnrollmentLimitConfiguration" { "Enrollment Limit" }
                    "#microsoft.graph.deviceEnrollmentPlatformRestrictionsConfiguration" { "Platform Restrictions" }
                    "#microsoft.graph.deviceEnrollmentWindowsHelloForBusinessConfiguration" { "Windows Hello" }
                    "#microsoft.graph.windows10EnrollmentCompletionPageConfiguration" { "Enrollment Status Page" }
                    "#microsoft.graph.deviceComanagementAuthorityConfiguration" { "Co-management Authority" }
                    default { $config.'@odata.type' -replace '#microsoft.graph.', '' }
                }

                $priority = if ($config.priority) { $config.priority } else { "N/A" }

                $results += [PSCustomObject]@{
                    Id = $config.id
                    DisplayName = $config.displayName
                    Description = $config.description
                    ConfigType = $configType
                    Priority = $priority
                    CreatedDateTime = $config.createdDateTime
                    LastModifiedDateTime = $config.lastModifiedDateTime
                    RawConfig = $config
                }
            }
        }
    } catch {
        Write-ColorOutput -Message "[!] Failed to retrieve enrollment configurations: $($_.Exception.Message)" -Color "Yellow"
    }

    return $results
}

function Get-IntuneCompliancePolicies {
    param()

    $results = @()

    try {
        # Query device compliance policies
        $uri = "https://graph.microsoft.com/beta/deviceManagement/deviceCompliancePolicies"
        $response = Invoke-MgGraphRequest -Uri $uri -Method GET -ErrorAction Stop

        if ($response.value) {
            foreach ($policy in $response.value) {
                $platform = switch ($policy.'@odata.type') {
                    "#microsoft.graph.windows10CompliancePolicy" { "Windows 10/11" }
                    "#microsoft.graph.iosCompliancePolicy" { "iOS/iPadOS" }
                    "#microsoft.graph.androidCompliancePolicy" { "Android" }
                    "#microsoft.graph.androidWorkProfileCompliancePolicy" { "Android Work Profile" }
                    "#microsoft.graph.androidDeviceOwnerCompliancePolicy" { "Android Enterprise" }
                    "#microsoft.graph.macOSCompliancePolicy" { "macOS" }
                    default { $policy.'@odata.type' -replace '#microsoft.graph.', '' -replace 'CompliancePolicy', '' }
                }

                # Extract key security settings
                $securitySettings = @()

                if ($policy.passwordRequired) { $securitySettings += "Password:Required" }
                if ($policy.passwordMinimumLength) { $securitySettings += "MinLen:$($policy.passwordMinimumLength)" }
                if ($policy.bitLockerEnabled) { $securitySettings += "BitLocker:Required" }
                if ($policy.secureBootEnabled) { $securitySettings += "SecureBoot:Required" }
                if ($policy.codeIntegrityEnabled) { $securitySettings += "CodeIntegrity:Required" }
                if ($policy.storageRequireEncryption) { $securitySettings += "Encryption:Required" }
                if ($policy.deviceThreatProtectionEnabled) { $securitySettings += "ThreatProtection:Enabled" }
                if ($policy.firewallEnabled) { $securitySettings += "Firewall:Required" }
                if ($policy.antivirusRequired) { $securitySettings += "Antivirus:Required" }
                if ($policy.defenderEnabled) { $securitySettings += "Defender:Required" }

                $results += [PSCustomObject]@{
                    Id = $policy.id
                    DisplayName = $policy.displayName
                    Description = $policy.description
                    Platform = $platform
                    SecuritySettings = ($securitySettings -join " | ")
                    CreatedDateTime = $policy.createdDateTime
                    LastModifiedDateTime = $policy.lastModifiedDateTime
                    RawPolicy = $policy
                }
            }
        }
    } catch {
        Write-ColorOutput -Message "[!] Failed to retrieve compliance policies: $($_.Exception.Message)" -Color "Yellow"
    }

    return $results
}

function Get-IntuneConfigurationProfiles {
    param()

    $results = @()

    try {
        # Query device configuration profiles
        $uri = "https://graph.microsoft.com/beta/deviceManagement/deviceConfigurations"
        $response = Invoke-MgGraphRequest -Uri $uri -Method GET -ErrorAction Stop

        if ($response.value) {
            foreach ($profile in $response.value) {
                $profileType = switch ($profile.'@odata.type') {
                    "#microsoft.graph.windows10GeneralConfiguration" { "Windows General" }
                    "#microsoft.graph.windows10EndpointProtectionConfiguration" { "Endpoint Protection" }
                    "#microsoft.graph.windowsIdentityProtectionConfiguration" { "Identity Protection" }
                    "#microsoft.graph.windowsWifiConfiguration" { "WiFi" }
                    "#microsoft.graph.windowsVpnConfiguration" { "VPN" }
                    "#microsoft.graph.windows10CertificateProfileBase" { "Certificate" }
                    "#microsoft.graph.windows10CustomConfiguration" { "Custom (OMA-URI)" }
                    "#microsoft.graph.iosGeneralDeviceConfiguration" { "iOS General" }
                    "#microsoft.graph.iosWiFiConfiguration" { "iOS WiFi" }
                    "#microsoft.graph.iosVpnConfiguration" { "iOS VPN" }
                    "#microsoft.graph.androidGeneralDeviceConfiguration" { "Android General" }
                    "#microsoft.graph.androidWorkProfileGeneralDeviceConfiguration" { "Android Work Profile" }
                    "#microsoft.graph.macOSGeneralDeviceConfiguration" { "macOS General" }
                    "#microsoft.graph.windowsDefenderAdvancedThreatProtectionConfiguration" { "Defender ATP" }
                    "#microsoft.graph.sharedPCConfiguration" { "Shared PC" }
                    "#microsoft.graph.windows10TeamGeneralConfiguration" { "Surface Hub" }
                    default { $profile.'@odata.type' -replace '#microsoft.graph.', '' }
                }

                # Determine sensitivity level
                $sensitivity = "Normal"
                $sensitiveTypes = @("VPN", "WiFi", "Certificate", "Custom", "Endpoint Protection", "Defender")
                foreach ($st in $sensitiveTypes) {
                    if ($profileType -like "*$st*") {
                        $sensitivity = "SENSITIVE"
                        break
                    }
                }

                $results += [PSCustomObject]@{
                    Id = $profile.id
                    DisplayName = $profile.displayName
                    Description = $profile.description
                    ProfileType = $profileType
                    Sensitivity = $sensitivity
                    CreatedDateTime = $profile.createdDateTime
                    LastModifiedDateTime = $profile.lastModifiedDateTime
                    RawProfile = $profile
                }
            }
        }
    } catch {
        Write-ColorOutput -Message "[!] Failed to retrieve configuration profiles: $($_.Exception.Message)" -Color "Yellow"
    }

    return $results
}

function Get-IntuneRoleDefinitions {
    param()

    $results = @()

    try {
        # Query Intune role definitions
        $uri = "https://graph.microsoft.com/beta/deviceManagement/roleDefinitions"
        $response = Invoke-MgGraphRequest -Uri $uri -Method GET -ErrorAction Stop

        if ($response.value) {
            foreach ($role in $response.value) {
                $isBuiltIn = $role.isBuiltIn

                # Determine privilege level
                $privilegeLevel = "Standard"
                $highPrivRoles = @("Intune Administrator", "Intune Role Administrator", "Global Administrator", "Cloud Device Administrator")
                foreach ($hpr in $highPrivRoles) {
                    if ($role.displayName -like "*$hpr*" -or $role.displayName -eq $hpr) {
                        $privilegeLevel = "HIGH"
                        break
                    }
                }

                # Count permissions
                $permissionCount = 0
                if ($role.permissions) {
                    foreach ($perm in $role.permissions) {
                        if ($perm.actions) { $permissionCount += $perm.actions.Count }
                    }
                }

                $results += [PSCustomObject]@{
                    Id = $role.id
                    DisplayName = $role.displayName
                    Description = $role.description
                    IsBuiltIn = $isBuiltIn
                    PrivilegeLevel = $privilegeLevel
                    PermissionCount = $permissionCount
                    RawRole = $role
                }
            }
        }
    } catch {
        Write-ColorOutput -Message "[!] Failed to retrieve role definitions: $($_.Exception.Message)" -Color "Yellow"
    }

    return $results
}

function Get-IntuneRoleAssignments {
    param()

    $results = @()

    try {
        # Query Intune role assignments
        $uri = "https://graph.microsoft.com/beta/deviceManagement/roleAssignments"
        $response = Invoke-MgGraphRequest -Uri $uri -Method GET -ErrorAction Stop

        if ($response.value) {
            foreach ($assignment in $response.value) {
                # Get members if available
                $members = @()
                if ($assignment.members) {
                    $members = $assignment.members
                }

                # Get scope tags
                $scopeTags = @()
                if ($assignment.scopeMembers) {
                    $scopeTags = $assignment.scopeMembers
                }

                $results += [PSCustomObject]@{
                    Id = $assignment.id
                    DisplayName = $assignment.displayName
                    Description = $assignment.description
                    RoleDefinitionId = $assignment.roleDefinition.id
                    RoleDefinitionName = $assignment.roleDefinition.displayName
                    Members = ($members -join ", ")
                    MemberCount = $members.Count
                    ScopeTags = ($scopeTags -join ", ")
                    RawAssignment = $assignment
                }
            }
        }
    } catch {
        Write-ColorOutput -Message "[!] Failed to retrieve role assignments: $($_.Exception.Message)" -Color "Yellow"
    }

    return $results
}

function Get-IntuneAutopilotProfiles {
    param()

    $results = @()

    try {
        # Query Windows Autopilot deployment profiles
        $uri = "https://graph.microsoft.com/beta/deviceManagement/windowsAutopilotDeploymentProfiles"
        $response = Invoke-MgGraphRequest -Uri $uri -Method GET -ErrorAction Stop

        if ($response.value) {
            foreach ($profile in $response.value) {
                $deploymentMode = switch ($profile.extractHardwareHash) {
                    $true { "Self-Deploying" }
                    default { "User-Driven" }
                }

                if ($profile.'@odata.type' -eq "#microsoft.graph.azureADWindowsAutopilotDeploymentProfile") {
                    $deploymentMode = "Azure AD Join"
                } elseif ($profile.'@odata.type' -eq "#microsoft.graph.activeDirectoryWindowsAutopilotDeploymentProfile") {
                    $deploymentMode = "Hybrid Azure AD Join"
                }

                # Extract OOBE settings
                $oobeSettings = @()
                if ($profile.outOfBoxExperienceSettings) {
                    $oobe = $profile.outOfBoxExperienceSettings
                    if ($oobe.hidePrivacySettings) { $oobeSettings += "SkipPrivacy" }
                    if ($oobe.hideEULA) { $oobeSettings += "SkipEULA" }
                    if ($oobe.skipKeyboardSelectionPage) { $oobeSettings += "SkipKeyboard" }
                    if ($oobe.userType -eq "administrator") { $oobeSettings += "LocalAdmin" }
                }

                $results += [PSCustomObject]@{
                    Id = $profile.id
                    DisplayName = $profile.displayName
                    Description = $profile.description
                    DeploymentMode = $deploymentMode
                    OOBESettings = ($oobeSettings -join " | ")
                    Language = $profile.language
                    CreatedDateTime = $profile.createdDateTime
                    LastModifiedDateTime = $profile.lastModifiedDateTime
                    RawProfile = $profile
                }
            }
        }
    } catch {
        Write-ColorOutput -Message "[!] Failed to retrieve Autopilot profiles: $($_.Exception.Message)" -Color "Yellow"
    }

    return $results
}

function Get-IntuneManagedDevicesSummary {
    param()

    $summary = @{
        TotalDevices = 0
        WindowsDevices = 0
        iOSDevices = 0
        AndroidDevices = 0
        macOSDevices = 0
        CompliantDevices = 0
        NonCompliantDevices = 0
    }

    try {
        # Get device counts using overview endpoint
        $uri = "https://graph.microsoft.com/beta/deviceManagement/managedDeviceOverview"
        $response = Invoke-MgGraphRequest -Uri $uri -Method GET -ErrorAction Stop

        if ($response) {
            $summary.TotalDevices = $response.enrolledDeviceCount

            if ($response.deviceOperatingSystemSummary) {
                $os = $response.deviceOperatingSystemSummary
                $summary.WindowsDevices = $os.windowsCount + $os.windowsMobileCount
                $summary.iOSDevices = $os.iosCount
                $summary.AndroidDevices = $os.androidCount + $os.androidDedicatedCount + $os.androidFullyManagedCount + $os.androidWorkProfileCount
                $summary.macOSDevices = $os.macOSCount
            }

            if ($response.deviceExchangeAccessStateSummary) {
                # Compliance approximation from exchange access
                $eas = $response.deviceExchangeAccessStateSummary
                $summary.CompliantDevices = $eas.allowedDeviceCount
                $summary.NonCompliantDevices = $eas.blockedDeviceCount + $eas.quarantinedDeviceCount
            }
        }
    } catch {
        Write-ColorOutput -Message "[!] Failed to retrieve managed device summary: $($_.Exception.Message)" -Color "Yellow"
    }

    return $summary
}

function Invoke-IntuneEnumeration {
    param(
        [string]$ExportPath
    )

    Write-ColorOutput -Message "`n[*] AZX - Intune/Endpoint Manager Enumeration" -Color "Yellow"
    Write-ColorOutput -Message "[*] Command: intune-enum (Similar to: nxc smb -M sccm-recon6)" -Color "Yellow"
    Write-ColorOutput -Message "[*] Azure equivalent of NetExec's SCCM reconnaissance`n" -Color "Yellow"

    Write-ColorOutput -Message "[*] Technical Comparison:" -Color "Cyan"
    Write-ColorOutput -Message "    On-Premises SCCM: Registry at HKLM\SOFTWARE\Microsoft\SMS via SMB (port 445)" -Color "Gray"
    Write-ColorOutput -Message "    Azure Intune: Microsoft Graph API deviceManagement endpoints (HTTPS/443)`n" -Color "Gray"

    Write-ColorOutput -Message "[*] This command enumerates:" -Color "Cyan"
    Write-ColorOutput -Message "    • Enrollment configurations and restrictions (Distribution Point equivalent)" -Color "Gray"
    Write-ColorOutput -Message "    • Compliance policies (Management Point security policies)" -Color "Gray"
    Write-ColorOutput -Message "    • Configuration profiles (Task Sequences equivalent)" -Color "Gray"
    Write-ColorOutput -Message "    • Intune RBAC role definitions and assignments" -Color "Gray"
    Write-ColorOutput -Message "    • Windows Autopilot deployment profiles (PXE Boot equivalent)" -Color "Gray"
    Write-ColorOutput -Message "    • Managed device summary`n" -Color "Gray"

    # Prepare export data
    $exportData = @{
        EnrollmentConfigs = @()
        CompliancePolicies = @()
        ConfigurationProfiles = @()
        RoleDefinitions = @()
        RoleAssignments = @()
        AutopilotProfiles = @()
        DeviceSummary = $null
    }

    # Statistics
    $stats = @{
        EnrollmentConfigs = 0
        CompliancePolicies = 0
        ConfigProfiles = 0
        SensitiveProfiles = 0
        RoleDefinitions = 0
        HighPrivRoles = 0
        RoleAssignments = 0
        AutopilotProfiles = 0
        TotalManagedDevices = 0
    }

    # ========================================
    # ENROLLMENT CONFIGURATION
    # ========================================
    Write-ColorOutput -Message "[*] ========================================" -Color "Cyan"
    Write-ColorOutput -Message "[*] ENROLLMENT CONFIGURATION" -Color "Cyan"
    Write-ColorOutput -Message "[*] ========================================`n" -Color "Cyan"

    $enrollmentConfigs = Get-IntuneEnrollmentConfigurations
    $stats.EnrollmentConfigs = $enrollmentConfigs.Count

    if ($enrollmentConfigs.Count -gt 0) {
        foreach ($config in $enrollmentConfigs) {
            $details = "[*] Type: $($config.ConfigType)"
            if ($config.Priority -ne "N/A") { $details += " | Priority: $($config.Priority)" }

            $color = "Cyan"
            if ($config.ConfigType -eq "Enrollment Limit") {
                # Check for overly permissive limits
                if ($config.RawConfig.limit -and $config.RawConfig.limit -gt 10) {
                    $details += " | Limit: $($config.RawConfig.limit) devices"
                    $color = "Yellow"
                    $details = "[!] HIGH LIMIT - " + $details
                } elseif ($config.RawConfig.limit) {
                    $details += " | Limit: $($config.RawConfig.limit) devices"
                }
            }

            Format-IntuneOutput -Category "Enrollment" -ItemName $config.DisplayName -Details $details -Color $color
            $exportData.EnrollmentConfigs += $config
        }
    } else {
        Write-ColorOutput -Message "    No enrollment configurations found or access denied" -Color "Gray"
    }

    Write-Host ""

    # ========================================
    # COMPLIANCE POLICIES
    # ========================================
    Write-ColorOutput -Message "[*] ========================================" -Color "Cyan"
    Write-ColorOutput -Message "[*] COMPLIANCE POLICIES" -Color "Cyan"
    Write-ColorOutput -Message "[*] ========================================`n" -Color "Cyan"

    $compliancePolicies = Get-IntuneCompliancePolicies
    $stats.CompliancePolicies = $compliancePolicies.Count

    if ($compliancePolicies.Count -gt 0) {
        foreach ($policy in $compliancePolicies) {
            $details = "[*] Platform: $($policy.Platform)"
            if ($policy.SecuritySettings) {
                $details += " | $($policy.SecuritySettings)"
            }

            $color = "Cyan"
            # Check for weak policies (no security requirements)
            if (-not $policy.SecuritySettings -or $policy.SecuritySettings -eq "") {
                $color = "Yellow"
                $details = "[!] NO SECURITY REQUIREMENTS - $details"
            }

            Format-IntuneOutput -Category "Compliance" -ItemName $policy.DisplayName -Details $details -Color $color
            $exportData.CompliancePolicies += $policy
        }
    } else {
        Write-ColorOutput -Message "    No compliance policies found or access denied" -Color "Gray"
    }

    Write-Host ""

    # ========================================
    # INTUNE RBAC ROLES
    # ========================================
    Write-ColorOutput -Message "[*] ========================================" -Color "Cyan"
    Write-ColorOutput -Message "[*] INTUNE RBAC ROLES" -Color "Cyan"
    Write-ColorOutput -Message "[*] ========================================`n" -Color "Cyan"

    $roleDefinitions = Get-IntuneRoleDefinitions
    $stats.RoleDefinitions = $roleDefinitions.Count

    if ($roleDefinitions.Count -gt 0) {
        foreach ($role in $roleDefinitions) {
            $details = "[*] "
            if ($role.IsBuiltIn) { $details += "Built-in | " } else { $details += "Custom | " }
            $details += "Permissions: $($role.PermissionCount)"

            $color = "Cyan"
            if ($role.PrivilegeLevel -eq "HIGH") {
                $color = "Red"
                $details = "[!] HIGH PRIV - Full Intune access"
                $stats.HighPrivRoles++
            }

            Format-IntuneOutput -Category "Role" -ItemName $role.DisplayName -Details $details -Color $color
            $exportData.RoleDefinitions += $role
        }
    } else {
        Write-ColorOutput -Message "    No role definitions found or access denied" -Color "Gray"
    }

    Write-Host ""

    # ========================================
    # ROLE ASSIGNMENTS
    # ========================================
    Write-ColorOutput -Message "[*] ========================================" -Color "Cyan"
    Write-ColorOutput -Message "[*] ROLE ASSIGNMENTS" -Color "Cyan"
    Write-ColorOutput -Message "[*] ========================================`n" -Color "Cyan"

    $roleAssignments = Get-IntuneRoleAssignments
    $stats.RoleAssignments = $roleAssignments.Count

    if ($roleAssignments.Count -gt 0) {
        foreach ($assignment in $roleAssignments) {
            $details = "[*] Role: $($assignment.RoleDefinitionName) | Members: $($assignment.MemberCount)"

            $color = "Cyan"
            Format-IntuneOutput -Category "Assignment" -ItemName $assignment.DisplayName -Details $details -Color $color

            # Show members if available
            if ($assignment.Members -and $assignment.Members -ne "") {
                Write-ColorOutput -Message "        Members: $($assignment.Members)" -Color "Gray"
            }

            $exportData.RoleAssignments += $assignment
        }
    } else {
        Write-ColorOutput -Message "    No role assignments found or access denied" -Color "Gray"
    }

    Write-Host ""

    # ========================================
    # CONFIGURATION PROFILES
    # ========================================
    Write-ColorOutput -Message "[*] ========================================" -Color "Cyan"
    Write-ColorOutput -Message "[*] CONFIGURATION PROFILES" -Color "Cyan"
    Write-ColorOutput -Message "[*] ========================================`n" -Color "Cyan"

    $configProfiles = Get-IntuneConfigurationProfiles
    $stats.ConfigProfiles = $configProfiles.Count

    if ($configProfiles.Count -gt 0) {
        foreach ($profile in $configProfiles) {
            $details = "[*] Type: $($profile.ProfileType)"

            $color = "Cyan"
            if ($profile.Sensitivity -eq "SENSITIVE") {
                $color = "Yellow"
                $details = "[!] SENSITIVE - $($profile.ProfileType)"
                $stats.SensitiveProfiles++
            }

            Format-IntuneOutput -Category "Config" -ItemName $profile.DisplayName -Details $details -Color $color
            $exportData.ConfigurationProfiles += $profile
        }
    } else {
        Write-ColorOutput -Message "    No configuration profiles found or access denied" -Color "Gray"
    }

    Write-Host ""

    # ========================================
    # AUTOPILOT PROFILES
    # ========================================
    Write-ColorOutput -Message "[*] ========================================" -Color "Cyan"
    Write-ColorOutput -Message "[*] AUTOPILOT PROFILES" -Color "Cyan"
    Write-ColorOutput -Message "[*] ========================================`n" -Color "Cyan"

    $autopilotProfiles = Get-IntuneAutopilotProfiles
    $stats.AutopilotProfiles = $autopilotProfiles.Count

    if ($autopilotProfiles.Count -gt 0) {
        foreach ($profile in $autopilotProfiles) {
            $details = "[*] Mode: $($profile.DeploymentMode)"
            if ($profile.OOBESettings) {
                $details += " | OOBE: $($profile.OOBESettings)"
            }

            $color = "Cyan"
            # Check for risky settings
            if ($profile.OOBESettings -like "*LocalAdmin*") {
                $color = "Yellow"
                $details = "[!] LOCAL ADMIN - $details"
            }

            Format-IntuneOutput -Category "Autopilot" -ItemName $profile.DisplayName -Details $details -Color $color
            $exportData.AutopilotProfiles += $profile
        }
    } else {
        Write-ColorOutput -Message "    No Autopilot profiles found or access denied" -Color "Gray"
    }

    Write-Host ""

    # ========================================
    # MANAGED DEVICES SUMMARY
    # ========================================
    Write-ColorOutput -Message "[*] ========================================" -Color "Cyan"
    Write-ColorOutput -Message "[*] MANAGED DEVICES SUMMARY" -Color "Cyan"
    Write-ColorOutput -Message "[*] ========================================`n" -Color "Cyan"

    $deviceSummary = Get-IntuneManagedDevicesSummary
    $stats.TotalManagedDevices = $deviceSummary.TotalDevices
    $exportData.DeviceSummary = $deviceSummary

    if ($deviceSummary.TotalDevices -gt 0) {
        Write-ColorOutput -Message "    Total Enrolled Devices: $($deviceSummary.TotalDevices)" -Color "Green"
        Write-ColorOutput -Message "    Windows Devices: $($deviceSummary.WindowsDevices)" -Color "Cyan"
        Write-ColorOutput -Message "    iOS/iPadOS Devices: $($deviceSummary.iOSDevices)" -Color "Cyan"
        Write-ColorOutput -Message "    Android Devices: $($deviceSummary.AndroidDevices)" -Color "Cyan"
        Write-ColorOutput -Message "    macOS Devices: $($deviceSummary.macOSDevices)" -Color "Cyan"
        if ($deviceSummary.CompliantDevices -gt 0 -or $deviceSummary.NonCompliantDevices -gt 0) {
            Write-ColorOutput -Message "    Compliant: $($deviceSummary.CompliantDevices) | Non-Compliant: $($deviceSummary.NonCompliantDevices)" -Color "Yellow"
        }
    } else {
        Write-ColorOutput -Message "    No managed device data available or access denied" -Color "Gray"
    }

    Write-Host ""

    # ========================================
    # EXPORT
    # ========================================
    if ($ExportPath) {
        try {
            $extension = [System.IO.Path]::GetExtension($ExportPath).ToLower()

            # Prepare flat export data for CSV
            $flatExportData = @()

            foreach ($config in $exportData.EnrollmentConfigs) {
                $flatExportData += [PSCustomObject]@{
                    Category = "Enrollment Configuration"
                    Name = $config.DisplayName
                    Type = $config.ConfigType
                    Description = $config.Description
                    Priority = $config.Priority
                    CreatedDateTime = $config.CreatedDateTime
                    LastModifiedDateTime = $config.LastModifiedDateTime
                    Sensitivity = "Normal"
                    PrivilegeLevel = "N/A"
                }
            }

            foreach ($policy in $exportData.CompliancePolicies) {
                $flatExportData += [PSCustomObject]@{
                    Category = "Compliance Policy"
                    Name = $policy.DisplayName
                    Type = $policy.Platform
                    Description = $policy.Description
                    Priority = "N/A"
                    CreatedDateTime = $policy.CreatedDateTime
                    LastModifiedDateTime = $policy.LastModifiedDateTime
                    Sensitivity = if ($policy.SecuritySettings) { "Normal" } else { "Weak" }
                    PrivilegeLevel = "N/A"
                    SecuritySettings = $policy.SecuritySettings
                }
            }

            foreach ($profile in $exportData.ConfigurationProfiles) {
                $flatExportData += [PSCustomObject]@{
                    Category = "Configuration Profile"
                    Name = $profile.DisplayName
                    Type = $profile.ProfileType
                    Description = $profile.Description
                    Priority = "N/A"
                    CreatedDateTime = $profile.CreatedDateTime
                    LastModifiedDateTime = $profile.LastModifiedDateTime
                    Sensitivity = $profile.Sensitivity
                    PrivilegeLevel = "N/A"
                }
            }

            foreach ($role in $exportData.RoleDefinitions) {
                $flatExportData += [PSCustomObject]@{
                    Category = "Role Definition"
                    Name = $role.DisplayName
                    Type = if ($role.IsBuiltIn) { "Built-in" } else { "Custom" }
                    Description = $role.Description
                    Priority = "N/A"
                    CreatedDateTime = "N/A"
                    LastModifiedDateTime = "N/A"
                    Sensitivity = "N/A"
                    PrivilegeLevel = $role.PrivilegeLevel
                    PermissionCount = $role.PermissionCount
                }
            }

            foreach ($assignment in $exportData.RoleAssignments) {
                $flatExportData += [PSCustomObject]@{
                    Category = "Role Assignment"
                    Name = $assignment.DisplayName
                    Type = $assignment.RoleDefinitionName
                    Description = $assignment.Description
                    Priority = "N/A"
                    CreatedDateTime = "N/A"
                    LastModifiedDateTime = "N/A"
                    Sensitivity = "N/A"
                    PrivilegeLevel = "N/A"
                    Members = $assignment.Members
                    MemberCount = $assignment.MemberCount
                }
            }

            foreach ($autopilot in $exportData.AutopilotProfiles) {
                $flatExportData += [PSCustomObject]@{
                    Category = "Autopilot Profile"
                    Name = $autopilot.DisplayName
                    Type = $autopilot.DeploymentMode
                    Description = $autopilot.Description
                    Priority = "N/A"
                    CreatedDateTime = $autopilot.CreatedDateTime
                    LastModifiedDateTime = $autopilot.LastModifiedDateTime
                    Sensitivity = if ($autopilot.OOBESettings -like "*LocalAdmin*") { "SENSITIVE" } else { "Normal" }
                    PrivilegeLevel = "N/A"
                    OOBESettings = $autopilot.OOBESettings
                }
            }

            if ($extension -eq ".csv") {
                $flatExportData | Export-Csv -Path $ExportPath -NoTypeInformation -Force
                Write-ColorOutput -Message "[+] Results exported to: $ExportPath" -Color "Green"
            } elseif ($extension -eq ".json") {
                $exportData | ConvertTo-Json -Depth 10 | Out-File -FilePath $ExportPath -Force
                Write-ColorOutput -Message "[+] Results exported to: $ExportPath" -Color "Green"
            } elseif ($extension -eq ".html") {
                $statsFormatted = [ordered]@{
                    "Enrollment Configs" = $stats.EnrollmentConfigs
                    "Compliance Policies" = $stats.CompliancePolicies
                    "Configuration Profiles" = $stats.ConfigProfiles
                    "Sensitive Profiles" = $stats.SensitiveProfiles
                    "Role Definitions" = $stats.RoleDefinitions
                    "High Privilege Roles" = $stats.HighPrivRoles
                    "Role Assignments" = $stats.RoleAssignments
                    "Autopilot Profiles" = $stats.AutopilotProfiles
                    "Total Managed Devices" = $stats.TotalManagedDevices
                }

                $description = "Intune/Endpoint Manager enumeration results. This is the Azure equivalent of NetExec's sccm-recon6 module for SCCM infrastructure reconnaissance. Intune replaces on-premises SCCM in Azure/cloud environments."

                $success = Export-HtmlReport -Data $flatExportData -OutputPath $ExportPath -Title "Intune/Endpoint Manager Enumeration Report" -Statistics $statsFormatted -CommandName "intune-enum" -Description $description

                if ($success) {
                    Write-ColorOutput -Message "[+] HTML report exported to: $ExportPath" -Color "Green"
                }
            } else {
                # Default to CSV
                $flatExportData | Export-Csv -Path $ExportPath -NoTypeInformation -Force
                Write-ColorOutput -Message "[+] Results exported to: $ExportPath" -Color "Green"
            }
        } catch {
            Write-ColorOutput -Message "[!] Failed to export results: $_" -Color "Red"
        }
    }

    # ========================================
    # SUMMARY
    # ========================================
    Write-ColorOutput -Message "`n[*] ========================================" -Color "Yellow"
    Write-ColorOutput -Message "[*] ENUMERATION SUMMARY" -Color "Yellow"
    Write-ColorOutput -Message "[*] ========================================`n" -Color "Yellow"

    Write-ColorOutput -Message "[*] Intune Infrastructure Statistics:" -Color "Cyan"
    Write-ColorOutput -Message "    Enrollment Configurations: $($stats.EnrollmentConfigs)" -Color "White"
    Write-ColorOutput -Message "    Compliance Policies: $($stats.CompliancePolicies)" -Color "White"
    Write-ColorOutput -Message "    Configuration Profiles: $($stats.ConfigProfiles)" -Color "White"
    if ($stats.SensitiveProfiles -gt 0) {
        Write-ColorOutput -Message "    Sensitive Profiles: $($stats.SensitiveProfiles)" -Color "Yellow"
    }
    Write-ColorOutput -Message "    Role Definitions: $($stats.RoleDefinitions)" -Color "White"
    if ($stats.HighPrivRoles -gt 0) {
        Write-ColorOutput -Message "    High Privilege Roles: $($stats.HighPrivRoles)" -Color "Red"
    }
    Write-ColorOutput -Message "    Role Assignments: $($stats.RoleAssignments)" -Color "White"
    Write-ColorOutput -Message "    Autopilot Profiles: $($stats.AutopilotProfiles)" -Color "White"
    Write-ColorOutput -Message "    Total Managed Devices: $($stats.TotalManagedDevices)" -Color "Green"

    # Security Analysis
    Write-ColorOutput -Message "`n[*] Security Analysis:" -Color "Yellow"

    $securityIssues = @()

    if ($stats.SensitiveProfiles -gt 0) {
        $securityIssues += "[!] $($stats.SensitiveProfiles) SENSITIVE configuration profiles detected (VPN, WiFi, Certificates)"
    }

    if ($stats.HighPrivRoles -gt 0) {
        $securityIssues += "[!] $($stats.HighPrivRoles) HIGH PRIVILEGE Intune roles detected"
    }

    # Check for weak compliance policies
    $weakPolicies = ($exportData.CompliancePolicies | Where-Object { -not $_.SecuritySettings -or $_.SecuritySettings -eq "" }).Count
    if ($weakPolicies -gt 0) {
        $securityIssues += "[!] $weakPolicies compliance policies have NO security requirements"
    }

    # Check for risky Autopilot settings
    $riskyAutopilot = ($exportData.AutopilotProfiles | Where-Object { $_.OOBESettings -like "*LocalAdmin*" }).Count
    if ($riskyAutopilot -gt 0) {
        $securityIssues += "[!] $riskyAutopilot Autopilot profiles grant LOCAL ADMIN rights"
    }

    if ($securityIssues.Count -gt 0) {
        foreach ($issue in $securityIssues) {
            Write-ColorOutput -Message "    $issue" -Color "Red"
        }
    } else {
        Write-ColorOutput -Message "    [+] No critical security issues detected" -Color "Green"
    }

    # SCCM vs Intune comparison note
    Write-ColorOutput -Message "`n[*] NetExec SCCM-Recon6 Comparison:" -Color "Cyan"
    Write-ColorOutput -Message "    SCCM Distribution Points → Enrollment Configurations" -Color "Gray"
    Write-ColorOutput -Message "    SCCM Management Points → Compliance Policies (security enforcement)" -Color "Gray"
    Write-ColorOutput -Message "    SCCM Site Codes → Intune Tenant (single management plane)" -Color "Gray"
    Write-ColorOutput -Message "    SCCM PXE Boot → Windows Autopilot Profiles" -Color "Gray"
    Write-ColorOutput -Message "    SCCM Task Sequences → Configuration Profiles + Autopilot" -Color "Gray"
    Write-ColorOutput -Message "    SCCM Admin Roles → Intune RBAC Role Definitions & Assignments`n" -Color "Gray"
}
