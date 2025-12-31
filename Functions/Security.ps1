# AZexec - Security Functions (AV/EDR Enumeration)
# These functions are loaded into the main script scope via dot-sourcing

function Format-SecurityOutput {
    param(
        [PSCustomObject]$Device,
        [PSCustomObject]$SecurityInfo
    )
    
    $deviceName = if ($Device.DisplayName) { $Device.DisplayName } else { "UNKNOWN" }
    
    # Truncate long device names for column display
    $maxNameLength = 35
    $displayName = if ($deviceName.Length -gt $maxNameLength) {
        $deviceName.Substring(0, $maxNameLength - 3) + "..."
    } else {
        $deviceName
    }
    
    # Use device ID as "IP" equivalent (first 15 chars for alignment)
    $deviceIdShort = if ($Device.DeviceId) { 
        $Device.DeviceId.Substring(0, [Math]::Min(15, $Device.DeviceId.Length))
    } else { 
        "UNKNOWN-ID" 
    }
    
    # Build security status string
    $securityStatus = ""
    
    # Antivirus/Antimalware information
    if ($SecurityInfo.AntivirusProduct) {
        $securityStatus += "AV:$($SecurityInfo.AntivirusProduct)"
    } else {
        $securityStatus += "AV:Unknown"
    }
    
    if ($SecurityInfo.AntivirusEnabled) {
        $securityStatus += "(enabled)"
    } else {
        $securityStatus += "(disabled)"
    }
    
    if ($SecurityInfo.AntivirusVersion) {
        $securityStatus += " v$($SecurityInfo.AntivirusVersion)"
    }
    
    # EDR/XDR information
    if ($SecurityInfo.EDRProduct) {
        $securityStatus += " | EDR:$($SecurityInfo.EDRProduct)"
        if ($SecurityInfo.EDREnabled) {
            $securityStatus += "(enabled)"
        } else {
            $securityStatus += "(disabled)"
        }
    }
    
    # Microsoft Defender for Endpoint
    if ($SecurityInfo.DefenderATPOnboarded) {
        $securityStatus += " | MDE:Onboarded"
        if ($SecurityInfo.DefenderATPHealthy) {
            $securityStatus += "(healthy)"
        } else {
            $securityStatus += "(unhealthy)"
        }
    } else {
        $securityStatus += " | MDE:Not Onboarded"
    }
    
    # Firewall status
    if ($null -ne $SecurityInfo.FirewallEnabled) {
        if ($SecurityInfo.FirewallEnabled) {
            $securityStatus += " | FW:Enabled"
        } else {
            $securityStatus += " | FW:DISABLED"
        }
    }
    
    # Encryption status
    if ($SecurityInfo.EncryptionStatus) {
        $securityStatus += " | Encryption:$($SecurityInfo.EncryptionStatus)"
    }
    
    # Build output line
    $output = "AZR".PadRight(12) + 
              $deviceIdShort.PadRight(17) + 
              "443".PadRight(7) + 
              $displayName.PadRight(38) + 
              "[*] $securityStatus"
    
    # Color based on security status
    # More nuanced logic considering device OS type
    $isWindowsDevice = $Device.OperatingSystem -like "Windows*"
    $color = "Cyan"  # Default: good security posture
    
    # Determine risk level based on device type and security controls
    $hasSecurityGaps = $false
    $hasWarnings = $false
    
    # PRIORITY 1: If device is compliant, trust that (GREEN)
    # Device compliance is the most reliable indicator in Azure AD
    if ($Device.IsCompliant) {
        $color = "Green"
        
        # Only downgrade to YELLOW if we have EXPLICIT evidence of issues
        if ($isWindowsDevice) {
            # Only warn if we have actual data showing problems
            if ($SecurityInfo.FirewallEnabled -eq $false) {
                $color = "Yellow"
            }
        }
    }
    # PRIORITY 2: Critical security gaps (RED)
    elseif ($isWindowsDevice -and -not $SecurityInfo.AntivirusEnabled) {
        # Windows devices with disabled AV
        $color = "Red"
    }
    elseif (-not $Device.IsCompliant) {
        # Non-compliant devices
        $color = "Yellow"
    }
    else {
        # Unknown compliance state
        $color = "Cyan"
    }
    
    Write-ColorOutput -Message $output -Color $color
}

function Get-DefenderForEndpointStatus {
    param(
        [string]$DeviceId,
        [string]$AzureADDeviceId,
        [string]$IntuneDeviceId = $null
    )
    
    # Method 1: Try Windows Protection State via Intune (most reliable for managed devices)
    # This requires DeviceManagementManagedDevices.Read.All
    if ($IntuneDeviceId) {
        try {
            $uri = "https://graph.microsoft.com/v1.0/deviceManagement/managedDevices/$IntuneDeviceId/windowsProtectionState"
            $protectionState = Invoke-MgGraphRequest -Uri $uri -Method GET -ErrorAction Stop
            
            if ($protectionState) {
                return @{
                    Onboarded = $true
                    Healthy = ($protectionState.malwareProtectionEnabled -eq $true -and $protectionState.realTimeProtectionEnabled -eq $true)
                    RiskScore = $null
                    ExposureLevel = $null
                    AVSignatureVersion = $protectionState.signatureVersion
                    AVEngineVersion = $protectionState.engineVersion
                    AVLastQuickScan = $protectionState.lastQuickScanDateTime
                    AVLastFullScan = $protectionState.lastFullScanDateTime
                    AVMode = if ($protectionState.realTimeProtectionEnabled) { "Active" } else { "Passive" }
                    MalwareProtectionEnabled = $protectionState.malwareProtectionEnabled
                    RealTimeProtectionEnabled = $protectionState.realTimeProtectionEnabled
                    NetworkInspectionEnabled = $protectionState.networkInspectionEnabled
                    QuickScanOverdue = $protectionState.quickScanOverdue
                    FullScanOverdue = $protectionState.fullScanOverdue
                    SignatureUpdateOverdue = $protectionState.signatureUpdateOverdue
                    IsVirtualMachine = $protectionState.isVirtualMachine
                    Method = "WindowsProtectionState"
                }
            }
        } catch {
            # Continue to fallback methods
        }
    }
    
    # Method 2: Try Microsoft 365 Defender API (requires SecurityEvents.Read.All)
    try {
        $uri = "https://graph.microsoft.com/beta/security/microsoft365Defender/devices?`$filter=azureAdDeviceId eq '$AzureADDeviceId'"
        $mdeDevice = Invoke-MgGraphRequest -Uri $uri -Method GET -ErrorAction Stop
        
        if ($mdeDevice.value -and $mdeDevice.value.Count -gt 0) {
            $device = $mdeDevice.value[0]
            return @{
                Onboarded = $true
                Healthy = ($device.healthStatus -eq "Active")
                RiskScore = $device.riskScore
                ExposureLevel = $device.exposureLevel
                AVSignatureVersion = $device.defenderAvStatus.engineVersion
                AVLastScanTime = $device.defenderAvStatus.lastQuickScanDateTime
                AVMode = $device.defenderAvStatus.antivirusMode
                Method = "M365Defender"
            }
        }
    } catch {
        # Continue to fallback
    }
    
    return @{
        Onboarded = $false
        Healthy = $false
        Method = "None"
    }
}

function Get-IntuneDeviceCompliance {
    param(
        [string]$AzureADDeviceId,
        [string]$IntuneDeviceId = $null
    )
    
    try {
        # Query Intune device compliance policies
        # This requires DeviceManagementManagedDevices.Read.All
        $intuneDevice = $null
        
        if ($IntuneDeviceId) {
            # If we already have the Intune device ID, query directly with all properties
            $uri = "https://graph.microsoft.com/v1.0/deviceManagement/managedDevices/$IntuneDeviceId`?`$select=id,complianceState,osVersion,lastSyncDateTime,deviceHealthAttestationState,isEncrypted,managementAgent,deviceName"
            $intuneDevice = Invoke-MgGraphRequest -Uri $uri -Method GET -ErrorAction Stop
        } else {
            # Otherwise, search by Azure AD Device ID with explicit property selection
            $uri = "https://graph.microsoft.com/v1.0/deviceManagement/managedDevices?`$filter=azureADDeviceId eq '$AzureADDeviceId'&`$select=id,complianceState,osVersion,lastSyncDateTime,deviceHealthAttestationState,isEncrypted,managementAgent,deviceName"
            $result = Invoke-MgGraphRequest -Uri $uri -Method GET -ErrorAction Stop
            
            if ($result.value -and $result.value.Count -gt 0) {
                $intuneDevice = $result.value[0]
            }
        }
        
        if ($intuneDevice) {
            # Extract Device Health Attestation State if available
            $healthState = $intuneDevice.deviceHealthAttestationState
            
            # Parse health state properties (they vary by OS)
            $avEnabled = $null
            $fwEnabled = $null
            $blEnabled = $false
            
            if ($healthState) {
                # Try different property names for AV status
                if ($null -ne $healthState.dataExcutionPolicy) {
                    $avEnabled = ($healthState.dataExcutionPolicy -eq "Enabled")
                }
                # Try different property names for Firewall
                if ($null -ne $healthState.windowsFirewall) {
                    $fwEnabled = ($healthState.windowsFirewall -eq "Enabled")
                } elseif ($null -ne $healthState.firewall) {
                    $fwEnabled = ($healthState.firewall -eq "Enabled")
                }
                # BitLocker status
                if ($null -ne $healthState.bitLockerStatus) {
                    $blEnabled = ($healthState.bitLockerStatus -eq "Enabled")
                }
            }
            
            # Also check for encryption state property directly on device
            if (-not $blEnabled -and $intuneDevice.isEncrypted -eq $true) {
                $blEnabled = $true
            }
            
            return @{
                CompliantState = $intuneDevice.complianceState
                OSVersion = $intuneDevice.osVersion
                LastSyncDateTime = $intuneDevice.lastSyncDateTime
                DeviceHealthAttestationState = $healthState
                AntivirusEnabled = $avEnabled
                FirewallEnabled = $fwEnabled
                BitLockerEnabled = $blEnabled
                IsEncrypted = $intuneDevice.isEncrypted
                SecureBootEnabled = if ($healthState) { $healthState.secureBootEnabled -eq $true } else { $false }
                IntuneDeviceId = $intuneDevice.id
                Found = $true
            }
        }
    } catch {
        # Silently handle permission errors or API issues
    }
    
    return $null
}

function Get-DeviceSecurityInfo {
    param(
        [PSCustomObject]$Device
    )
    
    $securityInfo = @{
        AntivirusProduct = $null
        AntivirusEnabled = $false
        AntivirusVersion = $null
        EDRProduct = $null
        EDREnabled = $false
        DefenderATPOnboarded = $false
        DefenderATPHealthy = $false
        FirewallEnabled = $null
        EncryptionStatus = $null
        ComplianceState = $null
        RiskScore = $null
    }
    
    # IMPORTANT: Intune's azureADDeviceId matches Azure AD's DeviceId property, NOT the Id property!
    # - $Device.Id = Azure AD Object ID (used for Graph API /devices/{id})
    # - $Device.DeviceId = The actual device identifier that Intune uses
    $deviceIdForIntune = $Device.DeviceId
    $intuneDeviceId = $null
    
    # First, try to get Intune device info (we'll need the Intune device ID for protection state)
    try {
        # Explicitly select isEncrypted and other relevant properties
        $uri = "https://graph.microsoft.com/v1.0/deviceManagement/managedDevices?`$filter=azureADDeviceId eq '$deviceIdForIntune'&`$select=id,complianceState,osVersion,lastSyncDateTime,deviceHealthAttestationState,isEncrypted"
        $intuneResult = Invoke-MgGraphRequest -Uri $uri -Method GET -ErrorAction Stop
        
        if ($intuneResult.value -and $intuneResult.value.Count -gt 0) {
            $intuneDeviceId = $intuneResult.value[0].id
            
            # Check encryption status directly from the first query
            if ($intuneResult.value[0].isEncrypted -eq $true) {
                $securityInfo.EncryptionStatus = "Encrypted (BitLocker)"
            }
        }
    } catch {
        # Continue without Intune device ID
    }
    
    try {
        # Try to get Microsoft Defender for Endpoint / Windows Protection status
        $mdeStatus = Get-DefenderForEndpointStatus -DeviceId $Device.DeviceId -AzureADDeviceId $deviceIdForIntune -IntuneDeviceId $intuneDeviceId
        if ($mdeStatus.Onboarded) {
            $securityInfo.DefenderATPOnboarded = $true
            $securityInfo.DefenderATPHealthy = $mdeStatus.Healthy
            $securityInfo.RiskScore = $mdeStatus.RiskScore
            
            # If MDE/Defender is detected, use the detailed info
            $securityInfo.AntivirusProduct = "Microsoft Defender"
            $securityInfo.AntivirusEnabled = ($mdeStatus.AVMode -eq "Active" -or $mdeStatus.RealTimeProtectionEnabled -eq $true)
            $securityInfo.AntivirusVersion = $mdeStatus.AVSignatureVersion
            $securityInfo.EDRProduct = "Microsoft Defender for Endpoint"
            $securityInfo.EDREnabled = $true
            
            # Store the detection method for debugging
            $securityInfo | Add-Member -NotePropertyName "DetectionMethod" -NotePropertyValue $mdeStatus.Method -Force
        }
    } catch {
        # Silently continue if MDE status cannot be retrieved
    }
    
    try {
        # Try to get Intune device compliance information
        $intuneInfo = Get-IntuneDeviceCompliance -AzureADDeviceId $deviceIdForIntune -IntuneDeviceId $intuneDeviceId
        if ($intuneInfo) {
            $securityInfo.ComplianceState = $intuneInfo.CompliantState
            
            # Check isEncrypted property for BitLocker
            if ($intuneInfo.IsEncrypted -eq $true) {
                $securityInfo.EncryptionStatus = "Encrypted (Intune)"
            }
            
            # If Intune data available, use it to supplement security info
            if ($null -ne $intuneInfo.AntivirusEnabled) {
                if (-not $securityInfo.AntivirusProduct) {
                    $securityInfo.AntivirusProduct = "Windows Defender (via Intune)"
                }
                $securityInfo.AntivirusEnabled = $intuneInfo.AntivirusEnabled
            }
            
            if ($null -ne $intuneInfo.FirewallEnabled) {
                $securityInfo.FirewallEnabled = $intuneInfo.FirewallEnabled
            }
            
            if ($intuneInfo.BitLockerEnabled) {
                $securityInfo.EncryptionStatus = "BitLocker Enabled"
            }
            
            if ($intuneInfo.SecureBootEnabled) {
                $securityInfo.SecureBootEnabled = $true
            }
        }
    } catch {
        # Silently continue if Intune info cannot be retrieved
    }
    
    # If we still don't have AV info, try to infer from device properties
    if (-not $securityInfo.AntivirusProduct) {
        $isWindowsDevice = $Device.OperatingSystem -like "Windows*"
        
        # Check if device is compliant - often indicates AV is present
        if ($Device.IsCompliant) {
            if ($isWindowsDevice) {
                # Windows compliant devices typically have Defender
                $securityInfo.AntivirusProduct = "Assumed Present (Device Compliant)"
                $securityInfo.AntivirusEnabled = $true
            } else {
                # Non-Windows compliant devices (iOS, Android) likely have built-in protection
                $securityInfo.AntivirusProduct = "Assumed Present (Device Compliant)"
                $securityInfo.AntivirusEnabled = $true
            }
        } else {
            # Non-compliant devices - cannot assume AV status
            $securityInfo.AntivirusProduct = "Unknown"
            $securityInfo.AntivirusEnabled = $false
        }
    }
    
    return [PSCustomObject]$securityInfo
}

function Invoke-SecurityEnumeration {
    param(
        [string]$Filter = "all",
        [string]$ExportPath
    )
    
    Write-ColorOutput -Message "`n[*] AZX - Azure/Entra Enumeration Tool" -Color "Yellow"
    Write-ColorOutput -Message "[*] Command: Security Enumeration (AV/EDR)" -Color "Yellow"
    Write-ColorOutput -Message "[*] Azure Equivalent of: nxc smb <ip> -u user -p pass -M enum_av`n" -Color "Yellow"
    
    Write-ColorOutput -Message "[*] This command enumerates:" -Color "Cyan"
    Write-ColorOutput -Message "    • Antivirus/Antimalware products and status" -Color "Gray"
    Write-ColorOutput -Message "    • EDR/XDR solutions (Microsoft Defender for Endpoint)" -Color "Gray"
    Write-ColorOutput -Message "    • Firewall status" -Color "Gray"
    Write-ColorOutput -Message "    • Encryption status (BitLocker)" -Color "Gray"
    Write-ColorOutput -Message "    • Device compliance posture" -Color "Gray"
    Write-ColorOutput -Message "    • Security risk scores`n" -Color "Gray"
    
    Write-ColorOutput -Message "[*] Required Permissions:" -Color "Yellow"
    Write-ColorOutput -Message "    • Device.Read.All (basic device enumeration)" -Color "Gray"
    Write-ColorOutput -Message "    • SecurityEvents.Read.All or ThreatIndicators.Read.All (MDE status)" -Color "Gray"
    Write-ColorOutput -Message "    • DeviceManagementManagedDevices.Read.All (Intune compliance)`n" -Color "Gray"
    
    # Check current permissions
    try {
        $context = Get-MgContext
        if ($context -and $context.Scopes) {
            $hasSecurityEvents = $context.Scopes -contains "SecurityEvents.Read.All" -or $context.Scopes -contains "ThreatIndicators.Read.All"
            $hasIntune = $context.Scopes -contains "DeviceManagementManagedDevices.Read.All"
            
            if (-not $hasSecurityEvents) {
                Write-ColorOutput -Message "[!] Warning: SecurityEvents.Read.All permission not detected in current session" -Color "Yellow"
                Write-ColorOutput -Message "    MDE status may not be available (this permission requires admin consent)`n" -Color "Gray"
            }
            if (-not $hasIntune) {
                Write-ColorOutput -Message "[!] Warning: DeviceManagementManagedDevices.Read.All permission not detected" -Color "Yellow"
                Write-ColorOutput -Message "    BitLocker/Firewall status may not be available`n" -Color "Gray"
            }
        }
    } catch {
        # Silently continue if we can't check permissions
    }
    
    # Get all devices
    Write-ColorOutput -Message "[*] Retrieving devices from Azure/Entra ID..." -Color "Yellow"
    
    try {
        $allDevices = Get-MgDevice -All -ErrorAction Stop
        Write-ColorOutput -Message "[+] Retrieved $($allDevices.Count) total devices`n" -Color "Green"
    } catch {
        Write-ColorOutput -Message "[!] Failed to retrieve devices: $_" -Color "Red"
        Write-ColorOutput -Message "[!] Ensure you have Device.Read.All permissions" -Color "Red"
        return
    }
    
    # Apply filter (same as hosts command)
    $devices = switch ($Filter) {
        "windows" { $allDevices | Where-Object { $_.OperatingSystem -like "Windows*" } }
        "azuread" { $allDevices | Where-Object { $_.TrustType -eq "AzureAd" } }
        "hybrid" { $allDevices | Where-Object { $_.TrustType -eq "ServerAd" } }
        "compliant" { $allDevices | Where-Object { $_.IsCompliant -eq $true } }
        "noncompliant" { $allDevices | Where-Object { $_.IsCompliant -eq $false } }
        "disabled" { $allDevices | Where-Object { $_.AccountEnabled -eq $false } }
        default { $allDevices }
    }
    
    if ($devices.Count -eq 0) {
        Write-ColorOutput -Message "[!] No devices found matching filter: $Filter" -Color "Red"
        return
    }
    
    Write-ColorOutput -Message "[*] Enumerating security posture for $($devices.Count) devices..." -Color "Yellow"
    Write-ColorOutput -Message "[*] Note: This may take a while for large environments`n" -Color "Cyan"
    
    # Prepare export data
    $exportData = @()
    
    # Statistics
    $stats = @{
        TotalDevices = $devices.Count
        MDEOnboarded = 0
        MDEHealthy = 0
        AVEnabled = 0
        AVDisabled = 0
        FirewallEnabled = 0
        FirewallDisabled = 0
        Encrypted = 0
        HighRisk = 0
        MediumRisk = 0
        LowRisk = 0
    }
    
    # Track devices with issues for detailed reporting
    $issueDevices = @{
        AVDisabled = @()
        FirewallDisabled = @()
        NotEncrypted = @()
        MDENotOnboarded = @()
        HighRisk = @()
    }
    
    # Enumerate security info for each device
    $counter = 0
    foreach ($device in $devices) {
        $counter++
        Write-Progress -Activity "Enumerating Security Posture" -Status "Processing device $counter of $($devices.Count)" -PercentComplete (($counter / $devices.Count) * 100)
        
        $securityInfo = Get-DeviceSecurityInfo -Device $device
        
        # Update statistics and track devices with issues
        $deviceName = $device.DisplayName
        $isWindowsDevice = $device.OperatingSystem -like "Windows*"
        
        if ($securityInfo.DefenderATPOnboarded) { 
            $stats.MDEOnboarded++ 
        } elseif ($isWindowsDevice) {
            $issueDevices.MDENotOnboarded += $deviceName
        }
        
        if ($securityInfo.DefenderATPHealthy) { $stats.MDEHealthy++ }
        
        if ($securityInfo.AntivirusEnabled) { 
            $stats.AVEnabled++ 
        } else { 
            $stats.AVDisabled++
            $issueDevices.AVDisabled += $deviceName
        }
        
        if ($securityInfo.FirewallEnabled -eq $true) { 
            $stats.FirewallEnabled++ 
        }
        if ($securityInfo.FirewallEnabled -eq $false) { 
            $stats.FirewallDisabled++
            $issueDevices.FirewallDisabled += $deviceName
        }
        
        if ($securityInfo.EncryptionStatus -like "*Enabled*") { 
            $stats.Encrypted++ 
        } elseif ($isWindowsDevice) {
            $issueDevices.NotEncrypted += $deviceName
        }
        
        if ($securityInfo.RiskScore -eq "High") { 
            $stats.HighRisk++
            $issueDevices.HighRisk += $deviceName
        }
        elseif ($securityInfo.RiskScore -eq "Medium") { $stats.MediumRisk++ }
        elseif ($securityInfo.RiskScore -eq "Low") { $stats.LowRisk++ }
        
        Format-SecurityOutput -Device $device -SecurityInfo $securityInfo
        
        # Collect for export
        if ($ExportPath) {
            $exportData += [PSCustomObject]@{
                DeviceId = $device.DeviceId
                DisplayName = $device.DisplayName
                OperatingSystem = $device.OperatingSystem
                OSVersion = $device.OperatingSystemVersion
                TrustType = $device.TrustType
                IsCompliant = $device.IsCompliant
                AntivirusProduct = $securityInfo.AntivirusProduct
                AntivirusEnabled = $securityInfo.AntivirusEnabled
                AntivirusVersion = $securityInfo.AntivirusVersion
                EDRProduct = $securityInfo.EDRProduct
                EDREnabled = $securityInfo.EDREnabled
                MDEOnboarded = $securityInfo.DefenderATPOnboarded
                MDEHealthy = $securityInfo.DefenderATPHealthy
                FirewallEnabled = $securityInfo.FirewallEnabled
                EncryptionStatus = $securityInfo.EncryptionStatus
                ComplianceState = $securityInfo.ComplianceState
                RiskScore = $securityInfo.RiskScore
            }
        }
    }
    
    Write-Progress -Activity "Enumerating Security Posture" -Completed
    
    # Export if requested
    if ($ExportPath) {
        try {
            $extension = [System.IO.Path]::GetExtension($ExportPath).ToLower()
            
            if ($extension -eq ".csv") {
                $exportData | Export-Csv -Path $ExportPath -NoTypeInformation -Force
                Write-ColorOutput -Message "`n[+] Results exported to: $ExportPath" -Color "Green"
            } elseif ($extension -eq ".json") {
                $exportData | ConvertTo-Json -Depth 5 | Out-File -FilePath $ExportPath -Force
                Write-ColorOutput -Message "`n[+] Results exported to: $ExportPath" -Color "Green"
            } elseif ($extension -eq ".html") {
                $statsFormatted = [ordered]@{
                    "Total Devices" = $stats.TotalDevices
                    "MDE Onboarded" = $stats.MDEOnboarded
                    "MDE Healthy" = $stats.MDEHealthy
                    "Antivirus Enabled" = $stats.AVEnabled
                    "Antivirus DISABLED" = $stats.AVDisabled
                    "Firewall Enabled" = $stats.FirewallEnabled
                    "Firewall DISABLED" = $stats.FirewallDisabled
                    "Encrypted Devices" = $stats.Encrypted
                    "High Risk Devices" = $stats.HighRisk
                    "Medium Risk Devices" = $stats.MediumRisk
                    "Low Risk Devices" = $stats.LowRisk
                }
                
                $description = "Security posture enumeration for Azure/Entra ID devices. This report shows antivirus, EDR, firewall, and encryption status. Azure equivalent of NetExec's 'nxc smb -M enum_av' module."
                
                $success = Export-HtmlReport -Data $exportData -OutputPath $ExportPath -Title "Security Enumeration Report (AV/EDR)" -Statistics $statsFormatted -CommandName "av-enum" -Description $description
                
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
    
    Write-ColorOutput -Message "`n[*] Enumeration complete!" -Color "Green"
    
    # Check if we got MDE or Intune data
    $windowsDevices = ($devices | Where-Object { $_.OperatingSystem -like "Windows*" }).Count
    
    if ($stats.MDEOnboarded -eq 0 -and $windowsDevices -gt 0) {
        Write-ColorOutput -Message "`n[!] Note: No Microsoft Defender for Endpoint (MDE) data was retrieved." -Color "Yellow"
        Write-ColorOutput -Message "[*] Possible reasons:" -Color "Cyan"
        Write-ColorOutput -Message "    1. Permission 'SecurityEvents.Read.All' requires ADMIN CONSENT" -Color "Yellow"
        Write-ColorOutput -Message "       → Run: Connect-MgGraph -Scopes 'SecurityEvents.Read.All' (as admin)" -Color "Gray"
        Write-ColorOutput -Message "    2. Permission was requested but not yet consented by admin" -Color "Gray"
        Write-ColorOutput -Message "    3. API endpoint requires additional setup or licensing" -Color "Gray"
        Write-ColorOutput -Message "[*] Even if you have E5 licenses, admin consent is required for this API" -Color "Yellow"
    }
    
    if ($stats.Encrypted -eq 0 -and $windowsDevices -gt 0) {
        Write-ColorOutput -Message "`n[!] Note: No BitLocker/Intune encryption data was retrieved." -Color "Yellow"
        Write-ColorOutput -Message "[*] Possible reasons:" -Color "Cyan"
        Write-ColorOutput -Message "    1. Permission 'DeviceManagementManagedDevices.Read.All' may require ADMIN CONSENT" -Color "Yellow"
        Write-ColorOutput -Message "       → Run: Connect-MgGraph -Scopes 'DeviceManagementManagedDevices.Read.All' (as admin)" -Color "Gray"
        Write-ColorOutput -Message "    2. Devices not enrolled in Intune or Device Health Attestation not enabled" -Color "Gray"
        Write-ColorOutput -Message "[*] Alternative: Use .\azx.ps1 bitlocker-enum (queries VMs directly via Azure ARM)" -Color "Cyan"
    }
    
    # Display summary statistics
    Write-ColorOutput -Message "`n[*] Security Posture Summary:" -Color "Yellow"
    Write-ColorOutput -Message "    Total Devices: $($stats.TotalDevices)" -Color "Cyan"
    Write-ColorOutput -Message "    Microsoft Defender for Endpoint (MDE):" -Color "Cyan"
    Write-ColorOutput -Message "      • Onboarded: $($stats.MDEOnboarded)" -Color "Green"
    Write-ColorOutput -Message "      • Healthy: $($stats.MDEHealthy)" -Color "Green"
    Write-ColorOutput -Message "    Antivirus/Antimalware:" -Color "Cyan"
    Write-ColorOutput -Message "      • Enabled: $($stats.AVEnabled)" -Color "Green"
    
    if ($stats.AVDisabled -gt 0) {
        Write-ColorOutput -Message "      • DISABLED: $($stats.AVDisabled)" -Color "Red"
    } else {
        Write-ColorOutput -Message "      • Disabled: $($stats.AVDisabled)" -Color "Gray"
    }
    
    Write-ColorOutput -Message "    Firewall:" -Color "Cyan"
    Write-ColorOutput -Message "      • Enabled: $($stats.FirewallEnabled)" -Color "Green"
    
    if ($stats.FirewallDisabled -gt 0) {
        Write-ColorOutput -Message "      • DISABLED: $($stats.FirewallDisabled)" -Color "Red"
    } else {
        Write-ColorOutput -Message "      • Disabled: $($stats.FirewallDisabled)" -Color "Gray"
    }
    
    Write-ColorOutput -Message "    Encryption:" -Color "Cyan"
    Write-ColorOutput -Message "      • Encrypted: $($stats.Encrypted)" -Color "Green"
    
    if ($stats.HighRisk -gt 0 -or $stats.MediumRisk -gt 0) {
        Write-ColorOutput -Message "    Risk Assessment:" -Color "Cyan"
        if ($stats.HighRisk -gt 0) {
            Write-ColorOutput -Message "      • HIGH RISK: $($stats.HighRisk)" -Color "Red"
        }
        if ($stats.MediumRisk -gt 0) {
            Write-ColorOutput -Message "      • Medium Risk: $($stats.MediumRisk)" -Color "Yellow"
        }
        if ($stats.LowRisk -gt 0) {
            Write-ColorOutput -Message "      • Low Risk: $($stats.LowRisk)" -Color "Green"
        }
    }
    
    # Security recommendations
    Write-ColorOutput -Message "`n[*] Security Recommendations:" -Color "Yellow"
    
    if ($issueDevices.AVDisabled.Count -gt 0) {
        Write-ColorOutput -Message "    [!] $($issueDevices.AVDisabled.Count) devices have DISABLED antivirus - HIGH RISK!" -Color "Red"
        foreach ($deviceName in $issueDevices.AVDisabled) {
            Write-ColorOutput -Message "        → $deviceName" -Color "Red"
        }
    }
    
    if ($issueDevices.FirewallDisabled.Count -gt 0) {
        Write-ColorOutput -Message "    [!] $($issueDevices.FirewallDisabled.Count) devices have DISABLED firewall - HIGH RISK!" -Color "Red"
        foreach ($deviceName in $issueDevices.FirewallDisabled) {
            Write-ColorOutput -Message "        → $deviceName" -Color "Red"
        }
    }
    
    if ($issueDevices.MDENotOnboarded.Count -gt 0) {
        Write-ColorOutput -Message "    [!] $($issueDevices.MDENotOnboarded.Count) Windows devices NOT onboarded to Microsoft Defender for Endpoint" -Color "Yellow"
        foreach ($deviceName in $issueDevices.MDENotOnboarded) {
            Write-ColorOutput -Message "        → $deviceName" -Color "Yellow"
        }
        Write-ColorOutput -Message "        Consider onboarding to MDE for enhanced threat protection" -Color "Gray"
    }
    
    if ($issueDevices.NotEncrypted.Count -gt 0) {
        Write-ColorOutput -Message "    [!] $($issueDevices.NotEncrypted.Count) Windows devices NOT encrypted (BitLocker)" -Color "Yellow"
        foreach ($deviceName in $issueDevices.NotEncrypted) {
            Write-ColorOutput -Message "        → $deviceName" -Color "Yellow"
        }
        Write-ColorOutput -Message "        Enable BitLocker to protect data at rest" -Color "Gray"
    }
    
    if ($issueDevices.HighRisk.Count -gt 0) {
        Write-ColorOutput -Message "    [!] $($issueDevices.HighRisk.Count) HIGH RISK devices detected!" -Color "Red"
        foreach ($deviceName in $issueDevices.HighRisk) {
            Write-ColorOutput -Message "        → $deviceName" -Color "Red"
        }
    }
    
    # Check if everything is good
    $noIssues = ($issueDevices.AVDisabled.Count -eq 0) -and 
                ($issueDevices.FirewallDisabled.Count -eq 0) -and 
                ($issueDevices.MDENotOnboarded.Count -eq 0) -and 
                ($issueDevices.NotEncrypted.Count -eq 0)
    
    if ($noIssues) {
        Write-ColorOutput -Message "    [+] Excellent security posture! All Windows devices have AV enabled, MDE onboarded, and BitLocker encryption" -Color "Green"
    }
}

