# AZexec - Device Enumeration Functions
# These functions are loaded into the main script scope via dot-sourcing
function Format-DeviceOutput {
    param(
        [PSCustomObject]$Device,
        [string]$Owner = $null
    )
    
    # Parse OS and version info
    $osName = if ($Device.OperatingSystem) { 
        $Device.OperatingSystem -replace "Windows ", "Win" 
    } else { 
        "Unknown" 
    }
    
    $osVersion = if ($Device.OperatingSystemVersion) { 
        $Device.OperatingSystemVersion 
    } else { 
        "0" 
    }
    
    # Determine trust type/join type
    $joinType = switch ($Device.TrustType) {
        "AzureAd" { "AzureAD" }
        "ServerAd" { "Hybrid" }
        "Workplace" { "Workplace" }
        default { $Device.TrustType }
    }
    
    # Compliance and status
    $compliant = if ($Device.IsCompliant) { "True" } else { "False" }
    $enabled = if ($Device.AccountEnabled) { "True" } else { "False" }
    
    # Format output similar to netexec SMB output
    $deviceName = if ($Device.DisplayName) { $Device.DisplayName } else { "UNKNOWN" }
    
    # Truncate long device names for column display (but show full name in details)
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
    
    $output = "AZR".PadRight(12) + 
              $deviceIdShort.PadRight(17) + 
              "443".PadRight(7) + 
              $displayName.PadRight(38) + 
              "[*] $osName $osVersion (name:$deviceName) (trust:$joinType) (compliant:$compliant) (enabled:$enabled)"
    
    if ($Owner) {
        $output += " (owner:$Owner)"
    }
    
    # Color based on status
    $color = "Cyan"
    if (-not $Device.AccountEnabled) {
        $color = "DarkGray"
    } elseif (-not $Device.IsCompliant) {
        $color = "Yellow"
    }
    
    Write-ColorOutput -Message $output -Color $color
}

# Get device owners
function Get-DeviceOwners {
    param(
        [string]$DeviceId
    )
    
    try {
        $owners = Get-MgDeviceRegisteredOwner -DeviceId $DeviceId -ErrorAction SilentlyContinue
        if ($owners) {
            $ownerNames = @()
            foreach ($owner in $owners) {
                if ($owner.AdditionalProperties.userPrincipalName) {
                    $ownerNames += $owner.AdditionalProperties.userPrincipalName
                }
            }
            return ($ownerNames -join ", ")
        }
    } catch {
        return $null
    }
    
    return $null
}

# Filter devices based on criteria
function Get-FilteredDevices {
    param(
        [array]$Devices,
        [string]$Filter
    )
    
    switch ($Filter) {
        "windows" {
            return $Devices | Where-Object { $_.OperatingSystem -like "Windows*" }
        }
        "azuread" {
            return $Devices | Where-Object { $_.TrustType -eq "AzureAd" }
        }
        "hybrid" {
            return $Devices | Where-Object { $_.TrustType -eq "ServerAd" }
        }
        "compliant" {
            return $Devices | Where-Object { $_.IsCompliant -eq $true }
        }
        "noncompliant" {
            return $Devices | Where-Object { $_.IsCompliant -eq $false }
        }
        "disabled" {
            return $Devices | Where-Object { $_.AccountEnabled -eq $false }
        }
        default {
            return $Devices
        }
    }
}

# Main host enumeration function
function Invoke-HostEnumeration {
    param(
        [string]$Filter,
        [bool]$ShowOwners,
        [string]$ExportPath
    )
    
    Write-ColorOutput -Message "`n[*] AZX - Azure/Entra Enumeration Tool" -Color "Yellow"
    Write-ColorOutput -Message "[*] Command: Host Enumeration" -Color "Yellow"
    Write-ColorOutput -Message "[*] Filter: $Filter`n" -Color "Yellow"
    
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
    
    # Apply filter
    $devices = Get-FilteredDevices -Devices $allDevices -Filter $Filter
    
    if ($devices.Count -eq 0) {
        Write-ColorOutput -Message "[!] No devices found matching filter: $Filter" -Color "Red"
        return
    }
    
    Write-ColorOutput -Message "[*] Displaying $($devices.Count) devices after filtering`n" -Color "Green"
    
    # Prepare export data
    $exportData = @()
    
    # Enumerate devices
    foreach ($device in $devices) {
        $owner = $null
        if ($ShowOwners) {
            $owner = Get-DeviceOwners -DeviceId $device.Id
        }
        
        Format-DeviceOutput -Device $device -Owner $owner
        
        # Collect for export
        if ($ExportPath) {
            $exportData += [PSCustomObject]@{
                DeviceId             = $device.DeviceId
                DisplayName          = $device.DisplayName
                OperatingSystem      = $device.OperatingSystem
                OperatingSystemVersion = $device.OperatingSystemVersion
                TrustType            = $device.TrustType
                IsCompliant          = $device.IsCompliant
                AccountEnabled       = $device.AccountEnabled
                ApproximateLastSignInDateTime = $device.ApproximateLastSignInDateTime
                RegisteredOwners     = $owner
            }
        }
    }
    
    # Calculate summary statistics
    $windowsCount = ($devices | Where-Object { $_.OperatingSystem -like "Windows*" }).Count
    $azureAdCount = ($devices | Where-Object { $_.TrustType -eq "AzureAd" }).Count
    $hybridCount = ($devices | Where-Object { $_.TrustType -eq "ServerAd" }).Count
    $compliantCount = ($devices | Where-Object { $_.IsCompliant -eq $true }).Count
    $enabledCount = ($devices | Where-Object { $_.AccountEnabled -eq $true }).Count
    
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
                $stats = [ordered]@{
                    "Total Devices" = $devices.Count
                    "Windows Devices" = $windowsCount
                    "Azure Entra ID Joined" = $azureAdCount
                    "Hybrid Joined" = $hybridCount
                    "Compliant Devices" = $compliantCount
                    "Enabled Devices" = $enabledCount
                }
                
                $description = "Comprehensive device enumeration from Azure/Entra ID. Filter applied: $Filter"
                
                $success = Export-HtmlReport -Data $exportData -OutputPath $ExportPath -Title "Device Enumeration Report" -Statistics $stats -CommandName "hosts" -Description $description
                
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
    
    # Display summary statistics
    Write-ColorOutput -Message "`n[*] Summary:" -Color "Yellow"
    Write-ColorOutput -Message "    Total Devices: $($devices.Count)" -Color "Cyan"
    Write-ColorOutput -Message "    Windows Devices: $windowsCount" -Color "Cyan"
    Write-ColorOutput -Message "    Azure Entra ID Joined: $azureAdCount" -Color "Cyan"
    Write-ColorOutput -Message "    Hybrid Joined: $hybridCount" -Color "Cyan"
    Write-ColorOutput -Message "    Compliant: $compliantCount" -Color "Cyan"
    Write-ColorOutput -Message "    Enabled: $enabledCount" -Color "Cyan"
}

