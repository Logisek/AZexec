<#
    This file is part of the toolkit EvilMist
    Copyright (C) 2025 Logisek
    https://github.com/Logisek/AZexec

    AZexec - The Azure Execution Tool.

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.

    For more see the file 'LICENSE' for copying permission.
#>

<#
.SYNOPSIS
    A PowerShell-based Azure/Entra enumeration tool with netexec-style output.

.DESCRIPTION
    AZX is a PowerShell 7 compatible enumeration tool designed to provide netexec-style 
    output for Azure/Entra ID environments. It queries Microsoft Graph API to enumerate 
    devices, users, and other cloud resources accessible to the current authenticated user.
    
    Current capabilities:
    - Device enumeration from Azure/Entra ID
    - Netexec-style formatted output
    - Filter by OS, trust type, compliance status
    - Device owner enumeration
    
    Future capabilities (planned):
    - User enumeration
    - Group membership analysis
    - Application enumeration
    - Service principal discovery
    - Conditional access policy review
    - Role assignments enumeration

.PARAMETER Command
    The operation to perform. Currently supported:
    - hosts: Enumerate devices from Azure/Entra ID

.PARAMETER Filter
    Optional filter for device enumeration:
    - windows: Only Windows devices
    - azuread: Only Azure AD joined devices
    - hybrid: Only Hybrid joined devices
    - compliant: Only compliant devices
    - noncompliant: Only non-compliant devices
    - disabled: Only disabled devices

.PARAMETER NoColor
    Disable colored output.

.PARAMETER ShowOwners
    Display device owners (slower, makes additional API calls).

.PARAMETER ExportPath
    Optional path to export results to CSV or JSON.

.PARAMETER Scopes
    Microsoft Graph scopes to request. Default: "Device.Read.All"
    You can specify additional scopes as comma-separated values.

.EXAMPLE
    .\azx.ps1 hosts
    Enumerate all devices in the Azure/Entra tenant

.EXAMPLE
    .\azx.ps1 hosts -Filter windows
    Enumerate only Windows devices

.EXAMPLE
    .\azx.ps1 hosts -Filter azuread -ShowOwners
    Enumerate Azure AD joined devices with their owners

.EXAMPLE
    .\azx.ps1 hosts -Filter noncompliant -ExportPath devices.csv
    Enumerate non-compliant devices and export to CSV

.EXAMPLE
    .\azx.ps1 hosts -NoColor
    Enumerate devices without colored output

.NOTES
    Requires PowerShell 7+
    Requires Microsoft.Graph PowerShell module
    Requires appropriate Azure/Entra permissions
    First run will prompt for authentication
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true, Position = 0)]
    [ValidateSet("hosts")]
    [string]$Command,
    
    [Parameter(Mandatory = $false)]
    [ValidateSet("windows", "azuread", "hybrid", "compliant", "noncompliant", "disabled", "all")]
    [string]$Filter = "all",
    
    [Parameter(Mandatory = $false)]
    [switch]$NoColor,
    
    [Parameter(Mandatory = $false)]
    [switch]$ShowOwners,
    
    [Parameter(Mandatory = $false)]
    [string]$ExportPath,
    
    [Parameter(Mandatory = $false)]
    [string]$Scopes = "Device.Read.All"
)

# Color output functions
function Write-ColorOutput {
    param(
        [string]$Message,
        [string]$Color = "White"
    )
    
    if ($NoColor) {
        Write-Host $Message
    } else {
        Write-Host $Message -ForegroundColor $Color
    }
}

# Check and import Microsoft.Graph module
function Initialize-GraphModule {
    Write-ColorOutput -Message "[*] Checking Microsoft.Graph module..." -Color "Yellow"
    
    if (-not (Get-Module -ListAvailable -Name Microsoft.Graph.Authentication)) {
        Write-ColorOutput -Message "[!] Microsoft.Graph module not found. Installing..." -Color "Yellow"
        try {
            Install-Module Microsoft.Graph -Scope CurrentUser -Force -AllowClobber
            Write-ColorOutput -Message "[+] Microsoft.Graph module installed successfully" -Color "Green"
        } catch {
            Write-ColorOutput -Message "[!] Failed to install Microsoft.Graph module: $_" -Color "Red"
            exit 1
        }
    }
    
    try {
        Import-Module Microsoft.Graph.Authentication -ErrorAction Stop
        Import-Module Microsoft.Graph.Identity.DirectoryManagement -ErrorAction Stop
    } catch {
        Write-ColorOutput -Message "[!] Failed to import Microsoft.Graph modules: $_" -Color "Red"
        exit 1
    }
}

# Connect to Microsoft Graph
function Connect-GraphAPI {
    param(
        [string]$Scopes
    )
    
    Write-ColorOutput -Message "[*] Connecting to Microsoft Graph..." -Color "Yellow"
    
    try {
        $scopeArray = $Scopes -split ','
        
        # Check if already connected
        $context = Get-MgContext
        if ($context) {
            Write-ColorOutput -Message "[+] Already connected to tenant: $($context.TenantId)" -Color "Green"
            Write-ColorOutput -Message "[+] Account: $($context.Account)" -Color "Green"
        } else {
            Connect-MgGraph -Scopes $scopeArray -ErrorAction Stop
            $context = Get-MgContext
            Write-ColorOutput -Message "[+] Connected to tenant: $($context.TenantId)" -Color "Green"
            Write-ColorOutput -Message "[+] Account: $($context.Account)" -Color "Green"
        }
    } catch {
        Write-ColorOutput -Message "[!] Failed to connect to Microsoft Graph: $_" -Color "Red"
        exit 1
    }
}

# Format device output like netexec
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
    $deviceIdShort = $Device.DeviceId.Substring(0, [Math]::Min(15, $Device.DeviceId.Length))
    
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
    
    # Export if requested
    if ($ExportPath) {
        try {
            $extension = [System.IO.Path]::GetExtension($ExportPath).ToLower()
            
            if ($extension -eq ".csv") {
                $exportData | Export-Csv -Path $ExportPath -NoTypeInformation -Force
            } elseif ($extension -eq ".json") {
                $exportData | ConvertTo-Json -Depth 5 | Out-File -FilePath $ExportPath -Force
            } else {
                # Default to CSV
                $exportData | Export-Csv -Path $ExportPath -NoTypeInformation -Force
            }
            
            Write-ColorOutput -Message "`n[+] Results exported to: $ExportPath" -Color "Green"
        } catch {
            Write-ColorOutput -Message "`n[!] Failed to export results: $_" -Color "Red"
        }
    }
    
    Write-ColorOutput -Message "`n[*] Enumeration complete!" -Color "Green"
    
    # Display summary statistics
    Write-ColorOutput -Message "`n[*] Summary:" -Color "Yellow"
    Write-ColorOutput -Message "    Total Devices: $($devices.Count)" -Color "Cyan"
    
    $windowsCount = ($devices | Where-Object { $_.OperatingSystem -like "Windows*" }).Count
    $azureAdCount = ($devices | Where-Object { $_.TrustType -eq "AzureAd" }).Count
    $hybridCount = ($devices | Where-Object { $_.TrustType -eq "ServerAd" }).Count
    $compliantCount = ($devices | Where-Object { $_.IsCompliant -eq $true }).Count
    $enabledCount = ($devices | Where-Object { $_.AccountEnabled -eq $true }).Count
    
    Write-ColorOutput -Message "    Windows Devices: $windowsCount" -Color "Cyan"
    Write-ColorOutput -Message "    Azure AD Joined: $azureAdCount" -Color "Cyan"
    Write-ColorOutput -Message "    Hybrid Joined: $hybridCount" -Color "Cyan"
    Write-ColorOutput -Message "    Compliant: $compliantCount" -Color "Cyan"
    Write-ColorOutput -Message "    Enabled: $enabledCount" -Color "Cyan"
}

# Main execution
Initialize-GraphModule

Connect-GraphAPI -Scopes $Scopes

switch ($Command) {
    "hosts" {
        Invoke-HostEnumeration -Filter $Filter -ShowOwners $ShowOwners -ExportPath $ExportPath
    }
    default {
        Write-ColorOutput -Message "[!] Unknown command: $Command" -Color "Red"
        Write-ColorOutput -Message "[*] Available commands: hosts" -Color "Yellow"
    }
}
