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
    - Tenant discovery and configuration enumeration
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
    - tenant: Discover tenant configuration and endpoints

.PARAMETER Domain
    Domain name or tenant ID for tenant discovery. If not provided, the tool will attempt
    to auto-detect the current user's domain from UPN or environment variables.

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

.EXAMPLE
    .\azx.ps1 tenant
    Discover tenant configuration for current user's domain (auto-detected)

.EXAMPLE
    .\azx.ps1 tenant -Domain example.com
    Discover tenant configuration for example.com

.EXAMPLE
    .\azx.ps1 tenant -Domain contoso.onmicrosoft.com -ExportPath tenant-info.json
    Discover tenant configuration and export to JSON

.NOTES
    Requires PowerShell 7+
    Requires Microsoft.Graph PowerShell module (for 'hosts' command)
    Requires appropriate Azure/Entra permissions (for 'hosts' command)
    The 'tenant' command does not require authentication
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true, Position = 0)]
    [ValidateSet("hosts", "tenant")]
    [string]$Command,
    
    [Parameter(Mandatory = $false)]
    [ValidateSet("windows", "azuread", "hybrid", "compliant", "noncompliant", "disabled", "all")]
    [string]$Filter = "all",
    
    [Parameter(Mandatory = $false)]
    [string]$Domain,
    
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

# Tenant discovery function
function Invoke-TenantDiscovery {
    param(
        [string]$Domain,
        [string]$ExportPath
    )
    
    # Auto-detect domain if not provided
    if (-not $Domain) {
        Write-ColorOutput -Message "[*] No domain specified, attempting to auto-detect..." -Color "Yellow"
        
        # Try to get the domain from the current user's UPN
        $detectedDomain = $null
        
        try {
            # Method 1: Try to get UPN from whoami command (Windows)
            if ($IsWindows -or $PSVersionTable.PSVersion.Major -le 5) {
                $upn = whoami /upn 2>$null
                if ($upn -and $upn -match '@(.+)$') {
                    $detectedDomain = $matches[1]
                    Write-ColorOutput -Message "[+] Detected domain from UPN: $detectedDomain" -Color "Green"
                }
            }
            
            # Method 2: Try environment variable for USERDNSDOMAIN
            if (-not $detectedDomain) {
                $envDomain = [System.Environment]::GetEnvironmentVariable("USERDNSDOMAIN")
                if ($envDomain) {
                    $detectedDomain = $envDomain
                    Write-ColorOutput -Message "[+] Detected domain from environment: $detectedDomain" -Color "Green"
                }
            }
            
            # Method 3: Try to get domain from current user's email-like username
            if (-not $detectedDomain) {
                $currentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
                if ($currentUser -match '@(.+)$') {
                    $detectedDomain = $matches[1]
                    Write-ColorOutput -Message "[+] Detected domain from username: $detectedDomain" -Color "Green"
                } elseif ($currentUser -match '(.+)\\') {
                    $domainName = $matches[1]
                    # Check if it's not a local machine name by checking if it looks like a NETBIOS name
                    if ($domainName -ne $env:COMPUTERNAME -and $domainName.Length -le 15) {
                        Write-ColorOutput -Message "[*] Detected NETBIOS domain: $domainName" -Color "Yellow"
                        Write-ColorOutput -Message "[!] Please provide the full DNS domain name for tenant discovery" -Color "Yellow"
                    }
                }
            }
        } catch {
            # Silent catch - we'll handle the error below
        }
        
        if ($detectedDomain) {
            $Domain = $detectedDomain
            Write-ColorOutput -Message "[+] Using auto-detected domain: $Domain`n" -Color "Green"
        } else {
            Write-ColorOutput -Message "[!] Could not auto-detect domain" -Color "Red"
            Write-ColorOutput -Message "[!] Please provide the domain using: .\azx.ps1 tenant -Domain example.com" -Color "Yellow"
            return
        }
    }
    
    Write-ColorOutput -Message "`n[*] AZX - Azure/Entra Tenant Discovery" -Color "Yellow"
    Write-ColorOutput -Message "[*] Target Domain: $Domain`n" -Color "Yellow"
    
    # Construct the OpenID configuration URL
    $openIdConfigUrl = "https://login.microsoftonline.com/$Domain/.well-known/openid-configuration"
    
    Write-ColorOutput -Message "[*] Querying OpenID configuration endpoint..." -Color "Yellow"
    
    try {
        # Query the OpenID configuration endpoint
        $openIdConfig = Invoke-RestMethod -Uri $openIdConfigUrl -Method Get -ErrorAction Stop
        
        Write-ColorOutput -Message "[+] Successfully retrieved tenant configuration`n" -Color "Green"
        
        # Extract tenant ID from the issuer or token_endpoint
        $tenantId = $null
        if ($openIdConfig.issuer) {
            if ($openIdConfig.issuer -match '([a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})') {
                $tenantId = $matches[1]
            }
        }
        
        # Determine federation status
        $isFederated = $false
        if ($openIdConfig.tenant_region_scope -or $openIdConfig.tenant_region_sub_scope) {
            $isFederated = $true
        }
        
        # Format output in netexec style
        Write-ColorOutput -Message "AZR".PadRight(12) + $Domain.PadRight(35) + "443".PadRight(7) + "[*] Tenant Discovery" -Color "Cyan"
        Write-ColorOutput -Message ""
        
        # Display key information
        if ($tenantId) {
            Write-ColorOutput -Message "    [+] Tenant ID:                $tenantId" -Color "Green"
        }
        
        if ($openIdConfig.issuer) {
            Write-ColorOutput -Message "    [+] Issuer:                   $($openIdConfig.issuer)" -Color "Cyan"
        }
        
        if ($openIdConfig.authorization_endpoint) {
            Write-ColorOutput -Message "    [+] Authorization Endpoint:   $($openIdConfig.authorization_endpoint)" -Color "Cyan"
        }
        
        if ($openIdConfig.token_endpoint) {
            Write-ColorOutput -Message "    [+] Token Endpoint:           $($openIdConfig.token_endpoint)" -Color "Cyan"
        }
        
        if ($openIdConfig.userinfo_endpoint) {
            Write-ColorOutput -Message "    [+] UserInfo Endpoint:        $($openIdConfig.userinfo_endpoint)" -Color "Cyan"
        }
        
        if ($openIdConfig.end_session_endpoint) {
            Write-ColorOutput -Message "    [+] End Session Endpoint:     $($openIdConfig.end_session_endpoint)" -Color "Cyan"
        }
        
        if ($openIdConfig.jwks_uri) {
            Write-ColorOutput -Message "    [+] JWKS URI:                 $($openIdConfig.jwks_uri)" -Color "Cyan"
        }
        
        if ($openIdConfig.tenant_region_scope) {
            Write-ColorOutput -Message "    [+] Tenant Region Scope:      $($openIdConfig.tenant_region_scope)" -Color "Cyan"
        }
        
        if ($openIdConfig.tenant_region_sub_scope) {
            Write-ColorOutput -Message "    [+] Tenant Region SubScope:   $($openIdConfig.tenant_region_sub_scope)" -Color "Cyan"
        }
        
        if ($openIdConfig.cloud_instance_name) {
            Write-ColorOutput -Message "    [+] Cloud Instance:           $($openIdConfig.cloud_instance_name)" -Color "Cyan"
        }
        
        if ($openIdConfig.cloud_graph_host_name) {
            Write-ColorOutput -Message "    [+] Graph Host:               $($openIdConfig.cloud_graph_host_name)" -Color "Cyan"
        }
        
        Write-ColorOutput -Message "    [+] Federation Status:        $(if ($isFederated) { 'Federated' } else { 'Managed' })" -Color $(if ($isFederated) { "Yellow" } else { "Green" })
        
        # Additional metadata
        Write-ColorOutput -Message "`n    [*] Supported Response Types: $($openIdConfig.response_types_supported -join ', ')" -Color "DarkGray"
        Write-ColorOutput -Message "    [*] Supported Scopes:         $($openIdConfig.scopes_supported -join ', ')" -Color "DarkGray"
        Write-ColorOutput -Message "    [*] Supported Claims:         $($openIdConfig.claims_supported.Count) claims available" -Color "DarkGray"
        
        # Export if requested
        if ($ExportPath) {
            try {
                $extension = [System.IO.Path]::GetExtension($ExportPath).ToLower()
                
                $exportData = [PSCustomObject]@{
                    Domain                    = $Domain
                    TenantId                  = $tenantId
                    Issuer                    = $openIdConfig.issuer
                    AuthorizationEndpoint     = $openIdConfig.authorization_endpoint
                    TokenEndpoint             = $openIdConfig.token_endpoint
                    UserInfoEndpoint          = $openIdConfig.userinfo_endpoint
                    EndSessionEndpoint        = $openIdConfig.end_session_endpoint
                    JwksUri                   = $openIdConfig.jwks_uri
                    TenantRegionScope         = $openIdConfig.tenant_region_scope
                    TenantRegionSubScope      = $openIdConfig.tenant_region_sub_scope
                    CloudInstanceName         = $openIdConfig.cloud_instance_name
                    CloudGraphHostName        = $openIdConfig.cloud_graph_host_name
                    FederationStatus          = if ($isFederated) { "Federated" } else { "Managed" }
                    ResponseTypesSupported    = $openIdConfig.response_types_supported
                    ScopesSupported           = $openIdConfig.scopes_supported
                    ClaimsSupported           = $openIdConfig.claims_supported
                    FullConfiguration         = $openIdConfig
                }
                
                if ($extension -eq ".csv") {
                    $exportData | Select-Object -Property * -ExcludeProperty FullConfiguration | Export-Csv -Path $ExportPath -NoTypeInformation -Force
                } elseif ($extension -eq ".json") {
                    $exportData | ConvertTo-Json -Depth 10 | Out-File -FilePath $ExportPath -Force
                } else {
                    # Default to JSON
                    $exportData | ConvertTo-Json -Depth 10 | Out-File -FilePath $ExportPath -Force
                }
                
                Write-ColorOutput -Message "`n[+] Tenant information exported to: $ExportPath" -Color "Green"
            } catch {
                Write-ColorOutput -Message "`n[!] Failed to export results: $_" -Color "Red"
            }
        }
        
        Write-ColorOutput -Message "`n[*] Tenant discovery complete!" -Color "Green"
        
    } catch {
        Write-ColorOutput -Message "[!] Failed to retrieve tenant configuration" -Color "Red"
        Write-ColorOutput -Message "[!] Error: $_" -Color "Red"
        
        # Check if it's a 400 error (invalid tenant)
        if ($_.Exception.Response.StatusCode -eq 400) {
            Write-ColorOutput -Message "[!] The specified domain does not appear to be a valid Azure/Entra tenant" -Color "Yellow"
        }
    }
}

# Main execution
# For tenant discovery, we don't need Graph module
if ($Command -ne "tenant") {
    Initialize-GraphModule
    Connect-GraphAPI -Scopes $Scopes
}

switch ($Command) {
    "hosts" {
        Invoke-HostEnumeration -Filter $Filter -ShowOwners $ShowOwners -ExportPath $ExportPath
    }
    "tenant" {
        Invoke-TenantDiscovery -Domain $Domain -ExportPath $ExportPath
    }
    default {
        Write-ColorOutput -Message "[!] Unknown command: $Command" -Color "Red"
        Write-ColorOutput -Message "[*] Available commands: hosts, tenant" -Color "Yellow"
    }
}
