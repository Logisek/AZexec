<#
    This file is part of the toolkit EvilMist
    Copyright (C) 2025-2026 Logisek
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
    - Local groups enumeration via Administrative Units (mimics nxc smb --local-group)
      * Enumerate Azure AD Administrative Units (scoped administration)
      * Display membership types (Assigned vs Dynamic)
      * Show member counts and scoped role assignments
      * Identify privileged administrative boundaries
    - Password policy enumeration (mimics nxc smb --pass-pol)
      * Azure AD default password requirements (min/max length, complexity, banned passwords)
      * Smart lockout settings (lockout threshold, duration, familiar location detection)
      * Password expiration policies (validity period, notification windows)
      * MFA/authentication methods (Authenticator, SMS, FIDO2, etc.)
      * Security defaults status (MFA enforcement, legacy auth blocking)
      * Conditional access policies (MFA, device compliance, location restrictions)
      * NetExec-style summary with all key password policy settings
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
    - Azure VM Logged-On Users Enumeration (mimics nxc smb --logged-on-users)
      * Azure equivalent of Workstation Service (wkssvc) enumeration
      * Query logged-on users on Azure VMs using VM Run Command
      * Support for both Windows and Linux VMs
      * Display username, session state, idle time, and connection source
      * Filter by resource group, subscription, and VM power state
      * Multi-subscription support with automatic enumeration
      * Requires VM Contributor role or VM Command Executor role
    - Azure VM Process Enumeration (mimics nxc smb --tasklist)
      * Azure equivalent of remote process enumeration
      * Query running processes on Azure VMs using VM Run Command
      * Support for both Windows (tasklist) and Linux (ps aux) VMs
      * Display process name, PID, memory usage, CPU usage, user, and session
      * Filter by process name (e.g., "keepass.exe", "ssh", "python")
      * Filter by resource group, subscription, and VM power state
      * Multi-subscription support with automatic enumeration
      * Requires VM Contributor role or VM Command Executor role
    - Azure Storage Account Enumeration (authentication required)
      * Discover storage accounts across subscriptions
      * Security analysis: public access, HTTPS-only, TLS version, network rules
      * Identify misconfigured blob public access and shared key access
      * Multi-subscription support with automatic enumeration
    - Azure Key Vault Enumeration (authentication required)
      * Discover Key Vaults across subscriptions
      * Security analysis: soft delete, purge protection, RBAC authorization
      * Identify access policy configurations and network exposure
      * Multi-subscription support with automatic enumeration
    - Azure Network Resource Enumeration (authentication required)
      * Discover VNets, NSGs, Public IPs, Load Balancers, and Network Interfaces
      * Identify risky NSG inbound rules (open ports from internet)
      * Detect unassociated public IPs and unattached NICs
      * Enumerate network interfaces with IP configurations and security analysis
      * Multi-subscription support with automatic enumeration
    - Azure File Shares Enumeration (mimics nxc smb --shares)
      * Enumerate Azure File Shares across Storage Accounts
      * Display access permissions (READ, WRITE) similar to SMB share enumeration
      * Filter by access level (READ, WRITE, READ,WRITE)
      * Show quotas, access tiers, and enabled protocols (SMB/NFS)
      * Multi-subscription support with automatic enumeration
    - Antivirus/EDR enumeration (mimics nxc smb -M enum_av)
      * Enumerate antivirus products (Microsoft Defender, etc.)
      * Detect Microsoft Defender for Endpoint (MDE) onboarding status
      * Query device compliance and security posture
      * Identify firewall status and encryption configuration
      * Security risk assessment and recommendations
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
    - user-profiles: Enumerate domain users with full details (authentication required, Azure equivalent of nxc smb/ldap --users)
    - rid-brute: Enumerate users by bruteforcing RID (Azure equivalent, alias for user-profiles)
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
    - vm-loggedon: Enumerate logged-on users on Azure VMs (similar to nxc smb --logged-on-users / Workstation Service wkssvc)
    - storage-enum: Enumerate Azure Storage Accounts with security configurations (multi-subscription support)
    - keyvault-enum: Enumerate Azure Key Vaults with security configurations (multi-subscription support)
    - network-enum: Enumerate Azure Network resources (VNets, NSGs, Public IPs, Load Balancers, Network Interfaces) (multi-subscription support)
    - shares-enum: Enumerate Azure File Shares with access permissions (mimics nxc smb --shares) (multi-subscription support)
    - disks-enum: Enumerate Azure Managed Disks with encryption and security configurations (mimics nxc smb --disks) (multi-subscription support)
    - bitlocker-enum: Enumerate BitLocker encryption status on Windows Azure VMs (mimics nxc smb -M bitlocker) (multi-subscription support)
    - local-groups: Enumerate Azure AD Administrative Units (mimics nxc smb --local-group) (authentication required)
    - av-enum: Enumerate Anti-Virus and EDR products on Azure/Entra devices (mimics nxc smb -M enum_av) (authentication required)
    - process-enum: Enumerate remote processes on Azure VMs (mimics nxc smb --tasklist) (multi-subscription support)
    - lockscreen-enum: Detect accessibility backdoors on Azure VMs (mimics nxc smb -M lockscreendoors) (multi-subscription support)
    - intune-enum: Enumerate Intune/Endpoint Manager configuration (mimics nxc smb -M sccm-recon6) (authentication required)
    - delegation-enum: Enumerate OAuth2 delegation/impersonation paths (mimics nxc smb --delegate) (authentication required)
    - exec: Execute remote commands on Azure VMs (mimics nxc smb -x/-X) (multi-subscription support)

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

.PARAMETER SharesFilter
    Optional filter for file share access level (for shares-enum command).
    Similar to NetExec's --shares READ,WRITE filter.
    - all: Show all file shares (default)
    - READ: Only show shares with READ access
    - WRITE: Only show shares with WRITE access
    - READ,WRITE: Only show shares with both READ and WRITE access

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
    Enumerate all domain users in the Azure/Entra tenant (authenticated, Azure equivalent of nxc smb/ldap --users)

.EXAMPLE
    .\azx.ps1 user-profiles -ExportPath users.csv
    Enumerate domain users and export to CSV (like nxc ldap --users-export users.csv)

.EXAMPLE
    .\azx.ps1 user-profiles -ExportPath users.json
    Enumerate domain users with full details exported to JSON

.EXAMPLE
    .\azx.ps1 rid-brute
    Enumerate users by bruteforcing RID (Azure equivalent - enumerates all users via Graph API)

.EXAMPLE
    .\azx.ps1 rid-brute -ExportPath users.csv
    Enumerate users via RID bruteforce method and export to CSV (Azure equivalent)

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

.EXAMPLE
    .\azx.ps1 storage-enum
    Enumerate Azure Storage Accounts across all accessible subscriptions

.EXAMPLE
    .\azx.ps1 storage-enum -SubscriptionId "12345678-1234-1234-1234-123456789012"
    Enumerate Storage Accounts in a specific subscription

.EXAMPLE
    .\azx.ps1 storage-enum -ResourceGroup Production-RG -ExportPath storage.csv
    Enumerate Storage Accounts in a specific resource group and export to CSV

.EXAMPLE
    .\azx.ps1 keyvault-enum
    Enumerate Azure Key Vaults across all accessible subscriptions

.EXAMPLE
    .\azx.ps1 keyvault-enum -SubscriptionId "12345678-1234-1234-1234-123456789012" -ExportPath keyvaults.json
    Enumerate Key Vaults in a specific subscription and export to JSON

.EXAMPLE
    .\azx.ps1 keyvault-enum -ExportPath keyvaults.html
    Enumerate Key Vaults across all subscriptions and export HTML report

.EXAMPLE
    .\azx.ps1 network-enum
    Enumerate Azure Network resources (VNets, NSGs, Public IPs, Load Balancers, Network Interfaces) across all subscriptions

.EXAMPLE
    .\azx.ps1 network-enum -SubscriptionId "12345678-1234-1234-1234-123456789012"
    Enumerate Network resources in a specific subscription (includes network interface enumeration)

.EXAMPLE
    .\azx.ps1 network-enum -ResourceGroup Production-RG -ExportPath network.csv
    Enumerate Network resources in a specific resource group and export to CSV (includes NICs with IP configurations)

.EXAMPLE
    .\azx.ps1 shares-enum
    Enumerate Azure File Shares across all accessible subscriptions (similar to nxc smb --shares)

.EXAMPLE
    .\azx.ps1 shares-enum -SharesFilter READ,WRITE
    Enumerate only file shares with both READ and WRITE access (similar to nxc smb --shares READ,WRITE)

.EXAMPLE
    .\azx.ps1 shares-enum -SharesFilter WRITE -ExportPath writable-shares.csv
    Enumerate file shares with WRITE access and export to CSV

.EXAMPLE
    .\azx.ps1 shares-enum -SubscriptionId "12345678-1234-1234-1234-123456789012" -ExportPath shares.json
    Enumerate File Shares in a specific subscription and export to JSON

.EXAMPLE
    .\azx.ps1 disks-enum
    Enumerate Azure Managed Disks across all accessible subscriptions (similar to nxc smb --disks)

.EXAMPLE
    .\azx.ps1 disks-enum -SubscriptionId "12345678-1234-1234-1234-123456789012"
    Enumerate Managed Disks in a specific subscription

.EXAMPLE
    .\azx.ps1 disks-enum -ResourceGroup Production-RG -ExportPath disks.csv
    Enumerate Managed Disks in a specific resource group and export to CSV

.EXAMPLE
    .\azx.ps1 disks-enum -ExportPath disks.json
    Enumerate Managed Disks across all subscriptions and export to JSON with full details

.EXAMPLE
    .\azx.ps1 bitlocker-enum
    Enumerate BitLocker encryption status on all Windows Azure VMs across subscriptions (similar to nxc smb -M bitlocker)

.EXAMPLE
    .\azx.ps1 bitlocker-enum -SubscriptionId "12345678-1234-1234-1234-123456789012"
    Enumerate BitLocker status in a specific subscription

.EXAMPLE
    .\azx.ps1 bitlocker-enum -ResourceGroup Production-RG -VMFilter running
    Enumerate BitLocker status on running VMs in a specific resource group

.EXAMPLE
    .\azx.ps1 bitlocker-enum -ExportPath bitlocker-status.csv
    Enumerate BitLocker status and export to CSV with volume encryption details

.EXAMPLE
    .\azx.ps1 local-groups
    Enumerate Azure AD Administrative Units (local groups equivalent)

.EXAMPLE
    .\azx.ps1 local-groups -ShowOwners
    Enumerate Administrative Units with member counts and scoped role counts

.EXAMPLE
    .\azx.ps1 local-groups -ExportPath admin-units.csv
    Enumerate Administrative Units and export to CSV

.EXAMPLE
    .\azx.ps1 local-groups -ExportPath admin-units.json
    Enumerate Administrative Units with full details exported to JSON

.EXAMPLE
    .\azx.ps1 av-enum
    Enumerate antivirus and EDR products on all devices (similar to nxc smb -M enum_av)

.EXAMPLE
    .\azx.ps1 av-enum -Filter windows
    Enumerate security posture only on Windows devices

.EXAMPLE
    .\azx.ps1 av-enum -Filter noncompliant -ExportPath security-gaps.csv
    Identify non-compliant devices and their security gaps

.EXAMPLE
    .\azx.ps1 av-enum -ExportPath security-report.html
    Generate comprehensive HTML security report with statistics

.EXAMPLE
    .\azx.ps1 process-enum
    Enumerate all running processes on all Azure VMs (similar to nxc smb --tasklist)

.EXAMPLE
    .\azx.ps1 process-enum -ProcessName "keepass.exe"
    Enumerate specific process by name (similar to nxc smb --tasklist keepass.exe)

.EXAMPLE
    .\azx.ps1 process-enum -ResourceGroup Production-RG
    Enumerate processes on VMs in a specific resource group

.EXAMPLE
    .\azx.ps1 process-enum -VMFilter running -ExportPath processes.csv
    Enumerate processes only on running VMs and export to CSV

.EXAMPLE
    .\azx.ps1 process-enum -SubscriptionId "12345678-1234-1234-1234-123456789012" -ProcessName "python"
    Enumerate Python processes in a specific subscription

.EXAMPLE
    .\azx.ps1 lockscreen-enum
    Detect lockscreen backdoors on all Azure VMs (similar to nxc smb -M lockscreendoors)

.EXAMPLE
    .\azx.ps1 lockscreen-enum -VMFilter running
    Check only running VMs for accessibility backdoors

.EXAMPLE
    .\azx.ps1 lockscreen-enum -ResourceGroup Production-RG -ExportPath lockscreen-report.html
    Check VMs in specific resource group and export HTML report

.EXAMPLE
    .\azx.ps1 intune-enum
    Enumerate Intune/Endpoint Manager configuration (similar to nxc smb -M sccm-recon6)

.EXAMPLE
    .\azx.ps1 intune-enum -ExportPath intune-report.csv
    Enumerate Intune configuration and export to CSV

.EXAMPLE
    .\azx.ps1 intune-enum -ExportPath intune-report.html
    Enumerate Intune configuration and generate HTML report

.EXAMPLE
    .\azx.ps1 delegation-enum
    Enumerate OAuth2 delegated permissions and identify impersonation paths (Azure equivalent of nxc smb --delegate)

.EXAMPLE
    .\azx.ps1 delegation-enum -ExportPath delegation.csv
    Enumerate OAuth2 delegation and export to CSV

.EXAMPLE
    .\azx.ps1 delegation-enum -ExportPath delegation.json
    Enumerate OAuth2 delegation with full details exported to JSON

.EXAMPLE
    .\azx.ps1 exec -VMName "vm-web-01" -x "whoami"
    Execute shell command on single VM (like nxc smb -x)

.EXAMPLE
    .\azx.ps1 exec -VMName "vm-web-01" -x '$env:COMPUTERNAME' -PowerShell
    Execute PowerShell on single VM (like nxc smb -X)

.EXAMPLE
    .\azx.ps1 exec -ResourceGroup "Production-RG" -x "hostname" -AllVMs
    Execute on all VMs in resource group (requires -AllVMs flag)

.EXAMPLE
    .\azx.ps1 exec -VMName "arc-server-01" -x "id" -ExecMethod arc
    Force specific execution method (Arc-enabled server)

.EXAMPLE
    .\azx.ps1 exec -x "whoami /all" -AllVMs -ExportPath results.csv
    Execute across all subscriptions with export

.NOTES
    Requires PowerShell 7+
    Requires Microsoft.Graph PowerShell module (for 'hosts', 'groups', 'local-groups', 'pass-pol', 'sessions', 'vuln-list', 'guest-vuln-scan', 'apps', 'sp-discovery', 'roles', 'ca-policies', 'intune-enum' commands)
    Requires Az PowerShell module (for ARM-based commands: 'vm-loggedon', 'storage-enum', 'keyvault-enum', 'network-enum', 'shares-enum')
    Requires appropriate Azure/Entra permissions (for authenticated commands)
    The 'tenant' and 'users' commands do not require authentication
    The 'vuln-list' and 'guest-vuln-scan' commands perform unauthenticated checks first, then authenticated checks
    The 'sessions' command requires AuditLog.Read.All permission
    The 'sp-discovery' command requires Application.Read.All and Directory.Read.All permissions (add -IncludeWritePermissions for AppRoleAssignment.ReadWrite.All)
    The 'roles' command requires RoleManagement.Read.Directory and Directory.Read.All permissions (PIM requires RoleEligibilitySchedule.Read.Directory)
    The 'ca-policies' command requires Policy.Read.All permission (guest users cannot access conditional access policies)
    The 'local-groups' command requires AdministrativeUnit.Read.All or Directory.Read.All permissions (Azure AD Premium P1/P2 required)
    The 'local-groups' command is the Azure equivalent of NetExec's --local-group (enumerates Administrative Units instead of local groups)
    The 'vm-loggedon' command requires Azure authentication and 'Virtual Machine Contributor' role or 'Reader' + 'Virtual Machine Command Executor' role
    The 'vm-loggedon' command is the Azure equivalent of NetExec's Workstation Service (wkssvc) enumeration
    
    ARM-based commands with multi-subscription support:
    - 'vm-loggedon': Requires Az.Accounts, Az.Compute, Az.Resources
    - 'storage-enum': Requires Az.Accounts, Az.Resources, Az.Storage (Reader role required, Storage Account Contributor for full details)
    - 'keyvault-enum': Requires Az.Accounts, Az.Resources, Az.KeyVault (Reader role required, Key Vault Reader for full details)
    - 'network-enum': Requires Az.Accounts, Az.Resources, Az.Network (Reader role required)
    - 'shares-enum': Requires Az.Accounts, Az.Resources, Az.Storage (Reader + Storage Account Key Operator or Storage File Data SMB Share Reader)
    - 'disks-enum': Requires Az.Accounts, Az.Resources, Az.Compute (Reader role required)
    - 'bitlocker-enum': Requires Az.Accounts, Az.Compute, Az.Resources (VM Contributor or VM Command Executor role required)
    - 'process-enum': Requires Az.Accounts, Az.Compute, Az.Resources (VM Contributor or VM Command Executor role required)
    - 'lockscreen-enum': Requires Az.Accounts, Az.Compute, Az.Resources (VM Contributor or VM Command Executor role required)
    - 'exec': Requires Az.Accounts, Az.Compute, Az.Resources (VM Contributor or VM Command Executor role required)

    The 'shares-enum' command is the Azure equivalent of NetExec's --shares command for SMB share enumeration
    The 'disks-enum' command is the Azure equivalent of NetExec's --disks command for disk enumeration
    The 'bitlocker-enum' command is the Azure equivalent of NetExec's -M bitlocker module for BitLocker encryption status
    The 'av-enum' command is the Azure equivalent of NetExec's -M enum_av module for antivirus/EDR enumeration
    The 'process-enum' command is the Azure equivalent of NetExec's --tasklist command for remote process enumeration
    The 'lockscreen-enum' command is the Azure equivalent of NetExec's -M lockscreendoors module for detecting accessibility backdoors
    The 'intune-enum' command is the Azure equivalent of NetExec's -M sccm-recon6 module for SCCM/Intune infrastructure reconnaissance
    The 'intune-enum' command requires DeviceManagementConfiguration.Read.All, DeviceManagementRBAC.Read.All, and DeviceManagementManagedDevices.Read.All permissions
    The 'delegation-enum' command requires Application.Read.All and Directory.Read.All permissions (Azure equivalent of NetExec --delegate)
    The 'exec' command is the Azure equivalent of NetExec's -x/-X remote command execution
    The 'exec' command supports six methods:
    - vmrun: Azure VM Run Command (synchronous - for Azure VMs)
    - arc: Azure Arc Run Command (synchronous - for Arc-enabled servers)
    - mde: MDE Live Response (async with polling - for MDE-enrolled devices)
    - intune: Intune Proactive Remediation (async - for Intune-managed devices)
    - automation: Azure Automation Hybrid Worker (job-based - for servers with Automation extension)

    All ARM-based commands support multi-subscription enumeration:
    - By default, all accessible subscriptions are enumerated automatically
    - Use -SubscriptionId to target a specific subscription
    - Use -ResourceGroup to filter by resource group within subscriptions
    
    Guest users may have limited access to groups, policy information, audit logs, service principal data, and role assignments
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true, Position = 0)]
    [ValidateSet("hosts", "tenant", "users", "user-profiles", "rid-brute", "groups", "pass-pol", "guest", "spray", "vuln-list", "sessions", "guest-vuln-scan", "apps", "sp-discovery", "roles", "ca-policies", "vm-loggedon", "storage-enum", "keyvault-enum", "network-enum", "shares-enum", "disks-enum", "bitlocker-enum", "local-groups", "av-enum", "process-enum", "lockscreen-enum", "intune-enum", "delegation-enum", "exec", "help")]
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
    [string]$VMFilter = "all",
    
    [Parameter(Mandatory = $false)]
    [ValidateSet("all", "READ", "WRITE", "READ,WRITE")]
    [string]$SharesFilter = "all",
    
    [Parameter(Mandatory = $false)]
    [string]$ProcessName,

    # Password spray options (NetExec-style)
    [Parameter(Mandatory = $false)]
    [switch]$ContinueOnSuccess,

    [Parameter(Mandatory = $false)]
    [switch]$NoBruteforce,

    [Parameter(Mandatory = $false)]
    [string]$PasswordFile,

    [Parameter(Mandatory = $false)]
    [int]$Delay = 0,

    # Token-based authentication (Azure's Pass-the-Hash equivalent)
    [Parameter(Mandatory = $false)]
    [string]$AccessToken,

    # Local authentication mode (Azure equivalent of netexec --local-auth)
    # Only spray managed (cloud-only) domains, skip federated domains
    [Parameter(Mandatory = $false)]
    [switch]$LocalAuth,

    # Remote command execution options (exec command - NetExec -x/-X equivalent)
    [Parameter(Mandatory = $false)]
    [string]$x,                    # Command to execute (-x shell mode)

    [Parameter(Mandatory = $false)]
    [string]$VMName,               # Target VM name for single-target execution

    [Parameter(Mandatory = $false)]
    [ValidateSet("auto", "vmrun", "arc", "mde", "intune", "automation")]
    [string]$ExecMethod = "auto",  # Execution method selection

    [Parameter(Mandatory = $false)]
    [switch]$PowerShell,           # For PowerShell execution (use -PowerShell instead of -X due to case insensitivity)

    [Parameter(Mandatory = $false)]
    [switch]$AllVMs,               # Execute on all matching VMs (explicit opt-in)

    [Parameter(Mandatory = $false)]
    [string]$DeviceName,           # Target device name (Arc or Intune)

    [Parameter(Mandatory = $false)]
    [switch]$AllDevices,           # Execute on all Arc-enabled devices

    [Parameter(Mandatory = $false)]
    [int]$Timeout = 300,           # Command execution timeout in seconds

    [Parameter(Mandatory = $false)]
    [string]$AmsiBypass            # Path to AMSI bypass script file (PowerShell only)
)


# ============================================
# LOAD FUNCTION FILES
# ============================================
# Functions are loaded via dot-sourcing to maintain access to script-level variables
$FunctionsPath = Join-Path $PSScriptRoot "Functions"

# Core functions (must be loaded first)
. "$FunctionsPath\Core.ps1"
. "$FunctionsPath\UI.ps1"

# Feature-specific functions
. "$FunctionsPath\Devices.ps1"
. "$FunctionsPath\Users.ps1"
. "$FunctionsPath\Groups.ps1"
. "$FunctionsPath\AdministrativeUnits.ps1"
. "$FunctionsPath\Applications.ps1"
. "$FunctionsPath\ServicePrincipals.ps1"
. "$FunctionsPath\Roles.ps1"
. "$FunctionsPath\Policies.ps1"
. "$FunctionsPath\Guest.ps1"
. "$FunctionsPath\Sessions.ps1"
. "$FunctionsPath\Tenant.ps1"
. "$FunctionsPath\Vulnerabilities.ps1"
. "$FunctionsPath\Security.ps1"
. "$FunctionsPath\AzureRM.ps1"
. "$FunctionsPath\Intune.ps1"
. "$FunctionsPath\Delegation.ps1"
. "$FunctionsPath\CommandExecution.ps1"

# ============================================
# MAIN EXECUTION
# ============================================
Show-Banner

# Main execution
# For tenant discovery and user enumeration, we don't need Graph module
# For authenticated commands (hosts, groups, pass-pol, sessions), we need Graph module
# vuln-list handles authentication internally (hybrid unauthenticated + authenticated)
# rid-brute is an alias for user-profiles (Azure equivalent of RID bruteforcing)
if ($Command -in @("hosts", "groups", "pass-pol", "sessions", "user-profiles", "rid-brute", "roles", "apps", "sp-discovery", "ca-policies", "local-groups", "intune-enum", "delegation-enum")) {
    # Determine required Graph modules based on command
    $graphModules = switch ($Command) {
        "hosts" {
            @("Microsoft.Graph.Authentication", "Microsoft.Graph.Identity.DirectoryManagement")
        }
        { $_ -in @("user-profiles", "rid-brute") } {
            @("Microsoft.Graph.Authentication", "Microsoft.Graph.Users")
        }
        "groups" {
            @("Microsoft.Graph.Authentication", "Microsoft.Graph.Groups")
        }
        "pass-pol" {
            @("Microsoft.Graph.Authentication", "Microsoft.Graph.Identity.DirectoryManagement")
        }
        "sessions" {
            @("Microsoft.Graph.Authentication", "Microsoft.Graph.Reports")
        }
        "roles" {
            @("Microsoft.Graph.Authentication", "Microsoft.Graph.Identity.DirectoryManagement")
        }
        "apps" {
            @("Microsoft.Graph.Authentication", "Microsoft.Graph.Applications")
        }
        "sp-discovery" {
            @("Microsoft.Graph.Authentication", "Microsoft.Graph.Applications")
        }
        "ca-policies" {
            @("Microsoft.Graph.Authentication", "Microsoft.Graph.Identity.SignIns")
        }
        "local-groups" {
            @("Microsoft.Graph.Authentication", "Microsoft.Graph.Identity.DirectoryManagement")
        }
        "intune-enum" {
            @("Microsoft.Graph.Authentication", "Microsoft.Graph.DeviceManagement", "Microsoft.Graph.DeviceManagement.Administration")
        }
        "delegation-enum" {
            @("Microsoft.Graph.Authentication", "Microsoft.Graph.Applications")
        }
        default {
            @("Microsoft.Graph.Authentication", "Microsoft.Graph.Identity.DirectoryManagement")
        }
    }
    Initialize-GraphModule -RequiredModules $graphModules

    # Determine required scopes based on command
    $requiredScopes = switch ($Command) {
        "hosts" { "Device.Read.All" }
        "user-profiles" { "User.Read.All,Directory.Read.All,AuditLog.Read.All" }
        "rid-brute" { "User.Read.All,Directory.Read.All,AuditLog.Read.All" }
        "groups" { "Group.Read.All,Directory.Read.All" }
        "pass-pol" { "Organization.Read.All,Directory.Read.All,Policy.Read.All" }
        "sessions" { "AuditLog.Read.All,Directory.Read.All" }
        "roles" { "RoleManagement.Read.Directory,Directory.Read.All,RoleEligibilitySchedule.Read.Directory" }
        "guest-vuln-scan" { "User.Read.All,Group.Read.All,Device.Read.All,Application.Read.All,Directory.Read.All,Policy.Read.All" }
        "apps" { "Application.Read.All,Directory.Read.All" }
        "ca-policies" { "Policy.Read.All,Directory.Read.All" }
        "local-groups" { "AdministrativeUnit.Read.All,Directory.Read.All" }
        "sp-discovery" {
            if ($IncludeWritePermissions) {
                "Application.Read.All,Directory.Read.All,AppRoleAssignment.ReadWrite.All"
            } else {
                "Application.Read.All,Directory.Read.All"
            }
        }
        "intune-enum" { "DeviceManagementConfiguration.Read.All,DeviceManagementRBAC.Read.All,DeviceManagementManagedDevices.Read.All,DeviceManagementServiceConfig.Read.All" }
        "delegation-enum" { "Application.Read.All,Directory.Read.All" }
        default { $Scopes }
    }

    Connect-GraphAPI -Scopes $requiredScopes
}

# vuln-list, guest-vuln-scan, and av-enum require Graph module but handle connection internally
if ($Command -eq "vuln-list" -or $Command -eq "guest-vuln-scan") {
    $graphModules = @("Microsoft.Graph.Authentication", "Microsoft.Graph.Identity.DirectoryManagement", "Microsoft.Graph.Users", "Microsoft.Graph.Groups", "Microsoft.Graph.Applications")
    Initialize-GraphModule -RequiredModules $graphModules
}

# av-enum requires Graph module with specific permissions
if ($Command -eq "av-enum") {
    $graphModules = @("Microsoft.Graph.Authentication", "Microsoft.Graph.Identity.DirectoryManagement", "Microsoft.Graph.DeviceManagement")
    Initialize-GraphModule -RequiredModules $graphModules

    # av-enum needs Device.Read.All at minimum, plus MDE/Intune permissions for full data
    # DeviceManagementConfiguration.Read.All is needed for some encryption/compliance data
    $requiredScopes = "Device.Read.All,SecurityEvents.Read.All,DeviceManagementManagedDevices.Read.All,DeviceManagementConfiguration.Read.All"

    Write-ColorOutput -Message "`n[*] Connecting to Microsoft Graph for Security Enumeration..." -Color "Yellow"
    Write-ColorOutput -Message "[*] Permissions requested (some require admin consent):" -Color "Cyan"
    Write-ColorOutput -Message "    • Device.Read.All (required - device enumeration)" -Color "White"
    Write-ColorOutput -Message "    • DeviceManagementManagedDevices.Read.All (Intune device data, BitLocker status)" -Color "White"
    Write-ColorOutput -Message "    • DeviceManagementConfiguration.Read.All (device compliance, encryption policies)" -Color "White"
    Write-ColorOutput -Message "    • SecurityEvents.Read.All (MDE/Defender status - requires admin consent)`n" -Color "Gray"

    Connect-GraphAPI -Scopes $requiredScopes
}

# ARM-based commands use Azure Resource Manager (Az modules) with RBAC, not Graph API
if ($Command -in @("vm-loggedon", "storage-enum", "keyvault-enum", "network-enum", "shares-enum", "disks-enum", "bitlocker-enum", "process-enum", "lockscreen-enum", "exec")) {
    Write-ColorOutput -Message "`n[*] ========================================" -Color "Cyan"
    Write-ColorOutput -Message "[*] AZURE RESOURCE MANAGER - RBAC REQUIREMENTS" -Color "Cyan"
    Write-ColorOutput -Message "[*] ========================================`n" -Color "Cyan"
    
    Write-ColorOutput -Message "[*] This command uses Azure Resource Manager API (not Microsoft Graph)" -Color "Yellow"
    Write-ColorOutput -Message "[*] Multi-subscription support: All accessible subscriptions will be enumerated`n" -Color "Cyan"
    
    switch ($Command) {
        "vm-loggedon" {
            Write-ColorOutput -Message "[*] Required Azure RBAC Roles for VM Enumeration:`n" -Color "Yellow"
            Write-ColorOutput -Message "    Option 1 (Recommended - Minimal Permissions):" -Color "White"
            Write-ColorOutput -Message "      • Reader role (to list VMs)" -Color "Gray"
            Write-ColorOutput -Message "      • Virtual Machine Command Executor role (to query logged-on users)`n" -Color "Gray"
            Write-ColorOutput -Message "    Option 2 (Common - Full VM Access):" -Color "White"
            Write-ColorOutput -Message "      • Virtual Machine Contributor role`n" -Color "Gray"
        }
        "storage-enum" {
            Write-ColorOutput -Message "[*] Required Azure RBAC Roles for Storage Enumeration:`n" -Color "Yellow"
            Write-ColorOutput -Message "    Minimum: Reader role (to list storage accounts)" -Color "Gray"
            Write-ColorOutput -Message "    Recommended: Storage Account Contributor (for full details)`n" -Color "Gray"
        }
        "keyvault-enum" {
            Write-ColorOutput -Message "[*] Required Azure RBAC Roles for Key Vault Enumeration:`n" -Color "Yellow"
            Write-ColorOutput -Message "    Minimum: Reader role (to list Key Vaults)" -Color "Gray"
            Write-ColorOutput -Message "    Recommended: Key Vault Reader (for security configurations)`n" -Color "Gray"
        }
        "network-enum" {
            Write-ColorOutput -Message "[*] Required Azure RBAC Roles for Network Enumeration:`n" -Color "Yellow"
            Write-ColorOutput -Message "    Minimum: Reader role (to list network resources)" -Color "Gray"
            Write-ColorOutput -Message "    Recommended: Network Contributor (for full details)`n" -Color "Gray"
        }
        "shares-enum" {
            Write-ColorOutput -Message "[*] Required Azure RBAC Roles for File Shares Enumeration:`n" -Color "Yellow"
            Write-ColorOutput -Message "    Minimum: Reader + Storage Account Key Operator Service Role" -Color "Gray"
            Write-ColorOutput -Message "    Recommended: Storage File Data SMB Share Reader (for file shares)`n" -Color "Gray"
            Write-ColorOutput -Message "    For write access testing: Storage File Data SMB Share Contributor`n" -Color "Gray"
        }
        "disks-enum" {
            Write-ColorOutput -Message "[*] Required Azure RBAC Roles for Managed Disks Enumeration:`n" -Color "Yellow"
            Write-ColorOutput -Message "    Minimum: Reader role (to list managed disks)" -Color "Gray"
            Write-ColorOutput -Message "    Recommended: Disk Reader or Contributor (for full details)`n" -Color "Gray"
        }
        "bitlocker-enum" {
            Write-ColorOutput -Message "[*] Required Azure RBAC Roles for BitLocker Enumeration:`n" -Color "Yellow"
            Write-ColorOutput -Message "    Option 1 (Recommended - Minimal Permissions):" -Color "White"
            Write-ColorOutput -Message "      • Reader role (to list VMs)" -Color "Gray"
            Write-ColorOutput -Message "      • Virtual Machine Command Executor role (to query BitLocker status)`n" -Color "Gray"
            Write-ColorOutput -Message "    Option 2 (Common - Full VM Access):" -Color "White"
            Write-ColorOutput -Message "      • Virtual Machine Contributor role`n" -Color "Gray"
        }
        "process-enum" {
            Write-ColorOutput -Message "[*] Required Azure RBAC Roles for Process Enumeration:`n" -Color "Yellow"
            Write-ColorOutput -Message "    Option 1 (Recommended - Minimal Permissions):" -Color "White"
            Write-ColorOutput -Message "      • Reader role (to list VMs)" -Color "Gray"
            Write-ColorOutput -Message "      • Virtual Machine Command Executor role (to query processes)`n" -Color "Gray"
            Write-ColorOutput -Message "    Option 2 (Common - Full VM Access):" -Color "White"
            Write-ColorOutput -Message "      • Virtual Machine Contributor role`n" -Color "Gray"
        }
        "lockscreen-enum" {
            Write-ColorOutput -Message "[*] Required Azure RBAC Roles for Lockscreen Backdoor Enumeration:`n" -Color "Yellow"
            Write-ColorOutput -Message "    Option 1 (Recommended - Minimal Permissions):" -Color "White"
            Write-ColorOutput -Message "      • Reader role (to list VMs)" -Color "Gray"
            Write-ColorOutput -Message "      • Virtual Machine Command Executor role (to query accessibility executables)`n" -Color "Gray"
            Write-ColorOutput -Message "    Option 2 (Common - Full VM Access):" -Color "White"
            Write-ColorOutput -Message "      • Virtual Machine Contributor role`n" -Color "Gray"
        }
        "exec" {
            Write-ColorOutput -Message "[*] Required Azure RBAC Roles for Remote Command Execution:`n" -Color "Yellow"
            Write-ColorOutput -Message "    VM Run Command (vmrun):" -Color "White"
            Write-ColorOutput -Message "      • Reader role (to list VMs)" -Color "Gray"
            Write-ColorOutput -Message "      • Virtual Machine Command Executor role (to execute commands)`n" -Color "Gray"
            Write-ColorOutput -Message "    Arc Run Command (arc):" -Color "White"
            Write-ColorOutput -Message "      • Azure Connected Machine Resource Administrator`n" -Color "Gray"
            Write-ColorOutput -Message "    MDE Live Response (mde):" -Color "White"
            Write-ColorOutput -Message "      • Machine.LiveResponse permission (Security API)" -Color "Gray"
            Write-ColorOutput -Message "      • Machine.Read.All permission`n" -Color "Gray"
            Write-ColorOutput -Message "    Intune Proactive Remediation (intune):" -Color "White"
            Write-ColorOutput -Message "      • DeviceManagementManagedDevices.PrivilegedOperations.All`n" -Color "Gray"
            Write-ColorOutput -Message "    Azure Automation (automation):" -Color "White"
            Write-ColorOutput -Message "      • Automation Contributor role`n" -Color "Gray"
        }
    }
    
    Write-ColorOutput -Message "[*] Role assignment scope: Subscription or Resource Group level" -Color "Yellow"
    Write-ColorOutput -Message "[*] If you lack permissions, the authentication will succeed but enumeration may fail`n" -Color "Yellow"
    
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
    "rid-brute" {
        # Azure equivalent of RID bruteforcing - enumerate all users via Graph API
        Write-ColorOutput -Message "`n[*] RID Bruteforce Mode (Azure Equivalent)" -Color "Yellow"
        Write-ColorOutput -Message "[*] Note: Azure AD uses GUIDs instead of sequential RIDs" -Color "Cyan"
        Write-ColorOutput -Message "[*] Enumerating all users via Microsoft Graph API...`n" -Color "Cyan"
        Invoke-UserProfileEnumeration -ExportPath $ExportPath
    }
    "groups" {
        Invoke-GroupEnumeration -ShowMembers $ShowOwners -ExportPath $ExportPath
    }
    "pass-pol" {
        Invoke-PasswordPolicyEnumeration -ExportPath $ExportPath
    }
    "guest" {
        Invoke-GuestEnumeration -Domain $Domain -Username $Username -Password $Password -UserFile $UserFile -PasswordFile $PasswordFile -ContinueOnSuccess $ContinueOnSuccess -NoBruteforce $NoBruteforce -Delay $Delay -ExportPath $ExportPath -AccessToken $AccessToken -LocalAuth $LocalAuth
    }
    "spray" {
        Invoke-PasswordSpray -Domain $Domain -UserFile $UserFile -Password $Password -PasswordFile $PasswordFile -ContinueOnSuccess $ContinueOnSuccess -NoBruteforce $NoBruteforce -Delay $Delay -ExportPath $ExportPath -LocalAuth $LocalAuth
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
    "storage-enum" {
        Invoke-StorageEnumeration -ResourceGroup $ResourceGroup -SubscriptionId $SubscriptionId -ExportPath $ExportPath
    }
    "keyvault-enum" {
        Invoke-KeyVaultEnumeration -ResourceGroup $ResourceGroup -SubscriptionId $SubscriptionId -ExportPath $ExportPath
    }
    "network-enum" {
        Invoke-NetworkEnumeration -ResourceGroup $ResourceGroup -SubscriptionId $SubscriptionId -ExportPath $ExportPath
    }
    "shares-enum" {
        Invoke-SharesEnumeration -ResourceGroup $ResourceGroup -SubscriptionId $SubscriptionId -SharesFilter $SharesFilter -ExportPath $ExportPath
    }
    "disks-enum" {
        Invoke-DisksEnumeration -ResourceGroup $ResourceGroup -SubscriptionId $SubscriptionId -ExportPath $ExportPath
    }
    "bitlocker-enum" {
        Invoke-BitLockerEnumeration -ResourceGroup $ResourceGroup -SubscriptionId $SubscriptionId -VMFilter $VMFilter -ExportPath $ExportPath
    }
    "process-enum" {
        Invoke-VMProcessEnumeration -ResourceGroup $ResourceGroup -SubscriptionId $SubscriptionId -VMFilter $VMFilter -ProcessName $ProcessName -ExportPath $ExportPath
    }
    "lockscreen-enum" {
        Invoke-LockscreenEnumeration -ResourceGroup $ResourceGroup -SubscriptionId $SubscriptionId -VMFilter $VMFilter -ExportPath $ExportPath
    }
    "local-groups" {
        Invoke-AdministrativeUnitsEnumeration -ShowMembers $ShowOwners -ExportPath $ExportPath
    }
    "av-enum" {
        Invoke-SecurityEnumeration -Filter $Filter -ExportPath $ExportPath
    }
    "intune-enum" {
        Invoke-IntuneEnumeration -ExportPath $ExportPath
    }
    "delegation-enum" {
        Invoke-DelegationEnumeration -ExportPath $ExportPath
    }
    "exec" {
        # Validate exec command has required parameter
        if (-not $x) {
            Write-ColorOutput -Message "[!] Error: -x parameter is required for exec command" -Color "Red"
            Write-ColorOutput -Message "[*] Usage: .\azx.ps1 exec -VMName 'vm-name' -x 'command'" -Color "Yellow"
            Write-ColorOutput -Message "[*]        .\azx.ps1 exec -ResourceGroup 'RG' -x 'command' -AllVMs" -Color "Yellow"
            Write-ColorOutput -Message "[*]        .\azx.ps1 exec -DeviceName 'device-name' -x 'command'" -Color "Yellow"
            Write-ColorOutput -Message "[*]        .\azx.ps1 exec -x 'command' -AllDevices" -Color "Yellow"
            return
        }
        Invoke-RemoteCommandExecution -x $x -VMName $VMName `
            -ResourceGroup $ResourceGroup -SubscriptionId $SubscriptionId `
            -VMFilter $VMFilter -ExecMethod $ExecMethod `
            -PowerShell:$PowerShell -AllVMs:$AllVMs `
            -DeviceName $DeviceName -AllDevices:$AllDevices `
            -Timeout $Timeout -ExportPath $ExportPath `
            -AmsiBypass $AmsiBypass
    }
    "help" {
        Show-Help
    }
    default {
        Write-ColorOutput -Message "[!] Unknown command: $Command" -Color "Red"
        Write-ColorOutput -Message "[*] Available commands: hosts, tenant, users, user-profiles, rid-brute, groups, pass-pol, guest, spray, vuln-list, sessions, guest-vuln-scan, apps, sp-discovery, roles, ca-policies, vm-loggedon, storage-enum, keyvault-enum, network-enum, shares-enum, disks-enum, bitlocker-enum, local-groups, av-enum, process-enum, lockscreen-enum, intune-enum, delegation-enum, exec, help" -Color "Yellow"
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
