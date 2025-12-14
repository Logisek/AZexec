## Planned Features

The following capabilities are planned for future releases:

- **User Profile Enumeration**: Enumerate detailed user information from Azure/Entra ID (requires authentication)
- **Guest User Vulnerability Scanner**: Automated testing for guest enumeration vulnerabilities
  - Detect if external collaboration is enabled
  - Test guest permission boundaries
  - Generate security assessment report
  - Compare guest vs member access levels
- **Group Membership Analysis**: Analyze group memberships and nested groups
- **Application Enumeration**: List registered applications and service principals
- **Service Principal Discovery**: Discover service principals and their permissions
- **Conditional Access Policy Review**: Review conditional access policies (member accounts only)
- **Role Assignments Enumeration**: List role assignments and privileged accounts
- **Advanced Querying**: Support for custom OData filters
- **Reporting**: Generate comprehensive HTML/PDF reports
- **Guest Activity Monitoring**: Generate detection rules for suspicious guest behavior

## Security Research Notes

### Guest User Enumeration (Azure Null Session)

**Critical Finding**: Guest users = modern null session equivalent

**Default Vulnerable Configuration:**
```
External collaboration: Enabled (default)
Guest user access: "Same as member users" OR "Limited access" (both allow enumeration)
Result: Guest users can enumerate directory with minimal detection
```

**Attack Chain:**
1. Obtain guest credentials (social engineering, compromised partner, etc.)
2. Authenticate to target tenant as guest
3. Use Microsoft Graph API to enumerate:
   - Users (names, emails, titles, departments)
   - Groups (names, descriptions, memberships)
   - Devices (names, OS, compliance status)
   - Applications (app registrations, service principals)
4. Identify high-value targets
5. Pivot to targeted attacks

**Detection Challenges:**
- Guest activity generates fewer alerts than compromised member accounts
- Many orgs don't monitor guest API usage
- Guest enumeration looks like "normal" external collaboration
- Low and slow enumeration can evade rate-based detections

**Defensive Measures:**
1. Set guest permissions to "Most restricted" (recommended)
2. Monitor Microsoft Graph API calls from guest users
3. Implement conditional access for guests
4. Regular guest account audits and cleanup
5. Alert on guest users with unusual API activity patterns

**Why Organizations Are Vulnerable:**
- Default settings prioritize collaboration over security
- Most IT admins unaware of guest enumeration capabilities
- Business pressure to enable external collaboration
- Lack of visibility into guest user activities
- Assumption that "guest" = limited access (false in default config)

---
