## Planned Features

The following capabilities are planned for future releases:

  - Phase 1: Username enumeration via GetCredentialType API (no auth logs, stealthy)
  - Phase 2: ROPC-based password spray with lockout detection
  - Support for multiple attack patterns (single password, multi-password campaigns, username:password format)
  - Comprehensive result analysis and reporting capabilities
  - Smart delays and lockout avoidance
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
