# AZexec - Azure Execution Tool

**AZX** is a PowerShell-based Azure/Entra ID enumeration tool designed to provide netexec-style output for cloud environments. It's part of the **EvilMist** toolkit and offers a familiar command-line interface for security professionals and administrators working with Azure/Entra ID.

[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)

## 🎯 Features

- **Tenant Discovery**: Discover Azure/Entra ID tenant configuration without authentication
- **Device Enumeration**: Query and display all devices registered in Azure/Entra ID
- **Netexec-Style Output**: Familiar output format for penetration testers and security professionals
- **Advanced Filtering**: Filter devices by OS, trust type, compliance status, and more
- **Owner Information**: Optional device owner enumeration with additional API calls
- **Export Capabilities**: Export results to CSV or JSON formats
- **Colored Output**: Color-coded output for better readability (can be disabled)
- **Automatic Authentication**: Handles Microsoft Graph API authentication seamlessly (for authenticated commands)
- **PowerShell 7 Compatible**: Modern PowerShell implementation

## 📋 Requirements

- **PowerShell 7+** (PowerShell Core)
- **Internet Connection**: Required for API access

### For Device Enumeration (hosts command):
- **Microsoft.Graph PowerShell Module** (automatically installed if missing)
- **Azure/Entra ID Permissions**: 
  - Minimum: `Device.Read.All` scope
  - For owner enumeration: Additional directory read permissions may be required

### For Tenant Discovery (tenant command):
- **No authentication required** - Uses public OpenID configuration endpoints

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

### Basic Syntax

```powershell
# Device enumeration
.\azx.ps1 hosts [-Filter <FilterType>] [-ShowOwners] [-NoColor] [-ExportPath <Path>] [-Scopes <Scopes>]

# Tenant discovery (auto-detects domain if not specified)
.\azx.ps1 tenant [-Domain <DomainName>] [-NoColor] [-ExportPath <Path>]
```

### Parameters

| Parameter | Description | Required | Default |
|-----------|-------------|----------|---------|
| `Command` | Operation to perform: `hosts`, `tenant` | Yes | - |
| `Domain` | Domain name for tenant discovery (auto-detected if not provided) | No | Auto-detect |
| `Filter` | Filter devices by criteria | No | `all` |
| `ShowOwners` | Display device owners (slower) | No | `False` |
| `NoColor` | Disable colored output | No | `False` |
| `ExportPath` | Export results to CSV or JSON | No | - |
| `Scopes` | Microsoft Graph scopes to request | No | `Device.Read.All` |

### Available Filters

- `all` - All devices (default)
- `windows` - Only Windows devices
- `azuread` - Only Azure AD joined devices
- `hybrid` - Only Hybrid Azure AD joined devices
- `compliant` - Only compliant devices
- `noncompliant` - Only non-compliant devices
- `disabled` - Only disabled devices

## 💡 Usage Examples

### Tenant Discovery Examples

### Example 1: Auto-Detect Current User's Domain
Discover tenant configuration for your current domain (auto-detected):
```powershell
.\azx.ps1 tenant
```

### Example 2: Basic Tenant Discovery
Discover tenant configuration for a specific domain:
```powershell
.\azx.ps1 tenant -Domain example.com
```

### Example 3: Tenant Discovery with Export
Discover tenant configuration and export to JSON:
```powershell
.\azx.ps1 tenant -Domain contoso.onmicrosoft.com -ExportPath tenant-info.json
```

### Example 4: Tenant Discovery for Multiple Domains
Discover configuration for multiple domains:
```powershell
@("example.com", "contoso.com", "fabrikam.onmicrosoft.com") | ForEach-Object { 
    .\azx.ps1 tenant -Domain $_ 
}
```

### Device Enumeration Examples

### Example 5: Basic Device Enumeration
Enumerate all devices in the Azure/Entra tenant:
```powershell
.\azx.ps1 hosts
```

### Example 6: Filter Windows Devices
Enumerate only Windows devices:
```powershell
.\azx.ps1 hosts -Filter windows
```

### Example 7: Azure AD Joined Devices with Owners
Enumerate Azure AD joined devices and display their registered owners:
```powershell
.\azx.ps1 hosts -Filter azuread -ShowOwners
```

### Example 8: Non-Compliant Devices with Export
Enumerate non-compliant devices and export results to CSV:
```powershell
.\azx.ps1 hosts -Filter noncompliant -ExportPath devices.csv
```

### Example 9: Export to JSON
Enumerate all devices and export to JSON format:
```powershell
.\azx.ps1 hosts -ExportPath results.json
```

### Example 10: Disable Colored Output
Enumerate devices without colored output (useful for logging):
```powershell
.\azx.ps1 hosts -NoColor
```

### Example 11: Hybrid Joined Devices Only
Enumerate only Hybrid Azure AD joined devices:
```powershell
.\azx.ps1 hosts -Filter hybrid
```

### Example 12: Disabled Devices
Find all disabled devices in the tenant:
```powershell
.\azx.ps1 hosts -Filter disabled
```

### Example 13: Compliant Windows Devices with Export
Enumerate compliant Windows devices and export:
```powershell
.\azx.ps1 hosts -Filter compliant | Where-Object { $_.OperatingSystem -like "Windows*" }
```
*Note: For complex filtering, combine with PowerShell pipeline*

### Example 14: Custom Scopes
Specify custom Microsoft Graph scopes:
```powershell
.\azx.ps1 hosts -Scopes "Device.Read.All,Directory.Read.All"
```

## 📊 Output Format

The tool provides netexec-style output with the following information:

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
```

**Information Retrieved:**
- Tenant ID (GUID)
- Authentication and authorization endpoints
- Token endpoints
- JWKS URI for token validation
- Tenant region and cloud instance
- Federation status (Managed vs Federated)
- Supported response types, scopes, and claims

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

## 🔐 Authentication

### Tenant Discovery (No Authentication Required)
The `tenant` command uses public OpenID configuration endpoints and does not require authentication. This makes it perfect for reconnaissance and initial discovery.

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

To use a different account or tenant:
```powershell
Disconnect-MgGraph
.\azx.ps1 hosts
```

## 📁 Export Formats

### Tenant Discovery Export

#### JSON Export (Recommended)
```powershell
.\azx.ps1 tenant -Domain example.com -ExportPath tenant.json
```
Includes: Domain, TenantId, Issuer, all endpoints, federation status, supported response types, scopes, claims, and full OpenID configuration

#### CSV Export
```powershell
.\azx.ps1 tenant -Domain example.com -ExportPath tenant.csv
```
Includes: Domain, TenantId, Issuer, endpoints, and federation status (simplified view)

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

## 🛠️ Troubleshooting

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

This tool is provided for legitimate security testing and administrative purposes only. Users are responsible for ensuring they have proper authorization before using this tool in any environment. The authors assume no liability for misuse or damage caused by this tool.

## 👤 Author

**Logisek**
- GitHub: [@Logisek](https://github.com/Logisek)
- Project Link: [https://github.com/Logisek/AZexec](https://github.com/Logisek/AZexec)

## 🌟 Acknowledgments

- Inspired by the netexec tool
- Built with Microsoft Graph PowerShell SDK

---

**Note**: This tool requires PowerShell 7+ and appropriate Azure/Entra ID permissions. Always ensure you have proper authorization before conducting any enumeration activities.
