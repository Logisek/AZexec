# AZexec - Azure Execution Tool

**AZX** is a PowerShell-based Azure/Entra ID enumeration tool designed to provide netexec-style output for cloud environments. It's part of the **EvilMist** toolkit and offers a familiar command-line interface for security professionals and administrators working with Azure/Entra ID.

[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)

## 🎯 Features

- **Device Enumeration**: Query and display all devices registered in Azure/Entra ID
- **Netexec-Style Output**: Familiar output format for penetration testers and security professionals
- **Advanced Filtering**: Filter devices by OS, trust type, compliance status, and more
- **Owner Information**: Optional device owner enumeration with additional API calls
- **Export Capabilities**: Export results to CSV or JSON formats
- **Colored Output**: Color-coded output for better readability (can be disabled)
- **Automatic Authentication**: Handles Microsoft Graph API authentication seamlessly
- **PowerShell 7 Compatible**: Modern PowerShell implementation

## 📋 Requirements

- **PowerShell 7+** (PowerShell Core)
- **Microsoft.Graph PowerShell Module** (automatically installed if missing)
- **Azure/Entra ID Permissions**: 
  - Minimum: `Device.Read.All` scope
  - For owner enumeration: Additional directory read permissions may be required
- **Internet Connection**: Required for Microsoft Graph API access

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
.\azx.ps1 <Command> [-Filter <FilterType>] [-ShowOwners] [-NoColor] [-ExportPath <Path>] [-Scopes <Scopes>]
```

### Parameters

| Parameter | Description | Required | Default |
|-----------|-------------|----------|---------|
| `Command` | Operation to perform. Currently: `hosts` | Yes | - |
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

### Example 1: Basic Device Enumeration
Enumerate all devices in the Azure/Entra tenant:
```powershell
.\azx.ps1 hosts
```

### Example 2: Filter Windows Devices
Enumerate only Windows devices:
```powershell
.\azx.ps1 hosts -Filter windows
```

### Example 3: Azure AD Joined Devices with Owners
Enumerate Azure AD joined devices and display their registered owners:
```powershell
.\azx.ps1 hosts -Filter azuread -ShowOwners
```

### Example 4: Non-Compliant Devices with Export
Enumerate non-compliant devices and export results to CSV:
```powershell
.\azx.ps1 hosts -Filter noncompliant -ExportPath devices.csv
```

### Example 5: Export to JSON
Enumerate all devices and export to JSON format:
```powershell
.\azx.ps1 hosts -ExportPath results.json
```

### Example 6: Disable Colored Output
Enumerate devices without colored output (useful for logging):
```powershell
.\azx.ps1 hosts -NoColor
```

### Example 7: Hybrid Joined Devices Only
Enumerate only Hybrid Azure AD joined devices:
```powershell
.\azx.ps1 hosts -Filter hybrid
```

### Example 8: Disabled Devices
Find all disabled devices in the tenant:
```powershell
.\azx.ps1 hosts -Filter disabled
```

### Example 9: Compliant Windows Devices with Export
Enumerate compliant Windows devices and export:
```powershell
.\azx.ps1 hosts -Filter compliant | Where-Object { $_.OperatingSystem -like "Windows*" }
```
*Note: For complex filtering, combine with PowerShell pipeline*

### Example 10: Custom Scopes
Specify custom Microsoft Graph scopes:
```powershell
.\azx.ps1 hosts -Scopes "Device.Read.All,Directory.Read.All"
```

## 📊 Output Format

The tool provides netexec-style output with the following information:

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

On first run, the script will:
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

### CSV Export
```powershell
.\azx.ps1 hosts -ExportPath output.csv
```
Includes: DeviceId, DisplayName, OperatingSystem, OperatingSystemVersion, TrustType, IsCompliant, AccountEnabled, ApproximateLastSignInDateTime, RegisteredOwners

### JSON Export
```powershell
.\azx.ps1 hosts -ExportPath output.json
```
Structured JSON with all device properties

## 🔮 Planned Features

The following capabilities are planned for future releases:

- **User Enumeration**: Enumerate users from Azure/Entra ID
- **Group Membership Analysis**: Analyze group memberships and nested groups
- **Application Enumeration**: List registered applications and service principals
- **Service Principal Discovery**: Discover service principals and their permissions
- **Conditional Access Policy Review**: Review conditional access policies
- **Role Assignments Enumeration**: List role assignments and privileged accounts
- **Advanced Querying**: Support for custom OData filters
- **Reporting**: Generate comprehensive HTML/PDF reports

## 🛠️ Troubleshooting

### "Microsoft.Graph module not found"
The script will automatically install the module. If installation fails:
```powershell
Install-Module Microsoft.Graph -Scope CurrentUser -Force
```

### "Failed to connect to Microsoft Graph"
- Ensure you have internet connectivity
- Check if your organization allows Microsoft Graph API access
- Verify you have the necessary Azure/Entra ID permissions

### "No devices found"
- Verify your account has Device.Read.All permissions
- Check if your filter criteria is too restrictive
- Ensure devices exist in the tenant

### Permission Issues
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
