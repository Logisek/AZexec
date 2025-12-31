# AZexec - UI Functions (Banner and Help)
# These functions are loaded into the main script scope via dot-sourcing
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
        @{Name="vm-loggedon"; Auth="Required"; Description="Enumerate logged-on users on Azure VMs (mimics nxc smb --logged-on-users)"}
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
    Write-Host "    .\azx.ps1 vm-loggedon -VMFilter running  - Enumerate logged-on users on running VMs"
    
    Write-ColorOutput -Message "`n[*] For detailed help and more examples, see README.md or use Get-Help .\azx.ps1" -Color "Cyan"
    Write-Host ""
}

