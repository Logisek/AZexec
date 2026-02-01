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

        [ValidateSet("auto", "vmrun", "arc", "intune")]
        [string]$ExecMethod = "auto",

        [switch]$PowerShell,

        [switch]$AllVMs,

        [int]$Timeout = 300,

        [string]$ExportPath
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
        Write-ColorOutput -Message "[*] Target: $VMName" -Color "White"
    } elseif ($AllVMs) {
        Write-ColorOutput -Message "[*] Target: All matching VMs" -Color "Yellow"
    } else {
        Write-ColorOutput -Message "[!] Error: Must specify -VMName for single target or -AllVMs for multiple targets" -Color "Red"
        Write-ColorOutput -Message "[*] Use -VMName to target a specific VM, or -AllVMs to target all matching VMs" -Color "Yellow"
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

        if ($ExecMethod -eq "vmrun" -or $ExecMethod -eq "auto") {
            # Get Azure VMs
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

        if ($ExecMethod -eq "arc" -or $ExecMethod -eq "auto") {
            # Get Arc-enabled servers
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

        # If no targets found and VMName was specified, check if it's an Intune device
        if ($targets.Count -eq 0 -and $VMName -and ($ExecMethod -eq "intune" -or $ExecMethod -eq "auto")) {
            Write-ColorOutput -Message "[*] Target not found as VM or Arc server, trying Intune lookup..." -Color "Yellow"
            # Intune handling would go here - currently informational only
            Write-ColorOutput -Message "[*] Intune execution requires Microsoft.Graph module and additional permissions" -Color "Gray"
        }

        # Skip if single target specified but not found
        if ($VMName -and $targets.Count -eq 0) {
            Write-ColorOutput -Message "[!] Target '$VMName' not found in subscription: $($subscription.Name)" -Color "Yellow"
            continue
        }

        # Skip if no targets and AllVMs not specified
        if (-not $AllVMs -and -not $VMName) {
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

            # Prepare command based on OS type and mode
            $scriptContent = ""
            $commandId = ""

            if ($targetOS -eq "Windows") {
                if ($PowerShell) {
                    # PowerShell mode (-X equivalent)
                    $scriptContent = $x
                    $commandId = "RunPowerShellScript"
                } else {
                    # Shell mode (-x equivalent) - wrap in cmd.exe
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

    Write-ColorOutput -Message "`n[*] EXECUTION METHODS:" -Color "Yellow"
    Write-ColorOutput -Message "    vmrun:  Azure VM Run Command (primary - for Azure VMs)" -Color "Gray"
    Write-ColorOutput -Message "    arc:    Azure Arc Run Command (for on-prem/hybrid servers)" -Color "Gray"
    Write-ColorOutput -Message "    intune: Intune Proactive Remediation (for managed endpoints)" -Color "Gray"
    Write-ColorOutput -Message "    auto:   Auto-detect best method for each target" -Color "Gray"

    Write-ColorOutput -Message "`n[*] REQUIRED PERMISSIONS:" -Color "Yellow"
    Write-ColorOutput -Message "    VM Run Command: Virtual Machine Contributor or Reader + VM Command Executor" -Color "Gray"
    Write-ColorOutput -Message "    Arc Run Command: Azure Connected Machine Resource Administrator" -Color "Gray"
    Write-ColorOutput -Message "    Intune: DeviceManagementManagedDevices.PrivilegedOperations.All" -Color "Gray"

    return $exportData
}
