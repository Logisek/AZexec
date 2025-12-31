# AZexec - Session and VM Enumeration Functions
# These functions are loaded into the main script scope via dot-sourcing
function Invoke-SessionEnumeration {
    param(
        [string]$Username,
        [string]$ExportPath,
        [int]$Hours = 24
    )
    
    Write-ColorOutput -Message "`n[*] AZX - Azure/Entra Active Session Enumeration" -Color "Yellow"
    Write-ColorOutput -Message "[*] Command: Sessions (Similar to: nxc smb --qwinsta)" -Color "Yellow"
    Write-ColorOutput -Message "[*] Querying sign-in logs for last $Hours hours..." -Color "Cyan"
    
    # Initialize connection context
    try {
        $context = Get-MgContext -ErrorAction SilentlyContinue
        
        if (-not $context) {
            Write-ColorOutput -Message "[!] Not authenticated to Microsoft Graph" -Color "Red"
            Write-ColorOutput -Message "[*] Attempting authentication..." -Color "Yellow"
            
            # Connect with required permissions
            $requiredScopes = "AuditLog.Read.All,Directory.Read.All"
            Connect-GraphAPI -Scopes $requiredScopes
            $context = Get-MgContext
        }
        
        if ($context) {
            Write-ColorOutput -Message "[+] Authenticated as: $($context.Account)" -Color "Green"
            
            # Check if current user is guest
            $isGuest = Test-IsGuestUser -UserPrincipalName $context.Account
            if ($isGuest) {
                Write-ColorOutput -Message "[!] Warning: Guest users typically have limited access to audit logs" -Color "Yellow"
            }
        }
    } catch {
        Write-ColorOutput -Message "[!] Failed to get authentication context: $($_.Exception.Message)" -Color "Red"
        return
    }
    
    # Calculate time filter
    $startTime = (Get-Date).AddHours(-$Hours).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
    
    Write-ColorOutput -Message "`n[*] ========================================" -Color "Cyan"
    Write-ColorOutput -Message "[*] ACTIVE SIGN-IN SESSIONS" -Color "Cyan"
    Write-ColorOutput -Message "[*] ========================================`n" -Color "Cyan"
    
    $sessions = @()
    $uniqueUsers = @{}
    
    try {
        # Build filter query
        $filterQuery = "createdDateTime ge $startTime"
        if ($Username) {
            $filterQuery += " and userPrincipalName eq '$Username'"
        }
        
        # Query sign-in logs
        Write-ColorOutput -Message "[*] Querying Azure Entra ID sign-in logs (this may take a moment)..." -Color "Cyan"
        
        $uri = "https://graph.microsoft.com/v1.0/auditLogs/signIns?`$filter=$filterQuery&`$top=999&`$orderby=createdDateTime desc"
        
        $allSignIns = @()
        do {
            $response = Invoke-MgGraphRequest -Uri $uri -Method GET -ErrorAction Stop
            $allSignIns += $response.value
            $uri = $response.'@odata.nextLink'
        } while ($uri)
        
        if ($allSignIns.Count -eq 0) {
            Write-ColorOutput -Message "[!] No sign-in events found in the last $Hours hours" -Color "Yellow"
            if ($Username) {
                Write-ColorOutput -Message "[!] No sign-ins found for user: $Username" -Color "Yellow"
            }
            return
        }
        
        Write-ColorOutput -Message "[+] Found $($allSignIns.Count) sign-in events" -Color "Green"
        Write-ColorOutput -Message ""
        
        # Process and display sessions
        foreach ($signIn in $allSignIns) {
            # Track unique users
            $userKey = $signIn.userPrincipalName
            if (-not $uniqueUsers.ContainsKey($userKey)) {
                $uniqueUsers[$userKey] = 0
            }
            $uniqueUsers[$userKey]++
            
            # Determine success/failure status
            $statusColor = if ($signIn.status.errorCode -eq 0) { "Green" } else { "Red" }
            $statusIcon = if ($signIn.status.errorCode -eq 0) { "+" } else { "!" }
            $statusText = if ($signIn.status.errorCode -eq 0) { "SUCCESS" } else { "FAILED" }
            
            # Format device info
            $deviceName = if ($signIn.deviceDetail.displayName) { 
                $signIn.deviceDetail.displayName 
            } else { 
                "Unknown Device" 
            }
            
            $deviceOS = if ($signIn.deviceDetail.operatingSystem) {
                $signIn.deviceDetail.operatingSystem
            } else {
                "Unknown OS"
            }
            
            # Format location
            $location = if ($signIn.location.city -and $signIn.location.countryOrRegion) {
                "$($signIn.location.city), $($signIn.location.countryOrRegion)"
            } elseif ($signIn.location.countryOrRegion) {
                $signIn.location.countryOrRegion
            } else {
                "Unknown Location"
            }
            
            # Format IP address
            $ipAddress = if ($signIn.ipAddress) { $signIn.ipAddress } else { "N/A" }
            
            # Format application
            $appName = if ($signIn.appDisplayName) { $signIn.appDisplayName } else { "Unknown App" }
            
            # Format timestamp
            $timestamp = ([DateTime]$signIn.createdDateTime).ToLocalTime().ToString("yyyy-MM-dd HH:mm:ss")
            
            # Risk level (if available)
            $riskLevel = if ($signIn.riskLevelDuringSignIn -and $signIn.riskLevelDuringSignIn -ne "none") {
                $signIn.riskLevelDuringSignIn.ToUpper()
            } else {
                $null
            }
            
            # MFA details
            $mfaRequired = $signIn.conditionalAccessStatus -eq "success" -or $signIn.authenticationRequirement -eq "multiFactorAuthentication"
            
            # Build session object
            $sessionObj = [PSCustomObject]@{
                Timestamp = $timestamp
                User = $signIn.userPrincipalName
                DisplayName = $signIn.userDisplayName
                Status = $statusText
                ErrorCode = $signIn.status.errorCode
                ErrorReason = $signIn.status.failureReason
                Application = $appName
                DeviceName = $deviceName
                OperatingSystem = $deviceOS
                Browser = $signIn.deviceDetail.browser
                IsCompliant = $signIn.deviceDetail.isCompliant
                IsManagedDevice = $signIn.deviceDetail.isManaged
                IPAddress = $ipAddress
                Location = $location
                RiskLevel = $riskLevel
                MFARequired = $mfaRequired
                ConditionalAccessStatus = $signIn.conditionalAccessStatus
                SessionId = $signIn.id
            }
            
            $sessions += $sessionObj
            
            # Display in netexec-style format
            # Handle null/empty userPrincipalName
            $displayUser = if ($signIn.userPrincipalName) { $signIn.userPrincipalName } else { $signIn.userDisplayName }
            if (-not $displayUser) { $displayUser = "Unknown User" }
            
            $userDisplay = $displayUser.PadRight(45)
            $ipDisplay = $ipAddress.PadRight(15)
            
            Write-ColorOutput -Message "AZR".PadRight(12) + $userDisplay + $ipDisplay + "[$statusIcon] $statusText" -Color $statusColor
            
            # Show display name if different from UPN
            if ($signIn.userDisplayName -and $signIn.userDisplayName -ne $displayUser) {
                Write-ColorOutput -Message "    Name:      $($signIn.userDisplayName)" -Color "DarkGray"
            }
            Write-ColorOutput -Message "    Time:      $timestamp" -Color "DarkGray"
            Write-ColorOutput -Message "    Device:    $deviceName ($deviceOS)" -Color "DarkGray"
            Write-ColorOutput -Message "    App:       $appName" -Color "DarkGray"
            Write-ColorOutput -Message "    Location:  $location" -Color "DarkGray"
            
            if ($mfaRequired) {
                Write-ColorOutput -Message "    MFA:       Required" -Color "Cyan"
            }
            
            if ($riskLevel) {
                $riskColor = switch ($riskLevel) {
                    "HIGH" { "Red" }
                    "MEDIUM" { "Yellow" }
                    default { "Cyan" }
                }
                Write-ColorOutput -Message "    Risk:      $riskLevel" -Color $riskColor
            }
            
            if ($signIn.status.errorCode -ne 0) {
                Write-ColorOutput -Message "    Error:     $($signIn.status.failureReason)" -Color "Red"
            }
            
            Write-ColorOutput -Message ""
        }
        
        # Summary statistics
        Write-ColorOutput -Message "`n[*] ========================================" -Color "Cyan"
        Write-ColorOutput -Message "[*] SESSION SUMMARY" -Color "Cyan"
        Write-ColorOutput -Message "[*] ========================================`n" -Color "Cyan"
        
        $successCount = ($sessions | Where-Object { $_.Status -eq "SUCCESS" }).Count
        $failedCount = ($sessions | Where-Object { $_.Status -eq "FAILED" }).Count
        $uniqueUserCount = $uniqueUsers.Count
        $mfaCount = ($sessions | Where-Object { $_.MFARequired -eq $true }).Count
        $riskyCount = ($sessions | Where-Object { $_.RiskLevel -ne $null }).Count
        
        Write-ColorOutput -Message "AZR".PadRight(12) + "Total Sign-ins:      $($sessions.Count)" -Color "Cyan"
        Write-ColorOutput -Message "AZR".PadRight(12) + "Unique Users:        $uniqueUserCount" -Color "Cyan"
        Write-ColorOutput -Message "AZR".PadRight(12) + "Successful:          $successCount" -Color "Green"
        if ($failedCount -gt 0) {
            Write-ColorOutput -Message "AZR".PadRight(12) + "Failed:              $failedCount" -Color "Red"
        }
        if ($mfaCount -gt 0) {
            Write-ColorOutput -Message "AZR".PadRight(12) + "MFA Protected:       $mfaCount" -Color "Cyan"
        }
        if ($riskyCount -gt 0) {
            Write-ColorOutput -Message "AZR".PadRight(12) + "Risky Sign-ins:      $riskyCount" -Color "Yellow"
        }
        
        # Top users
        if ($uniqueUsers.Count -gt 1) {
            Write-ColorOutput -Message "`n[*] Top Active Users:" -Color "Yellow"
            $topUsers = $uniqueUsers.GetEnumerator() | Sort-Object -Property Value -Descending | Select-Object -First 5
            foreach ($user in $topUsers) {
                Write-ColorOutput -Message "    $($user.Name): $($user.Value) sign-ins" -Color "DarkGray"
            }
        }
        
        # Top applications
        $appCounts = @{}
        foreach ($session in $sessions) {
            if (-not $appCounts.ContainsKey($session.Application)) {
                $appCounts[$session.Application] = 0
            }
            $appCounts[$session.Application]++
        }
        
        if ($appCounts.Count -gt 0) {
            Write-ColorOutput -Message "`n[*] Top Applications:" -Color "Yellow"
            $topApps = $appCounts.GetEnumerator() | Sort-Object -Property Value -Descending | Select-Object -First 5
            foreach ($app in $topApps) {
                Write-ColorOutput -Message "    $($app.Name): $($app.Value) sign-ins" -Color "DarkGray"
            }
        }
        
        # Export if requested
        if ($ExportPath) {
            try {
                $extension = [System.IO.Path]::GetExtension($ExportPath).ToLower()
                
                if ($extension -eq ".csv") {
                    $sessions | Export-Csv -Path $ExportPath -NoTypeInformation -Force
                    Write-ColorOutput -Message "`n[+] Session data exported to: $ExportPath" -Color "Green"
                } elseif ($extension -eq ".json") {
                    $sessions | ConvertTo-Json -Depth 10 | Out-File -FilePath $ExportPath -Force
                    Write-ColorOutput -Message "`n[+] Session data exported to: $ExportPath" -Color "Green"
                } elseif ($extension -eq ".html") {
                    $stats = [ordered]@{
                        "Total Sign-in Events" = $sessions.Count
                        "Unique Users" = $uniqueUsers.Count
                        "Successful Sign-ins" = $successCount
                        "Failed Sign-ins" = $failedCount
                        "Risky Sign-ins (HIGH RISK)" = $riskyCount
                        "MFA Required Sign-ins" = $mfaCount
                        "Time Range (Hours)" = $Hours
                    }
                    
                    $description = "Active sign-in session enumeration from Azure/Entra ID audit logs. Shows recent authentication events, device details, locations, and security risk levels."
                    
                    $success = Export-HtmlReport -Data $sessions -OutputPath $ExportPath -Title "Active Session Enumeration Report" -Statistics $stats -CommandName "sessions" -Description $description
                    
                    if ($success) {
                        Write-ColorOutput -Message "`n[+] HTML report exported to: $ExportPath" -Color "Green"
                    }
                } else {
                    # Default to JSON
                    $sessions | ConvertTo-Json -Depth 10 | Out-File -FilePath $ExportPath -Force
                    Write-ColorOutput -Message "`n[+] Session data exported to: $ExportPath" -Color "Green"
                }
            } catch {
                Write-ColorOutput -Message "`n[!] Failed to export results: $_" -Color "Red"
            }
        }
        
        Write-ColorOutput -Message "`n[*] Session enumeration complete!" -Color "Green"
        
    } catch {
        # Check if it's a permission error
        if ($_.Exception.Message -like "*403*" -or $_.Exception.Message -like "*Forbidden*" -or $_.Exception.Message -like "*Insufficient privileges*") {
            Write-ColorOutput -Message "[!] Access Denied: Insufficient permissions to read sign-in logs" -Color "Red"
            Write-ColorOutput -Message "[*] Required permissions: AuditLog.Read.All or Directory.Read.All" -Color "Yellow"
            Write-ColorOutput -Message "[*] Guest users typically cannot access audit logs" -Color "Yellow"
        } else {
            Write-ColorOutput -Message "[!] Failed to enumerate sessions" -Color "Red"
            Write-ColorOutput -Message "[!] Error: $($_.Exception.Message)" -Color "Red"
        }
    }
    
    return $sessions
}

# Enumerate logged-on users on Azure VMs
# This is the Azure equivalent of NetExec's Workstation Service (wkssvc) enumeration
# 
# On-Premises: nxc smb 192.168.1.0/24 -u User -p Pass --loggedon-users
#   - Uses Workstation Service (wkssvc) RPC interface over SMB
#   - Calls NetWkstaUserEnum to enumerate logged-on users
#   - Requires network access and valid credentials
#
# Azure Cloud: .\azx.ps1 vm-loggedon
#   - Uses Azure VM Run Command API (similar to PsExec/WinRM)
#   - Executes 'quser' (Windows) or 'who' (Linux) directly on VMs
#   - Requires Azure RBAC permissions (VM Contributor or VM Command Executor)
#   - Works across subscriptions and resource groups
#
# Both methods enumerate: username, session type, state, idle time, connection source

function Invoke-VMLoggedOnUsersEnumeration {
    param(
        [string]$ResourceGroup,
        [string]$SubscriptionId,
        [string]$VMFilter,
        [string]$ExportPath
    )
    
    Write-ColorOutput -Message "`n[*] AZX - Azure VM Logged-On Users Enumeration" -Color "Yellow"
    Write-ColorOutput -Message "[*] Command: VM-LoggedOn (Similar to: nxc smb --logged-on-users)" -Color "Yellow"
    Write-ColorOutput -Message "[*] Azure equivalent of Workstation Service (wkssvc) enumeration" -Color "Cyan"
    Write-ColorOutput -Message "[*] Uses Azure VM Run Command instead of RPC/SMB`n" -Color "Cyan"
    
    # Use shared helper functions from AzureRM.ps1
    $requiredModules = @('Az.Accounts', 'Az.Compute', 'Az.Resources')
    if (-not (Initialize-AzureRMModules -RequiredModules $requiredModules)) {
        return
    }
    
    # Connect to Azure using shared helper
    $azContext = Connect-AzureRM
    if (-not $azContext) { return }
    
    # Get subscriptions to enumerate using shared helper
    $subscriptionsToScan = Get-SubscriptionsToEnumerate -SubscriptionId $SubscriptionId -CurrentContext $azContext
    if (-not $subscriptionsToScan) { return }
    
    # Global counters across all subscriptions
    $exportData = @()
    $totalLoggedOnUsers = 0
    $successfulQueries = 0
    $failedQueries = 0
    $totalVMsFound = 0
    $totalVMsQueried = 0
    
    Write-ColorOutput -Message "[*] ========================================" -Color "Cyan"
    Write-ColorOutput -Message "[*] MULTI-SUBSCRIPTION VM ENUMERATION" -Color "Cyan"
    Write-ColorOutput -Message "[*] ========================================`n" -Color "Cyan"
    
    # Loop through each subscription
    foreach ($subscription in $subscriptionsToScan) {
        # Use shared helper for subscription context switching
        if (-not (Set-SubscriptionContext -Subscription $subscription)) {
            continue
        }
        
        # Get VMs in this subscription
        Write-ColorOutput -Message "[*] Retrieving Azure VMs..." -Color "Yellow"
        
        try {
            $vms = @()
            if ($ResourceGroup) {
                $vms = @(Get-AzVM -ResourceGroupName $ResourceGroup -Status -ErrorAction Stop)
                if ($vms.Count -gt 0) {
                    Write-ColorOutput -Message "[+] Retrieved $($vms.Count) VM(s) from resource group: $ResourceGroup" -Color "Green"
                } else {
                    Write-ColorOutput -Message "[*] No VMs found in resource group: $ResourceGroup" -Color "Yellow"
                }
            } else {
                $vms = @(Get-AzVM -Status -ErrorAction Stop)
                if ($vms.Count -gt 0) {
                    Write-ColorOutput -Message "[+] Retrieved $($vms.Count) VM(s) across all resource groups" -Color "Green"
                } else {
                    Write-ColorOutput -Message "[*] No VMs found in this subscription" -Color "Yellow"
                }
            }
        } catch {
            $errorMessage = $_.Exception.Message
            
            # Parse Azure authorization error for cleaner display
            if ($errorMessage -like "*AuthorizationFailed*" -or $errorMessage -like "*does not have authorization*") {
                Write-ColorOutput -Message "[!] Authorization failed for subscription: $($subscription.Name)" -Color "Red"
                Write-ColorOutput -Message "[*] You don't have permission to list VMs in this subscription" -Color "Yellow"
                Write-ColorOutput -Message "[*] Skipping to next subscription...`n" -Color "Yellow"
            } else {
                Write-ColorOutput -Message "[!] Error retrieving VMs: $errorMessage" -Color "Red"
                Write-ColorOutput -Message "[*] Skipping to next subscription...`n" -Color "Yellow"
            }
            continue
        }
        
        if ($vms.Count -eq 0) {
            Write-ColorOutput -Message "[*] No VMs to enumerate in this subscription`n" -Color "Yellow"
            continue
        }
        
        $totalVMsFound += $vms.Count
        
        # Apply VM filter
        $filteredVMs = $vms
        if ($VMFilter -ne "all") {
            $filteredVMs = @($vms | Where-Object {
                $powerState = ($_.PowerState -split ' ')[-1]
                if ($VMFilter -eq "running") {
                    # Match running or available states
                    $powerState -match "running|available"
                } elseif ($VMFilter -eq "stopped") {
                    # Not running/available
                    $powerState -notmatch "running|available"
                } else {
                    $true
                }
            })
            Write-ColorOutput -Message "[*] Filtered to $($filteredVMs.Count) VM(s) with status: $VMFilter`n" -Color "Cyan"
        }
        
        if ($filteredVMs.Count -eq 0) {
            Write-ColorOutput -Message "[*] No VMs matching filter: $VMFilter`n" -Color "Yellow"
            continue
        }
        
        $totalVMsQueried += $filteredVMs.Count
        
        # Enumerate VMs in this subscription
        foreach ($vm in $filteredVMs) {
        $vmName = $vm.Name
        $vmResourceGroup = $vm.ResourceGroupName
        $powerState = ($vm.PowerState -split ' ')[-1]
        $osType = $vm.StorageProfile.OsDisk.OsType
        
        # Check if VM is in a running/available state
        # Azure may report different states: "running", "Available", "VM running", etc.
        $isRunning = $powerState -match "running|available"
        $stateColor = if ($isRunning) { "Green" } else { "Yellow" }
        
        Write-ColorOutput -Message "[*] VM: $vmName" -Color "White"
        Write-ColorOutput -Message "    Resource Group: $vmResourceGroup" -Color "Gray"
        Write-ColorOutput -Message "    OS Type: $osType" -Color "Gray"
        Write-ColorOutput -Message "    Power State: $powerState" -Color $stateColor
        
        # Only query running/available VMs
        if (-not $isRunning) {
            Write-ColorOutput -Message "    [!] VM is not in running state - skipping query" -Color "Yellow"
            $failedQueries++
            Write-Host ""
            continue
        }
        
        # Prepare script based on OS type
        $scriptContent = ""
        $scriptId = ""
        
        if ($osType -eq "Windows") {
            $scriptContent = @"
# Query logged-on users using quser (same as Remote Registry Service would show)
try {
    `$users = quser 2>&1 | Select-Object -Skip 1
    if (`$users) {
        `$users | ForEach-Object {
            if (`$_ -match '^\s*(\S+)\s+(\S*)\s+(\d+)\s+(\S+)\s+(.+)$') {
                `$username = `$matches[1]
                `$sessionName = `$matches[2]
                `$id = `$matches[3]
                `$state = `$matches[4]
                `$idleTime = `$matches[5]
                Write-Output "USER:`$username|SESSION:`$sessionName|ID:`$id|STATE:`$state|IDLE:`$idleTime"
            }
        }
    } else {
        Write-Output "NO_USERS_LOGGED_ON"
    }
} catch {
    Write-Output "ERROR:`$(`$_.Exception.Message)"
}
"@
            $scriptId = "RunPowerShellScript"
        } else {
            # Linux
            $scriptContent = @"
#!/bin/bash
# Query logged-on users (equivalent to Windows Remote Registry Service)
users_output=`$(who 2>&1)
if [ `$? -eq 0 ] && [ -n "`$users_output" ]; then
    echo "`$users_output" | awk '{print "USER:" `$1 "|TTY:" `$2 "|LOGIN:" `$3 " " `$4 "|FROM:" `$5}'
else
    echo "NO_USERS_LOGGED_ON"
fi
"@
            $scriptId = "RunShellScript"
        }
        
        # Execute Run Command
        Write-ColorOutput -Message "    [*] Querying logged-on users..." -Color "Yellow"
        
        try {
            $result = Invoke-AzVMRunCommand -ResourceGroupName $vmResourceGroup -VMName $vmName -CommandId $scriptId -ScriptString $scriptContent -ErrorAction Stop
            
            $output = $result.Value[0].Message
            
            # Clean up Azure RunCommand output artifacts
            # Remove "Enable succeeded:", "[stdout]", "[stderr]" and other metadata
            $output = $output -replace "Enable succeeded:", ""
            $output = $output -replace "\[stdout\]", ""
            $output = $output -replace "\[stderr\]", ""
            $output = $output.Trim()
            
            if ($output -match "NO_USERS_LOGGED_ON") {
                Write-ColorOutput -Message "    [+] Query successful - No users currently logged on" -Color "Cyan"
                $successfulQueries++
            } elseif ($output -match "ERROR:") {
                $errorMsg = ($output -split "ERROR:")[1]
                Write-ColorOutput -Message "    [!] Error querying users: $errorMsg" -Color "Red"
                $failedQueries++
            } else {
                $loggedOnUsers = @()
                $lines = $output -split "`n" | Where-Object { $_.Trim() -ne "" -and $_ -notmatch "^\s*$" }
                
                foreach ($line in $lines) {
                    if ($osType -eq "Windows") {
                        if ($line -match "USER:([^|]+)\|SESSION:([^|]*)\|ID:([^|]+)\|STATE:([^|]+)\|IDLE:(.+)") {
                            $loggedOnUsers += [PSCustomObject]@{
                                Subscription = $subscription.Name
                                SubscriptionId = $subscription.Id
                                VM = $vmName
                                ResourceGroup = $vmResourceGroup
                                OSType = $osType
                                Username = $matches[1].Trim()
                                SessionName = $matches[2].Trim()
                                SessionID = $matches[3].Trim()
                                State = $matches[4].Trim()
                                IdleTime = $matches[5].Trim()
                                Location = ""
                            }
                        }
                    } else {
                        # Linux
                        if ($line -match "USER:([^|]+)\|TTY:([^|]*)\|LOGIN:([^|]+)\|FROM:(.*)") {
                            $loggedOnUsers += [PSCustomObject]@{
                                Subscription = $subscription.Name
                                SubscriptionId = $subscription.Id
                                VM = $vmName
                                ResourceGroup = $vmResourceGroup
                                OSType = $osType
                                Username = $matches[1].Trim()
                                SessionName = $matches[2].Trim()
                                SessionID = "-"
                                State = "Active"
                                IdleTime = "-"
                                Location = $matches[4].Trim()
                            }
                        }
                    }
                }
                
                if ($loggedOnUsers.Count -gt 0) {
                    Write-ColorOutput -Message "    [+] Found $($loggedOnUsers.Count) logged-on user(s):" -Color "Green"
                    
                    foreach ($user in $loggedOnUsers) {
                        $displayName = $user.Username
                        $displayState = $user.State
                        $displaySession = if ($user.SessionName) { $user.SessionName } else { "console" }
                        
                        # NetExec style output
                        Write-ColorOutput -Message "        [*] $displayName" -Color "Cyan"
                        Write-ColorOutput -Message "            Session: $displaySession | State: $displayState | Idle: $($user.IdleTime)" -Color "Gray"
                        if ($user.Location) {
                            Write-ColorOutput -Message "            From: $($user.Location)" -Color "Gray"
                        }
                    }
                    
                    $exportData += $loggedOnUsers
                    $totalLoggedOnUsers += $loggedOnUsers.Count
                    $successfulQueries++
                } else {
                    Write-ColorOutput -Message "    [!] Query returned data but could not parse users" -Color "Yellow"
                    Write-ColorOutput -Message "    [*] Raw output: $output" -Color "Gray"
                    $failedQueries++
                }
            }
        } catch {
            $errorMessage = $_.Exception.Message
            
            # Check for common permission issues
            if ($errorMessage -like "*AuthorizationFailed*" -or $errorMessage -like "*Microsoft.Compute/virtualMachines/runCommand/action*") {
                Write-ColorOutput -Message "    [!] Authorization failed - Missing 'Virtual Machine Contributor' role or 'runCommand' permission" -Color "Red"
            } elseif ($errorMessage -like "*VM agent*" -or $errorMessage -like "*GuestAgent*") {
                Write-ColorOutput -Message "    [!] VM Guest Agent is not running or not installed" -Color "Red"
            } elseif ($errorMessage -like "*timeout*") {
                Write-ColorOutput -Message "    [!] Query timed out - VM may be unresponsive" -Color "Red"
            } else {
                Write-ColorOutput -Message "    [!] Failed to query users: $errorMessage" -Color "Red"
            }
            
            $failedQueries++
            }
            
            Write-Host ""
        } # End VM loop
        
        Write-ColorOutput -Message "[*] Subscription enumeration complete`n" -Color "Green"
    } # End subscription loop
    
    # Summary across all subscriptions
    Write-ColorOutput -Message "`n[*] ========================================" -Color "Cyan"
    Write-ColorOutput -Message "[*] MULTI-SUBSCRIPTION ENUMERATION SUMMARY" -Color "Cyan"
    Write-ColorOutput -Message "[*] ========================================`n" -Color "Cyan"
    
    Write-ColorOutput -Message "[*] Subscriptions Scanned: $($subscriptionsToScan.Count)" -Color "White"
    Write-ColorOutput -Message "[*] Total VMs Found: $totalVMsFound" -Color "White"
    Write-ColorOutput -Message "[*] VMs Queried (after filters): $totalVMsQueried" -Color "White"
    Write-ColorOutput -Message "[*] Successful Queries: $successfulQueries" -Color "Green"
    Write-ColorOutput -Message "[*] Failed Queries: $failedQueries" -Color "Red"
    Write-ColorOutput -Message "[*] Total Logged-On Users Found: $totalLoggedOnUsers" -Color "Cyan"
    
    # Export if requested
    if ($ExportPath -and $exportData.Count -gt 0) {
        try {
            $extension = [System.IO.Path]::GetExtension($ExportPath).ToLower()
            
            switch ($extension) {
                ".csv" {
                    $exportData | Export-Csv -Path $ExportPath -NoTypeInformation -ErrorAction Stop
                    Write-ColorOutput -Message "`n[+] Results exported to: $ExportPath" -Color "Green"
                }
                ".json" {
                    $exportData | ConvertTo-Json -Depth 10 | Out-File -FilePath $ExportPath -ErrorAction Stop
                    Write-ColorOutput -Message "`n[+] Results exported to: $ExportPath" -Color "Green"
                }
                ".html" {
                    $stats = @{
                        "Subscriptions Scanned" = $subscriptionsToScan.Count
                        "Total VMs Found" = $totalVMsFound
                        "VMs Queried" = $totalVMsQueried
                        "Successful Queries" = $successfulQueries
                        "Failed Queries" = $failedQueries
                        "Total Logged-On Users" = $totalLoggedOnUsers
                    }
                    
                    Export-HtmlReport -Data $exportData -OutputPath $ExportPath -Title "Azure VM Logged-On Users" -Statistics $stats -CommandName "vm-loggedon" -Description "Enumeration of logged-on users on Azure VMs (equivalent to Remote Registry Service)"
                    Write-ColorOutput -Message "`n[+] HTML report exported to: $ExportPath" -Color "Green"
                }
                default {
                    Write-ColorOutput -Message "`n[!] Unsupported export format. Use .csv, .json, or .html" -Color "Red"
                }
            }
        } catch {
            Write-ColorOutput -Message "`n[!] Failed to export results: $_" -Color "Red"
        }
    } elseif ($ExportPath -and $exportData.Count -eq 0) {
        Write-ColorOutput -Message "`n[!] No data to export" -Color "Yellow"
    }
    
    # Helpful tips
    if ($failedQueries -gt 0) {
        Write-ColorOutput -Message "`n[*] TIP: To query VMs, you need:" -Color "Yellow"
        Write-ColorOutput -Message "    - 'Virtual Machine Contributor' role OR 'Reader' + 'Virtual Machine Command Executor' role" -Color "Yellow"
        Write-ColorOutput -Message "    - VM Guest Agent must be running on each VM" -Color "Yellow"
        Write-ColorOutput -Message "    - VMs must be in 'running' state" -Color "Yellow"
    }
    
    # Multi-subscription tips
    if ($subscriptionsToScan.Count -gt 1 -and -not $SubscriptionId) {
        Write-ColorOutput -Message "`n[*] MULTI-SUBSCRIPTION SCAN:" -Color "Cyan"
        Write-ColorOutput -Message "    - Scanned $($subscriptionsToScan.Count) subscriptions automatically" -Color "Cyan"
        Write-ColorOutput -Message "    - Use -SubscriptionId to target a specific subscription" -Color "Cyan"
        Write-ColorOutput -Message "    - Export includes subscription information for each user" -Color "Cyan"
        
        # Show which subscriptions had issues
        $failedSubs = $subscriptionsToScan | Where-Object { 
            $subId = $_.Id
            -not ($exportData | Where-Object { $_.SubscriptionId -eq $subId })
        }
        if ($failedSubs.Count -gt 0) {
            Write-ColorOutput -Message "`n[*] Subscriptions with issues (0 VMs or errors):" -Color "Yellow"
            foreach ($sub in $failedSubs) {
                Write-ColorOutput -Message "    • $($sub.Name) - Try: .\azx.ps1 vm-loggedon -SubscriptionId $($sub.Id)" -Color "Yellow"
            }
        }
    }
    
    if ($totalLoggedOnUsers -gt 0) {
        Write-ColorOutput -Message "`n[*] NEXT STEPS:" -Color "Cyan"
        Write-ColorOutput -Message "    - Investigate logged-on users for privileged accounts" -Color "Cyan"
        Write-ColorOutput -Message "    - Correlate with Azure AD sign-in logs: .\azx.ps1 sessions" -Color "Cyan"
        Write-ColorOutput -Message "    - Check for stale sessions or suspicious activity" -Color "Cyan"
        if ($subscriptionsToScan.Count -gt 1) {
            Write-ColorOutput -Message "    - Review users across multiple subscriptions for anomalies" -Color "Cyan"
        }
    }
    
    return $exportData
}

# Main guest enumeration function
