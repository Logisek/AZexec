# AZexec - User Enumeration Functions
# These functions are loaded into the main script scope via dot-sourcing
function Get-CommonUsernames {
    param(
        [string]$Domain
    )
    
    # Common username patterns
    $commonNames = @(
        # Administrative accounts
        "admin",
        "administrator",
        "root",
        "sysadmin",
        "sa",
        "sql",
        "dba",
        "dbadmin",
        "dbmanager",
        "dbowner",
        "dbroot",
        "dbadmin",
        "dbmanager",
        "dbowner",
        "dbroot",
        
        # Support and helpdesk
        "support",
        "helpdesk",
        "servicedesk",
        "itadmin",
        "itsupport",
        "ithelp",
        "ithelper",
        
        # Security and compliance
        "security",
        "cybersecurity",
        "infosec",
        "secops",
        "dpo",
        "compliance",
        "privacy",
        "privacyofficer",
        
        # Business departments
        "accounting",
        "finance",
        "billing",
        "payroll",
        "invoices",
        "accounts",
        "hr",
        "humanresources",
        "recruitment",
        "sales",
        "marketing",
        "legal",
        "contracts",
        "contractsmanager",        
        
        # Communications
        "info",
        "contact",
        "hello",
        "noreply",
        "no-reply",
        "donotreply",
        "mailer",
        "postmaster",
        "webmaster",
        "notifications",
        "alerts",
        "social",
        "supportemail",
        
        # Web and portal accounts
        "webadmin",
        "webmail",
        "portal",
        "mail",
        "smtp",
        "imap",
        "help",
        
        # IT and operations
        "it",
        "dev",
        "developer",
        "ops",
        "devops",
        "sysops",
        "operations",
        "infrastructure",
        "network",
        "monitoring",
        "logs",
        "logging",
        "internal",
        "intranet",        
        
        # Service accounts
        "service",
        "backup",
        "reports",
        "reporting",
        "automation",
        "api",
        "webhook",
        
        # Testing and demo
        "test",
        "testing",
        "demo",
        "guest",
        "user",
        "users",
        
        # Executive accounts
        "ceo",
        "cfo",
        "cto",
        "cio",
        "cso",
        "ciso"
    )
    
    # Generate usernames with domain
    $usernames = @()
    foreach ($name in $commonNames) {
        $usernames += "$name@$Domain"
    }
    
    return $usernames
}

# Check username existence using GetCredentialType API
# ============================================
# PASSWORD SPRAY ATTACK WORKFLOW
# ============================================
# This function is Phase 1 of a two-phase password spray attack:
#
# PHASE 1: Username Enumeration (this function, called by 'users' command)
#   - Uses Microsoft's public GetCredentialType API
#   - No authentication required
#   - Does NOT trigger authentication logs (stealthy!)
#   - Validates which usernames exist in the tenant
#   - Returns authentication type (Managed/Federated/Alternate)
#
# PHASE 2: Password Spraying (Test-GuestAuthentication function, called by 'guest' command)
#   - Uses ROPC (Resource Owner Password Credentials) OAuth2 flow
#   - Tests actual username/password combinations
#   - Detects MFA requirements, account lockouts, password expiration
#   - Generates authentication logs (moderate stealth)
#
# WHY TWO PHASES?
#   1. GetCredentialType only validates usernames (not passwords)
#   2. Spraying only validated usernames reduces account lockout risk
#   3. Separating enumeration from auth testing improves OPSEC
#   4. Can test 100s of usernames quickly without triggering alerts
#
# EXAMPLE WORKFLOW:
#   Step 1: .\azx.ps1 users -Domain target.com -CommonUsernames -ExportPath valid-users.csv
#   Step 2: $validUsers = Import-Csv valid-users.csv | Where-Object { $_.Exists -eq 'True' } | Select-Object -ExpandProperty Username
#   Step 3: $validUsers | Out-File spray-targets.txt
#   Step 4: .\azx.ps1 guest -Domain target.com -UserFile spray-targets.txt -Password 'Summer2024!' -ExportPath spray-results.json
#
# ============================================
function Test-UsernameExistence {
    param(
        [string]$Username
    )
    
    try {
        $body = @{
            username = $Username
        } | ConvertTo-Json
        
        $response = Invoke-RestMethod `
            -Method POST `
            -Uri "https://login.microsoftonline.com/common/GetCredentialType" `
            -ContentType "application/json" `
            -Body $body `
            -ErrorAction Stop
        
        # Parse response
        $result = [PSCustomObject]@{
            Username = $Username
            Exists = $false
            IfExistsResult = $null
            ThrottleStatus = $null
            EstsProperties = $null
        }
        
        # IfExistsResult values:
        # 0 = User exists
        # 1 = User does not exist
        # 5 = User exists (different authentication)
        # 6 = User exists (federated)
        
        if ($response.IfExistsResult -ne $null) {
            $result.IfExistsResult = $response.IfExistsResult
            
            if ($response.IfExistsResult -eq 0 -or 
                $response.IfExistsResult -eq 5 -or 
                $response.IfExistsResult -eq 6) {
                $result.Exists = $true
            }
        }
        
        $result.ThrottleStatus = $response.ThrottleStatus
        $result.EstsProperties = $response.EstsProperties
        
        return $result
        
    } catch {
        # If we get an error, return null to indicate the check failed
        return $null
    }
}

# Format username enumeration output like netexec
function Format-UsernameOutput {
    param(
        [string]$Domain,
        [string]$Username,
        [PSCustomObject]$Result
    )
    
    if ($null -eq $Result) {
        # Check failed (network error, etc.)
        $output = "AZR".PadRight(12) + 
                  $Domain.PadRight(35) + 
                  "443".PadRight(7) + 
                  $Username.PadRight(38) + 
                  "[!] Check failed"
        Write-ColorOutput -Message $output -Color "Red"
        return
    }
    
    # Format output
    $username = $Result.Username
    $maxUsernameLength = 35
    $displayUsername = if ($username.Length -gt $maxUsernameLength) {
        $username.Substring(0, $maxUsernameLength - 3) + "..."
    } else {
        $username
    }
    
    if ($Result.Exists) {
        # User exists
        $status = switch ($Result.IfExistsResult) {
            0 { "[+] Valid username (Managed)" }
            5 { "[+] Valid username (Alternate auth)" }
            6 { "[+] Valid username (Federated)" }
            default { "[+] Valid username" }
        }
        
        $output = "AZR".PadRight(12) + 
                  $Domain.PadRight(35) + 
                  "443".PadRight(7) + 
                  $displayUsername.PadRight(38) + 
                  $status
        
        Write-ColorOutput -Message $output -Color "Green"
    } else {
        # User does not exist
        $output = "AZR".PadRight(12) + 
                  $Domain.PadRight(35) + 
                  "443".PadRight(7) + 
                  $displayUsername.PadRight(38) + 
                  "[-] Invalid username"
        
        Write-ColorOutput -Message $output -Color "DarkGray"
    }
}

# Main user enumeration function
function Invoke-UserEnumeration {
    param(
        [string]$Domain,
        [string]$Username,
        [string]$UserFile,
        [bool]$CommonUsernames,
        [string]$ExportPath
    )
    
    # Validate that at least one input method is provided
    if (-not $Username -and -not $UserFile -and -not $CommonUsernames) {
        Write-ColorOutput -Message "[!] Please provide one of: -Username, -UserFile, or -CommonUsernames" -Color "Red"
        Write-ColorOutput -Message "[*] Examples (domain is optional and will be auto-detected if not provided):" -Color "Yellow"
        Write-ColorOutput -Message "    .\azx.ps1 users -Username alice@example.com" -Color "Yellow"
        Write-ColorOutput -Message "    .\azx.ps1 users -CommonUsernames" -Color "Yellow"
        Write-ColorOutput -Message "    .\azx.ps1 users -Domain example.com -UserFile users.txt" -Color "Yellow"
        return
    }
    
    # Auto-detect domain if not provided
    if (-not $Domain) {
        Write-ColorOutput -Message "[*] No domain specified, attempting to auto-detect..." -Color "Yellow"
        
        $detectedDomain = $null
        
        try {
            if ($IsWindows -or $PSVersionTable.PSVersion.Major -le 5) {
                $upn = whoami /upn 2>$null
                if ($upn -and $upn -match '@(.+)$') {
                    $detectedDomain = $matches[1]
                }
            }
            
            if (-not $detectedDomain) {
                $envDomain = [System.Environment]::GetEnvironmentVariable("USERDNSDOMAIN")
                if ($envDomain) {
                    $detectedDomain = $envDomain
                }
            }
        } catch {
            # Silent catch
        }
        
        if ($detectedDomain) {
            $Domain = $detectedDomain
            Write-ColorOutput -Message "[+] Using auto-detected domain: $Domain`n" -Color "Green"
        } else {
            Write-ColorOutput -Message "[!] Could not auto-detect domain" -Color "Red"
            Write-ColorOutput -Message "[!] Please provide the domain using: -Domain example.com" -Color "Yellow"
            return
        }
    }
    
    Write-ColorOutput -Message "`n[*] AZX - Azure/Entra Username Enumeration" -Color "Yellow"
    Write-ColorOutput -Message "[*] Target Domain: $Domain" -Color "Yellow"
    Write-ColorOutput -Message "[*] Method: GetCredentialType API (No authentication required)`n" -Color "Yellow"
    
    # Build username list
    $usernames = @()
    
    if ($Username) {
        # Single username
        # If username doesn't contain @, append domain
        if ($Username -notlike "*@*") {
            $Username = "$Username@$Domain"
        }
        $usernames += $Username
        Write-ColorOutput -Message "[*] Checking single username: $Username`n" -Color "Yellow"
    }
    
    if ($UserFile) {
        # Read from file
        if (-not (Test-Path $UserFile)) {
            Write-ColorOutput -Message "[!] User file not found: $UserFile" -Color "Red"
            return
        }
        
        try {
            $fileUsernames = Get-Content $UserFile -ErrorAction Stop
            foreach ($user in $fileUsernames) {
                $user = $user.Trim()
                if ($user -and $user -notlike "#*") {  # Skip empty lines and comments
                    # If username doesn't contain @, append domain
                    if ($user -notlike "*@*") {
                        $user = "$user@$Domain"
                    }
                    $usernames += $user
                }
            }
            Write-ColorOutput -Message "[*] Loaded $($usernames.Count) usernames from file: $UserFile`n" -Color "Green"
        } catch {
            Write-ColorOutput -Message "[!] Failed to read user file: $_" -Color "Red"
            return
        }
    }
    
    if ($CommonUsernames) {
        # Use common usernames
        $commonUsers = Get-CommonUsernames -Domain $Domain
        $usernames += $commonUsers
        Write-ColorOutput -Message "[*] Using $($commonUsers.Count) common usernames`n" -Color "Yellow"
    }
    
    if ($usernames.Count -eq 0) {
        Write-ColorOutput -Message "[!] No usernames to check" -Color "Red"
        return
    }
    
    Write-ColorOutput -Message "[*] Checking $($usernames.Count) username(s)...`n" -Color "Yellow"
    
    # Check each username with progress indicator
    $results = @()
    $validUsers = @()
    $checkedCount = 0
    $failedCount = 0
    $startTime = Get-Date
    
    # Track auth types for statistics
    $authTypeStats = @{
        Managed = 0
        Federated = 0
        Alternate = 0
        Unknown = 0
    }
    
    foreach ($user in $usernames) {
        # Show progress for large lists (>10 users)
        if ($usernames.Count -gt 10) {
            $percentComplete = [math]::Round(($checkedCount / $usernames.Count) * 100)
            $elapsed = (Get-Date) - $startTime
            $estimatedTotal = if ($checkedCount -gt 0) { 
                $elapsed.TotalSeconds * ($usernames.Count / $checkedCount) 
            } else { 0 }
            $remaining = $estimatedTotal - $elapsed.TotalSeconds
            
            Write-Progress -Activity "Username Enumeration" `
                -Status "Checking $($checkedCount + 1)/$($usernames.Count): $user" `
                -PercentComplete $percentComplete `
                -SecondsRemaining ([math]::Max(0, $remaining))
        }
        
        # Test username with retry logic
        $result = $null
        $maxRetries = 3
        $retryCount = 0
        
        while ($retryCount -lt $maxRetries -and $null -eq $result) {
            $result = Test-UsernameExistence -Username $user
            
            if ($null -eq $result -and $retryCount -lt ($maxRetries - 1)) {
                # Exponential backoff: 100ms, 200ms, 400ms
                $backoffMs = 100 * [math]::Pow(2, $retryCount)
                Start-Sleep -Milliseconds $backoffMs
                $retryCount++
            } else {
                break
            }
        }
        
        Format-UsernameOutput -Domain $Domain -Username $user -Result $result
        
        if ($result) {
            if ($result.Exists) {
                $validUsers += $result
                
                # Track auth type statistics
                $authType = switch ($result.IfExistsResult) {
                    0 { "Managed" }
                    5 { "Alternate" }
                    6 { "Federated" }
                    default { "Unknown" }
                }
                $authTypeStats[$authType]++
            }
            $results += $result
        } else {
            $failedCount++
            # Still add to results for export
            $results += [PSCustomObject]@{
                Username = $user
                Exists = $false
                IfExistsResult = $null
                ThrottleStatus = $null
                EstsProperties = $null
                Error = "Failed after $maxRetries retries"
            }
        }
        
        $checkedCount++
        
        # Adaptive delay: faster for small lists, slower for large lists to avoid throttling
        $delayMs = if ($usernames.Count -lt 50) { 50 } 
                   elseif ($usernames.Count -lt 200) { 100 }
                   else { 150 }
        Start-Sleep -Milliseconds $delayMs
    }
    
    # Clear progress bar
    if ($usernames.Count -gt 10) {
        Write-Progress -Activity "Username Enumeration" -Completed
    }
    
    # Calculate duration
    $duration = (Get-Date) - $startTime
    $durationStr = "{0:mm}m {0:ss}s" -f $duration
    
    # Summary with enhanced statistics
    Write-ColorOutput -Message "`n[*] Username enumeration complete!" -Color "Green"
    Write-ColorOutput -Message "`n[*] Summary:" -Color "Yellow"
    Write-ColorOutput -Message "    Total Checked:   $checkedCount" -Color "Cyan"
    Write-ColorOutput -Message "    Valid Users:     $($validUsers.Count)" -Color "Green"
    Write-ColorOutput -Message "    Invalid Users:   $($checkedCount - $validUsers.Count - $failedCount)" -Color "DarkGray"
    if ($failedCount -gt 0) {
        Write-ColorOutput -Message "    Failed Checks:   $failedCount" -Color "Red"
    }
    Write-ColorOutput -Message "    Duration:        $durationStr" -Color "Cyan"
    Write-ColorOutput -Message "    Rate:            $([math]::Round($checkedCount / $duration.TotalSeconds, 2)) checks/sec" -Color "Cyan"
    
    # Auth type breakdown
    if ($validUsers.Count -gt 0) {
        Write-ColorOutput -Message "`n[*] Authentication Type Breakdown:" -Color "Yellow"
        if ($authTypeStats['Managed'] -gt 0) {
            Write-ColorOutput -Message "    Managed:    $($authTypeStats['Managed'])" -Color "Green"
        }
        if ($authTypeStats['Federated'] -gt 0) {
            Write-ColorOutput -Message "    Federated:  $($authTypeStats['Federated'])" -Color "Green"
        }
        if ($authTypeStats['Alternate'] -gt 0) {
            Write-ColorOutput -Message "    Alternate:  $($authTypeStats['Alternate'])" -Color "Green"
        }
        if ($authTypeStats['Unknown'] -gt 0) {
            Write-ColorOutput -Message "    Unknown:    $($authTypeStats['Unknown'])" -Color "Yellow"
        }
    }
    
    # Export if requested
    if ($ExportPath) {
        try {
            $extension = [System.IO.Path]::GetExtension($ExportPath).ToLower()
            
            $exportData = @()
            foreach ($result in $results) {
                if ($result) {
                    $exportData += [PSCustomObject]@{
                        Username = $result.Username
                        Exists = $result.Exists
                        IfExistsResult = $result.IfExistsResult
                        AuthType = switch ($result.IfExistsResult) {
                            0 { "Managed" }
                            5 { "Alternate" }
                            6 { "Federated" }
                            default { "Unknown" }
                        }
                        ThrottleStatus = $result.ThrottleStatus
                        Error = if ($result.PSObject.Properties['Error']) { $result.Error } else { $null }
                    }
                }
            }
            
            if ($extension -eq ".csv") {
                $exportData | Export-Csv -Path $ExportPath -NoTypeInformation -Force
                Write-ColorOutput -Message "`n[+] Results exported to: $ExportPath" -Color "Green"
            } elseif ($extension -eq ".json") {
                $exportData | ConvertTo-Json -Depth 5 | Out-File -FilePath $ExportPath -Force
                Write-ColorOutput -Message "`n[+] Results exported to: $ExportPath" -Color "Green"
            } elseif ($extension -eq ".html") {
                $stats = [ordered]@{
                    "Total Checked" = $results.Count
                    "Valid Usernames" = $validUsers.Count
                    "Managed Auth" = ($validUsers | Where-Object { $_.IfExistsResult -eq 0 }).Count
                    "Federated Auth" = ($validUsers | Where-Object { $_.IfExistsResult -eq 6 }).Count
                    "Invalid Usernames" = ($results | Where-Object { $_.Exists -eq $false }).Count
                }
                
                $description = "Username enumeration results for domain: $Domain. This phase validates username existence without authentication."
                
                $success = Export-HtmlReport -Data $exportData -OutputPath $ExportPath -Title "Username Enumeration Report" -Statistics $stats -CommandName "users" -Description $description
                
                if ($success) {
                    Write-ColorOutput -Message "`n[+] HTML report exported to: $ExportPath" -Color "Green"
                }
            } else {
                # Default to CSV
                $exportData | Export-Csv -Path $ExportPath -NoTypeInformation -Force
                Write-ColorOutput -Message "`n[+] Results exported to: $ExportPath" -Color "Green"
            }
        } catch {
            Write-ColorOutput -Message "`n[!] Failed to export results: $_" -Color "Red"
        }
    }
    
    # Display valid usernames
    if ($validUsers.Count -gt 0) {
        Write-ColorOutput -Message "`n[*] Valid Usernames Found:" -Color "Green"
        foreach ($validUser in $validUsers) {
            $authType = switch ($validUser.IfExistsResult) {
                0 { "Managed" }
                5 { "Alternate" }
                6 { "Federated" }
                default { "Unknown" }
            }
            Write-ColorOutput -Message "    [+] $($validUser.Username) ($authType)" -Color "Green"
        }
        
        # Security tip for password spraying
        Write-ColorOutput -Message "`n[*] Next Steps:" -Color "Yellow"
        Write-ColorOutput -Message "    To perform password spraying with these valid users:" -Color "Cyan"
        if ($ExportPath) {
            Write-ColorOutput -Message "    1. Extract valid users: `$users = Import-Csv '$ExportPath' | Where { `$_.Exists -eq 'True' } | Select -ExpandProperty Username" -Color "Cyan"
            Write-ColorOutput -Message "    2. Save to file: `$users | Out-File spray-targets.txt" -Color "Cyan"
            Write-ColorOutput -Message "    3. Run spray: .\azx.ps1 guest -Domain $Domain -UserFile spray-targets.txt -Password 'YourPassword123!'" -Color "Cyan"
        } else {
            Write-ColorOutput -Message "    .\azx.ps1 guest -Domain $Domain -Username <username> -Password 'YourPassword123!'" -Color "Cyan"
        }
    }
}


function Format-UserProfileOutput {
    param(
        [PSCustomObject]$User
    )
    
    # User display name
    $displayName = if ($User.DisplayName) { $User.DisplayName } else { "UNKNOWN" }
    
    # Truncate long names for column display
    $maxNameLength = 35
    $displayNameShort = if ($displayName.Length -gt $maxNameLength) {
        $displayName.Substring(0, $maxNameLength - 3) + "..."
    } else {
        $displayName
    }
    
    # Use first 15 chars of user ID for alignment
    $userIdShort = if ($User.Id) { 
        $User.Id.Substring(0, [Math]::Min(15, $User.Id.Length))
    } else { 
        "UNKNOWN-ID" 
    }
    
    # User Principal Name
    $upn = if ($User.UserPrincipalName) { $User.UserPrincipalName } else { "N/A" }
    
    # Job title
    $jobTitle = if ($User.JobTitle) { $User.JobTitle } else { "N/A" }
    
    # Department
    $department = if ($User.Department) { $User.Department } else { "N/A" }
    
    # User type (Member or Guest)
    $userType = if ($User.UserType) { $User.UserType } else { "Member" }
    
    # Account enabled status
    $accountEnabled = if ($User.AccountEnabled) { "Enabled" } else { "Disabled" }
    
    # Office location
    $officeLocation = if ($User.OfficeLocation) { $User.OfficeLocation } else { "N/A" }
    
    # Last sign-in date
    $lastSignIn = if ($User.SignInActivity -and $User.SignInActivity.LastSignInDateTime) { 
        $User.SignInActivity.LastSignInDateTime.ToString("yyyy-MM-dd")
    } else { 
        "Never/Unknown" 
    }
    
    $output = "AZR".PadRight(12) + 
              $userIdShort.PadRight(17) + 
              "443".PadRight(7) + 
              $displayNameShort.PadRight(38) + 
              "[*] (upn:$upn) (job:$jobTitle) (dept:$department) (type:$userType) (status:$accountEnabled) (location:$officeLocation) (lastSignIn:$lastSignIn)"
    
    # Color based on user type and status
    $color = "Cyan"
    if ($userType -eq "Guest") {
        $color = "Yellow"  # Guest users in yellow
    } elseif ($accountEnabled -eq "Disabled") {
        $color = "DarkGray"  # Disabled users in gray
    } else {
        $color = "Green"  # Active member users in green
    }
    
    Write-ColorOutput -Message $output -Color $color
}

# Main user profile enumeration function
function Invoke-UserProfileEnumeration {
    param(
        [string]$ExportPath
    )
    
    Write-ColorOutput -Message "`n[*] AZX - Azure/Entra User Profile Enumeration" -Color "Yellow"
    Write-ColorOutput -Message "[*] Command: User Profile Enumeration (Authenticated)" -Color "Yellow"
    Write-ColorOutput -Message "[*] Method: Microsoft Graph API with current user permissions`n" -Color "Yellow"
    
    # Get context to display current user info
    $context = Get-MgContext
    if ($context) {
        Write-ColorOutput -Message "[*] Authenticated as: $($context.Account)" -Color "Cyan"
        Write-ColorOutput -Message "[*] Tenant: $($context.TenantId)`n" -Color "Cyan"
    }
    
    # Get all users
    Write-ColorOutput -Message "[*] Retrieving user profiles from Azure/Entra ID..." -Color "Yellow"
    Write-ColorOutput -Message "[*] This may take a while for large organizations...`n" -Color "Yellow"
    
    try {
        # Try to get users with sign-in activity (requires AuditLog.Read.All)
        # If that fails, fall back to basic user info
        $allUsers = @()
        
        try {
            Write-ColorOutput -Message "[*] Attempting to retrieve users with sign-in activity..." -Color "Yellow"
            $allUsers = Get-MgUser -All -Property "Id,DisplayName,UserPrincipalName,JobTitle,Department,UserType,AccountEnabled,OfficeLocation,Mail,SignInActivity" -ErrorAction Stop
            Write-ColorOutput -Message "[+] Retrieved $($allUsers.Count) users with sign-in activity`n" -Color "Green"
        } catch {
            # Fall back to basic properties if sign-in activity is not available
            Write-ColorOutput -Message "[!] Could not retrieve sign-in activity (requires AuditLog.Read.All)" -Color "Yellow"
            Write-ColorOutput -Message "[*] Falling back to basic user properties...`n" -Color "Yellow"
            $allUsers = Get-MgUser -All -Property "Id,DisplayName,UserPrincipalName,JobTitle,Department,UserType,AccountEnabled,OfficeLocation,Mail" -ErrorAction Stop
            Write-ColorOutput -Message "[+] Retrieved $($allUsers.Count) users`n" -Color "Green"
        }
        
    } catch {
        Write-ColorOutput -Message "[!] Failed to retrieve users: $_" -Color "Red"
        Write-ColorOutput -Message "[!] Ensure you have User.Read.All or Directory.Read.All permissions" -Color "Red"
        Write-ColorOutput -Message "[*] Guest users may have restricted access to user enumeration" -Color "Yellow"
        return
    }
    
    if ($allUsers.Count -eq 0) {
        Write-ColorOutput -Message "[!] No users found or insufficient permissions" -Color "Red"
        return
    }
    
    Write-ColorOutput -Message "[*] Displaying $($allUsers.Count) users`n" -Color "Green"
    
    # Prepare export data
    $exportData = @()
    
    # Enumerate users
    foreach ($user in $allUsers) {
        Format-UserProfileOutput -User $user
        
        # Collect for export
        if ($ExportPath) {
            $lastSignIn = if ($user.SignInActivity -and $user.SignInActivity.LastSignInDateTime) {
                $user.SignInActivity.LastSignInDateTime
            } else {
                $null
            }
            
            $exportData += [PSCustomObject]@{
                UserId              = $user.Id
                DisplayName         = $user.DisplayName
                UserPrincipalName   = $user.UserPrincipalName
                Mail                = $user.Mail
                JobTitle            = $user.JobTitle
                Department          = $user.Department
                OfficeLocation      = $user.OfficeLocation
                UserType            = $user.UserType
                AccountEnabled      = $user.AccountEnabled
                LastSignInDateTime  = $lastSignIn
            }
        }
    }
    
    # Calculate summary statistics
    $memberUsers = ($allUsers | Where-Object { $_.UserType -eq "Member" -or -not $_.UserType }).Count
    $guestUsers = ($allUsers | Where-Object { $_.UserType -eq "Guest" }).Count
    $enabledUsers = ($allUsers | Where-Object { $_.AccountEnabled -eq $true }).Count
    $disabledUsers = ($allUsers | Where-Object { $_.AccountEnabled -eq $false }).Count
    
    # Export if requested
    if ($ExportPath) {
        try {
            $extension = [System.IO.Path]::GetExtension($ExportPath).ToLower()
            
            if ($extension -eq ".csv") {
                $exportData | Export-Csv -Path $ExportPath -NoTypeInformation -Force
                Write-ColorOutput -Message "`n[+] Results exported to: $ExportPath" -Color "Green"
            } elseif ($extension -eq ".json") {
                $exportData | ConvertTo-Json -Depth 5 | Out-File -FilePath $ExportPath -Force
                Write-ColorOutput -Message "`n[+] Results exported to: $ExportPath" -Color "Green"
            } elseif ($extension -eq ".html") {
                $stats = [ordered]@{
                    "Total Users" = $allUsers.Count
                    "Member Users" = $memberUsers
                    "Guest Users" = $guestUsers
                    "Enabled Accounts" = $enabledUsers
                    "Disabled Accounts" = $disabledUsers
                }
                
                $description = "Comprehensive user profile enumeration including job titles, departments, and account status. Includes sign-in activity when available."
                
                $success = Export-HtmlReport -Data $exportData -OutputPath $ExportPath -Title "User Profile Enumeration Report" -Statistics $stats -CommandName "user-profiles" -Description $description
                
                if ($success) {
                    Write-ColorOutput -Message "`n[+] HTML report exported to: $ExportPath" -Color "Green"
                }
            } else {
                # Default to CSV
                $exportData | Export-Csv -Path $ExportPath -NoTypeInformation -Force
                Write-ColorOutput -Message "`n[+] Results exported to: $ExportPath" -Color "Green"
            }
        } catch {
            Write-ColorOutput -Message "`n[!] Failed to export results: $_" -Color "Red"
        }
    }
    
    Write-ColorOutput -Message "`n[*] User profile enumeration complete!" -Color "Green"
    
    # Display summary statistics
    Write-ColorOutput -Message "`n[*] Summary:" -Color "Yellow"
    Write-ColorOutput -Message "    Total Users: $($allUsers.Count)" -Color "Cyan"
    Write-ColorOutput -Message "    Member Users: $memberUsers" -Color "Cyan"
    Write-ColorOutput -Message "    Guest Users: $guestUsers" -Color "Cyan"
    Write-ColorOutput -Message "    Enabled Accounts: $enabledUsers" -Color "Cyan"
    Write-ColorOutput -Message "    Disabled Accounts: $disabledUsers" -Color "Cyan"
}

