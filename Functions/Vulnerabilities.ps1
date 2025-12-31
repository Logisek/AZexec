# AZexec - Vulnerability Enumeration Functions
# These functions are loaded into the main script scope via dot-sourcing
function Invoke-VulnListEnumeration {
    param(
        [string]$Domain,
        [string]$ExportPath
    )
    
    Write-ColorOutput -Message "`n[*] AZX - Vulnerable Target Enumeration" -Color "Yellow"
    Write-ColorOutput -Message "[*] Command: Vuln-List (Azure Relay Target Equivalent)" -Color "Yellow"
    Write-ColorOutput -Message "[*] Similar to: nxc smb 192.168.1.0/24 --gen-relay-list`n" -Color "Yellow"
    
    $vulnTargets = @()
    $unauthFindings = @()
    $authFindings = @()
    
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
            # Method 1: Try to get UPN from whoami command (Windows)
            if ($IsWindows -or $PSVersionTable.PSVersion.Major -le 5) {
                $upn = whoami /upn 2>$null
                if ($upn -and $upn -match '@(.+)$') {
                    $detectedDomain = $matches[1]
                    Write-ColorOutput -Message "[+] Detected domain from UPN: $detectedDomain" -Color "Green"
                }
            }
            
            # Method 2: Try environment variable for USERDNSDOMAIN
            if (-not $detectedDomain) {
                $envDomain = [System.Environment]::GetEnvironmentVariable("USERDNSDOMAIN")
                if ($envDomain) {
                    $detectedDomain = $envDomain
                    Write-ColorOutput -Message "[+] Detected domain from environment: $detectedDomain" -Color "Green"
                }
            }
            
            # Method 3: Try to get domain from current user's email-like username
            if (-not $detectedDomain) {
                $currentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
                if ($currentUser -match '@(.+)$') {
                    $detectedDomain = $matches[1]
                    Write-ColorOutput -Message "[+] Detected domain from username: $detectedDomain" -Color "Green"
                }
            }
            
            # Method 4: Check if already connected to Graph
            if (-not $detectedDomain) {
                try {
                    $context = Get-MgContext -ErrorAction SilentlyContinue
                    if ($context -and $context.Account -match '@(.+)$') {
                        $detectedDomain = $matches[1]
                        Write-ColorOutput -Message "[+] Detected domain from Graph context: $detectedDomain" -Color "Green"
                    }
                } catch {
                    # Silent - Graph not connected yet
                }
            }
        } catch {
            # Silent catch - we'll handle the error below
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
    
    # 1.1 Check tenant configuration (unauthenticated)
    if ($Domain) {
        Write-ColorOutput -Message "[*] Checking tenant configuration for: $Domain" -Color "Yellow"
        
        $openIdConfigUrl = "https://login.microsoftonline.com/$Domain/.well-known/openid-configuration"
        
        try {
            $openIdConfig = Invoke-RestMethod -Uri $openIdConfigUrl -Method Get -ErrorAction Stop
            
            # Extract tenant ID
            $tenantId = $null
            if ($openIdConfig.issuer -match '([a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})') {
                $tenantId = $matches[1]
            }
            
            Write-ColorOutput -Message "    [+] Tenant ID: $tenantId" -Color "Green"
            
            # Check for implicit flow (OAuth misconfiguration)
            if ($openIdConfig.response_types_supported -contains "token" -or 
                $openIdConfig.response_types_supported -contains "id_token token") {
                $finding = [PSCustomObject]@{
                    Type = "TenantConfig"
                    Target = $Domain
                    Vulnerability = "ImplicitFlowEnabled"
                    Risk = "MEDIUM"
                    Description = "Implicit OAuth flow enabled - potential token theft risk"
                    Authenticated = $false
                }
                $unauthFindings += $finding
                Write-ColorOutput -Message "    [!] IMPLICIT FLOW ENABLED - Token theft risk" -Color "Yellow"
            }
            
        } catch {
            Write-ColorOutput -Message "    [!] Could not retrieve tenant configuration" -Color "Red"
        }
        
        # 1.2 Check external collaboration / guest access settings
        Write-ColorOutput -Message "`n[*] Testing guest/external authentication..." -Color "Yellow"
        
        $guestTestUrl = "https://login.microsoftonline.com/$Domain/oauth2/v2.0/token"
        $testBody = @{
            client_id     = "1b730954-1685-4b74-9bfd-dac224a7b894"  # Azure PowerShell client
            grant_type    = "password"
            username      = "nonexistent_test_user_12345@$Domain"
            password      = "TestPassword123!"
            scope         = "https://graph.microsoft.com/.default"
        }
        
        try {
            $null = Invoke-RestMethod -Uri $guestTestUrl -Method Post -Body $testBody -ContentType "application/x-www-form-urlencoded" -ErrorAction Stop
        } catch {
            $errorResponse = $_.ErrorDetails.Message | ConvertFrom-Json -ErrorAction SilentlyContinue
            
            if ($errorResponse.error -eq "invalid_grant") {
                $errorDesc = $errorResponse.error_description
                
                # AADSTS50034 = user doesn't exist (but tenant accepts ROPC)
                if ($errorDesc -match "AADSTS50034") {
                    $finding = [PSCustomObject]@{
                        Type = "TenantConfig"
                        Target = $Domain
                        Vulnerability = "ROPCEnabled"
                        Risk = "HIGH"
                        Description = "Resource Owner Password Credentials (ROPC) flow accepted - Password spray possible"
                        Authenticated = $false
                    }
                    $unauthFindings += $finding
                    Write-ColorOutput -Message "    [!] ROPC ENABLED - Password spray/brute force possible" -Color "Red"
                }
                
                # AADSTS50053 = account locked (but ROPC works)
                if ($errorDesc -match "AADSTS50053") {
                    $finding = [PSCustomObject]@{
                        Type = "TenantConfig"
                        Target = $Domain
                        Vulnerability = "ROPCEnabled"
                        Risk = "HIGH"
                        Description = "ROPC flow accepted (account lockout detected)"
                        Authenticated = $false
                    }
                    $unauthFindings += $finding
                    Write-ColorOutput -Message "    [!] ROPC ENABLED - Account lockout policy detected" -Color "Yellow"
                }
                
                # AADSTS50126 = invalid password (ROPC works, user exists)
                if ($errorDesc -match "AADSTS50126") {
                    Write-ColorOutput -Message "    [+] ROPC enabled, user validation possible" -Color "Green"
                }
            }
            
            # AADSTS7000218 = ROPC disabled (good security)
            if ($_.ErrorDetails.Message -match "AADSTS7000218") {
                Write-ColorOutput -Message "    [+] ROPC DISABLED - Good security posture" -Color "Green"
            }
        }
        
        # 1.3 Check for legacy authentication endpoints
        Write-ColorOutput -Message "`n[*] Checking legacy authentication endpoints..." -Color "Yellow"
        
        $legacyEndpoints = @(
            @{ Name = "Exchange ActiveSync"; Url = "https://outlook.office365.com/Microsoft-Server-ActiveSync"; Method = "OPTIONS" },
            @{ Name = "Autodiscover"; Url = "https://autodiscover.$Domain/autodiscover/autodiscover.xml"; Method = "GET" },
            @{ Name = "EWS"; Url = "https://outlook.office365.com/EWS/Exchange.asmx"; Method = "OPTIONS" }
        )
        
        foreach ($endpoint in $legacyEndpoints) {
            try {
                $response = Invoke-WebRequest -Uri $endpoint.Url -Method $endpoint.Method -TimeoutSec 5 -ErrorAction SilentlyContinue -UseBasicParsing
                if ($response.StatusCode -in @(200, 401, 403)) {
                    Write-ColorOutput -Message "    [*] $($endpoint.Name) endpoint accessible" -Color "DarkGray"
                }
            } catch {
                if ($_.Exception.Response.StatusCode -eq 401) {
                    Write-ColorOutput -Message "    [*] $($endpoint.Name) endpoint accessible (requires auth)" -Color "DarkGray"
                }
            }
        }
    }
    
    # ============================================
    # PHASE 2: AUTHENTICATED CHECKS
    # ============================================
    Write-ColorOutput -Message "`n[*] PHASE 2: Authenticated Enumeration" -Color "Cyan"
    Write-ColorOutput -Message "[*] ========================================`n" -Color "Cyan"
    
    # Check if we can connect to Graph
    $graphConnected = $false
    try {
        $context = Get-MgContext -ErrorAction SilentlyContinue
        if ($context) {
            $graphConnected = $true
            Write-ColorOutput -Message "[+] Using existing Graph connection: $($context.Account)" -Color "Green"
        }
    } catch {
        # Not connected yet
    }
    
    if (-not $graphConnected) {
        Write-ColorOutput -Message "[*] Attempting to connect to Microsoft Graph..." -Color "Yellow"
        try {
            # Request scopes needed for vuln enumeration
            Connect-MgGraph -Scopes "Application.Read.All","Directory.Read.All","Policy.Read.All","AuditLog.Read.All" -ErrorAction Stop
            $context = Get-MgContext
            $graphConnected = $true
            Write-ColorOutput -Message "[+] Connected as: $($context.Account)" -Color "Green"
            
            # Check if user is a guest
            $isGuest = Test-IsGuestUser -UserPrincipalName $context.Account
            if ($isGuest) {
                Write-ColorOutput -Message "[!] GUEST USER - Some enumeration may be restricted`n" -Color "Yellow"
            }
        } catch {
            Write-ColorOutput -Message "[!] Could not connect to Microsoft Graph" -Color "Yellow"
            Write-ColorOutput -Message "[*] Authenticated checks will be skipped" -Color "DarkGray"
            Write-ColorOutput -Message "[*] Error: $($_.Exception.Message)" -Color "DarkGray"
        }
    }
    
    if ($graphConnected) {
        Write-ColorOutput -Message ""
        
        # 2.1 Service Principals with Password Credentials (HIGH VALUE)
        Write-ColorOutput -Message "[*] Enumerating Service Principals with password credentials..." -Color "Yellow"
        Write-ColorOutput -Message "    (Like SMB hosts without signing - weaker authentication)" -Color "DarkGray"
        
        try {
            $servicePrincipals = Get-MgServicePrincipal -All -Property "id,displayName,appId,passwordCredentials,keyCredentials,servicePrincipalType" -ErrorAction Stop
            
            $passwordOnlyCount = 0
            foreach ($sp in $servicePrincipals) {
                $hasPasswordCred = $sp.PasswordCredentials.Count -gt 0
                $hasCertCred = $sp.KeyCredentials.Count -gt 0
                
                if ($hasPasswordCred -and -not $hasCertCred) {
                    # Password-only = VULNERABLE (like SMB signing disabled)
                    $finding = [PSCustomObject]@{
                        Type = "ServicePrincipal"
                        Target = $sp.DisplayName
                        AppId = $sp.AppId
                        ObjectId = $sp.Id
                        Vulnerability = "PasswordCredentialOnly"
                        Risk = "HIGH"
                        Description = "Uses password credential without certificate - vulnerable to credential theft"
                        Authenticated = $true
                        CredentialCount = $sp.PasswordCredentials.Count
                        ExpiringCredentials = ($sp.PasswordCredentials | Where-Object { $_.EndDateTime -lt (Get-Date).AddDays(30) }).Count
                    }
                    $authFindings += $finding
                    $passwordOnlyCount++
                    
                    if ($passwordOnlyCount -le 10) {
                        $expiring = if ($finding.ExpiringCredentials -gt 0) { " [EXPIRING SOON]" } else { "" }
                        Write-ColorOutput -Message "    [!] $($sp.DisplayName)$expiring" -Color "Red"
                        Write-ColorOutput -Message "        AppId: $($sp.AppId)" -Color "DarkGray"
                    }
                }
            }
            
            if ($passwordOnlyCount -gt 10) {
                Write-ColorOutput -Message "    ... and $($passwordOnlyCount - 10) more" -Color "DarkGray"
            }
            
            Write-ColorOutput -Message "`n    [*] Total password-only service principals: $passwordOnlyCount" -Color $(if ($passwordOnlyCount -gt 0) { "Yellow" } else { "Green" })
            
        } catch {
            if ($_.Exception.Message -like "*403*" -or $_.Exception.Message -like "*Forbidden*" -or $_.Exception.Message -like "*Authorization*") {
                Write-ColorOutput -Message "    [!] Access Denied - Requires Application.Read.All permission" -Color "Yellow"
            } else {
                Write-ColorOutput -Message "    [!] Error: $($_.Exception.Message)" -Color "Red"
            }
        }
        
        # 2.2 Applications with Public Client enabled (ROPC vulnerable)
        Write-ColorOutput -Message "`n[*] Enumerating applications with public client flows enabled..." -Color "Yellow"
        Write-ColorOutput -Message "    (Allows ROPC - direct username/password authentication)" -Color "DarkGray"
        
        try {
            $apps = Get-MgApplication -All -Property "id,displayName,appId,isFallbackPublicClient,publicClient,signInAudience,requiredResourceAccess" -ErrorAction Stop
            
            $publicClientCount = 0
            foreach ($app in $apps) {
                $isPublicClient = $app.IsFallbackPublicClient -eq $true -or ($app.PublicClient -and $app.PublicClient.RedirectUris.Count -gt 0)
                
                if ($isPublicClient) {
                    # Check for dangerous permissions
                    $dangerousPerms = @()
                    foreach ($resource in $app.RequiredResourceAccess) {
                        foreach ($perm in $resource.ResourceAccess) {
                            if ($perm.Type -eq "Role") {
                                $dangerousPerms += "AppRole"
                            }
                        }
                    }
                    
                    $risk = if ($dangerousPerms.Count -gt 0) { "HIGH" } else { "MEDIUM" }
                    
                    $finding = [PSCustomObject]@{
                        Type = "Application"
                        Target = $app.DisplayName
                        AppId = $app.AppId
                        ObjectId = $app.Id
                        Vulnerability = "PublicClientEnabled"
                        Risk = $risk
                        Description = "Public client flow enabled - ROPC authentication possible"
                        Authenticated = $true
                        SignInAudience = $app.SignInAudience
                        HasAppRoles = $dangerousPerms.Count -gt 0
                    }
                    $authFindings += $finding
                    $publicClientCount++
                    
                    if ($publicClientCount -le 10) {
                        $riskColor = if ($risk -eq "HIGH") { "Red" } else { "Yellow" }
                        Write-ColorOutput -Message "    [!] $($app.DisplayName) [$risk]" -Color $riskColor
                        Write-ColorOutput -Message "        AppId: $($app.AppId) | Audience: $($app.SignInAudience)" -Color "DarkGray"
                    }
                }
            }
            
            if ($publicClientCount -gt 10) {
                Write-ColorOutput -Message "    ... and $($publicClientCount - 10) more" -Color "DarkGray"
            }
            
            Write-ColorOutput -Message "`n    [*] Total public client applications: $publicClientCount" -Color $(if ($publicClientCount -gt 0) { "Yellow" } else { "Green" })
            
        } catch {
            if ($_.Exception.Message -like "*403*" -or $_.Exception.Message -like "*Forbidden*" -or $_.Exception.Message -like "*Authorization*") {
                Write-ColorOutput -Message "    [!] Access Denied - Requires Application.Read.All permission" -Color "Yellow"
            } else {
                Write-ColorOutput -Message "    [!] Error: $($_.Exception.Message)" -Color "Red"
            }
        }
        
        # 2.3 Check Security Defaults status
        Write-ColorOutput -Message "`n[*] Checking Security Defaults and Conditional Access..." -Color "Yellow"
        
        try {
            $securityDefaults = Invoke-MgGraphRequest -Uri "https://graph.microsoft.com/v1.0/policies/identitySecurityDefaultsEnforcementPolicy" -Method GET -ErrorAction Stop
            
            if ($securityDefaults.isEnabled -eq $false) {
                $finding = [PSCustomObject]@{
                    Type = "Policy"
                    Target = "SecurityDefaults"
                    Vulnerability = "SecurityDefaultsDisabled"
                    Risk = "MEDIUM"
                    Description = "Security Defaults disabled - check for Conditional Access coverage"
                    Authenticated = $true
                }
                $authFindings += $finding
                Write-ColorOutput -Message "    [!] SECURITY DEFAULTS DISABLED" -Color "Yellow"
                Write-ColorOutput -Message "        Check if Conditional Access provides equivalent protection" -Color "DarkGray"
            } else {
                Write-ColorOutput -Message "    [+] Security Defaults ENABLED - Good baseline" -Color "Green"
            }
        } catch {
            Write-ColorOutput -Message "    [!] Could not check Security Defaults (requires Policy.Read.All)" -Color "DarkGray"
        }
        
        # 2.4 Check for legacy authentication in Conditional Access
        try {
            $caPolicies = Invoke-MgGraphRequest -Uri "https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies" -Method GET -ErrorAction Stop
            
            $legacyAuthBlocked = $false
            foreach ($policy in $caPolicies.value) {
                if ($policy.conditions.clientAppTypes -contains "exchangeActiveSync" -or 
                    $policy.conditions.clientAppTypes -contains "other") {
                    if ($policy.grantControls.builtInControls -contains "block" -and $policy.state -eq "enabled") {
                        $legacyAuthBlocked = $true
                    }
                }
            }
            
            if (-not $legacyAuthBlocked) {
                $finding = [PSCustomObject]@{
                    Type = "Policy"
                    Target = "ConditionalAccess"
                    Vulnerability = "LegacyAuthNotBlocked"
                    Risk = "HIGH"
                    Description = "No Conditional Access policy blocking legacy authentication - MFA bypass possible"
                    Authenticated = $true
                }
                $authFindings += $finding
                Write-ColorOutput -Message "    [!] LEGACY AUTH NOT BLOCKED - MFA bypass possible" -Color "Red"
            } else {
                Write-ColorOutput -Message "    [+] Legacy authentication blocked by Conditional Access" -Color "Green"
            }
            
            Write-ColorOutput -Message "    [*] Found $($caPolicies.value.Count) Conditional Access policies" -Color "DarkGray"
            
        } catch {
            Write-ColorOutput -Message "    [!] Could not enumerate Conditional Access (requires Policy.Read.All)" -Color "DarkGray"
        }
        
        # 2.5 Enumerate guest users with potentially excessive permissions
        Write-ColorOutput -Message "`n[*] Enumerating guest users..." -Color "Yellow"
        Write-ColorOutput -Message "    (External users = potential 'null session' equivalent)" -Color "DarkGray"
        
        try {
            $guestUsers = Get-MgUser -Filter "userType eq 'Guest'" -All -Property "id,displayName,userPrincipalName,createdDateTime,signInActivity" -ErrorAction Stop
            
            $staleGuestCount = 0
            $activeGuestCount = 0
            $cutoffDate = (Get-Date).AddDays(-90)
            
            foreach ($guest in $guestUsers) {
                $lastSignIn = $guest.SignInActivity.LastSignInDateTime
                $isStale = (-not $lastSignIn) -or ($lastSignIn -lt $cutoffDate)
                
                if ($isStale) {
                    $staleGuestCount++
                    if ($staleGuestCount -le 5) {
                        $finding = [PSCustomObject]@{
                            Type = "User"
                            Target = $guest.DisplayName
                            UPN = $guest.UserPrincipalName
                            Vulnerability = "StaleGuestAccount"
                            Risk = "MEDIUM"
                            Description = "Guest account with no recent sign-in activity"
                            Authenticated = $true
                            LastSignIn = $lastSignIn
                            CreatedDate = $guest.CreatedDateTime
                        }
                        $authFindings += $finding
                    }
                } else {
                    $activeGuestCount++
                }
            }
            
            Write-ColorOutput -Message "    [*] Total guest users: $($guestUsers.Count)" -Color "Cyan"
            Write-ColorOutput -Message "    [*] Active guests (90 days): $activeGuestCount" -Color "Cyan"
            if ($staleGuestCount -gt 0) {
                Write-ColorOutput -Message "    [!] Stale guests (no activity 90+ days): $staleGuestCount" -Color "Yellow"
            }
            
        } catch {
            if ($_.Exception.Message -like "*403*" -or $_.Exception.Message -like "*Forbidden*") {
                Write-ColorOutput -Message "    [!] Access Denied - Guest enumeration restricted" -Color "Yellow"
            } else {
                Write-ColorOutput -Message "    [!] Error: $($_.Exception.Message)" -Color "DarkGray"
            }
        }
        
        # 2.6 Check for apps with dangerous permissions
        Write-ColorOutput -Message "`n[*] Checking for applications with dangerous API permissions..." -Color "Yellow"
        
        try {
            $dangerousPermissions = @(
                "RoleManagement.ReadWrite.Directory",
                "AppRoleAssignment.ReadWrite.All", 
                "Application.ReadWrite.All",
                "Directory.ReadWrite.All",
                "Mail.ReadWrite",
                "Mail.Send",
                "Files.ReadWrite.All",
                "Sites.ReadWrite.All",
                "User.ReadWrite.All"
            )
            
            $oauth2Grants = Invoke-MgGraphRequest -Uri "https://graph.microsoft.com/v1.0/oauth2PermissionGrants" -Method GET -ErrorAction Stop
            
            $dangerousGrantCount = 0
            foreach ($grant in $oauth2Grants.value) {
                $grantedScopes = $grant.scope -split ' '
                $dangerousScopes = $grantedScopes | Where-Object { $_ -in $dangerousPermissions }
                
                if ($dangerousScopes.Count -gt 0) {
                    # Get the app name
                    try {
                        $sp = Get-MgServicePrincipal -ServicePrincipalId $grant.clientId -Property "displayName" -ErrorAction SilentlyContinue
                        $appName = if ($sp) { $sp.DisplayName } else { $grant.clientId }
                    } catch {
                        $appName = $grant.clientId
                    }
                    
                    $finding = [PSCustomObject]@{
                        Type = "OAuth2Grant"
                        Target = $appName
                        ClientId = $grant.clientId
                        Vulnerability = "DangerousPermissions"
                        Risk = "HIGH"
                        Description = "Application has dangerous delegated permissions: $($dangerousScopes -join ', ')"
                        Authenticated = $true
                        Permissions = $dangerousScopes -join ', '
                        ConsentType = $grant.consentType
                    }
                    $authFindings += $finding
                    $dangerousGrantCount++
                    
                    if ($dangerousGrantCount -le 5) {
                        Write-ColorOutput -Message "    [!] $appName" -Color "Red"
                        Write-ColorOutput -Message "        Permissions: $($dangerousScopes -join ', ')" -Color "DarkGray"
                    }
                }
            }
            
            if ($dangerousGrantCount -gt 5) {
                Write-ColorOutput -Message "    ... and $($dangerousGrantCount - 5) more" -Color "DarkGray"
            }
            
            if ($dangerousGrantCount -eq 0) {
                Write-ColorOutput -Message "    [+] No applications with high-risk permissions found" -Color "Green"
            } else {
                Write-ColorOutput -Message "`n    [*] Total apps with dangerous permissions: $dangerousGrantCount" -Color "Yellow"
            }
            
        } catch {
            Write-ColorOutput -Message "    [!] Could not enumerate OAuth grants (requires Directory.Read.All)" -Color "DarkGray"
        }
        
        # 2.7 Check Guest User Permission Level (Authorization Policy)
        Write-ColorOutput -Message "`n[*] Checking guest user permission level..." -Color "Yellow"
        Write-ColorOutput -Message "    (Determines what guests can enumerate - the 'null session' equivalent)" -Color "DarkGray"
        
        try {
            $authPolicy = Invoke-MgGraphRequest -Uri "https://graph.microsoft.com/v1.0/policies/authorizationPolicy" -Method GET -ErrorAction Stop
            
            $guestAccess = $authPolicy.guestUserRoleId
            
            # Guest role IDs:
            # a0b1b346-4d3e-4e8b-98f8-753987be4970 = Same as member users (MOST PERMISSIVE)
            # 10dae51f-b6af-4016-8d66-8c2a99b929b3 = Limited access (default)
            # 2af84b1e-32c8-42b7-82bc-daa82404023b = Restricted access (MOST RESTRICTIVE)
            
            $guestPermissionLevel = switch ($guestAccess) {
                "a0b1b346-4d3e-4e8b-98f8-753987be4970" { "SameAsMemberUsers" }
                "10dae51f-b6af-4016-8d66-8c2a99b929b3" { "LimitedAccess" }
                "2af84b1e-32c8-42b7-82bc-daa82404023b" { "RestrictedAccess" }
                default { "Unknown ($guestAccess)" }
            }
            
            if ($guestAccess -eq "a0b1b346-4d3e-4e8b-98f8-753987be4970") {
                $finding = [PSCustomObject]@{
                    Type = "Policy"
                    Target = "GuestUserAccess"
                    Vulnerability = "GuestAccessSameAsMember"
                    Risk = "HIGH"
                    Description = "Guest users have SAME permissions as member users - full directory enumeration possible"
                    Authenticated = $true
                    GuestRoleId = $guestAccess
                    PermissionLevel = $guestPermissionLevel
                }
                $authFindings += $finding
                Write-ColorOutput -Message "    [!] CRITICAL: Guest access = SAME AS MEMBER USERS" -Color "Red"
                Write-ColorOutput -Message "        Guests can enumerate entire directory (null session equivalent)" -Color "DarkGray"
            } elseif ($guestAccess -eq "10dae51f-b6af-4016-8d66-8c2a99b929b3") {
                $finding = [PSCustomObject]@{
                    Type = "Policy"
                    Target = "GuestUserAccess"
                    Vulnerability = "GuestAccessLimited"
                    Risk = "MEDIUM"
                    Description = "Guest users have limited access - can still enumerate some directory info"
                    Authenticated = $true
                    GuestRoleId = $guestAccess
                    PermissionLevel = $guestPermissionLevel
                }
                $authFindings += $finding
                Write-ColorOutput -Message "    [!] Guest access = LIMITED (default)" -Color "Yellow"
                Write-ColorOutput -Message "        Guests can enumerate users/groups they interact with" -Color "DarkGray"
            } else {
                Write-ColorOutput -Message "    [+] Guest access = RESTRICTED (most secure)" -Color "Green"
                Write-ColorOutput -Message "        Guests can only see their own profile" -Color "DarkGray"
            }
            
            # Check if guest invite settings are permissive
            $guestInviteSettings = $authPolicy.allowInvitesFrom
            if ($guestInviteSettings -eq "everyone") {
                $finding = [PSCustomObject]@{
                    Type = "Policy"
                    Target = "GuestInvitePolicy"
                    Vulnerability = "AnyoneCanInviteGuests"
                    Risk = "MEDIUM"
                    Description = "Anyone (including guests) can invite external users"
                    Authenticated = $true
                    AllowInvitesFrom = $guestInviteSettings
                }
                $authFindings += $finding
                Write-ColorOutput -Message "    [!] Guest invites: ANYONE can invite (including guests)" -Color "Yellow"
            } elseif ($guestInviteSettings -eq "adminsAndGuestInviters") {
                Write-ColorOutput -Message "    [*] Guest invites: Admins and Guest Inviters only" -Color "DarkGray"
            } else {
                Write-ColorOutput -Message "    [+] Guest invites: Admins only" -Color "Green"
            }
            
        } catch {
            Write-ColorOutput -Message "    [!] Could not check authorization policy (requires Policy.Read.All)" -Color "DarkGray"
        }
        
        # 2.8 Check for users without MFA registered
        Write-ColorOutput -Message "`n[*] Checking for users without MFA methods registered..." -Color "Yellow"
        Write-ColorOutput -Message "    (Users vulnerable to credential stuffing/phishing)" -Color "DarkGray"
        
        try {
            # Get authentication methods registration details
            $authMethodsReport = Invoke-MgGraphRequest -Uri "https://graph.microsoft.com/v1.0/reports/authenticationMethods/userRegistrationDetails" -Method GET -ErrorAction Stop
            
            $noMfaUsers = @()
            $mfaRegisteredCount = 0
            $totalChecked = 0
            
            foreach ($user in $authMethodsReport.value) {
                $totalChecked++
                
                # Check if user has any MFA method registered
                $hasMfa = $user.isMfaRegistered -eq $true
                
                if (-not $hasMfa) {
                    $noMfaUsers += $user
                    
                    if ($noMfaUsers.Count -le 5) {
                        $finding = [PSCustomObject]@{
                            Type = "User"
                            Target = $user.userDisplayName
                            UPN = $user.userPrincipalName
                            Vulnerability = "NoMFARegistered"
                            Risk = "HIGH"
                            Description = "User has no MFA methods registered - vulnerable to credential attacks"
                            Authenticated = $true
                            IsAdmin = $user.isAdmin
                            MethodsRegistered = ($user.methodsRegistered -join ', ')
                        }
                        $authFindings += $finding
                    }
                } else {
                    $mfaRegisteredCount++
                }
            }
            
            # Show results
            if ($noMfaUsers.Count -gt 0) {
                Write-ColorOutput -Message "    [!] Users WITHOUT MFA: $($noMfaUsers.Count)" -Color "Red"
                
                # Show first few
                $displayCount = [Math]::Min(5, $noMfaUsers.Count)
                for ($i = 0; $i -lt $displayCount; $i++) {
                    $u = $noMfaUsers[$i]
                    $adminTag = if ($u.isAdmin) { " [ADMIN]" } else { "" }
                    Write-ColorOutput -Message "        - $($u.userDisplayName)$adminTag" -Color "Red"
                }
                
                if ($noMfaUsers.Count -gt 5) {
                    Write-ColorOutput -Message "        ... and $($noMfaUsers.Count - 5) more" -Color "DarkGray"
                }
                
                # Check for admins without MFA (critical)
                $adminsNoMfa = $noMfaUsers | Where-Object { $_.isAdmin -eq $true }
                if ($adminsNoMfa.Count -gt 0) {
                    Write-ColorOutput -Message "    [!] CRITICAL: $($adminsNoMfa.Count) ADMIN(S) without MFA!" -Color "Red"
                }
            } else {
                Write-ColorOutput -Message "    [+] All users have MFA registered" -Color "Green"
            }
            
            Write-ColorOutput -Message "    [*] Total checked: $totalChecked | With MFA: $mfaRegisteredCount | Without: $($noMfaUsers.Count)" -Color "DarkGray"
            
        } catch {
            if ($_.Exception.Message -like "*403*" -or $_.Exception.Message -like "*Forbidden*") {
                Write-ColorOutput -Message "    [!] Access Denied - Requires UserAuthenticationMethod.Read.All or Reports.Read.All" -Color "Yellow"
                Write-ColorOutput -Message "        Try alternative: checking per-user auth methods (slower)" -Color "DarkGray"
            } else {
                Write-ColorOutput -Message "    [!] Could not retrieve MFA registration report" -Color "DarkGray"
                Write-ColorOutput -Message "        Error: $($_.Exception.Message)" -Color "DarkGray"
            }
        }
    }
    
    # ============================================
    # SUMMARY AND EXPORT
    # ============================================
    Write-ColorOutput -Message "`n[*] ========================================" -Color "Cyan"
    Write-ColorOutput -Message "[*] VULNERABILITY SUMMARY" -Color "Cyan"
    Write-ColorOutput -Message "[*] ========================================`n" -Color "Cyan"
    
    # Combine all findings
    $vulnTargets = $unauthFindings + $authFindings
    
    # Count by risk level
    $highRisk = ($vulnTargets | Where-Object { $_.Risk -eq "HIGH" }).Count
    $mediumRisk = ($vulnTargets | Where-Object { $_.Risk -eq "MEDIUM" }).Count
    $lowRisk = ($vulnTargets | Where-Object { $_.Risk -eq "LOW" }).Count
    
    Write-ColorOutput -Message "AZR".PadRight(12) + $(if ($Domain) { $Domain } else { "(auto-detected)" }).ToString().PadRight(35) + "443".PadRight(7) + "[*] Vuln-List Results" -Color "Cyan"
    Write-ColorOutput -Message ""
    
    if ($highRisk -gt 0) {
        Write-ColorOutput -Message "    [!] HIGH RISK findings:   $highRisk" -Color "Red"
    }
    if ($mediumRisk -gt 0) {
        Write-ColorOutput -Message "    [!] MEDIUM RISK findings: $mediumRisk" -Color "Yellow"
    }
    if ($lowRisk -gt 0) {
        Write-ColorOutput -Message "    [*] LOW RISK findings:    $lowRisk" -Color "DarkGray"
    }
    
    Write-ColorOutput -Message "    [*] Total findings:       $($vulnTargets.Count)" -Color "Cyan"
    Write-ColorOutput -Message ""
    
    # Export if requested
    if ($ExportPath -and $vulnTargets.Count -gt 0) {
        try {
            $extension = [System.IO.Path]::GetExtension($ExportPath).ToLower()
            
            if ($extension -eq ".csv") {
                $vulnTargets | Export-Csv -Path $ExportPath -NoTypeInformation -Force
            } elseif ($extension -eq ".json") {
                $vulnTargets | ConvertTo-Json -Depth 10 | Out-File -FilePath $ExportPath -Force
            } elseif ($extension -eq ".txt") {
                # Text format similar to nxc relay list
                $relayList = $vulnTargets | Where-Object { $_.Risk -eq "HIGH" } | ForEach-Object {
                    "$($_.Type),$($_.Target),$($_.Vulnerability)"
                }
                $relayList | Out-File -FilePath $ExportPath -Force
                Write-ColorOutput -Message "[+] Exported $($relayList.Count) HIGH risk targets to: $ExportPath" -Color "Green"
            } else {
                # Default to JSON
                $vulnTargets | ConvertTo-Json -Depth 10 | Out-File -FilePath $ExportPath -Force
            }
            
            if ($extension -ne ".txt") {
                Write-ColorOutput -Message "[+] Full results exported to: $ExportPath" -Color "Green"
            }
        } catch {
            Write-ColorOutput -Message "[!] Failed to export results: $_" -Color "Red"
        }
    }
    
    # Provide recommendations
    Write-ColorOutput -Message "`n[*] RECOMMENDATIONS:" -Color "Yellow"
    
    if ($highRisk -gt 0) {
        Write-ColorOutput -Message "    [!] Address HIGH risk findings immediately:" -Color "Red"
        Write-ColorOutput -Message "        - Replace password credentials with certificates for service principals" -Color "DarkGray"
        Write-ColorOutput -Message "        - Block legacy authentication via Conditional Access" -Color "DarkGray"
        Write-ColorOutput -Message "        - Review and minimize dangerous API permissions" -Color "DarkGray"
    }
    
    if ($mediumRisk -gt 0) {
        Write-ColorOutput -Message "    [*] Review MEDIUM risk findings:" -Color "Yellow"
        Write-ColorOutput -Message "        - Audit public client applications" -Color "DarkGray"
        Write-ColorOutput -Message "        - Clean up stale guest accounts" -Color "DarkGray"
        Write-ColorOutput -Message "        - Enable Security Defaults or equivalent CA policies" -Color "DarkGray"
    }
    
    Write-ColorOutput -Message "`n[*] Vuln-list enumeration complete!" -Color "Green"
    
    return $vulnTargets
}

