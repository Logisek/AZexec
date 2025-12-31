# AZexec - Password Policy and Conditional Access Functions
# These functions are loaded into the main script scope via dot-sourcing
function Invoke-PasswordPolicyEnumeration {
    param(
        [string]$ExportPath
    )
    
    Write-ColorOutput -Message "`n[*] AZX - Azure/Entra Password Policy Enumeration" -Color "Yellow"
    Write-ColorOutput -Message "[*] Command: Password Policy" -Color "Yellow"
    Write-ColorOutput -Message "[*] Similar to: nxc smb --pass-pol`n" -Color "Yellow"
    
    # Get organization/tenant information
    Write-ColorOutput -Message "[*] Retrieving tenant password policies..." -Color "Yellow"
    
    $policyData = @{
        TenantId = $null
        TenantDisplayName = $null
        PasswordPolicies = @{}
        SecurityDefaults = $null
        ConditionalAccessPolicies = @()
        AuthenticationMethods = @{}
        SmartLockout = @{}
        DefaultPasswordRequirements = @{
            MinimumLength = 8
            MaximumLength = 256
            BannedPasswordCheck = "Enabled (Global banned password list)"
            ComplexityRequirements = "3 of 4 character types required (uppercase, lowercase, numbers, symbols)"
            CommonPasswordCheck = "Enabled (fuzzy matching)"
            ContextualPasswordCheck = "Enabled (based on username, display name)"
        }
    }
    
    try {
        # Get organization details
        $org = Get-MgOrganization -ErrorAction Stop
        
        if ($org) {
            $policyData.TenantId = $org.Id
            $policyData.TenantDisplayName = $org.DisplayName
            
            Write-ColorOutput -Message "[+] Tenant: $($org.DisplayName) ($($org.Id))`n" -Color "Green"
            
            # Display password policies
            Write-ColorOutput -Message "AZR".PadRight(12) + $org.DisplayName.PadRight(35) + "443".PadRight(7) + "[*] Password Policy Information" -Color "Cyan"
            Write-ColorOutput -Message ""
            
            # Display Azure AD Default Password Requirements (always enforced)
            Write-ColorOutput -Message "    [*] Azure AD Default Password Requirements (Always Enforced):" -Color "Yellow"
            Write-ColorOutput -Message "        Minimum Length:            8 characters" -Color "DarkGray"
            Write-ColorOutput -Message "        Maximum Length:            256 characters" -Color "DarkGray"
            Write-ColorOutput -Message "        Complexity:                3 of 4 character types (upper, lower, numbers, symbols)" -Color "DarkGray"
            Write-ColorOutput -Message "        Banned Passwords:          Global banned password list (enforced)" -Color "Green"
            Write-ColorOutput -Message "        Common Password Check:     Fuzzy matching enabled" -Color "Green"
            Write-ColorOutput -Message "        Contextual Check:          Username/display name check enabled" -Color "Green"
            Write-ColorOutput -Message ""
            
            # Password validity period
            if ($org.PasswordValidityPeriodInDays) {
                Write-ColorOutput -Message "    [+] Password Validity Period:     $($org.PasswordValidityPeriodInDays) days" -Color "Green"
                $policyData.PasswordPolicies.ValidityPeriodDays = $org.PasswordValidityPeriodInDays
            } else {
                Write-ColorOutput -Message "    [+] Password Validity Period:     No expiration (Azure AD default)" -Color "Cyan"
                $policyData.PasswordPolicies.ValidityPeriodDays = "No expiration"
            }
            
            # Password notification window
            if ($org.PasswordNotificationWindowInDays) {
                Write-ColorOutput -Message "    [+] Password Notification Window: $($org.PasswordNotificationWindowInDays) days" -Color "Cyan"
                $policyData.PasswordPolicies.NotificationWindowDays = $org.PasswordNotificationWindowInDays
            }
            
            # Verified domains
            if ($org.VerifiedDomains) {
                Write-ColorOutput -Message "    [+] Verified Domains:             $($org.VerifiedDomains.Count) domain(s)" -Color "Cyan"
                foreach ($domain in $org.VerifiedDomains) {
                    $isDefault = if ($domain.IsDefault) { " (Default)" } else { "" }
                    $isInitial = if ($domain.IsInitial) { " (Initial)" } else { "" }
                    Write-ColorOutput -Message "        - $($domain.Name)$isDefault$isInitial" -Color "DarkGray"
                }
            }
            
            # Technical notification emails
            if ($org.TechnicalNotificationMails) {
                Write-ColorOutput -Message "    [+] Technical Notification Emails: $($org.TechnicalNotificationMails.Count)" -Color "Cyan"
                foreach ($email in $org.TechnicalNotificationMails) {
                    Write-ColorOutput -Message "        - $email" -Color "DarkGray"
                }
            }
            
            # Security contacts
            if ($org.SecurityComplianceNotificationMails) {
                Write-ColorOutput -Message "    [+] Security Notification Emails:  $($org.SecurityComplianceNotificationMails.Count)" -Color "Cyan"
                foreach ($email in $org.SecurityComplianceNotificationMails) {
                    Write-ColorOutput -Message "        - $email" -Color "DarkGray"
                }
            }
        }
    } catch {
        # Check if it's a permission error (403)
        if ($_.Exception.Response.StatusCode -eq 403 -or $_.Exception.Message -like "*403*" -or $_.Exception.Message -like "*Forbidden*" -or $_.Exception.Message -like "*AccessDenied*") {
            Write-ColorOutput -Message "[!] Access Denied: Insufficient permissions to read organization details" -Color "Yellow"
            Write-ColorOutput -Message "[*] This requires Organization.Read.All or Directory.Read.All permissions" -Color "DarkGray"
        } else {
            Write-ColorOutput -Message "[!] Failed to retrieve organization details" -Color "Red"
            Write-ColorOutput -Message "[!] Error: $($_.Exception.Message)" -Color "Red"
        }
    }
    
    # Try to get domain password policies
    Write-ColorOutput -Message "`n[*] Retrieving domain password policies..." -Color "Yellow"
    
    try {
        $domains = Get-MgDomain -All -ErrorAction Stop
        
        if ($domains) {
            Write-ColorOutput -Message "[+] Found $($domains.Count) domain(s)`n" -Color "Green"
            
            foreach ($domain in $domains) {
                Write-ColorOutput -Message "    [*] Domain: $($domain.Id)" -Color "Yellow"
                
                # Password validity period for the domain
                if ($domain.PasswordValidityPeriodInDays) {
                    Write-ColorOutput -Message "        Password Expiry: $($domain.PasswordValidityPeriodInDays) days" -Color "Cyan"
                }
                
                if ($domain.PasswordNotificationWindowInDays) {
                    Write-ColorOutput -Message "        Notification Window: $($domain.PasswordNotificationWindowInDays) days" -Color "Cyan"
                }
                
                if ($domain.IsDefault) {
                    Write-ColorOutput -Message "        [+] This is the DEFAULT domain" -Color "Green"
                }
                
                if ($domain.IsInitial) {
                    Write-ColorOutput -Message "        [+] This is the INITIAL domain" -Color "Green"
                }
                
                if ($domain.IsVerified) {
                    Write-ColorOutput -Message "        [+] Domain is VERIFIED" -Color "Green"
                } else {
                    Write-ColorOutput -Message "        [!] Domain is NOT verified" -Color "Yellow"
                }
                
                if ($domain.SupportedServices) {
                    Write-ColorOutput -Message "        Supported Services: $($domain.SupportedServices -join ', ')" -Color "DarkGray"
                }
                
                Write-ColorOutput -Message ""
            }
        }
    } catch {
        # Check if it's a permission error (403)
        if ($_.Exception.Response.StatusCode -eq 403 -or $_.Exception.Message -like "*403*" -or $_.Exception.Message -like "*Forbidden*" -or $_.Exception.Message -like "*AccessDenied*") {
            Write-ColorOutput -Message "[!] Access Denied: Insufficient permissions to read domain policies" -Color "Yellow"
            Write-ColorOutput -Message "[*] This requires Directory.Read.All permissions" -Color "DarkGray"
        } else {
            Write-ColorOutput -Message "[!] Failed to retrieve domain policies" -Color "Red"
            Write-ColorOutput -Message "[!] Error: $($_.Exception.Message)" -Color "Red"
        }
    }
    
    # Try to get authentication methods policy
    Write-ColorOutput -Message "[*] Retrieving authentication methods policy..." -Color "Yellow"
    
    try {
        $authMethods = Invoke-MgGraphRequest -Uri "https://graph.microsoft.com/v1.0/policies/authenticationMethodsPolicy" -Method GET -ErrorAction Stop
        
        if ($authMethods) {
            Write-ColorOutput -Message "[+] Authentication methods policy retrieved`n" -Color "Green"
            
            # Registration enforcement
            if ($authMethods.registrationEnforcement) {
                $authRequired = $authMethods.registrationEnforcement.authenticationMethodsRegistrationCampaign
                if ($authRequired) {
                    Write-ColorOutput -Message "    [*] MFA Registration Campaign:" -Color "Yellow"
                    Write-ColorOutput -Message "        State: $($authRequired.state)" -Color "Cyan"
                    if ($authRequired.snoozeDurationInDays) {
                        Write-ColorOutput -Message "        Snooze Duration: $($authRequired.snoozeDurationInDays) days" -Color "Cyan"
                    }
                }
            }
            
            # Authentication method configurations
            if ($authMethods.authenticationMethodConfigurations) {
                Write-ColorOutput -Message "`n    [*] Enabled Authentication Methods:" -Color "Yellow"
                
                foreach ($method in $authMethods.authenticationMethodConfigurations) {
                    if ($method.state -eq "enabled") {
                        $methodType = switch ($method.'@odata.type') {
                            "#microsoft.graph.fido2AuthenticationMethodConfiguration" { "FIDO2 Security Key" }
                            "#microsoft.graph.microsoftAuthenticatorAuthenticationMethodConfiguration" { "Microsoft Authenticator" }
                            "#microsoft.graph.smsAuthenticationMethodConfiguration" { "SMS" }
                            "#microsoft.graph.voiceAuthenticationMethodConfiguration" { "Voice Call" }
                            "#microsoft.graph.emailAuthenticationMethodConfiguration" { "Email OTP" }
                            "#microsoft.graph.temporaryAccessPassAuthenticationMethodConfiguration" { "Temporary Access Pass" }
                            "#microsoft.graph.softwareOathAuthenticationMethodConfiguration" { "Software OATH Token" }
                            default { $method.'@odata.type' -replace '#microsoft\.graph\.', '' -replace 'AuthenticationMethodConfiguration', '' }
                        }
                        Write-ColorOutput -Message "        [+] $methodType (Enabled)" -Color "Green"
                        
                        $policyData.AuthenticationMethods[$methodType] = "Enabled"
                    }
                }
            }
        }
    } catch {
        # Check if it's a permission error (403)
        if ($_.Exception.Response.StatusCode -eq 403 -or $_.Exception.Message -like "*403*" -or $_.Exception.Message -like "*Forbidden*" -or $_.Exception.Message -like "*AccessDenied*") {
            Write-ColorOutput -Message "[!] Access Denied: Insufficient permissions to read authentication methods policy" -Color "Yellow"
            Write-ColorOutput -Message "[*] This requires Policy.Read.All permissions" -Color "DarkGray"
            Write-ColorOutput -Message "[*] Guest users typically cannot access this information" -Color "DarkGray"
        } else {
            Write-ColorOutput -Message "[!] Failed to retrieve authentication methods policy" -Color "Red"
            Write-ColorOutput -Message "[!] Error: $($_.Exception.Message)" -Color "Red"
        }
    }
    
    # Try to get Smart Lockout Settings (Azure AD account protection)
    Write-ColorOutput -Message "`n[*] Retrieving Smart Lockout Settings (Account Protection)..." -Color "Yellow"
    
    try {
        # Smart lockout is configured via authentication methods policy or conditional access
        # Try to get lockout policy from authorization policy
        $authzPolicy = Invoke-MgGraphRequest -Uri "https://graph.microsoft.com/v1.0/policies/authorizationPolicy" -Method GET -ErrorAction Stop
        
        if ($authzPolicy) {
            Write-ColorOutput -Message "[+] Smart Lockout Configuration:" -Color "Green"
            
            # Azure AD Smart Lockout defaults (documented by Microsoft)
            Write-ColorOutput -Message "    [*] Lockout Threshold:            10 failed attempts (Azure AD default)" -Color "Cyan"
            Write-ColorOutput -Message "    [*] Lockout Duration:             60 seconds initial, increases with repeated attempts" -Color "Cyan"
            Write-ColorOutput -Message "    [*] Lockout Counter Reset:        After successful sign-in" -Color "Cyan"
            Write-ColorOutput -Message "    [*] Account Lockout Detection:    Automated based on sign-in patterns" -Color "Green"
            Write-ColorOutput -Message "    [*] Familiar Location Detection:  Enabled (sign-ins from familiar IPs are less restricted)" -Color "Green"
            
            $policyData.SmartLockout.LockoutThreshold = 10
            $policyData.SmartLockout.LockoutDuration = "60 seconds (increases with repeated attempts)"
            $policyData.SmartLockout.CounterReset = "After successful sign-in"
            $policyData.SmartLockout.FamiliarLocationDetection = "Enabled"
            
            # Check if guest users are allowed (affects guest lockout policy)
            if ($authzPolicy.allowedToUseSSPR -ne $null) {
                Write-ColorOutput -Message "    [+] Self-Service Password Reset:  $($authzPolicy.allowedToUseSSPR)" -Color "Cyan"
                $policyData.SmartLockout.SSPRAllowed = $authzPolicy.allowedToUseSSPR
            }
        }
    } catch {
        # Check if it's a permission error (403)
        if ($_.Exception.Response.StatusCode -eq 403 -or $_.Exception.Message -like "*403*" -or $_.Exception.Message -like "*Forbidden*" -or $_.Exception.Message -like "*AccessDenied*") {
            Write-ColorOutput -Message "[!] Access Denied: Insufficient permissions to read Smart Lockout policy" -Color "Yellow"
            Write-ColorOutput -Message "[*] This requires Policy.Read.All permissions" -Color "DarkGray"
            Write-ColorOutput -Message "[*] Smart Lockout is still active (Azure AD default: 10 failed attempts, 60s lockout)" -Color "Cyan"
        } else {
            Write-ColorOutput -Message "[!] Failed to retrieve Smart Lockout settings" -Color "Red"
            Write-ColorOutput -Message "[!] Error: $($_.Exception.Message)" -Color "Red"
            Write-ColorOutput -Message "[*] Smart Lockout is still active (Azure AD default: 10 failed attempts, 60s lockout)" -Color "Cyan"
        }
        
        # Set defaults even if we can't retrieve
        $policyData.SmartLockout.LockoutThreshold = 10
        $policyData.SmartLockout.LockoutDuration = "60 seconds (increases with repeated attempts)"
    }
    
    # Try to check if Security Defaults are enabled
    Write-ColorOutput -Message "`n[*] Checking Security Defaults status..." -Color "Yellow"
    
    try {
        $identitySecurityDefaults = Invoke-MgGraphRequest -Uri "https://graph.microsoft.com/v1.0/policies/identitySecurityDefaultsEnforcementPolicy" -Method GET -ErrorAction Stop
        
        if ($identitySecurityDefaults) {
            $isEnabled = $identitySecurityDefaults.isEnabled
            $policyData.SecurityDefaults = $isEnabled
            
            if ($isEnabled) {
                Write-ColorOutput -Message "[+] Security Defaults: ENABLED" -Color "Green"
                Write-ColorOutput -Message "    [*] This enforces MFA for administrators and users when needed" -Color "Cyan"
                Write-ColorOutput -Message "    [*] Blocks legacy authentication protocols" -Color "Cyan"
                Write-ColorOutput -Message "    [*] Protects privileged activities (Azure portal, PowerShell, etc.)" -Color "Cyan"
            } else {
                Write-ColorOutput -Message "[!] Security Defaults: DISABLED" -Color "Yellow"
                Write-ColorOutput -Message "    [!] Consider using Conditional Access Policies or enable Security Defaults" -Color "Yellow"
            }
        }
    } catch {
        # Check if it's a permission error (403)
        if ($_.Exception.Response.StatusCode -eq 403 -or $_.Exception.Message -like "*403*" -or $_.Exception.Message -like "*Forbidden*" -or $_.Exception.Message -like "*AccessDenied*") {
            Write-ColorOutput -Message "[!] Access Denied: Insufficient permissions to read Security Defaults status" -Color "Yellow"
            Write-ColorOutput -Message "[*] This requires Policy.Read.All permissions" -Color "DarkGray"
            Write-ColorOutput -Message "[*] Guest users typically cannot access this information" -Color "DarkGray"
        } else {
            Write-ColorOutput -Message "[!] Failed to check Security Defaults" -Color "Red"
            Write-ColorOutput -Message "[!] Error: $($_.Exception.Message)" -Color "Red"
        }
    }
    
    # Try to enumerate Conditional Access Policies
    Write-ColorOutput -Message "`n[*] Enumerating Conditional Access Policies..." -Color "Yellow"
    
    try {
        $caPolicies = Get-MgIdentityConditionalAccessPolicy -All -ErrorAction Stop
        
        if ($caPolicies) {
            Write-ColorOutput -Message "[+] Found $($caPolicies.Count) Conditional Access Policies`n" -Color "Green"
            
            $enabledCount = 0
            $reportOnlyCount = 0
            $disabledCount = 0
            
            foreach ($policy in $caPolicies) {
                $stateColor = switch ($policy.State) {
                    "enabled" { 
                        $enabledCount++
                        "Green" 
                    }
                    "enabledForReportingButNotEnforced" { 
                        $reportOnlyCount++
                        "Yellow" 
                    }
                    "disabled" { 
                        $disabledCount++
                        "DarkGray" 
                    }
                    default { "Cyan" }
                }
                
                Write-ColorOutput -Message "    [$($policy.State.ToUpper())] $($policy.DisplayName)" -Color $stateColor
                
                if ($policy.Conditions) {
                    # Show if it requires MFA
                    if ($policy.GrantControls -and $policy.GrantControls.BuiltInControls -contains "mfa") {
                        Write-ColorOutput -Message "        [+] Requires MFA" -Color "Green"
                    }
                    
                    # Show application/user scope
                    if ($policy.Conditions.Applications) {
                        $appScope = if ($policy.Conditions.Applications.IncludeApplications -contains "All") {
                            "All Applications"
                        } else {
                            "$($policy.Conditions.Applications.IncludeApplications.Count) Applications"
                        }
                        Write-ColorOutput -Message "        Scope: $appScope" -Color "DarkGray"
                    }
                }
                
                $policyData.ConditionalAccessPolicies += [PSCustomObject]@{
                    DisplayName = $policy.DisplayName
                    State = $policy.State
                    CreatedDateTime = $policy.CreatedDateTime
                    ModifiedDateTime = $policy.ModifiedDateTime
                }
            }
            
            Write-ColorOutput -Message "`n    [*] CA Policy Summary:" -Color "Yellow"
            Write-ColorOutput -Message "        Enabled: $enabledCount" -Color "Green"
            Write-ColorOutput -Message "        Report-Only: $reportOnlyCount" -Color "Yellow"
            Write-ColorOutput -Message "        Disabled: $disabledCount" -Color "DarkGray"
        } else {
            Write-ColorOutput -Message "[!] No Conditional Access Policies found" -Color "Yellow"
            Write-ColorOutput -Message "    [!] Consider implementing Conditional Access for enhanced security" -Color "Yellow"
        }
    } catch {
        # Check if it's a permission error (403)
        if ($_.Exception.Response.StatusCode -eq 403 -or $_.Exception.Message -like "*403*" -or $_.Exception.Message -like "*Forbidden*" -or $_.Exception.Message -like "*AccessDenied*" -or $_.Exception.Message -like "*Unauthorized*") {
            Write-ColorOutput -Message "[!] Access Denied: Insufficient permissions to read Conditional Access Policies" -Color "Yellow"
            Write-ColorOutput -Message "[*] This requires Policy.Read.All permissions" -Color "DarkGray"
            Write-ColorOutput -Message "[*] Guest users typically cannot access this information (expected behavior)" -Color "DarkGray"
        } else {
            Write-ColorOutput -Message "[!] Failed to enumerate Conditional Access Policies" -Color "Red"
            Write-ColorOutput -Message "[!] Error: $($_.Exception.Message)" -Color "Red"
        }
    }
    
    # Display comprehensive summary
    Write-ColorOutput -Message "`n[*] ========================================" -Color "Yellow"
    Write-ColorOutput -Message "[*] Password Policy Summary (NetExec Style)" -Color "Yellow"
    Write-ColorOutput -Message "[*] ========================================" -Color "Yellow"
    Write-ColorOutput -Message "[+] Minimum Password Length:     8 characters (Azure AD enforced)" -Color "Green"
    Write-ColorOutput -Message "[+] Password Complexity:         3 of 4 character types required" -Color "Green"
    Write-ColorOutput -Message "[+] Password History:            N/A (Azure AD cloud-only)" -Color "DarkGray"
    Write-ColorOutput -Message "[+] Lockout Threshold:           10 failed attempts (Smart Lockout)" -Color "Green"
    Write-ColorOutput -Message "[+] Lockout Duration:            60 seconds (increases with repeated attempts)" -Color "Green"
    Write-ColorOutput -Message "[+] Lockout Observation Window:  Dynamic based on sign-in patterns" -Color "Green"
    
    if ($policyData.PasswordPolicies.ValidityPeriodDays) {
        if ($policyData.PasswordPolicies.ValidityPeriodDays -eq "No expiration") {
            Write-ColorOutput -Message "[+] Maximum Password Age:        No expiration (Azure AD default)" -Color "Cyan"
        } else {
            Write-ColorOutput -Message "[+] Maximum Password Age:        $($policyData.PasswordPolicies.ValidityPeriodDays) days" -Color "Green"
        }
    }
    
    Write-ColorOutput -Message "[+] Minimum Password Age:        N/A (Azure AD cloud-only)" -Color "DarkGray"
    Write-ColorOutput -Message "[+] Banned Password List:        Enabled (Global + Custom if configured)" -Color "Green"
    Write-ColorOutput -Message "[+] Smart Lockout:               Enabled (Azure AD default)" -Color "Green"
    
    if ($policyData.SecurityDefaults -eq $true) {
        Write-ColorOutput -Message "[+] Security Defaults:           Enabled (MFA enforced)" -Color "Green"
    } elseif ($policyData.SecurityDefaults -eq $false) {
        Write-ColorOutput -Message "[!] Security Defaults:           Disabled" -Color "Yellow"
    }
    
    if ($policyData.ConditionalAccessPolicies.Count -gt 0) {
        Write-ColorOutput -Message "[+] Conditional Access:          $($policyData.ConditionalAccessPolicies.Count) policies configured" -Color "Green"
    } else {
        Write-ColorOutput -Message "[!] Conditional Access:          No policies found" -Color "Yellow"
    }
    
    # Export if requested
    if ($ExportPath) {
        try {
            $extension = [System.IO.Path]::GetExtension($ExportPath).ToLower()
            
            if ($extension -eq ".csv") {
                # For CSV, flatten the data
                $exportData = [PSCustomObject]@{
                    TenantId = $policyData.TenantId
                    TenantDisplayName = $policyData.TenantDisplayName
                    MinPasswordLength = 8
                    PasswordComplexity = "3 of 4 character types"
                    PasswordValidityDays = $policyData.PasswordPolicies.ValidityPeriodDays
                    PasswordNotificationDays = $policyData.PasswordPolicies.NotificationWindowDays
                    LockoutThreshold = $policyData.SmartLockout.LockoutThreshold
                    LockoutDuration = $policyData.SmartLockout.LockoutDuration
                    BannedPasswordList = "Enabled"
                    SmartLockout = "Enabled"
                    SecurityDefaultsEnabled = $policyData.SecurityDefaults
                    ConditionalAccessPolicyCount = $policyData.ConditionalAccessPolicies.Count
                }
                $exportData | Export-Csv -Path $ExportPath -NoTypeInformation -Force
                Write-ColorOutput -Message "`n[+] Policy information exported to: $ExportPath" -Color "Green"
            } elseif ($extension -eq ".json") {
                $policyData | ConvertTo-Json -Depth 10 | Out-File -FilePath $ExportPath -Force
                Write-ColorOutput -Message "`n[+] Policy information exported to: $ExportPath" -Color "Green"
            } elseif ($extension -eq ".html") {
                $stats = [ordered]@{
                    "Tenant Display Name" = $policyData.TenantDisplayName
                    "Tenant ID" = $policyData.TenantId
                    "Minimum Password Length" = "8 characters"
                    "Password Complexity" = "3 of 4 character types"
                    "Password Validity Period (Days)" = $policyData.PasswordPolicies.ValidityPeriodDays
                    "Password Notification Window (Days)" = $policyData.PasswordPolicies.NotificationWindowDays
                    "Lockout Threshold" = "$($policyData.SmartLockout.LockoutThreshold) failed attempts"
                    "Lockout Duration" = $policyData.SmartLockout.LockoutDuration
                    "Banned Password List" = "Enabled"
                    "Smart Lockout" = "Enabled"
                    "Security Defaults Enabled" = $policyData.SecurityDefaults
                    "Conditional Access Policies" = $policyData.ConditionalAccessPolicies.Count
                    "Authentication Methods Configured" = $policyData.AuthenticationMethods.Count
                }
                
                # Create table data for CA policies if available
                $tableData = @()
                if ($policyData.ConditionalAccessPolicies.Count -gt 0) {
                    foreach ($cap in $policyData.ConditionalAccessPolicies) {
                        $tableData += [PSCustomObject]@{
                            PolicyName = $cap.DisplayName
                            State = $cap.State
                            CreatedDateTime = $cap.CreatedDateTime
                            ModifiedDateTime = $cap.ModifiedDateTime
                        }
                    }
                } else {
                    # If no CA policies, export the simple policy data
                    $tableData = @([PSCustomObject]@{
                        TenantId = $policyData.TenantId
                        TenantDisplayName = $policyData.TenantDisplayName
                        PasswordValidityDays = $policyData.PasswordPolicies.ValidityPeriodDays
                        PasswordNotificationDays = $policyData.PasswordPolicies.NotificationWindowDays
                        SecurityDefaultsEnabled = $policyData.SecurityDefaults
                    })
                }
                
                $description = "Password policy and security configuration enumeration including password expiration policies, security defaults, and conditional access policies."
                
                $success = Export-HtmlReport -Data $tableData -OutputPath $ExportPath -Title "Password Policy Enumeration Report" -Statistics $stats -CommandName "pass-pol" -Description $description
                
                if ($success) {
                    Write-ColorOutput -Message "`n[+] HTML report exported to: $ExportPath" -Color "Green"
                }
            } else {
                # Default to JSON for complex data
                $policyData | ConvertTo-Json -Depth 10 | Out-File -FilePath $ExportPath -Force
                Write-ColorOutput -Message "`n[+] Policy information exported to: $ExportPath" -Color "Green"
            }
        } catch {
            Write-ColorOutput -Message "`n[!] Failed to export results: $_" -Color "Red"
        }
    }
    
    Write-ColorOutput -Message "`n[*] Password policy enumeration complete!" -Color "Green"
    
    # Display access summary
    Write-ColorOutput -Message "`n[*] Access Summary:" -Color "Yellow"
    
    $hasOrgDetails = $policyData.TenantId -ne $null
    $hasAuthMethods = $policyData.AuthenticationMethods.Count -gt 0
    $hasSecurityDefaults = $policyData.SecurityDefaults -ne $null
    $hasCAPolicies = $policyData.ConditionalAccessPolicies.Count -gt 0
    
    if ($hasOrgDetails) {
        Write-ColorOutput -Message "    [+] Organization details: Retrieved" -Color "Green"
    } else {
        Write-ColorOutput -Message "    [-] Organization details: Not accessible" -Color "DarkGray"
    }
    
    if ($hasAuthMethods) {
        Write-ColorOutput -Message "    [+] Authentication methods: Retrieved" -Color "Green"
    } else {
        Write-ColorOutput -Message "    [-] Authentication methods: Not accessible (requires Policy.Read.All)" -Color "DarkGray"
    }
    
    if ($hasSecurityDefaults) {
        Write-ColorOutput -Message "    [+] Security Defaults: Retrieved" -Color "Green"
    } else {
        Write-ColorOutput -Message "    [-] Security Defaults: Not accessible (requires Policy.Read.All)" -Color "DarkGray"
    }
    
    if ($hasCAPolicies) {
        Write-ColorOutput -Message "    [+] Conditional Access Policies: Retrieved ($($policyData.ConditionalAccessPolicies.Count) policies)" -Color "Green"
    } else {
        Write-ColorOutput -Message "    [-] Conditional Access Policies: Not accessible (requires Policy.Read.All)" -Color "DarkGray"
    }
    
    # Provide guidance based on what was accessible
    if (-not $hasAuthMethods -and -not $hasSecurityDefaults -and -not $hasCAPolicies) {
        Write-ColorOutput -Message "`n[*] Limited information retrieved - this is expected for:" -Color "Yellow"
        Write-ColorOutput -Message "    - Guest users (restricted by design)" -Color "Cyan"
        Write-ColorOutput -Message "    - Users without Policy.Read.All permissions" -Color "Cyan"
        Write-ColorOutput -Message "`n[*] To get full policy information:" -Color "Yellow"
        Write-ColorOutput -Message "    1. Request Policy.Read.All permissions from your admin" -Color "Cyan"
        Write-ColorOutput -Message "    2. Or use a member account with appropriate permissions" -Color "Cyan"
    }
}

# Format Conditional Access Policy output like netexec

function Format-ConditionalAccessPolicyOutput {
    param(
        [PSCustomObject]$Policy,
        [int]$Index,
        [int]$Total
    )
    
    # Policy display name and ID
    $policyName = if ($Policy.DisplayName) { $Policy.DisplayName } elseif ($Policy.displayName) { $Policy.displayName } else { "UNKNOWN" }
    $policyId = if ($Policy.Id) { $Policy.Id } elseif ($Policy.id) { $Policy.id } else { "N/A" }
    
    # Truncate policy name if too long
    $maxNameLength = 40
    $policyNameShort = if ($policyName.Length -gt $maxNameLength) {
        $policyName.Substring(0, $maxNameLength - 3) + "..."
    } else {
        $policyName
    }
    
    # Policy state
    $state = if ($Policy.State) { $Policy.State } elseif ($Policy.state) { $Policy.state } else { "unknown" }
    
    # Determine color based on state and controls
    $stateColor = switch ($state) {
        "enabled" { "Green" }
        "enabledForReportingButNotEnforced" { "Yellow" }
        "disabled" { "DarkGray" }
        default { "Cyan" }
    }
    
    # Check for high-risk conditions
    $isHighRisk = $false
    $riskIndicators = @()
    
    # Check for block access
    if ($Policy.GrantControls -and $Policy.GrantControls.BuiltInControls -contains "block") {
        $isHighRisk = $true
        $riskIndicators += "BLOCK_ACCESS"
    }
    
    # Check for risky sign-in conditions
    if ($Policy.Conditions -and $Policy.Conditions.SignInRiskLevels) {
        if ($Policy.Conditions.SignInRiskLevels -contains "high") {
            $riskIndicators += "HIGH_RISK"
        }
    }
    
    # Check for user risk conditions
    if ($Policy.Conditions -and $Policy.Conditions.UserRiskLevels) {
        if ($Policy.Conditions.UserRiskLevels -contains "high") {
            $riskIndicators += "USER_RISK"
        }
    }
    
    # Get grant controls summary
    $grantControls = @()
    if ($Policy.GrantControls -and $Policy.GrantControls.BuiltInControls) {
        foreach ($control in $Policy.GrantControls.BuiltInControls) {
            switch ($control) {
                "mfa" { $grantControls += "MFA" }
                "compliantDevice" { $grantControls += "Compliant Device" }
                "domainJoinedDevice" { $grantControls += "Domain Joined" }
                "approvedApplication" { $grantControls += "Approved App" }
                "compliantApplication" { $grantControls += "Compliant App" }
                "passwordChange" { $grantControls += "Password Change" }
                "block" { $grantControls += "BLOCK"; $isHighRisk = $true }
                default { $grantControls += $control }
            }
        }
    }
    
    # Build main output line in netexec style
    $indexStr = "[$Index/$Total]"
    $output = "AZR".PadRight(12) + 
              $policyId.Substring(0, [Math]::Min(15, $policyId.Length)).PadRight(18) + 
              "443".PadRight(7) + 
              $policyNameShort.PadRight(43) + 
              "$indexStr [*] (state:$state)"
    
    # Override color for high-risk policies
    if ($isHighRisk -and $state -eq "enabled") {
        $stateColor = "Red"
    }
    
    Write-ColorOutput -Message $output -Color $stateColor
    
    # Display grant controls if any
    if ($grantControls.Count -gt 0) {
        $controlsStr = $grantControls -join ", "
        Write-ColorOutput -Message "    [+] Grant Controls: $controlsStr" -Color $(if ($isHighRisk) { "Red" } else { "Cyan" })
    }
    
    # Display risk indicators if any
    if ($riskIndicators.Count -gt 0) {
        $riskStr = $riskIndicators -join ", "
        Write-ColorOutput -Message "    [!] Risk Indicators: $riskStr" -Color "Yellow"
    }
    
    # Display conditions summary
    if ($Policy.Conditions) {
        # Users/Groups
        if ($Policy.Conditions.Users) {
            if ($Policy.Conditions.Users.IncludeUsers -contains "All") {
                Write-ColorOutput -Message "    [*] Target: All Users" -Color "DarkGray"
            } elseif ($Policy.Conditions.Users.IncludeUsers -or $Policy.Conditions.Users.IncludeGroups) {
                $userCount = if ($Policy.Conditions.Users.IncludeUsers) { $Policy.Conditions.Users.IncludeUsers.Count } else { 0 }
                $groupCount = if ($Policy.Conditions.Users.IncludeGroups) { $Policy.Conditions.Users.IncludeGroups.Count } else { 0 }
                Write-ColorOutput -Message "    [*] Target: $userCount Users, $groupCount Groups" -Color "DarkGray"
            }
            
            # Exclusions
            if ($Policy.Conditions.Users.ExcludeUsers -or $Policy.Conditions.Users.ExcludeGroups) {
                $excludeUserCount = if ($Policy.Conditions.Users.ExcludeUsers) { $Policy.Conditions.Users.ExcludeUsers.Count } else { 0 }
                $excludeGroupCount = if ($Policy.Conditions.Users.ExcludeGroups) { $Policy.Conditions.Users.ExcludeGroups.Count } else { 0 }
                Write-ColorOutput -Message "    [*] Exclusions: $excludeUserCount Users, $excludeGroupCount Groups" -Color "DarkGray"
            }
        }
        
        # Applications
        if ($Policy.Conditions.Applications) {
            if ($Policy.Conditions.Applications.IncludeApplications -contains "All") {
                Write-ColorOutput -Message "    [*] Apps: All Applications" -Color "DarkGray"
            } elseif ($Policy.Conditions.Applications.IncludeApplications) {
                Write-ColorOutput -Message "    [*] Apps: $($Policy.Conditions.Applications.IncludeApplications.Count) Applications" -Color "DarkGray"
            }
        }
        
        # Platforms
        if ($Policy.Conditions.Platforms -and $Policy.Conditions.Platforms.IncludePlatforms) {
            $platforms = $Policy.Conditions.Platforms.IncludePlatforms -join ", "
            Write-ColorOutput -Message "    [*] Platforms: $platforms" -Color "DarkGray"
        }
        
        # Locations
        if ($Policy.Conditions.Locations) {
            if ($Policy.Conditions.Locations.IncludeLocations -contains "All") {
                Write-ColorOutput -Message "    [*] Locations: All" -Color "DarkGray"
            } elseif ($Policy.Conditions.Locations.IncludeLocations) {
                Write-ColorOutput -Message "    [*] Locations: $($Policy.Conditions.Locations.IncludeLocations.Count) Named Locations" -Color "DarkGray"
            }
        }
        
        # Client app types
        if ($Policy.Conditions.ClientAppTypes) {
            $clientApps = $Policy.Conditions.ClientAppTypes -join ", "
            Write-ColorOutput -Message "    [*] Client Apps: $clientApps" -Color "DarkGray"
        }
    }
    
    # Display session controls if any
    if ($Policy.SessionControls) {
        $sessionControls = @()
        
        if ($Policy.SessionControls.SignInFrequency) {
            $frequency = $Policy.SessionControls.SignInFrequency
            $sessionControls += "Sign-in Frequency: $($frequency.Value) $($frequency.Type)"
        }
        
        if ($Policy.SessionControls.PersistentBrowser) {
            $sessionControls += "Persistent Browser: $($Policy.SessionControls.PersistentBrowser.Mode)"
        }
        
        if ($Policy.SessionControls.ApplicationEnforcedRestrictions) {
            $sessionControls += "App Enforced Restrictions"
        }
        
        if ($Policy.SessionControls.CloudAppSecurity) {
            $sessionControls += "Cloud App Security: $($Policy.SessionControls.CloudAppSecurity.CloudAppSecurityType)"
        }
        
        if ($sessionControls.Count -gt 0) {
            $sessionStr = $sessionControls -join ", "
            Write-ColorOutput -Message "    [*] Session Controls: $sessionStr" -Color "Cyan"
        }
    }
    
    # Display creation and modification dates
    if ($Policy.CreatedDateTime) {
        Write-ColorOutput -Message "    [*] Created: $($Policy.CreatedDateTime)" -Color "DarkGray"
    }
    if ($Policy.ModifiedDateTime) {
        Write-ColorOutput -Message "    [*] Modified: $($Policy.ModifiedDateTime)" -Color "DarkGray"
    }
}

# Invoke Conditional Access Policy Review enumeration
function Invoke-ConditionalAccessPolicyReview {
    param(
        [string]$ExportPath
    )
    
    Write-ColorOutput -Message "[*] AZexec - Conditional Access Policy Review" -Color "Yellow"
    Write-ColorOutput -Message "[*] Enumerating Conditional Access Policies...`n" -Color "Cyan"
    
    # Check if user is a guest
    $isGuest = Test-IsGuestUser
    
    if ($isGuest) {
        Write-ColorOutput -Message "[!] WARNING: You are authenticated as a guest user" -Color "Red"
        Write-ColorOutput -Message "[!] Guest users typically cannot access Conditional Access Policies" -Color "Red"
        Write-ColorOutput -Message "[!] This command requires a member account with Policy.Read.All permissions`n" -Color "Red"
    }
    
    # Get tenant info
    $tenantInfo = $null
    try {
        $tenantInfo = Get-MgOrganization -ErrorAction Stop | Select-Object -First 1
        $tenantName = if ($tenantInfo.DisplayName) { $tenantInfo.DisplayName } else { "Unknown" }
        $tenantId = if ($tenantInfo.Id) { $tenantInfo.Id } else { "Unknown" }
        Write-ColorOutput -Message "[+] Tenant: $tenantName (ID: $tenantId)" -Color "Green"
    } catch {
        Write-ColorOutput -Message "[!] Could not retrieve tenant information" -Color "Yellow"
    }
    
    # Get current user context
    try {
        $context = Get-MgContext
        if ($context) {
            Write-ColorOutput -Message "[+] Authenticated as: $($context.Account)" -Color "Green"
            Write-ColorOutput -Message "[+] Required permissions: Policy.Read.All`n" -Color "Cyan"
        }
    } catch {
        Write-ColorOutput -Message "[!] Could not retrieve authentication context`n" -Color "Yellow"
    }
    
    # Initialize data collection
    $policyData = @{
        TenantId = $tenantId
        TenantDisplayName = $tenantName
        Policies = @()
        Summary = @{
            Total = 0
            Enabled = 0
            ReportOnly = 0
            Disabled = 0
            BlockPolicies = 0
            MFAPolicies = 0
        }
    }
    
    # Enumerate Conditional Access Policies
    try {
        $policies = Get-MgIdentityConditionalAccessPolicy -All -ErrorAction Stop
        
        if ($policies) {
            $policyCount = ($policies | Measure-Object).Count
            $policyData.Summary.Total = $policyCount
            
            Write-ColorOutput -Message "[+] Found $policyCount Conditional Access Policies`n" -Color "Green"
            
            $index = 1
            foreach ($policy in $policies) {
                # Update summary counts
                switch ($policy.State) {
                    "enabled" { $policyData.Summary.Enabled++ }
                    "enabledForReportingButNotEnforced" { $policyData.Summary.ReportOnly++ }
                    "disabled" { $policyData.Summary.Disabled++ }
                }
                
                # Check for block policies
                if ($policy.GrantControls -and $policy.GrantControls.BuiltInControls -contains "block") {
                    $policyData.Summary.BlockPolicies++
                }
                
                # Check for MFA policies
                if ($policy.GrantControls -and $policy.GrantControls.BuiltInControls -contains "mfa") {
                    $policyData.Summary.MFAPolicies++
                }
                
                # Format and display policy
                Format-ConditionalAccessPolicyOutput -Policy $policy -Index $index -Total $policyCount
                
                # Store policy data for export
                $policyData.Policies += [PSCustomObject]@{
                    DisplayName = $policy.DisplayName
                    Id = $policy.Id
                    State = $policy.State
                    CreatedDateTime = $policy.CreatedDateTime
                    ModifiedDateTime = $policy.ModifiedDateTime
                    GrantControls = ($policy.GrantControls.BuiltInControls -join ", ")
                    TargetUsers = if ($policy.Conditions.Users.IncludeUsers -contains "All") { "All" } else { "$($policy.Conditions.Users.IncludeUsers.Count) users" }
                    TargetApps = if ($policy.Conditions.Applications.IncludeApplications -contains "All") { "All" } else { "$($policy.Conditions.Applications.IncludeApplications.Count) apps" }
                    Platforms = ($policy.Conditions.Platforms.IncludePlatforms -join ", ")
                    ClientAppTypes = ($policy.Conditions.ClientAppTypes -join ", ")
                }
                
                $index++
                Write-Host ""
            }
            
            # Display summary
            Write-ColorOutput -Message "[*] ========================================" -Color "Yellow"
            Write-ColorOutput -Message "[*] Conditional Access Policy Summary" -Color "Yellow"
            Write-ColorOutput -Message "[*] ========================================" -Color "Yellow"
            Write-ColorOutput -Message "[+] Total Policies: $($policyData.Summary.Total)" -Color "Green"
            Write-ColorOutput -Message "    [*] Enabled: $($policyData.Summary.Enabled)" -Color "Green"
            Write-ColorOutput -Message "    [*] Report-Only: $($policyData.Summary.ReportOnly)" -Color "Yellow"
            Write-ColorOutput -Message "    [*] Disabled: $($policyData.Summary.Disabled)" -Color "DarkGray"
            Write-ColorOutput -Message "    [*] Block Policies: $($policyData.Summary.BlockPolicies)" -Color $(if ($policyData.Summary.BlockPolicies -gt 0) { "Red" } else { "DarkGray" })
            Write-ColorOutput -Message "    [*] MFA Policies: $($policyData.Summary.MFAPolicies)" -Color $(if ($policyData.Summary.MFAPolicies -gt 0) { "Green" } else { "Yellow" })
            
            # Security recommendations
            Write-ColorOutput -Message "`n[*] Security Recommendations:" -Color "Yellow"
            
            if ($policyData.Summary.Enabled -eq 0) {
                Write-ColorOutput -Message "    [!] No enabled Conditional Access Policies found - consider enabling policies" -Color "Red"
            }
            
            if ($policyData.Summary.MFAPolicies -eq 0) {
                Write-ColorOutput -Message "    [!] No MFA enforcement policies found - consider requiring MFA" -Color "Yellow"
            } else {
                Write-ColorOutput -Message "    [+] MFA policies are configured" -Color "Green"
            }
            
            if ($policyData.Summary.ReportOnly -gt 0) {
                Write-ColorOutput -Message "    [*] $($policyData.Summary.ReportOnly) policies in report-only mode - review and enable if appropriate" -Color "Cyan"
            }
            
            if ($policyData.Summary.Disabled -gt 0) {
                Write-ColorOutput -Message "    [*] $($policyData.Summary.Disabled) policies disabled - review if still needed" -Color "DarkGray"
            }
            
        } else {
            Write-ColorOutput -Message "[!] No Conditional Access Policies found in this tenant" -Color "Yellow"
            Write-ColorOutput -Message "[*] Consider implementing Conditional Access for enhanced security" -Color "Cyan"
        }
        
    } catch {
        # Check for permission errors
        if ($_.Exception.Response.StatusCode -eq 403 -or 
            $_.Exception.Message -like "*403*" -or 
            $_.Exception.Message -like "*Forbidden*" -or 
            $_.Exception.Message -like "*AccessDenied*" -or 
            $_.Exception.Message -like "*Unauthorized*") {
            
            Write-ColorOutput -Message "[!] Access Denied: Insufficient permissions to read Conditional Access Policies" -Color "Red"
            Write-ColorOutput -Message "[*] Required permission: Policy.Read.All" -Color "Yellow"
            Write-ColorOutput -Message "[*] Guest users typically cannot access Conditional Access Policies (expected behavior)" -Color "Cyan"
            Write-ColorOutput -Message "`n[*] To access this information:" -Color "Yellow"
            Write-ColorOutput -Message "    1. Use a member account (not a guest user)" -Color "Cyan"
            Write-ColorOutput -Message "    2. Request Policy.Read.All permissions from your admin" -Color "Cyan"
            Write-ColorOutput -Message "    3. Ensure your account has appropriate directory roles" -Color "Cyan"
            
        } else {
            Write-ColorOutput -Message "[!] Failed to enumerate Conditional Access Policies" -Color "Red"
            Write-ColorOutput -Message "[!] Error: $($_.Exception.Message)" -Color "Red"
        }
    }
    
    # Export if requested
    if ($ExportPath -and $policyData.Policies.Count -gt 0) {
        try {
            $extension = [System.IO.Path]::GetExtension($ExportPath).ToLower()
            
            if ($extension -eq ".csv") {
                # Export policies to CSV
                $policyData.Policies | Export-Csv -Path $ExportPath -NoTypeInformation -Force
                Write-ColorOutput -Message "`n[+] Policies exported to: $ExportPath" -Color "Green"
            } elseif ($extension -eq ".json") {
                # Export full data to JSON
                $policyData | ConvertTo-Json -Depth 10 | Out-File -FilePath $ExportPath -Force
                Write-ColorOutput -Message "`n[+] Full policy data exported to: $ExportPath" -Color "Green"
            } else {
                # Default to JSON for complex data
                $policyData | ConvertTo-Json -Depth 10 | Out-File -FilePath $ExportPath -Force
                Write-ColorOutput -Message "`n[+] Full policy data exported to: $ExportPath" -Color "Green"
            }
        } catch {
            Write-ColorOutput -Message "[!] Failed to export policies: $($_.Exception.Message)" -Color "Red"
        }
    }
    
    Write-ColorOutput -Message "`n[*] Conditional Access Policy review complete!" -Color "Green"
}

# Test if a tenant allows guest/external authentication (unauthenticated check)
