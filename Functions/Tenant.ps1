# AZexec - Tenant Discovery Functions
# These functions are loaded into the main script scope via dot-sourcing
function Invoke-TenantDiscovery {
    param(
        [string]$Domain,
        [string]$ExportPath
    )
    
    # Auto-detect domain if not provided
    if (-not $Domain) {
        Write-ColorOutput -Message "[*] No domain specified, attempting to auto-detect..." -Color "Yellow"
        
        # Try to get the domain from the current user's UPN
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
                } elseif ($currentUser -match '(.+)\\') {
                    $domainName = $matches[1]
                    # Check if it's not a local machine name by checking if it looks like a NETBIOS name
                    if ($domainName -ne $env:COMPUTERNAME -and $domainName.Length -le 15) {
                        Write-ColorOutput -Message "[*] Detected NETBIOS domain: $domainName" -Color "Yellow"
                        Write-ColorOutput -Message "[!] Please provide the full DNS domain name for tenant discovery" -Color "Yellow"
                    }
                }
            }
        } catch {
            # Silent catch - we'll handle the error below
        }
        
        if ($detectedDomain) {
            $Domain = $detectedDomain
            Write-ColorOutput -Message "[+] Using auto-detected domain: $Domain`n" -Color "Green"
        } else {
            Write-ColorOutput -Message "[!] Could not auto-detect domain" -Color "Red"
            Write-ColorOutput -Message "[!] Please provide the domain using: .\azx.ps1 tenant -Domain example.com" -Color "Yellow"
            return
        }
    }
    
    Write-ColorOutput -Message "`n[*] AZX - Azure/Entra Tenant Discovery" -Color "Yellow"
    Write-ColorOutput -Message "[*] Target Domain: $Domain`n" -Color "Yellow"
    
    # Construct the OpenID configuration URLs
    $openIdConfigUrl = "https://login.microsoftonline.com/$Domain/.well-known/openid-configuration"
    $commonOpenIdConfigUrl = "https://login.microsoftonline.com/common/v2.0/.well-known/openid-configuration"
    
    Write-ColorOutput -Message "[*] Querying OpenID configuration endpoints..." -Color "Yellow"
    
    try {
        # Query the tenant-specific OpenID configuration endpoint
        $openIdConfig = Invoke-RestMethod -Uri $openIdConfigUrl -Method Get -ErrorAction Stop
        
        Write-ColorOutput -Message "[+] Successfully retrieved tenant configuration`n" -Color "Green"
        
        # Extract tenant ID from the issuer or token_endpoint
        $tenantId = $null
        if ($openIdConfig.issuer) {
            if ($openIdConfig.issuer -match '([a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})') {
                $tenantId = $matches[1]
            }
        }
        
        # Determine federation status
        $isFederated = $false
        if ($openIdConfig.tenant_region_scope -or $openIdConfig.tenant_region_sub_scope) {
            $isFederated = $true
        }
        
        # Format output in netexec style
        Write-ColorOutput -Message "AZR".PadRight(12) + $Domain.PadRight(35) + "443".PadRight(7) + "[*] Tenant Discovery" -Color "Cyan"
        Write-ColorOutput -Message ""
        
        # Display key information
        if ($tenantId) {
            Write-ColorOutput -Message "    [+] Tenant ID:                $tenantId" -Color "Green"
        }
        
        if ($openIdConfig.issuer) {
            Write-ColorOutput -Message "    [+] Issuer:                   $($openIdConfig.issuer)" -Color "Cyan"
        }
        
        if ($openIdConfig.authorization_endpoint) {
            Write-ColorOutput -Message "    [+] Authorization Endpoint:   $($openIdConfig.authorization_endpoint)" -Color "Cyan"
        }
        
        if ($openIdConfig.token_endpoint) {
            Write-ColorOutput -Message "    [+] Token Endpoint:           $($openIdConfig.token_endpoint)" -Color "Cyan"
        }
        
        if ($openIdConfig.userinfo_endpoint) {
            Write-ColorOutput -Message "    [+] UserInfo Endpoint:        $($openIdConfig.userinfo_endpoint)" -Color "Cyan"
        }
        
        if ($openIdConfig.end_session_endpoint) {
            Write-ColorOutput -Message "    [+] End Session Endpoint:     $($openIdConfig.end_session_endpoint)" -Color "Cyan"
        }
        
        if ($openIdConfig.jwks_uri) {
            Write-ColorOutput -Message "    [+] JWKS URI:                 $($openIdConfig.jwks_uri)" -Color "Cyan"
        }
        
        if ($openIdConfig.tenant_region_scope) {
            Write-ColorOutput -Message "    [+] Tenant Region Scope:      $($openIdConfig.tenant_region_scope)" -Color "Cyan"
        }
        
        if ($openIdConfig.tenant_region_sub_scope) {
            Write-ColorOutput -Message "    [+] Tenant Region SubScope:   $($openIdConfig.tenant_region_sub_scope)" -Color "Cyan"
        }
        
        if ($openIdConfig.cloud_instance_name) {
            Write-ColorOutput -Message "    [+] Cloud Instance:           $($openIdConfig.cloud_instance_name)" -Color "Cyan"
        }
        
        if ($openIdConfig.cloud_graph_host_name) {
            Write-ColorOutput -Message "    [+] Graph Host:               $($openIdConfig.cloud_graph_host_name)" -Color "Cyan"
        }
        
        Write-ColorOutput -Message "    [+] Federation Status:        $(if ($isFederated) { 'Federated' } else { 'Managed' })" -Color $(if ($isFederated) { "Yellow" } else { "Green" })
        
        # Additional metadata
        Write-ColorOutput -Message "`n    [*] Supported Response Types: $($openIdConfig.response_types_supported -join ', ')" -Color "DarkGray"
        Write-ColorOutput -Message "    [*] Supported Scopes:         $($openIdConfig.scopes_supported -join ', ')" -Color "DarkGray"
        Write-ColorOutput -Message "    [*] Supported Claims:         $($openIdConfig.claims_supported.Count) claims available" -Color "DarkGray"
        
        # Enumerate exposed applications and misconfigurations
        Write-ColorOutput -Message "`n[*] Enumerating exposed applications and configurations..." -Color "Yellow"
        
        $exposedApps = @()
        $exposedRedirectUris = @()
        $misconfigurations = @()
        
        # Check for common OpenID misconfigurations
        if ($openIdConfig.response_types_supported -contains "token" -or 
            $openIdConfig.response_types_supported -contains "id_token token") {
            $misconfigurations += "Implicit flow enabled (potential security risk)"
            Write-ColorOutput -Message "    [!] Implicit flow enabled (security consideration)" -Color "Yellow"
        }
        
        # Check for exposed redirect URIs in the configuration
        if ($openIdConfig.PSObject.Properties.Name -contains "redirect_uris") {
            $exposedRedirectUris = $openIdConfig.redirect_uris
            Write-ColorOutput -Message "    [!] Found $($exposedRedirectUris.Count) exposed redirect URI(s)" -Color "Yellow"
            foreach ($uri in $exposedRedirectUris) {
                Write-ColorOutput -Message "        - $uri" -Color "Cyan"
            }
        }
        
        # Try to enumerate federation metadata (for federated tenants)
        if ($isFederated) {
            Write-ColorOutput -Message "`n[*] Attempting to retrieve federation metadata..." -Color "Yellow"
            $federationMetadataUrl = "https://login.microsoftonline.com/$Domain/FederationMetadata/2007-06/FederationMetadata.xml"
            
            try {
                $fedMetadata = Invoke-RestMethod -Uri $federationMetadataUrl -Method Get -ErrorAction SilentlyContinue
                if ($fedMetadata) {
                    Write-ColorOutput -Message "    [+] Federation metadata accessible" -Color "Green"
                    
                    # Extract entity IDs and endpoints from federation metadata
                    if ($fedMetadata.EntityDescriptor) {
                        $entityId = $fedMetadata.EntityDescriptor.entityID
                        Write-ColorOutput -Message "    [+] Federation Entity ID: $entityId" -Color "Cyan"
                    }
                }
            } catch {
                # Silent catch - federation metadata may not be available
            }
        }
        
        # Check common v2.0 endpoint for additional metadata
        try {
            $commonConfig = Invoke-RestMethod -Uri $commonOpenIdConfigUrl -Method Get -ErrorAction SilentlyContinue
            if ($commonConfig) {
                # Compare configurations to identify tenant-specific settings
                $differences = @()
                
                # Check for additional grant types
                if ($openIdConfig.PSObject.Properties.Name -contains "grant_types_supported") {
                    Write-ColorOutput -Message "`n    [*] Supported Grant Types:" -Color "DarkGray"
                    foreach ($grantType in $openIdConfig.grant_types_supported) {
                        Write-ColorOutput -Message "        - $grantType" -Color "DarkGray"
                        
                        # Flag potentially risky grant types
                        if ($grantType -eq "password" -or $grantType -eq "client_credentials") {
                            Write-ColorOutput -Message "          [!] Note: $grantType grant type enabled" -Color "Yellow"
                        }
                    }
                }
            }
        } catch {
            # Silent catch
        }
        
        # Try to probe for exposed application endpoints
        Write-ColorOutput -Message "`n[*] Probing for exposed application information..." -Color "Yellow"
        
        # Check for app registration endpoint exposure
        $appEndpoints = @(
            "https://graph.microsoft.com/.well-known/openid-configuration",
            "https://management.azure.com/metadata/endpoints?api-version=2021-01-01"
        )
        
        foreach ($endpoint in $appEndpoints) {
            try {
                $response = Invoke-RestMethod -Uri $endpoint -Method Get -ErrorAction SilentlyContinue -TimeoutSec 5
                if ($response) {
                    Write-ColorOutput -Message "    [+] Accessible endpoint: $endpoint" -Color "Green"
                    
                    # Extract any exposed client IDs or app IDs
                    if ($response.PSObject.Properties.Name -contains "client_id") {
                        $exposedApps += $response.client_id
                    }
                }
            } catch {
                # Silent catch - endpoint not accessible
            }
        }
        
        # Summary of findings
        if ($exposedApps.Count -gt 0 -or $exposedRedirectUris.Count -gt 0 -or $misconfigurations.Count -gt 0) {
            Write-ColorOutput -Message "`n[*] Security Findings:" -Color "Yellow"
            
            if ($exposedApps.Count -gt 0) {
                Write-ColorOutput -Message "    [!] Exposed Application IDs: $($exposedApps.Count)" -Color "Yellow"
                foreach ($app in $exposedApps) {
                    Write-ColorOutput -Message "        - $app" -Color "Cyan"
                }
            }
            
            if ($exposedRedirectUris.Count -gt 0) {
                Write-ColorOutput -Message "    [!] Exposed Redirect URIs: $($exposedRedirectUris.Count)" -Color "Yellow"
            }
            
            if ($misconfigurations.Count -gt 0) {
                Write-ColorOutput -Message "    [!] Potential Misconfigurations: $($misconfigurations.Count)" -Color "Yellow"
                foreach ($config in $misconfigurations) {
                    Write-ColorOutput -Message "        - $config" -Color "Yellow"
                }
            }
        } else {
            Write-ColorOutput -Message "`n    [*] No exposed applications or obvious misconfigurations detected" -Color "Green"
        }
        
        # Export if requested
        if ($ExportPath) {
            try {
                $extension = [System.IO.Path]::GetExtension($ExportPath).ToLower()
                
                $exportData = [PSCustomObject]@{
                    Domain                    = $Domain
                    TenantId                  = $tenantId
                    Issuer                    = $openIdConfig.issuer
                    AuthorizationEndpoint     = $openIdConfig.authorization_endpoint
                    TokenEndpoint             = $openIdConfig.token_endpoint
                    UserInfoEndpoint          = $openIdConfig.userinfo_endpoint
                    EndSessionEndpoint        = $openIdConfig.end_session_endpoint
                    JwksUri                   = $openIdConfig.jwks_uri
                    TenantRegionScope         = $openIdConfig.tenant_region_scope
                    TenantRegionSubScope      = $openIdConfig.tenant_region_sub_scope
                    CloudInstanceName         = $openIdConfig.cloud_instance_name
                    CloudGraphHostName        = $openIdConfig.cloud_graph_host_name
                    FederationStatus          = if ($isFederated) { "Federated" } else { "Managed" }
                    ResponseTypesSupported    = $openIdConfig.response_types_supported
                    ScopesSupported           = $openIdConfig.scopes_supported
                    ClaimsSupported           = $openIdConfig.claims_supported
                    ExposedApplications       = $exposedApps
                    ExposedRedirectUris       = $exposedRedirectUris
                    PotentialMisconfigurations = $misconfigurations
                    FullConfiguration         = $openIdConfig
                }
                
                if ($extension -eq ".csv") {
                    $exportData | Select-Object -Property * -ExcludeProperty FullConfiguration,ExposedApplications,ExposedRedirectUris,PotentialMisconfigurations | Export-Csv -Path $ExportPath -NoTypeInformation -Force
                } elseif ($extension -eq ".json") {
                    $exportData | ConvertTo-Json -Depth 10 | Out-File -FilePath $ExportPath -Force
                } else {
                    # Default to JSON
                    $exportData | ConvertTo-Json -Depth 10 | Out-File -FilePath $ExportPath -Force
                }
                
                Write-ColorOutput -Message "`n[+] Tenant information exported to: $ExportPath" -Color "Green"
            } catch {
                Write-ColorOutput -Message "`n[!] Failed to export results: $_" -Color "Red"
            }
        }
        
        Write-ColorOutput -Message "`n[*] Tenant discovery complete!" -Color "Green"
        
    } catch {
        Write-ColorOutput -Message "[!] Failed to retrieve tenant configuration" -Color "Red"
        Write-ColorOutput -Message "[!] Error: $_" -Color "Red"
        
        # Check if it's a 400 error (invalid tenant)
        if ($_.Exception.Response.StatusCode -eq 400) {
            Write-ColorOutput -Message "[!] The specified domain does not appear to be a valid Azure/Entra tenant" -Color "Yellow"
        }
    }
}

# Enumerate vulnerable targets (Azure equivalent of --gen-relay-list)
