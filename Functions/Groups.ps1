# AZexec - Group Enumeration Functions
# These functions are loaded into the main script scope via dot-sourcing
function Format-GroupOutput {
    param(
        [PSCustomObject]$Group,
        [int]$MemberCount = 0
    )
    
    # Group name
    $groupName = if ($Group.DisplayName) { $Group.DisplayName } else { "UNKNOWN" }
    
    # Truncate long group names for column display
    $maxNameLength = 35
    $displayName = if ($groupName.Length -gt $maxNameLength) {
        $groupName.Substring(0, $maxNameLength - 3) + "..."
    } else {
        $groupName
    }
    
    # Use group ID as "IP" equivalent (first 15 chars for alignment)
    $groupIdShort = if ($Group.Id) { 
        $Group.Id.Substring(0, [Math]::Min(15, $Group.Id.Length))
    } else { 
        "UNKNOWN-ID" 
    }
    
    # Group type and security status
    $groupTypes = if ($Group.GroupTypes -and $Group.GroupTypes.Count -gt 0) {
        $Group.GroupTypes -join ","
    } else {
        "Security"
    }
    
    $securityEnabled = if ($Group.SecurityEnabled) { "True" } else { "False" }
    $mailEnabled = if ($Group.MailEnabled) { "True" } else { "False" }
    
    # Description
    $description = if ($Group.Description) { 
        if ($Group.Description.Length -gt 50) {
            $Group.Description.Substring(0, 47) + "..."
        } else {
            $Group.Description
        }
    } else { 
        "No description" 
    }
    
    # Check if this is a privileged/administrative group based on name
    $privilegedKeywords = @(
        "admin", "administrator", "admins",
        "global", "privileged", "security",
        "domain admins", "enterprise admins",
        "root", "sudo", "wheel",
        "helpdesk", "tier", "pim"
    )
    
    $isPrivilegedGroup = $false
    foreach ($keyword in $privilegedKeywords) {
        if ($groupName -match $keyword) {
            $isPrivilegedGroup = $true
            break
        }
    }
    
    $output = "AZR".PadRight(12) + 
              $groupIdShort.PadRight(17) + 
              "443".PadRight(7) + 
              $displayName.PadRight(38) + 
              "[*] (name:$groupName) (type:$groupTypes) (security:$securityEnabled) (mail:$mailEnabled) (members:$MemberCount) (desc:$description)"
    
    # Color based on privilege level and type
    $color = "Cyan"
    if ($isPrivilegedGroup -and $Group.SecurityEnabled) {
        $color = "Red"  # Privileged security groups in red (highest priority)
    } elseif ($Group.SecurityEnabled) {
        $color = "Green"  # Security groups in green
    } elseif ($Group.MailEnabled) {
        $color = "Yellow"  # Mail-enabled groups in yellow
    }
    
    Write-ColorOutput -Message $output -Color $color
}

# Get group member count
function Get-GroupMemberCount {
    param(
        [string]$GroupId
    )
    
    try {
        $members = Get-MgGroupMember -GroupId $GroupId -ErrorAction SilentlyContinue
        if ($members) {
            return $members.Count
        }
    } catch {
        return 0
    }
    
    return 0
}

# Main group enumeration function
function Invoke-GroupEnumeration {
    param(
        [bool]$ShowMembers,
        [string]$ExportPath
    )
    
    Write-ColorOutput -Message "`n[*] AZX - Azure/Entra Group Enumeration" -Color "Yellow"
    Write-ColorOutput -Message "[*] Command: Group Enumeration" -Color "Yellow"
    Write-ColorOutput -Message "[*] Similar to: nxc smb --groups`n" -Color "Yellow"
    
    # Get all groups
    Write-ColorOutput -Message "[*] Retrieving groups from Azure/Entra ID..." -Color "Yellow"
    
    try {
        $allGroups = Get-MgGroup -All -ErrorAction Stop
        Write-ColorOutput -Message "[+] Retrieved $($allGroups.Count) total groups`n" -Color "Green"
    } catch {
        Write-ColorOutput -Message "[!] Failed to retrieve groups: $_" -Color "Red"
        Write-ColorOutput -Message "[!] Ensure you have Group.Read.All or Directory.Read.All permissions" -Color "Red"
        Write-ColorOutput -Message "[*] Guest users may have restricted access to group enumeration" -Color "Yellow"
        return
    }
    
    if ($allGroups.Count -eq 0) {
        Write-ColorOutput -Message "[!] No groups found or insufficient permissions" -Color "Red"
        return
    }
    
    Write-ColorOutput -Message "[*] Displaying $($allGroups.Count) groups`n" -Color "Green"
    
    # Prepare export data
    $exportData = @()
    
    # Enumerate groups
    foreach ($group in $allGroups) {
        $memberCount = 0
        if ($ShowMembers) {
            $memberCount = Get-GroupMemberCount -GroupId $group.Id
        }
        
        Format-GroupOutput -Group $group -MemberCount $memberCount
        
        # Collect for export
        if ($ExportPath) {
            $exportData += [PSCustomObject]@{
                GroupId          = $group.Id
                DisplayName      = $group.DisplayName
                Description      = $group.Description
                GroupTypes       = ($group.GroupTypes -join ",")
                SecurityEnabled  = $group.SecurityEnabled
                MailEnabled      = $group.MailEnabled
                Mail             = $group.Mail
                MailNickname     = $group.MailNickname
                CreatedDateTime  = $group.CreatedDateTime
                MemberCount      = $memberCount
            }
        }
    }
    
    # Calculate summary statistics
    $securityGroups = ($allGroups | Where-Object { $_.SecurityEnabled -eq $true }).Count
    $mailEnabledGroups = ($allGroups | Where-Object { $_.MailEnabled -eq $true }).Count
    $unifiedGroups = ($allGroups | Where-Object { $_.GroupTypes -contains "Unified" }).Count
    $dynamicGroups = ($allGroups | Where-Object { $_.GroupTypes -contains "DynamicMembership" }).Count
    
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
                    "Total Groups" = $allGroups.Count
                    "Security Groups" = $securityGroups
                    "Mail-Enabled Groups" = $mailEnabledGroups
                    "Microsoft 365 Groups" = $unifiedGroups
                    "Dynamic Groups" = $dynamicGroups
                }
                
                $description = "Comprehensive group enumeration from Azure/Entra ID including security groups, M365 groups, and distribution lists."
                
                $success = Export-HtmlReport -Data $exportData -OutputPath $ExportPath -Title "Group Enumeration Report" -Statistics $stats -CommandName "groups" -Description $description
                
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
    
    Write-ColorOutput -Message "`n[*] Group enumeration complete!" -Color "Green"
    
    # Display summary statistics
    Write-ColorOutput -Message "`n[*] Summary:" -Color "Yellow"
    Write-ColorOutput -Message "    Total Groups: $($allGroups.Count)" -Color "Cyan"
    Write-ColorOutput -Message "    Security Groups: $securityGroups" -Color "Cyan"
    Write-ColorOutput -Message "    Mail-Enabled Groups: $mailEnabledGroups" -Color "Cyan"
    Write-ColorOutput -Message "    Microsoft 365 Groups: $unifiedGroups" -Color "Cyan"
    Write-ColorOutput -Message "    Dynamic Groups: $dynamicGroups" -Color "Cyan"
}

