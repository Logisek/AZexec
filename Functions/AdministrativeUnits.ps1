# AZexec - Administrative Units Enumeration Functions
# These functions are loaded into the main script scope via dot-sourcing

function Format-AdministrativeUnitOutput {
    param(
        [PSCustomObject]$AdminUnit,
        [int]$MemberCount = 0,
        [int]$ScopedRoleCount = 0
    )
    
    # Admin unit name
    $auName = if ($AdminUnit.DisplayName) { $AdminUnit.DisplayName } else { "UNKNOWN" }
    
    # Truncate long names for column display
    $maxNameLength = 35
    $displayName = if ($auName.Length -gt $maxNameLength) {
        $auName.Substring(0, $maxNameLength - 3) + "..."
    } else {
        $auName
    }
    
    # Use admin unit ID as "IP" equivalent (first 15 chars for alignment)
    $auIdShort = if ($AdminUnit.Id) { 
        $AdminUnit.Id.Substring(0, [Math]::Min(15, $AdminUnit.Id.Length))
    } else { 
        "UNKNOWN-ID" 
    }
    
    # Membership type
    $membershipType = if ($AdminUnit.MembershipType) {
        $AdminUnit.MembershipType
    } else {
        "Assigned"
    }
    
    # Visibility
    $visibility = if ($AdminUnit.Visibility) {
        $AdminUnit.Visibility
    } else {
        "Public"
    }
    
    # Description
    $description = if ($AdminUnit.Description) { 
        if ($AdminUnit.Description.Length -gt 50) {
            $AdminUnit.Description.Substring(0, 47) + "..."
        } else {
            $AdminUnit.Description
        }
    } else { 
        "No description" 
    }
    
    # Check if this is a privileged/administrative AU based on name
    $privilegedKeywords = @(
        "admin", "administrator", "admins",
        "privileged", "security", "tier",
        "executive", "sensitive", "critical",
        "it", "infrastructure", "global"
    )
    
    $isPrivilegedAU = $false
    foreach ($keyword in $privilegedKeywords) {
        if ($auName -match $keyword) {
            $isPrivilegedAU = $true
            break
        }
    }
    
    # Build output in netexec style
    $output = "AZR".PadRight(12) + 
              $auIdShort.PadRight(17) + 
              "443".PadRight(7) + 
              $displayName.PadRight(38) + 
              "[*] (name:$auName) (type:$membershipType) (visibility:$visibility) (members:$MemberCount) (scopedRoles:$ScopedRoleCount) (desc:$description)"
    
    # Color based on privilege level and configuration
    $color = "Cyan"
    if ($isPrivilegedAU) {
        $color = "Red"  # Privileged AUs in red (highest priority)
    } elseif ($membershipType -eq "Dynamic") {
        $color = "Yellow"  # Dynamic AUs in yellow (automated membership)
    } elseif ($MemberCount -gt 0 -or $ScopedRoleCount -gt 0) {
        $color = "Green"  # Active AUs with members or roles in green
    }
    
    Write-ColorOutput -Message $output -Color $color
}

# Get administrative unit member count
function Get-AdministrativeUnitMemberCount {
    param(
        [string]$AdminUnitId
    )
    
    try {
        $members = Get-MgDirectoryAdministrativeUnitMember -AdministrativeUnitId $AdminUnitId -ErrorAction SilentlyContinue
        if ($members) {
            return $members.Count
        }
    } catch {
        return 0
    }
    
    return 0
}

# Get scoped role assignments for an administrative unit
function Get-AdministrativeUnitScopedRoleCount {
    param(
        [string]$AdminUnitId
    )
    
    try {
        $scopedMembers = Get-MgDirectoryAdministrativeUnitScopedRoleMember -AdministrativeUnitId $AdminUnitId -ErrorAction SilentlyContinue
        if ($scopedMembers) {
            return $scopedMembers.Count
        }
    } catch {
        return 0
    }
    
    return 0
}

# Main administrative units enumeration function
function Invoke-AdministrativeUnitsEnumeration {
    param(
        [bool]$ShowMembers,
        [string]$ExportPath
    )
    
    Write-ColorOutput -Message "`n[*] AZX - Azure/Entra Administrative Units Enumeration" -Color "Yellow"
    Write-ColorOutput -Message "[*] Command: Administrative Units (Local Groups Equivalent)" -Color "Yellow"
    Write-ColorOutput -Message "[*] Similar to: nxc smb --local-group`n" -Color "Yellow"
    
    Write-ColorOutput -Message "[*] Technical Context:" -Color "Cyan"
    Write-ColorOutput -Message "    On-Premises: Local groups provide machine-scoped access control" -Color "Gray"
    Write-ColorOutput -Message "                 (e.g., Administrators, Users, Remote Desktop Users)" -Color "Gray"
    Write-ColorOutput -Message "    Azure:       Administrative Units provide directory-scoped delegation" -Color "Gray"
    Write-ColorOutput -Message "                 (scoped admin roles for subset of users/groups/devices)`n" -Color "Gray"
    
    # Get all administrative units
    Write-ColorOutput -Message "[*] Retrieving administrative units from Azure/Entra ID..." -Color "Yellow"
    
    try {
        $allAdminUnits = Get-MgDirectoryAdministrativeUnit -All -ErrorAction Stop
        Write-ColorOutput -Message "[+] Retrieved $($allAdminUnits.Count) administrative units`n" -Color "Green"
    } catch {
        Write-ColorOutput -Message "[!] Failed to retrieve administrative units: $_" -Color "Red"
        Write-ColorOutput -Message "[!] Ensure you have AdministrativeUnit.Read.All or Directory.Read.All permissions" -Color "Red"
        Write-ColorOutput -Message "[*] Guest users may have restricted access to administrative unit enumeration" -Color "Yellow"
        return
    }
    
    if ($allAdminUnits.Count -eq 0) {
        Write-ColorOutput -Message "[!] No administrative units found" -Color "Yellow"
        Write-ColorOutput -Message "[*] This may indicate:" -Color "Cyan"
        Write-ColorOutput -Message "    - No administrative units are configured in this tenant" -Color "Gray"
        Write-ColorOutput -Message "    - Insufficient permissions to enumerate administrative units" -Color "Gray"
        Write-ColorOutput -Message "    - Administrative Units require Azure AD Premium P1/P2 licensing" -Color "Gray"
        return
    }
    
    Write-ColorOutput -Message "[*] Displaying $($allAdminUnits.Count) administrative units`n" -Color "Green"
    
    # Prepare export data
    $exportData = @()
    
    # Enumerate administrative units
    foreach ($au in $allAdminUnits) {
        $memberCount = 0
        $scopedRoleCount = 0
        
        if ($ShowMembers) {
            $memberCount = Get-AdministrativeUnitMemberCount -AdminUnitId $au.Id
            $scopedRoleCount = Get-AdministrativeUnitScopedRoleCount -AdminUnitId $au.Id
        }
        
        Format-AdministrativeUnitOutput -AdminUnit $au -MemberCount $memberCount -ScopedRoleCount $scopedRoleCount
        
        # Collect for export
        if ($ExportPath) {
            $exportData += [PSCustomObject]@{
                AdminUnitId       = $au.Id
                DisplayName       = $au.DisplayName
                Description       = $au.Description
                MembershipType    = $au.MembershipType
                MembershipRule    = $au.MembershipRule
                Visibility        = $au.Visibility
                MemberCount       = $memberCount
                ScopedRoleCount   = $scopedRoleCount
            }
        }
    }
    
    # Calculate summary statistics
    $assignedAUs = ($allAdminUnits | Where-Object { -not $_.MembershipType -or $_.MembershipType -eq "Assigned" }).Count
    $dynamicAUs = ($allAdminUnits | Where-Object { $_.MembershipType -eq "Dynamic" }).Count
    
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
                    "Total Administrative Units" = $allAdminUnits.Count
                    "Assigned Membership" = $assignedAUs
                    "Dynamic Membership" = $dynamicAUs
                }
                
                $description = "Administrative Units provide scoped administration in Azure AD, similar to how local groups provide machine-scoped access control in on-premises Windows environments."
                
                $success = Export-HtmlReport -Data $exportData -OutputPath $ExportPath -Title "Administrative Units Enumeration Report" -Statistics $stats -CommandName "local-groups" -Description $description
                
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
    
    Write-ColorOutput -Message "`n[*] Administrative units enumeration complete!" -Color "Green"
    
    # Display summary statistics
    Write-ColorOutput -Message "`n[*] Summary:" -Color "Yellow"
    Write-ColorOutput -Message "    Total Administrative Units: $($allAdminUnits.Count)" -Color "Cyan"
    Write-ColorOutput -Message "    Assigned Membership: $assignedAUs" -Color "Cyan"
    Write-ColorOutput -Message "    Dynamic Membership: $dynamicAUs" -Color "Cyan"
    
    # Security recommendations
    Write-ColorOutput -Message "`n[*] Security Recommendations:" -Color "Yellow"
    Write-ColorOutput -Message "    - Review scoped role assignments for least privilege" -Color "Gray"
    Write-ColorOutput -Message "    - Audit administrative unit membership regularly" -Color "Gray"
    Write-ColorOutput -Message "    - Use dynamic membership rules for automated governance" -Color "Gray"
    Write-ColorOutput -Message "    - Restrict administrative unit creation to authorized admins" -Color "Gray"
    
    # Azure AD Premium note
    Write-ColorOutput -Message "`n[*] Note: Administrative Units require Azure AD Premium P1 or P2 licensing" -Color "Cyan"
}

