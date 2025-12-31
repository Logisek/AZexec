# AZexec - Role Assignment Enumeration Functions
# These functions are loaded into the main script scope via dot-sourcing
function Format-RoleAssignmentOutput {
    param(
        [PSCustomObject]$RoleAssignment,
        [PSCustomObject]$RoleDefinition,
        [PSCustomObject]$Principal,
        [string]$AssignmentType
    )
    
    # Principal display name and UPN (handle both PascalCase and camelCase)
    $principalName = if ($Principal.DisplayName) { $Principal.DisplayName } elseif ($Principal.displayName) { $Principal.displayName } else { "UNKNOWN" }
    $principalUPN = if ($Principal.UserPrincipalName) { $Principal.UserPrincipalName } elseif ($Principal.userPrincipalName) { $Principal.userPrincipalName } else { "N/A" }
    
    # Truncate long names for column display
    $maxNameLength = 30
    $principalNameShort = if ($principalName.Length -gt $maxNameLength) {
        $principalName.Substring(0, $maxNameLength - 3) + "..."
    } else {
        $principalName
    }
    
    # Role display name (handle both PascalCase and camelCase)
    $roleName = if ($RoleDefinition.DisplayName) { $RoleDefinition.DisplayName } elseif ($RoleDefinition.displayName) { $RoleDefinition.displayName } else { "UNKNOWN" }
    
    # Truncate role name if needed
    $maxRoleLength = 35
    $roleNameShort = if ($roleName.Length -gt $maxRoleLength) {
        $roleName.Substring(0, $maxRoleLength - 3) + "..."
    } else {
        $roleName
    }
    
    # Principal type
    $principalType = if ($Principal.'@odata.type') {
        $Principal.'@odata.type' -replace '#microsoft.graph.', ''
    } elseif ($Principal.UserPrincipalName) {
        "user"
    } elseif ($Principal.ServicePrincipalType) {
        "servicePrincipal"
    } elseif ($Principal.GroupTypes) {
        "group"
    } else {
        "unknown"
    }
    
    # Assignment scope (Direct vs PIM eligible)
    $assignmentScope = $AssignmentType
    
    # Get role template ID (for identifying privileged roles) - handle both case formats
    $roleTemplateId = if ($RoleDefinition.TemplateId) { $RoleDefinition.TemplateId } elseif ($RoleDefinition.templateId) { $RoleDefinition.templateId } elseif ($RoleDefinition.Id) { $RoleDefinition.Id } elseif ($RoleDefinition.id) { $RoleDefinition.id } else { $null }
    
    # Determine if this is a privileged/high-risk role
    $privilegedRoleIds = @(
        "62e90394-69f5-4237-9190-012177145e10",  # Global Administrator
        "e8611ab8-c189-46e8-94e1-60213ab1f814",  # Privileged Role Administrator
        "194ae4cb-b126-40b2-bd5b-6091b380977d",  # Security Administrator
        "9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3",  # Application Administrator
        "c4e39bd9-1100-46d3-8c65-fb160da0071f",  # Authentication Administrator
        "b0f54661-2d74-4c50-afa3-1ec803f12efe",  # Privileged Authentication Administrator
        "7be44c8a-adaf-4e2a-84d6-ab2649e08a13",  # Helpdesk Administrator
        "729827e3-9c14-49f7-bb1b-9608f156bbb8",  # User Administrator
        "fe930be7-5e62-47db-91af-98c3a49a38b1",  # Exchange Administrator
        "f28a1f50-f6e7-4571-818b-6a12f2af6b6c",  # SharePoint Administrator
        "29232cdf-9323-42fd-ade2-1d097af3e4de",  # Exchange Recipient Administrator
        "4ba39ca4-527c-499a-b93d-d9b492c50246",  # Partner Tier1 Support
        "e00e864a-17c5-4a4b-9c06-f5b95a8d5bd8"   # Partner Tier2 Support
    )
    
    $isPrivileged = $roleTemplateId -in $privilegedRoleIds
    
    # Build main output line in netexec style
    $output = "AZR".PadRight(12) + 
              $principalUPN.PadRight(35) + 
              "443".PadRight(7) + 
              $roleNameShort.PadRight(38) + 
              "[*] (principal:$principalNameShort) (type:$principalType) (scope:$assignmentScope) (privileged:$isPrivileged)"
    
    # Color based on privilege level and principal type
    $color = "Cyan"
    if ($isPrivileged) {
        $color = "Red"  # Privileged roles in red (high security concern)
    } elseif ($principalType -eq "servicePrincipal") {
        $color = "Yellow"  # Service principals in yellow
    } elseif ($principalType -eq "group") {
        $color = "Magenta"  # Groups in magenta
    } else {
        $color = "Green"  # Regular users in green
    }
    
    Write-ColorOutput -Message $output -Color $color
    
    # Display role description if available (handle both case formats)
    $description = if ($RoleDefinition.Description) { $RoleDefinition.Description } elseif ($RoleDefinition.description) { $RoleDefinition.description } else { $null }
    if ($description) {
        if ($description.Length -gt 80) {
            $description = $description.Substring(0, 77) + "..."
        }
        Write-ColorOutput -Message "    [+] Description: $description" -Color "DarkCyan"
    }
    
    # Display role permissions count (handle both case formats)
    $rolePerms = if ($RoleDefinition.RolePermissions) { $RoleDefinition.RolePermissions } elseif ($RoleDefinition.rolePermissions) { $RoleDefinition.rolePermissions } else { $null }
    if ($rolePerms) {
        $permCount = $rolePerms.Count
        Write-ColorOutput -Message "    [+] Role Permissions: $permCount permission set(s)" -Color "DarkCyan"
    }
    
    Write-ColorOutput -Message "" -Color "White"
}

# Main role assignment enumeration function
function Invoke-RoleAssignmentEnumeration {
    param(
        [string]$ExportPath
    )
    
    Write-ColorOutput -Message "`n[*] AZX - Azure/Entra Role Assignments Enumeration" -Color "Yellow"
    Write-ColorOutput -Message "[*] Command: Directory Role Assignments and Privileged Accounts" -Color "Yellow"
    Write-ColorOutput -Message "[*] Enumerates Azure Entra ID role assignments and privileged account access`n" -Color "Yellow"
    
    # Get context to display current user info
    $context = Get-MgContext
    if ($context) {
        Write-ColorOutput -Message "[*] Authenticated as: $($context.Account)" -Color "Cyan"
        Write-ColorOutput -Message "[*] Tenant: $($context.TenantId)" -Color "Cyan"
        Write-ColorOutput -Message "[*] Requested Scopes: RoleManagement.Read.Directory, Directory.Read.All, RoleEligibilitySchedule.Read.Directory" -Color "Cyan"
        Write-ColorOutput -Message "[*] Note: PIM data requires RoleEligibilitySchedule.Read.Directory + Azure Entra ID Premium P2`n" -Color "DarkGray"
    }
    
    # Prepare export data
    $exportData = @()
    
    # ===== PHASE 1: ENUMERATE DIRECTORY ROLES =====
    Write-ColorOutput -Message "[*] ========================================" -Color "Cyan"
    Write-ColorOutput -Message "[*] PHASE 1: Directory Role Enumeration" -Color "Cyan"
    Write-ColorOutput -Message "[*] ========================================`n" -Color "Cyan"
    
    Write-ColorOutput -Message "[*] Retrieving directory roles from Azure/Entra ID..." -Color "Yellow"
    
    try {
        # Get all active directory roles (roles that have been activated in the tenant)
        $activeRoles = Get-MgDirectoryRole -All -ErrorAction Stop
        Write-ColorOutput -Message "[+] Retrieved $($activeRoles.Count) active directory roles`n" -Color "Green"
    } catch {
        Write-ColorOutput -Message "[!] Failed to retrieve directory roles: $_" -Color "Red"
        Write-ColorOutput -Message "[!] Ensure you have RoleManagement.Read.Directory or Directory.Read.All permissions" -Color "Red"
        Write-ColorOutput -Message "[*] Guest users may have restricted access to role enumeration" -Color "Yellow"
        return
    }
    
    # Get all role definitions (templates) using Graph API directly
    Write-ColorOutput -Message "[*] Retrieving role definitions..." -Color "Yellow"
    
    try {
        $response = Invoke-MgGraphRequest -Uri "https://graph.microsoft.com/v1.0/roleManagement/directory/roleDefinitions" -Method GET -ErrorAction Stop
        $roleDefinitions = $response.value
        Write-ColorOutput -Message "[+] Retrieved $($roleDefinitions.Count) role definitions`n" -Color "Green"
    } catch {
        Write-ColorOutput -Message "[!] Failed to retrieve role definitions: $_" -Color "Yellow"
        Write-ColorOutput -Message "[*] Continuing with limited role data...`n" -Color "Yellow"
        $roleDefinitions = @()
    }
    
    # Build role definition lookup
    $roleDefLookup = @{}
    foreach ($roleDef in $roleDefinitions) {
        # Convert hashtable to PSCustomObject if needed
        if ($roleDef -is [hashtable]) {
            $roleDef = [PSCustomObject]$roleDef
        }
        
        if ($roleDef.id) {
            $roleDefLookup[$roleDef.id] = $roleDef
        }
        if ($roleDef.templateId) {
            $roleDefLookup[$roleDef.templateId] = $roleDef
        }
    }
    
    # ===== PHASE 2: ENUMERATE ACTIVE ROLE ASSIGNMENTS =====
    Write-ColorOutput -Message "[*] ========================================" -Color "Cyan"
    Write-ColorOutput -Message "[*] PHASE 2: Active Role Assignments" -Color "Cyan"
    Write-ColorOutput -Message "[*] ========================================`n" -Color "Cyan"
    
    Write-ColorOutput -Message "[*] Retrieving role members..." -Color "Yellow"
    Write-ColorOutput -Message "[*] This may take a while for large organizations...`n" -Color "Yellow"
    
    $totalAssignments = 0
    $privilegedCount = 0
    $userAssignments = 0
    $groupAssignments = 0
    $spnAssignments = 0
    
    foreach ($role in $activeRoles) {
        try {
            # Get members of this role
            $members = Get-MgDirectoryRoleMember -DirectoryRoleId $role.Id -All -ErrorAction SilentlyContinue
            
            if ($members -and $members.Count -gt 0) {
                $totalAssignments += $members.Count
                
                # Get role definition details
                $roleDef = $null
                if ($role.RoleTemplateId -and $roleDefLookup.ContainsKey($role.RoleTemplateId)) {
                    $roleDef = $roleDefLookup[$role.RoleTemplateId]
                } elseif ($roleDefLookup.ContainsKey($role.Id)) {
                    $roleDef = $roleDefLookup[$role.Id]
                } else {
                    # Create a minimal role def from the role object
                    $roleDef = [PSCustomObject]@{
                        Id = $role.Id
                        DisplayName = $role.DisplayName
                        Description = $role.Description
                        TemplateId = $role.RoleTemplateId
                        RolePermissions = @()
                    }
                }
                
                foreach ($member in $members) {
                    # Resolve principal details
                    $principal = $null
                    $principalType = "unknown"
                    
                    # Try to get full principal object
                    try {
                        $principalId = $member.Id
                        $odataType = $member.AdditionalProperties['@odata.type']
                        
                        if ($odataType -eq '#microsoft.graph.user' -or (-not $odataType -and $member.UserPrincipalName)) {
                            $principal = Get-MgUser -UserId $principalId -ErrorAction SilentlyContinue
                            $principalType = "user"
                            $userAssignments++
                        } elseif ($odataType -eq '#microsoft.graph.servicePrincipal') {
                            $principal = Get-MgServicePrincipal -ServicePrincipalId $principalId -ErrorAction SilentlyContinue
                            $principalType = "servicePrincipal"
                            $spnAssignments++
                        } elseif ($odataType -eq '#microsoft.graph.group') {
                            $principal = Get-MgGroup -GroupId $principalId -ErrorAction SilentlyContinue
                            $principalType = "group"
                            $groupAssignments++
                        }
                        
                        # Fallback to member object if we can't get full principal
                        if (-not $principal) {
                            $principal = $member
                        }
                    } catch {
                        $principal = $member
                    }
                    
                    # Check if privileged
                    $privilegedRoleIds = @(
                        "62e90394-69f5-4237-9190-012177145e10",  # Global Administrator
                        "e8611ab8-c189-46e8-94e1-60213ab1f814",  # Privileged Role Administrator
                        "194ae4cb-b126-40b2-bd5b-6091b380977d",  # Security Administrator
                        "9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3",  # Application Administrator
                        "c4e39bd9-1100-46d3-8c65-fb160da0071f",  # Authentication Administrator
                        "b0f54661-2d74-4c50-afa3-1ec803f12efe",  # Privileged Authentication Administrator
                        "7be44c8a-adaf-4e2a-84d6-ab2649e08a13",  # Helpdesk Administrator
                        "729827e3-9c14-49f7-bb1b-9608f156bbb8",  # User Administrator
                        "fe930be7-5e62-47db-91af-98c3a49a38b1",  # Exchange Administrator
                        "f28a1f50-f6e7-4571-818b-6a12f2af6b6c",  # SharePoint Administrator
                        "29232cdf-9323-42fd-ade2-1d097af3e4de",  # Exchange Recipient Administrator
                        "4ba39ca4-527c-499a-b93d-d9b492c50246",  # Partner Tier1 Support
                        "e00e864a-17c5-4a4b-9c06-f5b95a8d5bd8"   # Partner Tier2 Support
                    )
                    
                    $roleTemplateId = if ($role.RoleTemplateId) { $role.RoleTemplateId } else { $role.Id }
                    if ($roleTemplateId -in $privilegedRoleIds) {
                        $privilegedCount++
                    }
                    
                    # Format and display output
                    Format-RoleAssignmentOutput -RoleAssignment $member -RoleDefinition $roleDef -Principal $principal -AssignmentType "Active"
                    
                    # Collect for export
                    if ($ExportPath) {
                        $exportData += [PSCustomObject]@{
                            PrincipalId          = $principal.Id
                            PrincipalName        = $principal.DisplayName
                            PrincipalUPN         = if ($principal.UserPrincipalName) { $principal.UserPrincipalName } else { "N/A" }
                            PrincipalType        = $principalType
                            RoleId               = $role.Id
                            RoleName             = $role.DisplayName
                            RoleDescription      = $roleDef.Description
                            RoleTemplateId       = $role.RoleTemplateId
                            AssignmentType       = "Active"
                            IsPrivileged         = ($roleTemplateId -in $privilegedRoleIds)
                        }
                    }
                }
            }
        } catch {
            Write-ColorOutput -Message "[!] Failed to retrieve members for role $($role.DisplayName): $_" -Color "DarkGray"
        }
    }
    
    # ===== PHASE 3: PIM ELIGIBLE ASSIGNMENTS (if available) =====
    Write-ColorOutput -Message "`n[*] ========================================" -Color "Cyan"
    Write-ColorOutput -Message "[*] PHASE 3: PIM Eligible Assignments" -Color "Cyan"
    Write-ColorOutput -Message "[*] ========================================`n" -Color "Cyan"
    
    Write-ColorOutput -Message "[*] Checking for PIM eligible role assignments..." -Color "Yellow"
    
    $pimAssignments = 0
    try {
        # Try to get role eligibility schedules (PIM) using Graph API directly
        $response = Invoke-MgGraphRequest -Uri "https://graph.microsoft.com/v1.0/roleManagement/directory/roleEligibilitySchedules?`$expand=principal,roleDefinition" -Method GET -ErrorAction Stop
        $eligibleAssignments = $response.value
        
        if ($eligibleAssignments -and $eligibleAssignments.Count -gt 0) {
            Write-ColorOutput -Message "[+] Retrieved $($eligibleAssignments.Count) PIM eligible assignments`n" -Color "Green"
            $pimAssignments = $eligibleAssignments.Count
            
            foreach ($assignment in $eligibleAssignments) {
                # Get role definition (handle both case formats)
                $roleDef = if ($assignment.RoleDefinition) { $assignment.RoleDefinition } elseif ($assignment.roleDefinition) { $assignment.roleDefinition } else { $null }
                $roleDefId = if ($assignment.RoleDefinitionId) { $assignment.RoleDefinitionId } elseif ($assignment.roleDefinitionId) { $assignment.roleDefinitionId } else { $null }
                if (-not $roleDef -and $roleDefId -and $roleDefLookup.ContainsKey($roleDefId)) {
                    $roleDef = $roleDefLookup[$roleDefId]
                }
                
                # Get principal (handle both case formats)
                $principal = if ($assignment.Principal) { $assignment.Principal } elseif ($assignment.principal) { $assignment.principal } else { $null }
                $principalId = if ($assignment.PrincipalId) { $assignment.PrincipalId } elseif ($assignment.principalId) { $assignment.principalId } else { $null }
                if (-not $principal -and $principalId) {
                    try {
                        $principal = Get-MgUser -UserId $principalId -ErrorAction SilentlyContinue
                        if (-not $principal) {
                            $principal = Get-MgServicePrincipal -ServicePrincipalId $principalId -ErrorAction SilentlyContinue
                        }
                        if (-not $principal) {
                            $principal = Get-MgGroup -GroupId $principalId -ErrorAction SilentlyContinue
                        }
                    } catch {
                        # Use assignment object if we can't resolve
                        $principal = [PSCustomObject]@{
                            Id = $principalId
                            DisplayName = "Unknown"
                            UserPrincipalName = "N/A"
                        }
                    }
                }
                
                if ($roleDef -and $principal) {
                    Format-RoleAssignmentOutput -RoleAssignment $assignment -RoleDefinition $roleDef -Principal $principal -AssignmentType "PIM-Eligible"
                    
                    # Collect for export (handle both case formats)
                    if ($ExportPath) {
                        $exportData += [PSCustomObject]@{
                            PrincipalId          = if ($principal.Id) { $principal.Id } else { $principal.id }
                            PrincipalName        = if ($principal.DisplayName) { $principal.DisplayName } else { $principal.displayName }
                            PrincipalUPN         = if ($principal.UserPrincipalName) { $principal.UserPrincipalName } elseif ($principal.userPrincipalName) { $principal.userPrincipalName } else { "N/A" }
                            PrincipalType        = if ($principal.'@odata.type') { $principal.'@odata.type' -replace '#microsoft.graph.', '' } else { "unknown" }
                            RoleId               = if ($roleDef.Id) { $roleDef.Id } elseif ($roleDef.id) { $roleDef.id } else { "N/A" }
                            RoleName             = if ($roleDef.DisplayName) { $roleDef.DisplayName } elseif ($roleDef.displayName) { $roleDef.displayName } else { "Unknown" }
                            RoleDescription      = if ($roleDef.Description) { $roleDef.Description } elseif ($roleDef.description) { $roleDef.description } else { "" }
                            RoleTemplateId       = if ($roleDef.TemplateId) { $roleDef.TemplateId } elseif ($roleDef.templateId) { $roleDef.templateId } else { "" }
                            AssignmentType       = "PIM-Eligible"
                            IsPrivileged         = $true  # PIM roles are typically privileged
                        }
                    }
                }
            }
        } else {
            Write-ColorOutput -Message "[*] No PIM eligible assignments found or PIM not configured`n" -Color "DarkGray"
        }
    } catch {
        # Check if it's a permission error (403) - this is expected for most users
        $errorMessage = $_.Exception.Message
        if ($errorMessage -match "403" -or $errorMessage -match "Forbidden" -or $errorMessage -match "PermissionScopeNotGranted") {
            Write-ColorOutput -Message "[*] PIM data not accessible (permission denied)" -Color "DarkGray"
            Write-ColorOutput -Message "[*] Possible reasons:" -Color "DarkGray"
            Write-ColorOutput -Message "    - RoleEligibilitySchedule.Read.Directory permission not granted during consent" -Color "DarkGray"
            Write-ColorOutput -Message "    - Tenant doesn't have Azure Entra ID Premium P2 license" -Color "DarkGray"
            Write-ColorOutput -Message "    - Your account doesn't have sufficient privileges to read PIM data" -Color "DarkGray"
            Write-ColorOutput -Message "[*] To enable PIM access: Disconnect and reconnect with admin consent for all requested scopes`n" -Color "DarkGray"
        } else {
            # Unexpected error
            Write-ColorOutput -Message "[!] Failed to retrieve PIM assignments: $errorMessage" -Color "DarkGray"
            Write-ColorOutput -Message "[*] Continuing without PIM data...`n" -Color "DarkGray"
        }
    }
    
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
                    "Total Active Directory Roles" = $activeRoles.Count
                    "Total Role Assignments" = $totalAssignments
                    "Privileged Role Assignments (HIGH RISK)" = $privilegedCount
                    "User Assignments" = $userAssignments
                    "Group Assignments" = $groupAssignments
                    "Service Principal Assignments" = $spnAssignments
                    "PIM Eligible Assignments" = $pimAssignments
                }
                
                $description = "Directory role assignment enumeration including active and PIM eligible assignments. Highlights privileged accounts and group-based role assignments."
                
                $success = Export-HtmlReport -Data $exportData -OutputPath $ExportPath -Title "Role Assignment Enumeration Report" -Statistics $stats -CommandName "roles" -Description $description
                
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
    
    Write-ColorOutput -Message "`n[*] Role assignment enumeration complete!" -Color "Green"
    
    # Display summary statistics
    Write-ColorOutput -Message "`n[*] Summary:" -Color "Yellow"
    Write-ColorOutput -Message "    Total Active Directory Roles: $($activeRoles.Count)" -Color "Cyan"
    Write-ColorOutput -Message "    Total Role Assignments: $totalAssignments" -Color "Cyan"
    Write-ColorOutput -Message "    Privileged Role Assignments: $privilegedCount" -Color "Cyan"
    Write-ColorOutput -Message "    User Assignments: $userAssignments" -Color "Cyan"
    Write-ColorOutput -Message "    Group Assignments: $groupAssignments" -Color "Cyan"
    Write-ColorOutput -Message "    Service Principal Assignments: $spnAssignments" -Color "Cyan"
    if ($pimAssignments -gt 0) {
        Write-ColorOutput -Message "    PIM Eligible Assignments: $pimAssignments" -Color "Cyan"
    }
    
    # Security warnings
    if ($privilegedCount -gt 0) {
        Write-ColorOutput -Message "`n[!] Security Notice:" -Color "Yellow"
        Write-ColorOutput -Message "    [!] Found $privilegedCount privileged role assignments" -Color "Yellow"
        Write-ColorOutput -Message "    [*] Review these accounts for security compliance" -Color "DarkGray"
        Write-ColorOutput -Message "    [*] Ensure MFA is enforced for all privileged accounts" -Color "DarkGray"
    }
    
    if ($groupAssignments -gt 0) {
        Write-ColorOutput -Message "`n[*] Group-Based Role Assignments:" -Color "Yellow"
        Write-ColorOutput -Message "    [*] Found $groupAssignments role assignments via groups" -Color "Cyan"
        Write-ColorOutput -Message "    [*] Review group memberships to understand effective permissions" -Color "DarkGray"
    }
    
    # PIM access guidance
    if ($pimAssignments -eq 0) {
        Write-ColorOutput -Message "`n[*] PIM Eligible Assignments:" -Color "Yellow"
        Write-ColorOutput -Message "    [*] No PIM eligible assignments retrieved" -Color "Cyan"
        Write-ColorOutput -Message "    [*] To enable PIM enumeration:" -Color "DarkGray"
        Write-ColorOutput -Message "        1. Ensure tenant has Azure Entra ID Premium P2 license" -Color "DarkGray"
        Write-ColorOutput -Message "        2. Disconnect: Disconnect-MgGraph" -Color "DarkGray"
        Write-ColorOutput -Message "        3. Reconnect with admin consent for all scopes" -Color "DarkGray"
        Write-ColorOutput -Message "        4. Run: .\azx.ps1 roles" -Color "DarkGray"
    }
}

# Format service principal discovery output like netexec
