# AZexec - Core Functions
# These functions are loaded into the main script scope via dot-sourcing
function Write-ColorOutput {
    param(
        [string]$Message,
        [string]$Color = "White"
    )
    
    if ($NoColor) {
        Write-Host $Message
    } else {
        Write-Host $Message -ForegroundColor $Color
    }
}

function Export-HtmlReport {
    param(
        [Parameter(Mandatory=$true)]
        [array]$Data,
        
        [Parameter(Mandatory=$true)]
        [string]$OutputPath,
        
        [Parameter(Mandatory=$true)]
        [string]$Title,
        
        [Parameter(Mandatory=$false)]
        [hashtable]$Statistics = @{},
        
        [Parameter(Mandatory=$false)]
        [string]$CommandName = "",
        
        [Parameter(Mandatory=$false)]
        [string]$Description = ""
    )
    
    # HTML Header with NetExec-style dark theme
    $html = @"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>$Title - AZexec Report</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: 'Consolas', 'Monaco', 'Courier New', monospace;
            background: linear-gradient(135deg, #0d0d0d 0%, #1a1a1a 100%);
            color: #00ff00;
            padding: 20px;
            line-height: 1.6;
        }
        
        .container {
            max-width: 1400px;
            margin: 0 auto;
            background: rgba(0, 0, 0, 0.8);
            border: 2px solid #00ff00;
            border-radius: 10px;
            box-shadow: 0 0 20px rgba(0, 255, 0, 0.3);
            padding: 30px;
        }
        
        .header {
            text-align: center;
            margin-bottom: 30px;
            padding-bottom: 20px;
            border-bottom: 2px solid #00ff00;
        }
        
        .header h1 {
            color: #00ff00;
            font-size: 2.5em;
            text-shadow: 0 0 10px #00ff00;
            margin-bottom: 10px;
            letter-spacing: 3px;
        }
        
        .header .subtitle {
            color: #00ccff;
            font-size: 1.2em;
            margin-top: 10px;
        }
        
        .metadata {
            background: rgba(0, 50, 0, 0.5);
            border-left: 4px solid #00ff00;
            padding: 15px;
            margin-bottom: 25px;
            border-radius: 5px;
        }
        
        .metadata p {
            color: #00ccff;
            margin: 5px 0;
            font-size: 0.95em;
        }
        
        .metadata strong {
            color: #00ff00;
        }
        
        .statistics {
            background: rgba(0, 50, 50, 0.5);
            border-left: 4px solid #00ccff;
            padding: 20px;
            margin-bottom: 25px;
            border-radius: 5px;
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 15px;
        }
        
        .stat-item {
            background: rgba(0, 0, 0, 0.5);
            padding: 15px;
            border-radius: 5px;
            border: 1px solid #00ccff;
        }
        
        .stat-label {
            color: #888;
            font-size: 0.9em;
            margin-bottom: 5px;
        }
        
        .stat-value {
            color: #00ff00;
            font-size: 1.5em;
            font-weight: bold;
        }
        
        .stat-value.high {
            color: #ff3333;
        }
        
        .stat-value.medium {
            color: #ffaa00;
        }
        
        .stat-value.low {
            color: #888;
        }
        
        .section-title {
            color: #00ff00;
            font-size: 1.5em;
            margin: 30px 0 15px 0;
            padding-bottom: 10px;
            border-bottom: 1px solid #00ff00;
            text-transform: uppercase;
            letter-spacing: 2px;
        }
        
        .table-container {
            overflow-x: auto;
            margin-bottom: 30px;
        }
        
        table {
            width: 100%;
            border-collapse: collapse;
            background: rgba(0, 0, 0, 0.6);
            border-radius: 5px;
            overflow: hidden;
        }
        
        thead {
            background: rgba(0, 100, 0, 0.5);
        }
        
        th {
            color: #00ff00;
            padding: 15px;
            text-align: left;
            font-weight: bold;
            text-transform: uppercase;
            font-size: 0.9em;
            border-bottom: 2px solid #00ff00;
        }
        
        td {
            color: #00ccff;
            padding: 12px 15px;
            border-bottom: 1px solid #333;
        }
        
        tr:hover {
            background: rgba(0, 100, 0, 0.2);
        }
        
        tr:nth-child(even) {
            background: rgba(0, 0, 0, 0.3);
        }
        
        .badge {
            display: inline-block;
            padding: 4px 10px;
            border-radius: 3px;
            font-size: 0.85em;
            font-weight: bold;
            margin: 2px;
        }
        
        .badge-success {
            background: rgba(0, 255, 0, 0.2);
            color: #00ff00;
            border: 1px solid #00ff00;
        }
        
        .badge-danger {
            background: rgba(255, 51, 51, 0.2);
            color: #ff3333;
            border: 1px solid #ff3333;
        }
        
        .badge-warning {
            background: rgba(255, 170, 0, 0.2);
            color: #ffaa00;
            border: 1px solid #ffaa00;
        }
        
        .badge-info {
            background: rgba(0, 204, 255, 0.2);
            color: #00ccff;
            border: 1px solid #00ccff;
        }
        
        .badge-secondary {
            background: rgba(136, 136, 136, 0.2);
            color: #888;
            border: 1px solid #888;
        }
        
        .footer {
            margin-top: 40px;
            padding-top: 20px;
            border-top: 1px solid #00ff00;
            text-align: center;
            color: #888;
            font-size: 0.9em;
        }
        
        .footer a {
            color: #00ccff;
            text-decoration: none;
        }
        
        .footer a:hover {
            text-decoration: underline;
        }
        
        .risk-high {
            color: #ff3333 !important;
            font-weight: bold;
        }
        
        .risk-medium {
            color: #ffaa00 !important;
        }
        
        .risk-low {
            color: #888 !important;
        }
        
        .description {
            background: rgba(0, 50, 100, 0.3);
            border-left: 4px solid #00ccff;
            padding: 15px;
            margin-bottom: 25px;
            border-radius: 5px;
            color: #aaa;
            font-size: 0.95em;
        }
        
        @media print {
            body {
                background: white;
                color: black;
            }
            
            .container {
                border: 1px solid black;
                box-shadow: none;
            }
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>⚡ AZexec Report ⚡</h1>
            <div class="subtitle">$Title</div>
        </div>
        
        <div class="metadata">
            <p><strong>Command:</strong> $CommandName</p>
            <p><strong>Generated:</strong> $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")</p>
            <p><strong>Total Records:</strong> $($Data.Count)</p>
        </div>
"@

    # Add description if provided
    if ($Description) {
        $html += @"
        <div class="description">
            $Description
        </div>
"@
    }

    # Add statistics if provided
    if ($Statistics.Count -gt 0) {
        $html += @"
        <div class="statistics">
"@
        foreach ($stat in $Statistics.GetEnumerator()) {
            $valueClass = ""
            if ($stat.Key -match "High|Critical|Privileged|Risk") {
                $valueClass = "high"
            } elseif ($stat.Key -match "Medium|Warning") {
                $valueClass = "medium"
            } elseif ($stat.Key -match "Low|Disabled") {
                $valueClass = "low"
            }
            
            $html += @"
            <div class="stat-item">
                <div class="stat-label">$($stat.Key)</div>
                <div class="stat-value $valueClass">$($stat.Value)</div>
            </div>
"@
        }
        $html += @"
        </div>
"@
    }

    # Add data table
    if ($Data.Count -gt 0) {
        $html += @"
        <h2 class="section-title">📊 Data</h2>
        <div class="table-container">
            <table>
                <thead>
                    <tr>
"@
        # Get column headers from first object
        $properties = $Data[0].PSObject.Properties.Name
        foreach ($prop in $properties) {
            $html += "                        <th>$prop</th>`n"
        }
        
        $html += @"
                    </tr>
                </thead>
                <tbody>
"@
        
        # Add data rows
        foreach ($row in $Data) {
            $html += "                    <tr>`n"
            foreach ($prop in $properties) {
                $value = $row.$prop
                
                # Handle null/empty values
                if ($null -eq $value -or $value -eq "") {
                    $value = "-"
                }
                
                # Convert boolean values to badges
                if ($value -is [bool]) {
                    if ($value) {
                        $value = "<span class='badge badge-success'>True</span>"
                    } else {
                        $value = "<span class='badge badge-secondary'>False</span>"
                    }
                }
                
                # Apply risk-based coloring for specific columns
                $cellClass = ""
                if ($prop -match "Risk|Severity") {
                    if ($value -match "HIGH|Critical") {
                        $cellClass = " class='risk-high'"
                    } elseif ($value -match "MEDIUM|Warning") {
                        $cellClass = " class='risk-medium'"
                    } elseif ($value -match "LOW") {
                        $cellClass = " class='risk-low'"
                    }
                }
                
                # Handle array values
                if ($value -is [array]) {
                    $value = $value -join ", "
                }
                
                # Escape HTML special characters
                $value = [System.Web.HttpUtility]::HtmlEncode($value.ToString())
                
                $html += "                        <td$cellClass>$value</td>`n"
            }
            $html += "                    </tr>`n"
        }
        
        $html += @"
                </tbody>
            </table>
        </div>
"@
    }

    # Add footer
    $html += @"
        <div class="footer">
            <p>Generated by <strong>AZexec</strong> - Azure/Entra Execution Tool</p>
            <p><a href="https://github.com/Logisek/AZexec" target="_blank">https://github.com/Logisek/AZexec</a></p>
            <p>Part of the EvilMist Toolkit | Copyright © 2025-2026 Logisek</p>
        </div>
    </div>
</body>
</html>
"@

    # Write HTML to file
    try {
        # Add System.Web for HTML encoding
        Add-Type -AssemblyName System.Web
        $html | Out-File -FilePath $OutputPath -Encoding UTF8 -Force
        return $true
    } catch {
        Write-ColorOutput -Message "[!] Failed to generate HTML report: $_" -Color "Red"
        return $false
    }
}


function Initialize-GraphModule {
    param(
        [string[]]$RequiredModules = @("Microsoft.Graph.Authentication", "Microsoft.Graph.Identity.DirectoryManagement")
    )

    Write-ColorOutput -Message "[*] Checking Microsoft.Graph modules..." -Color "Yellow"

    # Always ensure Authentication is first (dependency for all other modules)
    if ($RequiredModules -notcontains "Microsoft.Graph.Authentication") {
        $RequiredModules = @("Microsoft.Graph.Authentication") + $RequiredModules
    } else {
        # Move Authentication to the front
        $RequiredModules = @("Microsoft.Graph.Authentication") + ($RequiredModules | Where-Object { $_ -ne "Microsoft.Graph.Authentication" })
    }

    # First pass: Check all modules are installed and get the highest required version
    $highestVersion = $null
    foreach ($moduleName in $RequiredModules) {
        $installedModule = Get-Module -ListAvailable -Name $moduleName | Sort-Object Version -Descending | Select-Object -First 1
        if ($installedModule) {
            if ($null -eq $highestVersion -or $installedModule.Version -gt $highestVersion) {
                $highestVersion = $installedModule.Version
            }
        }
    }

    # Check if Authentication module needs to be updated to match other modules
    $authModule = Get-Module -ListAvailable -Name "Microsoft.Graph.Authentication" | Sort-Object Version -Descending | Select-Object -First 1
    if ($authModule -and $highestVersion -and $authModule.Version -lt $highestVersion) {
        Write-ColorOutput -Message "[!] Microsoft.Graph.Authentication ($($authModule.Version)) needs update to match other modules ($highestVersion)" -Color "Yellow"
        Write-ColorOutput -Message "[*] Updating Microsoft.Graph.Authentication..." -Color "Yellow"
        try {
            Update-Module Microsoft.Graph.Authentication -Force -ErrorAction Stop
            Write-ColorOutput -Message "[+] Microsoft.Graph.Authentication updated successfully" -Color "Green"
        } catch {
            Write-ColorOutput -Message "[!] Failed to update module. Attempting fresh install..." -Color "Yellow"
            try {
                Install-Module Microsoft.Graph.Authentication -Scope CurrentUser -Force -AllowClobber -ErrorAction Stop
                Write-ColorOutput -Message "[+] Microsoft.Graph.Authentication installed successfully" -Color "Green"
            } catch {
                Write-ColorOutput -Message "[!] Failed to install Microsoft.Graph.Authentication: $_" -Color "Red"
                exit 1
            }
        }
    }

    foreach ($moduleName in $RequiredModules) {
        # Check if module is available (installed)
        if (-not (Get-Module -ListAvailable -Name $moduleName)) {
            Write-ColorOutput -Message "[!] Module $moduleName not found. Installing..." -Color "Yellow"
            try {
                Install-Module $moduleName -Scope CurrentUser -Force -AllowClobber -ErrorAction Stop
                Write-ColorOutput -Message "[+] Module $moduleName installed successfully" -Color "Green"
            } catch {
                Write-ColorOutput -Message "[!] Failed to install module $moduleName : $_" -Color "Red"
                exit 1
            }
        }

        # Import module if not already loaded
        if (-not (Get-Module -Name $moduleName)) {
            try {
                Import-Module $moduleName -ErrorAction Stop
                Write-ColorOutput -Message "[+] Loaded module: $moduleName" -Color "Green"
            } catch {
                # If import fails due to version mismatch, try updating the module
                if ($_ -match "RequiredModules" -or $_ -match "is not loaded") {
                    Write-ColorOutput -Message "[!] Module version conflict detected. Updating $moduleName..." -Color "Yellow"
                    try {
                        Update-Module $moduleName -Force -ErrorAction Stop
                        Import-Module $moduleName -ErrorAction Stop
                        Write-ColorOutput -Message "[+] Loaded module: $moduleName (after update)" -Color "Green"
                    } catch {
                        Write-ColorOutput -Message "[!] Failed to update/import module $moduleName : $_" -Color "Red"
                        exit 1
                    }
                } else {
                    Write-ColorOutput -Message "[!] Failed to import module $moduleName : $_" -Color "Red"
                    exit 1
                }
            }
        }
    }
}


function Test-IsGuestUser {
    param(
        [string]$UserPrincipalName
    )
    
    try {
        # Get the current user's details from Microsoft Graph
        $currentUser = Get-MgUser -UserId $UserPrincipalName -ErrorAction SilentlyContinue
        
        if ($currentUser) {
            # Check if userType is Guest
            if ($currentUser.UserType -eq "Guest") {
                return $true
            }
            
            # Also check if UPN contains #EXT# (external user marker)
            if ($UserPrincipalName -like "*#EXT#*") {
                return $true
            }
        }
    } catch {
        # If we can't determine, assume not guest
        return $false
    }
    
    return $false
}


function Connect-GraphAPI {
    param(
        [string]$Scopes
    )

    Write-ColorOutput -Message "[*] Connecting to Microsoft Graph..." -Color "Yellow"

    try {
        $scopeArray = $Scopes -split ','

        # Check if already connected
        $context = Get-MgContext
        if ($context) {
            # Check if the current session has all required scopes
            $currentScopes = $context.Scopes
            $missingScopes = @()

            foreach ($requiredScope in $scopeArray) {
                $requiredScope = $requiredScope.Trim()
                # Check if scope is present (case-insensitive, handle .Default suffix)
                $scopeFound = $currentScopes | Where-Object {
                    $_ -ieq $requiredScope -or
                    $_ -ieq "$requiredScope" -or
                    $_ -like "*$requiredScope*"
                }
                if (-not $scopeFound) {
                    $missingScopes += $requiredScope
                }
            }

            if ($missingScopes.Count -gt 0) {
                Write-ColorOutput -Message "[!] Current session missing required scopes: $($missingScopes -join ', ')" -Color "Yellow"
                Write-ColorOutput -Message "[*] Reconnecting with required scopes..." -Color "Yellow"

                # Disconnect and reconnect with new scopes
                Disconnect-MgGraph -ErrorAction SilentlyContinue
                Connect-MgGraph -Scopes $scopeArray -ErrorAction Stop
                $context = Get-MgContext
                Write-ColorOutput -Message "[+] Connected to tenant: $($context.TenantId)" -Color "Green"
                Write-ColorOutput -Message "[+] Account: $($context.Account)" -Color "Green"
            } else {
                Write-ColorOutput -Message "[+] Already connected to tenant: $($context.TenantId)" -Color "Green"
                Write-ColorOutput -Message "[+] Account: $($context.Account)" -Color "Green"
            }

            # Check if user is a guest
            $isGuest = Test-IsGuestUser -UserPrincipalName $context.Account
            if ($isGuest) {
                Write-ColorOutput -Message "`n[!] GUEST USER DETECTED" -Color "Yellow"
                Write-ColorOutput -Message "[*] You are authenticated as a GUEST/EXTERNAL user" -Color "Yellow"
                Write-ColorOutput -Message "[*] This is the Azure equivalent of a 'null session' - low-privileged enumeration" -Color "Cyan"
                Write-ColorOutput -Message "[*] Many organizations do NOT restrict guest permissions properly" -Color "Cyan"
                Write-ColorOutput -Message "[*] This is a LOW-NOISE reconnaissance technique`n" -Color "Green"
            }
        } else {
            Connect-MgGraph -Scopes $scopeArray -ErrorAction Stop
            $context = Get-MgContext
            Write-ColorOutput -Message "[+] Connected to tenant: $($context.TenantId)" -Color "Green"
            Write-ColorOutput -Message "[+] Account: $($context.Account)" -Color "Green"

            # Check if user is a guest
            $isGuest = Test-IsGuestUser -UserPrincipalName $context.Account
            if ($isGuest) {
                Write-ColorOutput -Message "`n[!] GUEST USER DETECTED" -Color "Yellow"
                Write-ColorOutput -Message "[*] You are authenticated as a GUEST/EXTERNAL user" -Color "Yellow"
                Write-ColorOutput -Message "[*] This is the Azure equivalent of a 'null session' - low-privileged enumeration" -Color "Cyan"
                Write-ColorOutput -Message "[*] Many organizations do NOT restrict guest permissions properly" -Color "Cyan"
                Write-ColorOutput -Message "[*] This is a LOW-NOISE reconnaissance technique`n" -Color "Green"
            }
        }
    } catch {
        Write-ColorOutput -Message "[!] Failed to connect to Microsoft Graph: $_" -Color "Red"
        exit 1
    }
}

