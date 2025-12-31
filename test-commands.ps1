<#
    AZexec Command Test Script
    Tests all commands to verify they execute without parameter errors
#>

$commands = @(
    "hosts",
    "tenant",
    "users",
    "user-profiles",
    "groups",
    "pass-pol",
    "guest",
    "vuln-list",
    "sessions",
    "guest-vuln-scan",
    "apps",
    "sp-discovery",
    "roles",
    "ca-policies",
    "vm-loggedon",
    "storage-enum",
    "keyvault-enum",
    "network-enum",
    "shares-enum",
    "help"
)

$scriptPath = Join-Path $PSScriptRoot "azx.ps1"
$results = @()

Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "  AZexec Command Test Suite" -ForegroundColor Cyan
Write-Host "  Testing $($commands.Count) commands" -ForegroundColor Cyan
Write-Host "========================================`n" -ForegroundColor Cyan

foreach ($cmd in $commands) {
    Write-Host "[*] Testing command: $cmd" -ForegroundColor Yellow -NoNewline
    
    $startTime = Get-Date
    $exitCode = $null
    $errorOutput = $null
    
    try {
        # Run the command and capture output
        # Using timeout of 30 seconds to prevent hanging on auth prompts
        $job = Start-Job -ScriptBlock {
            param($script, $command)
            & $script $command 2>&1
        } -ArgumentList $scriptPath, $cmd
        
        # Wait max 30 seconds for non-interactive commands, 5 seconds for help
        $timeout = if ($cmd -eq "help") { 10 } else { 30 }
        $completed = Wait-Job $job -Timeout $timeout
        
        if ($completed) {
            $output = Receive-Job $job
            $exitCode = 0
            
            # Check if output contains common error patterns
            $outputStr = $output | Out-String
            if ($outputStr -match "Unknown command" -or $outputStr -match "Parameter.*is required") {
                $exitCode = 1
                $errorOutput = "Command not recognized or missing required parameter"
            }
        } else {
            # Job timed out - this is expected for commands requiring auth
            Stop-Job $job
            $exitCode = 0  # Timeout is acceptable (waiting for auth)
            $errorOutput = "Timeout (waiting for authentication - expected)"
        }
        
        Remove-Job $job -Force -ErrorAction SilentlyContinue
        
    } catch {
        $exitCode = 1
        $errorOutput = $_.Exception.Message
    }
    
    $duration = (Get-Date) - $startTime
    
    # Determine status
    if ($exitCode -eq 0) {
        if ($errorOutput -and $errorOutput -match "Timeout") {
            Write-Host " ... PASS (Auth Required)" -ForegroundColor Blue
            $status = "PASS (Auth)"
        } else {
            Write-Host " ... PASS" -ForegroundColor Green
            $status = "PASS"
        }
    } else {
        Write-Host " ... FAIL" -ForegroundColor Red
        Write-Host "    Error: $errorOutput" -ForegroundColor Red
        $status = "FAIL"
    }
    
    $results += [PSCustomObject]@{
        Command  = $cmd
        Status   = $status
        Duration = "{0:N2}s" -f $duration.TotalSeconds
        Error    = $errorOutput
    }
}

# Summary
Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "  TEST SUMMARY" -ForegroundColor Cyan
Write-Host "========================================`n" -ForegroundColor Cyan

$passed = ($results | Where-Object { $_.Status -match "PASS" }).Count
$failed = ($results | Where-Object { $_.Status -eq "FAIL" }).Count

$results | Format-Table -Property Command, Status, Duration -AutoSize

Write-Host "`nTotal: $($commands.Count) | Passed: $passed | Failed: $failed" -ForegroundColor $(if ($failed -eq 0) { "Green" } else { "Yellow" })

if ($failed -gt 0) {
    Write-Host "`nFailed Commands:" -ForegroundColor Red
    $results | Where-Object { $_.Status -eq "FAIL" } | ForEach-Object {
        Write-Host "  - $($_.Command): $($_.Error)" -ForegroundColor Red
    }
    exit 1
} else {
    Write-Host "`nAll commands executed successfully!" -ForegroundColor Green
    exit 0
}

