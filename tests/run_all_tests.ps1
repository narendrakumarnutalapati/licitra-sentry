# LICITRA-SENTRY v0.2 - Run Current Test Suites
Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "  LICITRA-SENTRY v0.2 Test Suite" -ForegroundColor Cyan
Write-Host "========================================`n" -ForegroundColor Cyan

$ErrorActionPreference = "Stop"
$projectRoot = Split-Path -Parent $PSScriptRoot
$env:PYTHONPATH = $projectRoot

$tests = @(
    @{
        Name = "test_sentry_v02"
        Cmd  = "python `"$PSScriptRoot\test_sentry_v02.py`""
    },
    @{
        Name = "test_witness"
        Cmd  = "python `"$PSScriptRoot\test_witness.py`""
    }
)

$results = @{}
$allPassed = $true

foreach ($t in $tests) {
    Write-Host "Running $($t.Name)..." -ForegroundColor Yellow
    try {
        Invoke-Expression $t.Cmd
        if ($LASTEXITCODE -eq 0) {
            $results[$t.Name] = "PASS"
            Write-Host "  $($t.Name) : PASS" -ForegroundColor Green
        } else {
            $results[$t.Name] = "FAIL"
            $allPassed = $false
            Write-Host "  $($t.Name) : FAIL" -ForegroundColor Red
        }
    } catch {
        $results[$t.Name] = "FAIL"
        $allPassed = $false
        Write-Host "  $($t.Name) : FAIL" -ForegroundColor Red
        Write-Host "    $($_.Exception.Message)" -ForegroundColor DarkRed
    }
}

Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "  RESULTS" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
foreach ($t in $tests) {
    $status = $results[$t.Name]
    $color = if ($status -eq "PASS") { "Green" } else { "Red" }
    Write-Host "  $($t.Name) : $status" -ForegroundColor $color
}
Write-Host "========================================`n" -ForegroundColor Cyan

if ($allPassed) {
    Write-Host "  ALL 2/2 CURRENT TEST SUITES PASSED" -ForegroundColor Green
    exit 0
} else {
    $failCount = ($results.Values | Where-Object { $_ -eq "FAIL" }).Count
    Write-Host "  $failCount TEST SUITE(S) FAILED" -ForegroundColor Red
    exit 1
}
