# LICITRA-SENTRY - Run All Tests
Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "  LICITRA-SENTRY Test Suite" -ForegroundColor Cyan
Write-Host "========================================`n" -ForegroundColor Cyan

$tests = @(
    "t01_identity",
    "t02_contract",
    "t03_authority",
    "t04_content_inspector",
    "t05_middleware",
    "t06_audit_bridge",
    "t07_swarm_scenarios",
    "t08_determinism",
    "t09_owasp_coverage"
)

$results = @{}
$allPassed = $true

foreach ($t in $tests) {
    Write-Host "Running $t..." -ForegroundColor Yellow
    powershell -ExecutionPolicy Bypass -File "$PSScriptRoot/$t.ps1" 2>&1 | Out-Null
    if ($LASTEXITCODE -eq 0) {
        $results[$t] = "PASS"
        Write-Host "  $t : PASS" -ForegroundColor Green
    } else {
        $results[$t] = "FAIL"
        $allPassed = $false
        Write-Host "  $t : FAIL" -ForegroundColor Red
    }
}

Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "  RESULTS" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
foreach ($t in $tests) {
    $status = $results[$t]
    $color = if ($status -eq "PASS") { "Green" } else { "Red" }
    Write-Host "  $t : $status" -ForegroundColor $color
}
Write-Host "========================================`n" -ForegroundColor Cyan

if ($allPassed) {
    Write-Host "  ALL 9/9 TESTS PASSED" -ForegroundColor Green
    exit 0
} else {
    $failCount = ($results.Values | Where-Object { $_ -eq "FAIL" }).Count
    Write-Host "  $failCount TEST(S) FAILED" -ForegroundColor Red
    exit 1
}
