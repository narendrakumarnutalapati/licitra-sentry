# LICITRA-SENTRY Test Commons
$script:PASS_COUNT = 0
$script:FAIL_COUNT = 0
$script:TEST_NAME = ""
$script:PROJECT_ROOT = Split-Path -Parent $PSScriptRoot
$env:PYTHONPATH = $script:PROJECT_ROOT

function Set-TestName($name) {
    $script:TEST_NAME = $name
    Write-Host "`n  TEST: $name" -ForegroundColor Cyan
}

function Assert-True($condition, $msg) {
    if ($condition) {
        $script:PASS_COUNT++
        Write-Host "    PASS: $msg" -ForegroundColor Green
    } else {
        $script:FAIL_COUNT++
        Write-Host "    FAIL: $msg" -ForegroundColor Red
    }
}

function Assert-Equal($actual, $expected, $msg) {
    if ($actual -eq $expected) {
        $script:PASS_COUNT++
        Write-Host "    PASS: $msg" -ForegroundColor Green
    } else {
        $script:FAIL_COUNT++
        Write-Host "    FAIL: $msg (expected='$expected', got='$actual')" -ForegroundColor Red
    }
}

function Assert-Contains($haystack, $needle, $msg) {
    if ($haystack -like "*$needle*") {
        $script:PASS_COUNT++
        Write-Host "    PASS: $msg" -ForegroundColor Green
    } else {
        $script:FAIL_COUNT++
        Write-Host "    FAIL: $msg (not found: '$needle')" -ForegroundColor Red
    }
}

function Run-Py($file, $arg) {
    $fullpath = Join-Path $script:PROJECT_ROOT $file
    $result = python $fullpath $arg 2>&1
    return ($result -join "")
}

function Write-TestSummary {
    $total = $script:PASS_COUNT + $script:FAIL_COUNT
    Write-Host "`n  SUMMARY: $script:PASS_COUNT/$total passed" -ForegroundColor White
    if ($script:FAIL_COUNT -gt 0) {
        Write-Host "  RESULT: FAIL" -ForegroundColor Red
        exit 1
    } else {
        Write-Host "  RESULT: PASS" -ForegroundColor Green
        exit 0
    }
}
