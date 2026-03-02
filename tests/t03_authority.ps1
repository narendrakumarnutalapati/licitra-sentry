# LICITRA-SENTRY Test 03 - Authority Gate
. $PSScriptRoot/_common.ps1
Set-TestName "t03_authority"

$r1 = Run-Py "tests/_py_t03.py" "1"
Assert-Equal $r1 "APPROVED" "Valid token + allowed intent + tool = APPROVED"

$r2 = Run-Py "tests/_py_t03.py" "2"
Assert-Contains $r2 "REJECTED" "Expired token REJECTED"
Assert-Contains $r2 "expired" "Reason mentions expired"

$r3 = Run-Py "tests/_py_t03.py" "3"
Assert-Contains $r3 "REJECTED" "Disallowed intent REJECTED"

$r4 = Run-Py "tests/_py_t03.py" "4"
Assert-Contains $r4 "REJECTED" "Disallowed tool REJECTED"

Write-TestSummary
