# LICITRA-SENTRY Test 02 - Contract Engine
. $PSScriptRoot/_common.ps1
Set-TestName "t02_contract"

$r1 = Run-Py "tests/_py_t02.py" "1"
Assert-Equal $r1 "APPROVED" "Allowed intent APPROVED"

$r2 = Run-Py "tests/_py_t02.py" "2"
Assert-Contains $r2 "REJECTED" "Unknown intent REJECTED"

$r3 = Run-Py "tests/_py_t02.py" "3"
Assert-Equal $r3 "APPROVED" "Allowed tool APPROVED"

$r4 = Run-Py "tests/_py_t02.py" "4"
Assert-Contains $r4 "REJECTED" "Disallowed tool REJECTED"

$r5 = Run-Py "tests/_py_t02.py" "5"
Assert-Equal $r5 "APPROVED" "Valid parameter shape APPROVED"

$r6 = Run-Py "tests/_py_t02.py" "6"
Assert-Contains $r6 "REJECTED" "Invalid parameter pattern REJECTED"

$r7 = Run-Py "tests/_py_t02.py" "7"
Assert-Contains $r7 "REJECTED" "No contract for unknown agent"

Write-TestSummary
