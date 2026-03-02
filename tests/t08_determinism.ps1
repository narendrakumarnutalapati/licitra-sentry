# LICITRA-SENTRY Test 08 - Determinism
. $PSScriptRoot/_common.ps1
Set-TestName "t08_determinism"

$r1 = Run-Py "tests/_py_t08.py" "1"
$p1 = $r1 -split "\|"
Assert-Equal $p1[0] "True" "Inspector: same clean result"
Assert-Equal $p1[1] "True" "Inspector: same findings count"
Assert-Equal $p1[2] "True" "Inspector: same rule IDs"

$r2 = Run-Py "tests/_py_t08.py" "2"
$p2 = $r2 -split "\|"
Assert-Equal $p2[0] "True" "Contract: same APPROVED result"
Assert-Equal $p2[1] "True" "Contract: same REJECTED result"

$r3 = Run-Py "tests/_py_t08.py" "3"
$p3 = $r3 -split "\|"
Assert-Equal $p3[0] "True" "Identity: token 1 valid"
Assert-Equal $p3[1] "True" "Identity: token 2 valid"

Write-TestSummary
