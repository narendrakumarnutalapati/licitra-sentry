# LICITRA-SENTRY Test 05 - Middleware Pipeline
. $PSScriptRoot/_common.ps1
Set-TestName "t05_middleware"

$r1 = Run-Py "tests/_py_t05.py" "1"
$p1 = $r1 -split "\|"
Assert-Equal $p1[0] "APPROVED" "Happy path APPROVED"
Assert-Equal $p1[1] "approved" "Gate fired is approved"
Assert-Equal $p1[2] "True" "MMR leaf_hash present (64 hex)"

$r2 = Run-Py "tests/_py_t05.py" "2"
$p2 = $r2 -split "\|"
Assert-Equal $p2[0] "REJECTED" "Disallowed intent REJECTED"
Assert-Equal $p2[1] "contract" "Gate fired is contract"
Assert-Equal $p2[2] "True" "Rejected event also has MMR leaf_hash"

$r3 = Run-Py "tests/_py_t05.py" "3"
$p3 = $r3 -split "\|"
Assert-Equal $p3[0] "REJECTED" "Relay injection REJECTED"
Assert-Equal $p3[1] "inspector" "Gate fired is inspector"
Assert-Equal $p3[2] "True" "Inspection rejection has MMR leaf_hash"
Assert-True ([int]$p3[3] -gt 0) "Inspection findings count > 0"

Write-TestSummary
