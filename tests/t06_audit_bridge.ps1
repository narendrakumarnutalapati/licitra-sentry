# LICITRA-SENTRY Test 06 - Audit Bridge
. $PSScriptRoot/_common.ps1
Set-TestName "t06_audit_bridge"

$r1 = Run-Py "tests/_py_t06.py" "1"
$p1 = $r1 -split "\|"
Assert-Equal $p1[0] "True" "Emit succeeds"
Assert-Equal $p1[1] "True" "staged_id present"
Assert-Equal $p1[2] "True" "event_id present"
Assert-Equal $p1[3] "True" "leaf_hash is 64 hex chars"

$r2 = Run-Py "tests/_py_t06.py" "2"
$p2 = $r2 -split "\|"
Assert-Equal $p2[0] "True" "Rejected event emit succeeds"
Assert-Equal $p2[1] "True" "Rejected event has leaf_hash"

$r3 = Run-Py "tests/_py_t06.py" "3"
$p3 = $r3 -split "\|"
Assert-Equal $p3[0] "True" "Inspection event emit succeeds"
Assert-Equal $p3[1] "True" "Inspection event has leaf_hash"

Write-TestSummary
