# LICITRA-SENTRY Test 09 - OWASP Coverage (10/10)
. $PSScriptRoot/_common.ps1
Set-TestName "t09_owasp_coverage"

$r1 = Run-Py "tests/_py_t09.py" "ASI01"
$p1 = $r1 -split "\|"
Assert-Equal $p1[0] "REJECTED" "ASI01: Relay injection REJECTED"
Assert-Equal $p1[2] "True" "ASI01: MMR leaf_hash present"

$r2 = Run-Py "tests/_py_t09.py" "ASI02"
$p2 = $r2 -split "\|"
Assert-Equal $p2[0] "REJECTED" "ASI02: Excessive agency REJECTED"
Assert-Equal $p2[2] "True" "ASI02: MMR leaf_hash present"

$r3 = Run-Py "tests/_py_t09.py" "ASI03"
$p3 = $r3 -split "\|"
Assert-Equal $p3[0] "REJECTED" "ASI03: Impersonation REJECTED"
Assert-Equal $p3[2] "True" "ASI03: MMR leaf_hash present"

$r4 = Run-Py "tests/_py_t09.py" "ASI04"
$p4 = $r4 -split "\|"
Assert-Equal $p4[0] "COMMITTED" "ASI04: Output committed to MMR"
Assert-Equal $p4[1] "True" "ASI04: MMR leaf_hash present"

$r5 = Run-Py "tests/_py_t09.py" "ASI05"
$p5 = $r5 -split "\|"
Assert-Equal $p5[0] "REJECTED" "ASI05: Unauthorized delegation REJECTED"
Assert-Equal $p5[1] "orchestration" "ASI05: Gate is orchestration"
Assert-Equal $p5[2] "True" "ASI05: MMR leaf_hash present"

$r6 = Run-Py "tests/_py_t09.py" "ASI06"
$p6 = $r6 -split "\|"
Assert-Equal $p6[0] "REJECTED" "ASI06: PII exposure REJECTED"
Assert-Equal $p6[2] "True" "ASI06: MMR leaf_hash present"

$r7 = Run-Py "tests/_py_t09.py" "ASI07"
$p7 = $r7 -split "\|"
Assert-Equal $p7[0] "APPROVED" "ASI07: Full pipeline passes clean msg"
Assert-Equal $p7[1] "True" "ASI07: MMR leaf_hash present"

$r8 = Run-Py "tests/_py_t09.py" "ASI08"
$p8 = $r8 -split "\|"
Assert-Equal $p8[0] "True" "ASI08: Audit leaf_hash present"
Assert-Equal $p8[1] "True" "ASI08: staged_id present"

$r9 = Run-Py "tests/_py_t09.py" "ASI09"
$p9 = $r9 -split "\|"
Assert-Equal $p9[0] "APPROVED" "ASI09: Allowed action APPROVED"
Assert-Equal $p9[1] "REJECTED" "ASI09: Blocked action REJECTED"
Assert-Equal $p9[2] "True" "ASI09: Allowed has leaf_hash"
Assert-Equal $p9[3] "True" "ASI09: Blocked has leaf_hash"

$r10 = Run-Py "tests/_py_t09.py" "ASI10"
$p10 = $r10 -split "\|"
Assert-Equal $p10[0] "True" "ASI10: Known agent registered"
Assert-Equal $p10[1] "False" "ASI10: Unknown agent not registered"

Write-TestSummary
