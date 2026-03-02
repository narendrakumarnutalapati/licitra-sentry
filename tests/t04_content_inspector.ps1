# LICITRA-SENTRY Test 04 - Content Inspector
. $PSScriptRoot/_common.ps1
Set-TestName "t04_content_inspector"

$r1 = Run-Py "tests/_py_t04.py" "1"
$p1 = $r1 -split "\|"
Assert-Equal $p1[0] "True" "Clean message returns clean=True"
Assert-Equal $p1[1] "0" "Clean message has 0 findings"
Assert-Equal $p1[2] "none" "Clean message severity is none"

$r2 = Run-Py "tests/_py_t04.py" "2"
$p2 = $r2 -split "\|"
Assert-Equal $p2[0] "False" "Relay injection blocked"
Assert-Contains $p2[1] "RI-001" "Relay injection rule RI-001 fired"

$r3 = Run-Py "tests/_py_t04.py" "3"
$p3 = $r3 -split "\|"
Assert-Equal $p3[0] "False" "PII SSN blocked"
Assert-Contains $p3[1] "PII-001" "PII rule PII-001 fired"

$r4 = Run-Py "tests/_py_t04.py" "4"
$p4 = $r4 -split "\|"
Assert-Equal $p4[0] "False" "Prompt injection blocked"
Assert-Contains $p4[1] "PI-001" "Prompt injection rule PI-001 fired"

$r5 = Run-Py "tests/_py_t04.py" "5"
$p5 = $r5 -split "\|"
Assert-Equal $p5[0] "False" "Privilege escalation blocked"
Assert-Contains $p5[1] "PE-003" "Privilege escalation rule PE-003 fired"

$r6 = Run-Py "tests/_py_t04.py" "6"
Assert-True ($r6 -ge 20) "At least 20 rules loaded (got $r6)"

Write-TestSummary
