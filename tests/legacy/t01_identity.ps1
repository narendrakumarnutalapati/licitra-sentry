# LICITRA-SENTRY Test 01 - Identity Layer
. $PSScriptRoot/_common.ps1
Set-TestName "t01_identity"

$r = Run-Py "tests/_py_t01.py" "1"
$parts = $r -split "\|"
Assert-Equal $parts[0] "True" "Valid token returns True"
Assert-Equal $parts[1] "valid" "Valid token reason is valid"
Assert-Equal $parts[2] "agent-a" "Token agent_id matches"

$r2 = Run-Py "tests/_py_t01.py" "2"
Assert-Contains $r2 "ERROR" "Unknown agent raises ValueError"
Assert-Contains $r2 "not registered" "Error mentions not registered"

$r3 = Run-Py "tests/_py_t01.py" "3"
$parts3 = $r3 -split "\|"
Assert-Equal $parts3[0] "False" "Expired token returns False"
Assert-Contains $r3 "expired" "Expired token reason mentions expired"

$r4 = Run-Py "tests/_py_t01.py" "4"
$parts4 = $r4 -split "\|"
Assert-Equal $parts4[0] "True" "Registered agent returns True"
Assert-Equal $parts4[1] "False" "Unregistered agent returns False"

Write-TestSummary
