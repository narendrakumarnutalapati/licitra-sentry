# LICITRA-SENTRY Test 07 - Swarm Scenarios (6 scenarios)
. $PSScriptRoot/_common.ps1
Set-TestName "t07_swarm_scenarios"

$output = Run-Py "tests/_py_t07.py" "all"
$lines = $output -split "(?<=True|False)(?=S)"

foreach ($line in $lines) {
    $p = $line -split "\|"
    if ($p.Length -ge 4) {
        $sid = $p[0]
        $dec = $p[1]
        $gate = $p[2]
        $hasLeaf = $p[3]
        Assert-Equal $hasLeaf "True" "$sid has MMR leaf_hash"
        if ($sid -eq "S1") { Assert-Equal $dec "APPROVED" "S1 Researcher READ APPROVED" }
        if ($sid -eq "S2") { Assert-Equal $dec "REJECTED" "S2 Researcher FILE_WRITE REJECTED" }
        if ($sid -eq "S3") { Assert-Equal $dec "REJECTED" "S3 Expired token REJECTED" }
        if ($sid -eq "S4") { Assert-Equal $dec "REJECTED" "S4 Relay injection REJECTED" }
        if ($sid -eq "S5") { Assert-Equal $dec "REJECTED" "S5 PII exfiltration REJECTED" }
        if ($sid -eq "S6") {
            Assert-Equal $dec "REJECTED" "S6 Unauthorized delegation REJECTED"
            Assert-Equal $gate "orchestration" "S6 Gate is orchestration"
        }
    }
}

Write-TestSummary
