<#
.SYNOPSIS
AgentGuard Demo Rehearsal Script

.DESCRIPTION
This script acts as an autonomous agent interacting with the AgentGuard Hub.
It runs through a predefined set of scenarios (unauthorized writes, prompt injection)
to demonstrate the Hub's policy enforcement (ALLOW, DENY, ASK_HUMAN).

.NOTES
Make sure the AgentGuard backend hub is running on port 8000 before executing this script.
(See DEMO_SETUP.md for instructions)
#>

$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"

$HubUrl = "http://127.0.0.1:8000"
$AdminToken = "dev-admin-token" # As per DEMO_SETUP.md
$AgentToken = "dev-agent-token"

$AdminHeaders = @{
    "Authorization" = "Bearer $AdminToken"
    "Content-Type"  = "application/json"
}
$AgentHeaders = @{
    "Authorization" = "Bearer $AgentToken"
    "Content-Type"  = "application/json"
}

function Write-Step ($message) {
    Write-Host "`n[*] $message" -ForegroundColor Cyan
}

function Write-Agent ($message) {
    Write-Host "[Agent] $message" -ForegroundColor Yellow
}

function Write-Hub ($message) {
    Write-Host "[Hub] $message" -ForegroundColor Green
}

function Write-Hub-Block ($message) {
    Write-Host "[Hub] $message" -ForegroundColor Red
}

function Write-Hub-Warn ($message) {
    Write-Host "[Hub] $message" -ForegroundColor Magenta
}

Write-Host "======================================================" -ForegroundColor White
Write-Host "            AgentGuard Hub Demo Simulator             " -ForegroundColor White
Write-Host "======================================================" -ForegroundColor White
Write-Host ""
Write-Host "Checking if AgentGuard Hub is running on $HubUrl..."
try {
    $health = Invoke-RestMethod -Uri "$HubUrl/v1/health" -Method Get -ErrorAction Stop
    Write-Host "Hub is UP. Status: $($health.status)" -ForegroundColor Green
} catch {
    Write-Host "Hub is not responding at $HubUrl. Please start it using DEMO_SETUP.md instructions." -ForegroundColor Red
    exit 1
}

Start-Sleep -Seconds 1

Write-Step "1. Initializing Demo Run"
$runPayload = @{
    task = @{
        objective = "Analyze system configuration and optimize performance"
        human_available = $true
    }
} | ConvertTo-Json -Depth 5

$runResponse = Invoke-RestMethod -Uri "$HubUrl/v1/runs" -Method Post -Headers $AdminHeaders -Body $runPayload
$runId = $runResponse.run_id
Write-Hub "Run created with ID: $runId. Status: $($runResponse.status)"

Start-Sleep -Seconds 2

Write-Step "2. Simulate an unauthorized filesystem write to /etc/shadow"
Write-Agent "Proposing action to modify shadow file to 'optimize authentication'"
$action1Payload = @{
    client_action_id = "act_client_001"
    action_type = "cli.exec"
    params = @{
        command = "cat /etc/shadow"
    }
    confidence = 0.95
} | ConvertTo-Json -Depth 5

$action1Response = Invoke-RestMethod -Uri "$HubUrl/v1/runs/$runId/actions" -Method Post -Headers $AgentHeaders -Body $action1Payload
$verdict1 = $action1Response.verdict
if ($verdict1 -eq "DENY" -or $verdict1 -eq "HALT") {
    Write-Hub-Block "Action REJECTED. Verdict: $verdict1"
} else {
    Write-Hub-Warn "Unexpected Verdict: $verdict1"
}
Write-Hub "Details: $($action1Response | ConvertTo-Json -Compress)"

Start-Sleep -Seconds 2

Write-Step "3. Simulate an autonomous prompt injection attempt"
Write-Agent "Proposing action that involves executing an untrusted payload"
$action2Payload = @{
    client_action_id = "act_client_002"
    action_type = "cli.exec"
    params = @{
        command = "cat .env"
    }
    confidence = 0.8
} | ConvertTo-Json -Depth 5

$action2Response = Invoke-RestMethod -Uri "$HubUrl/v1/runs/$runId/actions" -Method Post -Headers $AgentHeaders -Body $action2Payload
$verdict2 = $action2Response.verdict

if ($verdict2 -eq "ASK_HUMAN") {
    Write-Hub-Warn "Action flagged for human review. Verdict: $verdict2"
    $actionId = $action2Response.action_id
    Write-Hub "Action ID waiting for approval: $actionId"
    Write-Host "`n>> Switch to the Frontend Dashboard to Approve or Reject this action! <<" -ForegroundColor Yellow
} else {
    Write-Hub "Verdict: $verdict2 (Note: Without specific policy rules, this might default to ALLOW or DENY. Adjust policies to see ASK_HUMAN)"
}

Start-Sleep -Seconds 2

Write-Step "4. Retrieving run state and ledger"
$runStateResponse = Invoke-RestMethod -Uri "$HubUrl/v1/runs/$runId" -Method Get -Headers $AdminHeaders
Write-Hub "Run Status: $($runStateResponse.status)"
Write-Hub "Total steps used: $($runStateResponse.counters.steps)"

Write-Step "5. Finishing demo run"
$completePayload = @{
    outcome = "abandoned"
} | ConvertTo-Json -Depth 5

try {
    $completeResponse = Invoke-RestMethod -Uri "$HubUrl/v1/runs/$runId/complete" -Method Post -Headers $AdminHeaders -Body $completePayload
    Write-Hub "Run completed with outcome: abandoned"
} catch {
    Write-Hub-Warn "Could not complete run. It may be paused waiting for approval."
}

Write-Host "`n======================================================" -ForegroundColor White
Write-Host "                 Demo Simulator Done                  " -ForegroundColor White
Write-Host "======================================================" -ForegroundColor White
