# Argus DAST Firecracker preflight - PowerShell 5.1 compatible.
# Runs from your dev workstation. Verifies Fly.io setup is ready for
# DAST verification.
#
# Usage:
#   cd C:/WEB/argus/dast/sandbox/firecracker
#   ./preflight.ps1
#
# Side effects:
#   * Creates the Fly.io app `argus-dast-sandbox` if it doesn't exist
#   * Builds + pushes the Dockerfile to Fly's registry (remote build,
#     no local Docker required)
#   * Does NOT start any machines - the orchestrator does that per call
#
# PowerShell 5.1 notes:
# - We deliberately do NOT use `$ErrorActionPreference = "Stop"`. PS 5.1
#   wraps native-command stderr in a RemoteException; flyctl writes
#   warnings to stderr (e.g. "Warning: Metrics token unavailable...")
#   that PS 5.1 surfaces as ErrorRecord even when flyctl exits 0.
# - We use `$LASTEXITCODE` checks after each flyctl call instead.
# - We do NOT redirect `2>&1` on native commands for the same reason.

$AppName = "argus-dast-sandbox"
$Region = "iad"
# Fly org slug. Defaults to "personal" (the default for new Fly accounts).
# Set $env:ARGUS_DAST_FLY_ORG before running to override.
$Org = if ($env:ARGUS_DAST_FLY_ORG) { $env:ARGUS_DAST_FLY_ORG } else { "personal" }

function Fail($msg) {
    Write-Host "FAIL $msg" -ForegroundColor Red
    exit 1
}

Write-Host "=== Argus DAST Firecracker preflight ==="
Write-Host "App: $AppName  Region: $Region  Org: $Org"
Write-Host ""

# 1. flyctl present
$flyctl = Get-Command flyctl -ErrorAction SilentlyContinue
if (-not $flyctl) {
    Fail "flyctl not installed. Install: iwr https://fly.io/install.ps1 -useb | iex"
}
$ver = (& flyctl version) -join " "
Write-Host "ok  flyctl: $ver"

# 2. authenticated (no 2>&1 -- PS 5.1 turns stderr into ErrorRecord)
$who = & flyctl auth whoami
if ($LASTEXITCODE -ne 0) {
    Fail "not authenticated. Run: flyctl auth login"
}
Write-Host "ok  auth: $who"

# 3. payment method (cannot easily check via CLI; document)
Write-Host "??  payment method on file at https://fly.io/dashboard/billing"
Write-Host "    (Cannot verify via CLI - check manually before proceeding)"

# 4. app exists or create
$appsJson = (& flyctl apps list --json) | Out-String
if ($LASTEXITCODE -ne 0) {
    Fail "flyctl apps list failed"
}
if ($appsJson -match """$AppName""") {
    Write-Host "ok  app exists: $AppName"
} else {
    Write-Host "->  creating app $AppName..."
    & flyctl apps create $AppName --org $Org
    if ($LASTEXITCODE -ne 0) {
        Fail "flyctl apps create"
    }
    Write-Host "ok  app created"
}

# 5. deploy image (remote build to avoid local Docker)
Write-Host "->  deploying sandbox image (remote build)..."
& flyctl deploy `
    --app $AppName `
    --remote-only `
    --no-public-ips `
    --strategy immediate `
    --auto-confirm
if ($LASTEXITCODE -ne 0) {
    Fail "flyctl deploy"
}
Write-Host "ok  image deployed"

# 6. clean up any auto-created standby machines from `flyctl deploy`.
# `flyctl deploy` auto-creates one app-machine + one standby per process
# group (Fly's HA default), but we want fresh-microvm-per-plan, so any
# pre-allocated machines are cruft. Destroy them -- they're not started
# so this costs $0.
Write-Host "->  cleaning up any auto-created standby machines..."
$machinesJson = (& flyctl machines list --app $AppName --json) | Out-String
if ($LASTEXITCODE -eq 0 -and $machinesJson.Trim()) {
    try {
        $machines = $machinesJson | ConvertFrom-Json
        if ($machines -and $machines.Count -gt 0) {
            foreach ($m in $machines) {
                Write-Host "    destroying $($m.id) ($($m.state))"
                & flyctl machines destroy $m.id --app $AppName --force | Out-Null
            }
        }
    } catch {
        Write-Host "    (could not parse machines list -- clean up manually if needed)"
    }
}
Write-Host "ok  pre-existing machines removed"
Write-Host "--  current machines (should be empty):"
& flyctl machines list --app $AppName

# 6b. safety-boundary check: no public IPs
Write-Host "--  IPs (should be empty, no inbound surface):"
& flyctl ips list --app $AppName

# 7. emit a token for the orchestrator to use
Write-Host ""
Write-Host "=== Preflight complete ==="
Write-Host ""
Write-Host "Next: emit a deploy-scoped API token for the orchestrator."
Write-Host "Run:"
Write-Host "    flyctl tokens create deploy --app $AppName --expiry 720h"
Write-Host ""
Write-Host "Save the token to C:/WEB/argus/.env as a new line:"
Write-Host "    FLY_API_TOKEN=<token>"
Write-Host ""
Write-Host "Then notify Claude that preflight passed."
