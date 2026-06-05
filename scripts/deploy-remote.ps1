param(
    [Parameter(Mandatory = $true)]
    [string]$SshTarget,
    [string]$RemotePath = "/opt/callsign",
    [ValidateSet("systemd", "python")]
    [string]$Mode = "systemd",
    [string]$ControlService = "",
    [string]$TunnelService = ""
)

$ErrorActionPreference = "Stop"
Set-Location "$PSScriptRoot\.."

function Invoke-Ssh([string]$Command) {
    & ssh $SshTarget $Command
    if ($LASTEXITCODE -ne 0) {
        throw "SSH command failed: $Command"
    }
}

function Resolve-ServiceName([string]$Preferred, [string[]]$Candidates) {
    if ($Preferred) {
        return $Preferred
    }
    foreach ($name in $Candidates) {
        & ssh $SshTarget "systemctl list-unit-files | grep -q '^$name\.service'"
        if ($LASTEXITCODE -eq 0) {
            return $name
        }
    }
    return ""
}

Write-Host "[deploy] creating remote path: $RemotePath"
Invoke-Ssh "sudo mkdir -p $RemotePath"
Invoke-Ssh "sudo chown -R `$(id -un):`$(id -gn) $RemotePath"

Write-Host "[deploy] uploading project files"
$tarFile = Join-Path $env:TEMP "callsign-deploy.tar.gz"
if (Test-Path $tarFile) { Remove-Item $tarFile -Force }

# Exclude heavy local artifacts from deployment package.
$exclude = @(
    "--exclude=.venv",
    "--exclude=build",
    "--exclude=dist",
    "--exclude=__pycache__",
    "--exclude=.git"
)

& tar -czf $tarFile @exclude -C (Get-Location).Path .
if ($LASTEXITCODE -ne 0) {
    throw "failed to create deployment archive"
}

& scp $tarFile "$SshTarget`:$RemotePath/callsign-deploy.tar.gz"
if ($LASTEXITCODE -ne 0) {
    throw "failed to upload deployment archive"
}

Write-Host "[deploy] extracting files on remote"
Invoke-Ssh "cd $RemotePath && tar -xzf callsign-deploy.tar.gz && rm -f callsign-deploy.tar.gz"

Write-Host "[deploy] installing persistent NAT setup assets"
Invoke-Ssh "sudo install -m 755 $RemotePath/deploy/systemd/callsign-nat-setup.sh /usr/local/bin/callsign-nat-setup.sh"
Invoke-Ssh "sudo install -m 644 $RemotePath/deploy/systemd/callsign-nat.service /etc/systemd/system/callsign-nat.service"

Write-Host "[deploy] ensuring required env vars"
Invoke-Ssh "if [ ! -f /etc/proxy-server.env ]; then sudo install -m 600 /dev/null /etc/proxy-server.env; fi"
Invoke-Ssh "sudo install -d -m 700 /etc/callsign"
Invoke-Ssh "if [ ! -s /etc/callsign/access_token ]; then python3 - <<'PY' | sudo tee /etc/callsign/access_token >/dev/null
import secrets
print(secrets.token_urlsafe(32))
PY
fi"
Invoke-Ssh "sudo chmod 600 /etc/callsign/access_token"
Invoke-Ssh "if ! sudo grep -q '^CALLSIGN_ACCESS_TOKEN_FILE=' /etc/proxy-server.env; then echo CALLSIGN_ACCESS_TOKEN_FILE=/etc/callsign/access_token | sudo tee -a /etc/proxy-server.env >/dev/null; fi"
Invoke-Ssh "if ! sudo grep -q '^CALLSIGN_ACCESS_TOKEN=' /etc/proxy-server.env; then TOK=`$(sudo cat /etc/callsign/access_token); echo CALLSIGN_ACCESS_TOKEN=`$TOK | sudo tee -a /etc/proxy-server.env >/dev/null; fi"
Invoke-Ssh "if ! sudo grep -q '^CONTROL_VALIDATE_URL=' /etc/proxy-server.env; then echo CONTROL_VALIDATE_URL=http://127.0.0.1:5000/api/v1/validate | sudo tee -a /etc/proxy-server.env >/dev/null; fi"
Invoke-Ssh "if ! sudo grep -q '^CALLSIGN_TUNNEL_PATH=' /etc/proxy-server.env; then echo CALLSIGN_TUNNEL_PATH=/connect-ws | sudo tee -a /etc/proxy-server.env >/dev/null; fi"
Invoke-Ssh "if ! sudo grep -q '^CALLSIGN_TUN_MODE=' /etc/proxy-server.env; then echo CALLSIGN_TUN_MODE=tun | sudo tee -a /etc/proxy-server.env >/dev/null; fi"
Invoke-Ssh "if ! sudo grep -q '^CALLSIGN_TUN_INTERFACE=' /etc/proxy-server.env; then echo CALLSIGN_TUN_INTERFACE=tun0 | sudo tee -a /etc/proxy-server.env >/dev/null; fi"
Invoke-Ssh "if ! sudo grep -q '^CALLSIGN_TUN_LOCAL_CIDR=' /etc/proxy-server.env; then echo CALLSIGN_TUN_LOCAL_CIDR=10.99.0.1/24 | sudo tee -a /etc/proxy-server.env >/dev/null; fi"

$resolvedControl = Resolve-ServiceName -Preferred $ControlService -Candidates @("proxy-control", "callsign-control")
$resolvedTunnel = Resolve-ServiceName -Preferred $TunnelService -Candidates @("proxy-tunnel", "callsign-tunnel")

if ($Mode -eq "systemd") {
    if (-not $resolvedControl -or -not $resolvedTunnel) {
        throw "unable to resolve systemd service names; set -ControlService and -TunnelService explicitly"
    }
    Write-Host "[deploy] restarting systemd services"
    Invoke-Ssh "sudo systemctl daemon-reload || true"
    Invoke-Ssh "sudo systemctl enable callsign-nat.service"
    Invoke-Ssh "sudo systemctl restart callsign-nat.service"
    Invoke-Ssh "sudo systemctl restart $resolvedControl"
    Invoke-Ssh "sudo systemctl restart $resolvedTunnel"
    Invoke-Ssh "sudo systemctl status callsign-nat.service --no-pager -l | head -n 20"
    Invoke-Ssh "sudo systemctl status $resolvedControl --no-pager -l | head -n 20"
    Invoke-Ssh "sudo systemctl status $resolvedTunnel --no-pager -l | head -n 20"
}
else {
    Write-Host "[deploy] python mode selected - no service restart commands executed"
    Write-Host "[deploy] please restart your process manager manually"
}

Write-Host "[deploy] smoke checks"
Invoke-Ssh "curl -s -o /dev/null -w '%{http_code}\n' http://127.0.0.1:5000/healthz"
Invoke-Ssh "TOK=`$(sudo awk -F= '/^CALLSIGN_ACCESS_TOKEN=/{print `$2}' /etc/proxy-server.env); curl -s -o /dev/null -w '%{http_code}\n' -X POST http://127.0.0.1:5000/api/v1/bootstrap -H 'Content-Type: application/json' -H \"X-Access-Token: `$TOK\" -d '{\"device_id\":\"deploy-smoke\"}'"

Write-Host "[deploy] access token stored at: /etc/callsign/access_token"
Write-Host "[deploy] show token command: sudo cat /etc/callsign/access_token"
Invoke-Ssh "echo TOKEN=`$(sudo cat /etc/callsign/access_token)"

Write-Host "[deploy] completed"
