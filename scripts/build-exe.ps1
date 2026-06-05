$ErrorActionPreference = "Stop"

Set-Location "$PSScriptRoot\.."

$py = ".\.venv\Scripts\python.exe"

if (-not (Test-Path $py)) {
    throw "Python venv not found at .venv. Create it first."
}

function Invoke-Step([string]$Command, [string[]]$CmdArgs) {
    & $Command @CmdArgs
    if ($LASTEXITCODE -ne 0) {
        throw "Command failed ($LASTEXITCODE): $Command $($CmdArgs -join ' ')"
    }
}

Invoke-Step $py @("-m", "PyInstaller", "--noconfirm", "--clean", "agent.spec")
Invoke-Step $py @("-m", "PyInstaller", "--noconfirm", "--clean", "gui_client.spec")

$target = "dist\callsign"
if (-not (Test-Path $target)) {
    throw "Build output not found: $target"
}

$agentBundle = "dist\agent"
if (-not (Test-Path "$agentBundle\agent.exe")) {
    throw "Agent build output not found: $agentBundle"
}

$targetAgent = "$target\agent"
if (Test-Path $targetAgent) {
    Remove-Item -Recurse -Force $targetAgent
}

Copy-Item -Recurse -Force $agentBundle $targetAgent

# Never ship local runtime profiles in distributable artifacts.
$profileStore = "$target\client_profiles.json"
if (Test-Path $profileStore) {
    Remove-Item -Force $profileStore
}

$arch = $env:PROCESSOR_ARCHITECTURE
if ([string]::IsNullOrWhiteSpace($arch)) {
    $arch = "unknown"
}
$zipTarget = "dist\callsign-windows-$($arch.ToLower()).zip"
if (Test-Path $zipTarget) {
    Remove-Item -Force $zipTarget
}
Compress-Archive -Path "$target\*" -DestinationPath $zipTarget -Force

Write-Host "Build complete. Run: dist\callsign\callsign.exe"
Write-Host "Distribution archive: $zipTarget"
