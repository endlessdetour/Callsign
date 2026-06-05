param(
    [string]$ControlUrl = "https://overlay.example.com",
    [string]$TunnelUrl = "",
    [string]$DeviceId = "",
    [switch]$AllowInsecure,
    [switch]$UseWintun,
    [switch]$ApplyRoutes,
    [switch]$Elevated,
    [string]$LogFile = ""
)

function Import-DotEnv([string]$Path) {
    if (-not (Test-Path $Path)) {
        return
    }

    foreach ($line in Get-Content -Path $Path) {
        $text = $line.Trim()
        if ([string]::IsNullOrWhiteSpace($text) -or $text.StartsWith("#")) {
            continue
        }

        $idx = $text.IndexOf("=")
        if ($idx -le 0) {
            continue
        }

        $name = $text.Substring(0, $idx).Trim()
        $value = $text.Substring($idx + 1).Trim().Trim("\"").Trim("'")
        if (-not [string]::IsNullOrWhiteSpace($name)) {
            Set-Item -Path "Env:$name" -Value $value
        }
    }
}

function Test-IsAdministrator {
    $currentIdentity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($currentIdentity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

Set-Location "$PSScriptRoot\.."
Import-DotEnv ".env"

if ([string]::IsNullOrWhiteSpace($env:CALLSIGN_ACCESS_TOKEN)) {
    throw "CALLSIGN_ACCESS_TOKEN is required. Set it in .env."
}

$needsAdmin = $UseWintun.IsPresent -or $ApplyRoutes.IsPresent
if ($needsAdmin -and -not (Test-IsAdministrator)) {
    if ($Elevated) {
        throw "Elevation requested but process is still not running as Administrator."
    }

    $relaunchArgs = @(
        "-NoProfile",
        "-ExecutionPolicy", "RemoteSigned",
        "-File", $PSCommandPath,
        "-ControlUrl", $ControlUrl,
        "-Elevated"
    )
    if (-not [string]::IsNullOrWhiteSpace($TunnelUrl)) {
        $relaunchArgs += @("-TunnelUrl", $TunnelUrl)
    }
    if (-not [string]::IsNullOrWhiteSpace($DeviceId)) {
        $relaunchArgs += @("-DeviceId", $DeviceId)
    }
    if ($AllowInsecure) {
        $relaunchArgs += "-AllowInsecure"
    }
    if ($UseWintun) {
        $relaunchArgs += "-UseWintun"
    }
    if ($ApplyRoutes) {
        $relaunchArgs += "-ApplyRoutes"
    }
    if (-not [string]::IsNullOrWhiteSpace($LogFile)) {
        $relaunchArgs += @("-LogFile", $LogFile)
    }

    Start-Process -FilePath "powershell.exe" -Verb RunAs -ArgumentList $relaunchArgs
    return
}

$py = ".\.venv\Scripts\python.exe"
if (-not (Test-Path $py)) {
    throw "Python venv not found at .venv. Run: python -m venv .venv"
}

$args = @("client\windows\agent.py", "--control-url", $ControlUrl)
if (-not [string]::IsNullOrWhiteSpace($TunnelUrl)) {
    $args += @("--tunnel-url", $TunnelUrl)
}
if ($AllowInsecure) {
    $args += "--allow-insecure"
}
if ($UseWintun) {
    $args += "--use-wintun"
}
if ($ApplyRoutes) {
    $args += "--apply-routes"
}
if (-not [string]::IsNullOrWhiteSpace($LogFile)) {
    $args += @("--log-file", $LogFile)
}

if ([string]::IsNullOrWhiteSpace($DeviceId)) {
    & $py @args
} else {
    & $py @args --device-id $DeviceId
}
