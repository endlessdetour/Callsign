param(
    [string]$ValidateUrl = "http://127.0.0.1:5000/api/v1/validate"
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

Set-Location "$PSScriptRoot\.."
Import-DotEnv ".env"

$py = ".\.venv\Scripts\python.exe"
if (-not (Test-Path $py)) {
    throw "Python venv not found at .venv. Run: python -m venv .venv"
}

if ([string]::IsNullOrWhiteSpace($env:CALLSIGN_ACCESS_TOKEN)) {
    throw "CALLSIGN_ACCESS_TOKEN is required. Set it in .env."
}

$env:CONTROL_VALIDATE_URL = $ValidateUrl
& $py server\tunnel\app.py
