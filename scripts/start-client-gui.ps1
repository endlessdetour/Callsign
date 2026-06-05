Set-Location "$PSScriptRoot\.."

$py = ".\.venv\Scripts\python.exe"
if (-not (Test-Path $py)) {
	throw "Python venv not found at .venv. Run: python -m venv .venv"
}

& $py client\windows\gui_client.py
