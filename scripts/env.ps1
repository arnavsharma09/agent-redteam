# Activate the venv and set PYTHONPATH for the agent-redteam workspace.
# Usage: . .\scripts\env.ps1  (dot-source to affect the current shell)

$root = Split-Path -Parent $PSScriptRoot
$venvActivate = Join-Path $root ".venv\Scripts\Activate.ps1"

if (Test-Path $venvActivate) {
    & $venvActivate
} else {
    Write-Warning "venv not found at $venvActivate. Create it first with: py -m venv .venv"
}

$env:PYTHONPATH = "$root;$root\third_party\kaggle_pkg"
Write-Host "PYTHONPATH set to: $env:PYTHONPATH"
