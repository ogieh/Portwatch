# PortWatch launcher - starts the backend with Patchy's online mode wired up.
#
#   .\run.ps1                cloud mode, config from patchy.env (see the example file)
#   .\run.ps1 -Mode ollama   local Ollama preset, no key needed beyond "local"
#   .\run.ps1 -CheckOnly     print what would be used and exit
#
# precedence: real environment variables > patchy.env > mode defaults

param(
    [ValidateSet("cloud", "ollama")]
    [string]$Mode = "cloud",
    [switch]$CheckOnly
)

$ErrorActionPreference = "Stop"
$root = $PSScriptRoot

Write-Host ""
Write-Host "  ,___," -NoNewline
Write-Host "  PortWatch launcher" -ForegroundColor Cyan
Write-Host "  (O,O)" -NoNewline
Write-Host "  Patchy is stretching his wings..." -ForegroundColor DarkGray
Write-Host "  (   )" 
Write-Host "  -'-'-" 

# ---- python: prefer a repo-local venv if someone made one ----
$py = "python"
if (Test-Path "$root\backend\venv\Scripts\python.exe") { $py = "$root\backend\venv\Scripts\python.exe" }
if (Test-Path "$root\venv\Scripts\python.exe")         { $py = "$root\venv\Scripts\python.exe" }

& $py --version *> $null
if ($LASTEXITCODE -ne 0) {
    Write-Host "  [x] python not found on PATH" -ForegroundColor Red
    exit 1
}

# ---- deps: only pip-install if flask isn't importable yet ----
& $py -c "import flask, flask_cors, nmap" *> $null
if ($LASTEXITCODE -ne 0) {
    Write-Host "  [..] installing backend dependencies (first run)"
    & $py -m pip install -r "$root\backend\requirements.txt" --quiet
}

# ---- Patchy config ----
$envFile = Join-Path $root "patchy.env"
if (Test-Path $envFile) {
    Get-Content $envFile | ForEach-Object {
        $line = $_.Trim()
        if ($line -and -not $line.StartsWith("#") -and $line -match "^([A-Z0-9_]+)=(.*)$") {
            Set-Item -Path ("Env:" + $Matches[1]) -Value $Matches[2]
        }
    }
    Write-Host "  [i] loaded $($envFile)"
}
else {
    Write-Host "  [i] no patchy.env found (copy patchy.env.example to configure cloud models)"
}

if ($Mode -eq "ollama") {
    # preset only fills gaps; anything set above still wins
    if (-not $env:PORTWATCH_AI_API_KEY)  { $env:PORTWATCH_AI_API_KEY  = "local" }
    if (-not $env:PORTWATCH_AI_BASE_URL) { $env:PORTWATCH_AI_BASE_URL = "http://127.0.0.1:11434/v1" }
    if (-not $env:PORTWATCH_AI_MODEL)    { $env:PORTWATCH_AI_MODEL    = "llama3.1" }
}

# last-resort default so "online" mode has somewhere to point even with a bare key
if ($env:PORTWATCH_AI_API_KEY -and -not $env:PORTWATCH_AI_BASE_URL) {
    $env:PORTWATCH_AI_BASE_URL = "https://api.openai.com/v1"
}
if ($env:PORTWATCH_AI_API_KEY -and -not $env:PORTWATCH_AI_MODEL) {
    $env:PORTWATCH_AI_MODEL = "gpt-4o-mini"
}

$patchyMode = if ($env:PORTWATCH_AI_API_KEY) { "ONLINE" } else { "OFFLINE (local brain)" }
$keyPreview = if ($env:PORTWATCH_AI_API_KEY) { $env:PORTWATCH_AI_API_KEY.Substring(0, [Math]::Min(6, $env:PORTWATCH_AI_API_KEY.Length)) + "..." } else { "-" }
$modelOrDash = if ($env:PORTWATCH_AI_MODEL) { $env:PORTWATCH_AI_MODEL } else { "-" }

Write-Host ""
Write-Host "  Patchy : " -NoNewline
Write-Host $patchyMode -ForegroundColor $(if ($env:PORTWATCH_AI_API_KEY) { "Green" } else { "Yellow" })
Write-Host "  base   : $env:PORTWATCH_AI_BASE_URL"
Write-Host "  model  : $modelOrDash"
Write-Host "  key    : $keyPreview"

nmap --version *> $null
if ($LASTEXITCODE -ne 0) {
    Write-Host "  [!] nmap not on PATH - scans will fail until it's installed (nmap.org)" -ForegroundColor Yellow
}

if ($CheckOnly) {
    Write-Host ""
    Write-Host "  check-only: stopping before server start" -ForegroundColor DarkGray
    exit 0
}

Write-Host ""
Write-Host "  starting backend on http://127.0.0.1:5000 (Ctrl+C to stop)`n" -ForegroundColor Cyan
Set-Location "$root\backend"
& $py app.py