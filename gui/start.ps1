# ============================================================
# Cloud Security Reporter — Windows startup script
# Right-click → Run with PowerShell
# Or: powershell -ExecutionPolicy Bypass -File start.ps1
# ============================================================

$ErrorActionPreference = "Stop"
$PORT = 8000
$PYTHON_MIN_MAJOR = 3
$PYTHON_MIN_MINOR = 11

$SCRIPT_DIR  = Split-Path -Parent $MyInvocation.MyCommand.Path
$REPO_ROOT   = Split-Path -Parent $SCRIPT_DIR
$GUI_DIR     = $SCRIPT_DIR

# ── Colours ──────────────────────────────────────────────────
function Write-Info    { param($msg) Write-Host "[INFO]  $msg" -ForegroundColor Cyan }
function Write-Success { param($msg) Write-Host "[OK]    $msg" -ForegroundColor Green }
function Write-Warn    { param($msg) Write-Host "[WARN]  $msg" -ForegroundColor Yellow }
function Write-Err     { param($msg) Write-Host "[ERROR] $msg" -ForegroundColor Red }
function Write-Header  { param($msg) Write-Host "`n$msg" -ForegroundColor White; Write-Host ("─" * 44) }

Write-Header "Cloud Security Reporter — Startup"
Write-Info "Script dir : $SCRIPT_DIR"
Write-Info "Repo root  : $REPO_ROOT"

# ── 1. OS / Execution Policy ──────────────────────────────────
Write-Header "Step 1: Environment Check"
Write-Success "OS: Windows"

$policy = Get-ExecutionPolicy -Scope CurrentUser
Write-Info "PowerShell execution policy (CurrentUser): $policy"
$blockingPolicies = @("Restricted", "AllSigned")
if ($blockingPolicies -contains $policy) {
    Write-Warn "Execution policy '$policy' may block module installation."
    Write-Warn "To fix, run in PowerShell:"
    Write-Warn "  Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser"
    $fix = Read-Host "Fix execution policy now? (y/N)"
    if ($fix -eq "y" -or $fix -eq "Y") {
        Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser -Force
        Write-Success "Execution policy set to RemoteSigned"
    }
}

# ── 2. Check Python ───────────────────────────────────────────
Write-Header "Step 2: Python"
$pythonCmd = $null
foreach ($cmd in @("python", "python3", "py")) {
    try {
        $ver = & $cmd -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')" 2>$null
        if ($ver) {
            $parts = $ver.Split(".")
            $major = [int]$parts[0]; $minor = [int]$parts[1]
            if ($major -ge $PYTHON_MIN_MAJOR -and $minor -ge $PYTHON_MIN_MINOR) {
                $pythonCmd = $cmd
                Write-Success "Found: $cmd ($ver)"
                break
            } else {
                Write-Warn "$cmd version $ver is below minimum 3.11"
            }
        }
    } catch {}
}

if (-not $pythonCmd) {
    Write-Err "Python 3.11+ not found."
    Write-Err "Download from https://python.org/downloads/"
    Write-Err "Make sure to check 'Add Python to PATH' during install."
    Read-Host "Press Enter to exit"
    exit 1
}

# ── 3. Install / verify uv ────────────────────────────────────
Write-Header "Step 3: uv Package Manager"
$uvInstalled = $null -ne (Get-Command uv -ErrorAction SilentlyContinue)
if (-not $uvInstalled) {
    Write-Warn "uv not found — installing..."
    try {
        Invoke-RestMethod https://astral.sh/uv/install.ps1 | Invoke-Expression
        # Refresh PATH for this session
        $env:PATH = [System.Environment]::GetEnvironmentVariable("PATH", "User") + ";" + $env:PATH
        $uvInstalled = $null -ne (Get-Command uv -ErrorAction SilentlyContinue)
        if ($uvInstalled) {
            Write-Success "uv installed"
        } else {
            Write-Warn "uv installed but not on PATH yet — restart terminal if issues occur"
        }
    } catch {
        Write-Warn "uv install failed: $_"
        Write-Warn "Install manually from https://docs.astral.sh/uv/"
    }
} else {
    $uvVer = (uv --version 2>$null) | Select-Object -First 1
    Write-Success "uv: $uvVer"
}

# ── 4. Install Prowler ────────────────────────────────────────
Write-Header "Step 4: Prowler"
$prowlerInstalled = $null -ne (Get-Command prowler -ErrorAction SilentlyContinue)
if ($prowlerInstalled) {
    Write-Success "Already installed"
} else {
    Write-Info "Installing Prowler via uv tool install..."
    try {
        uv tool install prowler
        Write-Success "Prowler installed"
        Write-Warn "Note: Prowler on Windows may have dependency issues."
        Write-Warn "If prowler fails at runtime, see https://docs.prowler.com for WSL instructions."
    } catch {
        Write-Warn "Prowler install failed: $_"
        Write-Warn "You can install it later from Tools & Setup in the GUI."
    }
}

# ── 5. Install ScubaGear ──────────────────────────────────────
Write-Header "Step 5: ScubaGear"
$scubaInstalled = $null -ne (Get-Module -ListAvailable ScubaGear -ErrorAction SilentlyContinue)
if ($scubaInstalled) {
    $scubaVer = (Get-Module -ListAvailable ScubaGear | Select-Object -First 1).Version
    Write-Success "Already installed: v$scubaVer"
} else {
    Write-Info "Installing ScubaGear PowerShell module..."
    try {
        Install-Module -Name PowerShellGet -Force -AllowClobber -Scope CurrentUser -ErrorAction SilentlyContinue
        Install-Module -Name ScubaGear -Force -AllowClobber -Scope CurrentUser
        Write-Success "ScubaGear installed"
    } catch {
        Write-Warn "ScubaGear install failed: $_"
        Write-Warn "You can install it later from Tools & Setup in the GUI."
    }
}

# ── 6. Install pipeline Python dependencies ───────────────────
Write-Header "Step 6: Pipeline Dependencies"
$venvPath = Join-Path $REPO_ROOT ".venv"
if (-not (Test-Path $venvPath)) {
    Write-Info "Creating root venv at $venvPath..."
    uv venv $venvPath --python $pythonCmd
}

$venvPython = Join-Path $venvPath "Scripts\python.exe"
Write-Info "Installing pipeline dependencies into root venv..."
try {
    uv pip install --python $venvPython openpyxl pydantic boto3 tomli --quiet
    Write-Success "Pipeline dependencies ready"
} catch {
    Write-Warn "Some dependencies failed to install: $_"
}

# ── 7. Install GUI dependencies ───────────────────────────────
Write-Header "Step 7: GUI Dependencies"
Set-Location $GUI_DIR
Write-Info "Syncing GUI dependencies via uv..."
try {
    uv sync --quiet
    Write-Success "GUI dependencies ready"
} catch {
    Write-Err "GUI dependency sync failed: $_"
    Read-Host "Press Enter to exit"
    exit 1
}

# ── 8. Launch ─────────────────────────────────────────────────
Write-Header "Step 8: Launch"
$URL = "http://localhost:$PORT"
Write-Info "Starting GUI on $URL"
Write-Info "Press Ctrl+C to stop"
Write-Host ""

# Open browser after delay
Start-Job -ScriptBlock {
    param($url)
    Start-Sleep -Seconds 2
    Start-Process $url
} -ArgumentList $URL | Out-Null

# Launch the app
Set-Location $GUI_DIR
uv run python main.py