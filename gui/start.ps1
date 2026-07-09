# ============================================================
# Cloud Security Reporter -- Windows startup script
# Right-click -> Run with PowerShell
# Or: powershell -ExecutionPolicy Bypass -File start.ps1
# ============================================================

$ErrorActionPreference = "Stop"
$PORT = 8000
$PYTHON_MIN_MAJOR = 3
$PYTHON_MIN_MINOR = 11

$SCRIPT_DIR = Split-Path -Parent $MyInvocation.MyCommand.Path
$REPO_ROOT  = Split-Path -Parent $SCRIPT_DIR
$GUI_DIR    = $SCRIPT_DIR

function Write-Info    { param($msg) Write-Host "[INFO]  $msg" -ForegroundColor Cyan }
function Write-Success { param($msg) Write-Host "[OK]    $msg" -ForegroundColor Green }
function Write-Warn    { param($msg) Write-Host "[WARN]  $msg" -ForegroundColor Yellow }
function Write-Err     { param($msg) Write-Host "[ERROR] $msg" -ForegroundColor Red }
function Write-Header  { param($msg) Write-Host ""; Write-Host $msg -ForegroundColor White; Write-Host ("-" * 44) }

Write-Header "Cloud Security Reporter -- Startup"
Write-Info "Script dir : $SCRIPT_DIR"
Write-Info "Repo root  : $REPO_ROOT"

# -- 1. Execution Policy ---------------------------------------
Write-Header "Step 1: Environment Check"
Write-Success "OS: Windows"

$policy = Get-ExecutionPolicy -Scope CurrentUser
Write-Info "PowerShell execution policy (CurrentUser): $policy"

$blockingPolicies = @("Restricted", "AllSigned")
if ($blockingPolicies -contains $policy) {
    Write-Warn "Execution policy '$policy' may block module installation."
    Write-Warn "To fix manually, run in PowerShell:"
    Write-Warn "  Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser"
    $fix = Read-Host "Fix execution policy now- (y/N)"
    if ($fix -eq "y" -or $fix -eq "Y") {
        Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser -Force
        Write-Success "Execution policy set to RemoteSigned"
    }
} else {
    Write-Success "Execution policy OK: $policy"
}

# -- 2. Check Python -------------------------------------------
Write-Header "Step 2: Python"
$pythonCmd = $null

foreach ($cmd in @("python", "python3", "py")) {
    try {
        $ver = & $cmd -c "import sys; print(str(sys.version_info.major) + '.' + str(sys.version_info.minor))" 2>$null
        if ($ver) {
            $parts = $ver.Split(".")
            $major = [int]$parts[0]
            $minor = [int]$parts[1]
            if ($major -ge $PYTHON_MIN_MAJOR -and $minor -ge $PYTHON_MIN_MINOR) {
                $pythonCmd = $cmd
                Write-Success "Found: $cmd ($ver)"
                if ($minor -gt 12) {
                    Write-Warn "Python $ver detected. Prowler requires Python 3.12 or below."
                    Write-Warn "uv will install Prowler using Python 3.12 automatically."
                    Write-Warn "The GUI will continue using Python $ver."
                }
                break
            } else {
                Write-Warn "$cmd version $ver is below minimum 3.11"
            }
        }
    } catch {
        # command not found, try next
    }
}

if (-not $pythonCmd) {
    Write-Err "Python 3.11+ not found."
    Write-Err "Download from https://python.org/downloads/"
    Write-Err "Make sure to check 'Add Python to PATH' during install."
    Read-Host "Press Enter to exit"
    exit 1
}

# -- 3. uv -----------------------------------------------------
Write-Header "Step 3: uv Package Manager"

$uvCmd = Get-Command uv -ErrorAction SilentlyContinue
if (-not $uvCmd) {
    Write-Warn "uv not found -- installing..."
    try {
        Invoke-RestMethod https://astral.sh/uv/install.ps1 | Invoke-Expression
        $env:PATH = [System.Environment]::GetEnvironmentVariable("PATH", "User") + ";" + $env:PATH
        $uvCmd = Get-Command uv -ErrorAction SilentlyContinue
        if ($uvCmd) {
            Write-Success "uv installed successfully"
        } else {
            Write-Warn "uv installed but not on PATH yet -- restart terminal if issues occur"
        }
    } catch {
        Write-Warn "uv install failed: $_"
        Write-Warn "Install manually: https://docs.astral.sh/uv/"
    }
} else {
    $uvVer = (uv --version 2>$null) | Select-Object -First 1
    Write-Success "uv already installed: $uvVer"
}

# -- 4. Prowler ------------------------------------------------
Write-Header "Step 4: Prowler"

# Fix OneDrive hardlink error (os error 396).
# uv uses hardlinks for caching; OneDrive blocks hardlinks on synced paths.
# Force copy mode and move cache outside OneDrive.
$env:UV_LINK_MODE = "copy"
$env:UV_CACHE_DIR = "C:\uv-cache"
Write-Info "uv link mode: copy (avoids OneDrive hardlink conflicts)"

$prowlerCmd = Get-Command prowler -ErrorAction SilentlyContinue
if ($prowlerCmd) {
    Write-Success "Already installed"
} else {
    Write-Info "Installing Prowler via uv tool install..."
    try {
        # Install Prowler using Python 3.12 -- pandas 2.x has no wheels for 3.14+
        # uv will download Python 3.12 automatically if not present
        uv tool install prowler --python 3.12 --link-mode copy
        Write-Success "Prowler installed"
        Write-Warn "Note: Prowler on Windows may require WSL for full functionality."
        Write-Warn "See https://docs.prowler.com if you encounter runtime errors."
    } catch {
        Write-Warn "Prowler install failed: $_"
        Write-Warn "You can retry from Tools and Setup in the GUI."
    }
}

# -- 5. ScubaGear ----------------------------------------------
Write-Header "Step 5: ScubaGear"

$scubaModule = Get-Module -ListAvailable ScubaGear -ErrorAction SilentlyContinue
if ($scubaModule) {
    $scubaVer = ($scubaModule | Select-Object -First 1).Version
    Write-Success "Already installed: v$scubaVer"
} else {
    Write-Info "Installing ScubaGear PowerShell module..."
    try {
        Install-Module -Name PowerShellGet -Force -AllowClobber -Scope CurrentUser -ErrorAction SilentlyContinue
        Install-Module -Name ScubaGear -Force -AllowClobber -Scope CurrentUser
        Write-Success "ScubaGear installed"
    } catch {
        Write-Warn "ScubaGear install failed: $_"
        Write-Warn "You can retry from Tools and Setup in the GUI."
    }
}

# -- 6. Pipeline Python dependencies --------------------------
Write-Header "Step 6: Pipeline Dependencies"

$venvPath   = Join-Path $REPO_ROOT ".venv"
$venvPython = Join-Path $venvPath "Scripts\python.exe"

if (-not (Test-Path $venvPath)) {
    Write-Info "Creating root venv at $venvPath (Python 3.12 for pandas compatibility)..."
    # Use Python 3.12 for the pipeline venv -- pandas 2.x has no wheels for 3.14+
    uv venv $venvPath --python 3.12
}

Write-Info "Installing openpyxl, pydantic, boto3, tomli..."
try {
    uv pip install --python $venvPython openpyxl pydantic boto3 tomli `
        "pandas>=2.0.0" --only-binary pandas --link-mode copy --quiet
    Write-Success "Pipeline dependencies ready"
} catch {
    Write-Warn "Some dependencies failed: $_"
}

# -- 7. GUI dependencies ---------------------------------------
Write-Header "Step 7: GUI Dependencies"

Set-Location $GUI_DIR
Write-Info "Running uv sync..."
try {
    uv sync --quiet
    Write-Success "GUI dependencies ready"
} catch {
    Write-Err "GUI dependency sync failed: $_"
    Read-Host "Press Enter to exit"
    exit 1
}

# -- 8. Launch -------------------------------------------------
Write-Header "Step 8: Launch"

$URL = "http://localhost:$PORT"
Write-Info "Starting GUI on $URL"
Write-Info "Press Ctrl+C to stop the server"
Write-Host ""

# Open browser after 2s delay (non-blocking)
Start-Job -ScriptBlock {
    param($url)
    Start-Sleep -Seconds 2
    Start-Process $url
} -ArgumentList $URL | Out-Null

# Launch the app
Set-Location $GUI_DIR
uv run python main.py