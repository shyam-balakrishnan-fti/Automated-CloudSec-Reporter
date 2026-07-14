#!/usr/bin/env bash
# ============================================================
# Cloud Security Reporter — Linux/macOS startup script
# Double-click or run: bash start.sh
# ============================================================
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
GUI_DIR="$SCRIPT_DIR"
PORT=8000
PYTHON_MIN="3.11"

# ── Colours ──────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

info()    { echo -e "${CYAN}[INFO]${NC}  $*"; }
success() { echo -e "${GREEN}[OK]${NC}    $*"; }
warn()    { echo -e "${YELLOW}[WARN]${NC}  $*"; }
error()   { echo -e "${RED}[ERROR]${NC} $*"; }
header()  { echo -e "\n${BOLD}$*${NC}"; echo "────────────────────────────────────────"; }

header "Cloud Security Reporter — Startup"
info "Script dir : $SCRIPT_DIR"
info "Repo root  : $REPO_ROOT"
echo ""

# ── 1. Check OS ───────────────────────────────────────────────
header "Step 1: OS Detection"
OS="$(uname -s)"
case "$OS" in
  Linux*)   OS_NAME="Linux" ;;
  Darwin*)  OS_NAME="macOS" ;;
  *)        OS_NAME="$OS" ;;
esac
success "OS: $OS_NAME"
info "ScubaGear requires Windows — only Prowler is available on this platform"

# ── 2. Check Python ───────────────────────────────────────────
header "Step 2: Python"
PYTHON=""
for cmd in python3.12 python3.11 python3 python; do
  if command -v "$cmd" &>/dev/null; then
    VER="$($cmd -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')"
    MAJOR="${VER%%.*}"; MINOR="${VER##*.}"
    if [ "$MAJOR" -ge 3 ] && [ "$MINOR" -ge 11 ]; then
      PYTHON="$cmd"
      success "Found: $cmd ($VER)"
      break
    else
      warn "$cmd version $VER is below minimum $PYTHON_MIN"
    fi
  fi
done

if [ -z "$PYTHON" ]; then
  error "Python $PYTHON_MIN+ not found."
  error "Install from https://python.org/downloads/ then re-run this script."
  exit 1
fi

# ── 3. Install / verify uv ────────────────────────────────────
header "Step 3: uv Package Manager"
if ! command -v uv &>/dev/null; then
  warn "uv not found — installing..."
  curl -LsSf https://astral.sh/uv/install.sh | sh
  # Add to PATH for this session
  export PATH="$HOME/.local/bin:$HOME/.cargo/bin:$PATH"
  if ! command -v uv &>/dev/null; then
    error "uv install succeeded but binary not on PATH."
    error "Add ~/.local/bin to your PATH and re-run."
    exit 1
  fi
fi
UV_VER="$(uv --version 2>/dev/null | head -1)"
success "uv: $UV_VER"

# ── 4. Install Prowler ────────────────────────────────────────
header "Step 4: Prowler"
if command -v prowler &>/dev/null; then
  PROWLER_VER="$(prowler -v 2>/dev/null | head -1 || echo 'installed')"
  success "Already installed: $PROWLER_VER"
else
  info "Installing Prowler via uv tool install..."
  if uv tool install prowler; then
    success "Prowler installed"
    # Ensure uv tool bin is on PATH
    export PATH="$(uv tool dir --bin 2>/dev/null || echo "$HOME/.local/bin"):$PATH"
  else
    warn "Prowler install failed — you can install it later from Tools & Setup in the GUI"
  fi
fi

# ── 5. Install pipeline Python dependencies ───────────────────
header "Step 5: Pipeline Dependencies"
VENV="$REPO_ROOT/.venv"
if [ ! -d "$VENV" ]; then
  info "Creating root venv at $VENV..."
  uv venv "$VENV" --python "$PYTHON"
fi

info "Installing pipeline dependencies into root venv..."
uv pip install --python "$VENV/bin/python" \
  openpyxl pydantic boto3 tomli \
  --quiet
success "Pipeline dependencies ready"

# ── 6. Install GUI dependencies ───────────────────────────────
header "Step 6: GUI Dependencies"
cd "$GUI_DIR"
info "Syncing GUI dependencies via uv..."
uv sync --quiet
success "GUI dependencies ready"

# Step 7: Open browser and launch
header "Step 7: Launch"

BEDROCK_DEPLOYMENT_NAME="arn:aws:bedrock:ap-southeast-2:213146990554:application-inference-profile/mxnvznqf72bh"
export BEDROCK_DEPLOYMENT_NAME




URL="http://localhost:$PORT"
info "Starting GUI on $URL"
info "Press Ctrl+C to stop"
echo ""

# Open browser after a short delay (non-blocking)
(sleep 2 && \
  if command -v xdg-open &>/dev/null; then xdg-open "$URL"; \
  elif command -v open &>/dev/null; then open "$URL"; \
  fi) &

# Launch the app
cd "$GUI_DIR"
uv run python main.py