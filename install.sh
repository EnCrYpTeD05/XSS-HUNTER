#!/usr/bin/env bash
set -Eeuo pipefail
IFS=$'\n\t'

APP_NAME="XSS Hunter"
AUTHOR="EnCrYpTeD05"
REPO_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
GLOBAL_BIN="/usr/local/bin"
GLOBAL_CMD="${GLOBAL_BIN}/xsshunter"
GO_BIN="${HOME}/go/bin"
LOG_FILE="${REPO_DIR}/install.log"

SKIP_TOOLS=0
LINK_ONLY=0

if [[ -t 1 ]]; then
  RED='\033[0;31m'
  GREEN='\033[0;32m'
  CYAN='\033[0;36m'
  PINK='\033[0;95m'
  YELLOW='\033[1;33m'
  BOLD='\033[1m'
  RESET='\033[0m'
else
  RED=''
  GREEN=''
  CYAN=''
  PINK=''
  YELLOW=''
  BOLD=''
  RESET=''
fi

usage() {
  cat <<'EOF'
XSS Hunter installer

Usage:
  ./install.sh              Install dependencies and command launcher
  ./install.sh --skip-tools Only create the xsshunter launcher
  ./install.sh --link-only  Same as --skip-tools
  ./install.sh --help       Show help
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --skip-tools|--link-only)
      SKIP_TOOLS=1
      LINK_ONLY=1
      shift
      ;;
    --help|-h)
      usage
      exit 0
      ;;
    *)
      printf '%b\n' "${RED}[x] Unknown option: $1${RESET}"
      usage
      exit 1
      ;;
  esac
done

banner() {
  clear 2>/dev/null || true
  printf '%b\n' "${CYAN}${BOLD}"
  printf '%s\n' '+------------------------------------------------------+'
  printf '%s\n' '|                    XSS HUNTER                       |'
  printf '%s\n' '|        Automated Reflected XSS Scanner              |'
  printf '%s\n' '|              CLI + Web Dashboard                    |'
  printf '%s\n' '+------------------------------------------------------+'
  printf '%b\n' "${RESET}${PINK}Created by ${AUTHOR}${RESET}"
  printf '\n'
}

note() {
  printf '%b\n' "${CYAN}[*]${RESET} $1"
}

ok() {
  printf '%b\n' "${GREEN}[+]${RESET} $1"
}

warn() {
  printf '%b\n' "${YELLOW}[!]${RESET} $1"
}

fail() {
  printf '%b\n' "${RED}[x]${RESET} $1"
  printf '%b\n' "${YELLOW}[!] Full log: ${LOG_FILE}${RESET}"
  exit 1
}

run_quiet() {
  local label="$1"
  shift
  printf '%b' "${CYAN}[*]${RESET} ${label}..."
  if "$@" >>"${LOG_FILE}" 2>&1; then
    printf '%b\n' " ${GREEN}done${RESET}"
  else
    printf '%b\n' " ${RED}failed${RESET}"
    fail "${label}"
  fi
}

have() {
  command -v "$1" >/dev/null 2>&1
}

need_sudo() {
  if [[ "${EUID}" -eq 0 ]]; then
    SUDO=""
    return
  fi
  if ! have sudo; then
    fail "sudo is required for package installation"
  fi
  note "Requesting sudo once for system packages"
  sudo -v || fail "sudo authorization failed"
  SUDO="sudo"
}

install_system_packages() {
  if ! have apt-get; then
    warn "apt-get not found. Skipping system package install."
    return
  fi

  need_sudo
  run_quiet "Updating package index" ${SUDO} apt-get update
  run_quiet "Installing base packages" ${SUDO} apt-get install -y \
    python3 python3-pip pipx golang-go git curl ca-certificates
}

ensure_user_path() {
  mkdir -p "${GO_BIN}"

  local profile="${HOME}/.profile"
  local path_line='export PATH="$HOME/go/bin:$PATH"'
  if [[ ! -f "${profile}" ]] || ! grep -Fq "${path_line}" "${profile}"; then
    printf '\n%s\n' "${path_line}" >>"${profile}"
    warn "Go tool PATH updated in ~/.profile. Run: source ~/.profile"
  fi

  export PATH="${GO_BIN}:${PATH}"
}

install_go_tool() {
  local binary="$1"
  local module="$2"

  if have "${binary}"; then
    ok "${binary} already installed"
    return
  fi

  if ! have go; then
    fail "go is required to install ${binary}"
  fi

  run_quiet "Installing ${binary}" env GOBIN="${GO_BIN}" go install "${module}"
}

install_paramspider() {
  if have paramspider; then
    ok "paramspider already installed"
    return
  fi

  if have pipx; then
    if pipx install "git+https://github.com/devanshbatham/ParamSpider.git" >>"${LOG_FILE}" 2>&1; then
      ok "paramspider installed"
      pipx ensurepath >>"${LOG_FILE}" 2>&1 || true
      return
    fi
    warn "pipx git install failed, trying PyPI package"
    if pipx install paramspider >>"${LOG_FILE}" 2>&1; then
      ok "paramspider installed"
      pipx ensurepath >>"${LOG_FILE}" 2>&1 || true
      return
    fi
  fi

  if python3 -m pip install --user "git+https://github.com/devanshbatham/ParamSpider.git" >>"${LOG_FILE}" 2>&1; then
    ok "paramspider installed"
    return
  fi

  fail "paramspider installation failed"
}

install_launcher() {
  if [[ ! -f "${REPO_DIR}/xsshunter.py" ]]; then
    fail "xsshunter.py not found in ${REPO_DIR}"
  fi

  need_sudo
  run_quiet "Preparing global command path" ${SUDO} mkdir -p "${GLOBAL_BIN}"

  local tmp_launcher
  tmp_launcher="$(mktemp)"
  cat >"${tmp_launcher}" <<EOF
#!/usr/bin/env bash
exec python3 "${REPO_DIR}/xsshunter.py" "\$@"
EOF
  chmod +x "${tmp_launcher}"
  run_quiet "Installing global xsshunter command" ${SUDO} install -m 0755 "${tmp_launcher}" "${GLOBAL_CMD}"
  rm -f "${tmp_launcher}"

  if [[ -f "${REPO_DIR}/xsshunter" ]]; then
    chmod +x "${REPO_DIR}/xsshunter" || true
  fi

  ok "Global launcher installed: ${GLOBAL_CMD}"
}

verify_install() {
  local missing=()

  have python3 || missing+=("python3")
  have subfinder || missing+=("subfinder")
  have paramspider || missing+=("paramspider")
  have dalfox || missing+=("dalfox")

  if [[ ${#missing[@]} -gt 0 ]]; then
    warn "Missing from PATH: ${missing[*]}"
    warn "If Go tools were just installed, run: source ~/.profile"
  else
    ok "All required commands are available"
  fi

  if [[ -x "${GLOBAL_CMD}" ]]; then
    ok "xsshunter is globally executable"
  else
    warn "Global xsshunter launcher was not found at ${GLOBAL_CMD}"
  fi
}

main() {
  : >"${LOG_FILE}"
  banner
  note "Install directory: ${REPO_DIR}"

  ensure_user_path

  if [[ "${SKIP_TOOLS}" -eq 0 ]]; then
    install_system_packages
    install_go_tool "subfinder" "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
    install_go_tool "dalfox" "github.com/hahwul/dalfox/v2@latest"
    install_paramspider
  else
    warn "Skipping external tool installation"
  fi

  install_launcher
  verify_install

  printf '\n%b\n' "${GREEN}${BOLD}Setup complete.${RESET}"
  printf '%b\n' "${CYAN}Run web UI:${RESET} xsshunter --web"
  printf '%b\n' "${CYAN}Run CLI:${RESET}    xsshunter -d example.com"
  printf '%b\n' "${CYAN}Log file:${RESET}   ${LOG_FILE}"
}

main "$@"
