#!/usr/bin/env bash
# ┌─────────────────────────────────────────────────────────────────────────┐
# │  Supply Chain Triage CLI  (SCT)  v2.1                                   │
# │  Mini Shai-Hulud Edition  ·  TeamPCP  ·  CVE-2026-45321                 │
# │                                                                         │
# │  Interactive:  ./sct.sh                                                 │
# │  Direct CLI:   ./sct.sh <command> [flags]                               │
# │  Help:         ./sct.sh --help                                          │
# └─────────────────────────────────────────────────────────────────────────┘

set -euo pipefail
SCT_VERSION="2.1.0"
SCT_DATE="$(date -u +%Y%m%d-%H%M%S)"

# ── RUNTIME STATE ────────────────────────────────────────────────────────────
EXTRA_IOCS=()
EXTRA_SECRET_PATTERNS=()
EXTRA_PKGS=()
SCAN_DIRS=()
OUTPUT_FILE=""
QUIET=0
TOTAL_FINDINGS=0
TOTAL_WARNS=0
declare -A MODULE_RESULTS  # module_name => "CLEAN|WARN:n|CRITICAL:n"

# ── COLOUR SETUP ─────────────────────────────────────────────────────────────
if [[ -t 1 ]] && [[ "${NO_COLOR:-0}" != "1" ]]; then
  RED='\033[0;31m'; BRED='\033[1;31m'; AMBER='\033[0;33m'; GREEN='\033[0;32m'
  BLUE='\033[0;34m'; CYAN='\033[0;36m'; BCYAN='\033[1;36m'; BOLD='\033[1m'
  DIM='\033[2m'; NC='\033[0m'
else
  RED=''; BRED=''; AMBER=''; GREEN=''; BLUE=''; CYAN=''; BCYAN=''; BOLD=''; DIM=''; NC=''
fi

# ── OUTPUT HELPERS ────────────────────────────────────────────────────────────
_say()     { echo -e "$@"; }
CRIT()     { _say "${BRED}[CRIT]${NC}  $1"; TOTAL_FINDINGS=$((TOTAL_FINDINGS+1)); }
WARN()     { _say "${RED}[!]${NC}    $1"; TOTAL_FINDINGS=$((TOTAL_FINDINGS+1)); TOTAL_WARNS=$((TOTAL_WARNS+1)); }
INFO()     { _say "${AMBER}[?]${NC}    $1"; }
OK()       { _say "${GREEN}[OK]${NC}   $1"; }
SKIP()     { _say "${DIM}[--]   $1${NC}"; }
SECTION()  { _say "\n${CYAN}┌─ $1 ${NC}"; }
SUBHEAD()  { _say "${CYAN}│${NC}  ${BOLD}$1${NC}"; }
HR()       { _say "${DIM}────────────────────────────────────────────────────${NC}"; }

# Redact sensitive values before printing
redact() { sed -E "s/([:=][[:space:]]*['\"]?)[^'\"[:space:]#]{8,}/\1***REDACTED***/g"; }

# ── DEFAULT IOC LIST ──────────────────────────────────────────────────────────
DEFAULT_IOCS=(
  "zero.masscan.cloud" "94.154.172.43" "masscan.cloud" "beautifulcastle"
  "api.masscan.cloud"
  "filev2.getsession.org" "seed1.getsession.org" "seed2.getsession.org" "seed3.getsession.org"
  "git-tanstack.com" "litter.catbox.moe"
)

# ── DEFAULT SECRET PATTERNS (case-insensitive grep -E) ────────────────────────
DEFAULT_SECRET_PATTERNS=(
  "-----BEGIN (RSA|EC|DSA|PGP|OPENSSH|PRIVATE) KEY"
  "AKIA[0-9A-Z]{16}"
  "aws[_.-]?(access[_.-]?key|secret[_.-]?key|session[_.-]?token)[^a-z0-9]*[:=][^a-z0-9]*['\"]?[A-Za-z0-9/+]{20,}"
  "AccountKey=[A-Za-z0-9+/]{88}=="
  "DefaultEndpointsProtocol=https;AccountName="
  "client[_.-]?secret[^a-z0-9]*[:=][^a-z0-9]*['\"]?[A-Za-z0-9._~-]{16,}"
  "AIza[0-9A-Za-z_-]{35}"
  "ya29\.[0-9A-Za-z_-]{20,}"
  "ghp_[A-Za-z0-9]{36}"
  "ghs_[A-Za-z0-9]{36}"
  "gho_[A-Za-z0-9]{36}"
  "ghu_[A-Za-z0-9]{36}"
  "github_pat_[A-Za-z0-9_]{82}"
  "npm_[A-Za-z0-9]{36}"
  "sk_live_[0-9a-zA-Z]{24}"
  "rk_live_[0-9a-zA-Z]{24}"
  "sk_(live|test)_[A-Za-z0-9]{32,}"
  "FLWSECK[_-]?(TEST|PROD)|FLW(PUB|SEC)K?[_-]"
  "SK[0-9a-fA-F]{32}"
  "AC[0-9a-fA-F]{32}"
  "SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}"
  "eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"
  "(postgres|postgresql|mysql|mongodb|redis|mssql|sqlserver|cockroach)://[^[:space:]'\"]{10,}"
  "(password|passwd|pwd)[[:space:]]*[:=][[:space:]]*['\"][^'\"[:space:]]{6,}['\"]"
  "(api[_-]?key|apikey)[[:space:]]*[:=][[:space:]]*['\"][^'\"[:space:]]{10,}['\"]"
  "(secret[_-]?key|secretkey|client[_-]?secret)[[:space:]]*[:=][[:space:]]*['\"][^'\"[:space:]]{10,}['\"]"
  "(token|auth[_-]?token|access[_-]?token|refresh[_-]?token|bearer)[[:space:]]*[:=][[:space:]]*['\"][^'\"[:space:]]{10,}['\"]"
  "(private[_-]?key|signing[_-]?key)[[:space:]]*[:=][[:space:]]*['\"][^'\"[:space:]]{10,}['\"]"
  "^(SECRET|TOKEN|API_KEY|PASSWORD|CREDENTIAL|PRIVATE_KEY|DB_PASS(WORD)?|AUTH_SECRET|ENCRYPTION_KEY|SIGNING_KEY|SERVICE_ACCOUNT)[[:space:]]*=[[:space:]]*[^#[:space:]]{8,}"
)

# ── DEFAULT COMPROMISED PACKAGES (Mini Shai-Hulud + downstream waves) ────────
DEFAULT_PKGS=(
  # TanStack router/start ecosystem — 42 packages, GHSA-g7cv-rxg3-hmpx
  "@tanstack/arktype-adapter"          "@tanstack/eslint-plugin-router"
  "@tanstack/eslint-plugin-start"      "@tanstack/history"
  "@tanstack/nitro-v2-vite-plugin"     "@tanstack/react-router"
  "@tanstack/react-router-devtools"    "@tanstack/react-router-ssr-query"
  "@tanstack/react-start"              "@tanstack/react-start-client"
  "@tanstack/react-start-rsc"          "@tanstack/react-start-server"
  "@tanstack/router-cli"               "@tanstack/router-core"
  "@tanstack/router-devtools"          "@tanstack/router-devtools-core"
  "@tanstack/router-generator"         "@tanstack/router-plugin"
  "@tanstack/router-ssr-query-core"    "@tanstack/router-utils"
  "@tanstack/router-vite-plugin"       "@tanstack/solid-router"
  "@tanstack/solid-router-devtools"    "@tanstack/solid-router-ssr-query"
  "@tanstack/solid-start"              "@tanstack/solid-start-client"
  "@tanstack/solid-start-server"       "@tanstack/start-client-core"
  "@tanstack/start-fn-stubs"           "@tanstack/start-plugin-core"
  "@tanstack/start-server-core"        "@tanstack/start-static-server-functions"
  "@tanstack/start-storage-context"    "@tanstack/valibot-adapter"
  "@tanstack/virtual-file-routes"      "@tanstack/vue-router"
  "@tanstack/vue-router-devtools"      "@tanstack/vue-router-ssr-query"
  "@tanstack/vue-start"                "@tanstack/vue-start-client"
  "@tanstack/vue-start-server"         "@tanstack/zod-adapter"
  # Mistral AI — npm packages + PyPI
  "@mistralai/mistralai"               "@mistralai/mistralai-azure"
  "@mistralai/mistralai-gcp"
  "mistralai"           # PyPI: pip install mistralai==2.4.6 is affected
  # OpenSearch
  "@opensearch-project/opensearch"
  # UiPath platform / AI tooling
  "@uipath/access-policy-sdk"          "@uipath/access-policy-tool"
  "@uipath/admin-tool"                 "@uipath/agent-sdk"
  "@uipath/agent-tool"                 "@uipath/agent.sdk"
  "@uipath/aops-policy-tool"           "@uipath/ap-chat"
  "@uipath/api-workflow-tool"          "@uipath/apollo-core"
  "@uipath/apollo-react"               "@uipath/apollo-wind"
  "@uipath/auth"                       "@uipath/case-tool"
  "@uipath/cli"                        "@uipath/codedagent-tool"
  "@uipath/codedagents-tool"           "@uipath/codedapp-tool"
  "@uipath/common"                     "@uipath/context-grounding-tool"
  "@uipath/data-fabric-tool"           "@uipath/docsai-tool"
  "@uipath/filesystem"                 "@uipath/flow-tool"
  "@uipath/functions-tool"             "@uipath/gov-tool"
  "@uipath/identity-tool"              "@uipath/insights-sdk"
  "@uipath/insights-tool"              "@uipath/integrationservice-sdk"
  "@uipath/integrationservice-tool"    "@uipath/llmgw-tool"
  "@uipath/maestro-sdk"                "@uipath/maestro-tool"
  "@uipath/orchestrator-tool"          "@uipath/packager-tool-apiworkflow"
  "@uipath/packager-tool-bpmn"         "@uipath/packager-tool-case"
  "@uipath/packager-tool-connector"    "@uipath/packager-tool-flow"
  "@uipath/packager-tool-functions"    "@uipath/packager-tool-webapp"
  "@uipath/packager-tool-workflowcompiler"
  "@uipath/packager-tool-workflowcompiler-browser"
  "@uipath/platform-tool"              "@uipath/project-packager"
  "@uipath/resource-tool"              "@uipath/resourcecatalog-tool"
  "@uipath/resources-tool"             "@uipath/robot"
  "@uipath/rpa-legacy-tool"            "@uipath/rpa-tool"
  "@uipath/solution-packager"          "@uipath/solution-tool"
  "@uipath/solutionpackager-sdk"       "@uipath/solutionpackager-tool-core"
  "@uipath/tasks-tool"                 "@uipath/telemetry"
  "@uipath/test-manager-tool"          "@uipath/tool-workflowcompiler"
  "@uipath/traces-tool"                "@uipath/ui-widgets-multi-file-upload"
  "@uipath/uipath-python-bridge"       "@uipath/vertical-solutions-tool"
  "@uipath/vss"                        "@uipath/widget.sdk"
  # DraftAuth / DraftLab auth stack
  "@draftauth/client"  "@draftauth/core"
  "@draftlab/auth"     "@draftlab/auth-router"  "@draftlab/db"
  # CLI / SDK tools
  "@taskflow-corp/cli"  "@tolka/cli"
  "@supersurkhet/cli"   "@supersurkhet/sdk"
  "@dirigible-ai/sdk"   "agentwork-cli"
  # MCP (Model Context Protocol) servers
  "cmux-agent-mcp"  "nextmove-mcp"  "@squawk/mcp"
  # Git utilities
  "git-git-git"  "git-branch-selector"
  # Auth / backend
  "@beproduct/nestjs-auth"  "safe-action"
  # ML Toolkit (TypeScript)
  "@ml-toolkit-ts/preprocessing"  "@ml-toolkit-ts/xgboost"  "ml-toolkit-ts"
  # Squawk aviation platform
  "@squawk/airport-data"       "@squawk/airports"        "@squawk/airspace"
  "@squawk/airspace-data"      "@squawk/airway-data"     "@squawk/airways"
  "@squawk/fix-data"           "@squawk/fixes"           "@squawk/flight-math"
  "@squawk/flightplan"         "@squawk/geo"             "@squawk/icao-registry"
  "@squawk/icao-registry-data" "@squawk/navaid-data"     "@squawk/navaids"
  "@squawk/notams"             "@squawk/procedure-data"  "@squawk/procedures"
  "@squawk/types"              "@squawk/units"           "@squawk/weather"
  # TallyUI e-commerce platform
  "@tallyui/components"           "@tallyui/connector-medusa"
  "@tallyui/connector-shopify"    "@tallyui/connector-vendure"
  "@tallyui/connector-woocommerce" "@tallyui/core"
  "@tallyui/database"             "@tallyui/pos"
  "@tallyui/storage-sqlite"       "@tallyui/theme"
  # MesaDev
  "@mesadev/rest"  "@mesadev/saguaro"  "@mesadev/sdk"
  # Miscellaneous npm
  "wot-api"  "cross-stitch"  "ts-dna"
  # PyPI
  "guardrails-ai"   # PyPI: pip install guardrails-ai==0.10.1 is affected
  # Worm attack-vector marker — fictitious package; any lockfile hit = compromise
  "@tanstack/setup"
)

# ── BANNER ────────────────────────────────────────────────────────────────────
banner() {
  _say ""
  _say "${BCYAN}╔══════════════════════════════════════════════════════════════╗${NC}"
  _say "${BCYAN}║${NC}  ${BOLD}Supply Chain Triage CLI  (SCT)  v${SCT_VERSION}${NC}                     ${BCYAN}║${NC}"
  _say "${BCYAN}║${NC}  ${DIM}Mini Shai-Hulud Edition  ·  TeamPCP  ·  CVE-2026-45321${NC}    ${BCYAN}║${NC}"
  _say "${BCYAN}╚══════════════════════════════════════════════════════════════╝${NC}"
  _say "  Host: ${BOLD}$(hostname)${NC}  ·  User: ${BOLD}$(whoami)${NC}  ·  ${DIM}$(date -u)${NC}"
  _say ""
}

# ── HELP ──────────────────────────────────────────────────────────────────────
show_help() {
  banner
  cat << EOF
${BOLD}USAGE${NC}
  ./sct.sh                        Launch interactive menu
  ./sct.sh <command> [flags]      Run a command directly

${BOLD}COMMANDS${NC}
  ${CYAN}all${NC}          Full triage: machine + deps (default interactive choice)
  ${CYAN}machine${NC}      Machine scan: IOCs, secrets, shell history, git history
  ${CYAN}deps${NC}         Dependency audit: npm, pnpm, yarn, pip, cargo, go, composer, nuget
  ${CYAN}ide${NC}          IDE audit: VS Code, JetBrains, Sublime Text, Vim/Neovim, Eclipse, Atom
  ${CYAN}platform${NC}     ADO / GitHub audit guidance (interactive checklist)
  ${CYAN}harden${NC}       Print hardening configs (.npmrc, pnpm, pipeline snippets)

${BOLD}GLOBAL FLAGS${NC}
  ${GREEN}-i, --ioc${NC}         Add extra IOC domain or IP (repeatable)
  ${GREEN}-s, --secret${NC}      Add extra secret regex pattern (repeatable, case-insensitive)
  ${GREEN}-p, --package${NC}     Add extra package to scan for (repeatable)
  ${GREEN}-d, --dir${NC}         Add project directory to scan (repeatable; default: current dir). Supports '~' expansion.
  ${GREEN}-o, --output${NC}      Write full output to file (auto-names if no value given)
  ${GREEN}-q, --quiet${NC}       Suppress colors and decorations (pipe-friendly)
  ${GREEN}-h, --help${NC}        Show this help

${BOLD}EXAMPLES${NC}
  ./sct.sh all -d /repos/frontend -d /repos/backend
  ./sct.sh machine -i evil.c2.io -s CORP_INTERNAL_SECRET
  ./sct.sh deps -p my-internal-lib -d /path/to/project -o
  ./sct.sh machine --output /tmp/triage-$(hostname).txt
  ./sct.sh all -q | tee report.txt
EOF
}

# ── ARG PARSING ───────────────────────────────────────────────────────────────
# Sets global SCT_COMMAND rather than returning via stdout (avoids subshell issues)
SCT_COMMAND=""

parse_args() {
  while [[ $# -gt 0 ]]; do
    case $1 in
      all|machine|deps|ide|platform|harden) SCT_COMMAND="$1"; shift ;;
      -i|--ioc)        EXTRA_IOCS+=("$2");            shift 2 ;;
      -s|--secret)     EXTRA_SECRET_PATTERNS+=("$2"); shift 2 ;;
      -p|--package)    EXTRA_PKGS+=("$2");            shift 2 ;;
      -d|--dir)        SCAN_DIRS+=("$(expand_path "$2")");             shift 2 ;;
      -o|--output)
        if [[ $# -gt 1 && ! "$2" =~ ^- ]]; then
          OUTPUT_FILE="$2"; shift 2
        else
          OUTPUT_FILE="sct-report-$(hostname)-${SCT_DATE}.txt"; shift
        fi ;;
      -q|--quiet)      QUIET=1; RED=''; BRED=''; AMBER=''; GREEN=''; BLUE=''
                       CYAN=''; BCYAN=''; BOLD=''; DIM=''; NC=''; shift ;;
      -h|--help)       show_help; exit 0 ;;
      *) _say "Unknown flag: $1  (try --help)"; shift ;;
    esac
  done
  [[ ${#SCAN_DIRS[@]} -eq 0 ]] && SCAN_DIRS=(".")
}

# ── INTERACTIVE PARAMETER COLLECTION ─────────────────────────────────────────
collect_params() {
  local scope="$1"  # "machine", "deps", or "all"

  _say "\n${BOLD}Configure scan (press Enter to accept defaults):${NC}\n"

  # Extra IOCs (always relevant)
  if [[ "$scope" == "machine" || "$scope" == "all" ]]; then
    _say "  ${DIM}Default IOCs: ${DEFAULT_IOCS[*]}${NC}"
    read -rp "  Extra IOC domain/IP (or Enter to skip): " _val
    [[ -n "$_val" ]] && EXTRA_IOCS+=("$_val")
    while [[ -n "$_val" ]]; do
      read -rp "  Another IOC (or Enter to stop): " _val
      [[ -n "$_val" ]] && EXTRA_IOCS+=("$_val")
    done

    _say ""
    read -rp "  Extra secret pattern regex (or Enter to skip): " _val
    [[ -n "$_val" ]] && EXTRA_SECRET_PATTERNS+=("$_val")
    while [[ -n "$_val" ]]; do
      read -rp "  Another pattern (or Enter to stop): " _val
      [[ -n "$_val" ]] && EXTRA_SECRET_PATTERNS+=("$_val")
    done
  fi

  # Extra packages (relevant for deps and all)
  if [[ "$scope" == "deps" || "$scope" == "all" ]]; then
    _say ""
    read -rp "  Extra package to scan for (or Enter to skip): " _val
    [[ -n "$_val" ]] && EXTRA_PKGS+=("$_val")
    while [[ -n "$_val" ]]; do
      read -rp "  Another package (or Enter to stop): " _val
      [[ -n "$_val" ]] && EXTRA_PKGS+=("$_val")
    done

    _say ""
    _say "  ${DIM}Project directories to scan (default: current dir):${NC}"
    read -rp "  Add directory path (or Enter to skip): " _val
    if [[ -n "$_val" ]]; then
      SCAN_DIRS=()
      SCAN_DIRS+=("$(expand_path "$_val")")
      while [[ -n "$_val" ]]; do
        read -rp "  Another directory (or Enter to stop): " _val
        [[ -n "$_val" ]] && SCAN_DIRS+=("$(expand_path "$_val")")
      done
    fi
    [[ ${#SCAN_DIRS[@]} -eq 0 ]] && SCAN_DIRS=(".")
  fi

  # Output file
  _say ""
  read -rp "  Save report to file? [y/N]: " _val
  if [[ "${_val,,}" == "y" ]]; then
    local default_file="sct-report-$(hostname)-${SCT_DATE}.txt"
    read -rp "  Filename [${default_file}]: " _fname
    OUTPUT_FILE="${_fname:-$default_file}"
  fi
}

# ── COMBINED PATTERNS ─────────────────────────────────────────────────────────
build_patterns() {
  ALL_IOCS=("${DEFAULT_IOCS[@]}" "${EXTRA_IOCS[@]}")
  ALL_PATTERNS=("${DEFAULT_SECRET_PATTERNS[@]}")
  # Validate user-supplied secret patterns: skip (do not fail) any pattern grep -E cannot parse
  if [[ ${#EXTRA_SECRET_PATTERNS[@]} -gt 0 ]]; then
    for pat in "${EXTRA_SECRET_PATTERNS[@]}"; do
      if echo "" | grep -qE "$pat" 2>/dev/null || echo "test" | grep -qE "$pat" 2>/dev/null; then
        ALL_PATTERNS+=("$pat")
      else
        WARN "Skipping invalid secret pattern (grep -E error): $pat"
      fi
    done
  fi
  ALL_PKGS=("${DEFAULT_PKGS[@]}" "${EXTRA_PKGS[@]}")
  IOC_PATTERN=$(printf '%s|' "${ALL_IOCS[@]}" | sed 's/\./\\./g; s/|$//')
  SECRET_PATTERN=$(printf '%s|' "${ALL_PATTERNS[@]}" | sed 's/|$//')
}

expand_path() {
  local path="$1"
  if [[ "$path" == "~" ]]; then
    printf '%s' "$HOME"
  elif [[ "$path" == "~/"* ]]; then
    printf '%s' "${path/#\~/$HOME}"
  else
    printf '%s' "$path"
  fi
}

# Cross-platform realpath replacement (BSD/macOS lacks GNU realpath unless coreutils installed)
_realpath() {
  python3 -c "import os,sys; print(os.path.realpath(sys.argv[1]))" "$1" 2>/dev/null \
    || { local p; p="$(expand_path "$1")"; ( cd "$p" 2>/dev/null && pwd ) || echo "$p"; }
}

# ── MODULE: MACHINE SCAN ─────────────────────────────────────────────────────
cmd_machine() {
  SECTION "Machine Scan"
  _say "  IOCs: ${#ALL_IOCS[@]}  ·  Secret patterns: ${#ALL_PATTERNS[@]}"
  [[ ${#EXTRA_IOCS[@]} -gt 0 ]]           && _say "  Custom IOCs: ${EXTRA_IOCS[*]}"
  [[ ${#EXTRA_SECRET_PATTERNS[@]} -gt 0 ]] && _say "  Custom patterns: ${#EXTRA_SECRET_PATTERNS[@]} added"

  local module_start_findings=$TOTAL_FINDINGS

  # 1. Network connections
  SUBHEAD "1/7  Network connections"
  for ioc in "${ALL_IOCS[@]}"; do
    if ss -tunp 2>/dev/null | grep -iq "$ioc" || netstat -tunp 2>/dev/null | grep -iq "$ioc"; then
      CRIT "ACTIVE CONNECTION: $ioc"
    else
      OK "No connection: $ioc"
    fi
  done

  # 2. DNS / hosts
  SUBHEAD "2/7  /etc/hosts and DNS"
  local suspicious
  suspicious=$(grep -vEi "^#|^127|^::1|^$|^0\.0\.0\.0|^ff" /etc/hosts 2>/dev/null || true)
  if [[ -n "$suspicious" ]]; then
    INFO "/etc/hosts non-standard entries:"
    echo "$suspicious"
  else
    OK "/etc/hosts clean"
  fi
  for ioc in "${ALL_IOCS[@]}"; do
    local resolve
    resolve=$(getent hosts "$ioc" 2>/dev/null || dig +short "$ioc" 2>/dev/null | head -1 || true)
    [[ -n "$resolve" ]] && INFO "IOC resolves: $ioc => $resolve"
  done

  # 3. Shell history
  SUBHEAD "3/7  Shell history"
  for f in ~/.bash_history ~/.zsh_history ~/.history ~/.local/share/fish/fish_history; do
    [[ -f "$f" ]] || continue
    local hits
    hits=$(grep -iE -- "$IOC_PATTERN" "$f" 2>/dev/null | head -5 || true)
    if [[ -n "$hits" ]]; then
      WARN "IOC in $f:"
      echo "$hits" | head -5
    else
      OK "$f clean"
    fi
  done

  # 4. Environment + credential files
  SUBHEAD "4/7  Environment variables and credential files"
  local env_hits
  env_hits=$(env 2>/dev/null | grep -iE -- "$SECRET_PATTERN" | redact || true)
  if [[ -n "$env_hits" ]]; then
    INFO "Secret patterns in environment (redacted):"
    echo "$env_hits" | head -10
  else
    OK "No secret patterns in environment"
  fi

  local cred_files=(
    ~/.env ~/.env.local ~/.env.development ~/.env.production ~/.env.staging
    ~/.netrc ~/.pgpass ~/.my.cnf ~/.boto ~/.pypirc
    ~/.aws/credentials ~/.aws/config ~/.azure/credentials ~/.azure/config
    ~/.config/gcloud/application_default_credentials.json
    ~/.npmrc ~/.yarnrc ~/.yarnrc.yml
    ~/.docker/config.json
    ~/.git-credentials
    ~/.config/gh/hosts.yml
  )
  for f in "${cred_files[@]}"; do
    [[ -f "$f" ]] || continue
    local hits
    hits=$(grep -iE -- "$SECRET_PATTERN" "$f" 2>/dev/null | redact | head -3 || true)
    if [[ -n "$hits" ]]; then
      WARN "Secret in $f (redacted):"
      echo "$hits"
    fi
  done

  # 5. Git history secret scan
  SUBHEAD "5/7  Git history secret scan"
  local scan_dirs=("${SCAN_DIRS[@]}")
  [[ ${#scan_dirs[@]} -eq 0 ]] && scan_dirs=(".")
  local found_git_repo=0

  for scan_dir in "${scan_dirs[@]}"; do
    scan_dir=$(expand_path "$scan_dir")
    if [[ ! -d "$scan_dir" ]]; then
      INFO "Directory not found for git scan: $scan_dir (skipping)"
      continue
    fi

    pushd "$scan_dir" > /dev/null || { INFO "Cannot cd to $scan_dir, skipping"; continue; }

    if git rev-parse --is-inside-work-tree &>/dev/null; then
      found_git_repo=1
      local repo
      repo=$(git rev-parse --show-toplevel)
      INFO "Repo: $(basename "$repo") — scanning commit history since 2026-04-01 (may take a moment)..."
      _say "  ${DIM}▶ git log --all --since=2026-04-01 -p --diff-filter=AMR${NC}"
      local git_hits
      git_hits=$(git log --all --since="2026-04-01" -p --diff-filter=AMR 2>/dev/null \
        | grep -E "^\+" | grep -v "^\+\+\+" \
        | grep -iE -- "$SECRET_PATTERN" | redact | sort -u | head -20 || true)
      if [[ -n "$git_hits" ]]; then
        WARN "Secrets in recent git history (redacted):"
        echo "$git_hits"
      else
        OK "No secret patterns in post-April-2026 git history"
      fi

      _say "  ${DIM}Checking full history for private key material...${NC}"
      _say "  ${DIM}▶ git log --all -p --diff-filter=AMR | grep BEGIN.*KEY${NC}"
      local pkey_hits
      pkey_hits=$(git log --all -p --diff-filter=AMR 2>/dev/null \
        | grep -E "^\+" | grep -v "^\+\+\+" \
        | grep -iE -- "-----BEGIN (RSA|EC|DSA|PGP|OPENSSH|PRIVATE) KEY" | head -5 || true)
      if [[ -n "$pkey_hits" ]]; then
        CRIT "Private key in ALL-TIME git history:"
        echo "$pkey_hits"
      else
        OK "No private key material found in full git history"
      fi

      _say "  ${DIM}▶ git log --all --oneline --since=2026-04-01 | grep IOC patterns${NC}"
      local ioc_commits
      ioc_commits=$(git log --all --oneline --since="2026-04-01" 2>/dev/null \
        | grep -iE -- "$IOC_PATTERN" || true)
      if [[ -n "$ioc_commits" ]]; then
        WARN "IOC in commit messages:"
        echo "$ioc_commits"
      else
        OK "No IOC patterns in recent commit messages"
      fi
    else
      SKIP "Not inside a git repository: $scan_dir"
    fi

    popd > /dev/null
  done

  if [[ $found_git_repo -eq 0 ]]; then
    SKIP "No git repository found in scanned directories"
  fi

  # 6. Processes + cron
  SUBHEAD "6/7  Processes and scheduled tasks"
  local proc_hits
  proc_hits=$(ps aux 2>/dev/null | grep -iE -- "$IOC_PATTERN" | grep -v grep || true)
  if [[ -n "$proc_hits" ]]; then
    WARN "Suspicious processes:"
    echo "$proc_hits"
  else
    OK "No suspicious processes"
  fi
  local cron
  cron=$(crontab -l 2>/dev/null | grep -vE "^#|^$" || true)
  if [[ -n "$cron" ]]; then
    INFO "Crontab (verify these are expected):"
    echo "$cron"
  else
    OK "No user crontab"
  fi

  # 7. Malware artifact scan
  SUBHEAD "7/7  Malware artifact scan"
  local artifact_hits=0
  # Check for known malicious payload files anywhere under scan dirs and home
  for afile in router_init.js tanstack_runner.js; do
    local found_paths
    found_paths=$(find "${HOME}" "${SCAN_DIRS[@]}" -name "$afile" -not -path "*/node_modules/.cache/*" 2>/dev/null | head -5 || true)
    if [[ -n "$found_paths" ]]; then
      CRIT "Malicious payload file found: $afile"
      echo "$found_paths"
      artifact_hits=$((artifact_hits+1))
    fi
  done

  # Check for worm persistence files dropped by compromised install scripts
  local _persist_files=(
    "${HOME}/.claude/router_runtime.js"
    "${HOME}/.claude/setup.mjs"
    "${HOME}/.vscode/setup.mjs"
    "${HOME}/.local/bin/gh-token-monitor.sh"
  )
  for _pf in "${_persist_files[@]}"; do
    if [[ -f "$_pf" ]]; then
      CRIT "Worm persistence file found: $_pf"
      artifact_hits=$((artifact_hits+1))
    fi
  done

  # Check per-repo Claude Code and VS Code injection (settings files modified by worm)
  for scan_dir in "${SCAN_DIRS[@]}"; do
    for _injected in "${scan_dir}/.claude/router_runtime.js" \
                     "${scan_dir}/.claude/setup.mjs" \
                     "${scan_dir}/.vscode/setup.mjs"; do
      if [[ -f "$_injected" ]]; then
        CRIT "Worm persistence file found: $_injected"
        artifact_hits=$((artifact_hits+1))
      fi
    done
  done

  # Check for gh-token-monitor systemd service (Linux persistence)
  local _systemd_svc="${HOME}/.config/systemd/user/gh-token-monitor.service"
  if [[ -f "$_systemd_svc" ]]; then
    CRIT "Worm systemd persistence unit found: $_systemd_svc — disable and remove"
    artifact_hits=$((artifact_hits+1))
  fi
  if systemctl --user is-active gh-token-monitor &>/dev/null 2>&1; then
    CRIT "Worm service gh-token-monitor is ACTIVE — stop and disable immediately"
    artifact_hits=$((artifact_hits+1))
  fi

  # Check for gh-token-monitor LaunchAgent (macOS persistence)
  local _plist="${HOME}/Library/LaunchAgents/com.user.gh-token-monitor.plist"
  if [[ -f "$_plist" ]]; then
    CRIT "Worm LaunchAgent found: $_plist — unload and remove"
    artifact_hits=$((artifact_hits+1))
  fi

  # Check for gh-token-monitor config directory
  if [[ -d "${HOME}/.config/gh-token-monitor" ]]; then
    CRIT "Worm config directory found: ${HOME}/.config/gh-token-monitor"
    artifact_hits=$((artifact_hits+1))
  fi

  # Check package.json files for @tanstack/setup in optionalDependencies (attack vector marker)
  for scan_dir in "${SCAN_DIRS[@]}"; do
    local _pkgjson="${scan_dir}/package.json"
    if [[ -f "$_pkgjson" ]]; then
      if python3 -c "
import json, sys
try:
  d = json.load(open(sys.argv[1]))
  od = d.get('optionalDependencies', {})
  if any('@tanstack/setup' in str(k) for k in od):
    sys.exit(0)
  sys.exit(1)
except: sys.exit(1)
" "$_pkgjson" 2>/dev/null; then
        CRIT "@tanstack/setup in optionalDependencies of $_pkgjson — this is the worm attack-vector marker"
        artifact_hits=$((artifact_hits+1))
      fi
    fi
  done

  # Check for suspicious npm token (ransom threat marker)
  local ransom_token
  ransom_token=$(grep -r "IfYouRevokeThisTokenItWillWipeTheComputerOfTheOwner" "${HOME}/.npmrc" ~/.config/npm/ 2>/dev/null || true)
  if [[ -n "$ransom_token" ]]; then
    CRIT "RANSOMWARE npm token marker found — DO NOT REVOKE without isolating machine first"
  fi
  # Check for injected Claude Code hooks
  if [[ -f "${HOME}/.claude/hooks.json" || -d "${HOME}/.claude/hooks" ]]; then
    INFO "Claude Code hooks present — verify these are expected: ${HOME}/.claude/hooks*"
  fi
  # Check for injected GH Actions workflow
  for scan_dir in "${SCAN_DIRS[@]}"; do
    local codeql_path="${scan_dir}/.github/workflows/codeql_analysis.yml"
    if [[ -f "$codeql_path" ]]; then
      WARN "Suspicious injected workflow: $codeql_path — verify this was intentionally added"
    fi
  done
  if [[ $artifact_hits -eq 0 ]]; then
    OK "No known malware artifact files found"
    INFO "Known SHA-256: router_init.js=ab4fcadaec49c03278063dd269ea5eef82d24f2124a8e15d7b90f2fa8601266c  tanstack_runner.js=2ec78d556d696e208927cc503d48e4b5eb56b31abc2870c2ed2e98d6be27fc96"
  fi

  local delta=$((TOTAL_FINDINGS - module_start_findings))
  MODULE_RESULTS["machine"]=$([[ $delta -eq 0 ]] && echo "CLEAN" || echo "FINDINGS:$delta")
}

# ── MODULE: DEPENDENCY AUDIT ──────────────────────────────────────────────────
cmd_deps() {
  local dirs=("${SCAN_DIRS[@]}")

  # Expand monorepo workspaces: find lockfiles up to 4 levels deep in each scan dir
  local -a ws_extra=()
  local _rd _rws _dup _chk _rc _ws _lf _d
  for _d in "${dirs[@]}"; do
    _rd=$(_realpath "$(expand_path "$_d")")
    [[ -d "$_rd" ]] || continue
    while IFS= read -r _ws; do
      [[ -z "$_ws" ]] && continue
      _rws=$(_realpath "$_ws")
      _dup=0
      for _chk in "${dirs[@]}" "${ws_extra[@]+"${ws_extra[@]}"}"; do
        _rc=$(_realpath "$(expand_path "$_chk")")
        [[ "$_rws" == "$_rc" ]] && _dup=1 && break
      done
      [[ $_dup -eq 0 ]] && ws_extra+=("$_ws")
    done < <(find "$_rd" -maxdepth 4 \
      \( -path '*/node_modules' -o -path '*/.git' -o -path '*/vendor' -o -path '*/.pnpm-store' \) -prune \
      -o \( -name 'package-lock.json' -o -name 'yarn.lock' -o -name 'pnpm-lock.yaml' \) -print \
      2>/dev/null | while IFS= read -r _lf; do dirname "$_lf"; done | sort -u | grep -Fxv "$_rd" || true)
  done
  [[ ${#ws_extra[@]} -gt 0 ]] && dirs+=("${ws_extra[@]}")

  SECTION "Dependency Audit  [${#ALL_PKGS[@]} packages  ·  ${#dirs[@]} dir(s)]"
  [[ ${#ws_extra[@]} -gt 0 ]] && SUBHEAD "Monorepo: ${#ws_extra[@]} workspace package(s) auto-discovered"
  local module_start_findings=$TOTAL_FINDINGS

  # Per-directory finding helpers (defined once; WARN already increments TOTAL_FINDINGS)
  local dir_findings=0
  _flag_pkg() { WARN "$1 @ $2 in $3"; dir_findings=$((dir_findings+1)); }
  _clean_eco() { OK "$1: no flagged packages"; }
  _skip_eco()  { SKIP "$1: no lockfile — run install first"; }

  for scan_dir in "${dirs[@]}"; do
    scan_dir=$(expand_path "$scan_dir")
    if [[ ! -d "$scan_dir" ]]; then INFO "Directory not found: $scan_dir (skipping)"; continue; fi
    local abs_dir
    abs_dir=$(_realpath "$scan_dir")
    SUBHEAD "Scanning: $abs_dir"
    pushd "$abs_dir" > /dev/null

    dir_findings=0

    # npm
    if [[ -f "package-lock.json" ]]; then
      _say "  ${DIM}Checking npm (package-lock.json)...${NC}"
      local npm_f=0
      for pkg in "${ALL_PKGS[@]}"; do
        local ver
        ver=$(python3 -c "
import json,sys
try:
  d=json.load(open('package-lock.json'))
  t=sys.argv[1].lower()
  pkgs=d.get('packages') or d.get('dependencies',{})
  for k,v in pkgs.items():
    kl=k.lower()
    if kl in (f'node_modules/{t}',t) or kl.endswith(f'/node_modules/{t}'):
      print(v.get('version','?') if isinstance(v,dict) else '?'); break
except:pass
" "$pkg" 2>/dev/null)
        [[ -n "$ver" ]] && _flag_pkg "$pkg" "$ver" "package-lock.json" && npm_f=$((npm_f+1))
      done
      [[ $npm_f -eq 0 ]] && _clean_eco "npm"
    fi

    # pnpm
    if [[ -f "pnpm-lock.yaml" ]]; then
      _say "  ${DIM}Checking pnpm (pnpm-lock.yaml)...${NC}"
      local pnpm_f=0
      for pkg in "${ALL_PKGS[@]}"; do
        if grep -iqE "\"${pkg}\"|'${pkg}'|/${pkg}@|^[[:space:]]+${pkg}@" pnpm-lock.yaml 2>/dev/null; then
          _flag_pkg "$pkg" "see pnpm-lock.yaml" "pnpm-lock.yaml"; pnpm_f=$((pnpm_f+1))
        fi
      done
      [[ $pnpm_f -eq 0 ]] && _clean_eco "pnpm"
    fi

    # yarn
    if [[ -f "yarn.lock" ]]; then
      _say "  ${DIM}Checking yarn (yarn.lock)...${NC}"
      local yarn_f=0
      for pkg in "${ALL_PKGS[@]}"; do
        if grep -iqE "^\"?${pkg}@|^${pkg}@" yarn.lock 2>/dev/null; then
          local ver
          ver=$(grep -iA2 "^\"?${pkg}@" yarn.lock | grep -i "version" | grep -oP '"\K[^"]+' | head -1 || echo "see lockfile")
          _flag_pkg "$pkg" "$ver" "yarn.lock"; yarn_f=$((yarn_f+1))
        fi
      done
      [[ $yarn_f -eq 0 ]] && _clean_eco "yarn"
    fi

    # Python
    local py_files=()
    for pf in requirements.txt requirements-dev.txt requirements-prod.txt Pipfile.lock pyproject.toml poetry.lock setup.py setup.cfg; do
      [[ -f "$pf" ]] && py_files+=("$pf")
    done
    if [[ ${#py_files[@]} -gt 0 ]]; then
      _say "  ${DIM}Checking Python (${py_files[*]})...${NC}"
      local py_f=0
      for pkg in "${ALL_PKGS[@]}"; do
        local py_pkg
        py_pkg=$(echo "$pkg" | sed 's|^@[^/]*/||; s/[_-]/[_-]/g')
        for pf in "${py_files[@]}"; do
          if grep -iqE "^${py_pkg}([>=<!\[; ]|$)|['\"]${py_pkg}['\"]" "$pf" 2>/dev/null; then
            _flag_pkg "$py_pkg" "see $pf" "$pf"; py_f=$((py_f+1)); break
          fi
        done
      done
      [[ $py_f -eq 0 ]] && _clean_eco "Python (${py_files[*]})"
    else
      _skip_eco "Python"
    fi

    # Cargo
    if [[ -f "Cargo.lock" ]]; then
      _say "  ${DIM}Checking Cargo (Cargo.lock)...${NC}"
      local cargo_f=0
      for pkg in "${ALL_PKGS[@]}"; do
        local cp
        cp=$(echo "$pkg" | sed 's|^@[^/]*/||')
        if grep -iqE "^name = \"${cp}\"" Cargo.lock 2>/dev/null; then
          local ver
          ver=$(grep -A1 -iE "^name = \"${cp}\"" Cargo.lock | grep version | grep -oP '"\K[^"]+' | head -1 || echo "?")
          _flag_pkg "$cp" "$ver" "Cargo.lock"; cargo_f=$((cargo_f+1))
        fi
      done
      [[ $cargo_f -eq 0 ]] && _clean_eco "Cargo"
    elif [[ -f "Cargo.toml" ]]; then _skip_eco "Cargo"; fi

    # Go
    if [[ -f "go.mod" || -f "go.sum" ]]; then
      _say "  ${DIM}Checking Go modules...${NC}"
      local go_f=0
      for pkg in "${ALL_PKGS[@]}"; do
        local gp
        gp=$(echo "$pkg" | sed 's|^@[^/]*/||')
        for gf in go.mod go.sum; do
          [[ -f "$gf" ]] || continue
          if grep -iq "$gp" "$gf" 2>/dev/null; then
            local ver
            ver=$(grep -i "$gp" "$gf" | head -1 | grep -oP "v[0-9]+\.[0-9]+\.[0-9a-z.-]+" | head -1 || echo "see $gf")
            _flag_pkg "$gp" "$ver" "$gf"; go_f=$((go_f+1)); break
          fi
        done
      done
      [[ $go_f -eq 0 ]] && _clean_eco "Go modules"
    else _skip_eco "Go modules"; fi

    # Composer
    if [[ -f "composer.lock" ]]; then
      _say "  ${DIM}Checking Composer (composer.lock)...${NC}"
      local comp_f=0
      for pkg in "${ALL_PKGS[@]}"; do
        local cp
        cp=$(echo "$pkg" | sed 's|^@||; s|/|-|g')
        local ver
        ver=$(python3 -c "
import json,sys
try:
  d=json.load(open('composer.lock'))
  for p in d.get('packages',[])+d.get('packages-dev',[]):
    if p.get('name','').lower()==sys.argv[1].lower():
      print(p.get('version','?')); break
except:pass
" "$cp" 2>/dev/null)
        [[ -n "$ver" ]] && _flag_pkg "$cp" "$ver" "composer.lock" && comp_f=$((comp_f+1))
      done
      [[ $comp_f -eq 0 ]] && _clean_eco "Composer"
    elif [[ -f "composer.json" ]]; then _skip_eco "Composer"; fi

    # NuGet
    local nuget_present=0
    [[ -f "packages.lock.json" ]] && nuget_present=1
    compgen -G "*.csproj" > /dev/null 2>&1 && nuget_present=1 || true
    if [[ $nuget_present -eq 1 ]]; then
      _say "  ${DIM}Checking NuGet...${NC}"
      local nuget_f=0
      for pkg in "${ALL_PKGS[@]}"; do
        local np
        np=$(echo "$pkg" | sed 's|^@[^/]*/||')
        if [[ -f "packages.lock.json" ]]; then
          local ver
          ver=$(python3 -c "
import json,sys
try:
  d=json.load(open('packages.lock.json'))
  t=sys.argv[1].lower()
  for fw,deps in d.get('dependencies',{}).items():
    for name,meta in deps.items():
      if name.lower()==t:
        print(meta.get('resolved','?')); break
except:pass
" "$np" 2>/dev/null)
          [[ -n "$ver" ]] && _flag_pkg "$np" "$ver" "packages.lock.json" && nuget_f=$((nuget_f+1))
        fi
        for proj in *.csproj; do
          [[ -f "$proj" ]] || continue
          if grep -iqE "PackageReference[^>]*Include=\"${np}\"" "$proj" 2>/dev/null; then
            local ver
            ver=$(grep -iE "Include=\"${np}\"" "$proj" | grep -oP '(?i)Version="\K[^"]+' | head -1 || echo "see $proj")
            _flag_pkg "$np" "$ver" "$proj"; nuget_f=$((nuget_f+1))
          fi
        done
      done
      [[ $nuget_f -eq 0 ]] && _clean_eco "NuGet"
    else _skip_eco "NuGet"; fi

    popd > /dev/null
    [[ $dir_findings -eq 0 ]] && OK "Directory clean: $abs_dir" || WARN "$dir_findings finding(s) in $abs_dir"
  done

  local delta=$((TOTAL_FINDINGS - module_start_findings))
  MODULE_RESULTS["deps"]=$([[ $delta -eq 0 ]] && echo "CLEAN" || echo "FINDINGS:$delta")
}

# ── MODULE: IDE AUDIT ─────────────────────────────────────────────────────────
cmd_ide() {
  SECTION "IDE Extension and Plugin Audit"
  _say "  ${AMBER}Active vector: malicious IDE extensions traced to GitHub breach (May 19, 2026)${NC}"
  _say "  ${DIM}Automatically flagging any extension/plugin modified May 10-20, 2026.${NC}\n"

  local ide_start_findings=$TOTAL_FINDINGS
  local any_found=0
  local datestr
  datestr=$(date -u +%Y%m%d)

  # Reference files for find -newer date-range check (May 10-20, 2026)
  local flag_start flag_end
  flag_start=$(mktemp 2>/dev/null) || flag_start="/tmp/sct_flag_start_$$"
  flag_end=$(mktemp 2>/dev/null)   || flag_end="/tmp/sct_flag_end_$$"
  touch -t 202605100000 "$flag_start" 2>/dev/null
  touch -t 202605210000 "$flag_end"   2>/dev/null

  # List items in $1 modified in flag window; $2=maxdepth (default 1), $3=type (default d)
  _ide_recent() {
    local dir="$1" depth="${2:-1}" ftype="${3:-d}"
    [[ -d "$dir" ]] || return 0
    find "$dir" -maxdepth "$depth" -type "$ftype" \
      -newer "$flag_start" ! -newer "$flag_end" 2>/dev/null || true
  }

  # Cross-platform file mtime as YYYY-MM-DD
  _ide_mtime() {
    python3 -c "
import os,sys
from datetime import datetime
try: print(datetime.fromtimestamp(os.path.getmtime(sys.argv[1])).strftime('%Y-%m-%d'))
except: print('?')
" "$1" 2>/dev/null || echo "?"
  }

  # ── 1. VS Code / Cursor ────────────────────────────────────────────────────
  _say "  ${BOLD}[1/6] VS Code / Cursor${NC}"
  local vsc_cmd_found=0
  for vsc_cmd in code code-insiders cursor; do
    command -v "$vsc_cmd" &>/dev/null || continue
    vsc_cmd_found=1; any_found=1
    local ext_file="vscode-extensions-${datestr}.txt"
    "$vsc_cmd" --list-extensions --show-versions 2>/dev/null | sort > "$ext_file" || true
    local ext_count
    ext_count=$(wc -l < "$ext_file" | tr -d ' ')
    OK "${vsc_cmd}: ${ext_count} extension(s) saved to ${ext_file}"
  done
  for ext_dir in "${HOME}/.vscode/extensions" "${HOME}/.vscode-insiders/extensions" "${HOME}/.cursor/extensions"; do
    [[ -d "$ext_dir" ]] || continue
    any_found=1
    local recent
    recent=$(_ide_recent "$ext_dir")
    if [[ -n "$recent" ]]; then
      local cnt; cnt=$(echo "$recent" | grep -c . || true)
      WARN "VS Code/Cursor: ${cnt} extension(s) modified May 10-20 - REVIEW:"
      echo "$recent" | while IFS= read -r item; do
        _say "    ${RED}$(basename "$item")${NC}  ($(_ide_mtime "$item"))"
      done
    else
      OK "VS Code/Cursor: no extensions modified in May 10-20 window (${ext_dir})"
    fi
  done
  [[ $vsc_cmd_found -eq 0 ]] && SKIP "VS Code/Cursor: command not found (check Extensions pane manually)"
  INFO "Specifically verify publisher for: Nx Console, ESLint, Prettier, GitLens"
  _say ""

  # ── 2. JetBrains (IntelliJ, WebStorm, PyCharm, GoLand, Rider, etc.) ────────
  _say "  ${BOLD}[2/6] JetBrains IDEs${NC}"
  local jb_found=0
  for jb_root in \
    "${HOME}/.local/share/JetBrains" \
    "${HOME}/.config/JetBrains" \
    "${HOME}/Library/Application Support/JetBrains"
  do
    [[ -d "$jb_root" ]] || continue
    jb_found=1; any_found=1
    for prod_dir in "${jb_root}"/*/; do
      [[ -d "$prod_dir" ]] || continue
      local plugin_dir="${prod_dir}plugins"
      [[ -d "$plugin_dir" ]] || continue
      local plugin_count
      plugin_count=$(find "$plugin_dir" -maxdepth 1 -type d 2>/dev/null | tail -n +2 | wc -l | tr -d ' ')
      OK "$(basename "$prod_dir"): ${plugin_count} plugin(s)"
      local recent
      recent=$(_ide_recent "$plugin_dir")
      if [[ -n "$recent" ]]; then
        local cnt; cnt=$(echo "$recent" | grep -c . || true)
        WARN "$(basename "$prod_dir"): ${cnt} plugin(s) modified May 10-20 - REVIEW:"
        echo "$recent" | while IFS= read -r item; do
          _say "    ${RED}$(basename "$item")${NC}  ($(_ide_mtime "$item"))"
        done
      else
        OK "$(basename "$prod_dir"): no plugins modified in May 10-20 window"
      fi
    done
  done
  [[ $jb_found -eq 0 ]] && SKIP "JetBrains IDEs: not detected"
  [[ $jb_found -eq 1 ]] && INFO "Manual: Settings -> Plugins -> Installed -> sort by Date Updated"
  _say ""

  # ── 3. Sublime Text ───────────────────────────────────────────────────────
  _say "  ${BOLD}[3/6] Sublime Text${NC}"
  local st_found=0
  for st_dir in \
    "${HOME}/.config/sublime-text/Installed Packages" \
    "${HOME}/.config/sublime-text-3/Installed Packages" \
    "${HOME}/Library/Application Support/Sublime Text/Installed Packages" \
    "${HOME}/Library/Application Support/Sublime Text 3/Installed Packages"
  do
    [[ -d "$st_dir" ]] || continue
    st_found=1; any_found=1
    local pkg_count
    pkg_count=$(find "$st_dir" -maxdepth 1 -name '*.sublime-package' 2>/dev/null | wc -l | tr -d ' ')
    OK "Sublime Text: ${pkg_count} package(s) in ${st_dir}"
    local recent
    recent=$(_ide_recent "$st_dir" 1 f | grep '\.sublime-package$' || true)
    if [[ -n "$recent" ]]; then
      local cnt; cnt=$(echo "$recent" | grep -c . || true)
      WARN "Sublime Text: ${cnt} package(s) modified May 10-20 - REVIEW:"
      echo "$recent" | while IFS= read -r item; do
        _say "    ${RED}$(basename "$item")${NC}  ($(_ide_mtime "$item"))"
      done
    else
      OK "Sublime Text: no packages modified in May 10-20 window"
    fi
  done
  [[ $st_found -eq 0 ]] && SKIP "Sublime Text: not detected"
  [[ $st_found -eq 1 ]] && INFO "Manual: Package Control -> List Packages -> inspect modification dates"
  _say ""

  # ── 4. Vim / Neovim ───────────────────────────────────────────────────────
  _say "  ${BOLD}[4/6] Vim / Neovim${NC}"
  local vim_found=0
  for vim_dir in \
    "${HOME}/.local/share/nvim/site/pack" \
    "${HOME}/.config/nvim/pack" \
    "${HOME}/.vim/pack"
  do
    [[ -d "$vim_dir" ]] || continue
    vim_found=1; any_found=1
    local plugin_count
    plugin_count=$(find "$vim_dir" -mindepth 2 -maxdepth 3 \( -name 'start' -o -name 'opt' \) -type d 2>/dev/null | wc -l | tr -d ' ')
    OK "Vim/Neovim: ${plugin_count} pack bucket(s) in ${vim_dir}"
    local recent
    recent=$(_ide_recent "$vim_dir" 4)
    if [[ -n "$recent" ]]; then
      local cnt; cnt=$(echo "$recent" | grep -c . || true)
      WARN "Vim/Neovim: ${cnt} item(s) modified May 10-20 in ${vim_dir}:"
      echo "$recent" | head -10 | while IFS= read -r item; do
        _say "    ${RED}$(basename "$item")${NC}  ($(_ide_mtime "$item"))"
      done
    else
      OK "Vim/Neovim: no plugins modified in May 10-20 window (${vim_dir})"
    fi
  done
  [[ $vim_found -eq 0 ]] && SKIP "Vim/Neovim: not detected (no pack directory found)"
  _say ""

  # ── 5. Eclipse ────────────────────────────────────────────────────────────
  _say "  ${BOLD}[5/6] Eclipse${NC}"
  local eclipse_found=0
  for eclipse_dir in \
    "${HOME}/.p2/pool/plugins" \
    "${HOME}/eclipse/plugins" \
    "${HOME}/eclipse/jee/plugins" \
    "${HOME}/eclipse/java/plugins" \
    "${HOME}/eclipse/committers/plugins"
  do
    [[ -d "$eclipse_dir" ]] || continue
    eclipse_found=1; any_found=1
    local plugin_count
    plugin_count=$(find "$eclipse_dir" -maxdepth 1 -name '*.jar' 2>/dev/null | wc -l | tr -d ' ')
    OK "Eclipse: ${plugin_count} plugin jar(s) in ${eclipse_dir}"
    local recent
    recent=$(_ide_recent "$eclipse_dir" 1 f | grep '\.jar$' || true)
    if [[ -n "$recent" ]]; then
      local cnt; cnt=$(echo "$recent" | grep -c . || true)
      WARN "Eclipse: ${cnt} plugin jar(s) modified May 10-20 - REVIEW:"
      echo "$recent" | head -10 | while IFS= read -r item; do
        _say "    ${RED}$(basename "$item")${NC}  ($(_ide_mtime "$item"))"
      done
    else
      OK "Eclipse: no plugins modified in May 10-20 window"
    fi
  done
  [[ $eclipse_found -eq 0 ]] && SKIP "Eclipse: not detected"
  [[ $eclipse_found -eq 1 ]] && INFO "Manual: Help -> About Eclipse -> Installation Details -> check dates"
  _say ""

  # ── 6. Atom ───────────────────────────────────────────────────────────────
  _say "  ${BOLD}[6/6] Atom${NC}"
  local atom_dir="${HOME}/.atom/packages"
  if [[ -d "$atom_dir" ]]; then
    any_found=1
    local pkg_count
    pkg_count=$(find "$atom_dir" -maxdepth 1 -type d 2>/dev/null | tail -n +2 | wc -l | tr -d ' ')
    OK "Atom: ${pkg_count} package(s)"
    local recent
    recent=$(_ide_recent "$atom_dir")
    if [[ -n "$recent" ]]; then
      local cnt; cnt=$(echo "$recent" | grep -c . || true)
      WARN "Atom: ${cnt} package(s) modified May 10-20 - REVIEW:"
      echo "$recent" | while IFS= read -r item; do
        _say "    ${RED}$(basename "$item")${NC}  ($(_ide_mtime "$item"))"
      done
    else
      OK "Atom: no packages modified in May 10-20 window"
    fi
    INFO "Note: Atom is end-of-life (Dec 2022) — migrate to VS Code"
  else
    SKIP "Atom: not detected"
  fi
  _say ""

  # ── Universal checklist ───────────────────────────────────────────────────
  _say "${BOLD}  Universal checklist for all IDEs:${NC}"
  _say "  [ ]  Filter extension/plugin list to 'Recently Updated' -> flag May 10-20 entries"
  _say "  [ ]  Verify publisher identity for each flagged item (not just display name)"
  _say "  [ ]  Disable auto-update across all IDEs until incident window closes"
  _say "  [ ]  VS Code specifically: verify Nx Console, ESLint, Prettier, GitLens"
  _say ""

  rm -f "$flag_start" "$flag_end"

  local delta=$((TOTAL_FINDINGS - ide_start_findings))
  MODULE_RESULTS["ide"]=$([[ $delta -gt 0 ]] && echo "FINDINGS:$delta" || echo "CHECKLIST")
}

# ── MODULE: PLATFORM AUDIT (CHECKLIST) ────────────────────────────────────────
cmd_platform() {
  SECTION "DevOps Platform Audit Checklist"
  _say "  Complete each item in your ADO/GitHub org. Mark done as you go.\n"

  _say "${BOLD}Azure DevOps${NC}"
  _say "  [ ]  ${BRED}[CRITICAL]${NC}  Org Audit Log — filter April 29 to today"
  _say "        https://dev.azure.com/{org}/_settings/audit"
  _say "  [ ]  ${BRED}[CRITICAL]${NC}  Revoke ALL PATs → regenerate minimum-scope"
  _say "  [ ]  ${RED}[HIGH]${NC}     Service Connections — verify no post-April-29 additions"
  _say "  [ ]  ${RED}[HIGH]${NC}     Variable Groups — rotate any modified post-April-29"
  _say "  [ ]  ${AMBER}[MED]${NC}      Pipeline run history May 10-20 — flag anomalies"
  _say "  [ ]  ${RED}[HIGH]${NC}     Search pipeline run logs (May 10-20) for outbound HTTPS to getsession.org or git-tanstack.com"

  _say "\n${BOLD}GitHub${NC}"
  _say "  [ ]  ${BRED}[CRITICAL]${NC}  Security Log — filter oauth_access, PAT creation May 10-20"
  _say "        github.com → Settings → Security log"
  _say "  [ ]  ${BRED}[CRITICAL]${NC}  Revoke ALL PATs (classic + fine-grained) → regenerate"
  _say "  [ ]  ${RED}[HIGH]${NC}     Authorized OAuth Apps — revoke write:packages or repo scope apps"
  _say "  [ ]  ${RED}[HIGH]${NC}     Org Audit log → filter fork, pull_request → look for 'zblgg'"
  _say "  [ ]  ${RED}[HIGH]${NC}     Actions secrets → rotate all regardless of triage result"
  _say "  [ ]  ${RED}[HIGH]${NC}     Search commits/PRs for author 'voicproducoes' or email 'voicproducoes@gmail.com'"
  _say "  [ ]  ${RED}[HIGH]${NC}     Search commits for author 'claude@users.noreply.github.com' (malware self-commit marker)"
  _say "  [ ]  ${RED}[HIGH]${NC}     Check for branches matching 'dependabot/github_actions/format/*' (attacker branch pattern)"
  _say "  [ ]  ${RED}[HIGH]${NC}     Audit .github/workflows/ for injected 'codeql_analysis.yml' added after May 10"
  _say "  [ ]  ${BRED}[CRITICAL]${NC}  WARNING: Do NOT revoke npm tokens before isolating affected machine — payload contains destructive wipe triggered by revocation"
  MODULE_RESULTS["platform"]="CHECKLIST"
}

# ── MODULE: HARDENING ─────────────────────────────────────────────────────────
cmd_harden() {
  SECTION "Hardening Configurations"

  _say "\n${BOLD}1. Project .npmrc${NC} (add to every project root)"
  _say "${DIM}───────────────────────────────${NC}"
  cat << 'NPMRC'
ignore-scripts=true
audit=true
fund=false
package-lock=true
NPMRC

  _say "\n${BOLD}2. package.json — pnpm block${NC}"
  _say "${DIM}───────────────────────────────${NC}"
  cat << 'PNPM'
{
  "pnpm": {
    "onlyBuiltDependencies": ["esbuild", "node-gyp", "sharp"],
    "minimumReleaseAge": "3 days",
    "blockExoticSubdeps": true
  }
}
PNPM

  _say "\n${BOLD}3. GitHub Actions — pin action refs to SHA${NC}"
  _say "${DIM}───────────────────────────────${NC}"
  cat << 'ACTIONS'
# BEFORE (tag mutation attack surface):
- uses: actions/checkout@v4

# AFTER (immutable SHA reference):
- uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683  # v4.2.2

# Auto-pin tool:
npx pin-github-action .github/workflows/*.yml
# Or: https://app.stepsecurity.io
ACTIONS

  _say "\n${BOLD}4. Pipeline install commands${NC}"
  _say "${DIM}───────────────────────────────${NC}"
  cat << 'INSTALL'
# npm CI (add --ignore-scripts):
npm ci --ignore-scripts

# pnpm install (add --ignore-scripts):
pnpm install --frozen-lockfile --ignore-scripts

# pip (add --no-deps for untrusted extras):
pip install -r requirements.txt --no-deps
INSTALL

  _say "\n${BOLD}5. IOC DNS block${NC}"
  _say "${DIM}───────────────────────────────${NC}"
  _say "  Block at firewall/DNS:"
  _say "    zero.masscan.cloud | api.masscan.cloud | 94.154.172.43"
  _say "    filev2.getsession.org | seed1.getsession.org | seed2.getsession.org | seed3.getsession.org"
  _say "    git-tanstack.com | litter.catbox.moe"
  MODULE_RESULTS["harden"]="DONE"
}

# ── FINAL SUMMARY ─────────────────────────────────────────────────────────────
print_summary() {
  _say ""
  HR
  _say "${BCYAN}${BOLD}  SCT TRIAGE SUMMARY${NC}"
  HR
  _say "  Host:    $(hostname)"
  _say "  User:    $(whoami)"
  _say "  Ran:     $(date -u)"
  _say "  IOCs:    ${#ALL_IOCS[@]} | Secret patterns: ${#ALL_PATTERNS[@]} | Packages: ${#ALL_PKGS[@]}"
  _say "  Findings: ${TOTAL_FINDINGS} | Warnings: ${TOTAL_WARNS}"
  _say ""

  for module in machine deps ide platform harden; do
    [[ -v MODULE_RESULTS[$module] ]] || continue
    local result="${MODULE_RESULTS[$module]}"
    local label
    label=$(printf "  %-12s" "[$module]")
    if [[ "$result" == "CLEAN" ]]; then
      _say "${label} ${GREEN}CLEAN${NC}"
    elif [[ "$result" =~ ^FINDINGS ]]; then
      _say "${label} ${BRED}${result}${NC}"
    else
      _say "${label} ${DIM}${result}${NC}"
    fi
  done

  _say ""
  if [[ $TOTAL_FINDINGS -eq 0 ]]; then
    _say "  ${GREEN}${BOLD}Result: ALL CLEAR — no IOC hits or secret exposures detected.${NC}"
    _say "  ${DIM}Apply hardening configs and rotate secrets preventatively.${NC}"
  else
    _say "  ${BRED}${BOLD}Result: $TOTAL_FINDINGS FINDING(S) — ESCALATE IMMEDIATELY.${NC}"
    _say "  ${RED}Isolate affected machines, rotate ALL org credentials, open DefectDojo incident.${NC}"
  fi

  [[ -n "$OUTPUT_FILE" ]] && _say "\n  ${DIM}Report written to: $OUTPUT_FILE${NC}"
  HR
  _say ""
}

# ── INTERACTIVE MENU ──────────────────────────────────────────────────────────
show_menu() {
  while true; do
    banner
    _say "  ${BOLD}Select a scan module:${NC}\n"
    _say "  ${CYAN}[1]${NC}  Full Triage      — machine scan + dependency audit"
    _say "  ${CYAN}[2]${NC}  Machine Scan     — IOCs, secrets, shell history, git history"
    _say "  ${CYAN}[3]${NC}  Dependency Audit — npm, pnpm, yarn, pip, cargo, go, composer, nuget"
    _say "  ${CYAN}[4]${NC}  IDE Audit        — VS Code, JetBrains, Sublime, Vim/Neovim, Eclipse, Atom"
    _say "  ${CYAN}[5]${NC}  Platform Checklist — ADO / GitHub audit guidance"
    _say "  ${CYAN}[6]${NC}  Hardening        — print .npmrc, pnpm, pipeline configs"
    _say ""
    _say "  ${DIM}[h]${NC}  Help  ·  ${DIM}[0]${NC}  Exit"
    _say ""
    read -rp "  Select [0-6, h]: " choice

    case "$choice" in
      0) _say "\n  Exiting. Stay safe.\n"; exit 0 ;;
      h) show_help; read -rp "  Press Enter to return to menu..." _; continue ;;
      1) collect_params "all";     build_patterns; cmd_machine; cmd_deps;   print_summary; read -rp "Press Enter..." _; ;;
      2) collect_params "machine"; build_patterns; cmd_machine;             print_summary; read -rp "Press Enter..." _; ;;
      3) collect_params "deps";    build_patterns; cmd_deps;               print_summary; read -rp "Press Enter..." _; ;;
      4) build_patterns; cmd_ide;                                           print_summary; read -rp "Press Enter..." _; ;;
      5) build_patterns; cmd_platform;                                      print_summary; read -rp "Press Enter..." _; ;;
      6) build_patterns; cmd_harden;                                        read -rp "Press Enter..." _; ;;
      *) _say "  ${AMBER}Invalid choice.${NC}" ;;
    esac
  done
}

# ── ENTRY POINT ───────────────────────────────────────────────────────────────
main() {
  parse_args "$@"
  build_patterns

  if [[ -n "$OUTPUT_FILE" ]]; then
    exec > >(tee -a "$OUTPUT_FILE") 2>&1
  fi

  if [[ -z "$SCT_COMMAND" ]]; then
    show_menu
  else
    banner
    case "$SCT_COMMAND" in
      all)      cmd_machine; cmd_deps ;;
      machine)  cmd_machine ;;
      deps)     cmd_deps ;;
      ide)      cmd_ide ;;
      platform) cmd_platform ;;
      harden)   cmd_harden ;;
    esac
    print_summary
    [[ $TOTAL_FINDINGS -gt 0 ]] && exit 1 || exit 0
  fi
}

main "$@"
