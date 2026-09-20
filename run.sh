#!/usr/bin/env bash
#
# Cerberus - one script to run everything.
#
#   ./run.sh              set up if needed, then start the API and the dashboard
#   ./run.sh help         every command
#
# Design notes, because two of these were learned the hard way:
#   * It only ever stops processes it started (PID files in .run/). `pkill -f uvicorn` would kill
#     another project's API - or, if the pattern appears in the command line, this script itself.
#   * A port held by something else is reported, never taken. You are told what holds it.
#   * Secrets are generated into .env, never printed and never passed on a command line (the
#     command line of a process is readable by every user on the machine).

set -Eeuo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT"

VENV="$ROOT/.venv"
PY="$VENV/bin/python"
RUN_DIR="$ROOT/.run"
LOG_DIR="$RUN_DIR/logs"
API_PORT="${API_PORT:-8000}"
WEB_PORT="${WEB_PORT:-5173}"
API_URL="http://localhost:$API_PORT"
WEB_URL="http://localhost:$WEB_PORT"

# Colour only when a terminal is attached, so piping to a file stays readable.
if [ -t 1 ]; then
  BOLD=$'\033[1m'; DIM=$'\033[2m'; RED=$'\033[31m'; GREEN=$'\033[32m'; YELLOW=$'\033[33m'; OFF=$'\033[0m'
else
  BOLD=""; DIM=""; RED=""; GREEN=""; YELLOW=""; OFF=""
fi

say()  { printf '%s\n' "${BOLD}==>${OFF} $*"; }
info() { printf '%s\n' "    $*"; }
warn() { printf '%s\n' "${YELLOW}warning:${OFF} $*" >&2; }
die()  { printf '%s\n' "${RED}error:${OFF} $*" >&2; exit 1; }

mkdir -p "$LOG_DIR"

# --- small helpers -----------------------------------------------------------------------

# Every lookup below must succeed even when it finds nothing: under `set -e` with `pipefail`, a
# grep that matches nothing would otherwise end the script mid-sentence.
port_pid() { # the pid listening on a port, if any
  local port="$1"
  {
    if command -v ss >/dev/null 2>&1; then
      ss -ltnp 2>/dev/null | awk -v p=":$port\$" '$4 ~ p {print $NF}' |
        grep -o 'pid=[0-9]*' | head -1 | cut -d= -f2
    else
      lsof -ti ":$port" -sTCP:LISTEN 2>/dev/null | head -1
    fi
  } || true
}

pid_command() { ps -p "$1" -o args= 2>/dev/null | head -c 100 || true; }

running() { # true if the PID file names a live process
  local pid_file="$RUN_DIR/$1.pid"
  [ -f "$pid_file" ] && kill -0 "$(cat "$pid_file")" 2>/dev/null
}

wait_for_http() { # wait_for_http URL SECONDS
  local url="$1" deadline=$((SECONDS + ${2:-30}))
  while [ $SECONDS -lt $deadline ]; do
    curl -fsS -o /dev/null "$url" 2>/dev/null && return 0
    sleep 0.3
  done
  return 1
}

need_venv() {
  [ -x "$PY" ] || die "no virtualenv yet. Run: ./run.sh setup"
}

count() { # count users | count unowned_scans -> a number, or 0 if anything goes wrong
  "$PY" - "$1" <<'EOF' 2>/dev/null || echo 0
import sys
from sqlalchemy import func, select
from core.db import session_scope
from core.models import Scan, User

with session_scope() as session:
    if sys.argv[1] == "users":
        stmt = select(func.count()).select_from(User)
    else:
        stmt = select(func.count()).select_from(Scan).where(Scan.user_id.is_(None))
    print(session.scalar(stmt) or 0)
EOF
}

# --- environment -------------------------------------------------------------------------

ensure_env() {
  if [ ! -f .env ]; then
    say "Creating .env"
    if [ -f .env.example ]; then cp .env.example .env; else : > .env; fi
  fi

  # API_SECRET_KEY signs every sign-in token. Generated here so no real deployment ever runs on a
  # value that shipped in the repository.
  local current
  current="$(grep -E '^API_SECRET_KEY=' .env | head -1 | cut -d= -f2- || true)"
  if [ -z "$current" ] || [ "$current" = "change-me" ] || [ "${#current}" -lt 32 ]; then
    local generated
    generated="$(openssl rand -hex 24 2>/dev/null || "$PY" -c 'import secrets;print(secrets.token_hex(24))')"
    if grep -qE '^API_SECRET_KEY=' .env; then
      # A temp file, not `sed -i`: .env holds secrets, and this never leaves them world-readable.
      local tmp; tmp="$(mktemp)"; chmod 600 "$tmp"
      grep -vE '^API_SECRET_KEY=' .env > "$tmp"
      printf 'API_SECRET_KEY=%s\n' "$generated" >> "$tmp"
      mv "$tmp" .env
    else
      printf 'API_SECRET_KEY=%s\n' "$generated" >> .env
    fi
    chmod 600 .env
    say "Generated a new API_SECRET_KEY in .env ${DIM}(this signs out anyone signed in before)${OFF}"
  fi

  # PROVIDER_TOKEN_ENCRYPTION_KEY encrypts the Vercel/Netlify/Cloudflare tokens at rest. Only ever filled
  # in when empty: replacing a key that exists would make every stored token unreadable.
  local enc
  enc="$(grep -E '^PROVIDER_TOKEN_ENCRYPTION_KEY=' .env | head -1 | cut -d= -f2- || true)"
  if [ -z "$enc" ]; then
    local key
    key="$("$PY" -c 'from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())' 2>/dev/null || true)"
    if [ -n "$key" ]; then
      local tmp; tmp="$(mktemp)"; chmod 600 "$tmp"
      grep -vE '^PROVIDER_TOKEN_ENCRYPTION_KEY=' .env > "$tmp"
      printf 'PROVIDER_TOKEN_ENCRYPTION_KEY=%s\n' "$key" >> "$tmp"
      mv "$tmp" .env
      chmod 600 .env
      say "Generated a PROVIDER_TOKEN_ENCRYPTION_KEY in .env ${DIM}(back it up: without it, stored provider tokens cannot be read)${OFF}"
    fi
  fi

  if ! grep -qE '^CORS_ORIGINS=' .env; then
    printf 'CORS_ORIGINS=http://localhost:%s,http://127.0.0.1:%s\n' "$WEB_PORT" "$WEB_PORT" >> .env
  fi
}

# --- setup -------------------------------------------------------------------------------

cmd_setup() {
  if [ ! -x "$PY" ]; then
    say "Creating the virtualenv"
    python3 -m venv "$VENV"
  fi
  say "Installing Python dependencies"
  "$PY" -m pip install --quiet --upgrade pip
  "$PY" -m pip install --quiet -r requirements.txt

  ensure_env

  say "Creating or upgrading the database"
  "$PY" scripts/init_db.py

  if [ ! -d frontend/node_modules ]; then
    command -v npm >/dev/null 2>&1 || die "npm is not installed. Install Node 18 or newer."
    say "Installing dashboard dependencies"
    (cd frontend && npm install --silent)
  fi

  # KEV/EPSS is what makes the ranking mean anything: without it every finding scores as "nobody is
  # exploiting this", which silently inverts the results. Fetch it if it has never been fetched.
  if ! "$PY" - <<'EOF' >/dev/null 2>&1
import sys
from sqlalchemy import select
from core.db import session_scope
from core.models import SourceRefresh
with session_scope() as s:
    sys.exit(0 if s.scalar(select(SourceRefresh).where(SourceRefresh.name == "kev")) else 1)
EOF
  then
    say "Loading exploitation data (CISA KEV + EPSS, about 30 seconds)"
    "$PY" scripts/refresh_enrichment.py
  fi

  say "${GREEN}Ready.${OFF} Start it with: ./run.sh"
}

ensure_setup() { # the quiet version, run before starting anything
  [ -x "$PY" ] || { say "First run: setting up"; cmd_setup; return; }
  [ -d frontend/node_modules ] || { say "Dashboard dependencies are missing"; cmd_setup; return; }
  ensure_env
  "$PY" scripts/init_db.py >/dev/null
}

# --- starting and stopping ----------------------------------------------------------------

start_one() { # start_one NAME PORT COMMAND...
  local name="$1" port="$2"; shift 2
  local log="$LOG_DIR/$name.log"

  if running "$name"; then
    info "$name is already running (pid $(cat "$RUN_DIR/$name.pid"))"
    return 0
  fi

  local holder; holder="$(port_pid "$port")"
  if [ -n "$holder" ]; then
    warn "port $port is held by pid $holder: $(pid_command "$holder")"
    if [ "$name" = "api" ]; then
      die "Stop it first (./run.sh stop, or close that terminal), or set API_PORT to another port."
    else
      die "Stop it first (./run.sh stop, or close that terminal), or set WEB_PORT to another port."
    fi
  fi

  : > "$log"
  nohup "$@" >>"$log" 2>&1 &
  local pid=$!
  disown "$pid" 2>/dev/null || true
  echo "$pid" > "$RUN_DIR/$name.pid"
}

stop_one() {
  local name="$1" pid_file="$RUN_DIR/$1.pid"
  [ -f "$pid_file" ] || return 0
  local pid; pid="$(cat "$pid_file")"
  if kill -0 "$pid" 2>/dev/null; then
    # The child may have children of its own (vite, uvicorn reloader), so signal the group.
    kill -TERM -- "-$(ps -o pgid= "$pid" | tr -d ' ')" 2>/dev/null || kill -TERM "$pid" 2>/dev/null || true
    for _ in $(seq 1 20); do kill -0 "$pid" 2>/dev/null || break; sleep 0.25; done
    kill -KILL "$pid" 2>/dev/null || true
    info "stopped $name (pid $pid)"
  fi
  rm -f "$pid_file"
}

cmd_stop() {
  say "Stopping"
  stop_one web
  stop_one api
  info "done"
}

cmd_api() {
  ensure_setup
  say "Starting the API"
  start_one api "$API_PORT" "$VENV/bin/uvicorn" api.main:app --host 127.0.0.1 --port "$API_PORT"
  if wait_for_http "$API_URL/healthz" 30; then
    info "${GREEN}API${OFF}       $API_URL   ${DIM}(docs at $API_URL/docs)${OFF}"
  else
    warn "the API did not come up; last lines of its log:"
    tail -n 15 "$LOG_DIR/api.log" >&2
    stop_one api
    die "see $LOG_DIR/api.log"
  fi
}

cmd_web() {
  ensure_setup
  command -v npm >/dev/null 2>&1 || die "npm is not installed. Install Node 18 or newer."
  say "Starting the dashboard"
  start_one web "$WEB_PORT" npm --prefix frontend run dev -- --port "$WEB_PORT" --strictPort
  if wait_for_http "$WEB_URL" 45; then
    info "${GREEN}Dashboard${OFF} $WEB_URL"
  else
    warn "the dashboard did not come up; last lines of its log:"
    tail -n 15 "$LOG_DIR/web.log" >&2
    stop_one web
    die "see $LOG_DIR/web.log"
  fi
}

cmd_start() {
  ensure_setup
  cmd_api
  cmd_web

  echo
  if [ "$(count users)" = "0" ]; then
    say "Open $WEB_URL and create an account."
    info "Then add a domain you own, publish the DNS record it shows you, and scan it."
    local unowned; unowned="$(count unowned_scans)"
    if [ "$unowned" != "0" ]; then
      info "${YELLOW}$unowned earlier scan(s) have no owner${OFF} (they predate accounts, or came from the CLI)."
      info "After signing up:  ./run.sh claim your@email"
    fi
  else
    say "Open $WEB_URL"
  fi
  echo
  info "${DIM}logs:  ./run.sh logs        stop:  ./run.sh stop        state: ./run.sh status${OFF}"
}

# --- everything else -----------------------------------------------------------------------

cmd_status() {
  local api_pid web_pid
  api_pid="$(port_pid "$API_PORT")"; web_pid="$(port_pid "$WEB_PORT")"
  printf '%s\n' "${BOLD}Cerberus${OFF}"
  if [ -n "$api_pid" ]; then
    printf '  API        %srunning%s  %s  pid %s%s\n' "$GREEN" "$OFF" "$API_URL" "$api_pid" \
      "$(running api || printf ' (not started by this script)')"
  else
    printf '  API        %sstopped%s\n' "$DIM" "$OFF"
  fi
  if [ -n "$web_pid" ]; then
    printf '  Dashboard  %srunning%s  %s  pid %s%s\n' "$GREEN" "$OFF" "$WEB_URL" "$web_pid" \
      "$(running web || printf ' (not started by this script)')"
  else
    printf '  Dashboard  %sstopped%s\n' "$DIM" "$OFF"
  fi
  if [ -x "$PY" ]; then
    local data
    data="$("$PY" cerberus.py status 2>/dev/null | grep -E '^assets:' | head -1 || true)"
    printf '  Data       %s\n' "${data:-unavailable}"
  fi
  if command -v docker >/dev/null 2>&1 && docker ps --filter label=cerberus.lab=true --format '{{.Names}}' 2>/dev/null | grep -q .; then
    printf '  Lab        %srunning%s  127.0.0.1:18081, 127.0.0.1:18082\n' "$GREEN" "$OFF"
  fi
}

cmd_logs() {
  local which="${1:-all}"
  case "$which" in
    api) tail -n 50 -f "$LOG_DIR/api.log" ;;
    web) tail -n 50 -f "$LOG_DIR/web.log" ;;
    *)   tail -n 25 -f "$LOG_DIR"/*.log ;;
  esac
}

cmd_test() {
  need_venv
  say "Python tests"
  "$PY" -m pytest -q
  say "Lint"
  "$VENV/bin/ruff" check .
  say "Dashboard type-check and build"
  (cd frontend && npm run build --silent)
  say "${GREEN}All green.${OFF}"
  info "The browser test needs a running API on a copy of the database; see frontend/README.md."
}

cmd_scan() {
  need_venv
  [ $# -ge 1 ] || die "usage: ./run.sh scan <domain> [--owner you@example.com] [other cerberus.py flags]"
  say "Scanning $1"
  info "${DIM}Only scan a domain you own or have written permission to test.${OFF}"
  "$PY" cerberus.py scan --target "$@" --authorized
}

cmd_claim() {
  need_venv
  [ $# -eq 1 ] || die "usage: ./run.sh claim you@example.com"
  "$PY" scripts/claim_legacy.py "$1"
}

cmd_enrich() {
  need_venv
  say "Refreshing CISA KEV + EPSS"
  "$PY" scripts/refresh_enrichment.py
}

cmd_lab() {
  command -v docker >/dev/null 2>&1 || die "docker is not installed."
  case "${1:-up}" in
    up)
      say "Starting the vulnerable lab ${DIM}(loopback only)${OFF}"
      docker compose -f lab/docker-compose.yml up -d
      info "Apache 2.4.49 at 127.0.0.1:18081, Apache 2.4.50 at 127.0.0.1:18082"
      info "Scan it with:  ./run.sh lab scan"
      ;;
    down)
      say "Stopping the lab"
      docker compose -f lab/docker-compose.yml down
      ;;
    scan)
      need_venv
      say "Scanning the lab ${DIM}(about 15 minutes with the safe profile)${OFF}"
      # --allow-private is a CLI-only flag by design: the API must never be steerable at loopback.
      "$PY" cerberus.py scan --target 127.0.0.1 --authorized --allow-private \
        --no-subdomains --ports 18081,18082 "${@:2}"
      ;;
    *) die "usage: ./run.sh lab [up|down|scan]" ;;
  esac
}

cmd_help() {
  cat <<EOF
${BOLD}Cerberus${OFF} - attack surface and exploitability intelligence

  ${BOLD}./run.sh${OFF}                  set up if needed, then start the API and dashboard
  ${BOLD}./run.sh stop${OFF}             stop both (only what this script started)
  ${BOLD}./run.sh status${OFF}           what is running, and how much data there is
  ${BOLD}./run.sh logs${OFF} [api|web]   follow the logs

  ${BOLD}./run.sh setup${OFF}            install dependencies, create .env and the database
  ${BOLD}./run.sh api${OFF}              the API only
  ${BOLD}./run.sh web${OFF}              the dashboard only
  ${BOLD}./run.sh test${OFF}             tests, lint and the dashboard build

  ${BOLD}./run.sh scan${OFF} <domain>    scan from the command line (you attest authorization)
  ${BOLD}./run.sh claim${OFF} <email>    give scans that have no owner to an account
  ${BOLD}./run.sh enrich${OFF}           refresh CISA KEV + EPSS (do this daily)
  ${BOLD}./run.sh lab${OFF} [up|down|scan]   the local vulnerable target (Docker, loopback only)

Ports: API_PORT=$API_PORT WEB_PORT=$WEB_PORT (override in the environment)
Logs:  $LOG_DIR
EOF
}

case "${1:-start}" in
  ""|start|up|dev) shift || true; cmd_start ;;
  setup|install)   shift || true; cmd_setup ;;
  api|backend)     shift || true; cmd_api ;;
  web|frontend|ui) shift || true; cmd_web ;;
  stop|down)       shift || true; cmd_stop ;;
  restart)         shift || true; cmd_stop; cmd_start ;;
  status|ps)       shift || true; cmd_status ;;
  logs|log)        shift || true; cmd_logs "$@" ;;
  test|check)      shift || true; cmd_test ;;
  scan)            shift || true; cmd_scan "$@" ;;
  claim)           shift || true; cmd_claim "$@" ;;
  enrich)          shift || true; cmd_enrich ;;
  lab)             shift || true; cmd_lab "$@" ;;
  help|-h|--help)  cmd_help ;;
  *) printf '%sunknown command:%s %s\n\n' "$RED" "$OFF" "$1" >&2; cmd_help >&2; exit 2 ;;
esac
