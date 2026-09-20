#!/usr/bin/env bash
#
# Local HTTPS for development: some OAuth providers (Cloudflare, possibly Vercel) refuse an http://
# redirect URL, and the OAuth cookie needs the dashboard and the API on the same scheme.
#
#   scripts/local_https.sh setup     make the certificates (once) and trust them in Chrome
#   scripts/local_https.sh untrust   remove the trust again
#   scripts/local_https.sh status
#
# What it creates, and why it is safe to trust:
#   * A private CA in .certs/ whose certificate carries a NAME CONSTRAINT: it may only vouch for
#     `localhost`, 127.0.0.1 and ::1. Even if .certs/ca.key were stolen it could not be used to
#     impersonate any other site to this browser. The key is mode 600 and .certs/ is git-ignored.
#   * A server certificate for localhost signed by that CA (397 days, Chrome's maximum).
#   * The CA is added to Chrome's certificate store for THIS USER (~/.pki/nssdb). Nothing system-wide,
#     no sudo. Firefox keeps its own store: import .certs/ca.pem there by hand if you use it.

set -Eeuo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CERTS="${CERBERUS_CERTS_DIR:-$ROOT/.certs}"          # overridable so the script can be tested away from the real store
NSSDIR="${CERBERUS_NSSDB_DIR:-$HOME/.pki/nssdb}"
NSSDB="sql:$NSSDIR"
NICK="Cerberus local dev CA (localhost only)"

need() { command -v "$1" >/dev/null 2>&1 || { echo "error: $1 is required" >&2; exit 1; }; }

make_ca() {
  openssl ecparam -name prime256v1 -genkey -noout -out "$CERTS/ca.key"
  chmod 600 "$CERTS/ca.key"
  openssl req -x509 -new -key "$CERTS/ca.key" -sha256 -days 825 \
    -subj "/CN=$NICK" -out "$CERTS/ca.pem" \
    -addext "basicConstraints=critical,CA:TRUE,pathlen:0" \
    -addext "keyUsage=critical,keyCertSign,cRLSign" \
    -addext "nameConstraints=critical,permitted;DNS:localhost,permitted;IP:127.0.0.1/255.255.255.255,permitted;IP:::1/ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"
}

make_server_cert() {
  openssl ecparam -name prime256v1 -genkey -noout -out "$CERTS/localhost.key"
  chmod 600 "$CERTS/localhost.key"
  openssl req -new -key "$CERTS/localhost.key" -subj "/CN=localhost" -out "$CERTS/localhost.csr"
  cat > "$CERTS/localhost.ext" <<'EOF'
subjectAltName=DNS:localhost,IP:127.0.0.1,IP:::1
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature
extendedKeyUsage=serverAuth
EOF
  openssl x509 -req -in "$CERTS/localhost.csr" -CA "$CERTS/ca.pem" -CAkey "$CERTS/ca.key" \
    -CAcreateserial -out "$CERTS/localhost.pem" -days 397 -sha256 -extfile "$CERTS/localhost.ext" 2>/dev/null
  rm -f "$CERTS/localhost.csr" "$CERTS/localhost.ext" "$CERTS/ca.srl"
}

valid_for() { # valid_for FILE DAYS: true if the certificate is still good for DAYS more days
  openssl x509 -in "$1" -noout -checkend $(( $2 * 86400 )) >/dev/null 2>&1
}

trusted() { certutil -L -d "$NSSDB" 2>/dev/null | grep -qF "$NICK"; }

cmd_setup() {
  need openssl; need certutil
  mkdir -p "$CERTS"; chmod 700 "$CERTS"

  if [ ! -f "$CERTS/ca.pem" ] || ! valid_for "$CERTS/ca.pem" 30; then
    echo "creating the local CA"
    rm -f "$CERTS"/*
    make_ca
  fi
  if [ ! -f "$CERTS/localhost.pem" ] || ! valid_for "$CERTS/localhost.pem" 14; then
    echo "creating the localhost certificate"
    make_server_cert
  fi

  if ! trusted; then
    [ -f "$NSSDIR/cert9.db" ] || { mkdir -p "$NSSDIR"; certutil -N -d "$NSSDB" --empty-password; }
    certutil -A -d "$NSSDB" -t "C,," -n "$NICK" -i "$CERTS/ca.pem"
    echo "trusted in Chrome for this user (restart Chrome if it was already open)"
  fi
  echo "ok: $CERTS/localhost.pem"
}

cmd_untrust() {
  need certutil
  if trusted; then certutil -D -d "$NSSDB" -n "$NICK" && echo "removed from Chrome's certificate store"
  else echo "not trusted"; fi
  echo "(the files in $CERTS remain; delete that folder to remove them)"
}

cmd_status() {
  if [ -f "$CERTS/localhost.pem" ]; then
    openssl x509 -in "$CERTS/localhost.pem" -noout -enddate | sed 's/^/certificate /'
  else echo "no certificate yet"; fi
  if trusted; then echo "trusted in Chrome"; else echo "not trusted in Chrome"; fi
}

case "${1:-setup}" in
  setup) cmd_setup ;;
  untrust) cmd_untrust ;;
  status) cmd_status ;;
  *) echo "usage: $0 setup|untrust|status" >&2; exit 2 ;;
esac
