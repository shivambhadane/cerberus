#!/usr/bin/env python3
"""Create the Cloudflare OAuth client for Cerberus over Cloudflare's API.

Why this exists: Cloudflare's dashboard form for OAuth clients refuses to submit for reasons it does not
explain, and the identifiers of its Pages scopes are not published anywhere. Both problems go away over the
API, which lists the scopes your account actually has and creates the client in one call.

You need a Cloudflare API token with the **OAuth Clients Write** permission
(https://dash.cloudflare.com/profile/api-tokens -> Create Token -> Custom token).

The API token is read from a hidden prompt, used only for these calls, and is never stored, logged or
printed. The client secret Cloudflare returns is written straight into .env and never shown on screen.

    python scripts/setup_cloudflare_oauth.py
"""

from __future__ import annotations

import getpass
import json
import os
import pathlib
import re
import sys
import urllib.error
import urllib.request

ROOT = pathlib.Path(__file__).resolve().parent.parent
ENV = ROOT / ".env"
API = "https://api.cloudflare.com/client/v4"

# What Cerberus calls: the account list, and Pages projects. Nothing that writes.
WANTED = ("pages", "account")
ALWAYS = ("openid", "offline_access")


class Refused(Exception):
    """Cloudflare answered with an error. `status` is the HTTP status, `code` Cloudflare's own error code."""

    def __init__(self, message: str, status: int = 0, code: str = ""):
        super().__init__(message)
        self.status = status
        self.code = code


def call(path: str, token: str, method: str = "GET", body: dict | None = None, fatal: bool = True) -> dict:
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(f"{API}{path}", data=data, method=method)
    req.add_header("Authorization", f"Bearer {token}")
    req.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            return json.loads(r.read())
    except urllib.error.HTTPError as e:
        detail = e.read().decode(errors="replace")[:600]
        code = ""
        try:
            errs = json.loads(detail).get("errors", [])
            code = str(errs[0].get("code", "")) if errs else ""
            detail = "; ".join(f"{x.get('code')}: {x.get('message')}" for x in errs) or detail
        except Exception:
            pass
        message = f"Cloudflare refused {method} {path} ({e.code}): {detail}"
        if fatal:
            sys.exit(f"\n{message}")
        raise Refused(message, e.code, code) from None
    except urllib.error.URLError as e:
        sys.exit(f"\nCould not reach Cloudflare: {e.reason}")


def clean(raw: str) -> str:
    """What a paste brings along: the terminal's bracketed-paste markers, quotes, whitespace."""
    return re.sub(r"\x1b\[20[01]~", "", raw).strip().strip("\"'").strip()


def read_token() -> str:
    """The API token, from $CLOUDFLARE_API_TOKEN, else a prompt. A hidden prompt shows nothing at all, so
    the length received is printed: it is the only way to tell a paste that worked from one that did not."""
    token = clean(os.environ.get("CLOUDFLARE_API_TOKEN", ""))
    if token:
        print(f"token: received {len(token)} characters from $CLOUDFLARE_API_TOKEN")
        return token
    visible = "--visible" in sys.argv
    prompt = "Cloudflare API token (OAuth Clients Edit): "
    token = clean(input(prompt) if visible else getpass.getpass(prompt.replace(": ", " (hidden): ")))
    if not token:
        sys.exit(
            "\nNothing was received, so the paste did not reach the prompt. Two ways around it:\n"
            "  1. Read it in the shell instead, then run this script:\n"
            "       read -rs -p 'Cloudflare token: ' CLOUDFLARE_API_TOKEN; echo\n"
            "       export CLOUDFLARE_API_TOKEN\n"
            "       python3 scripts/setup_cloudflare_oauth.py; unset CLOUDFLARE_API_TOKEN\n"
            "  2. Run with --visible to see what you paste (the token then appears on screen)."
        )
    print(f"token: received {len(token)} characters")
    return token


def redirect_uri() -> str:
    """The exact URI Cerberus will present. It must match what the client is created with."""
    env = {}
    if ENV.exists():
        for line in ENV.read_text().splitlines():
            if "=" in line and not line.strip().startswith("#"):
                k, _, v = line.partition("=")
                env[k.strip()] = v.strip()
    base = env.get("PUBLIC_API_URL") or ""
    if not base:
        scheme = "https" if env.get("LOCAL_HTTPS", "").lower() in {"1", "true", "yes", "on"} else "http"
        base = f"{scheme}://localhost:{env.get('API_PORT') or '8000'}"
    return f"{base.rstrip('/')}/api/v1/providers/cloudflare/callback"


def write_env(values: dict[str, str]) -> None:
    lines = ENV.read_text().splitlines(keepends=True) if ENV.exists() else []
    if lines and not lines[-1].endswith("\n"):
        lines[-1] += "\n"
    for key, value in values.items():
        for i, line in enumerate(lines):
            if line.startswith(f"{key}=") or line.startswith(f"# {key}="):
                lines[i] = f"{key}={value}\n"
                break
        else:
            lines.append(f"{key}={value}\n")
    tmp = ENV.with_suffix(".tmp")
    tmp.write_text("".join(lines))
    os.chmod(tmp, 0o600)
    tmp.replace(ENV)
    os.chmod(ENV, 0o600)


ACCOUNT_ID = re.compile(r"^[0-9a-f]{32}$")


def choose_account(token: str) -> dict:
    """The account to create the client in. Listing accounts needs Account Settings: Read; a token without
    it is refused with 9109, which is no reason to stop: the account id is in the dashboard address."""
    try:
        accounts = call("/accounts", token, fatal=False).get("result") or []
    except Refused as why:
        print(f"\nCould not list accounts ({str(why).split(': ', 1)[-1][:120]}).")
        print("That needs the 'Account Settings: Read' permission on the token. You can skip it: your")
        print("account ID is the 32-character code in the dashboard address, dash.cloudflare.com/<ID>/...\n")
        while True:
            typed = input("Account ID: ").strip().lower()
            if ACCOUNT_ID.match(typed):
                return {"id": typed, "name": typed}
            print("  That is not a 32-character hex account ID. Copy it from the address bar.")
    if not accounts:
        sys.exit("That token cannot see any account. Add Account Settings Read, or enter the ID by hand.")
    for i, a in enumerate(accounts, 1):
        print(f"  {i}. {a['name']}  ({a['id']})")
    if len(accounts) == 1:
        return accounts[0]
    return accounts[int(input(f"Which account? [1-{len(accounts)}]: ") or "1") - 1]


def diagnose(token: str) -> None:
    """Try each endpoint the setup needs and print only the HTTP status and Cloudflare's error code. No
    response bodies are printed, so nothing about the account leaks into a terminal or a paste."""
    while True:
        account = input("Account ID: ").strip().lower()
        if ACCOUNT_ID.match(account):
            break
        print("  That is not a 32-character hex account ID.")
    probes = [
        ("verify the token", "/user/tokens/verify", "any token"),
        ("read your user", "/user", "User Details: Read"),
        ("list accounts", "/accounts", "Account Settings: Read"),
        ("read this account", f"/accounts/{account}", "Account Settings: Read"),
        ("list OAuth clients", f"/accounts/{account}/oauth_clients", "OAuth Clients: Read or Edit"),
        ("list OAuth scopes", "/oauth/scopes", "not documented"),
    ]
    print(f"\n{'endpoint':22s} {'result':18s} likely permission needed")
    for name, path, needs in probes:
        try:
            call(path, token, fatal=False)
            result = "OK"
        except Refused as why:
            result = f"refused {why.status}/{why.code}"
        print(f"{name:22s} {result:18s} {needs}")
    print("\nSend this table back (it contains no secrets). OK rows are permissions the token has.")


def main() -> None:
    uri = redirect_uri()
    print(f"Cerberus will use this redirect URI:\n  {uri}\n")
    if uri.startswith("http://") and "localhost" not in uri:
        sys.exit("Refusing to register a plain-http redirect URI that is not localhost.")

    token = read_token()
    if "--diagnose" in sys.argv:
        diagnose(token)
        return

    # Informational only. This address verifies user tokens; an account-owned token is verified elsewhere, so
    # a refusal here says nothing about whether the token can do the work.
    try:
        status = call("/user/tokens/verify", token, fatal=False).get("result", {}).get("status", "unknown")
        print(f"token status: {status}")
    except Refused:
        print("token status: not checked (this looks like an account-owned token; that is fine)")

    account = choose_account(token)
    print(f"using account: {account['name']}\n")

    try:
        listed = call("/oauth/scopes", token, fatal=False).get("result") or []
    except Refused as why:
        sys.exit(
            f"\n{why}\n\nThe scope list is what Cloudflare does not publish, so this cannot be skipped. Run\n"
            "  python3 scripts/setup_cloudflare_oauth.py --diagnose\n"
            "to see which of the token's permissions Cloudflare accepts and which it refuses."
        )
    scopes = [s for s in listed if isinstance(s, dict)]
    names = [s.get("id") or s.get("name") for s in scopes]
    names = [n for n in names if isinstance(n, str)]
    print(f"{len(names)} scopes available to this token.")

    picked = sorted({n for n in names if any(w in n.lower() for w in WANTED) and ".read" in n.lower()})
    if not picked:
        print("\nNo read scope matched 'pages' or 'account'. All scopes:")
        for n in sorted(names):
            print(f"   {n}")
        sys.exit("\nRe-run with the right ones, or tell Cerberus's docs which they are.")

    print("\nRead-only scopes matched for Pages and account access:")
    for n in picked:
        print(f"   {n}")
    extra = [n for n in ALWAYS if n in names]
    print(f"plus: {', '.join(extra) or '(openid/offline_access not listed; Cerberus requests them anyway)'}")
    if input("\nCreate the OAuth client with these? [y/N]: ").strip().lower() != "y":
        sys.exit("Nothing created.")

    created = call(
        f"/accounts/{account['id']}/oauth_clients",
        token,
        method="POST",
        body={
            "client_name": "Cerberus",
            "redirect_uris": [uri],
            "grant_types": ["authorization_code", "refresh_token"],
            "response_types": ["code"],
            "token_endpoint_auth_method": "client_secret_post",
            "scopes": sorted(set(picked) | set(extra)),
        },
    ).get("result") or {}

    client_id = created.get("client_id") or created.get("id")
    secret = created.get("client_secret") or created.get("secret")
    if not client_id or not secret:
        sys.exit(f"Cloudflare did not return a client id and secret. Keys returned: {sorted(created)}")

    write_env({
        "CLOUDFLARE_CLIENT_ID": client_id,
        "CLOUDFLARE_CLIENT_SECRET": secret,
        "CLOUDFLARE_OAUTH_SCOPES": " ".join(sorted(set(picked) | set(extra))),
    })
    print("\nWritten to .env: CLOUDFLARE_CLIENT_ID, CLOUDFLARE_CLIENT_SECRET, CLOUDFLARE_OAUTH_SCOPES")
    print("The client secret was not printed. Cloudflare shows it once, so do not lose .env.")
    print("\nNext:  ./run.sh     then Targets -> Deployment -> Connect Cloudflare Pages")


if __name__ == "__main__":
    main()
