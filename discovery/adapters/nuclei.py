"""Nuclei adapter.

Cerberus does not reimplement vulnerability detection; nuclei does that well. What
this adapter adds is control and provenance: it is handed a resolved ScanProfile and
has no way to widen it, and every result it keeps becomes an Observation carrying the
template, tags, severity and matched location that produced it.

Three independent safety layers, because a single check is one bug away from nothing:

  1. the profile itself refuses forbidden categories at construction
  2. `enforce_safety_floor` re-checks the profile handed to this adapter, and
     `audit_nuclei_args` inspects the actual argv before it is executed
  3. `result_is_permitted` filters returned results, since a template's own tag list
     is metadata we did not choose and must not trust
"""

from __future__ import annotations

import json
import logging
import shutil
import subprocess
import tempfile
from datetime import UTC, datetime
from pathlib import Path

from core.adapters import Endpoint, Observation, ObservationKind, register
from core.profiles import (
    ScanProfile,
    audit_nuclei_args,
    enforce_safety_floor,
    result_is_permitted,
)
from core.scope import Scope

log = logging.getLogger(__name__)

RUN_TIMEOUT = 1800
HTTPS_PORTS = {443, 8443}


def _url_for(endpoint: Endpoint) -> str:
    scheme = "https" if endpoint.port in HTTPS_PORTS else "http"
    return f"{scheme}://{endpoint.hostname}:{endpoint.port}"


class NucleiScanner:
    name = "nuclei"
    kind = ObservationKind.VULNERABILITY

    def is_available(self) -> bool:
        return shutil.which("nuclei") is not None

    def version(self) -> str | None:
        if not self.is_available():
            return None
        try:
            proc = subprocess.run(
                ["nuclei", "-version"], capture_output=True, text=True, timeout=20
            )
            output = (proc.stdout + proc.stderr).strip()
            for line in output.splitlines():
                if "nuclei" in line.lower() and any(c.isdigit() for c in line):
                    return line.strip()
            return output.splitlines()[-1].strip() if output else None
        except (subprocess.SubprocessError, IndexError):
            return None

    def build_command(self, targets_file: Path, output_file: Path, profile: ScanProfile) -> list[str]:
        """Assemble and audit the invocation. Raises rather than run anything unsafe."""
        enforce_safety_floor(profile)
        profile_args = profile.nuclei_args()
        audit_nuclei_args(profile_args)
        return [
            "nuclei",
            "-list", str(targets_file),
            "-jsonl", "-o", str(output_file),
            "-silent", "-no-interactsh", "-no-color",
            *profile_args,
        ]

    def run(
        self, endpoints: list[Endpoint], scope: Scope, profile: ScanProfile
    ) -> list[Observation]:
        if not profile.runs_active_probes:
            log.info("profile %s permits no active probing; skipping nuclei", profile.name)
            return []
        if not self.is_available():
            log.info("nuclei is not installed; skipping active detection")
            return []

        targets = [
            _url_for(e)
            for e in endpoints
            if e.port is not None and scope.permits_host(e.hostname) and scope.permits_port(e.port)
        ]
        if not targets:
            return []

        with tempfile.TemporaryDirectory() as tmp:
            targets_file = Path(tmp) / "targets.txt"
            output_file = Path(tmp) / "results.jsonl"
            targets_file.write_text("\n".join(targets))

            command = self.build_command(targets_file, output_file, profile)
            log.info(
                "nuclei: %d targets, profile=%s, rate=%s/s, concurrency=%s",
                len(targets), profile.name, profile.rate_limit, profile.concurrency,
            )
            try:
                subprocess.run(command, capture_output=True, text=True, timeout=RUN_TIMEOUT, check=False)
            except subprocess.TimeoutExpired:
                log.warning("nuclei timed out after %ss", RUN_TIMEOUT)
                return []

            raw = output_file.read_text() if output_file.exists() else ""

        return self.parse(raw, profile, scope)

    def parse(self, raw: str, profile: ScanProfile, scope: Scope | None = None) -> list[Observation]:
        """Turn nuclei JSONL into Observations, dropping anything malformed or forbidden."""
        version = self.version()
        observations: list[Observation] = []
        seen: set[tuple[str, str]] = set()
        skipped = malformed = 0

        for line in raw.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                result = json.loads(line)
            except json.JSONDecodeError:
                malformed += 1
                continue
            if not isinstance(result, dict):
                malformed += 1
                continue

            info = result.get("info") or {}
            if not isinstance(info, dict):
                info = {}
            tags = info.get("tags") or []
            if isinstance(tags, str):
                tags = [t.strip() for t in tags.split(",") if t.strip()]

            template_id = result.get("template-id") or result.get("templateID")
            if not template_id:
                malformed += 1
                continue

            if not result_is_permitted(tags, result.get("type")):
                skipped += 1
                log.warning(
                    "discarding nuclei result %s: template carries a forbidden category (tags=%s type=%s)",
                    template_id, tags, result.get("type"),
                )
                continue

            host = result.get("host") or ""
            matched_at = result.get("matched-at") or result.get("matched") or host
            target = self._target_from(host, matched_at)
            if scope is not None and target and not scope.permits_host(_hostname_of(target)):
                skipped += 1
                log.warning("discarding nuclei result %s: %s is outside scope", template_id, target)
                continue

            key = (template_id, matched_at or target)
            if key in seen:
                continue
            seen.add(key)

            classification = info.get("classification") or {}
            if not isinstance(classification, dict):
                classification = {}

            observations.append(
                Observation(
                    kind=self.kind,
                    target=target,
                    source_tool=self.name,
                    source_version=version,
                    observed_at=_parse_timestamp(result.get("timestamp")),
                    data={
                        "template_id": template_id,
                        "template_name": info.get("name"),
                        "severity": (info.get("severity") or "unknown").lower(),
                        "tags": tags,
                        "type": result.get("type"),
                        "host": host,
                        "matched_at": matched_at,
                        "cve_ids": _as_list(classification.get("cve-id")),
                        "cwe_ids": _as_list(classification.get("cwe-id")),
                        "cvss_score": classification.get("cvss-score"),
                        "technology": _technology_from(tags),
                        "matcher_name": result.get("matcher-name"),
                        "extracted": result.get("extracted-results"),
                        "profile": profile.name,
                        "description": info.get("description"),
                    },
                    raw=line[:4000],
                )
            )

        if malformed:
            log.warning("nuclei: skipped %d malformed result line(s)", malformed)
        if skipped:
            log.warning("nuclei: discarded %d result(s) on safety or scope grounds", skipped)
        log.info("nuclei: %d detections retained", len(observations))
        return observations

    @staticmethod
    def _target_from(host: str, matched_at: str) -> str:
        value = host or matched_at or ""
        return value.split("://")[-1].split("/")[0] if value else ""


def _hostname_of(target: str) -> str:
    return target.split(":")[0]


def _as_list(value) -> list[str]:
    if not value:
        return []
    if isinstance(value, str):
        return [value]
    return [str(v) for v in value if v]


def _technology_from(tags: list[str]) -> str | None:
    """Nuclei tags name the affected product; skip the taxonomy tags."""
    generic = {"cve", "rce", "lfi", "xss", "sqli", "ssrf", "misconfig", "exposure",
               "tech", "ssl", "takeover", "unauth", "config", "default-login", "panel"}
    for tag in tags:
        clean = tag.strip().lower()
        if clean and clean not in generic and not clean.startswith("cve"):
            return clean
    return None


def _parse_timestamp(value) -> datetime:
    if isinstance(value, str):
        try:
            return datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            pass
    return datetime.now(UTC)


register(NucleiScanner())
