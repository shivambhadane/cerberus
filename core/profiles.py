"""Scan profiles: what a scanner is permitted to do.

Nuclei ships tens of thousands of community templates. Running whatever happens to
be in the repository is not acceptable on infrastructure we are authorized to assess
but do not own, so template selection is an **allowlist** here, never "everything
minus a few". A profile states which categories may run; anything unlisted does not.

Two layers:

  * A safety floor (FORBIDDEN_TAGS / FORBIDDEN_PROTOCOLS) that no profile can lift.
    Denial-of-service, fuzzing, brute force, and templates that execute local code or
    touch the filesystem are refused at construction time.
  * The profile itself, which allowlists tags, protocols and severities, and caps
    rate, concurrency and timeouts.

Profiles are also the unit of provenance: a finding records the profile that produced
it, so "why did we send this request" always has an answer.
"""

from __future__ import annotations

from dataclasses import dataclass, field

# Categories no profile may enable. These either intentionally degrade the target or
# execute code outside the HTTP request/response cycle.
FORBIDDEN_TAGS = frozenset({
    "dos", "ddos", "fuzz", "fuzzing", "intrusive", "brute-force", "bruteforce",
})
# nuclei protocol types. `code` runs local commands and `file` reads the local disk:
# neither is remote assessment, and both are a sandbox-escape risk.
FORBIDDEN_PROTOCOLS = frozenset({"code", "file"})
# Every value nuclei's `-type` flag accepts (v3.x). A name outside this list makes nuclei exit 2
# before scanning anything, so a typo is refused when the profile is built, not mid-scan. (The
# Thorough profile once said "network", which older nuclei called TCP; every Thorough scan ran
# without nuclei until this check existed.)
NUCLEI_PROTOCOLS = frozenset({
    "dns", "file", "http", "headless", "tcp", "workflow", "ssl", "websocket", "whois", "code", "javascript",
})

SEVERITIES = ("info", "low", "medium", "high", "critical")


class ProfileViolation(ValueError):
    """Raised when a profile tries to permit something the safety floor forbids."""


@dataclass(frozen=True)
class ScanProfile:
    name: str
    description: str
    allowed_tags: frozenset[str]
    allowed_protocols: frozenset[str]
    severities: tuple[str, ...]
    rate_limit: int = 20          # requests per second
    concurrency: int = 10
    timeout_seconds: int = 10
    retries: int = 1
    requires_opt_in: bool = False
    # When set, ONLY these template ids may run - the strictest form of allowlisting.
    template_ids: frozenset[str] = field(default_factory=frozenset)

    def __post_init__(self) -> None:
        forbidden = self.allowed_tags & FORBIDDEN_TAGS
        if forbidden:
            raise ProfileViolation(
                f"profile {self.name!r} may not enable {sorted(forbidden)}: "
                "these categories are destructive and are refused unconditionally"
            )
        bad_protocols = self.allowed_protocols & FORBIDDEN_PROTOCOLS
        if bad_protocols:
            raise ProfileViolation(
                f"profile {self.name!r} may not enable protocols {sorted(bad_protocols)}: "
                "they execute code or read local files rather than probing the target"
            )
        unsupported = self.allowed_protocols - NUCLEI_PROTOCOLS
        if unsupported:
            raise ProfileViolation(
                f"profile {self.name!r} names protocols nuclei does not accept: {sorted(unsupported)} "
                f"(valid: {sorted(NUCLEI_PROTOCOLS)})"
            )
        unknown = set(self.severities) - set(SEVERITIES)
        if unknown:
            raise ProfileViolation(f"profile {self.name!r} has unknown severities {sorted(unknown)}")
        if self.rate_limit <= 0 or self.concurrency <= 0:
            raise ProfileViolation(f"profile {self.name!r} must bound rate and concurrency")

    @property
    def runs_active_probes(self) -> bool:
        return bool(self.allowed_tags or self.template_ids)

    def nuclei_args(self) -> list[str]:
        """Command-line flags expressing this profile.

        The exclusions are emitted even though selection is already an allowlist:
        a template can carry several tags, so an allowed one must not drag in a
        forbidden one.
        """
        if not self.runs_active_probes:
            raise ProfileViolation(f"profile {self.name!r} does not permit active probing")

        args: list[str] = []
        if self.template_ids:
            for template_id in sorted(self.template_ids):
                args += ["-id", template_id]
        else:
            args += ["-tags", ",".join(sorted(self.allowed_tags))]

        args += [
            "-severity", ",".join(self.severities),
            "-exclude-tags", ",".join(sorted(FORBIDDEN_TAGS)),
            "-exclude-type", ",".join(sorted(FORBIDDEN_PROTOCOLS)),
            "-type", ",".join(sorted(self.allowed_protocols)),
            "-rate-limit", str(self.rate_limit),
            "-concurrency", str(self.concurrency),
            "-timeout", str(self.timeout_seconds),
            "-retries", str(self.retries),
            "-disable-update-check",
        ]
        return args


PASSIVE = ScanProfile(
    name="passive",
    description="No active probing. Certificate transparency and DNS only.",
    allowed_tags=frozenset(),
    allowed_protocols=frozenset(),
    severities=SEVERITIES,
)

SAFE = ScanProfile(
    name="safe",
    description=(
        "Default. Non-destructive detection only: known CVEs, exposed panels and files, "
        "misconfiguration and TLS issues, at medium severity and above."
    ),
    allowed_tags=frozenset({"cve", "exposure", "misconfig", "ssl", "tech", "takeover"}),
    allowed_protocols=frozenset({"http", "ssl", "dns"}),
    severities=("medium", "high", "critical"),
    rate_limit=20,
    concurrency=10,
)

THOROUGH = ScanProfile(
    name="thorough",
    description=(
        "Broader coverage for targets you own: adds low/info severity and default-credential "
        "checks. Still non-destructive, and must be requested explicitly."
    ),
    allowed_tags=frozenset({
        "cve", "exposure", "misconfig", "ssl", "tech", "takeover",
        "default-login", "unauth", "config",
    }),
    allowed_protocols=frozenset({"http", "ssl", "dns", "tcp"}),
    severities=SEVERITIES,
    rate_limit=40,
    concurrency=20,
    requires_opt_in=True,
)

PROFILES = {p.name: p for p in (PASSIVE, SAFE, THOROUGH)}
DEFAULT_PROFILE = SAFE


# Flags whose values *select* what runs. Exclusion flags legitimately contain the
# forbidden words, so only these are audited for them.
SELECTION_FLAGS = ("-tags", "-type", "-id")


def enforce_safety_floor(profile: ScanProfile) -> None:
    """Re-check a profile immediately before use.

    Construction already validates, but the adapter must not assume the profile it was
    handed came from a validated path - it may have been built elsewhere, mutated, or
    assembled from API input.
    """
    forbidden = profile.allowed_tags & FORBIDDEN_TAGS
    if forbidden:
        raise ProfileViolation(
            f"refusing to run profile {profile.name!r}: forbidden tags {sorted(forbidden)}"
        )
    bad_protocols = profile.allowed_protocols & FORBIDDEN_PROTOCOLS
    if bad_protocols:
        raise ProfileViolation(
            f"refusing to run profile {profile.name!r}: forbidden types {sorted(bad_protocols)}"
        )


def audit_nuclei_args(args: list[str]) -> None:
    """Inspect the actual argv about to be executed.

    The last line of defence: whatever built these arguments, nothing forbidden may be
    selected and the exclusions must be present and complete.
    """
    pairs = dict(zip(args, args[1:], strict=False))

    for flag in SELECTION_FLAGS:
        if flag not in pairs:
            continue
        values = {v.strip().lower() for v in pairs[flag].split(",")}
        forbidden = values & (FORBIDDEN_TAGS | FORBIDDEN_PROTOCOLS)
        if forbidden:
            raise ProfileViolation(
                f"refusing to execute: {flag} selects forbidden {sorted(forbidden)}"
            )

    for flag, required in (("-exclude-tags", FORBIDDEN_TAGS), ("-exclude-type", FORBIDDEN_PROTOCOLS)):
        present = {v.strip().lower() for v in pairs.get(flag, "").split(",") if v.strip()}
        missing = required - present
        if missing:
            raise ProfileViolation(
                f"refusing to execute: {flag} is missing {sorted(missing)}"
            )


def result_is_permitted(tags: list[str] | None, template_type: str | None) -> bool:
    """Whether a returned result may be kept.

    Templates carry several tags, and the tag set in a result is the template's own
    metadata rather than what we selected on, so results are filtered again on the way
    back in.
    """
    tag_set = {t.strip().lower() for t in (tags or [])}
    if tag_set & FORBIDDEN_TAGS:
        return False
    return (template_type or "").strip().lower() not in FORBIDDEN_PROTOCOLS


def get_profile(name: str | None, opted_in: bool = False) -> ScanProfile:
    """Look up a profile, refusing opt-in profiles that were not explicitly requested."""
    if not name:
        return DEFAULT_PROFILE
    try:
        profile = PROFILES[name]
    except KeyError:
        raise ProfileViolation(
            f"unknown scan profile {name!r}; available: {', '.join(sorted(PROFILES))}"
        ) from None
    if profile.requires_opt_in and not opted_in:
        raise ProfileViolation(
            f"scan profile {name!r} is more intrusive than the default and must be "
            "requested explicitly (CLI --accept-profile, API accept_profile=true)"
        )
    return profile
