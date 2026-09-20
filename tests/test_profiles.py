import shutil
import subprocess

import pytest

from core.profiles import (
    DEFAULT_PROFILE,
    FORBIDDEN_PROTOCOLS,
    FORBIDDEN_TAGS,
    PASSIVE,
    PROFILES,
    SAFE,
    THOROUGH,
    ProfileViolation,
    ScanProfile,
    get_profile,
)


def build(**overrides) -> ScanProfile:
    defaults = dict(
        name="test",
        description="",
        allowed_tags=frozenset({"cve"}),
        allowed_protocols=frozenset({"http"}),
        severities=("high",),
    )
    return ScanProfile(**{**defaults, **overrides})


# --- the safety floor cannot be lifted -------------------------------------------------

@pytest.mark.parametrize("tag", sorted(FORBIDDEN_TAGS))
def test_destructive_tags_are_refused_at_construction(tag):
    with pytest.raises(ProfileViolation, match="destructive"):
        build(allowed_tags=frozenset({"cve", tag}))


@pytest.mark.parametrize("protocol", sorted(FORBIDDEN_PROTOCOLS))
def test_local_execution_protocols_are_refused(protocol):
    with pytest.raises(ProfileViolation):
        build(allowed_protocols=frozenset({"http", protocol}))


def test_every_shipped_profile_respects_the_floor():
    for profile in PROFILES.values():
        assert not profile.allowed_tags & FORBIDDEN_TAGS
        assert not profile.allowed_protocols & FORBIDDEN_PROTOCOLS


def test_exclusions_are_always_passed_to_nuclei():
    """A template can carry several tags, so an allowed tag must not drag in a forbidden one."""
    for profile in (SAFE, THOROUGH):
        args = " ".join(profile.nuclei_args())
        for tag in FORBIDDEN_TAGS:
            assert tag in args.split("-exclude-tags ")[1].split(" ")[0]
        assert "-exclude-type" in args
        for protocol in FORBIDDEN_PROTOCOLS:
            assert protocol in args.split("-exclude-type ")[1].split(" ")[0]


def test_rate_and_concurrency_must_be_bounded():
    with pytest.raises(ProfileViolation):
        build(rate_limit=0)
    with pytest.raises(ProfileViolation):
        build(concurrency=0)


def test_unknown_severity_is_refused():
    with pytest.raises(ProfileViolation):
        build(severities=("apocalyptic",))


# --- selection is an allowlist ---------------------------------------------------------

def test_templates_are_selected_not_excluded():
    """Nothing runs because it merely exists in nuclei-templates."""
    args = SAFE.nuclei_args()
    assert "-tags" in args
    selected = args[args.index("-tags") + 1].split(",")
    assert set(selected) == set(SAFE.allowed_tags)


def test_template_id_allowlist_pins_exact_templates():
    profile = build(template_ids=frozenset({"CVE-2021-41773", "CVE-2021-42013"}))
    args = profile.nuclei_args()
    assert args.count("-id") == 2
    assert "-tags" not in args  # ids supersede category selection


def test_rate_limit_is_always_expressed():
    for profile in (SAFE, THOROUGH):
        args = profile.nuclei_args()
        assert "-rate-limit" in args and "-concurrency" in args and "-timeout" in args


def test_auto_update_is_disabled():
    """Templates must not silently change underneath a scan."""
    assert "-disable-update-check" in SAFE.nuclei_args()


# --- profiles must be something nuclei will actually run --------------------------------

def test_a_protocol_nuclei_does_not_know_is_refused():
    """Thorough once named "network" (nuclei calls it "tcp"). nuclei exits 2 on an unknown -type
    before scanning anything, and every Thorough scan silently ran without it."""
    with pytest.raises(ProfileViolation, match="does not accept"):
        build(allowed_protocols=frozenset({"http", "network"}))


@pytest.mark.skipif(shutil.which("nuclei") is None, reason="nuclei is not installed")
@pytest.mark.parametrize("profile", [SAFE, THOROUGH], ids=lambda p: p.name)
def test_real_nuclei_accepts_every_profile(profile):
    """The flags a profile generates are parsed by the installed nuclei. -tl lists matching
    templates without touching any target, so this proves the invocation is valid, offline."""
    proc = subprocess.run(
        ["nuclei", *profile.nuclei_args(), "-tl"],
        stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=120,
    )
    assert proc.returncode == 0, (proc.stdout + proc.stderr)[-300:]
    assert proc.stdout.strip(), "the profile matched no templates at all"


# --- profile selection -----------------------------------------------------------------

def test_default_profile_is_the_non_destructive_one():
    assert DEFAULT_PROFILE is SAFE
    assert get_profile(None) is SAFE
    assert SAFE.severities == ("medium", "high", "critical")


def test_passive_profile_runs_no_active_probes():
    assert not PASSIVE.runs_active_probes
    with pytest.raises(ProfileViolation, match="does not permit active probing"):
        PASSIVE.nuclei_args()


def test_opt_in_profile_is_refused_without_explicit_request():
    with pytest.raises(ProfileViolation, match="explicitly"):
        get_profile("thorough")
    assert get_profile("thorough", opted_in=True) is THOROUGH


def test_unknown_profile_name_is_refused():
    with pytest.raises(ProfileViolation, match="unknown scan profile"):
        get_profile("yolo")
