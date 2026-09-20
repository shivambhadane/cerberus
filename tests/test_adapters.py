import discovery.adapters  # noqa: F401  (registers adapters)
from core.adapters import (
    Endpoint,
    Observation,
    ObservationKind,
    Scanner,
    available,
    registered,
)
from core.scope import Scope
from discovery.adapters.nmap_scan import NmapScanner

MALFORMED_NMAP = "<nmaprun><host><ports><port"  # truncated mid-element


def test_every_registered_adapter_satisfies_the_contract():
    for kind in (ObservationKind.SUBDOMAIN, ObservationKind.OPEN_PORT, ObservationKind.TECHNOLOGY):
        scanners = registered(kind)
        assert scanners, f"no adapters registered for {kind}"
        for scanner in scanners:
            assert isinstance(scanner, Scanner)
            assert scanner.name and scanner.kind == kind
            assert isinstance(scanner.is_available(), bool)


def test_available_is_a_subset_of_registered():
    for kind in (ObservationKind.SUBDOMAIN, ObservationKind.OPEN_PORT):
        names = {s.name for s in registered(kind)}
        assert {s.name for s in available(kind)} <= names


def test_nmap_parser_survives_truncated_xml():
    assert NmapScanner()._parse(MALFORMED_NMAP, Scope(domain="example.com")) == []


def test_nmap_parser_survives_empty_output():
    assert NmapScanner()._parse("", Scope(domain="example.com")) == []


def test_nmap_parser_drops_out_of_scope_hosts():
    xml = """<nmaprun><host>
      <address addr="93.184.216.34" addrtype="ipv4"/>
      <hostnames><hostname name="evilexample.com"/></hostnames>
      <ports><port protocol="tcp" portid="443"><state state="open"/>
      <service name="http" product="nginx" version="1.24.0"/></port></ports>
    </host></nmaprun>"""
    assert NmapScanner()._parse(xml, Scope(domain="example.com")) == []


def test_nmap_parser_extracts_service_version_for_in_scope_host():
    xml = """<nmaprun><host>
      <address addr="93.184.216.34" addrtype="ipv4"/>
      <hostnames><hostname name="api.example.com"/></hostnames>
      <ports><port protocol="tcp" portid="443"><state state="open"/>
      <service name="http" product="nginx" version="1.24.0"/></port></ports>
    </host></nmaprun>"""
    observations = NmapScanner()._parse(xml, Scope(domain="example.com"))

    assert len(observations) == 1
    obs = observations[0]
    assert obs.target == "api.example.com:443"
    assert obs.source_tool == "nmap"
    assert obs.data["technology"] == "nginx/1.24.0"
    assert obs.raw  # provenance retained


def test_nmap_parser_ignores_closed_ports():
    xml = """<nmaprun><host>
      <address addr="93.184.216.34" addrtype="ipv4"/>
      <hostnames><hostname name="api.example.com"/></hostnames>
      <ports><port protocol="tcp" portid="443"><state state="closed"/></port></ports>
    </host></nmaprun>"""
    assert NmapScanner()._parse(xml, Scope(domain="example.com")) == []


def test_observation_carries_provenance():
    obs = Observation(
        kind=ObservationKind.TECHNOLOGY,
        target="api.example.com:443",
        source_tool="http_probe",
        data={"technology": "nginx/1.24.0"},
    )
    assert obs.source_tool == "http_probe"
    assert obs.observed_at is not None


def test_endpoint_renders_host_port():
    assert str(Endpoint("api.example.com", "203.0.113.10", 443)) == "api.example.com:443"
    assert str(Endpoint("api.example.com")) == "api.example.com"


def test_duplicate_ports_from_multiple_scanners_collapse_to_one_endpoint():
    """tcp_connect and nmap both report the same port; later stages must see it once."""
    from discovery.runner import _endpoints_from_ports

    scope = Scope(domain="example.com")
    observations = [
        Observation(kind=ObservationKind.OPEN_PORT, target="api.example.com:443",
                    source_tool="tcp_connect",
                    data={"hostname": "api.example.com", "port": 443, "protocol": "tcp"}),
        Observation(kind=ObservationKind.OPEN_PORT, target="api.example.com:443",
                    source_tool="nmap",
                    data={"hostname": "api.example.com", "ip_address": "203.0.113.10",
                          "port": 443, "protocol": "tcp", "technology": "nginx/1.24.0"}),
    ]
    endpoints = _endpoints_from_ports(observations, scope)

    assert len(endpoints) == 1
    assert endpoints[0].ip_address == "203.0.113.10"  # richer observation wins


def test_out_of_scope_ports_are_dropped_when_building_endpoints():
    from discovery.runner import _endpoints_from_ports

    scope = Scope(domain="example.com", excluded_ports={22})
    observations = [
        Observation(kind=ObservationKind.OPEN_PORT, target="api.example.com:22",
                    source_tool="nmap",
                    data={"hostname": "api.example.com", "port": 22, "protocol": "tcp"}),
    ]
    assert _endpoints_from_ports(observations, scope) == []


def test_discovery_config_actually_reaches_the_adapters():
    """Adapters are registered once at import, so config must be pushed into them per run.

    Regression: discovery.ports/connect_timeout/max_concurrency were silently ignored after
    the adapter refactor, so a lab on a non-default port was never scanned.
    """
    from core.config import DiscoveryConfig
    from discovery.adapters.nmap_scan import NmapScanner
    from discovery.adapters.tcp_connect import DEFAULT_PORTS, TcpConnectScanner
    from discovery.runner import _configure

    tcp, nmap = TcpConnectScanner(), NmapScanner()
    config = DiscoveryConfig(ports=[18081, 18082], connect_timeout=0.5, max_concurrency=7)

    _configure(tcp, config)
    _configure(nmap, config)

    assert tcp.ports == [18081, 18082]
    assert tcp.timeout == 0.5 and tcp.concurrency == 7
    assert nmap.ports == [18081, 18082]

    _configure(tcp, DiscoveryConfig(ports=[]))
    assert tcp.ports == DEFAULT_PORTS  # empty means "use the defaults", not "scan nothing"


def test_private_addresses_are_refused_unless_the_operator_opts_in():
    from core.config import DiscoveryConfig

    assert DiscoveryConfig().allow_private_addresses is False
    assert Scope(domain="127.0.0.1").permits_address("127.0.0.1") is False
    assert Scope(domain="127.0.0.1", allow_private_addresses=True).permits_address("127.0.0.1")


# --- nmap must not take identity from reverse DNS -------------------------------------------
# tests/fixtures/nmap_real_lab.xml is what nmap 7.94 actually emitted for the Docker lab: the
# host is labelled by its PTR record (`localhost`), not the 127.0.0.1 that was requested.

def _real_nmap_xml() -> str:
    from pathlib import Path

    return (Path(__file__).parent / "fixtures" / "nmap_real_lab.xml").read_text()


def test_nmap_result_is_mapped_back_to_the_requested_endpoint_not_the_ptr_name():
    lab = Scope(domain="127.0.0.1", allow_private_addresses=True)
    requested = [Endpoint("127.0.0.1", "127.0.0.1")]

    observations = NmapScanner()._parse(_real_nmap_xml(), lab, requested)

    assert [o.target for o in observations] == ["127.0.0.1:18081", "127.0.0.1:18082"]
    assert observations[0].data["technology"] == "Apache httpd/2.4.49"
    assert observations[1].data["technology"] == "Apache httpd/2.4.50"


def test_a_cloud_ptr_name_does_not_cause_in_scope_results_to_be_dropped():
    """On a real host the PTR is an unrelated hosting name that scope would (rightly) reject."""
    xml = """<nmaprun><host>
      <address addr="93.184.216.34" addrtype="ipv4"/>
      <hostnames><hostname name="93-184-216-34.bc.googleusercontent.com" type="PTR"/></hostnames>
      <ports><port protocol="tcp" portid="443"><state state="open"/>
      <service name="http" product="nginx" version="1.24.0"/></port></ports>
    </host></nmaprun>"""
    requested = [Endpoint("api.example.com", "93.184.216.34")]

    observations = NmapScanner()._parse(xml, Scope(domain="example.com"), requested)

    assert [o.target for o in observations] == ["api.example.com:443"]


def test_user_supplied_name_takes_precedence():
    xml = """<nmaprun><host>
      <address addr="93.184.216.34" addrtype="ipv4"/>
      <hostnames><hostname name="api.example.com" type="user"/>
                 <hostname name="something.else.net" type="PTR"/></hostnames>
      <ports><port protocol="tcp" portid="80"><state state="open"/>
      <service name="http" product="nginx"/></port></ports>
    </host></nmaprun>"""
    observations = NmapScanner()._parse(xml, Scope(domain="example.com"), [])
    assert [o.target for o in observations] == ["api.example.com:80"]


def test_a_ptr_only_host_with_no_matching_endpoint_is_dropped_not_guessed():
    xml = """<nmaprun><host>
      <address addr="93.184.216.34" addrtype="ipv4"/>
      <hostnames><hostname name="api.example.com" type="PTR"/></hostnames>
      <ports><port protocol="tcp" portid="80"><state state="open"/></port></ports>
    </host></nmaprun>"""
    # A PTR record is attacker-influenceable; it must never be what puts a host in scope.
    assert NmapScanner()._parse(xml, Scope(domain="example.com"), []) == []


# --- a passive profile must not touch the target --------------------------------------------

class _Recorder:
    def __init__(self, name, kind, result=None):
        self.name, self.kind, self.calls, self._result = name, kind, 0, result or []

    def is_available(self):
        return True

    def version(self):
        return None

    def run(self, *args):
        self.calls += 1
        return list(self._result)


def _fake_stages(monkeypatch):
    subdomain = _Recorder(
        "fake_ct", ObservationKind.SUBDOMAIN,
        [Observation(kind=ObservationKind.SUBDOMAIN, target="api.example.com", source_tool="fake_ct",
                     data={"hostname": "api.example.com", "ip_address": "93.184.216.34"})],
    )
    port = _Recorder(
        "fake_ports", ObservationKind.OPEN_PORT,
        [Observation(kind=ObservationKind.OPEN_PORT, target="api.example.com:443", source_tool="fake_ports",
                     data={"hostname": "api.example.com", "ip_address": "93.184.216.34", "port": 443})],
    )
    tech = _Recorder("fake_probe", ObservationKind.TECHNOLOGY)
    vuln = _Recorder("fake_vuln", ObservationKind.VULNERABILITY)
    stages = {
        ObservationKind.SUBDOMAIN: [subdomain], ObservationKind.OPEN_PORT: [port],
        ObservationKind.TECHNOLOGY: [tech], ObservationKind.VULNERABILITY: [vuln],
    }
    monkeypatch.setattr("discovery.runner.available", lambda kind: stages.get(kind, []))
    return subdomain, port, tech, vuln


def test_passive_profile_never_contacts_the_target(monkeypatch):
    """Regression: only the vulnerability stage used to be gated, so `passive` still ran a
    port scan, nmap -sV and HTTP requests against the target."""
    from core.profiles import PASSIVE
    from discovery.runner import run_discovery

    subdomain, port, tech, vuln = _fake_stages(monkeypatch)
    result = run_discovery(Scope(domain="example.com"), PASSIVE)

    assert subdomain.calls == 1  # passive enumeration still happens
    assert (port.calls, tech.calls, vuln.calls) == (0, 0, 0)
    assert result.endpoints == []
    assert any(o.source_tool == "fake_ct" for o in result.observations)


def test_safe_profile_runs_every_stage(monkeypatch):
    from core.profiles import SAFE
    from discovery.runner import run_discovery

    subdomain, port, tech, vuln = _fake_stages(monkeypatch)
    result = run_discovery(Scope(domain="example.com"), SAFE)

    assert (subdomain.calls, port.calls, vuln.calls) == (1, 1, 1)
    assert [str(e) for e in result.endpoints] == ["api.example.com:443"]
