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
