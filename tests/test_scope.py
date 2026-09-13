import pytest

from core.scope import OutOfScopeError, Scope, development_scope


def test_apex_and_subdomains_are_in_scope():
    scope = Scope(domain="example.com")
    assert scope.permits_host("example.com")
    assert scope.permits_host("api.example.com")
    assert scope.permits_host("deep.nested.example.com")


def test_suffix_confusion_is_rejected():
    """A naive endswith() check accepts these; they are different organisations."""
    scope = Scope(domain="example.com")
    assert not scope.permits_host("evilexample.com")
    assert not scope.permits_host("notexample.com")
    assert not scope.permits_host("example.com.attacker.net")


def test_subdomains_can_be_excluded_from_scope():
    scope = Scope(domain="example.com", include_subdomains=False)
    assert scope.permits_host("example.com")
    assert not scope.permits_host("api.example.com")


def test_explicit_exclusions_win():
    scope = Scope(domain="example.com", excluded_hosts={"vpn.example.com"})
    assert not scope.permits_host("vpn.example.com")
    assert not scope.permits_host("VPN.example.com.")


def test_private_and_loopback_addresses_are_refused_by_default():
    scope = Scope(domain="example.com")
    assert scope.permits_address("93.184.216.34")
    assert not scope.permits_address("10.0.0.5")
    assert not scope.permits_address("192.168.1.1")
    assert not scope.permits_address("127.0.0.1")
    assert not scope.permits_address("169.254.169.254")  # cloud metadata endpoint


def test_development_scope_allows_private_addresses():
    assert development_scope("localhost").permits_address("127.0.0.1")


def test_excluded_ports_are_refused():
    scope = Scope(domain="example.com", excluded_ports={22, 3389})
    assert not scope.permits_port(22)
    assert scope.permits_port(443)


def test_filter_hosts_drops_out_of_scope_and_private():
    scope = Scope(domain="example.com")
    kept = scope.filter_hosts({
        "api.example.com": "93.184.216.34",
        "evilexample.com": "93.184.216.34",
        "internal.example.com": "10.0.0.5",
    })
    assert list(kept) == ["api.example.com"]


def test_require_host_raises_for_out_of_scope():
    scope = Scope(domain="example.com")
    scope.require_host("api.example.com")
    with pytest.raises(OutOfScopeError):
        scope.require_host("evilexample.com")
