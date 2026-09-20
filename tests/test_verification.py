"""DNS TXT domain verification. The lookup is injected, so no test touches the network."""

import pytest

from core.verification import (
    LookupUnavailable,
    RecordNotFound,
    challenge_record,
    check_dns_txt,
    lookup_txt,
)

TOKEN = "tok_abc123"


def answering(*records):
    return lambda name: list(records)


def test_the_record_to_publish_names_the_challenge_label_and_carries_the_token():
    name, value = challenge_record("example.com", TOKEN)
    assert name == "_cerberus-challenge.example.com"
    assert value == "cerberus-verify=tok_abc123"


def test_the_expected_record_verifies():
    result = check_dns_txt("example.com", TOKEN, answering("cerberus-verify=tok_abc123"))
    assert result.verified and result.reason == "verified"


def test_it_asks_for_the_challenge_name_not_the_bare_domain():
    asked = []

    def lookup(name):
        asked.append(name)
        return ["cerberus-verify=tok_abc123"]

    check_dns_txt("example.com", TOKEN, lookup)
    assert asked == ["_cerberus-challenge.example.com"]


def test_quotes_and_whitespace_around_the_value_are_tolerated():
    records = (
        '"cerberus-verify=tok_abc123"',
        "  cerberus-verify=tok_abc123 ",
        ' "cerberus-verify=tok_abc123" ',
    )
    for record in records:
        assert check_dns_txt("example.com", TOKEN, answering(record)).verified, record


def test_the_record_may_sit_among_others():
    result = check_dns_txt(
        "example.com", TOKEN,
        answering(
            "v=spf1 include:_spf.example.com ~all",
            "cerberus-verify=tok_abc123",
            "google-site-verification=xyz",
        ),
    )
    assert result.verified


@pytest.mark.parametrize("record", [
    "cerberus-verify=tok_abc12",        # a prefix of the token
    "cerberus-verify=tok_abc1234",      # the token plus more
    "cerberus-verify=TOK_ABC123",       # tokens are case-sensitive
    "cerberus-verify=other-token",
    "tok_abc123",                       # the token without the prefix
    "prefix cerberus-verify=tok_abc123",  # must be the whole record, not a substring
    "",
])
def test_a_wrong_or_partial_value_does_not_verify(record):
    result = check_dns_txt("example.com", TOKEN, answering(record))
    assert not result.verified and result.reason == "token_mismatch"
    assert "cerberus-verify=tok_abc123" in result.detail  # tells the owner exactly what to publish


def test_someone_elses_token_does_not_verify_my_claim():
    """Two people claim the same domain; each has their own token. Only the DNS owner can
    publish either, and publishing one proves only that one."""
    result = check_dns_txt("example.com", "mine", answering("cerberus-verify=theirs"))
    assert not result.verified


def test_a_missing_record_tells_the_owner_what_to_do_and_is_not_a_failure_of_dns():
    def lookup(name):
        raise RecordNotFound(name)

    result = check_dns_txt("example.com", TOKEN, lookup)
    assert not result.verified and result.reason == "record_not_found"
    assert "_cerberus-challenge.example.com" in result.detail


def test_an_unreachable_resolver_is_reported_as_unknown_not_as_absent():
    """A timeout must not read as "you did it wrong"."""
    def lookup(name):
        raise LookupUnavailable("timed out")

    result = check_dns_txt("example.com", TOKEN, lookup)
    assert not result.verified and result.reason == "lookup_failed"
    assert "try again" in result.detail.lower()


def test_no_records_at_all_is_a_mismatch_not_a_verification():
    assert check_dns_txt("example.com", TOKEN, answering()).reason == "token_mismatch"


def test_the_real_resolver_maps_dns_failures_to_our_two_kinds(monkeypatch):
    """lookup_txt is the only code that touches dnspython; check its error mapping directly."""
    import dns.exception
    import dns.resolver

    def resolver_raising(exc):
        class Fake:
            lifetime = timeout = 0

            def resolve(self, *_):
                raise exc

        return lambda: Fake()

    for exc, expected in [
        (dns.resolver.NXDOMAIN(), RecordNotFound),
        (dns.resolver.NoAnswer(), RecordNotFound),
        (dns.exception.Timeout(), LookupUnavailable),
        (dns.resolver.NoNameservers(), LookupUnavailable),
    ]:
        monkeypatch.setattr(dns.resolver, "Resolver", resolver_raising(exc))
        with pytest.raises(expected):
            lookup_txt("_cerberus-challenge.example.com")


def test_long_values_split_across_dns_strings_are_rejoined(monkeypatch):
    import dns.resolver

    class Record:
        strings = (b"cerberus-verify=", b"tok_abc123")

    class Fake:
        lifetime = timeout = 0

        def resolve(self, *_):
            return [Record()]

    monkeypatch.setattr(dns.resolver, "Resolver", lambda: Fake())
    assert lookup_txt("x") == ["cerberus-verify=tok_abc123"]
