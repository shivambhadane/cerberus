"""Passwords, tokens, and the sign-in throttle: the parts that must not be wrong."""

from datetime import UTC, datetime, timedelta

import jwt
import pytest

from core.security import (
    ALGORITHM,
    MAX_PASSWORD_LENGTH,
    MIN_PASSWORD_LENGTH,
    PasswordPolicyError,
    TokenError,
    create_access_token,
    decode_access_token,
    hash_password,
    hash_refresh_token,
    new_refresh_token,
    password_needs_rehash,
    spend_password_check_time,
    validate_password,
    verify_password,
)
from core.throttle import FailureLimiter, Throttled

SECRET = "s" * 48


# --- passwords -------------------------------------------------------------------------

def test_the_hash_is_argon2id_and_never_the_password():
    hashed = hash_password("correct horse battery staple")
    assert hashed.startswith("$argon2id$")
    assert "correct horse" not in hashed


def test_a_password_verifies_only_against_its_own_hash():
    hashed = hash_password("correct horse battery staple")
    assert verify_password(hashed, "correct horse battery staple") is True
    assert verify_password(hashed, "correct horse battery stapler") is False
    assert verify_password(hashed, "") is False


def test_hashing_is_salted():
    assert hash_password("same password here") != hash_password("same password here")


@pytest.mark.parametrize("stored", ["", "x", "not-a-hash", "$argon2id$garbage"])
def test_a_malformed_stored_hash_is_a_failed_login_not_a_crash(stored):
    assert verify_password(stored, "anything at all 123") is False


def test_a_weaker_hash_is_flagged_for_upgrade():
    from argon2 import PasswordHasher

    weak = PasswordHasher(time_cost=1, memory_cost=8, parallelism=1).hash("a long enough password")
    assert password_needs_rehash(weak) is True
    assert password_needs_rehash(hash_password("a long enough password")) is False


def test_policy_is_about_length_not_composition():
    validate_password("a" * MIN_PASSWORD_LENGTH)
    validate_password("correct horse battery staple")  # no digits or symbols, and fine
    with pytest.raises(PasswordPolicyError, match="at least"):
        validate_password("a" * (MIN_PASSWORD_LENGTH - 1))
    with pytest.raises(PasswordPolicyError, match="at most"):
        validate_password("a" * (MAX_PASSWORD_LENGTH + 1))


def test_the_password_may_not_be_the_email():
    with pytest.raises(PasswordPolicyError, match="email"):
        validate_password("shivam@example.com", email="shivam@example.com")
    with pytest.raises(PasswordPolicyError, match="email"):
        validate_password("Shivam@Example.com", email="shivam@example.com")


def test_an_unknown_account_still_costs_a_full_password_check():
    """Login for an email that has no account must take as long as one that does."""
    import time

    hashed = hash_password("a long enough password")
    start = time.perf_counter()
    verify_password(hashed, "wrong password entirely")
    real = time.perf_counter() - start
    start = time.perf_counter()
    spend_password_check_time("wrong password entirely")
    dummy = time.perf_counter() - start
    assert dummy > real * 0.3, (real, dummy)


# --- access tokens ---------------------------------------------------------------------

def test_a_token_round_trips_to_the_user_id():
    token = create_access_token("user-1", SECRET, timedelta(minutes=15))
    assert decode_access_token(token, SECRET) == "user-1"


def test_an_expired_token_is_distinguishable_so_the_client_can_refresh():
    long_ago = datetime.now(UTC) - timedelta(hours=1)
    token = create_access_token("user-1", SECRET, timedelta(minutes=15), now=long_ago)
    with pytest.raises(TokenError) as error:
        decode_access_token(token, SECRET)
    assert error.value.code == "token_expired"


def test_a_token_signed_with_another_secret_is_refused():
    token = create_access_token("user-1", "another-secret-" + "x" * 40, timedelta(minutes=15))
    with pytest.raises(TokenError) as error:
        decode_access_token(token, SECRET)
    assert error.value.code == "token_invalid"


def test_alg_none_forgery_is_refused():
    """The classic: an unsigned token claiming to be signed with no algorithm."""
    forged = jwt.encode(
        {"sub": "admin", "iss": "cerberus", "typ": "access", "iat": 1, "exp": 4102444800},
        key=None, algorithm="none",
    )
    with pytest.raises(TokenError) as error:
        decode_access_token(forged, SECRET)
    assert error.value.code == "token_invalid"


@pytest.mark.filterwarnings("ignore:The HMAC key")
def test_a_different_hmac_algorithm_is_refused():
    token = jwt.encode(
        {"sub": "u", "iss": "cerberus", "typ": "access", "iat": 1, "exp": 4102444800},
        SECRET, algorithm="HS512",
    )
    assert ALGORITHM == "HS256"
    with pytest.raises(TokenError):
        decode_access_token(token, SECRET)


@pytest.mark.parametrize("missing", ["sub", "exp", "iat", "iss"])
def test_a_token_missing_a_required_claim_is_refused(missing):
    claims = {"sub": "u", "iss": "cerberus", "typ": "access", "iat": 1, "exp": 4102444800}
    del claims[missing]
    with pytest.raises(TokenError):
        decode_access_token(jwt.encode(claims, SECRET, algorithm=ALGORITHM), SECRET)


def test_a_token_of_another_type_or_issuer_is_not_an_access_token():
    base = {"sub": "u", "iss": "cerberus", "typ": "access", "iat": 1, "exp": 4102444800}
    for change in ({"typ": "refresh"}, {"iss": "someone-else"}, {"sub": ""}, {"sub": 7}):
        with pytest.raises(TokenError):
            decode_access_token(jwt.encode({**base, **change}, SECRET, algorithm=ALGORITHM), SECRET)


@pytest.mark.parametrize("garbage", ["", "abc", "a.b.c", "Bearer x", " "])
def test_garbage_is_refused_without_crashing(garbage):
    with pytest.raises(TokenError):
        decode_access_token(garbage, SECRET)


# --- refresh tokens --------------------------------------------------------------------

def test_refresh_tokens_are_long_random_and_unique():
    tokens = {new_refresh_token() for _ in range(50)}
    assert len(tokens) == 50 and all(len(t) >= 60 for t in tokens)


def test_only_a_hash_of_a_refresh_token_is_stored():
    token = new_refresh_token()
    stored = hash_refresh_token(token)
    assert stored != token and len(stored) == 64
    assert hash_refresh_token(token) == stored  # deterministic, so it can be looked up


# --- the throttle ----------------------------------------------------------------------

class Clock:
    def __init__(self):
        self.now = 1000.0

    def __call__(self):
        return self.now


def test_the_limit_trips_after_the_allowed_failures():
    limiter = FailureLimiter(max_failures=3, window_seconds=60, clock=(clock := Clock()))
    for _ in range(3):
        limiter.check("a")
        limiter.record_failure("a")
    with pytest.raises(Throttled) as error:
        limiter.check("a")
    assert 1 <= error.value.retry_after <= 61
    limiter.check("someone-else")  # keys are independent
    assert clock.now == 1000.0


def test_failures_age_out_of_the_window():
    clock = Clock()
    limiter = FailureLimiter(max_failures=2, window_seconds=60, clock=clock)
    limiter.record_failure("a")
    limiter.record_failure("a")
    with pytest.raises(Throttled):
        limiter.check("a")
    clock.now += 61
    limiter.check("a")


def test_success_resets_the_counter():
    limiter = FailureLimiter(max_failures=2, window_seconds=60, clock=Clock())
    limiter.record_failure("a")
    limiter.reset("a")
    limiter.record_failure("a")
    limiter.check("a")


def test_the_tracker_does_not_grow_without_bound(monkeypatch):
    import core.throttle as throttle

    monkeypatch.setattr(throttle, "MAX_TRACKED_KEYS", 50)
    clock = Clock()
    limiter = FailureLimiter(max_failures=5, window_seconds=10, clock=clock)
    for i in range(50):
        limiter.record_failure(f"k{i}")
    clock.now += 11  # all of those have expired
    limiter.record_failure("fresh")
    assert len(limiter._failures) <= 2
