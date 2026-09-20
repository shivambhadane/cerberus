"""Provider tokens at rest: encrypted, tied to their row, and rotatable."""

import pytest
from cryptography.fernet import Fernet

from core.crypto import CryptoError, TokenCipher, get_cipher


def key() -> str:
    return Fernet.generate_key().decode()


def test_a_token_round_trips():
    cipher = TokenCipher([key()])
    sealed = cipher.encrypt("vercel-secret-token", "conn-1")
    assert cipher.decrypt(sealed, "conn-1") == "vercel-secret-token"


def test_the_stored_value_is_not_the_token_and_does_not_contain_it():
    cipher = TokenCipher([key()])
    sealed = cipher.encrypt("vercel-secret-token", "conn-1")
    assert "vercel-secret-token" not in sealed and sealed != "vercel-secret-token"


def test_encryption_is_not_deterministic():
    cipher = TokenCipher([key()])
    assert cipher.encrypt("same", "c") != cipher.encrypt("same", "c")


def test_a_ciphertext_copied_to_another_row_will_not_decrypt_there():
    """Someone with write access to the database moves user A's token onto their own connection."""
    cipher = TokenCipher([key()])
    sealed = cipher.encrypt("alices-token", "alices-connection")
    with pytest.raises(CryptoError, match="different record"):
        cipher.decrypt(sealed, "attackers-connection")


def test_tampered_or_foreign_data_is_refused():
    cipher = TokenCipher([key()])
    sealed = cipher.encrypt("t", "c")
    for bad in (sealed[:-4] + "AAAA", "", "not-a-token", sealed.upper()):
        with pytest.raises(CryptoError):
            cipher.decrypt(bad, "c")


def test_a_different_key_cannot_read_it():
    sealed = TokenCipher([key()]).encrypt("t", "c")
    with pytest.raises(CryptoError):
        TokenCipher([key()]).decrypt(sealed, "c")


def test_keys_rotate_old_data_still_reads_and_new_data_uses_the_new_key():
    old, new = key(), key()
    sealed_old = TokenCipher([old]).encrypt("t", "c")
    rotated = TokenCipher([new, old])
    assert rotated.decrypt(sealed_old, "c") == "t"
    sealed_new = rotated.encrypt("t2", "c")
    assert TokenCipher([new]).decrypt(sealed_new, "c") == "t2"  # encrypts under the first key


def test_a_malformed_key_is_reported_with_how_to_make_one():
    with pytest.raises(CryptoError, match="Fernet.generate_key"):
        TokenCipher(["not-a-fernet-key"])
    with pytest.raises(CryptoError):
        TokenCipher([])


def test_no_key_means_provider_connections_are_off_not_broken(monkeypatch):
    monkeypatch.delenv("PROVIDER_TOKEN_ENCRYPTION_KEY", raising=False)
    assert get_cipher() is None


def test_the_cipher_is_built_from_the_environment(monkeypatch):
    monkeypatch.setenv("PROVIDER_TOKEN_ENCRYPTION_KEY", f"{key()}, {key()}")
    assert get_cipher() is not None
