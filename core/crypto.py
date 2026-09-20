"""Encryption of provider tokens at rest.

A provider access or refresh token is a credential for someone else's cloud account, so it is never
stored in the clear. Tokens are encrypted with Fernet (AES-128-CBC + HMAC-SHA256, authenticated) under
a key that lives only in the environment, never in the database or the repository.

Two properties beyond "it is encrypted":
  * The ciphertext is bound to the row it belongs to. What is encrypted is `<context>\\n<token>`, and the
    context (the connection id) is checked on the way out, so a ciphertext copied to another row by
    someone with write access to the database will not decrypt there.
  * Keys rotate. `PROVIDER_TOKEN_ENCRYPTION_KEY` may hold several keys, comma-separated: the first
    encrypts, all decrypt. Prepend a new key, and old rows keep working until they are rewritten.
"""

from __future__ import annotations

from cryptography.fernet import Fernet, InvalidToken, MultiFernet

from core.config import load_config


class CryptoError(Exception):
    """A token could not be encrypted or decrypted (bad key, tampered data, or wrong row)."""


class TokenCipher:
    def __init__(self, keys: list[str]):
        if not keys:
            raise CryptoError("no encryption key configured")
        try:
            self._fernet = MultiFernet([Fernet(key.encode()) for key in keys])
        except (ValueError, TypeError) as exc:
            raise CryptoError(
                "PROVIDER_TOKEN_ENCRYPTION_KEY is not a valid Fernet key. Generate one with: "
                "python -c \"from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())\""
            ) from exc

    def encrypt(self, plaintext: str, context: str) -> str:
        return self._fernet.encrypt(f"{context}\n{plaintext}".encode()).decode()

    def decrypt(self, ciphertext: str, context: str) -> str:
        try:
            decoded = self._fernet.decrypt(ciphertext.encode()).decode()
        except (InvalidToken, ValueError) as exc:
            raise CryptoError("the stored token cannot be decrypted") from exc
        bound, _, plaintext = decoded.partition("\n")
        if bound != context:
            raise CryptoError("the stored token belongs to a different record")
        return plaintext


def get_cipher() -> TokenCipher | None:
    """The configured cipher, or None when provider connections are not set up."""
    keys = load_config().provider_token_keys
    return TokenCipher(keys) if keys else None
