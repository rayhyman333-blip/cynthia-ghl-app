"""HighLevel Custom Page user-context decryption.

Per HighLevel's official "User Context in Marketplace Apps" doc
(marketplace.gohighlevel.com/docs/other/user-context-marketplace-apps):
the Custom Page iframe asks the parent CRM window for user data via
postMessage ({message: "REQUEST_USER_DATA"}), receives an encrypted
payload in the REQUEST_USER_DATA_RESPONSE message, and the app's
BACKEND decrypts it with the app's Shared Secret (generated in the
portal under Advanced Settings -> Auth). The doc's reference backend
uses CryptoJS.AES.decrypt(encrypted, sharedSecret), which is the
OpenSSL-compatible format:

    base64( "Salted__" || 8-byte salt || AES-256-CBC ciphertext )
    key/IV derived with EVP_BytesToKey (MD5, 1 iteration):
        key = 32 bytes, iv = 16 bytes, passphrase = the Shared Secret.

The decrypted JSON carries userId, companyId, role, type, userName,
email, isAgencyOwner, region, versionId, appStatus, whitelabelDetails,
and — in a Location context — activeLocation. The doc warns the payload
is additive: read the keys you need, never reject unknown keys.

The Shared Secret must never reach the browser; decryption happens
only here, server-side.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json

from crypto_pure import aes_cbc_decrypt

_SALTED_MAGIC = b"Salted__"


def _evp_bytes_to_key(password: bytes, salt: bytes,
                      key_len: int, iv_len: int) -> tuple[bytes, bytes]:
    """OpenSSL EVP_BytesToKey with MD5 and 1 iteration (the CryptoJS
    default derivation for passphrase-based AES)."""
    derived = b""
    block = b""
    while len(derived) < key_len + iv_len:
        block = hashlib.md5(block + password + salt).digest()
        derived += block
    return derived[:key_len], derived[key_len:key_len + iv_len]


def decrypt_user_context(encrypted_b64: str, shared_secret: str) -> dict:
    """Decrypt a HighLevel user-context payload and return the parsed
    JSON object. Raises ValueError on any malformed input — callers
    should treat that as "no trustworthy context", never fall back to
    trusting anything the browser sent."""
    if not encrypted_b64 or not shared_secret:
        raise ValueError("missing encrypted payload or shared secret")
    try:
        raw = base64.b64decode(encrypted_b64, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise ValueError("payload is not valid base64") from exc
    if len(raw) < 16 or not raw.startswith(_SALTED_MAGIC):
        raise ValueError("payload is not in OpenSSL Salted__ format")
    salt = raw[8:16]
    ciphertext = raw[16:]
    key, iv = _evp_bytes_to_key(shared_secret.encode("utf-8"), salt, 32, 16)
    try:
        plaintext = aes_cbc_decrypt(key, iv, ciphertext)
    except ValueError as exc:
        raise ValueError("payload decryption failed") from exc
    try:
        data = json.loads(plaintext.decode("utf-8"))
    except (UnicodeDecodeError, ValueError) as exc:
        raise ValueError("decrypted payload is not valid JSON") from exc
    if not isinstance(data, dict):
        raise ValueError("decrypted payload is not a JSON object")
    return data


def location_id_from_context(context: dict) -> str | None:
    """The location (sub-account) a decrypted context belongs to, if
    any. Location contexts carry `activeLocation`; some payloads use
    `locationId`. Agency contexts have neither."""
    for key in ("activeLocation", "locationId"):
        value = context.get(key)
        if isinstance(value, str) and value:
            return value
    return None
