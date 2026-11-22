"""Tests for ghl_sso.decrypt_user_context.

The fixture payload was generated with OpenSSL 3.0, which produces
exactly the CryptoJS passphrase format HighLevel's doc specifies:

    printf '%s' '<json>' | openssl enc -aes-256-cbc -md md5 -salt \
        -base64 -pass pass:test-shared-secret

Plaintext JSON:
{"userId":"u123","companyId":"c456","role":"admin","type":"location",
 "activeLocation":"loc789","userName":"Test User",
 "email":"t@example.com","isAgencyOwner":false,"region":"us"}
"""

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from ghl_sso import decrypt_user_context, location_id_from_context  # noqa: E402

PAYLOAD = (
    "U2FsdGVkX1+2N1GueUAqRe3VcRh68USIpp+CV8FYsHHtR6YJJqRqBQgUjbCJq3Gh5"
    "HlbjyUFfZTSCvz68jp86rdkXbDDWqYKJ0YnLlBHshjuMLeO4RunuOVHT+Iujf3l"
    "C5kvaWT99mERIwYVmsr/ydJjxtR+jm1XesKdPHQD+OEkBwuj6WxOGPOpr3vKu4k"
    "x4udnuS63QkoSjAEdI07DB/RKmM1HK9Apl8EV52rHhQ/NtL1FNxCxtXu5CV809A"
    "063KiTLPOFcRd7PGv4kASaZg=="
)
SECRET = "test-shared-secret"


class TestSSO(unittest.TestCase):
    def test_openssl_payload_decrypts(self):
        ctx = decrypt_user_context(PAYLOAD, SECRET)
        self.assertEqual(ctx["userId"], "u123")
        self.assertEqual(ctx["companyId"], "c456")
        self.assertEqual(ctx["region"], "us")
        self.assertEqual(location_id_from_context(ctx), "loc789")

    def test_wrong_secret_rejected(self):
        with self.assertRaises(ValueError):
            decrypt_user_context(PAYLOAD, "wrong-secret")

    def test_garbage_rejected(self):
        for bad in ("", "not base64 !!!", "aGVsbG8="):
            with self.assertRaises(ValueError):
                decrypt_user_context(bad, SECRET)

    def test_agency_context_has_no_location(self):
        self.assertIsNone(location_id_from_context({"companyId": "c1"}))
        self.assertEqual(
            location_id_from_context({"locationId": "L9"}), "L9")


if __name__ == "__main__":
    unittest.main()
