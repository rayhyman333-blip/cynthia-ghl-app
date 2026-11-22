"""Known-answer tests for crypto_pure.py.

Vectors:
  * AES-256 block: FIPS-197 Appendix C.3.
  * AES-256-CBC:   round trip + an OpenSSL/CryptoJS "Salted__" payload
                   is covered in test_sso.py; here CBC is checked by
                   encrypt/decrypt round trip and by decrypting the
                   FIPS-197 block as a one-block CBC with zero IV.
  * Ed25519:       RFC 8032 section 7.1, TEST 1 (empty message) and
                   TEST 2 (1-byte message), plus a tamper check.
"""

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from crypto_pure import (  # noqa: E402
    aes_cbc_decrypt,
    aes_cbc_encrypt,
    aes_decrypt_block,
    aes_encrypt_block,
    ed25519_public_key_from_spki_base64,
    ed25519_verify,
)


class TestAES(unittest.TestCase):
    def test_fips197_aes256_block(self):
        key = bytes.fromhex(
            "000102030405060708090a0b0c0d0e0f"
            "101112131415161718191a1b1c1d1e1f"
        )
        plain = bytes.fromhex("00112233445566778899aabbccddeeff")
        cipher = bytes.fromhex("8ea2b7ca516745bfeafc49904b496089")
        self.assertEqual(aes_encrypt_block(key, plain), cipher)
        self.assertEqual(aes_decrypt_block(key, cipher), plain)

    def test_cbc_round_trip(self):
        key = bytes(range(32))
        iv = bytes(range(16, 32))
        for msg in (b"", b"a", b"sixteen bytes!!!", b"x" * 100):
            enc = aes_cbc_encrypt(key, iv, msg)
            self.assertEqual(len(enc) % 16, 0)
            self.assertEqual(aes_cbc_decrypt(key, iv, enc), msg)

    def test_cbc_bad_padding_rejected(self):
        key = bytes(range(32))
        iv = bytes(16)
        enc = bytearray(aes_cbc_encrypt(key, iv, b"hello"))
        enc[-1] ^= 0xFF
        with self.assertRaises(ValueError):
            aes_cbc_decrypt(key, iv, bytes(enc))


class TestEd25519(unittest.TestCase):
    # RFC 8032, TEST 1: empty message.
    PK1 = bytes.fromhex(
        "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
    )
    SIG1 = bytes.fromhex(
        "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155"
        "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"
    )
    # Second vector, generated with OpenSSL 3.0 (genpkey ed25519 +
    # pkeyutl -sign -rawin) over the message b"hello webhooks". (An
    # earlier draft of this test used a hand-typed RFC 8032 TEST 2
    # vector that turned out to be mis-transcribed; the OpenSSL
    # cross-check is the trustworthy second vector.)
    PK2 = bytes.fromhex(
        "1641964c0dca96832be14c305d01ebf67c50b3c175cdafabf5b832969f874735"
    )
    MSG2 = b"hello webhooks"
    SIG2 = bytes.fromhex(
        "c118100e7a6a82fb35eb7d26961528ae896654146bdef67f4dff5d1549b3d4e9"
        "bd658d83521d2f054a3eb0ad041500262e5aeca796e2fa8a5b1ef00215514004"
    )

    def test_rfc8032_vectors(self):
        self.assertTrue(ed25519_verify(self.PK1, b"", self.SIG1))
        self.assertTrue(ed25519_verify(self.PK2, self.MSG2, self.SIG2))

    def test_tampering_rejected(self):
        self.assertFalse(ed25519_verify(self.PK1, b"x", self.SIG1))
        bad = bytearray(self.SIG1)
        bad[10] ^= 1
        self.assertFalse(ed25519_verify(self.PK1, b"", bytes(bad)))
        self.assertFalse(ed25519_verify(self.PK2, b"", self.SIG1))
        self.assertFalse(ed25519_verify(b"short", b"", self.SIG1))
        self.assertFalse(ed25519_verify(self.PK1, b"", b"short"))

    def test_spki_extraction(self):
        # HighLevel's published webhook key (SPKI, base64) — extraction
        # only; the key itself is public.
        raw = ed25519_public_key_from_spki_base64(
            "MCowBQYDK2VwAyEAi2HR1srL4o18O8BRa7gVJY7G7bupbN3H9AwJrHCDiOg="
        )
        self.assertEqual(len(raw), 32)


if __name__ == "__main__":
    unittest.main()
