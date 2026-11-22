"""Tests for the tenant store, the webhook handler + signature check,
OAuth URL/state handling, and the Cynthia bridge routing (with the
transports stubbed — the live transports are exercised separately in
tests/test_live_cynthia.py).
"""

import sys
import tempfile
import time
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import cynthia_client  # noqa: E402
import ghl_oauth  # noqa: E402
import ghl_webhooks  # noqa: E402
from config import Config  # noqa: E402
from cynthia_client import CynthiaBridge  # noqa: E402
from store import Store  # noqa: E402

# Throwaway Ed25519 test keypair (OpenSSL-generated for these tests
# only — NOT HighLevel's key and NOT a credential for anything).
TEST_KEY_SPKI_B64 = \
    "MCowBQYDK2VwAyEAFkGWTA3KloMr4UwwXQHr9nxQs8F1za+r9bgylp+HRzU="
INSTALL_BODY = (
    b'{"type":"INSTALL","appId":"app123","versionId":"app123",'
    b'"installType":"Location","locationId":"loc789","companyId":"c456",'
    b'"userId":"u123","companyName":"Test Agency",'
    b'"isWhitelabelCompany":true,'
    b'"whitelabelDetails":{"logoUrl":"https://example.com/logo.gif",'
    b'"domain":"test.example.com"},'
    b'"timestamp":"2026-11-22T00:00:00.000Z","webhookId":"wh-1"}'
)
INSTALL_SIG_B64 = (
    "Me7Doi9BQ/R6lxAIat//upVvr4J3j2EaaGA7E1m59XlSJNe6CB5SXRnpwOICOi/"
    "SFLOFOJljO2kB4VuaRnL+Ag=="
)


def make_store() -> Store:
    tmp = tempfile.NamedTemporaryFile(suffix=".json", delete=False)
    tmp.close()
    return Store(tmp.name)


def make_config(**overrides) -> Config:
    cfg = Config(
        ghl_client_id="cid-123",
        ghl_client_secret="secret",
        ghl_shared_secret="test-shared-secret",
        ghl_redirect_uri="https://example.com/oauth/callback",
        ghl_webhook_public_key_b64=TEST_KEY_SPKI_B64,
        cynthia_mcp_url="https://demo.example/mcp",
    )
    for key, value in overrides.items():
        setattr(cfg, key, value)
    return cfg


class TestStore(unittest.TestCase):
    def test_tenant_round_trip(self):
        store = make_store()
        store.upsert_tenant("L1", company_id="C1", installed=True)
        store.set_tenant_tokens("L1", {"access_token": "a"})
        tenant = store.get_tenant("L1")
        self.assertTrue(tenant["installed"])
        self.assertEqual(tenant["tokens"]["access_token"], "a")
        self.assertEqual(tenant["cynthia"]["mode"], "demo")
        store.mark_uninstalled("L1")
        tenant = store.get_tenant("L1")
        self.assertFalse(tenant["installed"])
        self.assertIsNone(tenant["tokens"])


class TestWebhooks(unittest.TestCase):
    def test_signature_verifies(self):
        cfg = make_config()
        headers = {"X-GHL-Signature": INSTALL_SIG_B64}
        self.assertTrue(
            ghl_webhooks.verify_signature(cfg, INSTALL_BODY, headers))

    def test_signature_rejects_tampering(self):
        cfg = make_config()
        headers = {"X-GHL-Signature": INSTALL_SIG_B64}
        self.assertFalse(ghl_webhooks.verify_signature(
            cfg, INSTALL_BODY + b" ", headers))
        self.assertFalse(ghl_webhooks.verify_signature(cfg, INSTALL_BODY, {}))

    def test_install_uninstall_events(self):
        store = make_store()
        summary = ghl_webhooks.handle_event(store, {
            "type": "INSTALL", "locationId": "loc789",
            "companyId": "c456", "timestamp": "2026-11-22T00:00:00Z"})
        self.assertTrue(summary["handled"])
        self.assertTrue(store.get_tenant("loc789")["installed"])
        self.assertTrue(store.get_company("c456")["installed"])
        ghl_webhooks.handle_event(store, {
            "type": "UNINSTALL", "locationId": "loc789",
            "companyId": "c456"})
        self.assertFalse(store.get_tenant("loc789")["installed"])

    def test_unknown_event_acknowledged(self):
        summary = ghl_webhooks.handle_event(make_store(),
                                            {"type": "ContactCreate"})
        self.assertFalse(summary["handled"])


class TestOAuth(unittest.TestCase):
    def test_install_url_shape(self):
        cfg = make_config(ghl_scopes="conversations/message.readonly")
        url = ghl_oauth.build_install_url(cfg, "state-xyz")
        self.assertTrue(url.startswith(
            "https://marketplace.gohighlevel.com/v2/oauth/chooselocation?"))
        self.assertIn("response_type=code", url)
        self.assertIn("client_id=cid-123", url)
        self.assertIn("state=state-xyz", url)
        self.assertIn("scope=conversations%2Fmessage.readonly", url)

    def test_whitelabel_install_domain(self):
        cfg = make_config(ghl_whitelabel_install=True)
        url = ghl_oauth.build_install_url(cfg, "s")
        self.assertTrue(url.startswith(
            "https://marketplace.leadconnectorhq.com/"))


class FakeMcp:
    def __init__(self, text):
        self.text = text
        self.calls = []

    def call_tool(self, name, arguments):
        self.calls.append((name, arguments))
        return self.text


class TestBridge(unittest.TestCase):
    def setUp(self):
        self.store = make_store()
        self.store.upsert_tenant("L1", installed=True)
        self.cfg = make_config()
        self.bridge = CynthiaBridge(self.cfg, self.store)

    def test_demo_mode_routes_to_shared_cynthia(self):
        mode, transport, endpoint = self.bridge.resolve(
            self.store.get_tenant("L1"))
        self.assertEqual((mode, transport), ("demo", "mcp"))
        self.assertEqual(endpoint, "https://demo.example/mcp")

    def test_provisioned_mode_routes_to_own_endpoint(self):
        self.store.set_tenant_cynthia("L1", {
            "mode": "provisioned", "transport": "rest",
            "endpoint": "https://client.example/ask-host"})
        mode, transport, endpoint = self.bridge.resolve(
            self.store.get_tenant("L1"))
        self.assertEqual((mode, transport), ("provisioned", "rest"))
        self.assertEqual(endpoint, "https://client.example/ask-host")

    def test_ask_classifies_verified_answer(self):
        fake = FakeMcp("Verified answer:\nThe sky is blue.")
        self.bridge._mcp_clients["https://demo.example/mcp"] = fake
        result = self.bridge.ask("L1", "What colour is the sky?")
        self.assertTrue(result["matched"])
        self.assertEqual(result["source"], "verified_lookup")
        self.assertEqual(result["mode"], "demo")
        self.assertEqual(fake.calls[0][0], "ask_cynthia")

    def test_ask_classifies_abstention(self):
        fake = FakeMcp("I don't know — this isn't in my verified "
                       "knowledge.")
        self.bridge._mcp_clients["https://demo.example/mcp"] = fake
        result = self.bridge.ask("L1", "Do you repair bicycles?")
        self.assertFalse(result["matched"])
        self.assertEqual(result["source"], "unknown")

    def test_ask_uninstalled_location_rejected(self):
        self.store.upsert_tenant("L2", installed=False)
        with self.assertRaises(cynthia_client.CynthiaError):
            self.bridge.ask("L2", "anything")


class TestTokenFreshness(unittest.TestCase):
    def test_fresh_token_not_refreshed(self):
        store = make_store()
        store.upsert_tenant("L1", installed=True)
        tokens = {"access_token": "a", "refresh_token": "r",
                  "expires_at": int(time.time()) + 3600,
                  "user_type": "Location"}
        store.set_tenant_tokens("L1", tokens)
        got = ghl_oauth.ensure_fresh_tokens(make_config(), store, "L1")
        self.assertEqual(got["access_token"], "a")


if __name__ == "__main__":
    unittest.main()
