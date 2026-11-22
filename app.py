"""Cynthia for HighLevel — the Marketplace wrapper app.

A thin, standard-library-only Python server (the same stack rule as
Cynthia herself: no dependencies, no paid services) implementing
HighLevel's documented Marketplace app flows:

  GET  /install          -> 302 to HighLevel's chooselocation OAuth
                            URL with a single-use CSRF `state`.
  GET  /oauth/callback   -> validates state, exchanges the code at
                            services.leadconnectorhq.com/oauth/token,
                            stores tokens per location/company, and
                            creates the tenant (bridge) record.
  POST /webhooks/ghl     -> Ed25519-verified (X-GHL-Signature) webhook
                            receiver: INSTALL activates a tenant,
                            UNINSTALL deactivates it and drops tokens.
  GET  /app              -> the Custom Page (iframe) UI. Served with
                            a CSP frame-ancestors header allowing
                            HighLevel embedding and NO X-Frame-Options
                            (either would blank the page inside GHL).
  POST /api/session      -> decrypts the Custom Page user-context
                            payload (Shared Secret, server-side only)
                            and returns the context + tenant status.
  POST /api/ask          -> {encryptedData, question}: decrypts the
                            context to learn WHICH location is asking
                            (never trusts a browser-sent locationId),
                            then routes the question to that location's
                            Cynthia via the bridge.
  POST /api/config       -> {encryptedData, mode, transport, endpoint}:
                            admin-only; points a location at its own
                            provisioned Cynthia endpoint.
  GET  /health           -> liveness + which integrations are set up.

Usage:
  python3 app.py            # 127.0.0.1:8200, env-configured
See .env.example and README.md.
"""

from __future__ import annotations

import json
import sys
import time
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

sys.path.insert(0, str(Path(__file__).resolve().parent))

import ghl_oauth  # noqa: E402
import ghl_webhooks  # noqa: E402
from config import Config  # noqa: E402
from cynthia_client import CynthiaBridge, CynthiaError  # noqa: E402
from ghl_sso import decrypt_user_context, location_id_from_context  # noqa: E402
from store import Store  # noqa: E402

APP_NAME = "cynthia-for-highlevel"
APP_VERSION = "0.1.0"
STATIC_DIR = Path(__file__).resolve().parent / "static"

# OAuth state values: single-use, 10-minute TTL (docs: codes expire
# in 5 minutes; the state only needs to outlive the consent screen).
_STATE_TTL_SECONDS = 600
_pending_states: dict[str, float] = {}


def _prune_states() -> None:
    now = time.time()
    for state in [s for s, ts in _pending_states.items()
                  if now - ts > _STATE_TTL_SECONDS]:
        _pending_states.pop(state, None)


WELCOME_HTML = """<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<title>Cynthia — installed</title></head>
<body style="font-family: system-ui, sans-serif; margin: 3rem;">
<h1>Cynthia is installed</h1>
<p>{detail}</p>
<p>Open Cynthia from inside HighLevel (the app's Custom Page) to ask
her questions and, as an admin, to point this location at its own
provisioned Cynthia.</p>
</body></html>
"""


def _endpoint_ok(endpoint) -> bool:
    """Provisioned Cynthia endpoints must be https:// (HighLevel apps
    are served over HTTPS, and a client's questions should never cross
    the wire in cleartext). The one exception is loopback, so the app
    can be developed against a local Cynthia."""
    if not isinstance(endpoint, str):
        return False
    if endpoint.startswith("https://"):
        return True
    parsed = urlparse(endpoint)
    return parsed.scheme == "http" and parsed.hostname in (
        "127.0.0.1", "localhost", "::1")


class App:
    def __init__(self, config: Config):
        self.config = config
        self.store = Store(config.store_path)
        self.bridge = CynthiaBridge(config, self.store)


class Handler(BaseHTTPRequestHandler):
    server_version = "CynthiaGHL/0.1.0"
    protocol_version = "HTTP/1.1"
    app: App  # set by serve()

    # -- plumbing -------------------------------------------------------
    def _send(self, code: int, body: bytes, content_type: str,
              extra_headers: dict | None = None) -> None:
        self.send_response(code)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Content-Type-Options", "nosniff")
        for key, value in (extra_headers or {}).items():
            self.send_header(key, value)
        self.end_headers()
        self.wfile.write(body)

    def _send_json(self, code: int, payload: dict) -> None:
        self._send(code, json.dumps(payload, indent=2).encode("utf-8"),
                   "application/json; charset=utf-8")

    def _read_json(self) -> dict:
        try:
            length = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            length = 0
        raw = self.rfile.read(length) if length > 0 else b""
        if not raw:
            return {}
        try:
            data = json.loads(raw.decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            return {}
        return data if isinstance(data, dict) else {}

    def _context_from(self, payload: dict) -> dict:
        """Decrypt the user context from a request body, or raise
        ValueError. This is the ONLY way API routes learn who is
        asking — a browser-supplied locationId is never trusted."""
        encrypted = payload.get("encryptedData")
        if not encrypted:
            raise ValueError("missing encryptedData")
        if not self.app.config.ghl_shared_secret:
            raise ValueError("GHL_SHARED_SECRET is not configured")
        return decrypt_user_context(
            encrypted, self.app.config.ghl_shared_secret)

    # -- routes -----------------------------------------------------------
    def do_GET(self) -> None:  # noqa: N802
        parsed = urlparse(self.path)
        path = parsed.path.rstrip("/") or "/"
        query = parse_qs(parsed.query)
        try:
            if path == "/health":
                cfg = self.app.config
                self._send_json(200, {
                    "status": "ok",
                    "service": APP_NAME,
                    "version": APP_VERSION,
                    "oauth_configured": bool(cfg.ghl_client_id
                                             and cfg.ghl_client_secret),
                    "sso_configured": bool(cfg.ghl_shared_secret),
                    "demo_cynthia": cfg.cynthia_mcp_url,
                    "rest_facade_configured": bool(cfg.cynthia_rest_url),
                })
            elif path == "/install":
                self._install()
            elif path == "/oauth/callback":
                self._oauth_callback(query)
            elif path == "/app":
                self._custom_page()
            else:
                self._send_json(404, {"error": "not_found", "path": path})
        except Exception as exc:  # never leak a stack trace to GHL
            self._send_json(500, {"error": "internal", "detail": str(exc)})

    def do_POST(self) -> None:  # noqa: N802
        parsed = urlparse(self.path)
        path = parsed.path.rstrip("/") or "/"
        try:
            if path == "/webhooks/ghl":
                self._webhook()
            elif path == "/api/session":
                self._api_session()
            elif path == "/api/ask":
                self._api_ask()
            elif path == "/api/config":
                self._api_config()
            else:
                self._send_json(404, {"error": "not_found", "path": path})
        except Exception as exc:
            self._send_json(500, {"error": "internal", "detail": str(exc)})

    # -- OAuth ------------------------------------------------------------
    def _install(self) -> None:
        cfg = self.app.config
        if not cfg.ghl_client_id:
            self._send_json(500, {
                "error": "not_configured",
                "detail": "GHL_CLIENT_ID is not set; create the app in "
                          "the HighLevel Developer Portal first (see "
                          "listing/app-manifest.json).",
            })
            return
        _prune_states()
        state = ghl_oauth.new_state()
        _pending_states[state] = time.time()
        url = ghl_oauth.build_install_url(cfg, state)
        self._send(302, b"", "text/plain", {
            "Location": url,
            "Set-Cookie": f"ghl_oauth_state={state}; Path=/; "
                          "HttpOnly; SameSite=Lax; Max-Age=600",
        })

    def _oauth_callback(self, query: dict) -> None:
        cfg = self.app.config
        store = self.app.store
        code = (query.get("code") or [""])[0]
        state = (query.get("state") or [""])[0]
        cookie_state = ""
        cookie = SimpleCookie(self.headers.get("Cookie") or "")
        if "ghl_oauth_state" in cookie:
            cookie_state = cookie["ghl_oauth_state"].value
        _prune_states()
        if (not state or state != cookie_state
                or _pending_states.pop(state, None) is None):
            self._send_json(400, {
                "error": "bad_state",
                "detail": "OAuth state missing, mismatched, or already "
                          "used. Restart the install.",
            })
            return
        if not code:
            self._send_json(400, {"error": "missing_code"})
            return
        try:
            tokens, raw = ghl_oauth.exchange_code(cfg, code)
        except Exception as exc:
            self._send_json(502, {"error": "token_exchange_failed",
                                  "detail": str(exc)})
            return
        location_id = raw.get("locationId")
        company_id = raw.get("companyId")
        detail_bits = []
        if location_id:
            store.upsert_tenant(
                location_id, company_id=company_id, installed=True,
                installed_at=int(time.time()))
            store.set_tenant_tokens(location_id, tokens)
            detail_bits.append(f"Location {location_id} connected.")
        if company_id:
            store.upsert_company(company_id, installed=True)
            if raw.get("userType") == "Company" or not location_id:
                store.set_company_tokens(company_id, tokens)
            detail_bits.append(f"Agency {company_id} connected.")
            if raw.get("isBulkInstallation"):
                detail_bits.append(
                    "Bulk installation: per-location tokens are "
                    "exchanged via /oauth/locationToken when a "
                    "location first uses Cynthia.")
        if not detail_bits:
            detail_bits.append(
                "Connected, but the token response carried no "
                "locationId or companyId — check the app's target-user "
                "setting in the portal.")
        html = WELCOME_HTML.format(detail=" ".join(detail_bits))
        self._send(200, html.encode("utf-8"),
                   "text/html; charset=utf-8")

    # -- Webhooks -----------------------------------------------------------
    def _webhook(self) -> None:
        try:
            length = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            length = 0
        raw = self.rfile.read(length) if length > 0 else b""
        headers = {k: v for k, v in self.headers.items()}
        if not ghl_webhooks.verify_signature(self.app.config, raw, headers):
            self._send_json(401, {"error": "bad_signature"})
            return
        try:
            payload = json.loads(raw.decode("utf-8")) if raw else {}
        except (ValueError, UnicodeDecodeError):
            self._send_json(400, {"error": "invalid_json"})
            return
        summary = ghl_webhooks.handle_event(self.app.store, payload)
        self._send_json(200, {"received": True, **summary})

    # -- Custom Page + API --------------------------------------------------
    def _custom_page(self) -> None:
        page = STATIC_DIR / "custom-page.html"
        try:
            body = page.read_bytes()
        except OSError:
            self._send_json(500, {"error": "page_missing"})
            return
        # Iframe embedding inside HighLevel is the entire point of a
        # Custom Page: no X-Frame-Options, and a CSP frame-ancestors
        # that names HighLevel's domains (incl. white-label domain
        # host) instead of blocking framing.
        self._send(200, body, "text/html; charset=utf-8", {
            "Content-Security-Policy":
                "frame-ancestors 'self' https://app.gohighlevel.com "
                "https://*.gohighlevel.com "
                "https://*.leadconnectorhq.com",
            "Cache-Control": "no-store",
        })

    def _tenant_status(self, context: dict) -> dict:
        location_id = location_id_from_context(context)
        tenant = self.app.store.get_tenant(location_id) if location_id \
            else None
        status = {
            "installed": bool(tenant and tenant.get("installed")),
            "location_id": location_id,
            "company_id": context.get("companyId"),
        }
        if tenant:
            mode, transport, endpoint = self.app.bridge.resolve(tenant)
            status.update({"mode": mode, "transport": transport,
                           "endpoint": endpoint})
        return status

    def _api_session(self) -> None:
        payload = self._read_json()
        try:
            context = self._context_from(payload)
        except ValueError as exc:
            self._send_json(401, {"error": "bad_context",
                                  "detail": str(exc)})
            return
        safe = {k: context.get(k) for k in (
            "userId", "companyId", "role", "type", "activeLocation",
            "userName", "email", "isAgencyOwner", "region", "appStatus")}
        self._send_json(200, {"context": safe,
                              "tenant": self._tenant_status(context)})

    def _api_ask(self) -> None:
        payload = self._read_json()
        try:
            context = self._context_from(payload)
        except ValueError as exc:
            self._send_json(401, {"error": "bad_context",
                                  "detail": str(exc)})
            return
        location_id = location_id_from_context(context)
        if not location_id:
            self._send_json(400, {
                "error": "no_location",
                "detail": "Cynthia answers per location (sub-account). "
                          "Open her from inside a location, not the "
                          "agency view.",
            })
            return
        question = payload.get("question")
        if not isinstance(question, str) or not question.strip():
            self._send_json(400, {"error": "missing_question"})
            return
        try:
            result = self.app.bridge.ask(location_id, question)
        except CynthiaError as exc:
            self._send_json(502, {"error": "cynthia_unavailable",
                                  "detail": str(exc)})
            return
        self._send_json(200, result)

    def _api_config(self) -> None:
        payload = self._read_json()
        try:
            context = self._context_from(payload)
        except ValueError as exc:
            self._send_json(401, {"error": "bad_context",
                                  "detail": str(exc)})
            return
        if context.get("role") != "admin":
            self._send_json(403, {
                "error": "admin_only",
                "detail": "Only location/agency admins can change "
                          "which Cynthia this location uses.",
            })
            return
        location_id = location_id_from_context(context)
        tenant = self.app.store.get_tenant(location_id) if location_id \
            else None
        if tenant is None:
            self._send_json(404, {"error": "unknown_location"})
            return
        mode = payload.get("mode")
        if mode == "demo":
            cynthia = {"mode": "demo", "transport": "mcp",
                       "endpoint": None}
        elif mode == "provisioned":
            endpoint = payload.get("endpoint")
            transport = payload.get("transport", "mcp")
            if transport not in ("mcp", "rest"):
                self._send_json(400, {"error": "bad_transport"})
                return
            if not _endpoint_ok(endpoint):
                self._send_json(400, {
                    "error": "bad_endpoint",
                    "detail": "Provisioned mode needs the https:// "
                              "endpoint of this business's own Cynthia "
                              "(provided by Planet Leads at setup). "
                              "Plain http is accepted only for "
                              "loopback local development.",
                })
                return
            cynthia = {"mode": "provisioned", "transport": transport,
                       "endpoint": endpoint}
        else:
            self._send_json(400, {"error": "bad_mode"})
            return
        updated = self.app.store.set_tenant_cynthia(location_id, cynthia)
        self._send_json(200, {"tenant": self._tenant_status(context),
                              "cynthia": updated["cynthia"]})

    def log_message(self, fmt: str, *args) -> None:
        sys.stderr.write("%s - %s\n" % (self.address_string(),
                                        fmt % args))


def serve(config: Config | None = None) -> int:
    config = config or Config.from_env()
    handler = type("BoundHandler", (Handler,), {})
    handler.app = App(config)  # type: ignore[attr-defined]
    server = ThreadingHTTPServer((config.host, config.port), handler)
    print(f"{APP_NAME} {APP_VERSION} listening on "
          f"http://{config.host}:{config.port}", file=sys.stderr)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    return 0


if __name__ == "__main__":
    raise SystemExit(serve())
