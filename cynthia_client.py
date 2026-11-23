"""The bridge to Cynthia — the heart of this wrapper.

Cynthia's REAL, implemented API surface (inspected 2026-11-22 in
~/workspace/work/cynthia-mcp-server and ~/workspace/work/cynthia-api-facade):

  LIVE — MCP over Streamable HTTP at
  https://cynthia-mcp-server-6d5fb7.apps.deployvera.com/mcp, tools:
      ask_cynthia(question)  -> "Verified answer:\n..." or an honest
                                "I don't know — ..." abstention, or
                                "Clarification needed:\n..."
      cynthia_status()       -> JSON health/fact-count
      cynthia_capabilities() -> plain text

  IMPLEMENTED BUT NOT DEPLOYED — the REST facade (same behaviour):
      POST /ask {"question": ...} -> {matched, source, fact_id, answer}
      GET  /status, GET /capabilities, GET /health

So this client speaks MCP JSON-RPC to the live server by default
(transport "mcp"), and can speak REST to a facade base URL
(transport "rest") for any tenant whose Cynthia is served that way.

TENANCY — the honest part. Cynthia's existing APIs serve ONE fact
store per deployment; there is no store selector parameter, because a
white-label Cynthia IS her own deployment with her own approved
verified_store.json (Planet Leads stamps one Cynthia per business).
The bridge therefore routes per HighLevel location:

  * mode "provisioned": the location points at that business's own
    Cynthia endpoint (set on the app config screen after Planet Leads
    provisions the business's Cynthia). Questions go only there.
  * mode "demo" (default for a fresh install): questions go to the
    shared LIVE Cynthia — Planet Leads' own fact store. The UI labels
    this DEMO in plain sight, because those are Planet Leads' facts,
    not the client's. A client location must be switched to
    "provisioned" before it serves real customers.

No question is ever answered from the wrong store silently: the mode
travels with every response and is shown in the page.
"""

from __future__ import annotations

import json
import urllib.request

DEFAULT_MCP_URL = "https://cynthia-mcp-server-6d5fb7.apps.deployvera.com/mcp"
_PROTOCOL_VERSION = "2025-03-26"


class CynthiaError(Exception):
    pass


def _parse_mcp_body(raw: bytes, content_type: str) -> dict:
    """A Streamable HTTP MCP response is either a single JSON object
    or an SSE stream of `data:` lines. Return the JSON-RPC object."""
    text = raw.decode("utf-8", errors="replace")
    if "text/event-stream" in (content_type or ""):
        result = None
        for line in text.splitlines():
            line = line.strip()
            if line.startswith("data:"):
                try:
                    obj = json.loads(line[5:].strip())
                except ValueError:
                    continue
                if isinstance(obj, dict) and ("result" in obj or "error" in obj):
                    result = obj
        if result is None:
            raise CynthiaError("MCP server returned an unreadable SSE stream")
        return result
    try:
        return json.loads(text)
    except ValueError as exc:
        raise CynthiaError("MCP server returned non-JSON") from exc


class McpTransport:
    """Minimal MCP Streamable HTTP client: initialize handshake,
    session-id handling, notifications/initialized, tools/call.
    Sessions are cached per endpoint; a stale session is rebuilt once
    on failure. Stateless servers (no session id) work too."""

    def __init__(self, url: str, timeout: int = 60):
        self.url = url
        self.timeout = timeout
        self._session_id: str | None = None
        self._next_id = 0

    def _post(self, payload: dict, session: bool = True) -> tuple[dict, dict]:
        self._next_id += 1
        body = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(self.url, data=body, method="POST")
        req.add_header("Content-Type", "application/json")
        req.add_header("Accept", "application/json, text/event-stream")
        if session and self._session_id:
            req.add_header("Mcp-Session-Id", self._session_id)
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                headers = {k.lower(): v for k, v in resp.headers.items()}
                raw = resp.read()
        except urllib.error.HTTPError as exc:  # type: ignore[attr-defined]
            raise CynthiaError(f"MCP HTTP {exc.code}") from exc
        except OSError as exc:
            raise CynthiaError(f"MCP request failed: {exc}") from exc
        if not raw:
            return {}, headers
        return _parse_mcp_body(raw, headers.get("content-type", "")), headers

    def _ensure_session(self) -> None:
        if self._session_id is not None:
            return
        result, headers = self._post({
            "jsonrpc": "2.0",
            "id": 0,
            "method": "initialize",
            "params": {
                "protocolVersion": _PROTOCOL_VERSION,
                "capabilities": {},
                "clientInfo": {"name": "cynthia-for-highlevel",
                               "version": "0.1.0"},
            },
        }, session=False)
        if "error" in result:
            raise CynthiaError(f"MCP initialize failed: {result['error']}")
        self._session_id = headers.get("mcp-session-id")
        # Notification: no response body expected.
        try:
            self._post({"jsonrpc": "2.0",
                        "method": "notifications/initialized"})
        except CynthiaError:
            pass

    def call_tool(self, name: str, arguments: dict) -> str:
        for attempt in (1, 2):
            try:
                self._ensure_session()
                result, _ = self._post({
                    "jsonrpc": "2.0",
                    "id": self._next_id + 1,
                    "method": "tools/call",
                    "params": {"name": name, "arguments": arguments},
                })
                break
            except CynthiaError:
                if attempt == 2:
                    raise
                self._session_id = None  # stale session: rebuild once
        if "error" in result:
            raise CynthiaError(f"MCP tool error: {result['error']}")
        content = (result.get("result") or {}).get("content") or []
        texts = [c.get("text", "") for c in content
                 if isinstance(c, dict) and c.get("type") == "text"]
        if not texts:
            raise CynthiaError("MCP tool returned no text content")
        return "\n".join(texts)


class RestTransport:
    """Client for Cynthia's REST facade (POST /ask). Used only for
    tenants whose Cynthia is served by a facade deployment."""

    def __init__(self, base_url: str, timeout: int = 60):
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout

    def ask(self, question: str) -> dict:
        body = json.dumps({"question": question}).encode("utf-8")
        req = urllib.request.Request(
            self.base_url + "/ask", data=body, method="POST")
        req.add_header("Content-Type", "application/json")
        req.add_header("Accept", "application/json")
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                data = json.loads(resp.read().decode("utf-8"))
        except OSError as exc:
            raise CynthiaError(f"REST ask failed: {exc}") from exc
        return {
            "answer": data.get("answer", ""),
            "matched": bool(data.get("matched")),
            "source": data.get("source", "unknown"),
            "fact_id": data.get("fact_id"),
        }


def _classify_mcp_answer(text: str) -> dict:
    """Map ask_cynthia's text protocol onto the facade's structured
    shape, so callers see one answer format for both transports."""
    if text.startswith("Verified answer:"):
        return {"answer": text, "matched": True,
                "source": "verified_lookup", "fact_id": None}
    if text.startswith("Clarification needed:"):
        return {"answer": text, "matched": False,
                "source": "clarification", "fact_id": None}
    return {"answer": text, "matched": False,
            "source": "unknown", "fact_id": None}


class CynthiaBridge:
    """Routes a location's question to that location's Cynthia."""

    def __init__(self, config, store):
        self.config = config
        self.store = store
        self._mcp_clients: dict[str, McpTransport] = {}

    def _mcp(self, url: str) -> McpTransport:
        client = self._mcp_clients.get(url)
        if client is None:
            client = McpTransport(url)
            self._mcp_clients[url] = client
        return client

    def resolve(self, tenant: dict) -> tuple[str, str, str]:
        """Return (mode, transport, endpoint) for a tenant."""
        cynthia = tenant.get("cynthia") or {}
        mode = cynthia.get("mode", "demo")
        if mode == "provisioned" and cynthia.get("endpoint"):
            return "provisioned", cynthia.get("transport", "mcp"), \
                cynthia["endpoint"]
        # Demo mode: the shared live Cynthia. REST only if a facade
        # base URL has actually been configured.
        if self.config.cynthia_rest_url:
            return "demo", "rest", self.config.cynthia_rest_url
        return "demo", "mcp", self.config.cynthia_mcp_url

    def ask(self, location_id: str, question: str) -> dict:
        tenant = self.store.get_tenant(location_id)
        if tenant is None or not tenant.get("installed"):
            raise CynthiaError(
                "Cynthia is not installed for this location.")
        mode, transport, endpoint = self.resolve(tenant)
        if transport == "rest":
            result = RestTransport(endpoint).ask(question)
        else:
            text = self._mcp(endpoint).call_tool(
                "ask_cynthia", {"question": question})
            result = _classify_mcp_answer(text)
        result.update({
            "mode": mode,
            "transport": transport,
            "endpoint": endpoint,
            "location_id": location_id,
        })
        return result

    def status(self, location_id: str) -> dict:
        tenant = self.store.get_tenant(location_id)
        if tenant is None:
            raise CynthiaError("Unknown location.")
        mode, transport, endpoint = self.resolve(tenant)
        if transport == "rest":
            req = urllib.request.Request(endpoint.rstrip("/") + "/status")
            try:
                with urllib.request.urlopen(req, timeout=30) as resp:
                    data = json.loads(resp.read().decode("utf-8"))
            except OSError as exc:
                raise CynthiaError(f"REST status failed: {exc}") from exc
        else:
            text = self._mcp(endpoint).call_tool("cynthia_status", {})
            data = json.loads(text)
        return {"mode": mode, "transport": transport,
                "endpoint": endpoint, "cynthia": data}
