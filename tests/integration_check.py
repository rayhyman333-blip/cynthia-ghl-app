"""Live integration check — NOT a unit test.

Exercises the whole wrapper against the REAL Cynthia servers running
locally:
  * the Cynthia MCP server (its own venv) on 127.0.0.1:8901,
  * the Cynthia REST facade on 127.0.0.1:8902,
  * this wrapper app on 127.0.0.1:8200, configured with the throwaway
    test keys from test_bridge.py / test_sso.py.

Start the three servers first (see BUILD-REPORT.md for the commands),
then:  python3 tests/integration_check.py
Exits non-zero on the first failed check.
"""

import json
import sys
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from cynthia_client import McpTransport, RestTransport  # noqa: E402
from test_bridge import INSTALL_BODY, INSTALL_SIG_B64  # noqa: E402
from test_sso import PAYLOAD as SSO_PAYLOAD  # noqa: E402

APP = "http://127.0.0.1:8200"
MCP = "http://127.0.0.1:8901/mcp"
REST = "http://127.0.0.1:8902"

checks = 0


def check(name: str, condition: bool, extra: str = "") -> None:
    global checks
    checks += 1
    if not condition:
        print(f"FAIL: {name} {extra}")
        raise SystemExit(1)
    print(f"ok: {name}")


def req(method: str, url: str, body: bytes | None = None,
        headers: dict | None = None):
    r = urllib.request.Request(url, data=body, method=method)
    for k, v in (headers or {}).items():
        r.add_header(k, v)
    try:
        with urllib.request.urlopen(r, timeout=60) as resp:
            return resp.status, dict(resp.headers), resp.read()
    except urllib.error.HTTPError as exc:
        return exc.code, dict(exc.headers), exc.read()


def post_json(url: str, payload: dict):
    return req("POST", url, json.dumps(payload).encode(),
               {"Content-Type": "application/json"})


def main() -> int:
    # 1. Direct MCP transport against the real Cynthia server.
    mcp = McpTransport(MCP)
    status = json.loads(mcp.call_tool("cynthia_status", {}))
    check("MCP cynthia_status health ok", status["health"] == "ok")
    check("MCP verified_facts == 68", status["verified_facts"] == 68,
          f"got {status['verified_facts']}")
    answer = mcp.call_tool("ask_cynthia",
                           {"question": "Who created Cynthia?"})
    check("MCP ask_cynthia verified answer",
          answer.startswith("Verified answer:")
          and "Ramel Hyman" in answer)

    # 2. Direct REST transport against the real facade.
    rest = RestTransport(REST)
    result = rest.ask("Who created Cynthia?")
    check("REST /ask matched", result["matched"]
          and "Ramel Hyman" in result["answer"])
    result = rest.ask("Do you repair bicycles?")
    check("REST /ask honest abstention", not result["matched"])

    # 3. Wrapper health.
    code, _, body = req("GET", APP + "/health")
    health = json.loads(body)
    check("wrapper /health", code == 200 and health["status"] == "ok"
          and health["oauth_configured"] and health["sso_configured"])

    # 4. Webhook: unsigned rejected, signed INSTALL accepted.
    code, _, _ = req("POST", APP + "/webhooks/ghl", INSTALL_BODY,
                     {"Content-Type": "application/json"})
    check("webhook unsigned -> 401", code == 401)
    code, _, body = req("POST", APP + "/webhooks/ghl", INSTALL_BODY, {
        "Content-Type": "application/json",
        "X-GHL-Signature": INSTALL_SIG_B64})
    check("webhook signed INSTALL -> 200 handled",
          code == 200 and json.loads(body)["handled"])

    # 5. Custom Page headers: frameable by HighLevel, not blocked.
    code, headers, _ = req("GET", APP + "/app")
    check("custom page 200", code == 200)
    check("custom page has no X-Frame-Options",
          "X-Frame-Options" not in headers)
    check("custom page CSP frame-ancestors names HighLevel",
          "frame-ancestors" in headers.get("Content-Security-Policy", "")
          and "gohighlevel.com" in headers["Content-Security-Policy"])

    # 6. Session: decrypted context + tenant installed via webhook.
    code, _, body = post_json(APP + "/api/session",
                              {"encryptedData": SSO_PAYLOAD})
    session = json.loads(body)
    check("session decrypts context",
          code == 200 and session["context"]["userId"] == "u123")
    check("session tenant installed, demo mode",
          session["tenant"]["installed"]
          and session["tenant"]["mode"] == "demo")

    # 7. Ask through the full stack (demo -> local real Cynthia).
    code, _, body = post_json(APP + "/api/ask", {
        "encryptedData": SSO_PAYLOAD,
        "question": "Who created Cynthia?"})
    result = json.loads(body)
    check("wrapper ask verified (demo)",
          code == 200 and result["matched"]
          and "Ramel Hyman" in result["answer"]
          and result["mode"] == "demo")
    code, _, body = post_json(APP + "/api/ask", {
        "encryptedData": SSO_PAYLOAD,
        "question": "Do you repair bicycles?"})
    result = json.loads(body)
    check("wrapper ask abstains honestly",
          code == 200 and not result["matched"])

    # 8. Admin config: provision this location with its own Cynthia
    #    (the same local server, standing in for a client's instance).
    code, _, body = post_json(APP + "/api/config", {
        "encryptedData": SSO_PAYLOAD, "mode": "provisioned",
        "endpoint": MCP, "transport": "mcp"})
    check("config provisioned accepted", code == 200)
    code, _, body = post_json(APP + "/api/ask", {
        "encryptedData": SSO_PAYLOAD,
        "question": "Who created Cynthia?"})
    result = json.loads(body)
    check("wrapper ask verified (provisioned)",
          code == 200 and result["matched"]
          and result["mode"] == "provisioned"
          and result["endpoint"] == MCP)

    # 9. Install redirect: correct host, state present, cookie set.
    #    (urllib follows redirects by default — use a no-redirect
    #    opener so we can inspect the 302 itself.)
    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, req, fp, code, msg, headers, newurl):
            return None

    opener = urllib.request.build_opener(NoRedirect)
    try:
        resp = opener.open(APP + "/install", timeout=30)
        code, headers = resp.status, dict(resp.headers)
    except urllib.error.HTTPError as exc:
        code, headers = exc.code, dict(exc.headers)
    location = headers.get("Location", "")
    check("install 302 to chooselocation",
          code == 302 and location.startswith(
              "https://marketplace.gohighlevel.com/v2/oauth/"
              "chooselocation?") and "state=" in location)
    check("install sets state cookie",
          "ghl_oauth_state=" in headers.get("Set-Cookie", ""))

    print(f"\nALL {checks} INTEGRATION CHECKS PASSED")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
