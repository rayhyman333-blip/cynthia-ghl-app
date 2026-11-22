"""Environment-based configuration for the Cynthia for HighLevel app.

Everything secret comes from the environment (the Planet Leads rule:
secrets in shell env only, never in code, never in the repo). See
.env.example for the full list. Nothing in this file has a real
default for a secret — missing secrets disable the feature that needs
them and say so, they never fall back to a baked-in value.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field


@dataclass
class Config:
    # HighLevel app credentials (from the Developer Portal, once the
    # app is created there — Advanced Settings -> Auth -> Client Keys).
    ghl_client_id: str = ""
    ghl_client_secret: str = ""
    # Shared Secret for Custom Page user-context decryption (portal:
    # Advanced Settings -> Auth -> Shared Secret).
    ghl_shared_secret: str = ""
    # The redirect URI registered in the portal; must match exactly.
    ghl_redirect_uri: str = "http://127.0.0.1:8200/oauth/callback"
    # Scopes requested at install. Minimum-necessary is HighLevel's own
    # documented best practice, and this wrapper's v1 surface (a Custom
    # Page that talks to Cynthia, not to HighLevel data) needs none.
    # Phase 2 (answering inside GHL Conversations) would add:
    #   conversations/message.readonly conversations/message.write
    ghl_scopes: str = ""
    # "Location" or "Company" — must match how the app is configured
    # in the portal. The documented recommendation (and ours) is a
    # Sub-account target user, i.e. Location installs, with bulk
    # install handled through a Company token + locationToken exchange.
    ghl_user_type: str = "Location"
    # White-label install domain variant (portal provides both links).
    ghl_whitelabel_install: bool = False

    # Cynthia bridge defaults. The LIVE Cynthia is the MCP server;
    # the REST facade endpoints exist in code (~/workspace/work/
    # cynthia-api-facade) but the facade is not deployed, so "mcp"
    # against the live server is the working default.
    cynthia_mcp_url: str = "https://cynthia-mcp-server.onrender.com/mcp"
    cynthia_rest_url: str = ""  # set when a facade deployment exists

    # Server + storage.
    host: str = "127.0.0.1"
    port: int = 8200
    store_path: str = "data/store.json"
    # Webhook signature checking: HighLevel's current scheme is
    # Ed25519 via the X-GHL-Signature header. Their published public
    # key (SPKI, base64) is a public value, safe to ship as a default.
    ghl_webhook_public_key_b64: str = (
        "MCowBQYDK2VwAyEAi2HR1srL4o18O8BRa7gVJY7G7bupbN3H9AwJrHCDiOg="
    )
    # Legacy RSA scheme (X-WH-Signature) is deprecated by HighLevel on
    # 2026-07-01; we do not implement it. Verification can be relaxed
    # ONLY for local development:
    webhook_allow_unsigned_local: bool = False

    extra: dict = field(default_factory=dict)

    @classmethod
    def from_env(cls) -> "Config":
        env = os.environ.get
        return cls(
            ghl_client_id=env("GHL_CLIENT_ID", ""),
            ghl_client_secret=env("GHL_CLIENT_SECRET", ""),
            ghl_shared_secret=env("GHL_SHARED_SECRET", ""),
            ghl_redirect_uri=env(
                "GHL_REDIRECT_URI", "http://127.0.0.1:8200/oauth/callback"),
            ghl_scopes=env("GHL_SCOPES", ""),
            ghl_user_type=env("GHL_USER_TYPE", "Location"),
            ghl_whitelabel_install=env(
                "GHL_WHITELABEL_INSTALL", "").lower() in ("1", "true"),
            cynthia_mcp_url=env(
                "CYNTHIA_MCP_URL",
                "https://cynthia-mcp-server.onrender.com/mcp"),
            cynthia_rest_url=env("CYNTHIA_REST_URL", ""),
            host=env("HOST", "127.0.0.1"),
            port=int(env("PORT", "8200")),
            store_path=env("STORE_PATH", "data/store.json"),
            ghl_webhook_public_key_b64=env(
                "GHL_WEBHOOK_PUBLIC_KEY_B64",
                "MCowBQYDK2VwAyEAi2HR1srL4o18O8BRa7gVJY7G7bupbN3H9AwJrHCDiOg="),
            webhook_allow_unsigned_local=env(
                "WEBHOOK_ALLOW_UNSIGNED_LOCAL", "").lower() in ("1", "true"),
        )

    @property
    def install_base(self) -> str:
        if self.ghl_whitelabel_install:
            return "https://marketplace.leadconnectorhq.com"
        return "https://marketplace.gohighlevel.com"
