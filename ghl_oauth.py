"""HighLevel OAuth 2.0 — Authorization Code Grant, per the official
docs (marketplace.gohighlevel.com/docs/Authorization/OAuth2.0).

Flow implemented here:
  1. build_install_url(state) — the chooselocation URL the agency /
     location admin visits. `state` is a random single-use CSRF value
     (the docs recommend it; PKCE is NOT supported for this flow).
  2. exchange_code(code) — POST https://services.leadconnectorhq.com
     /oauth/token. Authorization codes expire after 5 minutes and are
     single-use. Access tokens live ~24h (expires_in 86399); refresh
    tokens live 1 year OR until used — every refresh returns a NEW
     refresh token and invalidates the old one, so the store is
     updated atomically with each refresh.
  3. refresh_tokens(...) — same endpoint, grant_type=refresh_token.
  4. get_location_token(...) — POST /oauth/locationToken exchanges a
     Company (agency) token for a per-location token; this is how
     bulk installs (userType Company + isBulkInstallation true) reach
     individual sub-accounts.

Token-endpoint body format: the docs' Get Access Token sample shows a
JSON body and their Refresh sample shows form-urlencoded. This client
sends form-urlencoded (the OAuth 2.0 standard, and the form the
refresh sample documents); the endpoint accepts it. No Version header
is sent to the token endpoint; API calls elsewhere carry
Version: 2021-07-28 (not needed by this wrapper's v1 surface).
"""

from __future__ import annotations

import json
import secrets
import time
import urllib.parse
import urllib.request

TOKEN_URL = "https://services.leadconnectorhq.com/oauth/token"
LOCATION_TOKEN_URL = "https://services.leadconnectorhq.com/oauth/locationToken"
API_VERSION_HEADER = "2021-07-28"


def new_state() -> str:
    """Cryptographically random, single-use CSRF state value."""
    return secrets.token_urlsafe(32)


def build_install_url(config, state: str) -> str:
    params = {
        "response_type": "code",
        "redirect_uri": config.ghl_redirect_uri,
        "client_id": config.ghl_client_id,
        "state": state,
    }
    if config.ghl_scopes:
        params["scope"] = config.ghl_scopes
    return (config.install_base + "/v2/oauth/chooselocation?"
            + urllib.parse.urlencode(params))


def _post_form(url: str, fields: dict, bearer: str | None = None) -> dict:
    body = urllib.parse.urlencode(fields).encode("utf-8")
    req = urllib.request.Request(url, data=body, method="POST")
    req.add_header("Content-Type", "application/x-www-form-urlencoded")
    req.add_header("Accept", "application/json")
    if bearer:
        req.add_header("Authorization", f"Bearer {bearer}")
        req.add_header("Version", API_VERSION_HEADER)
    with urllib.request.urlopen(req, timeout=30) as resp:
        return json.loads(resp.read().decode("utf-8"))


def _tokens_from_response(data: dict) -> dict:
    return {
        "access_token": data.get("access_token"),
        "refresh_token": data.get("refresh_token"),
        "expires_at": int(time.time()) + int(data.get("expires_in", 86399)),
        "scope": data.get("scope"),
        "user_type": data.get("userType"),
        "user_id": data.get("userId"),
        "refresh_token_id": data.get("refreshTokenId"),
    }


def exchange_code(config, code: str) -> tuple[dict, dict]:
    """Exchange an authorization code. Returns (tokens, raw) where raw
    carries locationId / companyId / isBulkInstallation."""
    data = _post_form(TOKEN_URL, {
        "client_id": config.ghl_client_id,
        "client_secret": config.ghl_client_secret,
        "grant_type": "authorization_code",
        "code": code,
        "user_type": config.ghl_user_type,
        "redirect_uri": config.ghl_redirect_uri,
    })
    return _tokens_from_response(data), data


def refresh_tokens(config, refresh_token: str, user_type: str) -> dict:
    data = _post_form(TOKEN_URL, {
        "client_id": config.ghl_client_id,
        "client_secret": config.ghl_client_secret,
        "grant_type": "refresh_token",
        "refresh_token": refresh_token,
        "user_type": user_type or config.ghl_user_type,
        "redirect_uri": config.ghl_redirect_uri,
    })
    return _tokens_from_response(data)


def get_location_token(company_access_token: str, company_id: str,
                       location_id: str) -> dict:
    """Exchange a Company token for a token scoped to one location."""
    data = _post_form(LOCATION_TOKEN_URL, {
        "companyId": company_id,
        "locationId": location_id,
    }, bearer=company_access_token)
    return _tokens_from_response(data)


def ensure_fresh_tokens(config, store, location_id: str) -> dict | None:
    """Return a tenant's tokens, refreshing first if the access token
    is expired (or within 60 seconds of it). Refresh rotation means
    the stored refresh token is replaced on every refresh — losing
    that write would strand the install, so the new pair is saved
    before returning."""
    tenant = store.get_tenant(location_id)
    if not tenant or not tenant.get("tokens"):
        return None
    tokens = tenant["tokens"]
    if int(time.time()) < int(tokens.get("expires_at", 0)) - 60:
        return tokens
    new_tokens = refresh_tokens(
        config, tokens["refresh_token"], tokens.get("user_type"))
    store.set_tenant_tokens(location_id, new_tokens)
    return new_tokens
