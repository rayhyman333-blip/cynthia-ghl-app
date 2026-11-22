# Cynthia for HighLevel — Marketplace wrapper app

**Cynthia, by Planet Leads — created by Ramel Hyman.**

A thin wrapper that lists Cynthia in the GoHighLevel App Marketplace:
an agency installs Cynthia into a client sub-account, and she answers
that business's customer questions from the business's own approved
fact store, through Cynthia's existing API. No new product, no new
pricing — the listing maps to the existing white-label tiers.

**Stack:** Python 3 standard library only — the same rule as Cynthia
herself. No dependencies, no paid services, nothing to install.

## How it works

```
HighLevel agency/location admin
        |  installs (OAuth Authorization Code Grant, v2)
        v
  /install -> chooselocation -> /oauth/callback -> tokens per location
        |
  INSTALL / UNINSTALL webhooks (Ed25519-signed) keep tenants in sync
        |
  Custom Page (/app, iframe inside HighLevel)
        |  REQUEST_USER_DATA postMessage -> encrypted user context
        |  -> backend decrypts with the Shared Secret (never client-side)
        v
  /api/ask -> CynthiaBridge -> the location's Cynthia
                  |-- provisioned: the business's OWN Cynthia endpoint
                  |-- demo (default): the shared live Cynthia —
                      labelled DEMO in the page, in plain sight
```

The tenancy rule is the honest core of the design: Cynthia's existing
APIs serve one fact store per deployment (a white-label Cynthia *is*
her own deployment with her own approved facts), so the bridge routes
each HighLevel location to its own provisioned Cynthia endpoint. A
fresh install runs in clearly-labelled demo mode until an admin pastes
in the endpoint Planet Leads provisioned for that business. No
question is ever silently answered from the wrong store.

## Files

| File | Purpose |
|---|---|
| `app.py` | The server: OAuth install/callback, webhooks, Custom Page, `/api/session`, `/api/ask`, `/api/config`, `/health` |
| `config.py` | Env-based configuration (secrets from env only) |
| `ghl_oauth.py` | Install URL, code exchange, refresh rotation, locationToken |
| `ghl_webhooks.py` | INSTALL/UNINSTALL handling + signature check |
| `ghl_sso.py` | Custom Page user-context decryption (OpenSSL/CryptoJS format) |
| `crypto_pure.py` | Pure-Python AES-256-CBC + Ed25519 verify (stdlib has neither) |
| `cynthia_client.py` | The bridge: MCP (live) + REST (facade) transports, per-location routing |
| `store.py` | Tenant/token JSON store (see its production note) |
| `static/custom-page.html` | The iframe UI: SSO handshake, ask box, admin setup panel |
| `listing/` | Listing assets: copy, pricing mapping, portal manifest mirror, privacy/terms drafts, logo placeholder |
| `tests/` | Unit tests + a live integration check |

## Run it locally

```bash
cp .env.example .env   # fill in the portal credentials when they exist
set -a; . ./.env; set +a
python3 app.py         # http://127.0.0.1:8200
```

Without portal credentials the app still runs: `/health` reports what
is and isn't configured, and the bridge can be exercised end-to-end
against a local Cynthia (see `tests/integration_check.py`).

## Tests

```bash
python3 -m unittest discover -s tests        # 23 unit tests
python3 tests/integration_check.py           # 19 live checks (needs the
                                             # local servers running —
                                             # see BUILD-REPORT.md)
```

## Status

Built and verified locally (2026-11-22). NOT submitted anywhere: the
Developer Portal signup, app creation, deployment to an HTTPS host,
and review submission are the listing step — see BUILD-REPORT.md.

## Licence

Proprietary — Copyright © 2026 Ramel Hyman, Planet Leads.
