"""HighLevel webhook receiver.

Configured in the portal (Advanced Settings -> Webhooks): one webhook
URL, per-event toggles. If a webhook URL is set, the App Install event
is subscribed by default. Payloads (official OAuth doc sample):

    {"type": "INSTALL", "appId": ..., "versionId": ...,
     "installType": "Location", "locationId": ..., "companyId": ...,
     "userId": ..., "companyName": ..., "isWhitelabelCompany": true,
     "whitelabelDetails": {"logoUrl": ..., "domain": ...},
     "timestamp": ..., "webhookId": ...}

    {"type": "UNINSTALL", ... same identifying fields ...}

Signature: HighLevel's current scheme sends an Ed25519 signature in
the X-GHL-Signature header over the raw request body, verifiable with
HighLevel's published public key. The legacy RSA scheme
(X-WH-Signature) is deprecated by HighLevel effective 2026-07-01 and
is deliberately NOT accepted here.

What the events do in this wrapper:
  INSTALL   -> create/activate the tenant (and company) record. The
               OAuth callback remains the source of tokens; the
               webhook is the source of truth for "is it installed".
  UNINSTALL -> mark the tenant uninstalled and DROP its tokens.
Unknown event types are acknowledged (200) and ignored — HighLevel
retries non-200 responses, and an event we do not use is not an error.
"""

from __future__ import annotations

import base64
import binascii

from crypto_pure import ed25519_public_key_from_spki_base64, ed25519_verify


def verify_signature(config, raw_body: bytes, headers: dict) -> bool:
    """Verify the X-GHL-Signature Ed25519 signature over the raw body.
    `headers` is a case-insensitive-ish dict; we check common casings.
    WEBHOOK_ALLOW_UNSIGNED_LOCAL exists ONLY for local development
    against hand-sent test payloads and must never be on in production.
    """
    signature_b64 = None
    for key in ("x-ghl-signature", "X-GHL-Signature", "X-Ghl-Signature"):
        if headers.get(key):
            signature_b64 = headers[key]
            break
    if not signature_b64:
        return bool(config.webhook_allow_unsigned_local)
    try:
        signature = base64.b64decode(signature_b64, validate=True)
        public_key = ed25519_public_key_from_spki_base64(
            config.ghl_webhook_public_key_b64)
    except (binascii.Error, ValueError):
        return False
    return ed25519_verify(public_key, raw_body, signature)


def handle_event(store, payload: dict) -> dict:
    """Apply one webhook payload to the store. Returns a small summary
    dict for logging; never raises on unknown shapes."""
    event_type = payload.get("type")
    location_id = payload.get("locationId")
    company_id = payload.get("companyId")
    if event_type == "INSTALL":
        if company_id:
            store.upsert_company(company_id, installed=True)
        if location_id:
            store.upsert_tenant(
                location_id,
                company_id=company_id,
                installed=True,
                installed_at=payload.get("timestamp"),
            )
        return {"handled": True, "type": event_type,
                "location_id": location_id, "company_id": company_id}
    if event_type == "UNINSTALL":
        if location_id:
            store.mark_uninstalled(location_id)
        return {"handled": True, "type": event_type,
                "location_id": location_id, "company_id": company_id}
    return {"handled": False, "type": event_type,
            "reason": "event type not used by this app"}
