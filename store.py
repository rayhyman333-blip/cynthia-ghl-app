"""Tenant + token storage for the Cynthia for HighLevel wrapper.

Deliberately simple, like the rest of Cynthia's stack: one JSON file
on disk, guarded by a lock, written atomically (temp file + rename).
It holds, per installed location (sub-account):

  tenants[locationId] = {
      "location_id", "company_id", "installed": bool,
      "installed_at", "updated_at",
      "tokens": {access_token, refresh_token, expires_at, scope,
                 user_type, user_id} | None,
      "cynthia": {                     # the bridge configuration
          "mode": "demo" | "provisioned",
          "transport": "mcp" | "rest",
          "endpoint": "https://.../mcp" (provisioned mode only),
      },
  }

Company-level (agency) installs are kept under companies[companyId]
with their tokens; per HighLevel's docs a Company token can be
exchanged for a location token via POST /oauth/locationToken.

PRODUCTION NOTE (also in BUILD-REPORT.md): a JSON file is the right
size for this thin wrapper's first form and for local testing. Before
real customer volume, move this to the shell database (the Planet
Leads blueprint's one database per business) — the Store class is the
only thing that would change; every caller uses its methods.
"""

from __future__ import annotations

import json
import os
import threading
import time
from pathlib import Path


class Store:
    def __init__(self, path: str | Path):
        self.path = Path(path)
        self._lock = threading.Lock()
        self._data: dict = {"tenants": {}, "companies": {}}
        if self.path.exists():
            try:
                loaded = json.loads(self.path.read_text(encoding="utf-8"))
                if isinstance(loaded, dict):
                    self._data.update(loaded)
            except (OSError, ValueError):
                pass  # Corrupt store: start empty rather than crash.

    # -- persistence ---------------------------------------------------
    def _save_locked(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_suffix(".tmp")
        tmp.write_text(json.dumps(self._data, indent=2), encoding="utf-8")
        os.replace(tmp, self.path)

    # -- tenants ---------------------------------------------------------
    def get_tenant(self, location_id: str) -> dict | None:
        with self._lock:
            tenant = self._data["tenants"].get(location_id)
            return json.loads(json.dumps(tenant)) if tenant else None

    def upsert_tenant(self, location_id: str, **fields) -> dict:
        with self._lock:
            tenant = self._data["tenants"].setdefault(location_id, {
                "location_id": location_id,
                "company_id": None,
                "installed": False,
                "installed_at": None,
                "tokens": None,
                "cynthia": {"mode": "demo", "transport": "mcp",
                            "endpoint": None},
            })
            tenant.update(fields)
            tenant["updated_at"] = int(time.time())
            self._save_locked()
            return json.loads(json.dumps(tenant))

    def set_tenant_tokens(self, location_id: str, tokens: dict) -> None:
        with self._lock:
            tenant = self._data["tenants"].get(location_id)
            if tenant is None:
                return
            tenant["tokens"] = tokens
            tenant["updated_at"] = int(time.time())
            self._save_locked()

    def set_tenant_cynthia(self, location_id: str, cynthia: dict) -> dict:
        with self._lock:
            tenant = self._data["tenants"].get(location_id)
            if tenant is None:
                raise KeyError(location_id)
            tenant["cynthia"] = cynthia
            tenant["updated_at"] = int(time.time())
            self._save_locked()
            return json.loads(json.dumps(tenant))

    def mark_uninstalled(self, location_id: str) -> None:
        with self._lock:
            tenant = self._data["tenants"].get(location_id)
            if tenant is None:
                return
            tenant["installed"] = False
            tenant["tokens"] = None
            tenant["updated_at"] = int(time.time())
            self._save_locked()

    # -- companies -------------------------------------------------------
    def get_company(self, company_id: str) -> dict | None:
        with self._lock:
            company = self._data["companies"].get(company_id)
            return json.loads(json.dumps(company)) if company else None

    def upsert_company(self, company_id: str, **fields) -> dict:
        with self._lock:
            company = self._data["companies"].setdefault(company_id, {
                "company_id": company_id,
                "installed": True,
                "tokens": None,
            })
            company.update(fields)
            company["updated_at"] = int(time.time())
            self._save_locked()
            return json.loads(json.dumps(company))

    def set_company_tokens(self, company_id: str, tokens: dict) -> None:
        with self._lock:
            company = self._data["companies"].get(company_id)
            if company is None:
                return
            company["tokens"] = tokens
            company["updated_at"] = int(time.time())
            self._save_locked()
