from __future__ import annotations

import json
import os
import time
from dataclasses import dataclass


@dataclass
class ApprovalStore:
    base_dir: str

    @property
    def path(self) -> str:
        return os.path.join(self.base_dir, ".state", "approvals", "requests.json")

    def _load(self) -> list[dict]:
        if not os.path.exists(self.path):
            return []
        with open(self.path, "r", encoding="utf-8") as handle:
            return json.load(handle)

    def _save(self, requests: list[dict]) -> None:
        os.makedirs(os.path.dirname(self.path), exist_ok=True)
        with open(self.path, "w", encoding="utf-8") as handle:
            json.dump(requests, handle, indent=2, ensure_ascii=False)

    def create_request(self, actor_id: str, tenant_id: str, target_scope: str, reason: str) -> dict:
        requests = self._load()
        request_id = f"APR-{int(time.time())}-{len(requests) + 1:03d}"
        request = {
            "request_id": request_id,
            "actor_id": actor_id,
            "tenant_id": tenant_id,
            "target_scope": target_scope,
            "reason": reason[:400],
            "status": "pending_review",
            "created_at_epoch": int(time.time()),
        }
        requests.append(request)
        self._save(requests)
        return request

    def get_request(self, request_id: str) -> dict | None:
        for request in self._load():
            if request["request_id"] == request_id:
                return request
        return None

