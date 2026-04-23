from __future__ import annotations

import json
import os
from datetime import datetime, timezone

from agents.models import ActorContext, Decision
from retrieval.search import mask_pii


class MemoryStore:
    def __init__(self, base_dir: str):
        self.base_dir = base_dir
        self.root = os.path.join(base_dir, ".state", "memory")

    def _path(self, tenant_id: str) -> str:
        return os.path.join(self.root, tenant_id, "summary.json")

    def load(self, tenant_id: str) -> list[dict]:
        path = self._path(tenant_id)
        if not os.path.exists(path):
            return []
        with open(path, "r", encoding="utf-8") as handle:
            return json.load(handle)

    def append_summary(
        self,
        actor: ActorContext,
        query: str,
        response_text: str,
        decision: Decision,
    ) -> None:
        path = self._path(actor.tenant_id)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        entries = self.load(actor.tenant_id)
        entries.append(
            {
                "timestamp_utc": datetime.now(timezone.utc).isoformat(),
                "actor_id": actor.actor_id,
                "decision": decision.value,
                "query_preview": mask_pii(query)[:120],
                "response_preview": mask_pii(response_text)[:220],
            }
        )
        with open(path, "w", encoding="utf-8") as handle:
            json.dump(entries[-5:], handle, indent=2, ensure_ascii=False)

