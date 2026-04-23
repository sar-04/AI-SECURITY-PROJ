from __future__ import annotations

import hashlib
import json
import os
from datetime import datetime, timezone

from agents.models import AuditEvent


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def append_jsonl(path: str, record: dict) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "a", encoding="utf-8") as handle:
        handle.write(json.dumps(record, ensure_ascii=False) + "\n")


def log_audit(path: str, event: AuditEvent) -> None:
    payload = event.model_dump()
    payload["timestamp_utc"] = datetime.now(timezone.utc).isoformat()
    append_jsonl(path, payload)

