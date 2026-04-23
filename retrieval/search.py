from __future__ import annotations

import re

from retrieval.index import Hit


PII_PATTERNS = [
    re.compile(r"\b\d{5}-\d{7}-\d\b"),
    re.compile(r"\+?92-?\d{3}-?\d{7}"),
]

INDIRECT_INJECTION_PATTERNS = [
    re.compile(r"ignore\s+(all|previous|system)\s+instructions", re.IGNORECASE),
    re.compile(r"override\s+policy", re.IGNORECASE),
    re.compile(r"print\s+hidden\s+system", re.IGNORECASE),
    re.compile(r"dump\s+memory", re.IGNORECASE),
]


def mask_pii(text: str) -> str:
    out = text
    for pattern in PII_PATTERNS:
        out = pattern.sub("[REDACTED]", out)
    return out


def sanitize_retrieved_text(text: str) -> str:
    safe_lines: list[str] = []
    for line in text.splitlines():
        if any(pattern.search(line) for pattern in INDIRECT_INJECTION_PATTERNS):
            continue
        safe_lines.append(line)
    return "\n".join(safe_lines).strip()


def scrub_hit(hit: Hit) -> Hit:
    sanitized = sanitize_retrieved_text(hit.text)
    masked = mask_pii(sanitized)
    hit.pii_masked = masked != sanitized
    hit.text = masked
    return hit


def text_contains_pii(text: str) -> bool:
    return any(pattern.search(text) for pattern in PII_PATTERNS)

