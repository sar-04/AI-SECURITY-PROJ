from __future__ import annotations

import csv
import os
import re
from dataclasses import dataclass
from functools import cached_property
from typing import Iterable

from agents.tenant import normalize_tenant_id


TOKEN_RE = re.compile(r"[a-zA-Z0-9_]+")
STOPWORDS = {
    "a",
    "an",
    "and",
    "all",
    "as",
    "at",
    "be",
    "do",
    "for",
    "from",
    "how",
    "i",
    "in",
    "internal",
    "is",
    "it",
    "list",
    "of",
    "on",
    "or",
    "please",
    "show",
    "summarize",
    "tell",
    "the",
    "to",
    "what",
    "with",
}


@dataclass
class Hit:
    doc_id: str
    tenant: str
    visibility: str
    page: str
    text: str
    score: float
    pii_masked: bool = False
    path: str | None = None


@dataclass
class DocumentRecord:
    doc_id: str
    tenant_id: str
    visibility: str
    pii: bool
    retention_policy: str
    path: str
    text: str


def load_manifest(base_dir: str) -> list[dict]:
    manifest_path = os.path.join(base_dir, "data", "manifest.csv")
    with open(manifest_path, "r", encoding="utf-8") as handle:
        return list(csv.DictReader(handle))


def load_acl(base_dir: str) -> dict[str, dict]:
    acl_path = os.path.join(base_dir, "data", "tenant_acl.csv")
    with open(acl_path, "r", encoding="utf-8") as handle:
        rows = list(csv.DictReader(handle))
    return {row["doc_id"]: row for row in rows}


def read_doc(base_dir: str, rel_path: str) -> str:
    with open(os.path.join(base_dir, rel_path), "r", encoding="utf-8") as handle:
        return handle.read()


def tokenize(text: str) -> list[str]:
    return [token.lower() for token in TOKEN_RE.findall(text) if token.lower() not in STOPWORDS]


def score_document(query_tokens: Iterable[str], text: str, doc_id: str) -> float:
    haystack = text.lower()
    score = 0.0
    for token in query_tokens:
        token_hits = haystack.count(token)
        if token_hits:
            score += 1.0 + min(token_hits, 3) * 0.4
        if token in doc_id.lower():
            score += 0.6
    if "title:" in haystack:
        score += 0.2
    return score


class Retriever:
    def __init__(self, base_dir: str):
        self.base_dir = base_dir

    @cached_property
    def documents(self) -> list[DocumentRecord]:
        manifest = load_manifest(self.base_dir)
        acl = load_acl(self.base_dir)
        docs: list[DocumentRecord] = []
        for row in manifest:
            meta = acl.get(row["doc_id"], {})
            tenant_id = normalize_tenant_id(meta.get("tenant_id", row["tenant"]))
            visibility = meta.get("visibility", "public" if tenant_id == "public" else "private")
            docs.append(
                DocumentRecord(
                    doc_id=row["doc_id"],
                    tenant_id=tenant_id,
                    visibility=visibility,
                    pii=(meta.get("pii", "N") == "Y"),
                    retention_policy=meta.get("retention_policy", "retain_3y"),
                    path=row["path"],
                    text=read_doc(self.base_dir, row["path"]),
                )
            )
        return docs

    def build_or_update(self) -> None:
        return None

    def _candidate_docs(self, actor_tenant_id: str) -> list[DocumentRecord]:
        actor_tenant_id = normalize_tenant_id(actor_tenant_id)
        return [
            doc
            for doc in self.documents
            if doc.tenant_id in {actor_tenant_id, "public"} or doc.visibility == "public"
        ]

    def search(self, query: str, actor_tenant_id: str, top_k: int = 6) -> list[Hit]:
        query_tokens = tokenize(query)
        if not query_tokens:
            query_tokens = tokenize(query[:80])

        hits: list[Hit] = []
        for doc in self._candidate_docs(actor_tenant_id):
            score = score_document(query_tokens, doc.text, doc.doc_id)
            if score <= 0:
                continue
            hits.append(
                Hit(
                    doc_id=doc.doc_id,
                    tenant=doc.tenant_id,
                    visibility=doc.visibility,
                    page="n/a",
                    text=doc.text,
                    score=score,
                    path=doc.path,
                )
            )
        hits.sort(key=lambda item: item.score, reverse=True)
        return hits[:top_k]

