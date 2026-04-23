from __future__ import annotations

import os

from mcp.server.auth.settings import AuthSettings
from mcp.server.fastmcp import FastMCP
from mcp.server.transport_security import TransportSecuritySettings

from agents.tenant import tool_scope
from mcp_server.auth import LocalJWTTokenVerifier, current_actor, require_scope
from mcp_server.state import ApprovalStore
from policies.guard import apply_policy, planner, snippets_from_hits
from retrieval.index import Retriever
from retrieval.search import mask_pii, sanitize_retrieved_text


def _server_audience(cfg: dict) -> str:
    return (cfg.get("mcp") or {}).get("server_audience", "mcp-server")


def _auth_settings(cfg: dict) -> AuthSettings:
    mcp_cfg = cfg.get("mcp") or {}
    issuer_url = mcp_cfg.get("issuer_url", "http://securelab.local/auth")
    resource_server_url = mcp_cfg.get("resource_server_url", "http://securelab.local/mcp")
    return AuthSettings(
        issuer_url=issuer_url,
        required_scopes=["mcp:invoke"],
        resource_server_url=resource_server_url,
    )


def build_server_app(base_dir: str, cfg: dict):
    retriever = Retriever(base_dir)
    approvals = ApprovalStore(base_dir)
    audience = _server_audience(cfg)
    verifier = LocalJWTTokenVerifier(cfg, audience=audience)

    mcp = FastMCP(
        name="SecureLabKnowledgeMCP",
        instructions="Secure lab retrieval and governance tools only.",
        token_verifier=verifier,
        auth=_auth_settings(cfg),
        stateless_http=True,
        streamable_http_path="/mcp",
        log_level="WARNING",
        transport_security=TransportSecuritySettings(
            enable_dns_rebinding_protection=True,
            allowed_hosts=["127.0.0.1", "127.0.0.1:*", "testserver", "testserver:*"],
            allowed_origins=["http://127.0.0.1", "http://127.0.0.1:*", "http://testserver", "http://testserver:*"],
        ),
    )

    @mcp.tool(
        name="lab_search_snippets",
        description="Search authorized lab snippets for the active tenant and public corpus only.",
    )
    def lab_search_snippets(query: str, max_snippets: int = 4) -> dict:
        actor, scopes = current_actor(cfg, audience)
        require_scope(scopes, tool_scope("lab_search_snippets"))
        hits = retriever.search(query, actor.tenant_id, top_k=max_snippets)
        safe_hits = apply_policy(hits, actor, planner(actor, query))
        if isinstance(safe_hits, dict):
            return {**safe_hits, "documents": [], "snippets": []}
        snippets = snippets_from_hits(safe_hits)
        return {
            "actor_tenant": actor.tenant_id,
            "documents": [snippet.doc_id for snippet in snippets],
            "snippets": [snippet.model_dump() for snippet in snippets],
        }

    @mcp.tool(
        name="lab_read_doc_excerpt",
        description="Read a short redacted excerpt from an already authorized document.",
    )
    def lab_read_doc_excerpt(doc_id: str) -> dict:
        actor, scopes = current_actor(cfg, audience)
        require_scope(scopes, tool_scope("lab_read_doc_excerpt"))
        for doc in retriever.documents:
            if doc.doc_id != doc_id:
                continue
            if doc.tenant_id not in {actor.tenant_id, "public"} and doc.visibility != "public":
                raise PermissionError("Document is not accessible for the active tenant.")
            excerpt = mask_pii(sanitize_retrieved_text(doc.text))[:500]
            return {
                "doc_id": doc.doc_id,
                "tenant_id": doc.tenant_id,
                "visibility": doc.visibility,
                "excerpt": excerpt,
                "documents": [doc.doc_id],
            }
        raise FileNotFoundError(f"Unknown document: {doc_id}")

    @mcp.tool(
        name="governance_submit_access_request",
        description="Create a manual approval request for higher-risk or cross-tenant access.",
    )
    def governance_submit_access_request(target_scope: str, reason: str) -> dict:
        actor, scopes = current_actor(cfg, audience)
        require_scope(scopes, tool_scope("governance_submit_access_request"))
        request = approvals.create_request(actor.actor_id, actor.tenant_id, target_scope, reason)
        return {
            **request,
            "message": "Approval required; request recorded for manual review.",
            "documents": [],
        }

    @mcp.tool(
        name="governance_get_request_status",
        description="Look up the status of a previously created approval request.",
    )
    def governance_get_request_status(request_id: str) -> dict:
        actor, scopes = current_actor(cfg, audience)
        require_scope(scopes, tool_scope("governance_get_request_status"))
        request = approvals.get_request(request_id)
        if request is None:
            return {"request_id": request_id, "status": "not_found", "documents": []}
        if request["actor_id"] != actor.actor_id and request["tenant_id"] != actor.tenant_id:
            raise PermissionError("Approval request belongs to a different actor.")
        return {**request, "documents": []}

    return mcp, mcp.streamable_http_app()
