from __future__ import annotations

import asyncio

import httpx
import pytest

from agents.models import ActorContext
from agents.mcp_client import ManagedMCPClient
from mcp_gateway.app import build_gateway_app
from mcp_gateway.auth import issue_client_token
from mcp_server.app import build_server_app


@pytest.mark.anyio
async def test_gateway_rejects_wrong_tenant_scope(base_dir: str, test_cfg: dict):
    _, server_app = build_server_app(base_dir, test_cfg)
    gateway_app = build_gateway_app(server_app, test_cfg)
    actor = ActorContext(actor_id="U1", tenant_id="U1_genomics", scopes=["mcp:invoke", "tenant:WRONG"], authn_method="cli")
    token = issue_client_token(actor, actor.scopes, test_cfg)
    transport = httpx.ASGITransport(app=gateway_app)
    async with gateway_app.router.lifespan_context(gateway_app):
        async with httpx.AsyncClient(
            transport=transport,
            base_url="http://127.0.0.1",
            headers={"Authorization": f"Bearer {token}"},
        ) as client:
            response = await client.post("/mcp", json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"})
    assert response.status_code == 403


@pytest.mark.anyio
async def test_server_rejects_client_token_direct_bypass(base_dir: str, test_cfg: dict):
    _, server_app = build_server_app(base_dir, test_cfg)
    actor = ActorContext(
        actor_id="U1",
        tenant_id="U1_genomics",
        scopes=["mcp:invoke", "tenant:U1_genomics", "tool:lab_search_snippets"],
        authn_method="cli",
    )
    client_token = issue_client_token(actor, actor.scopes, test_cfg)
    transport = httpx.ASGITransport(app=server_app)
    async with server_app.router.lifespan_context(server_app):
        async with httpx.AsyncClient(
            transport=transport,
            base_url="http://127.0.0.1",
            headers={"Authorization": f"Bearer {client_token}"},
        ) as client:
            response = await client.post("/mcp", json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"})
    assert response.status_code == 401


@pytest.mark.anyio
async def test_valid_gateway_session_can_call_scoped_tool(base_dir: str, test_cfg: dict):
    mcp_server, server_app = build_server_app(base_dir, test_cfg)
    gateway_app = build_gateway_app(server_app, test_cfg)
    gateway_app.state.mcp_server = mcp_server
    actor = ActorContext(
        actor_id="U1",
        tenant_id="U1_genomics",
        scopes=["mcp:invoke", "tenant:U1_genomics", "tool:lab_search_snippets"],
        authn_method="cli",
    )
    token = issue_client_token(actor, actor.scopes, test_cfg)
    async with ManagedMCPClient(gateway_app, token, trace_id="test-trace").session() as session:
        result = await session.call_tool("lab_search_snippets", {"query": "Genomics results", "max_snippets": 2})
    assert result.isError is False
    assert "documents" in result.content[0].text
