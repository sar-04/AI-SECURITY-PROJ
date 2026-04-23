from __future__ import annotations

import json
import time
from collections import defaultdict, deque
from typing import Any
from uuid import uuid4

import httpx
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from starlette.routing import Route

from agents.audit import append_jsonl
from agents.models import ActorContext
from mcp_gateway.auth import issue_server_token, verify_client_token
from mcp_server.app import build_server_app


class RateLimiter:
    def __init__(self, max_requests: int, window_s: int = 60):
        self.max_requests = max_requests
        self.window_s = window_s
        self.calls: dict[str, deque[float]] = defaultdict(deque)

    def allow(self, key: str) -> bool:
        now = time.time()
        queue = self.calls[key]
        while queue and now - queue[0] > self.window_s:
            queue.popleft()
        if len(queue) >= self.max_requests:
            return False
        queue.append(now)
        return True


def _gateway_log_path(cfg: dict) -> str:
    return (cfg.get("logging") or {}).get("gateway_path", "logs/gateway.jsonl")


def build_gateway_app(server_app: Any, cfg: dict) -> Starlette:
    mcp_cfg = cfg.get("mcp") or {}
    limiter = RateLimiter(int(mcp_cfg.get("rate_limit_per_minute", 30)))
    kill_switch = bool(mcp_cfg.get("kill_switch", False))
    server_client = httpx.AsyncClient(
        transport=httpx.ASGITransport(app=server_app),
        base_url="http://127.0.0.1",
    )

    async def health(_: Request) -> Response:
        return JSONResponse({"ok": True, "kill_switch": kill_switch})

    async def authorize_token(raw_token: str, trace_id: str) -> dict:
        if kill_switch:
            raise PermissionError("Gateway kill switch is active.")

        claims = verify_client_token(raw_token, cfg)
        tenant_scope = f"tenant:{claims.tenant_id}"
        if "mcp:invoke" not in claims.scopes or tenant_scope not in claims.scopes:
            raise PermissionError("Missing invoke or tenant scope.")
        if not limiter.allow(claims.client_id):
            raise RuntimeError("Too many requests for this actor.")

        actor = ActorContext(
            actor_id=claims.actor_id,
            tenant_id=claims.tenant_id,
            scopes=claims.scopes,
            authn_method=claims.authn_method,
        )
        server_token = issue_server_token(actor, claims.scopes, cfg)
        append_jsonl(
            _gateway_log_path(cfg),
            {
                "timestamp": time.time(),
                "trace_id": trace_id,
                "actor_id": claims.actor_id,
                "tenant_id": claims.tenant_id,
                "status_code": 200,
                "path": "session_broker",
                "method": "INTERNAL",
            },
        )
        return {"actor": actor, "server_token": server_token, "claims": claims}

    async def proxy(request: Request) -> Response:
        trace_id = request.headers.get("x-trace-id", str(uuid4()))
        if kill_switch:
            return JSONResponse(
                {"error": "service_unavailable", "error_description": "Gateway kill switch is active."},
                status_code=503,
            )

        auth_header = request.headers.get("authorization", "")
        if not auth_header.lower().startswith("bearer "):
            return JSONResponse(
                {"error": "invalid_token", "error_description": "Authentication required."},
                status_code=401,
                headers={"www-authenticate": 'Bearer error="invalid_token"'},
            )

        token = auth_header.split(" ", 1)[1]
        try:
            auth_result = await authorize_token(token, trace_id)
            claims = auth_result["claims"]
        except PermissionError as exc:
            return JSONResponse(
                {"error": "insufficient_scope", "error_description": str(exc)},
                status_code=403,
                headers={"www-authenticate": 'Bearer error="insufficient_scope"'},
            )
        except RuntimeError as exc:
            return JSONResponse(
                {"error": "rate_limited", "error_description": str(exc)},
                status_code=429,
            )
        except Exception:  # noqa: BLE001
            return JSONResponse(
                {"error": "invalid_token", "error_description": "Token is invalid or expired."},
                status_code=401,
                headers={"www-authenticate": 'Bearer error="invalid_token"'},
            )
        actor = auth_result["actor"]
        server_token = auth_result["server_token"]

        body = await request.body()
        forwarded_headers = {
            key: value
            for key, value in request.headers.items()
            if key.lower() not in {"host", "authorization", "content-length"}
        }
        forwarded_headers["authorization"] = f"Bearer {server_token}"
        forwarded_headers["x-trace-id"] = trace_id

        response = await server_client.request(
            request.method,
            request.url.path,
            params=request.query_params,
            content=body,
            headers=forwarded_headers,
        )

        append_jsonl(
            _gateway_log_path(cfg),
            {
                "timestamp": time.time(),
                "trace_id": trace_id,
                "actor_id": claims.actor_id,
                "tenant_id": claims.tenant_id,
                "status_code": response.status_code,
                "path": request.url.path,
                "method": request.method,
            },
        )

        return Response(
            content=response.content,
            status_code=response.status_code,
            headers={key: value for key, value in response.headers.items() if key.lower() != "content-length"},
            media_type=response.headers.get("content-type"),
        )

    app = Starlette(routes=[Route("/healthz", health), Route("/mcp", proxy, methods=["GET", "POST", "DELETE"])])
    app.state.server_client = server_client
    app.state.server_app = server_app
    app.state.authorize_token = authorize_token
    return app


def build_local_mcp_apps(base_dir: str, cfg: dict):
    mcp_server, server_app = build_server_app(base_dir, cfg)
    gateway_app = build_gateway_app(server_app, cfg)
    gateway_app.state.mcp_server = mcp_server
    return gateway_app, {"transport": "asgi", "gateway": "local-jwt", "server": "fastmcp"}
