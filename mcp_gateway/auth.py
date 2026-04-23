from __future__ import annotations

from agents.models import ActorContext
from security.tokens import issue_token, verify_token


def gateway_audience(cfg: dict) -> str:
    return (cfg.get("mcp") or {}).get("gateway_audience", "mcp-gateway")


def server_audience(cfg: dict) -> str:
    return (cfg.get("mcp") or {}).get("server_audience", "mcp-server")


def issue_client_token(actor: ActorContext, scopes: list[str], cfg: dict) -> str:
    return issue_token(actor, scopes, audience=gateway_audience(cfg), cfg=cfg)


def issue_server_token(actor: ActorContext, scopes: list[str], cfg: dict) -> str:
    return issue_token(actor, scopes, audience=server_audience(cfg), cfg=cfg, ttl_s=120)


def verify_client_token(token: str, cfg: dict):
    return verify_token(token, gateway_audience(cfg), cfg)

