from __future__ import annotations

import time
import uuid
from dataclasses import dataclass

import jwt

from agents.models import ActorContext


ALGORITHM = "HS256"


@dataclass
class TokenClaims:
    sub: str
    aud: str
    scopes: list[str]
    exp: int
    iat: int
    jti: str
    actor_id: str
    tenant_id: str
    authn_method: str

    @property
    def client_id(self) -> str:
        return build_client_id(self.actor_id, self.tenant_id, self.authn_method)


def secret_from_cfg(cfg: dict) -> str:
    mcp_cfg = cfg.get("mcp") or {}
    return mcp_cfg.get("shared_secret", "secure-lab-demo-secret-change-me")


def build_client_id(actor_id: str, tenant_id: str, authn_method: str) -> str:
    return f"actor={actor_id};tenant={tenant_id};authn={authn_method}"


def parse_client_id(client_id: str) -> dict[str, str]:
    parts = {}
    for item in client_id.split(";"):
        if "=" not in item:
            continue
        key, value = item.split("=", 1)
        parts[key] = value
    return parts


def issue_token(actor: ActorContext, scopes: list[str], audience: str, cfg: dict, ttl_s: int = 300) -> str:
    now = int(time.time())
    payload = {
        "sub": actor.actor_id,
        "aud": audience,
        "scopes": scopes,
        "exp": now + ttl_s,
        "iat": now,
        "jti": str(uuid.uuid4()),
        "actor_id": actor.actor_id,
        "tenant_id": actor.tenant_id,
        "authn_method": actor.authn_method,
    }
    return jwt.encode(payload, secret_from_cfg(cfg), algorithm=ALGORITHM)


def verify_token(token: str, audience: str, cfg: dict) -> TokenClaims:
    payload = jwt.decode(
        token,
        secret_from_cfg(cfg),
        algorithms=[ALGORITHM],
        audience=audience,
        options={"require": ["exp", "iat", "aud", "sub"]},
    )
    return TokenClaims(
        sub=payload["sub"],
        aud=payload["aud"],
        scopes=list(payload.get("scopes") or []),
        exp=int(payload["exp"]),
        iat=int(payload["iat"]),
        jti=payload.get("jti", ""),
        actor_id=payload.get("actor_id", payload["sub"]),
        tenant_id=payload["tenant_id"],
        authn_method=payload.get("authn_method", "unknown"),
    )
