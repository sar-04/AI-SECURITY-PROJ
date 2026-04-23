from __future__ import annotations

import contextvars
from contextlib import contextmanager

from mcp.server.auth.middleware.auth_context import get_access_token
from mcp.server.auth.provider import AccessToken, TokenVerifier

from agents.models import ActorContext
from security.tokens import verify_token


local_actor_context: contextvars.ContextVar[tuple[ActorContext, set[str]] | None] = contextvars.ContextVar(
    "local_actor_context",
    default=None,
)


class LocalJWTTokenVerifier(TokenVerifier):
    def __init__(self, cfg: dict, audience: str):
        self.cfg = cfg
        self.audience = audience

    async def verify_token(self, token: str) -> AccessToken | None:
        try:
            claims = verify_token(token, self.audience, self.cfg)
        except Exception:  # noqa: BLE001
            return None
        return AccessToken(
            token=token,
            client_id=claims.client_id,
            scopes=claims.scopes,
            expires_at=claims.exp,
            resource=claims.aud,
        )


def current_actor(cfg: dict, audience: str) -> tuple[ActorContext, set[str]]:
    access_token = get_access_token()
    if access_token is None:
        local = local_actor_context.get()
        if local is not None:
            return local
        raise PermissionError("Authentication required")
    claims = verify_token(access_token.token, audience, cfg)
    actor = ActorContext(
        actor_id=claims.actor_id,
        tenant_id=claims.tenant_id,
        scopes=claims.scopes,
        authn_method=claims.authn_method,
    )
    return actor, set(claims.scopes)


def require_scope(scopes: set[str], required_scope: str) -> None:
    if required_scope not in scopes:
        raise PermissionError(f"Missing required scope: {required_scope}")


@contextmanager
def push_local_actor(actor: ActorContext, scopes: list[str]):
    token = local_actor_context.set((actor, set(scopes)))
    try:
        yield
    finally:
        local_actor_context.reset(token)
