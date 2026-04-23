from __future__ import annotations

import json
from contextlib import AsyncExitStack
from contextlib import asynccontextmanager
from typing import Any

import httpx
from mcp import ClientSession
from mcp.shared.memory import create_connected_server_and_client_session

from mcp_server.auth import push_local_actor


class ManagedMCPClient:
    def __init__(self, gateway_app: Any, token: str, trace_id: str):
        self.gateway_app = gateway_app
        self.token = token
        self.trace_id = trace_id

    @asynccontextmanager
    async def session(self):
        async with AsyncExitStack() as stack:
            server_app = getattr(self.gateway_app.state, "server_app", None)
            if server_app is not None:
                await stack.enter_async_context(server_app.router.lifespan_context(server_app))
            await stack.enter_async_context(self.gateway_app.router.lifespan_context(self.gateway_app))

            auth_result = await self.gateway_app.state.authorize_token(self.token, self.trace_id)
            actor = auth_result["actor"]
            stack.enter_context(push_local_actor(actor, actor.scopes))
            session = await stack.enter_async_context(
                create_connected_server_and_client_session(self.gateway_app.state.mcp_server)
            )
            await session.initialize()
            yield session

    @staticmethod
    def tool_result_to_json(tool_name: str, result: Any) -> str:
        if hasattr(result, "content"):
            serialized = {"_tool_name": tool_name, "content": []}
            for block in result.content:
                if hasattr(block, "text"):
                    serialized["content"].append(block.text)
            if len(serialized["content"]) == 1:
                first = serialized["content"][0]
                try:
                    payload = json.loads(first)
                    if isinstance(payload, dict):
                        payload["_tool_name"] = tool_name
                        return json.dumps(payload)
                except json.JSONDecodeError:
                    pass
            return json.dumps(serialized)
        return json.dumps({"_tool_name": tool_name, "result": result})
