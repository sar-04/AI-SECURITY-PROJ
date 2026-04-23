from __future__ import annotations

import asyncio
import json
import os
import time
import uuid
from typing import Any

import yaml

from agents.audit import log_audit, sha256_text
from agents.llm import SYSTEM_PROMPT, build_provider
from agents.mcp_client import ManagedMCPClient
from agents.memory import MemoryStore
from agents.models import ActorContext, AgentRunResult, AuditEvent, CacheHint, Decision, PolicyDecision, ToolInvocation
from agents.tenant import normalize_tenant_id, tenant_scope, tool_scope
from mcp_gateway.app import build_local_mcp_apps
from mcp_gateway.auth import issue_client_token
from policies.guard import (
    evaluate_input_policy,
    plain_language_decision,
    refusal_template,
    validate_output,
)


def _load_cfg_from_disk(base_dir: str) -> dict:
    path = os.path.join(base_dir, "config.yaml")
    if os.path.exists(path):
        with open(path, "r", encoding="utf-8") as handle:
            return yaml.safe_load(handle) or {}
    return {}


def _logging_paths(cfg: dict) -> tuple[str, str]:
    logging_cfg = cfg.get("logging") or {}
    run_path = logging_cfg.get("path", "logs/run.jsonl")
    audit_path = logging_cfg.get("audit_path", "logs/audit.jsonl")
    return run_path, audit_path


async def _list_allowed_tools(session, allowed_tools: list[str]) -> list[dict[str, Any]]:
    result = await session.list_tools()
    tools: list[dict[str, Any]] = []
    for tool in result.tools:
        if tool.name not in allowed_tools:
            continue
        tools.append(
            {
                "name": tool.name,
                "description": tool.description or "",
                "input_schema": tool.inputSchema,
            }
        )
    return tools


def _assistant_tool_message(tool_calls: list[ToolInvocation]) -> dict[str, Any]:
    return {
        "role": "assistant",
        "content": [
            {
                "type": "tool_use",
                "id": tool_call.tool_call_id or f"toolu_{uuid.uuid4().hex[:8]}",
                "name": tool_call.name,
                "input": tool_call.input,
            }
            for tool_call in tool_calls
        ],
    }


async def _execute_tool_calls(session, tool_calls: list[ToolInvocation], allowed_tools: list[str]) -> tuple[list[dict[str, Any]], list[str], list[str]]:
    tool_result_blocks: list[dict[str, Any]] = []
    tools_called: list[str] = []
    doc_ids: list[str] = []
    for tool_call in tool_calls:
        if tool_call.name not in allowed_tools:
            payload = {"_tool_name": tool_call.name, "error": "ToolNotAllowed"}
            tool_result_blocks.append(
                {
                    "type": "tool_result",
                    "tool_use_id": tool_call.tool_call_id,
                    "content": json.dumps(payload),
                    "is_error": True,
                }
            )
            continue

        result = await session.call_tool(tool_call.name, tool_call.input)
        serialized = ManagedMCPClient.tool_result_to_json(tool_call.name, result)
        try:
            payload = json.loads(serialized)
            if "documents" in payload:
                doc_ids.extend(payload["documents"])
        except json.JSONDecodeError:
            payload = {"raw": serialized}
        tool_result_blocks.append(
            {
                "type": "tool_result",
                "tool_use_id": tool_call.tool_call_id,
                "content": serialized,
            }
        )
        tools_called.append(tool_call.name)
    return tool_result_blocks, tools_called, doc_ids


async def run_agent_async(
    base_dir: str,
    tenant_id: str,
    user_query: str,
    cfg: dict | None = None,
    memory: Any = None,
) -> AgentRunResult:
    cfg = cfg or _load_cfg_from_disk(base_dir)
    trace_id = str(uuid.uuid4())
    actor_ctx = ActorContext(
        actor_id=tenant_id,
        tenant_id=normalize_tenant_id(tenant_id),
        scopes=[],
        authn_method="cli_demo",
    )
    started = time.time()
    run_path, audit_path = _logging_paths(cfg)
    provider = build_provider(cfg)
    memory_store = MemoryStore(base_dir)

    plan, policy = evaluate_input_policy(actor_ctx, user_query)
    tools_called: list[str] = []
    doc_ids: list[str] = []
    if policy.decision == Decision.REFUSE:
        text = refusal_template(policy.reason)
        latency_ms = int((time.time() - started) * 1000)
        audit = AuditEvent(
            trace_id=trace_id,
            actor=actor_ctx.actor_id,
            tenant=actor_ctx.tenant_id,
            decision=Decision.REFUSE.value,
            model=provider.providers[0].name,
            latency_ms=latency_ms,
            policy_reason=policy.reason,
            tools_called=[],
            redactions=policy.redactions,
            query_sha256=sha256_text(user_query),
        )
        log_audit(audit_path, audit)
        log_audit(
            run_path,
            audit.model_copy(update={"extra": {"query": user_query, "explanation": plain_language_decision(policy, actor_ctx, plan)}}),
        )
        memory_store.append_summary(actor_ctx, user_query, text, Decision.REFUSE)
        return AgentRunResult(
            text=text,
            decision=Decision.REFUSE,
            policy_reason=policy.reason,
            explanation=plain_language_decision(policy, actor_ctx, plan),
            trace_id=trace_id,
            docs=[],
            tools_called=[],
            model=provider.providers[0].name,
        )

    all_scopes = ["mcp:invoke", tenant_scope(actor_ctx.tenant_id)] + [tool_scope(name) for name in policy.allowed_tools]
    actor_ctx.scopes = all_scopes
    client_token = issue_client_token(actor_ctx, all_scopes, cfg)
    gateway_app, server_state = build_local_mcp_apps(base_dir, cfg)

    messages: list[dict[str, Any]] = [{"role": "user", "content": [{"type": "text", "text": plan.normalized_query}]}]
    provider_name = provider.providers[0].name

    async with ManagedMCPClient(gateway_app, client_token, trace_id).session() as session:
        allowed_tools = policy.allowed_tools
        anthropic_tools = await _list_allowed_tools(session, allowed_tools)
        response_text = ""
        final_decision = Decision.APPROVAL_REQUIRED if policy.required_approval else Decision.ALLOW
        for _ in range(3):
            llm_response = await provider.generate(
                messages=messages,
                system=SYSTEM_PROMPT,
                tools=anthropic_tools,
                stream=False,
                cache_hint=CacheHint(static_prefix=True),
            )
            provider_name = llm_response.raw.get("provider", provider_name)
            if llm_response.tool_calls:
                messages.append(_assistant_tool_message(llm_response.tool_calls))
                tool_result_blocks, current_tools, current_docs = await _execute_tool_calls(
                    session, llm_response.tool_calls, allowed_tools
                )
                tools_called.extend(current_tools)
                doc_ids.extend(current_docs)
                messages.append({"role": "user", "content": tool_result_blocks})
                continue
            response_text = llm_response.text.strip()
            break

        if not response_text:
            response_text = refusal_template("InsufficientAuthorizedEvidence")
            final_decision = Decision.REFUSE
            policy = PolicyDecision(decision=Decision.REFUSE, reason="InsufficientAuthorizedEvidence")
        else:
            output_policy = validate_output(response_text, [])
            if output_policy.decision == Decision.REFUSE:
                response_text = refusal_template(output_policy.reason)
                final_decision = Decision.REFUSE
                policy = output_policy

        if policy.required_approval and response_text.startswith("Approval required"):
            final_decision = Decision.APPROVAL_REQUIRED

    latency_ms = int((time.time() - started) * 1000)
    audit = AuditEvent(
        trace_id=trace_id,
        actor=actor_ctx.actor_id,
        tenant=actor_ctx.tenant_id,
        decision=final_decision.value,
        model=provider_name,
        latency_ms=latency_ms,
        policy_reason=policy.reason,
        tools_called=tools_called,
        docs=doc_ids,
        redactions=policy.redactions,
        query_sha256=sha256_text(user_query),
        extra={"server_state": server_state},
    )
    log_audit(audit_path, audit)
    log_audit(
        run_path,
        audit.model_copy(
            update={"extra": {"query": user_query, "text": response_text, "explanation": plain_language_decision(policy, actor_ctx, plan)}}
        ),
    )
    memory_store.append_summary(actor_ctx, user_query, response_text, final_decision)
    return AgentRunResult(
        text=response_text,
        decision=final_decision,
        policy_reason=policy.reason,
        explanation=plain_language_decision(policy, actor_ctx, plan),
        trace_id=trace_id,
        docs=doc_ids,
        tools_called=tools_called,
        model=provider_name,
    )


def agent(base_dir: str, tenant_id: str, user_query: str, cfg: dict | None = None, memory: Any = None) -> str:
    return asyncio.run(run_agent_async(base_dir, tenant_id, user_query, cfg=cfg, memory=memory)).text
