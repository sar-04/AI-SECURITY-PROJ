from __future__ import annotations

from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class Decision(str, Enum):
    ALLOW = "allow"
    REFUSE = "refuse"
    APPROVAL_REQUIRED = "approval_required"


class ActorContext(BaseModel):
    actor_id: str
    tenant_id: str
    scopes: list[str] = Field(default_factory=list)
    authn_method: str = "cli_demo"


class ToolInvocation(BaseModel):
    name: str
    input: dict[str, Any] = Field(default_factory=dict)
    trace_id: str
    tool_call_id: str | None = None


class SourceSnippet(BaseModel):
    index: int
    doc_id: str
    tenant_id: str
    visibility: str
    text: str
    score: float
    pii_masked: bool = False
    source_path: str | None = None


class PolicyDecision(BaseModel):
    decision: Decision
    reason: str
    required_approval: bool = False
    redactions: list[str] = Field(default_factory=list)
    allowed_tools: list[str] = Field(default_factory=list)
    explain: str = ""


class RequestPlan(BaseModel):
    action: str
    normalized_query: str
    target_tenant_id: str | None = None
    requests_private_data: bool = False
    requests_sensitive_memory: bool = False
    requests_approval_flow: bool = False
    requests_status_check: bool = False
    requested_request_id: str | None = None
    mentioned_lab: str | None = None


class AuditEvent(BaseModel):
    trace_id: str
    actor: str
    tenant: str
    decision: str
    tool: str | None = None
    docs: list[str] = Field(default_factory=list)
    model: str
    latency_ms: int
    policy_reason: str
    tools_called: list[str] = Field(default_factory=list)
    redactions: list[str] = Field(default_factory=list)
    query_sha256: str = ""
    extra: dict[str, Any] = Field(default_factory=dict)


class CacheHint(BaseModel):
    static_prefix: bool = False


class LLMResponse(BaseModel):
    text: str = ""
    tool_calls: list[ToolInvocation] = Field(default_factory=list)
    stop_reason: str | None = None
    raw: dict[str, Any] = Field(default_factory=dict)
    usage: dict[str, int] = Field(default_factory=dict)


class AgentRunResult(BaseModel):
    text: str
    decision: Decision
    policy_reason: str
    explanation: str
    trace_id: str
    docs: list[str] = Field(default_factory=list)
    tools_called: list[str] = Field(default_factory=list)
    model: str = ""

