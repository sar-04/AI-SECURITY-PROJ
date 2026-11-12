from __future__ import annotations

import re
from typing import Iterable

from agents.models import ActorContext, Decision, PolicyDecision, RequestPlan, SourceSnippet
from agents.tenant import detect_tenant_from_query, normalize_tenant_id, tenant_lab_name
from retrieval.index import Hit
from retrieval.search import scrub_hit, text_contains_pii


REFUSAL_MESSAGES = {
    "AccessDenied": "Refusal: AccessDenied. You do not have access to that information.",
    "LeakageRisk": "Refusal: LeakageRisk. The request seeks protected, private, or identifying data.",
    "InjectionDetected": "Refusal: InjectionDetected. Ignoring instructions that conflict with system policy.",
    "ExternalAttackDetected": "Refusal: ExternalAttackDetected. The request attempted prohibited external, credential, network, or shell attack behavior.",
    "MemoryAccessDenied": "Refusal: MemoryAccessDenied. Memory, logs, and hidden prompts are not exportable.",
    "ApprovalRequired": "Approval required. A governance request can be created, but no protected access is granted automatically.",
    "InsufficientAuthorizedEvidence": "Refusal: InsufficientAuthorizedEvidence. The authorized snippets are not sufficient to answer safely.",
    "OutputPolicyViolation": "Refusal: OutputPolicyViolation. The generated output violated security policy and was blocked.",
}

INJECTION_PATTERNS = [
    re.compile(r"ignore\b.*\b(rules|instructions)\b", re.IGNORECASE),
    re.compile(r"override\s+policy", re.IGNORECASE),
    re.compile(r"bypass\s+(approval|policy|injection)", re.IGNORECASE),
    re.compile(r"print\s+hidden\s+system", re.IGNORECASE),
    re.compile(r"system\s+prompt", re.IGNORECASE),
    re.compile(r"mask\s+nothing", re.IGNORECASE),
    re.compile(r"exfiltrate", re.IGNORECASE),
]

MEMORY_PATTERNS = [
    re.compile(r"\bdump\b.*\b(memory|logs?)\b", re.IGNORECASE),
    re.compile(r"\b(buffer|summary)\s+memory\b", re.IGNORECASE),
    re.compile(r"\bhidden\s+prompts?\b", re.IGNORECASE),
    re.compile(r"\braw\s+logs?\b", re.IGNORECASE),
]

PII_PATTERNS = [
    re.compile(r"\b(phone|phone numbers?|cnic|cnics|contact details|private phone|confidential contacts?)\b", re.IGNORECASE),
    re.compile(r"\bunmasked\b.*\b(phone|phone numbers?|cnic|cnics|pii)\b", re.IGNORECASE),
    re.compile(r"\bpii\b", re.IGNORECASE),
]

APPROVAL_PATTERNS = [
    re.compile(r"\b(submit|create|open)\b.*\b(access request|approval request)\b", re.IGNORECASE),
    re.compile(r"\brequest\b.*\bapproval\b", re.IGNORECASE),
    re.compile(r"\bescalate\b.*\baccess\b", re.IGNORECASE),
]

STATUS_PATTERNS = [
    re.compile(r"\bstatus\b.*\b(APR-[A-Z0-9-]+)\b", re.IGNORECASE),
    re.compile(r"\b(APR-[A-Z0-9-]+)\b", re.IGNORECASE),
]

PRIVATE_DATA_HINTS = [
    re.compile(r"\b(private|internal|confidential|salary|notebook|memo|dataset)\b", re.IGNORECASE),
]


def refusal_template(kind: str, detail: str = "") -> str:
    base = REFUSAL_MESSAGES.get(kind, "Refusal.")
    return base + (f" {detail}" if detail else "")


def _matches_any(patterns: Iterable[re.Pattern[str]], text: str) -> bool:
    return any(pattern.search(text) for pattern in patterns)


def planner(actor: ActorContext, user_query: str) -> RequestPlan:
    query = " ".join(user_query.split())
    target_tenant = detect_tenant_from_query(query)
    request_id = None
    for pattern in STATUS_PATTERNS:
        match = pattern.search(query)
        if match:
            request_id = match.group(1).upper()
            break

    return RequestPlan(
        action="governance_status"
        if request_id
        else "governance_request"
        if _matches_any(APPROVAL_PATTERNS, query)
        else "retrieve",
        normalized_query=query,
        target_tenant_id=normalize_tenant_id(target_tenant) if target_tenant else None,
        requests_private_data=_matches_any(PII_PATTERNS + PRIVATE_DATA_HINTS, query),
        requests_sensitive_memory=_matches_any(MEMORY_PATTERNS, query),
        requests_approval_flow=_matches_any(APPROVAL_PATTERNS, query),
        requests_status_check=request_id is not None,
        requested_request_id=request_id,
        mentioned_lab=target_tenant,
    )


def evaluate_input_policy(actor: ActorContext, user_query: str) -> tuple[RequestPlan, PolicyDecision]:
    plan = planner(actor, user_query)
    query = plan.normalized_query

    if _matches_any(INJECTION_PATTERNS, query):
        return plan, PolicyDecision(
            decision=Decision.REFUSE,
            reason="InjectionDetected",
            explain="Prompt injection, hidden-instruction disclosure, or policy bypass language was detected.",
        )

    if plan.requests_sensitive_memory:
        return plan, PolicyDecision(
            decision=Decision.REFUSE,
            reason="MemoryAccessDenied",
            explain="The request attempted to dump memory, logs, or hidden prompts.",
        )

    if plan.requests_status_check:
        return plan, PolicyDecision(
            decision=Decision.ALLOW,
            reason="ApprovalStatusLookup",
            required_approval=False,
            allowed_tools=["governance_get_request_status"],
            explain="Only approval-status lookup is allowed for this request.",
        )

    if plan.requests_approval_flow:
        return plan, PolicyDecision(
            decision=Decision.ALLOW,
            reason="ApprovalRequired",
            required_approval=True,
            allowed_tools=["governance_submit_access_request"],
            explain="The request must be routed through a governance approval flow.",
        )

    target_tenant = normalize_tenant_id(plan.target_tenant_id or actor.tenant_id)
    if plan.requests_private_data and target_tenant != actor.tenant_id:
        return plan, PolicyDecision(
            decision=Decision.REFUSE,
            reason="AccessDenied",
            explain="The request seeks private or internal data from another tenant.",
        )

    if plan.requests_private_data and _matches_any(PII_PATTERNS, query):
        return plan, PolicyDecision(
            decision=Decision.REFUSE,
            reason="LeakageRisk",
            explain="The request is attempting to extract identifying or otherwise protected information.",
        )

    return plan, PolicyDecision(
        decision=Decision.ALLOW,
        reason="AllowRetrieval",
        required_approval=False,
        allowed_tools=["lab_search_snippets", "lab_read_doc_excerpt"],
        explain="The request can be answered only from authorized snippets with citations.",
    )


def apply_policy(hits: list[Hit], actor: ActorContext, plan: RequestPlan) -> list[Hit] | dict:
    safe_hits: list[Hit] = []
    actor_private_present = False
    for hit in hits:
        if hit.visibility == "public" or hit.tenant == "public":
            safe_hits.append(scrub_hit(hit))
            continue
        if hit.tenant != actor.tenant_id:
            continue
        actor_private_present = True
        safe_hits.append(scrub_hit(hit))

    if not safe_hits:
        return {"refusal": "InsufficientAuthorizedEvidence", "reason": "No authorized snippets were found."}

    if plan.requests_private_data and plan.target_tenant_id in {None, actor.tenant_id} and not actor_private_present:
        return {
            "refusal": "InsufficientAuthorizedEvidence",
            "reason": "Only public material was retrievable for a private-data request.",
        }
    return safe_hits


def snippets_from_hits(hits: list[Hit]) -> list[SourceSnippet]:
    snippets: list[SourceSnippet] = []
    for index, hit in enumerate(hits, start=1):
        snippet_text = " ".join(line.strip() for line in hit.text.splitlines() if line.strip())[:900]
        snippets.append(
            SourceSnippet(
                index=index,
                doc_id=hit.doc_id,
                tenant_id=hit.tenant,
                visibility=hit.visibility,
                text=snippet_text,
                score=round(hit.score, 3),
                pii_masked=hit.pii_masked,
                source_path=hit.path,
            )
        )
    return snippets


def validate_output(text: str, snippets: list[SourceSnippet]) -> PolicyDecision:
    if text.startswith("Refusal:") or text.startswith("Approval required"):
        return PolicyDecision(decision=Decision.ALLOW, reason="AlreadySafe")

    if text_contains_pii(text):
        return PolicyDecision(
            decision=Decision.REFUSE,
            reason="OutputPolicyViolation",
            explain="The generated output contained data that matches protected PII patterns.",
        )

    if "system prompt" in text.lower() or "override policy" in text.lower():
        return PolicyDecision(
            decision=Decision.REFUSE,
            reason="OutputPolicyViolation",
            explain="The generated output tried to disclose hidden instructions or unsafe policy changes.",
        )

    if snippets and not re.search(r"\[\d+\]", text):
        return PolicyDecision(
            decision=Decision.REFUSE,
            reason="OutputPolicyViolation",
            explain="A non-refusal answer must contain citations tied to authorized snippets.",
        )

    return PolicyDecision(decision=Decision.ALLOW, reason="OutputSafe")


def plain_language_decision(decision: PolicyDecision, actor: ActorContext, plan: RequestPlan) -> str:
    if decision.reason == "AccessDenied":
        target = tenant_lab_name(plan.target_tenant_id or "public")
        return f"The agent blocked the request because it targeted protected data outside {tenant_lab_name(actor.tenant_id)}."
    if decision.reason == "LeakageRisk":
        return "The agent blocked the request because it attempted to expose personally identifying or confidential information."
    if decision.reason == "InjectionDetected":
        return "The agent detected jailbreak or policy-bypass language and refused to follow it."
    if decision.reason == "ExternalAttackDetected":
        return "The agent blocked the request because it looked like an external attack or tool abuse attempt."
    if decision.reason == "ApprovalRequired":
        return "The agent routed the request into a manual approval flow instead of granting access automatically."
    if decision.reason == "InsufficientAuthorizedEvidence":
        return "The agent refused because the authorized evidence was too weak to answer safely."
    return decision.explain or "The agent completed the request using authorized evidence only."
