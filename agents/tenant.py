from __future__ import annotations

import re


RUNTIME_TENANT_ALIASES = {
    "U1": "U1_genomics",
    "U2": "U2_nlp",
    "U3": "U3_robotics",
    "U4": "U4_materials",
    "public": "public",
    "PUB": "public",
}

TENANT_LAB_NAMES = {
    "U1_genomics": "Genomics & Bioinformatics",
    "U2_nlp": "Natural Language Processing",
    "U3_robotics": "Field Robotics & Perception",
    "U4_materials": "Advanced Materials & Energy",
    "public": "Research Core",
}

LAB_KEYWORDS = {
    "genomics": "U1_genomics",
    "bioinformatics": "U1_genomics",
    "nlp": "U2_nlp",
    "natural language": "U2_nlp",
    "robotics": "U3_robotics",
    "materials": "U4_materials",
    "energy": "U4_materials",
    "public": "public",
    "research core": "public",
}


def normalize_tenant_id(tenant_id: str) -> str:
    tenant_id = tenant_id.strip()
    return RUNTIME_TENANT_ALIASES.get(tenant_id, tenant_id)


def runtime_tenant_id(tenant_id: str) -> str:
    tenant_id = normalize_tenant_id(tenant_id)
    for runtime, canonical in RUNTIME_TENANT_ALIASES.items():
        if canonical == tenant_id and runtime.startswith("U"):
            return runtime
    return tenant_id


def tenant_lab_name(tenant_id: str) -> str:
    return TENANT_LAB_NAMES.get(normalize_tenant_id(tenant_id), normalize_tenant_id(tenant_id))


def detect_tenant_from_query(query: str) -> str | None:
    low = query.lower()
    for marker, tenant_id in LAB_KEYWORDS.items():
        if marker in low:
            return tenant_id

    match = re.search(r"\b(U[1-4])\b", query, flags=re.IGNORECASE)
    if match:
        return normalize_tenant_id(match.group(1).upper())
    return None


def tenant_scope(tenant_id: str) -> str:
    return f"tenant:{normalize_tenant_id(tenant_id)}"


def tool_scope(tool_name: str) -> str:
    return f"tool:{tool_name}"


def default_tool_names() -> list[str]:
    return [
        "lab_search_snippets",
        "lab_read_doc_excerpt",
        "governance_submit_access_request",
        "governance_get_request_status",
    ]

