# Security Architecture Report

## Overview

The secure agent is implemented as a terminal-first Anthropic-compatible RAG system with a narrow MCP tool boundary. The main security design goal is to ensure that identity, authorization, and tool control are enforced outside the model.

## Main Architecture

- `app.main` and `app.showcase` create the operator-facing flows.
- `agents.controller` performs query classification, policy checks, tool orchestration, output validation, memory summarization, and audit logging.
- `agents.llm` provides an Anthropic-first Messages API adapter, plus mock and Groq fallbacks.
- `mcp_gateway` validates client tokens, checks scopes, rate-limits requests, injects correlation IDs, and issues audience-restricted service tokens.
- `mcp_server` exposes only four bounded tools: snippet search, excerpt read, approval-request creation, and approval-status lookup.
- `retrieval` loads the lab corpus and returns only the actor tenant plus public material.

## Threats And Mitigations

### Prompt injection and hidden-prompt disclosure

- Mitigation: pre-model pattern checks in `policies.guard`, refusal templates, and output scanning.
- Evidence: jailbreak-style prompts in tests are refused with `InjectionDetected`.

### Cross-tenant data exfiltration

- Mitigation: runtime tenant normalization, tenant-scoped retrieval, refusal on cross-tenant private requests, and tenant scope in JWT claims.
- Evidence: `tests/test_acl.py` and showcase scenario 2.

### PII extraction

- Mitigation: pre-request denial for explicit PII extraction, masking for retrieved snippets, and output scanning for leaked identifiers.
- Evidence: `tests/test_pii.py`.

### Memory, logs, and system prompt dumping

- Mitigation: dedicated denial path for memory/log export, redacted per-tenant summary memory only, and no raw secrets in audit logs.
- Evidence: `tests/test_injection.py` plus policy reason `MemoryAccessDenied`.

### MCP confused-deputy and token passthrough risks

- Mitigation: gateway validates client audience `mcp-gateway`, rewrites to service audience `mcp-server`, and never forwards the client bearer token.
- Evidence: `tests/test_mcp_security.py::test_server_rejects_client_token_direct_bypass`.

### Wrong scope or tenant misuse

- Mitigation: gateway requires `mcp:invoke` plus a matching `tenant:<tenant_id>` scope; server tools require per-tool scopes.
- Evidence: `tests/test_mcp_security.py::test_gateway_rejects_wrong_tenant_scope`.

### Overpowered tool surface

- Mitigation: only four MCP tools exist, and there is no shell access, arbitrary URL fetch, raw filesystem export, or log dumping tool.

### Unsafe auto-execution of privileged actions

- Mitigation: high-risk requests are mapped to `governance_submit_access_request`, which records a pending request and explicitly does not grant access.
- Evidence: showcase scenario 5 and `tests/test_showcase_flow.py`.

## Anthropic Compatibility Notes

- The primary provider is the native Anthropic Messages API request shape.
- Tool execution is modeled using Anthropic-style tool schemas and `tool_use` / `tool_result` message blocks.
- Tool names are implemented with underscores instead of dotted namespace names so they remain valid for Anthropic tool definitions.
- Prompt caching is only enabled for static system boilerplate, never tenant-specific snippets.

## Residual Risks

- A determined attacker may still discover new prompt patterns that require additional blocking rules.
- The mock provider used for CI is intentionally simpler than a live Claude model.
- The local JWT issuer is suitable for a demo and test environment; production would need enterprise key management and stronger operational controls.
- The lexical retriever is deterministic and lightweight, but it is less semantically capable than a production vector stack.

## Release Evidence

- Security regression tests
- MCP auth tests
- Red-team runner results
- Structured audit logs
- Plain-language showcase script for live demonstrations
