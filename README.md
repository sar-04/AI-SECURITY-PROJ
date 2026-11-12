# Secure Lab Knowledge Agent Showcase

This repository is a terminal-first demo of how to build and secure an AI agent in a multi-tenant enterprise-style environment.

It simulates a research organization with separate labs, shared public knowledge, sensitive internal data, and a tool-using agent that must stay useful without becoming unsafe.

## Measured results

On 44 labelled attacks and 38 normal questions, offline with the rules layer only: **0 of 44 attacks leaked data**, 35 of 44 were refused outright, and all 28 plain questions were answered. The keyword rules wrongly refused 7 of 8 normal questions that used words like "token" or "logs", which is the job of the LLM judge layer. Full numbers, method and the open questions are in [eval/RESULTS.md](eval/RESULTS.md).

```
python tools/measure_defences.py --config config.test.yaml   # offline, no API key
```


The project is designed to showcase:

- Anthropic-compatible agent orchestration
- least-privilege access control
- cross-tenant isolation
- prompt injection resistance
- PII protection
- approval-gated high-risk actions
- secured MCP gateway and server patterns
- audit logging and red-team verification

## What It Simulates

The demo models a fictional research environment with several tenant-isolated labs:

- `U1_genomics`
- `U2_nlp`
- `U3_robotics`
- `U4_materials`
- `public`

Users can ask the agent questions about lab knowledge, but the system must:

- answer allowed questions with grounded citations
- refuse cross-tenant access attempts
- block prompt injection and hidden-prompt disclosure attempts
- deny PII extraction
- stop memory/log dumping requests
- turn risky actions into approval workflows instead of auto-executing them

## Architecture At A Glance

Main runtime path:

1. `app/main.py` accepts a tenant and query.
2. `agents/controller.py` normalizes the actor context and applies policy.
3. `policies/guard.py` evaluates injection, leakage, tenant, PII, and approval rules.
4. `mcp_gateway/app.py` enforces gateway auth, rate limits, scopes, and tenant checks.
5. `mcp_server/app.py` exposes a narrow MCP tool surface.
6. `agents/llm.py` sends authorized, sanitized context to the Anthropic Messages API or fallback providers.
7. audit and memory summaries are written locally.

Core MCP tools:

- `lab_search_snippets`
- `lab_read_doc_excerpt`
- `governance_submit_access_request`
- `governance_get_request_status`

## Security Layers

This repo demonstrates layered defenses rather than relying on one prompt.

- Input controls: detect prompt injection, policy override attempts, hidden-prompt disclosure, memory dumping, and sensitive-data extraction patterns.
- Retrieval controls: enforce ACLs from the data manifests, restrict retrieval to authorized tenants, redact sensitive content, and scrub indirect prompt injection in retrieved text.
- Model controls: require grounded, citation-based answers and refuse when authorized evidence is insufficient.
- Output controls: check for leaked PII, unsupported claims, and policy-violating responses before returning output.
- MCP controls: validate token audience, scope, and tenant claims; avoid token passthrough; rate-limit requests; and keep the tool surface narrow.
- Governance controls: route high-risk operations into approval flows rather than auto-running them.
- Audit controls: log policy decisions, tools, documents, trace IDs, and outcomes for review.

## Main Docs

Start here depending on the audience:

- [showcase_report.md](./showcase_report.md): plain-language walkthrough for demos and non-specialist stakeholders
- [security_architecture_report.md](./security_architecture_report.md): detailed technical security design and mitigation mapping
- [MAC_SETUP_GUIDE.md](./MAC_SETUP_GUIDE.md): end-to-end setup guide for macOS

## Quick Start

### 1. Create a virtual environment

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip setuptools wheel
python -m pip install -r requirements.txt
```

### 2. Set your Anthropic key

```bash
export ANTHROPIC_API_KEY="your_key_here"
```

### 3. Run the showcase

```bash
python -m app.showcase
```

### 4. Run a direct query

```bash
python -m app.main \
  --tenant U1 \
  --query "Summarize the Genomics lab notebook results." \
  --config config.yaml \
  --show-trace
```

## Verification

Run the automated tests:

```bash
pytest -q
```

Run the red-team evaluation:

```bash
python tools/run_redteam.py --config config.test.yaml --out eval/redteam_results_secure.json
```

## Repository Highlights

- [app/main.py](./app/main.py): CLI entrypoint
- [app/showcase.py](./app/showcase.py): guided terminal demo
- [agents/controller.py](./agents/controller.py): secure orchestration flow
- [agents/llm.py](./agents/llm.py): Anthropic-compatible provider layer
- [policies/guard.py](./policies/guard.py): security decision layer
- [mcp_gateway/app.py](./mcp_gateway/app.py): secured MCP gateway
- [mcp_server/app.py](./mcp_server/app.py): narrow MCP tool server
- [tests](./tests): security and behavior coverage

## Notes

- The primary runtime path is Anthropic-native, not OpenAI-compat mode.
- Test and certification flows can run against the mock provider for deterministic results.
- The project presents itself as hardened and evidenced, not as literally unbreakable.
