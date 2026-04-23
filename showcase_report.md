# Secure Lab Knowledge Agent Showcase

This project demonstrates a secure AI agent that answers lab knowledge questions without exposing private data or hidden system behavior. The demo uses a simple terminal workflow so viewers can focus on the security decisions rather than a front-end.

## What The Agent Does

- Answers questions for the active lab tenant using authorized lab notes and public research-core documents.
- Refuses unsafe requests, including PII extraction, cross-tenant access, memory dumping, and prompt-injection attempts.
- Routes higher-risk access requests into a manual approval flow instead of granting access automatically.
- Uses an MCP gateway and MCP server so tool access is isolated, authenticated, and auditable.

## What People See In The Demo

1. A valid same-tenant summary succeeds and shows exactly which evidence was used.
2. A cross-tenant question is refused before any unsafe disclosure happens.
3. A PII request is blocked because phone numbers and CNIC-style identifiers are protected.
4. A jailbreak attempt is refused because the agent does not obey instructions that conflict with policy.
5. A risky access request becomes “approval required” instead of an automatic grant.
6. A bad gateway token is rejected before the MCP tool server processes the request.

## Why This Is A Good Security Example

- The model is not trusted to enforce access control.
- Tenant isolation is decided in code before the answer is generated.
- Tool access is scoped and authenticated with short-lived JWTs.
- The gateway rewrites tokens so client tokens are never passed directly to the MCP server.
- Logs are structured for review without storing raw secrets or exported private content.
- The system can still be useful while saying “no” safely and clearly.

## Plain-English Takeaway

The point of this showcase is not that the agent is magically impossible to break. The point is that the system is designed so that even when someone tries common attacks, the risky behavior is blocked by multiple layers before sensitive data can leak.

