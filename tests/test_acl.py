from __future__ import annotations

import asyncio

from agents.controller import run_agent_async


def test_cross_tenant_block(base_dir: str, test_cfg: dict):
    result = asyncio.run(run_agent_async(base_dir, "U2", "Summarize Robotics internal memos.", cfg=test_cfg))
    assert result.decision.value == "refuse"
    assert result.policy_reason == "AccessDenied"
    assert "Refusal" in result.text
