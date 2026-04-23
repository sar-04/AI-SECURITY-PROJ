from __future__ import annotations

import asyncio

from app.showcase import run_showcase


def test_showcase_runs_all_scenarios(base_dir: str, test_cfg: dict):
    rows = asyncio.run(run_showcase(base_dir, test_cfg))
    assert len(rows) == 6
    assert any(row["decision"] == "approval_required" for row in rows if row["scenario"] == "Approval required flow")
    assert any(row["decision"] == "blocked" for row in rows if row["scenario"] == "Invalid tenant scope at gateway")

