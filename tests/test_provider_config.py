from __future__ import annotations

from agents.llm import build_provider


def test_strict_primary_live_config_disables_mock_fallback():
    provider = build_provider(
        {
            "llm": {
                "provider": "anthropic",
                "fallback_provider": "mock",
                "strict_primary": True,
            }
        }
    )
    assert [p.name for p in provider.providers] == ["anthropic"]
