from __future__ import annotations

from agents.llm import AnthropicMessagesProvider
from agents.models import CacheHint


def test_anthropic_request_builder_uses_messages_api_shape():
    provider = AnthropicMessagesProvider(
        {
            "llm": {
                "anthropic": {
                    "model": "claude-3-5-sonnet-latest",
                    "api_base": "https://api.anthropic.com/v1/messages",
                    "api_version": "2023-06-01",
                    "max_tokens": 321,
                }
            }
        }
    )
    payload = provider.build_request_payload(
        messages=[{"role": "user", "content": [{"type": "text", "text": "hello"}]}],
        system="system text",
        tools=[{"name": "lab_search_snippets", "description": "x", "input_schema": {"type": "object"}}],
        stream=False,
        cache_hint=CacheHint(static_prefix=True),
    )
    assert payload["model"] == "claude-3-5-sonnet-latest"
    assert payload["messages"][0]["role"] == "user"
    assert payload["tools"][0]["name"] == "lab_search_snippets"
    assert isinstance(payload["system"], list)
    assert payload["system"][0]["cache_control"]["type"] == "ephemeral"


def test_anthropic_stream_parser_handles_tool_events():
    parsed = AnthropicMessagesProvider.parse_stream_events(
        [
            'event: content_block_start',
            'data: {"type":"content_block_start","content_block":{"type":"tool_use","id":"toolu_1","name":"lab_search_snippets","input":{"query":"hello"}}}',
            'event: message_stop',
            'data: {"type":"message_stop"}',
        ]
    )
    assert parsed["events"][0]["event"] == "content_block_start"
    assert parsed["events"][0]["data"]["content_block"]["name"] == "lab_search_snippets"

