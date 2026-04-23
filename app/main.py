import argparse
import asyncio
import json
import os

import yaml

from agents.controller import run_agent_async

def load_cfg(path: str):
    if path and os.path.exists(path):
        with open(path, "r", encoding="utf-8") as f:
            return yaml.safe_load(f) or {}
    return {}

def main():
    p = argparse.ArgumentParser()
    p.add_argument("--tenant", required=True, help="U1, U2, U3, U4")
    p.add_argument("--query", required=True)
    p.add_argument("--config", default="config.yaml")
    p.add_argument("--memory", choices=["off", "buffer", "summary"], default="summary")
    p.add_argument("--json", action="store_true", dest="as_json")
    p.add_argument("--show-trace", action="store_true")
    args = p.parse_args()

    cfg = load_cfg(args.config)
    base_dir = os.path.dirname(os.path.dirname(__file__))

    class _Mem: pass
    mem = _Mem(); mem.kind = args.memory

    result = asyncio.run(run_agent_async(base_dir, args.tenant, args.query, cfg, memory=mem))
    if args.as_json:
        print(json.dumps(result.model_dump(), indent=2, ensure_ascii=False))
        return

    if args.show_trace:
        print(f"Decision: {result.decision.value}")
        print(f"Policy: {result.policy_reason}")
        print(f"Trace: {result.trace_id}")
        if result.docs:
            print(f"Docs: {', '.join(result.docs)}")
        if result.tools_called:
            print(f"Tools: {', '.join(result.tools_called)}")
        print(f"Why: {result.explanation}")
        print()
    print(result.text)

if __name__ == "__main__":
    main()
