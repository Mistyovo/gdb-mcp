"""One-shot probe: does deepseek-reasoner accept tool calls?

Temporary bench utility - answers model-selection questions for ~free
before committing to a full --go run. Delete or keep at your leisure.
"""

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from gdb_mcp.bench import DeepSeekClient  # noqa: E402


def probe(model: str) -> None:
    llm = DeepSeekClient(model=model, max_tokens=4096)
    llm.bind_tools(
        [
            {
                "type": "function",
                "function": {
                    "name": "probe_tool",
                    "description": "trivial probe tool",
                    "parameters": {
                        "type": "object",
                        "properties": {"value": {"type": "integer"}},
                    },
                },
            }
        ]
    )
    reply = llm.chat(
        [
            {
                "role": "user",
                "content": "Call probe_tool with value=42. Do not answer "
                "in prose; use the tool.",
            }
        ]
    )
    calls = reply.get("tool_calls") or []
    print(
        "model=%s tool_calls=%s content_head=%r total_tokens=%d"
        % (
            model,
            [(c["name"], c["arguments"]) for c in calls],
            str(reply.get("content") or "")[:80],
            llm.total_tokens,
        )
    )


if __name__ == "__main__":
    for name in sys.argv[1:] or ["deepseek-reasoner"]:
        try:
            probe(name)
        except Exception as exc:
            print("model=%s FAILED: %s" % (name, exc))
