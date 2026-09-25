"""Model agent runner (M3): an LLM drives gdb-mcp over MCP, the harness grades.

The loop is deliberately provider-agnostic: anything speaking the OpenAI
chat-completions dialect (DeepSeek, OpenAI, vLLM, …) works through
:class:`OpenAICompatProvider`. Tool schemas come from the live server's
``list_tools`` — no second hand-written tool table to drift.

Honesty rules carried over from E3 (see bench/SPEC.md §1):

* the agent's final message is never evidence — grading re-uses the same
  harness-side ``run_checks`` as the selfcheck;
* every tool result is truncated to a bounded observation window so the
  model cannot blow its context on a spilled dump;
* a task the model abandons (no ``submit`` within budget) is a failure,
  recorded with its reason — never silently dropped.

Usage::

    python -m bench.framework.cli agent --model deepseek-chat \
        --api-key-env DEEPSEEK_API_KEY [--filter breakpoints] [--limit 3]
"""

from __future__ import annotations

import asyncio
import json
import os
import time
from contextlib import suppress
from pathlib import Path
from typing import Any

import httpx

from .driver import McpDriver
from .generators.common import program_path
from .verifiers import run_checks

ROOT = Path(__file__).resolve().parents[2]
RESULTS_DIR = ROOT / "bench" / "results"

SUBMIT_TOOL = "submit"

#: Tools that cannot help inside a benchmark task: the static bridge needs a
#: Ghidra install (absent in bench environments), the rest manage the server
#: itself rather than the debugging session.
EXCLUDED_TOOLS = frozenset(
    {
        "analyze_binary",
        "annotate_code",
        "decompile_function",
        "get_analysis_status",
        "get_binary_overview",
        "get_call_graph",
        "get_static_disassembly",
        "get_xrefs",
        "list_analyses",
        "list_functions",
        "list_sections",
        "list_strings",
        "list_symbols",
        "search_decompiled_code",
        "remove_code_annotation",
        "launch_script",
        "kill_session",
        "quit_gdb",
    }
)


class ProviderError(RuntimeError):
    pass


# --------------------------------------------------------------------------
# provider


class ProviderReply:
    def __init__(
        self,
        content: str | None,
        tool_calls: list[dict[str, Any]],
        usage: dict[str, int],
        raw_finish: str,
    ):
        self.content = content
        self.tool_calls = tool_calls  # [{id, name, arguments(dict)}]
        self.usage = usage  # {prompt_tokens, completion_tokens}
        self.raw_finish = raw_finish


class OpenAICompatProvider:
    """Minimal async client for OpenAI-style /chat/completions endpoints."""

    def __init__(
        self,
        model: str,
        api_key: str,
        base_url: str = "https://api.deepseek.com",
        timeout_s: float = 180.0,
        max_tokens: int = 2048,
        temperature: float = 0.0,
        retries: int = 3,
    ):
        self.model = model
        self.api_key = api_key
        self.base_url = base_url.rstrip("/")
        self.timeout_s = timeout_s
        self.max_tokens = max_tokens
        self.temperature = temperature
        self.retries = retries
        self.total_usage = {"prompt_tokens": 0, "completion_tokens": 0}

    async def chat(
        self,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]],
    ) -> ProviderReply:
        payload: dict[str, Any] = {
            "model": self.model,
            "messages": messages,
            "max_tokens": self.max_tokens,
            "temperature": self.temperature,
        }
        if tools:
            payload["tools"] = tools
            payload["tool_choice"] = "auto"
        headers = {"Authorization": "Bearer %s" % self.api_key}
        last_error: Exception | None = None
        for attempt in range(self.retries):
            try:
                async with httpx.AsyncClient(
                    timeout=self.timeout_s
                ) as client:
                    response = await client.post(
                        "%s/chat/completions" % self.base_url,
                        json=payload,
                        headers=headers,
                    )
                if response.status_code in (429, 500, 502, 503, 529):
                    last_error = ProviderError(
                        "HTTP %d: %s" % (response.status_code, response.text[:200])
                    )
                    await asyncio.sleep(2.0 * (attempt + 1))
                    continue
                if response.status_code != 200:
                    raise ProviderError(
                        "HTTP %d: %s" % (response.status_code, response.text[:500])
                    )
                return self._parse(response.json())
            except (httpx.TimeoutException, httpx.TransportError) as exc:
                last_error = exc
                await asyncio.sleep(2.0 * (attempt + 1))
        raise ProviderError("chat failed after %d attempts: %s" % (self.retries, last_error))

    def _parse(self, data: dict[str, Any]) -> ProviderReply:
        try:
            choice = data["choices"][0]
            message = choice["message"]
        except (KeyError, IndexError) as exc:
            raise ProviderError("malformed completion: %s" % json.dumps(data)[:300]) from exc
        tool_calls = []
        for call in message.get("tool_calls") or []:
            function = call.get("function") or {}
            raw_args = function.get("arguments") or "{}"
            try:
                arguments = json.loads(raw_args)
            except json.JSONDecodeError:
                arguments = {"_unparsed": str(raw_args)[:500]}
            tool_calls.append(
                {
                    "id": call.get("id") or "call_%d" % len(tool_calls),
                    "name": function.get("name") or "",
                    "arguments": arguments,
                }
            )
        usage = data.get("usage") or {}
        prompt_tokens = int(usage.get("prompt_tokens") or 0)
        completion_tokens = int(usage.get("completion_tokens") or 0)
        self.total_usage["prompt_tokens"] += prompt_tokens
        self.total_usage["completion_tokens"] += completion_tokens
        return ProviderReply(
            content=message.get("content"),
            tool_calls=tool_calls,
            usage={"prompt_tokens": prompt_tokens, "completion_tokens": completion_tokens},
            raw_finish=choice.get("finish_reason") or "",
        )


def load_env_file(path: Path) -> dict[str, str]:
    """Parse a simple KEY=VALUE .env file (no shell quoting interpretation)."""
    out: dict[str, str] = {}
    if not path.exists():
        return out
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        out[key.strip()] = value.strip().strip('"').strip("'")
    return out


# --------------------------------------------------------------------------
# schemas + prompts


def tools_for_agent(descriptors: list[dict]) -> list[dict[str, Any]]:
    """MCP tool descriptors -> OpenAI function-tool schemas + the submit tool."""
    tools: list[dict[str, Any]] = []
    for desc in descriptors:
        if desc["name"] in EXCLUDED_TOOLS:
            continue
        tools.append(
            {
                "type": "function",
                "function": {
                    "name": desc["name"],
                    "description": (desc["description"] or "")[:1000],
                    "parameters": desc["input_schema"],
                },
            }
        )
    tools.append(
        {
            "type": "function",
            "function": {
                "name": SUBMIT_TOOL,
                "description": (
                    "Call this when the task is done (or cannot proceed). "
                    "The harness will verify the live session state."
                ),
                "parameters": {
                    "type": "object",
                    "properties": {
                        "summary": {
                            "type": "string",
                            "description": "One sentence on what you did.",
                        },
                        "answer": {
                            "type": "object",
                            "description": (
                                "For fact-extraction tasks only: the JSON answer "
                                "with exactly the requested fields."
                            ),
                        },
                    },
                },
            },
        }
    )
    return tools


def system_prompt(task, program_path: str, max_chars_observation: int) -> str:
    return """You are a security researcher solving ONE debugging task against a real Linux gdb session, driven through the gdb-mcp MCP tools.

The target program path (pass it verbatim to launch_gdb): %s

How to work:
1. Call launch_gdb(program=<target path above>) to start a session. It may return with state="connecting" while gdb starts in WSL; just proceed — the server queues your next tool call until the session is live.
2. "continue_execution" never starts an unstarted inferior: run the program with execute_command(command="run"). "run" returns immediately while the inferior runs asynchronously — after it, call wait_for_stop(timeout_ms=15000) ONCE (it blocks server-side until the inferior stops). Never poll get_stop_reason in a loop; if wait_for_stop times out, the program is still running — interrupt it or reassess.
3. Many targets are built WITHOUT debug info: you cannot reference local variable names or set conditions on locals. Read globals through casts, e.g. break audit if *(int *)&g == 7 or watch *(int *)&probe. &symbol and raw memory reads still work.
4. Inspect what you need (registers, memory, backtrace, breakpoints) and leave the live session in EXACTLY the state the task asks for. Do not kill or quit the session.
5. When done — or when you cannot proceed — call the submit tool. The harness verifies the live session state itself; your summary is not evidence.

Keep every observation small: tool results are truncated to %d characters. Spend your steps wisely; you have a hard step budget. The task:

%s""" % (program_path, max_chars_observation, task.prompt)


# --------------------------------------------------------------------------
# the loop


class AgentRunError(RuntimeError):
    pass


async def run_agent_loop(
    driver: McpDriver,
    provider: OpenAICompatProvider,
    task,
    max_tool_chars: int = 6000,
    wall_clock_s: float = 900.0,
) -> dict:
    """Drive one task; returns a record (no grading here)."""
    descriptors = await driver.list_tools()
    tools = tools_for_agent(descriptors)
    messages: list[dict[str, Any]] = [
        {"role": "system", "content": system_prompt(
            task, program_path(task), max_tool_chars
        )}
    ]
    record: dict[str, Any] = {
        "steps_used": 0,
        "tool_calls": 0,
        "submitted": False,
        "abandoned": None,
        "answer": None,
        "summary": None,
        "prompt_tokens": 0,
        "completion_tokens": 0,
        "tool_errors": 0,
        "trace": [],  # per-step [{step, calls: [{tool, args, result_head}]}]
    }
    session_id: str | None = None
    deadline = time.monotonic() + wall_clock_s
    budget = task.max_steps + 2  # headroom for the final submit turn

    try:
        while True:
            if time.monotonic() > deadline:
                record["abandoned"] = "wall_clock"
                break
            if record["steps_used"] >= budget:
                record["abandoned"] = "step_budget"
                break
            reply = await provider.chat(messages, tools)
            record["prompt_tokens"] += reply.usage["prompt_tokens"]
            record["completion_tokens"] += reply.usage["completion_tokens"]
            record["steps_used"] += 1
            if not reply.tool_calls:
                # bare prose: nudge once per occurrence toward submit
                if record["steps_used"] >= budget:
                    record["abandoned"] = "no_submit"
                    break
                messages.append({"role": "assistant", "content": reply.content or ""})
                messages.append(
                    {
                        "role": "user",
                        "content": (
                            "Do not reply in prose. Either call a gdb-mcp tool to "
                            "advance the task, or call submit when finished."
                        ),
                    }
                )
                continue
            messages.append(
                {
                    "role": "assistant",
                    "content": reply.content or "",
                    "tool_calls": [
                        {
                            "id": c["id"],
                            "type": "function",
                            "function": {
                                "name": c["name"],
                                "arguments": json.dumps(c["arguments"]),
                            },
                        }
                        for c in reply.tool_calls
                    ],
                }
            )
            step_trace: list[dict[str, Any]] = []
            for call in reply.tool_calls:
                record["tool_calls"] += 1
                name, args = call["name"], call["arguments"]
                if name == SUBMIT_TOOL:
                    record["submitted"] = True
                    record["summary"] = str(args.get("summary", ""))[:500]
                    record["answer"] = args.get("answer")
                    messages.append(
                        {"role": "tool", "tool_call_id": call["id"], "content": "ok"}
                    )
                    return record
                try:
                    if not isinstance(args, dict):
                        raise AgentRunError("arguments must be an object")
                    payload = await driver.call(name, args)
                    if "session_id" in (payload or {}) and isinstance(payload["session_id"], str):
                        if session_id is None and name == "launch_gdb":
                            session_id = payload["session_id"]
                    text = json.dumps(payload, ensure_ascii=False, default=str)
                except Exception as exc:
                    record["tool_errors"] += 1
                    text = "ERROR: %s" % str(exc)[:500]
                step_trace.append(
                    {
                        "tool": name,
                        "args": json.dumps(args, ensure_ascii=False, default=str)[:200],
                        "result_head": text[:200],
                        "error": text.startswith("ERROR:"),
                    }
                )
                if len(text) > max_tool_chars:
                    text = text[:max_tool_chars] + "…<truncated>"
                messages.append(
                    {"role": "tool", "tool_call_id": call["id"], "content": text}
                )
            record["trace"].append(
                {"step": record["steps_used"], "calls": step_trace}
            )
    finally:
        record["session_id"] = session_id
    return record


async def run_agent_suite(
    tasks,
    provider: OpenAICompatProvider,
    distro: str,
    port: int,
    results_dir: Path,
    label: str = "agent",
    log_dir: str | None = None,
    max_tool_chars: int = 6000,
) -> dict:
    results_dir.mkdir(parents=True, exist_ok=True)
    stamp = time.strftime("%Y%m%d-%H%M%S")
    jsonl_path = results_dir / ("%s-%s-%s.jsonl" % (label, provider.model, stamp))
    summary_path = results_dir / ("%s-%s-%s.summary.json" % (label, provider.model, stamp))

    records: list[dict] = []
    async with McpDriver(port=port, distro=distro, log_dir=log_dir) as driver:
        for task in tasks:
            record: dict = {
                "id": task.id,
                "family": task.family,
                "difficulty": task.difficulty,
                "kind": task.kind,
                "tags": task.tags,
                "max_steps": task.max_steps,
                "binary_sha256": task.target.binary_sha256,
                "model": provider.model,
            }
            started = time.perf_counter()
            try:
                loop_record = await run_agent_loop(
                    driver, provider, task, max_tool_chars=max_tool_chars
                )
                record.update(loop_record)
                session_id = loop_record.get("session_id")
                try:
                    checks = await run_checks(driver, session_id, task)
                except Exception as exc:
                    checks = []
                    record["error"] = "grading failed: %s" % exc
                record["checks"] = [
                    {"op": c.op, "passed": c.passed, "detail": c.detail} for c in checks
                ]
                checks_ok = bool(checks) and all(c.passed for c in checks)
                steps_ok = record["steps_used"] <= task.max_steps
                record["passed"] = bool(checks_ok and steps_ok and record["submitted"])
                if not record["passed"]:
                    reasons = []
                    if not checks_ok:
                        reasons.append("checks")
                    if not steps_ok:
                        reasons.append(
                            "steps %d > %d" % (record["steps_used"], task.max_steps)
                        )
                    if not record["submitted"]:
                        reasons.append("no_submit:%s" % record["abandoned"])
                    record["error"] = "failed: " + ", ".join(reasons)
            except Exception as exc:  # never let one task kill the suite
                record["passed"] = False
                record["error"] = "%s: %s" % (type(exc).__name__, exc)
            finally:
                record["wall_ms"] = round((time.perf_counter() - started) * 1000, 1)
                record["provider_usage"] = dict(provider.total_usage)
                records.append(record)
                print("[%s] %-24s steps=%-3d tok=%-7d %s" % (
                    "PASS" if record["passed"] else "FAIL",
                    task.id,
                    record.get("steps_used", 0),
                    record.get("prompt_tokens", 0) + record.get("completion_tokens", 0),
                    record.get("error", "")[:110],
                ), flush=True)
                with suppress(Exception):
                    sid = record.get("session_id")
                    if sid:
                        await driver.call(
                            "kill_session", {"session_id": sid, "force": True}
                        )

    summary = summarize(records, model=provider.model, latency=driver.latency_report())
    with jsonl_path.open("w", encoding="utf-8") as fh:
        for r in records:
            fh.write(json.dumps(r, ensure_ascii=False) + "\n")
    summary_path.write_text(
        json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    print("results: %s" % jsonl_path)
    print("summary: %s" % summary_path)
    return summary


def summarize(records: list[dict], model: str = "", latency: dict | None = None) -> dict:
    def rate(subset: list[dict]) -> float:
        if not subset:
            return 0.0
        return round(sum(1 for r in subset if r.get("passed")) / len(subset), 4)

    def avg(subset: list[dict], key: str) -> float | None:
        vals = [r[key] for r in subset if isinstance(r.get(key), (int, float))]
        return round(sum(vals) / len(vals), 1) if vals else None

    by_family: dict[str, list[dict]] = {}
    by_difficulty: dict[str, list[dict]] = {}
    tag_records: dict[str, list[dict]] = {}
    for record in records:
        by_family.setdefault(record["family"], []).append(record)
        by_difficulty.setdefault(record["difficulty"], []).append(record)
        for tag in record.get("tags", []):
            tag_records.setdefault(tag, []).append(record)

    prompt_total = sum(r.get("prompt_tokens", 0) for r in records)
    completion_total = sum(r.get("completion_tokens", 0) for r in records)
    per_task = [
        r.get("prompt_tokens", 0) + r.get("completion_tokens", 0) for r in records
    ]
    return {
        "bench_version": "1.0.0",
        "label": "agent",
        "model": model,
        "total": len(records),
        "passed": sum(1 for r in records if r.get("passed")),
        "success_rate": rate(records),
        "avg_steps": avg(records, "steps_used"),
        "avg_tool_calls": avg(records, "tool_calls"),
        "avg_tokens_per_task": round(sum(per_task) / len(per_task), 1) if per_task else None,
        "tokens": {"prompt": prompt_total, "completion": completion_total,
                   "total": prompt_total + completion_total},
        "by_family": {k: {"n": len(v), "rate": rate(v)} for k, v in sorted(by_family.items())},
        "by_difficulty": {k: {"n": len(v), "rate": rate(v)}
                          for k, v in sorted(by_difficulty.items())},
        "by_tag": {k: {"n": len(v), "rate": rate(v)} for k, v in sorted(tag_records.items())},
        "latency": latency or {},
    }
