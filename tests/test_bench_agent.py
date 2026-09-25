"""Unit tests for the M3 agent runner — no network, no gdb.

FakeProvider scripts the model's turns; FakeDriver records tool calls and
returns canned payloads. Together they pin down the loop's contract: submit
ends the run, tool errors feed back instead of aborting, the step budget is
enforced, and grading/summary math is honest.
"""

import json
from pathlib import Path

import pytest

from bench.framework.agent import (
    SUBMIT_TOOL,
    OpenAICompatProvider,
    ProviderReply,
    run_agent_loop,
    run_agent_suite,
    summarize,
    tools_for_agent,
)
from bench.framework.generators import FAMILY_MODULES

ROOT = Path(__file__).resolve().parents[1]


# -- fakes -------------------------------------------------------------------

class FakeProvider:
    def __init__(self, turns, model="fake-model"):
        self.turns = list(turns)
        self.model = model
        self.requests = []
        self.total_usage = {"prompt_tokens": 0, "completion_tokens": 0}

    async def chat(self, messages, tools):
        self.requests.append({"messages": [dict(m) for m in messages], "tools": tools})
        turn = self.turns.pop(0) if self.turns else {"tool_calls": []}
        usage = turn.get("usage", {"prompt_tokens": 10, "completion_tokens": 5})
        self.total_usage["prompt_tokens"] += usage["prompt_tokens"]
        self.total_usage["completion_tokens"] += usage["completion_tokens"]
        return ProviderReply(
            content=turn.get("content"),
            tool_calls=turn.get("tool_calls", []),
            usage=usage,
            raw_finish=turn.get("finish", "tool_calls"),
        )


class FakeDriver:
    def __init__(self, results=None, fail=()):
        self.results = results or {}
        self.fail = set(fail)
        self.calls = []

    async def list_tools(self):
        return [
            {"name": "launch_gdb", "description": "launch", "input_schema": {"type": "object"}},
            {"name": "execute_command", "description": "raw", "input_schema": {"type": "object"}},
            {"name": "decompile_function", "description": "static", "input_schema": {"type": "object"}},
        ]

    async def call(self, tool, arguments=None):
        self.calls.append((tool, arguments))
        if tool in self.fail:
            raise RuntimeError("boom: %s" % tool)
        return self.results.get(tool, {"ok": True})


def _task(max_steps=4):
    task = FAMILY_MODULES["lifecycle"].generate(3)
    task.max_steps = max_steps
    return task


# -- schema conversion -------------------------------------------------------

_DESCRIPTORS = [
    {"name": "launch_gdb", "description": "launch", "input_schema": {"type": "object"}},
    {"name": "execute_command", "description": "raw", "input_schema": {"type": "object"}},
    {"name": "decompile_function", "description": "static", "input_schema": {"type": "object"}},
]


def test_tools_for_agent_excludes_server_admin_and_static():
    tools = tools_for_agent(_DESCRIPTORS)
    names = {t["function"]["name"] for t in tools}
    assert "launch_gdb" in names and "execute_command" in names
    assert "decompile_function" not in names
    assert SUBMIT_TOOL in names


def test_submit_tool_takes_optional_answer():
    (tool,) = [t for t in tools_for_agent([]) if t["function"]["name"] == SUBMIT_TOOL]
    assert tool["function"]["parameters"]["type"] == "object"


def test_system_prompt_carries_program_path_and_budget_rules():
    from bench.framework.agent import system_prompt
    from bench.framework.generators.common import program_path

    task = FAMILY_MODULES["breakpoints"].generate(1)
    text = system_prompt(task, program_path(task), 6000)
    assert program_path(task) in text          # the /challenge hallucination guard
    assert "wait_for_stop" in text             # teach the one-call wait
    assert "submit" in text


# -- provider parsing --------------------------------------------------------

def _completion(message, usage=None):
    return {
        "choices": [{"message": message, "finish_reason": "tool_calls"}],
        "usage": usage or {"prompt_tokens": 7, "completion_tokens": 3},
    }


def test_provider_parses_tool_calls_and_accumulates_usage():
    provider = OpenAICompatProvider(model="m", api_key="k")

    class FakeResponse:
        status_code = 200
        text = ""

        def json(self):
            return _completion(
                {
                    "content": None,
                    "tool_calls": [
                        {"id": "1", "function": {"name": "launch_gdb", "arguments": '{"program": "/x"}'}},
                        {"id": "2", "function": {"name": "run", "arguments": "not-json"}},
                    ],
                }
            )

    reply = provider._parse(FakeResponse().json())
    assert [c["name"] for c in reply.tool_calls] == ["launch_gdb", "run"]
    assert reply.tool_calls[0]["arguments"] == {"program": "/x"}
    assert reply.tool_calls[1]["arguments"] == {"_unparsed": "not-json"}
    assert provider.total_usage == {"prompt_tokens": 7, "completion_tokens": 3}


# -- the loop ----------------------------------------------------------------

def _turn(name, args, call_id="c1"):
    return {"tool_calls": [{"id": call_id, "name": name, "arguments": args}]}


@pytest.mark.asyncio
async def test_loop_happy_path_submit_ends_run():
    driver = FakeDriver(results={"launch_gdb": {"session_id": "s1"}})
    provider = FakeProvider(
        [
            _turn("launch_gdb", {"program": "/tmp/x"}, "c1"),
            {"tool_calls": [{"id": "c2", "name": SUBMIT_TOOL,
                             "arguments": {"summary": "done"}}]},
        ]
    )
    record = await run_agent_loop(driver, provider, _task())
    assert record["submitted"] is True
    assert record["summary"] == "done"
    assert record["session_id"] == "s1"
    assert record["steps_used"] == 1  # one work turn; submit is not a step
    assert record["turns_used"] == 2
    assert record["abandoned"] is None


@pytest.mark.asyncio
async def test_loop_feeds_tool_error_back_and_continues():
    driver = FakeDriver(results={"launch_gdb": {"session_id": "s1"}}, fail=("execute_command",))
    provider = FakeProvider(
        [
            _turn("launch_gdb", {"program": "/x"}),
            _turn("execute_command", {"command": "run"}),
            {"tool_calls": [{"id": "c3", "name": SUBMIT_TOOL, "arguments": {}}]},
        ]
    )
    record = await run_agent_loop(driver, provider, _task())
    assert record["tool_errors"] == 1
    assert record["submitted"] is True
    # the tool message the model received carries the error text
    tool_msgs = [m for m in provider.requests[2]["messages"] if m["role"] == "tool"]
    assert any("boom: execute_command" in m["content"] for m in tool_msgs)


@pytest.mark.asyncio
async def test_loop_truncates_oversized_observations():
    driver = FakeDriver(results={"launch_gdb": {"session_id": "s1", "blob": "A" * 50000}})
    provider = FakeProvider(
        [
            _turn("launch_gdb", {"program": "/x"}),
            {"tool_calls": [{"id": "c2", "name": SUBMIT_TOOL, "arguments": {}}]},
        ]
    )
    record = await run_agent_loop(driver, provider, _task(), max_tool_chars=1000)
    tool_msgs = [m for m in provider.requests[1]["messages"] if m["role"] == "tool"]
    assert len(tool_msgs[0]["content"]) <= 1000 + len("…<truncated>")


@pytest.mark.asyncio
async def test_loop_budget_exhaustion_marks_abandoned():
    provider = FakeProvider([_turn("execute_command", {"command": "x"}, "c%d" % i) for i in range(10)])
    driver = FakeDriver()
    record = await run_agent_loop(driver, provider, _task(max_steps=2))
    assert record["submitted"] is False
    assert record["abandoned"] == "step_budget"
    # max_steps=2 -> max_turns=4 (submit turn + one nudge are exempt)
    assert record["turns_used"] == 4
    assert record["steps_used"] == 4


@pytest.mark.asyncio
async def test_submit_turn_is_not_counted_as_a_step():
    provider = FakeProvider(
        [
            _turn("launch_gdb", {"program": "/x"}),
            {"tool_calls": [{"id": "c2", "name": SUBMIT_TOOL, "arguments": {}}]},
        ]
    )
    record = await run_agent_loop(FakeDriver(), provider, _task(max_steps=1))
    assert record["submitted"] is True
    assert record["steps_used"] == 1      # the work turn
    assert record["turns_used"] == 2      # + the submit turn
    assert record["abandoned"] is None


@pytest.mark.asyncio
async def test_mixed_work_and_submit_turn_counts_the_work():
    provider = FakeProvider(
        [
            {"tool_calls": [
                {"id": "c1", "name": "launch_gdb", "arguments": {"program": "/x"}},
                {"id": "c2", "name": SUBMIT_TOOL, "arguments": {"summary": "s"}},
            ]},
        ]
    )
    record = await run_agent_loop(FakeDriver(results={"launch_gdb": {"session_id": "s1"}}),
                                  provider, _task(max_steps=3))
    assert record["submitted"] is True
    assert record["steps_used"] == 1


@pytest.mark.asyncio
async def test_loop_prose_gets_one_nudge_then_abandons():
    provider = FakeProvider([{"content": "I think I am done."}, {"content": "really."}])
    record = await run_agent_loop(FakeDriver(), provider, _task(max_steps=1))
    nudge = [m for m in provider.requests[1]["messages"] if m.get("role") == "user"]
    assert nudge and "submit" in nudge[-1]["content"]
    assert record["abandoned"] in ("no_submit", "step_budget")


# -- grading + summary -------------------------------------------------------

class _SuiteDriver:
    """Stands in for McpDriver at suite level (no server process)."""

    def __init__(self, **kwargs):
        self.calls = []

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return False

    async def list_tools(self):
        return [
            {"name": "launch_gdb", "description": "launch",
             "input_schema": {"type": "object"}},
        ]

    async def call(self, tool, arguments=None):
        self.calls.append((tool, arguments))
        if tool == "launch_gdb":
            return {"session_id": "s1"}
        return {"ok": True}

    def latency_report(self):
        return {"total_calls": len(self.calls)}


@pytest.mark.asyncio
async def test_suite_grades_live_state_and_penalizes_overbudget(tmp_path, monkeypatch):
    import bench.framework.agent as agent_mod

    async def fake_run_checks(driver, session_id, task):
        from bench.framework.verifiers import CheckResult

        return [CheckResult(op="session_alive", passed=session_id == "s1", detail="")]

    monkeypatch.setattr(agent_mod, "McpDriver", lambda **kw: _SuiteDriver())
    monkeypatch.setattr(agent_mod, "run_checks", fake_run_checks)

    provider = FakeProvider(
        [
            _turn("launch_gdb", {"program": "/x"}),
            {"tool_calls": [{"id": "c2", "name": SUBMIT_TOOL, "arguments": {}}]},
        ],
        model="fake-model",
    )
    task = _task(max_steps=5)
    summary = await run_agent_suite(
        [task], provider, distro=None, port=0, results_dir=tmp_path
    )
    assert summary["total"] == 1 and summary["passed"] == 1
    assert summary["success_rate"] == 1.0
    assert summary["model"] == "fake-model"
    assert summary["tokens"]["total"] > 0
    # records on disk carry the per-task verdict
    jsonl = next(tmp_path.glob("agent-fake-model-*.jsonl"))
    record = json.loads(jsonl.read_text(encoding="utf-8").splitlines()[0])
    assert record["passed"] is True and record["session_id"] == "s1"


@pytest.mark.asyncio
async def test_suite_fails_task_when_checks_fail(tmp_path, monkeypatch):
    import bench.framework.agent as agent_mod

    async def fake_run_checks(driver, session_id, task):
        from bench.framework.verifiers import CheckResult

        return [CheckResult(op="session_alive", passed=False, detail="dead")]

    monkeypatch.setattr(agent_mod, "McpDriver", lambda **kw: _SuiteDriver())
    monkeypatch.setattr(agent_mod, "run_checks", fake_run_checks)

    provider = FakeProvider(
        [{"tool_calls": [{"id": "c1", "name": SUBMIT_TOOL, "arguments": {}}]}]
    )
    summary = await run_agent_suite(
        [_task(max_steps=5)], provider, distro=None, port=0, results_dir=tmp_path
    )
    assert summary["passed"] == 0
    jsonl = next(tmp_path.glob("agent-fake-model-*.jsonl"))
    record = json.loads(jsonl.read_text(encoding="utf-8").splitlines()[0])
    assert record["error"] == "failed: checks"


def test_summarize_breaks_down_by_family_and_difficulty():
    records = [
        {"family": "crash", "difficulty": "easy", "tags": ["t1"],
         "passed": True, "steps_used": 3, "tool_calls": 4,
         "prompt_tokens": 100, "completion_tokens": 20},
        {"family": "crash", "difficulty": "hard", "tags": ["t2"],
         "passed": False, "steps_used": 9, "tool_calls": 10,
         "prompt_tokens": 200, "completion_tokens": 40},
        {"family": "pie", "difficulty": "easy", "tags": ["t1"],
         "passed": True, "steps_used": 4, "tool_calls": 5,
         "prompt_tokens": 60, "completion_tokens": 10},
    ]
    summary = summarize(records, model="m")
    assert summary["success_rate"] == round(2 / 3, 4)
    assert summary["by_family"]["crash"] == {"n": 2, "rate": 0.5}
    assert summary["by_difficulty"]["easy"] == {"n": 2, "rate": 1.0}
    assert summary["by_tag"]["t1"]["rate"] == 1.0
    assert summary["avg_steps"] == 5.3
    assert summary["tokens"]["total"] == 430
