"""E3 bench: a quota-frugal LLM agent loop and DeepSeek client.

Design rules (the reason this module stays small):

* The agent loop is pure logic speaking OpenAI-shaped tool-calling
  messages, so it is fully testable against a scripted fake LLM —
  developing the bench costs zero API quota. Real calls happen only
  when a runner script is invoked deliberately.
* The DeepSeek client reads the key from ``DEEPSEEK_API_KEY`` or a
  repo-local ``.env`` (gitignored), never logs it, and redacts it from
  anything passing through :func:`redact`.
* Every runner hard-caps turns and reports token usage — the quota is
  a budget, not an estimate.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from pathlib import Path

API_ENV = "DEEPSEEK_API_KEY"
DEFAULT_BASE_URL = "https://api.deepseek.com"
DEFAULT_MODEL = "deepseek-chat"
MAX_TOOL_OBSERVATION_CHARS = 8000


def redact(text: str, secret: str | None) -> str:
    """Replace the secret in ``text`` with a marker (best effort)."""
    if secret and secret in text:
        return text.replace(secret, "***REDACTED***")
    return text


def load_api_key(
    env: dict[str, str] | None = None, env_file: Path | None = None
) -> str | None:
    """Key lookup order: ``env`` dict (default: process environment),
    then ``KEY=VALUE`` lines in ``env_file`` (default: repo-local
    ``.env``, which is gitignored)."""
    environment = os.environ if env is None else env
    key = environment.get(API_ENV)
    if key:
        return key.strip()
    path = env_file or (Path(__file__).resolve().parents[2] / ".env")
    try:
        text = path.read_text(encoding="utf-8")
    except OSError:
        return None
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith(API_ENV + "="):
            return stripped.split("=", 1)[1].strip()
    return None


def _post_json(
    url: str, headers: dict, payload: dict, timeout: float
) -> dict:
    """Minimal stdlib JSON POST. Seam for tests; keeps the client
    dependency-free so the bench also runs on bare WSL python3."""
    import urllib.request

    request = urllib.request.Request(
        url,
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json", **headers},
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=timeout) as response:
        return json.loads(response.read().decode("utf-8"))


class DeepSeekClient:
    """Thin OpenAI-compatible chat client with tool calling."""

    def __init__(
        self,
        api_key: str | None = None,
        model: str = DEFAULT_MODEL,
        base_url: str = DEFAULT_BASE_URL,
        env_file: Path | None = None,
        max_tokens: int = 1024,
    ):
        self.api_key = api_key or load_api_key(env_file=env_file)
        if not self.api_key:
            raise RuntimeError(
                "DEEPSEEK_API_KEY is not set (environment or repo-local .env)"
            )
        self.model = model
        self.base_url = base_url
        self.max_tokens = max_tokens
        self.total_tokens = 0
        self._tools: list[dict] | None = None

    def bind_tools(self, tools: list[dict]) -> None:
        """Bind OpenAI-format tool schemas (from the next call on)."""
        self._tools = tools or None

    def chat(self, messages: list[dict]) -> dict:
        payload: dict = {
            "model": self.model,
            "messages": messages,
            "max_tokens": self.max_tokens,
        }
        if self._tools:
            payload["tools"] = self._tools
        data = _post_json(
            self.base_url.rstrip("/") + "/chat/completions",
            headers={"Authorization": "Bearer " + self.api_key},
            payload=payload,
            timeout=120.0,
        )
        self.total_tokens += int((data.get("usage") or {}).get("total_tokens") or 0)
        message = data["choices"][0]["message"]
        tool_calls = []
        for call in message.get("tool_calls") or []:
            function = call.get("function") or {}
            raw_arguments = function.get("arguments") or "{}"
            try:
                arguments = json.loads(raw_arguments)
            except ValueError:
                arguments = {"_raw": raw_arguments}
            tool_calls.append(
                {
                    "id": call.get("id") or "call_0",
                    "name": function.get("name"),
                    "arguments": arguments,
                }
            )
        return {"content": message.get("content"), "tool_calls": tool_calls}


@dataclass
class AgentResult:
    solved: bool
    finish: str  # "solved" | "no_tool" | "max_turns"
    turns: int
    tool_calls: int
    messages: list[dict] = field(default_factory=list)
    answer: str | None = None


def run_agent(
    llm,
    tools: dict[str, object],
    task: str,
    system_prompt: str | None = None,
    max_turns: int = 16,
    check_solved=None,
    solved_answer: str | None = None,
) -> AgentResult:
    """Generic tool-calling loop.

    ``tools`` maps tool name -> callable(arguments dict) -> observation
    dict. ``check_solved(tool_name, observation) -> bool`` declares the
    task solved as soon as an observation proves it. Tool errors never
    abort the loop — they go back to the model as observations so it can
    recover. The loop speaks OpenAI-shaped messages; the LLM client owns
    any wire-format differences.
    """
    messages: list[dict] = []
    if system_prompt:
        messages.append({"role": "system", "content": system_prompt})
    messages.append({"role": "user", "content": task})
    tool_call_count = 0
    for turn in range(1, max_turns + 1):
        reply = llm.chat(messages)
        assistant: dict = {"role": "assistant", "content": reply.get("content")}
        calls = reply.get("tool_calls") or []
        if calls:
            assistant["tool_calls"] = [
                {
                    "id": call["id"],
                    "type": "function",
                    "function": {
                        "name": call["name"],
                        "arguments": json.dumps(call.get("arguments") or {}),
                    },
                }
                for call in calls
            ]
        messages.append(assistant)
        if not calls:
            return AgentResult(
                solved=False,
                finish="no_tool",
                turns=turn,
                tool_calls=tool_call_count,
                messages=messages,
                answer=reply.get("content"),
            )
        for index, call in enumerate(calls):
            function = tools.get(call["name"])
            if function is None:
                observation: object = {"error": "unknown tool %r" % call["name"]}
            else:
                try:
                    observation = function(call.get("arguments") or {})
                except Exception as exc:
                    observation = {"error": str(exc)}
            tool_call_count += 1
            messages.append(
                {
                    "role": "tool",
                    "tool_call_id": call.get("id") or "call_%d_%d" % (turn, index),
                    "content": json.dumps(observation, ensure_ascii=False)[
                        :MAX_TOOL_OBSERVATION_CHARS
                    ],
                }
            )
            if check_solved and check_solved(call["name"], observation):
                return AgentResult(
                    solved=True,
                    finish="solved",
                    turns=turn,
                    tool_calls=tool_call_count,
                    messages=messages,
                    answer=solved_answer,
                )
    return AgentResult(
        solved=False,
        finish="max_turns",
        turns=max_turns,
        tool_calls=tool_call_count,
        messages=messages,
    )
