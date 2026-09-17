"""Tests for the E3 bench agent loop and DeepSeek client (no network)."""

import pytest

from gdb_mcp.bench import (
    DeepSeekClient,
    load_api_key,
    redact,
    run_agent,
)


class FakeLLM:
    """Scripted replies; each reply is consumed once."""

    def __init__(self, replies):
        self.replies = list(replies)
        self.seen_messages = []
        self.total_tokens = 0

    def chat(self, messages):
        self.seen_messages.append([dict(m) for m in messages])
        return self.replies.pop(0)


class TestRunAgent:
    def test_solves_when_check_passes(self):
        llm = FakeLLM([
            {"content": None, "tool_calls": [
                {"id": "c1", "name": "run_payload",
                 "arguments": {"payload": "AAAA"}}
            ]},
        ])
        observations = []

        def run_payload(args):
            observation = {"output": "WIN{ok}", "win": True}
            observations.append(observation)
            return observation

        result = run_agent(
            llm,
            {"run_payload": run_payload},
            task="solve it",
            max_turns=5,
            check_solved=lambda name, obs: bool(obs.get("win")),
        )
        assert result.solved is True
        assert result.finish == "solved"
        assert result.turns == 1
        assert result.tool_calls == 1
        assert observations and observations[0]["output"] == "WIN{ok}"

    def test_max_turns_stops(self):
        replies = [
            {"content": None, "tool_calls": [
                {"id": "c%d" % i, "name": "probe", "arguments": {}}
            ]}
            for i in range(10)
        ]

        class LLM(FakeLLM):
            def chat(self, messages):
                self.seen_messages.append(messages)
                return self.replies.pop(0)

        llm = LLM(replies)
        result = run_agent(
            llm, {"probe": lambda a: {"ok": True}}, task="x", max_turns=3,
        )
        assert result.solved is False
        assert result.finish == "max_turns"
        assert result.turns == 3
        assert result.tool_calls == 3

    def test_tool_error_goes_back_to_model(self):
        reply_fail = {"content": None, "tool_calls": [
            {"id": "c1", "name": "boom", "arguments": {}}
        ]}
        reply_give_up = {"content": "I cannot proceed", "tool_calls": []}

        class LLM(FakeLLM):
            def chat(self, messages):
                self.seen_messages.append(messages)
                return self.replies.pop(0)

        llm = LLM([reply_fail, reply_give_up])

        def boom(_args):
            raise RuntimeError("kaput")

        result = run_agent(llm, {"boom": boom}, task="x", max_turns=3)
        assert result.finish == "no_tool"
        assert result.answer == "I cannot proceed"
        # the failure was surfaced to the model as an observation
        second_turn_tools = [
            m for m in llm.seen_messages[1] if m["role"] == "tool"
        ]
        assert "kaput" in second_turn_tools[0]["content"]

    def test_unknown_tool_reported(self):
        reply = {"content": None, "tool_calls": [
            {"id": "c1", "name": "no_such_tool", "arguments": {}}
        ]}
        done = {"content": "done", "tool_calls": []}

        class LLM(FakeLLM):
            def chat(self, messages):
                self.seen_messages.append(messages)
                return self.replies.pop(0)

        llm = LLM([reply, done])
        result = run_agent(llm, {}, task="x", max_turns=3)
        tool_message = [m for m in llm.seen_messages[1] if m["role"] == "tool"]
        assert "unknown tool" in tool_message[0]["content"]
        assert result.finish == "no_tool"


class TestDeepSeekClient:
    def test_missing_key_raises(self, tmp_path, monkeypatch):
        monkeypatch.delenv("DEEPSEEK_API_KEY", raising=False)
        with pytest.raises(RuntimeError):
            DeepSeekClient(env_file=tmp_path / "missing.env")

    def test_key_from_env_file(self, tmp_path):
        env_file = tmp_path / ".env"
        env_file.write_text("DEEPSEEK_API_KEY=sk-test-123\n", encoding="utf-8")
        client = DeepSeekClient(env_file=env_file)
        assert client.api_key == "sk-test-123"

    def test_chat_accounts_usage_and_parses_tools(self, tmp_path, monkeypatch):
        captured = {}

        def fake_post(url, headers=None, json=None, timeout=None):
            captured["url"] = url
            captured["auth"] = headers["Authorization"]
            captured["payload"] = json

            class Response:
                def raise_for_status(self):
                    pass

                def json(self):
                    return {
                        "choices": [{"message": {
                            "content": None,
                            "tool_calls": [{"id": "call_1", "function": {
                                "name": "run_payload",
                                "arguments": "{\"payload\": \"AA\"}",
                            }}],
                        }}],
                        "usage": {"total_tokens": 321},
                    }

            return Response()

        import httpx

        monkeypatch.setattr(httpx, "post", fake_post)
        env_file = tmp_path / ".env"
        env_file.write_text("DEEPSEEK_API_KEY=sk-secret\n", encoding="utf-8")
        client = DeepSeekClient(env_file=env_file)
        client.bind_tools([{"type": "function", "function": {"name": "x"}}])
        reply = client.chat([{"role": "user", "content": "go"}])
        assert reply["tool_calls"][0]["name"] == "run_payload"
        assert reply["tool_calls"][0]["arguments"] == {"payload": "AA"}
        assert client.total_tokens == 321
        assert captured["auth"] == "Bearer sk-secret"
        assert captured["url"] == "https://api.deepseek.com/chat/completions"
        assert captured["payload"]["tools"]

    def test_redact(self):
        assert redact("key is sk-abc here", "sk-abc") == "key is ***REDACTED*** here"
        assert redact("nothing", None) == "nothing"


class TestLoadApiKey:
    def test_env_dict_priority(self, tmp_path):
        env_file = tmp_path / ".env"
        env_file.write_text("DEEPSEEK_API_KEY=sk-from-file\n", encoding="utf-8")
        key = load_api_key(
            env={"DEEPSEEK_API_KEY": "sk-from-env"}, env_file=env_file
        )
        assert key == "sk-from-env"

    def test_env_file_fallback(self, tmp_path):
        env_file = tmp_path / ".env"
        env_file.write_text(
            "# comment\nDEEPSEEK_API_KEY=sk-from-file\n", encoding="utf-8"
        )
        assert load_api_key(env={}, env_file=env_file) == "sk-from-file"

    def test_missing_everywhere(self, tmp_path):
        assert load_api_key(env={}, env_file=tmp_path / "nope.env") is None
