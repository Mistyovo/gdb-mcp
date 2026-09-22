"""Versioned task schema for the gdb-mcp acceptance benchmark.

A task manifest is fully self-describing: the C source, build flags, prompt,
step budget and ground-truth checks all live in one JSON file. Generation is
seeded and deterministic — regenerating a family with the same seeds produces
byte-identical manifests, which is what makes the benchmark reproducible and
the hidden set truly held-out (different seed ranges, same generators).
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

BENCH_VERSION = "1.0.0"
TASK_SCHEMA_VERSION = "1.0.0"

DIFFICULTIES = ("easy", "medium", "hard")
TASK_KINDS = ("state", "fact")


class SchemaError(ValueError):
    """Raised when a task manifest violates the schema."""


@dataclass
class BuildSpec:
    flags: list[str] = field(default_factory=list)
    strip: bool = False
    core: bool = False
    ldflags: list[str] = field(default_factory=list)


@dataclass
class TargetSpec:
    name: str
    source: str
    build: BuildSpec = field(default_factory=BuildSpec)
    binary_sha256: str | None = None  # filled by `bench build`
    symbols: dict[str, str] = field(default_factory=dict)  # name -> hex offset

    def source_sha256(self) -> str:
        return hashlib.sha256(self.source.encode("utf-8")).hexdigest()


@dataclass
class Check:
    op: str
    spec: dict[str, Any] = field(default_factory=dict)


@dataclass
class TaskSpec:
    id: str
    family: str
    kind: str
    difficulty: str
    tags: list[str]
    target: TargetSpec
    params: dict[str, Any]
    prompt: str
    max_steps: int
    checks: list[Check]
    bench_version: str = BENCH_VERSION
    schema_version: str = TASK_SCHEMA_VERSION

    def validate(self) -> None:
        if self.kind not in TASK_KINDS:
            raise SchemaError("%s: kind %r not in %s" % (self.id, self.kind, TASK_KINDS))
        if self.difficulty not in DIFFICULTIES:
            raise SchemaError(
                "%s: difficulty %r not in %s" % (self.id, self.difficulty, DIFFICULTIES)
            )
        if not self.prompt.strip():
            raise SchemaError("%s: empty prompt" % self.id)
        if self.max_steps < 1:
            raise SchemaError("%s: max_steps must be >= 1" % self.id)
        if not self.checks:
            raise SchemaError("%s: task has no ground-truth checks" % self.id)
        known = _known_check_ops()
        for check in self.checks:
            if check.op not in known:
                raise SchemaError(
                    "%s: unknown check op %r (known: %s)"
                    % (self.id, check.op, sorted(known))
                )
            if not isinstance(check.spec, dict):
                raise SchemaError("%s: check %r spec must be an object" % (self.id, check.op))

    def to_json(self) -> str:
        self.validate()
        return json.dumps(asdict(self), indent=2, sort_keys=True) + "\n"

    @classmethod
    def from_json(cls, text: str) -> "TaskSpec":
        raw = json.loads(text)
        try:
            target = TargetSpec(
                name=raw["target"]["name"],
                source=raw["target"]["source"],
                build=BuildSpec(**raw["target"].get("build", {})),
                binary_sha256=raw["target"].get("binary_sha256"),
                symbols=raw["target"].get("symbols", {}),
            )
            task = cls(
                id=raw["id"],
                family=raw["family"],
                kind=raw["kind"],
                difficulty=raw["difficulty"],
                tags=list(raw.get("tags", [])),
                target=target,
                params=raw.get("params", {}),
                prompt=raw["prompt"],
                max_steps=raw["max_steps"],
                checks=[Check(op=c["op"], spec=c.get("spec", {})) for c in raw["checks"]],
                bench_version=raw.get("bench_version", BENCH_VERSION),
                schema_version=raw.get("schema_version", TASK_SCHEMA_VERSION),
            )
        except (KeyError, TypeError) as exc:
            raise SchemaError("malformed task manifest: %s" % exc) from exc
        if task.bench_version != BENCH_VERSION or task.schema_version != TASK_SCHEMA_VERSION:
            raise SchemaError(
                "%s: manifest versions (%s/%s) do not match harness (%s/%s)"
                % (task.id, task.bench_version, task.schema_version,
                   BENCH_VERSION, TASK_SCHEMA_VERSION)
            )
        task.validate()
        return task


_KNOWN_OPS = frozenset(
    {
        "exit_code",
        "breakpoint_present",
        "breakpoint_hit",
        "stop_signal",
        "memory_value",
        "register_value",
        "variable_value",
        "pc_in_range",
        "backtrace_contains",
        "thread_stopped_at",
        "thread_count",
        "fault_addr",
        "session_alive",
    }
)


def _known_check_ops() -> frozenset[str]:
    return _KNOWN_OPS


def manifest_hash(task: TaskSpec) -> str:
    """Stable content hash of a manifest (independent of dict ordering)."""
    return hashlib.sha256(task.to_json().encode("utf-8")).hexdigest()


def write_task(out_dir: Path, task: TaskSpec) -> Path:
    out_dir = out_dir / task.family
    out_dir.mkdir(parents=True, exist_ok=True)
    path = out_dir / ("%s.json" % task.id)
    path.write_text(task.to_json(), encoding="utf-8")
    return path


def load_tasks(tasks_dir: Path) -> list[TaskSpec]:
    paths = [p for p in sorted(tasks_dir.rglob("*.json")) if p.name != "index.json"]
    tasks = [TaskSpec.from_json(p.read_text(encoding="utf-8")) for p in paths]
    ids = [t.id for t in tasks]
    if len(ids) != len(set(ids)):
        dupes = sorted({i for i in ids if ids.count(i) > 1})
        raise SchemaError("duplicate task ids: %s" % dupes)
    return tasks


def index_hash(tasks: list[TaskSpec]) -> str:
    """Hash over sorted per-task manifest hashes: the benchmark's identity."""
    payload = json.dumps(
        {t.id: manifest_hash(t) for t in sorted(tasks, key=lambda t: t.id)},
        sort_keys=True,
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()
