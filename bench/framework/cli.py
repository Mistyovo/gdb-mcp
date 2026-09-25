"""CLI for the gdb-mcp acceptance benchmark.

    python -m bench.framework.cli generate --per-family 6
    python -m bench.framework.cli build --distro kali-linux
    python -m bench.framework.cli selfcheck --distro kali-linux --port 39690
    python -m bench.framework.cli report --results <summary.json> [--gate baseline.json]
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))

from bench.framework import agent as agent_mod  # noqa: E402
from bench.framework import build as build_mod  # noqa: E402
from bench.framework import selfcheck as selfcheck_mod  # noqa: E402
from bench.framework.agent import OpenAICompatProvider, load_env_file  # noqa: E402
from bench.framework.generators import FAMILY_MODULES  # noqa: E402
from bench.framework.schema import index_hash, load_tasks, write_task  # noqa: E402

TASKS_DIR = ROOT / "bench" / "tasks"
RESULTS_DIR = ROOT / "bench" / "results"

# Tier-1 metrics for the CI regression gate (goal §9): a drop of more than
# one percentage point in any of these fails the run.
TIER1_KEYS = ("success_rate",)


def cmd_generate(args) -> int:
    count = 0
    for family in args.families:
        module = FAMILY_MODULES[family]
        for offset in range(args.per_family):
            seed = args.seed_base + offset
            write_task(TASKS_DIR, module.generate(seed))
            count += 1
    tasks = load_tasks(TASKS_DIR)
    index = {
        "bench_version": "1.0.0",
        "task_count": len(tasks),
        "families": sorted({t.family for t in tasks}),
        "index_hash": index_hash(tasks),
    }
    (TASKS_DIR / "index.json").write_text(
        json.dumps(index, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    print("generated %d task(s) this run; %d total, index_hash=%s"
          % (count, len(tasks), index["index_hash"][:16]))
    return 0


def cmd_build(args) -> int:
    tasks = load_tasks(TASKS_DIR)
    records = build_mod.build_all(tasks, args.distro, force=args.force)
    for task in tasks:  # write back pinned manifests
        write_task(TASKS_DIR, task)
    print("built %d target(s)" % len(records))
    for name, record in sorted(records.items()):
        notes = (" | " + "; ".join(record.warnings)) if record.warnings else ""
        print("  %-24s %s%s" % (name, record.binary_sha256[:12], notes))
    tasks = load_tasks(TASKS_DIR)
    print("index_hash=%s" % index_hash(tasks)[:16])
    return 0


def cmd_selfcheck(args) -> int:
    tasks = load_tasks(TASKS_DIR)
    if args.filter:
        tasks = [t for t in tasks if args.filter in t.family or args.filter in t.id]
    if not tasks:
        print("no tasks matched; run `generate` first", file=sys.stderr)
        return 2
    summary = asyncio.run(
        selfcheck_mod.run_selfcheck(
            tasks, distro=args.distro, port=args.port,
            results_dir=RESULTS_DIR, label=args.label,
        )
    )
    print("success_rate=%s (%d/%d)" % (
        summary["success_rate"], summary["passed"], summary["total"]))
    return 0 if summary["passed"] == summary["total"] else 1


def cmd_agent(args) -> int:
    env = dict(load_env_file(ROOT / ".env"))
    env.update(os.environ)
    api_key = env.get(args.api_key_env, "")
    if not api_key:
        print(
            "no API key: set --api-key-env (default %s) in the environment "
            "or in the repo-root .env" % args.api_key_env,
            file=sys.stderr,
        )
        return 2
    tasks = load_tasks(TASKS_DIR)
    if args.filter:
        tasks = [t for t in tasks if args.filter in t.family or args.filter in t.id]
    if args.limit:
        tasks = tasks[: args.limit]
    if not tasks:
        print("no tasks matched; run `generate` first", file=sys.stderr)
        return 2
    provider = OpenAICompatProvider(
        model=args.model,
        api_key=api_key,
        base_url=args.base_url,
        max_tokens=args.max_tokens,
        temperature=args.temperature,
    )
    summary = asyncio.run(
        agent_mod.run_agent_suite(
            tasks, provider, distro=args.distro, port=args.port,
            results_dir=RESULTS_DIR, label="agent",
        )
    )
    print("success_rate=%s (%d/%d) tokens=%s" % (
        summary["success_rate"], summary["passed"], summary["total"],
        summary["tokens"]["total"],
    ))
    return 0 if summary["passed"] == summary["total"] else 1


def cmd_report(args) -> int:
    summary = json.loads(Path(args.results).read_text(encoding="utf-8"))
    print(json.dumps(summary, indent=2, sort_keys=True))
    if not args.gate:
        return 0
    baseline = json.loads(Path(args.gate).read_text(encoding="utf-8"))
    failures = []
    for key in TIER1_KEYS:
        base = baseline.get(key)
        now = summary.get(key)
        if base is None or now is None:
            failures.append("%s missing (baseline=%r now=%r)" % (key, base, now))
        elif base - now > 0.01:
            failures.append("%s dropped %.4f -> %.4f (>1pp)" % (key, base, now))
    if failures:
        print("GATE FAILED:\n  " + "\n  ".join(failures), file=sys.stderr)
        return 1
    print("gate passed (tier-1 metrics within 1pp of baseline)")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(prog="bench")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("generate", help="generate task manifests (deterministic)")
    p.add_argument("--per-family", type=int, default=6)
    p.add_argument("--seed-base", type=int, default=1)
    p.add_argument("--families", nargs="*", default=sorted(FAMILY_MODULES))
    p.set_defaults(func=cmd_generate)

    p = sub.add_parser("build", help="compile targets in WSL, pin build evidence")
    p.add_argument("--distro", default="kali-linux")
    p.add_argument("--force", action="store_true")
    p.set_defaults(func=cmd_build)

    p = sub.add_parser("selfcheck", help="reference-solve + grade every task")
    p.add_argument("--distro", default="kali-linux")
    p.add_argument("--port", type=int, default=39690)
    p.add_argument("--filter", default=None, help="substring match on family or id")
    p.add_argument("--label", default="selfcheck")
    p.set_defaults(func=cmd_selfcheck)

    p = sub.add_parser("agent", help="run a model agent over tasks and grade")
    p.add_argument("--model", default="deepseek-chat")
    p.add_argument("--base-url", default="https://api.deepseek.com")
    p.add_argument("--api-key-env", default="DEEPSEEK_API_KEY")
    p.add_argument("--distro", default="kali-linux")
    p.add_argument("--port", type=int, default=39691)
    p.add_argument("--filter", default=None, help="substring match on family or id")
    p.add_argument("--limit", type=int, default=None, help="first N tasks after filter")
    p.add_argument("--max-tokens", type=int, default=2048)
    p.add_argument("--temperature", type=float, default=0.0)
    p.set_defaults(func=cmd_agent)

    p = sub.add_parser("report", help="print a results summary; optional CI gate")
    p.add_argument("--results", required=True)
    p.add_argument("--gate", default=None, help="baseline summary JSON to compare")
    p.set_defaults(func=cmd_report)

    args = parser.parse_args()
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
