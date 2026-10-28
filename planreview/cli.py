"""CLI for CI use.  Exit codes: 0 approve, 1 needs_changes, 2 block, 3 error.

terraform show -json tfplan > plan.json
planreview review plan.json --llm none
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
from datetime import date

from .llm import Budget, LLMError, make_llm
from .models import Review, Waiver
from .orchestrator import review_plan
from .plan import PlanError
from .rules import REGISTRY

EXIT = {"approve": 0, "needs_changes": 1, "block": 2}
COLOR = {"critical": "1;31", "high": "31", "medium": "33", "low": "36", "info": "37"}


def render(r: Review, color: bool) -> str:
    def c(code: str, s: str) -> str:
        return f"\033[{code}m{s}\033[0m" if color else s

    head = {"approve": "32", "needs_changes": "33", "block": "1;31"}[r.verdict]
    out = [
        c(head, f"VERDICT: {r.verdict.upper()}"),
        r.summary,
        (
            f"{r.stats.resources} resources ({r.stats.create}+ {r.stats.update}~ "
            f"{r.stats.delete}- {r.stats.replace}±), provider={r.provider}, ${r.cost_usd:.4f}, {r.duration_ms} ms"
        ),
    ]
    for d in r.degraded:
        out.append(c("33", f"! {d}"))
    for f in r.findings:
        tag = c(COLOR[f.severity], f"{f.severity.upper():8}")
        flag = (
            " (waived: " + f.waiver_reason + ")"
            if f.waived
            else " (model)"
            if f.source == "llm"
            else ""
        )
        out.append(f"{tag} {f.id:8} {f.rule:7} {f.address}\n         {f.title}{flag}")
        if f.remediation:
            out.append(f"         fix: {f.remediation}")
        if f.context:
            out.append(f"         note: {f.context}")
    for d in r.dropped:
        out.append(c("2", f"dropped by critic: {d['title']} ({d['reason']})"))
    return "\n".join(out)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="planreview")
    sub = ap.add_subparsers(dest="cmd", required=True)
    rv = sub.add_parser("review", help="review a `terraform show -json` plan")
    rv.add_argument("plan", help="path to plan JSON, or - for stdin")
    rv.add_argument("--llm", default="none", choices=["none", "mock", "vertex", "openai"])
    rv.add_argument("--model")
    rv.add_argument("--waivers", help="JSON file: [{rule, address, reason, expires}]")
    rv.add_argument("--format", default="text", choices=["text", "json"])
    sub.add_parser("rules", help="list the review rules")
    a = ap.parse_args(argv)

    if a.cmd == "rules":
        for r in REGISTRY:
            print(f"{r.id:8} {r.agent:12} {r.description}")
        return 0
    try:
        doc = json.load(sys.stdin if a.plan == "-" else open(a.plan))
        waivers = (
            [Waiver.model_validate(w) for w in json.load(open(a.waivers))] if a.waivers else []
        )
        review = asyncio.run(
            review_plan(
                doc, make_llm(a.llm, a.model), waivers=waivers, budget=Budget(), today=date.today()
            )
        )
    except (OSError, ValueError, PlanError, LLMError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 3
    print(
        review.model_dump_json(indent=2)
        if a.format == "json"
        else render(review, sys.stdout.isatty())
    )
    return EXIT[review.verdict]


if __name__ == "__main__":
    sys.exit(main())
