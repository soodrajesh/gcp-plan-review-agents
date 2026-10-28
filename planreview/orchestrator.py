"""Orchestration: triage -> specialists in parallel -> critic -> waivers -> judge -> summary.

plan JSON
   |
[triage]  which agents have something to review
   |
[security] [cost] [reliability] [compliance]     parallel; rules first, then model commentary
   |
[critic]  drop hallucinated / duplicate / link-bearing model output
   |
[waivers] apply expiring, reasoned exceptions
   |
[judge]   verdict = f(rule findings); the model only writes the summary"""

from __future__ import annotations

import asyncio
import time
import uuid
from datetime import date
from typing import Any

from . import plan as planmod
from .agents import AgentResult, run_specialist
from .critic import review_findings
from .judge import decide, summarize
from .llm import LLM, Budget
from .models import AGENTS, Finding, Review, TraceStep, Waiver
from .rules import Policy


async def review_plan(
    doc: Any,
    llm: LLM,
    *,
    policy: Policy | None = None,
    waivers: list[Waiver] | None = None,
    budget: Budget | None = None,
    today: date | None = None,
    llm_timeout: float = 45.0,
) -> Review:
    t0 = time.perf_counter()
    policy, waivers, budget = policy or Policy(), waivers or [], budget or Budget()
    today = today or date.today()
    changes = planmod.parse_plan(doc)  # raises PlanError on garbage; callers map it to a 4xx
    st = planmod.stats(changes)

    trace = [
        TraceStep(
            agent="triage",
            action="parse",
            start_ms=0,
            duration_ms=int((time.perf_counter() - t0) * 1000),
            note=f"{st.resources} changed resources: {st.create} create, {st.update} update, "
            f"{st.delete} delete, {st.replace} replace",
        )
    ]

    results: list[AgentResult] = await asyncio.gather(
        *(run_specialist(a, changes, policy, llm, budget, t0, llm_timeout) for a in AGENTS)
    )
    findings: list[Finding] = []
    degraded: list[str] = []
    for r in results:
        findings += r.findings
        trace += r.steps
        degraded += r.degraded

    c0 = time.perf_counter()
    findings, dropped = review_findings(findings, _scope_notes(results), changes)
    trace.append(
        TraceStep(
            agent="critic",
            action="validate",
            start_ms=int((c0 - t0) * 1000),
            duration_ms=int((time.perf_counter() - c0) * 1000),
            note=f"kept {len(findings)}, dropped {len(dropped)}",
        )
    )

    for f in findings:
        for w in waivers:
            if w.matches(f, today) and f.source == "rule":
                f.waived, f.waiver_reason = True, w.reason
                break

    verdict, reason = decide(findings, degraded)
    j0 = time.perf_counter()
    step = TraceStep(agent="judge", action="summarize", start_ms=int((j0 - t0) * 1000))
    summary = await summarize(verdict, reason, findings, llm, budget, step)
    step.duration_ms = int((time.perf_counter() - j0) * 1000)
    trace.append(step)

    findings.sort(key=lambda f: (-_rank(f), f.agent, f.address))
    return Review(
        id=uuid.uuid4().hex[:12],
        plan_sha256=planmod.plan_sha256(doc),
        provider=llm.name,
        model=llm.model,
        verdict=verdict,
        summary=summary,
        degraded=degraded,
        stats=st,
        findings=findings,
        dropped=dropped,
        trace=trace,
        cost_usd=round(sum(s.cost_usd for s in trace), 6),
        duration_ms=int((time.perf_counter() - t0) * 1000),
    )


def _rank(f: Finding) -> int:
    from .models import SEV_RANK

    return SEV_RANK[f.severity]


def _scope_notes(results: list[AgentResult]) -> dict[str, str]:
    """Finding ids are per agent (SEC-1, COS-1...), so notes from agent A can only target A's ids."""
    merged: dict[str, str] = {}
    for r in results:
        own = {f.id for f in r.findings}
        for fid, ctx in r.notes.items():
            merged[fid if fid in own else f"{r.agent}:{fid}"] = (
                ctx  # foreign id -> unknown -> dropped
            )
    return merged
