"""The critic validates everything the specialists produced before the judge sees it.

It is deterministic on purpose: the point is to catch a model that hallucinates resources,
repeats a rule finding, or smuggles links into text a human will read."""

from __future__ import annotations

import re

from .models import Finding, ResourceChange

URL = re.compile(r"https?://|www\.|\]\(", re.IGNORECASE)
MAX_CONTEXT = 300


def _words(s: str) -> set[str]:
    return set(re.findall(r"[a-z0-9]+", s.lower()))


def _similar(a: str, b: str) -> bool:
    wa, wb = _words(a), _words(b)
    return bool(wa and wb) and len(wa & wb) / len(wa | wb) >= 0.5


def review_findings(
    findings: list[Finding], notes: dict[str, str], changes: list[ResourceChange]
) -> tuple[list[Finding], list[dict[str, str]]]:
    known = {c.address for c in changes}
    kept: list[Finding] = []
    dropped: list[dict[str, str]] = []

    def drop(f: Finding, why: str) -> None:
        dropped.append(
            {"agent": f.agent, "title": f.title[:120], "address": f.address, "reason": why}
        )

    rule_findings = [f for f in findings if f.source == "rule"]
    for f in findings:
        if f.source == "rule":
            kept.append(f)
            continue
        if f.address not in known:
            drop(f, "model cited a resource that is not in the plan")
        elif URL.search(f.title + f.detail + f.remediation):
            drop(f, "model output contained a link")
        elif any(r.address == f.address and _similar(r.title, f.title) for r in rule_findings):
            drop(f, "duplicates an existing rule finding")
        else:
            kept.append(f)

    by_id = {f.id: f for f in kept}
    for fid, ctx in notes.items():
        f = by_id.get(fid)
        if f is None:
            dropped.append(
                {
                    "agent": "-",
                    "title": f"note for {fid}",
                    "address": "",
                    "reason": "note referenced an unknown finding id",
                }
            )
        elif URL.search(ctx):
            dropped.append(
                {
                    "agent": f.agent,
                    "title": f"note for {fid}",
                    "address": f.address,
                    "reason": "model note contained a link",
                }
            )
        else:
            f.context = ctx.strip()[:MAX_CONTEXT]
    return kept, dropped
