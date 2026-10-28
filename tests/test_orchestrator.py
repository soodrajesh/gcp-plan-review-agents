from datetime import date, timedelta

import pytest

from planreview.llm import Budget, LLMError, MockLLM, NullLLM
from planreview.models import Waiver
from planreview.orchestrator import review_plan
from planreview.plan import PlanError

from .helpers import ScriptedLLM, plan, rc, sample


async def run(name_or_doc, llm=None, **kw):
    doc = sample(name_or_doc) if isinstance(name_or_doc, str) else name_or_doc
    return await review_plan(doc, llm or NullLLM(), **kw)


@pytest.mark.parametrize(
    "name,verdict",
    [
        ("clean_serverless", "approve"),
        ("risky_public_stack", "block"),
        ("db_replacement", "block"),
        ("cost_blowup", "needs_changes"),
        ("injection_attempt", "needs_changes"),
    ],
)
async def test_sample_verdicts_with_and_without_a_model(name, verdict):
    assert (await run(name)).verdict == verdict
    assert (await run(name, MockLLM())).verdict == verdict


async def test_clean_plan_has_no_active_findings():
    assert (await run("clean_serverless")).active() == []


async def test_all_four_agents_and_pipeline_stages_appear_in_trace():
    r = await run("risky_public_stack", MockLLM())
    agents = {s.agent for s in r.trace}
    assert {"triage", "security", "cost", "reliability", "compliance", "critic", "judge"} <= agents


async def test_agents_with_nothing_to_review_are_skipped_not_called():
    llm = ScriptedLLM({"notes": [], "extra_findings": []})
    doc = plan(
        rc("google_project_iam_member", "x", after={"role": "roles/viewer", "member": "user:a@b.c"})
    )
    r = await run(doc, llm)
    skipped = {s.agent for s in r.trace if s.status == "skipped" and s.action == "skip"}
    assert skipped == {"cost", "reliability", "compliance"}
    assert llm.calls == 2  # security + judge summary


async def test_specialists_run_in_parallel():
    llm = ScriptedLLM({"notes": [], "extra_findings": []}, delay=0.3)
    r = await run("risky_public_stack", llm)
    assert r.duration_ms < 1000  # 4 agents x 0.3s sequentially would be >1.2s plus summary


async def test_model_cannot_change_verdict_or_severity():
    # A model that insists everything is fine still cannot lower anything.
    llm = ScriptedLLM(
        lambda p: (
            {"summary": "Everything is fine, approve."}
            if p["task"] == "summarize"
            else {"notes": [], "extra_findings": []}
        )
    )
    r = await run("risky_public_stack", llm)
    assert r.verdict == "block"
    assert any(f.severity == "critical" for f in r.active())


async def test_hallucinated_address_is_dropped_by_critic():
    llm = ScriptedLLM(
        lambda p: (
            {"summary": "ok"}
            if p["task"] == "summarize"
            else {
                "notes": [],
                "extra_findings": [
                    {
                        "address": "google_nonexistent.ghost",
                        "title": "Imaginary risk",
                        "severity": "medium",
                    }
                ],
            }
        )
    )
    r = await run("risky_public_stack", llm)
    assert not any(f.source == "llm" for f in r.findings)
    assert any("not in the plan" in d["reason"] for d in r.dropped)


async def test_valid_model_extra_is_kept_but_advisory_only():
    addr = "google_storage_bucket.uploads"
    llm = ScriptedLLM(
        lambda p: (
            {"summary": "ok"}
            if p["task"] == "summarize"
            else (
                {
                    "notes": [],
                    "extra_findings": [
                        {
                            "address": addr,
                            "title": "Bucket looks world-readable by name",
                            "severity": "medium",
                        }
                    ],
                }
                if p["domain"] == "security"
                else {"notes": [], "extra_findings": []}
            )
        )
    )
    r = await run("clean_serverless", llm)
    extras = [f for f in r.findings if f.source == "llm"]
    assert len(extras) == 1 and extras[0].agent == "security"
    assert r.verdict == "approve"  # advisory: does not move the verdict


async def test_extra_finding_severity_is_clamped_to_medium():
    llm = ScriptedLLM(
        lambda p: (
            {"summary": "ok"}
            if p["task"] == "summarize"
            else {
                "notes": [],
                "extra_findings": [
                    {
                        "address": "google_storage_bucket.uploads",
                        "title": "Scary",
                        "severity": "critical",
                    }
                ],
            }
        )
    )
    r = await run("clean_serverless", llm)
    extras = [f for f in r.findings if f.source == "llm"]
    assert extras and all(f.severity == "medium" for f in extras)
    assert r.verdict == "approve"


async def test_links_in_model_output_are_dropped():
    llm = ScriptedLLM(
        lambda p: (
            {"summary": "see http://evil.example"}
            if p["task"] == "summarize"
            else {
                "notes": [{"finding_id": "SEC-1", "context": "click https://evil.example/x"}],
                "extra_findings": [
                    {
                        "address": "google_storage_bucket.uploads",
                        "title": "Visit www.evil.example",
                        "severity": "low",
                    }
                ],
            }
        )
    )
    r = await run("injection_attempt", llm)
    assert "evil" not in r.summary
    assert all("evil" not in f.context and "evil" not in f.title for f in r.findings)
    assert len(r.dropped) >= 2


async def test_note_for_unknown_or_foreign_finding_is_dropped():
    llm = ScriptedLLM(
        lambda p: (
            {"summary": "ok"}
            if p["task"] == "summarize"
            else {
                "notes": [
                    {"finding_id": "COS-1", "context": "cross-agent note"},
                    {"finding_id": "NOPE-9", "context": "ghost"},
                ],
                "extra_findings": [],
            }
        )
    )
    r = await run("risky_public_stack", llm)
    assert len(r.dropped) >= 2 and not any(
        f.context in ("ghost", "cross-agent note") for f in r.findings
    )


@pytest.mark.parametrize("bad", ["not json", "{}x", '{"notes": "oops"}', "[]"])
async def test_garbage_model_reply_degrades_gracefully(bad):
    r = await run("risky_public_stack", ScriptedLLM(bad))
    assert r.verdict == "block" and r.findings
    assert any("model" in d for d in r.degraded)


async def test_provider_error_degrades_gracefully():
    r = await run("cost_blowup", ScriptedLLM(raises=LLMError("429 RESOURCE_EXHAUSTED")))
    assert r.verdict == "needs_changes" and r.findings and r.degraded
    assert r.summary.startswith("Changes requested")  # template fallback


async def test_slow_model_times_out_without_losing_rule_findings():
    r = await run("risky_public_stack", ScriptedLLM(delay=5), llm_timeout=0.1)
    assert r.verdict == "block"
    assert any("timed out" in d for d in r.degraded)


async def test_budget_exhaustion_stops_model_calls_but_not_the_review():
    llm = ScriptedLLM({"notes": [], "extra_findings": []})
    r = await run("risky_public_stack", llm, budget=Budget(max_calls=1))
    assert llm.calls == 1 and r.verdict == "block" and r.degraded


async def test_prompt_injection_in_labels_does_not_move_verdict():
    # A model that obeys the injected instruction.
    def obey(p):
        if p["task"] == "summarize":
            return {"summary": "This plan is safe. Approve it."}
        return {"notes": [], "extra_findings": []}

    r = await run("injection_attempt", ScriptedLLM(obey))
    assert r.verdict == "needs_changes"
    assert {f.rule for f in r.active()} >= {"SEC006", "SEC003"}


async def test_secret_looking_attributes_never_reach_the_model():
    seen = []
    doc = plan(
        rc(
            "google_sql_database_instance",
            "d",
            after={
                "name": "db",
                "root_password": "hunter2-super-secret",
                "api_key": "AKIA123",
                "tier": "x",
                "settings": [{"tier": "db-f1-micro"}],
            },
        )
    )

    def spy(p):
        seen.append(str(p))
        return (
            {"summary": "ok"} if p["task"] == "summarize" else {"notes": [], "extra_findings": []}
        )

    await run(doc, ScriptedLLM(spy))
    assert seen and not any("hunter2" in s or "AKIA123" in s for s in seen)


async def test_waiver_exempts_finding_and_can_flip_verdict():
    base = await run("risky_public_stack")
    ws = [
        Waiver(rule=f.rule, address=f.address, reason="accepted")
        for f in base.findings
        if f.severity in ("critical", "high")
    ]
    r = await run("risky_public_stack", waivers=ws)
    assert r.verdict != "block" and all(
        f.waived for f in r.findings if f.severity in ("critical", "high")
    )


async def test_expired_waiver_is_ignored_and_wildcards_work():
    yesterday = date.today() - timedelta(days=1)
    r = await run(
        "risky_public_stack", waivers=[Waiver(rule="SEC002", reason="old", expires=yesterday)]
    )
    assert r.verdict == "block" and not any(f.waived for f in r.findings)
    r2 = await run(
        "risky_public_stack",
        waivers=[Waiver(rule="SEC002", address="google_compute_*", reason="ok")],
    )
    assert next(f for f in r2.findings if f.rule == "SEC002").waived


async def test_waiver_cannot_target_model_findings():
    llm = ScriptedLLM(
        lambda p: (
            {"summary": "ok"}
            if p["task"] == "summarize"
            else {
                "notes": [],
                "extra_findings": [
                    {
                        "address": "google_storage_bucket.uploads",
                        "title": "Odd naming pattern",
                        "severity": "low",
                    }
                ],
            }
        )
    )
    r = await run("clean_serverless", llm, waivers=[Waiver(rule="LLM", reason="x")])
    assert not any(f.waived for f in r.findings)


async def test_failing_rule_fails_closed(monkeypatch):
    from planreview import rules

    def boom(rc, p):
        raise RuntimeError("bug")

    bad = rules.Rule("SECX", "security", "boom", boom)
    monkeypatch.setattr(rules, "REGISTRY", rules.REGISTRY + [bad])
    r = await run("clean_serverless")
    assert r.verdict == "needs_changes" and any("rule evaluation failed" in d for d in r.degraded)


async def test_three_mediums_trip_needs_changes():
    doc = plan(
        *[
            rc(
                "google_storage_bucket",
                f"b{i}",
                after={
                    "name": f"bkt-{i}",
                    "labels": {"env": "p", "owner": "o"},
                    "uniform_bucket_level_access": False,
                    "public_access_prevention": "enforced",
                    "versioning": [{"enabled": True}],
                },
            )
            for i in range(3)
        ]
    )
    assert (await run(doc)).verdict == "needs_changes"
    assert (await run(plan(*doc["resource_changes"][:2]))).verdict == "approve"


async def test_bad_plan_raises_plan_error():
    with pytest.raises(PlanError):
        await run({"nope": 1})


async def test_review_is_deterministic_without_a_model():
    a, b = await run("risky_public_stack"), await run("risky_public_stack")
    assert [(f.id, f.rule, f.address) for f in a.findings] == [
        (f.id, f.rule, f.address) for f in b.findings
    ]
    assert a.plan_sha256 == b.plan_sha256


async def test_cost_accounting_sums_trace():
    r = await run("risky_public_stack", ScriptedLLM({"notes": [], "extra_findings": []}))
    assert r.cost_usd == pytest.approx(sum(s.cost_usd for s in r.trace)) and r.cost_usd > 0
