"""Shared data model. Everything an agent produces is one of these, so the critic and judge can
validate it without knowing which agent (or which model) it came from."""

from __future__ import annotations

from datetime import UTC, date, datetime
from typing import Any, Literal

from pydantic import BaseModel, Field

Severity = Literal["info", "low", "medium", "high", "critical"]
SEV_RANK: dict[str, int] = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
Verdict = Literal["approve", "needs_changes", "block"]
AgentName = Literal["security", "cost", "reliability", "compliance"]
AGENTS: tuple[AgentName, ...] = ("security", "cost", "reliability", "compliance")


def now_iso() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds")


class ResourceChange(BaseModel):
    address: str
    type: str
    name: str
    actions: list[str]
    before: dict[str, Any] | None = None
    after: dict[str, Any] | None = None

    @property
    def is_delete(self) -> bool:
        return "delete" in self.actions

    @property
    def removed(self) -> bool:
        """Destroyed with nothing taking its place; a replaced resource still has a new config to check."""
        return "delete" in self.actions and "create" not in self.actions

    @property
    def is_replace(self) -> bool:
        return "delete" in self.actions and "create" in self.actions

    @property
    def is_create(self) -> bool:
        return self.actions == ["create"]


class Finding(BaseModel):
    id: str = ""
    agent: AgentName
    rule: str
    severity: Severity
    address: str
    title: str
    detail: str = ""
    remediation: str = ""
    source: Literal["rule", "llm"] = "rule"
    context: str = (
        ""  # model-written explanation attached to a rule finding (never changes severity)
    )
    waived: bool = False
    waiver_reason: str = ""


class Waiver(BaseModel):
    rule: str
    address: str = "*"  # exact address, a prefix ending in '*', or '*'
    reason: str
    expires: date | None = None

    def matches(self, f: Finding, today: date) -> bool:
        if self.expires and self.expires < today:
            return False
        if self.rule != f.rule:
            return False
        if self.address == "*":
            return True
        if self.address.endswith("*"):
            return f.address.startswith(self.address[:-1])
        return self.address == f.address


class TraceStep(BaseModel):
    agent: str
    action: str
    status: Literal["ok", "skipped", "error"] = "ok"
    start_ms: int = 0
    duration_ms: int = 0
    tokens_in: int = 0
    tokens_out: int = 0
    cost_usd: float = 0.0
    note: str = ""


class PlanStats(BaseModel):
    resources: int = 0
    create: int = 0
    update: int = 0
    delete: int = 0
    replace: int = 0
    types: dict[str, int] = Field(default_factory=dict)


class Review(BaseModel):
    id: str
    created_at: str = Field(default_factory=now_iso)
    plan_sha256: str
    provider: str
    model: str
    verdict: Verdict
    summary: str
    degraded: list[str] = Field(
        default_factory=list
    )  # reasons the review ran with less than full coverage
    stats: PlanStats
    findings: list[Finding] = Field(default_factory=list)
    dropped: list[dict[str, str]] = Field(
        default_factory=list
    )  # findings the critic rejected, with why
    trace: list[TraceStep] = Field(default_factory=list)
    cost_usd: float = 0.0
    duration_ms: int = 0

    def active(self) -> list[Finding]:
        return [f for f in self.findings if not f.waived]
