"""Runtime settings, read from the environment once at startup."""

from __future__ import annotations

import os
from dataclasses import dataclass, field


def _f(name: str, default: float) -> float:
    return float(os.environ.get(name, default))


@dataclass
class Settings:
    provider: str = field(default_factory=lambda: os.environ.get("PLANREVIEW_LLM", "mock"))
    model: str | None = field(default_factory=lambda: os.environ.get("PLANREVIEW_MODEL") or None)
    allowed_providers: tuple[str, ...] = field(
        default_factory=lambda: tuple(
            os.environ.get("PLANREVIEW_ALLOWED_PROVIDERS", "mock,none").split(",")
        )
    )
    store: str = field(default_factory=lambda: os.environ.get("PLANREVIEW_STORE", "memory"))
    project: str | None = field(default_factory=lambda: os.environ.get("GOOGLE_CLOUD_PROJECT"))
    firestore_db: str = field(
        default_factory=lambda: os.environ.get("PLANREVIEW_FIRESTORE_DB", "(default)")
    )
    daily_budget_usd: float = field(default_factory=lambda: _f("PLANREVIEW_DAILY_BUDGET_USD", 1.0))
    review_budget_usd: float = field(
        default_factory=lambda: _f("PLANREVIEW_REVIEW_BUDGET_USD", 0.05)
    )
    max_llm_calls: int = field(default_factory=lambda: int(_f("PLANREVIEW_MAX_LLM_CALLS", 6)))
    max_body_bytes: int = 5_000_000
