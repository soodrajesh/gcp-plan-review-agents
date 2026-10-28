"""Review persistence. Only findings and stats are stored, never the plan itself (plans can hold
sensitive values); the plan is identified by its SHA-256."""

from __future__ import annotations

import threading
from datetime import UTC, datetime, timedelta
from typing import Protocol

from .models import Review

TTL_DAYS = 30


class Store(Protocol):
    def save(self, review: Review) -> None: ...
    def get(self, review_id: str) -> Review | None: ...
    def recent(self, limit: int = 20) -> list[Review]: ...
    def spend_today(self) -> float: ...
    def add_spend(self, usd: float) -> float: ...


def _day() -> str:
    return datetime.now(UTC).strftime("%Y%m%d")


class MemoryStore:
    def __init__(self) -> None:
        self._reviews: dict[str, Review] = {}
        self._spend: dict[str, float] = {}
        self._lock = threading.Lock()

    def save(self, review: Review) -> None:
        with self._lock:
            self._reviews[review.id] = review

    def get(self, review_id: str) -> Review | None:
        return self._reviews.get(review_id)

    def recent(self, limit: int = 20) -> list[Review]:
        return sorted(self._reviews.values(), key=lambda r: r.created_at, reverse=True)[:limit]

    def spend_today(self) -> float:
        return self._spend.get(_day(), 0.0)

    def add_spend(self, usd: float) -> float:
        with self._lock:
            self._spend[_day()] = self._spend.get(_day(), 0.0) + usd
            return self._spend[_day()]


class FirestoreStore:
    """reviews/{id} (TTL on expires_at) and meta/spend-YYYYMMDD with an atomic Increment."""

    def __init__(self, project: str, database: str = "(default)") -> None:
        from google.cloud import firestore

        self._fs = firestore
        self._db = firestore.Client(project=project, database=database)

    def save(self, review: Review) -> None:
        data = review.model_dump(mode="json")
        data["expires_at"] = datetime.now(UTC) + timedelta(days=TTL_DAYS)
        self._db.collection("reviews").document(review.id).set(data)

    def get(self, review_id: str) -> Review | None:
        snap = self._db.collection("reviews").document(review_id).get()
        return Review.model_validate(self._clean(snap.to_dict())) if snap.exists else None

    def recent(self, limit: int = 20) -> list[Review]:
        q = (
            self._db.collection("reviews")
            .order_by("created_at", direction=self._fs.Query.DESCENDING)
            .limit(limit)
        )
        return [Review.model_validate(self._clean(d.to_dict())) for d in q.stream()]

    def spend_today(self) -> float:
        snap = self._db.collection("meta").document(f"spend-{_day()}").get()
        return float((snap.to_dict() or {}).get("usd", 0.0)) if snap.exists else 0.0

    def add_spend(self, usd: float) -> float:
        ref = self._db.collection("meta").document(f"spend-{_day()}")
        ref.set(
            {"usd": self._fs.Increment(usd), "expires_at": datetime.now(UTC) + timedelta(days=3)},
            merge=True,
        )
        return float(ref.get().to_dict().get("usd", usd))

    @staticmethod
    def _clean(d: dict | None) -> dict:
        d = dict(d or {})
        d.pop("expires_at", None)
        return d
