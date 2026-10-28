"""HTTP API and the review viewer. Authentication is Cloud Run IAM; the app has none of its own."""

from __future__ import annotations

import json
import logging
import re
from importlib import resources
from pathlib import Path

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel, Field

from . import __version__
from .config import Settings
from .llm import Budget, LLMError, make_llm
from .models import Review, Waiver
from .orchestrator import review_plan
from .plan import PlanError
from .rules import REGISTRY
from .store import FirestoreStore, MemoryStore, Store

SAMPLES = resources.files("planreview") / "samples"


class ReviewRequest(BaseModel):
    plan: dict
    waivers: list[Waiver] = Field(default_factory=list, max_length=50)
    llm: str | None = None  # must be in the server's allow-list


def create_app(settings: Settings | None = None, store: Store | None = None) -> FastAPI:
    cfg = settings or Settings()
    if store is None:
        store = (
            FirestoreStore(cfg.project, cfg.firestore_db)
            if cfg.store == "firestore"
            else MemoryStore()
        )
    app = FastAPI(title="planreview", version=__version__)

    @app.get("/healthz")
    def healthz():
        return {"ok": True, "version": __version__}

    @app.get("/", response_class=HTMLResponse)
    def index():
        return (resources.files("planreview") / "ui.html").read_text()

    @app.get("/api/config")
    def config():
        return {
            "version": __version__,
            "provider": cfg.provider,
            "model": cfg.model,
            "allowed_providers": cfg.allowed_providers,
            "store": cfg.store,
            "daily_budget_usd": cfg.daily_budget_usd,
            "spend_today_usd": round(store.spend_today(), 6),
            "rules": len(REGISTRY),
        }

    @app.get("/api/rules")
    def rules():
        return [{"id": r.id, "agent": r.agent, "description": r.description} for r in REGISTRY]

    @app.get("/api/samples")
    def samples():
        return sorted(p.name.removesuffix(".json") for p in Path(str(SAMPLES)).glob("*.json"))

    @app.get("/api/samples/{name}")
    def sample(name: str):
        f = SAMPLES / f"{name}.json"
        if not re.fullmatch(r"[a-z0-9_]+", name) or not f.is_file():
            raise HTTPException(404, "no such sample")
        return json.loads(f.read_text())

    @app.post("/api/reviews", response_model=Review)
    async def create_review(req: Request):
        raw = await req.body()
        if len(raw) > cfg.max_body_bytes:
            raise HTTPException(413, f"plan larger than {cfg.max_body_bytes} bytes")
        try:
            body = ReviewRequest.model_validate_json(raw)
        except ValueError as e:
            raise HTTPException(422, f"invalid request: {str(e)[:300]}") from e
        provider = body.llm or cfg.provider
        if provider not in cfg.allowed_providers:
            raise HTTPException(
                403, f"provider '{provider}' not allowed here ({', '.join(cfg.allowed_providers)})"
            )
        notes: list[str] = []
        if provider not in ("none", "mock") and store.spend_today() >= cfg.daily_budget_usd:
            provider = "none"
            notes.append(f"daily model budget ${cfg.daily_budget_usd:.2f} reached; rules only")
        try:
            llm = make_llm(provider, cfg.model if provider == cfg.provider else None)
        except LLMError as e:
            raise HTTPException(503, str(e)) from e
        try:
            review = await review_plan(
                body.plan,
                llm,
                waivers=body.waivers,
                budget=Budget(cfg.max_llm_calls, cfg.review_budget_usd),
            )
        except PlanError as e:
            raise HTTPException(422, str(e)) from e
        review.degraded = notes + review.degraded
        store.add_spend(review.cost_usd)
        store.save(review)
        return review

    @app.get("/api/reviews", response_model=list[Review])
    def list_reviews(limit: int = 20):
        return store.recent(max(1, min(limit, 100)))

    @app.get("/api/reviews/{review_id}", response_model=Review)
    def get_review(review_id: str):
        r = store.get(review_id)
        if r is None:
            raise HTTPException(404, "no such review")
        return r

    @app.exception_handler(Exception)
    async def unhandled(_: Request, exc: Exception):
        logging.getLogger("planreview").exception("unhandled error", exc_info=exc)
        return JSONResponse({"detail": "internal error"}, status_code=500)

    return app


def app_factory() -> FastAPI:  # uvicorn --factory planreview.api:app_factory
    return create_app()
