# Architecture

**Input**: `terraform show -json` plan. `plan.py` keeps managed resources whose actions are not
no-op/read and rejects malformed or >2000-resource plans (HTTP 422 / CLI exit 3).

**Triage**: each agent has a relevance predicate over resource types. An agent with nothing to review
is skipped, with no model call, and shows as `skipped` in the trace.

**Specialists** (`agents.py`), run with `asyncio.gather`:
1. Run that agent's rules over its resources (synchronous, cannot be delayed by the model).
2. One model call, `temperature 0`, JSON only, with a secret-free scalar view of at most 25 resources
   (keys matching pass/secret/key/token/credential/private are dropped; strings cut to 120 chars).
3. Reply is parsed with pydantic. Extras are clamped to severity <= medium and tagged `source=llm`.

**Critic** (`critic.py`) drops model output that cites an address not in the plan, repeats a rule
finding (title similarity on the same address), contains a link, or notes a finding id the agent never
issued. Every drop is returned in `dropped` with a reason.

**Judge** (`judge.py`): `block` if any active rule finding is critical; `needs_changes` if any high, or
3+ medium, or a rule set failed; else `approve`. Waived and model findings are excluded. The summary is
model-written but guarded (<=700 chars, no links) with a template fallback.

**Persistence**: only findings, stats and the plan SHA-256 are stored (never the plan). Firestore:
`reviews/{id}` (30-day TTL) and `meta/spend-YYYYMMDD` (atomic Increment) for the daily cap.

**Trace**: every step has start/duration, tokens and estimated cost; the UI draws it as a timeline.
