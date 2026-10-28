"""Parse `terraform show -json <planfile>` output into the resource changes the agents review."""

from __future__ import annotations

import hashlib
import json
from typing import Any

from .models import PlanStats, ResourceChange

MAX_RESOURCES = 2000


class PlanError(ValueError):
    """The input is not a usable Terraform JSON plan."""


def plan_sha256(doc: dict[str, Any]) -> str:
    return hashlib.sha256(json.dumps(doc, sort_keys=True, default=str).encode()).hexdigest()


def parse_plan(doc: Any) -> list[ResourceChange]:
    if not isinstance(doc, dict) or not isinstance(doc.get("resource_changes"), list):
        raise PlanError(
            "not a Terraform JSON plan: missing 'resource_changes' (use `terraform show -json`)"
        )
    changes: list[ResourceChange] = []
    for i, rc in enumerate(doc["resource_changes"]):
        try:
            change = rc["change"]
            actions = list(change["actions"])
            if actions in (["no-op"], ["read"]):
                continue
            if rc.get("mode", "managed") != "managed":
                continue
            changes.append(
                ResourceChange(
                    address=rc["address"],
                    type=rc["type"],
                    name=rc.get("name", rc["address"]),
                    actions=actions,
                    before=change.get("before"),
                    after=change.get("after"),
                )
            )
        except (KeyError, TypeError) as e:
            raise PlanError(f"resource_changes[{i}] is malformed: missing {e}") from e
        if len(changes) > MAX_RESOURCES:
            raise PlanError(f"plan has more than {MAX_RESOURCES} changed resources")
    return changes


def stats(changes: list[ResourceChange]) -> PlanStats:
    s = PlanStats(resources=len(changes))
    for c in changes:
        s.types[c.type] = s.types.get(c.type, 0) + 1
        if c.is_replace:
            s.replace += 1
        elif c.is_delete:
            s.delete += 1
        elif c.is_create:
            s.create += 1
        else:
            s.update += 1
    return s
