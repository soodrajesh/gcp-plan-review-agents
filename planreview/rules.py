"""Deterministic review rules, grouped by the agent that owns them.

The rules are the source of truth for severity. Models may explain a finding or propose extra
ones, but they cannot lower or remove a rule finding, and the verdict is computed from severities
alone (see judge.py)."""

from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from .models import AgentName, ResourceChange, Severity

PUBLIC_MEMBERS = {"allUsers", "allAuthenticatedUsers"}
PRIMITIVE_ROLES = {"roles/owner", "roles/editor"}
STATEFUL_TYPES = {
    "google_sql_database_instance",
    "google_storage_bucket",
    "google_spanner_instance",
    "google_spanner_database",
    "google_bigtable_instance",
    "google_firestore_database",
    "google_compute_disk",
    "google_bigquery_dataset",
    "google_bigquery_table",
    "google_kms_crypto_key",
    "google_redis_instance",
}
LABELED_TYPES = {
    "google_storage_bucket",
    "google_compute_instance",
    "google_compute_disk",
    "google_cloud_run_v2_service",
    "google_sql_database_instance",
    "google_bigquery_dataset",
}


@dataclass(frozen=True)
class Policy:
    required_labels: tuple[str, ...] = ("env", "owner")
    allowed_locations: tuple[str, ...] = ("us-", "US", "global")
    max_cloud_run_instances: int = 100
    max_vcpus: int = 16


@dataclass
class Hit:
    severity: Severity
    title: str
    detail: str = ""
    remediation: str = ""


@dataclass(frozen=True)
class Rule:
    id: str
    agent: AgentName
    description: str
    fn: Callable[[ResourceChange, Policy], list[Hit]]


REGISTRY: list[Rule] = []


def rule(rule_id: str, agent: AgentName, description: str):
    def deco(fn: Callable[[ResourceChange, Policy], list[Hit]]):
        REGISTRY.append(Rule(rule_id, agent, description, fn))
        return fn

    return deco


# --- helpers -------------------------------------------------------------------------------


def after(rc: ResourceChange) -> dict[str, Any]:
    return rc.after or {}


def block(d: dict[str, Any], key: str) -> dict[str, Any]:
    """Terraform JSON renders nested blocks as single-element lists."""
    v = d.get(key)
    if isinstance(v, list):
        return v[0] if v and isinstance(v[0], dict) else {}
    return v if isinstance(v, dict) else {}


def blocks(d: dict[str, Any], key: str) -> list[dict[str, Any]]:
    v = d.get(key)
    return [x for x in v if isinstance(x, dict)] if isinstance(v, list) else []


def members(a: dict[str, Any]) -> list[str]:
    out = [a["member"]] if isinstance(a.get("member"), str) else []
    if isinstance(a.get("members"), list):
        out += [m for m in a["members"] if isinstance(m, str)]
    return out


def vcpus(machine_type: str) -> int | None:
    m = re.search(r"-(\d+)$", machine_type or "")
    return int(m.group(1)) if m else None


def is_iam(rc: ResourceChange) -> bool:
    return rc.type.startswith("google_") and "_iam_" in rc.type


# --- security ------------------------------------------------------------------------------


@rule("SEC001", "security", "IAM grant to allUsers / allAuthenticatedUsers")
def sec001(rc, p):
    if not is_iam(rc) or rc.is_delete:
        return []
    a = after(rc)
    pub = [m for m in members(a) if m in PUBLIC_MEMBERS]
    if not pub:
        return []
    role = a.get("role", "")
    invoker = role in ("roles/run.invoker", "roles/cloudfunctions.invoker")
    return [
        Hit(
            "high" if invoker else "critical",
            f"{role or 'IAM role'} granted to {pub[0]}",
            "Anyone on the internet gets this role."
            + (" For a service invoker role this makes the endpoint public." if invoker else ""),
            "Grant to specific identities or groups; put public traffic behind a load balancer/IAP.",
        )
    ]


@rule("SEC002", "security", "Firewall rule allows ingress from 0.0.0.0/0")
def sec002(rc, p):
    if rc.type != "google_compute_firewall" or rc.is_delete:
        return []
    a = after(rc)
    if a.get("direction", "INGRESS") != "INGRESS" or a.get("disabled"):
        return []
    if "0.0.0.0/0" not in (a.get("source_ranges") or []):
        return []
    sensitive, all_ports = set(), False
    for allow in blocks(a, "allow"):
        ports = allow.get("ports") or []
        if not ports:
            all_ports = True
        for port in ports:
            lo, _, hi = str(port).partition("-")
            for risky in (22, 3389):
                if lo.isdigit() and int(lo) <= risky <= int(hi or lo):
                    sensitive.add(risky)
    if sensitive or all_ports:
        what = "all ports" if all_ports else "port " + ", ".join(map(str, sorted(sensitive)))
        return [
            Hit(
                "critical",
                f"Firewall opens {what} to the whole internet",
                "Admin/remote-access ports reachable from 0.0.0.0/0 are scanned within minutes.",
                "Restrict source_ranges to corporate CIDRs or use IAP TCP forwarding (35.235.240.0/20).",
            )
        ]
    return [
        Hit(
            "medium",
            "Firewall accepts ingress from 0.0.0.0/0",
            "Acceptable only for intentionally public services.",
            "Narrow source_ranges, or confirm the target tags are a public service.",
        )
    ]


@rule("SEC003", "security", "Bucket without uniform access / public access prevention")
def sec003(rc, p):
    if rc.type != "google_storage_bucket" or rc.is_delete:
        return []
    a = after(rc)
    hits = []
    if a.get("uniform_bucket_level_access") is not True:
        hits.append(
            Hit(
                "medium",
                "Bucket does not enforce uniform bucket-level access",
                "Object ACLs can grant access outside IAM review.",
                "Set uniform_bucket_level_access = true.",
            )
        )
    if a.get("public_access_prevention") != "enforced":
        hits.append(
            Hit(
                "medium",
                "Bucket does not enforce public access prevention",
                "A later ACL or IAM change could expose objects publicly.",
                'Set public_access_prevention = "enforced".',
            )
        )
    return hits


@rule("SEC004", "security", "Cloud SQL reachable from the public internet")
def sec004(rc, p):
    if rc.type != "google_sql_database_instance" or rc.is_delete:
        return []
    ipc = block(block(after(rc), "settings"), "ip_configuration")
    nets = [n.get("value") for n in blocks(ipc, "authorized_networks")]
    if "0.0.0.0/0" in nets:
        return [
            Hit(
                "critical",
                "Cloud SQL authorizes 0.0.0.0/0",
                "The database accepts connections from any address; only the password protects it.",
                "Remove the authorized network; use private IP and the Cloud SQL connector.",
            )
        ]
    if ipc.get("ipv4_enabled") is True:
        return [
            Hit(
                "medium",
                "Cloud SQL has a public IPv4 address",
                "Public IP widens the attack surface even with no authorized networks.",
                "Set ipv4_enabled = false and use private IP.",
            )
        ]
    return []


@rule("SEC005", "security", "Long-lived service account key created")
def sec005(rc, p):
    if rc.type == "google_service_account_key" and not rc.is_delete:
        return [
            Hit(
                "high",
                "Service account key is being created",
                "Exportable keys leak through repos, logs and laptops and never expire by default.",
                "Use workload identity / impersonation instead of keys.",
            )
        ]
    return []


@rule("SEC006", "security", "Primitive Owner/Editor role granted")
def sec006(rc, p):
    if not is_iam(rc) or rc.is_delete:
        return []
    role = after(rc).get("role")
    if role in PRIMITIVE_ROLES:
        return [
            Hit(
                "high",
                f"{role} is a primitive role",
                "Primitive roles carry thousands of permissions, far beyond least privilege.",
                "Replace with the narrowest predefined or custom role that covers the job.",
            )
        ]
    return []


# --- cost ----------------------------------------------------------------------------------


@rule("COST001", "cost", "Large VM or GPU machine type")
def cost001(rc, p):
    if rc.is_delete:
        return []
    a = after(rc)
    mts = []
    if rc.type == "google_compute_instance":
        mts.append(a.get("machine_type", ""))
    elif rc.type == "google_container_node_pool":
        mts.append(block(a, "node_config").get("machine_type", ""))
    hits = []
    for mt in filter(None, mts):
        n = vcpus(mt)
        gpu = mt.startswith(("a2-", "a3-", "g2-", "a4-"))
        if gpu or (n is not None and n > p.max_vcpus):
            hits.append(
                Hit(
                    "high" if gpu or (n or 0) >= 32 else "medium",
                    f"Machine type {mt} is expensive",
                    "GPU and 32+ vCPU machines cost hundreds to thousands of USD per month."
                    if gpu or (n or 0) >= 32
                    else f"{n} vCPUs exceeds the {p.max_vcpus} vCPU review threshold.",
                    "Confirm sizing with load data; prefer autoscaling smaller nodes or Spot VMs.",
                )
            )
    return hits


@rule("COST002", "cost", "Cloud Run scaling is unbounded or always-on")
def cost002(rc, p):
    if rc.type != "google_cloud_run_v2_service" or rc.is_delete:
        return []
    sc = block(block(after(rc), "template"), "scaling")
    mx, mn = sc.get("max_instance_count"), sc.get("min_instance_count") or 0
    hits = []
    if not mx or mx > p.max_cloud_run_instances:
        hits.append(
            Hit(
                "medium",
                "Cloud Run max_instance_count is unset or very high"
                if not mx
                else f"Cloud Run max_instance_count is {mx}",
                "A traffic spike or a retry storm scales spend without a ceiling.",
                f"Set max_instance_count <= {p.max_cloud_run_instances}.",
            )
        )
    if mn >= 1:
        hits.append(
            Hit(
                "low",
                f"Cloud Run keeps {mn} instance(s) warm",
                "min_instance_count > 0 bills idle time continuously.",
                "Use 0 unless cold-start latency is a requirement.",
            )
        )
    return hits


@rule("COST003", "cost", "Large or regional-HA Cloud SQL")
def cost003(rc, p):
    if rc.type != "google_sql_database_instance" or rc.is_delete:
        return []
    s = block(after(rc), "settings")
    hits = []
    m = re.match(r"db-custom-(\d+)-", s.get("tier", ""))
    if m and int(m.group(1)) >= 16:
        hits.append(
            Hit(
                "medium",
                f"Cloud SQL tier {s['tier']} has {m.group(1)} vCPUs",
                "Large tiers are billed 24/7.",
                "Right-size from observed CPU/memory.",
            )
        )
    if s.get("availability_type") == "REGIONAL":
        hits.append(
            Hit(
                "low",
                "Cloud SQL uses REGIONAL availability",
                "HA roughly doubles instance cost; correct for production, wasteful elsewhere.",
                "Use ZONAL for non-production environments.",
            )
        )
    return hits


@rule("COST004", "cost", "GKE node pool without a ceiling")
def cost004(rc, p):
    if rc.type != "google_container_node_pool" or rc.is_delete:
        return []
    a = after(rc)
    auto = block(a, "autoscaling")
    if (a.get("node_count") or 0) > 10 or (auto and (auto.get("max_node_count") or 0) > 20):
        return [
            Hit(
                "medium",
                "GKE node pool can grow beyond 10-20 nodes",
                "Large pools multiply per-node cost.",
                "Cap max_node_count and confirm with capacity planning.",
            )
        ]
    return []


@rule("COST005", "cost", "Very large persistent disk")
def cost005(rc, p):
    if rc.type != "google_compute_disk" or rc.is_delete:
        return []
    a = after(rc)
    if (a.get("size") or 0) >= 1000 and "ssd" in str(a.get("type", "")):
        return [
            Hit(
                "medium",
                f"{a['size']} GB SSD disk",
                "Large SSD disks cost over 150 USD/month each.",
                "Use pd-balanced / pd-standard or a smaller size unless IOPS demand it.",
            )
        ]
    return []


# --- reliability ---------------------------------------------------------------------------


@rule("REL001", "reliability", "Stateful resource is deleted or replaced")
def rel001(rc, p):
    if rc.type not in STATEFUL_TYPES or not rc.is_delete:
        return []
    if rc.is_replace:
        return [
            Hit(
                "high",
                f"{rc.type} will be replaced (destroy then create)",
                "Data in the old resource is lost unless it is migrated first.",
                "Avoid the forcing change, or use create_before_destroy plus a data migration.",
            )
        ]
    return [
        Hit(
            "critical",
            f"{rc.type} will be destroyed",
            "Deleting a stateful resource is irreversible once backups age out.",
            "Take and verify a backup/export, then remove with a reviewed, dedicated change.",
        )
    ]


@rule("REL002", "reliability", "Cloud SQL without deletion protection or backups")
def rel002(rc, p):
    if rc.type != "google_sql_database_instance" or rc.is_delete:
        return []
    a = after(rc)
    hits = []
    if not a.get("deletion_protection"):
        hits.append(
            Hit(
                "medium",
                "Cloud SQL deletion_protection is off",
                "One bad apply or console click removes the database.",
                "Set deletion_protection = true.",
            )
        )
    if not block(block(a, "settings"), "backup_configuration").get("enabled"):
        hits.append(
            Hit(
                "high",
                "Cloud SQL automated backups are disabled",
                "There is nothing to restore from after corruption or deletion.",
                "Enable backup_configuration with point_in_time_recovery.",
            )
        )
    return hits


@rule("REL003", "reliability", "Bucket force_destroy or no versioning")
def rel003(rc, p):
    if rc.type != "google_storage_bucket" or rc.is_delete:
        return []
    a = after(rc)
    hits = []
    if a.get("force_destroy"):
        hits.append(
            Hit(
                "medium",
                "Bucket has force_destroy = true",
                "Terraform will delete the bucket together with every object in it.",
                "Set force_destroy = false for buckets that hold data.",
            )
        )
    if not block(a, "versioning").get("enabled"):
        hits.append(
            Hit(
                "low",
                "Bucket versioning is off",
                "Overwritten or deleted objects cannot be recovered.",
                "Enable versioning, with a lifecycle rule to bound storage.",
            )
        )
    return hits


@rule("REL004", "reliability", "Cloud Run service has no health probe")
def rel004(rc, p):
    if rc.type != "google_cloud_run_v2_service" or rc.is_delete:
        return []
    c = block(block(after(rc), "template"), "containers")
    if c and not (blocks(c, "startup_probe") or blocks(c, "liveness_probe")):
        return [
            Hit(
                "low",
                "Cloud Run container defines no startup or liveness probe",
                "Broken revisions are marked healthy as soon as the port opens.",
                "Add a startup_probe on the health endpoint.",
            )
        ]
    return []


# --- compliance ----------------------------------------------------------------------------


def _labels(rc: ResourceChange) -> dict[str, Any]:
    a = after(rc)
    if rc.type == "google_sql_database_instance":
        return block(a, "settings").get("user_labels") or {}
    return a.get("labels") or {}


@rule("COMP001", "compliance", "Required labels missing")
def comp001(rc, p):
    if rc.type not in LABELED_TYPES or rc.is_delete:
        return []
    have = _labels(rc)
    missing = [k for k in p.required_labels if k not in have]
    if missing:
        return [
            Hit(
                "low",
                f"Missing required label(s): {', '.join(missing)}",
                "Unlabelled resources break cost allocation and ownership lookups.",
                f"Add labels {', '.join(missing)}.",
            )
        ]
    return []


@rule("COMP002", "compliance", "Resource outside allowed locations")
def comp002(rc, p):
    if rc.is_delete:
        return []
    a = after(rc)
    loc = a.get("location") or a.get("region") or a.get("zone")
    if isinstance(loc, str) and loc and not loc.startswith(p.allowed_locations):
        return [
            Hit(
                "medium",
                f"Location {loc} is outside the allowed set",
                f"Policy allows locations starting with {', '.join(p.allowed_locations)}.",
                "Move the resource to an approved location or request an exception.",
            )
        ]
    return []


@rule("COMP003", "compliance", "Resource name violates naming convention")
def comp003(rc, p):
    if rc.is_delete:
        return []
    name = after(rc).get("name")
    if (
        rc.type in LABELED_TYPES
        and isinstance(name, str)
        and not re.fullmatch(r"[a-z][a-z0-9-]{2,62}", name)
    ):
        return [
            Hit(
                "low",
                f"Name '{name}' is not lowercase-kebab-case",
                "Mixed-case or underscored names break bucket/DNS rules and automation.",
                "Use lowercase letters, digits and hyphens.",
            )
        ]
    return []


def rules_for(agent: AgentName) -> list[Rule]:
    return [r for r in REGISTRY if r.agent == agent]
