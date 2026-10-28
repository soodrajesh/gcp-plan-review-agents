import pytest

from planreview.plan import PlanError, parse_plan, stats
from planreview.rules import REGISTRY, Policy

from .helpers import plan, rc

P = Policy()


def hits(rule_id, change):
    r = next(r for r in REGISTRY if r.id == rule_id)
    return r.fn(parse_plan(plan(change))[0], P)


def test_every_rule_has_unique_id_and_description():
    ids = [r.id for r in REGISTRY]
    assert len(ids) == len(set(ids)) >= 15
    assert all(r.description for r in REGISTRY)


def test_parse_rejects_non_plans():
    for bad in ({}, [], {"resource_changes": "x"}, {"resource_changes": [{"address": "a"}]}):
        with pytest.raises(PlanError):
            parse_plan(bad)


def test_parse_skips_noop_read_and_data_sources():
    doc = plan(
        rc("google_x", "a", ["no-op"]),
        rc("google_x", "b", ["read"]),
        {**rc("google_x", "c"), "mode": "data"},
        rc("google_x", "d"),
    )
    assert [c.name for c in parse_plan(doc)] == ["d"]


def test_stats_counts_replace_separately():
    s = stats(
        parse_plan(
            plan(
                rc("t", "a"),
                rc("t", "b", ["update"]),
                rc("t", "c", ["delete"]),
                rc("t", "d", ["delete", "create"]),
            )
        )
    )
    assert (s.create, s.update, s.delete, s.replace) == (1, 1, 1, 1)


@pytest.mark.parametrize(
    "member,role,sev",
    [
        ("allUsers", "roles/storage.objectViewer", "critical"),
        ("allAuthenticatedUsers", "roles/viewer", "critical"),
        ("allUsers", "roles/run.invoker", "high"),
    ],
)
def test_sec001_public_iam(member, role, sev):
    h = hits(
        "SEC001",
        rc("google_storage_bucket_iam_member", "x", after={"role": role, "member": member}),
    )
    assert [x.severity for x in h] == [sev]


def test_sec001_ignores_specific_members_and_deletes():
    ok = rc(
        "google_project_iam_member", "x", after={"role": "roles/viewer", "member": "user:a@b.c"}
    )
    assert hits("SEC001", ok) == []
    gone = rc("google_project_iam_member", "x", ["delete"], before={"member": "allUsers"})
    assert hits("SEC001", gone) == []


def test_sec001_checks_members_list_in_bindings():
    b = rc(
        "google_project_iam_binding",
        "x",
        after={"role": "roles/viewer", "members": ["user:a@b.c", "allUsers"]},
    )
    assert hits("SEC001", b)[0].severity == "critical"


@pytest.mark.parametrize(
    "ports,sev",
    [
        (["22"], "critical"),
        (["3000-3300"], "medium"),
        (["3000-4000"], "critical"),
        (["3380-3400"], "critical"),
        ([], "critical"),
        (["443"], "medium"),
    ],
)
def test_sec002_firewall(ports, sev):
    fw = rc(
        "google_compute_firewall",
        "x",
        after={
            "direction": "INGRESS",
            "source_ranges": ["0.0.0.0/0"],
            "allow": [{"protocol": "tcp", "ports": ports}],
        },
    )
    assert hits("SEC002", fw)[0].severity == sev


def test_sec002_ignores_internal_and_egress():
    internal = rc(
        "google_compute_firewall",
        "x",
        after={
            "direction": "INGRESS",
            "source_ranges": ["10.0.0.0/8"],
            "allow": [{"protocol": "tcp", "ports": ["22"]}],
        },
    )
    egress = rc(
        "google_compute_firewall",
        "x",
        after={"direction": "EGRESS", "source_ranges": ["0.0.0.0/0"]},
    )
    assert hits("SEC002", internal) == [] and hits("SEC002", egress) == []


def test_sec003_bucket_controls():
    weak = rc("google_storage_bucket", "b", after={"uniform_bucket_level_access": False})
    assert len(hits("SEC003", weak)) == 2
    strong = rc(
        "google_storage_bucket",
        "b",
        after={"uniform_bucket_level_access": True, "public_access_prevention": "enforced"},
    )
    assert hits("SEC003", strong) == []


def test_sec004_sql_exposure_levels():
    def sql(**ip):
        return rc(
            "google_sql_database_instance", "d", after={"settings": [{"ip_configuration": [ip]}]}
        )

    assert (
        hits("SEC004", sql(ipv4_enabled=True, authorized_networks=[{"value": "0.0.0.0/0"}]))[
            0
        ].severity
        == "critical"
    )
    assert hits("SEC004", sql(ipv4_enabled=True))[0].severity == "medium"
    assert hits("SEC004", sql(ipv4_enabled=False)) == []


def test_sec005_and_sec006():
    assert hits("SEC005", rc("google_service_account_key", "k", after={}))[0].severity == "high"
    assert (
        hits("SEC006", rc("google_project_iam_member", "o", after={"role": "roles/owner"}))[
            0
        ].severity
        == "high"
    )
    assert (
        hits("SEC006", rc("google_project_iam_member", "o", after={"role": "roles/viewer"})) == []
    )


@pytest.mark.parametrize(
    "mt,sev",
    [
        ("a2-highgpu-1g", "high"),
        ("n2-standard-64", "high"),
        ("n2-standard-32", "high"),
        ("n2-standard-24", "medium"),
    ],
)
def test_cost001_machine_types(mt, sev):
    h = hits("COST001", rc("google_compute_instance", "v", after={"machine_type": mt}))
    assert h[0].severity == sev


def test_cost001_allows_small_machines():
    assert (
        hits("COST001", rc("google_compute_instance", "v", after={"machine_type": "e2-medium"}))
        == []
    )
    assert (
        hits(
            "COST001", rc("google_compute_instance", "v", after={"machine_type": "n2-standard-16"})
        )
        == []
    )


def test_cost002_cloud_run_scaling():
    def run(mn, mx):
        return rc(
            "google_cloud_run_v2_service",
            "r",
            after={
                "template": [{"scaling": [{"min_instance_count": mn, "max_instance_count": mx}]}]
            },
        )

    assert hits("COST002", run(0, 5)) == []
    assert {h.severity for h in hits("COST002", run(2, 500))} == {"medium", "low"}
    assert hits("COST002", run(0, None))[0].severity == "medium"


def test_cost003_004_005():
    sql = rc(
        "google_sql_database_instance",
        "d",
        after={"settings": [{"tier": "db-custom-32-65536", "availability_type": "REGIONAL"}]},
    )
    assert {h.severity for h in hits("COST003", sql)} == {"medium", "low"}
    pool = rc("google_container_node_pool", "p", after={"node_count": 12})
    assert hits("COST004", pool)
    disk = rc("google_compute_disk", "d", after={"size": 2000, "type": "pd-ssd"})
    assert hits("COST005", disk)
    assert (
        hits("COST005", rc("google_compute_disk", "d", after={"size": 2000, "type": "pd-standard"}))
        == []
    )


def test_rel001_delete_vs_replace():
    d = rc("google_sql_database_instance", "d", ["delete"], before={})
    r = rc("google_sql_database_instance", "d", ["delete", "create"], before={}, after={})
    assert hits("REL001", d)[0].severity == "critical"
    assert hits("REL001", r)[0].severity == "high"
    assert hits("REL001", rc("google_compute_instance", "v", ["delete"], before={})) == []


def test_rel002_003_004():
    sql = rc(
        "google_sql_database_instance", "d", after={"deletion_protection": False, "settings": [{}]}
    )
    assert {h.severity for h in hits("REL002", sql)} == {"medium", "high"}
    b = rc("google_storage_bucket", "b", after={"force_destroy": True})
    assert {h.severity for h in hits("REL003", b)} == {"medium", "low"}
    run = rc(
        "google_cloud_run_v2_service", "r", after={"template": [{"containers": [{"image": "x"}]}]}
    )
    assert hits("REL004", run)[0].severity == "low"


def test_compliance_rules():
    unlabeled = rc(
        "google_storage_bucket", "b", after={"labels": {"env": "dev"}, "name": "ok-name"}
    )
    assert "owner" in hits("COMP001", unlabeled)[0].title
    assert (
        hits("COMP002", rc("google_storage_bucket", "b", after={"location": "EU"}))[0].severity
        == "medium"
    )
    assert hits("COMP002", rc("google_storage_bucket", "b", after={"location": "us-east1"})) == []
    assert hits("COMP003", rc("google_storage_bucket", "b", after={"name": "Bad_Name"}))
    assert hits("COMP003", rc("google_storage_bucket", "b", after={"name": "good-name-1"})) == []


def test_replaced_resources_are_still_checked_for_their_new_config():
    """A destroy-then-create has a new `after` that must be reviewed like any create."""
    risky = {
        "settings": [{"ip_configuration": [{"authorized_networks": [{"value": "0.0.0.0/0"}]}]}]
    }
    repl = rc("google_sql_database_instance", "d", ["delete", "create"], before={}, after=risky)
    assert hits("SEC004", repl)[0].severity == "critical"
    gone = rc("google_sql_database_instance", "d", ["delete"], before=risky)
    assert hits("SEC004", gone) == []
