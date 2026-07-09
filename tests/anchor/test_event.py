"""MYB-8.3: identity records, anchor events v2, layout v1, flat-repo migration."""

import json
import re
import shutil

import pytest

from mybench import identity, paths
from mybench.anchor import event as ev
from mybench.anchor.batch import build_batch
from mybench.anchor.ots import proof_info, stamp_batch
from tests.fixtures import assert_no_canaries, generate_fixtures
from tests.fixtures.ledgers import build_canary_ledger

DATE = "2026-01-01"


@pytest.fixture
def canary(tmp_path):
    fx = generate_fixtures(tmp_path / "fx")
    led, canaries = build_canary_ledger(fx)
    return led, canaries


# --- Identity (ADR-0004 §3) ---------------------------------------------------------


def test_identity_id_is_domain_separated_sha256_of_genesis_pub():
    import hashlib

    raw = bytes(range(32))
    assert identity.identity_id_for(raw) == hashlib.sha256(
        b"mybench:v1:identity" + raw
    ).hexdigest()
    with pytest.raises(identity.IdentityError):
        identity.identity_id_for(b"short")


def test_identity_key_distinct_from_device_key_and_idempotent():
    key, pub = paths.ensure_identity_key()
    assert key.name == "identity.key" and key.parent == paths.keys_dir()
    dkey, _ = paths.ensure_device_key()
    assert key.read_bytes() != dkey.read_bytes()
    before = key.read_bytes()
    paths.ensure_identity_key()
    assert key.read_bytes() == before  # never regenerated
    assert re.fullmatch(r"[0-9a-f]{64}", identity.local_identity_id())


def test_records_sign_and_verify_and_tamper_fails():
    g = identity.genesis_record(DATE)
    identity.verify_record(g, g["identity_pub"])
    h = identity.handle_binding_record("ckeenan", DATE)
    d = identity.device_binding_record("ab" * 32, DATE, scope="retroactive")
    for record in (h, d):
        assert record["identity_id"] == g["identity_id"]
        identity.verify_record(record, g["identity_pub"])
    tampered = dict(h, handle="mallory")
    with pytest.raises(identity.IdentityError):
        identity.verify_record(tampered, g["identity_pub"])


def test_handle_charset_and_scope_enforced():
    for bad in ("ck", "x" * 33, "Has-Caps", "under_score", ""):
        with pytest.raises(identity.IdentityError):
            identity.handle_binding_record(bad, DATE)
    with pytest.raises(identity.IdentityError):
        identity.device_binding_record("ab" * 32, DATE, scope="forever")


# --- Anchor events v2 (ADR-0004 §§4-5) --------------------------------------------------


def test_build_event_projects_batch_with_coarse_date(canary):
    led, canaries = canary
    batch = build_batch(led)
    rows = led.rows()
    event = ev.build_event(batch, rows, date=DATE)
    assert event["date"] == DATE and "T" not in event["date"]  # coarse, no seconds
    assert event["root"] == batch["root"] and event["chain_tip"] == batch["chain_tip"]
    assert event["item_count"] == sum(
        r["item_count"] for r in rows[batch["row_start"]:batch["row_end"]]
        if r["type"] == "session"
    )
    assert event["identity_id"] == identity.local_identity_id()
    import mybench

    assert event["client_version"] == mybench.__version__
    ev.validate_event(event)
    assert ev.build_event(batch, rows, date=DATE) == event  # deterministic


def test_event_schema_rejects_extras_and_fine_timestamps(canary):
    led, _ = canary
    event = ev.build_event(build_batch(led), led.rows(), date=DATE)
    with pytest.raises(ev.EventError, match="schema"):
        ev.validate_event({**event, "filename": "x"})
    with pytest.raises(ev.EventError, match="schema"):
        ev.validate_event({**event, "date": "2026-01-01T00:00:00Z"})


def test_event_paths_layout():
    rel, ots = ev.event_relpaths("ab" * 32, "2026-07-09")
    assert str(rel) == f"anchors/{'ab' * 32}/2026/07/09.json"
    assert str(ots) == str(rel) + ".ots"


def test_event_file_is_leak_free(canary, tmp_path):
    led, canaries = canary
    event = ev.build_event(build_batch(led), led.rows(), date=DATE)
    out = tmp_path / "event.json"
    out.write_bytes(ev.event_bytes(event))
    assert assert_no_canaries([out], canaries) == 1


# --- Migration (pre-publication window only) -----------------------------------------------


def flat_repo(tmp_path, led, calendar):
    batch = build_batch(led)
    artifact, proof = stamp_batch(batch, calendars=[calendar.base_url])
    clone = tmp_path / "clone"
    clone.mkdir()
    for f in (artifact, proof):
        shutil.copy(f, clone / f.name)
    return clone, batch


def test_migrate_flat_repo_to_layout_v1(canary, tmp_path, calendar):
    led, canaries = canary
    clone, batch = flat_repo(tmp_path, led, calendar)
    manifest = ev.migrate_flat_repo(clone, led.rows(), handle="ckeenan")
    iid = manifest["identity_id"]
    date = batch["ts"][:10]
    y, m, d = date.split("-")
    event_path = clone / "anchors" / iid / y / m / f"{d}.json"
    proof_path = event_path.with_name(event_path.name + ".ots")
    assert event_path.is_file() and proof_path.is_file()
    assert not list(clone.glob("anchor-*.json"))  # flat files gone
    event = json.loads(event_path.read_bytes())
    ev.validate_event(event)
    # The proof carried over and still binds the (unchanged) root.
    assert proof_info(bytes.fromhex(event["root"]), proof_path.read_bytes())["digest_matches"]
    # Identity records present and verifiable.
    ids = clone / "identities" / iid
    genesis = json.loads((ids / "genesis.json").read_bytes())
    identity.verify_record(genesis, genesis["identity_pub"])
    handle = json.loads((ids / "handle-0000.json").read_bytes())
    assert handle["handle"] == "ckeenan"
    identity.verify_record(handle, genesis["identity_pub"])
    device = json.loads(next(ids.glob("device-*.json")).read_bytes())
    assert device["scope"] == "retroactive"
    assert device["device_pub"] == event["device_pub"]  # chains the published anchors
    assert (clone / "schema" / "anchor.v1.md").is_file()
    # Migrated tree is leak-free.
    assert assert_no_canaries([clone], canaries) >= 4


def test_migration_refuses_second_event_same_day_and_reruns(canary, tmp_path, calendar):
    led, _ = canary
    clone, _ = flat_repo(tmp_path, led, calendar)
    ev.migrate_flat_repo(clone, led.rows(), handle="ckeenan")
    with pytest.raises(ev.EventError, match="no flat artifacts"):
        ev.migrate_flat_repo(clone, led.rows(), handle="ckeenan")  # idempotent refusal
