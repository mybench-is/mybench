"""MYB-3.2: OTS stamping — wire discipline, pending→upgraded lifecycle, leak scan."""

import hashlib
import os
import stat
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from mybench import paths
from mybench.anchor import ots
from mybench.anchor.batch import build_batch
from tests.fixtures import assert_no_canaries, generate_fixtures
from tests.fixtures.ledgers import build_canary_ledger

BLOCK_HEIGHT = 700123


class _CalendarHandler(BaseHTTPRequestHandler):
    def log_message(self, *args):  # keep test output quiet
        pass

    def _respond(self, body: bytes):
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        from opentimestamps.core.notary import PendingAttestation
        from opentimestamps.core.serialize import BytesSerializationContext
        from opentimestamps.core.timestamp import Timestamp

        body = self.rfile.read(int(self.headers["Content-Length"]))
        self.server.captures.append(("POST", self.path, body))
        ts = Timestamp(body)
        ts.attestations.add(PendingAttestation(self.server.base_url))
        ctx = BytesSerializationContext()
        ts.serialize(ctx)
        self._respond(ctx.getbytes())

    def do_GET(self):
        from opentimestamps.core.notary import BitcoinBlockHeaderAttestation
        from opentimestamps.core.serialize import BytesSerializationContext
        from opentimestamps.core.timestamp import Timestamp

        self.server.captures.append(("GET", self.path, b""))
        msg = bytes.fromhex(self.path.rsplit("/", 1)[-1])
        ts = Timestamp(msg)
        ts.attestations.add(BitcoinBlockHeaderAttestation(BLOCK_HEIGHT))
        ctx = BytesSerializationContext()
        ts.serialize(ctx)
        self._respond(ctx.getbytes())


@pytest.fixture
def calendar():
    server = ThreadingHTTPServer(("127.0.0.1", 0), _CalendarHandler)
    server.captures = []
    server.base_url = f"http://127.0.0.1:{server.server_address[1]}"
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield server
    server.shutdown()
    thread.join(timeout=5)


@pytest.fixture
def canary_batch(tmp_path):
    fx = generate_fixtures(tmp_path / "fx")
    led, canaries = build_canary_ledger(fx)
    return build_batch(led), canaries


# --- Stamping + wire discipline (AC #1, #2) -----------------------------------------


def test_stamp_root_returns_pending_proof(calendar):
    root = hashlib.sha256(b"synthetic root").digest()
    proof = ots.stamp_root(root, calendars=[calendar.base_url])
    info = ots.proof_info(root, proof)
    assert info["digest_matches"]
    assert info["pending"] == [calendar.base_url]
    assert not info["confirmed"]


def test_wire_payload_is_exactly_the_root_digest(calendar, canary_batch):
    batch, canaries = canary_batch
    ots.stamp_root(bytes.fromhex(batch["root"]), calendars=[calendar.base_url])
    posts = [c for c in calendar.captures if c[0] == "POST"]
    assert len(posts) == 1
    method, path, body = posts[0]
    assert path == "/digest"
    assert body == bytes.fromhex(batch["root"]) and len(body) == 32
    for canary in canaries:  # nothing content/nonce-derived crosses the wire
        assert canary not in body and canary.hex().encode() not in body


def test_one_dead_calendar_does_not_block_stamping(calendar):
    root = hashlib.sha256(b"synthetic root 2").digest()
    proof = ots.stamp_root(
        root, calendars=["http://127.0.0.1:1", calendar.base_url], timeout=2.0
    )
    assert ots.proof_info(root, proof)["pending"] == [calendar.base_url]


def test_all_calendars_dead_is_an_error():
    with pytest.raises(ots.OtsError, match="no calendar"):
        ots.stamp_root(bytes(32), calendars=["http://127.0.0.1:1"], timeout=2.0)


def test_bad_digest_length_rejected():
    with pytest.raises(ots.OtsError, match="32-byte"):
        ots.stamp_root(b"short", calendars=["http://127.0.0.1:1"])


# --- Storage + upgrade lifecycle (AC #3, #4) ------------------------------------------


def test_stamp_batch_stores_under_data_dir_idempotently(calendar, canary_batch):
    batch, _ = canary_batch
    artifact, proof = ots.stamp_batch(batch, calendars=[calendar.base_url])
    assert artifact.parent == proof.parent == paths.anchors_dir()
    for p in (artifact, proof):
        assert stat.S_IMODE(p.stat().st_mode) == 0o600
    stamps = len([c for c in calendar.captures if c[0] == "POST"])
    ots.stamp_batch(batch, calendars=[calendar.base_url])  # second call: no restamp
    assert len([c for c in calendar.captures if c[0] == "POST"]) == stamps
    tampered = dict(batch, ts="2027-01-01T00:00:00Z")
    with pytest.raises(ots.OtsError, match="refusing overwrite"):
        ots.stamp_batch(tampered, calendars=[calendar.base_url])


def test_upgrade_path_pending_to_bitcoin(calendar, canary_batch):
    batch, _ = canary_batch
    root = bytes.fromhex(batch["root"])
    _, proof_path = ots.stamp_batch(batch, calendars=[calendar.base_url])
    assert not ots.proof_info(root, proof_path.read_bytes())["confirmed"]
    assert ots.upgrade_batch_proof(proof_path) is True
    info = ots.proof_info(root, proof_path.read_bytes())
    assert info["confirmed"] and info["bitcoin_heights"] == [BLOCK_HEIGHT]
    assert info["digest_matches"]


def test_proof_info_detects_wrong_root(calendar):
    root = hashlib.sha256(b"synthetic root 3").digest()
    proof = ots.stamp_root(root, calendars=[calendar.base_url])
    assert ots.proof_info(bytes(32), proof)["digest_matches"] is False
    with pytest.raises(ots.OtsError, match="unparseable"):
        ots.proof_info(root, b"garbage")


# --- Leak scan (AC #5) -----------------------------------------------------------------


def test_stored_artifact_and_proof_are_leak_free(calendar, canary_batch):
    batch, canaries = canary_batch
    artifact, proof = ots.stamp_batch(batch, calendars=[calendar.base_url])
    ots.upgrade_batch_proof(proof)
    assert assert_no_canaries([artifact, proof], canaries) == 2


# --- Live network check (optional; SETUP_TODO #4) ----------------------------------------


@pytest.mark.skipif(
    not os.environ.get("MYBENCH_LIVE_OTS"),
    reason="live public-calendar test; set MYBENCH_LIVE_OTS=1 (network, synthetic digest only)",
)
def test_live_public_calendars_accept_synthetic_digest():
    root = hashlib.sha256(b"mybench synthetic live-test digest").digest()
    proof = ots.stamp_root(root, timeout=30.0)
    info = ots.proof_info(root, proof)
    assert info["digest_matches"] and info["pending"]
