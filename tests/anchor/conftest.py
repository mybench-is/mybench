"""Shared anchor-test fixtures: in-process mock OTS calendar."""

import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

BLOCK_HEIGHT = 700123


class CalendarHandler(BaseHTTPRequestHandler):
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
    server = ThreadingHTTPServer(("127.0.0.1", 0), CalendarHandler)
    server.captures = []
    server.base_url = f"http://127.0.0.1:{server.server_address[1]}"
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield server
    server.shutdown()
    thread.join(timeout=5)
