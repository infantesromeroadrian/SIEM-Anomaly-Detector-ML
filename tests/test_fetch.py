"""Range-based remote zip reading and manifest verification against a local HTTP server."""

from __future__ import annotations

import hashlib
import http.server
import io
import json
import re
import threading
import zipfile

import pytest

from backend.eval import fetch


def make_zip(files: dict[str, bytes]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        for name, data in files.items():
            z.writestr(name, data)
    return buf.getvalue()


@pytest.fixture
def server():
    payload: dict[str, bytes] = {}

    class Handler(http.server.BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_HEAD(self):
            self.send_response(200)
            self.send_header("Content-Length", str(len(payload["z"])))
            self.end_headers()

        def do_GET(self):
            m = re.match(r"bytes=(\d+)-(\d+)", self.headers.get("Range", ""))
            data = payload["z"]
            chunk = data[int(m[1]) : int(m[2]) + 1] if m else data
            self.send_response(206 if m else 200)
            self.send_header("Content-Length", str(len(chunk)))
            self.end_headers()
            self.wfile.write(chunk)

    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield srv, payload
    srv.shutdown()


def test_remote_file_reads_zip_with_range_requests(server):
    srv, payload = server
    payload["z"] = make_zip({"a.txt": b"hello", "dir/b.txt": b"world" * 1000})
    rf = fetch.RemoteFile(f"http://127.0.0.1:{srv.server_port}/z")
    assert rf.size == len(payload["z"]) and rf.readable() and rf.seekable()
    zf = zipfile.ZipFile(io.BufferedReader(rf))
    assert zf.read("a.txt") == b"hello"
    assert rf.seek(0) == 0 and rf.tell() == 0
    buf = bytearray(4)
    assert rf.readinto(buf) == 4
    assert rf.read(0) == b""


def test_fetch_extracts_and_verifies(server, tmp_path, monkeypatch):
    srv, payload = server
    files = {name: name.encode() * 10 for name in fetch.WANTED}
    payload["z"] = make_zip(files)
    manifest = tmp_path / "manifest.json"
    manifest.write_text(
        json.dumps(
            {
                "files": {
                    n: {"sha256": hashlib.sha256(d).hexdigest(), "bytes": len(d)}
                    for n, d in files.items()
                }
            }
        )
    )
    monkeypatch.setattr(fetch, "MANIFEST", manifest)
    monkeypatch.setattr(fetch, "ZENODO_URL", f"http://127.0.0.1:{srv.server_port}/z")
    root = fetch.fetch(tmp_path / "data")
    assert fetch.verify(root) == []
    # Second call is a no-op (already verified).
    assert fetch.fetch(tmp_path / "data") == root


def test_verify_detects_tampering_and_missing(tmp_path, monkeypatch):
    manifest = tmp_path / "m.json"
    manifest.write_text(
        json.dumps({"files": {"x": {"sha256": "0" * 64}, "y": {"sha256": "0" * 64}}})
    )
    monkeypatch.setattr(fetch, "MANIFEST", manifest)
    (tmp_path / "x").write_text("tampered")
    problems = fetch.verify(tmp_path)
    assert any("mismatch: x" in p for p in problems) and any("missing: y" in p for p in problems)


def test_write_manifest_roundtrip(tmp_path, monkeypatch):
    root = fetch.dataset_root(tmp_path)
    for name in fetch.WANTED:
        p = root / name
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(name)
    manifest = tmp_path / "m.json"
    monkeypatch.setattr(fetch, "MANIFEST", manifest)
    fetch.fetch(tmp_path, write_manifest=True)
    assert fetch.verify(root) == []


def test_default_data_dir_env(monkeypatch, tmp_path):
    monkeypatch.setenv("SIEM_DATA_DIR", str(tmp_path))
    assert fetch.default_data_dir() == tmp_path
