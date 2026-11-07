"""
Download the evaluation subset of the AIT Log Data Set v2.0.

The full ``russellmitchell.zip`` is 7.1 GB, but only a few small files are
needed. The zip central directory and the required members are read with HTTP
Range requests (Zenodo supports them), so about 1 MB is transferred. Every
extracted file is verified against the SHA-256 pinned in
``datasets/ait-ldsv2-russellmitchell.manifest.json``.

Dataset: Landauer et al., "AIT Log Data Set V2.0", Zenodo 5789064,
license CC BY-NC-SA 4.0 (non-commercial). The data are NOT redistributed in
this repository.

Usage:
    python -m backend.eval.fetch [--data-dir ~/datasets/siem-anomaly] [--write-manifest]
"""

from __future__ import annotations

import argparse
import hashlib
import io
import json
import sys
import urllib.request
import zipfile
from pathlib import Path

ZENODO_URL = "https://zenodo.org/api/records/5789064/files/russellmitchell.zip/content"
MANIFEST = (
    Path(__file__).resolve().parents[2] / "datasets" / "ait-ldsv2-russellmitchell.manifest.json"
)
APACHE = "intranet_server/logs/apache2/intranet.smith.russellmitchell.com-access.log"
#: Unlabelled web logs of two other hosts (benign by the dataset's convention: labels exist only for
#: the files that contain attack lines). Used only to estimate false alarms on more benign volume.
OTHER_HOST_LOGS = tuple(
    f"gather/webserver/logs/apache2/{vhost}.smith.russellmitchell.com-access.log.{i}"
    for vhost in ("mail", "cloud")
    for i in (1, 2, 3, 4)
)
#: Members of the zip needed by the evaluation.
WANTED = (
    "dataset.yaml",
    *(f"gather/{APACHE}.{i}" for i in (1, 2, 3, 4)),
    f"labels/{APACHE}.2",
    *OTHER_HOST_LOGS,
)
_TIMEOUT = 60


class RemoteFile(io.RawIOBase):
    """Seekable read-only file backed by HTTP Range requests."""

    def __init__(self, url: str) -> None:
        """Open ``url`` and read its size."""
        self.url = url
        self.pos = 0
        req = urllib.request.Request(url, method="HEAD")  # noqa: S310
        with urllib.request.urlopen(req, timeout=_TIMEOUT) as r:  # noqa: S310
            self.size = int(r.headers["Content-Length"])

    def seekable(self) -> bool:
        """Return True."""
        return True

    def readable(self) -> bool:
        """Return True."""
        return True

    def tell(self) -> int:
        """Return the current offset."""
        return self.pos

    def seek(self, offset: int, whence: int = 0) -> int:
        """Move the read offset."""
        base = {0: 0, 1: self.pos, 2: self.size}[whence]
        self.pos = base + offset
        return self.pos

    def read(self, n: int = -1) -> bytes:
        """Read up to ``n`` bytes starting at the current offset."""
        if n < 0:
            n = self.size - self.pos
        n = min(n, self.size - self.pos)
        if n <= 0:
            return b""
        req = urllib.request.Request(  # noqa: S310
            self.url, headers={"Range": f"bytes={self.pos}-{self.pos + n - 1}"}
        )
        with urllib.request.urlopen(req, timeout=_TIMEOUT) as r:  # noqa: S310
            data = r.read()
        self.pos += len(data)
        return data

    def readinto(self, b: bytearray) -> int:
        """Fill ``b`` with data."""
        data = self.read(len(b))
        b[: len(data)] = data
        return len(data)


def sha256_file(path: Path) -> str:
    """Return the hex SHA-256 of a file."""
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def dataset_root(data_dir: Path) -> Path:
    """Return the directory holding the extracted scenario."""
    return data_dir / "ait-ldsv2" / "russellmitchell"


def verify(root: Path) -> list[str]:
    """Return a list of problems (empty if every pinned file matches)."""
    manifest = json.loads(MANIFEST.read_text())
    problems = []
    for name, expected in manifest["files"].items():
        p = root / name
        if not p.exists():
            problems.append(f"missing: {name}")
        elif sha256_file(p) != expected["sha256"]:
            problems.append(f"sha256 mismatch: {name}")
    return problems


def fetch(data_dir: Path, write_manifest: bool = False) -> Path:
    """Download and verify the subset; return the scenario root."""
    root = dataset_root(data_dir)
    if not write_manifest and not verify_quiet(root):
        zf = zipfile.ZipFile(io.BufferedReader(RemoteFile(ZENODO_URL), buffer_size=1 << 20))
        for name in WANTED:
            zf.extract(name, root)
            print(f"extracted {name}")
    if write_manifest:
        files = {
            n: {"sha256": sha256_file(root / n), "bytes": (root / n).stat().st_size} for n in WANTED
        }
        MANIFEST.write_text(
            json.dumps(
                {
                    "dataset": "AIT Log Data Set V2.0 / russellmitchell",
                    "zenodo": "https://doi.org/10.5281/zenodo.5789064",
                    "license": "CC-BY-NC-SA-4.0",
                    "files": files,
                },
                indent=2,
            )
            + "\n"
        )
        return root
    problems = verify(root)
    if problems:
        msg = "dataset verification failed: " + "; ".join(problems)
        raise RuntimeError(msg)
    return root


def verify_quiet(root: Path) -> bool:
    """Return True when all pinned files exist and match."""
    try:
        return not verify(root)
    except FileNotFoundError:
        return False


def main(argv: list[str] | None = None) -> int:
    """CLI entry point."""
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--data-dir", type=Path, default=default_data_dir())
    ap.add_argument("--write-manifest", action="store_true", help="(maintainers) pin hashes")
    args = ap.parse_args(argv)
    root = fetch(args.data_dir, args.write_manifest)
    print(f"dataset ready and verified: {root}")
    return 0


def default_data_dir() -> Path:
    """Dataset directory: ``$SIEM_DATA_DIR`` or ``~/datasets/siem-anomaly``."""
    import os

    return Path(os.environ.get("SIEM_DATA_DIR", Path.home() / "datasets" / "siem-anomaly"))


if __name__ == "__main__":
    sys.exit(main())
