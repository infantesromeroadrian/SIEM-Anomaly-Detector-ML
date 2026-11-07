"""Load the AIT-LDSv2 Apache access logs and their per-line attack labels."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from backend.parsers.nginx import NginxParser

APACHE_DIR = "gather/intranet_server/logs/apache2"
LABEL_DIR = "labels/intranet_server/logs/apache2"
LOG_STEM = "intranet.smith.russellmitchell.com-access.log"
#: Rotated files in chronological order (``.4`` is the oldest).
LOG_SUFFIXES = (4, 3, 2, 1)
#: Split boundaries (UTC), fixed a priori by calendar day, never tuned on test.
TRAIN_END = datetime(2022, 1, 23, tzinfo=timezone.utc)
VAL_END = datetime(2022, 1, 24, tzinfo=timezone.utc)
#: Fine-grained attack labels reported individually (``foothold`` etc. are supersets).
ATTACK_TYPES = (
    "service_scan",
    "dirb",
    "wpscan",
    "webshell_upload",
    "webshell_cmd",
    "escalate",
)


@dataclass
class Event:
    """One parsed access-log line with its ground truth."""

    parsed: dict[str, Any]
    timestamp: datetime
    is_attack: bool
    labels: frozenset[str] = field(default_factory=frozenset)


def read_labels(path: Path) -> dict[int, frozenset[str]]:
    """Return ``{1-based line number: labels}`` for the attack lines of a log file."""
    out: dict[int, frozenset[str]] = {}
    if not path.exists():
        return out
    with path.open() as f:
        for raw in f:
            rec = json.loads(raw)
            out[int(rec["line"])] = frozenset(rec["labels"])
    return out


def load_events(root: Path) -> tuple[list[Event], int]:
    """
    Parse every access log and attach labels.

    Lines without a label entry are benign (the dataset only lists attack lines).

    Returns:
        ``(events sorted by time, number of lines the parser could not parse)``.
    """
    parser = NginxParser()
    events: list[Event] = []
    unparsed = 0
    for suffix in LOG_SUFFIXES:
        name = f"{LOG_STEM}.{suffix}"
        labels = read_labels(root / LABEL_DIR / name)
        with (root / APACHE_DIR / name).open(errors="replace") as f:
            for lineno, line in enumerate(f, start=1):
                line = line.rstrip("\n")
                if not line:
                    continue
                parsed = parser.parse(line)
                if parsed.event_type == "nginx_generic":
                    unparsed += 1
                    continue
                lab = labels.get(lineno, frozenset())
                events.append(Event(parsed.to_dict(), parsed.timestamp, bool(lab), lab))
    events.sort(key=lambda e: e.timestamp)
    return events, unparsed


def split_events(events: list[Event]) -> dict[str, list[int]]:
    """Return index lists for the temporal ``train`` / ``val`` / ``test`` split."""
    idx: dict[str, list[int]] = {"train": [], "val": [], "test": []}
    for i, e in enumerate(events):
        if e.timestamp < TRAIN_END:
            idx["train"].append(i)
        elif e.timestamp < VAL_END:
            idx["val"].append(i)
        else:
            idx["test"].append(i)
    return idx


def load_other_host_events(root: Path) -> tuple[dict[str, list[Event]], int]:
    """
    Load the unlabelled web logs of other hosts, keeping only the test period.

    The dataset ships labels only for files that contain attack lines, so these logs are benign by
    its convention. Each vhost keeps its own stream so window features are not mixed across hosts.

    Returns:
        ``({vhost: events at or after VAL_END, sorted}, unparsed line count)``.
    """
    from backend.eval.fetch import OTHER_HOST_LOGS

    parser = NginxParser()
    streams: dict[str, list[Event]] = {}
    unparsed = 0
    for rel in OTHER_HOST_LOGS:
        vhost = Path(rel).name.split(".")[0]
        with (root / rel).open(errors="replace") as f:
            for line in f:
                line = line.rstrip("\n")
                if not line:
                    continue
                parsed = parser.parse(line)
                if parsed.event_type == "nginx_generic":
                    unparsed += 1
                    continue
                streams.setdefault(vhost, []).append(
                    Event(parsed.to_dict(), parsed.timestamp, False)
                )
    for evs in streams.values():
        evs.sort(key=lambda e: e.timestamp)
    return streams, unparsed
