#!/usr/bin/env python3
"""Maintain a local, cumulative record of CISA KEV CVEs and affected software.

Uses only the Python standard library. Each successful run fetches the current
CISA catalog, updates a SQLite history database, and exports a CSV. Historical
CVEs remain in the output; currently_listed shows whether CISA still includes
them in the latest downloaded feed.
"""

from __future__ import annotations

import argparse
import csv
import datetime as dt
import json
import os
import re
import sqlite3
import sys
import tempfile
import time
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


FEED_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
CVE_PATTERN = re.compile(r"^CVE-[0-9]{4}-[0-9]{4,19}$")
REQUIRED_CATALOG_FIELDS = ("catalogVersion", "dateReleased", "count", "vulnerabilities")
REQUIRED_ENTRY_FIELDS = (
    "cveID", "vendorProject", "product", "vulnerabilityName",
    "dateAdded", "shortDescription", "requiredAction", "dueDate",
)
OPTIONAL_STRING_FIELDS = (
    "knownRansomwareCampaignUse", "forensicTriage", "notes",
)
CSV_FIELDS = (
    "cveID", "vendorProject", "product", "vulnerabilityName", "dateAdded",
    "dueDate", "knownRansomwareCampaignUse", "forensicTriage", "cwes",
    "shortDescription", "requiredAction", "notes", "firstSeenUtc",
    "lastSeenUtc", "currentlyListed", "lastCatalogVersion",
)


class FeedError(Exception):
    """Raised when the remote feed cannot be trusted or parsed."""


def fetch_feed(timeout: float, retries: int) -> dict[str, Any]:
    request = Request(
        FEED_URL,
        headers={
            "User-Agent": "kev-tracker/1.0 (Python standard library)",
            "Accept": "application/json",
        },
    )
    last_error: Exception | None = None
    for attempt in range(retries + 1):
        try:
            with urlopen(request, timeout=timeout) as response:
                if response.status != 200:
                    raise FeedError(f"CISA returned HTTP {response.status}")
                data = json.loads(response.read().decode("utf-8"))
            if not isinstance(data, dict):
                raise FeedError("Feed root must be a JSON object")
            return data
        except (HTTPError, URLError, TimeoutError, UnicodeDecodeError, json.JSONDecodeError, FeedError) as exc:
            last_error = exc
            if attempt < retries:
                time.sleep(min(2 ** attempt, 8))
    raise FeedError(f"Could not fetch a valid CISA KEV feed: {last_error}")


def _check_date(value: Any, label: str, *, date_time: bool = False) -> None:
    if not isinstance(value, str):
        raise FeedError(f"{label} must be a string")
    try:
        if date_time:
            parsed = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
            if parsed.tzinfo is None:
                raise ValueError("timezone missing")
        else:
            dt.date.fromisoformat(value)
    except ValueError as exc:
        raise FeedError(f"{label} has an invalid date value: {value!r}") from exc


def validate_feed(data: dict[str, Any]) -> tuple[str, str, list[dict[str, Any]]]:
    """Check the schema-required envelope and entry fields before writing."""
    missing = [field for field in REQUIRED_CATALOG_FIELDS if field not in data]
    if missing:
        raise FeedError(f"Feed is missing required catalog field(s): {', '.join(missing)}")
    if not isinstance(data["catalogVersion"], str) or not data["catalogVersion"].strip():
        raise FeedError("catalogVersion must be a non-empty string")
    _check_date(data["dateReleased"], "dateReleased", date_time=True)
    count = data["count"]
    entries = data["vulnerabilities"]
    if isinstance(count, bool) or not isinstance(count, int) or count < 0:
        raise FeedError("count must be a non-negative integer")
    if not isinstance(entries, list):
        raise FeedError("vulnerabilities must be an array")
    if count != len(entries):
        raise FeedError(f"Feed count says {count}, but vulnerabilities contains {len(entries)} entries")

    seen: set[str] = set()
    normalized: list[dict[str, Any]] = []
    for index, entry in enumerate(entries):
        label = f"vulnerabilities[{index}]"
        if not isinstance(entry, dict):
            raise FeedError(f"{label} must be an object")
        missing_fields = [field for field in REQUIRED_ENTRY_FIELDS if field not in entry]
        if missing_fields:
            raise FeedError(f"{label} is missing required field(s): {', '.join(missing_fields)}")
        for field in REQUIRED_ENTRY_FIELDS:
            if not isinstance(entry[field], str) or not entry[field].strip():
                raise FeedError(f"{label}.{field} must be a non-empty string")
        cve_id = entry["cveID"]
        if not CVE_PATTERN.fullmatch(cve_id):
            raise FeedError(f"{label}.cveID has an invalid format: {cve_id!r}")
        if cve_id in seen:
            raise FeedError(f"Feed contains duplicate CVE ID {cve_id}")
        seen.add(cve_id)
        _check_date(entry["dateAdded"], f"{label}.dateAdded")
        _check_date(entry["dueDate"], f"{label}.dueDate")
        for field in OPTIONAL_STRING_FIELDS:
            if field in entry and not isinstance(entry[field], str):
                raise FeedError(f"{label}.{field} must be a string when present")
        if "cwes" in entry:
            cwes = entry["cwes"]
            if not isinstance(cwes, list) or any(not isinstance(cwe, str) for cwe in cwes):
                raise FeedError(f"{label}.cwes must be an array of strings when present")
        normalized.append(entry)
    return data["catalogVersion"], data["dateReleased"], normalized


def connect_database(path: Path) -> sqlite3.Connection:
    path.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(path)
    connection.execute("PRAGMA foreign_keys = ON")
    connection.execute(
        """CREATE TABLE IF NOT EXISTS kev_entries (
            cve_id TEXT PRIMARY KEY,
            vendor_project TEXT NOT NULL,
            product TEXT NOT NULL,
            date_added TEXT NOT NULL,
            due_date TEXT NOT NULL,
            raw_json TEXT NOT NULL,
            first_seen_utc TEXT NOT NULL,
            last_seen_utc TEXT NOT NULL,
            last_catalog_version TEXT NOT NULL,
            currently_listed INTEGER NOT NULL CHECK (currently_listed IN (0, 1))
        )"""
    )
    return connection


def update_database(
    connection: sqlite3.Connection,
    version: str,
    entries: list[dict[str, Any]],
) -> tuple[int, int, int]:
    now = dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")
    connection.execute("UPDATE kev_entries SET currently_listed = 0")
    added = changed = 0
    for entry in entries:
        cve_id = entry["cveID"]
        raw_json = json.dumps(entry, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        existing = connection.execute(
            "SELECT raw_json FROM kev_entries WHERE cve_id = ?", (cve_id,)
        ).fetchone()
        if existing is None:
            added += 1
            connection.execute(
                """INSERT INTO kev_entries (
                    cve_id, vendor_project, product, date_added, due_date, raw_json,
                    first_seen_utc, last_seen_utc, last_catalog_version, currently_listed
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 1)""",
                (cve_id, entry["vendorProject"], entry["product"], entry["dateAdded"],
                 entry["dueDate"], raw_json, now, now, version),
            )
        else:
            if existing[0] != raw_json:
                changed += 1
            connection.execute(
                """UPDATE kev_entries SET
                    vendor_project = ?, product = ?, date_added = ?, due_date = ?,
                    raw_json = ?, last_seen_utc = ?, last_catalog_version = ?, currently_listed = 1
                    WHERE cve_id = ?""",
                (entry["vendorProject"], entry["product"], entry["dateAdded"],
                 entry["dueDate"], raw_json, now, version, cve_id),
            )
    connection.commit()
    total = connection.execute("SELECT COUNT(*) FROM kev_entries").fetchone()[0]
    return added, changed, total - len(entries)


def export_csv(connection: sqlite3.Connection, destination: Path) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    fd, temp_name = tempfile.mkstemp(prefix=f".{destination.name}.", suffix=".tmp", dir=destination.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="") as output:
            writer = csv.DictWriter(output, fieldnames=CSV_FIELDS)
            writer.writeheader()
            rows = connection.execute(
                "SELECT cve_id, raw_json, first_seen_utc, last_seen_utc, currently_listed, last_catalog_version "
                "FROM kev_entries ORDER BY date_added, cve_id"
            )
            for cve_id, raw_json, first_seen, last_seen, currently_listed, version in rows:
                entry = json.loads(raw_json)
                writer.writerow({
                    "cveID": cve_id,
                    "vendorProject": entry.get("vendorProject", ""),
                    "product": entry.get("product", ""),
                    "vulnerabilityName": entry.get("vulnerabilityName", ""),
                    "dateAdded": entry.get("dateAdded", ""),
                    "dueDate": entry.get("dueDate", ""),
                    "knownRansomwareCampaignUse": entry.get("knownRansomwareCampaignUse", ""),
                    "forensicTriage": entry.get("forensicTriage", ""),
                    "cwes": ";".join(entry.get("cwes", [])),
                    "shortDescription": entry.get("shortDescription", ""),
                    "requiredAction": entry.get("requiredAction", ""),
                    "notes": entry.get("notes", ""),
                    "firstSeenUtc": first_seen,
                    "lastSeenUtc": last_seen,
                    "currentlyListed": "true" if currently_listed else "false",
                    "lastCatalogVersion": version,
                })
        os.replace(temp_name, destination)
    except Exception:
        try:
            os.unlink(temp_name)
        except FileNotFoundError:
            pass
        raise


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--db", type=Path, default=Path("kev_history.sqlite3"), help="SQLite history database")
    parser.add_argument("--csv", type=Path, default=Path("kev_software_cves.csv"), help="Cumulative CSV export")
    parser.add_argument("--timeout", type=float, default=30.0, help="HTTP timeout in seconds (default: 30)")
    parser.add_argument("--retries", type=int, default=2, help="Retries after a failed request (default: 2)")
    args = parser.parse_args()
    if args.timeout <= 0 or args.retries < 0:
        parser.error("--timeout must be positive and --retries cannot be negative")

    try:
        feed = fetch_feed(args.timeout, args.retries)
        version, released, entries = validate_feed(feed)
        connection = connect_database(args.db)
        try:
            added, changed, historical_only = update_database(connection, version, entries)
            export_csv(connection, args.csv)
        finally:
            connection.close()
    except (FeedError, OSError, sqlite3.Error, csv.Error) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1

    print(f"CISA KEV catalog {version} (released {released})")
    print(f"Current feed entries: {len(entries)} | newly recorded: {added} | changed: {changed}")
    print(f"Cumulative records: {historical_only + len(entries)} | no longer in current feed: {historical_only}")
    print(f"Database: {args.db} | CSV: {args.csv}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
