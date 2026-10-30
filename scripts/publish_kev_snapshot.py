#!/usr/bin/env python3
"""Refresh stable JSON/CSV snapshots for automation consumers.

This publisher is separate from kev_tracker.py. Its JSON files are committed by
the repository workflow, making them readable by automation tools that cannot
share the standalone script's SQLite database.
"""

import csv
import datetime as dt
import json
import os
import re
import sys
import tempfile
import time
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


ROOT = Path(__file__).resolve().parents[1]
DATA_DIR = ROOT / "data"
HISTORY_PATH = DATA_DIR / "kev-history.json"
FEED_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
CVE_PATTERN = re.compile(r"^CVE-[0-9]{4}-[0-9]{4,19}$")
REQUIRED_CATALOG_FIELDS = ("catalogVersion", "dateReleased", "count", "vulnerabilities")
REQUIRED_ENTRY_FIELDS = (
    "cveID", "vendorProject", "product", "vulnerabilityName",
    "dateAdded", "shortDescription", "requiredAction", "dueDate",
)
CSV_FIELDS = (
    "cveID", "vendorProject", "product", "vulnerabilityName", "dateAdded",
    "dueDate", "knownRansomwareCampaignUse", "forensicTriage", "cwes",
    "shortDescription", "requiredAction", "notes", "firstSeenUtc",
    "lastSeenUtc", "currentlyListed", "lastCatalogVersion",
)


class FeedError(Exception):
    pass


def fetch_feed():
    request = Request(
        FEED_URL,
        headers={"User-Agent": "cisa-kev-list-publisher/1.0", "Accept": "application/json"},
    )
    last_error = None
    for attempt in range(3):
        try:
            with urlopen(request, timeout=30) as response:
                if response.status != 200:
                    raise FeedError("CISA returned HTTP {}".format(response.status))
                payload = json.loads(response.read().decode("utf-8"))
            if not isinstance(payload, dict):
                raise FeedError("Feed root must be a JSON object")
            return payload
        except (HTTPError, URLError, TimeoutError, UnicodeDecodeError, ValueError, FeedError) as exc:
            last_error = exc
            if attempt < 2:
                time.sleep(2 ** attempt)
    raise FeedError("Unable to fetch a valid CISA KEV feed: {}".format(last_error))


def validate_feed(payload):
    missing = [field for field in REQUIRED_CATALOG_FIELDS if field not in payload]
    if missing:
        raise FeedError("Feed is missing catalog field(s): {}".format(", ".join(missing)))
    version = payload["catalogVersion"]
    released = payload["dateReleased"]
    count = payload["count"]
    entries = payload["vulnerabilities"]
    if not isinstance(version, str) or not version.strip():
        raise FeedError("catalogVersion must be a non-empty string")
    if not isinstance(released, str):
        raise FeedError("dateReleased must be a string")
    try:
        release_time = dt.datetime.fromisoformat(released.replace("Z", "+00:00"))
        if release_time.tzinfo is None:
            raise ValueError("timezone missing")
    except ValueError as exc:
        raise FeedError("dateReleased is invalid: {}".format(released)) from exc
    if isinstance(count, bool) or not isinstance(count, int) or count < 1:
        raise FeedError("count must be a positive integer")
    if not isinstance(entries, list) or count != len(entries):
        raise FeedError("count does not match vulnerabilities array")

    seen = set()
    for index, entry in enumerate(entries):
        label = "vulnerabilities[{}]".format(index)
        if not isinstance(entry, dict):
            raise FeedError("{} must be an object".format(label))
        missing_fields = [field for field in REQUIRED_ENTRY_FIELDS if field not in entry]
        if missing_fields:
            raise FeedError("{} is missing: {}".format(label, ", ".join(missing_fields)))
        for field in REQUIRED_ENTRY_FIELDS:
            if not isinstance(entry[field], str) or not entry[field].strip():
                raise FeedError("{}.{} must be a non-empty string".format(label, field))
        cve_id = entry["cveID"]
        if not CVE_PATTERN.fullmatch(cve_id):
            raise FeedError("{}.cveID has an invalid format: {}".format(label, cve_id))
        if cve_id in seen:
            raise FeedError("Duplicate CVE ID in feed: {}".format(cve_id))
        seen.add(cve_id)
        for field in ("dateAdded", "dueDate"):
            try:
                dt.date.fromisoformat(entry[field])
            except ValueError as exc:
                raise FeedError("{}.{} is an invalid date".format(label, field)) from exc
        for field in ("knownRansomwareCampaignUse", "forensicTriage", "notes"):
            if field in entry and not isinstance(entry[field], str):
                raise FeedError("{}.{} must be a string when present".format(label, field))
        if "cwes" in entry and (
            not isinstance(entry["cwes"], list)
            or any(not isinstance(cwe, str) for cwe in entry["cwes"])
        ):
            raise FeedError("{}.cwes must be an array of strings".format(label))
    return version, released, entries


def load_history():
    if not HISTORY_PATH.exists():
        return {"schemaVersion": "1.0", "records": {}}
    try:
        state = json.loads(HISTORY_PATH.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise FeedError("Cannot read existing history file safely: {}".format(exc)) from exc
    if not isinstance(state, dict) or state.get("schemaVersion") != "1.0":
        raise FeedError("History file has an unsupported structure or schema version")
    if not isinstance(state.get("records"), dict):
        raise FeedError("History file records must be an object keyed by CVE ID")
    return state


def merge_records(state, version, entries):
    now = dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")
    records = state["records"]
    for record_id, record in records.items():
        if not isinstance(record, dict) or record.get("cveID") != record_id:
            raise FeedError("History file contains an invalid record for {}".format(record_id))
        record["currentlyListed"] = False

    for entry in entries:
        cve_id = entry["cveID"]
        previous = records.get(cve_id)
        if previous is not None and not isinstance(previous, dict):
            raise FeedError("History record for {} is invalid".format(cve_id))
        record = dict(entry)
        record["firstSeenUtc"] = previous.get("firstSeenUtc", now) if previous else now
        if (previous is None or _source_fields(previous) != _source_fields(record)
                or previous.get("lastCatalogVersion") != version):
            record["lastSeenUtc"] = now
        else:
            record["lastSeenUtc"] = previous.get("lastSeenUtc", now)
        record["currentlyListed"] = True
        record["lastCatalogVersion"] = version
        records[cve_id] = record
    return records


def _source_fields(record):
    return {key: value for key, value in record.items()
            if key not in ("firstSeenUtc", "lastSeenUtc", "currentlyListed", "lastCatalogVersion")}


def _atomic_write(path, content):
    path.parent.mkdir(parents=True, exist_ok=True)
    encoded = content.encode("utf-8")
    if path.exists() and path.read_bytes() == encoded:
        return False
    fd, temporary = tempfile.mkstemp(prefix="." + path.name + ".", suffix=".tmp", dir=str(path.parent))
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(encoded)
        os.replace(temporary, str(path))
    except Exception:
        try:
            os.unlink(temporary)
        except OSError:
            pass
        raise
    return True


def _json_document(version, released, records, *, current_only):
    selected = [row for row in records.values() if row["currentlyListed"] or not current_only]
    selected.sort(key=lambda row: (row["dateAdded"], row["cveID"]))
    return {
        "schemaVersion": "1.0",
        "source": {
            "name": "CISA Known Exploited Vulnerabilities Catalog",
            "feedUrl": FEED_URL,
            "catalogVersion": version,
            "dateReleased": released,
            "currentFeedCount": sum(1 for row in records.values() if row["currentlyListed"]),
        },
        "recordCount": len(selected),
        "records": selected,
    }


def _csv_document(records, *, current_only):
    selected = [row for row in records.values() if row["currentlyListed"] or not current_only]
    selected.sort(key=lambda row: (row["dateAdded"], row["cveID"]))
    from io import StringIO
    output = StringIO(newline="")
    writer = csv.DictWriter(output, fieldnames=CSV_FIELDS, extrasaction="ignore")
    writer.writeheader()
    for record in selected:
        row = dict(record)
        row["cwes"] = ";".join(record.get("cwes", []))
        row["currentlyListed"] = "true" if record["currentlyListed"] else "false"
        writer.writerow(row)
    return output.getvalue()


def main():
    try:
        payload = fetch_feed()
        version, released, entries = validate_feed(payload)
        state = load_history()
        records = merge_records(state, version, entries)
        state["source"] = {
            "name": "CISA Known Exploited Vulnerabilities Catalog",
            "feedUrl": FEED_URL,
            "catalogVersion": version,
            "dateReleased": released,
            "currentFeedCount": len(entries),
        }
        history_json = json.dumps(state, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
        current_json = json.dumps(
            _json_document(version, released, records, current_only=True),
            ensure_ascii=False, indent=2, sort_keys=True,
        ) + "\n"
        cumulative_json = json.dumps(
            _json_document(version, released, records, current_only=False),
            ensure_ascii=False, indent=2, sort_keys=True,
        ) + "\n"
        outputs = (
            (HISTORY_PATH, history_json),
            (DATA_DIR / "kev-current.json", current_json),
            (DATA_DIR / "kev-cumulative.json", cumulative_json),
            (DATA_DIR / "kev-current.csv", _csv_document(records, current_only=True)),
            (DATA_DIR / "kev-cumulative.csv", _csv_document(records, current_only=False)),
        )
        changed = [str(path.relative_to(ROOT)) for path, content in outputs if _atomic_write(path, content)]
    except (FeedError, OSError, csv.Error) as exc:
        print("ERROR: {}".format(exc), file=sys.stderr)
        return 1

    print("CISA KEV {}: {} current CVEs, {} cumulative CVEs".format(
        version, len(entries), len(records)))
    if changed:
        print("Updated: {}".format(", ".join(changed)))
    else:
        print("No data changes to publish")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
