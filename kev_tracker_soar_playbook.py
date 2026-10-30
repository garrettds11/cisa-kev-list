"""Splunk SOAR playbook source for maintaining a cumulative CISA KEV list.

Import or paste this source into a Splunk SOAR playbook's code editor. The
playbook uses the SOAR Custom Lists API for persistence and does not use SQLite.

Before the first run, create an empty Custom List named ``cisa_kev_catalog``
with 16 columns. Column order is defined by ROW_FIELDS below. Each subsequent
run replaces the rows from the validated current feed while retaining historical
CVEs and marking them currentlyListed=false.
"""

import datetime
import json
import re
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

import phantom.rules as phantom


REPOSITORY_SNAPSHOT_URL = (
    "https://raw.githubusercontent.com/garrettds11/cisa-kev-list/main/data/kev-current.json"
)
CISA_FEED_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
CUSTOM_LIST_NAME = "cisa_kev_catalog"
CVE_PATTERN = re.compile(r"^CVE-[0-9]{4}-[0-9]{4,19}$")
REQUIRED_CATALOG_FIELDS = ("catalogVersion", "dateReleased", "count", "vulnerabilities")
REQUIRED_ENTRY_FIELDS = (
    "cveID", "vendorProject", "product", "vulnerabilityName",
    "dateAdded", "shortDescription", "requiredAction", "dueDate",
)
ROW_FIELDS = (
    "cveID", "vendorProject", "product", "vulnerabilityName", "dateAdded",
    "dueDate", "knownRansomwareCampaignUse", "forensicTriage", "cwes",
    "shortDescription", "requiredAction", "notes", "firstSeenUtc",
    "lastSeenUtc", "currentlyListed", "lastCatalogVersion",
)
ROW_WIDTH = len(ROW_FIELDS)


def _utc_now():
    return datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds")


def _fetch_feed():
    last_error = None
    for source_url in (REPOSITORY_SNAPSHOT_URL, CISA_FEED_URL):
        request = Request(
            source_url,
            headers={
                "User-Agent": "cisa-kev-soar-playbook/1.0",
                "Accept": "application/json",
            },
        )
        for attempt in range(3):
            try:
                with urlopen(request, timeout=30) as response:
                    if response.status != 200:
                        raise RuntimeError("Source returned HTTP {}".format(response.status))
                    payload = json.loads(response.read().decode("utf-8"))
                if not isinstance(payload, dict):
                    raise RuntimeError("Feed root must be a JSON object")
                return payload
            except (HTTPError, URLError, TimeoutError, UnicodeDecodeError, ValueError, RuntimeError) as exc:
                last_error = exc
                if attempt < 2:
                    import time
                    time.sleep(2 ** attempt)
    raise RuntimeError("Unable to fetch a valid CISA KEV feed: {}".format(last_error))


def _validate_feed(payload):
    if payload.get("schemaVersion") == "1.0":
        source = payload.get("source")
        if not isinstance(source, dict):
            raise RuntimeError("Published snapshot source metadata must be an object")
        version = source.get("catalogVersion")
        released = source.get("dateReleased")
        count = payload.get("recordCount")
        entries = payload.get("records")
    else:
        version = payload.get("catalogVersion")
        released = payload.get("dateReleased")
        count = payload.get("count")
        entries = payload.get("vulnerabilities")
    if not isinstance(version, str) or not version.strip():
        raise RuntimeError("catalogVersion must be a non-empty string")
    if not isinstance(released, str):
        raise RuntimeError("dateReleased must be a string")
    missing = [field for field in REQUIRED_CATALOG_FIELDS if field not in payload]
    if payload.get("schemaVersion") != "1.0" and missing:
        raise RuntimeError("Feed is missing catalog field(s): {}".format(", ".join(missing)))
    if not isinstance(released, str):
        raise RuntimeError("dateReleased must be a string")
    try:
        parsed_release = datetime.datetime.fromisoformat(released.replace("Z", "+00:00"))
        if parsed_release.tzinfo is None:
            raise ValueError("timezone missing")
    except ValueError as exc:
        raise RuntimeError("dateReleased is not a valid date-time: {}".format(released)) from exc
    if isinstance(count, bool) or not isinstance(count, int) or count < 0:
        raise RuntimeError("count must be a non-negative integer")
    if not isinstance(entries, list) or count != len(entries):
        raise RuntimeError("Feed count does not match its vulnerabilities array")
    if not entries:
        raise RuntimeError("Refusing to replace the saved catalog with an empty feed")

    seen = set()
    for index, entry in enumerate(entries):
        label = "vulnerabilities[{}]".format(index)
        if not isinstance(entry, dict):
            raise RuntimeError("{} must be an object".format(label))
        missing_fields = [field for field in REQUIRED_ENTRY_FIELDS if field not in entry]
        if missing_fields:
            raise RuntimeError("{} is missing field(s): {}".format(label, ", ".join(missing_fields)))
        for field in REQUIRED_ENTRY_FIELDS:
            if not isinstance(entry[field], str) or not entry[field].strip():
                raise RuntimeError("{}.{} must be a non-empty string".format(label, field))
        cve_id = entry["cveID"]
        if not CVE_PATTERN.match(cve_id):
            raise RuntimeError("{}.cveID has an invalid format: {}".format(label, cve_id))
        if cve_id in seen:
            raise RuntimeError("Feed contains duplicate CVE ID {}".format(cve_id))
        seen.add(cve_id)
        for field in ("dateAdded", "dueDate"):
            try:
                datetime.date.fromisoformat(entry[field])
            except (TypeError, ValueError) as exc:
                raise RuntimeError("{}.{} is not a valid date".format(label, field)) from exc
        for field in ("knownRansomwareCampaignUse", "forensicTriage", "notes"):
            if field in entry and not isinstance(entry[field], str):
                raise RuntimeError("{}.{} must be a string when present".format(label, field))
        if "cwes" in entry and (
            not isinstance(entry["cwes"], list)
            or any(not isinstance(cwe, str) for cwe in entry["cwes"])
        ):
            raise RuntimeError("{}.cwes must be an array of strings when present".format(label))
    return version, released, entries


def _read_existing_rows():
    success, message, rows = phantom.get_list(list_name=CUSTOM_LIST_NAME)
    if not success:
        raise RuntimeError(
            "Could not read SOAR Custom List '{}': {}. Create the empty list with 16 columns first."
            .format(CUSTOM_LIST_NAME, message)
        )
    if rows is None:
        return []
    if not isinstance(rows, list):
        raise RuntimeError("SOAR Custom List data is not a list of rows")
    normalized = []
    for index, row in enumerate(rows):
        if not isinstance(row, (list, tuple)) or len(row) != ROW_WIDTH:
            raise RuntimeError(
                "SOAR Custom List row {} must have exactly {} columns; refusing to overwrite it"
                .format(index, ROW_WIDTH)
            )
        normalized.append(["" if value is None else str(value) for value in row])
    return normalized


def _row_for_entry(entry, version, now, prior_row=None):
    prior = prior_row or [""] * ROW_WIDTH
    return [
        entry["cveID"],
        entry["vendorProject"],
        entry["product"],
        entry["vulnerabilityName"],
        entry["dateAdded"],
        entry["dueDate"],
        entry.get("knownRansomwareCampaignUse", ""),
        entry.get("forensicTriage", ""),
        ";".join(entry.get("cwes", [])),
        entry["shortDescription"],
        entry["requiredAction"],
        entry.get("notes", ""),
        entry.get("firstSeenUtc") or prior[12] or now,
        entry.get("lastSeenUtc") or now,
        "true",
        entry.get("lastCatalogVersion") or version,
    ]


def on_start(container):
    """Fetch CISA KEV and refresh the cumulative SOAR Custom List."""
    try:
        payload = _fetch_feed()
        version, released, entries = _validate_feed(payload)
        old_rows = _read_existing_rows()
        previous = {row[0]: row for row in old_rows if row[0]}
        current_ids = set(entry["cveID"] for entry in entries)
        now = _utc_now()

        new_count = sum(1 for entry in entries if entry["cveID"] not in previous)
        changed_count = 0
        updated_rows = []
        for entry in entries:
            old = previous.get(entry["cveID"])
            row = _row_for_entry(entry, version, now, old)
            if old is not None and row[:12] != old[:12]:
                changed_count += 1
            updated_rows.append(row)

        # Keep prior rows absent from the current feed, but mark them inactive.
        for cve_id, old in previous.items():
            if cve_id not in current_ids:
                historical = list(old)
                historical[14] = "false"
                updated_rows.append(historical)

        success, message = phantom.set_list(
            list_name=CUSTOM_LIST_NAME,
            values=updated_rows,
        )
        if not success:
            raise RuntimeError("Could not update SOAR Custom List: {}".format(message))

        phantom.debug(
            "CISA KEV sync complete: version={}, released={}, current={}, new={}, "
            "changed={}, cumulative={}, no_longer_listed={}".format(
                version,
                released,
                len(entries),
                new_count,
                changed_count,
                len(updated_rows),
                len(updated_rows) - len(entries),
            )
        )
    except Exception as exc:
        phantom.debug("CISA KEV sync failed: {}".format(exc))
        raise


def on_finish(container, summary):
    return
