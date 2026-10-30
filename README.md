# cisa-kev-list

A small Python utility that downloads CISA's Known Exploited Vulnerabilities (KEV) JSON feed and maintains a cumulative record of CVEs and affected software.

## Standalone Python tracker

### Requirements

- Python 3.10 or newer
- Network access to the CISA KEV JSON feed
- No third-party Python packages

### Run

```bash
python kev_tracker.py
```

The command creates or updates:

- `kev_history.sqlite3` — SQLite history database and source of truth
- `kev_software_cves.csv` — cumulative spreadsheet-friendly export

Both files are written to the current working directory. Use `--db` and `--csv` to choose other paths:

```bash
python kev_tracker.py --db data/kev_history.sqlite3 --csv data/kev_software_cves.csv
```

Run the script again whenever you want to refresh the list, or schedule it with Task Scheduler or cron. Existing CVEs remain in the cumulative output; `currentlyListed` indicates whether a CVE appeared in the latest successful feed refresh. The script also records first/last observation times and updates changed CISA fields.

## Splunk SOAR playbook

[`kev_tracker_soar_playbook.py`](kev_tracker_soar_playbook.py) is the SOAR-native version. It does not use SQLite; it uses Splunk SOAR's Custom Lists API to persist the cumulative catalog between runs.

### Configure and run

1. In Splunk SOAR, create an empty Custom List named `cisa_kev_catalog` with 16 columns.
2. Use the column order in `ROW_FIELDS` near the top of the playbook source: `cveID`, `vendorProject`, `product`, `vulnerabilityName`, `dateAdded`, `dueDate`, `knownRansomwareCampaignUse`, `forensicTriage`, `cwes`, `shortDescription`, `requiredAction`, `notes`, `firstSeenUtc`, `lastSeenUtc`, `currentlyListed`, `lastCatalogVersion`.
3. Add the source as a Python playbook in SOAR and run it on a schedule or manually. The SOAR execution environment needs outbound HTTPS access to the CISA feed.

The playbook validates the feed before modifying the list. It updates existing CVEs, appends newly observed CVEs, and retains historical rows with `currentlyListed=false` if an entry is absent from a later feed. Avoid overlapping executions because each run replaces the list contents as one cumulative snapshot.

The standalone SQLite database and CSV are local outputs. Neither version automatically commits its generated data back to GitHub.
