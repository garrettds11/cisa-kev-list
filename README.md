# cisa-kev-list

A small Python utility that downloads CISA's Known Exploited Vulnerabilities (KEV) JSON feed and maintains a cumulative local record of CVEs and affected software.

## Requirements

- Python 3.10 or newer
- Network access to the CISA KEV JSON feed
- No third-party Python packages

## Run

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

The database and CSV are local outputs. Running the script does not automatically commit or upload them to GitHub.
