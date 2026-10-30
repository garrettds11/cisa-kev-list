# cisa-kev-list

A small Python utility that downloads CISA's Known Exploited Vulnerabilities (KEV) feed, maintains a cumulative record, and publishes stable snapshots for automation consumers.

## Standalone Python tracker

The original standalone workflow remains available:

```bash
python kev_tracker.py
```

It creates or updates `kev_history.sqlite3` and `kev_software_cves.csv` in the current directory. Use `--db` and `--csv` to choose other paths. It requires Python 3.10 or newer and uses no third-party packages.

## Splunk SOAR playbook

[`kev_tracker_soar_playbook.py`](kev_tracker_soar_playbook.py) uses a SOAR Custom List for persistence. It first tries this repository's published snapshot and falls back to CISA's feed. Create an empty Custom List named `cisa_kev_catalog` with 16 columns in the order declared by `ROW_FIELDS`, then add the source as a Python playbook. The SOAR runner needs outbound HTTPS access to GitHub or CISA.

## Published snapshots for other automation tools

A scheduled GitHub Actions workflow publishes versioned data files on weekdays and can also be run manually. The first successful run creates the `data/` files.

| Snapshot | URL |
|---|---|
| Current JSON | [kev-current.json](https://raw.githubusercontent.com/garrettds11/cisa-kev-list/main/data/kev-current.json) |
| Cumulative JSON | [kev-cumulative.json](https://raw.githubusercontent.com/garrettds11/cisa-kev-list/main/data/kev-cumulative.json) |
| Current CSV | [kev-current.csv](https://raw.githubusercontent.com/garrettds11/cisa-kev-list/main/data/kev-current.csv) |
| Cumulative CSV | [kev-cumulative.csv](https://raw.githubusercontent.com/garrettds11/cisa-kev-list/main/data/kev-cumulative.csv) |

The JSON contract is versioned at [schemas/kev-snapshot.schema.json](schemas/kev-snapshot.schema.json). Integration examples and refresh behavior are in [docs/automation-integrations.md](docs/automation-integrations.md).

The publisher keeps CISA fields and adds observation metadata: first seen, last seen, current listing status, and last catalog version. Git history retains prior published snapshots. Do not add private asset inventory or other organization-specific data to these public files.

The standalone SQLite database and CSV remain local outputs. The GitHub workflow publishes only public CISA catalog data and its observation metadata.
