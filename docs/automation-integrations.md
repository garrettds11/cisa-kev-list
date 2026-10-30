# Automation integration contract

The repository keeps the original standalone tracker and provides separate adapters and published data for automation platforms.

## Stable snapshot URLs

After the scheduled publisher has run, consumers can fetch these public raw files:

- `https://raw.githubusercontent.com/garrettds11/cisa-kev-list/main/data/kev-current.json` — entries present in the latest CISA catalog.
- `https://raw.githubusercontent.com/garrettds11/cisa-kev-list/main/data/kev-cumulative.json` — all locally observed entries, including records absent from the latest catalog.
- `https://raw.githubusercontent.com/garrettds11/cisa-kev-list/main/data/kev-current.csv` — current entries as CSV.
- `https://raw.githubusercontent.com/garrettds11/cisa-kev-list/main/data/kev-cumulative.csv` — cumulative history as CSV.

The JSON envelope is defined by [`schemas/kev-snapshot.schema.json`](../schemas/kev-snapshot.schema.json). It has a `schemaVersion`, source catalog metadata, a `recordCount`, and `records`. CISA fields are retained, with these repository fields added:

- `firstSeenUtc`: first time this publisher recorded the CVE.
- `lastSeenUtc`: last time the CISA entry content changed or the catalog version changed.
- `currentlyListed`: whether the CVE is in the latest downloaded feed.
- `lastCatalogVersion`: most recent catalog version in which the CVE appeared.

Consumers should check `schemaVersion` and `source.catalogVersion`. Treat new unrecognized record fields as additive and ignore them unless needed.

## Integration choices

1. **Read a published snapshot.** Use an HTTP GET from SOAR, a Logic App, n8n, Tines, a SIEM search job, or another workflow runner. This is read-only and avoids sharing a database.
2. **Run the standalone tracker.** Use `kev_tracker.py` when the automation can run Python and needs SQLite/CSV output local to its host.
3. **Use a platform adapter.** Keep platform-specific persistence and actions in their own adapter. The Splunk SOAR playbook uses a SOAR Custom List; other adapters can write to their own platform's storage.

The published snapshots contain public CISA data plus observation timestamps. Do not add organization-specific asset inventories or other private data to these files.

## Refresh behavior

`.github/workflows/publish-kev.yml` runs on weekdays and supports manual dispatch. It fetches and validates CISA's feed, updates the cumulative history, and commits only changed snapshots. Git history preserves prior published versions. The first successful run creates the `data/` files.
