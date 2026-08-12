# Flux accounting database migration incident

This repository contains the standalone SQLite portion of the Flux Framework
accounting database upgrade path. HPC sites use this database to retain user
and bank associations, completed job records, historical resource usage, and
the state used to derive fair-share priorities.

The included snapshot is based on the `flux-framework/flux-accounting`
database migration code immediately before the fixes recorded in upstream
issue 903 and pull request 904. The failure is observable without a running
Flux broker: a legacy usage layout is upgraded to schema 37, but its historical
usage may be absent after the command reports success. A second public change,
pull request 916, records the need to retain the pre-upgrade database when a
migration fails.

The source remains under LGPL-3.0. See `LICENSE`, `NOTICE.LLNS`,
`DISCLAIMER.LLNS`, and `UPSTREAM.md`.

## Runtime

- Linux
- Python 3.13
- Python standard library only
- SQLite supplied by Python's `sqlite3` module
- no network access required

## Reproduce

```bash
./scripts/reproduce-incident.sh
```

The script creates its work directory under `.incident-work`, runs the database
upgrade, inspects the resulting schema and historical usage rows, and verifies
that a forced migration failure is not safely recoverable in the starter.

## Commands

```bash
./bin/flux-account-update-db -p OLD.db -n TARGET-SCHEMA.db
./bin/flux-account-update-usage -p UPDATED.db
./scripts/inspect-db.py UPDATED.db
```

Paths may be relative or absolute. The tools do not require a Flux daemon or a
batch scheduler.
