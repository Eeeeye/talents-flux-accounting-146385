# Repair the Flux accounting database upgrade path

An HPC site is upgrading a Flux accounting SQLite database from the legacy
column-per-period usage layout to schema version 37. The database stores user
and bank associations, completed jobs, and the historical usage that feeds
fair-share priority decisions. The migration command currently reports success
while silently dropping that history. Retrying a previously interrupted
migration also leaves associations incomplete, and a failed migration does not
provide a recoverable pre-upgrade database.

Work in `/workspace/flux-accounting`.

## Reproduce the incident

```bash
./scripts/reproduce-incident.sh
```

The starter deterministically reports three observed failures. These are
symptoms, not an exhaustive description of the affected inputs.

## Required behavior

Repair the implementation so that `bin/flux-account-update-db` satisfies all
of the following requirements.

### Schema preservation

- The command accepts `-p/--path OLD.db` and `-n/--new-db TARGET.db` exactly as
  documented by `--help`.
- It adds tables that exist in the target schema but not in the old database.
- Every target table must retain its complete declared primary key, including
  ordered composite primary keys.
- For tables present in both databases, the final column set and primary key
  must match the target schema. Values in columns shared by both schemas must
  be preserved.
- Existing rows and tables unrelated to a schema change must remain intact.
- A successful migration sets `PRAGMA user_version` to `37`, and
  `PRAGMA integrity_check` must return `ok`.

### Legacy usage migration

The legacy `job_usage_factor_table` may contain zero or more columns named
`usage_factor_period_N`, where `N` is a non-negative decimal integer. The
columns may appear in any physical column order and the sequence of `N` values
need not be contiguous.

For every legacy association `(username, userid, bank)` and every legacy
period column, the upgraded `job_usage_per_association_table` must contain the
row:

```text
(username, userid, bank, period=N, value=legacy_column_value)
```

The destination identity is `(username, bank, period)`. Associations sharing a
username but using different banks must remain distinct. Numeric values,
including zero, negative, fractional, and large finite values, must be
preserved as SQLite numeric values.

The migration must also repair a destination table that was only partially
populated by an earlier attempt. Existing correct rows may be retained, but
missing rows must be added and conflicting rows must be replaced with the
legacy source value. Re-running the command after success must be idempotent:
it must neither duplicate nor erase usage rows.

If no legacy period columns exist, the command must still perform an ordinary
schema upgrade without inventing usage values.

### Failure safety and backup

- Before modifying the database at `OLD.db`, checkpoint any committed WAL state
  into the main file, then create a byte-for-byte copy at `OLD.db.backup`. The
  backup path is the original path with the literal suffix `.backup`, including
  when the original filename contains spaces.
- The backup must represent the database state immediately before the current
  invocation. A repeated invocation must refresh a stale backup rather than
  silently reusing it.
- The backup must be a valid standalone SQLite database. Do not rely on an
  uncheckpointed WAL file beside it.
- If migration fails for any reason after the input paths are validated, exit
  non-zero and leave `OLD.db` byte-for-byte equal to `OLD.db.backup`.
- A failed migration must not advance `PRAGMA user_version` or leave temporary
  tables in the restored database.
- Missing source or target databases, and either input path being a directory or
  symbolic link rather than a regular file, must be rejected with a non-zero
  exit code before a migration begins.

### Downstream compatibility

After a successful migration, this command must succeed without schema or
uniqueness errors:

```bash
./bin/flux-account-update-usage -p OLD.db
```

Its JSON result must include every association, and repeated usage updates
must not create duplicate period rows.

## Preserved interfaces

- Keep the two public executables under `bin/` and their existing flags.
- Keep the database schema version at 37.
- Use only Python's standard library and SQLite. The task is self-contained;
  installing packages or making the repair depend on network access is not
  permitted.
- Do not weaken SQLite constraints, disable foreign-key handling, replace the
  migration with a database-specific hard-coded dump, or special-case the
  supplied fixture values.

## Allowed changes

You may modify:

- `src/**`
- `bin/**`

Do not modify or replace:

- `scripts/make-incident-db.py`
- `scripts/inspect-db.py`
- `scripts/reproduce-incident.sh`
- `scripts/offline-check.sh`
- `.dockerignore`, `.gitignore`, `Makefile`, `LICENSE`, `NOTICE.LLNS`,
  `DISCLAIMER.LLNS`, `UPSTREAM.md`, or `README.md`

The verifier supplies additional databases at grading time. It inspects the
SQLite files independently and does not trust candidate-emitted summaries.
