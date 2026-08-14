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
- Every target table must retain its complete declared table definition,
  including ordered composite primary keys, UNIQUE constraints, CHECK
  constraints, and foreign keys.
- Definition fidelity is checked against the target table's
  `sqlite_master.sql` body from its opening `(` onward after collapsing runs of
  whitespace. Column and constraint order therefore matter; only whitespace
  formatting and the spelling/quoting of the table name before `(` are ignored.
- For tables present in both databases, the final column set and primary key
  must exactly match the target schema. A source column absent from that target
  table is removed as part of the schema change; values in columns shared by
  both schemas must be preserved.
- A target-only column receives the behavior declared by the target table: an
  omitted column uses its declared DEFAULT or NULL where SQLite permits it. If
  existing rows cannot satisfy a target-only column (for example, it is NOT
  NULL and has no DEFAULT), the migration must fail and follow the post-backup
  recovery requirements below; inventing a value is not permitted.
- This rule also applies when a table exists in both databases but has no
  column names in common. Each existing source row must still produce one
  target row using only the target table's DEFAULT/NULL behavior. If target
  constraints make that impossible, the migration must fail rather than drop
  the source rows.
- Existing rows and tables unrelated to a schema change must remain intact.
- A successful migration sets `PRAGMA user_version` to `37`, and
  `PRAGMA integrity_check` must return `ok`.

### Legacy usage migration

The legacy `job_usage_factor_table` may contain zero or more columns whose
case-sensitive name is exactly `usage_factor_period_N`. `N` is the canonical
base-10 spelling of an integer from `0` through `9223372036854775807`: either
`0` or a nonzero ASCII digit followed by zero or more ASCII digits, with no
leading zero. Names with a different case, non-ASCII digits, a leading zero,
or an out-of-range suffix are not legacy period columns. The columns may appear
in any physical column order and the sequence of `N` values need not be
contiguous. The destination `period` is that suffix interpreted as an integer.
It must be bound directly as a SQLite INTEGER, including the maximum value;
conversion through REAL is not permitted.

The legacy table's declared primary key guarantees at most one source row for
each `(username, bank)`. For every legacy association
`(username, userid, bank)` and every legacy period column, the upgraded
`job_usage_per_association_table` must contain the row:

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
- Failure before a fresh backup is atomically published must leave `OLD.db`
  unchanged, must not restore an older `.backup` over it, and must leave any
  pre-existing `.backup` intact.
- If a migration operation fails after the fresh backup has been published —
  while reading the target schema, rebuilding or copying tables, migrating
  usage, initializing required configuration, or running final integrity and
  foreign-key checks — exit non-zero and leave `OLD.db` byte-for-byte equal to
  `OLD.db.backup`. Remove transient `OLD.db-wal`, `OLD.db-shm`, and
  `OLD.db-journal` sidecars before atomically restoring `OLD.db`; keep the fresh
  `.backup` available.
- A failed migration must not advance `PRAGMA user_version` or leave temporary
  tables in the restored database.
- Missing source databases and, when `-n` is supplied, missing target databases
  must be rejected before migration. Both explicit input paths must name
  existing regular files; directories and symbolic links are rejected. The
  internally generated target used when `-n` is omitted is not an external
  input and is exempt from this preflight check.
- When `-n` is omitted, the command must generate the bundled schema-version-37
  target through the existing `fluxacct.accounting.create_db` interface.
  When `-n` is supplied, `TARGET.db` must be a different physical file from
  `OLD.db`; the same path or a hard link to the source must be rejected before
  backup or migration work begins.

The caller must provide exclusive access to both database files for the
duration of the command. Concurrent readers/writers, forced termination,
kernel failure, and power loss are outside the required failure model. The
failure guarantees above apply to ordinary process errors and exceptions that
the command can catch.

Byte equality means equality of every byte in the SQLite main database file;
file ownership, mode bits, and timestamps are not compared. After a fresh
backup is published, recovery must prepare a replacement in the source
directory and atomically replace the main database after removing transient
WAL/SHM/journal sidecars. Atomicity against forced termination, kernel failure,
or power loss remains outside the required model above.

### Downstream compatibility

After a successful migration, this command must succeed without schema or
uniqueness errors:

```bash
./bin/flux-account-update-usage -p OLD.db
```

It must write one JSON object to standard output with exactly these top-level
members:

```json
{
  "database": "OLD.db",
  "associations": [
    {"username": "alice", "bank": "science", "job_usage": 12.5}
  ]
}
```

`database` is the path argument as supplied. `associations` is an array with
one object for every association; each object has exactly the string members
`username` and `bank` plus the finite numeric member `job_usage`. The array
order is not significant. Repeated usage updates must not create duplicate
period rows.

The usage calculation retains the bundled Flux semantics and uses Python
binary-float arithmetic. For each new job, `nnodes` is the larger of one and
the number of nonempty comma-separated tokens in `ranks`; `ncores` equals
`nnodes`, `ngpus` is zero, and `elapsed` is `actual_duration`. Read
`node_weight`, `core_weight`, and `gpu_weight` from `config_table` as floats,
using `1.0`, `0.0`, and `0.0` respectively when absent. Compute each job's
weighted usage as

```text
((nnodes * node_weight) + (ncores * core_weight) +
 (ngpus * gpu_weight)) * elapsed
```

and apply Python's built-in `round(weighted_usage, 5)` to each job separately
before summing the jobs. This is per-job binary-float rounding (ties to even
when the binary value is exactly halfway), not rounding once after summing.
For jobs in the current half-life period, add that per-job sum to period zero
and set `association_table.job_usage` to the sum of all period values. When a
new half-life period is due, shift prior values to the next period while
multiplying them by `decay_factor` (default `0.5`), set period zero from the
new-job sum, and again publish the sum of the resulting periods. The JSON
`job_usage`, the database `association_table.job_usage`, and period-zero value
must agree with these rules.

## Preserved interfaces

- Keep the two public executables under `bin/` and their existing flags.
- Keep the database schema version at 37.
- Use only Python's standard library and SQLite. The task is self-contained;
  installing packages or making the repair depend on network access is not
  permitted. Grading recursively inspects candidate files under `src/**` and
  `bin/**`, rejects additions elsewhere, and runs candidate processes with
  network socket creation blocked.
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

Adding files or directories anywhere outside `src/**` and `bin/**` also counts
as modifying the protected surface and is rejected.

The verifier supplies additional databases at grading time. It inspects the
SQLite files independently and does not trust candidate-emitted summaries.
