#!/bin/bash
set -Eeuo pipefail

task_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
work_root="${task_root}/.incident-work"
mkdir -p "${work_root}"
find "${work_root}" -mindepth 1 -depth -delete

"${task_root}/scripts/make-incident-db.py" "${work_root}" >/dev/null

echo "[1/3] successful upgrade loses legacy fair-share history"
"${task_root}/bin/flux-account-update-db" \
    -p "${work_root}/legacy.db" \
    -n "${work_root}/target-schema.db" \
    >"${work_root}/upgrade.out" 2>"${work_root}/upgrade.err"
python3 - "${work_root}/legacy.db" <<'PY'
import sqlite3
import sys

conn = sqlite3.connect(sys.argv[1])
version = conn.execute("PRAGMA user_version").fetchone()[0]
rows = conn.execute("SELECT COUNT(*) FROM job_usage_per_association_table").fetchone()[0]
if version != 37 or rows != 0:
    raise SystemExit(f"unexpected starter result: version={version} usage_rows={rows}")
print(f"OBSERVED history-loss schema={version} usage_rows={rows}")
PY

echo "[2/3] retry leaves a partially populated usage table incomplete"
"${task_root}/bin/flux-account-update-db" \
    -p "${work_root}/partial-legacy.db" \
    -n "${work_root}/target-schema.db" \
    >"${work_root}/partial.out" 2>"${work_root}/partial.err"
python3 - "${work_root}/partial-legacy.db" <<'PY'
import sqlite3
import sys

conn = sqlite3.connect(sys.argv[1])
rows = conn.execute("SELECT COUNT(*) FROM job_usage_per_association_table").fetchone()[0]
if rows != 1:
    raise SystemExit(f"unexpected starter partial-row count: {rows}")
print(f"OBSERVED non-idempotent-retry usage_rows={rows} expected=12")
PY

echo "[3/3] migration has no recoverable pre-upgrade snapshot"
"${task_root}/scripts/make-incident-db.py" "${work_root}/failure" >/dev/null
python3 - "${work_root}/failure/target-schema.db" <<'PY'
import sqlite3
import sys

conn = sqlite3.connect(sys.argv[1])
conn.execute("DROP TABLE queue_table")
conn.execute(
    "CREATE TABLE queue_table (queue TEXT PRIMARY KEY NOT NULL, "
    "required_new_value TEXT NOT NULL)"
)
conn.commit()
PY
set +e
"${task_root}/bin/flux-account-update-db" \
    -p "${work_root}/failure/legacy.db" \
    -n "${work_root}/failure/target-schema.db" \
    >"${work_root}/failure/upgrade.out" 2>"${work_root}/failure/upgrade.err"
failure_status=$?
set -e
if [[ "${failure_status}" -eq 0 ]]; then
    echo "forced migration unexpectedly succeeded" >&2
    exit 1
fi
if [[ -e "${work_root}/failure/legacy.db.backup" ]]; then
    echo "starter unexpectedly created a backup" >&2
    exit 1
fi
echo "OBSERVED unsafe-failure exit=${failure_status} backup=absent"

echo "incident reproduced: 3/3 symptoms observed"
