#!/usr/bin/env python3
import argparse
import hashlib
import json
import math
import os
from pathlib import Path
import random
import shutil
import signal
import sqlite3
import subprocess
import sys
import tempfile


TARGET_VERSION = 37
CANDIDATE_UID = 1000
CANDIDATE_GID = 1000


def terminate_candidate_processes():
    if os.geteuid() != 0 or not Path("/.dockerenv").exists():
        return
    for _ in range(4):
        found = False
        for entry in Path("/proc").iterdir():
            if not entry.name.isdigit():
                continue
            if entry.name == "1":
                continue
            try:
                fields = (entry / "status").read_text().splitlines()
                uid_line = next(line for line in fields if line.startswith("Uid:"))
                real_uid = int(uid_line.split()[1])
                if real_uid == CANDIDATE_UID:
                    os.kill(int(entry.name), signal.SIGKILL)
                    found = True
            except (FileNotFoundError, PermissionError, ProcessLookupError, StopIteration):
                pass
        if not found:
            break


def candidate_preexec():
    os.setsid()
    if os.geteuid() == 0:
        os.setgroups([])
        os.setgid(CANDIDATE_GID)
        os.setuid(CANDIDATE_UID)


def candidate_owner():
    if os.geteuid() == 0:
        return CANDIDATE_UID, CANDIDATE_GID
    return os.getuid(), os.getgid()


def make_source_directory(case, name="source"):
    path = case / name
    path.mkdir()
    uid, gid = candidate_owner()
    os.chown(path, uid, gid)
    path.chmod(0o700)
    return path


def handoff(path):
    uid, gid = candidate_owner()
    os.chown(path, uid, gid)


def run(command, *, cwd=None, env=None, expect=0):
    child_env = dict(os.environ)
    if env is not None:
        child_env.update(env)
    child_env.update({"HOME": "/home/candidate", "PYTHONDONTWRITEBYTECODE": "1"})
    process = subprocess.Popen(
        [str(item) for item in command],
        cwd=cwd,
        env=child_env,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        preexec_fn=candidate_preexec,
    )
    try:
        stdout, stderr = process.communicate(timeout=30)
    except subprocess.TimeoutExpired:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        stdout, stderr = process.communicate()
        raise AssertionError(f"command timed out: {command}\n{stdout}\n{stderr}")
    finally:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        terminate_candidate_processes()
    result = subprocess.CompletedProcess(command, process.returncode, stdout, stderr)
    if expect is not None and result.returncode != expect:
        raise AssertionError(
            f"command exit {result.returncode}, expected {expect}: {command}\n"
            f"stdout:\n{result.stdout}\nstderr:\n{result.stderr}"
        )
    return result


def sha256(path):
    digest = hashlib.sha256()
    with open(path, "rb") as stream:
        while True:
            chunk = stream.read(65536)
            if not chunk:
                return digest.hexdigest()
            digest.update(chunk)


def quote(identifier):
    return '"' + identifier.replace('"', '""') + '"'


def table_info(conn, table):
    return conn.execute(f"PRAGMA table_info({quote(table)})").fetchall()


def primary_key(conn, table):
    return [
        row[1]
        for row in sorted(table_info(conn, table), key=lambda row: row[5])
        if row[5] > 0
    ]


def create_target(path):
    conn = sqlite3.connect(path)
    conn.executescript(
        """
        PRAGMA user_version=37;
        CREATE TABLE association_table (
            creation_time INTEGER NOT NULL,
            mod_time INTEGER DEFAULT 0 NOT NULL,
            active INTEGER DEFAULT 1 NOT NULL,
            username TEXT NOT NULL,
            userid INTEGER NOT NULL,
            bank TEXT NOT NULL,
            default_bank TEXT NOT NULL,
            job_usage REAL DEFAULT 0.0 NOT NULL,
            fairshare REAL DEFAULT 0.5 NOT NULL,
            PRIMARY KEY (username, bank)
        );
        CREATE TABLE bank_table (
            bank_id INTEGER PRIMARY KEY AUTOINCREMENT,
            bank TEXT NOT NULL,
            active INTEGER DEFAULT 1 NOT NULL,
            parent_bank TEXT DEFAULT '',
            shares INTEGER NOT NULL,
            job_usage REAL DEFAULT 0.0 NOT NULL,
            priority REAL DEFAULT 0.0 NOT NULL,
            ignore_older_than INTEGER DEFAULT 0
        );
        CREATE TABLE job_usage_factor_table (
            username TEXT NOT NULL,
            userid INTEGER NOT NULL,
            bank TEXT NOT NULL,
            last_job_timestamp REAL DEFAULT 0.0,
            PRIMARY KEY (username, bank)
        );
        CREATE TABLE job_usage_per_association_table (
            username TEXT NOT NULL,
            userid INTEGER NOT NULL,
            bank TEXT NOT NULL,
            period INTEGER NOT NULL,
            value REAL DEFAULT 0.0,
            PRIMARY KEY (username, bank, period)
        );
        CREATE TABLE priority_factor_weight_table (
            factor TEXT PRIMARY KEY NOT NULL, weight INTEGER NOT NULL
        );
        CREATE TABLE config_table (
            key TEXT PRIMARY KEY NOT NULL, value TEXT NOT NULL
        );
        CREATE TABLE project_table (
            project_id INTEGER PRIMARY KEY AUTOINCREMENT,
            project TEXT NOT NULL,
            usage REAL DEFAULT 0.0 NOT NULL
        );
        CREATE TABLE queue_table (
            queue TEXT PRIMARY KEY NOT NULL,
            priority INTEGER DEFAULT 0 NOT NULL
        );
        CREATE TABLE t_half_life_period_table (
            cluster TEXT, end_half_life_period REAL
        );
        CREATE TABLE jobs (
            id TEXT PRIMARY KEY NOT NULL,
            userid INTEGER NOT NULL,
            t_submit REAL NOT NULL,
            t_run REAL NOT NULL,
            t_inactive REAL NOT NULL,
            ranks TEXT NOT NULL,
            R TEXT NOT NULL,
            jobspec TEXT NOT NULL,
            project TEXT,
            bank TEXT,
            requested_duration REAL DEFAULT 0.0,
            actual_duration REAL DEFAULT 0.0
        );
        CREATE TABLE migration_marker (
            cluster TEXT NOT NULL,
            generation INTEGER NOT NULL,
            value TEXT NOT NULL,
            PRIMARY KEY (cluster, generation)
        );
        """
    )
    conn.close()


def create_legacy(path, periods, associations, *, partial=None, no_periods=False):
    conn = sqlite3.connect(path)
    period_defs = ""
    if not no_periods:
        period_defs = ",\n" + ",\n".join(
            f"{quote(f'usage_factor_period_{period}')} REAL DEFAULT 0.0"
            for period in periods
        )
    conn.executescript(
        f"""
        PRAGMA user_version=31;
        CREATE TABLE association_table (
            creation_time INTEGER NOT NULL,
            username TEXT NOT NULL,
            userid INTEGER NOT NULL,
            bank TEXT NOT NULL,
            default_bank TEXT NOT NULL,
            job_usage REAL DEFAULT 0.0 NOT NULL,
            PRIMARY KEY (username, bank)
        );
        CREATE TABLE bank_table (
            bank_id INTEGER PRIMARY KEY AUTOINCREMENT,
            bank TEXT NOT NULL,
            active INTEGER DEFAULT 1 NOT NULL,
            parent_bank TEXT DEFAULT '',
            shares INTEGER NOT NULL,
            job_usage REAL DEFAULT 0.0 NOT NULL,
            priority REAL DEFAULT 0.0 NOT NULL,
            ignore_older_than INTEGER DEFAULT 0
        );
        CREATE TABLE job_usage_factor_table (
            username TEXT NOT NULL,
            userid INTEGER NOT NULL,
            bank TEXT NOT NULL,
            last_job_timestamp REAL DEFAULT 0.0
            {period_defs},
            PRIMARY KEY (username, bank)
        );
        CREATE TABLE priority_factor_weight_table (
            factor TEXT PRIMARY KEY NOT NULL, weight INTEGER NOT NULL
        );
        CREATE TABLE config_table (
            key TEXT PRIMARY KEY NOT NULL, value TEXT NOT NULL
        );
        CREATE TABLE project_table (
            project_id INTEGER PRIMARY KEY AUTOINCREMENT,
            project TEXT NOT NULL,
            usage REAL DEFAULT 0.0 NOT NULL
        );
        CREATE TABLE queue_table (
            queue TEXT PRIMARY KEY NOT NULL,
            priority INTEGER DEFAULT 0 NOT NULL,
            obsolete INTEGER DEFAULT 9
        );
        CREATE TABLE t_half_life_period_table (
            cluster TEXT, end_half_life_period REAL
        );
        CREATE TABLE jobs (
            id TEXT PRIMARY KEY NOT NULL,
            userid INTEGER NOT NULL,
            t_submit REAL NOT NULL,
            t_run REAL NOT NULL,
            t_inactive REAL NOT NULL,
            ranks TEXT NOT NULL,
            R TEXT NOT NULL,
            jobspec TEXT NOT NULL,
            project TEXT,
            bank TEXT,
            requested_duration REAL DEFAULT 0.0,
            actual_duration REAL DEFAULT 0.0
        );
        """
    )
    conn.execute("INSERT INTO bank_table (bank, parent_bank, shares) VALUES ('root', '', 1)")
    conn.execute("INSERT INTO bank_table (bank, parent_bank, shares) VALUES ('science', 'root', 1)")
    conn.execute("INSERT INTO project_table (project) VALUES ('*')")
    conn.execute("INSERT INTO queue_table (queue, priority, obsolete) VALUES ('batch', 3, 77)")
    conn.execute("INSERT INTO t_half_life_period_table VALUES ('cluster', 4102444800)")
    for factor, weight in (("fairshare", 100000), ("queue", 10000), ("bank", 0), ("urgency", 1000)):
        conn.execute("INSERT INTO priority_factor_weight_table VALUES (?, ?)", (factor, weight))
    for key, value in (
        ("priority_decay_half_life", "604800"),
        ("priority_usage_reset_period", "2419200"),
        ("decay_factor", "0.5"),
        ("node_weight", "1.0"),
        ("core_weight", "0.0"),
        ("gpu_weight", "0.0"),
    ):
        conn.execute("INSERT INTO config_table VALUES (?, ?)", (key, value))
    expected = {}
    for username, userid, bank, values in associations:
        conn.execute(
            "INSERT INTO association_table VALUES (?, ?, ?, ?, ?, ?)",
            (1710000000, username, userid, bank, bank, float(sum(values.values()))),
        )
        columns = ["username", "userid", "bank", "last_job_timestamp"]
        row = [username, userid, bank, 100.0]
        if not no_periods:
            columns += [f"usage_factor_period_{period}" for period in periods]
            row += [values[period] for period in periods]
            for period in periods:
                expected[(username, userid, bank, period)] = values[period]
        conn.execute(
            f"INSERT INTO job_usage_factor_table ({','.join(map(quote, columns))}) "
            f"VALUES ({','.join('?' for _ in row)})",
            row,
        )
    if partial is not None:
        conn.executescript(
            """
            CREATE TABLE job_usage_per_association_table (
                username TEXT NOT NULL,
                userid INTEGER NOT NULL,
                bank TEXT NOT NULL,
                period INTEGER NOT NULL,
                value REAL DEFAULT 0.0,
                PRIMARY KEY (username)
            );
            """
        )
        for row in partial:
            conn.execute(
                "INSERT INTO job_usage_per_association_table VALUES (?, ?, ?, ?, ?)", row
            )
    conn.commit()
    conn.close()
    return expected


def usage_rows(conn):
    return {
        (row[0], row[1], row[2], row[3]): row[4]
        for row in conn.execute(
            "SELECT username, userid, bank, period, value "
            "FROM job_usage_per_association_table"
        )
    }


def assert_database_matches_target(path, target, expected, preserved=None):
    conn = sqlite3.connect(path)
    target_conn = sqlite3.connect(target)
    assert conn.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
    assert conn.execute("PRAGMA user_version").fetchone()[0] == TARGET_VERSION
    for table in (
        "association_table",
        "job_usage_factor_table",
        "job_usage_per_association_table",
        "queue_table",
    ):
        assert [row[1:6] for row in table_info(conn, table)] == [
            row[1:6] for row in table_info(target_conn, table)
        ], table
        assert primary_key(conn, table) == primary_key(target_conn, table), table
    assert "migration_marker" in {
        row[0] for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")
    }
    assert [row[1:6] for row in table_info(conn, "migration_marker")] == [
        row[1:6] for row in table_info(target_conn, "migration_marker")
    ]
    assert primary_key(conn, "migration_marker") == ["cluster", "generation"]
    observed = usage_rows(conn)
    assert observed.keys() == expected.keys(), (observed, expected)
    for key, value in expected.items():
        assert math.isclose(observed[key], value, rel_tol=0, abs_tol=1e-12), key
    assert conn.execute("SELECT priority FROM queue_table WHERE queue='batch'").fetchone()[0] == 3
    if preserved is not None:
        for table, order_by, rows in preserved:
            observed_rows = conn.execute(
                f"SELECT * FROM {quote(table)} ORDER BY {order_by}"
            ).fetchall()
            assert observed_rows == rows, table
    expected_associations = len({(key[0], key[2]) for key in expected})
    if expected_associations:
        assert conn.execute("SELECT COUNT(*) FROM association_table").fetchone()[0] == expected_associations
    conn.close()
    target_conn.close()


def test_migration(workspace, tmp):
    target = tmp / "target schema.db"
    old = make_source_directory(tmp) / "old accounting data.db"
    create_target(target)
    randomizer = random.Random(4815162342)
    periods = [9, 0, 4, 2]
    associations = []
    for username, userid, bank in (
        ("alice", 1001, "science"),
        ("alice", 1001, "root"),
        ("bob", 1002, "science"),
        ("carol", 1003, "root"),
    ):
        values = {period: round(randomizer.uniform(-1000, 1000), 7) for period in periods}
        values[0] = 0.0 if username == "carol" else values[0]
        associations.append((username, userid, bank, values))
    partial = [
        ("alice", 1001, "science", 9, -999999.0),
        ("bob", 1002, "science", 0, 123456.0),
    ]
    expected = create_legacy(old, periods, associations, partial=partial)
    conn = sqlite3.connect(old)
    preserved = []
    for table, order_by in (
        ("bank_table", "bank_id"),
        ("config_table", "key"),
        ("priority_factor_weight_table", "factor"),
        ("project_table", "project_id"),
        ("t_half_life_period_table", "cluster"),
        ("jobs", "id"),
    ):
        preserved.append(
            (table, order_by, conn.execute(f"SELECT * FROM {quote(table)} ORDER BY {order_by}").fetchall())
        )
    conn.close()
    handoff(old)
    before_first = sha256(old)
    command = [workspace / "bin/flux-account-update-db", "-p", old, "-n", target]
    run(command)
    backup = Path(str(old) + ".backup")
    assert backup.is_file()
    assert sha256(backup) == before_first
    assert_database_matches_target(old, target, expected, preserved)
    first_rows = usage_rows(sqlite3.connect(old))
    before_second = sha256(old)
    run(command)
    assert sha256(backup) == before_second
    assert_database_matches_target(old, target, expected, preserved)
    assert usage_rows(sqlite3.connect(old)) == first_rows
    conn = sqlite3.connect(old)
    conn.execute(
        "INSERT INTO jobs VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        ("new-job", 1001, 5900, 6000, 6200, "0,1", "{}", "{}", "*", "science", 200, 200),
    )
    conn.commit()
    conn.close()
    update = run([workspace / "bin/flux-account-update-usage", "-p", old])
    payload = json.loads(update.stdout)
    assert {(row["username"], row["bank"]) for row in payload["associations"]} == {
        ("alice", "science"),
        ("alice", "root"),
        ("bob", "science"),
        ("carol", "root"),
    }
    conn = sqlite3.connect(old)
    row_count = conn.execute(
        "SELECT COUNT(*) FROM job_usage_per_association_table"
    ).fetchone()[0]
    conn.close()
    run([workspace / "bin/flux-account-update-usage", "-p", old])
    conn = sqlite3.connect(old)
    assert conn.execute(
        "SELECT COUNT(*) FROM job_usage_per_association_table"
    ).fetchone()[0] == row_count
    conn.close()


def test_no_periods(workspace, tmp):
    target = tmp / "target.db"
    old = make_source_directory(tmp) / "old.db"
    create_target(target)
    expected = create_legacy(
        old, [], [("noperiod", 2001, "science", {})], no_periods=True
    )
    handoff(old)
    run([workspace / "bin/flux-account-update-db", "-p", old, "-n", target])
    assert_database_matches_target(old, target, expected)
    conn = sqlite3.connect(old)
    assert conn.execute("SELECT COUNT(*) FROM association_table").fetchone()[0] == 1
    conn.close()


def test_failure_restore(workspace, tmp):
    target = tmp / "bad target.db"
    old = make_source_directory(tmp) / "failure source.db"
    create_target(target)
    create_legacy(
        old,
        [0, 1],
        [("alice", 1001, "science", {0: 2.5, 1: 7.5})],
    )
    stale = Path(str(old) + ".backup")
    stale.write_bytes(b"stale-backup")
    target_conn = sqlite3.connect(target)
    target_conn.execute("DROP TABLE queue_table")
    target_conn.execute(
        "CREATE TABLE queue_table (queue TEXT PRIMARY KEY NOT NULL, "
        "required_new_value TEXT NOT NULL)"
    )
    target_conn.commit()
    target_conn.close()
    handoff(old)
    handoff(stale)
    result = run(
        [workspace / "bin/flux-account-update-db", "-p", old, "-n", target],
        expect=None,
    )
    assert result.returncode != 0
    assert old.is_file() and stale.is_file()
    assert sha256(old) == sha256(stale)
    conn = sqlite3.connect(old)
    assert conn.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
    assert conn.execute("PRAGMA user_version").fetchone()[0] == 31
    assert not conn.execute(
        "SELECT 1 FROM sqlite_master WHERE name LIKE '%_tmp' LIMIT 1"
    ).fetchone()
    conn.close()


def test_wal_backup(workspace, tmp):
    target = tmp / "wal target.db"
    old = make_source_directory(tmp) / "wal source.db"
    create_target(target)
    expected = create_legacy(
        old,
        [0, 3],
        [("waluser", 3001, "science", {0: 1.25, 3: 9.75})],
    )
    conn = sqlite3.connect(old)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute(
        "UPDATE job_usage_factor_table SET usage_factor_period_3=77.25 "
        "WHERE username='waluser' AND bank='science'"
    )
    conn.commit()
    expected[("waluser", 3001, "science", 3)] = 77.25
    handoff(old)
    for suffix in ("-wal", "-shm"):
        sidecar = Path(str(old) + suffix)
        if sidecar.exists():
            handoff(sidecar)
    run([workspace / "bin/flux-account-update-db", "-p", old, "-n", target])
    backup = Path(str(old) + ".backup")
    backup_conn = sqlite3.connect(backup)
    assert backup_conn.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
    assert backup_conn.execute(
        "SELECT usage_factor_period_3 FROM job_usage_factor_table "
        "WHERE username='waluser' AND bank='science'"
    ).fetchone()[0] == 77.25
    backup_conn.close()
    conn.close()
    assert_database_matches_target(old, target, expected)


def test_invalid_paths(workspace, tmp):
    target = tmp / "target.db"
    create_target(target)
    source = make_source_directory(tmp)
    missing = source / "missing.db"
    result = run(
        [workspace / "bin/flux-account-update-db", "-p", missing, "-n", target],
        expect=None,
    )
    assert result.returncode != 0
    directory = source / "directory.db"
    directory.mkdir()
    result = run(
        [workspace / "bin/flux-account-update-db", "-p", directory, "-n", target],
        expect=None,
    )
    assert result.returncode != 0
    old = source / "old.db"
    create_legacy(old, [0], [("user", 1, "science", {0: 1.0})])
    handoff(old)
    missing_target = tmp / "missing-target.db"
    result = run(
        [workspace / "bin/flux-account-update-db", "-p", old, "-n", missing_target],
        expect=None,
    )
    assert result.returncode != 0
    target_directory = tmp / "target-directory.db"
    target_directory.mkdir()
    before_invalid_target = sha256(old)
    result = run(
        [workspace / "bin/flux-account-update-db", "-p", old, "-n", target_directory],
        expect=None,
    )
    assert result.returncode != 0
    assert sha256(old) == before_invalid_target
    target_symlink = tmp / "target-link.db"
    target_symlink.symlink_to(target)
    result = run(
        [workspace / "bin/flux-account-update-db", "-p", old, "-n", target_symlink],
        expect=None,
    )
    assert result.returncode != 0
    assert sha256(old) == before_invalid_target
    symlink = source / "linked.db"
    symlink.symlink_to(old)
    result = run(
        [workspace / "bin/flux-account-update-db", "-p", symlink, "-n", target],
        expect=None,
    )
    assert result.returncode != 0


def test_default_target_schema(workspace, tmp):
    old = make_source_directory(tmp) / "default target source.db"
    periods = [7, 1]
    associations = [
        ("default-user", 4101, "science", {7: 8.5, 1: -2.25}),
    ]
    expected = create_legacy(old, periods, associations)
    handoff(old)
    run([workspace / "bin/flux-account-update-db", "-p", old])
    conn = sqlite3.connect(old)
    assert conn.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
    assert conn.execute("PRAGMA user_version").fetchone()[0] == TARGET_VERSION
    assert primary_key(conn, "job_usage_per_association_table") == [
        "username",
        "bank",
        "period",
    ]
    observed = usage_rows(conn)
    assert observed.keys() == expected.keys()
    for key, value in expected.items():
        assert math.isclose(observed[key], value, rel_tol=0, abs_tol=1e-12), key
    conn.close()
    assert Path(str(old) + ".backup").is_file()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--workspace", type=Path, required=True)
    args = parser.parse_args()
    workspace = args.workspace.resolve()
    with tempfile.TemporaryDirectory(prefix="flux-accounting-verifier-") as directory:
        root = Path(directory)
        root.chmod(0o711)
        checks = [
            ("migration-and-retry", test_migration),
            ("no-period-layout", test_no_periods),
            ("failure-restore", test_failure_restore),
            ("wal-backup", test_wal_backup),
            ("invalid-paths", test_invalid_paths),
            ("default-target-schema", test_default_target_schema),
        ]
        for index, (name, check) in enumerate(checks):
            case = root / f"case-{index}"
            case.mkdir()
            case.chmod(0o755)
            check(workspace, case)
            print(f"PASS {name}")
    print("all verifier checks passed")


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        print(f"FAIL {type(exc).__name__}: {exc}", file=sys.stderr)
        raise
