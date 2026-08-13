#!/usr/bin/env python3
import argparse
import ast
import ctypes
import errno
import hashlib
import json
import math
import os
from pathlib import Path
import platform
import random
import re
import shutil
import signal
import sqlite3
import subprocess
import sys
import tempfile


TARGET_VERSION = 37
CANDIDATE_UID = 1000
CANDIDATE_GID = 1000
NETWORK_IMPORTS = {
    "ftplib",
    "http",
    "imaplib",
    "poplib",
    "requests",
    "smtplib",
    "socket",
    "telnetlib",
    "urllib",
    "xmlrpc",
}
NETWORK_SHELL = re.compile(
    r"(?:^|[;&|]\s*|\bexec\s+)(?:curl|wget|nc|ncat|ssh|scp|ftp|telnet|pip)\b"
    r"|\bpython(?:3)?\s+-m\s+pip\b",
    re.MULTILINE,
)
SOURCE_ROOTS = ("src", "bin", "scripts")
EXPECTED_HELP_FRAGMENTS = (
    "usage:",
    "[-p OLD_DB]",
    "[-n NEW_DB]",
    "-p, --path OLD_DB",
    "database file",
    "-n, --new-db NEW_DB",
    "target schema",
)


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
    install_network_seccomp_filter()


def install_network_seccomp_filter():
    syscall_numbers = {
        "x86_64": (41, 53),
        "amd64": (41, 53),
        "aarch64": (198, 199),
        "arm64": (198, 199),
    }.get(platform.machine().lower())
    if syscall_numbers is None:
        raise RuntimeError(
            f"unsupported verifier architecture for network isolation: {platform.machine()}"
        )

    class SockFilter(ctypes.Structure):
        _fields_ = [
            ("code", ctypes.c_ushort),
            ("jt", ctypes.c_ubyte),
            ("jf", ctypes.c_ubyte),
            ("k", ctypes.c_uint32),
        ]

    class SockFprog(ctypes.Structure):
        _fields_ = [
            ("len", ctypes.c_ushort),
            ("filter", ctypes.POINTER(SockFilter)),
        ]

    instructions = [SockFilter(0x20, 0, 0, 0)]
    for syscall_number in syscall_numbers:
        instructions.extend(
            (
                SockFilter(0x15, 0, 1, syscall_number),
                SockFilter(0x06, 0, 0, 0x00050000 | errno.EPERM),
            )
        )
    instructions.append(SockFilter(0x06, 0, 0, 0x7FFF0000))
    filters = (SockFilter * len(instructions))(*instructions)
    program = SockFprog(len(instructions), filters)
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.prctl(38, 1, 0, 0, 0) != 0:
        error = ctypes.get_errno()
        raise OSError(error, os.strerror(error))
    if libc.prctl(22, 2, ctypes.byref(program)) != 0:
        error = ctypes.get_errno()
        raise OSError(error, os.strerror(error))


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


def normalized_table_sql(conn, table):
    row = conn.execute(
        "SELECT sql FROM sqlite_master WHERE type='table' AND name=?", (table,)
    ).fetchone()
    assert row is not None and row[0], table
    opening = row[0].find("(")
    assert opening >= 0, table
    return re.sub(r"\s+", " ", row[0][opening:]).strip()


def explicit_indexes(conn, table):
    indexes = []
    for row in conn.execute(f"PRAGMA index_list({quote(table)})"):
        sequence, name, unique, origin, partial = row
        if origin == "pk":
            continue
        columns = tuple(
            item[2]
            for item in conn.execute(f"PRAGMA index_xinfo({quote(name)})")
            if item[5] and item[2] is not None
        )
        indexes.append((unique, origin, partial, columns))
    return sorted(indexes, key=repr)


def user_tables(conn):
    return {
        row[0]
        for row in conn.execute(
            "SELECT name FROM sqlite_master "
            "WHERE type='table' AND name NOT LIKE 'sqlite_%'"
        )
    }


def capture_shared_rows(old_conn, target_conn, *, excluded=()):
    snapshots = []
    excluded = set(excluded)
    for table in sorted(user_tables(old_conn) & user_tables(target_conn) - excluded):
        old_names = {row[1] for row in table_info(old_conn, table)}
        columns = [
            row[1] for row in table_info(target_conn, table) if row[1] in old_names
        ]
        if not columns:
            continue
        projection = ", ".join(quote(column) for column in columns)
        rows = old_conn.execute(
            f"SELECT {projection} FROM {quote(table)}"
        ).fetchall()
        snapshots.append((table, columns, sorted(rows, key=repr)))
    return snapshots


def assert_preserved_rows(conn, snapshots):
    for table, columns, expected_rows in snapshots:
        projection = ", ".join(quote(column) for column in columns)
        observed_rows = conn.execute(
            f"SELECT {projection} FROM {quote(table)}"
        ).fetchall()
        assert sorted(observed_rows, key=repr) == expected_rows, table


def candidate_source_files(workspace):
    paths = []
    for relative in SOURCE_ROOTS:
        root = workspace / relative
        assert root.is_dir() and not root.is_symlink(), (
            f"candidate source root is missing or unsafe: {relative}"
        )
        for path in root.rglob("*"):
            if path.is_symlink() or not (path.is_file() or path.is_dir()):
                raise AssertionError(f"unsafe candidate source path: {path}")
            if path.is_file():
                paths.append(path)
    return sorted(paths)


def local_module_names(workspace):
    names = {"fluxacct"}
    for relative in SOURCE_ROOTS:
        root = workspace / relative
        for path in root.iterdir():
            if path.is_dir():
                names.add(path.name)
            elif path.suffix == ".py":
                names.add(path.stem)
    return names


def assert_standard_library_only(workspace):
    local_modules = local_module_names(workspace)
    for path in candidate_source_files(workspace):
        try:
            text = path.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError) as exc:
            raise AssertionError(f"candidate source is not readable UTF-8 text: {path}") from exc
        assert "\x00" not in text, f"binary candidate source is not permitted: {path}"
        try:
            tree = ast.parse(text, filename=str(path))
        except SyntaxError:
            assert not NETWORK_SHELL.search(text), (
                f"network command in candidate source: {path}"
            )
            continue
        imported = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported.update(alias.name.split(".", 1)[0] for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module:
                imported.add(node.module.split(".", 1)[0])
        external = {
            name
            for name in imported
            if name not in local_modules and name not in sys.stdlib_module_names
        }
        assert not external, f"non-standard dependency in {path}: {sorted(external)}"
        assert not imported & NETWORK_IMPORTS, (
            f"network dependency in {path}: {sorted(imported & NETWORK_IMPORTS)}"
        )
        assert not NETWORK_SHELL.search(text), (
            f"network command in candidate source: {path}"
        )


def assert_network_syscalls_blocked():
    probe = (
        "import errno, socket, sys\n"
        "try:\n"
        "    socket.socket()\n"
        "except OSError as exc:\n"
        "    sys.exit(0 if exc.errno == errno.EPERM else 2)\n"
        "sys.exit(3)\n"
    )
    run([sys.executable, "-B", "-c", probe])


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
            ignore_older_than INTEGER DEFAULT 0,
            UNIQUE (bank),
            CHECK (shares > 0)
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
        CREATE TABLE site_fairshare_policy (
            bank TEXT NOT NULL,
            period INTEGER NOT NULL,
            username TEXT NOT NULL,
            allocation REAL DEFAULT 0.0 NOT NULL,
            PRIMARY KEY (username, bank, period),
            UNIQUE (bank, period, username),
            CHECK (period >= 0),
            CHECK (allocation >= 0),
            FOREIGN KEY (username, bank)
                REFERENCES association_table (username, bank)
        );
        CREATE TABLE "target schema marker" (
            generation INTEGER NOT NULL,
            cluster TEXT NOT NULL,
            note TEXT DEFAULT '' NOT NULL,
            PRIMARY KEY (cluster, generation),
            UNIQUE (generation, cluster),
            CHECK (generation >= 0)
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
        CREATE TABLE site_fairshare_policy (
            bank TEXT NOT NULL,
            period INTEGER NOT NULL,
            username TEXT NOT NULL,
            allocation REAL DEFAULT 0.0 NOT NULL,
            retired TEXT DEFAULT 'legacy' NOT NULL,
            PRIMARY KEY (bank, period, username)
        );
        CREATE TABLE site_local_metadata (
            setting TEXT PRIMARY KEY NOT NULL,
            value TEXT NOT NULL
        );
        """
    )
    conn.execute("INSERT INTO bank_table (bank, parent_bank, shares) VALUES ('root', '', 1)")
    conn.execute("INSERT INTO bank_table (bank, parent_bank, shares) VALUES ('science', 'root', 1)")
    conn.execute("INSERT INTO project_table (project) VALUES ('*')")
    conn.execute("INSERT INTO queue_table (queue, priority, obsolete) VALUES ('batch', 3, 77)")
    conn.execute("INSERT INTO t_half_life_period_table VALUES ('cluster', 4102444800)")
    conn.execute(
        "INSERT INTO site_local_metadata VALUES "
        "('scheduler-owner', 'site-extension-must-survive')"
    )
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
    if associations:
        username, _, bank, _ = associations[0]
        conn.execute(
            "INSERT INTO site_fairshare_policy VALUES (?, 4, ?, 13.5, ?)",
            (bank, username, "preserve-shared-columns"),
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
    expected_tables = user_tables(target_conn)
    observed_tables = user_tables(conn)
    assert expected_tables <= observed_tables, expected_tables - observed_tables
    for table in sorted(expected_tables):
        assert [row[1:6] for row in table_info(conn, table)] == [
            row[1:6] for row in table_info(target_conn, table)
        ], table
        assert primary_key(conn, table) == primary_key(target_conn, table), table
        assert normalized_table_sql(conn, table) == normalized_table_sql(
            target_conn, table
        ), table
        assert conn.execute(f"PRAGMA foreign_key_list({quote(table)})").fetchall() == (
            target_conn.execute(
                f"PRAGMA foreign_key_list({quote(table)})"
            ).fetchall()
        ), table
        assert explicit_indexes(conn, table) == explicit_indexes(
            target_conn, table
        ), table
    assert primary_key(conn, "migration_marker") == ["cluster", "generation"]
    assert primary_key(conn, "site_fairshare_policy") == [
        "username",
        "bank",
        "period",
    ]
    assert primary_key(conn, "target schema marker") == ["cluster", "generation"]
    observed = usage_rows(conn)
    assert observed.keys() == expected.keys(), (observed, expected)
    for key, value in expected.items():
        assert math.isclose(observed[key], value, rel_tol=0, abs_tol=1e-12), key
    assert conn.execute("SELECT priority FROM queue_table WHERE queue='batch'").fetchone()[0] == 3
    if preserved is not None:
        assert_preserved_rows(conn, preserved)
    assert conn.execute(
        "SELECT setting, value FROM site_local_metadata"
    ).fetchall() == [("scheduler-owner", "site-extension-must-survive")]
    assert conn.execute("PRAGMA foreign_key_check").fetchall() == []
    expected_associations = len({(key[0], key[2]) for key in expected})
    if expected_associations:
        assert conn.execute("SELECT COUNT(*) FROM association_table").fetchone()[0] == expected_associations
    conn.close()
    target_conn.close()


def assert_target_constraints_enforced(path):
    conn = sqlite3.connect(path)
    conn.execute("PRAGMA foreign_keys=ON")
    invalid = (
        (
            "INSERT INTO bank_table (bank, shares) VALUES ('invalid-shares', 0)",
            (),
        ),
        (
            "INSERT INTO site_fairshare_policy "
            "(username, bank, period, allocation) VALUES (?, ?, ?, ?)",
            ("alice", "science", -1, 1.0),
        ),
        (
            "INSERT INTO site_fairshare_policy "
            "(username, bank, period, allocation) VALUES (?, ?, ?, ?)",
            ("missing-user", "science", 3, 1.0),
        ),
    )
    for statement, values in invalid:
        try:
            conn.execute(statement, values)
        except sqlite3.IntegrityError:
            conn.rollback()
        else:
            raise AssertionError(f"target constraint was not enforced: {statement}")
    conn.close()


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
    target_conn = sqlite3.connect(target)
    preserved = capture_shared_rows(
        conn, target_conn, excluded={"job_usage_per_association_table"}
    )
    target_conn.close()
    conn.close()
    handoff(old)
    before_first = sha256(old)
    command = [workspace / "bin/flux-account-update-db", "-p", old, "-n", target]
    run(command)
    backup = Path(str(old) + ".backup")
    assert backup.is_file()
    assert sha256(backup) == before_first
    assert_database_matches_target(old, target, expected, preserved)
    assert_target_constraints_enforced(old)
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
    payload = json.loads(
        update.stdout,
        parse_constant=lambda value: (_ for _ in ()).throw(
            ValueError(f"non-finite JSON number: {value}")
        ),
    )
    assert set(payload) == {"database", "associations"}
    assert payload["database"] == str(old)
    assert isinstance(payload["associations"], list)
    for row in payload["associations"]:
        assert set(row) == {"username", "bank", "job_usage"}
        assert isinstance(row["username"], str) and isinstance(row["bank"], str)
        assert isinstance(row["job_usage"], (int, float))
        assert math.isfinite(row["job_usage"])
    expected_associations = {
        ("alice", "science"),
        ("alice", "root"),
        ("bob", "science"),
        ("carol", "root"),
    }
    assert {(row["username"], row["bank"]) for row in payload["associations"]} == (
        expected_associations
    )
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


def test_large_finite_usage_values(workspace, tmp):
    target = tmp / "large target schema.db"
    old = make_source_directory(tmp) / "large finite usage.db"
    create_target(target)
    periods = [31, 0, 12]
    values = {
        31: 8.988465674311579e307,
        0: -7.654321098765432e307,
        12: 1.234567890123456e250,
    }
    expected = create_legacy(
        old, periods, [("magnitude", 9223372036854770000, "science", values)]
    )
    handoff(old)
    run([workspace / "bin/flux-account-update-db", "-p", old, "-n", target])
    assert_database_matches_target(old, target, expected)
    conn = sqlite3.connect(old)
    observed = usage_rows(conn)
    for key, value in expected.items():
        assert math.isfinite(observed[key])
        assert observed[key] == value
        assert conn.execute(
            "SELECT typeof(value) FROM job_usage_per_association_table "
            "WHERE username=? AND bank=? AND period=?",
            (key[0], key[2], key[3]),
        ).fetchone()[0] in {"integer", "real"}
    conn.close()


def test_period_name_boundaries(workspace, tmp):
    target = tmp / "period-name target.db"
    old = make_source_directory(tmp) / "period-name source.db"
    create_target(target)
    maximum_period = 9223372036854775807
    expected = create_legacy(
        old,
        [maximum_period],
        [("period-boundary", 6001, "science", {maximum_period: 17.25})],
    )
    conn = sqlite3.connect(old)
    ignored_columns = (
        "usage_factor_period_01",
        "Usage_factor_period_7",
        "usage_factor_period_9223372036854775808",
        "usage_factor_period_١",
    )
    for index, column in enumerate(ignored_columns, start=1):
        conn.execute(
            f"ALTER TABLE job_usage_factor_table ADD COLUMN {quote(column)} REAL"
        )
        conn.execute(
            f"UPDATE job_usage_factor_table SET {quote(column)}=?",
            (index * 100.5,),
        )
    conn.commit()
    conn.close()
    handoff(old)
    run([workspace / "bin/flux-account-update-db", "-p", old, "-n", target])
    assert_database_matches_target(old, target, expected)
    conn = sqlite3.connect(old)
    assert conn.execute(
        "SELECT period, typeof(period) FROM job_usage_per_association_table"
    ).fetchall() == [(maximum_period, "integer")]
    conn.close()


def test_out_of_range_only_period_names(workspace, tmp):
    target = tmp / "ignored-period target.db"
    old = make_source_directory(tmp) / "ignored-period source.db"
    create_target(target)
    create_legacy(old, [], [], no_periods=True)
    conn = sqlite3.connect(old)
    conn.execute(
        "ALTER TABLE job_usage_factor_table ADD COLUMN "
        '"usage_factor_period_9223372036854775808" REAL'
    )
    conn.commit()
    conn.close()
    handoff(old)
    run([workspace / "bin/flux-account-update-db", "-p", old, "-n", target])
    assert_database_matches_target(old, target, {})


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


def test_empty_association_layouts(workspace, tmp):
    layouts = (
        ("sparse-period-columns", [23, 1, 9], False),
        ("no-period-columns", [], True),
    )
    for index, (name, periods, no_periods) in enumerate(layouts):
        case = tmp / f"empty-{index}-{name}"
        case.mkdir()
        target = case / "target schema.db"
        old = make_source_directory(case) / "empty associations.db"
        create_target(target)
        expected = create_legacy(
            old, periods, [], no_periods=no_periods
        )
        old_conn = sqlite3.connect(old)
        target_conn = sqlite3.connect(target)
        preserved = capture_shared_rows(
            old_conn,
            target_conn,
            excluded={"job_usage_per_association_table"},
        )
        old_conn.close()
        target_conn.close()
        handoff(old)

        command = [
            workspace / "bin/flux-account-update-db",
            "-p",
            old,
            "-n",
            target,
        ]
        before_first = sha256(old)
        run(command)
        backup = Path(str(old) + ".backup")
        assert backup.is_file() and sha256(backup) == before_first
        backup_conn = sqlite3.connect(backup)
        assert backup_conn.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
        backup_conn.close()
        assert_database_matches_target(old, target, expected, preserved)
        conn = sqlite3.connect(old)
        assert conn.execute("SELECT COUNT(*) FROM association_table").fetchone()[0] == 0
        assert conn.execute("SELECT COUNT(*) FROM job_usage_factor_table").fetchone()[0] == 0
        assert conn.execute(
            "SELECT COUNT(*) FROM job_usage_per_association_table"
        ).fetchone()[0] == 0
        conn.close()

        before_second = sha256(old)
        run(command)
        assert sha256(backup) == before_second
        assert_database_matches_target(old, target, expected, preserved)
        update = run([workspace / "bin/flux-account-update-usage", "-p", old])
        assert json.loads(update.stdout) == {
            "database": str(old),
            "associations": [],
        }


def assert_post_validation_failure_restored(workspace, old, target, *, stale=False):
    backup = Path(str(old) + ".backup")
    if stale:
        backup.write_bytes(b"stale-backup")
        handoff(backup)
    before = sha256(old)
    handoff(old)
    result = run(
        [workspace / "bin/flux-account-update-db", "-p", old, "-n", target],
        expect=None,
    )
    assert result.returncode != 0
    assert old.is_file() and backup.is_file()
    assert sha256(backup) == before
    assert sha256(old) == sha256(backup)
    conn = sqlite3.connect(old)
    assert conn.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
    assert conn.execute("PRAGMA user_version").fetchone()[0] == 31
    assert not conn.execute(
        "SELECT 1 FROM sqlite_master WHERE name LIKE '%_tmp' LIMIT 1"
    ).fetchone()
    conn.close()
    for suffix in ("-wal", "-shm", "-journal"):
        assert not Path(str(old) + suffix).exists()


def test_post_backup_failure_restore_matrix(workspace, tmp):
    cases = []

    constraint_target = tmp / "constraint target.db"
    constraint_old = make_source_directory(tmp, "constraint-source") / "old.db"
    create_target(constraint_target)
    create_legacy(
        constraint_old,
        [0, 1],
        [("alice", 1001, "science", {0: 2.5, 1: 7.5})],
    )
    target_conn = sqlite3.connect(constraint_target)
    target_conn.execute("DROP TABLE queue_table")
    target_conn.execute(
        "CREATE TABLE queue_table (queue TEXT PRIMARY KEY NOT NULL, "
        "required_new_value TEXT NOT NULL)"
    )
    target_conn.commit()
    target_conn.close()
    cases.append((constraint_old, constraint_target, True))

    missing_table_target = tmp / "missing destination target.db"
    missing_table_old = make_source_directory(tmp, "missing-table-source") / "old.db"
    create_target(missing_table_target)
    create_legacy(
        missing_table_old,
        [4],
        [("bob", 1002, "root", {4: 19.5})],
    )
    target_conn = sqlite3.connect(missing_table_target)
    target_conn.execute("DROP TABLE job_usage_per_association_table")
    target_conn.commit()
    target_conn.close()
    cases.append((missing_table_old, missing_table_target, False))

    corrupt_target = tmp / "corrupt target.db"
    corrupt_target.write_bytes(b"not a sqlite database")
    corrupt_old = make_source_directory(tmp, "corrupt-target-source") / "old.db"
    create_legacy(
        corrupt_old,
        [8],
        [("carol", 1003, "science", {8: -11.25})],
    )
    cases.append((corrupt_old, corrupt_target, False))

    usage_target = tmp / "usage target.db"
    usage_old = make_source_directory(tmp, "usage-source") / "old.db"
    create_target(usage_target)
    create_legacy(
        usage_old,
        [5],
        [("dave", 1004, "science", {5: 6.25})],
    )
    target_conn = sqlite3.connect(usage_target)
    target_conn.execute("DROP TABLE job_usage_per_association_table")
    target_conn.execute(
        "CREATE TABLE job_usage_per_association_table ("
        "username TEXT NOT NULL, userid INTEGER NOT NULL, bank TEXT NOT NULL, "
        "period INTEGER NOT NULL, value REAL DEFAULT 0.0, "
        "PRIMARY KEY (username, bank, period), CHECK (value < 0))"
    )
    target_conn.commit()
    target_conn.close()
    cases.append((usage_old, usage_target, False))

    init_target = tmp / "initializer target.db"
    init_old = make_source_directory(tmp, "initializer-source") / "old.db"
    create_target(init_target)
    create_legacy(
        init_old,
        [2],
        [("erin", 1005, "root", {2: 3.5})],
    )
    target_conn = sqlite3.connect(init_target)
    target_conn.execute("DROP TABLE config_table")
    target_conn.execute(
        "CREATE TABLE config_table (key TEXT PRIMARY KEY NOT NULL, "
        "value TEXT NOT NULL CHECK (key != 'decay_factor'))"
    )
    target_conn.commit()
    target_conn.close()
    cases.append((init_old, init_target, False))

    foreign_key_target = tmp / "foreign key target.db"
    foreign_key_old = make_source_directory(tmp, "foreign-key-source") / "old.db"
    create_target(foreign_key_target)
    create_legacy(
        foreign_key_old,
        [3],
        [("frank", 1006, "science", {3: 4.75})],
    )
    old_conn = sqlite3.connect(foreign_key_old)
    old_conn.execute(
        "UPDATE site_fairshare_policy SET username='missing-parent'"
    )
    old_conn.commit()
    old_conn.close()
    target_conn = sqlite3.connect(foreign_key_target)
    target_conn.execute("DROP TABLE site_fairshare_policy")
    target_conn.execute(
        "CREATE TABLE site_fairshare_policy ("
        "bank TEXT NOT NULL, period INTEGER NOT NULL, username TEXT NOT NULL, "
        "allocation REAL DEFAULT 0.0 NOT NULL, "
        "PRIMARY KEY (username, bank, period), "
        "FOREIGN KEY (username, bank) REFERENCES association_table "
        "(username, bank) DEFERRABLE INITIALLY DEFERRED)"
    )
    target_conn.commit()
    target_conn.close()
    cases.append((foreign_key_old, foreign_key_target, False))

    for old, target, stale in cases:
        assert_post_validation_failure_restored(
            workspace, old, target, stale=stale
        )


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
    backup = Path(str(old) + ".backup")
    assert not backup.exists()
    target_directory = tmp / "target-directory.db"
    target_directory.mkdir()
    before_invalid_target = sha256(old)
    result = run(
        [workspace / "bin/flux-account-update-db", "-p", old, "-n", target_directory],
        expect=None,
    )
    assert result.returncode != 0
    assert sha256(old) == before_invalid_target
    assert not backup.exists()
    target_symlink = tmp / "target-link.db"
    target_symlink.symlink_to(target)
    result = run(
        [workspace / "bin/flux-account-update-db", "-p", old, "-n", target_symlink],
        expect=None,
    )
    assert result.returncode != 0
    assert sha256(old) == before_invalid_target
    assert not backup.exists()
    symlink = source / "linked.db"
    symlink.symlink_to(old)
    result = run(
        [workspace / "bin/flux-account-update-db", "-p", symlink, "-n", target],
        expect=None,
    )
    assert result.returncode != 0
    assert not Path(str(symlink) + ".backup").exists()
    same_file_before = sha256(old)
    result = run(
        [workspace / "bin/flux-account-update-db", "-p", old, "-n", old],
        expect=None,
    )
    assert result.returncode != 0
    assert sha256(old) == same_file_before
    assert not backup.exists()
    target_hardlink = source / "same-physical-file.db"
    os.link(old, target_hardlink)
    result = run(
        [workspace / "bin/flux-account-update-db", "-p", old, "-n", target_hardlink],
        expect=None,
    )
    assert result.returncode != 0
    assert sha256(old) == same_file_before
    assert not backup.exists()


def test_pre_backup_failure_preserves_source(workspace, tmp):
    source = make_source_directory(tmp)
    old = source / "invalid sqlite.db"
    old.write_bytes(b"not-a-sqlite-database")
    handoff(old)
    backup = Path(str(old) + ".backup")
    backup.write_bytes(b"stale-backup-from-an-earlier-run")
    handoff(backup)
    target = tmp / "target.db"
    create_target(target)
    before_old = sha256(old)
    before_backup = sha256(backup)
    result = run(
        [workspace / "bin/flux-account-update-db", "-p", old, "-n", target],
        expect=None,
    )
    assert result.returncode != 0
    assert sha256(old) == before_old
    assert sha256(backup) == before_backup
    assert not Path(str(backup) + ".tmp").exists()


def test_self_contained_without_network_dependencies(workspace, tmp):
    target = tmp / "offline target.db"
    old = make_source_directory(tmp) / "offline source.db"
    create_target(target)
    expected = create_legacy(
        old,
        [6, 0],
        [("offline", 5001, "science", {6: 42.25, 0: -0.5})],
    )
    handoff(old)
    offline_env = {
        "ALL_PROXY": "http://127.0.0.1:9",
        "HTTP_PROXY": "http://127.0.0.1:9",
        "HTTPS_PROXY": "http://127.0.0.1:9",
        "NO_PROXY": "",
        "PIP_NO_INDEX": "1",
    }
    run(
        [workspace / "bin/flux-account-update-db", "-p", old, "-n", target],
        env=offline_env,
    )
    assert_database_matches_target(old, target, expected)


def test_public_help_interface(workspace, tmp):
    del tmp
    result = run([workspace / "bin/flux-account-update-db", "--help"])
    for fragment in EXPECTED_HELP_FRAGMENTS:
        assert fragment in result.stdout, fragment
    assert result.stderr == ""


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
    assert_standard_library_only(workspace)
    assert_network_syscalls_blocked()
    with tempfile.TemporaryDirectory(prefix="flux-accounting-verifier-") as directory:
        root = Path(directory)
        root.chmod(0o711)
        checks = [
            ("public-help-interface", test_public_help_interface),
            ("stdlib-only-offline-execution", test_self_contained_without_network_dependencies),
            ("migration-and-retry", test_migration),
            ("large-finite-usage-values", test_large_finite_usage_values),
            ("period-name-boundaries", test_period_name_boundaries),
            ("out-of-range-only-period-name", test_out_of_range_only_period_names),
            ("no-period-layout", test_no_periods),
            ("empty-association-layouts", test_empty_association_layouts),
            ("post-backup-failure-restore-matrix", test_post_backup_failure_restore_matrix),
            ("wal-backup", test_wal_backup),
            ("invalid-paths", test_invalid_paths),
            ("pre-backup-failure-preserves-source", test_pre_backup_failure_preserves_source),
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
