#!/usr/bin/env python3

###############################################################
# Copyright 2022 Lawrence Livermore National Security, LLC
# (c.f. NOTICE.LLNS, DISCLAIMER.LLNS)
#
# This file is part of the Flux resource manager framework.
# For details, see https://github.com/flux-framework.
#
# SPDX-License-Identifier: LGPL-3.0
###############################################################
import argparse
import os
from pathlib import Path
import re
import shutil
import sqlite3
import sys
import tempfile

from argparse import RawDescriptionHelpFormatter

import fluxacct.accounting
from fluxacct.accounting import create_db as c


CREATE_TABLE_PREFIX = re.compile(
    r"^(\s*CREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?)"
    r'(?:"(?:[^"]|"")*"|`[^`]*`|\[[^\]]+\]|[^\s(]+)',
    re.IGNORECASE | re.DOTALL,
)


def set_db_loc(args):
    return args.old_db if args.old_db else fluxacct.accounting.DB_PATH


def quote(identifier):
    return '"' + str(identifier).replace('"', '""') + '"'


def est_sqlite_conn(path):
    if os.path.islink(path) or not os.path.isfile(path):
        raise ValueError(f"Database file does not exist or is not regular: {path}")
    uri = Path(path).resolve().as_uri() + "?mode=rw"
    conn = sqlite3.connect(uri, uri=True)
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


def get_cols_list(old_columns, new_columns):
    del old_columns
    return list(new_columns)


def table_sql(cur, table_name):
    row = cur.execute(
        "SELECT sql FROM sqlite_master WHERE type='table' AND name=?",
        (table_name,),
    ).fetchone()
    if row is None or not row[0]:
        raise sqlite3.OperationalError(
            f"target table has no reusable CREATE TABLE definition: {table_name}"
        )
    return row[0]


def table_definition(cur, table_name):
    sql = table_sql(cur, table_name)
    opening = sql.find("(")
    if opening < 0:
        raise sqlite3.OperationalError(
            f"target table has malformed CREATE TABLE definition: {table_name}"
        )
    return re.sub(r"\s+", " ", sql[opening:]).strip()


def create_table_from_schema(old_cur, new_cur, source_name, destination_name=None):
    destination_name = destination_name or source_name
    sql = table_sql(new_cur, source_name)
    rewritten, count = CREATE_TABLE_PREFIX.subn(
        lambda match: match.group(1) + quote(destination_name), sql, count=1
    )
    if count != 1:
        raise sqlite3.OperationalError(
            f"cannot retarget CREATE TABLE definition for {source_name}"
        )
    old_cur.execute(rewritten)


def add_tmp_table_to_db(old_cur, new_cur, table_name):
    tmp_name = table_name + "_tmp"
    old_cur.execute(f"DROP TABLE IF EXISTS {quote(tmp_name)}")
    create_table_from_schema(old_cur, new_cur, table_name, tmp_name)


def move_existing_rows(old_cur, cols, old_columns, table):
    old_names = {column[1] for column in old_columns}
    existing = [column[1] for column in cols if column[1] in old_names]
    if not existing:
        return
    names = ", ".join(quote(name) for name in existing)
    old_cur.execute(
        f"INSERT INTO {quote(table[0] + '_tmp')} ({names}) "
        f"SELECT {names} FROM {quote(table[0])}"
    )


def rename_tmp_table(old_cur, table):
    old_cur.execute(f"DROP TABLE {quote(table[0])}")
    old_cur.execute(
        f"ALTER TABLE {quote(table[0] + '_tmp')} RENAME TO {quote(table[0])}"
    )


def update_tables(old_cur, new_cur):
    old_tables = {
        row[0]
        for row in old_cur.execute(
            "SELECT name FROM sqlite_master WHERE type='table'"
        )
    }
    new_tables = [
        row[0]
        for row in new_cur.execute(
            "SELECT name FROM sqlite_master "
            "WHERE type='table' AND name NOT LIKE 'sqlite_%'"
        )
    ]
    for table in new_tables:
        if table not in old_tables:
            create_table_from_schema(old_cur, new_cur, table)


def update_columns(old_cur, new_cur):
    tables = [
        row[0]
        for row in new_cur.execute(
            "SELECT name FROM sqlite_master "
            "WHERE type='table' AND name NOT LIKE 'sqlite_%'"
        )
    ]
    for table in tables:
        new_columns = new_cur.execute(
            f"PRAGMA table_info({quote(table)})"
        ).fetchall()
        old_columns = old_cur.execute(
            f"PRAGMA table_info({quote(table)})"
        ).fetchall()
        if not old_columns:
            continue
        old_signature = [row[1:6] for row in old_columns]
        new_signature = [row[1:6] for row in new_columns]
        if (
            old_signature == new_signature
            and table_definition(old_cur, table) == table_definition(new_cur, table)
        ):
            continue
        add_tmp_table_to_db(old_cur, new_cur, table)
        move_existing_rows(old_cur, new_columns, old_columns, (table,))
        rename_tmp_table(old_cur, (table,))


def init_priority_factor_table(cur):
    factors = (
        ("fairshare", fluxacct.accounting.FSHARE_WEIGHT_DEFAULT),
        ("queue", fluxacct.accounting.QUEUE_WEIGHT_DEFAULT),
        ("bank", fluxacct.accounting.BANK_WEIGHT_DEFAULT),
        ("urgency", fluxacct.accounting.URGENCY_WEIGHT_DEFAULT),
    )
    cur.executemany(
        "INSERT OR IGNORE INTO priority_factor_weight_table (factor, weight) "
        "VALUES (?, ?)",
        factors,
    )


def init_config_table(cur):
    entries = (
        ("priority_decay_half_life", 604800),
        ("priority_usage_reset_period", 2419200),
        ("decay_factor", "0.5"),
        ("node_weight", "1.0"),
        ("core_weight", "0.0"),
        ("gpu_weight", "0.0"),
    )
    cur.executemany("INSERT OR IGNORE INTO config_table VALUES (?, ?)", entries)


def legacy_usage(cur):
    columns = cur.execute("PRAGMA table_info(job_usage_factor_table)").fetchall()
    period_columns = []
    for column in columns:
        prefix = "usage_factor_period_"
        if column[1].startswith(prefix) and column[1][len(prefix):].isdigit():
            period_columns.append((column[1], int(column[1][len(prefix):])))
    if not period_columns:
        return []
    selected = ["username", "userid", "bank"] + [item[0] for item in period_columns]
    query = "SELECT " + ", ".join(quote(name) for name in selected)
    query += " FROM job_usage_factor_table"
    result = []
    for row in cur.execute(query).fetchall():
        for (column_name, period), value in zip(period_columns, row[3:]):
            del column_name
            result.append((row[0], row[1], row[2], period, value))
    return result


def migrate_job_usage_to_per_assoc(cur, rows):
    for username, userid, bank, period, value in rows:
        cur.execute(
            """
            INSERT INTO job_usage_per_association_table
                (username, userid, bank, period, value)
            VALUES (?, ?, ?, ?, ?)
            ON CONFLICT (username, bank, period) DO UPDATE SET
                userid=excluded.userid,
                value=excluded.value
            """,
            (username, userid, bank, period, value),
        )


def write_backup(source, backup):
    source_conn = sqlite3.connect(Path(source).resolve().as_uri() + "?mode=rw", uri=True)
    try:
        checkpoint = source_conn.execute("PRAGMA wal_checkpoint(TRUNCATE)").fetchone()
        if checkpoint is not None and checkpoint[0] != 0:
            raise sqlite3.OperationalError("unable to checkpoint source database")
    finally:
        source_conn.close()
    shutil.copy2(source, backup)


def update_db(path, new_db):
    if os.path.islink(path) or not os.path.isfile(path):
        raise ValueError(f"Database file does not exist or is not regular: {path}")
    if new_db is not None and (os.path.islink(new_db) or not os.path.isfile(new_db)):
        raise ValueError(f"Target schema does not exist or is not regular: {new_db}")
    backup_path = path + ".backup"
    backup_tmp = backup_path + ".tmp"
    if os.path.exists(backup_tmp):
        os.unlink(backup_tmp)
    try:
        write_backup(path, backup_tmp)
        os.replace(backup_tmp, backup_path)
        with tempfile.TemporaryDirectory() as directory:
            if new_db is None:
                target_path = os.path.join(directory, "target.db")
                c.create_db(target_path)
            else:
                target_path = new_db
            old_conn = est_sqlite_conn(path)
            new_conn = sqlite3.connect(
                Path(target_path).resolve().as_uri() + "?mode=ro", uri=True
            )
            try:
                rows = legacy_usage(old_conn.cursor())
                old_conn.execute("BEGIN IMMEDIATE")
                update_tables(old_conn.cursor(), new_conn.cursor())
                update_columns(old_conn.cursor(), new_conn.cursor())
                migrate_job_usage_to_per_assoc(old_conn.cursor(), rows)
                init_priority_factor_table(old_conn.cursor())
                init_config_table(old_conn.cursor())
                old_conn.execute(
                    f"PRAGMA user_version={fluxacct.accounting.DB_SCHEMA_VERSION}"
                )
                if old_conn.execute("PRAGMA integrity_check").fetchone()[0] != "ok":
                    raise sqlite3.IntegrityError("post-migration integrity check failed")
                foreign_key_errors = old_conn.execute(
                    "PRAGMA foreign_key_check"
                ).fetchall()
                if foreign_key_errors:
                    raise sqlite3.IntegrityError(
                        f"post-migration foreign key check failed: {foreign_key_errors}"
                    )
                old_conn.commit()
            except BaseException:
                old_conn.rollback()
                raise
            finally:
                old_conn.close()
                new_conn.close()
    except BaseException:
        if os.path.isfile(backup_path):
            for suffix in ("-wal", "-shm", "-journal"):
                sidecar = path + suffix
                if os.path.exists(sidecar):
                    os.unlink(sidecar)
            shutil.copyfile(backup_path, path)
        if os.path.exists(backup_tmp):
            os.unlink(backup_tmp)
        raise


def main():
    parser = argparse.ArgumentParser(
        description="Update a flux-accounting database schema.",
        formatter_class=RawDescriptionHelpFormatter,
    )
    parser.add_argument("-p", "--path", dest="old_db", help="database file")
    parser.add_argument("-n", "--new-db", dest="new_db", help="target schema")
    args = parser.parse_args()
    try:
        update_db(set_db_loc(args), args.new_db)
    except (OSError, sqlite3.Error, ValueError) as exc:
        print(f"database update failed: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
