#!/usr/bin/env python3

# SPDX-License-Identifier: LGPL-3.0
import argparse
import sqlite3
from pathlib import Path


def create_legacy(path):
    conn = sqlite3.connect(path)
    conn.executescript(
        """
        PRAGMA user_version=31;
        CREATE TABLE association_table (
            creation_time INTEGER NOT NULL,
            mod_time INTEGER DEFAULT 0 NOT NULL,
            active INTEGER DEFAULT 1 NOT NULL,
            username TEXT NOT NULL,
            userid INTEGER NOT NULL,
            bank TEXT NOT NULL,
            default_bank TEXT NOT NULL,
            shares INTEGER DEFAULT 1 NOT NULL,
            job_usage REAL DEFAULT 0.0 NOT NULL,
            fairshare REAL DEFAULT 0.5 NOT NULL,
            max_running_jobs INTEGER DEFAULT 5 NOT NULL,
            max_active_jobs INTEGER DEFAULT 7 NOT NULL,
            max_nodes INTEGER DEFAULT 2147483647 NOT NULL,
            max_cores INTEGER DEFAULT 2147483647 NOT NULL,
            queues TEXT DEFAULT '' NOT NULL,
            projects TEXT DEFAULT '*' NOT NULL,
            default_project TEXT DEFAULT '*' NOT NULL,
            max_sched_jobs INTEGER DEFAULT 2147483647 NOT NULL,
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
            usage_factor_period_0 REAL DEFAULT 0.0,
            usage_factor_period_1 REAL DEFAULT 0.0,
            usage_factor_period_2 REAL DEFAULT 0.0,
            usage_factor_period_3 REAL DEFAULT 0.0,
            PRIMARY KEY (username, bank)
        );
        CREATE TABLE t_half_life_period_table (
            cluster TEXT DEFAULT 'cluster',
            end_half_life_period REAL DEFAULT 0.0
        );
        CREATE TABLE queue_table (
            queue TEXT NOT NULL PRIMARY KEY,
            min_nodes_per_job INTEGER DEFAULT 1 NOT NULL,
            max_nodes_per_job INTEGER DEFAULT 1 NOT NULL,
            max_time_per_job INTEGER DEFAULT 60 NOT NULL,
            priority INTEGER DEFAULT 0 NOT NULL
        );
        CREATE TABLE project_table (
            project_id INTEGER PRIMARY KEY AUTOINCREMENT,
            project TEXT NOT NULL,
            usage REAL DEFAULT 0.0 NOT NULL
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
        CREATE TABLE priority_factor_weight_table (
            factor TEXT PRIMARY KEY NOT NULL,
            weight INTEGER NOT NULL
        );
        CREATE TABLE config_table (
            key TEXT PRIMARY KEY NOT NULL,
            value TEXT NOT NULL
        );

        INSERT INTO bank_table (bank, parent_bank, shares) VALUES ('root', '', 1);
        INSERT INTO bank_table (bank, parent_bank, shares) VALUES ('science', 'root', 1);
        INSERT INTO t_half_life_period_table VALUES ('cluster', 4102444800);
        INSERT INTO project_table (project) VALUES ('*');
        INSERT INTO queue_table (queue) VALUES ('batch');
        INSERT INTO priority_factor_weight_table VALUES ('fairshare', 100000);
        INSERT INTO priority_factor_weight_table VALUES ('queue', 10000);
        INSERT INTO priority_factor_weight_table VALUES ('bank', 0);
        INSERT INTO priority_factor_weight_table VALUES ('urgency', 1000);
        INSERT INTO config_table VALUES ('priority_decay_half_life', '604800');
        INSERT INTO config_table VALUES ('priority_usage_reset_period', '2419200');
        INSERT INTO config_table VALUES ('decay_factor', '0.5');
        INSERT INTO config_table VALUES ('node_weight', '1.0');
        INSERT INTO config_table VALUES ('core_weight', '0.0');
        INSERT INTO config_table VALUES ('gpu_weight', '0.0');

        INSERT INTO association_table
            (creation_time, username, userid, bank, default_bank, job_usage)
        VALUES (1710000000, 'alice', 1001, 'science', 'science', 100.0);
        INSERT INTO association_table
            (creation_time, username, userid, bank, default_bank, job_usage)
        VALUES (1710000000, 'bob', 1002, 'science', 'science', 26.0);
        INSERT INTO association_table
            (creation_time, username, userid, bank, default_bank, job_usage)
        VALUES (1710000000, 'alice', 1001, 'root', 'science', 9.0);

        INSERT INTO job_usage_factor_table VALUES
            ('alice', 1001, 'science', 2500, 40.0, 30.0, 20.0, 10.0);
        INSERT INTO job_usage_factor_table VALUES
            ('bob', 1002, 'science', 3000, 11.0, 7.0, 5.0, 3.0);
        INSERT INTO job_usage_factor_table VALUES
            ('alice', 1001, 'root', 1800, 4.0, 3.0, 2.0, 0.0);

        INSERT INTO jobs VALUES
            ('job-long', 1001, 900, 1000, 5000, '0,1', '{}', '{}', '*', 'science', 4000, 4000);
        INSERT INTO jobs VALUES
            ('job-short', 1002, 1900, 2000, 3000, '0', '{}', '{}', '*', 'science', 1000, 1000);
        """
    )
    conn.commit()
    conn.close()


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
            shares INTEGER DEFAULT 1 NOT NULL,
            job_usage REAL DEFAULT 0.0 NOT NULL,
            fairshare REAL DEFAULT 0.5 NOT NULL,
            max_running_jobs INTEGER DEFAULT 5 NOT NULL,
            max_active_jobs INTEGER DEFAULT 7 NOT NULL,
            max_nodes INTEGER DEFAULT 2147483647 NOT NULL,
            max_cores INTEGER DEFAULT 2147483647 NOT NULL,
            queues TEXT DEFAULT '' NOT NULL,
            projects TEXT DEFAULT '*' NOT NULL,
            default_project TEXT DEFAULT '*' NOT NULL,
            max_sched_jobs INTEGER DEFAULT 2147483647 NOT NULL,
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
        CREATE TABLE t_half_life_period_table (
            cluster TEXT DEFAULT 'cluster', end_half_life_period REAL DEFAULT 0.0
        );
        CREATE TABLE queue_table (
            queue TEXT NOT NULL PRIMARY KEY,
            min_nodes_per_job INTEGER DEFAULT 1 NOT NULL,
            max_nodes_per_job INTEGER DEFAULT 1 NOT NULL,
            max_time_per_job INTEGER DEFAULT 60 NOT NULL,
            priority INTEGER DEFAULT 0 NOT NULL
        );
        CREATE TABLE project_table (
            project_id INTEGER PRIMARY KEY AUTOINCREMENT,
            project TEXT NOT NULL,
            usage REAL DEFAULT 0.0 NOT NULL
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
        CREATE TABLE priority_factor_weight_table (
            factor TEXT PRIMARY KEY NOT NULL, weight INTEGER NOT NULL
        );
        CREATE TABLE config_table (
            key TEXT PRIMARY KEY NOT NULL, value TEXT NOT NULL
        );
        CREATE TABLE job_usage_per_association_table (
            username TEXT NOT NULL,
            userid INTEGER NOT NULL,
            bank TEXT NOT NULL,
            period INTEGER NOT NULL,
            value REAL DEFAULT 0.0,
            PRIMARY KEY (username, bank, period)
        );
        """
    )
    conn.close()


def create_add_table_legacy(path):
    conn = sqlite3.connect(path)
    conn.executescript(
        """
        PRAGMA user_version=31;
        CREATE TABLE job_usage_factor_table (
            username TEXT NOT NULL,
            userid INTEGER NOT NULL,
            bank TEXT NOT NULL,
            last_job_timestamp REAL DEFAULT 0.0,
            usage_factor_period_0 REAL DEFAULT 0.0,
            usage_factor_period_1 REAL DEFAULT 0.0,
            PRIMARY KEY (username, bank)
        );
        INSERT INTO job_usage_factor_table VALUES
            ('alice', 1001, 'science', 2500, 40.0, 30.0);
        INSERT INTO job_usage_factor_table VALUES
            ('bob', 1002, 'science', 3000, 11.0, 7.0);
        CREATE TABLE priority_factor_weight_table (
            factor TEXT PRIMARY KEY NOT NULL,
            weight INTEGER NOT NULL
        );
        CREATE TABLE config_table (
            key TEXT PRIMARY KEY NOT NULL,
            value TEXT NOT NULL
        );
        """
    )
    conn.close()


def create_usage_only_target(path):
    conn = sqlite3.connect(path)
    conn.executescript(
        """
        PRAGMA user_version=37;
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
            factor TEXT PRIMARY KEY NOT NULL,
            weight INTEGER NOT NULL
        );
        CREATE TABLE config_table (
            key TEXT PRIMARY KEY NOT NULL,
            value TEXT NOT NULL
        );
        """
    )
    conn.close()


def create_partial_legacy(path):
    create_legacy(path)
    conn = sqlite3.connect(path)
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
        INSERT INTO job_usage_per_association_table
            (username, userid, bank, period, value)
        VALUES ('alice', 1001, 'science', 0, 40.0);
        """
    )
    conn.close()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("directory", type=Path)
    args = parser.parse_args()
    args.directory.mkdir(parents=True, exist_ok=True)
    for name in (
        "legacy.db",
        "target-schema.db",
        "add-table-legacy.db",
        "usage-only-target.db",
        "partial-legacy.db",
    ):
        path = args.directory / name
        if path.exists():
            path.unlink()
    create_legacy(args.directory / "legacy.db")
    create_target(args.directory / "target-schema.db")
    create_add_table_legacy(args.directory / "add-table-legacy.db")
    create_usage_only_target(args.directory / "usage-only-target.db")
    create_partial_legacy(args.directory / "partial-legacy.db")
    print(args.directory / "legacy.db")
    print(args.directory / "target-schema.db")
    print(args.directory / "add-table-legacy.db")
    print(args.directory / "usage-only-target.db")
    print(args.directory / "partial-legacy.db")


if __name__ == "__main__":
    main()
