#!/usr/bin/env python3
import argparse
import json
import sqlite3


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("database")
    args = parser.parse_args()
    conn = sqlite3.connect(args.database)
    tables = {
        row[0]
        for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")
    }
    payload = {
        "integrity": conn.execute("PRAGMA integrity_check").fetchone()[0],
        "user_version": conn.execute("PRAGMA user_version").fetchone()[0],
        "tables": sorted(tables),
    }
    if "job_usage_per_association_table" in tables:
        payload["usage_primary_key"] = [
            row[1]
            for row in sorted(
                conn.execute("PRAGMA table_info(job_usage_per_association_table)"),
                key=lambda row: row[5],
            )
            if row[5] > 0
        ]
        payload["usage_rows"] = conn.execute(
            """
            SELECT username, userid, bank, period, value
            FROM job_usage_per_association_table
            ORDER BY username, bank, period
            """
        ).fetchall()
    print(json.dumps(payload, sort_keys=True))
    conn.close()


if __name__ == "__main__":
    main()
