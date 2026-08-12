#!/usr/bin/env python3

###############################################################
# Copyright 2020 Lawrence Livermore National Security, LLC
# (c.f. NOTICE.LLNS, DISCLAIMER.LLNS)
#
# This file is part of the Flux resource manager framework.
# For details, see https://github.com/flux-framework.
#
# SPDX-License-Identifier: LGPL-3.0
###############################################################
import argparse
import json
import sqlite3
import sys

from fluxacct.accounting.job_usage_calculation import update_job_usage


def main():
    parser = argparse.ArgumentParser(description="Update Flux accounting job usage")
    parser.add_argument("-p", "--path", required=True, help="accounting database")
    args = parser.parse_args()

    try:
        conn = sqlite3.connect(f"file:{args.path}?mode=rw", uri=True)
        update_job_usage(conn)
        rows = conn.execute(
            """
            SELECT username, bank, job_usage
            FROM association_table
            ORDER BY username, bank
            """
        ).fetchall()
        print(
            json.dumps(
                {
                    "database": args.path,
                    "associations": [
                        {"username": row[0], "bank": row[1], "job_usage": row[2]}
                        for row in rows
                    ],
                },
                sort_keys=True,
            )
        )
    except (OSError, sqlite3.Error, ValueError) as exc:
        print(f"usage update failed: {exc}", file=sys.stderr)
        return 1
    finally:
        if "conn" in locals():
            conn.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
