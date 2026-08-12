#!/bin/bash
set -Eeuo pipefail

workspace="${FLUX_ACCOUNTING_WORKSPACE:-/workspace/flux-accounting}"
solution_root="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source_path="${solution_root}/files/src/flux_account_update_db.py"
destination="${workspace}/src/flux_account_update_db.py"

if [[ ! -f "${source_path}" || ! -f "${destination}" ]]; then
    echo "missing reference file or workspace source" >&2
    exit 1
fi
cp -- "${source_path}" "${destination}"
