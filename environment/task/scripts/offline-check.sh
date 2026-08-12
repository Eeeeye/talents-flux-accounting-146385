#!/bin/bash
set -Eeuo pipefail

task_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

PYTHONPATH="${task_root}/src" python3 -B -m compileall -q -f -b \
    "${task_root}/src" "${task_root}/scripts"
find "${task_root}" -type f -name '*.pyc' -delete

for script in "${task_root}"/bin/* "${task_root}"/scripts/*.sh; do
    bash -n "${script}"
done

"${task_root}/bin/flux-account-update-db" --help >/dev/null
"${task_root}/bin/flux-account-update-usage" --help >/dev/null
echo "offline source checks passed"
