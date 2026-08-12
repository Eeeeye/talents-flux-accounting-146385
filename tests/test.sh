#!/bin/bash
set -Eeuo pipefail

workspace="${FLUX_ACCOUNTING_WORKSPACE:-/workspace/flux-accounting}"
verifier_root="/logs/verifier"
reward_path="${verifier_root}/reward.txt"
log_path="${verifier_root}/flux-accounting-tests.log"

mkdir -p "${verifier_root}"
chown 0:0 /logs "${verifier_root}"
chmod 0755 /logs "${verifier_root}"
install -o 0 -g 0 -m 0644 /dev/null "${reward_path}"
install -o 0 -g 0 -m 0644 /dev/null "${log_path}"
printf '0\n' >"${reward_path}"
exec > >(tee "${log_path}") 2>&1

if [[ ! -d "${workspace}" || -L "${workspace}" ]]; then
    echo "workspace is missing or unsafe" >&2
    exit 1
fi

if [[ -d "${workspace}/.incident-work" && ! -L "${workspace}/.incident-work" ]]; then
    find "${workspace}/.incident-work" -mindepth 1 -depth -delete
    rmdir "${workspace}/.incident-work"
fi

while IFS= read -r -d '' entry; do
    name="$(basename -- "${entry}")"
    case "${name}" in
        .dockerignore|.gitignore|DISCLAIMER.LLNS|LICENSE|Makefile|NOTICE.LLNS|README.md|UPSTREAM.md|bin|scripts|src)
            ;;
        *)
            echo "path outside the allowed workspace surface: ${name}" >&2
            exit 1
            ;;
    esac
done < <(find "${workspace}" -mindepth 1 -maxdepth 1 -print0)

if find "${workspace}" -xdev \( -type l -o -type b -o -type c -o -type p -o -type s \) -print -quit | grep -q .; then
    echo "workspace contains a symlink or special file" >&2
    exit 1
fi
if find "${workspace}" -xdev -type f -links +1 -print -quit | grep -q .; then
    echo "workspace contains a multiply-linked file" >&2
    exit 1
fi
file_count="$(find "${workspace}" -xdev -type f | wc -l)"
byte_count="$(find "${workspace}" -xdev -type f -printf '%s\n' | awk '{sum += $1} END {print sum + 0}')"
(( file_count <= 250 )) || { echo "workspace contains too many files" >&2; exit 1; }
(( byte_count <= 10000000 )) || { echo "workspace is unexpectedly large" >&2; exit 1; }

python3 -B /tests/verify_starter_assets.py "${workspace}"

if [[ ! -d /tests || -L /tests ]]; then
    echo "verifier input directory is missing or unsafe" >&2
    exit 1
fi
chown -R 0:0 /tests
find /tests -type d -exec chmod 0700 {} +
find /tests -type f -exec chmod 0600 {} +

if [[ -f /.dockerenv ]]; then
python3 - <<'PY'
import os
import signal
from pathlib import Path

for entry in Path('/proc').iterdir():
    if not entry.name.isdigit():
        continue
    if entry.name == '1':
        continue
    try:
        lines = (entry / 'status').read_text().splitlines()
        uid = int(next(line for line in lines if line.startswith('Uid:')).split()[1])
        if uid == 1000:
            os.kill(int(entry.name), signal.SIGKILL)
    except (FileNotFoundError, PermissionError, ProcessLookupError, StopIteration):
        pass
PY
fi

python3 -B /tests/test_task.py --workspace "${workspace}"
printf '1\n' >"${reward_path}"
