#!/usr/bin/env python3
import hashlib
from pathlib import Path
import sys


EXPECTED = {
    ".dockerignore": "55ec31713d53b92307d28414690d42eb8cf1f576be1fe426b4c81ec6d13a1c0b",
    ".gitignore": "0802944a9bc86d956279111d486fe200d1346237ddf24952d38041bfbb29f1b3",
    "DISCLAIMER.LLNS": "d4374c3480f194964ddd595a562f29d7c88849c42d471610cb9e13659ec1c3ef",
    "LICENSE": "e3a994d82e644b03a792a930f574002658412f62407f5fee083f2555c5f23118",
    "Makefile": "13009d6008103f59ddf08941a4c0fd3d26dad7b70b1ce87dc031c309c9e52b62",
    "NOTICE.LLNS": "f4247dde07952a5ff866b24e45b5cdd1fce410cdb2e038255a1635867f59c10c",
    "README.md": "a243647c8b54122cf067d68d6e926b213cb9b66cee9a79139bbe34305637b9af",
    "UPSTREAM.md": "a32200c562610b675f0888a8a21304debeb4131e78d9fc5565ec782012b474ef",
    "scripts/inspect-db.py": "e6bb16ce1edf0182df8714f3a5fa3fe4ebde0dcf9dde231d9a38263896c53913",
    "scripts/make-incident-db.py": "cbc232cd657dd0a742aa4543bb712812fd1db7bbdc686cfc8fbe1c2f62c1c652",
    "scripts/offline-check.sh": "58196035deedd85135c40a3a724f3f13910febf094bdcb2d899074b7d3ab1f89",
    "scripts/reproduce-incident.sh": "fe1b752ef85bb23e661659478396af24c4b41acdc0229c1af24430f89900feef",
}
EDITABLE_ROOTS = {"bin", "src"}
EXPECTED_DIRECTORIES = {
    str(parent)
    for relative in EXPECTED
    for parent in Path(relative).parents
    if str(parent) != "."
}


def sha256(path):
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def main():
    workspace = Path(sys.argv[1])
    observed_protected_files = set()
    for path in workspace.rglob("*"):
        relative = path.relative_to(workspace)
        if relative.parts[0] in EDITABLE_ROOTS:
            continue
        name = relative.as_posix()
        if path.is_dir():
            if name not in EXPECTED_DIRECTORIES:
                raise SystemExit(
                    f"path added outside the allowed src/** and bin/** surface: {name}"
                )
            continue
        if name not in EXPECTED:
            raise SystemExit(
                f"file added outside the allowed src/** and bin/** surface: {name}"
            )
        observed_protected_files.add(name)
    missing = set(EXPECTED) - observed_protected_files
    if missing:
        raise SystemExit(f"protected starter assets are missing: {sorted(missing)}")
    for relative, expected in EXPECTED.items():
        path = workspace / relative
        if not path.is_file() or path.is_symlink():
            raise SystemExit(f"protected starter asset is missing or unsafe: {relative}")
        observed = sha256(path)
        if observed != expected:
            raise SystemExit(f"protected starter asset was modified: {relative}")


if __name__ == "__main__":
    main()
