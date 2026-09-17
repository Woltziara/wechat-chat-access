#!/usr/bin/env python3
"""Save encrypted page-one inventory for the explicitly invoked key collector."""
import argparse
import json
import os
from pathlib import Path
import tempfile


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--db-root", type=Path, required=True)
    ap.add_argument("--out", type=Path, required=True)
    args = ap.parse_args()
    root = args.db_root.resolve()
    if not root.is_dir():
        raise ValueError("db_root_invalid")
    out = args.out.resolve()
    if out.is_relative_to(root):
        raise ValueError("output_inside_source")
    records = []
    plaintext = 0
    for path in sorted(root.rglob("*.db")):
        real = path.resolve()
        if not real.is_relative_to(root):
            raise ValueError("source_symlink_outside_root")
        with path.open("rb") as handle:
            page = handle.read(4096)
        if page.startswith(b"SQLite format 3\0"):
            plaintext += 1
            continue
        if len(page) != 4096:
            raise ValueError("database_page_incomplete")
        records.append({"path": real.relative_to(root).as_posix(),
                        "page1_hex": page.hex()})
    if not records:
        raise ValueError("no_encrypted_databases")
    out.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=out.parent, prefix=".inventory-")
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w") as handle:
            json.dump({"databases": records}, handle)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp, out)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)
    print(json.dumps({"status": "prepared", "encrypted_databases": len(records),
                      "plaintext_databases": plaintext}))


if __name__ == "__main__":
    try:
        main()
    except Exception:
        print(json.dumps({"status": "error", "error_code": "inventory_failed"}))
        raise SystemExit(1)
