#!/usr/bin/env python3
"""Validate complete, read-only SQLCipher access without exposing row values.

Key file schema::

    {
      "message/message_0.db": {
        "enc_key": "64 lowercase or uppercase hex characters",
        "salt": "32 hex characters"
      }
    }

Keys are indexed by POSIX-style paths relative to ``--db-root``.  Fields whose
names begin with ``_`` are ignored.  The validator opens each source database
with SQLite URI ``mode=ro``, enables ``query_only``, and holds one read
transaction per database.  SQLite/SQLCipher therefore supplies that database's
WAL-consistent snapshot.  Snapshots of different databases are acquired at
different times and are not a cross-database atomic snapshot.

No message values, contact values, keys, salts, or SQL exception text are
printed.  The only output is aggregate JSON statistics and stable error codes.
"""

from __future__ import annotations

import argparse
import io
import json
import os
import re
import sys
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Iterable
from urllib.parse import quote

import sqlcipher3
import zstandard


HEX_32_RE = re.compile(r"^[0-9a-fA-F]{64}$")
HEX_16_RE = re.compile(r"^[0-9a-fA-F]{32}$")
MESSAGE_DB_RE = re.compile(r"^message_\d+\.db$")
MSG_TABLE_RE = re.compile(r"^Msg_[0-9a-fA-F]+$")
FETCH_BATCH = 512


class ValidationFailure(Exception):
    """A failure safe to report by stable code only."""

    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


@dataclass
class DatabaseStats:
    path: str
    status: str = "error"
    wal_present: bool = False
    shm_present: bool = False
    integrity_ok: bool = False
    cipher_integrity_ok: bool = False
    tables: int = 0
    rows: int = 0
    msg_tables: int = 0
    msg_rows: int = 0
    zstd_checked: int = 0
    zstd_errors: int = 0
    source_changed_during_read: bool = False
    errors: list[str] = field(default_factory=list)


def _safe_relpath(path: Path, root: Path) -> str:
    resolved = path.resolve()
    try:
        rel = resolved.relative_to(root.resolve())
    except ValueError as exc:
        raise ValidationFailure("path_outside_db_root") from exc
    return rel.as_posix()


def _source_metadata(paths: Iterable[Path]) -> dict[str, tuple[int, int]]:
    result: dict[str, tuple[int, int]] = {}
    for path in paths:
        try:
            stat = path.stat()
        except FileNotFoundError:
            continue
        result[path.name] = (stat.st_size, stat.st_mtime_ns)
    return result


def _load_keys(path: Path) -> dict[str, dict[str, str]]:
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ValidationFailure("keys_file_invalid") from exc
    if not isinstance(raw, dict):
        raise ValidationFailure("keys_file_invalid")

    result: dict[str, dict[str, str]] = {}
    for rel, value in raw.items():
        if not isinstance(rel, str) or rel.startswith("_"):
            continue
        normalized = rel.replace("\\", "/")
        if normalized.startswith("/") or ".." in Path(normalized).parts:
            raise ValidationFailure("keys_path_invalid")
        if not isinstance(value, dict):
            raise ValidationFailure("key_entry_invalid")
        enc_key = value.get("enc_key")
        salt = value.get("salt")
        if not isinstance(enc_key, str) or not HEX_32_RE.fullmatch(enc_key):
            raise ValidationFailure("enc_key_invalid")
        if not isinstance(salt, str) or not HEX_16_RE.fullmatch(salt):
            raise ValidationFailure("salt_invalid")
        result[normalized] = {
            "enc_key": enc_key.lower(),
            "salt": salt.lower(),
        }
        if "algorithm" in value:
            result[normalized]["algorithm"] = value["algorithm"]
    return result


def _discover_databases(root: Path) -> list[Path]:
    if not root.is_dir():
        raise ValidationFailure("db_root_invalid")
    databases = sorted(
        (path for path in root.rglob("*.db") if path.is_file()),
        key=lambda path: _safe_relpath(path, root),
    )
    if not databases:
        raise ValidationFailure("no_databases")
    return databases


def _quote_identifier(name: str) -> str:
    return '"' + name.replace('"', '""') + '"'


def _preserve_binary_text(raw: bytes):
    # WCDB can store binary serialized values using SQLite's TEXT storage
    # class. Preserve those bytes rather than failing or replacing content.
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        return raw


def _connect_read_only(db_path: Path, key_info: dict[str, str]):
    if key_info.get("algorithm", "hmac-sha512-reserve80") != "hmac-sha512-reserve80":
        raise ValidationFailure("unsupported_cipher_algorithm")
    # safe='/' keeps an absolute POSIX URI readable; all URI metacharacters in
    # the path are escaped.  mode=ro prevents database write transactions.
    uri = "file:" + quote(str(db_path.resolve()), safe="/") + "?mode=ro"
    conn = sqlcipher3.connect(uri, uri=True, timeout=10.0)
    conn.text_factory = _preserve_binary_text
    raw_key = key_info["enc_key"] + key_info["salt"]
    conn.execute(f'PRAGMA key = "x\'{raw_key}\'"')
    conn.execute("PRAGMA query_only = ON")
    conn.execute("PRAGMA temp_store = MEMORY")
    conn.execute("PRAGMA busy_timeout = 10000")
    return conn


def _cipher_integrity_ok(conn) -> bool:
    # SQLCipher returns no rows when all encrypted pages authenticate.
    rows = conn.execute("PRAGMA cipher_integrity_check").fetchall()
    return len(rows) == 0


def _integrity_ok(conn) -> bool:
    rows = conn.execute("PRAGMA integrity_check").fetchall()
    return len(rows) == 1 and rows[0][0] == "ok"


def _table_columns(conn, table: str) -> list[str]:
    return [row[1] for row in conn.execute(
        f"PRAGMA table_info({_quote_identifier(table)})"
    )]


def _stream_table(conn, table: str, stats: DatabaseStats) -> int:
    quoted = _quote_identifier(table)
    expected = conn.execute(f"SELECT COUNT(*) FROM {quoted}").fetchone()[0]
    columns = _table_columns(conn, table)
    compressed_fields = [
        (columns.index(name[len("WCDB_CT_"):]), index)
        for index, name in enumerate(columns)
        if name.startswith("WCDB_CT_") and name[len("WCDB_CT_"):] in columns
    ]
    cursor = conn.execute(f"SELECT * FROM {quoted}")
    seen = 0
    decoder = zstandard.ZstdDecompressor()
    while True:
        batch = cursor.fetchmany(FETCH_BATCH)
        if not batch:
            break
        seen += len(batch)
        for row in batch:
            for content_index, compression_index in compressed_fields:
                if row[compression_index] != 4:
                    continue
                value = row[content_index]
                if not isinstance(value, (bytes, bytearray, memoryview)):
                    stats.zstd_errors += 1
                    continue
                stats.zstd_checked += 1
                try:
                    # Stream and discard output.  Some valid WCDB frames omit a
                    # declared content size, so one-shot decompress is unsafe.
                    total = 0
                    with decoder.stream_reader(io.BytesIO(bytes(value))) as reader:
                        while True:
                            chunk = reader.read(1024 * 1024)
                            if not chunk:
                                break
                            total += len(chunk)
                            if total > 64 * 1024 * 1024:
                                raise ValidationFailure("zstd_output_too_large")
                except ValidationFailure:
                    stats.zstd_errors += 1
                except zstandard.ZstdError:
                    stats.zstd_errors += 1
    if seen != expected:
        raise ValidationFailure("row_count_mismatch")
    return seen


def validate_database(
    db_path: Path, root: Path, key_info: dict[str, str]
) -> DatabaseStats:
    rel = _safe_relpath(db_path, root)
    stats = DatabaseStats(path=rel)
    wal_path = Path(str(db_path) + "-wal")
    shm_path = Path(str(db_path) + "-shm")
    stats.wal_present = wal_path.exists() and wal_path.stat().st_size > 0
    stats.shm_present = shm_path.exists()
    if stats.wal_present and not stats.shm_present:
        stats.errors.append("wal_without_shm_unsupported")
        return stats

    tracked = (db_path, wal_path, shm_path)
    before = _source_metadata(tracked)
    conn = None
    try:
        with db_path.open("rb") as handle:
            actual_salt = handle.read(16).hex()
        if actual_salt != key_info["salt"]:
            raise ValidationFailure("salt_mismatch")

        conn = _connect_read_only(db_path, key_info)
        conn.execute("BEGIN")
        stats.cipher_integrity_ok = _cipher_integrity_ok(conn)
        if not stats.cipher_integrity_ok:
            raise ValidationFailure("cipher_integrity_failed")
        stats.integrity_ok = _integrity_ok(conn)
        if not stats.integrity_ok:
            raise ValidationFailure("integrity_failed")

        tables = [row[0] for row in conn.execute(
            "SELECT name FROM sqlite_master "
            "WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name"
        )]
        stats.tables = len(tables)
        for table in tables:
            count = _stream_table(conn, table, stats)
            stats.rows += count
            if MSG_TABLE_RE.fullmatch(table):
                stats.msg_tables += 1
                stats.msg_rows += count
        if stats.zstd_errors:
            raise ValidationFailure("zstd_validation_failed")
        stats.status = "ok"
    except ValidationFailure as exc:
        stats.errors.append(exc.code)
    except sqlcipher3.DatabaseError:
        stats.errors.append("database_read_failed")
    except (OSError, OverflowError, TypeError, ValueError):
        stats.errors.append("validation_runtime_failed")
    except Exception:
        # Privacy boundary: never emit driver exception text, SQL fragments, or
        # values originating in the database.
        stats.errors.append("unexpected_validation_failure")
    finally:
        if conn is not None:
            try:
                conn.rollback()
            except sqlcipher3.Error:
                pass
            try:
                conn.close()
            except sqlcipher3.Error:
                if "connection_close_failed" not in stats.errors:
                    stats.errors.append("connection_close_failed")
                stats.status = "error"
        after = _source_metadata(tracked)
        # This is diagnostic only: WeChat may legitimately write concurrently,
        # and WAL readers may update reader marks in an existing SHM file.
        stats.source_changed_during_read = before != after
    return stats


def validate_all(db_root: Path, keys_file: Path) -> tuple[dict[str, Any], int]:
    root = db_root.resolve()
    try:
        keys = _load_keys(keys_file)
        databases = _discover_databases(root)
    except ValidationFailure as exc:
        return {
            "status": "error",
            "errors": [exc.code],
            "databases": [],
            "snapshot_scope": "one_read_transaction_per_database",
        }, 1

    results: list[DatabaseStats] = []
    for db_path in databases:
        rel = _safe_relpath(db_path, root)
        key_info = keys.get(rel)
        if key_info is None:
            results.append(DatabaseStats(path=rel, errors=["missing_key"]))
            continue
        results.append(validate_database(db_path, root, key_info))

    unused_keys = sorted(set(keys) - {item.path for item in results})
    totals = {
        "databases": len(results),
        "databases_ok": sum(item.status == "ok" for item in results),
        "tables": sum(item.tables for item in results),
        "rows": sum(item.rows for item in results),
        "msg_tables": sum(item.msg_tables for item in results),
        "msg_rows": sum(item.msg_rows for item in results),
        "zstd_checked": sum(item.zstd_checked for item in results),
        "zstd_errors": sum(item.zstd_errors for item in results),
        "unused_key_entries": len(unused_keys),
    }
    ok = all(item.status == "ok" for item in results) and not unused_keys
    report = {
        "status": "ok" if ok else "error",
        "snapshot_scope": "one_read_transaction_per_database",
        "cross_database_atomic": False,
        "source_write_policy": (
            "mode=ro and query_only; WAL reader marks/locks may update SHM"
        ),
        "totals": totals,
        "databases": [asdict(item) for item in results],
    }
    return report, 0 if ok else 1


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Validate complete read access to encrypted SQLCipher databases"
    )
    parser.add_argument("--db-root", required=True, type=Path)
    parser.add_argument("--keys-file", required=True, type=Path)
    args = parser.parse_args(argv)
    report, exit_code = validate_all(args.db_root, args.keys_file)
    json.dump(report, sys.stdout, ensure_ascii=False, separators=(",", ":"))
    sys.stdout.write("\n")
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
