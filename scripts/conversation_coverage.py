#!/usr/bin/env python3
"""Aggregate conversation coverage without emitting identities or content."""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import re
import sys
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import sqlcipher3

from validate_read_access import ValidationFailure, _connect_read_only, _load_keys


ORDINARY_DB_RE = re.compile(r"^message_(\d+)\.db$")
BUSINESS_DB_RE = re.compile(r"^biz_message_(\d+)\.db$")
MSG_TABLE_RE = re.compile(r"^Msg_([0-9a-fA-F]{32})$")
REQUIRED_MESSAGE_COLUMNS = (
    "local_id",
    "server_id",
    "local_type",
    "real_sender_id",
    "create_time",
    "message_content",
    "WCDB_CT_message_content",
)
FETCH_SIZE = 2048


class CoverageError(Exception):
    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


@dataclass
class CategoryCoverage:
    raw_rows: int = 0
    nonempty_conversations: set[str] = field(default_factory=set)
    unknown_conversations: set[str] = field(default_factory=set)
    earliest: float | None = None
    latest: float | None = None
    per_shard: list[dict[str, int]] = field(default_factory=list)

    def observe_time(self, value: Any) -> None:
        timestamp = _timestamp_seconds(value)
        if timestamp is None:
            return
        if self.earliest is None or timestamp < self.earliest:
            self.earliest = timestamp
        if self.latest is None or timestamp > self.latest:
            self.latest = timestamp

    def report(self) -> dict[str, Any]:
        return {
            "raw_rows": self.raw_rows,
            "nonempty_conversations": len(self.nonempty_conversations),
            "unmapped_conversations": len(self.unknown_conversations),
            "start_time_utc": _iso_time(self.earliest),
            "end_time_utc": _iso_time(self.latest),
            "per_shard": self.per_shard,
        }


def _emit(value: dict[str, Any]) -> None:
    json.dump(value, sys.stdout, ensure_ascii=False, separators=(",", ":"))
    sys.stdout.write("\n")


def _quote_identifier(value: str) -> str:
    return '"' + value.replace('"', '""') + '"'


def _identity_bytes(value: Any) -> bytes | None:
    if isinstance(value, str):
        encoded = value.encode("utf-8")
    elif isinstance(value, (bytes, bytearray, memoryview)):
        encoded = bytes(value)
    else:
        return None
    return encoded if encoded else None


def _table_hash(value: Any) -> str | None:
    encoded = _identity_bytes(value)
    if encoded is None:
        return None
    return hashlib.md5(encoded).hexdigest()


def _timestamp_seconds(value: Any) -> float | None:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    number = float(value)
    if not math.isfinite(number) or number <= 0:
        return None
    # Desktop schemas have used seconds and milliseconds.  Normalize only for
    # comparison and aggregate time output; the raw value is never reported.
    if number >= 1e15:
        number /= 1_000_000.0
    elif number >= 1e12:
        number /= 1_000.0
    return number


def _iso_time(value: float | None) -> str | None:
    if value is None:
        return None
    try:
        return datetime.fromtimestamp(value, tz=timezone.utc).isoformat().replace(
            "+00:00", "Z"
        )
    except (OverflowError, OSError, ValueError):
        return None


def _open_required(root: Path, keys: dict[str, dict[str, str]], rel: str):
    path = root / rel
    if not path.is_file():
        raise CoverageError("required_database_missing")
    key_info = keys.get(rel)
    if key_info is None:
        raise CoverageError("required_key_missing")
    try:
        conn = _connect_read_only(path, key_info)
        conn.execute("BEGIN")
        return conn
    except sqlcipher3.Error as exc:
        raise CoverageError("database_open_failed") from exc


def _known_hashes_from_contact_and_session(
    root: Path, keys: dict[str, dict[str, str]]
) -> tuple[set[str], dict[bytes, float]]:
    known_hashes: set[str] = set()
    sessions: dict[bytes, float] = {}

    contact = _open_required(root, keys, "contact/contact.db")
    try:
        cursor = contact.execute(
            "SELECT username, nick_name, remark, local_type, delete_flag FROM contact"
        )
        for row in cursor:
            hashed = _table_hash(row[0])
            if hashed is not None:
                known_hashes.add(hashed)
    except sqlcipher3.Error as exc:
        raise CoverageError("contact_schema_or_read_failed") from exc
    finally:
        contact.rollback()
        contact.close()

    session = _open_required(root, keys, "session/session.db")
    try:
        cursor = session.execute(
            "SELECT username, type, is_hidden, last_timestamp, "
            "last_msg_locald_id, last_msg_type FROM SessionTable"
        )
        for row in cursor:
            identity = _identity_bytes(row[0])
            hashed = _table_hash(row[0])
            if identity is None or hashed is None:
                continue
            known_hashes.add(hashed)
            timestamp = _timestamp_seconds(row[3])
            if timestamp is not None:
                sessions[identity] = max(timestamp, sessions.get(identity, 0.0))
    except sqlcipher3.Error as exc:
        raise CoverageError("session_schema_or_read_failed") from exc
    finally:
        session.rollback()
        session.close()
    return known_hashes, sessions


def _discover_message_databases(root: Path) -> list[tuple[str, int, Path, str]]:
    message_root = root / "message"
    if not message_root.is_dir():
        raise CoverageError("message_directory_missing")
    result: list[tuple[str, int, Path, str]] = []
    for path in message_root.iterdir():
        if not path.is_file():
            continue
        match = ORDINARY_DB_RE.fullmatch(path.name)
        category = "ordinary"
        if match is None:
            match = BUSINESS_DB_RE.fullmatch(path.name)
            category = "business"
        if match is not None:
            result.append((category, int(match.group(1)), path, f"message/{path.name}"))
    result.sort(key=lambda item: (item[0], item[1]))
    if not any(item[0] == "ordinary" for item in result):
        raise CoverageError("ordinary_message_database_missing")
    return result


def _message_tables(conn) -> list[tuple[str, str]]:
    tables: list[tuple[str, str]] = []
    try:
        rows = conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name"
        )
        for (name,) in rows:
            if not isinstance(name, str):
                continue
            match = MSG_TABLE_RE.fullmatch(name)
            if match is not None:
                tables.append((name, match.group(1).lower()))
    except sqlcipher3.Error as exc:
        raise CoverageError("message_table_enumeration_failed") from exc
    return tables


def _verify_columns(conn, table: str) -> None:
    try:
        columns = {
            row[1] for row in conn.execute(
                f"PRAGMA table_info({_quote_identifier(table)})"
            )
        }
    except sqlcipher3.Error as exc:
        raise CoverageError("message_schema_read_failed") from exc
    if not set(REQUIRED_MESSAGE_COLUMNS).issubset(columns):
        raise CoverageError("message_columns_missing")


def _scan_messages(
    conn,
    category: CategoryCoverage,
    known_hashes: set[str],
    all_table_hashes: set[str],
    latest_by_hash: dict[str, float],
) -> int:
    shard_rows = 0
    selected = ",".join(_quote_identifier(name) for name in REQUIRED_MESSAGE_COLUMNS)
    for table, table_hash in _message_tables(conn):
        all_table_hashes.add(table_hash)
        _verify_columns(conn, table)
        quoted = _quote_identifier(table)
        try:
            expected = conn.execute(f"SELECT COUNT(*) FROM {quoted}").fetchone()[0]
            cursor = conn.execute(f"SELECT {selected} FROM {quoted}")
            seen = 0
            table_latest: float | None = None
            while True:
                rows = cursor.fetchmany(FETCH_SIZE)
                if not rows:
                    break
                seen += len(rows)
                for row in rows:
                    timestamp = _timestamp_seconds(row[4])
                    category.observe_time(row[4])
                    if timestamp is not None and (
                        table_latest is None or timestamp > table_latest
                    ):
                        table_latest = timestamp
            if seen != expected:
                raise CoverageError("message_row_count_mismatch")
        except sqlcipher3.Error as exc:
            raise CoverageError("message_table_read_failed") from exc
        shard_rows += seen
        category.raw_rows += seen
        if seen > 0:
            category.nonempty_conversations.add(table_hash)
            if table_hash not in known_hashes:
                category.unknown_conversations.add(table_hash)
        if table_latest is not None:
            latest_by_hash[table_hash] = max(
                table_latest, latest_by_hash.get(table_hash, 0.0)
            )
    return shard_rows


def build_coverage(root: Path, keys_file: Path) -> dict[str, Any]:
    try:
        keys = _load_keys(keys_file)
    except ValidationFailure as exc:
        raise CoverageError(exc.code) from exc
    known_hashes, sessions = _known_hashes_from_contact_and_session(root, keys)
    databases = _discover_message_databases(root)
    ordinary = CategoryCoverage()
    business = CategoryCoverage()
    all_table_hashes: set[str] = set()
    latest_by_hash: dict[str, float] = {}
    opened: list[tuple[str, int, Any]] = []
    try:
        # Hold all message read transactions while building the complete
        # Name2Id hash set, so a name present only in a later shard can resolve
        # a table present in an earlier shard.
        for category_name, index, path, rel in databases:
            key_info = keys.get(rel)
            if key_info is None:
                raise CoverageError("required_key_missing")
            # Name2Id.rowid is the sender ID used by Msg_*.real_sender_id.  We
            # only consume user_name for hash resolution and never emit it.
            try:
                conn = _connect_read_only(path, key_info)
                conn.execute("BEGIN")
            except sqlcipher3.Error as exc:
                raise CoverageError("database_open_failed") from exc
            opened.append((category_name, index, conn))
            try:
                for (user_name,) in conn.execute("SELECT user_name FROM Name2Id"):
                    hashed = _table_hash(user_name)
                    if hashed is not None:
                        known_hashes.add(hashed)
            except sqlcipher3.Error as exc:
                raise CoverageError("name2id_schema_or_read_failed") from exc

        for category_name, index, conn in opened:
            category = ordinary if category_name == "ordinary" else business
            rows = _scan_messages(
                conn, category, known_hashes, all_table_hashes, latest_by_hash
            )
            category.per_shard.append({"index": index, "rows": rows})
    finally:
        for _category_name, _index, conn in opened:
            try:
                conn.rollback()
            except sqlcipher3.Error:
                pass
            try:
                conn.close()
            except sqlcipher3.Error:
                pass

    session_ahead = 0
    session_without_table = 0
    for identity, session_time in sessions.items():
        table_hash = hashlib.md5(identity).hexdigest()
        latest = latest_by_hash.get(table_hash)
        if table_hash not in all_table_hashes:
            session_without_table += 1
        elif latest is not None and session_time > latest:
            session_ahead += 1

    return {
        "status": "ok",
        "snapshot_scope": "one_read_transaction_per_database",
        "cross_database_atomic": False,
        "ordinary": ordinary.report(),
        "business": business.report(),
        "session": {
            "summary_ahead_of_message_latest": session_ahead,
            "last_timestamp_without_msg_table": session_without_table,
            "interpretation": (
                "diagnostic_only_non_atomic_snapshots_and_unverified_system_or_aggregate_sessions"
            ),
        },
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Aggregate WeChat conversation coverage without content output"
    )
    parser.add_argument("--db-root", required=True, type=Path)
    parser.add_argument("--keys-file", required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        report = build_coverage(args.db_root.resolve(), args.keys_file)
    except CoverageError as exc:
        _emit({"status": "error", "error_code": exc.code})
        return 1
    except Exception:
        _emit({"status": "error", "error_code": "unexpected_coverage_failure"})
        return 1
    _emit(report)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
