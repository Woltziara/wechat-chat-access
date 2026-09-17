#!/usr/bin/env python3
"""Bounded, read-only access to local WeChat 4.x conversation databases.

The command intentionally emits JSON only.  Database and crypto exceptions are
converted to stable codes so keys, salts, SQL text, and database values never
appear in diagnostics.
"""

from __future__ import annotations

import argparse
import hashlib
import io
import json
import math
import plistlib
import re
import sys
import xml.etree.ElementTree as ET
from dataclasses import asdict
from datetime import date, datetime, time, timedelta
from pathlib import Path
from typing import Any, Iterable
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit
from zoneinfo import ZoneInfo

import sqlcipher3
import zstandard

import conversation_coverage
from validate_read_access import (
    ValidationFailure,
    _connect_read_only,
    _discover_databases,
    _load_keys,
    _safe_relpath,
    validate_all,
    validate_database,
)


DEFAULT_CONFIG = Path("~/Library/Application Support/CodexWeChatRead/config.json")
DEFAULT_KEYS = Path("~/Library/Application Support/CodexWeChatRead/validated-keys.json")
DEFAULT_CONTAINER = Path(
    "~/Library/Containers/com.tencent.xinWeChat/Data/Documents/xwechat_files"
)
SHANGHAI = ZoneInfo("Asia/Shanghai")
ORDINARY_RE = re.compile(r"^message_(\d+)\.db$")
BUSINESS_RE = re.compile(r"^biz_message_(\d+)\.db$")
MSG_TABLE_RE = re.compile(r"^Msg_([0-9a-fA-F]{32})$")
SENSITIVE_PARAM_RE = re.compile(
    r"^(?:aes_?key|cdn[a-z_]*key|encfilekey|encrykey|encryptkey|api_?key|key|token|access_?token|refresh_?token|"
    r"(?:pass_)?ticket|skey|password|passwd|pwd|signature|sign|secret|client_?secret|credential|"
    r"authorization|auth|auth_?key|expires?|expire_?time|ws_?secret|ws_?time)$",
    re.I,
)
URL_RE = re.compile(r"https?://[^\s<>\"']+", re.I)
CREDENTIAL_ASSIGNMENT_RE = re.compile(
    r"(?i)\b(api[-_ ]?key|access[-_ ]?token|refresh[-_ ]?token|authorization|"
    r"auth[-_ ]?key|aes[-_ ]?key|cdn[a-z_-]*key|encfilekey|encrykey|encryptkey|client[-_ ]?secret|password|"
    r"passwd|pwd|secret|credential|(?:pass_)?ticket|skey|token|key)\b([\"']?\s*[:=]\s*)"
    r"(?:\"[^\"]{4,}\"|'[^']{4,}'|[^\s,;&<>]{4,})"
)
BEARER_RE = re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._~+/=-]{6,}")
MAX_DECOMPRESSED = 64 * 1024 * 1024
FETCH_SIZE = 512


class AccessError(Exception):
    def __init__(self, code: str, metadata: dict[str, Any] | None = None):
        super().__init__(code)
        self.code = code
        self.metadata = metadata or {}


def _emit(value: dict[str, Any]) -> None:
    json.dump(value, sys.stdout, ensure_ascii=False, separators=(",", ":"))
    sys.stdout.write("\n")


def _text(value: Any) -> str | None:
    if isinstance(value, str):
        return value
    if isinstance(value, (bytes, bytearray, memoryview)):
        try:
            return bytes(value).decode("utf-8")
        except UnicodeDecodeError:
            return None
    return None


def _identity_bytes(value: Any) -> bytes | None:
    if isinstance(value, str):
        result = value.encode("utf-8")
    elif isinstance(value, (bytes, bytearray, memoryview)):
        result = bytes(value)
    else:
        return None
    return result or None


def _identity_hash(value: Any) -> str | None:
    raw = _identity_bytes(value)
    return hashlib.md5(raw).hexdigest() if raw else None


def _quote(name: str) -> str:
    return '"' + name.replace('"', '""') + '"'


def _load_config(config_path: Path, db_root: Path | None, keys_file: Path | None):
    config: dict[str, Any] = {}
    expanded_config = config_path.expanduser()
    if expanded_config.exists():
        try:
            raw = json.loads(expanded_config.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError) as exc:
            raise AccessError("config_invalid") from exc
        if not isinstance(raw, dict):
            raise AccessError("config_invalid")
        config = raw

    root_value = db_root or config.get("db_root")
    if root_value is None:
        container = DEFAULT_CONTAINER.expanduser()
        candidates = sorted(
            path for path in container.glob("*/db_storage") if path.is_dir()
        )
        if not candidates:
            raise AccessError("db_root_not_found")
        if len(candidates) != 1:
            raise AccessError(
                "multiple_db_roots", {"candidate_count": len(candidates)}
            )
        root = candidates[0]
    else:
        if not isinstance(root_value, (str, Path)):
            raise AccessError("config_invalid")
        root = Path(root_value).expanduser()
    if not root.is_dir():
        raise AccessError("db_root_invalid")

    key_value = keys_file or config.get("keys_file") or DEFAULT_KEYS
    if not isinstance(key_value, (str, Path)):
        raise AccessError("config_invalid")
    return root.resolve(), Path(key_value).expanduser()


def _message_databases(root: Path) -> list[tuple[str, Path]]:
    folder = root / "message"
    if not folder.is_dir():
        raise AccessError("message_directory_missing")
    found: list[tuple[int, int, str, Path]] = []
    for path in folder.iterdir():
        if not path.is_file():
            continue
        match = ORDINARY_RE.fullmatch(path.name)
        kind = 0
        if match is None:
            match = BUSINESS_RE.fullmatch(path.name)
            kind = 1
        if match is not None:
            found.append((kind, int(match.group(1)), f"message/{path.name}", path))
    found.sort()
    if not any(kind == 0 for kind, _index, _rel, _path in found):
        raise AccessError("ordinary_message_database_missing")
    return [(rel, path) for _kind, _index, rel, path in found]


def _open(root: Path, keys: dict[str, dict[str, str]], rel: str):
    path = root / rel
    if not path.is_file():
        raise AccessError("required_database_missing", {"path": rel})
    key = keys.get(rel)
    if key is None:
        raise AccessError("required_key_missing", {"path": rel})
    conn = None
    try:
        conn = _connect_read_only(path, key)
        conn.execute("BEGIN")
        # SQLCipher accepts PRAGMA key before it authenticates a page.  Force a
        # harmless schema-page read here so every caller gets the same stable
        # open failure instead of a later operation-specific error.
        conn.execute("SELECT COUNT(*) FROM sqlite_master").fetchone()
        return conn
    except sqlcipher3.Error as exc:
        if conn is not None:
            _close(conn)
        raise AccessError("database_open_failed", {"path": rel}) from exc


def _close(conn: Any) -> None:
    try:
        conn.rollback()
    except sqlcipher3.Error:
        pass
    try:
        conn.close()
    except sqlcipher3.Error:
        pass


def _columns(conn: Any, table: str) -> set[str]:
    try:
        return {row[1] for row in conn.execute(f"PRAGMA table_info({_quote(table)})")}
    except sqlcipher3.Error as exc:
        raise AccessError("schema_read_failed") from exc


def _message_tables(conn: Any) -> list[tuple[str, str]]:
    try:
        rows = conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name"
        )
        result = []
        for (name,) in rows:
            if isinstance(name, str) and (match := MSG_TABLE_RE.fullmatch(name)):
                result.append((name, match.group(1).lower()))
        return result
    except sqlcipher3.Error as exc:
        raise AccessError("message_table_enumeration_failed") from exc


def _all_identity_data(root: Path, keys: dict[str, dict[str, str]]):
    contacts: dict[str, dict[str, str | None]] = {}
    sessions: set[str] = set()
    hash_to_users: dict[str, set[str]] = {}
    sender_maps: dict[str, dict[int, str]] = {}

    conn = _open(root, keys, "contact/contact.db")
    try:
        cols = _columns(conn, "contact")
        required = {"username", "nick_name", "remark"}
        if not required.issubset(cols):
            raise AccessError("contact_columns_missing")
        for username, nick, remark, alias in conn.execute(
            "SELECT username,nick_name,remark,"
            + ("alias" if "alias" in cols else "NULL")
            + " FROM contact"
        ):
            user = _text(username)
            if not user:
                continue
            contacts[user] = {
                "nickname": _text(nick),
                "remark": _text(remark),
                "alias": _text(alias),
            }
            hash_to_users.setdefault(hashlib.md5(user.encode()).hexdigest(), set()).add(user)
    except sqlcipher3.Error as exc:
        raise AccessError("contact_schema_or_read_failed") from exc
    finally:
        _close(conn)

    conn = _open(root, keys, "session/session.db")
    try:
        if "username" not in _columns(conn, "SessionTable"):
            raise AccessError("session_columns_missing")
        for (value,) in conn.execute("SELECT username FROM SessionTable"):
            user = _text(value)
            if user:
                sessions.add(user)
                hash_to_users.setdefault(hashlib.md5(user.encode()).hexdigest(), set()).add(user)
    except sqlcipher3.Error as exc:
        raise AccessError("session_schema_or_read_failed") from exc
    finally:
        _close(conn)

    for rel, _path in _message_databases(root):
        conn = _open(root, keys, rel)
        mapping: dict[int, str] = {}
        try:
            cols = _columns(conn, "Name2Id")
            if "user_name" not in cols:
                raise AccessError("name2id_columns_missing", {"path": rel})
            for rowid, value in conn.execute("SELECT rowid,user_name FROM Name2Id"):
                user = _text(value)
                if not user:
                    continue
                mapping[int(rowid)] = user
                hash_to_users.setdefault(hashlib.md5(user.encode()).hexdigest(), set()).add(user)
        except (sqlcipher3.Error, TypeError, ValueError) as exc:
            if isinstance(exc, AccessError):
                raise
            raise AccessError("name2id_schema_or_read_failed", {"path": rel}) from exc
        finally:
            _close(conn)
        sender_maps[rel] = mapping
    return contacts, sessions, hash_to_users, sender_maps


def _display_name(user: str, contacts: dict[str, dict[str, str | None]]) -> str:
    record = contacts.get(user, {})
    return record.get("remark") or record.get("nickname") or record.get("alias") or user


def _conversation_catalog(root: Path, keys: dict[str, dict[str, str]]):
    contacts, sessions, hash_to_users, sender_maps = _all_identity_data(root, keys)
    table_sources: dict[str, list[dict[str, str]]] = {}
    for rel, _path in _message_databases(root):
        conn = _open(root, keys, rel)
        try:
            for table, digest in _message_tables(conn):
                table_sources.setdefault(digest, []).append({"path": rel, "table": table})
        finally:
            _close(conn)
    chats = []
    for digest in sorted(table_sources):
        users = sorted(hash_to_users.get(digest, ()))
        if len(users) == 1:
            user = users[0]
            chat_id = user
            display = _display_name(user, contacts)
        else:
            user = None
            chat_id = "hash:" + digest
            display = chat_id
        chats.append(
            {
                "chat_id": chat_id,
                "username": user,
                "display_name": display,
                "in_sessions": bool(user and user in sessions),
                "hash": digest,
                "sources": table_sources[digest],
                "search_names": sorted(
                    {
                        item
                        for item in (
                            user,
                            contacts.get(user, {}).get("nickname") if user else None,
                            contacts.get(user, {}).get("remark") if user else None,
                            contacts.get(user, {}).get("alias") if user else None,
                        )
                        if item
                    }
                ),
            }
        )
    return chats, contacts, sender_maps


def _public_chat(chat: dict[str, Any]) -> dict[str, Any]:
    return {
        "chat_id": chat["chat_id"],
        "username": chat["username"],
        "display_name": chat["display_name"],
        "in_sessions": chat["in_sessions"],
        "shard_count": len(chat["sources"]),
    }


def _resolve_chat(chats: list[dict[str, Any]], chat_id: str | None, name: str | None):
    if chat_id:
        needle = chat_id.lower() if chat_id.startswith("hash:") else chat_id
        matches = [c for c in chats if c["chat_id"] == needle]
        if not matches:
            raise AccessError("chat_not_found")
        return matches[0]
    if not name:
        raise AccessError("chat_required")
    exact = [c for c in chats if name in c["search_names"]]
    matches = exact or [
        c for c in chats
        if any(name.casefold() in candidate.casefold() for candidate in c["search_names"])
    ]
    if not matches:
        raise AccessError("chat_not_found")
    if len(matches) != 1:
        raise AccessError(
            "ambiguous_chat", {"candidates": [_public_chat(c) for c in matches[:20]]}
        )
    return matches[0]


def _timestamp(value: Any) -> float | None:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    result = float(value)
    if not math.isfinite(result) or result <= 0:
        return None
    if result >= 1e15:
        result /= 1_000_000
    elif result >= 1e12:
        result /= 1_000
    return result


def _iso(value: float | None) -> str | None:
    try:
        return datetime.fromtimestamp(value, SHANGHAI).isoformat() if value else None
    except (OverflowError, OSError, ValueError):
        return None


def _parse_bound(value: str | None, until: bool = False) -> float | None:
    if value is None:
        return None
    try:
        if re.fullmatch(r"\d{4}-\d{2}-\d{2}", value):
            day = date.fromisoformat(value)
            moment = datetime.combine(day, time.min, SHANGHAI)
            if until:
                moment += timedelta(days=1)
        else:
            moment = datetime.fromisoformat(value)
            if moment.tzinfo is None:
                moment = moment.replace(tzinfo=SHANGHAI)
        return moment.timestamp()
    except ValueError as exc:
        raise AccessError("invalid_datetime") from exc


def _decompress(value: Any) -> tuple[str | None, str | None]:
    if not isinstance(value, (bytes, bytearray, memoryview)):
        return None, "compressed_content_not_binary"
    try:
        total = 0
        chunks: list[bytes] = []
        with zstandard.ZstdDecompressor().stream_reader(io.BytesIO(bytes(value))) as reader:
            while True:
                chunk = reader.read(1024 * 1024)
                if not chunk:
                    break
                total += len(chunk)
                if total > MAX_DECOMPRESSED:
                    return None, "decompressed_content_too_large"
                chunks.append(chunk)
        return b"".join(chunks).decode("utf-8"), None
    except (zstandard.ZstdError, UnicodeDecodeError):
        return None, "content_decode_failed"


def _redact_url(value: str) -> tuple[str, bool]:
    try:
        split = urlsplit(value)
        query = []
        redacted = "@" in split.netloc or bool(split.fragment)
        for key, val in parse_qsl(split.query, keep_blank_values=True):
            if SENSITIVE_PARAM_RE.fullmatch(key):
                val = "[redacted]"
                redacted = True
            query.append((key, val))
        netloc = split.netloc.rsplit("@", 1)[-1]
        return urlunsplit((split.scheme, netloc, split.path, urlencode(query), "")), redacted
    except ValueError:
        return "[unavailable URL]", True


def _sanitize_visible_text(value: str) -> tuple[str, list[str]]:
    redacted = False

    def replace_url(match: re.Match[str]) -> str:
        nonlocal redacted
        rendered, changed = _redact_url(match.group(0))
        redacted = redacted or changed
        return rendered

    result, bearer_count = BEARER_RE.subn("Bearer [redacted]", value)
    redacted = redacted or bearer_count > 0

    def replace_assignment(match: re.Match[str]) -> str:
        nonlocal redacted
        redacted = True
        return match.group(1) + match.group(2) + "[redacted]"

    result = CREDENTIAL_ASSIGNMENT_RE.sub(replace_assignment, result)
    result = URL_RE.sub(replace_url, result)
    return result, (["credential_redacted"] if redacted else [])


def _render_xml(value: str) -> tuple[str, list[str]]:
    warnings: list[str] = []
    try:
        root = ET.fromstring(value.strip())
    except ET.ParseError:
        # With malformed XML we cannot reliably separate visible copy from
        # signed media URLs or protocol credentials.
        return "[unavailable card]", ["xml_parse_failed"]
    visible: list[str] = []
    wanted = {"title", "des", "content", "displayname"}
    for elem in root.iter():
        tag = elem.tag.rsplit("}", 1)[-1].lower()
        text_value = (elem.text or "").strip()
        if not text_value or SENSITIVE_PARAM_RE.fullmatch(tag):
            continue
        if tag in wanted:
            # Referenced-message content can itself contain escaped protocol
            # XML.  Do not surface it unless it is ordinary visible copy.
            if text_value.lstrip().startswith("<"):
                warnings.append("nested_xml_not_rendered")
                continue
            sanitized, redaction_warnings = _sanitize_visible_text(text_value)
            warnings.extend(redaction_warnings)
            visible.append(sanitized)
        elif tag in {"url", "lowurl"} and text_value.startswith(("http://", "https://")):
            sanitized, changed = _redact_url(text_value)
            if changed:
                warnings.append("credential_redacted")
            visible.append(sanitized)
    deduped = list(dict.fromkeys(visible))
    return " | ".join(deduped) or "[card or system message]", list(dict.fromkeys(warnings))


def _render_content(local_type: int, value: Any, compression: Any):
    warnings: list[str] = []
    if compression == 4:
        content, warning = _decompress(value)
        if warning:
            return "[unavailable message content]", [warning]
    elif compression not in (None, 0):
        return "[unavailable message content]", ["unsupported_content_compression"]
    else:
        content = _text(value)
        if content is None:
            return "[unavailable message content]", ["content_not_utf8"]
    base_type = local_type & 0xFFFFFFFF
    stripped = content.lstrip()
    labels = {3: "image", 34: "voice", 43: "video"}
    if base_type in labels:
        return f"[{labels[base_type]} message]", ["media_not_decoded"]
    if stripped.startswith("<"):
        return _render_xml(content)
    if base_type in {1, 49, 10000}:
        return _sanitize_visible_text(content)
    return f"[message type {base_type}]", warnings


def _read_table_rows(
    conn: Any,
    rel: str,
    table: str,
    sender_map: dict[int, str],
    contacts: dict[str, dict[str, str | None]],
    since: float | None,
    until: float | None,
) -> Iterable[dict[str, Any]]:
    cols = _columns(conn, table)
    required = {"local_id", "server_id", "local_type", "real_sender_id", "create_time", "message_content"}
    if not required.issubset(cols):
        raise AccessError("message_columns_missing", {"path": rel})
    selected = [
        "local_id", "server_id", "local_type", "real_sender_id", "create_time",
        "message_content",
        "WCDB_CT_message_content" if "WCDB_CT_message_content" in cols else "NULL",
        "source" if "source" in cols else "NULL",
        "WCDB_CT_source" if "WCDB_CT_source" in cols else "NULL",
    ]
    sql = "SELECT " + ",".join(selected) + f" FROM {_quote(table)}"
    try:
        cursor = conn.execute(sql)
        while True:
            batch = cursor.fetchmany(FETCH_SIZE)
            if not batch:
                break
            for local_id, server_id, local_type, sender_id, raw_time, content, compression, source, source_compression in batch:
                stamp = _timestamp(raw_time)
                if since is not None and (stamp is None or stamp < since):
                    continue
                if until is not None and (stamp is None or stamp >= until):
                    continue
                try:
                    numeric_type = int(local_type)
                except (TypeError, ValueError, OverflowError):
                    numeric_type = 0
                rendered, warnings = _render_content(numeric_type, content, compression)
                if source is not None:
                    if source_compression == 4:
                        source_text, source_warning = _decompress(source)
                        if source_warning:
                            warnings.append("source_" + source_warning)
                    elif source_compression not in (None, 0):
                        source_text = None
                        warnings.append("source_unsupported_compression")
                    else:
                        source_text = _text(source)
                        if source_text is None:
                            warnings.append("source_not_utf8")
                    if source_text and source_text.lstrip().startswith("<"):
                        source_rendered, source_warnings = _render_xml(source_text)
                        warnings.extend("source_" + item for item in source_warnings)
                        if source_rendered not in {"[card or system message]", "[unavailable card]"}:
                            rendered = rendered + " | " + source_rendered
                try:
                    sender = sender_map.get(int(sender_id))
                except (TypeError, ValueError, OverflowError):
                    sender = None
                yield {
                    "source_db": rel,
                    "local_id": str(local_id),
                    "server_id": str(server_id),
                    "create_time": raw_time,
                    "create_time_iso": _iso(stamp),
                    "sender_username": sender,
                    "sender_display": _display_name(sender, contacts) if sender else None,
                    "type": numeric_type,
                    "text": rendered,
                    "parsing_warnings": warnings,
                    "_timestamp": stamp,
                }
    except sqlcipher3.Error as exc:
        raise AccessError("message_table_read_failed", {"path": rel}) from exc


def _read_chat_rows(root: Path, keys: dict[str, dict[str, str]], chat: dict[str, Any], contacts, sender_maps, since, until):
    rows: list[dict[str, Any]] = []
    for source in chat["sources"]:
        rel, table = source["path"], source["table"]
        conn = _open(root, keys, rel)
        try:
            rows.extend(_read_table_rows(conn, rel, table, sender_maps[rel], contacts, since, until))
        finally:
            _close(conn)
    rows.sort(key=lambda row: (row["_timestamp"] is not None, row["_timestamp"] or 0, row["source_db"], row["local_id"]))
    return rows


def _page_latest(rows: list[dict[str, Any]], limit: int, offset: int):
    if limit < 0 or offset < 0:
        raise AccessError("invalid_pagination")
    if limit == 0:
        end = max(0, len(rows) - offset)
        selected = rows[:end]
        has_more = False
    else:
        end = max(0, len(rows) - offset)
        start = max(0, end - limit)
        selected = rows[start:end]
        has_more = start > 0
    for row in selected:
        row.pop("_timestamp", None)
    return selected, has_more


def command_chats(root: Path, keys_file: Path, args: argparse.Namespace):
    keys = _load_keys(keys_file)
    chats, _contacts, _senders = _conversation_catalog(root, keys)
    if args.query:
        needle = args.query.casefold()
        chats = [
            c
            for c in chats
            if needle in c["chat_id"].casefold()
            or any(needle in candidate.casefold() for candidate in c["search_names"])
        ]
    offset = args.offset
    if args.limit < 0 or offset < 0:
        raise AccessError("invalid_pagination")
    selected = chats[offset:] if args.limit == 0 else chats[offset:offset + args.limit]
    return {"status": "ok", "returned": len(selected), "has_more": offset + len(selected) < len(chats), "chats": [_public_chat(c) for c in selected]}


def command_read(root: Path, keys_file: Path, args: argparse.Namespace):
    keys = _load_keys(keys_file)
    chats, contacts, sender_maps = _conversation_catalog(root, keys)
    chat = _resolve_chat(chats, args.chat_id, args.chat)
    rows = _read_chat_rows(root, keys, chat, contacts, sender_maps, _parse_bound(args.since), _parse_bound(args.until, True))
    selected, has_more = _page_latest(rows, args.limit, args.offset)
    warnings = sorted({warning for row in selected for warning in row["parsing_warnings"]})
    return {
        "status": "ok",
        "chat": _public_chat(chat),
        "selected": len(rows),
        "returned": len(selected),
        "has_more": has_more,
        "parsing_warnings": warnings,
        "messages": selected,
    }


def command_search(root: Path, keys_file: Path, args: argparse.Namespace):
    if not args.all_chats and not args.chat_id and not args.chat:
        raise AccessError("search_scope_required")
    keys = _load_keys(keys_file)
    chats, contacts, sender_maps = _conversation_catalog(root, keys)
    selected_chats = chats if args.all_chats else [_resolve_chat(chats, args.chat_id, args.chat)]
    since, until = _parse_bound(args.since), _parse_bound(args.until, True)
    matches = []
    examined = 0
    all_warnings: set[str] = set()
    needle = args.query.casefold()
    for chat in selected_chats:
        for row in _read_chat_rows(root, keys, chat, contacts, sender_maps, since, until):
            examined += 1
            all_warnings.update(row["parsing_warnings"])
            if needle in row["text"].casefold():
                row["chat_id"] = chat["chat_id"]
                row["chat_display_name"] = chat["display_name"]
                matches.append(row)
    matches.sort(key=lambda row: (row["_timestamp"] is not None, row["_timestamp"] or 0, row["source_db"], row["local_id"]))
    selected, has_more = _page_latest(matches, args.limit, args.offset)
    total_matches = len(matches)
    return {
        "status": "ok",
        "examined": examined,
        "matched": total_matches,
        "returned": len(selected),
        "has_more": has_more,
        "parsing_warnings": sorted(all_warnings),
        "messages": selected,
    }


def _app_version() -> dict[str, str | None]:
    candidates = [
        Path("/Applications/WeChat.app/Contents/Info.plist"),
        Path.home() / "Applications/WeChat.app/Contents/Info.plist",
    ]
    for path in candidates:
        try:
            data = plistlib.loads(path.read_bytes())
            return {"version": data.get("CFBundleShortVersionString"), "build": data.get("CFBundleVersion")}
        except (OSError, plistlib.InvalidFileException):
            continue
    return {"version": None, "build": None}


def command_doctor(root: Path, keys_file: Path, _args: argparse.Namespace):
    try:
        keys = _load_keys(keys_file)
        databases = _discover_databases(root)
    except ValidationFailure as exc:
        raise AccessError(exc.code) from exc
    required = {"contact/contact.db", "session/session.db"}
    required.update(rel for rel, _path in _message_databases(root))
    database_reports = []
    required_ok = True
    auxiliary_missing = 0
    discovered_relpaths = {_safe_relpath(path, root) for path in databases}
    for rel in sorted(required - discovered_relpaths):
        required_ok = False
        database_reports.append(
            {
                "path": rel,
                "required_for_conversations": True,
                "salt_coverage": "database_missing",
                "quick_open": "unavailable",
                "schema_tables": None,
            }
        )
    for path in databases:
        rel = _safe_relpath(path, root)
        key = keys.get(rel)
        salt_status = "missing_key"
        quick_status = "not_checked"
        schema_tables = None
        if key:
            try:
                with path.open("rb") as handle:
                    actual_salt = handle.read(16).hex()
                salt_status = "match" if actual_salt == key["salt"] else "mismatch"
            except OSError:
                salt_status = "unreadable"
        if rel in required:
            if salt_status != "match":
                quick_status = "unavailable"
                required_ok = False
            else:
                conn = None
                try:
                    conn = _open(root, keys, rel)
                    schema_tables = conn.execute("SELECT COUNT(*) FROM sqlite_master WHERE type='table'").fetchone()[0]
                    quick_status = "ok"
                except (AccessError, sqlcipher3.Error):
                    quick_status = "database_open_failed"
                    required_ok = False
                finally:
                    if conn is not None:
                        _close(conn)
        elif key is None:
            auxiliary_missing += 1
        database_reports.append({"path": rel, "required_for_conversations": rel in required, "salt_coverage": salt_status, "quick_open": quick_status, "schema_tables": schema_tables})
    return {
        "status": "ok" if required_ok else "error",
        "app": _app_version(),
        "discovered_databases": len(databases),
        "conversation_ready": required_ok,
        "all_database_key_salt_coverage": all(item["salt_coverage"] == "match" for item in database_reports),
        "all_databases_fully_validated": False,
        "auxiliary_databases_missing_keys": auxiliary_missing,
        "databases": database_reports,
        "content_scanned": False,
    }


def command_check(root: Path, keys_file: Path, args: argparse.Namespace):
    try:
        coverage = conversation_coverage.build_coverage(root, keys_file)
        keys = _load_keys(keys_file)
    except (conversation_coverage.CoverageError, ValidationFailure) as exc:
        raise AccessError(getattr(exc, "code", "check_failed")) from exc
    core = ["contact/contact.db", "session/session.db"] + [rel for rel, _path in _message_databases(root)]
    results = []
    for rel in core:
        key = keys.get(rel)
        if key is None:
            raise AccessError("required_key_missing", {"path": rel})
        results.append(asdict(validate_database(root / rel, root, key)))
    strict = None
    strict_code = 0
    if args.all_databases:
        strict, strict_code = validate_all(root, keys_file)
    ok = all(item["status"] == "ok" for item in results) and strict_code == 0
    return {"status": "ok" if ok else "error", "coverage": coverage, "core_databases": results, "all_databases": strict}


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Read local WeChat conversations without modifying WeChat databases")
    parser.add_argument("--config", type=Path, default=DEFAULT_CONFIG)
    parser.add_argument("--db-root", type=Path)
    parser.add_argument("--keys-file", type=Path)
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("doctor", help="Check conversation readiness without reading content")
    chats = sub.add_parser("chats", help="List discoverable conversation names")
    chats.add_argument("--query")
    chats.add_argument("--limit", type=int, default=20)
    chats.add_argument("--offset", type=int, default=0)
    read = sub.add_parser("read", help="Read one conversation")
    group = read.add_mutually_exclusive_group(required=True)
    group.add_argument("--chat-id")
    group.add_argument("--chat")
    read.add_argument("--since")
    read.add_argument("--until")
    read.add_argument("--limit", type=int, default=50)
    read.add_argument("--offset", type=int, default=0)
    search = sub.add_parser("search", help="Search decoded conversation text")
    search.add_argument("--query", required=True)
    scope = search.add_mutually_exclusive_group(required=True)
    scope.add_argument("--chat-id")
    scope.add_argument("--chat")
    scope.add_argument("--all-chats", action="store_true")
    search.add_argument("--since")
    search.add_argument("--until")
    search.add_argument("--limit", type=int, default=50)
    search.add_argument("--offset", type=int, default=0)
    check = sub.add_parser("check", help="Validate conversation coverage and database reads")
    check.add_argument("--all-databases", action="store_true")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = _parser()
    args = parser.parse_args(argv)
    try:
        root, keys_file = _load_config(args.config, args.db_root, args.keys_file)
        handlers = {"doctor": command_doctor, "chats": command_chats, "read": command_read, "search": command_search, "check": command_check}
        report = handlers[args.command](root, keys_file, args)
        _emit(report)
        return 0 if report.get("status") == "ok" else 1
    except (AccessError, ValidationFailure) as exc:
        metadata = getattr(exc, "metadata", {})
        _emit({"status": "error", "error_code": getattr(exc, "code", "access_failed"), **metadata})
        return 1
    except Exception:
        _emit({"status": "error", "error_code": "unexpected_access_failure"})
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
