#!/usr/bin/env python3
"""Capture candidate 32-byte values and persist only HMAC-validated DB keys.

The inventory schema is::

    {"databases": [{"path": "message/message_0.db",
                     "page1_hex": "8192 hex characters"}]}

The output schema is::

    {"message/message_0.db": {"enc_key": "64 hex characters",
                               "salt": "32 hex characters",
                               "algorithm": "hmac-sha512-reserve80"}}

No candidate value, salt, page bytes, database contents, or driver exception
text is printed.  The program never kills or restarts a process.
"""

from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import os
import re
import struct
import sys
import tempfile
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any


PAGE_SIZE = 4096
KEY_SIZE = 32
SALT_SIZE = 16
HEX_KEY_RE = re.compile(r"^[0-9a-fA-F]{64}$")
HEX_PAGE_RE = re.compile(r"^[0-9a-fA-F]{8192}$")
ALGORITHMS = (
    "hmac-sha512-reserve80",
    "hmac-sha1-reserve48",
)


class CaptureError(Exception):
    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


@dataclass(frozen=True)
class InventoryEntry:
    path: str
    page1: bytes


def _safe_relpath(value: Any) -> str:
    if not isinstance(value, str):
        raise CaptureError("inventory_path_invalid")
    normalized = value.replace("\\", "/")
    parts = Path(normalized).parts
    if not normalized or normalized.startswith("/") or ".." in parts:
        raise CaptureError("inventory_path_invalid")
    return normalized


def load_inventory(path: Path) -> list[InventoryEntry]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise CaptureError("inventory_invalid") from exc
    raw_entries = payload.get("databases") if isinstance(payload, dict) else None
    if not isinstance(raw_entries, list) or not raw_entries:
        raise CaptureError("inventory_invalid")
    result: list[InventoryEntry] = []
    seen: set[str] = set()
    for item in raw_entries:
        if not isinstance(item, dict):
            raise CaptureError("inventory_entry_invalid")
        rel = _safe_relpath(item.get("path"))
        page_hex = item.get("page1_hex")
        if rel in seen or not isinstance(page_hex, str) or not HEX_PAGE_RE.fullmatch(page_hex):
            raise CaptureError("inventory_entry_invalid")
        seen.add(rel)
        result.append(InventoryEntry(rel, bytes.fromhex(page_hex)))
    return result


def verify_candidate(key: bytes, page1: bytes, algorithm: str) -> bool:
    """Authenticate SQLCipher page 1 without decrypting or exposing it."""
    if len(key) != KEY_SIZE or len(page1) != PAGE_SIZE:
        return False
    salt = page1[:SALT_SIZE]
    mac_salt = bytes(value ^ 0x3A for value in salt)
    if algorithm == "hmac-sha512-reserve80":
        digest = "sha512"
        reserve = 80
        tag_offset = PAGE_SIZE - 64
        tag_size = 64
    elif algorithm == "hmac-sha1-reserve48":
        digest = "sha1"
        reserve = 48
        tag_offset = PAGE_SIZE - reserve + 16
        tag_size = 20
    else:
        return False
    mac_key = hashlib.pbkdf2_hmac(digest, key, mac_salt, 2, dklen=KEY_SIZE)
    authenticated = page1[SALT_SIZE : PAGE_SIZE - reserve + 16]
    expected = page1[tag_offset : tag_offset + tag_size]
    calculated = hmac.new(mac_key, authenticated, digest)
    calculated.update(struct.pack("<I", 1))
    return hmac.compare_digest(calculated.digest(), expected)


def match_candidate(
    key: bytes, entries: list[InventoryEntry], covered: set[str]
) -> dict[str, dict[str, str]]:
    matches: dict[str, dict[str, str]] = {}
    for entry in entries:
        if entry.path in covered:
            continue
        for algorithm in ALGORITHMS:
            if verify_candidate(key, entry.page1, algorithm):
                matches[entry.path] = {
                    "enc_key": key.hex(),
                    "salt": entry.page1[:SALT_SIZE].hex(),
                    "algorithm": algorithm,
                }
                break
    return matches


def load_valid_existing(
    path: Path, entries: list[InventoryEntry]
) -> dict[str, dict[str, str]]:
    if not path.exists():
        return {}
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError):
        return {}
    if not isinstance(payload, dict):
        return {}
    by_path = {entry.path: entry for entry in entries}
    validated: dict[str, dict[str, str]] = {}
    for rel, item in payload.items():
        entry = by_path.get(rel)
        if entry is None or not isinstance(item, dict):
            continue
        key_hex = item.get("enc_key")
        if not isinstance(key_hex, str) or not HEX_KEY_RE.fullmatch(key_hex):
            continue
        key = bytes.fromhex(key_hex)
        matches = match_candidate(key, [entry], set())
        if rel in matches:
            validated[rel] = matches[rel]
    return validated


def atomic_write_keys(path: Path, keys: dict[str, dict[str, str]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        os.fchmod(fd, 0o600)
        # The elevated collector writes into the invoking user's private
        # runtime directory. Preserve that user's ownership for later reads.
        if os.geteuid() == 0:
            owner = path.parent.stat()
            os.fchown(fd, owner.st_uid, owner.st_gid)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(keys, handle, ensure_ascii=False, indent=2, sort_keys=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        os.chmod(path, 0o600)
    except Exception:
        try:
            os.close(fd)
        except OSError:
            pass
        try:
            os.unlink(temporary)
        except OSError:
            pass
        raise


def atomic_write_status(path: Path, status: dict[str, Any]) -> None:
    """Atomically publish non-sensitive progress with private permissions."""
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        os.fchmod(fd, 0o600)
        if os.geteuid() == 0:
            owner = path.parent.stat()
            os.fchown(fd, owner.st_uid, owner.st_gid)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(status, handle, ensure_ascii=False, separators=(",", ":"))
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        os.chmod(path, 0o600)
    except Exception:
        try:
            os.close(fd)
        except OSError:
            pass
        try:
            os.unlink(temporary)
        except OSError:
            pass
        raise


def _status_payload(
    phase: str,
    *,
    inventory: int = 0,
    matched: int = 0,
    candidates: int = 0,
    hook_ready: bool = False,
    hooks: int = 0,
    error_code: str | None = None,
    exit_status: int | None = None,
) -> dict[str, Any]:
    return {
        "phase": phase,
        "inventory": inventory,
        "matched": matched,
        "candidates": candidates,
        "hook_ready": hook_ready,
        "hooks": hooks,
        "error_code": error_code,
        "exit_status": exit_status,
    }


def _emit(report: dict[str, Any]) -> None:
    json.dump(report, sys.stdout, ensure_ascii=False, separators=(",", ":"))
    sys.stdout.write("\n")
    sys.stdout.flush()


def capture(args: argparse.Namespace) -> int:
    def write_early_status(phase: str, **values: Any) -> bool:
        if args.status_file is None:
            return True
        try:
            atomic_write_status(args.status_file, _status_payload(phase, **values))
            return True
        except Exception:
            return False

    if not write_early_status("starting"):
        _emit({"status": "error", "error_code": "status_file_failed"})
        return 1
    try:
        entries = load_inventory(args.inventory)
    except CaptureError as exc:
        write_early_status("finished", error_code=exc.code, exit_status=1)
        _emit({"status": "error", "error_code": exc.code})
        return 1

    results = load_valid_existing(args.out, entries)
    existing_valid = len(results)
    total = len(entries)
    if len(results) == total:
        write_early_status(
            "finished", inventory=total, matched=total, exit_status=0
        )
        _emit({
            "status": "complete", "error_code": None,
            "inventory": total, "matched": total, "existing_valid": total,
            "candidates_received": 0, "hook_ready": False, "hooks": 0,
        })
        return 0

    try:
        import frida
    except Exception:
        write_early_status(
            "finished", inventory=total, matched=len(results),
            error_code="frida_import_failed", exit_status=1,
        )
        _emit({"status": "error", "error_code": "frida_import_failed"})
        return 1

    try:
        source = args.script.read_text(encoding="utf-8")
    except (OSError, UnicodeError):
        write_early_status(
            "finished", inventory=total, matched=len(results),
            error_code="hook_script_unreadable", exit_status=1,
        )
        _emit({"status": "error", "error_code": "hook_script_unreadable"})
        return 1

    lock = threading.RLock()
    status_write_lock = threading.Lock()
    candidates_seen: set[str] = set()
    hook_count = 0
    hook_ready = False
    hook_error = False
    last_candidate_at = time.monotonic()
    complete = threading.Event()
    status_write_failed = False

    def publish_status(
        phase: str, error: str | None = None, exit_status: int | None = None
    ) -> None:
        nonlocal status_write_failed
        if args.status_file is None:
            return
        with lock:
            payload = _status_payload(
                phase,
                inventory=total,
                matched=len(results),
                candidates=len(candidates_seen),
                hook_ready=hook_ready,
                hooks=hook_count,
                error_code=error,
                exit_status=exit_status,
            )
        try:
            with status_write_lock:
                atomic_write_status(args.status_file, payload)
        except Exception:
            with lock:
                status_write_failed = True

    def on_message(message, _data):
        nonlocal hook_count, hook_ready, hook_error, last_candidate_at
        if not isinstance(message, dict) or message.get("type") != "send":
            with lock:
                hook_error = True
            return
        payload = message.get("payload")
        if not isinstance(payload, dict):
            return
        kind = payload.get("kind")
        if kind == "readiness":
            count = payload.get("hooked")
            if isinstance(count, int) and count >= 0:
                with lock:
                    hook_count = max(hook_count, count)
                    hook_ready = hook_count > 0
                if hook_ready:
                    publish_status("hook_ready")
            return
        if kind != "candidate":
            return
        value = payload.get("value")
        if not isinstance(value, str) or not HEX_KEY_RE.fullmatch(value):
            return
        normalized = value.lower()
        with lock:
            last_candidate_at = time.monotonic()
            if normalized in candidates_seen:
                return
            candidates_seen.add(normalized)
            key = bytes.fromhex(normalized)
            results.update(match_candidate(key, entries, set(results)))
            if len(results) == total:
                complete.set()

    device = None
    session = None
    script = None
    spawned_pid: int | None = None
    spawned_resumed = False
    error_code: str | None = None
    try:
        device = frida.get_local_device()
        if args.spawn is not None:
            spawned_pid = device.spawn([str(args.spawn)])
            session = device.attach(spawned_pid)
        else:
            session = device.attach(args.pid)
        publish_status("attached")
        script = session.create_script(source)
        script.on("message", on_message)
        script.load()
        if spawned_pid is not None:
            device.resume(spawned_pid)
            spawned_resumed = True

        started = time.monotonic()
        next_status_at = started + 5.0
        with lock:
            last_candidate_at = started
        while not complete.is_set():
            now = time.monotonic()
            with lock:
                quiet_for = now - last_candidate_at
                failed_status = status_write_failed
            if failed_status:
                error_code = "status_file_failed"
                break
            if now >= next_status_at:
                publish_status("collecting")
                next_status_at = now + 5.0
            if now - started >= args.timeout:
                error_code = "capture_timeout"
                break
            if quiet_for >= args.quiet:
                error_code = "capture_quiet"
                break
            time.sleep(0.1)
    except KeyboardInterrupt:
        error_code = "capture_interrupted"
    except Exception:
        error_code = "spawn_failed" if args.spawn is not None and session is None else "attach_or_hook_failed"
    finally:
        if spawned_pid is not None and not spawned_resumed and device is not None:
            try:
                device.resume(spawned_pid)
                spawned_resumed = True
            except Exception:
                error_code = "spawn_resume_failed"
        if script is not None:
            try:
                script.unload()
            except Exception:
                pass
        if session is not None:
            try:
                session.detach()
            except Exception:
                pass

    with lock:
        received = len(candidates_seen)
        ready = hook_ready
        hooks = hook_count
        internal_hook_error = hook_error
    if internal_hook_error and error_code is None:
        error_code = "hook_message_error"
    if results:
        try:
            atomic_write_keys(args.out, results)
        except Exception:
            publish_status(
                "finished", error="key_output_failed", exit_status=1
            )
            _emit({
                "status": "error", "error_code": "key_output_failed",
                "inventory": total, "matched": len(results),
                "candidates_received": received, "hook_ready": ready, "hooks": hooks,
            })
            return 1

    matched = len(results)
    if matched == total:
        status, exit_code, final_error = "complete", 0, None
    elif matched > 0:
        status, exit_code, final_error = "partial", 2, error_code or "inventory_incomplete"
    else:
        status, exit_code = "error", 1
        final_error = error_code or ("hook_not_ready" if not ready else "no_valid_keys")
    publish_status("finished", error=final_error, exit_status=exit_code)
    _emit({
        "status": status, "error_code": final_error,
        "inventory": total, "matched": matched,
        "existing_valid": existing_valid,
        "candidates_received": received, "hook_ready": ready, "hooks": hooks,
    })
    return exit_code


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Capture and HMAC-validate WeChat DB keys")
    target = parser.add_mutually_exclusive_group(required=True)
    target.add_argument("--pid", type=int)
    target.add_argument("--spawn", type=Path)
    parser.add_argument("--inventory", required=True, type=Path)
    parser.add_argument("--out", required=True, type=Path)
    parser.add_argument("--status-file", type=Path)
    parser.add_argument(
        "--script", type=Path,
        default=Path(__file__).with_name("capture_crypto.js"),
    )
    parser.add_argument("--timeout", type=float, default=180.0)
    parser.add_argument("--quiet", type=float, default=45.0)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if (args.pid is not None and args.pid <= 0) or args.timeout <= 0 or args.quiet <= 0:
        if args.status_file is not None:
            try:
                atomic_write_status(
                    args.status_file,
                    _status_payload(
                        "finished", error_code="arguments_invalid", exit_status=1
                    ),
                )
            except Exception:
                pass
        _emit({"status": "error", "error_code": "arguments_invalid"})
        return 1
    return capture(args)


if __name__ == "__main__":
    raise SystemExit(main())
