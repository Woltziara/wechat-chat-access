from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path

import sqlcipher3
import zstandard

from validate_read_access import validate_all


class ValidateReadAccessCanary(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.db_dir = self.root / "message"
        self.db_dir.mkdir()
        self.db_path = self.db_dir / "message_0.db"
        self.enc_key = os.urandom(32).hex()
        self.salt = os.urandom(16).hex()
        self.keys_path = self.root / "keys.json"
        self.table = "Msg_" + "a" * 32  # intentionally has no contact mapping

        self.writer = sqlcipher3.connect(str(self.db_path))
        self.writer.execute(f'PRAGMA key = "x\'{self.enc_key}{self.salt}\'"')
        self.writer.execute("PRAGMA journal_mode=WAL")
        self.writer.execute("PRAGMA wal_autocheckpoint=0")
        self.writer.execute(
            f'CREATE TABLE "{self.table}" ('
            "local_id INTEGER, message_content BLOB, "
            "WCDB_CT_message_content INTEGER)"
        )
        self.writer.execute(
            f'INSERT INTO "{self.table}" VALUES (1, ?, 4)',
            (zstandard.ZstdCompressor().compress(b"base"),),
        )
        self.writer.commit()
        self.writer.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        # This committed row exists only in the non-checkpointed WAL while the
        # writer remains open.
        self.writer.execute(
            f'INSERT INTO "{self.table}" VALUES (2, ?, 0)', (b"wal",)
        )
        self.writer.commit()
        self._write_keys(self.enc_key)

    def tearDown(self):
        self.writer.close()
        self.temp.cleanup()

    def _write_keys(self, key: str, salt: str | None = None):
        payload = {
            "message/message_0.db": {
                "enc_key": key,
                "salt": salt or self.salt,
            }
        }
        self.keys_path.write_text(json.dumps(payload), encoding="utf-8")

    def test_reads_uncheckpointed_wal_and_unmapped_msg_table(self):
        self.assertGreater(Path(str(self.db_path) + "-wal").stat().st_size, 0)
        report, code = validate_all(self.root, self.keys_path)
        self.assertEqual(code, 0, report)
        self.assertEqual(report["totals"]["msg_tables"], 1)
        self.assertEqual(report["totals"]["msg_rows"], 2)
        self.assertEqual(report["totals"]["rows"], 2)
        self.assertEqual(report["totals"]["zstd_checked"], 1)
        self.assertEqual(report["totals"]["zstd_errors"], 0)

    def test_wrong_key_fails_without_disclosing_it(self):
        wrong_key = os.urandom(32).hex()
        self._write_keys(wrong_key)
        report, code = validate_all(self.root, self.keys_path)
        encoded = json.dumps(report)
        self.assertEqual(code, 1)
        self.assertNotIn(wrong_key, encoded)
        self.assertTrue(
            "database_read_failed" in encoded or "cipher_integrity_failed" in encoded
        )

    def test_preserves_binary_values_stored_as_text(self):
        self.writer.execute("CREATE TABLE binary_metadata(value TEXT)")
        self.writer.execute("INSERT INTO binary_metadata VALUES (CAST(X'80FF0012' AS TEXT))")
        self.writer.commit()
        report, code = validate_all(self.root, self.keys_path)
        self.assertEqual(code, 0, report)
        self.assertEqual(report["totals"]["rows"], 3)

    def test_corrupt_page_fails_integrity_validation(self):
        # Use a separate checkpointed DB so corruption cannot be masked by the
        # live WAL in the primary canary.
        corrupt = self.db_dir / "message_1.db"
        key = os.urandom(32).hex()
        salt = os.urandom(16).hex()
        conn = sqlcipher3.connect(str(corrupt))
        conn.execute(f'PRAGMA key = "x\'{key}{salt}\'"')
        conn.execute("CREATE TABLE payload(value BLOB)")
        conn.executemany(
            "INSERT INTO payload VALUES (?)", [(os.urandom(3000),) for _ in range(8)]
        )
        conn.commit()
        conn.close()
        with corrupt.open("r+b") as handle:
            handle.seek(4096 + 100)
            original = handle.read(1)
            handle.seek(4096 + 100)
            handle.write(bytes([original[0] ^ 0x01]))

        payload = json.loads(self.keys_path.read_text(encoding="utf-8"))
        payload["message/message_1.db"] = {"enc_key": key, "salt": salt}
        self.keys_path.write_text(json.dumps(payload), encoding="utf-8")
        report, code = validate_all(self.root, self.keys_path)
        self.assertEqual(code, 1)
        item = next(
            entry for entry in report["databases"]
            if entry["path"] == "message/message_1.db"
        )
        self.assertIn("cipher_integrity_failed", item["errors"])


if __name__ == "__main__":
    unittest.main()
