from __future__ import annotations

import hashlib
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

import sqlcipher3
import zstandard


SCRIPT_DIR = Path(__file__).resolve().parent
CLI = SCRIPT_DIR / "wechat_access.py"


class SyntheticStore:
    def __init__(self, base: Path):
        self.root = base / "db_storage"
        (self.root / "contact").mkdir(parents=True)
        (self.root / "session").mkdir(parents=True)
        (self.root / "message").mkdir(parents=True)
        self.keys: dict[str, dict[str, str]] = {}
        self.counter = 1

    def create(self, rel: str, statements: list[tuple[str, tuple]]):
        path = self.root / rel
        salt = f"{self.counter:032x}"[-32:]
        key = f"{self.counter + 100:064x}"[-64:]
        self.counter += 1
        conn = sqlcipher3.connect(path)
        conn.execute(f'PRAGMA key = "x\'{key + salt}\'"')
        for sql, params in statements:
            conn.execute(sql, params)
        conn.commit()
        conn.close()
        self.keys[rel] = {"enc_key": key, "salt": salt}

    def finish(self) -> Path:
        path = self.root.parent / "keys.json"
        path.write_text(json.dumps(self.keys), encoding="utf-8")
        return path


def md5(value: str) -> str:
    return hashlib.md5(value.encode()).hexdigest()


class WeChatAccessTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.store = SyntheticStore(Path(self.temp.name))
        contacts = [
            ("alice", "Alice", "", "alice_alias", 0, 0),
            ("bob1", "Bob", "", "", 0, 0),
            ("bob2", "Bob", "", "", 0, 0),
        ]
        statements = [
            (
                "CREATE TABLE contact(username TEXT,nick_name TEXT,remark TEXT,alias TEXT,local_type INTEGER,delete_flag INTEGER)",
                (),
            )
        ] + [("INSERT INTO contact VALUES(?,?,?,?,?,?)", item) for item in contacts]
        self.store.create("contact/contact.db", statements)
        self.store.create(
            "session/session.db",
            [
                (
                    "CREATE TABLE SessionTable(username TEXT,type INTEGER,is_hidden INTEGER,last_timestamp INTEGER,last_msg_locald_id INTEGER,last_msg_type INTEGER)",
                    (),
                ),
                ("INSERT INTO SessionTable VALUES(?,?,?,?,?,?)", ("alice", 0, 0, 300, 3, 1)),
            ],
        )

        compressed = zstandard.ZstdCompressor().compress("needle in compressed text".encode())
        xml = (
            "<msg><appmsg><title>Visible title</title><des>Visible summary</des>"
            "<aeskey>TOPSECRET</aeskey><url>https://example.test/article?id=7&amp;token=SECRET&amp;ticket=NOPE</url>"
            "</appmsg></msg>"
        )
        unknown = "f" * 32
        self.store.create(
            "message/message_0.db",
            self._message_statements(
                [(1, "alice"), (2, "bob1"), (3, "bob2")],
                {
                    md5("alice"): [
                        (1, 101, 1, 1, 100, "old shard", 0),
                        (8, 108, 10000, 1, 180, "You are now friends. Say hello!", 0),
                        (9, 109, 3, 1, 181, "<msg><img aeskey='MEDIASECRET'/></msg>", 0),
                        (10, 110, 10000, 1, 182, "<msg><url>https://media.test/file?auth_key=SIGNEDSECRET", 0),
                        (
                            11,
                            111,
                            1,
                            1,
                            183,
                            "token and key concepts; API key: 'sk-secret123'; Bearer abcdef.123456; https://example.test/page?id=7&auth_key=urlsecret",
                            0,
                        ),
                        (12, 112, 1, 1, 184, "must not surface", 7, "source must not surface", 9),
                        (2, 102, 49, 1, 200, xml, 0),
                    ],
                    md5("bob1"): [(3, 103, 1, 2, 150, "one", 0)],
                    md5("bob2"): [(4, 104, 1, 3, 160, "two", 0)],
                    unknown: [(5, 105, 1, 999, 170, "unknown", 0)],
                },
            ),
        )
        self.store.create(
            "message/message_1.db",
            self._message_statements(
                [(1, "alice")],
                {
                    md5("alice"): [
                        (6, 106, 1, 1, 300, "new shard", 0),
                        (7, 107, 1, 1, 250, compressed, 4),
                    ]
                },
            ),
        )
        self.keys = self.store.finish()

    @staticmethod
    def _message_statements(names, tables):
        result = [("CREATE TABLE Name2Id(user_name TEXT)", ())]
        for rowid, name in names:
            result.append(("INSERT INTO Name2Id(rowid,user_name) VALUES(?,?)", (rowid, name)))
        for digest, rows in tables.items():
            table = "Msg_" + digest
            result.append(
                (
                    f'CREATE TABLE "{table}"(local_id INTEGER,server_id INTEGER,local_type INTEGER,real_sender_id INTEGER,create_time INTEGER,message_content,WCDB_CT_message_content INTEGER,source,WCDB_CT_source INTEGER)',
                    (),
                )
            )
            for row in rows:
                expanded = row if len(row) == 9 else (*row, None, None)
                result.append((f'INSERT INTO "{table}" VALUES(?,?,?,?,?,?,?,?,?)', expanded))
        return result

    def run_cli(self, *args, keys=None):
        proc = subprocess.run(
            [
                sys.executable,
                str(CLI),
                "--db-root",
                str(self.store.root),
                "--keys-file",
                str(keys or self.keys),
                *args,
            ],
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertTrue(proc.stdout, proc.stderr)
        return proc, json.loads(proc.stdout)

    def test_multi_shard_latest_merge_is_chronological(self):
        proc, report = self.run_cli("read", "--chat-id", "alice", "--limit", "2")
        self.assertEqual(proc.returncode, 0)
        self.assertEqual([m["local_id"] for m in report["messages"]], ["7", "6"])
        self.assertTrue(report["has_more"])
        self.assertEqual({m["source_db"] for m in report["messages"]}, {"message/message_1.db"})

    def test_ambiguous_names_refuse_to_choose(self):
        proc, report = self.run_cli("read", "--chat", "Bob")
        self.assertEqual(proc.returncode, 1)
        self.assertEqual(report["error_code"], "ambiguous_chat")
        self.assertEqual({c["chat_id"] for c in report["candidates"]}, {"bob1", "bob2"})

    def test_unmatched_hash_is_preserved(self):
        proc, report = self.run_cli("chats", "--limit", "0")
        self.assertEqual(proc.returncode, 0)
        self.assertIn("hash:" + "f" * 32, {c["chat_id"] for c in report["chats"]})

    def test_search_decodes_zstd_before_filtering(self):
        proc, report = self.run_cli("search", "--query", "needle", "--chat-id", "alice")
        self.assertEqual(proc.returncode, 0)
        self.assertEqual(report["matched"], 1)
        self.assertEqual(report["messages"][0]["text"], "needle in compressed text")

    def test_invalid_key_never_leaks_crypto_or_sql_error(self):
        bad_path = Path(self.temp.name) / "bad-keys.json"
        bad = json.loads(self.keys.read_text())
        secret = "a" * 64
        bad["message/message_0.db"]["enc_key"] = secret
        bad_path.write_text(json.dumps(bad), encoding="utf-8")
        proc, report = self.run_cli("chats", keys=bad_path)
        self.assertEqual(proc.returncode, 1)
        self.assertEqual(report["error_code"], "database_open_failed")
        self.assertNotIn(secret, proc.stdout + proc.stderr)
        self.assertNotIn("SQL", proc.stdout + proc.stderr)

    def test_xml_protocol_secrets_are_redacted(self):
        proc, report = self.run_cli("read", "--chat-id", "alice", "--limit", "0")
        self.assertEqual(proc.returncode, 0)
        message = next(item for item in report["messages"] if item["local_id"] == "2")
        self.assertIn("Visible title", message["text"])
        self.assertIn("token=%5Bredacted%5D", message["text"])
        self.assertNotIn("TOPSECRET", message["text"])
        self.assertNotIn("SECRET", message["text"])
        self.assertNotIn("NOPE", message["text"])
        self.assertNotIn("<appmsg>", message["text"])

    def test_plain_system_media_malformed_xml_and_plain_credentials(self):
        proc, report = self.run_cli("read", "--chat-id", "alice", "--limit", "0")
        self.assertEqual(proc.returncode, 0)
        messages = {item["local_id"]: item for item in report["messages"]}

        self.assertEqual(messages["8"]["text"], "You are now friends. Say hello!")
        self.assertEqual(messages["8"]["parsing_warnings"], [])

        self.assertEqual(messages["9"]["text"], "[image message]")
        self.assertEqual(messages["9"]["parsing_warnings"], ["media_not_decoded"])
        self.assertNotIn("MEDIASECRET", proc.stdout)

        self.assertEqual(messages["10"]["text"], "[unavailable card]")
        self.assertEqual(messages["10"]["parsing_warnings"], ["xml_parse_failed"])
        self.assertNotIn("SIGNEDSECRET", proc.stdout)
        self.assertNotIn("https://media.test", messages["10"]["text"])

        credential_text = messages["11"]["text"]
        self.assertIn("token and key concepts", credential_text)
        self.assertIn("id=7", credential_text)
        self.assertNotIn("sk-secret123", credential_text)
        self.assertNotIn("abcdef.123456", credential_text)
        self.assertNotIn("urlsecret", credential_text)
        self.assertIn("credential_redacted", messages["11"]["parsing_warnings"])

        self.assertEqual(messages["12"]["text"], "[unavailable message content]")
        self.assertEqual(
            messages["12"]["parsing_warnings"],
            ["unsupported_content_compression", "source_unsupported_compression"],
        )
        self.assertNotIn("must not surface", proc.stdout)

    def test_chats_query_matches_alias_even_when_nickname_is_displayed(self):
        proc, report = self.run_cli("chats", "--query", "alice_alias")
        self.assertEqual(proc.returncode, 0)
        self.assertEqual([item["chat_id"] for item in report["chats"]], ["alice"])

    def test_nested_xml_and_json_credentials_do_not_escape(self):
        import wechat_access as access

        xml = '<msg><appmsg><title>visible</title><refermsg><content>&lt;msg&gt;&lt;img cdnthumbkey="SECRET_IN_NESTED"/&gt;&lt;/msg&gt;</content></refermsg></appmsg></msg>'
        rendered, warnings = access._render_xml(xml)
        self.assertNotIn("SECRET_IN_NESTED", rendered)
        self.assertIn("nested_xml_not_rendered", warnings)
        rendered, warnings = access._sanitize_visible_text('{"api_key": "SECRET_IN_JSON"}')
        self.assertNotIn("SECRET_IN_JSON", rendered)
        self.assertIn("credential_redacted", warnings)

    def test_doctor_is_content_free_and_check_validates_core(self):
        proc, doctor = self.run_cli("doctor")
        self.assertEqual(proc.returncode, 0)
        self.assertTrue(doctor["conversation_ready"])
        self.assertFalse(doctor["content_scanned"])
        self.assertNotIn("old shard", proc.stdout)

        proc, check = self.run_cli("check")
        self.assertEqual(proc.returncode, 0)
        self.assertEqual(check["status"], "ok")
        self.assertEqual(len(check["core_databases"]), 4)
        self.assertIsNone(check["all_databases"])


if __name__ == "__main__":
    unittest.main()
