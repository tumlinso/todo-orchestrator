"""Guardrails for bounded inline coordination text."""

import hashlib
import sqlite3
import unittest

from todo_orchestrator.coordination.payloads import (
    MAX_INLINE_TEXT_BYTES,
    PayloadRejectedError,
    validate_bounded_text,
)


class BoundedPayloadTests(unittest.TestCase):
    def test_accepts_ordinary_bounded_prose_without_rewriting_it(self):
        text = "The interface draft is ready for review.\nPlease check the examples."
        self.assertEqual(validate_bounded_text(text), text)

    def test_rejects_oversized_control_and_unpaired_unicode(self):
        with self.assertRaises(PayloadRejectedError):
            validate_bounded_text("x" * (MAX_INLINE_TEXT_BYTES + 1))
        with self.assertRaises(PayloadRejectedError):
            validate_bounded_text("safe\x00unsafe")
        with self.assertRaises(PayloadRejectedError):
            validate_bounded_text("bad\ud800text")

    def test_rejects_common_credential_and_log_shapes(self):
        samples = (
            "Authorization: Bearer abcdefghijklmnopqrstuvwxyz123456",
            "Authorization: Basic YWxpY2U6Y29ycmVjdGhvcnNlYmF0dGVyeXN0YXBsZQ==",
            "-----BEGIN RSA PRIVATE KEY-----\nmaterial",
            "api_key=AbCdEfGhIjKlMnOp",
            "password=hunter2",
            "Traceback (most recent call last):\n  File \"app.py\", line 4",
            "2026-10-18T12:00:00Z ERROR worker failed",
        )
        for sample in samples:
            with self.subTest(sample=sample[:28]), self.assertRaises(PayloadRejectedError):
                validate_bounded_text(sample)

    def test_rejects_a_known_issued_bearer_without_storing_plaintext(self):
        token = "Z" * 43
        digest = hashlib.sha256(token.encode("ascii")).hexdigest()
        connection = sqlite3.connect(":memory:")
        self.addCleanup(connection.close)
        connection.execute("CREATE TABLE capability_tokens(token_digest TEXT NOT NULL)")
        connection.execute("INSERT INTO capability_tokens VALUES (?)", (digest,))
        with self.assertRaises(PayloadRejectedError):
            validate_bounded_text(f"Use this token: {token}", connection=connection)

    def test_issued_token_lookup_does_not_reject_unissued_opaque_reference(self):
        connection = sqlite3.connect(":memory:")
        self.addCleanup(connection.close)
        connection.execute("CREATE TABLE capability_tokens(token_digest TEXT NOT NULL)")
        self.assertEqual(
            validate_bounded_text("artifact-ref-0123456789abcdef0123456789abcdef", connection=connection),
            "artifact-ref-0123456789abcdef0123456789abcdef",
        )


if __name__ == "__main__":
    unittest.main()
