"""Malformed CLI requests do not echo authentication input or create state."""

from contextlib import redirect_stderr, redirect_stdout
import io
from pathlib import Path
import tempfile
import unittest

from todo_orchestrator.api.cli import main


class CliErrorBoundaryTests(unittest.TestCase):
    def test_existing_token_output_is_refused_before_initialization(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            root = directory / "missing-project"
            token_path = directory / "existing.token"
            token_path.write_bytes(b"preserve-this-existing-file\n")
            credential = directory / "owner-credential"
            credential.write_text("temporary owner credential 937")
            with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
                result = main([
                    "--root", str(root), "init", "--project-id", "token-output-project",
                    "--repository-id", "token-output-repository",
                    "--owner-credential-file", str(credential),
                    "--token-output", str(token_path), "--json",
                ])
            self.assertNotEqual(result, 0)
            self.assertEqual(token_path.read_bytes(), b"preserve-this-existing-file\n")
            self.assertFalse(root.exists())

    def test_rejected_raw_password_option_does_not_echo_into_either_stream(self):
        secret = "synthetic-private-password-never-echo-937"
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "missing-project"
            output, errors = io.StringIO(), io.StringIO()
            with redirect_stdout(output), redirect_stderr(errors):
                with self.assertRaises(SystemExit) as caught:
                    main([
                        "--root", str(root), "auth", "login",
                        "--token-output", str(root / "token"), "--password", secret,
                    ])
            self.assertNotEqual(caught.exception.code, 0)
            self.assertNotIn(secret, output.getvalue())
            self.assertNotIn(secret, errors.getvalue())
            self.assertFalse(root.exists())
