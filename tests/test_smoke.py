"""Smoke tests for LOGSIFT. Standard library only, no network."""
import io
import json
import os
import sys
import unittest
from contextlib import redirect_stdout

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from logsift import (  # noqa: E402
    TOOL_NAME,
    TOOL_VERSION,
    parse_line,
    parse_lines,
    analyze,
    summarize,
)
from logsift.cli import main  # noqa: E402

DEMO = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "demos", "01-basic", "auth.log",
)


class TestParse(unittest.TestCase):
    def test_parse_failure_line(self):
        ev = parse_line(
            "Jun  8 09:02:14 host sshd[2002]: "
            "Failed password for root from 203.0.113.66 port 40001 ssh2",
            lineno=1,
        )
        self.assertIsNotNone(ev)
        self.assertEqual(ev.outcome, "fail")
        self.assertEqual(ev.ip, "203.0.113.66")
        self.assertEqual(ev.user, "root")
        self.assertIsNotNone(ev.ts)

    def test_parse_success_line(self):
        ev = parse_line(
            "Jun  8 09:03:05 host sshd[2009]: "
            "Accepted password for root from 203.0.113.66 port 40010 ssh2"
        )
        self.assertEqual(ev.outcome, "success")
        self.assertEqual(ev.ip, "203.0.113.66")

    def test_parse_invalid_user(self):
        ev = parse_line(
            "Jun  8 09:05:00 host sshd[2100]: "
            "Failed password for invalid user admin from 198.51.100.23 port 1 ssh2"
        )
        self.assertEqual(ev.user, "admin")
        self.assertEqual(ev.outcome, "fail")

    def test_blank_line_ignored(self):
        self.assertIsNone(parse_line("   "))


class TestAnalyze(unittest.TestCase):
    def setUp(self):
        with open(DEMO, encoding="utf-8") as fh:
            self.events = parse_lines(fh.read().splitlines())

    def test_detects_bruteforce(self):
        findings = analyze(self.events)
        kinds = {f.kind for f in findings}
        self.assertIn("bruteforce", kinds)

    def test_detects_spray(self):
        findings = analyze(self.events)
        spray = [f for f in findings if f.kind == "spray"]
        self.assertTrue(spray)
        self.assertEqual(spray[0].ip, "198.51.100.23")

    def test_detects_success_after_bruteforce(self):
        findings = analyze(self.events)
        crit = [f for f in findings if f.kind == "success-after-bruteforce"]
        self.assertTrue(crit)
        self.assertEqual(crit[0].severity, "critical")

    def test_clean_log_no_findings(self):
        clean = parse_lines([
            "Jun  8 09:01:02 host sshd[1]: "
            "Accepted publickey for deploy from 192.0.2.10 port 1 ssh2: RSA x",
            "Jun  8 09:01:30 host sshd[2]: "
            "Accepted publickey for jdoe from 192.0.2.11 port 2 ssh2: RSA y",
        ])
        self.assertEqual(analyze(clean), [])

    def test_summary_shape(self):
        findings = analyze(self.events)
        s = summarize(self.events, findings)
        self.assertGreater(s["events_parsed"], 0)
        self.assertGreaterEqual(s["failures"], 1)
        self.assertIn("severity_counts", s)


class TestCLI(unittest.TestCase):
    def test_json_output_and_exit_code(self):
        buf = io.StringIO()
        with redirect_stdout(buf):
            rc = main(["scan", DEMO, "--format", "json"])
        self.assertEqual(rc, 1)  # findings present -> non-zero
        payload = json.loads(buf.getvalue())
        self.assertEqual(payload["tool"], TOOL_NAME)
        self.assertEqual(payload["version"], TOOL_VERSION)
        self.assertTrue(payload["findings"])

    def test_no_command_returns_2(self):
        buf = io.StringIO()
        with redirect_stdout(buf):
            rc = main([])
        self.assertEqual(rc, 2)

    def test_clean_stdin_exit_zero(self):
        # Route a clean log through a temp file path via table format.
        import tempfile
        with tempfile.NamedTemporaryFile(
            "w", suffix=".log", delete=False, encoding="utf-8"
        ) as tf:
            tf.write(
                "Jun  8 09:01:02 host sshd[1]: "
                "Accepted publickey for deploy from 192.0.2.10 port 1 ssh2: x\n"
            )
            path = tf.name
        try:
            buf = io.StringIO()
            with redirect_stdout(buf):
                rc = main(["scan", path])
            self.assertEqual(rc, 0)
        finally:
            os.unlink(path)


if __name__ == "__main__":
    unittest.main()
