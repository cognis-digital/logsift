"""Hardening tests: edge cases, bad input, and error-path coverage for LOGSIFT."""
import io
import os
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from logsift.cli import main  # noqa: E402
from logsift.core import analyze, parse_lines, summarize  # noqa: E402


class TestCLIErrorPaths(unittest.TestCase):
    def test_missing_file_returns_exit_2(self):
        """A nonexistent log file must print an error to stderr and return 2."""
        err = io.StringIO()
        with redirect_stderr(err):
            rc = main(["scan", "/no/such/file/logsift_test_xyz.log"])
        self.assertEqual(rc, 2)
        self.assertIn("error", err.getvalue().lower())

    def test_zero_bruteforce_threshold_returns_exit_2(self):
        """--bruteforce-threshold 0 is invalid; must return 2 with a clear message."""
        err = io.StringIO()
        with redirect_stderr(err):
            rc = main(["scan", "-", "--bruteforce-threshold", "0"])
        self.assertEqual(rc, 2)
        self.assertIn("bruteforce-threshold", err.getvalue())

    def test_negative_window_minutes_returns_exit_2(self):
        """--window-minutes -5 is invalid; must return 2 with a clear message."""
        err = io.StringIO()
        with redirect_stderr(err):
            rc = main(["scan", "-", "--window-minutes", "-5"])
        self.assertEqual(rc, 2)
        self.assertIn("window-minutes", err.getvalue())

    def test_zero_spray_threshold_returns_exit_2(self):
        """--spray-threshold 0 is invalid; must return 2."""
        err = io.StringIO()
        with redirect_stderr(err):
            rc = main(["scan", "-", "--spray-threshold", "0"])
        self.assertEqual(rc, 2)

    def test_zero_distributed_threshold_returns_exit_2(self):
        """--distributed-threshold 0 is invalid; must return 2."""
        err = io.StringIO()
        with redirect_stderr(err):
            rc = main(["scan", "-", "--distributed-threshold", "0"])
        self.assertEqual(rc, 2)

    def test_empty_log_file_exits_zero(self):
        """An empty log file has no events and no findings; must return 0."""
        with tempfile.NamedTemporaryFile(
            "w", suffix=".log", delete=False, encoding="utf-8"
        ) as tf:
            path = tf.name  # write nothing
        try:
            buf = io.StringIO()
            with redirect_stdout(buf):
                rc = main(["scan", path])
            self.assertEqual(rc, 0)
            self.assertIn("No suspicious", buf.getvalue())
        finally:
            os.unlink(path)

    def test_empty_log_file_json_exits_zero(self):
        """An empty log file with --format json returns valid JSON and exit 0."""
        import json

        with tempfile.NamedTemporaryFile(
            "w", suffix=".log", delete=False, encoding="utf-8"
        ) as tf:
            path = tf.name
        try:
            buf = io.StringIO()
            with redirect_stdout(buf):
                rc = main(["scan", path, "--format", "json"])
            self.assertEqual(rc, 0)
            payload = json.loads(buf.getvalue())
            self.assertEqual(payload["summary"]["events_parsed"], 0)
            self.assertEqual(payload["findings"], [])
        finally:
            os.unlink(path)

    def test_log_file_with_only_blank_lines_exits_zero(self):
        """A file containing only blank lines should parse to zero events."""
        with tempfile.NamedTemporaryFile(
            "w", suffix=".log", delete=False, encoding="utf-8"
        ) as tf:
            tf.write("\n\n   \n\t\n")
            path = tf.name
        try:
            buf = io.StringIO()
            with redirect_stdout(buf):
                rc = main(["scan", path])
            self.assertEqual(rc, 0)
        finally:
            os.unlink(path)


class TestCoreEdgeCases(unittest.TestCase):
    def test_analyze_empty_events(self):
        """analyze() on an empty list must return an empty list without error."""
        self.assertEqual(analyze([]), [])

    def test_summarize_empty(self):
        """summarize() with no events and no findings returns zero counts."""
        s = summarize([], [])
        self.assertEqual(s["events_parsed"], 0)
        self.assertEqual(s["failures"], 0)
        self.assertEqual(s["successes"], 0)
        self.assertEqual(s["distinct_ips"], 0)
        self.assertEqual(s["findings"], 0)
        self.assertEqual(s["severity_counts"], {})

    def test_parse_lines_all_blank(self):
        """parse_lines() with only blank lines returns an empty list."""
        self.assertEqual(parse_lines(["", "  ", "\t"]), [])

    def test_analyze_events_without_timestamps_no_crash(self):
        """Events with ts=None (no syslog prefix) must not crash the analyzer."""
        events = parse_lines([
            "Failed password for root from 1.2.3.4 port 22 ssh2",
        ] * 10)
        # All events lack timestamps; analysis should complete without error.
        result = analyze(events, bruteforce_threshold=5)
        self.assertIsInstance(result, list)

    def test_analyze_events_without_ip_no_crash(self):
        """Events with no parseable IP should not crash the analyzer."""
        events = parse_lines([
            "Jun  8 09:00:01 host sshd[1]: Failed password for root from UNKNOWN port 22",
        ] * 10)
        result = analyze(events, bruteforce_threshold=5)
        self.assertIsInstance(result, list)


if __name__ == "__main__":
    unittest.main()
