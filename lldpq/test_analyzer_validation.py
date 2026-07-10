#!/usr/bin/env python3
"""Fail-closed and timing contracts for parallel analyzer JSON validation."""

from __future__ import annotations

import contextlib
import io
from pathlib import Path
import tempfile
import threading
import time
import unittest
from unittest import mock

from lldpq import validate_analysis_json


ROOT = Path(__file__).resolve().parents[1]
MONITOR = (ROOT / "lldpq/monitor.sh").read_text(encoding="utf-8")


class AnalyzerValidationTests(unittest.TestCase):
    def test_valid_and_invalid_json_are_fully_parsed(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "valid.json").write_text('{"ok":[1,2,3]}\n', encoding="utf-8")
            (root / "invalid.json").write_text('{"broken":\n', encoding="utf-8")
            results = validate_analysis_json.validate_json_files(
                root, ["valid.json", "invalid.json"], max_workers=2
            )
        self.assertEqual([item[0] for item in results], ["valid.json", "invalid.json"])
        self.assertIsNone(results[0][2])
        self.assertIsNotNone(results[1][2])

    def test_cli_reports_all_errors_and_timings_in_input_order(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for name in ("second.json", "first.json"):
                (root / name).write_text("{bad", encoding="utf-8")
            stdout, stderr = io.StringIO(), io.StringIO()
            with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                status = validate_analysis_json.main([
                    str(root), "second.json", "first.json"
                ])
        self.assertEqual(status, 1)
        self.assertLess(stdout.getvalue().index("second.json"), stdout.getvalue().index("first.json"))
        self.assertIn("Invalid analysis JSON second.json", stderr.getvalue())
        self.assertIn("Invalid analysis JSON first.json", stderr.getvalue())

    def test_worker_limit_is_bounded(self):
        active = 0
        peak = 0
        lock = threading.Lock()

        def slow(_root, relative):
            nonlocal active, peak
            with lock:
                active += 1
                peak = max(peak, active)
            time.sleep(0.03)
            with lock:
                active -= 1
            return relative, 30, None

        with mock.patch.object(validate_analysis_json, "_validate_one", side_effect=slow):
            results = validate_analysis_json.validate_json_files(
                Path("/tmp"), [f"{index}.json" for index in range(6)], max_workers=2
            )
        self.assertEqual(len(results), 6)
        self.assertEqual(peak, 2)

    def test_monitor_preserves_precheck_and_rollback_contract(self):
        self.assertIn('[[ ! -f "$path" || ! -s "$path" || "$path" -ot "$marker" ]]', MONITOR)
        self.assertIn('python3 "$SCRIPT_DIR/validate_analysis_json.py"', MONITOR)
        failure = MONITOR.split(
            'if ! validate_analysis_outputs "$analysis_output_marker"; then', 1
        )[1].split("fi", 1)[0]
        self.assertIn("rollback_analysis_state", failure)
        self.assertIn('mark_reports_stale "analysis outputs were incomplete"', failure)
        self.assertIn("exit 1", failure)


if __name__ == "__main__":
    unittest.main()
