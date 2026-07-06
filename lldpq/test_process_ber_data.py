#!/usr/bin/env python3
"""Focused regression tests for bounded BER history and report reuse."""

import json
import os
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR))

import ber_analyzer as ber_module
import process_ber_data as processor
from ber_analyzer import BERAnalyzer


def _history_entry(sequence, sample_status="analyzed"):
    return {
        "sequence": sequence,
        "timestamp": time.time() - (100 - sequence),
        "ber_value": float(sequence + 1) * 1e-12,
        "sample_status": sample_status,
        "symbol_errors": sequence,
    }


class BERHistoryTests(unittest.TestCase):
    def test_legacy_history_migration_preserves_trend_and_context(self):
        with tempfile.TemporaryDirectory() as temporary:
            history = [
                _history_entry(index, "analyzed" if index < 15 else "baseline")
                for index in range(20)
            ]
            current = {"leaf-01:swp1": history[-1]}
            Path(temporary, "ber_history.json").write_text(
                json.dumps({
                    "ber_history": {"leaf-01:swp1": history},
                    "current_ber_stats": current,
                }),
                encoding="utf-8",
            )
            baseline = {"leaf-01": {"swp1": {"rx_errors": 7}}}
            Path(temporary, "ber_baseline.json").write_text(
                json.dumps(baseline), encoding="utf-8"
            )

            analyzer = BERAnalyzer(temporary)
            migrated = analyzer.ber_history["leaf-01:swp1"]

            self.assertEqual(len(migrated), 12)
            self.assertEqual(
                [entry["sequence"] for entry in migrated],
                list(range(5, 15)) + [18, 19],
            )
            self.assertEqual(analyzer.baseline_data, baseline)
            self.assertEqual(analyzer.current_ber_stats, current)
            self.assertEqual(analyzer.get_ber_trend("leaf-01:swp1")["trend"], "worsening")

            self.assertTrue(analyzer.save_ber_history())
            serialized = Path(temporary, "ber_history.json").read_text(
                encoding="utf-8"
            )
            saved = json.loads(serialized)
            self.assertEqual(saved["history_schema_version"], 2)
            self.assertEqual(saved["history_max_entries_per_port"], 12)
            self.assertEqual(
                len(saved["ber_history"]["leaf-01:swp1"]), 12
            )
            self.assertNotIn("\n  ", serialized)

    def test_atomic_history_failure_keeps_previous_file(self):
        with tempfile.TemporaryDirectory() as temporary:
            analyzer = BERAnalyzer(temporary)
            history_path = Path(temporary, "ber_history.json")
            history_path.write_text('{"previous":true}\n', encoding="utf-8")
            analyzer.ber_history = {
                "leaf-01:swp1": [_history_entry(1)]
            }

            with mock.patch.object(
                ber_module.json, "dump", side_effect=RuntimeError("serialize")
            ):
                self.assertFalse(analyzer.save_ber_history())

            self.assertEqual(
                history_path.read_text(encoding="utf-8"), '{"previous":true}\n'
            )
            self.assertEqual(
                list(Path(temporary).glob(".ber_history.json.*")), []
            )


class BERProcessingTests(unittest.TestCase):
    def test_successful_run_serializes_history_once_and_reuses_analysis(self):
        with tempfile.TemporaryDirectory() as temporary:
            result_dir = Path(temporary, "monitor-results")
            data_dir = result_dir / "ber-data"
            data_dir.mkdir(parents=True)
            (data_dir / "leaf-01_interface_errors.txt").write_text(
                "Inter-|   Receive                                                |  Transmit\n"
                " face |bytes packets errs drop fifo frame compressed multicast|"
                "bytes packets errs drop fifo colls carrier compressed\n"
                " swp1: 1000 10 0 0 0 0 0 0 2000 20 0 0 0 0 0 0\n",
                encoding="utf-8",
            )

            original_save = BERAnalyzer.save_ber_history
            save_calls = []

            def counted_save(analyzer):
                save_calls.append(analyzer)
                return original_save(analyzer)

            with mock.patch.object(
                processor.BERAnalyzer, "save_ber_history", new=counted_save
            ):
                self.assertTrue(processor.process_ber_data_files(str(data_dir)))

            self.assertEqual(len(save_calls), 1)
            self.assertTrue((result_dir / "ber-analysis.html").is_file())
            saved = json.loads(
                (result_dir / "ber_history.json").read_text(encoding="utf-8")
            )
            current = saved["current_ber_stats"]["leaf-01:swp1"]
            # Summary classification enriches the record before the sole save.
            self.assertIn("effective_grade", current)
            self.assertEqual(saved["history_schema_version"], 2)


if __name__ == "__main__":
    unittest.main()
