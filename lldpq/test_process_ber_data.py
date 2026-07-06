#!/usr/bin/env python3
"""Focused regression tests for bounded BER history and report reuse."""

import json
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
            self.assertEqual(saved["history_max_entries_per_port"], 13)
            self.assertEqual(
                len(saved["ber_history"]["leaf-01:swp1"]), 12
            )
            self.assertNotIn("\n  ", serialized)

    def test_l1_symbol_baseline_survives_a_long_collection_gap(self):
        with tempfile.TemporaryDirectory() as temporary:
            history = [_history_entry(0)]
            history[0]["symbol_errors"] = 1234
            for index in range(1, 30):
                entry = _history_entry(index)
                entry.pop("symbol_errors")
                history.append(entry)

            analyzer = BERAnalyzer(temporary)
            analyzer.ber_history = {"leaf-01:swp1": history}
            analyzer.cleanup_old_history()
            retained = analyzer.ber_history["leaf-01:swp1"]

            # The ten newest analyzed records overlap the two newest context
            # records, so the old symbol baseline is the eleventh retained
            # entry; 13 is the maximum, not a forced size.
            self.assertEqual(len(retained), 11)
            self.assertEqual(retained[0]["symbol_errors"], 1234)
            current = {"timestamp": time.time(), "symbol_errors": 1400}
            analyzer.ber_history["leaf-01:swp1"].append(current)
            self.assertEqual(
                analyzer._previous_symbol_errors("leaf-01:swp1", current), 1234
            )

            self.assertTrue(analyzer.save_ber_history())
            reloaded = BERAnalyzer(temporary)
            reloaded_current = {"timestamp": time.time() + 1, "symbol_errors": 1500}
            self.assertEqual(
                reloaded._previous_symbol_errors(
                    "leaf-01:swp1", reloaded_current
                ),
                1400,
            )

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
    @staticmethod
    def _write_current_fixture(temporary):
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
        return result_dir, data_dir

    def test_successful_run_serializes_history_once_and_reuses_analysis(self):
        with tempfile.TemporaryDirectory() as temporary:
            result_dir, data_dir = self._write_current_fixture(temporary)

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

    def test_state_write_failure_fails_closed(self):
        with tempfile.TemporaryDirectory() as temporary:
            _result_dir, data_dir = self._write_current_fixture(temporary)
            with (
                mock.patch.object(
                    processor.BERAnalyzer,
                    "save_baseline_data",
                    return_value=False,
                ) as baseline_save,
                mock.patch.object(
                    processor.BERAnalyzer,
                    "save_ber_history",
                    return_value=True,
                ) as history_save,
            ):
                self.assertFalse(processor.process_ber_data_files(str(data_dir)))
            baseline_save.assert_called_once_with()
            history_save.assert_not_called()

        with tempfile.TemporaryDirectory() as temporary:
            _result_dir, data_dir = self._write_current_fixture(temporary)
            with (
                mock.patch.object(
                    processor.BERAnalyzer,
                    "save_baseline_data",
                    return_value=True,
                ) as baseline_save,
                mock.patch.object(
                    processor.BERAnalyzer,
                    "save_ber_history",
                    return_value=False,
                ) as history_save,
            ):
                self.assertFalse(processor.process_ber_data_files(str(data_dir)))
            baseline_save.assert_called_once_with()
            history_save.assert_called_once_with()


if __name__ == "__main__":
    unittest.main()
