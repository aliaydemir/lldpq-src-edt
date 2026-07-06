#!/usr/bin/env python3
"""Focused tests for the static PFC/ECN analyzer."""

import json
import os
import sys
import tempfile
import time
import unittest
from unittest import mock
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR))

import process_pfc_ecn_data as analyzer
from collection_freshness import AssetStatusMap


def qos_payload(ecn=100, rx=200, tx=300, tx_frames=1000, no_buffer=4, wred=5):
    return {
        "egress-queue-stats": {
            "3": {
                "ecn-marked-frames": ecn,
                "tx-frames": tx_frames,
                "tx-uc-buffer-discards": no_buffer,
                "wred-discards": wred,
            },
            "4": {"ecn-marked-frames": 999999},
        },
        "pfc-stats": {
            "3": {"rx-pause-frames": rx, "tx-pause-frames": tx},
            "4": {"rx-pause-frames": 999999, "tx-pause-frames": 999999},
        },
    }


class ParserTests(unittest.TestCase):
    def test_current_collector_markers_status_before_payload_and_nested_json(self):
        payload = {"operational": {"interface": {"swp1": {"qos": qos_payload()}}}}
        raw = "\n".join(
            [
                "__LLDPQ_PFC_ECN_INVENTORY_STATUS__:OK:1",
                "__LLDPQ_PFC_ECN_PORT_START__:swp1",
                "__LLDPQ_PFC_ECN_PORT_STATUS__:swp1:OK:0",
                json.dumps(payload, indent=2),
                "__LLDPQ_PFC_ECN_PORT_END__:swp1",
            ]
        )
        parsed = analyzer.parse_pfc_ecn_snapshot(raw)
        self.assertEqual(parsed["swp1"]["status"], "ok")
        counters = analyzer.extract_counters(parsed["swp1"]["payload"])
        self.assertEqual(counters["ecn_marked_frames"], 100)
        self.assertEqual(counters["rx_pause_frames"], 200)
        self.assertEqual(counters["tx_pause_frames"], 300)
        self.assertNotEqual(counters["ecn_marked_frames"], 999999)

    def test_status_after_payload_and_legacy_markers(self):
        current = "\n".join(
            [
                "__LLDPQ_PFC_ECN_PORT_START__:swp2",
                json.dumps(qos_payload(ecn=17)),
                "__LLDPQ_PFC_ECN_PORT_STATUS__:swp2:OK:0",
                "__LLDPQ_PFC_ECN_PORT_END__:swp2",
            ]
        )
        legacy = "\n".join(
            [
                "===PFC_ECN_PORT_START port=swp3===",
                json.dumps(qos_payload(rx=23)),
                "===PFC_ECN_PORT_END port=swp3 status=ok===",
            ]
        )
        self.assertEqual(
            analyzer.extract_counters(
                analyzer.parse_pfc_ecn_snapshot(current)["swp2"]["payload"]
            )["ecn_marked_frames"],
            17,
        )
        self.assertEqual(
            analyzer.extract_counters(
                analyzer.parse_pfc_ecn_snapshot(legacy)["swp3"]["payload"]
            )["rx_pause_frames"],
            23,
        )

    def test_error_and_invalid_success_are_missing_not_zero(self):
        raw = "\n".join(
            [
                "__LLDPQ_PFC_ECN_PORT_START__:swp1",
                "__LLDPQ_PFC_ECN_PORT_STATUS__:swp1:ERROR:1",
                "nv command failed",
                "__LLDPQ_PFC_ECN_PORT_END__:swp1",
                "__LLDPQ_PFC_ECN_PORT_START__:swp2",
                "__LLDPQ_PFC_ECN_PORT_STATUS__:swp2:OK:0",
                "not json",
                "__LLDPQ_PFC_ECN_PORT_END__:swp2",
            ]
        )
        parsed = analyzer.parse_pfc_ecn_snapshot(raw)
        self.assertEqual(parsed["swp1"]["status"], "error")
        self.assertEqual(parsed["swp2"]["status"], "error")
        for port in ("swp1", "swp2"):
            counters = analyzer.extract_counters(parsed[port]["payload"])
            self.assertTrue(all(value is None for value in counters.values()))

    def test_direct_json_layout(self):
        parsed = analyzer.parse_pfc_ecn_snapshot(
            json.dumps({"ports": {"swp4": qos_payload(tx=44)}})
        )
        self.assertEqual(
            analyzer.extract_counters(parsed["swp4"]["payload"])["tx_pause_frames"],
            44,
        )

    def test_inventory_contract_detects_truncated_capture(self):
        raw = "\n".join(
            [
                "__LLDPQ_PFC_ECN_INVENTORY_STATUS__:OK:2",
                "__LLDPQ_PFC_ECN_PORT_START__:swp1",
                "__LLDPQ_PFC_ECN_PORT_STATUS__:swp1:OK:0",
                json.dumps(qos_payload()),
                "__LLDPQ_PFC_ECN_PORT_END__:swp1",
            ]
        )
        parsed = analyzer.parse_pfc_ecn_snapshot(raw)
        valid, message = analyzer.validate_inventory_contract(raw, parsed)
        self.assertFalse(valid)
        self.assertIn("declared 2", message)


class DeltaTests(unittest.TestCase):
    def test_first_sample_delta_rate_reset_and_missing_semantics(self):
        counters = analyzer.extract_counters(qos_payload())
        first = analyzer.build_port_record("leaf1", "swp1", counters, None, 1000)
        self.assertEqual(first["sample_status"], "first_sample")
        self.assertIsNone(first["deltas"]["ecn_marked_frames"])

        previous = {"timestamp": 1000, "counters": counters}
        duplicate = analyzer.build_port_record("leaf1", "swp1", counters, previous, 1000)
        self.assertEqual(duplicate["sample_status"], "first_sample")
        self.assertIsNone(duplicate["deltas"]["ecn_marked_frames"])

        newer = analyzer.extract_counters(qos_payload(ecn=130, rx=220, tx=306, tx_frames=1100))
        record = analyzer.build_port_record("leaf1", "swp1", newer, previous, 1010)
        self.assertEqual(record["sample_status"], "analyzed")
        self.assertEqual(record["deltas"]["ecn_marked_frames"], 30)
        self.assertEqual(record["rates"]["ecn_marked_frames"], 3.0)
        self.assertEqual(record["ecn_share_percent"], 30.0)

        reset = analyzer.extract_counters(qos_payload(ecn=2, rx=1, tx=1))
        reset_record = analyzer.build_port_record("leaf1", "swp1", reset, previous, 1020)
        self.assertEqual(reset_record["sample_status"], "counter_reset")
        self.assertIsNone(reset_record["deltas"]["ecn_marked_frames"])

        missing = dict(counters)
        missing["tx_pause_frames"] = None
        missing_record = analyzer.build_port_record("leaf1", "swp1", missing, previous, 1020)
        self.assertEqual(missing_record["sample_status"], "missing")
        self.assertIsNone(missing_record["counters"]["tx_pause_frames"])

        partial_discards = dict(counters)
        partial_discards["wred_discards"] = None
        partial_discard_record = analyzer.build_port_record(
            "leaf1", "swp1", partial_discards, previous, 1020
        )
        self.assertEqual(partial_discard_record["sample_status"], "analyzed")
        self.assertIsNone(partial_discard_record["loss_delta"])
        self.assertEqual(partial_discard_record["signal"], "quiet")
        partial_report = analyzer.render_report([partial_discard_record], {})
        self.assertIn("No ECN/PFC activity", partial_report)
        self.assertNotIn("no new ECN marks, PFC frames, or discards", partial_report)


class EndToEndTests(unittest.TestCase):
    def test_unavailable_report_is_explicit_and_not_telemetry_worded(self):
        report = analyzer.render_report(
            [], {}, expected_hosts=0, current_hosts=0, collection_unavailable=True
        )
        self.assertIn('data-collection-status="unavailable"', report)
        self.assertIn("No current switch collection is available", report)
        self.assertNotIn("telemetry", report.lower())

    def test_report_uses_ber_style_header_human_time_and_metric_guide(self):
        counters = analyzer.extract_counters(qos_payload())
        previous = {"timestamp": 1000, "counters": counters}
        record = analyzer.build_port_record(
            "leaf1", "swp1", counters, previous, 1010
        )
        report = analyzer.render_report([record], {})

        self.assertIn('class="page-header"', report)
        self.assertIn('id="deviceSearch"', report)
        self.assertIn('id="metric-guide-btn"', report)
        self.assertIn('id="run-analysis"', report)
        self.assertIn('id="download-csv"', report)
        self.assertIn('/css/select2.min.css', report)
        self.assertIn('/css/jquery-3.5.1.min.js', report)
        self.assertIn('/css/select2.min.js', report)
        self.assertIn("jq(deviceSearch).select2({", report)
        self.assertIn('/p2p-alias.js', report)
        self.assertIn('/css/analysis-guard.js', report)
        self.assertEqual(report.count('class="sortable"'), 13)
        self.assertEqual(report.count('aria-sort="none"'), 13)
        self.assertEqual(report.count('class="sort-arrow">▲▼</span>'), 13)
        self.assertIn("1 Jan 1970, 00:16:50 UTC", report)
        self.assertIn("10s window", report)
        self.assertIn('data-device="leaf1"', report)
        self.assertIn("row.dataset.device", report)
        self.assertIn("row.dataset.search + ' ' + row.textContent", report)
        self.assertIn("option.setAttribute('data-p2p-key', device)", report)
        self.assertIn('data-csv-value="+0 / 0.0000/s"', report)
        self.assertIn(
            'data-csv-value="1 Jan 1970, 00:16:50 UTC / 10s window"', report
        )
        self.assertIn("window.LLDPqP2P.canonicalText", report)
        self.assertIn("metricGuideReturnFocus = document.activeElement", report)
        self.assertIn("returnTarget.focus()", report)

        self.assertNotIn("Aggregate interval trend", report)
        self.assertNotIn("How to read direction", report)
        self.assertNotIn('<svg class="trend"', report)
        self.assertIn("PFC/ECN Metric Guide", report)
        self.assertIn("SP3 PFC RX — peer paused us", report)
        self.assertIn("SP3 PFC TX — we paused the peer", report)
        self.assertIn("There are no arbitrary warning or critical thresholds", report)

    def test_partial_unreachable_inventory_reports_partial_coverage(self):
        with tempfile.TemporaryDirectory() as directory:
            data_dir = Path(directory) / "monitor-results" / "pfc-ecn-data"
            data_dir.mkdir(parents=True)
            (data_dir / "leaf1_pfc_ecn.txt").write_text(
                "\n".join(
                    [
                        "__LLDPQ_PFC_ECN_INVENTORY_STATUS__:OK:1",
                        "__LLDPQ_PFC_ECN_PORT_START__:swp1",
                        "__LLDPQ_PFC_ECN_PORT_STATUS__:swp1:OK:0",
                        json.dumps(qos_payload()),
                        "__LLDPQ_PFC_ECN_PORT_END__:swp1",
                    ]
                ),
                encoding="utf-8",
            )
            statuses = AssetStatusMap(
                {"leaf1": "OK", "leaf2": "UNREACHABLE"},
                snapshot_valid=True,
                authoritative=False,
            )
            with mock.patch.object(
                analyzer,
                "read_asset_snapshot",
                return_value=(statuses, 0.0, True),
            ):
                self.assertTrue(analyzer.process_pfc_ecn_data_files(str(data_dir)))
            report = (data_dir.parent / "pfc-ecn-analysis.html").read_text()
            self.assertIn('data-coverage-status="partial"', report)
            self.assertIn('data-coverage-expected="2"', report)
            self.assertIn('data-coverage-current="1"', report)
            self.assertIn('<div class="metric">1/2</div>', report)

    def test_all_port_command_errors_publish_missing_values(self):
        with tempfile.TemporaryDirectory() as directory:
            data_dir = Path(directory) / "monitor-results" / "pfc-ecn-data"
            data_dir.mkdir(parents=True)
            (data_dir / "leaf1_pfc_ecn.txt").write_text(
                "\n".join(
                    [
                        "__LLDPQ_PFC_ECN_INVENTORY_STATUS__:OK:1",
                        "__LLDPQ_PFC_ECN_PORT_START__:swp1",
                        "__LLDPQ_PFC_ECN_PORT_STATUS__:swp1:ERROR:127",
                        "nv: command not found",
                        "__LLDPQ_PFC_ECN_PORT_END__:swp1",
                    ]
                ),
                encoding="utf-8",
            )
            self.assertTrue(analyzer.process_pfc_ecn_data_files(str(data_dir)))
            report = (data_dir.parent / "pfc-ecn-analysis.html").read_text()
            self.assertIn("Collection failed", report)
            self.assertIn("0/1", report)
            self.assertIn("&mdash;", report)

    def test_generates_static_report_state_and_second_sample_deltas(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            data_dir = root / "monitor-results" / "pfc-ecn-data"
            data_dir.mkdir(parents=True)
            raw_file = data_dir / "leaf1_pfc_ecn.txt"

            def write_capture(payload, stamp):
                raw_file.write_text(
                    "\n".join(
                        [
                            "__LLDPQ_PFC_ECN_INVENTORY_STATUS__:OK:1",
                            "__LLDPQ_PFC_ECN_PORT_START__:swp1",
                            "__LLDPQ_PFC_ECN_PORT_STATUS__:swp1:OK:0",
                            json.dumps(payload),
                            "__LLDPQ_PFC_ECN_PORT_END__:swp1",
                        ]
                    ),
                    encoding="utf-8",
                )
                os.utime(raw_file, (stamp, stamp))

            now = time.time()
            write_capture(qos_payload(), now - 60)
            self.assertTrue(analyzer.process_pfc_ecn_data_files(str(data_dir)))
            write_capture(qos_payload(ecn=120, rx=230, tx=310, tx_frames=1100), now)
            self.assertTrue(analyzer.process_pfc_ecn_data_files(str(data_dir)))

            report = (root / "monitor-results" / "pfc-ecn-analysis.html").read_text()
            self.assertIn("PFC/ECN Analysis", report)
            self.assertIn("Download CSV", report)
            self.assertIn("ECN marked — total", report)
            self.assertIn("120", report)  # cumulative value requested by the operator
            self.assertIn("+20", report)  # additional interval analysis
            self.assertIn("fetch('/trigger-monitor'", report)
            self.assertNotIn("prometheus", report.lower())

            baseline = json.loads(
                (root / "monitor-results" / "pfc_ecn_baseline.json").read_text()
            )
            history = json.loads(
                (root / "monitor-results" / "pfc_ecn_history.json").read_text()
            )
            self.assertEqual(
                baseline["ports"]["leaf1:swp1"]["counters"]["ecn_marked_frames"],
                120,
            )
            self.assertEqual(
                history["history"]["leaf1:swp1"][-1]["deltas"]["ecn_marked_frames"],
                20,
            )


if __name__ == "__main__":
    unittest.main()
