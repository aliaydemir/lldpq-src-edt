#!/usr/bin/env python3
"""Regression tests for duplicate IP severity and summary classification."""

import tempfile
import time
import unittest
from pathlib import Path

from duplicate_analyzer import ACTIVE_WINDOW_SEC, DuplicateAnalyzer


class DuplicateIpSeverityTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.analyzer = DuplicateAnalyzer(self.tmp.name)
        self.analyzer.coverage = {
            "expected": {"tor-a", "tor-b"},
            "current": {"tor-a", "tor-b"},
            "failures": [],
            "partial": False,
        }

    def add_ip(self, ip, *, hosts=("tor-a",), recency=None, delta=0,
               seq=100, flagged=True):
        rec = self.analyzer._blank_ip("8", "100008", ip)
        rec.update({
            "seq": seq,
            "flagged": flagged,
            "recency": recency,
            "delta": delta,
        })
        rec["macs"].add("00:11:22:33:44:55")
        rec["authoritative_hosts"].update(hosts)
        rec["severity"] = self.analyzer._ip_sev(rec)
        self.analyzer.ip_dups[("8", ip)] = rec
        if hosts:
            self.analyzer.authoritative_ip_pairs[("100008", ip)] = set(hosts)
        return rec

    def test_current_authoritative_old_flat_is_quiesced(self):
        rec = self.add_ip(
            "10.2.240.88",
            recency=ACTIVE_WINDOW_SEC + 1,
            delta=0,
        )

        self.assertEqual("WARNING", rec["severity"])

    def test_parsed_flat_frr_row_is_quiesced_after_finalize(self):
        self.analyzer.vni_to_vlan["100008"] = "8"
        self.analyzer.prev_state["ip:100008|10.2.240.88"] = {
            "seq": 100,
            "ts": time.time() - (ACTIVE_WINDOW_SEC + 1),
        }
        self.analyzer._parse_arp_dup("tor-a", [
            "VNI 100008 #ARP (IPv4 and IPv6, local and remote) 1",
            "10.2.240.88 local active 00:11:22:33:44:55 100/99",
        ])

        self.analyzer._finalize()

        rec = self.analyzer.ip_dups[("8", "10.2.240.88")]
        self.assertEqual(0, rec["delta"])
        self.assertEqual("WARNING", rec["severity"])
        self.assertEqual(0, self.analyzer.summary()["ip_active"])
        self.assertEqual(1, self.analyzer.summary()["ip_quiesced"])

    def test_recent_authoritative_is_critical(self):
        rec = self.add_ip(
            "10.2.240.88",
            recency=ACTIVE_WINDOW_SEC - 1,
            delta=0,
        )

        self.assertEqual("CRITICAL", rec["severity"])

    def test_climbing_sequence_is_critical(self):
        rec = self.add_ip(
            "10.2.240.88",
            recency=ACTIVE_WINDOW_SEC + 1,
            delta=1,
        )

        self.assertEqual("CRITICAL", rec["severity"])

    def test_summary_splits_active_and_quiesced(self):
        self.add_ip("10.2.240.88", recency=10, delta=0)
        self.add_ip(
            "10.2.241.88",
            recency=ACTIVE_WINDOW_SEC + 1,
            delta=0,
        )

        summary = self.analyzer.summary()

        self.assertEqual(1, summary["ip_active"])
        self.assertEqual(1, summary["confirmed_ip_active"])
        self.assertEqual(1, summary["ip_quiesced"])
        self.assertEqual(2, summary["ip_total"])

    def test_same_ip_from_two_current_hosts_is_counted_once(self):
        self.add_ip(
            "10.2.240.88",
            hosts=("tor-a", "tor-b"),
            recency=10,
            delta=0,
        )

        summary = self.analyzer.summary()

        self.assertEqual(1, summary["ip_active"])
        self.assertEqual(1, summary["ip_total"])

    def test_non_authoritative_context_is_excluded_from_summary(self):
        rec = self.add_ip(
            "10.2.242.88",
            hosts=(),
            recency=10,
            delta=0,
            flagged=False,
            seq=0,
        )

        self.assertEqual("CRITICAL", rec["severity"])
        summary = self.analyzer.summary()
        self.assertEqual(0, summary["ip_active"])
        self.assertEqual(0, summary["ip_quiesced"])
        self.assertEqual(0, summary["ip_total"])
        self.assertEqual(0, summary["vlans"])

    def test_html_marks_latched_frr_record_as_quiesced(self):
        self.add_ip(
            "10.2.240.88",
            recency=ACTIVE_WINDOW_SEC + 1,
            delta=0,
        )
        output = Path(self.tmp.name) / "duplicate-analysis.html"

        self.analyzer.export_html(str(output))
        report = output.read_text(encoding="utf-8")

        self.assertIn('data-confirmed-ip-active="0"', report)
        self.assertIn('data-ip-quiesced="1"', report)
        self.assertIn("quiesced / latched", report)


if __name__ == "__main__":
    unittest.main()
