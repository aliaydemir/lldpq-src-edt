#!/usr/bin/env python3
"""assets.ini header validation in check_alerts must accept the real
column-padded snapshot written by assets.sh (regression for the
single-spaced header comparison that rejected every genuine file)."""

import datetime
import sys
import tempfile
import unittest
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR))

import check_alerts

HEADER = (
    "DEVICE-NAME", "IP", "ETH0-MAC", "SERIAL", "MODEL", "RELEASE",
    "UPTIME", "STATUS", "LAST-SEEN",
)


def formatted(fields):
    """Copy of the header/row writer embedded in assets.sh."""
    widths = (20, 15, 17, 12, 20, 10, 15, 12)
    return " ".join(
        f"{value:<{width}}" for value, width in zip(fields[:8], widths)
    ) + " " + fields[8]


def write_assets_ini(script_dir, header_line=None):
    created_at = datetime.datetime.now().strftime("%Y-%m-%d %H-%M-%S")
    row = (
        "switch01", "10.0.0.1", "aa:bb:cc:dd:ee:ff", "MT12345",
        "MSN3700-CS2F", "5.9.2", "1_day", "OK", "2026-08-21_10:00:00",
    )
    lines = [
        f"Created on {created_at}",
        "",
        header_line if header_line is not None else formatted(HEADER),
        formatted(row),
    ]
    (Path(script_dir) / "assets.ini").write_text(
        "\n".join(lines) + "\n", encoding="utf-8")


class AssetHeaderTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.script_dir = Path(self.tmp.name)
        (self.script_dir / "notifications.yaml").write_text(
            "notifications:\n  enabled: true\n", encoding="utf-8")
        (self.script_dir / "devices.yaml").write_text(
            'devices:\n  10.0.0.1: "switch01 @cumulus"\n', encoding="utf-8")

    def test_real_padded_header_is_accepted(self):
        write_assets_ini(self.script_dir)
        checker = check_alerts.LLDPqAlerts(self.script_dir)
        rows = checker._load_asset_rows()
        self.assertIsNotNone(rows)
        self.assertEqual({"switch01": "OK"}, rows)
        self.assertFalse(checker.had_error)
        stats = checker.get_asset_stats(checker.get_inventory_devices())
        self.assertTrue(stats)
        self.assertEqual(1, stats["successful"])
        self.assertEqual("successful", stats["statuses"]["switch01"])

    def test_garbage_header_is_rejected(self):
        write_assets_ini(self.script_dir,
                         header_line="HOSTNAME ADDRESS MAC OTHER")
        checker = check_alerts.LLDPqAlerts(self.script_dir)
        self.assertIsNone(checker._load_asset_rows())
        self.assertTrue(checker.had_error)


if __name__ == "__main__":
    unittest.main()
