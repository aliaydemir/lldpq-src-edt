#!/usr/bin/env python3
"""assets.ini header validation in check_alerts must accept the real
column-padded snapshot written by assets.sh (regression for the
single-spaced header comparison that rejected every genuine file)."""

import datetime
import os
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

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


def write_assets_ini(script_dir, header_line=None, created_at=None):
    if created_at is None:
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


class AssetTimestampTests(unittest.TestCase):
    """Fold-aware 'Created on' validation and the shared tolerance knob
    (regression for the DST fall-back hour rejecting every snapshot and
    for the hardcoded 120s tolerance ignoring the operator knob)."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.script_dir = Path(self.tmp.name)
        (self.script_dir / "notifications.yaml").write_text(
            "notifications:\n  enabled: true\n", encoding="utf-8")
        (self.script_dir / "devices.yaml").write_text(
            'devices:\n  10.0.0.1: "switch01 @cumulus"\n', encoding="utf-8")

    def set_timezone(self, zone):
        original = os.environ.get("TZ")
        os.environ["TZ"] = zone
        time.tzset()

        def restore():
            if original is None:
                os.environ.pop("TZ", None)
            else:
                os.environ["TZ"] = original
            time.tzset()

        self.addCleanup(restore)

    def test_dst_fall_back_second_pass_is_accepted(self):
        self.set_timezone("America/New_York")
        ambiguous = datetime.datetime(2026, 11, 1, 1, 30)
        second_pass = ambiguous.replace(fold=1).timestamp()
        # Guard: the zone must really repeat this hour (fold=1 is EST).
        self.assertEqual(3600.0, second_pass - ambiguous.timestamp())
        write_assets_ini(self.script_dir, created_at="2026-11-01 01-30-00")
        assets = self.script_dir / "assets.ini"
        os.utime(assets, (second_pass, second_pass))
        checker = check_alerts.LLDPqAlerts(self.script_dir)
        with mock.patch("time.time", return_value=second_pass + 60):
            rows = checker._load_asset_rows()
        self.assertEqual({"switch01": "OK"}, rows)
        self.assertFalse(checker.had_error)

    def test_skew_beyond_both_folds_is_still_rejected(self):
        self.set_timezone("America/New_York")
        ambiguous = datetime.datetime(2026, 11, 1, 1, 30)
        second_pass = ambiguous.replace(fold=1).timestamp()
        write_assets_ini(self.script_dir, created_at="2026-11-01 01-30-00")
        assets = self.script_dir / "assets.ini"
        skewed = second_pass + 7200.0
        os.utime(assets, (skewed, skewed))
        checker = check_alerts.LLDPqAlerts(self.script_dir)
        with mock.patch.dict(os.environ, {
            "ASSET_TIMESTAMP_TOLERANCE_SECONDS": "120",
        }), mock.patch("time.time", return_value=skewed + 60):
            self.assertIsNone(checker._load_asset_rows())
        self.assertTrue(checker.had_error)

    def test_tolerance_env_knob_is_honored(self):
        self.set_timezone("UTC")
        created_epoch = datetime.datetime(2026, 11, 5, 12, 0).timestamp()
        write_assets_ini(self.script_dir, created_at="2026-11-05 12-00-00")
        assets = self.script_dir / "assets.ini"
        skewed = created_epoch + 600.0
        os.utime(assets, (skewed, skewed))

        rejected = check_alerts.LLDPqAlerts(self.script_dir)
        with mock.patch.dict(os.environ, {
            "ASSET_TIMESTAMP_TOLERANCE_SECONDS": "120",
        }), mock.patch("time.time", return_value=skewed + 60):
            self.assertIsNone(rejected._load_asset_rows())
        self.assertTrue(rejected.had_error)

        accepted = check_alerts.LLDPqAlerts(self.script_dir)
        with mock.patch.dict(os.environ, {
            "ASSET_TIMESTAMP_TOLERANCE_SECONDS": "900",
        }), mock.patch("time.time", return_value=skewed + 60):
            rows = accepted._load_asset_rows()
        self.assertEqual({"switch01": "OK"}, rows)
        self.assertFalse(accepted.had_error)


if __name__ == "__main__":
    unittest.main()
