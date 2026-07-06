#!/usr/bin/env python3
"""Focused tests for the single-pass collection bundle splitter."""

from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR))

from collection_bundle import (  # noqa: E402
    CollectionBundleError,
    SECTIONS,
    split_collection_bundle,
)


def bundle_bytes(bodies=None, order=SECTIONS, suffix=b""):
    bodies = bodies or {}
    records = [b"ignored preamble"]
    for section in order:
        records.append(f"==={section}_START===".encode("ascii"))
        body = bodies.get(section, [f"{section} body".encode("ascii")])
        records.extend(body)
        records.append(f"==={section}_END===".encode("ascii"))
        records.append(b"ignored inter-section noise")
    return b"\n".join(records) + b"\n" + suffix


class CollectionBundleTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.raw = self.root / "raw.txt"
        self.outputs = {
            section: self.root / f"{section.lower()}.txt" for section in SECTIONS
        }

    def tearDown(self):
        self.temporary.cleanup()

    def test_valid_bundle_is_split_and_preserves_analyzer_records(self):
        pfc_error = b"__LLDPQ_PFC_ECN_PORT_STATUS__:swp1:ERROR:1"
        self.raw.write_bytes(
            bundle_bytes(
                {
                    "HTML_OUTPUT": [b"<p>device</p>", b""],
                    "PFC_ECN_DATA": [pfc_error, b"command-specific detail"],
                    "LOG_DATA": [b"non-UTF-8:\xff", b"last line"],
                },
                suffix=b"arbitrary trailing diagnostic\n",
            )
        )

        split_collection_bundle(self.raw, self.outputs)

        self.assertEqual(
            self.outputs["HTML_OUTPUT"].read_bytes(), b"<p>device</p>\n\n"
        )
        self.assertEqual(
            self.outputs["PFC_ECN_DATA"].read_bytes(),
            pfc_error + b"\ncommand-specific detail\n",
        )
        self.assertEqual(
            self.outputs["LOG_DATA"].read_bytes(),
            b"non-UTF-8:\xff\nlast line\n",
        )
        for section in SECTIONS:
            self.assertTrue(self.outputs[section].is_file())
            self.assertNotIn(b"===" + section.encode("ascii"), self.outputs[section].read_bytes())

    def test_missing_end_marker_rejects_without_replacing_destinations(self):
        self.raw.write_bytes(
            bundle_bytes().replace(b"===LOG_DATA_END===\n", b"", 1)
        )
        for path in self.outputs.values():
            path.write_bytes(b"old\n")

        with self.assertRaisesRegex(
            CollectionBundleError,
            r"invalid LOG_DATA marker count: start=1 end=0",
        ):
            split_collection_bundle(self.raw, self.outputs)

        self.assertTrue(
            all(path.read_bytes() == b"old\n" for path in self.outputs.values())
        )
        self.assertEqual(list(self.root.glob(".*.tmp")), [])

    def test_duplicate_trailing_marker_is_rejected(self):
        self.raw.write_bytes(bundle_bytes(suffix=b"===LOG_DATA_END===\n"))
        with self.assertRaisesRegex(
            CollectionBundleError,
            r"invalid LOG_DATA marker count: start=1 end=2",
        ):
            split_collection_bundle(self.raw, self.outputs)

    def test_out_of_order_sections_are_rejected(self):
        order = list(SECTIONS)
        order[0], order[1] = order[1], order[0]
        self.raw.write_bytes(bundle_bytes(order=order))
        with self.assertRaisesRegex(
            CollectionBundleError,
            r"out-of-order collection section: BGP_DATA",
        ):
            split_collection_bundle(self.raw, self.outputs)

    def test_collection_command_error_takes_precedence_and_is_not_published(self):
        marker = b"__LLDPQ_COLLECTION_ERROR__:BGP_SUMMARY"
        self.raw.write_bytes(
            bundle_bytes({"BGP_DATA": [marker]}).replace(
                b"===LOG_DATA_END===\n", b"", 1
            )
        )
        with self.assertRaisesRegex(
            CollectionBundleError,
            r"remote collection command failures: .*BGP_SUMMARY",
        ):
            split_collection_bundle(self.raw, self.outputs)
        self.assertTrue(all(not path.exists() for path in self.outputs.values()))

    def test_all_output_sections_are_required(self):
        self.raw.write_bytes(bundle_bytes())
        partial = dict(self.outputs)
        partial.pop("LOG_DATA")
        with self.assertRaisesRegex(CollectionBundleError, r"missing=LOG_DATA"):
            split_collection_bundle(self.raw, partial)

    def test_cli_contract_writes_all_outputs(self):
        self.raw.write_bytes(bundle_bytes())
        command = [sys.executable, str(SCRIPT_DIR / "collection_bundle.py"), str(self.raw)]
        for section in SECTIONS:
            command.extend(["--output", section, str(self.outputs[section])])

        result = subprocess.run(command, text=True, capture_output=True, check=False)

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(
            self.outputs["EVPN_DATA"].read_text(encoding="utf-8"),
            "EVPN_DATA body\n",
        )


if __name__ == "__main__":
    unittest.main()
