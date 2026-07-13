#!/usr/bin/env python3
"""Tests for port serialization in html/ai_p2p.py and html/ai_generate.py.

Covers the three-part port/group/sub notation ('3/1/2' <-> swp3s1), the
group-fitted breakout resolution (2x/4x/8x formula family from p2p-parser),
and the display-alias translation applied when generating topology.dot.
"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "html"))

import ai_generate  # noqa: E402
import ai_p2p  # noqa: E402


def _conn(src, sport, dst, dport, ctype="oob"):
    return {
        "source_name": src, "source_port": sport,
        "dest_name": dst, "dest_port": dport,
        "connection_type": ctype, "network_type": "eth",
        "unresolved": False,
    }


class PortAliasTests(unittest.TestCase):
    def test_two_part_breakout_roundtrip(self):
        self.assertIn("swp41s0", ai_p2p._port_aliases("41/1"))
        self.assertIn("41/1", ai_p2p._port_aliases("swp41s0"))

    def test_two_part_first_lane_matches_unsplit_port(self):
        self.assertIn("swp49", ai_p2p._port_aliases("49/1"))
        self.assertIn("49/1", ai_p2p._port_aliases("swp49"))

    def test_three_part_candidates_cover_all_breakout_modes(self):
        aliases = ai_p2p._port_aliases("3/1/2")
        # y=1, z=2: 2x_group -> s0, 2x_sub/4x/8x -> s1
        self.assertIn("swp3s1", aliases)
        self.assertIn("swp3s0", aliases)
        aliases = ai_p2p._port_aliases("1/2/1")
        # y=2, z=1: 2x_group -> s1, 2x_sub -> s0, 4x -> s2, 8x -> s4
        for lane in ("swp1s1", "swp1s0", "swp1s2", "swp1s4"):
            self.assertIn(lane, aliases)

    def test_os_spelling_gains_three_part_alias(self):
        self.assertIn("3/1/2", ai_p2p._port_aliases("swp3s1"))


class ResolvePortMapTests(unittest.TestCase):
    def test_full_8x_group(self):
        conns = [
            _conn("LEAF-%d" % i, "49", "SPINE SP-01", "1/%d/%d" % (y, z))
            for i, (y, z) in enumerate(
                [(y, z) for y in (1, 2) for z in (1, 2, 3, 4)])
        ]
        resolved = ai_p2p.resolve_port_map(conns)
        self.assertEqual(resolved[("spine sp-01", "1/1/1")], "swp1s0")
        self.assertEqual(resolved[("spine sp-01", "1/2/1")], "swp1s4")
        self.assertEqual(resolved[("spine sp-01", "1/2/4")], "swp1s7")

    def test_sparse_group_uses_device_level_max_z(self):
        # Port 3 leaves lanes uncabled, but port 1 proves the switch is a 4x
        # split, so 3/2/1 is lane s4 (not s3).
        conns = [
            _conn("A", "49", "SP-01", "1/1/4"),
            _conn("B", "49", "SP-01", "3/1/1"),
            _conn("C", "49", "SP-01", "3/2/1"),
        ]
        resolved = ai_p2p.resolve_port_map(conns)
        self.assertEqual(resolved[("sp-01", "3/2/1")], "swp3s4")

    def test_singleton_y1_matches_sub_minus_one(self):
        resolved = ai_p2p.resolve_port_map([_conn("A", "49", "SP-01", "3/1/2")])
        self.assertEqual(resolved[("sp-01", "3/1/2")], "swp3s1")

    def test_resolved_os_port_accepts_any_device_spelling(self):
        conns = [_conn("A", "49", "sp-01.example.com", "3/1/2")]
        resolved = ai_p2p.resolve_port_map(conns)
        self.assertEqual(
            ai_p2p.resolved_os_port(resolved, "SP-01", "3/1/2"), "swp3s1")

    def test_lookup_by_live_os_spelling_finds_three_part_record(self):
        conns = [_conn("OOB-02", "51", "OOB SP-02", "3/1/2")]
        hits = ai_p2p.lookup(conns, "OOB SP-02", "swp3s1")
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0]["peer_device"], "OOB-02")


class TopologyGenerationTests(unittest.TestCase):
    def test_three_part_ports_resolve_in_dot(self):
        conns = [
            _conn("leaf-01", "49", "SPINE-01", "1/1/2"),
            _conn("leaf-02", "49", "SPINE-01", "1/2/2"),
            _conn("leaf-03", "49", "SPINE-01", "1/1/4"),
        ]
        dot = ai_generate.p2p_to_topology_dot(conns)
        self.assertIn('"SPINE-01":"swp1s1"', dot)
        self.assertIn('"SPINE-01":"swp1s5"', dot)
        self.assertNotIn("1/1/2", dot)

    def test_device_alias_translates_design_labels_to_live_names(self):
        conns = [_conn("OOB-02", "51", "OOB SP-02", "3/1/2")]
        dot = ai_generate.p2p_to_topology_dot(
            conns,
            device_aliases={"oob sp-02": "oob-spine-02", "oob-02": "oob-leaf-02"})
        self.assertIn('"oob-spine-02":"swp3s1"', dot)
        self.assertIn('"oob-leaf-02":"swp51"', dot)
        # Untranslated spaced design labels can never appear in topology.dot.
        self.assertNotIn("OOB SP-02", dot)

    def test_spaced_design_label_without_alias_is_dropped(self):
        conns = [_conn("OOB-02", "51", "OOB SP-02", "3/1/2")]
        dot = ai_generate.p2p_to_topology_dot(conns)
        self.assertNotIn("OOB SP-02", dot)


class TopologyScopeTests(unittest.TestCase):
    def setUp(self):
        def ib(src, sport, dst, dport):
            link = _conn(src, sport, dst, dport, ctype="compute")
            link["network_type"] = "ib"
            return link

        self.conns = [
            # ETH switch-to-switch
            _conn("leaf-01", "49", "spine-01", "1/1/1", ctype="converged"),
            # ETH switch-to-host (BMC endpoint)
            _conn("dgx-01", "BMC", "tor-01", "48", ctype="oob"),
            # OOB switch-to-switch (mgmt plane)
            _conn("oob-leaf-01", "51", "oob-spine-01", "3/1/2", ctype="oob"),
            # IB fabric link (HCA endpoint)
            ib("gb300-1-1-dgx", "M1", "cleaf-01", "19/2"),
            # power plane must never appear
            _conn("pdu-01", "1", "pwrshelf-01", "2", ctype="power"),
        ]

    def _edges(self, **kwargs):
        dot = ai_generate.p2p_to_topology_dot(self.conns, **kwargs)
        return [line.strip() for line in dot.splitlines() if " -- " in line]

    def test_full_scope_keeps_everything_but_power(self):
        edges = "\n".join(self._edges(scope="full"))
        for dev in ("leaf-01", "dgx-01", "oob-leaf-01", "gb300-1-1-dgx"):
            self.assertIn(dev, edges)
        self.assertNotIn("pdu-01", edges)

    def test_sw_to_sw_keeps_only_eth_switch_pairs(self):
        edges = "\n".join(self._edges(scope="sw-to-sw"))
        self.assertIn("leaf-01", edges)
        self.assertIn("oob-leaf-01", edges)  # OOB leaf-spine is switch-switch
        self.assertNotIn("dgx-01", edges)    # BMC endpoint is a host
        self.assertNotIn("gb300-1-1-dgx", edges)  # IB excluded
        self.assertNotIn("pdu-01", edges)

    def test_eth_only_excludes_ib(self):
        edges = "\n".join(self._edges(scope="eth-only"))
        self.assertIn("dgx-01", edges)       # host ETH links stay
        self.assertNotIn("gb300-1-1-dgx", edges)

    def test_ib_only_keeps_ib_and_mgmt_modifier_adds_oob(self):
        edges = "\n".join(self._edges(scope="ib-only"))
        self.assertIn("gb300-1-1-dgx", edges)
        self.assertNotIn('"leaf-01"', edges)
        self.assertNotIn('"oob-leaf-01"', edges)
        with_mgmt = "\n".join(self._edges(scope="ib-only", include_mgmt=True))
        self.assertIn("oob-leaf-01", with_mgmt)
        self.assertIn("dgx-01", with_mgmt)   # oob ctype rides in via mgmt
        self.assertNotIn("pdu-01", with_mgmt)

    def test_unknown_scope_is_rejected(self):
        with self.assertRaises(ValueError):
            ai_generate.p2p_to_topology_dot(self.conns, scope="bogus")


class DevicesYamlRoleTests(unittest.TestCase):
    def _yaml(self, records):
        ipam = {"format": "ipam", "fabric": records, "subnets": [], "hosts": []}
        return ai_generate.ipam_to_devices_yaml(ipam)["yaml"]

    def test_design_role_column_is_preserved_verbatim(self):
        text = self._yaml([
            {"hostname": "tan-spine-01", "role": "tan_spine", "mgmt_ip": "172.31.44.1"},
            {"hostname": "oob-tor-1-1-01", "role": "oob_tor", "mgmt_ip": "172.31.44.27"},
        ])
        self.assertIn("tan-spine-01 @tan_spine", text)
        self.assertIn("oob-tor-1-1-01 @oob_tor", text)

    def test_missing_role_falls_back_to_canonical_vocabulary(self):
        text = self._yaml([
            {"hostname": "leaf-07", "role": "", "mgmt_ip": "10.0.0.7"},
        ])
        self.assertIn("leaf-07 @leaf", text)

    def test_role_text_is_sanitized_to_a_token(self):
        text = self._yaml([
            {"hostname": "spine-x", "role": "Tan Spine (row 3)!", "mgmt_ip": "10.0.0.1"},
        ])
        self.assertIn("spine-x @Tan_Spine_row_3", text)

    def test_non_switch_records_stay_filtered(self):
        result = ai_generate.ipam_to_devices_yaml({
            "format": "ipam", "subnets": [], "hosts": [],
            "fabric": [
                {"hostname": "gb300-1-1-dgx-01", "role": "DGX", "mgmt_ip": "10.0.1.1"},
                {"hostname": "pdu-a1", "role": "pdu", "mgmt_ip": "10.0.1.2"},
            ],
        })
        self.assertNotIn("dgx", result["yaml"])
        self.assertEqual(sorted(result["skipped"]), ["gb300-1-1-dgx-01", "pdu-a1"])


if __name__ == "__main__":
    unittest.main()
