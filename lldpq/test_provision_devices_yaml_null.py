#!/usr/bin/env python3
"""Keeps an all-planned devices.yaml from poisoning every consumer.

Before any switch has ZTP'd, every inventory binding is planned (no MAC yet,
dhcp=true), so both rebuild renderers used to emit `devices:` followed only by
commented entries.  That parses as {'devices': None}: the pre-write safe_load
verification passes, and afterwards Inventory Save
(sync_bindings_to_devices_yaml), the Base Config device list
(action_list_devices) and update-role all crash on `.items()` over None,
answering the UI with a non-JSON body it cannot explain.

Two properties are pinned here:

1. The renderers emit `devices: {}` when zero active entries are written,
   keeping the commented planned lines visible.
2. The consumers guard the map anyway — a file written before the fix, or an
   entirely empty one, must not raise — while a legacy flat file, where the
   whole document is the device map, keeps its in-place semantics.

The functions are executed for real, sliced out of the CGI's embedded Python
with ast (the extract_source pattern of test_dhcp_multi_pool.py), against a
temporary filesystem.
"""

from __future__ import annotations

import ast
import contextlib
import fcntl
import io
import ipaddress
import json
import os
from pathlib import Path
import re
import shutil
import sys
import tempfile
import time
import unittest
from unittest import mock

import yaml as pyyaml


ROOT = Path(__file__).resolve().parents[1]
PROVISION_API = (ROOT / "html" / "provision-api.sh").read_text(encoding="utf-8")

_BODY = PROVISION_API[
    PROVISION_API.index("python3 << 'PYTHON_SCRIPT'\n"):
    PROVISION_API.rindex("\nPYTHON_SCRIPT\n")
]
_TREE = ast.parse(_BODY)


def extract_source(name: str) -> str:
    """Slice one top-level def out of the CGI's embedded Python."""
    for node in _TREE.body:
        if isinstance(node, ast.FunctionDef) and node.name == name:
            start = min([node.lineno] +
                        [decorator.lineno for decorator in node.decorator_list])
            return "\n".join(_BODY.splitlines()[start - 1:node.end_lineno]) + "\n"
    raise AssertionError(f"{name} not found in provision-api.sh")


class Emitted(BaseException):
    """A CGI response.  Not an Exception, so no `except Exception` swallows it."""

    def __init__(self, payload):
        super().__init__(payload)
        self.payload = payload


# In dependency order.
API_NAMES = (
    'is_valid_provision_hostname', 'normalize_inventory_bindings',
    'render_inventory_devices_yaml', 'sync_bindings_to_devices_yaml',
    'action_list_devices', 'action_update_role', 'action_rebuild_devices_yaml',
)


def planned(hostname, ip, role=''):
    return {'hostname': hostname, 'ip': ip, 'mac': '-', 'serial': '',
            'role': role, 'inv_status': 'planned', 'dhcp': True}


def active(hostname, ip, mac, role=''):
    return {'hostname': hostname, 'ip': ip, 'mac': mac, 'serial': '',
            'role': role, 'inv_status': 'active', 'dhcp': True}


# The exact shape both renderers produced before the fix: it parses fine (so
# the pre-write verification let it through) but the devices map is None.
NULL_MAP_YAML = (
    "# devices.yaml — Auto-generated from Provision Inventory\n"
    "# Generated: 2026-08-20 10:00:00\n"
    "#\n"
    "\n"
    "defaults:\n"
    "  username: cumulus\n"
    "\n"
    "devices:\n"
    "\n"
    "  # leaf\n"
    "#  10.0.0.1: leaf01 @leaf\n"
)


class DevicesYamlFixture(unittest.TestCase):
    """Runs the real inventory code from the CGI against a temp filesystem."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.root = Path(self._tmp.name)
        self.devices_file = self.root / "devices.yaml"
        self.api = self.load_api()

    def load_api(self):
        def atomic_write_text(path, content, mode=0o664):
            with open(path, 'w') as handle:
                handle.write(content)
            os.chmod(path, mode)

        @contextlib.contextmanager
        def exclusive_file_lock(path):
            yield

        namespace = {
            "os": os, "re": re, "io": io, "json": json, "time": time,
            "fcntl": fcntl, "shutil": shutil, "ipaddress": ipaddress,
            "LLDPQ_DIR": str(self.root),
            "INVENTORY_LOCK_FILE": str(self.root / ".inventory.lock"),
            "POST_DATA": "",
            "result_json": lambda payload: (_ for _ in ()).throw(Emitted(payload)),
            "error_json": lambda message: (_ for _ in ()).throw(
                Emitted({"success": False, "error": message})
            ),
            "atomic_write_text": atomic_write_text,
            "exclusive_file_lock": exclusive_file_lock,
            "inventory_revision": lambda: "rev0",
        }
        for name in API_NAMES:
            exec(compile(extract_source(name), "provision-api.sh", "exec"),
                 namespace)
        return namespace

    def call(self, name):
        """Invoke a CGI action and hand back the response it emitted."""
        try:
            self.api[name]()
        except Emitted as response:
            return response.payload
        self.fail(f"{name} returned without emitting a response")

    def read_yaml(self):
        return pyyaml.safe_load(self.devices_file.read_text(encoding="utf-8"))


class RendererTests(DevicesYamlFixture):
    """Zero active entries must still render a parseable devices map."""

    def test_all_planned_render_parses_to_an_empty_devices_map(self):
        content, active_count, planned_count = self.api[
            'render_inventory_devices_yaml'
        ]([planned('leaf01', '10.0.0.1', 'leaf'),
           planned('leaf02', '10.0.0.2', 'leaf')])
        self.assertEqual((active_count, planned_count), (0, 2))
        self.assertEqual(pyyaml.safe_load(content),
                         {'defaults': {'username': 'cumulus'}, 'devices': {}})
        # The planned entries stay visible as comments.
        self.assertIn('#  10.0.0.1: leaf01 @leaf', content)
        self.assertIn('#  10.0.0.2: leaf02 @leaf', content)

    def test_one_active_entry_keeps_the_real_map(self):
        content, active_count, _ = self.api['render_inventory_devices_yaml'](
            [planned('leaf01', '10.0.0.1', 'leaf'),
             active('leaf02', '10.0.0.2', 'aa:bb:cc:dd:ee:02', 'leaf')])
        self.assertEqual(active_count, 1)
        self.assertEqual(pyyaml.safe_load(content)['devices'],
                         {'10.0.0.2': 'leaf02 @leaf'})

    def test_rebuild_action_writes_a_parseable_empty_map(self):
        self.api['POST_DATA'] = json.dumps({'bindings': [
            {'hostname': 'leaf01', 'ip': '10.0.0.1', 'mac': '-',
             'role': 'leaf', 'inv_status': 'planned', 'dhcp': True},
        ]})
        payload = self.call('action_rebuild_devices_yaml')
        self.assertTrue(payload.get('success'), payload)
        self.assertEqual(self.read_yaml()['devices'], {})
        self.assertIn('#  10.0.0.1: leaf01 @leaf',
                      self.devices_file.read_text(encoding="utf-8"))


class NullMapConsumerTests(DevicesYamlFixture):
    """A devices: null file written before the fix must stop crashing."""

    def setUp(self):
        super().setUp()
        self.devices_file.write_text(NULL_MAP_YAML, encoding="utf-8")

    def test_inventory_save_sync_no_longer_raises(self):
        rendered, message = self.api['sync_bindings_to_devices_yaml'](
            [active('leaf01', '10.0.0.1', 'aa:bb:cc:dd:ee:01', 'leaf')],
            [], write=False)
        self.assertIn('1 added', message)
        self.assertEqual(pyyaml.safe_load(rendered)['devices'],
                         {'10.0.0.1': 'leaf01 @leaf'})

    def test_list_devices_no_longer_raises(self):
        payload = self.call('action_list_devices')
        self.assertTrue(payload.get('success'), payload)
        self.assertEqual(payload['devices'], [])
        self.assertEqual(payload['groups'], {})

    def test_update_role_repairs_the_null_map(self):
        self.api['POST_DATA'] = json.dumps(
            {'hostname': 'leaf01', 'ip': '10.0.0.1', 'role': 'leaf'})
        payload = self.call('action_update_role')
        self.assertTrue(payload.get('success'), payload)
        self.assertEqual(self.read_yaml()['devices'],
                         {'10.0.0.1': 'leaf01 @leaf'})

    # The deploy target may lack ruamel; the pyyaml ImportError fallbacks
    # carry their own copy of the guard and need exercising too.

    def test_inventory_save_sync_survives_without_ruamel(self):
        with mock.patch.dict(sys.modules,
                             {'ruamel': None, 'ruamel.yaml': None}):
            rendered, message = self.api['sync_bindings_to_devices_yaml'](
                [active('leaf01', '10.0.0.1', 'aa:bb:cc:dd:ee:01', 'leaf')],
                [], write=False)
        self.assertIn('1 added', message)
        self.assertEqual(pyyaml.safe_load(rendered)['devices'],
                         {'10.0.0.1': 'leaf01 @leaf'})

    def test_update_role_repairs_the_null_map_without_ruamel(self):
        self.api['POST_DATA'] = json.dumps(
            {'hostname': 'leaf01', 'ip': '10.0.0.1', 'role': 'leaf'})
        with mock.patch.dict(sys.modules,
                             {'ruamel': None, 'ruamel.yaml': None}):
            payload = self.call('action_update_role')
        self.assertTrue(payload.get('success'), payload)
        self.assertEqual(self.read_yaml()['devices'],
                         {'10.0.0.1': 'leaf01 @leaf'})


class EmptyFileConsumerTests(DevicesYamlFixture):
    """An entirely empty devices.yaml loads as None at the document level."""

    def setUp(self):
        super().setUp()
        self.devices_file.write_text("", encoding="utf-8")

    def test_sync_handles_an_empty_file(self):
        rendered, message = self.api['sync_bindings_to_devices_yaml'](
            [active('leaf01', '10.0.0.1', 'aa:bb:cc:dd:ee:01')],
            [], write=False)
        self.assertIn('1 added', message)
        # No 'devices' key existed, so the flat legacy layout is kept.
        self.assertEqual(pyyaml.safe_load(rendered), {'10.0.0.1': 'leaf01'})

    def test_list_devices_handles_an_empty_file(self):
        payload = self.call('action_list_devices')
        self.assertTrue(payload.get('success'), payload)
        self.assertEqual(payload['devices'], [])


class LegacyFlatFileTests(DevicesYamlFixture):
    """No 'devices' key: the whole document is the device map."""

    def setUp(self):
        super().setUp()
        self.devices_file.write_text(
            "10.0.0.1: leaf01 @leaf\n10.0.0.2: leaf02\n", encoding="utf-8")

    def test_sync_still_edits_the_flat_map_in_place(self):
        rendered, message = self.api['sync_bindings_to_devices_yaml'](
            [active('leaf03', '10.0.0.3', 'aa:bb:cc:dd:ee:03', 'spine')],
            [], write=False)
        self.assertIn('1 added', message)
        parsed = pyyaml.safe_load(rendered)
        self.assertNotIn('devices', parsed)
        self.assertEqual(parsed['10.0.0.1'], 'leaf01 @leaf')
        self.assertEqual(parsed['10.0.0.3'], 'leaf03 @spine')

    def test_list_devices_still_reads_the_flat_map(self):
        payload = self.call('action_list_devices')
        self.assertTrue(payload.get('success'), payload)
        by_ip = {device['ip']: device for device in payload['devices']}
        self.assertEqual(by_ip['10.0.0.1']['hostname'], 'leaf01')
        self.assertEqual(by_ip['10.0.0.1']['role'], 'leaf')
        self.assertEqual(by_ip['10.0.0.2']['hostname'], 'leaf02')


if __name__ == "__main__":
    unittest.main()
