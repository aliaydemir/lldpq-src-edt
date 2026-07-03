#!/usr/bin/env python3
"""
Duplicate IP / MAC Analyzer for LLDPq

Fabric-wide detection of duplicate IPs and MACs in an EVPN/VXLAN OOB/in-band
network, grouped per VLAN/VNI. Combines several signals collected by monitor.sh
(per device, under monitor-results/dup-data/):

  * show evpn arp-cache vni all duplicate  -> authoritative duplicate IPs (+ EVPN seq)
  * show evpn mac vni all duplicate        -> duplicate MACs (when FRR latches them)
  * zebra log "detected as duplicate"      -> timestamped event history (recency + rate)
  * show evpn (duplicate-detection config) -> max-moves/time, enabled? (avoid false-negatives)
  * bridge fdb show                        -> same MAC LOCAL on >=2 switches (non-EVPN + location)
  * ip -4 neigh show                       -> APIPA (169.254/16 = DHCP failed) + IP<->multi-MAC

Severity is driven by *recency* (a duplicate logged in the last hour = actively
flapping = CRITICAL) and by the EVPN mobility *sequence delta* between monitor
cycles (climbing seq = active). A flagged-but-stale entry is WARNING.

Copyright (c) 2024 LLDPq Project - MIT License
"""

import os
import re
import json
import copy
import time
import tempfile
from datetime import datetime, timezone
from collection_freshness import (
    asset_snapshot_is_authoritative,
    asset_snapshot_is_valid,
    is_current_collection,
    max_data_age_seconds,
    read_asset_snapshot,
)
try:
    from duplicate_report import export_duplicate_report
except ImportError:  # package-style imports used by some tests/tools
    from .duplicate_report import export_duplicate_report

try:
    from device_names import canonical
except Exception:
    def canonical(_n):
        return _n

MAC_RE = re.compile(r'(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}')
IPV4_RE = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
SEQ_RE = re.compile(r'(\d+)\s*/\s*(\d+)\s*$')
LOG_TS_RE = re.compile(
    r'(?P<ts>'
    r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+\-]\d{2}:?\d{2})'
    r'|\d{4}/\d{2}/\d{2}\s+\d{2}:\d{2}:\d{2}(?:\.\d+)?'
    r')'
)
LOG_VNI_RE = re.compile(r'\bVNI\s+(\d+)\s*:', re.I)
LOG_MAC_RE = re.compile(r'\bMAC\s+(' + MAC_RE.pattern + r')\b', re.I)
LOG_IP_RE = re.compile(r'\bIP\s+(\S+)', re.I)
LOG_VTEP_RE = re.compile(r'\b(?:last|from)\s+VTEP\s+(\S+)', re.I)

# Severity thresholds
ACTIVE_WINDOW_SEC = 3600       # compatibility cap; per-host DAD window is preferred
APIPA_CRITICAL = 50            # APIPA neighbours on one switch >= this = critical
SEQ_WARN = 10                  # EVPN mobility seq >= this = the entry has moved at all (collection floor)
# A single-MAC, single-location, non-climbing entry is only treated as a (past) duplicate if its
# sequence is this high -- real duplicate storms reach 100k+, whereas normal EVPN-MH failover churn
# stays in the hundreds. This keeps genuine settled duplicates while dropping MH mobility noise.
SEQ_STORM = 10000
LOOP_MIN_MACS = 10             # >= this many MACs flapping between the SAME endpoint pair (no dup IP) = likely L2 loop
STALE_AGE_SEC = 7 * 86400      # a quiesced dup whose EVPN sequence has not moved for this long = aged/stale
                               # (collapsed out of the main list; still available via the "aged" toggle)
DEFAULT_DAD_MOVES = 5
DEFAULT_DAD_WINDOW_SEC = 180
SEQ_SAMPLE_TTL_SEC = 6 * 3600
EVIDENCE_TTL_SEC = 6 * 3600
LOG_EVIDENCE_TTL_SEC = 3600
FUTURE_CLOCK_SKEW_SEC = 300
STATE_VERSION = 2
DUP_COVERAGE_SOURCES = {
    "COLLECTION_TIMESTAMP", "VNI_MAP", "CONFIG", "SELF", "ARP_DUPLICATES",
    "MAC_DUPLICATES", "FRR_LOG", "MAC_MOBILITY", "ARP_MOBILITY", "IFALIAS",
}
DUP_SAMPLE_META_SOURCES = {
    "CONFIG", "SELF", "FRR_LOG", "MAC_MOBILITY", "ARP_MOBILITY",
}


def _parse_ts(s):
    """Parse supported FRR timestamps into an aware UTC datetime, or ``None``.

    Current Cumulus releases can log RFC3339 while older/default FRR file logs
    use ``YYYY/MM/DD HH:MM:SS.ffffff``.  The latter has no offset; FRR systems
    normally log it in UTC, so it is treated as UTC instead of producing a
    naive datetime that cannot safely be compared with collection time.
    """
    try:
        value = datetime.fromisoformat(s.replace("Z", "+00:00"))
        if value.tzinfo is None:
            value = value.replace(tzinfo=timezone.utc)
        return value.astimezone(timezone.utc)
    except Exception:
        pass
    for fmt in ('%Y/%m/%d %H:%M:%S.%f', '%Y/%m/%d %H:%M:%S'):
        try:
            return datetime.strptime(s, fmt).replace(tzinfo=timezone.utc)
        except Exception:
            continue
    return None


class DuplicateAnalyzer:
    def __init__(self, data_dir="monitor-results"):
        self.data_dir = os.path.abspath(data_dir)
        self.dup_dir = os.path.join(self.data_dir, "dup-data")
        self.state_file = os.path.join(self.dup_dir, "dup_seq_state.json")
        os.makedirs(self.dup_dir, exist_ok=True)

        self.analysis_epoch = time.time()
        self.analysis_now = datetime.fromtimestamp(
            self.analysis_epoch, timezone.utc
        )
        self.collection_times = {}
        self.collection_meta = {}

        # VLAN is local to a VTEP.  VNI is the fabric-wide broadcast-domain
        # identity, so never use one global VLAN map as an incident key.
        self.vni_to_vlan = {}          # compatibility: only unambiguous VNI -> VLAN
        self.host_vni_to_vlan = {}     # (host, vni) -> vlan
        self.host_vlan_to_vnis = {}    # (host, vlan) -> set(vni)
        self.host_vni_to_vrf = {}      # (host, vni) -> tenant VRF
        self.vni_vlans = {}            # vni -> set(local VLANs)
        self.vni_vrfs = {}             # vni -> set(tenant VRFs)
        self.dup_config = {}           # host -> {'enabled': bool, 'max_moves': int, 'time': int}
        self.ip_dups = {}              # (scope, ip) -> record; scope is vni:<id>/vlan:<id>
        self.mac_dups = {}             # (scope, mac) -> record
        self.apipa = {}                # host -> {'total': int, 'per_vlan': {vlan: count}}
        self.apipa_claims = {}         # (scope, ip, mac) -> unique claim + observations
        self.fdb_local = {}            # (scope, mac) -> {host -> set(ports)}
        self.if_desc = {}              # (host, port) -> interface description (ifalias)
        self.arp_pairs = {}            # (scope, ip) -> {mac -> observation records}
        self.mac_mob = {}              # (scope, mac) -> aggregated per-observer mobility
        self.ip_mob = {}               # (scope, ip)  -> aggregated per-observer mobility
        self.log_events = {}           # (vni, ip) -> {'count': int, 'latest': dt, 'macs': set, 'vteps': set}
        self.log_events_mac = {}       # (vni, mac) -> {'count': int, 'latest': dt, 'vteps': set, 'ips': set}  (last VTEP = contender)
        self.log_signatures = set()
        self.self_vteps = {}           # host -> set(local VTEP ip)   ; used to resolve a VTEP IP -> switch name
        self.vtep2host = {}            # vtep ip -> host
        self.sequence_baseline_warmup = False
        self.sequence_baseline_warmup_hosts = set()
        self.collection_time_stale_hosts = set()
        self.prev_state = self._load_state()
        self.new_state = {
            "version": STATE_VERSION,
            "updated_at": self.analysis_epoch,
            "coverage_hosts": [],
            "samples": {},
        }
        # Cross-cycle evidence is timestamped per MAC/port. Historical evidence
        # may be displayed, but is never promoted back to current simply because
        # its parent incident is still present.
        self.ip_state_file = os.path.join(self.dup_dir, "dup_ip_state.json")
        self.prev_ip_state = self._load_ip_state()
        self.new_ip_state = {
            "version": STATE_VERSION,
            "updated_at": self.analysis_epoch,
            "evidence": {},
        }
        assets_file = os.path.join(os.path.dirname(self.data_dir), "assets.ini")
        self.asset_snapshot = read_asset_snapshot(assets_file)
        self.collection_errors = []
        self.current_hosts = set()
        self.expected_hosts = set()
        self.unavailable_hosts = {}
        self.coverage_partial = False
        self.collection_unavailable = False
        self.coverage_failures = {}

    # ------------------------------------------------------------------ state
    def _load_state(self):
        try:
            with open(self.state_file, encoding="utf-8") as f:
                raw = json.load(f)
        except Exception:
            raw = {}
        if isinstance(raw, dict) and raw.get("version") == STATE_VERSION \
                and isinstance(raw.get("samples"), dict):
            return raw

        self.sequence_baseline_warmup = True

        # Version 1 stored one aggregate sample as ``ip:vni|address``.  Keep
        # it only as a quiet-age hint; there is no observer identity, so using
        # it for a mobility delta would create false activity after a partial
        # collection or topology change.
        legacy = {}
        if isinstance(raw, dict):
            for key, value in raw.items():
                if not isinstance(key, str) or not isinstance(value, dict):
                    continue
                seq, changed = value.get("seq"), value.get("ts")
                if isinstance(seq, int) and isinstance(changed, (int, float)):
                    legacy[key] = {
                        "seq": seq,
                        "changed_at": float(changed),
                    }
        return {
            "version": STATE_VERSION,
            "updated_at": 0,
            "coverage_hosts": [],
            "samples": {},
            "legacy": legacy,
        }

    def _load_ip_state(self):
        try:
            with open(self.ip_state_file, encoding="utf-8") as f:
                raw = json.load(f)
        except Exception:
            raw = {}
        if isinstance(raw, dict) and raw.get("version") == STATE_VERSION \
                and isinstance(raw.get("evidence"), dict):
            return raw

        # Migrate the legacy ``vlan|ip -> {ports, macs, ts}`` shape.  These
        # entries remain historical and keep their original timestamp; a
        # current incident can consume them for context without refreshing
        # their lifetime.
        evidence = {}
        if isinstance(raw, dict):
            for key, value in raw.items():
                if not isinstance(key, str) or not isinstance(value, dict):
                    continue
                ts = value.get("ts")
                if not isinstance(ts, (int, float)):
                    continue
                macs = {
                    str(mac).lower(): float(ts)
                    for mac in (value.get("macs") or [])
                    if isinstance(mac, str) and MAC_RE.fullmatch(mac)
                }
                ports = {}
                for host, port in (value.get("ports") or {}).items():
                    if isinstance(host, str) and isinstance(port, str):
                        ports[f"{host}|{port}"] = float(ts)
                evidence[f"legacy:{key}"] = {
                    "scope": "legacy",
                    "address": key.split("|", 1)[-1],
                    "legacy_key": key,
                    "macs": macs,
                    "ports": ports,
                }
        return {
            "version": STATE_VERSION,
            "updated_at": 0,
            "evidence": evidence,
        }

    def _save_state(self):
        self._atomic_json_dump(self.state_file, self.new_state)
        self._atomic_json_dump(self.ip_state_file, self.new_ip_state)

    @staticmethod
    def _atomic_json_dump(path, value):
        temp_path = None
        try:
            with tempfile.NamedTemporaryFile(
                mode="w",
                encoding="utf-8",
                dir=os.path.dirname(path),
                prefix=".duplicate-state.",
                delete=False,
            ) as fh:
                temp_path = fh.name
                json.dump(value, fh)
                fh.flush()
                os.fsync(fh.fileno())
            os.replace(temp_path, path)
        except Exception:
            if temp_path:
                try:
                    os.unlink(temp_path)
                except OSError:
                    pass
            raise

    # ------------------------------------------------------------------ parse
    def _hosts(self):
        candidates = {}
        if not os.path.isdir(self.dup_dir):
            return candidates
        statuses, _asset_mtime, assets_available = self.asset_snapshot
        snapshot_valid = asset_snapshot_is_valid(self.asset_snapshot)
        assets_authoritative = asset_snapshot_is_authoritative(self.asset_snapshot)
        if assets_available and not snapshot_valid:
            self.collection_errors.append("asset snapshot is invalid or incomplete")
            return candidates
        if snapshot_valid:
            self.expected_hosts = {canonical(host) for host in statuses}
            self.unavailable_hosts = {
                canonical(host): status
                for host, status in statuses.items()
                if status != "OK"
            }
            self.coverage_partial = bool(self.unavailable_hosts)
            for host, status in sorted(self.unavailable_hosts.items()):
                self.coverage_failures.setdefault(host, []).append(
                    f"DEVICE_{status.replace('-', '_')}"
                )
        for fn in os.listdir(self.dup_dir):
            for suffix in ("_dup.txt", "_fdb.txt", "_neigh.txt"):
                if fn.endswith(suffix):
                    host = fn[: -len(suffix)]
                    path = os.path.join(self.dup_dir, fn)
                    if assets_authoritative and host not in statuses:
                        try:
                            os.unlink(path)
                        except OSError as exc:
                            self.collection_errors.append(
                                f"could not prune retired duplicate data {fn}: {exc}"
                            )
                        continue
                    if snapshot_valid and host not in statuses:
                        # Without a validated inventory we cannot prove that an
                        # unlisted artifact is retired. Preserve but ignore it.
                        continue
                    candidates.setdefault(host, {})[suffix] = path

        required = {"_dup.txt", "_fdb.txt", "_neigh.txt"}
        current = {}
        if snapshot_valid:
            expected_current_hosts = {
                host for host, status in statuses.items() if status == "OK"
            }
            for host in sorted(expected_current_hosts - set(candidates)):
                self.collection_errors.append(
                    f"{host}: missing duplicate collection bundle"
                )
        for host, files in candidates.items():
            # A non-OK inventory member is unavailable for this run, not a
            # parser error. Its old raw files remain LKG but are not consumed.
            if snapshot_valid and statuses.get(host) != "OK":
                continue
            missing = required.difference(files)
            if missing:
                self.collection_errors.append(
                    f"{host}: missing duplicate collection files {sorted(missing)}"
                )
                continue
            stale = [
                suffix for suffix, path in files.items()
                if not is_current_collection(path, host, self.asset_snapshot)
            ]
            if stale:
                self.collection_errors.append(
                    f"{host}: non-current duplicate collection files {sorted(stale)}"
                )
                continue
            current[host] = files
        return current

    def parse_all(self):
        hosts = self._hosts()
        if self.collection_errors:
            return False
        if not hosts:
            statuses, _asset_mtime, _assets_available = self.asset_snapshot
            expected_hosts = {
                host for host, status in statuses.items() if status == "OK"
            }
            if asset_snapshot_is_valid(self.asset_snapshot) and not expected_hosts:
                # No device produced a current bundle because the entire
                # inventory is unavailable. Preserve mobility baselines and
                # emit fresh state/report files without claiming a clean scan.
                self.new_state = copy.deepcopy(self.prev_state)
                self.new_state["version"] = STATE_VERSION
                self.new_state["updated_at"] = self.analysis_epoch
                self.new_state["coverage_hosts"] = []
                self.new_ip_state = copy.deepcopy(self.prev_ip_state)
                self.new_ip_state["version"] = STATE_VERSION
                self.new_ip_state["updated_at"] = self.analysis_epoch
                self._save_state()
                self.collection_unavailable = True
                return True
            return False
        self.current_hosts = {canonical(host) for host in hosts}
        previous_coverage = self.prev_state.get("coverage_hosts", [])
        if not isinstance(previous_coverage, (list, tuple, set)):
            previous_coverage = []
        previous_coverage_hosts = {
            canonical(host)
            for host in previous_coverage
            if isinstance(host, str)
        }
        if self.sequence_baseline_warmup:
            self.sequence_baseline_warmup_hosts = set(self.current_hosts)
        else:
            self.sequence_baseline_warmup_hosts = (
                self.current_hosts - previous_coverage_hosts
            )
            if self.sequence_baseline_warmup_hosts:
                self.sequence_baseline_warmup = True
        if self.sequence_baseline_warmup:
            self.coverage_partial = True
            self.coverage_failures.setdefault("analysis", []).append(
                "SEQUENCE_BASELINE_WARMUP"
            )
        self.new_state["coverage_hosts"] = sorted(self.current_hosts)
        contents = {}
        for host, files in hosts.items():
            try:
                observed_epoch = max(os.path.getmtime(path) for path in files.values())
            except OSError:
                observed_epoch = self.analysis_epoch
            self.collection_times[canonical(host)] = min(
                observed_epoch, self.analysis_epoch + FUTURE_CLOCK_SKEW_SEC
            )
            for suffix, path in files.items():
                try:
                    content = self._read(path)
                except OSError as exc:
                    self.collection_errors.append(f"{host}: could not read {suffix}: {exc}")
                    continue
                if "__LLDPQ_COLLECTION_ERROR__:" in content:
                    self.collection_errors.append(
                        f"{host}: device collection failed in {suffix}"
                    )
                    continue
                contents[(host, suffix)] = content
        if self.collection_errors:
            return False
        for host, files in hosts.items():
            ch = canonical(host)
            if "_dup.txt" in files:
                self._parse_dup(ch, contents[(host, "_dup.txt")])
            if "_fdb.txt" in files:
                self._parse_fdb(ch, contents[(host, "_fdb.txt")])
            if "_neigh.txt" in files:
                self._parse_neigh(ch, contents[(host, "_neigh.txt")])
        self._merge_arp_conflicts()
        self._finalize()
        return True

    @staticmethod
    def _read(path):
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            return f.read()

    def _split_sections(self, text):
        """Split a _dup.txt into the labelled sections."""
        sections = {}
        cur = None
        buf = []
        for line in text.splitlines():
            m = re.match(r'^===\s*DUP (VNI MAP|CONFIG|SELF|ARP|MAC|LOG|MACMOB|ARPMOB|IFALIAS)\s*===\s*$', line)
            if m:
                if cur is not None:
                    sections[cur] = buf
                cur = m.group(1)
                buf = []
            else:
                if cur is not None:
                    buf.append(line)
        if cur is not None:
            sections[cur] = buf
        return sections

    def _parse_dup(self, host, text):
        coverage_records = re.findall(
            r'^__LLDPQ_DUP_COVERAGE__:([A-Z0-9_]+):([A-Z]+)\s*$',
            text,
            re.MULTILINE,
        )
        for label, status in coverage_records:
            if status != "OK":
                suffix = "_TRUNCATED" if status == "TRUNCATED" else ""
                self.coverage_failures.setdefault(host, []).append(label + suffix)
        seen_coverage = {label for label, _status in coverage_records}
        if not DUP_COVERAGE_SOURCES.issubset(seen_coverage):
            self.coverage_failures.setdefault(host, []).append(
                "COVERAGE_MARKERS_MISSING"
            )
        self._parse_collection_meta(host, text)
        if not self.collection_meta.get(host, {}).get("collection_time_marker_seen"):
            self.coverage_failures.setdefault(host, []).append(
                "COLLECTION_TIMESTAMP_MARKER_MISSING"
            )
        sample_labels = set(
            self.collection_meta.get(host, {}).get("samples", {})
        )
        missing_sample_meta = sorted(DUP_SAMPLE_META_SOURCES - sample_labels)
        if missing_sample_meta:
            self.coverage_failures.setdefault(host, []).append(
                "SAMPLE_META_MISSING_" + "_".join(missing_sample_meta)
            )
        sec = self._split_sections(text)
        sample_sections = {
            "CONFIG": "CONFIG",
            "SELF": "SELF",
            "FRR_LOG": "LOG",
            "MAC_MOBILITY": "MACMOB",
            "ARP_MOBILITY": "ARPMOB",
        }
        samples = self.collection_meta.get(host, {}).get("samples", {})
        for label, section in sample_sections.items():
            sample = samples.get(label)
            if not sample or not str(sample.get("emitted", "")).isdigit():
                continue
            actual_emitted = sum(
                1 for line in sec.get(section, [])
                if line.strip() and not line.startswith("__LLDPQ_")
            )
            sample["actual_emitted"] = actual_emitted
            if int(sample["emitted"]) != actual_emitted:
                self.coverage_failures.setdefault(host, []).append(
                    f"{label}_EMITTED_COUNT_MISMATCH"
                )
        vni_count = self._parse_vni_map(host, sec.get("VNI MAP", []))
        self._parse_config(host, sec.get("CONFIG", []))
        self._parse_self(host, sec.get("SELF", []))
        arp_count = self._parse_arp_dup(host, sec.get("ARP", []))
        mac_count = self._parse_mac_dup(host, sec.get("MAC", []))
        log_count = self._parse_log(host, sec.get("LOG", []))
        mac_mob_count = self._parse_mac_mobility(host, sec.get("MACMOB", []))
        arp_mob_count = self._parse_ip_mobility(host, sec.get("ARPMOB", []))
        self._parse_ifalias(host, sec.get("IFALIAS", []))

        parser_counts = {
            "VNI_MAP": vni_count,
            "ARP_DUPLICATES": arp_count,
            "MAC_DUPLICATES": mac_count,
            "FRR_LOG": log_count,
            "MAC_MOBILITY": mac_mob_count,
            "ARP_MOBILITY": arp_mob_count,
        }
        self.collection_meta.setdefault(host, {}).setdefault(
            "parsed", {}
        ).update(parser_counts)
        config_lines = [
            line for line in sec.get("CONFIG", [])
            if line.strip() and not line.startswith("__LLDPQ_")
        ]
        if config_lines and host not in self.dup_config:
            self.coverage_failures.setdefault(host, []).append(
                "CONFIG_SCHEMA_UNPARSED"
            )
        schema_checks = {
            "ARP": ("ARP_DUPLICATES", arp_count,
                    lambda line: bool(re.match(r'\s*(?:\d{1,3}\.){3}\d{1,3}\b', line))),
            "MAC": ("MAC_DUPLICATES", mac_count,
                    lambda line: bool(MAC_RE.match(line.strip()))),
            "LOG": ("FRR_LOG", log_count,
                    lambda line: "detected as duplicate" in line.lower()),
        }
        for section, (label, parsed_count, predicate) in schema_checks.items():
            if not parsed_count and any(predicate(line) for line in sec.get(section, [])):
                self.coverage_failures.setdefault(host, []).append(
                    f"{label}_SCHEMA_UNPARSED"
                )
        section_names = {
            "MACMOB": "MAC_MOBILITY",
            "ARPMOB": "ARP_MOBILITY",
        }
        for section, label in section_names.items():
            data_lines = [
                line for line in sec.get(section, [])
                if line.strip()
                and not line.startswith("__LLDPQ_")
            ]
            # monitor.sh historically capped filtered output with head -800.
            # Until the producer emits an explicit marker, an exact/full cap is
            # conservatively reported as possible truncation.
            if label not in sample_labels and len(data_lines) >= 800:
                self.coverage_failures.setdefault(host, []).append(
                    f"{label}_POSSIBLY_TRUNCATED"
                )
            candidates = sum(
                1 for line in data_lines
                if SEQ_RE.search(line) and (MAC_RE.search(line) or IPV4_RE.search(line))
            )
            if candidates and not parser_counts[label]:
                self.coverage_failures.setdefault(host, []).append(
                    f"{label}_SCHEMA_UNPARSED"
                )

    def _parse_collection_meta(self, host, text):
        meta = self.collection_meta.setdefault(host, {})
        for line in text.splitlines():
            value = None
            if line.startswith("__LLDPQ_DUP_COLLECTION_UTC__:"):
                value = line.split(":", 1)[1].strip()
            elif line.startswith("__LLDPQ_COLLECTION_TIME__:"):
                value = line.split(":", 1)[1].strip()
            else:
                match = re.match(
                    r'^__LLDPQ_DUP_META__:COLLECTION_TIME:(.+)$', line
                )
                if match:
                    value = match.group(1).strip()
            if value:
                meta["collection_time_marker_seen"] = True
                parsed = _parse_ts(value)
                if parsed is None:
                    try:
                        epoch = float(value)
                    except ValueError:
                        self.coverage_failures.setdefault(host, []).append(
                            "COLLECTION_TIME_INVALID"
                        )
                        continue
                else:
                    epoch = parsed.timestamp()
                if epoch > self.analysis_epoch + FUTURE_CLOCK_SKEW_SEC:
                    self.coverage_failures.setdefault(host, []).append(
                        "COLLECTION_CLOCK_FUTURE"
                    )
                    continue
                if self.analysis_epoch - epoch > max_data_age_seconds():
                    self.coverage_failures.setdefault(host, []).append(
                        "COLLECTION_TIME_STALE"
                    )
                    self.collection_time_stale_hosts.add(host)
                    self.collection_times.pop(host, None)
                    meta["stale_collection_time"] = epoch
                    continue
                self.collection_times[host] = epoch
                meta["collection_time"] = epoch

            sample = re.match(
                r'^__LLDPQ_DUP_SAMPLE_META__:([A-Z0-9_]+):'
                r'MATCHES=([^:]+):EMITTED=([^:]+):CAP=([^:]+):'
                r'TRUNCATED=([^:]+)$',
                line,
            )
            if sample:
                label, matches, emitted, cap, truncated_value = sample.groups()
                parsed_meta = {
                    "matches": matches,
                    "emitted": emitted,
                    "cap": cap,
                    "truncated": truncated_value,
                }
                meta.setdefault("samples", {})[label] = parsed_meta
                if truncated_value == "YES":
                    self.coverage_failures.setdefault(host, []).append(
                        f"{label}_TRUNCATED"
                    )
                elif truncated_value != "NO":
                    self.coverage_failures.setdefault(host, []).append(
                        f"{label}_TRUNCATION_UNKNOWN"
                    )
                if matches.isdigit() and emitted.isdigit() and cap.isdigit():
                    match_count, emitted_count, cap_count = map(
                        int, (matches, emitted, cap)
                    )
                    metadata_valid = (
                        cap_count > 0
                        and emitted_count <= match_count
                        and emitted_count <= cap_count
                        and (
                            (truncated_value == "YES" and match_count > cap_count
                             and emitted_count == cap_count)
                            or (truncated_value == "NO" and match_count == emitted_count
                                and match_count <= cap_count)
                            or truncated_value not in {"YES", "NO"}
                        )
                    )
                    if not metadata_valid:
                        self.coverage_failures.setdefault(host, []).append(
                            f"{label}_SAMPLE_META_INVALID"
                        )
                elif not (matches == "UNKNOWN" and emitted.isdigit() and cap.isdigit()):
                    self.coverage_failures.setdefault(host, []).append(
                        f"{label}_SAMPLE_META_INVALID"
                    )

            truncated = re.match(
                r'^__LLDPQ_DUP_(?:META__:)?TRUNCATED__:?'
                r'([A-Z0-9_]+)(?::(.*))?$', line
            )
            if not truncated:
                truncated = re.match(
                    r'^__LLDPQ_DUP_META__:([A-Z0-9_]+):TRUNCATED(?::(.*))?$',
                    line,
                )
            if truncated:
                label = truncated.group(1)
                self.coverage_failures.setdefault(host, []).append(
                    f"{label}_TRUNCATED"
                )
                meta.setdefault("truncated", {})[label] = (
                    truncated.group(2) or "true"
                )

    def _parse_vni_map(self, host, lines):
        parsed = 0
        detail_vni = None
        for line in lines:
            detail = re.match(r'\s*VNI:\s*(\d+)\s*$', line, re.I)
            if detail:
                detail_vni = detail.group(1)
                continue
            detail_vlan = re.match(r'\s*Vlan:\s*(\d+)\s*$', line, re.I)
            if detail_vlan and detail_vni:
                self._record_vni_mapping(
                    host, detail_vni, detail_vlan.group(1), None
                )
                parsed += 1
                continue
            p = line.split()
            if len(p) < 2 or not p[0].isdigit() or p[1].upper() not in ("L2", "L3"):
                continue
            # Cumulus variants that expose Tenant VLAN place it at the end.
            # Do not invent VLAN=VNI when that optional column is absent.
            vlan = p[-1] if len(p) >= 8 and p[-1].isdigit() else None
            vrf = p[-2] if vlan and len(p) >= 3 and not p[-2].isdigit() else None
            self._record_vni_mapping(host, p[0], vlan, vrf)
            parsed += 1
        has_candidate = any(
            re.match(r'\s*(?:VNI:\s*)?\d+', line)
            for line in lines if not line.startswith("__LLDPQ_")
        )
        if has_candidate and not parsed:
            self.coverage_failures.setdefault(host, []).append(
                "VNI_MAP_SCHEMA_UNPARSED"
            )
        return parsed

    def _record_vni_mapping(self, host, vni, vlan, vrf):
        vni = str(vni)
        if vlan:
            vlan = str(vlan)
            previous = self.host_vni_to_vlan.get((host, vni))
            if previous is not None and previous != vlan:
                self.coverage_failures.setdefault(host, []).append(
                    f"VNI_{vni}_VLAN_MAPPING_CONFLICT"
                )
            self.host_vni_to_vlan[(host, vni)] = vlan
            self.host_vlan_to_vnis.setdefault((host, vlan), set()).add(vni)
            self.vni_vlans.setdefault(vni, set()).add(vlan)
            if len(self.vni_vlans[vni]) == 1:
                self.vni_to_vlan[vni] = vlan
            else:
                self.vni_to_vlan.pop(vni, None)
        if vrf and vrf.lower() not in ("n/a", "none", "default"):
            self.host_vni_to_vrf[(host, vni)] = vrf
            self.vni_vrfs.setdefault(vni, set()).add(vrf)
            if len(self.vni_vrfs[vni]) > 1:
                self.coverage_failures.setdefault(host, []).append(
                    f"VNI_{vni}_VRF_MAPPING_CONFLICT"
                )

    @staticmethod
    def _scope(vni=None, vlan=None):
        if vni and str(vni).isdigit():
            return f"vni:{vni}"
        if vlan and str(vlan).isdigit():
            return f"vlan:{vlan}"
        return "unknown"

    @staticmethod
    def _scope_vni(scope):
        return scope.split(":", 1)[1] if scope.startswith("vni:") else "unknown"

    @staticmethod
    def _scope_vlan(scope):
        return scope.split(":", 1)[1] if scope.startswith("vlan:") else "unknown"

    def _scope_for_vlan(self, host, vlan):
        vnis = self.host_vlan_to_vnis.get((host, str(vlan)), set())
        if len(vnis) == 1:
            vni = next(iter(vnis))
            return self._scope(vni=vni), vni
        return self._scope(vlan=vlan), "unknown"

    def _vlan_of(self, vni, host=None):
        if host is not None:
            return self.host_vni_to_vlan.get((host, str(vni)), "unknown")
        vlans = self.vni_vlans.get(str(vni), set())
        return next(iter(vlans)) if len(vlans) == 1 else "unknown"

    def _vrf_of(self, vni, host=None):
        if host is not None:
            return self.host_vni_to_vrf.get((host, str(vni)))
        vrfs = self.vni_vrfs.get(str(vni), set())
        return next(iter(vrfs)) if len(vrfs) == 1 else None

    def _parse_config(self, host, lines):
        enabled, max_moves, t, freeze, warning_only = None, None, None, None, None
        for line in lines:
            low = line.lower()
            if "duplicate address detection" in low:
                enabled = "enable" in low
            m = re.search(r'max-moves\s+(\d+),?\s+time\s+(\d+)', line, re.I)
            if m:
                max_moves, t = int(m.group(1)), int(m.group(2))
            freeze_match = re.search(r'\bfreeze\s*:?\s+(\S+)', line, re.I)
            if freeze_match:
                freeze = freeze_match.group(1).rstrip(",")
            warning_match = re.search(
                r'\bwarning[- ]only\s*:?\s*(enabled?|disabled?|yes|no|true|false|on|off)',
                line,
                re.I,
            )
            if warning_match:
                warning_only = warning_match.group(1).lower() in {
                    "enable", "enabled", "yes", "true", "on",
                }
        if (enabled is not None or max_moves is not None or freeze is not None
                or warning_only is not None):
            self.dup_config[host] = {
                "enabled": bool(enabled) if enabled is not None else None,
                "max_moves": max_moves,
                "time": t,
                "freeze": freeze,
                "warning_only": warning_only,
            }

    def _parse_self(self, host, lines):
        """This switch's own EVPN VTEP IP(s) -> lets us resolve a remote VTEP back to a switch name."""
        for line in lines:
            for ip in IPV4_RE.findall(line):
                self.self_vteps.setdefault(host, set()).add(ip)

    def _parse_ifalias(self, host, lines):
        """Interface descriptions ('nv set interface swpX description ...' = kernel ifalias),
        collected as 'port|description' lines. Lets each switch:port cell name the attached
        device -> which physical box is duplicating."""
        for line in lines:
            if "|" not in line:
                continue
            port, desc = line.split("|", 1)
            port, desc = port.strip(), desc.strip()
            if port and desc:
                self.if_desc[(host, port)] = desc

    def _parse_arp_dup(self, host, lines):
        vni = None
        parsed = 0
        for line in lines:
            m = re.match(r'\s*VNI\s+(\d+)\s+#ARP', line)
            if m:
                vni = m.group(1)
                continue
            if not vni or "Neighbor" in line or line.strip().startswith("Flags:") or not line.strip():
                continue
            parts = line.split()
            if len(parts) < 3:
                continue
            neighbor = parts[0]
            if not (IPV4_RE.fullmatch(neighbor) or ":" in neighbor):
                continue
            mac_m = MAC_RE.search(line)
            if not mac_m:
                continue
            mac = mac_m.group(0).lower()
            typ = "remote" if re.search(r'\bremote\b', line) else "local"
            ipv4s = [ip for ip in IPV4_RE.findall(line) if ip != neighbor]
            vtep = ipv4s[-1] if (typ == "remote" and ipv4s) else ""
            seq_m = SEQ_RE.search(line)
            seq = max(int(seq_m.group(1)), int(seq_m.group(2))) if seq_m else 0
            vlan = self._vlan_of(vni, host)
            scope = self._scope(vni=vni)
            rec = self.ip_dups.setdefault(
                (scope, neighbor), self._blank_ip(scope, vlan, vni, neighbor)
            )
            self._add_location_context(rec, host, vni, vlan)
            rec["macs"].add(mac)
            rec["seq"] = max(rec["seq"], seq)
            rec["seq_by_host"][host] = max(
                rec["seq_by_host"].get(host, 0), seq
            )
            rec["flagged"] = True
            rec["dad_flagged"] = True
            rec["flagged_hosts"].add(host)
            rec["evidence_sources"].add("frr_dad_ip")
            if typ == "local":
                rec["local_hosts"].add(host)
            if vtep:
                rec["vteps"].add(vtep)
            parsed += 1
        return parsed

    def _blank_ip(self, scope, vlan, vni, ip):
        vlan_value = str(vlan) if vlan and str(vlan) != "unknown" else "unknown"
        vni_value = str(vni) if vni and str(vni).isdigit() else "unknown"
        return {"scope": scope, "vlan": vlan_value, "vlans": set(),
                "vni": vni_value, "vrfs": set(), "ip": ip,
                "macs": set(), "log_macs": set(), "seq": 0, "seq_by_host": {},
                "flagged": False, "local_hosts": set(), "vteps": set(),
                "ports": set(), "apipa": False, "recency": None, "delta": None,
                "events": 0, "latest": None, "mobility": False,
                "flagged_hosts": set(), "dad_flagged": False,
                "dad_event": False, "confirmed_conflict": False,
                "suspected_conflict": False, "neighbor_conflict_strong": False,
                "mobility_only": False, "incident_type": "unknown",
                "activity": "settled", "seq_interval_sec": None,
                "seq_rate_per_min": None, "seq_activity_threshold": None,
                "sequence_active": False, "evidence_sources": set(),
                "historical_macs": set(), "historical_ports": set()}

    def _parse_mac_dup(self, host, lines):
        vni = None
        parsed = 0
        for line in lines:
            m = re.match(r'\s*VNI\s+(\d+)\s+#MAC', line)
            if m:
                vni = m.group(1)
                continue
            if not vni or "Intf/Remote" in line or line.strip().startswith("Flags:") or not line.strip():
                continue
            mac_m = MAC_RE.match(line.strip())
            if not mac_m:
                continue
            mac = mac_m.group(0).lower()
            typ = "remote" if re.search(r'\bremote\b', line) else "local"
            port = self._port_from_evpn_line(line) if typ == "local" else None
            vtep_m = IPV4_RE.search(line)
            seq_m = SEQ_RE.search(line)
            seq = max(int(seq_m.group(1)), int(seq_m.group(2))) if seq_m else 0
            vlan = self._vlan_of(vni, host)
            scope = self._scope(vni=vni)
            rec = self.mac_dups.setdefault(
                (scope, mac), self._blank_mac(scope, vlan, vni, mac)
            )
            self._add_location_context(rec, host, vni, vlan)
            rec["seq"] = max(rec["seq"], seq)
            rec["seq_by_host"][host] = max(
                rec["seq_by_host"].get(host, 0), seq
            )
            rec["flagged"] = True
            rec["dad_flagged"] = True
            rec["flagged_hosts"].add(host)
            rec["evidence_sources"].add("frr_dad_mac")
            if typ == "local" and port:
                rec["local_ports"].setdefault(host, set()).add(port)
            elif vtep_m:
                rec["vteps"].add(vtep_m.group(0))
            parsed += 1
        return parsed

    def _blank_mac(self, scope, vlan, vni, mac):
        vlan_value = str(vlan) if vlan and str(vlan) != "unknown" else "unknown"
        vni_value = str(vni) if vni and str(vni).isdigit() else "unknown"
        return {"scope": scope, "vlan": vlan_value, "vlans": set(),
                "vni": vni_value, "vrfs": set(), "mac": mac,
                "seq": 0, "seq_by_host": {},
                "flagged": False, "flagged_hosts": set(),
                "local": {}, "local_ports": {}, "vteps": set(),
                "delta": None, "fdb_multi": False, "mobility": False,
                "classification": "", "loop_count": 0,
                "dad_flagged": False, "dad_event": False,
                "confirmed_conflict": False, "mobility_only": False,
                "possible_loop": False, "mh_possible": False,
                "loop_correlation_id": "",
                "incident_type": "unknown", "activity": "settled",
                "seq_interval_sec": None, "seq_rate_per_min": None,
                "seq_activity_threshold": None, "sequence_active": False,
                "attachment_count": 0, "evidence_sources": set()}

    def _add_location_context(self, rec, host, vni, vlan):
        if vlan and str(vlan) != "unknown":
            rec["vlans"].add(str(vlan))
            rec["vlan"] = ", ".join(sorted(rec["vlans"], key=lambda x: int(x)))
        vrf = self._vrf_of(vni, host) if vni and str(vni).isdigit() else None
        if vrf:
            rec["vrfs"].add(vrf)

    @staticmethod
    def _port_from_evpn_line(line):
        parts = line.split()
        try:
            index = next(i for i, value in enumerate(parts) if value.lower() == "local")
        except StopIteration:
            return None
        ignored = {
            "active", "inactive", "local", "remote", "dynamic", "static",
            "i", "p", "x", "n", "b", "-",
        }
        for token in parts[index + 1:]:
            clean = token.strip(",")
            if clean.lower() in ignored or re.fullmatch(r'\d+(?:/\d+)?', clean):
                continue
            if MAC_RE.fullmatch(clean) or IPV4_RE.fullmatch(clean):
                continue
            if re.fullmatch(r'[A-Za-z][A-Za-z0-9_.:@/-]*', clean):
                return clean
        return None

    def _parse_log(self, host, lines):
        parsed = 0
        for line in lines:
            if "detected as duplicate" not in line.lower():
                continue
            ts_m, vni_m = LOG_TS_RE.search(line), LOG_VNI_RE.search(line)
            mac_m, ip_m, vtep_m = (
                LOG_MAC_RE.search(line), LOG_IP_RE.search(line), LOG_VTEP_RE.search(line)
            )
            if not vni_m or not mac_m:
                continue
            ts = _parse_ts(ts_m.group("ts")) if ts_m else None
            vni = vni_m.group(1)
            mac = mac_m.group(1).lower()
            ip = ip_m.group(1).rstrip(",.;") if ip_m else None
            vtep = vtep_m.group(1).rstrip(",.;") if vtep_m else ""
            signature = (
                ts.isoformat() if ts else "", vni, mac, ip or "", vtep
            )
            if signature in self.log_signatures:
                continue
            self.log_signatures.add(signature)
            evm = self.log_events_mac.setdefault(
                (vni, mac), {"count": 0, "latest": None, "vteps": set(),
                             "ips": set(), "hosts": set()}
            )
            evm["count"] += 1
            evm["hosts"].add(host)
            if vtep:
                evm["vteps"].add(vtep)
            if ip:
                evm["ips"].add(ip)
                ev = self.log_events.setdefault(
                    (vni, ip), {"count": 0, "latest": None, "macs": set(),
                                "vteps": set(), "hosts": set()}
                )
                ev["count"] += 1
                ev["hosts"].add(host)
                ev["macs"].add(mac)
                if vtep:
                    ev["vteps"].add(vtep)
            if ts:
                events = [evm]
                if ip:
                    events.append(ev)
                for event in events:
                    if event["latest"] is None or ts > event["latest"]:
                        event["latest"] = ts
            parsed += 1
        return parsed

    def _parse_mac_mobility(self, host, lines):
        """Parse non-zero-seq lines from 'show evpn mac vni all' (works even with DAD off)."""
        vni = None
        parsed = 0
        for line in lines:
            m = re.match(r'\s*VNI\s+(\d+)\b', line)
            if m:
                vni = m.group(1)
                continue
            if not vni:
                continue
            mac_m = MAC_RE.match(line.strip())
            seq_m = SEQ_RE.search(line)
            if not mac_m or not seq_m:
                continue
            seq = max(int(seq_m.group(1)), int(seq_m.group(2)))
            if seq < SEQ_WARN:
                continue
            mac = mac_m.group(0).lower()
            vlan = self._vlan_of(vni, host)
            scope = self._scope(vni=vni)
            rec = self.mac_mob.setdefault(
                (scope, mac), {"scope": scope, "seq": 0, "seq_by_host": {},
                               "hosts": set(), "vteps": set(), "ports": {},
                               "vni": str(vni), "vlans": set(), "vrfs": set()}
            )
            rec["seq"] = max(rec["seq"], seq)
            rec["seq_by_host"][host] = max(rec["seq_by_host"].get(host, 0), seq)
            rec["hosts"].add(host)
            if vlan != "unknown":
                rec["vlans"].add(vlan)
            vrf = self._vrf_of(vni, host)
            if vrf:
                rec["vrfs"].add(vrf)
            port = self._port_from_evpn_line(line)
            vtep_m = IPV4_RE.search(line)
            if port and re.search(r'\blocal\b', line):
                rec["ports"].setdefault(host, set()).add(port)
            elif vtep_m:
                rec["vteps"].add(vtep_m.group(0))
            parsed += 1
        return parsed

    def _parse_ip_mobility(self, host, lines):
        """Parse non-zero-seq lines from 'show evpn arp-cache vni all' (works even with DAD off)."""
        vni = None
        parsed = 0
        for line in lines:
            m = re.match(r'\s*VNI\s+(\d+)\b', line)
            if m:
                vni = m.group(1)
                continue
            if not vni or "Neighbor" in line or line.strip().startswith("Flags:") or not line.strip():
                continue
            parts = line.split()
            neighbor = parts[0]
            if neighbor.lower().startswith("fe80"):   # link-local: not a meaningful duplicate IP
                continue
            if not (IPV4_RE.fullmatch(neighbor) or ":" in neighbor):
                continue
            seq_m = SEQ_RE.search(line)
            mac_m = MAC_RE.search(line)
            if not seq_m or not mac_m:
                continue
            seq = max(int(seq_m.group(1)), int(seq_m.group(2)))
            if seq < SEQ_WARN:
                continue
            vlan = self._vlan_of(vni, host)
            scope = self._scope(vni=vni)
            rec = self.ip_mob.setdefault(
                (scope, neighbor), {"scope": scope, "seq": 0,
                                    "seq_by_host": {}, "macs": set(),
                                    "vteps": set(), "vni": str(vni),
                                    "vlans": set(), "vrfs": set()}
            )
            rec["seq"] = max(rec["seq"], seq)
            rec["seq_by_host"][host] = max(rec["seq_by_host"].get(host, 0), seq)
            rec["macs"].add(mac_m.group(0).lower())
            if vlan != "unknown":
                rec["vlans"].add(vlan)
            vrf = self._vrf_of(vni, host)
            if vrf:
                rec["vrfs"].add(vrf)
            for ip in IPV4_RE.findall(line):
                if ip != neighbor:
                    rec["vteps"].add(ip)
            parsed += 1
        return parsed

    def _parse_fdb(self, host, text):
        for line in text.splitlines():
            if "permanent" in line or "self" in line:
                continue
            mac_m = MAC_RE.match(line.strip())
            if not mac_m:
                continue
            mac = mac_m.group(0).lower()
            dev_m = re.search(r'\bdev\s+(\S+)', line)
            vlan_m = re.search(r'\bvlan\s+(\d+)', line)
            if not dev_m or not vlan_m:
                continue
            dev = dev_m.group(1)
            vlan = vlan_m.group(1)
            is_remote = ("extern_learn" in line) or dev.startswith("vxlan")
            if is_remote or dev.startswith(("bridge", "br_", "vlan", "vrf", "lo")):
                continue
            scope, _vni = self._scope_for_vlan(host, vlan)
            self.fdb_local.setdefault((scope, mac), {}).setdefault(host, set()).add(dev)

    @staticmethod
    def _vlan_from_interface(dev):
        for pattern in (r'(?i)^vlan(\d+)(?:[_-].*)?$', r'^.+\.(\d+)$'):
            match = re.match(pattern, dev)
            if match:
                return match.group(1)
        return None

    def _parse_neigh(self, host, text):
        ap = self.apipa.setdefault(host, {"total": 0, "per_vlan": {}})
        for line in text.splitlines():
            parts = line.split()
            if len(parts) < 3:
                continue
            ip = parts[0]
            if not IPV4_RE.fullmatch(ip):
                continue
            dev_m = re.search(r'\bdev\s+(\S+)', line)
            mac_m = re.search(r'\blladdr\s+(' + MAC_RE.pattern + r')', line)
            dev = dev_m.group(1) if dev_m else ""
            vlan = self._vlan_from_interface(dev)
            state_match = re.search(
                r'\b(INCOMPLETE|REACHABLE|STALE|DELAY|PROBE|FAILED|NOARP|PERMANENT)\b',
                line, re.I,
            )
            state = state_match.group(1).upper() if state_match else "UNKNOWN"
            extern = bool(re.search(r'\bextern_(?:learn|valid)\b', line))
            mac = mac_m.group(1).lower() if mac_m else "unknown"
            if vlan:
                scope, vni = self._scope_for_vlan(host, vlan)
            else:
                scope, vni = f"interface:{host}:{dev or 'unknown'}", "unknown"
            if ip.startswith("169.254."):
                ap["total"] += 1
                if vlan:
                    ap["per_vlan"][vlan] = ap["per_vlan"].get(vlan, 0) + 1
                key = (scope, ip, mac)
                claim = self.apipa_claims.setdefault(
                    key, {"scope": scope, "vni": vni, "ip": ip, "mac": mac,
                          "vlans": set(), "vrfs": set(), "observers": set(),
                          "interfaces": set(), "states": set(), "observations": set(),
                          "local_observations": 0, "extern_observations": 0,
                          "non_vlan_observations": 0, "observation_count": 0}
                )
                observation = (host, dev, state, extern)
                if observation not in claim["observations"]:
                    claim["observations"].add(observation)
                    claim["observation_count"] += 1
                    if extern:
                        claim["extern_observations"] += 1
                    else:
                        claim["local_observations"] += 1
                    if not vlan:
                        claim["non_vlan_observations"] += 1
                claim["observers"].add(host)
                claim["interfaces"].add((host, dev))
                claim["states"].add(state)
                if vlan:
                    claim["vlans"].add(vlan)
                vrf = self._vrf_of(vni, host) if vni != "unknown" else None
                if vrf:
                    claim["vrfs"].add(vrf)
                continue
            if vlan and mac_m and state not in {"FAILED", "INCOMPLETE", "NOARP"}:
                self.arp_pairs.setdefault((scope, ip), {}).setdefault(mac, set()).add(
                    (host, vlan, state, extern)
                )

    def _merge_arp_conflicts(self):
        """Add IP duplicates seen via cross-device ARP (>=2 distinct MACs) that EVPN
        may not have flagged, so the page is complete even outside EVPN."""
        for (scope, ip), mac_observations in self.arp_pairs.items():
            if len(mac_observations) < 2:
                continue
            vni = self._scope_vni(scope)
            vlan = self._scope_vlan(scope)
            all_vlans = {
                observation[1]
                for observations in mac_observations.values()
                for observation in observations
                if observation[1]
            }
            if vlan == "unknown" and len(all_vlans) == 1:
                vlan = next(iter(all_vlans))
            rec = self.ip_dups.get((scope, ip))
            if rec is None:
                rec = self._blank_ip(scope, vlan, vni, ip)
                self.ip_dups[(scope, ip)] = rec
            rec["vlans"].update(all_vlans)
            if rec["vlans"]:
                rec["vlan"] = ", ".join(sorted(rec["vlans"], key=lambda x: int(x)))
            if vni != "unknown":
                for observations in mac_observations.values():
                    for observation in observations:
                        vrf = self._vrf_of(vni, observation[0])
                        if vrf:
                            rec["vrfs"].add(vrf)
            for mac, observations in mac_observations.items():
                rec["macs"].add(mac)
            active_states = {"REACHABLE", "PERMANENT", "DELAY", "PROBE"}
            strong_macs = sum(
                1 for observations in mac_observations.values()
                if any(observation[2] in active_states for observation in observations)
            )
            rec["neighbor_conflict_strong"] = strong_macs >= 2
            rec["suspected_conflict"] = not rec["neighbor_conflict_strong"]
            rec["evidence_sources"].add("neighbor_multi_mac")

    # --------------------------------------------------------------- finalize
    def _recency(self, latest):
        if not latest:
            return None
        try:
            if latest.tzinfo is None:
                latest = latest.replace(tzinfo=timezone.utc)
            seconds = (self.analysis_now - latest.astimezone(timezone.utc)).total_seconds()
        except Exception:
            return None
        # A slightly future timestamp is normal clock skew. A timestamp farther
        # in the future is not evidence of a current incident and must not turn
        # into a permanent CRITICAL row.
        if seconds < -FUTURE_CLOCK_SKEW_SEC:
            return None
        return max(0.0, seconds)

    @staticmethod
    def _sample_key(kind, scope, address, host):
        return json.dumps([kind, scope, address, host], separators=(",", ":"))

    def _dad_policy(self, host):
        config = self.dup_config.get(host, {})
        moves = config.get("max_moves")
        window = config.get("time")
        if not isinstance(moves, int) or moves < 2:
            moves = DEFAULT_DAD_MOVES
        if not isinstance(window, int) or window < 2:
            window = DEFAULT_DAD_WINDOW_SEC
        return moves, window

    def _apply_sequence_sample(self, rec, kind, address):
        """Compare each observer only with itself, exactly once per cycle."""
        seq_by_host = dict(rec.get("seq_by_host") or {})
        if not seq_by_host and rec.get("seq", 0):
            seq_by_host["aggregate"] = rec["seq"]

        prev_samples = self.prev_state.get("samples", {})
        legacy = self.prev_state.get("legacy", {})
        deltas = []
        meaningful = []
        changed_times = []
        per_host = {}
        for host, seq in sorted(seq_by_host.items()):
            if not isinstance(seq, int) or seq < 0:
                continue
            if host in self.collection_time_stale_hosts:
                moves, window = self._dad_policy(host)
                per_host[host] = {
                    "delta": None,
                    "interval_sec": None,
                    "rate_per_min": None,
                    "threshold_moves": moves,
                    "window_sec": window,
                    "meaningful": False,
                    "collection_time_stale": True,
                }
                continue
            observed_at = self.collection_times.get(host, self.analysis_epoch)
            observed_at = min(observed_at, self.analysis_epoch + FUTURE_CLOCK_SKEW_SEC)
            key = self._sample_key(kind, rec["scope"], address, host)
            previous = (
                {} if host in self.sequence_baseline_warmup_hosts
                else prev_samples.get(key, {})
            )
            if not isinstance(previous, dict):
                previous = {}
            prev_seq = previous.get("seq")
            prev_observed = previous.get("observed_at")
            interval = None
            delta = None
            changed_at = observed_at
            if isinstance(prev_seq, int) and isinstance(prev_observed, (int, float)):
                interval = observed_at - float(prev_observed)
                if 0 < interval <= SEQ_SAMPLE_TTL_SEC and seq >= prev_seq:
                    delta = seq - prev_seq
                if seq == prev_seq and isinstance(previous.get("changed_at"), (int, float)):
                    changed_at = float(previous["changed_at"])
            elif rec.get("vni") != "unknown":
                old = legacy.get(f"{kind}:{rec['vni']}|{address}", {})
                if old.get("seq") == seq and isinstance(old.get("changed_at"), (int, float)):
                    changed_at = float(old["changed_at"])

            moves, window = self._dad_policy(host)
            rate = None
            is_meaningful = False
            if delta is not None and interval and interval > 0:
                rate = delta * 60.0 / interval
                equivalent_window_moves = delta * window / interval
                is_meaningful = (
                    (interval <= window and delta >= moves)
                    or (interval > window and equivalent_window_moves >= moves)
                )
                deltas.append((delta, interval, rate, moves, host))
                if is_meaningful:
                    meaningful.append(host)
            changed_times.append(changed_at)
            per_host[host] = {
                "delta": delta,
                "interval_sec": interval,
                "rate_per_min": rate,
                "threshold_moves": moves,
                "window_sec": window,
                "meaningful": is_meaningful,
            }
            self.new_state["samples"][key] = {
                "seq": seq,
                "observed_at": observed_at,
                "changed_at": changed_at,
            }

        if deltas:
            active_deltas = [item for item in deltas if item[4] in meaningful]
            best = max(active_deltas or deltas, key=lambda item: item[2])
            rec["delta"], rec["seq_interval_sec"], rec["seq_rate_per_min"] = best[:3]
            rec["seq_activity_threshold"] = best[3]
        else:
            rec["delta"] = None
            rec["seq_interval_sec"] = None
            rec["seq_rate_per_min"] = None
            rec["seq_activity_threshold"] = None
        rec["sequence_active"] = bool(meaningful)
        rec["seq_observers"] = per_host
        rec["quiet_age"] = (
            max(0.0, self.analysis_epoch - max(changed_times))
            if changed_times else None
        )

    def _carry_sequence_state(self):
        cutoff = self.analysis_epoch - SEQ_SAMPLE_TTL_SEC
        for key, value in self.prev_state.get("samples", {}).items():
            if key in self.new_state["samples"] or not isinstance(value, dict):
                continue
            if value.get("observed_at", 0) >= cutoff:
                self.new_state["samples"][key] = value

    def _event_window(self, rec):
        hosts = set(rec.get("flagged_hosts", set())) | set(rec.get("seq_by_host", {}))
        windows = [self._dad_policy(host)[1] for host in hosts]
        return max(windows or [DEFAULT_DAD_WINDOW_SEC])

    def _event_is_active(self, rec):
        return (
            rec.get("recency") is not None
            and rec["recency"] <= self._event_window(rec)
        )

    def _merge_mobility_records(self):
        for (scope, ip), mob in self.ip_mob.items():
            vlan = next(iter(mob["vlans"])) if len(mob["vlans"]) == 1 else "unknown"
            rec = self.ip_dups.setdefault(
                (scope, ip), self._blank_ip(scope, vlan, mob["vni"], ip)
            )
            rec["mobility"] = True
            rec["evidence_sources"].add("evpn_ip_mobility")
            rec["macs"].update(mob["macs"])
            rec["vteps"].update(mob["vteps"])
            rec["vlans"].update(mob["vlans"])
            rec["vrfs"].update(mob["vrfs"])
            rec["seq"] = max(rec["seq"], mob["seq"])
            for host, seq in mob["seq_by_host"].items():
                rec["seq_by_host"][host] = max(rec["seq_by_host"].get(host, 0), seq)
            if rec["vlans"]:
                rec["vlan"] = ", ".join(sorted(rec["vlans"], key=lambda x: int(x)))

        for (scope, mac), mob in self.mac_mob.items():
            vlan = next(iter(mob["vlans"])) if len(mob["vlans"]) == 1 else "unknown"
            rec = self.mac_dups.setdefault(
                (scope, mac), self._blank_mac(scope, vlan, mob["vni"], mac)
            )
            rec["mobility"] = True
            rec["evidence_sources"].add("evpn_mac_mobility")
            rec["vteps"].update(mob["vteps"])
            rec["vlans"].update(mob["vlans"])
            rec["vrfs"].update(mob["vrfs"])
            rec["seq"] = max(rec["seq"], mob["seq"])
            for host, seq in mob["seq_by_host"].items():
                rec["seq_by_host"][host] = max(rec["seq_by_host"].get(host, 0), seq)
            for host, ports in mob.get("ports", {}).items():
                rec["local_ports"].setdefault(host, set()).update(ports)
            if rec["vlans"]:
                rec["vlan"] = ", ".join(sorted(rec["vlans"], key=lambda x: int(x)))

    def _merge_log_records(self):
        for (vni, ip), event in self.log_events.items():
            recency = self._recency(event.get("latest"))
            key = (self._scope(vni=vni), ip)
            rec = self.ip_dups.get(key)
            if rec is None and (recency is None or recency > LOG_EVIDENCE_TTL_SEC):
                continue
            if rec is None:
                vlan = self._vlan_of(vni)
                rec = self._blank_ip(key[0], vlan, vni, ip)
                self.ip_dups[key] = rec
            rec["events"] = event["count"]
            rec["latest"] = event.get("latest")
            rec["recency"] = recency
            if recency is not None and recency <= LOG_EVIDENCE_TTL_SEC:
                rec["dad_event"] = True
                rec["evidence_sources"].add("frr_dad_log")
                rec["macs"].update(event["macs"])
                rec["log_macs"].update(event["macs"])
                rec["vteps"].update(event["vteps"])
                rec["flagged_hosts"].update(event.get("hosts", set()))

        for (vni, mac), event in self.log_events_mac.items():
            recency = self._recency(event.get("latest"))
            key = (self._scope(vni=vni), mac)
            rec = self.mac_dups.get(key)
            if rec is None and (recency is None or recency > LOG_EVIDENCE_TTL_SEC):
                continue
            if rec is None:
                vlan = self._vlan_of(vni)
                rec = self._blank_mac(key[0], vlan, vni, mac)
                self.mac_dups[key] = rec
            rec["events"] = event["count"]
            rec["latest"] = event.get("latest")
            rec["recency"] = recency
            if recency is not None and recency <= LOG_EVIDENCE_TTL_SEC:
                rec["dad_event"] = True
                rec["evidence_sources"].add("frr_dad_log")
                rec["vteps"].update(event["vteps"])
                rec["flagged_hosts"].update(event.get("hosts", set()))

    @staticmethod
    def _port_is_mh_like(port):
        low = port.lower()
        return "bond" in low or "lag" in low or low.startswith("peerlink")

    def _merge_fdb_records(self):
        for (scope, mac), hosts in self.fdb_local.items():
            points = {(host, port) for host, ports in hosts.items() for port in ports}
            if len(points) < 2 and (scope, mac) not in self.mac_dups:
                continue
            vni, vlan = self._scope_vni(scope), self._scope_vlan(scope)
            rec = self.mac_dups.setdefault(
                (scope, mac), self._blank_mac(scope, vlan, vni, mac)
            )
            for host, ports in hosts.items():
                rec["local_ports"].setdefault(host, set()).update(ports)
            rec["attachment_count"] = len(
                {(host, port) for host, ports in rec["local_ports"].items() for port in ports}
            )
            non_mh_points = {
                (host, port) for host, ports in rec["local_ports"].items()
                for port in ports if not self._port_is_mh_like(port)
            }
            same_host_multi = any(len(ports) >= 2 for ports in rec["local_ports"].values())
            rec["fdb_multi"] = same_host_multi or len(non_mh_points) >= 2
            rec["mh_possible"] = rec["attachment_count"] >= 2 and not rec["fdb_multi"]
            if rec["fdb_multi"]:
                rec["evidence_sources"].add("fdb_multi_attachment")
            elif rec["mh_possible"]:
                rec["evidence_sources"].add("fdb_multi_mh_possible")

    @staticmethod
    def _sync_mac_local_projection(rec):
        rec["local"] = {
            host: ", ".join(sorted(ports))
            for host, ports in rec.get("local_ports", {}).items()
            if ports
        }

    @staticmethod
    def _loop_correlation_id(scope, endpoints):
        """Return a stable, human-readable identity for one loop signal group."""
        return "%s | %s" % (
            scope or "unknown",
            " <-> ".join(sorted(set(endpoints))) or "unknown endpoints",
        )

    def _resolve_ip_ports(self, rec):
        for mac in rec["macs"]:
            for host, ports in self.fdb_local.get((rec["scope"], mac), {}).items():
                rec["local_hosts"].add(host)
                for port in ports:
                    rec["ports"].add(f"{host}:{port}")

    def _apply_ip_evidence_memory(self, rec):
        key = f"{rec['scope']}|{rec['ip']}"
        previous = self.prev_ip_state.get("evidence", {}).get(key, {})
        if not isinstance(previous, dict):
            previous = {}
        if not previous:
            for vlan in rec.get("vlans", set()) | ({rec["vlan"]} if rec.get("vlan") != "unknown" else set()):
                candidate = self.prev_ip_state.get("evidence", {}).get(
                    f"legacy:{vlan}|{rec['ip']}"
                )
                if candidate:
                    previous = candidate
                    break
        cutoff = self.analysis_epoch - EVIDENCE_TTL_SEC
        current_macs = set(rec["macs"])
        current_ports = set(rec["ports"])
        macs = {mac: self.analysis_epoch for mac in current_macs}
        ports = {port.replace(":", "|", 1): self.analysis_epoch for port in current_ports}
        for mac, last_seen in (previous.get("macs") or {}).items():
            if not isinstance(last_seen, (int, float)) or last_seen < cutoff:
                continue
            if mac not in current_macs:
                rec["historical_macs"].add(mac)
                macs[mac] = float(last_seen)
        for encoded, last_seen in (previous.get("ports") or {}).items():
            if not isinstance(last_seen, (int, float)) or last_seen < cutoff:
                continue
            display = encoded.replace("|", ":", 1)
            if display not in current_ports:
                rec["historical_ports"].add(display)
                ports[encoded] = float(last_seen)
        self.new_ip_state["evidence"][key] = {
            "scope": rec["scope"], "address": rec["ip"],
            "macs": macs, "ports": ports,
        }

    def _carry_ip_evidence(self):
        cutoff = self.analysis_epoch - EVIDENCE_TTL_SEC
        for key, value in self.prev_ip_state.get("evidence", {}).items():
            if key in self.new_ip_state["evidence"] or not isinstance(value, dict):
                continue
            timestamps = list((value.get("macs") or {}).values()) + list(
                (value.get("ports") or {}).values()
            )
            if any(isinstance(ts, (int, float)) and ts >= cutoff for ts in timestamps):
                self.new_ip_state["evidence"][key] = value

    def _is_frozen(self, rec):
        for host in rec.get("flagged_hosts", set()):
            value = self.dup_config.get(host, {}).get("freeze")
            if value is None:
                continue
            if str(value).strip().lower() not in {
                "", "0", "off", "false", "no", "none", "disabled", "disable",
            }:
                return True
        return False

    def _finalize(self):
        for host, ips in self.self_vteps.items():
            for ip in ips:
                self.vtep2host[ip] = host

        self._merge_mobility_records()
        self._merge_log_records()
        self._merge_fdb_records()

        remove_ips = []
        for (scope, ip), rec in self.ip_dups.items():
            self._resolve_ip_ports(rec)
            self._apply_sequence_sample(rec, "ip", ip)
            self._apply_ip_evidence_memory(rec)
            current_nonlog_macs = rec["macs"] - rec.get("log_macs", set())
            current_multi_mac = len(current_nonlog_macs) >= 2
            rec["confirmed_conflict"] = bool(
                current_multi_mac and (
                    rec["dad_flagged"]
                    or rec.get("neighbor_conflict_strong")
                    or "evpn_ip_mobility" in rec["evidence_sources"]
                )
            )
            rec["suspected_conflict"] = bool(
                current_multi_mac and not rec["confirmed_conflict"]
            )
            rec["mobility_only"] = bool(
                rec["mobility"] and not rec["confirmed_conflict"]
                and not rec["dad_flagged"] and not rec["dad_event"]
            )
            if rec["confirmed_conflict"]:
                rec["incident_type"] = "confirmed_ip_conflict"
            elif rec["dad_flagged"]:
                rec["incident_type"] = "dad_flagged_ip"
            elif rec["dad_event"]:
                rec["incident_type"] = "dad_event_ip"
            elif rec["mobility"]:
                rec["incident_type"] = "ip_mobility"
            rec["frozen"] = self._is_frozen(rec)
            rec["activity"] = (
                "active" if rec["confirmed_conflict"] or rec["sequence_active"]
                or self._event_is_active(rec) or rec["frozen"] else "settled"
            )
            rec["severity"] = self._ip_sev(rec)
            if (rec["incident_type"] == "ip_mobility"
                    and not rec["sequence_active"] and rec["seq"] < SEQ_STORM):
                remove_ips.append((scope, ip))

        for key in remove_ips:
            self.ip_dups.pop(key, None)

        remove_macs = []
        for (scope, mac), rec in self.mac_dups.items():
            self._sync_mac_local_projection(rec)
            self._apply_sequence_sample(rec, "mac", mac)
            rec["confirmed_conflict"] = bool(rec["fdb_multi"])
            rec["mobility_only"] = bool(
                rec["mobility"] and not rec["confirmed_conflict"]
                and not rec["dad_flagged"] and not rec["dad_event"]
            )
            if rec["confirmed_conflict"]:
                rec["incident_type"] = "confirmed_mac_conflict"
            elif rec["dad_flagged"]:
                rec["incident_type"] = "dad_flagged_mac"
            elif rec["dad_event"]:
                rec["incident_type"] = "dad_event_mac"
            elif rec["mobility"]:
                rec["incident_type"] = "mac_mobility"
            rec["frozen"] = self._is_frozen(rec)
            rec["activity"] = (
                "active" if rec["confirmed_conflict"] or rec["sequence_active"]
                or self._event_is_active(rec) or rec["frozen"] else "settled"
            )
            rec["severity"] = self._mac_sev(rec)
            if (rec["incident_type"] == "mac_mobility"
                    and not rec["sequence_active"] and rec["seq"] < SEQ_STORM
                    and not rec["mh_possible"]):
                remove_macs.append((scope, mac))

        for key in remove_macs:
            self.mac_dups.pop(key, None)

        # Loop evidence is scoped to the same broadcast domain and only counts
        # MACs that are moving now or simultaneously present at multiple
        # attachment points. Historical flat sequence values cannot accumulate
        # into a loop diagnosis.
        confirmed_ip_macs = {
            (rec["scope"], mac)
            for rec in self.ip_dups.values() if rec["confirmed_conflict"]
            for mac in rec["macs"]
        }
        pair_count, endpoints_by_key = {}, {}
        for key, rec in self.mac_dups.items():
            hosts = set(rec["local_ports"])
            hosts.update(
                self.vtep2host[vtep] for vtep in rec["vteps"]
                if vtep in self.vtep2host
            )
            endpoints = tuple(sorted(hosts))
            endpoints_by_key[key] = endpoints
            if len(endpoints) >= 2 and (rec["sequence_active"] or rec["fdb_multi"]):
                pair_key = (rec["scope"], endpoints)
                pair_count[pair_key] = pair_count.get(pair_key, 0) + 1

        for key, rec in self.mac_dups.items():
            endpoints = endpoints_by_key[key]
            participates = (rec["scope"], rec["mac"]) in confirmed_ip_macs
            rec["participates_in_ip_conflict"] = participates
            if participates:
                rec["classification"] = "ip-conflict-participant"
            elif (not rec["confirmed_conflict"] and not rec["dad_flagged"]
                  and len(endpoints) >= 2
                  and pair_count.get((rec["scope"], endpoints), 0) >= LOOP_MIN_MACS):
                rec["possible_loop"] = True
                rec["classification"] = "loop"
                rec["loop_count"] = pair_count[(rec["scope"], endpoints)]
                rec["loop_correlation_id"] = self._loop_correlation_id(
                    rec["scope"], endpoints
                )
                rec["incident_type"] = "possible_loop"
                rec["activity"] = "active"
                rec["severity"] = "CRITICAL"

        for rec in list(self.ip_dups.values()) + list(self.mac_dups.values()):
            rec["stale"] = bool(
                rec.get("severity") == "WARNING"
                and not rec.get("confirmed_conflict")
                and not rec.get("dad_flagged")
                and rec.get("quiet_age") is not None
                and rec["quiet_age"] >= STALE_AGE_SEC
                and (rec.get("recency") is None or rec["recency"] >= STALE_AGE_SEC)
            )
            if rec["stale"]:
                rec["activity"] = "historical"

        self._carry_sequence_state()
        self._carry_ip_evidence()

        self._save_state()

    def _ip_sev(self, rec):
        if rec.get("confirmed_conflict") or self._is_frozen(rec):
            return "CRITICAL"
        if rec.get("sequence_active") or self._event_is_active(rec):
            return "CRITICAL"
        if (rec.get("dad_flagged") or rec.get("dad_event")
                or rec.get("mobility") or rec.get("suspected_conflict")):
            return "WARNING"
        return "OK"

    def _mac_sev(self, rec):
        if rec.get("confirmed_conflict") or self._is_frozen(rec):
            return "CRITICAL"
        if rec.get("sequence_active") or self._event_is_active(rec):
            return "CRITICAL"
        if (rec.get("dad_flagged") or rec.get("dad_event")
                or rec.get("mobility") or rec.get("mh_possible")):
            return "WARNING"
        return "OK"

    # -------------------------------------------------------------- summary
    def summary(self):
        ips = list(self.ip_dups.values())
        macs = list(self.mac_dups.values())
        count = lambda rows, **wanted: sum(
            1 for row in rows if all(row.get(key) == value for key, value in wanted.items())
        )
        confirmed_ips = [row for row in ips if row.get("confirmed_conflict")]
        confirmed_macs = [row for row in macs if row.get("confirmed_conflict")]
        ip_mobility = [row for row in ips if row.get("incident_type") == "ip_mobility"]
        mac_mobility = [row for row in macs if row.get("incident_type") == "mac_mobility"]
        dad_ip_types = {"dad_flagged_ip", "dad_event_ip"}
        dad_mac_types = {"dad_flagged_mac", "dad_event_mac"}
        dad_findings = {}
        dad_ip_participants = {}
        for row in ips:
            if row.get("incident_type") not in dad_ip_types:
                continue
            key = ("ip", row.get("scope", "unknown"), row.get("ip", "unknown"))
            dad_findings[key] = row.get("activity") == "active"
            for mac in row.get("macs", set()):
                dad_ip_participants.setdefault(
                    (row.get("scope", "unknown"), mac), set()
                ).add(key)
        for row in macs:
            if row.get("incident_type") not in dad_mac_types:
                continue
            participant = (
                row.get("scope", "unknown"), row.get("mac", "unknown")
            )
            linked_ip_findings = dad_ip_participants.get(participant, set())
            if linked_ip_findings:
                if row.get("activity") == "active":
                    for key in linked_ip_findings:
                        dad_findings[key] = True
                continue
            key = ("mac",) + participant
            dad_findings[key] = row.get("activity") == "active"
        mobility_incidents = {}
        for row in ip_mobility:
            keys = {
                (row.get("scope", "unknown"), mac)
                for mac in row.get("macs", set())
            } or {
                (row.get("scope", "unknown"), "ip:" + row.get("ip", "unknown"))
            }
            for key in keys:
                mobility_incidents[key] = (
                    "active" if row.get("activity") == "active"
                    or mobility_incidents.get(key) == "active" else "settled"
                )
        for row in mac_mobility:
            key = (row.get("scope", "unknown"), row.get("mac", "unknown"))
            mobility_incidents[key] = (
                "active" if row.get("activity") == "active"
                or mobility_incidents.get(key) == "active" else "settled"
            )
        apipa_observations = sum(
            claim["observation_count"] for claim in self.apipa_claims.values()
        )
        apipa_local = sum(
            claim["local_observations"] for claim in self.apipa_claims.values()
        )
        apipa_extern = sum(
            claim["extern_observations"] for claim in self.apipa_claims.values()
        )
        apipa_non_vlan = sum(
            claim["non_vlan_observations"] for claim in self.apipa_claims.values()
        )
        resolved_apipa_claims = [
            claim for claim in self.apipa_claims.values()
            if claim.get("mac") != "unknown"
            and bool(set(claim.get("states", set())) - {"FAILED", "INCOMPLETE"})
        ]
        affected_vnis = {
            row["vni"] for row in ips + macs if row.get("vni") != "unknown"
        } | {
            claim["vni"] for claim in self.apipa_claims.values()
            if claim.get("vni") != "unknown"
        }
        affected_vlans = set()
        for row in ips + macs:
            affected_vlans.update(row.get("vlans", set()))
        for claim in self.apipa_claims.values():
            affected_vlans.update(claim["vlans"])
        disabled = [h for h, c in self.dup_config.items() if c.get("enabled") is False]
        confirmed_ip_active = count(confirmed_ips, activity="active")
        confirmed_ip_settled = count(confirmed_ips, activity="settled") + count(
            confirmed_ips, activity="historical"
        )
        confirmed_mac_active = count(confirmed_macs, activity="active")
        confirmed_mac_settled = count(confirmed_macs, activity="settled") + count(
            confirmed_macs, activity="historical"
        )
        standalone_active_macs = sum(
            1 for row in confirmed_macs
            if row.get("activity") == "active"
            and not row.get("participates_in_ip_conflict")
        )
        confirmed_conflict_incident_active = confirmed_ip_active + standalone_active_macs
        possible_loop_rows = [row for row in macs if row.get("possible_loop")]
        possible_loop_incidents = set()
        for row in possible_loop_rows:
            endpoints = set(row.get("local_ports", {}))
            endpoints.update(
                self.vtep2host[vtep] for vtep in row.get("vteps", set())
                if vtep in self.vtep2host
            )
            possible_loop_incidents.add(
                row.get("loop_correlation_id")
                or self._loop_correlation_id(row.get("scope", "unknown"), endpoints)
            )
        coverage_failure_count = sum(
            len(set(labels)) for labels in self.coverage_failures.values()
        )
        return {
            "confirmed_ip_total": len(confirmed_ips),
            "confirmed_ip_active": confirmed_ip_active,
            "confirmed_ip_settled": confirmed_ip_settled,
            "dad_flagged_ip_total": count(ips, incident_type="dad_flagged_ip"),
            "dad_event_ip_total": count(ips, incident_type="dad_event_ip"),
            "dad_flagged_ip_evidence_total": count(ips, dad_flagged=True),
            "dad_finding_total": len(dad_findings),
            "dad_finding_active": sum(dad_findings.values()),
            "ip_mobility_total": len(ip_mobility),
            "ip_mobility_active": count(ip_mobility, activity="active"),
            "ip_mobility_settled": len(ip_mobility) - count(ip_mobility, activity="active"),
            "confirmed_mac_total": len(confirmed_macs),
            "confirmed_mac_active": confirmed_mac_active,
            "confirmed_mac_standalone_active": standalone_active_macs,
            "confirmed_mac_settled": confirmed_mac_settled,
            "confirmed_conflict_incident_active": confirmed_conflict_incident_active,
            "dad_flagged_mac_total": count(macs, incident_type="dad_flagged_mac"),
            "dad_event_mac_total": count(macs, incident_type="dad_event_mac"),
            "dad_flagged_mac_evidence_total": count(macs, dad_flagged=True),
            "mac_mobility_total": len(mac_mobility),
            "mac_mobility_active": count(mac_mobility, activity="active"),
            "mac_mobility_settled": len(mac_mobility) - count(mac_mobility, activity="active"),
            "mobility_incident_total": len(mobility_incidents),
            "mobility_incident_active": sum(
                1 for activity in mobility_incidents.values() if activity == "active"
            ),
            "mobility_incident_settled": sum(
                1 for activity in mobility_incidents.values() if activity != "active"
            ),
            "possible_loops": len(possible_loop_incidents),
            "possible_loop_mac_signals": len(possible_loop_rows),
            "apipa_unique": len(resolved_apipa_claims),
            "apipa_unresolved_unique": len(self.apipa_claims) - len(resolved_apipa_claims),
            "apipa_observations": apipa_observations,
            "apipa_local_observations": apipa_local,
            "apipa_extern_observations": apipa_extern,
            "apipa_non_vlan_observations": apipa_non_vlan,
            "coverage_expected_hosts": len(self.expected_hosts),
            "coverage_current_hosts": len(self.current_hosts),
            "coverage_unavailable_hosts": sorted(self.unavailable_hosts),
            "coverage_partial": self.coverage_partial or bool(coverage_failure_count),
            "coverage_failures": coverage_failure_count,
            "sequence_baseline_warmup": self.sequence_baseline_warmup,
            "sequence_baseline_warmup_hosts": sorted(
                self.sequence_baseline_warmup_hosts
            ),
            "affected_vnis": len(affected_vnis),
            "affected_vlans": len(affected_vlans),
            # Backwards-compatible keys now expose confirmed incidents rather
            # than mixing mobility/APIPA observations into duplicate totals.
            "ip_active": confirmed_ip_active,
            "ip_quiesced": confirmed_ip_settled,
            "mac_total": len(confirmed_macs),
            "apipa_total": len(resolved_apipa_claims),
            "vlans": len(affected_vlans),
            "disabled": disabled,
            "ip_total": len(confirmed_ips),
        }

    # ---------------------------------------------------------------- web
    def export_html(self, output_file):
        """Render the semantic duplicate report."""
        return export_duplicate_report(self, output_file)
