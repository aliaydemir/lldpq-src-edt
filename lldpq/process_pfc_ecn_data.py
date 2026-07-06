#!/usr/bin/env python3
"""Build the static PFC/ECN analysis report from monitor.sh snapshots.

The collector owns switch access.  This analyzer only reads the current raw
files, derives interval deltas/rates from a local baseline, and writes static
artifacts under ``monitor-results``.  Missing or failed counters are kept as
``None`` throughout; they are never presented as zero.
"""

from __future__ import annotations

import html
import json
import math
import os
import re
import sys
import tempfile
import time
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, MutableMapping, Optional, Tuple

from collection_freshness import (
    asset_snapshot_is_authoritative,
    asset_snapshot_is_valid,
    is_current_collection,
    read_asset_snapshot,
)


PORT_RE = re.compile(r"^swp[0-9]+(?:s[0-9]+)?$")
LEGACY_START_RE = re.compile(
    r"^===PFC_ECN_PORT_START\s+port=([^\s=]+)===$"
)
LEGACY_END_RE = re.compile(
    r"^===PFC_ECN_PORT_END\s+port=([^\s=]+)\s+status=(ok|error)===$",
    re.IGNORECASE,
)
COLLECTOR_START_RE = re.compile(r"^__LLDPQ_PFC_ECN_PORT_START__:(\S+)$")
COLLECTOR_STATUS_RE = re.compile(
    r"^__LLDPQ_PFC_ECN_PORT_STATUS__:(\S+):(OK|ERROR):(-?[0-9]+)$",
    re.IGNORECASE,
)
COLLECTOR_END_RE = re.compile(r"^__LLDPQ_PFC_ECN_PORT_END__:(\S+)$")
INVENTORY_STATUS_RE = re.compile(
    r"^__LLDPQ_PFC_ECN_INVENTORY_STATUS__:(OK|EMPTY|ERROR):([0-9]+)$",
    re.IGNORECASE,
)
INVENTORY_COUNT_RE = re.compile(
    r"^__LLDPQ_PFC_ECN_INVENTORY_COUNT__:([0-9]+)$"
)

COUNTER_PATHS = {
    "ecn_marked_frames": ("egress-queue-stats", "ecn-marked-frames"),
    "tx_frames": ("egress-queue-stats", "tx-frames"),
    "tx_uc_buffer_discards": (
        "egress-queue-stats",
        "tx-uc-buffer-discards",
    ),
    "wred_discards": ("egress-queue-stats", "wred-discards"),
    "rx_pause_frames": ("pfc-stats", "rx-pause-frames"),
    "tx_pause_frames": ("pfc-stats", "tx-pause-frames"),
}
REQUIRED_COUNTERS = (
    "ecn_marked_frames",
    "rx_pause_frames",
    "tx_pause_frames",
)
HISTORY_SECONDS = 24 * 60 * 60
HISTORY_MAX_RECORDS_PER_PORT = 288


def _deep_merge(target: MutableMapping[str, Any], source: Mapping[str, Any]) -> None:
    for key, value in source.items():
        if isinstance(value, Mapping) and isinstance(target.get(key), MutableMapping):
            _deep_merge(target[key], value)
        else:
            target[key] = value


def _decode_json_values(text: str) -> List[Any]:
    """Decode one or more whitespace-separated JSON values."""
    decoder = json.JSONDecoder()
    values: List[Any] = []
    position = 0
    while position < len(text):
        while position < len(text) and text[position].isspace():
            position += 1
        if position >= len(text):
            break
        value, position = decoder.raw_decode(text, position)
        values.append(value)
    return values


def _payload_for_port(value: Any, port: str) -> Optional[Mapping[str, Any]]:
    if not isinstance(value, Mapping):
        return None
    if isinstance(value.get(port), Mapping):
        return value[port]
    ports = value.get("ports")
    if isinstance(ports, Mapping) and isinstance(ports.get(port), Mapping):
        return ports[port]
    named_port = value.get("interface", value.get("port", value.get("name")))
    if named_port is not None and str(named_port) == port:
        for wrapper in ("data", "counters", "qos"):
            if isinstance(value.get(wrapper), Mapping):
                return value[wrapper]
    return value


def _direct_payloads(value: Any) -> Iterable[Tuple[str, Mapping[str, Any]]]:
    """Yield ``(port, payload)`` from useful unmarked JSON layouts."""
    if isinstance(value, list):
        for item in value:
            yield from _direct_payloads(item)
        return
    if not isinstance(value, Mapping):
        return
    ports = value.get("ports")
    if isinstance(ports, Mapping):
        for port, payload in ports.items():
            if isinstance(payload, Mapping):
                yield str(port), payload
        return
    if isinstance(ports, list):
        for item in ports:
            yield from _direct_payloads(item)
        return
    named_port = value.get("interface", value.get("port", value.get("name")))
    if named_port is not None:
        payload = _payload_for_port(value, str(named_port))
        if payload is not None:
            yield str(named_port), payload
        return
    for port, payload in value.items():
        if PORT_RE.fullmatch(str(port)) and isinstance(payload, Mapping):
            yield str(port), payload


def parse_pfc_ecn_snapshot(content: str) -> Dict[str, Dict[str, Any]]:
    """Parse marker-delimited collector output or direct JSON.

    The current collector uses ``__LLDPQ_...`` markers.  The earlier proposed
    ``===PFC_ECN...===`` markers remain accepted so stored fixtures and manual
    captures stay useful.  A collector ``ERROR`` status produces a port entry
    with no trusted payload instead of a zero-filled record.
    """
    ports: Dict[str, Dict[str, Any]] = {}
    current: Optional[str] = None
    current_body: List[str] = []
    current_status: Optional[str] = None
    current_rc: Optional[int] = None
    saw_markers = False

    def finish(port: str, status_from_end: Optional[str] = None) -> None:
        nonlocal current, current_body, current_status, current_rc
        effective = (status_from_end or current_status or "error").lower()
        payload: Dict[str, Any] = {}
        error: Optional[str] = None
        if effective == "ok":
            try:
                for value in _decode_json_values("\n".join(current_body)):
                    candidate = _payload_for_port(value, port)
                    if candidate is not None:
                        _deep_merge(payload, candidate)
                if not payload:
                    error = "successful collector record contained no JSON object"
                    effective = "error"
            except (json.JSONDecodeError, TypeError, ValueError) as exc:
                error = f"invalid JSON payload: {exc}"
                effective = "error"
        elif current_body:
            error = "collector reported an error"

        existing = ports.get(port)
        if existing is not None and existing.get("status") == "ok" and effective == "ok":
            _deep_merge(existing["payload"], payload)
        else:
            ports[port] = {
                "status": effective,
                "return_code": current_rc,
                "payload": payload if effective == "ok" else {},
                "error": error,
            }
        current = None
        current_body = []
        current_status = None
        current_rc = None

    for raw_line in content.splitlines():
        line = raw_line.strip()
        start = COLLECTOR_START_RE.fullmatch(line) or LEGACY_START_RE.fullmatch(line)
        if start:
            saw_markers = True
            if current is not None:
                finish(current, "error")
            current = start.group(1)
            current_body = []
            current_status = None
            current_rc = None
            continue
        if current is None:
            continue
        status = COLLECTOR_STATUS_RE.fullmatch(line)
        if status and status.group(1) == current:
            current_status = status.group(2).lower()
            current_rc = int(status.group(3))
            continue
        legacy_end = LEGACY_END_RE.fullmatch(line)
        if legacy_end and legacy_end.group(1) == current:
            finish(current, legacy_end.group(2))
            continue
        collector_end = COLLECTOR_END_RE.fullmatch(line)
        if collector_end and collector_end.group(1) == current:
            finish(current)
            continue
        current_body.append(raw_line)

    if current is not None:
        finish(current, "error")
    if saw_markers:
        return ports

    try:
        for value in _decode_json_values(content):
            for port, payload in _direct_payloads(value):
                entry = ports.setdefault(
                    port,
                    {"status": "ok", "return_code": 0, "payload": {}, "error": None},
                )
                _deep_merge(entry["payload"], payload)
    except (json.JSONDecodeError, TypeError, ValueError):
        return {}
    return ports


def validate_inventory_contract(
    content: str, ports: Mapping[str, Any]
) -> Tuple[bool, Optional[str]]:
    """Validate optional collector inventory markers against parsed ports.

    Legacy captures and direct JSON have no inventory marker and remain valid.
    Current collector output is rejected if it was truncated between the
    inventory declaration and the final port record.
    """
    status: Optional[str] = None
    declared_count: Optional[int] = None
    separate_count: Optional[int] = None
    for raw_line in content.splitlines():
        line = raw_line.strip()
        match = INVENTORY_STATUS_RE.fullmatch(line)
        if match:
            if status is not None:
                return False, "duplicate inventory status marker"
            status = match.group(1).lower()
            declared_count = int(match.group(2))
            continue
        match = INVENTORY_COUNT_RE.fullmatch(line)
        if match:
            if separate_count is not None:
                return False, "duplicate inventory count marker"
            separate_count = int(match.group(1))

    if status is None and separate_count is None:
        return True, None
    expected = separate_count if separate_count is not None else declared_count
    if declared_count is not None and separate_count is not None and declared_count != separate_count:
        return False, "inventory status/count markers disagree"
    if status == "error":
        return False, "collector reported an inventory error"
    if status == "empty" and (expected != 0 or ports):
        return False, "empty inventory marker conflicts with port records"
    if status == "ok" and (expected is None or expected <= 0):
        return False, "successful inventory has an invalid port count"
    if expected is not None and len(ports) != expected:
        return False, f"inventory declared {expected} ports but parsed {len(ports)}"
    return True, None


def _find_qos_object(value: Any) -> Optional[Mapping[str, Any]]:
    """Recursively locate the NVUE object containing both exact QoS groups."""
    if isinstance(value, Mapping):
        if "egress-queue-stats" in value and "pfc-stats" in value:
            return value
        for child in value.values():
            found = _find_qos_object(child)
            if found is not None:
                return found
    elif isinstance(value, list):
        for child in value:
            found = _find_qos_object(child)
            if found is not None:
                return found
    return None


def _priority_three(group: Any) -> Optional[Mapping[str, Any]]:
    if isinstance(group, Mapping):
        candidate = group.get("3")
        if isinstance(candidate, Mapping):
            return candidate
    if isinstance(group, list):
        for candidate in group:
            if not isinstance(candidate, Mapping):
                continue
            selector = candidate.get(
                "traffic-class", candidate.get("switch-priority", candidate.get("id"))
            )
            if str(selector) == "3":
                return candidate
    return None


def _counter_number(value: Any) -> Optional[int]:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value if value >= 0 else None
    if isinstance(value, float):
        return int(value) if value >= 0 and math.isfinite(value) and value.is_integer() else None
    if isinstance(value, str):
        text = value.strip().replace(",", "")
        if re.fullmatch(r"[0-9]+", text):
            return int(text)
    if isinstance(value, Mapping):
        for key in ("value", "counter", "operational"):
            if key in value:
                return _counter_number(value[key])
    return None


def extract_counters(payload: Mapping[str, Any]) -> Dict[str, Optional[int]]:
    qos = _find_qos_object(payload)
    result: Dict[str, Optional[int]] = {name: None for name in COUNTER_PATHS}
    if qos is None:
        return result
    groups = {
        "egress-queue-stats": _priority_three(qos.get("egress-queue-stats")),
        "pfc-stats": _priority_three(qos.get("pfc-stats")),
    }
    for name, (group_name, field) in COUNTER_PATHS.items():
        group = groups[group_name]
        if group is not None:
            result[name] = _counter_number(group.get(field))
    return result


def _iso(timestamp: float) -> str:
    return datetime.fromtimestamp(timestamp, timezone.utc).isoformat()


def build_port_record(
    hostname: str,
    interface: str,
    counters: Mapping[str, Optional[int]],
    previous: Optional[Mapping[str, Any]],
    timestamp: float,
    collection_status: str = "ok",
) -> Dict[str, Any]:
    previous_counters = previous.get("counters", {}) if isinstance(previous, Mapping) else {}
    previous_timestamp = previous.get("timestamp") if isinstance(previous, Mapping) else None
    duration = (
        timestamp - float(previous_timestamp)
        if isinstance(previous_timestamp, (int, float)) and timestamp > previous_timestamp
        else None
    )
    deltas: Dict[str, Optional[int]] = {}
    rates: Dict[str, Optional[float]] = {}
    reset_counters: List[str] = []
    missing_baseline: List[str] = []

    for name in COUNTER_PATHS:
        current = counters.get(name)
        old = previous_counters.get(name) if isinstance(previous_counters, Mapping) else None
        if current is None or old is None or duration is None:
            deltas[name] = None
            rates[name] = None
            if current is not None and old is None:
                missing_baseline.append(name)
            continue
        if current < old:
            deltas[name] = None
            rates[name] = None
            reset_counters.append(name)
            continue
        delta = current - old
        deltas[name] = delta
        rates[name] = delta / duration

    exact = all(counters.get(name) is not None for name in REQUIRED_COUNTERS)
    if collection_status != "ok":
        sample_status = "collection_error"
    elif not exact:
        sample_status = "missing"
    elif any(name in reset_counters for name in REQUIRED_COUNTERS):
        sample_status = "counter_reset"
    elif (
        previous is None
        or duration is None
        or any(name in missing_baseline for name in REQUIRED_COUNTERS)
    ):
        sample_status = "first_sample"
    else:
        sample_status = "analyzed"

    discard_values = [
        deltas.get("tx_uc_buffer_discards"), deltas.get("wred_discards")
    ]
    known_discards = [value for value in discard_values if value is not None]
    loss_delta = sum(known_discards) if known_discards else None
    ecn_delta = deltas.get("ecn_marked_frames")
    tx_delta = deltas.get("tx_frames")
    ecn_share = (
        ecn_delta / tx_delta * 100.0
        if ecn_delta is not None and tx_delta is not None and tx_delta > 0
        else None
    )
    pfc_active = any(
        (deltas.get(name) or 0) > 0
        for name in ("rx_pause_frames", "tx_pause_frames")
    )
    ecn_active = (ecn_delta or 0) > 0
    if sample_status != "analyzed":
        signal = sample_status
    elif (loss_delta or 0) > 0:
        signal = "loss"
    elif ecn_active and pfc_active:
        signal = "combined"
    elif pfc_active:
        signal = "pfc"
    elif ecn_active:
        signal = "ecn"
    else:
        signal = "quiet"

    return {
        "hostname": hostname,
        "interface": interface,
        "port_key": f"{hostname}:{interface}",
        "timestamp": timestamp,
        "timestamp_iso": _iso(timestamp),
        "sample_duration_seconds": duration,
        "sample_status": sample_status,
        "signal": signal,
        "exact": exact,
        "counters": dict(counters),
        "deltas": deltas,
        "rates": rates,
        "reset_counters": reset_counters,
        "ecn_share_percent": ecn_share,
        "loss_delta": loss_delta,
    }


def _read_state(path: Path, default: Dict[str, Any]) -> Dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
        return value if isinstance(value, dict) else default
    except (OSError, UnicodeError, json.JSONDecodeError):
        return default


def _atomic_write(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    except BaseException:
        try:
            os.unlink(temporary)
        except OSError:
            pass
        raise


def _atomic_json(path: Path, value: Mapping[str, Any]) -> None:
    _atomic_write(path, json.dumps(value, indent=2, sort_keys=True) + "\n")


def _fmt_total(value: Optional[int]) -> str:
    return "&mdash;" if value is None else f"{value:,}"


def _fmt_delta(value: Optional[int]) -> str:
    return "&mdash;" if value is None else f"+{value:,}"


def _fmt_rate(value: Optional[float]) -> str:
    if value is None:
        return "&mdash;"
    if value >= 1000:
        return f"{value:,.0f}/s"
    if value >= 1:
        return f"{value:,.2f}/s"
    return f"{value:,.4f}/s"


def _fmt_percent(value: Optional[float]) -> str:
    return "&mdash;" if value is None else f"{value:.4f}%"


def _fmt_duration(value: Optional[float]) -> str:
    if value is None or value < 0:
        return "&mdash;"
    seconds = int(round(value))
    minutes, seconds = divmod(seconds, 60)
    hours, minutes = divmod(minutes, 60)
    if hours:
        return f"{hours}h {minutes}m {seconds}s"
    if minutes:
        return f"{minutes}m {seconds}s"
    return f"{seconds}s"


def _trend_svg(history: Mapping[str, Any]) -> str:
    buckets: Dict[int, Dict[str, float]] = defaultdict(lambda: defaultdict(float))
    for records in history.values():
        if not isinstance(records, list):
            continue
        for record in records:
            if not isinstance(record, Mapping) or record.get("sample_status") != "analyzed":
                continue
            timestamp = record.get("timestamp")
            rates = record.get("rates")
            if not isinstance(timestamp, (int, float)) or not isinstance(rates, Mapping):
                continue
            bucket = int(timestamp // 60 * 60)
            for name in REQUIRED_COUNTERS:
                value = rates.get(name)
                if isinstance(value, (int, float)) and math.isfinite(value):
                    buckets[bucket][name] += max(float(value), 0.0)
    points = sorted(buckets.items())[-24:]
    if len(points) < 2:
        return '<div class="trend-empty">A trend appears after two complete samples.</div>'

    width, height = 920, 220
    left, right, top, bottom = 54, 18, 18, 36
    plot_w, plot_h = width - left - right, height - top - bottom
    maximum = max(
        [bucket.get(name, 0.0) for _ts, bucket in points for name in REQUIRED_COUNTERS]
        or [0.0]
    )
    maximum = maximum if maximum > 0 else 1.0
    colors = {
        "ecn_marked_frames": "#76b900",
        "rx_pause_frames": "#4fc3f7",
        "tx_pause_frames": "#ffb74d",
    }
    labels = {
        "ecn_marked_frames": "TC3 ECN",
        "rx_pause_frames": "SP3 PFC RX",
        "tx_pause_frames": "SP3 PFC TX",
    }
    polylines = []
    for name in REQUIRED_COUNTERS:
        coordinates = []
        for index, (_timestamp, values) in enumerate(points):
            x = left + (plot_w * index / (len(points) - 1))
            y = top + plot_h * (1 - values.get(name, 0.0) / maximum)
            coordinates.append(f"{x:.1f},{y:.1f}")
        polylines.append(
            f'<polyline fill="none" stroke="{colors[name]}" stroke-width="2.5" '
            f'points="{" ".join(coordinates)}" />'
        )
    first_label = datetime.fromtimestamp(points[0][0]).strftime("%H:%M")
    last_label = datetime.fromtimestamp(points[-1][0]).strftime("%H:%M")
    legend = "".join(
        f'<span><i style="background:{colors[name]}"></i>{labels[name]}</span>'
        for name in REQUIRED_COUNTERS
    )
    return f'''<div class="trend-legend">{legend}</div>
<svg class="trend" viewBox="0 0 {width} {height}" role="img" aria-label="Aggregate counter rates">
  <line x1="{left}" y1="{top + plot_h}" x2="{width-right}" y2="{top + plot_h}" class="axis" />
  <line x1="{left}" y1="{top}" x2="{left}" y2="{top + plot_h}" class="axis" />
  <text x="8" y="{top + 6}" class="axis-label">{maximum:,.2f}/s</text>
  <text x="{left}" y="{height-8}" class="axis-label">{first_label}</text>
  <text x="{width-right-35}" y="{height-8}" class="axis-label">{last_label}</text>
  {''.join(polylines)}
</svg>'''


def render_report(
    records: List[Mapping[str, Any]],
    history: Mapping[str, Any],
    expected_hosts: Optional[int] = None,
    current_hosts: Optional[int] = None,
    collection_unavailable: bool = False,
) -> str:
    records = sorted(records, key=lambda row: (row["hostname"], row["interface"]))
    total = len(records)
    exact = sum(bool(row.get("exact")) for row in records)
    ecn_active = sum((row["deltas"].get("ecn_marked_frames") or 0) > 0 for row in records)
    rx_active = sum((row["deltas"].get("rx_pause_frames") or 0) > 0 for row in records)
    tx_active = sum((row["deltas"].get("tx_pause_frames") or 0) > 0 for row in records)
    loss_active = sum((row.get("loss_delta") or 0) > 0 for row in records)
    incomplete = sum(row.get("sample_status") != "analyzed" for row in records)
    device_coverage = (
        f"{current_hosts}/{expected_hosts}"
        if expected_hosts is not None and current_hosts is not None
        else "&mdash;"
    )
    coverage_attrs = ""
    if collection_unavailable:
        coverage_attrs = ' data-collection-status="unavailable" data-coverage-status="unavailable"'
    elif expected_hosts is not None and current_hosts is not None:
        coverage = "complete" if current_hosts >= expected_hosts else "partial"
        coverage_attrs = (
            f' data-coverage-status="{coverage}" data-coverage-expected="{expected_hosts}"'
            f' data-coverage-current="{current_hosts}"'
        )

    rows = []
    for row in records:
        counters, deltas, rates = row["counters"], row["deltas"], row["rates"]
        status = str(row["sample_status"])
        status_label = {
            "analyzed": row.get("signal", "quiet"),
            "first_sample": "first sample",
            "counter_reset": "counter reset",
            "collection_error": "collection error",
            "missing": "missing",
        }.get(status, status)
        status_class = {
            "loss": "danger", "combined": "warn", "pfc": "warn", "ecn": "info",
            "quiet": "ok", "first_sample": "muted", "counter_reset": "muted",
            "collection_error": "danger", "missing": "muted",
        }.get(status_label, "muted")
        search = html.escape(
            f'{row["hostname"]} {row["interface"]} {status_label}'.lower(), quote=True
        )
        sort = lambda value: "" if value is None else str(value)
        rows.append(f'''<tr data-search="{search}" data-status="{html.escape(status_label, quote=True)}">
<td data-sort="{html.escape(str(row['hostname']), quote=True)}">{html.escape(str(row['hostname']))}</td>
<td data-sort="{html.escape(str(row['interface']), quote=True)}"><code>{html.escape(str(row['interface']))}</code></td>
<td data-sort="{html.escape(status_label, quote=True)}"><span class="badge {status_class}">{html.escape(status_label)}</span></td>
<td data-sort="{sort(counters.get('ecn_marked_frames'))}">{_fmt_total(counters.get('ecn_marked_frames'))}</td>
<td data-sort="{sort(deltas.get('ecn_marked_frames'))}">{_fmt_delta(deltas.get('ecn_marked_frames'))}<small>{_fmt_rate(rates.get('ecn_marked_frames'))}</small></td>
<td data-sort="{sort(row.get('ecn_share_percent'))}">{_fmt_percent(row.get('ecn_share_percent'))}</td>
<td data-sort="{sort(counters.get('rx_pause_frames'))}">{_fmt_total(counters.get('rx_pause_frames'))}</td>
<td data-sort="{sort(deltas.get('rx_pause_frames'))}">{_fmt_delta(deltas.get('rx_pause_frames'))}<small>{_fmt_rate(rates.get('rx_pause_frames'))}</small></td>
<td data-sort="{sort(counters.get('tx_pause_frames'))}">{_fmt_total(counters.get('tx_pause_frames'))}</td>
<td data-sort="{sort(deltas.get('tx_pause_frames'))}">{_fmt_delta(deltas.get('tx_pause_frames'))}<small>{_fmt_rate(rates.get('tx_pause_frames'))}</small></td>
<td data-sort="{sort(deltas.get('tx_frames'))}">{_fmt_delta(deltas.get('tx_frames'))}</td>
<td data-sort="{sort(row.get('loss_delta'))}">{_fmt_delta(row.get('loss_delta'))}</td>
<td data-sort="{row['timestamp']}">{html.escape(str(row['timestamp_iso']).replace('+00:00', 'Z'))}<small>{_fmt_duration(row.get('sample_duration_seconds'))}</small></td>
</tr>''')

    generated = datetime.now().astimezone().strftime("%Y-%m-%d %H:%M:%S %Z")
    trend = _trend_svg(history)
    unavailable_banner = (
        '<div class="notice">No current switch collection is available; '
        'the table intentionally shows no current counters.</div>'
        if collection_unavailable else ""
    )
    return f'''<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>PFC/ECN Analysis</title>
<meta name="totalPorts" content="{total}"><meta name="exactPorts" content="{exact}">
<style>
:root{{--bg:#1e1e1e;--panel:#2a2a2a;--panel2:#242424;--line:#414141;--text:#ddd;--muted:#999;--green:#76b900;--cyan:#4fc3f7;--orange:#ffb74d;--red:#ff6b6b}}*{{box-sizing:border-box}}body{{margin:0;padding:20px;background:var(--bg);color:var(--text);font:14px/1.45 system-ui,-apple-system,"Segoe UI",sans-serif}}header{{display:flex;justify-content:space-between;gap:16px;align-items:flex-start;border-bottom:1px solid var(--line);padding-bottom:14px;margin-bottom:18px}}h1{{margin:0;color:var(--green);font-size:25px}}.subtitle,.updated{{color:var(--muted);font-size:12px;margin-top:4px}}.chip{{display:inline-block;border:1px solid #557d16;border-radius:99px;padding:4px 10px;color:#a9d764;background:#253017}}.notice{{margin:0 0 18px;padding:12px 14px;border-left:4px solid var(--orange);background:#332b20;color:#ffcc80}}.cards{{display:grid;grid-template-columns:repeat(auto-fit,minmax(135px,1fr));gap:10px;margin-bottom:18px}}.card,.section{{background:var(--panel);border:1px solid #353535;border-radius:8px}}.card{{padding:13px;border-left:3px solid var(--green)}}.card.warn{{border-left-color:var(--orange)}}.card.danger{{border-left-color:var(--red)}}.value{{font-size:23px;font-weight:700}}.label{{color:var(--muted);font-size:12px}}.section{{margin-bottom:18px;overflow:hidden}}.section h2{{margin:0;padding:11px 14px;background:#323232;color:var(--green);font-size:14px}}.content{{padding:14px}}.directions{{display:grid;grid-template-columns:repeat(3,1fr);gap:10px}}.direction{{background:var(--panel2);border-left:3px solid var(--cyan);padding:10px 12px}}.direction:first-child{{border-left-color:var(--green)}}.direction:last-child{{border-left-color:var(--orange)}}.direction b{{display:block;margin-bottom:4px}}.trend{{display:block;width:100%;height:auto;max-height:250px}}.axis{{stroke:#555;stroke-width:1}}.axis-label{{fill:#999;font-size:11px}}.trend-legend{{display:flex;gap:18px;flex-wrap:wrap;margin-bottom:5px;color:#bbb;font-size:12px}}.trend-legend i{{display:inline-block;width:12px;height:3px;margin:0 5px 3px 0}}.trend-empty{{padding:30px;text-align:center;color:var(--muted)}}.toolbar{{display:flex;gap:10px;flex-wrap:wrap;padding:12px 14px;border-bottom:1px solid var(--line)}}input,select,button{{background:#242424;color:var(--text);border:1px solid #555;border-radius:5px;padding:8px 10px}}input{{min-width:240px;flex:1}}button{{cursor:pointer;background:#5b8f00;border-color:#76b900;color:white;font-weight:600}}button:hover{{background:#6ca800}}.table-wrap{{overflow:auto}}table{{border-collapse:collapse;width:100%;min-width:1320px;font-size:12px}}th,td{{padding:9px 10px;border-bottom:1px solid #3d3d3d;text-align:right;white-space:nowrap}}th:first-child,th:nth-child(2),th:nth-child(3),td:first-child,td:nth-child(2),td:nth-child(3){{text-align:left}}th{{background:#333;color:var(--green);position:sticky;top:0;cursor:pointer}}tbody tr:nth-child(even){{background:#272727}}tbody tr:hover{{background:#303030}}td small{{display:block;color:var(--muted)}}code{{color:#9cdcfe}}.badge{{display:inline-block;padding:2px 7px;border-radius:4px;text-transform:uppercase;font-size:10px;font-weight:700}}.badge.ok{{color:#a8d66d;background:#26351e}}.badge.info{{color:#8ad9ff;background:#173544}}.badge.warn{{color:#ffd08a;background:#44331d}}.badge.danger{{color:#ff9a9a;background:#482323}}.badge.muted{{color:#bbb;background:#3b3b3b}}.foot{{color:var(--muted);font-size:12px;padding:0 2px}}@media(max-width:760px){{body{{padding:12px}}header{{display:block}}.chip{{margin-top:10px}}.directions{{grid-template-columns:1fr}}}}
</style></head><body{coverage_attrs}>
<header><div><h1>PFC/ECN Analysis</h1><div class="subtitle">Static TC3 egress and SP3 priority-flow-control counters</div></div><div><span class="chip">TC3 / SP3</span><div class="updated">Generated {html.escape(generated)}</div></div></header>
{unavailable_banner}
<section class="cards">
<div class="card"><div class="value">{device_coverage}</div><div class="label">Current inventory devices</div></div>
<div class="card"><div class="value">{total}</div><div class="label">Monitored ports</div></div>
<div class="card"><div class="value">{exact}/{total}</div><div class="label">Exact counter coverage</div></div>
<div class="card"><div class="value">{ecn_active}</div><div class="label">ECN active (interval)</div></div>
<div class="card warn"><div class="value">{rx_active}</div><div class="label">PFC RX active (interval)</div></div>
<div class="card warn"><div class="value">{tx_active}</div><div class="label">PFC TX active (interval)</div></div>
<div class="card danger"><div class="value">{loss_active}</div><div class="label">Discard evidence (interval)</div></div>
<div class="card {'warn' if incomplete else ''}"><div class="value">{incomplete}</div><div class="label">Pending / missing / reset</div></div>
</section>
<section class="section"><h2>How to read direction</h2><div class="content directions"><div class="direction"><b>TC3 ECN marked</b>Local egress congestion caused the switch to mark ECN-capable traffic.</div><div class="direction"><b>SP3 PFC RX</b>The link peer asked this port to pause priority 3 transmission.</div><div class="direction"><b>SP3 PFC TX</b>This switch asked the peer to pause priority 3 because of local ingress pressure.</div></div></section>
<section class="section"><h2>Aggregate interval trend</h2><div class="content">{trend}</div></section>
<section class="section"><h2>Port counters and interval analysis</h2><div class="toolbar"><input id="search" type="search" placeholder="Search device, interface or status" aria-label="Search ports"><select id="statusFilter" aria-label="Filter status"><option value="">All signals</option><option value="quiet">Quiet</option><option value="ecn">ECN</option><option value="pfc">PFC</option><option value="combined">Combined</option><option value="loss">Loss evidence</option><option value="missing">Missing</option><option value="first sample">First sample</option><option value="counter reset">Counter reset</option><option value="collection error">Collection error</option></select><button id="csv" type="button">Export visible CSV</button></div><div class="table-wrap"><table id="ports"><thead><tr>
<th>Device</th><th>Interface</th><th>Signal</th><th data-type="number">ECN total</th><th data-type="number">ECN delta / rate</th><th data-type="number">ECN share</th><th data-type="number">PFC RX total</th><th data-type="number">PFC RX delta / rate</th><th data-type="number">PFC TX total</th><th data-type="number">PFC TX delta / rate</th><th data-type="number">TC3 TX delta</th><th data-type="number">Discard delta</th><th data-type="number">Sample time / window</th>
</tr></thead><tbody>{''.join(rows)}</tbody></table></div></section>
<p class="foot">Cumulative totals are the actual switch counters. Deltas and rates compare this collection with the prior successful sample. An em dash means unavailable, not zero.</p>
<script>
(()=>{{const table=document.querySelector('#ports'),body=table.tBodies[0],search=document.querySelector('#search'),filter=document.querySelector('#statusFilter');let direction=1,last=-1;function apply(){{const q=search.value.trim().toLowerCase(),f=filter.value.toLowerCase();[...body.rows].forEach(r=>r.hidden=!!((q&&!r.dataset.search.includes(q))||(f&&r.dataset.status.toLowerCase()!==f)))}}search.addEventListener('input',apply);filter.addEventListener('change',apply);[...table.tHead.rows[0].cells].forEach((th,index)=>th.addEventListener('click',()=>{{direction=last===index?-direction:1;last=index;const numeric=th.dataset.type==='number';[...body.rows].sort((a,b)=>{{let av=a.cells[index].dataset.sort??'',bv=b.cells[index].dataset.sort??'';if(numeric){{av=av===''?Number.NEGATIVE_INFINITY:Number(av);bv=bv===''?Number.NEGATIVE_INFINITY:Number(bv);return (av-bv)*direction}}return av.localeCompare(bv,undefined,{{numeric:true}})*direction}}).forEach(row=>body.appendChild(row))}}));document.querySelector('#csv').addEventListener('click',()=>{{const visible=[...body.rows].filter(r=>!r.hidden),lines=[[...table.tHead.rows[0].cells].map(c=>c.textContent.trim()),...visible.map(r=>[...r.cells].map(c=>c.textContent.trim().replace(/\\s+/g,' ')))].map(row=>row.map(v=>'"'+v.replaceAll('"','""')+'"').join(','));const blob=new Blob([lines.join('\\n')+'\\n'],{{type:'text/csv;charset=utf-8'}}),url=URL.createObjectURL(blob),a=document.createElement('a');a.href=url;a.download='pfc-ecn-analysis.csv';a.click();URL.revokeObjectURL(url)}})}})();
</script></body></html>'''


def process_pfc_ecn_data_files(data_dir: str = "monitor-results/pfc-ecn-data") -> bool:
    data_path = Path(data_dir).resolve()
    result_dir = data_path.parent
    if not data_path.is_dir():
        print(f"PFC/ECN data directory not found: {data_path}", file=sys.stderr)
        return False

    asset_snapshot = read_asset_snapshot(str(result_dir.parent / "assets.ini"))
    statuses, _asset_mtime, assets_available = asset_snapshot
    snapshot_valid = asset_snapshot_is_valid(asset_snapshot)
    authoritative = asset_snapshot_is_authoritative(asset_snapshot)
    if assets_available and not snapshot_valid:
        print("Asset snapshot is invalid or incomplete", file=sys.stderr)
        return False

    if authoritative:
        active_hosts = set(statuses)
        for raw_file in data_path.glob("*_pfc_ecn.txt"):
            if raw_file.name.removesuffix("_pfc_ecn.txt") not in active_hosts:
                try:
                    raw_file.unlink()
                except OSError as exc:
                    print(f"Could not prune retired PFC/ECN data: {exc}", file=sys.stderr)
                    return False

    current_files = [
        path for path in data_path.glob("*_pfc_ecn.txt")
        if is_current_collection(
            str(path), path.name.removesuffix("_pfc_ecn.txt"), asset_snapshot
        )
    ]
    inventory_hosts = set(statuses) if snapshot_valid else set()
    expected_hosts = (
        {host for host, status in statuses.items() if status == "OK"}
        if snapshot_valid else set()
    )
    collected_hosts = {path.name.removesuffix("_pfc_ecn.txt") for path in current_files}
    if snapshot_valid and expected_hosts - collected_hosts:
        print(
            "Missing current PFC/ECN collections for: "
            + ", ".join(sorted(expected_hosts - collected_hosts)),
            file=sys.stderr,
        )
        return False
    all_devices_unavailable = snapshot_valid and not expected_hosts

    baseline_path = result_dir / "pfc_ecn_baseline.json"
    history_path = result_dir / "pfc_ecn_history.json"
    report_path = result_dir / "pfc-ecn-analysis.html"
    baseline_state = _read_state(baseline_path, {"version": 1, "ports": {}})
    history_state = _read_state(history_path, {"version": 1, "history": {}})
    baselines = baseline_state.get("ports", {})
    histories = history_state.get("history", {})
    if not isinstance(baselines, dict):
        baselines = {}
    if not isinstance(histories, dict):
        histories = {}
    if authoritative:
        baselines = {
            key: value for key, value in baselines.items()
            if key.split(":", 1)[0] in statuses
        }
        histories = {
            key: value for key, value in histories.items()
            if key.split(":", 1)[0] in statuses
        }

    records: List[Dict[str, Any]] = []
    hosts_with_ports = set()
    for raw_file in sorted(current_files):
        hostname = raw_file.name.removesuffix("_pfc_ecn.txt")
        try:
            raw_content = raw_file.read_text(encoding="utf-8", errors="replace")
            parsed_ports = parse_pfc_ecn_snapshot(raw_content)
        except OSError as exc:
            print(f"Could not read {raw_file}: {exc}", file=sys.stderr)
            return False
        inventory_valid, inventory_error = validate_inventory_contract(
            raw_content, parsed_ports
        )
        if not inventory_valid:
            print(
                f"Invalid PFC/ECN inventory for {hostname}: {inventory_error}",
                file=sys.stderr,
            )
            return False
        physical_ports = {
            name: entry for name, entry in parsed_ports.items() if PORT_RE.fullmatch(name)
        }
        if not physical_ports:
            print(f"No physical PFC/ECN port records for {hostname}", file=sys.stderr)
            return False
        hosts_with_ports.add(hostname)
        timestamp = raw_file.stat().st_mtime
        for interface, entry in sorted(physical_ports.items()):
            key = f"{hostname}:{interface}"
            counters = (
                extract_counters(entry.get("payload", {}))
                if entry.get("status") == "ok" else
                {name: None for name in COUNTER_PATHS}
            )
            record = build_port_record(
                hostname, interface, counters, baselines.get(key), timestamp,
                str(entry.get("status", "error")),
            )
            records.append(record)
            if entry.get("status") == "ok" and any(value is not None for value in counters.values()):
                baselines[key] = {
                    "hostname": hostname,
                    "interface": interface,
                    "timestamp": timestamp,
                    "counters": {
                        name: value for name, value in counters.items() if value is not None
                    },
                }
            port_history = histories.setdefault(key, [])
            if not isinstance(port_history, list):
                port_history = histories[key] = []
            port_history.append(record)

    if expected_hosts - hosts_with_ports:
        print(
            "No physical PFC/ECN counters for: "
            + ", ".join(sorted(expected_hosts - hosts_with_ports)),
            file=sys.stderr,
        )
        return False
    if not records and not all_devices_unavailable:
        print("No current PFC/ECN records", file=sys.stderr)
        return False

    cutoff = time.time() - HISTORY_SECONDS
    for key in list(histories):
        values = histories[key]
        if not isinstance(values, list):
            histories[key] = []
            continue
        histories[key] = [
            value for value in values
            if isinstance(value, Mapping)
            and isinstance(value.get("timestamp"), (int, float))
            and value["timestamp"] >= cutoff
        ][-HISTORY_MAX_RECORDS_PER_PORT:]

    now = time.time()
    baseline_output = {"version": 1, "updated_at": _iso(now), "ports": baselines}
    history_output = {"version": 1, "updated_at": _iso(now), "history": histories}
    report = render_report(
        records,
        histories,
        len(inventory_hosts) if snapshot_valid else None,
        len(hosts_with_ports) if snapshot_valid else None,
        collection_unavailable=all_devices_unavailable,
    )
    _atomic_json(baseline_path, baseline_output)
    _atomic_json(history_path, history_output)
    _atomic_write(report_path, report)
    print(f"PFC/ECN analysis report generated: {report_path}")
    return True


def main() -> int:
    try:
        return 0 if process_pfc_ecn_data_files() else 1
    except KeyboardInterrupt:
        return 130
    except Exception as exc:
        print(f"PFC/ECN analysis failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
