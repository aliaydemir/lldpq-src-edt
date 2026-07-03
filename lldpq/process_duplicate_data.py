#!/usr/bin/env python3
"""
Process collected duplicate IP/MAC data and generate the analysis page.

Reads monitor-results/dup-data/<host>_{dup,fdb,neigh}.txt (collected by monitor.sh)
and writes monitor-results/duplicate-analysis.html.

Copyright (c) 2024 LLDPq Project - MIT License
"""

import os
import sys
from duplicate_analyzer import DuplicateAnalyzer
from collection_freshness import mark_html_collection_unavailable


def main(data_dir="monitor-results"):
    try:
        analyzer = DuplicateAnalyzer(data_dir)
        if not analyzer.parse_all():
            if analyzer.collection_errors:
                for error in analyzer.collection_errors:
                    print(f"Duplicate collection error: {error}", file=sys.stderr)
            else:
                print("No complete current duplicate collections found", file=sys.stderr)
            return 1
        summary = analyzer.summary()

        output_file = os.path.join(analyzer.data_dir, "duplicate-analysis.html")
        analyzer.export_html(output_file)
        if analyzer.collection_unavailable:
            mark_html_collection_unavailable(output_file)
        if not os.path.isfile(output_file) or os.path.getsize(output_file) == 0:
            print("Duplicate analysis report was not generated", file=sys.stderr)
            return 1

        print("Duplicate analysis complete:")
        print(
            "  Correlated active conflicts   : %d"
            % summary["confirmed_conflict_incident_active"]
        )
        print("  Confirmed active IP conflicts : %d" % summary["confirmed_ip_active"])
        print("  Confirmed settled IP conflicts: %d" % summary["confirmed_ip_settled"])
        print("  Active IP mobility anomalies  : %d" % summary["ip_mobility_active"])
        print("  Active MAC evidence rows      : %d" % summary["confirmed_mac_active"])
        print(
            "  Standalone active MAC conflicts: %d"
            % summary["confirmed_mac_standalone_active"]
        )
        print("  Active DAD-only findings      : %d" % summary["dad_finding_active"])
        print("  Active MAC mobility anomalies : %d" % summary["mac_mobility_active"])
        print("  Correlated active mobility    : %d" % summary["mobility_incident_active"])
        print("  Possible loop incidents       : %d" % summary["possible_loops"])
        print(
            "  Loop-associated MAC signals   : %d"
            % summary["possible_loop_mac_signals"]
        )
        print(
            "  IPv4LL unique / observations  : %d / %d"
            % (summary["apipa_unique"], summary["apipa_observations"])
        )
        print(
            "  Coverage current / expected   : %d / %d"
            % (
                summary["coverage_current_hosts"],
                summary["coverage_expected_hosts"],
            )
        )
        print("  VNIs / VLANs with signals     : %d / %d" % (
            summary["affected_vnis"], summary["affected_vlans"]
        ))
        if summary["disabled"]:
            print(
                "  DAD off (reason unverified)    : %s"
                % ", ".join(sorted(summary["disabled"]))
            )
        if summary["coverage_failures"]:
            print(
                "  Data coverage warnings: %d (report is partial)"
                % summary["coverage_failures"]
            )
        if summary.get("sequence_baseline_warmup"):
            print(
                "  Mobility activity baseline: warming up; the next current collection can calculate per-observer deltas"
            )
        print("  -> %s" % output_file)
        return 0
    except Exception as exc:
        print(f"Duplicate analysis failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
