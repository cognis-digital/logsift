"""Command-line interface for LOGSIFT.

Usage:
    logsift scan <logfile> [--format table|json] [options]
    logsift --version

Reads an auth/SSH log, runs defensive detectors, and reports findings.
Exit codes:
    0  no findings
    1  one or more findings
    2  usage / runtime error
"""
from __future__ import annotations

import argparse
import json
import sys
from typing import Optional

from . import TOOL_NAME, TOOL_VERSION
from .core import parse_lines, analyze, summarize


def _read_lines(path: str):
    if path == "-":
        return sys.stdin.read().splitlines()
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        return fh.read().splitlines()


def _print_table(summary: dict, findings: list) -> None:
    print(f"{TOOL_NAME} {TOOL_VERSION} - auth log triage")
    print("-" * 60)
    print(
        f"parsed={summary['events_parsed']} "
        f"failures={summary['failures']} "
        f"successes={summary['successes']} "
        f"ips={summary['distinct_ips']} "
        f"findings={summary['findings']}"
    )
    print("-" * 60)
    if not findings:
        print("No suspicious activity detected.")
        return
    hdr = f"{'SEVERITY':<9} {'KIND':<24} {'COUNT':>5}  TARGET"
    print(hdr)
    print("-" * 60)
    for f in findings:
        target = f.ip or ""
        if f.user:
            target = f"{target} user={f.user}" if target else f"user={f.user}"
        print(f"{f.severity:<9} {f.kind:<24} {f.count:>5}  {target}")
        print(f"          {f.detail}")


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog=TOOL_NAME,
        description="Defensive auth-log triage: detect brute-force, spray, "
                    "and anomalous logins. Analysis/detection only.",
    )
    p.add_argument("--version", action="version",
                   version=f"{TOOL_NAME} {TOOL_VERSION}")
    sub = p.add_subparsers(dest="command")

    scan = sub.add_parser("scan", help="scan an auth log file (use - for stdin)")
    scan.add_argument("logfile", help="path to auth log, or - for stdin")
    scan.add_argument("--format", choices=("table", "json"), default="table")
    scan.add_argument("--bruteforce-threshold", type=int, default=5,
                      help="failures per (ip,user) to flag (default 5)")
    scan.add_argument("--spray-threshold", type=int, default=5,
                      help="distinct users per ip to flag spray (default 5)")
    scan.add_argument("--distributed-threshold", type=int, default=5,
                      help="distinct ips per user to flag (default 5)")
    scan.add_argument("--window-minutes", type=int, default=10,
                      help="sliding window for rate detectors (default 10)")
    return p


def main(argv: Optional[list] = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    if args.command != "scan":
        parser.print_help()
        return 2

    try:
        lines = _read_lines(args.logfile)
    except OSError as exc:
        print(f"error: cannot read {args.logfile!r}: {exc}", file=sys.stderr)
        return 2

    events = parse_lines(lines)
    findings = analyze(
        events,
        bruteforce_threshold=args.bruteforce_threshold,
        spray_user_threshold=args.spray_threshold,
        distributed_ip_threshold=args.distributed_threshold,
        window_minutes=args.window_minutes,
    )
    summary = summarize(events, findings)

    if args.format == "json":
        payload = {
            "tool": TOOL_NAME,
            "version": TOOL_VERSION,
            "summary": summary,
            "findings": [f.to_dict() for f in findings],
        }
        print(json.dumps(payload, indent=2))
    else:
        _print_table(summary, findings)

    return 1 if findings else 0


if __name__ == "__main__":
    sys.exit(main())
