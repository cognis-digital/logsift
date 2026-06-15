"""Core detection engine for LOGSIFT.

Pure standard-library log parsing and statistical detection. No network,
no side effects. The engine reads auth log lines, normalizes them into
AuthEvent records, and applies threshold-based detectors for:

  * brute-force      : many failures against one (ip, user) in a window
  * password-spray   : one ip hitting many distinct users with failures
  * distributed      : one user targeted by many distinct ips (failures)
  * success-after    : a successful login from an ip that just failed a lot

All detection is defensive triage only.
"""
from __future__ import annotations

import re
from collections import defaultdict
from dataclasses import dataclass, field, asdict
from datetime import datetime, timedelta
from typing import Iterable, Optional

TOOL_NAME = "logsift"
TOOL_VERSION = "0.1.0"

# Severity ranking for stable sorting / exit logic.
SEVERITY_ORDER = {"critical": 3, "high": 2, "medium": 1, "low": 0}

# syslog month abbreviations -> month number
_MONTHS = {
    "Jan": 1, "Feb": 2, "Mar": 3, "Apr": 4, "May": 5, "Jun": 6,
    "Jul": 7, "Aug": 8, "Sep": 9, "Oct": 10, "Nov": 11, "Dec": 12,
}

# Classic syslog prefix: "Jun  8 13:22:01 host sshd[1234]: <message>"
_SYSLOG_RE = re.compile(
    r"^(?P<mon>[A-Z][a-z]{2})\s+(?P<day>\d{1,2})\s+"
    r"(?P<time>\d{2}:\d{2}:\d{2})\s+\S+\s+\S+?(?:\[\d+\])?:\s+(?P<msg>.*)$"
)

_IP_RE = re.compile(r"(?P<ip>(?:\d{1,3}\.){3}\d{1,3}|[0-9a-fA-F:]{2,})")
_USER_RE = re.compile(
    r"(?:invalid user|user)\s+(?P<user>[^\s]+)"
    r"|(?:password|publickey|keyboard-interactive)\s+for\s+(?:invalid\s+user\s+)?(?P<user2>[^\s]+)",
    re.I,
)
_FROM_RE = re.compile(r"from\s+(?P<ip>(?:\d{1,3}\.){3}\d{1,3}|[0-9a-fA-F:]{2,})")

# Outcome detection patterns (lower-cased message tested against these).
_FAIL_MARKERS = (
    "failed password",
    "authentication failure",
    "invalid user",
    "failed publickey",
    "failed none",
    "connection closed by authenticating user",
    "maximum authentication attempts exceeded",
)
_SUCCESS_MARKERS = (
    "accepted password",
    "accepted publickey",
    "accepted keyboard-interactive",
    "session opened for user",
)


@dataclass
class AuthEvent:
    """A single normalized authentication attempt."""
    ts: Optional[datetime]
    ip: Optional[str]
    user: Optional[str]
    outcome: str  # "fail" | "success" | "other"
    raw: str
    lineno: int

    def to_dict(self) -> dict:
        return {
            "ts": self.ts.isoformat() if self.ts else None,
            "ip": self.ip,
            "user": self.user,
            "outcome": self.outcome,
            "lineno": self.lineno,
            "raw": self.raw,
        }


@dataclass
class Finding:
    """A detection result."""
    kind: str
    severity: str
    ip: Optional[str]
    user: Optional[str]
    count: int
    window_seconds: Optional[int]
    first_ts: Optional[str]
    last_ts: Optional[str]
    detail: str
    sample_lines: list = field(default_factory=list)

    def to_dict(self) -> dict:
        return asdict(self)


def _classify(msg_lower: str) -> str:
    for m in _SUCCESS_MARKERS:
        if m in msg_lower:
            return "success"
    for m in _FAIL_MARKERS:
        if m in msg_lower:
            return "fail"
    return "other"


def parse_line(line: str, lineno: int = 0, year: Optional[int] = None) -> Optional[AuthEvent]:
    """Parse one log line into an AuthEvent, or None if unparseable/blank."""
    line = line.rstrip("\n")
    if not line.strip():
        return None

    ts: Optional[datetime] = None
    msg = line
    m = _SYSLOG_RE.match(line)
    if m:
        msg = m.group("msg")
        if year is None:
            year = datetime.now().year
        try:
            hh, mm, ss = (int(x) for x in m.group("time").split(":"))
            ts = datetime(
                year,
                _MONTHS[m.group("mon")],
                int(m.group("day")),
                hh, mm, ss,
            )
        except (ValueError, KeyError):
            ts = None

    msg_lower = msg.lower()
    outcome = _classify(msg_lower)

    # Prefer the "from <ip>" form; fall back to any IP-like token in message.
    ip = None
    fm = _FROM_RE.search(msg)
    if fm:
        ip = fm.group("ip")
    else:
        im = _IP_RE.search(msg)
        if im:
            ip = im.group("ip")

    user = None
    um = _USER_RE.search(msg)
    if um:
        user = um.group("user") or um.group("user2")

    return AuthEvent(ts=ts, ip=ip, user=user, outcome=outcome, raw=line, lineno=lineno)


def parse_lines(lines: Iterable[str], year: Optional[int] = None) -> list:
    """Parse an iterable of raw lines into AuthEvent records."""
    events = []
    for i, line in enumerate(lines, start=1):
        ev = parse_line(line, lineno=i, year=year)
        if ev is not None:
            events.append(ev)
    return events


def _window_count(timestamps: list, window: timedelta) -> int:
    """Max number of events falling within any sliding window of `window`.

    If timestamps are missing (None), fall back to total count.
    """
    ts = sorted(t for t in timestamps if t is not None)
    if not ts:
        return len(timestamps)
    best = 1
    start = 0
    for end in range(len(ts)):
        while ts[end] - ts[start] > window:
            start += 1
        best = max(best, end - start + 1)
    return best


def analyze(
    events: list,
    *,
    bruteforce_threshold: int = 5,
    spray_user_threshold: int = 5,
    distributed_ip_threshold: int = 5,
    window_minutes: int = 10,
) -> list:
    """Run all detectors over parsed events and return Findings."""
    window = timedelta(minutes=window_minutes)
    findings: list = []

    fails = [e for e in events if e.outcome == "fail"]
    successes = [e for e in events if e.outcome == "success"]

    # --- Brute force: failures per (ip, user) ---
    by_pair = defaultdict(list)
    for e in fails:
        by_pair[(e.ip, e.user)].append(e)
    for (ip, user), evs in by_pair.items():
        if ip is None:
            continue
        wc = _window_count([e.ts for e in evs], window)
        if wc >= bruteforce_threshold:
            sev = "critical" if wc >= bruteforce_threshold * 4 else (
                "high" if wc >= bruteforce_threshold * 2 else "medium"
            )
            findings.append(_mk_finding(
                "bruteforce", sev, ip, user, wc, window_minutes * 60, evs,
                f"{wc} failed attempts for user '{user}' from {ip} within {window_minutes}m",
            ))

    # --- Password spray: one ip, many distinct users ---
    by_ip = defaultdict(list)
    for e in fails:
        if e.ip is not None:
            by_ip[e.ip].append(e)
    for ip, evs in by_ip.items():
        users = {e.user for e in evs if e.user}
        if len(users) >= spray_user_threshold:
            sev = "high" if len(users) >= spray_user_threshold * 2 else "medium"
            findings.append(_mk_finding(
                "spray", sev, ip, None, len(users), window_minutes * 60, evs,
                f"{ip} attempted {len(users)} distinct users (password spray pattern)",
            ))

    # --- Distributed: one user, many distinct ips ---
    by_user = defaultdict(list)
    for e in fails:
        if e.user is not None:
            by_user[e.user].append(e)
    for user, evs in by_user.items():
        ips = {e.ip for e in evs if e.ip}
        if len(ips) >= distributed_ip_threshold:
            sev = "high" if len(ips) >= distributed_ip_threshold * 2 else "medium"
            findings.append(_mk_finding(
                "distributed", sev, None, user, len(ips), None, evs,
                f"user '{user}' targeted from {len(ips)} distinct IPs",
            ))

    # --- Success after many failures from same ip (possible compromise) ---
    fail_ct_by_ip = {ip: len(evs) for ip, evs in by_ip.items()}
    for e in successes:
        if e.ip and fail_ct_by_ip.get(e.ip, 0) >= bruteforce_threshold:
            ev_set = by_ip[e.ip] + [e]
            findings.append(_mk_finding(
                "success-after-bruteforce", "critical", e.ip, e.user,
                fail_ct_by_ip[e.ip], None, ev_set,
                f"successful login for '{e.user}' from {e.ip} after "
                f"{fail_ct_by_ip[e.ip]} failures (possible compromise)",
            ))

    findings.sort(
        key=lambda f: (SEVERITY_ORDER.get(f.severity, 0), f.count),
        reverse=True,
    )
    return findings


def _mk_finding(kind, severity, ip, user, count, window_seconds, evs, detail) -> Finding:
    ts_list = sorted(e.ts for e in evs if e.ts is not None)
    first_ts = ts_list[0].isoformat() if ts_list else None
    last_ts = ts_list[-1].isoformat() if ts_list else None
    samples = [e.raw for e in evs[:3]]
    return Finding(
        kind=kind, severity=severity, ip=ip, user=user, count=count,
        window_seconds=window_seconds, first_ts=first_ts, last_ts=last_ts,
        detail=detail, sample_lines=samples,
    )


def summarize(events: list, findings: list) -> dict:
    """Build a structured summary of a triage run."""
    fails = sum(1 for e in events if e.outcome == "fail")
    succ = sum(1 for e in events if e.outcome == "success")
    distinct_ips = {e.ip for e in events if e.ip}
    sev_counts = defaultdict(int)
    for f in findings:
        sev_counts[f.severity] += 1
    return {
        "events_parsed": len(events),
        "failures": fails,
        "successes": succ,
        "distinct_ips": len(distinct_ips),
        "findings": len(findings),
        "severity_counts": dict(sev_counts),
    }
