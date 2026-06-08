"""LOGSIFT - defensive auth-log triage.

Detects brute-force, password-spray, and anomalous authentication events
from standard auth/SSH logs. Analysis and detection only; LOGSIFT never
performs or assists any attack. It is meant to support authorized incident
triage and monitoring, in the spirit of fail2ban.
"""
from .core import (
    AuthEvent,
    Finding,
    parse_line,
    parse_lines,
    analyze,
    summarize,
)

TOOL_NAME = "logsift"
TOOL_VERSION = "1.0.0"

__all__ = [
    "AuthEvent",
    "Finding",
    "parse_line",
    "parse_lines",
    "analyze",
    "summarize",
    "TOOL_NAME",
    "TOOL_VERSION",
]
