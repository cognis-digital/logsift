# Demo 01 - Basic auth-log triage

This demo runs LOGSIFT against a small, realistic SSH auth log
(`auth.log`) that contains three overlapping attack patterns plus normal
traffic. It is a defensive triage exercise only.

## What's in the log

- **Brute force**: `203.0.113.66` hammers user `root` with many failed
  passwords inside a few minutes.
- **Password spray**: `198.51.100.23` tries one failed login each against
  many different usernames (admin, oracle, postgres, git, ...).
- **Success after brute force**: `203.0.113.66` eventually gets an
  `Accepted password` for `root` -- flagged `critical` as a possible
  compromise.
- **Normal traffic**: a couple of legitimate `Accepted publickey` logins
  that should NOT be flagged.

All IPs use the RFC 5737 documentation ranges (203.0.113.0/24,
198.51.100.0/24); they are not real hosts.

## Run it

Table output:

```
python -m logsift scan demos/01-basic/auth.log
```

Machine-readable JSON (for piping into a SIEM/notebook):

```
python -m logsift scan demos/01-basic/auth.log --format json
```

## Expected result

LOGSIFT reports findings (brute force, spray, and a critical
success-after-bruteforce) and exits non-zero (`1`) because suspicious
activity was detected. With clean logs it would print "No suspicious
activity detected." and exit `0`.
