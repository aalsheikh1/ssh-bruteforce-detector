#!/usr/bin/env python3
"""
SSH Brute-Force Detector
Parses Linux auth logs, finds failed SSH logins, and flags IPs that exceed
a failure threshold within a sliding time window.
MITRE ATT&CK: T1110 (Brute Force)
"""
import argparse
import csv
import re
from collections import defaultdict, deque
from datetime import datetime

# Matches both "Failed password for root" and "Failed password for invalid user admin"
FAILED_RE = re.compile(
    r"Failed password for (?:invalid user )?(?P<user>\S+) "
    r"from (?P<ip>[0-9a-fA-F.:]+) port \d+"
)
# Classic syslog timestamp: "Oct 16 09:12:01"
SYSLOG_TS_RE = re.compile(r"^([A-Z][a-z]{2}\s+\d{1,2} \d{2}:\d{2}:\d{2})")
# Newer ISO timestamp (Ubuntu 23.10+): "2026-10-16T09:12:01.123456+00:00"
ISO_TS_RE = re.compile(r"^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})")

DEFAULT_USERNAMES = {"root", "admin", "test", "user", "guest", "oracle",
                     "ubuntu", "pi", "postgres", "ftp", "support"}


def parse_timestamp(line, year):
    m = ISO_TS_RE.match(line)
    if m:
        return datetime.strptime(m.group(1), "%Y-%m-%dT%H:%M:%S")
    m = SYSLOG_TS_RE.match(line)
    if m:  # syslog format has no year, so we supply one
        return datetime.strptime(f"{year} {m.group(1)}", "%Y %b %d %H:%M:%S")
    return None


def parse_log(path, year):
    """Return a list of failed-login events from the log file."""
    events = []
    with open(path, encoding="utf-8", errors="replace") as f:
        for line in f:
            if "Failed password" not in line:
                continue
            match = FAILED_RE.search(line)
            ts = parse_timestamp(line, year)
            if match and ts:
                events.append({"time": ts, "ip": match["ip"], "user": match["user"]})
    return events


def detect(events, threshold, window):
    """Flag IPs with >= threshold failures inside any `window`-second span."""
    by_ip = defaultdict(list)
    for e in events:
        by_ip[e["ip"]].append(e)

    findings = []
    for ip, evs in by_ip.items():
        evs.sort(key=lambda e: e["time"])
        win, peak = deque(), 0
        for e in evs:
            win.append(e["time"])
            # Drop attempts that fell out of the time window
            while (e["time"] - win[0]).total_seconds() > window:
                win.popleft()
            peak = max(peak, len(win))

        if peak >= threshold:
            users = sorted({e["user"] for e in evs})
            # Many distinct usernames suggests spraying rather than guessing one account
            technique = "T1110.003 Password Spraying" if len(users) >= 5 else "T1110.001 Password Guessing"
            findings.append({
                "ip": ip,
                "total_attempts": len(evs),
                "peak_in_window": peak,
                "first_seen": evs[0]["time"].strftime("%Y-%m-%d %H:%M:%S"),
                "last_seen": evs[-1]["time"].strftime("%Y-%m-%d %H:%M:%S"),
                "unique_usernames": len(users),
                "usernames": ", ".join(users[:8]) + (" ..." if len(users) > 8 else ""),
                "default_accounts_targeted": ", ".join(u for u in users if u in DEFAULT_USERNAMES),
                "mitre_technique": technique,
            })
    findings.sort(key=lambda f: f["total_attempts"], reverse=True)
    return findings


def print_report(events, findings, threshold, window):
    unique_ips = len({e["ip"] for e in events})
    print("=" * 60)
    print(" SSH BRUTE-FORCE DETECTION REPORT")
    print("=" * 60)
    print(f" Failed logins parsed : {len(events)}")
    print(f" Unique source IPs    : {unique_ips}")
    print(f" Rule                 : >= {threshold} failures in {window}s")
    print(f" IPs flagged          : {len(findings)}")
    print("=" * 60)
    for f in findings:
        print(f"\n[!] {f['ip']}")
        print(f"    Attempts      : {f['total_attempts']} (peak {f['peak_in_window']} in {window}s)")
        print(f"    Active        : {f['first_seen']} -> {f['last_seen']}")
        print(f"    Usernames     : {f['unique_usernames']} unique ({f['usernames']})")
        if f["default_accounts_targeted"]:
            print(f"    Default accts : {f['default_accounts_targeted']}")
        print(f"    MITRE ATT&CK  : {f['mitre_technique']}")
    if not findings:
        print("\nNo IPs exceeded the threshold.")


def main():
    parser = argparse.ArgumentParser(description="Detect SSH brute-force attempts in auth logs.")
    parser.add_argument("logfile", help="Path to auth.log or exported SSH log")
    parser.add_argument("-t", "--threshold", type=int, default=5, help="Failures needed to flag (default 5)")
    parser.add_argument("-w", "--window", type=int, default=60, help="Time window in seconds (default 60)")
    parser.add_argument("-y", "--year", type=int, default=datetime.now().year,
                        help="Year for syslog timestamps that lack one")
    parser.add_argument("--csv", help="Also save findings to this CSV file")
    parser.add_argument("--block", action="store_true", help="Print suggested ufw block rules")
    args = parser.parse_args()

    events = parse_log(args.logfile, args.year)
    findings = detect(events, args.threshold, args.window)
    print_report(events, findings, args.threshold, args.window)

    if args.csv and findings:
        with open(args.csv, "w", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=findings[0].keys())
            writer.writeheader()
            writer.writerows(findings)
        print(f"\nFindings saved to {args.csv}")

    if args.block and findings:
        print("\nSuggested firewall rules (review before running!):")
        for f in findings:
            print(f"  sudo ufw deny from {f['ip']}")


if __name__ == "__main__":
    main()
