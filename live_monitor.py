#!/usr/bin/env python3
"""
Live SSH Brute-Force Monitor
Watches an auth log in real time, alerts when an IP exceeds the failure
threshold, flags attackers that then log in, and can block them with ufw.
MITRE ATT&CK: T1110 (Brute Force), T1078 (Valid Accounts)
"""
import argparse
import ipaddress
import os
import subprocess
import sys
import time
from collections import defaultdict, deque
from datetime import datetime

from detector import ACCEPTED_RE, FAILED_RE


def follow(path):
    """Yield new lines as they're written, like `tail -f`."""
    if path == "-":  # read from stdin, e.g. piped from journalctl -f
        yield from sys.stdin
        return
    with open(path, encoding="utf-8", errors="replace") as f:
        f.seek(0, os.SEEK_END)  # start at the end; only watch new activity
        while True:
            line = f.readline()
            if line:
                yield line
                continue
            if os.path.getsize(path) < f.tell():  # log was rotated or truncated
                f.seek(0)
            time.sleep(0.5)


def parse_allowlist(entries):
    """Turn IPs or CIDR ranges into networks. Loopback is always allowed."""
    nets = [ipaddress.ip_network("127.0.0.0/8"), ipaddress.ip_network("::1/128")]
    for entry in entries:
        nets.append(ipaddress.ip_network(entry, strict=False))
    return nets


def is_allowed(ip, allowlist):
    return any(ip in net for net in allowlist if ip.version == net.version)


def block_ip(ip):
    """Insert a ufw deny rule at the top so it wins over any existing allow rules."""
    try:
        subprocess.run(["ufw", "insert", "1", "deny", "from", str(ip)],
                       check=True, capture_output=True)
        return True
    except (subprocess.CalledProcessError, FileNotFoundError) as e:
        print(f"    [x] Block failed: {e}")
        return False


def alert(msg, alert_log):
    stamped = f"{datetime.now():%Y-%m-%d %H:%M:%S} {msg}"
    print(f"\n[!] {stamped}")
    with open(alert_log, "a") as f:
        f.write(stamped + "\n")


def main():
    p = argparse.ArgumentParser(description="Live SSH brute-force monitor")
    p.add_argument("logfile", help="Log to watch, or '-' to read from stdin")
    p.add_argument("-t", "--threshold", type=int, default=5, help="Failures needed to alert (default 5)")
    p.add_argument("-w", "--window", type=int, default=60, help="Time window in seconds (default 60)")
    p.add_argument("--block", action="store_true", help="Actually block offenders with ufw (needs root)")
    p.add_argument("--allow", nargs="*", default=[], help="IPs or CIDR ranges never to block (add your own!)")
    p.add_argument("--alert-log", default="alerts.log", help="File to record alerts in (default alerts.log)")
    args = p.parse_args()

    allowlist = parse_allowlist(args.allow)
    attempts = defaultdict(deque)  # ip -> times of recent failures
    flagged = set()                # IPs that already triggered a brute-force alert

    if args.block and hasattr(os, "geteuid") and os.geteuid() != 0:
        sys.exit("[x] --block needs root. Run with sudo.")

    print(f"[*] Watching {args.logfile}  (rule: >= {args.threshold} failures in {args.window}s)")
    print(f"[*] Blocking is {'ON' if args.block else 'OFF (dry run)'}. "
          f"Allowlisted: {', '.join(str(n) for n in allowlist)}")

    try:
        for line in follow(args.logfile):
            failed, accepted = FAILED_RE.search(line), ACCEPTED_RE.search(line)
            m = failed or accepted
            if not m:
                continue
            try:
                ip = ipaddress.ip_address(m["ip"])  # never pass unvalidated text to ufw
            except ValueError:
                continue
            user = m["user"]

            # A flagged attacker that now logs in probably guessed a real password
            if accepted:
                if ip in flagged:
                    alert(f"ALERT T1078 POSSIBLE COMPROMISE: {ip} logged in as '{user}' "
                          f"after brute force", args.alert_log)
                    print("    [i] Investigate this account now: check its sessions and change its password\n")
                continue

            now = datetime.now()
            q = attempts[ip]
            q.append(now)
            while (now - q[0]).total_seconds() > args.window:
                q.popleft()
            print(f"[-] {now:%H:%M:%S} failed login: user={user} ip={ip} ({len(q)} in window)")

            if len(q) >= args.threshold and ip not in flagged:
                flagged.add(ip)
                alert(f"ALERT T1110 brute force from {ip} ({len(q)} failures in "
                      f"{args.window}s, last user={user})", args.alert_log)
                if is_allowed(ip, allowlist):
                    print("    [i] IP is allowlisted, not blocking")
                elif not args.block:
                    print(f"    [i] Dry run: would run 'ufw insert 1 deny from {ip}'")
                elif block_ip(ip):
                    print(f"    [+] Blocked {ip} with ufw")
                print()
    except KeyboardInterrupt:
        print(f"\n[*] Stopped. {len(flagged)} IP(s) flagged. Alerts saved to {args.alert_log}")


if __name__ == "__main__":
    main()
