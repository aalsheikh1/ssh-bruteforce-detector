#!/usr/bin/env python3
"""Generate a realistic sample SSH auth.log for testing the detector."""
import os
import random
from datetime import datetime, timedelta

random.seed(42)  # same output every run, so results are reproducible
START = datetime(2026, 10, 16, 8, 0, 0)
lines = []


def log(t, msg):
    pid = random.randint(1000, 9999)
    lines.append((t, f"{t:%b} {t.day:>2} {t:%H:%M:%S} labserver sshd[{pid}]: {msg}"))


def port():
    return random.randint(30000, 65000)


# 1. Legitimate user: one typo, then a successful login
t = START + timedelta(minutes=5)
log(t, f"Failed password for alice from 192.168.1.20 port {port()} ssh2")
log(t + timedelta(seconds=8), f"Accepted password for alice from 192.168.1.20 port {port()} ssh2")

# 2. Fast brute force: 40 attempts, 1-3 seconds apart, against common accounts
t = START + timedelta(hours=1, minutes=12)
for _ in range(40):
    user = random.choice(["root", "root", "root", "admin", "ubuntu"])
    prefix = "" if user == "root" else "invalid user "
    log(t, f"Failed password for {prefix}{user} from 203.0.113.45 port {port()} ssh2")
    t += timedelta(seconds=random.randint(1, 3))

# 3. Password spray: many different usernames, about 10 seconds apart
t = START + timedelta(hours=2)
for user in ["test", "guest", "oracle", "postgres", "pi", "ftp",
             "user", "deploy", "git", "jenkins", "backup", "support"]:
    log(t, f"Failed password for invalid user {user} from 192.0.2.99 port {port()} ssh2")
    t += timedelta(seconds=10)

# 4. Slow attacker: one attempt every 10 minutes, stays under the threshold
t = START + timedelta(hours=3)
for _ in range(6):
    log(t, f"Failed password for root from 198.51.100.7 port {port()} ssh2")
    t += timedelta(minutes=10)

lines.sort(key=lambda x: x[0])
os.makedirs("sample_logs", exist_ok=True)
with open("sample_logs/auth.log", "w", newline="\n") as f:
    f.write("\n".join(line for _, line in lines) + "\n")

print(f"Wrote {len(lines)} log lines to sample_logs/auth.log")
