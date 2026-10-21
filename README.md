# 🛡️ SSH Brute-Force Detector

![Python](https://img.shields.io/badge/Python-3.8%2B-3776AB?logo=python&logoColor=white)
![Dependencies](https://img.shields.io/badge/dependencies-none-brightgreen)
![MITRE ATT&CK](https://img.shields.io/badge/MITRE%20ATT%26CK-T1110%20%7C%20T1078-red)
![License](https://img.shields.io/badge/license-MIT-blue)

A Python tool that reads Linux SSH authentication logs, finds brute-force and password-spraying attacks, and maps them to the **MITRE ATT&CK** framework.

It answers the questions an analyst asks first: *Who is attacking? How hard? Which accounts are they after? What kind of attack is it? **Did they get in?***

---

## ✨ Features

| Feature | Description |
|---|---|
| ⏱️ Sliding-window detection | Flags any IP with **5+ failed logins in 60 seconds** (both adjustable) |
| 🚨 Compromise detection | Flags an attacker that **logs in successfully** after failing (T1078 Valid Accounts) and lists it first |
| 🎯 Attack classification | Tells **password guessing** (T1110.001) apart from **password spraying** (T1110.003) |
| 👤 Default account check | Highlights targeted default usernames like `root`, `admin`, `pi` |
| 🧾 CSV export | Saves findings for spreadsheets or a SIEM |
| 🧱 Response suggestions | Prints ready-to-review `ufw` block rules for each attacker |
| 🕒 Two log formats | Supports classic syslog and newer ISO timestamps |
| 📦 No dependencies | Python standard library only |

---

## 🚀 Usage

```bash
# 1. Create a sample log to test with
python generate_sample_log.py

# 2. Run the detector
python detector.py sample_logs/auth.log

# Optional: save to CSV and show suggested firewall rules
python detector.py sample_logs/auth.log --csv findings.csv --block
```

| Option | Default | Meaning |
|---|---|---|
| `-t`, `--threshold` | `5` | Failed logins needed to flag an IP |
| `-w`, `--window` | `60` | Time window in seconds |
| `-y`, `--year` | current year | Year for syslog timestamps that don't include one |
| `--csv FILE` | – | Save findings to a CSV file |
| `--block` | off | Print suggested `ufw` block rules |

---

## 📊 Sample Output

```text
============================================================
 SSH BRUTE-FORCE DETECTION REPORT
============================================================
 Failed logins parsed : 67
 Unique source IPs    : 5
 Rule                 : >= 5 failures in 60s
 IPs flagged          : 3
 Possible compromises : 1
============================================================

[!] 198.51.100.23
    !!! POSSIBLE COMPROMISE: logged in as 'admin' at 2026-10-16 12:00:16
    Attempts      : 8 (peak 8 in 60s)
    Active        : 2026-10-16 12:00:00 -> 2026-10-16 12:00:14
    Usernames     : 1 unique (admin)
    Default accts : admin
    MITRE ATT&CK  : T1110.001 Password Guessing + T1078 Valid Accounts

[!] 203.0.113.45
    Attempts      : 40 (peak 32 in 60s)
    Active        : 2026-10-16 09:12:00 -> 2026-10-16 09:13:16
    Usernames     : 3 unique (admin, root, ubuntu)
    Default accts : admin, root, ubuntu
    MITRE ATT&CK  : T1110.001 Password Guessing

[!] 192.0.2.99
    Attempts      : 12 (peak 7 in 60s)
    Active        : 2026-10-16 10:00:00 -> 2026-10-16 10:01:50
    Usernames     : 12 unique (backup, deploy, ftp, git, guest, jenkins, oracle, pi ...)
    Default accts : ftp, guest, oracle, pi, postgres, support, test, user
    MITRE ATT&CK  : T1110.003 Password Spraying

Suggested firewall rules (review before running!):
  sudo ufw deny from 198.51.100.23
  sudo ufw deny from 203.0.113.45
  sudo ufw deny from 192.0.2.99
```

---

## 🔍 How Detection Works

1. **Parse:** regexes pull the timestamp, username, and source IP from every `Failed password` and `Accepted` login line.
2. **Group:** failures are grouped by source IP and sorted by time.
3. **Slide a window:** for each IP, the tool finds the busiest time window. If it reaches the threshold, the IP is flagged.
4. **Classify:**
   - **Under 5 usernames** → `T1110.001 Password Guessing` (many passwords against a few accounts)
   - **5 or more usernames** → `T1110.003 Password Spraying` (a few passwords across many accounts)
5. **Check for compromise:** if a flagged IP later logs in successfully, the attacker probably guessed a real password. The finding is marked **POSSIBLE COMPROMISE**, tagged `T1078 Valid Accounts`, and moved to the top of the report.

### 🧪 Test Data

`generate_sample_log.py` creates a repeatable log with five scenarios:

| Source | Scenario | Detected (default rule)? |
|---|---|---|
| `192.168.1.20` | Normal user, one typo, then logs in | ✅ Correctly ignored |
| `203.0.113.45` | Fast brute force: 40 attempts | 🚨 Flagged: Password Guessing |
| `192.0.2.99` | Password spray: 12 usernames | 🚨 Flagged: Password Spraying |
| `198.51.100.7` | Slow attacker: 1 attempt every 10 minutes | ⚠️ Missed (see below) |
| `198.51.100.23` | 8 fast failures, then a successful login | 🚨 Flagged: **Possible Compromise** |

> All attacker IPs come from ranges reserved for documentation (RFC 5737), so none belong to real people.

---

## ⚖️ Detection Trade-off

The slow attacker stays under the default rule. Widening the window catches it:

```bash
python detector.py sample_logs/auth.log --window 3600
```

```text
[!] 198.51.100.7
    Attempts      : 6 (peak 6 in 3600s)
    MITRE ATT&CK  : T1110.001 Password Guessing
```

A wider window catches stealthier attackers but also raises the risk of **false positives**, like a real user who forgets their password several times in an hour. Choosing this balance is a core part of detection engineering.

---

## 🚧 Limitations

- **Slow attacks** can slip under a short time window (shown above).
- **Syslog timestamps have no year,** so the year is assumed. Logs that span New Year may be out of order.
- **Only `Failed password` lines are read.** Other failure types, like public key or PAM errors, are not counted yet.
- **Distributed attacks** from many IPs, each staying under the threshold, are not linked together.

---

## 🗺️ Roadmap

- [ ] Live monitoring mode with automatic `ufw` blocking and an allowlist
- [ ] GeoIP lookup for flagged IPs
- [ ] Findings from a real internet-facing server
- [ ] Detection of distributed attacks across multiple IPs

---

## 📚 References

- [MITRE ATT&CK T1110: Brute Force](https://attack.mitre.org/techniques/T1110/)
- [MITRE ATT&CK T1078: Valid Accounts](https://attack.mitre.org/techniques/T1078/)
- [RFC 5737: IP Addresses Reserved for Documentation](https://www.rfc-editor.org/rfc/rfc5737)

## 📄 License

[MIT](LICENSE)

> ⚠️ Only analyze logs from systems you own or are authorized to monitor.
