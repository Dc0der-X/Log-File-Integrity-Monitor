# Usage

Complete reference for every command and flag, plus deployment recipes and
troubleshooting.

---

## Requirements

Present on any stock Linux, macOS or BSD installation:

| Requirement | Notes |
|---|---|
| `bash` 3.2+ | macOS ships 3.2; the code avoids bash 4+ features |
| A digest tool | `md5sum` (GNU), `md5` (BSD), or `openssl` — any one |
| `stat`, `awk`, `sed`, `find`, `head`, `sort`, `grep` | POSIX; both dialects handled |
| `logger` | Optional, for `ALERT_SYSLOG` |
| `curl` | Optional, for `ALERT_WEBHOOK_URL` |
| `mail` | Optional, for `ALERT_EMAIL` |

Nothing to install. No Python, no package manager, no compiler.

## Installation

### Run from a clone

```bash
git clone https://github.com/Dc0der-X/Log-File-Integrity-Monitor.git
cd Log-File-Integrity-Monitor
./bin/logsentry help
```

### System install

```bash
sudo ./install/install.sh                # binary, libs, config, state dir
sudo ./install/install.sh --with-timer   # …and register a scheduler
sudo ./install/install.sh --uninstall    # remove (keeps config and baselines)
```

`--with-timer` detects systemd, launchd or cron and picks the right one.

Or via make:

```bash
sudo make install PREFIX=/usr/local
make help
```

### Layout after installation

```
/usr/local/bin/logsentry            Executable
/usr/local/lib/logsentry/*.sh       Libraries
/etc/logsentry/logsentry.conf       Configuration        (mode 0600)
/var/lib/logsentry/                 Baseline and state   (mode 0700)
  ├── baseline.db                   The baseline
  ├── baseline.seal                 Tamper-evidence for the baseline
  ├── baseline.db.<timestamp>       Superseded baselines, archived
  └── last_scan.tsv                 Most recent scan, for `logsentry report`
/var/log/logsentry/events.jsonl     Alert event log
```

---

## Commands

### `init` — create the baseline

```bash
logsentry init                                    # from the config
logsentry init -p /var/log/auth.log -p /var/log/syslog
logsentry init --sidecar                          # also write <file>.md5
logsentry init -y                                 # overwrite without prompting
```

Hashes every monitored file, writes `baseline.db`, and seals it. Prompts before
overwriting an existing baseline — that file is your root of trust, and
replacing it silently is not something a tool should do on your behalf.

> **Take the baseline on a host you have reason to believe is clean.** A
> baseline created after a compromise records the attacker's version of events
> as normal, and every check afterwards will agree with them.

### `check` — compare against the baseline

```bash
logsentry check                                   # human-readable
logsentry check --all                             # include unchanged files
logsentry check --format json                     # for a SIEM
logsentry check --format html -o /tmp/report.html # for a ticket
logsentry check --quiet                           # findings only, for cron
```

The main verb. Exits with the highest severity found: `0` clean, `1` low/medium,
`2` high, `3` critical.

### `watch` — continuous monitoring

```bash
logsentry watch                    # CHECK_INTERVAL from the config
logsentry watch -i 30              # every 30 seconds
```

Runs `check` on a loop. A clean pass prints a single dim heartbeat line; a pass
with findings prints the full report and fires the configured alerts. Ctrl-C to
stop.

Use this for a foreground console during an investigation. For unattended
monitoring, prefer the systemd timer — a `watch` in a terminal dies with the
SSH session.

### `status` — inspect the baseline

```bash
logsentry status
```

Shows version, config path, state directory, algorithm, baseline age, file
count, the host it was taken on, and the seal state. Exits `3` if the seal is
broken.

### `verify` — check the seal only

```bash
logsentry verify
```

Verifies that `baseline.db` still matches `baseline.seal`, and nothing else.
Fast, and the right first move when you suspect the monitoring itself has been
interfered with. Exits `0` intact, `1` no seal, `3` broken.

### `accept` — re-baseline reviewed changes

```bash
logsentry accept                   # show the changes, then confirm
logsentry accept -y                # no prompt (for automation)
```

Shows the current findings, asks for confirmation, archives the superseded
baseline as `baseline.db.<timestamp>`, and writes a new sealed one.

Use it after legitimate change — a package update that rotated logs, a
deliberate permission change, a new service writing to `/var/log`. The old
baseline is kept because during an investigation the previous root of trust is
evidence.

### `report` — re-render the last scan

```bash
logsentry report --format html -o incident-4471.html
logsentry report --format json
```

Re-renders the most recent `check` without re-hashing anything. Useful for
producing an attachment after the fact.

---

## Options

| Flag | Meaning |
|---|---|
| `-c, --config FILE` | Config file. Default: `./config/logsentry.conf`, then `/etc/logsentry/logsentry.conf` |
| `-p, --path PATH` | Monitor PATH. Repeatable. Overrides `WATCH_PATHS` entirely |
| `-s, --state DIR` | State directory. Default `~/.logsentry`, or `STATE_DIR` |
| `-f, --format FMT` | `text` (default), `json`, `html` |
| `-o, --output FILE` | Write the report to FILE instead of stdout |
| `-i, --interval SECS` | Poll interval for `watch` |
| `--algo ALGO` | `md5` (default) or `sha256` |
| `--sidecar` | Also write `<file>.md5` beside each monitored file |
| `--all` | Include unchanged files in the report |
| `-y, --yes` | Do not prompt for confirmation |
| `-v, --verbose` | Debug output on stderr |
| `-q, --quiet` | Suppress everything but findings |
| `-h, --help` | Full help text |

Precedence: **command-line flags > config file > built-in defaults.**

## Environment variables

| Variable | Effect |
|---|---|
| `LOGSENTRY_CONFIG` | Default config path |
| `BASELINE_SEAL_KEY` | HMAC key for the baseline seal — pass it at runtime, do not store it on the host |
| `NO_COLOR` | Disable colour ([no-color.org](https://no-color.org)) |
| `FORCE_COLOR` / `CLICOLOR_FORCE` | Force colour even when not a TTY |
| `TMPDIR` | Where the scan buffer is created |

---

## Deployment recipes

### systemd timer (recommended on Linux)

```bash
sudo ./install/install.sh --with-timer
systemctl status logsentry.timer
journalctl -u logsentry -f
```

The shipped unit is hardened (`ProtectSystem=strict`, `NoNewPrivileges`,
`SystemCallFilter=@system-service`) and sets `SuccessExitStatus=0 1 2 3` so a
detection is not reported as a unit failure. Findings go to syslog and
`ALERT_FILE`; the exit code is for orchestration.

Adjust the cadence in `/etc/systemd/system/logsentry.timer`:

```ini
[Timer]
OnUnitActiveSec=5min
RandomizedDelaySec=30      # stagger across a fleet
Persistent=true            # catch up after downtime
```

### cron

```cron
*/5 * * * * /usr/local/bin/logsentry check -c /etc/logsentry/logsentry.conf --quiet
```

`--quiet` keeps cron silent on a clean run and lets it mail you on findings.

### macOS launchd

```bash
sudo ./install/install.sh --with-timer     # detects launchd
sudo launchctl list | grep logsentry
```

### Nagios / Icinga style check

```bash
#!/bin/sh
out=$(/usr/local/bin/logsentry check --quiet 2>&1); rc=$?
case $rc in
  0) echo "OK - logs intact";              exit 0 ;;
  1) echo "WARNING - $out";                exit 1 ;;
  2|3) echo "CRITICAL - $out";             exit 2 ;;
  *) echo "UNKNOWN - logsentry rc=$rc";    exit 3 ;;
esac
```

### Shipping events to Elasticsearch

`ALERT_FILE` writes ECS-shaped JSONL. Point Filebeat at it:

```yaml
filebeat.inputs:
  - type: log
    paths: ["/var/log/logsentry/events.jsonl"]
    json.keys_under_root: true
    json.add_error_key: true
```

### Slack

```bash
ALERT_WEBHOOK_URL=https://hooks.slack.com/services/XXX/YYY/ZZZ
ALERT_MIN_SEVERITY=MEDIUM
```

One digest message per scan, not one per file.

### Ansible

```yaml
- name: Deploy LogSentry
  block:
    - copy: { src: bin/logsentry, dest: /usr/local/bin/logsentry, mode: "0755" }
    - copy: { src: lib/, dest: /usr/local/lib/logsentry/, mode: "0644" }
    - template: { src: logsentry.conf.j2, dest: /etc/logsentry/logsentry.conf, mode: "0600" }
    - file: { path: /var/lib/logsentry, state: directory, mode: "0700" }
    - command: logsentry init -y
      args: { creates: /var/lib/logsentry/baseline.db }
    - systemd: { name: logsentry.timer, enabled: yes, state: started }
```

The `creates:` guard matters — re-running `init` on every play would rebuild
the baseline from whatever is on disk at that moment, including an attacker's
edits.

---

## Troubleshooting

**`no files to monitor`**
`WATCH_PATHS` is empty and no `-p` was given. Set one or the other.

**`unreadable, skipping: /var/log/auth.log`**
On most distributions `auth.log` is `root:adm 640`. Run as root, or add your
user to the `adm` group.

**`unknown configuration key 'WATCH_PATH'`**
A typo. Unknown keys are rejected on purpose — silently ignoring them would
mean silently monitoring nothing. The error names the file and line.

**Alerts on every logrotate run**
Rotation should be classified `ROTATED`, INFO. If it is coming through as
`TRUNCATED`, the archived copy is not where the heuristic looks (it checks
`file.1`, `file.0`, `file.1.gz`, `file.0.gz`, `file-*`). Run `logsentry accept`
after rotation, or see
[DETECTION-LOGIC.md § 4](DETECTION-LOGIC.md#4-the-rotation-problem).

**Checks are too slow**
Every byte is hashed. Raise `CHECK_INTERVAL`, exclude high-volume access logs
and keep the security-relevant ones, or set `MAX_FILE_SIZE`. See
[ARCHITECTURE.md § Performance](ARCHITECTURE.md#performance).

**`baseline seal BROKEN`**
`baseline.db` changed after it was sealed. If you edited it by hand, re-seal
with `logsentry init`. If you did not, treat it as an incident and go to
[INCIDENT-RESPONSE.md](INCIDENT-RESPONSE.md).

**Colour codes in a log file**
Colour is suppressed automatically when stdout is not a TTY. If you see escape
codes, something is forcing a TTY (`script`, `unbuffer`) or `FORCE_COLOR` is
set. `NO_COLOR=1` overrides everything.

**Nothing appears in `events.jsonl`**
Check that the finding meets `ALERT_MIN_SEVERITY` — at the default `LOW`,
`APPENDED` and `ROTATED` (both INFO) are intentionally not alerted. Also
confirm the directory exists and is writable by the user running the check.

---

**See also:** [DETECTION-LOGIC.md](DETECTION-LOGIC.md) ·
[ARCHITECTURE.md](ARCHITECTURE.md) · [INCIDENT-RESPONSE.md](INCIDENT-RESPONSE.md)
