# Architecture

How LogSentry is put together, what it assumes about its environment, and which
design decisions were deliberate trade-offs rather than defaults.

---

## Design constraints

Three constraints shaped everything else.

**1. No runtime dependencies.** The moment you suspect a host is compromised,
`pip install` and `apt-get` stop being reasonable steps: the network may be
monitored, the package manager may be tampered with, and adding software to a
box you are about to image is bad practice. LogSentry runs on what is already
there — `bash`, `md5sum`/`md5`, `stat`, `awk`, `sed`, `find`, `head`. Nothing
else is required, and the CI matrix runs the suite on both GNU and BSD userland
to keep that claim honest.

**2. Portable across GNU and BSD.** Linux and macOS disagree on `stat` flags,
on whether `md5sum` exists, and on `date` arithmetic. Rather than sprinkling
`if [[ $(uname) == Darwin ]]` through the codebase, the differences are
resolved once at start-up into a set of shims.

**3. Every alert must be actionable.** A monitor that fires on routine activity
gets muted, and a muted monitor is worse than none — it produces the feeling of
coverage without the fact of it. This drove the entire severity model and the
append/rewrite distinction.

## Component layout

```
bin/logsentry              CLI: arg parsing, command dispatch, exit codes
│
├── lib/common.sh          Portability shims · logging · safe config parsing
│                          ls_hash_prefix()  ← the core primitive
├── lib/baseline.sh        Baseline record format, I/O, sealing
├── lib/detect.sh          Classification engine · ls_classify() · ls_scan()
├── lib/alert.sh           Dispatch: console, file, syslog, webhook, email
└── lib/report.sh          Renderers: text, JSON, HTML
```

The libraries are sourced, not executed, and hold no global state beyond the
configuration variables and the scan counters. `bin/logsentry` resolves symlinks
to find `lib/` so that `/usr/local/bin/logsentry` can point back into a checkout.

## Data flow

```
  config file ─┐
  CLI flags   ─┼─► ls_bootstrap()  resolve config, detect stat/hash dialects
  defaults    ─┘         │
                         ▼
                  ls_expand_targets()      globs, dirs, excludes, symlinks
                         │
              ┌──────────┴──────────┐
              ▼                     ▼
        init: ls_record()     check: ls_scan()
              │                     │
              │            ┌────────┴────────┐
              ▼            ▼                 ▼
        baseline.db   ls_classify()    (pass 2) files not in the baseline
        baseline.seal      │
                           ▼
                       ls_emit()          one TSV line per finding
                           │
                    ┌──────┴──────┐
                    ▼             ▼
             ls_report_*()   ls_dispatch_alerts()
             text/json/html   console · file · syslog · webhook · email
                    │
                    ▼
                exit code = highest severity found
```

Every finding funnels through `ls_emit()` into a single scan buffer. Both the
renderers and the alert dispatcher read that same buffer, so a finding can never
appear in the JSON output and be missing from the HTML, or reach syslog without
appearing on the console. One source of truth per scan.

## The baseline format

Tab-separated, with a commented header:

```
#!logsentry-baseline v1
# created_at=2026-09-03T09:56:29Z
# host=web01
# algo=MD5
# generator=logsentry/1.0.0
# fields=hash	size	mtime	inode	mode	owner	group	path
4f3a…9c	517	1756893989	8624417	644	root	adm	/var/log/auth.log
```

**Path is the last field, deliberately.** Filenames on Linux may contain tab
characters, and a path chosen to break a naive parser is a plausible evasion
attempt. Because `read` assigns the unsplit remainder of a line to its final
variable, a tabbed path is reconstructed intact:

```bash
IFS=$'\t' read -r hash size mtime inode mode owner group path <<<"$line"
```

Plain text was chosen over a binary format for one reason: during an incident
you want to be able to `grep` the baseline, diff two of them, and read it over
someone's shoulder on a console. There is a test for spaces in paths
(`path_with_spaces`) and for quotes in paths in the JSON output
(`json_escapes_quotes_in_paths`).

### Sidecar `.md5` files

With `SIDECAR_MD5=1`, LogSentry also writes `<file>.md5` next to each monitored
file, in exactly the format `md5sum -c` expects:

```
4f3a9c2e1b7d5a8f0c3e6b9d2a5f8c1e  /var/log/auth.log
```

This keeps the tool interoperable with the manual workflow analysts already
know — anyone can verify a single file by hand without LogSentry installed.
Off by default, because writing into the log directory is itself a filesystem
change and some hardened hosts audit exactly that. Verified by
`sidecar_md5_is_md5sum_compatible`.

## Threat model

### What LogSentry defends against

| Threat | Defence |
|---|---|
| Deleting incriminating log lines | Prefix hash catches the rewrite; shrink catches the deletion |
| Truncating a log to erase a session | `TRUNCATED`, CRITICAL |
| Same-length line substitution | Content is always hashed, never assumed from size/mtime |
| Backdating timestamps to hide an edit | `TIMESTOMP` on any backwards mtime |
| Deleting a log file outright | `DELETED`, CRITICAL |
| Loosening permissions to enable a later edit | `PERMS`, MEDIUM |
| Dropping a payload into the log directory | `NEW`, LOW |
| **Editing the baseline to legitimise an edit** | Baseline seal, CRITICAL on mismatch |
| Escalating privilege through the config file | Config is parsed, never sourced |

### What it does not defend against

Stated plainly, because a security tool that oversells itself is a liability:

- **Full root control of the host.** An attacker with root can stop the timer,
  delete the binary, and rewrite the baseline and its seal together. Nothing
  that runs on a box survives complete control of that box. The mitigations are
  architectural: ship the JSONL events off-host as they are written, and keep
  the seal key somewhere the host cannot reach.
- **A baseline taken after compromise.** It records the attacker's version of
  events as normal. Baseline hosts you have reason to believe are clean, and
  keep the baseline's `created_at` in mind when reading a report.
- **Events that were never logged.** Stopping `rsyslog` first leaves nothing to
  tamper with. Pair LogSentry with a check that the logging daemon is alive.
- **Kernel-level rootkits** that intercept `read()` and return the original
  content. Detecting those needs out-of-band verification — mount the disk
  read-only from a rescue environment and re-run the check there.

### The seal, and why the key placement matters

The seal is a digest of `baseline.db`, stored in `baseline.seal`. By default
that is a plain digest, which detects *accidental or careless* modification of
the baseline but not a deliberate one — an attacker who edits the baseline can
simply recompute the seal.

With `BASELINE_SEAL_KEY` set, the seal becomes an HMAC-SHA256. Now recomputing
it requires the key. **This is only meaningful if the key is not on the host:**

```bash
# From a management station, or with the key on removable media
BASELINE_SEAL_KEY=$(cat /mnt/usb/logsentry.key) logsentry check
```

A key written into `/etc/logsentry/logsentry.conf` on the monitored host buys
nothing against an attacker who already has root there. The config documents
this at the setting itself, because a security control that is silently useless
in its default configuration is worse than one that is absent.

## Design decisions

### Polling, not inotify

`inotify` gives sub-second detection on Linux. It was not chosen as the default
for four reasons:

1. **It is Linux-only.** macOS needs FSEvents, BSD needs kqueue. That is three
   implementations for the same feature, and three times the surface area for
   bugs in the part of the tool you most need to be correct.
2. **Watches are a finite resource.** `fs.inotify.max_user_watches` defaults to
   8192 on many distributions; a recursive watch over `/var/log` on a busy host
   can exhaust it, and the failure mode is *silently stopping watching*.
3. **A killed watcher is silent.** A polling check that does not run leaves a
   gap in cron logs or a failed systemd unit. A dead inotify watcher just stops
   producing events, which looks exactly like nothing happening.
4. **The threat does not require sub-second detection.** Tampering leaves
   persistent evidence in the file. A 60-second window is fine for an audit
   control; it would not be for an intrusion *prevention* system, which this is
   not.

It stays on the roadmap as a fast path *in addition to* polling, never instead
of it.

### One `stat` call per file

`stat` is forked once per file and parsed into six fields, rather than six
times:

```bash
stat -c '%s	%Y	%i	%a	%U	%G' -- "$file"     # GNU
stat -f '%z	%m	%i	%Lp	%Su	%Sg' -- "$file"    # BSD
```

On a 500-file baseline this is the difference between roughly 3000 forks and
500. Process creation dominates the runtime of any shell tool; the hashing
itself is I/O-bound and comparatively cheap.

### The config file is parsed, never sourced

`source config.sh` is the idiomatic shell approach and it is a privilege
escalation vector here. The monitor runs as root; the config lives in `/etc`.
Any misconfiguration that leaves the file writable hands root to a local user —
and the attacker whose log edits are being watched for is precisely the person
motivated to look for it.

So `ls_load_config()` reads `KEY=VALUE` pairs by hand, assigns them with
`printf -v` (no `eval`), and rejects unknown keys with a filename and line
number. Rejecting unknown keys also means a typo like `WATCH_PATH=` fails loudly
at start-up instead of silently monitoring nothing.

`config_is_not_executed` writes `ALERT_SYSLOG_TAG=$(touch $T/PWNED)` into a
config and asserts the marker file never appears.

### Diagnostics on stderr, data on stdout

`logsentry check --format json | jq` has to work. Everything advisory —
progress, warnings, errors — goes to stderr; only the report goes to stdout.

### Colour handling

Colour is disabled when stdout is not a TTY and when `NO_COLOR` is set
(<https://no-color.org>), so piping a report into a file or a SIEM never embeds
escape codes. `FORCE_COLOR` / `CLICOLOR_FORCE` override the TTY test for
`less -R`, CI logs, and the screenshot pipeline that produced the images in
this repository.

## Performance

Cost per check is `O(bytes monitored)` — every file is fully hashed, or
prefix-hashed up to the baseline size.

Rough figures, MD5, on a modern SSD:

| Monitored data | Approximate check time |
|---|---|
| 10 MB across 20 files | < 0.5 s |
| 100 MB across 50 files | ~1.5 s |
| 1 GB across 200 files | ~12 s |

If that is too much for your interval, in order of preference: raise
`CHECK_INTERVAL`; exclude the high-volume access logs and monitor the
security-relevant ones (`auth.log`, `secure`, `audit.log`, `sudo.log`) closely;
or set `MAX_FILE_SIZE` as a blunt cap. Switching to `sha256` roughly doubles
the hashing cost.

Memory use is flat regardless of file size — everything is streamed through
pipes, nothing is read into a variable.

---

**See also:** [DETECTION-LOGIC.md](DETECTION-LOGIC.md) · [USAGE.md](USAGE.md) ·
[INCIDENT-RESPONSE.md](INCIDENT-RESPONSE.md)
