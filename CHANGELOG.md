# Changelog

All notable changes to this project are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/);
versioning follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] — 2026-09-03

First release.

### Added

**Detection**
- Prefix-hash comparison that separates a benign append from a rewrite of
  already-written bytes — the core of the tool.
- Ten verdicts across five severities: `APPENDED`, `ROTATED`, `NEW`, `PERMS`,
  `TIMESTOMP`, `MODIFIED`, `UNREADABLE`, `TRUNCATED`, `DELETED`, `SEAL`.
- Same-size in-place rewrite detection (content is always hashed; size and
  mtime are never trusted to decide whether to read a file).
- Log-rotation heuristic, so nightly `logrotate` runs are not reported as wipes.
- Timestomping detection on any backwards `mtime`.
- Baseline sealing, with optional HMAC-SHA256 via `BASELINE_SEAL_KEY`.

**Interface**
- Commands: `init`, `check`, `watch`, `status`, `verify`, `accept`, `report`.
- Severity-mapped exit codes (0/1/2/3) for cron, systemd and monitoring agents.
- Text, JSON (ECS-shaped) and self-contained HTML output.
- Optional `<file>.md5` sidecars, verifiable with stock `md5sum -c`.

**Alerting**
- Console, JSONL file, syslog via `logger(1)`, webhook via `curl(1)`
  (Slack/Teams-compatible), and email via `mail(1)`.
- Per-finding delivery for file and syslog; one digest per scan for webhook and
  email.
- `ALERT_MIN_SEVERITY` threshold, defaulting to `LOW`.

**Platform**
- MD5 and SHA-256, resolved across `md5sum`, `md5`, `sha256sum`, `shasum` and
  `openssl`.
- GNU and BSD `stat` dialects handled behind a single shim.
- `NO_COLOR` and `FORCE_COLOR` support.

**Operations**
- `install.sh` with systemd, launchd and cron detection.
- Hardened `logsentry.service` plus a `logsentry.timer`, and a launchd plist.
- Makefile: `test`, `lint`, `syntax`, `demo`, `install`, `uninstall`.

**Quality**
- 73-assertion test suite in pure Bash, no framework required.
- GitHub Actions CI on Ubuntu and macOS, plus ShellCheck.
- Configuration is parsed rather than sourced, with a regression test proving
  command substitution in a config file is never executed.

**Documentation**
- README, and four deep-dive documents: detection logic, architecture and
  threat model, usage reference, and an incident-response runbook.
- `demo/demo.sh`, a sandboxed five-scene attack walkthrough.

[1.0.0]: https://github.com/Dc0der-X/Log-File-Integrity-Monitor/releases/tag/v1.0.0
