#!/usr/bin/env bash
#
# demo.sh — a self-contained walkthrough of LogSentry.
#
# Builds a throwaway /var/log lookalike under a temp directory, baselines it,
# then plays out four things that happen to real log files — one benign, three
# hostile — and shows what LogSentry says about each.
#
# Touches nothing outside its own scratch directory. Safe to run as a normal
# user on any machine.
#
#   ./demo/demo.sh              interactive, pauses between scenes
#   ./demo/demo.sh --fast       no pauses, for CI and for capturing output

set -u

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LOGSENTRY="$ROOT/bin/logsentry"

FAST=0
[ "${1:-}" = "--fast" ] && FAST=1

if { [ -t 1 ] || [ -n "${FORCE_COLOR:-}${CLICOLOR_FORCE:-}" ]; } && [ -z "${NO_COLOR:-}" ]; then
  B=$'\033[1m'; D=$'\033[2m'; G=$'\033[32m'; Y=$'\033[33m'; R=$'\033[31m'; C=$'\033[36m'; Z=$'\033[0m'
else
  B='' D='' G='' Y='' R='' C='' Z=''
fi

WORK=$(mktemp -d /tmp/logsentry-demo.XXXXXX)
LOGS="$WORK/var/log"
STATE="$WORK/state"
mkdir -p "$LOGS" "$STATE"
trap 'rm -rf "$WORK"' EXIT INT TERM

sentry() { "$LOGSENTRY" "$@" -s "$STATE" -p "$LOGS"; }

scene() {
  printf '\n%s┏━━ %s %s%s\n' "$B$C" "$1" "$2" "$Z"
  printf '%s┃%s   %s\n' "$C" "$Z" "$3"
  printf '%s┗━━%s\n' "$C" "$Z"
}

narrate() { printf '   %s%s%s\n' "$D" "$1" "$Z"; }
run()     { printf '\n   %s$ %s%s\n' "$B" "$1" "$Z"; shift; "$@"; }

pause() {
  [ "$FAST" = "1" ] && { sleep 0.3; return; }
  printf '\n   %s— press Enter to continue —%s' "$D" "$Z"
  read -r _ < /dev/tty 2>/dev/null || sleep 1
  printf '\n'
}

# ---------------------------------------------------------------------------
printf '\n%s  LogSentry — log file integrity monitor%s\n' "$B" "$Z"
printf '%s  A guided demo. Scratch directory: %s%s\n' "$D" "$WORK" "$Z"

# ---------------------------------------------------------------------------
scene "SETUP" "" "Create a miniature /var/log with three realistic log files."

cat > "$LOGS/auth.log" <<'LOGEOF'
Sep  3 09:14:02 web01 sshd[2841]: Accepted publickey for deploy from 10.0.3.14 port 51422 ssh2
Sep  3 09:14:02 web01 sshd[2841]: pam_unix(sshd:session): session opened for user deploy(uid=1001)
Sep  3 09:22:47 web01 sudo:   deploy : TTY=pts/0 ; PWD=/srv/app ; USER=root ; COMMAND=/usr/bin/systemctl restart app
Sep  3 10:03:11 web01 sshd[3120]: Failed password for invalid user admin from 203.0.113.77 port 44120 ssh2
Sep  3 10:03:13 web01 sshd[3120]: Failed password for invalid user admin from 203.0.113.77 port 44120 ssh2
Sep  3 10:03:15 web01 sshd[3122]: Failed password for invalid user oracle from 203.0.113.77 port 44188 ssh2
Sep  3 10:07:55 web01 sshd[3140]: Accepted password for root from 203.0.113.77 port 44902 ssh2
LOGEOF

cat > "$LOGS/syslog" <<'LOGEOF'
Sep  3 09:00:01 web01 CRON[2201]: (root) CMD (/usr/local/bin/backup.sh)
Sep  3 09:15:30 web01 systemd[1]: Started Application Service.
Sep  3 10:08:02 web01 kernel: [18422.339] audit: type=1400 apparmor="DENIED" operation="open"
LOGEOF

cat > "$LOGS/nginx-access.log" <<'LOGEOF'
10.0.3.14 - - [03/Sep/2026:09:31:02 +0000] "GET /health HTTP/1.1" 200 2
203.0.113.77 - - [03/Sep/2026:10:02:44 +0000] "GET /.env HTTP/1.1" 404 153
203.0.113.77 - - [03/Sep/2026:10:02:45 +0000] "GET /admin/ HTTP/1.1" 403 118
LOGEOF

narrate "Created auth.log, syslog and nginx-access.log."
narrate "auth.log records a brute-force from 203.0.113.77 followed by a successful root login."
pause

# ---------------------------------------------------------------------------
scene "1/5" "TAKE THE BASELINE" \
  "Hash every file and seal the result. This is the root of trust."
run "logsentry init" sentry init -y
pause

# ---------------------------------------------------------------------------
scene "2/5" "NORMAL LOGGING" \
  "A service appends new lines. This must NOT page anyone at 3am."
narrate "Appending two ordinary sshd lines to auth.log …"
cat >> "$LOGS/auth.log" <<'LOGEOF'
Sep  3 11:41:09 web01 sshd[3390]: Accepted publickey for deploy from 10.0.3.14 port 52001 ssh2
Sep  3 11:41:09 web01 sshd[3390]: pam_unix(sshd:session): session opened for user deploy(uid=1001)
LOGEOF

run "logsentry check" sentry check
printf '   %sVerdict APPENDED, severity INFO, exit code %s.%s\n' "$G" "$?" "$Z"
narrate "LogSentry re-hashed the first N bytes — the bytes that existed at baseline time —"
narrate "and proved they are untouched. Growth alone is not an incident."
printf '\n'
narrate "The analyst reviews the append, agrees it is routine, and rolls the baseline"
narrate "forward so the next check starts from today's known-good state:"
run "logsentry accept -y" sentry accept -y
pause

# ---------------------------------------------------------------------------
scene "3/5" "THE ATTACKER EDITS HISTORY" \
  "Same file size, different content: the evidence of a root login is rewritten."
narrate "The intruder replaces their own successful login line with a benign one,"
narrate "padding it to exactly the same length so a size check sees nothing."
# Rewrite the incriminating line in place, padded to exactly the original byte
# count, so that only a content hash can catch it. A size-and-mtime monitor
# sees nothing at all here. awk keeps the demo dependency-free.
awk '
  index($0, "Accepted password for root from 203.0.113.77") > 0 {
    r = "Sep  3 10:07:55 web01 sshd[3140]: Connection closed by 198.51.100.9 port 44902 [preauth]"
    while (length(r) < length($0)) r = r " "
    $0 = substr(r, 1, length($0))
  }
  { print }
' "$LOGS/auth.log" > "$LOGS/.auth.tmp" && mv "$LOGS/.auth.tmp" "$LOGS/auth.log"
touch -t 202609031007 "$LOGS/auth.log" 2>/dev/null   # and restore the mtime
narrate "Done — same byte count, mtime restored. A size-and-mtime monitor sees nothing."

run "logsentry check" sentry check
printf '   %sVerdict MODIFIED, severity HIGH.%s\n' "$R" "$Z"
narrate "The digest of the baselined region no longer matches. Log history was altered."
pause

# ---------------------------------------------------------------------------
scene "4/5" "THE LOG WIPE" \
  "Classic anti-forensics: truncate the file to erase the intrusion entirely."
narrate "Running the attacker's favourite one-liner:  : > nginx-access.log"
: > "$LOGS/nginx-access.log"

run "logsentry check" sentry check
printf '   %sVerdict TRUNCATED, severity CRITICAL.%s\n' "$R$B" "$Z"
narrate "The file shrank. Log files do not shrink on their own — only logrotate"
narrate "makes them smaller, and rotation leaves an archived copy behind, which"
narrate "LogSentry looks for before deciding this was a wipe."
pause

# ---------------------------------------------------------------------------
scene "5/5" "DELETION AND A DROPPED FILE" \
  "Remove a log outright, and drop something new into the log directory."
narrate "Deleting syslog and planting /var/log/.cache.log …"
rm -f "$LOGS/syslog"
printf 'implant beacon 203.0.113.77:4444\n' > "$LOGS/.cache.log"

run "logsentry check" sentry check
printf '   %sDELETED (CRITICAL) plus NEW (LOW) for the planted file.%s\n' "$R" "$Z"
pause

# ---------------------------------------------------------------------------
scene "REPORT" "" "Everything above, as an HTML report for the incident ticket."
run "logsentry check --format html -o report.html" \
  sentry check --format html -o "$WORK/report.html"
narrate "Self-contained HTML — no external CSS, no JavaScript, opens on an"
narrate "air-gapped forensics laptop."

printf '\n   %sJSON, for a SIEM:%s\n' "$B" "$Z"
sentry check --format json 2>/dev/null | head -14
printf '   %s…%s\n' "$D" "$Z"

# ---------------------------------------------------------------------------
printf '\n%s  ─────────────────────────────────────────────────────────────%s\n' "$D" "$Z"
printf '%s  What this demo showed%s\n' "$B" "$Z"
printf '     %sAPPEND    → INFO      %sroutine logging, no alert\n' "$G" "$Z"
printf '     %sMODIFIED  → HIGH      %scontent rewritten at the same size\n' "$Y" "$Z"
printf '     %sTRUNCATED → CRITICAL  %spartial or total log wipe\n' "$R" "$Z"
printf '     %sDELETED   → CRITICAL  %sthe file is gone\n' "$R" "$Z"
printf '     %sNEW       → LOW       %ssomething appeared in the log directory\n' "$C" "$Z"
printf '\n  %sThe distinction between the first line and the rest is the whole point.%s\n' "$D" "$Z"
printf '  %sScratch directory removed on exit.%s\n\n' "$D" "$Z"
