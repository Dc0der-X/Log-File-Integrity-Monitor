#!/usr/bin/env bash
#
# run_tests.sh — LogSentry's test suite.
#
# A miniature TAP-ish harness in pure Bash: no bats, no shunit2, nothing to
# install. Each test gets a private scratch directory and a private state
# directory, so tests cannot see each other's baselines.
#
#   ./tests/run_tests.sh            run everything
#   ./tests/run_tests.sh append     run tests whose name matches "append"
#
# Exit status is 0 only when every test passes.

set -u

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LOGSENTRY="$ROOT/bin/logsentry"
FILTER="${1:-}"

if [ -t 1 ] && [ -z "${NO_COLOR:-}" ]; then
  G=$'\033[32m'; R=$'\033[31m'; Y=$'\033[33m'; D=$'\033[2m'; B=$'\033[1m'; Z=$'\033[0m'
else
  G='' R='' Y='' D='' B='' Z=''
fi

PASS=0; FAIL=0; SKIP=0
FAILED_NAMES=""

SUITE_TMP=$(mktemp -d /tmp/logsentry-tests.XXXXXX)
trap 'rm -rf "$SUITE_TMP"' EXIT INT TERM

# --- Harness ---------------------------------------------------------------

# setup — fresh log dir + state dir for the test that is about to run.
setup() {
  T="$SUITE_TMP/$(printf '%s' "$CURRENT_TEST" | tr -c 'a-zA-Z0-9' '_')"
  LOGS="$T/logs"; STATE="$T/state"
  rm -rf "$T"; mkdir -p "$LOGS" "$STATE"
}

# sentry <args…> — invoke the tool against this test's sandbox.
sentry() { "$LOGSENTRY" "$@" -s "$STATE" -p "$LOGS" 2>/dev/null; }

# Capture both the report text and the exit code of a check.
check() { OUT=$(sentry check --all); RC=$?; }

ok()   { PASS=$((PASS+1)); printf '  %s✓%s %s\n' "$G" "$Z" "$1"; }
no()   { FAIL=$((FAIL+1)); FAILED_NAMES="${FAILED_NAMES}  · ${CURRENT_TEST}: $1"$'\n'
         printf '  %s✗%s %s\n' "$R" "$Z" "$1"; }

assert_contains() {
  case "$OUT" in
    *"$1"*) ok "output contains \"$1\"" ;;
    *) no "expected \"$1\" in output"
       printf '%s      ── actual output ──\n%s%s\n' "$D" "$OUT" "$Z" ;;
  esac
}

assert_not_contains() {
  case "$OUT" in
    *"$1"*) no "did NOT expect \"$1\" in output"
            printf '%s      ── actual output ──\n%s%s\n' "$D" "$OUT" "$Z" ;;
    *) ok "output excludes \"$1\"" ;;
  esac
}

assert_rc() {
  if [ "$RC" = "$1" ]; then ok "exit code $1"
  else no "expected exit code $1, got $RC"; fi
}

assert_true() {
  if eval "$1"; then ok "$2"; else no "$2"; fi
}

# --- Fixtures --------------------------------------------------------------

seed_logs() {
  cat > "$LOGS/auth.log" <<'EOF'
Sep  3 09:14:02 web01 sshd[2841]: Accepted publickey for deploy from 10.0.3.14
Sep  3 10:03:11 web01 sshd[3120]: Failed password for admin from 203.0.113.77
Sep  3 10:07:55 web01 sshd[3140]: Accepted password for root from 203.0.113.77
EOF
  cat > "$LOGS/syslog" <<'EOF'
Sep  3 09:00:01 web01 CRON[2201]: (root) CMD (/usr/local/bin/backup.sh)
Sep  3 09:15:30 web01 systemd[1]: Started Application Service.
EOF
}

baseline() { sentry init -y >/dev/null 2>&1; }

# ===========================================================================
# Tests
# ===========================================================================

test_baseline_creates_state() {
  setup; seed_logs; baseline
  assert_true '[ -f "$STATE/baseline.db" ]' "baseline.db is written"
  assert_true '[ -f "$STATE/baseline.seal" ]' "baseline.seal is written"
  assert_true '[ "$(grep -vc "^#" "$STATE/baseline.db")" = "2" ]' "baseline holds 2 records"
}

test_clean_check_is_exit_zero() {
  setup; seed_logs; baseline
  check
  assert_rc 0
  assert_contains "OK"
  assert_not_contains "MODIFIED"
}

test_append_is_info_not_alert() {
  # The core false-positive test. Log files grow constantly; if a plain append
  # produced anything above INFO the tool would be unusable in production.
  setup; seed_logs; baseline
  printf 'Sep  3 11:41:09 web01 sshd[3390]: Accepted publickey for deploy\n' >> "$LOGS/auth.log"
  check
  assert_contains "APPENDED"
  assert_contains "INFO"
  assert_not_contains "MODIFIED"
  assert_rc 0
}

test_inplace_edit_same_size_is_high() {
  # The core true-positive test: identical byte count, different content.
  # Anything that compares only size and mtime fails this.
  setup; seed_logs; baseline
  awk '
    index($0, "Accepted password for root") > 0 {
      r = "Sep  3 10:07:55 web01 sshd[3140]: Connection closed by 198.51.100.9"
      while (length(r) < length($0)) r = r " "
      $0 = substr(r, 1, length($0))
    } { print }' "$LOGS/auth.log" > "$T/tmp" && mv "$T/tmp" "$LOGS/auth.log"
  check
  assert_contains "MODIFIED"
  assert_contains "HIGH"
  assert_rc 2
}

test_append_that_rewrites_history_is_high() {
  # Grew AND altered earlier bytes. Size went up, so a naive "size increased,
  # must be an append" shortcut would wave this through.
  setup; seed_logs; baseline
  base_size=$(wc -c < "$LOGS/auth.log" | tr -d ' ')
  printf 'Sep  3 10:07:55 web01 sshd[3140]: Connection closed by 198.51.100.9\n' > "$LOGS/auth.log"
  # Grow past the baseline size so the "it got bigger, must be an append"
  # shortcut would wave this through.
  while [ "$(wc -c < "$LOGS/auth.log" | tr -d ' ')" -le "$base_size" ]; do
    printf 'Sep  3 12:00:00 web01 sshd[9999]: fabricated filler line\n' >> "$LOGS/auth.log"
  done
  check
  assert_contains "MODIFIED"
  assert_rc 2
}

test_truncation_is_critical() {
  setup; seed_logs; baseline
  : > "$LOGS/auth.log"
  check
  assert_contains "TRUNCATED"
  assert_contains "CRITICAL"
  assert_rc 3
}

test_partial_truncation_is_critical() {
  # Deleting only the incriminating lines, not the whole file.
  setup; seed_logs; baseline
  grep -v "Accepted password for root" "$LOGS/auth.log" > "$T/tmp" && mv "$T/tmp" "$LOGS/auth.log"
  check
  assert_contains "TRUNCATED"
  assert_rc 3
}

test_deletion_is_critical() {
  setup; seed_logs; baseline
  rm -f "$LOGS/syslog"
  check
  assert_contains "DELETED"
  assert_rc 3
}

test_new_file_is_low() {
  setup; seed_logs; baseline
  printf 'beacon\n' > "$LOGS/.implant.log"
  check
  assert_contains "NEW"
  assert_contains "LOW"
  assert_rc 1
}

test_permission_change_is_medium() {
  setup; seed_logs; baseline
  chmod 666 "$LOGS/auth.log"
  check
  assert_contains "PERMS"
  assert_contains "MEDIUM"
}

test_backdated_mtime_is_timestomp() {
  setup; seed_logs; baseline
  touch -t 202001010000 "$LOGS/syslog"
  check
  assert_contains "TIMESTOMP"
}

test_rotation_is_not_a_wipe() {
  # logrotate: move the file aside and start a fresh, smaller one. Without the
  # rotation heuristic this is indistinguishable from a partial log wipe.
  setup; seed_logs; baseline
  mv "$LOGS/auth.log" "$LOGS/auth.log.1"
  printf 'Sep  4 00:00:01 web01 rsyslogd: rotated\n' > "$LOGS/auth.log"
  check
  assert_contains "ROTATED"
  assert_not_contains "TRUNCATED"
}

test_baseline_seal_detects_edited_baseline() {
  # The attacker rewrites the baseline so their log edit looks legitimate.
  setup; seed_logs; baseline
  printf 'Sep  3 10:07:55 web01 sshd: nothing to see here\n' > "$LOGS/auth.log"
  # Forge a matching baseline record by hand.
  sed -i.bak "s|^[0-9a-f]*\(.*auth.log\)$|00000000000000000000000000000000\1|" "$STATE/baseline.db" 2>/dev/null
  rm -f "$STATE/baseline.db.bak"
  # verify reports on stderr, so merge the streams here.
  OUT=$("$LOGSENTRY" verify -s "$STATE" -p "$LOGS" 2>&1); RC=$?
  assert_contains "SEAL BROKEN"
  assert_rc 3
}

test_seal_intact_on_untouched_baseline() {
  setup; seed_logs; baseline
  OUT=$(sentry verify 2>&1); RC=$?
  assert_rc 0
}

test_accept_clears_findings() {
  setup; seed_logs; baseline
  printf 'appended\n' >> "$LOGS/auth.log"
  sentry accept -y >/dev/null 2>&1
  check
  assert_rc 0
  assert_not_contains "APPENDED"
}

test_accept_archives_previous_baseline() {
  setup; seed_logs; baseline
  printf 'appended\n' >> "$LOGS/auth.log"
  sentry accept -y >/dev/null 2>&1
  assert_true '[ -n "$(ls "$STATE"/baseline.db.* 2>/dev/null)" ]' \
    "the superseded baseline is archived as evidence"
}

test_json_output_is_wellformed() {
  setup; seed_logs; baseline
  : > "$LOGS/auth.log"
  OUT=$(sentry check --format json)
  assert_contains '"severity": "CRITICAL"'
  assert_contains '"verdict": "TRUNCATED"'
  # Validate with python3 when it happens to be present; the tool itself never
  # needs it, but if the CI runner has it we get real JSON validation for free.
  if command -v python3 >/dev/null 2>&1; then
    if printf '%s' "$OUT" | python3 -c 'import json,sys; json.load(sys.stdin)' 2>/dev/null; then
      ok "JSON parses"
    else
      no "JSON is malformed"
    fi
  else
    SKIP=$((SKIP+1)); printf '  %s-%s JSON parse check (no python3)\n' "$Y" "$Z"
  fi
}

test_json_escapes_quotes_in_paths() {
  setup; seed_logs
  printf 'x\n' > "$LOGS/we\"ird.log"
  baseline
  rm -f "$LOGS/we\"ird.log"
  OUT=$(sentry check --format json)
  assert_contains 'we\"ird.log'
  if command -v python3 >/dev/null 2>&1; then
    if printf '%s' "$OUT" | python3 -c 'import json,sys; json.load(sys.stdin)' 2>/dev/null; then
      ok "JSON with a quoted path still parses"
    else
      no "quote in a path breaks the JSON output"
    fi
  fi
}

test_html_output_is_selfcontained() {
  setup; seed_logs; baseline
  : > "$LOGS/auth.log"
  OUT=$(sentry check --format html)
  assert_contains "<!doctype html>"
  assert_contains "TAMPERING SUSPECTED"
  assert_not_contains "http://"          # no external resources
  assert_not_contains "<script"          # no JavaScript
}

test_sidecar_md5_is_md5sum_compatible() {
  # The `file.md5` sidecar must be verifiable with stock md5sum, so an analyst
  # who does not have LogSentry installed can still check a file by hand.
  setup; seed_logs
  sentry init -y --sidecar >/dev/null 2>&1
  assert_true '[ -f "$LOGS/auth.log.md5" ]' "sidecar file.md5 is written"
  if command -v md5sum >/dev/null 2>&1; then
    if (cd / && md5sum -c "$LOGS/auth.log.md5" >/dev/null 2>&1); then
      ok "md5sum -c accepts the sidecar"
    else
      no "md5sum -c rejected the sidecar"
    fi
  else
    SKIP=$((SKIP+1)); printf '  %s-%s md5sum -c check (md5sum not installed)\n' "$Y" "$Z"
  fi
}

test_sha256_algorithm_works() {
  setup; seed_logs
  sentry init -y --algo sha256 >/dev/null 2>&1
  assert_true 'grep -q "algo=SHA256" "$STATE/baseline.db"' "baseline records SHA256"
  OUT=$(sentry check --algo sha256 --all); RC=$?
  assert_rc 0
  : > "$LOGS/auth.log"
  OUT=$(sentry check --algo sha256); RC=$?
  assert_rc 3
}

test_excluded_files_are_ignored() {
  setup; seed_logs; baseline
  printf 'rotated archive\n' > "$LOGS/old.log.gz"
  check
  assert_not_contains "old.log.gz"
}

test_empty_file_is_handled() {
  # A zero-byte log must baseline and verify cleanly rather than dividing by
  # zero somewhere in the prefix logic.
  setup; : > "$LOGS/empty.log"; seed_logs; baseline
  check
  assert_rc 0
  printf 'first line ever\n' >> "$LOGS/empty.log"
  check
  assert_contains "APPENDED"
}

test_path_with_spaces() {
  setup; seed_logs
  printf 'line\n' > "$LOGS/my log file.log"
  baseline
  : > "$LOGS/my log file.log"
  check
  assert_contains "my log file.log"
  assert_contains "TRUNCATED"
}

test_unknown_config_key_is_rejected() {
  setup; seed_logs
  printf 'WATCH_PATHS=%s\nNOT_A_REAL_KEY=1\n' "$LOGS" > "$T/bad.conf"
  OUT=$("$LOGSENTRY" check -c "$T/bad.conf" -s "$STATE" 2>&1); RC=$?
  assert_contains "unknown configuration key"
  assert_rc 65
}

test_config_is_not_executed() {
  # Config parsing must never evaluate its input. If it did, this line would
  # create the marker file and hand code execution to whoever can write the
  # config — usually a lower-privileged user than the monitor itself.
  setup; seed_logs
  printf 'WATCH_PATHS=%s\nALERT_SYSLOG_TAG=$(touch %s/PWNED)\n' "$LOGS" "$T" > "$T/evil.conf"
  "$LOGSENTRY" init -y -c "$T/evil.conf" -s "$STATE" >/dev/null 2>&1
  assert_true '[ ! -f "$T/PWNED" ]' "command substitution in the config is not executed"
}

test_missing_baseline_is_a_clear_error() {
  setup; seed_logs
  OUT=$("$LOGSENTRY" check -s "$STATE" -p "$LOGS" 2>&1); RC=$?
  assert_contains "no baseline"
  assert_rc 65
}

test_unknown_command_exits_64() {
  OUT=$("$LOGSENTRY" frobnicate 2>&1); RC=$?
  assert_contains "unknown command"
  assert_rc 64
}

test_help_and_version() {
  OUT=$("$LOGSENTRY" --help 2>&1); RC=$?
  assert_contains "log file integrity monitor"
  assert_rc 0
  OUT=$("$LOGSENTRY" version 2>&1)
  assert_contains "logsentry 1."
}

test_alert_file_receives_jsonl() {
  setup; seed_logs
  printf 'WATCH_PATHS=%s\nSTATE_DIR=%s\nALERT_FILE=%s/events.jsonl\n' "$LOGS" "$STATE" "$T" > "$T/alert.conf"
  "$LOGSENTRY" init -y -c "$T/alert.conf" >/dev/null 2>&1
  : > "$LOGS/auth.log"
  "$LOGSENTRY" check -c "$T/alert.conf" >/dev/null 2>&1
  assert_true '[ -s "$T/events.jsonl" ]' "events.jsonl is written"
  OUT=$(cat "$T/events.jsonl" 2>/dev/null)
  assert_contains '"action":"TRUNCATED"'
  assert_contains '"severity":"CRITICAL"'
}

test_alert_min_severity_filters() {
  setup; seed_logs
  printf 'WATCH_PATHS=%s\nSTATE_DIR=%s\nALERT_FILE=%s/events.jsonl\nALERT_MIN_SEVERITY=HIGH\n' \
    "$LOGS" "$STATE" "$T" > "$T/alert.conf"
  "$LOGSENTRY" init -y -c "$T/alert.conf" >/dev/null 2>&1
  printf 'benign append\n' >> "$LOGS/auth.log"       # INFO — must not alert
  "$LOGSENTRY" check -c "$T/alert.conf" >/dev/null 2>&1
  assert_true '[ ! -s "$T/events.jsonl" ]' "an INFO finding does not alert at ALERT_MIN_SEVERITY=HIGH"
}

test_report_replays_last_scan() {
  setup; seed_logs; baseline
  : > "$LOGS/auth.log"
  sentry check >/dev/null 2>&1
  OUT=$(sentry report --format html)
  assert_contains "TRUNCATED"
  assert_contains "<!doctype html>"
}

test_status_reports_seal_state() {
  setup; seed_logs; baseline
  OUT=$(sentry status 2>&1); RC=$?
  assert_contains "intact"
  assert_rc 0
}

# ===========================================================================
# Runner
# ===========================================================================

printf '\n%s  LogSentry test suite%s\n' "$B" "$Z"
printf '%s  bash %s · %s%s\n\n' "$D" "${BASH_VERSION%%(*}" "$(uname -s)" "$Z"

TESTS=$(declare -F | awk '{print $3}' | grep '^test_' | sort)
for t in $TESTS; do
  if [ -n "$FILTER" ]; then
    case "$t" in *"$FILTER"*) ;; *) continue ;; esac
  fi
  CURRENT_TEST="$t"
  printf '%s%s%s\n' "$B" "${t#test_}" "$Z"
  "$t"
done

printf '\n%s  ─────────────────────────────────────────%s\n' "$D" "$Z"
if [ "$FAIL" -eq 0 ]; then
  printf '  %s%d assertions passed%s' "$G" "$PASS" "$Z"
  [ "$SKIP" -gt 0 ] && printf ', %s%d skipped%s' "$Y" "$SKIP" "$Z"
  printf '\n\n'
  exit 0
else
  printf '  %s%d passed, %d FAILED%s\n\n' "$R" "$PASS" "$FAIL" "$Z"
  printf '%s' "$FAILED_NAMES"
  printf '\n'
  exit 1
fi
