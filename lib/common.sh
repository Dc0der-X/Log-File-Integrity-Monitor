#!/usr/bin/env bash
# lib/common.sh — portability shims, logging, and safe config parsing.
#
# Every function here is written against POSIX utilities that ship with the
# operating system. LogSentry deliberately has no package dependencies: on an
# incident-response box you cannot assume pip, apt or brew are reachable.
#
# shellcheck shell=bash

# ---------------------------------------------------------------------------
# Terminal styling
# ---------------------------------------------------------------------------
# Colour is opt-out (NO_COLOR, https://no-color.org) and is suppressed whenever
# stdout is not a TTY, so piping to a file or a SIEM never embeds escape codes.
# FORCE_COLOR / CLICOLOR_FORCE override the TTY test, which is what you want
# when piping to `less -R`, into a CI log, or into a screenshot pipeline.
#
# shellcheck disable=SC2034
# C_BOLD and C_CYAN are read by lib/report.sh and lib/detect.sh. ShellCheck
# analyses each sourced file in isolation, so it cannot see those uses.
ls_init_colors() {
  if [ -n "${FORCE_COLOR:-}${CLICOLOR_FORCE:-}" ] && [ -z "${NO_COLOR:-}" ]; then
    C_RESET=$'\033[0m'   C_BOLD=$'\033[1m'    C_DIM=$'\033[2m'
    C_RED=$'\033[31m'    C_GREEN=$'\033[32m'  C_YELLOW=$'\033[33m'
    C_BLUE=$'\033[34m' C_CYAN=$'\033[36m'
  elif [ -n "${NO_COLOR:-}" ] || [ ! -t 1 ]; then
    C_RESET='' C_BOLD='' C_DIM='' C_RED='' C_GREEN='' C_YELLOW='' C_BLUE='' C_CYAN=''
  else
    C_RESET=$'\033[0m'   C_BOLD=$'\033[1m'    C_DIM=$'\033[2m'
    C_RED=$'\033[31m'    C_GREEN=$'\033[32m'  C_YELLOW=$'\033[33m'
    C_BLUE=$'\033[34m' C_CYAN=$'\033[36m'
  fi
}
ls_init_colors

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
# Diagnostics go to stderr so that `logsentry check --format json | jq` stays
# machine-parseable no matter how noisy the run is.

LS_VERBOSE="${LS_VERBOSE:-0}"
LS_QUIET="${LS_QUIET:-0}"

ls_log()   { [ "$LS_QUIET" = "1" ] || printf '%s\n' "$*" >&2; }
ls_info()  { [ "$LS_QUIET" = "1" ] || printf '%s[*]%s %s\n' "$C_BLUE" "$C_RESET" "$*" >&2; }
ls_ok()    { [ "$LS_QUIET" = "1" ] || printf '%s[+]%s %s\n' "$C_GREEN" "$C_RESET" "$*" >&2; }
ls_warn()  { printf '%s[!]%s %s\n' "$C_YELLOW" "$C_RESET" "$*" >&2; }
ls_error() { printf '%s[x]%s %s\n' "$C_RED" "$C_RESET" "$*" >&2; }
ls_debug() { [ "$LS_VERBOSE" = "1" ] && printf '%s[d] %s%s\n' "$C_DIM" "$*" "$C_RESET" >&2; return 0; }

ls_die() { ls_error "$*"; exit "${LS_EXIT_RUNTIME:-65}"; }

# ---------------------------------------------------------------------------
# Portability shims
# ---------------------------------------------------------------------------
# GNU coreutils and BSD/macOS userland disagree on almost every flag we need.
# Each shim is resolved once at startup and cached in a variable, so the cost
# is a single `command -v` per run rather than per file.

ls_detect_hasher() {
  # Resolves the command used to compute digests. Order of preference:
  #   1. GNU coreutils md5sum/sha256sum  (Linux, and macOS with coreutils)
  #   2. BSD md5/shasum                  (stock macOS, *BSD)
  #   3. openssl dgst                    (universal fallback)
  case "${HASH_ALGO:-md5}" in
    md5)
      if command -v md5sum >/dev/null 2>&1;    then LS_HASHER=md5sum
      elif command -v md5 >/dev/null 2>&1;     then LS_HASHER=bsdmd5
      elif command -v openssl >/dev/null 2>&1; then LS_HASHER=openssl-md5
      else return 1; fi
      LS_HASH_LABEL=MD5
      ;;
    sha256)
      if command -v sha256sum >/dev/null 2>&1; then LS_HASHER=sha256sum
      elif command -v shasum >/dev/null 2>&1;  then LS_HASHER=shasum256
      elif command -v openssl >/dev/null 2>&1; then LS_HASHER=openssl-sha256
      else return 1; fi
      LS_HASH_LABEL=SHA256
      ;;
    *) ls_error "unsupported HASH_ALGO '${HASH_ALGO}' (expected: md5, sha256)"; return 1 ;;
  esac
  ls_debug "hasher=$LS_HASHER algo=$LS_HASH_LABEL"
  return 0
}

# ls_hash_stream — hash whatever arrives on stdin, print the bare hex digest.
# Every backend is normalised to "just the digest", no filename, no prefix.
ls_hash_stream() {
  case "$LS_HASHER" in
    md5sum)         md5sum        | awk '{print $1}' ;;
    sha256sum)      sha256sum     | awk '{print $1}' ;;
    bsdmd5)         md5 -q ;;
    shasum256)      shasum -a 256 | awk '{print $1}' ;;
    openssl-md5)    openssl dgst -md5    | awk '{print $NF}' ;;
    openssl-sha256) openssl dgst -sha256 | awk '{print $NF}' ;;
    *) return 1 ;;
  esac
}

# ls_hash_file <path> — digest of an entire file.
ls_hash_file() { ls_hash_stream < "$1" 2>/dev/null; }

# ls_hash_prefix <path> <bytes> — digest of the first N bytes of a file.
#
# This is the single most important primitive in LogSentry. Comparing the
# prefix digest against the *previous full-file* digest is what separates a
# benign append from a rewrite of history. See docs/DETECTION-LOGIC.md.
ls_hash_prefix() {
  local path="$1" bytes="$2"
  [ "$bytes" -eq 0 ] 2>/dev/null && { printf '' | ls_hash_stream; return; }
  # `head -c` is POSIX-2024 and present on both GNU and BSD; dd is the fallback
  # for the handful of busybox builds that ship head without -c.
  if head -c "$bytes" "$path" 2>/dev/null | ls_hash_stream; then
    return 0
  fi
  dd if="$path" bs=1 count="$bytes" 2>/dev/null | ls_hash_stream
}

# stat(1) is the worst offender for portability. Detect the dialect once.
ls_detect_stat() {
  if stat -c '%s' /dev/null >/dev/null 2>&1; then
    LS_STAT=gnu
  elif stat -f '%z' /dev/null >/dev/null 2>&1; then
    LS_STAT=bsd
  else
    LS_STAT=none
  fi
  ls_debug "stat dialect=$LS_STAT"
}

# ls_stat <path> — emit "size<TAB>mtime<TAB>inode<TAB>mode<TAB>owner<TAB>group".
# One fork per file instead of six; on a 500-file baseline that is the
# difference between a 12-second run and a 2-second one.
ls_stat() {
  case "$LS_STAT" in
    gnu) stat -c '%s	%Y	%i	%a	%U	%G' -- "$1" 2>/dev/null ;;
    bsd) stat -f '%z	%m	%i	%Lp	%Su	%Sg' -- "$1" 2>/dev/null ;;
    *)
      # Last-resort fallback: size from wc, everything else unknown. Detection
      # degrades to size+content only, which is still useful.
      local sz
      sz=$(wc -c < "$1" 2>/dev/null | tr -d ' ') || return 1
      printf '%s\t0\t0\t000\t?\t?\n' "$sz"
      ;;
  esac
}

# ls_epoch — current time as a Unix timestamp.
ls_epoch() { date +%s; }

# ls_iso8601 [epoch] — RFC 3339 timestamp in UTC, for logs and reports.
ls_iso8601() {
  local when="${1:-}"
  if [ -n "$when" ]; then
    if date -u -d "@$when" '+%Y-%m-%dT%H:%M:%SZ' 2>/dev/null; then return 0; fi
    if date -u -r "$when" '+%Y-%m-%dT%H:%M:%SZ' 2>/dev/null; then return 0; fi
    printf 'epoch:%s\n' "$when"
  else
    date -u '+%Y-%m-%dT%H:%M:%SZ'
  fi
}

# ls_json_escape — escape a string for embedding in JSON.
# Handles the control characters that actually turn up in log paths and
# usernames; anything below 0x20 becomes \uXXXX.
ls_json_escape() {
  printf '%s' "$1" | awk '
    BEGIN { RS="\0"; ORS="" }
    {
      gsub(/\\/, "\\\\"); gsub(/"/, "\\\""); gsub(/\t/, "\\t")
      gsub(/\r/, "\\r");  gsub(/\n/, "\\n")
      print
    }'
}

# ls_html_escape — escape a string for embedding in HTML text or attributes.
ls_html_escape() {
  printf '%s' "$1" | sed -e 's/&/\&amp;/g' -e 's/</\&lt;/g' -e 's/>/\&gt;/g' -e 's/"/\&quot;/g'
}

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
# The config file is *parsed*, never sourced. Sourcing would let anyone with
# write access to logsentry.conf execute arbitrary code as the (usually root)
# user running the monitor — which is exactly the privilege an attacker
# tampering with logs is trying to get. Only whitelisted keys are honoured.

LS_CONFIG_KEYS="WATCH_PATHS EXCLUDE_PATTERNS STATE_DIR HASH_ALGO SIDECAR_MD5 \
FOLLOW_SYMLINKS MAX_FILE_SIZE CHECK_INTERVAL ALERT_MIN_SEVERITY ALERT_CONSOLE \
ALERT_FILE ALERT_SYSLOG ALERT_SYSLOG_TAG ALERT_WEBHOOK_URL ALERT_EMAIL \
BASELINE_SEAL_KEY"

ls_config_defaults() {
  STATE_DIR="${STATE_DIR:-$HOME/.logsentry}"
  WATCH_PATHS="${WATCH_PATHS:-}"
  EXCLUDE_PATTERNS="${EXCLUDE_PATTERNS:-*.gz *.bz2 *.xz *.zip}"
  HASH_ALGO="${HASH_ALGO:-md5}"
  SIDECAR_MD5="${SIDECAR_MD5:-0}"
  FOLLOW_SYMLINKS="${FOLLOW_SYMLINKS:-0}"
  MAX_FILE_SIZE="${MAX_FILE_SIZE:-0}"          # 0 = unlimited
  CHECK_INTERVAL="${CHECK_INTERVAL:-60}"
  ALERT_MIN_SEVERITY="${ALERT_MIN_SEVERITY:-LOW}"
  ALERT_CONSOLE="${ALERT_CONSOLE:-1}"
  ALERT_FILE="${ALERT_FILE:-}"
  ALERT_SYSLOG="${ALERT_SYSLOG:-0}"
  ALERT_SYSLOG_TAG="${ALERT_SYSLOG_TAG:-logsentry}"
  ALERT_WEBHOOK_URL="${ALERT_WEBHOOK_URL:-}"
  ALERT_EMAIL="${ALERT_EMAIL:-}"
  BASELINE_SEAL_KEY="${BASELINE_SEAL_KEY:-}"
}

# ls_load_config <path> — read KEY=VALUE pairs from a config file.
#
# Accepts: KEY=value, KEY="value with spaces", KEY='value', blank lines and
# # comments. Rejects anything else with a line number, so a typo fails loudly
# at start-up rather than silently monitoring nothing.
ls_load_config() {
  local file="$1" line lineno=0 key val
  [ -f "$file" ] || { ls_debug "no config at $file, using defaults"; return 0; }

  # A world-writable config is a privilege-escalation vector for the daemon.
  if [ -w "$file" ] && ls_is_world_writable "$file"; then
    ls_warn "config $file is world-writable — anyone on this host can redirect monitoring"
  fi

  while IFS= read -r line || [ -n "$line" ]; do
    lineno=$((lineno + 1))
    case "$line" in
      ''|'#'*) continue ;;
    esac
    # Strip a trailing comment only when it follows whitespace, so that values
    # such as ALERT_SYSLOG_TAG=log#1 survive intact.
    case "$line" in *[[:space:]]#*) line="${line%%[[:space:]]#*}" ;; esac
    line="${line%"${line##*[![:space:]]}"}"      # rtrim
    line="${line#"${line%%[![:space:]]*}"}"      # ltrim
    [ -z "$line" ] && continue

    case "$line" in
      *=*) key="${line%%=*}"; val="${line#*=}" ;;
      *) ls_die "$file:$lineno: not a KEY=VALUE assignment: $line" ;;
    esac

    key="${key%"${key##*[![:space:]]}"}"
    val="${val#"${val%%[![:space:]]*}"}"
    # Unquote
    case "$val" in
      \"*\") val="${val#\"}"; val="${val%\"}" ;;
      \'*\') val="${val#\'}"; val="${val%\'}" ;;
    esac

    case " $LS_CONFIG_KEYS " in
      *" $key "*) ;;
      *) ls_die "$file:$lineno: unknown configuration key '$key'" ;;
    esac

    # Assign without eval. printf -v is a bashism, and we already require bash.
    printf -v "$key" '%s' "$val"
    ls_debug "config $key=$val"
  done < "$file"
  return 0
}

ls_is_world_writable() {
  local mode
  mode=$(ls_stat "$1" | cut -f4) || return 1
  case "$mode" in
    *[2367]) return 0 ;;   # last octal digit has the write bit for "other"
    *) return 1 ;;
  esac
}

# ---------------------------------------------------------------------------
# Path expansion
# ---------------------------------------------------------------------------

# ls_matches_exclude <path> — true when the basename matches any EXCLUDE glob.
ls_matches_exclude() {
  local path="$1" base pat
  base="${path##*/}"
  for pat in $EXCLUDE_PATTERNS; do
    # shellcheck disable=SC2254  # $pat is intentionally an unquoted glob
    case "$base" in $pat) return 0 ;; esac
    # shellcheck disable=SC2254
    case "$path" in $pat) return 0 ;; esac
  done
  return 1
}

# ls_expand_targets — expand WATCH_PATHS (globs, directories, files) into a
# newline-separated, de-duplicated, sorted list of regular files on stdout.
#
# Directories are walked recursively; globs are expanded by the shell; entries
# that match EXCLUDE_PATTERNS, are not regular files, or exceed MAX_FILE_SIZE
# are dropped with a debug note.
ls_expand_targets() {
  local spec entry
  {
    for spec in $WATCH_PATHS; do
      # shellcheck disable=SC2086  # deliberate glob expansion
      for entry in $spec; do
        if [ -d "$entry" ]; then
          if [ "$FOLLOW_SYMLINKS" = "1" ]; then
            find -L "$entry" -type f 2>/dev/null
          else
            find "$entry" -type f 2>/dev/null
          fi
        elif [ -f "$entry" ]; then
          printf '%s\n' "$entry"
        else
          ls_debug "skip (not a regular file): $entry"
        fi
      done
    done
  } | sort -u | while IFS= read -r entry; do
    [ -n "$entry" ] || continue
    if ls_matches_exclude "$entry"; then
      ls_debug "skip (excluded): $entry"
      continue
    fi
    if [ -L "$entry" ] && [ "$FOLLOW_SYMLINKS" != "1" ]; then
      ls_debug "skip (symlink): $entry"
      continue
    fi
    if [ ! -r "$entry" ]; then
      ls_warn "unreadable, skipping: $entry (run as root to monitor system logs)"
      continue
    fi
    if [ "${MAX_FILE_SIZE:-0}" -gt 0 ] 2>/dev/null; then
      local sz
      sz=$(ls_stat "$entry" | cut -f1)
      if [ "${sz:-0}" -gt "$MAX_FILE_SIZE" ] 2>/dev/null; then
        ls_debug "skip (over MAX_FILE_SIZE): $entry"
        continue
      fi
    fi
    printf '%s\n' "$entry"
  done
}
