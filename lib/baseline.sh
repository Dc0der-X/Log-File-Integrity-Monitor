#!/usr/bin/env bash
# lib/baseline.sh — reading, writing and sealing the integrity baseline.
#
# The baseline is a tab-separated file. Path is the LAST field so that a path
# containing a tab (legal on Linux, and a plausible evasion attempt) can still
# be recovered intact with `cut -f8-`.
#
#   1 hash   2 size   3 mtime   4 inode   5 mode   6 owner   7 group   8.. path
#
# shellcheck shell=bash

LS_BASELINE_MAGIC='#!logsentry-baseline'
LS_BASELINE_VERSION=1

ls_baseline_path() { printf '%s/baseline.db\n' "$STATE_DIR"; }
ls_seal_path()     { printf '%s/baseline.seal\n' "$STATE_DIR"; }
ls_eventlog_path() { printf '%s/events.jsonl\n' "$STATE_DIR"; }

ls_state_init() {
  mkdir -p "$STATE_DIR" || ls_die "cannot create state directory: $STATE_DIR"
  # The baseline is the tool's root of trust. If an attacker can rewrite it,
  # they can legitimise any log edit, so keep it owner-only.
  chmod 700 "$STATE_DIR" 2>/dev/null || true
}

# ---------------------------------------------------------------------------
# Record construction
# ---------------------------------------------------------------------------

# ls_record <path> — emit one baseline record for a file, or return 1.
ls_record() {
  local path="$1" meta hash
  meta=$(ls_stat "$path") || { ls_warn "stat failed: $path"; return 1; }
  hash=$(ls_hash_file "$path") || { ls_warn "hash failed: $path"; return 1; }
  [ -n "$hash" ] || { ls_warn "empty digest: $path"; return 1; }
  printf '%s\t%s\t%s\n' "$hash" "$meta" "$path"
}

# ls_write_sidecar <path> <hash> — classic `file.md5` next to the monitored
# file, in the exact format `md5sum -c` expects. This keeps LogSentry
# interoperable with the manual workflow analysts already know:
#
#     md5sum -c /var/log/auth.log.md5
#
# Off by default: writing into the log directory is itself a filesystem change,
# which some hardened hosts audit.
ls_write_sidecar() {
  local path="$1" hash="$2" dir
  dir="${path%/*}"
  [ -w "$dir" ] || { ls_debug "sidecar skipped (dir not writable): $dir"; return 0; }
  printf '%s  %s\n' "$hash" "$path" > "${path}.md5" 2>/dev/null \
    || ls_debug "sidecar write failed: ${path}.md5"
}

# ---------------------------------------------------------------------------
# Baseline I/O
# ---------------------------------------------------------------------------

# ls_baseline_build — build a complete baseline on stdout from WATCH_PATHS.
# Prints the record count to LS_RECORD_COUNT.
ls_baseline_build() {
  local target count=0 rec hash
  printf '%s v%s\n' "$LS_BASELINE_MAGIC" "$LS_BASELINE_VERSION"
  printf '# created_at=%s\n' "$(ls_iso8601)"
  printf '# host=%s\n' "$(hostname 2>/dev/null || printf 'unknown')"
  printf '# algo=%s\n' "$LS_HASH_LABEL"
  printf '# generator=logsentry/%s\n' "$LS_VERSION"
  printf '# fields=hash\tsize\tmtime\tinode\tmode\towner\tgroup\tpath\n'

  while IFS= read -r target; do
    [ -n "$target" ] || continue
    if rec=$(ls_record "$target"); then
      printf '%s\n' "$rec"
      count=$((count + 1))
      if [ "$SIDECAR_MD5" = "1" ]; then
        hash="${rec%%	*}"
        ls_write_sidecar "$target" "$hash"
      fi
    fi
  done < <(ls_expand_targets)

  printf '%s\n' "$count" > "$STATE_DIR/.last_count"
}

# ls_baseline_records <file> — strip headers/comments, emit records only.
ls_baseline_records() { grep -v '^#' "$1" 2>/dev/null; }

# ls_baseline_meta <file> <key> — read a `# key=value` header.
ls_baseline_meta() {
  sed -n "s/^# $2=//p" "$1" 2>/dev/null | head -1
}

ls_baseline_count() { ls_baseline_records "$1" | grep -c . ; }

# ---------------------------------------------------------------------------
# Sealing — tamper-evidence for the baseline itself
# ---------------------------------------------------------------------------
# An attacker who rewrites /var/log/auth.log will also try to rewrite the
# baseline so the next check comes back clean. The seal is a digest of the
# baseline, stored separately; with BASELINE_SEAL_KEY set it becomes an HMAC
# the attacker cannot recompute without the key.
#
# Store the key off-box (or on read-only media) for this to mean anything —
# see docs/ARCHITECTURE.md, "Threat model".

ls_seal_compute() {
  local file="$1"
  if [ -n "$BASELINE_SEAL_KEY" ] && command -v openssl >/dev/null 2>&1; then
    openssl dgst -sha256 -hmac "$BASELINE_SEAL_KEY" < "$file" | awk '{print $NF}'
  else
    ls_hash_file "$file"
  fi
}

ls_seal_write() {
  local file="$1" seal
  seal=$(ls_seal_compute "$file") || return 1
  {
    printf '%s\n' "$seal"
    printf '# sealed_at=%s\n' "$(ls_iso8601)"
    if [ -n "$BASELINE_SEAL_KEY" ] && command -v openssl >/dev/null 2>&1; then
      printf '# method=hmac-sha256\n'
    else
      printf '# method=%s\n' "$LS_HASH_LABEL"
    fi
  } > "$(ls_seal_path)"
  chmod 600 "$(ls_seal_path)" 2>/dev/null || true
}

# ls_seal_verify <baseline> — 0 = intact, 1 = MISMATCH, 2 = no seal on file.
ls_seal_verify() {
  local file="$1" want have
  [ -f "$(ls_seal_path)" ] || return 2
  want=$(head -1 "$(ls_seal_path)")
  have=$(ls_seal_compute "$file") || return 1
  [ "$want" = "$have" ]
}
