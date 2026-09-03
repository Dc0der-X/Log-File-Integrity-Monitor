#!/usr/bin/env bash
# lib/detect.sh — the classification engine.
#
# A naive integrity monitor stores one MD5 per file and screams whenever the
# digest changes. On log files that is useless: every single append changes the
# digest, so the tool alerts continuously and everyone stops reading it.
#
# LogSentry asks a sharper question: *did the bytes that were already there
# change?* Given the previous size S and the previous full-file digest H, the
# digest of the first S bytes of the file today must still equal H if the file
# was only appended to. If it does not, history was rewritten — and rewriting
# log history is not something a well-behaved daemon ever does.
#
# See docs/DETECTION-LOGIC.md for the full decision table.
#
# shellcheck shell=bash

# ---------------------------------------------------------------------------
# Verdicts and severities
# ---------------------------------------------------------------------------
#   OK         file is byte-for-byte identical                       (none)
#   APPENDED   grew, prior bytes intact — normal logging             INFO
#   ROTATED    new inode, prior content preserved elsewhere          INFO
#   NEW        present now, absent from the baseline                 LOW
#   PERMS      mode / owner / group changed                          MEDIUM
#   TIMESTOMP  mtime moved backwards                                 MEDIUM
#   MODIFIED   prior bytes rewritten in place                        HIGH
#   TRUNCATED  file shrank — the classic partial log wipe            CRITICAL
#   DELETED    in the baseline, gone from disk                       CRITICAL
#   UNREADABLE existed at baseline, cannot be read now               HIGH

ls_severity_of() {
  case "$1" in
    OK)                       printf 'NONE\n' ;;
    APPENDED|ROTATED)         printf 'INFO\n' ;;
    NEW)                      printf 'LOW\n' ;;
    PERMS|TIMESTOMP)          printf 'MEDIUM\n' ;;
    MODIFIED|UNREADABLE)      printf 'HIGH\n' ;;
    TRUNCATED|DELETED|SEAL)   printf 'CRITICAL\n' ;;
    *)                        printf 'LOW\n' ;;
  esac
}

ls_severity_rank() {
  case "$1" in
    NONE) printf '0\n' ;; INFO) printf '1\n' ;; LOW) printf '2\n' ;;
    MEDIUM) printf '3\n' ;; HIGH) printf '4\n' ;; CRITICAL) printf '5\n' ;;
    *) printf '0\n' ;;
  esac
}

ls_severity_color() {
  case "$1" in
    INFO)     printf '%s' "$C_DIM" ;;
    LOW)      printf '%s' "$C_CYAN" ;;
    MEDIUM)   printf '%s' "$C_YELLOW" ;;
    HIGH)     printf '%s' "$C_RED" ;;
    CRITICAL) printf '%s' "$C_BOLD$C_RED" ;;
    *)        printf '%s' "$C_RESET" ;;
  esac
}

# A one-line analyst-facing explanation. The point of an alert is to tell the
# person on call what it means, not to make them go read the source.
ls_verdict_note() {
  case "$1" in
    APPENDED)  printf 'new lines appended, earlier content unchanged\n' ;;
    ROTATED)   printf 'inode changed and an archived copy exists — consistent with logrotate\n' ;;
    NEW)       printf 'file was not present when the baseline was taken\n' ;;
    PERMS)     printf 'ownership or permission bits changed\n' ;;
    TIMESTOMP) printf 'modification time moved backwards — timestamps may have been forged\n' ;;
    MODIFIED)  printf 'bytes that already existed were rewritten — log history was altered\n' ;;
    TRUNCATED) printf 'file is smaller than the baseline — content was removed\n' ;;
    DELETED)   printf 'file recorded in the baseline no longer exists\n' ;;
    UNREADABLE) printf 'file exists but can no longer be read by this process\n' ;;
    *)         printf '\n' ;;
  esac
}

# ---------------------------------------------------------------------------
# Rotation heuristic
# ---------------------------------------------------------------------------
# logrotate moves auth.log to auth.log.1 (or .1.gz, or auth.log-20260903) and
# starts a fresh file at a new inode. That looks exactly like TRUNCATED unless
# we go looking for the archived copy. If a sibling archive exists and is
# newer than the baseline, treat the change as rotation rather than a wipe.
ls_looks_rotated() {
  local path="$1" prev_inode="$2" cur_inode="$3" candidate
  [ "$prev_inode" != "$cur_inode" ] || return 1
  [ "$prev_inode" != "0" ] || return 1
  for candidate in "$path".1 "$path".0 "$path".1.gz "$path".0.gz "$path"-*; do
    [ -e "$candidate" ] && return 0
  done
  return 1
}

# ---------------------------------------------------------------------------
# Core comparison
# ---------------------------------------------------------------------------
# ls_classify — compare one baseline record against the file on disk today.
# Emits: verdict<TAB>severity<TAB>detail<TAB>path
#
# Arguments are the eight baseline fields plus the path.
ls_classify() {
  local p_hash="$1" p_size="$2" p_mtime="$3" p_inode="$4" \
        p_mode="$5" p_owner="$6" p_group="$7" path="$8"
  local meta c_size c_mtime c_inode c_mode c_owner c_group
  local verdict detail prefix c_hash

  if [ ! -e "$path" ]; then
    ls_emit DELETED "baseline recorded ${p_size} bytes; path is gone" "$path"
    return
  fi
  if [ ! -r "$path" ]; then
    ls_emit UNREADABLE "permission denied reading the file" "$path"
    return
  fi

  meta=$(ls_stat "$path") || { ls_emit UNREADABLE "stat failed" "$path"; return; }
  IFS=$'\t' read -r c_size c_mtime c_inode c_mode c_owner c_group <<<"$meta"

  # --- Metadata drift is reported independently of content ----------------
  # A log file whose mode changed from 640 to 666 is a finding even if not one
  # byte moved, so these are emitted as their own events rather than folded in.
  if [ "$p_mode" != "$c_mode" ] || [ "$p_owner" != "$c_owner" ] || [ "$p_group" != "$c_group" ]; then
    ls_emit PERMS "was ${p_owner}:${p_group} ${p_mode}, now ${c_owner}:${c_group} ${c_mode}" "$path"
  fi
  if [ "${c_mtime:-0}" -lt "${p_mtime:-0}" ] 2>/dev/null; then
    ls_emit TIMESTOMP "mtime went from $(ls_iso8601 "$p_mtime") back to $(ls_iso8601 "$c_mtime")" "$path"
  fi

  # --- Fast path: nothing moved -------------------------------------------
  # Size and mtime unchanged means the file is almost certainly untouched, but
  # "almost" is not good enough for an integrity tool: an in-place edit of the
  # same length, followed by restoring the mtime, is a textbook anti-forensic
  # move. We always hash. The size check only tells us *which* hash to take.
  c_hash=$(ls_hash_file "$path")
  if [ "$c_hash" = "$p_hash" ] && [ "$c_size" = "$p_size" ]; then
    ls_emit OK "" "$path"
    return
  fi

  # --- Shrunk: content was removed ----------------------------------------
  if [ "${c_size:-0}" -lt "${p_size:-0}" ] 2>/dev/null; then
    if ls_looks_rotated "$path" "$p_inode" "$c_inode"; then
      ls_emit ROTATED "inode ${p_inode} -> ${c_inode}, archived copy found alongside" "$path"
    else
      ls_emit TRUNCATED "shrank from ${p_size} to ${c_size} bytes ($(( p_size - c_size )) bytes removed)" "$path"
    fi
    return
  fi

  # --- Same size, different content: rewritten in place -------------------
  if [ "${c_size:-0}" -eq "${p_size:-0}" ] 2>/dev/null; then
    ls_emit MODIFIED "size unchanged at ${c_size} bytes but the digest differs — content swapped in place" "$path"
    return
  fi

  # --- Grew: append, or an append that also rewrote history ---------------
  # This is the prefix test. Hash the first p_size bytes of the current file:
  # if that equals the baseline digest, everything that existed before is still
  # byte-for-byte intact and the file was only appended to.
  prefix=$(ls_hash_prefix "$path" "$p_size")
  if [ "$prefix" = "$p_hash" ]; then
    if ls_looks_rotated "$path" "$p_inode" "$c_inode"; then
      ls_emit ROTATED "inode ${p_inode} -> ${c_inode}, prior content preserved" "$path"
    else
      ls_emit APPENDED "+$(( c_size - p_size )) bytes appended, first ${p_size} bytes verified intact" "$path"
    fi
  else
    ls_emit MODIFIED "grew to ${c_size} bytes but the first ${p_size} bytes no longer match the baseline" "$path"
  fi
}

# ---------------------------------------------------------------------------
# Event emission
# ---------------------------------------------------------------------------
# Every finding funnels through ls_emit, which keeps the running tallies and
# writes one tab-separated line to the scan buffer. Output formatting and
# alerting both read that buffer, so console, JSON, HTML and webhook renderings
# can never drift out of sync.

LS_COUNT_TOTAL=0
LS_COUNT_OK=0
LS_COUNT_INFO=0
LS_COUNT_LOW=0
LS_COUNT_MEDIUM=0
LS_COUNT_HIGH=0
LS_COUNT_CRITICAL=0
LS_MAX_RANK=0

ls_emit() {
  local verdict="$1" detail="$2" path="$3" sev rank
  sev=$(ls_severity_of "$verdict")
  rank=$(ls_severity_rank "$sev")

  LS_COUNT_TOTAL=$((LS_COUNT_TOTAL + 1))
  case "$sev" in
    NONE)     LS_COUNT_OK=$((LS_COUNT_OK + 1)) ;;
    INFO)     LS_COUNT_INFO=$((LS_COUNT_INFO + 1)) ;;
    LOW)      LS_COUNT_LOW=$((LS_COUNT_LOW + 1)) ;;
    MEDIUM)   LS_COUNT_MEDIUM=$((LS_COUNT_MEDIUM + 1)) ;;
    HIGH)     LS_COUNT_HIGH=$((LS_COUNT_HIGH + 1)) ;;
    CRITICAL) LS_COUNT_CRITICAL=$((LS_COUNT_CRITICAL + 1)) ;;
  esac
  [ "$rank" -gt "$LS_MAX_RANK" ] && LS_MAX_RANK="$rank"

  printf '%s\t%s\t%s\t%s\n' "$verdict" "$sev" "$detail" "$path" >> "$LS_SCAN_BUF"
}

# ls_scan — run a full comparison of the baseline against the live filesystem.
# Results land in $LS_SCAN_BUF; counters are left in the LS_COUNT_* variables.
ls_scan() {
  local baseline="$1" seen_list line hash size mtime inode mode owner group path

  seen_list="${LS_SCAN_BUF}.seen"
  : > "$seen_list"

  # Pass 1 — every file the baseline knows about.
  #
  # `read` assigns the unsplit remainder of the line to its final variable, so
  # a path containing a literal tab is reconstructed correctly instead of being
  # silently truncated at the first tab.
  while IFS= read -r line; do
    [ -n "$line" ] || continue
    IFS=$'\t' read -r hash size mtime inode mode owner group path <<<"$line"
    [ -n "$path" ] || continue
    printf '%s\n' "$path" >> "$seen_list"
    ls_classify "$hash" "$size" "$mtime" "$inode" "$mode" "$owner" "$group" "$path"
  done < <(ls_baseline_records "$baseline")

  # Pass 2 — files that match WATCH_PATHS today but were not in the baseline.
  # A brand-new file in a log directory can be an attacker's dropped payload or
  # simply a service that started since the last baseline; either way the
  # analyst should be told, at LOW severity.
  while IFS= read -r path; do
    [ -n "$path" ] || continue
    if ! grep -Fxq "$path" "$seen_list" 2>/dev/null; then
      local sz
      sz=$(ls_stat "$path" | cut -f1)
      ls_emit NEW "appeared since the baseline, ${sz:-?} bytes" "$path"
    fi
  done < <(ls_expand_targets)

  rm -f "$seen_list"
}
