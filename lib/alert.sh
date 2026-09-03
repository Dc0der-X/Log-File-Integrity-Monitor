#!/usr/bin/env bash
# lib/alert.sh — alert dispatch.
#
# Four sinks, all built on utilities the OS already provides:
#
#   console  stderr, colour-coded              (always available)
#   file     append-only JSONL                 (ships to any log collector)
#   syslog   logger(1)                         (journald / rsyslog / SIEM agent)
#   webhook  curl(1)                           (Slack- and Teams-compatible)
#   email    mail(1)                           (cron-style notification)
#
# A sink that is not configured is silently skipped; a sink that is configured
# but fails warns loudly, because a silent alerting failure is worse than no
# alerting at all.
#
# shellcheck shell=bash

# ls_alert_should_fire <severity> — honour ALERT_MIN_SEVERITY.
ls_alert_should_fire() {
  local have want
  have=$(ls_severity_rank "$1")
  want=$(ls_severity_rank "$ALERT_MIN_SEVERITY")
  [ "$have" -ge "$want" ] && [ "$have" -gt 0 ]
}

# ls_event_json <verdict> <severity> <detail> <path> — one JSONL event.
# Field names follow the Elastic Common Schema where an obvious equivalent
# exists, so this drops into an existing pipeline without a custom parser.
ls_event_json() {
  local verdict="$1" sev="$2" detail="$3" path="$4"
  printf '{"@timestamp":"%s","event":{"kind":"alert","category":"file","action":"%s","severity":"%s","module":"logsentry"},"file":{"path":"%s"},"host":{"name":"%s"},"message":"%s","logsentry":{"version":"%s","algo":"%s"}}\n' \
    "$(ls_iso8601)" \
    "$(ls_json_escape "$verdict")" \
    "$(ls_json_escape "$sev")" \
    "$(ls_json_escape "$path")" \
    "$(ls_json_escape "$(hostname 2>/dev/null || printf unknown)")" \
    "$(ls_json_escape "$detail")" \
    "$LS_VERSION" "$LS_HASH_LABEL"
}

ls_alert_file() {
  local json="$1" dir
  [ -n "$ALERT_FILE" ] || return 0
  dir="${ALERT_FILE%/*}"
  [ -d "$dir" ] || mkdir -p "$dir" 2>/dev/null
  printf '%s' "$json" >> "$ALERT_FILE" 2>/dev/null \
    || ls_warn "could not append to ALERT_FILE=$ALERT_FILE"
}

ls_alert_syslog() {
  local sev="$1" msg="$2" prio
  [ "$ALERT_SYSLOG" = "1" ] || return 0
  command -v logger >/dev/null 2>&1 || { ls_warn "ALERT_SYSLOG=1 but logger(1) is not installed"; return 0; }
  case "$sev" in
    CRITICAL) prio=auth.crit ;;
    HIGH)     prio=auth.err ;;
    MEDIUM)   prio=auth.warning ;;
    *)        prio=auth.notice ;;
  esac
  logger -t "$ALERT_SYSLOG_TAG" -p "$prio" -- "$msg" 2>/dev/null \
    || ls_warn "logger(1) rejected the message"
}

# Slack and Microsoft Teams both accept a bare {"text": "..."} payload, which
# keeps this to one curl invocation with no JSON templating per provider.
ls_alert_webhook() {
  local text="$1" payload
  [ -n "$ALERT_WEBHOOK_URL" ] || return 0
  command -v curl >/dev/null 2>&1 || { ls_warn "ALERT_WEBHOOK_URL is set but curl is not installed"; return 0; }
  payload=$(printf '{"text":"%s"}' "$(ls_json_escape "$text")")
  curl -fsS --max-time 10 -X POST -H 'Content-Type: application/json' \
       -d "$payload" "$ALERT_WEBHOOK_URL" >/dev/null 2>&1 \
    || ls_warn "webhook POST failed (network, or the URL was rejected)"
}

ls_alert_email() {
  local subject="$1" body="$2"
  [ -n "$ALERT_EMAIL" ] || return 0
  command -v mail >/dev/null 2>&1 || { ls_warn "ALERT_EMAIL is set but mail(1) is not installed"; return 0; }
  printf '%s\n' "$body" | mail -s "$subject" "$ALERT_EMAIL" 2>/dev/null \
    || ls_warn "mail(1) delivery failed"
}

# ls_dispatch_alerts <scan_buffer> — fan out every qualifying finding.
#
# Per-event sinks (file, syslog) fire once per finding so nothing is lost.
# Notification sinks (webhook, email) fire once per scan with a digest,
# because paging someone forty times for one logrotate run is how alerting
# gets muted permanently.
ls_dispatch_alerts() {
  local buf="$1" verdict sev detail path fired=0 summary="" line
  local host; host=$(hostname 2>/dev/null || printf unknown)

  while IFS=$'\t' read -r verdict sev detail path; do
    [ -n "$verdict" ] || continue
    ls_alert_should_fire "$sev" || continue
    fired=$((fired + 1))

    local msg="[$sev] $verdict $path — $detail"
    ls_alert_file "$(ls_event_json "$verdict" "$sev" "$detail" "$path")"
    ls_alert_syslog "$sev" "$msg"
    summary="${summary}${msg}"$'\n'
  done < "$buf"

  [ "$fired" -eq 0 ] && return 0

  local title="LogSentry: $fired finding(s) on $host"
  if [ "$LS_COUNT_CRITICAL" -gt 0 ]; then
    title="LogSentry CRITICAL: possible log tampering on $host"
  elif [ "$LS_COUNT_HIGH" -gt 0 ]; then
    title="LogSentry HIGH: log content modified on $host"
  fi

  ls_alert_webhook "$title"$'\n'"$summary"
  ls_alert_email "$title" "$summary"
  return 0
}
