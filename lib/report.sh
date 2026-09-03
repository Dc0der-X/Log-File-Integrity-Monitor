#!/usr/bin/env bash
# lib/report.sh — rendering a scan buffer as text, JSON or HTML.
#
# All three renderers read the same tab-separated scan buffer, so a finding can
# never appear in one output format and not another.
#
# shellcheck shell=bash

# ---------------------------------------------------------------------------
# Console
# ---------------------------------------------------------------------------

ls_report_text() {
  local buf="$1" show_ok="${2:-0}" verdict sev detail path colour shown=0

  printf '\n'
  printf '%s  LogSentry integrity report%s\n' "$C_BOLD" "$C_RESET"
  printf '%s  host %s   algo %s   %s%s\n' \
    "$C_DIM" "$(hostname 2>/dev/null || printf unknown)" "$LS_HASH_LABEL" "$(ls_iso8601)" "$C_RESET"
  printf '%s  ─────────────────────────────────────────────────────────────%s\n' "$C_DIM" "$C_RESET"

  while IFS=$'\t' read -r verdict sev detail path; do
    [ -n "$verdict" ] || continue
    if [ "$verdict" = "OK" ] && [ "$show_ok" != "1" ]; then continue; fi
    colour=$(ls_severity_color "$sev")
    shown=$((shown + 1))
    if [ "$verdict" = "OK" ]; then
      printf '  %s%-9s%s %-8s %s\n' "$C_GREEN" "OK" "$C_RESET" "" "$path"
    else
      printf '  %s%-9s%s %s%-8s%s %s\n' "$colour" "$verdict" "$C_RESET" "$C_DIM" "$sev" "$C_RESET" "$path"
      [ -n "$detail" ] && printf '            %s└─ %s%s\n' "$C_DIM" "$detail" "$C_RESET"
    fi
  done < "$buf"

  if [ "$shown" -eq 0 ]; then
    printf '  %sNo changes. All %s monitored files match the baseline.%s\n' \
      "$C_GREEN" "$LS_COUNT_OK" "$C_RESET"
  fi

  printf '%s  ─────────────────────────────────────────────────────────────%s\n' "$C_DIM" "$C_RESET"
  ls_report_summary_line
  printf '\n'
}

ls_report_summary_line() {
  printf '  %d checked' "$LS_COUNT_TOTAL"
  printf '  ·  %s%d ok%s' "$C_GREEN" "$LS_COUNT_OK" "$C_RESET"
  [ "$LS_COUNT_INFO"     -gt 0 ] && printf '  ·  %d info' "$LS_COUNT_INFO"
  [ "$LS_COUNT_LOW"      -gt 0 ] && printf '  ·  %s%d low%s' "$C_CYAN" "$LS_COUNT_LOW" "$C_RESET"
  [ "$LS_COUNT_MEDIUM"   -gt 0 ] && printf '  ·  %s%d medium%s' "$C_YELLOW" "$LS_COUNT_MEDIUM" "$C_RESET"
  [ "$LS_COUNT_HIGH"     -gt 0 ] && printf '  ·  %s%d high%s' "$C_RED" "$LS_COUNT_HIGH" "$C_RESET"
  [ "$LS_COUNT_CRITICAL" -gt 0 ] && printf '  ·  %s%d CRITICAL%s' "$C_BOLD$C_RED" "$LS_COUNT_CRITICAL" "$C_RESET"
  printf '\n'
}

# ---------------------------------------------------------------------------
# JSON
# ---------------------------------------------------------------------------
# One object per scan, with an embedded findings array. Written by hand rather
# than with jq, because jq is exactly the kind of dependency this tool refuses
# to require on a compromised host.

ls_report_json() {
  local buf="$1" verdict sev detail path first=1

  printf '{\n'
  printf '  "@timestamp": "%s",\n' "$(ls_iso8601)"
  printf '  "host": "%s",\n' "$(ls_json_escape "$(hostname 2>/dev/null || printf unknown)")"
  printf '  "tool": { "name": "logsentry", "version": "%s", "algo": "%s" },\n' \
    "$LS_VERSION" "$LS_HASH_LABEL"
  printf '  "summary": { "checked": %d, "ok": %d, "info": %d, "low": %d, "medium": %d, "high": %d, "critical": %d },\n' \
    "$LS_COUNT_TOTAL" "$LS_COUNT_OK" "$LS_COUNT_INFO" "$LS_COUNT_LOW" \
    "$LS_COUNT_MEDIUM" "$LS_COUNT_HIGH" "$LS_COUNT_CRITICAL"
  printf '  "findings": [\n'

  while IFS=$'\t' read -r verdict sev detail path; do
    [ -n "$verdict" ] || continue
    [ "$verdict" = "OK" ] && continue
    [ "$first" -eq 1 ] || printf ',\n'
    first=0
    printf '    { "verdict": "%s", "severity": "%s", "path": "%s", "detail": "%s", "note": "%s" }' \
      "$(ls_json_escape "$verdict")" "$(ls_json_escape "$sev")" \
      "$(ls_json_escape "$path")" "$(ls_json_escape "$detail")" \
      "$(ls_json_escape "$(ls_verdict_note "$verdict")")"
  done < "$buf"

  [ "$first" -eq 1 ] || printf '\n'
  printf '  ]\n'
  printf '}\n'
}

# ---------------------------------------------------------------------------
# HTML
# ---------------------------------------------------------------------------
# A self-contained report an analyst can attach to a ticket. No external CSS,
# no fonts, no JavaScript — it has to open on an air-gapped forensics laptop.

ls_report_html() {
  local buf="$1" verdict sev detail path rows="" cls status_word status_cls

  while IFS=$'\t' read -r verdict sev detail path; do
    [ -n "$verdict" ] || continue
    [ "$verdict" = "OK" ] && continue
    cls=$(printf '%s' "$sev" | tr '[:upper:]' '[:lower:]')
    rows="${rows}<tr class=\"sev-${cls}\">"
    rows="${rows}<td><span class=\"badge b-${cls}\">${sev}</span></td>"
    rows="${rows}<td class=\"verdict\">$(ls_html_escape "$verdict")</td>"
    rows="${rows}<td class=\"path\"><code>$(ls_html_escape "$path")</code></td>"
    rows="${rows}<td class=\"detail\">$(ls_html_escape "$detail")<br><span class=\"note\">$(ls_html_escape "$(ls_verdict_note "$verdict")")</span></td>"
    rows="${rows}</tr>"
  done < "$buf"

  if [ "$LS_COUNT_CRITICAL" -gt 0 ]; then
    status_word="TAMPERING SUSPECTED"; status_cls="critical"
  elif [ "$LS_COUNT_HIGH" -gt 0 ]; then
    status_word="INTEGRITY VIOLATION"; status_cls="high"
  elif [ "$LS_COUNT_MEDIUM" -gt 0 ] || [ "$LS_COUNT_LOW" -gt 0 ]; then
    status_word="REVIEW REQUIRED"; status_cls="medium"
  else
    status_word="ALL CLEAR"; status_cls="clear"
  fi

  [ -n "$rows" ] || rows='<tr><td colspan="4" class="empty">No deviations from the baseline.</td></tr>'

  cat <<HTMLDOC
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>LogSentry Report — $(ls_html_escape "$(hostname 2>/dev/null || printf unknown)")</title>
<style>
  :root{--bg:#f6f7f9;--card:#fff;--ink:#14171a;--muted:#6b7280;--line:#e5e7eb;
        --crit:#b91c1c;--high:#dc2626;--med:#d97706;--low:#0891b2;--info:#6b7280;--ok:#059669}
  @media (prefers-color-scheme:dark){
    :root{--bg:#0d1117;--card:#161b22;--ink:#e6edf3;--muted:#8b949e;--line:#30363d}
  }
  *{box-sizing:border-box}
  body{margin:0;padding:32px 20px;background:var(--bg);color:var(--ink);
       font:14px/1.55 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif}
  .wrap{max-width:1000px;margin:0 auto}
  h1{font-size:20px;margin:0 0 4px;letter-spacing:-.01em}
  .sub{color:var(--muted);font-size:13px;margin-bottom:20px}
  .status{display:inline-block;padding:6px 14px;border-radius:6px;font-weight:700;
          font-size:12px;letter-spacing:.08em;color:#fff;margin-bottom:20px}
  .s-critical{background:var(--crit)} .s-high{background:var(--high)}
  .s-medium{background:var(--med)} .s-clear{background:var(--ok)}
  .cards{display:flex;flex-wrap:wrap;gap:10px;margin-bottom:22px}
  .card{background:var(--card);border:1px solid var(--line);border-radius:8px;
        padding:12px 16px;min-width:96px}
  .card .n{font-size:22px;font-weight:700;line-height:1.1}
  .card .l{font-size:11px;color:var(--muted);text-transform:uppercase;letter-spacing:.06em}
  table{width:100%;border-collapse:collapse;background:var(--card);
        border:1px solid var(--line);border-radius:8px;overflow:hidden}
  th{text-align:left;font-size:11px;text-transform:uppercase;letter-spacing:.06em;
     color:var(--muted);padding:10px 14px;border-bottom:1px solid var(--line)}
  td{padding:12px 14px;border-bottom:1px solid var(--line);vertical-align:top}
  tr:last-child td{border-bottom:none}
  code{font:12px/1.4 ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;word-break:break-all}
  .verdict{font-weight:600;white-space:nowrap}
  .note{color:var(--muted);font-size:12px}
  .empty{color:var(--muted);text-align:center;padding:28px}
  .badge{display:inline-block;padding:3px 9px;border-radius:4px;font-size:10px;
         font-weight:700;letter-spacing:.05em;color:#fff;white-space:nowrap}
  .b-critical{background:var(--crit)} .b-high{background:var(--high)}
  .b-medium{background:var(--med)} .b-low{background:var(--low)} .b-info{background:var(--info)}
  footer{color:var(--muted);font-size:12px;margin-top:20px}
</style>
</head>
<body>
<div class="wrap">
  <h1>LogSentry integrity report</h1>
  <div class="sub">
    host <strong>$(ls_html_escape "$(hostname 2>/dev/null || printf unknown)")</strong> ·
    algorithm <strong>${LS_HASH_LABEL}</strong> ·
    generated $(ls_iso8601) ·
    logsentry ${LS_VERSION}
  </div>
  <div class="status s-${status_cls}">${status_word}</div>
  <div class="cards">
    <div class="card"><div class="n">${LS_COUNT_TOTAL}</div><div class="l">Checked</div></div>
    <div class="card"><div class="n">${LS_COUNT_OK}</div><div class="l">Unchanged</div></div>
    <div class="card"><div class="n">${LS_COUNT_INFO}</div><div class="l">Info</div></div>
    <div class="card"><div class="n">${LS_COUNT_MEDIUM}</div><div class="l">Medium</div></div>
    <div class="card"><div class="n">${LS_COUNT_HIGH}</div><div class="l">High</div></div>
    <div class="card"><div class="n">${LS_COUNT_CRITICAL}</div><div class="l">Critical</div></div>
  </div>
  <table>
    <thead><tr><th>Severity</th><th>Verdict</th><th>File</th><th>What changed</th></tr></thead>
    <tbody>${rows}</tbody>
  </table>
  <footer>Generated by LogSentry — baseline held at ${STATE_DIR}. Verify the baseline seal before trusting this report.</footer>
</div>
</body>
</html>
HTMLDOC
}
