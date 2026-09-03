#!/usr/bin/env bash
#
# install.sh — install LogSentry and, optionally, register it to run on a timer.
#
#   sudo ./install/install.sh                  install only
#   sudo ./install/install.sh --with-timer      install + systemd timer (Linux)
#   sudo ./install/install.sh --with-cron       install + a root crontab entry
#   sudo ./install/install.sh --uninstall       remove binary, libs and units
#
# Detects systemd, launchd or plain cron and picks the right scheduler.

set -eu

PREFIX="${PREFIX:-/usr/local}"
CONFDIR="${CONFDIR:-/etc/logsentry}"
STATEDIR="${STATEDIR:-/var/lib/logsentry}"
LOGDIR="${LOGDIR:-/var/log/logsentry}"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

MODE=install
SCHEDULER=none
for arg in "$@"; do
  case "$arg" in
    --with-timer) SCHEDULER=auto ;;
    --with-cron)  SCHEDULER=cron ;;
    --uninstall)  MODE=uninstall ;;
    -h|--help)    sed -n '2,12p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) printf 'unknown argument: %s\n' "$arg" >&2; exit 64 ;;
  esac
done

say()  { printf '  %s\n' "$*"; }
ok()   { printf '  \033[32m✓\033[0m %s\n' "$*"; }
warn() { printf '  \033[33m!\033[0m %s\n' "$*" >&2; }
die()  { printf '  \033[31mx\033[0m %s\n' "$*" >&2; exit 1; }

[ "$(id -u)" -eq 0 ] || die "run this as root (sudo ./install/install.sh)"

detect_scheduler() {
  if command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then
    printf 'systemd\n'
  elif [ "$(uname -s)" = "Darwin" ] && command -v launchctl >/dev/null 2>&1; then
    printf 'launchd\n'
  elif command -v crontab >/dev/null 2>&1; then
    printf 'cron\n'
  else
    printf 'none\n'
  fi
}

do_uninstall() {
  printf '\nRemoving LogSentry\n\n'
  if command -v systemctl >/dev/null 2>&1; then
    systemctl disable --now logsentry.timer >/dev/null 2>&1 || true
    rm -f /etc/systemd/system/logsentry.service /etc/systemd/system/logsentry.timer
    systemctl daemon-reload >/dev/null 2>&1 || true
    ok "systemd units removed"
  fi
  if [ "$(uname -s)" = "Darwin" ]; then
    launchctl unload /Library/LaunchDaemons/com.logsentry.monitor.plist >/dev/null 2>&1 || true
    rm -f /Library/LaunchDaemons/com.logsentry.monitor.plist
    ok "launchd job removed"
  fi
  if command -v crontab >/dev/null 2>&1; then
    crontab -l 2>/dev/null | grep -v 'logsentry' | crontab - 2>/dev/null || true
    ok "crontab entries removed"
  fi
  rm -f "$PREFIX/bin/logsentry"
  rm -rf "$PREFIX/lib/logsentry"
  ok "binary and libraries removed"
  warn "kept $CONFDIR and $STATEDIR — the baseline is evidence; delete it by hand if you mean to"
  printf '\n'
  exit 0
}

[ "$MODE" = "uninstall" ] && do_uninstall

printf '\n\033[1mInstalling LogSentry\033[0m\n\n'

# --- Preflight --------------------------------------------------------------
if   command -v md5sum  >/dev/null 2>&1; then ok "digest tool: md5sum"
elif command -v md5     >/dev/null 2>&1; then ok "digest tool: md5 (BSD)"
elif command -v openssl >/dev/null 2>&1; then ok "digest tool: openssl dgst"
else die "no digest tool found — install coreutils or openssl"; fi

command -v logger >/dev/null 2>&1 && ok "syslog: logger available" \
  || warn "logger(1) missing — set ALERT_SYSLOG=0 in the config"

# --- Files ------------------------------------------------------------------
install -d "$PREFIX/lib/logsentry" "$PREFIX/bin" "$CONFDIR" "$STATEDIR" "$LOGDIR"
install -m 0644 "$ROOT"/lib/*.sh "$PREFIX/lib/logsentry/"
install -m 0755 "$ROOT/bin/logsentry" "$PREFIX/bin/logsentry"
ok "installed $PREFIX/bin/logsentry"

if [ -f "$CONFDIR/logsentry.conf" ]; then
  warn "kept the existing $CONFDIR/logsentry.conf"
else
  install -m 0600 "$ROOT/config/logsentry.conf.example" "$CONFDIR/logsentry.conf"
  ok "wrote $CONFDIR/logsentry.conf (review it before the first run)"
fi

# The baseline is the root of trust; nobody but root reads or writes it.
chmod 0700 "$STATEDIR"; chmod 0750 "$LOGDIR"
ok "state directory $STATEDIR (mode 0700)"

# --- Scheduling -------------------------------------------------------------
if [ "$SCHEDULER" = "auto" ]; then SCHEDULER=$(detect_scheduler); fi

case "$SCHEDULER" in
  systemd)
    install -m 0644 "$ROOT/install/logsentry.service" /etc/systemd/system/
    install -m 0644 "$ROOT/install/logsentry.timer"   /etc/systemd/system/
    systemctl daemon-reload
    systemctl enable --now logsentry.timer
    ok "systemd timer enabled — checks every 5 minutes"
    say "  status:  systemctl status logsentry.timer"
    say "  logs:    journalctl -u logsentry -f"
    ;;
  launchd)
    install -m 0644 "$ROOT/install/com.logsentry.monitor.plist" /Library/LaunchDaemons/
    launchctl load /Library/LaunchDaemons/com.logsentry.monitor.plist
    ok "launchd daemon loaded — checks every 5 minutes"
    ;;
  cron)
    tmp=$(mktemp)
    crontab -l 2>/dev/null | grep -v 'logsentry' > "$tmp" || true
    printf '*/5 * * * * %s/bin/logsentry check -c %s/logsentry.conf --quiet\n' \
      "$PREFIX" "$CONFDIR" >> "$tmp"
    crontab "$tmp"; rm -f "$tmp"
    ok "root crontab entry added — checks every 5 minutes"
    ;;
  none) : ;;
esac

# --- Next steps -------------------------------------------------------------
cat <<NEXT

  Next steps

    1.  Edit the watch list:     $CONFDIR/logsentry.conf
    2.  Take the baseline:       logsentry init
    3.  Confirm it is clean:     logsentry check
    4.  See the state:           logsentry status

  Do step 2 on a host you have reason to believe is clean. A baseline taken
  after a compromise records the attacker's version of the truth as normal.

NEXT
