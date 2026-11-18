#!/system/bin/sh
# Optional advisory publisher. No daemon control or network operations.
PATH=/system/bin:/system/xbin
export PATH
unset ENV BASH_ENV CDPATH LD_PRELOAD LD_LIBRARY_PATH
umask 077
SH=/system/bin/sh
BASE=/data/local/tmp/private-adbd
SELF=$BASE/health-publisher.sh
SERVICE=$BASE/service.sh
EXPECT_UID=2000
EXPECT_CONTEXT=u:r:shell:s0

# Fixed code runs after run-as drops to the existing debuggable app UID.
# stdin is JSON data only. No permissions/SELinux policy are added.
health_write() {
 /system/bin/run-as com.termux /system/bin/sh -c '
  umask 077
  app_uid=$(id -u) || exit 1
  cd /data/data/com.termux || exit 1
  app_root=$(pwd -P) || exit 1
  for part in files files/home files/home/.config files/home/.config/tablet-daemon; do
   [ ! -L "$part" ] && [ -d "$part" ] || exit 1
   [ "$(stat -c %u "$part")" = "$app_uid" ] || exit 1
  done
  cd files/home/.config/tablet-daemon || exit 1
  [ "$(pwd -P)" = "$app_root/files/home/.config/tablet-daemon" ] || exit 1
  [ "$(stat -c "%u:%a" .)" = "$app_uid:700" ] || exit 1
  [ ! -L health.json ] || exit 1
  if [ -e health.json ]; then
   [ -f health.json ] && [ "$(stat -c "%u:%a:%h" health.json)" = "$app_uid:600:1" ] || exit 1
  fi
  tmp=.health.json.new.$$
  set -C
  exec 3>"$tmp" || exit 1
  set +C
  trap '\''rm -f "$tmp"'\'' EXIT
  # Bound the stdin transfer AFTER dropping UID. Keep this app shell alive
  # to run its owned-temp cleanup even when the transfer child is killed.
  /system/bin/toybox timeout -s KILL 5 /system/bin/cat >&3 || exit 1
  exec 3>&-
  [ ! -L "$tmp" ] && [ -f "$tmp" ] || exit 1
  [ "$(stat -c "%u:%a:%h" "$tmp")" = "$app_uid:600:1" ] || exit 1
  mv -f "$tmp" health.json
 '
}
publish() {
 state=$1; wp=$2; cp=$3
 case "$state" in healthy|failure|stopped) ;; *) return 0 ;; esac
 case "$BOOT" in ????????-????-????-????-????????????) ;; *) return 0 ;; esac
 case "$BOOT" in *[!0-9a-f-]*) return 0 ;; esac
 for pid in "$wp" "$cp"; do
  case "$pid" in ''|*[!0-9]*|0?*|??????????*) return 0 ;; esac
 done
 [ "$state" != healthy ] || { [ "$wp" -gt 1 ] && [ "$cp" -gt 1 ]; } || return 0
 IFS=' ' read -r uptime _idle </proc/uptime || return 0
 sec=${uptime%.*}; frac=${uptime#*.}
 # Seconds only are used in arithmetic. Milliseconds are concatenated, never
 # multiplied in mksh's signed 32-bit arithmetic. Reject absurd >31y uptimes.
 case "$sec" in ''|*[!0-9]*|??????????*) return 0 ;; esac
 case "$frac" in [0-9][0-9]) ;; *) return 0 ;; esac
 while [ "${sec#0}" != "$sec" ] && [ "$sec" != 0 ]; do sec=${sec#0}; done
 if [ -n "${last:-}" ]; then
  elapsed=$((sec - ${last%.*}))
  [ "$elapsed" -gt 15 ] || {
   [ "$elapsed" -eq 15 ] && [ "1$frac" -ge "1${last#*.}" ]
  } || return 0
 fi
 # All attempts (even failed writes and terminal states) share this cap.
 last=$sec.$frac
 ms=$sec${frac}0
 while [ "${ms#0}" != "$ms" ] && [ "$ms" != 0 ]; do ms=${ms#0}; done
 printf '{"version":1,"boot_id":"%s","uptime_ms":%s,"watch_pid":%s,"child_pid":%s,"state":"%s"}\n' \
  "$BOOT" "$ms" "$wp" "$cp" "$state" | health_write 9>&- 2>/dev/null || :
}
# Only service.sh status owns daemon identity validation. Do not source its
# records, reimplement daemon identity, or accept an exit-0 transition snapshot.
parse_status() {
 set -f
 # Intentional splitting, followed by byte-for-byte canonical reconstruction.
 set -- $snapshot
 set +f
 [ "$#" -eq 11 ] || return 1
 wp=${2#watch_pid=}; ws=${3#watch_start=}
 cp=${5#child_pid=}; cs=${6#child_start=}
 for pid in "$wp" "$cp"; do
  case "$pid" in ''|*[!0-9]*|0*|1|??????????*) return 1 ;; esac
 done
 for start in "$ws" "$cs"; do
  case "$start" in ''|*[!0-9]*|0*) return 1 ;; esac
 done
 [ "$snapshot" = "watch=exact watch_pid=$wp watch_start=$ws child=exact child_pid=$cp child_start=$cs lock=yes failure=no boot=$BOOT uid=$EXPECT_UID context=$EXPECT_CONTEXT" ]
}
sample() {
 snapshot=$(toybox timeout 5 "$SH" "$SERVICE" status 9>&- 2>/dev/null); result=$?
 if [ "$result" -eq 0 ] && parse_status; then
  publish healthy "$wp" "$cp"
 elif [ "$result" -eq 1 ] && [ "$snapshot" = 'watch=transition child=transition birth=busy' ]; then
  # No snapshot was observed. Keep the last real heartbeat (and its age/cap).
  return 0
 elif [ "$result" -eq 124 ]; then
  # toybox timeout's default deadline result, not a service status code.
  # Never turn missing/partial observations into fresh health or core failure.
  return 0
 elif [ "$result" -eq 3 ]; then
  publish stopped 0 0
 else
  publish failure 0 0
 fi
 return 0
}
fail() { printf 'health-publisher: %s\n' "$*" >&2; exit 2; }
hex() { od -An -v -tx1 | tr -d ' \n'; }
safe_file() {
 [ ! -L "$1" ] || return 1
 [ ! -e "$1" ] || { [ -f "$1" ] && [ "$(stat -c '%u:%a:%h' "$1")" = "$EXPECT_UID:$2:1" ]; }
}
preflight() {
 [ "$(id -u)" = "$EXPECT_UID" ] || fail 'requires shell UID'
 [ "$(getenforce)" = Enforcing ] || fail 'requires enforcing SELinux'
 [ "$(cat "/proc/$$/attr/current")" = "$EXPECT_CONTEXT" ] || fail 'wrong shell context'
 [ "$0" = "$SELF" ] || fail 'fixed absolute script path required'
 [ ! -L "$BASE" ] && [ -d "$BASE" ] || fail 'unsafe base'
 [ "$(CDPATH='' cd "$BASE" && pwd -P)" = "$BASE" ] || fail 'symlink ancestor'
 [ "$(stat -c '%u:%a' "$BASE")" = "$EXPECT_UID:700" ] || fail 'base must be shell-owned 0700'
 for file in "$SELF" "$SERVICE"; do
  safe_file "$file" 700 && [ -f "$file" ] || fail 'unsafe executable'
 done
 for name in lock watch watch.tmp; do
  safe_file "$BASE/health.$name" 600 || fail 'unsafe publisher state'
 done
 BOOT=$(cat /proc/sys/kernel/random/boot_id) || fail 'boot unavailable'
}
stamp() {
 IFS= read -r row <"/proc/$1/stat" 2>/dev/null || return 1
 rest=${row##*) }
 set -f
 set -- $rest
 set +f
 [ "$#" -ge 20 ] && [ "$1" != Z ] && [ "$1" != X ] || return 1
 shift 19; printf '%s' "$1"
}
# Publisher identity only; daemon identity remains exclusively in service.sh.
# Result: 0 exact, 1 absent/dead/old boot, 2 live mismatched or unreadable.
publisher_identity() {
 [ -f "$BASE/health.watch" ] || return 1
 [ "$(wc -l <"$BASE/health.watch")" = 1 ] || return 2
 IFS=' ' read -r p st boot extra <"$BASE/health.watch" || return 2
 case "$p" in ''|*[!0-9]*|0*|1|??????????*) return 2 ;; esac
 case "$st" in ''|*[!0-9]*|0*) return 2 ;; esac
 [ -z "$extra" ] || return 2
 case "$boot" in ????????-????-????-????-????????????) ;; *) return 2 ;; esac
 case "$boot" in *[!0-9a-f-]*) return 2 ;; esac
 [ "$(hex <"$BASE/health.watch")" = "$(printf '%s %s %s\n' "$p" "$st" "$boot" | hex)" ] || return 2
 [ "$boot" = "$BOOT" ] && [ -d "/proc/$p" ] || return 1
 actual=$(stamp "$p") || {
  [ -e "/proc/$p/stat" ] || return 1
  IFS= read -r row <"/proc/$p/stat" || return 2
  case "${row##*) }" in Z\ *|X\ *) return 1 ;; esac
  return 2
 }
 [ "$actual" = "$st" ] || return 2
 [ "$(readlink "/proc/$p/exe")" = "$(readlink -f "$SH")" ] || return 2
 [ "$(hex <"/proc/$p/cmdline")" = "$(printf '%s\000' "$SH" "$SELF" watch | hex)" ] || return 2
 [ "$(awk '/^Uid:/ {print $2 ":" $3 ":" $4 ":" $5}' "/proc/$p/status")" = "$EXPECT_UID:$EXPECT_UID:$EXPECT_UID:$EXPECT_UID" ] || return 2
 [ "$(cat "/proc/$p/attr/current")" = "$EXPECT_CONTEXT" ] || return 2
 [ "$(stamp "$p")" = "$st" ] || return 2
}
publisher_status() {
 exec 8>>"$BASE/health.lock"
 if toybox flock -n 8 8>&8; then
  exec 8>&-
  publisher_identity; r=$?
  [ "$r" -eq 1 ] && return 1
  return 2
 fi
 exec 8>&-
 publisher_identity; r=$?
 [ "$r" -eq 0 ] && return 0
 return 2
}
cleanup() {
 trap - EXIT INT TERM
 # No foreign PID is ever signalled, even during cleanup.
 if safe_file "$BASE/health.watch" 600 && [ -f "$BASE/health.watch" ]; then
  [ "$(cat "$BASE/health.watch")" != "$$ $mine $BOOT" ] || rm -f "$BASE/health.watch"
 fi
}
watch() {
 exec 9>>"$BASE/health.lock"
 toybox flock -n 9 9>&9 || return 0
 publisher_identity; r=$?
 [ "$r" -eq 1 ] || fail 'live or unknown publisher record without lock'
 mine=$(stamp "$$") || fail 'starttime unavailable'
 printf '%s %s %s\n' "$$" "$mine" "$BOOT" >"$BASE/health.watch.tmp" &&
  mv -f "$BASE/health.watch.tmp" "$BASE/health.watch" || fail 'record publication'
 trap cleanup EXIT
 trap 'exit 0' INT TERM
 trap '' HUP
 while :; do
  preflight
  sample
  sleep 1 9>&-
 done
}
ensure() {
 publisher_status; r=$?
 [ "$r" -ne 0 ] || return 0
 [ "$r" -ne 2 ] || fail 'publisher identity/lock unknown; no action taken'
 toybox setsid "$SH" "$SELF" watch 9>&- </dev/null >/dev/null 2>&1 &
 n=0
 while [ "$n" -lt 5 ]; do
  sleep 1
  publisher_status && return 0
  n=$((n + 1))
 done
 fail 'publisher did not become exact'
}
stop() {
 publisher_status; r=$?
 [ "$r" -ne 1 ] || return 0
 [ "$r" -eq 0 ] || fail 'unknown publisher; no signal sent'
 # Immediately revalidate PID/start/boot/exe/argv/UID/context before the only
 # signal. No escalation to KILL and never signal daemon/watch records.
 publisher_identity || fail 'publisher identity changed; no signal sent'
 kill -TERM "$p" 2>/dev/null || :
 n=0
 while [ "$n" -lt 8 ]; do
  sleep 1
  publisher_status; r=$?
  [ "$r" -ne 1 ] || return 0
  n=$((n + 1))
 done
 fail 'publisher did not stop; no escalation sent'
}
# CLI entry.
[ "$#" -eq 1 ] || fail 'usage: health-publisher.sh ensure|status|stop|watch'
preflight
case "$1" in
 ensure) ensure ;;
 status) publisher_status ;;
 stop) stop ;;
 watch) watch ;;
 *) fail 'usage: health-publisher.sh ensure|status|stop|watch' ;;
esac
