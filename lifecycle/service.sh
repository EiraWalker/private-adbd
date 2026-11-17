#!/system/bin/sh
# Private-adbd lifecycle V2. No root, boot hook, network or key changes.
# Always invoke by absolute path through /system/bin/sh. See README.md.
# The A && B || fail guards deliberately fail if either validation fails.
# shellcheck disable=SC2015
PATH=/system/bin:/system/xbin
export PATH
unset ENV BASH_ENV CDPATH LD_PRELOAD LD_LIBRARY_PATH
umask 077
SH=/system/bin/sh
BASE=/data/local/tmp/private-adbd
SELF=$BASE/service.sh
DAEMON=$BASE/private-adbd
KEYS=$BASE/authorized_keys
SERIAL=
EXPECT_UID=2000
EXPECT_CONTEXT=u:r:shell:s0
MAX_RETRIES=5
STABLE_SECONDS=60
LOG_LIMIT=32768

fail() { printf 'v2: %s\n' "$*" >&2; exit 2; }
hex() { od -An -v -tx1 | tr -d ' \n'; }
# Only known V2 paths may ever be removed/replaced. Never inspect/delete run.lock.
safe_file() {
 f=$1; mode=$2
 [ ! -L "$f" ] || return 1
 [ -e "$f" ] || return 0
 if [ -f "$f" ] && [ "$(stat -c '%u:%a:%h' "$f" 2>/dev/null)" = "$EXPECT_UID:$mode:1" ]; then return 0; fi
 # A trusted publisher may atomically remove V2 state during a preflight read.
 [ ! -e "$f" ] && [ ! -L "$f" ]
}
check_files() {
 for name in watch.lock birth.lock control.lock watch child gate go failure current.log previous.log watch.tmp child.tmp gate.tmp go.tmp failure.tmp; do
  safe_file "$BASE/v2.$name" 600 || fail "unsafe v2.$name"
 done
 for name in current.log previous.log; do
  if [ -f "$BASE/v2.$name" ]; then
   if size=$(wc -c 2>/dev/null <"$BASE/v2.$name"); then
    [ "$size" -le "$LOG_LIMIT" ] || fail "oversized v2.$name"
   else
    [ ! -e "$BASE/v2.$name" ] || fail "unreadable v2.$name"
   fi
  fi
 done
}
preflight() {
 [ "$(id -u)" = "$EXPECT_UID" ] || fail 'requires shell UID 2000'
 [ "$(getenforce)" = Enforcing ] || fail 'SELinux not Enforcing'
 [ "$(cat /proc/$$/attr/current)" = "$EXPECT_CONTEXT" ] || fail 'wrong SELinux context'
 [ "$0" = "$SELF" ] || fail 'absolute fixed service.sh path required'
 [ ! -L "$BASE" ] && [ -d "$BASE" ] || fail 'unsafe base'
 [ "$(CDPATH='' cd "$BASE" && pwd -P)" = "$BASE" ] || fail 'symlink base ancestor'
 [ "$(stat -c '%u:%a' "$BASE")" = "$EXPECT_UID:700" ] || fail 'base must be owner-only 0700'
 safe_file "$BASE/service.serial" 600 && [ -f "$BASE/service.serial" ] || fail 'unsafe or missing service.serial'
 [ "$(wc -l <"$BASE/service.serial")" = 1 ] || fail 'service.serial requires one line'
 IFS= read -r SERIAL <"$BASE/service.serial" || fail 'unreadable service.serial'
 [ -n "$SERIAL" ] || fail 'empty service.serial'
 # Shell read may discard NULs or ignore an unterminated suffix. Check all bytes.
 [ "$(hex <"$BASE/service.serial")" = "$(printf '%s\n' "$SERIAL" | hex)" ] || fail 'noncanonical service.serial bytes'
 [ "$(getprop ro.serialno)" = "$SERIAL" ] || fail 'wrong serial'
 safe_file "$SELF" 700 && [ -f "$SELF" ] || fail 'unsafe service.sh'
 safe_file "$DAEMON" 700 && [ -x "$DAEMON" ] || fail 'unsafe daemon'
 safe_file "$KEYS" 600 && [ -s "$KEYS" ] || fail 'unsafe keys'
 check_files
 BOOT=$(cat /proc/sys/kernel/random/boot_id) || fail 'boot ID unavailable'
 SHEX=$(readlink -f "$SH" | tr -d '\n' | hex)
 DHEX=$(printf '%s' "$DAEMON" | hex)
}
cmdhex() {
 case "$1" in
 watch) printf '%s\000' "$SH" "$SELF" watch ;;
 gate) printf '%s\000' "$SH" "$SELF" _child ;;
 child) printf '%s\000' "$DAEMON" --keys "$KEYS" --serial "$SERIAL" ;;
 esac | hex
}
stamp() {
 IFS= read -r row <"/proc/$1/stat" 2>/dev/null || return 1
 rest=${row##*) }
 # /proc stat numeric fields after comm require intentional field splitting.
 # shellcheck disable=SC2086
 set -- $rest
 [ "$#" -ge 20 ] && [ "$1" != Z ] && [ "$1" != X ] || return 1
 shift 19; printf '%s' "$1"
}
# Never source/eval persistent state. Expected exe/argv are policy, not state input.
load() {
 record=$BASE/v2.$1; role=$1
 [ -f "$record" ] || return 1
 [ "$(wc -l <"$record")" = 1 ] || return 2
 IFS=' ' read -r p st b ex cmd uid ctx extra <"$record" || return 2
 case "$p:$st" in *[!0-9:]*|:*|*:) return 2 ;; esac
 [ "$p" -gt 1 ] && [ -z "$extra" ] && [ "$uid" = "$EXPECT_UID" ] && [ "$ctx" = "$EXPECT_CONTEXT" ] || return 2
 [ "$cmd" = "$(cmdhex "$role")" ] || return 2
 case "$role" in child) expected=$DHEX ;; *) expected=$SHEX ;; esac
 [ "$ex" = "$expected" ] || return 2
 case "$b" in ????????-????-????-????-????????????) ;; *) return 2 ;; esac
 return 0
}
# Result 0 exact live identity, 1 dead/old boot, 2 live but mismatched/unknown.
known_dead() {
 [ "$b" = "$BOOT" ] || return 0
 [ -d "/proc/$p" ] || return 0
 IFS= read -r dead_row <"/proc/$p/stat" 2>/dev/null || return 1
 case "${dead_row##*) }" in Z\ *|X\ *) return 0 ;; esac
 return 1
}
identity_snapshot() {
 [ "$b" = "$BOOT" ] || return 1
 [ -d "/proc/$p" ] || return 1
 actual_stamp=$(stamp "$p") || { known_dead && return 1; return 2; }
 [ "$actual_stamp" = "$st" ] || return 2
 [ "$(readlink "/proc/$p/exe" | tr -d '\n' | hex)" = "$ex" ] || return 2
 [ "$(hex <"/proc/$p/cmdline")" = "$cmd" ] || return 2
 [ "$(awk '/^Uid:/ {print $2 ":" $3 ":" $4 ":" $5}' "/proc/$p/status")" = "$uid:$uid:$uid:$uid" ] || return 2
 [ "$(cat "/proc/$p/attr/current")" = "$ctx" ] || return 2
 [ "$(stamp "$p")" = "$st" ] || return 2
 return 0
}
identity() {
 identity_snapshot; snapshot_result=$?
 # An exit between /proc reads is dead, not an impostor. Unreadable stays unknown.
 if [ "$snapshot_result" -eq 2 ] && known_dead; then return 1; fi
 return "$snapshot_result"
}
write_record() {
 target=$1; pid=$2; start=$3
 case "$target" in child) exe=$DHEX ;; *) exe=$SHEX ;; esac
 printf '%s %s %s %s %s %s %s\n' "$pid" "$start" "$BOOT" "$exe" "$(cmdhex "$target")" "$EXPECT_UID" "$EXPECT_CONTEXT" >"$BASE/v2.$target.tmp" &&
 mv -f "$BASE/v2.$target.tmp" "$BASE/v2.$target"
}
log() {
 check_files
 bytes=0
 [ ! -f "$BASE/v2.current.log" ] || bytes=$(wc -c <"$BASE/v2.current.log")
 if [ "$bytes" -ge "$((LOG_LIMIT - 256))" ]; then
  mv -f "$BASE/v2.current.log" "$BASE/v2.previous.log" || fail 'log rotation'
 fi
 printf '%s %s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" "$*" >>"$BASE/v2.current.log"
}
# All sends revalidate immediately, including KILL after the grace period.
terminate() {
 identity; result=$?
 [ "$result" -ne 2 ] || return 2
 [ "$result" -eq 0 ] || return 0
 victim=$p
 kill -TERM "$victim" 2>/dev/null || :
 n=0
 while [ "$n" -lt 5 ]; do
  identity; result=$?
  [ "$result" -ne 2 ] || return 2
  [ "$result" -eq 0 ] || return 0
  sleep 1; n=$((n + 1))
 done
 identity || return 2
 kill -KILL "$victim" 2>/dev/null || :
 n=0
 while [ "$n" -lt 3 ]; do
  identity; result=$?
  [ "$result" -ne 2 ] || return 2
  [ "$result" -eq 0 ] || return 0
  sleep 1; n=$((n + 1))
 done
 return 2
}
birth_lock() {
 exec 8>>"$BASE/v2.birth.lock"
 # Bounded wait; a still-running unknown gate is never forcibly unlocked.
 n=0
 # mksh marks exec-created FDs CLOEXEC. Explicit N>&N exports only this FD.
 until toybox flock -n 8 8>&8; do
  [ "$n" -lt 20 ] || fail 'birth lock busy'
  sleep 1; n=$((n + 1))
 done
}
# Called only under birth lock, with no concurrent publisher.
reconcile() {
 found=0
 for which in child gate; do
  if load "$which"; then
   identity; result=$?
   case "$result" in
   0) terminate || fail "cannot terminate exact $which"; found=1; break ;;
   1) ;;
   2) # During the exec handshake, the other record can match the same PID.
      reserved_pid=$p; reserved_stamp=$st; reserved_boot=$b
      if [ "$which" = child ] && load gate && [ "$p:$st:$b" = "$reserved_pid:$reserved_stamp:$reserved_boot" ] && identity; then
       terminate || fail 'cannot terminate gate'; found=1; break
      fi
      fail "unknown live $which identity; no signal sent" ;;
   esac
  else
   result=$?; [ "$result" -eq 1 ] || fail "invalid $which state"
  fi
 done
 rm -f "$BASE/v2.child" "$BASE/v2.gate" "$BASE/v2.go"
 [ "$found" -eq 0 ] || log 'reclaimed exact surviving child/gate'
}
# Fail closed on any untracked daemon or old supervisor; never kill it.
no_untracked() {
 # Android fork/exec is expensive: inspect executable links in one native call.
 # A disappearing/unreadable unrelated process is ignored, as in the old scan.
 links=$(readlink /proc/[0-9]*/exe 2>/dev/null)
 printf '%s\n' "$links" | grep -Fx "$DAEMON" >/dev/null && fail 'untracked daemon'
 shell_exe=$(readlink -f "$SH")
 # Only the legacy launcher's known shell comm names need argv inspection.
 # shellcheck disable=SC2046
 for pid in $(ps -A -o PID,NAME | awk '$2 == "sh" || $2 == "mksh" {print $1}'); do
  case "$pid" in ''|*[!0-9]*) continue ;; esac
  [ "$(readlink "/proc/$pid/exe" 2>/dev/null)" = "$shell_exe" ] || continue
  tr '\000' '\n' <"/proc/$pid/cmdline" 2>/dev/null | grep -Fx "$BASE/supervise.sh" >/dev/null && fail "legacy supervisor $pid"
 done
 return 0
}
child_gate() {
 # FD8 is inherited only across the publish handshake; FD9 was closed by parent.
 [ "$(readlink /proc/$$/fd/8)" = "$BASE/v2.birth.lock" ] || fail 'internal child requires birth lock FD'
 [ ! -e /proc/$$/fd/9 ] || fail 'watch FD leaked into child'
 load watch && identity || fail 'parent watch identity missing'
 parent=$p; parent_stamp=$st
 mine=$(stamp "$$") || fail 'child starttime unavailable'
 write_record gate "$$" "$mine" && write_record child "$$" "$mine" || fail 'child state publication'
 exec 8>&-
 n=0
 while [ "$n" -lt 15 ]; do
  load watch && identity && [ "$p" = "$parent" ] && [ "$st" = "$parent_stamp" ] || exit 2
  if [ -f "$BASE/v2.go" ] && [ "$(cat "$BASE/v2.go")" = "$$ $mine $BOOT" ]; then
   exec "$DAEMON" --keys "$KEYS" --serial "$SERIAL" </dev/null >/dev/null 2>&1
   exit 2
  fi
  sleep 1; n=$((n + 1))
 done
 exit 2
}
cleanup_watch() {
 trap - EXIT INT TERM
 birth_lock
 reconcile
 rm -f "$BASE/v2.watch"
 exec 8>&-
}
watch() {
 exec 9>>"$BASE/v2.watch.lock"
 toybox flock -n 9 9>&9 || exit 0
 birth_lock
 # Never replace a live mismatched watch state.
 if load watch; then
  identity; result=$?
  [ "$result" -eq 1 ] || fail 'live/unknown watch without matching kernel lock'
 else
  [ "$?" -eq 1 ] || fail 'invalid watch state'
 fi
 reconcile
 no_untracked
 [ ! -f "$BASE/v2.failure" ] || fail 'latched failure; explicit restart required'
 mine=$(stamp "$$") || fail 'watch starttime unavailable'
 write_record watch "$$" "$mine" || fail 'watch state publication'
 exec 8>&-
 trap cleanup_watch EXIT
 trap 'exit 0' INT TERM
 trap '' HUP
 tries=0; delay=1
 while :; do
  preflight
  birth_lock
  reconcile
  no_untracked
  # Close parent's FD8 without LOCK_UN: child's inherited OFD protects publication
  # if watch is SIGKILLed between fork and durable child identity publication.
  "$SH" "$SELF" _child 8>&8 9>&- </dev/null >/dev/null 2>&1 &
  child=$!
  exec 8>&-
  birth_lock
  load gate && identity && [ "$p" = "$child" ] || fail 'gate publication failed'
  printf '%s %s %s\n' "$p" "$st" "$BOOT" >"$BASE/v2.go.tmp"
  mv -f "$BASE/v2.go.tmp" "$BASE/v2.go" || fail 'gate release'
  exec 8>&-
  log "child launched pid=$child attempt=$tries"
  # Poll, then wait: traps do not depend on shell-specific wait interruption.
  uncertain=0; stable=0; stable_since=
  while load child; do
   identity; result=$?
   if [ "$result" -eq 2 ]; then
    # exec is one-way: gate can disappear between the two identity snapshots.
    # Re-read the daemon before treating that handoff as an unknown process.
    if load gate && identity; then sleep 1; continue; fi
    load child || fail 'child state disappeared'
    identity; result=$?
    if [ "$result" -eq 2 ] && [ "$uncertain" -lt 2 ]; then
     uncertain=$((uncertain + 1)); sleep 1; continue
    fi
   fi
   [ "$result" -ne 2 ] || fail 'live child identity changed'
   [ "$result" -eq 0 ] || break
   uncertain=0
   if [ "$stable" -eq 0 ]; then
    # Kernel monotonic time; begin only after the daemon has exact identity.
    IFS=' ' read -r uptime _idle </proc/uptime || fail 'uptime unavailable'
    stable_since=${stable_since:-$uptime}
    elapsed=$((${uptime%.*} - ${stable_since%.*}))
    # Compare hundredths without truncating the window or overflowing uptime*100.
    if [ "$elapsed" -gt "$STABLE_SECONDS" ] || {
     [ "$elapsed" -eq "$STABLE_SECONDS" ] && [ "1${uptime#*.}" -ge "1${stable_since#*.}" ]
    }; then
     tries=0; delay=1; stable=1
     log 'stable child; retry budget reset'
    fi
   fi
   sleep 1
  done
  wait "$child"; code=$?
  log "child exited code=$code"
  birth_lock
  reconcile
  if [ "$code" -eq 2 ] || [ "$tries" -ge "$MAX_RETRIES" ]; then
   printf '%s\n' "exit=$code retries=$tries" >"$BASE/v2.failure.tmp"
   mv -f "$BASE/v2.failure.tmp" "$BASE/v2.failure"
   exec 8>&-
   log "latched failure exit=$code retries=$tries"
   exit 2
  fi
  exec 8>&-
  tries=$((tries + 1))
  log "backoff seconds=$delay retry=$tries"
  sleep "$delay"
  [ "$delay" -ge 8 ] || delay=$((delay * 2))
 done
}
status_snapshot() {
 check_files
 watch_state=absent; child_state=absent; wp=-; cp=-; ws=-; cs=-
 if load watch; then
  wp=$p; ws=$st; identity; r=$?
  case "$r" in 0) watch_state=exact ;; 1) watch_state=dead ;; *) watch_state=unknown ;; esac
 else
  [ "$?" -eq 1 ] || watch_state=invalid
 fi
 if load child; then
  cp=$p; cs=$st; identity; r=$?
  case "$r" in 0) child_state=exact ;; 1) child_state=dead ;; *)
   child_state=unknown
   if load gate && [ "$p:$st" = "$cp:$cs" ] && identity; then
    child_state=gate
   elif load child; then
    identity; r=$?
    case "$r" in 0) child_state=exact ;; 1) child_state=dead ;; esac
   fi ;;
  esac
 else
  [ "$?" -eq 1 ] || child_state=invalid
 fi
 exec 6>>"$BASE/v2.watch.lock"
 if toybox flock -n 6 6>&6; then locked=no; else locked=yes; fi
 exec 6>&-
 latched=no; [ ! -f "$BASE/v2.failure" ] || latched=yes
 printf 'watch=%s watch_pid=%s watch_start=%s child=%s child_pid=%s child_start=%s lock=%s failure=%s boot=%s uid=%s context=%s\n' "$watch_state" "$wp" "$ws" "$child_state" "$cp" "$cs" "$locked" "$latched" "$BOOT" "$EXPECT_UID" "$EXPECT_CONTEXT"
 case "$watch_state:$child_state" in *unknown*|*invalid*) return 4 ;; esac
 [ "$watch_state:$child_state:$locked:$latched" != exact:exact:yes:no ] || return 0
 [ "$latched" != yes ] || return 2
 [ "$watch_state" != exact ] || return 1
 [ "$child_state" != exact ] || return 1
 return 3
}
status() {
 # Snapshot state under the publication lock; missing during rename/removal is
 # a transition, not corrupt state. Never hold this lock across polling sleeps.
 exec 8>>"$BASE/v2.birth.lock"
 if toybox flock -n 8 8>&8; then
  status_snapshot; status_result=$?
 else
  printf 'watch=transition child=transition birth=busy\n'
  status_result=1
 fi
 exec 8>&-
 return "$status_result"
}
start() {
 status; r=$?
 [ "$r" -ne 0 ] || return 0
 [ "$r" -ne 4 ] || fail 'unknown process state'
 [ ! -f "$BASE/v2.failure" ] || fail 'latched failure; use restart after repair'
 n=0
 while [ "$n" -lt 15 ]; do
  # Helpers of a killed watch may briefly retain FD9: retry the contender.
  toybox setsid "$SH" "$SELF" watch 7>&- </dev/null >/dev/null 2>&1 &
  sleep 1
  status; r=$?
  [ "$r" -ne 0 ] || return 0
  [ "$r" -ne 2 ] || return 2
  [ "$r" -ne 4 ] || return 4
  n=$((n + 1))
 done
 return 1
}
stop() {
 exec 9>>"$BASE/v2.watch.lock"
 if ! toybox flock -n 9 9>&9; then
  load watch && identity || fail 'locked watch has no exact identity; no signal sent'
  terminate || fail 'watch did not stop safely'
  n=0
  until toybox flock -n 9 9>&9; do
   [ "$n" -lt 10 ] || fail 'watch lock not released'
   sleep 1; n=$((n + 1))
  done
 else
  if load watch; then
   identity; r=$?
   [ "$r" -eq 1 ] || fail 'live watch without kernel lock; no signal sent'
  else
   [ "$?" -eq 1 ] || fail 'invalid watch state'
  fi
 fi
 birth_lock
 reconcile
 rm -f "$BASE/v2.watch"
 exec 8>&- 9>&-
 printf 'stopped\n'
}
[ "$#" -eq 1 ] || fail 'usage: service.sh start|status|stop|restart|watch'
preflight
case "$1" in
 _child) child_gate ;;
 watch) watch ;;
 status) status ;;
 start|stop|restart)
  exec 7>>"$BASE/v2.control.lock"
  control_wait=0
  until toybox flock -n 7 7>&7; do
   [ "$control_wait" -lt 20 ] || { printf 'v2: control operation timed out\n' >&2; exit 1; }
   sleep 1; control_wait=$((control_wait + 1))
  done
  case "$1" in
   start) start ;;
   stop) stop ;;
   restart) stop && { rm -f "$BASE/v2.failure"; start; } ;;
  esac ;;
 *) fail 'usage: service.sh start|status|stop|restart|watch' ;;
esac
