# Optional integration with the existing Termux fork guardian

This adds **two scripts**, not an APK, permission bypass, boot hook, or a second
daemon supervisor. It requires the existing debuggable `com.termux` fork with
`PrivateAdbService`/`AutostartConfig` (the same APK on every participating device).
No changes to `lifecycle/service.sh` are needed. The private daemon still uses
its own keys and fixed `127.0.0.1:27184` endpoint.

## Fixed installation contract

| File | Owner | Mode |
| --- | --- | --- |
| `/data/local/tmp/private-adbd/health-publisher.sh` | shell UID 2000 | 0700 |
| `/data/data/com.termux/files/usr/bin/tablet-daemon` | existing Termux app UID | 0700 |
| `/data/data/com.termux/files/home/.config/tablet-daemon` | Termux app UID | 0700 directory |
| `device.serial`, `autostart.json` under that directory | Termux app UID | 0600 |
| `health.json` (created by publisher through run-as) | Termux app UID | 0600 |

The base directory must already be shell-owned 0700, containing the reviewed
`service.sh`, daemon, authorized keys and canonical 0600 `service.serial`.

Provision `device.serial` as **required data**, copied from that deployment's
canonical identity, not a command, environment fallback or public default. It
must contain exactly one nonempty ASCII `[A-Za-z0-9._-]{1,128}` serial plus LF,
with no NUL, CR or trailing bytes. Use the **same value** in `service.serial` and
`autostart.json.expectedSerial`. When the APK provides
`TABLET_DAEMON_EXPECTED_SERIAL`, the wrapper also requires it to match the file.
The wrapper does not parse or execute JSON configuration.

`autostart.json` must contain these exact fields (replace the bracketed data
placeholder; it is deliberately not a usable serial):

```json
{
  "version": 1,
  "enabled": true,
  "expectedSerial": "<deployment serial>",
  "managerPath": "/data/data/com.termux/files/usr/bin/tablet-daemon",
  "heartbeatPath": "/data/data/com.termux/files/home/.config/tablet-daemon/health.json"
}
```

The internal name **must remain `tablet-daemon`** because this unmodified APK
uses that fixed path, including on phones. An interactive `phone` alias may
point to it; do not change the APK or its managerPath for naming alone.

### Safe deployment responsibilities

These are deployment instructions, not an installer that runs an application:

1. Verify the intended fork APK's bytes/version/signature and complete its
   separate backup/migration first. Keep the guardian disabled during setup.
2. Verify source/artifact hashes before copying. Use an already authorized
   shell channel for shell-owned files, and `run-as com.termux` for app-owned
   files. Do not chmod app-private paths from shell, broaden permissions, or
   work around a rejected run-as/SELinux transition.
3. Before staging/replacing a file, reject symlink ancestors and targets,
   wrong ownership, wrong type/mode, multiple hard links, or a physical
   directory different from the intended app/base directory. Validate the
   already existing `files`, `home`, `.config`, `usr`, `usr/bin` ancestors too.
   Do not silently repair unsafe pre-existing paths.
4. Copy bytes to an exclusively created same-directory temporary file owned
   by the destination UID; set its final mode, verify its hash, then atomically
   rename it. Remove only a temporary file that this installation created.
   Do not overwrite a running publisher for upgrades: first disable guardian,
   then use the publisher's identity-checked `stop` command below.
5. Copy required serial/config as **data**; never source/eval them. Provision
   the app-owned directory before calling the publisher. No code is installed
   by the health publisher itself.
6. Parent deployment must later grant the existing fork's declared
   `android.permission.WRITE_SECURE_SETTINGS` and approve its battery exemption.
   This integration does not grant either or modify app preferences silently.

## CLI and pairing (inside Termux)

Install the Termux `android-tools`, Bash, coreutils and `flock` dependencies.
Pair **once, explicitly** using the pairing port in Android Wireless debugging;
enter the pairing code only at the local prompt. The pairing port and connection
port are different. Substitute observed ports for these shell variables:

```sh
tablet-daemon pair "$PAIRING_PORT"
tablet-daemon start "$TLS_CONNECTION_PORT"
tablet-daemon status "$TLS_CONNECTION_PORT"
# Saved connection port may be reused, but is never scanned or guessed:
tablet-daemon ensure
```

`start` and `ensure` have the same noninteractive, bounded behavior. The APK
calls `tablet-daemon start <NSD-observed TLS port>`; no new discovery logic lives
here. Only `127.0.0.1` is contacted. Manual ports must come from the device's
native **TLS** Wireless debugging UI, not a legacy TCP listener. The wrapper
never enables a listener, sets `adb tcpip`, scans ports, or changes network/key
policy. Native TLS recovery is Wi-Fi-dependent in the existing guardian;
cellular-only continuity/recovery remains a separate real-device acceptance
question, not something host fixtures prove.

The wrapper uses its own loopback ADB server (`tcp:localhost:5038`, not a shared
5037 server), disables mDNS auto-connect/emulator range auto-connect in its
launch environment, and uses a dedicated key under
`.config/tablet-daemon/native-home/.android/adbkey`. Inherited HOME/key/server
redirects are cleared or overridden. **Never add that helper public key to the
private daemon's authorized_keys**: it is only for native Android recovery.
Existing pairing for another ADB key/server does not pair this new key.
Deployment must verify the actual android-tools build honors the bind/key and
no-auto-connect settings; the host tests verify argv/environment, not its
network implementation. Do not reuse an unverified pre-existing 5038 server.
Every ADB invocation closes the wrapper's flock FD 9 before execution.

Before any remote control, `ro.serialno` must match the required app-private
serial and `id -u` must be exactly 2000. The **one mutating dispatch** is fixed:

```sh
/system/bin/sh /data/local/tmp/private-adbd/service.sh start && /system/bin/sh /data/local/tmp/private-adbd/health-publisher.sh ensure
```

Transport/candidate failures before dispatch return 1. Configuration/identity
failures, or any ambiguous/failing mutating result, return 2, which this APK
maps to its existing safety pause. Success returns 0.

A 0600 `start.pending` latch is reserved *before* dispatch. It survives wrapper
kill, timeout, or an uncertain response and prevents subsequent automatic
`start`/`ensure` replay, including a later APK recovery window. Only a confirmed
successful dispatch clears it automatically. This is not a journal/fsync or
transactional execution guarantee across power loss.

After an uncertain result, inspect status, repair separately if needed, and use
this **explicit operator action**, which does not start/restart the daemon:

```sh
tablet-daemon status "$TLS_CONNECTION_PORT"
tablet-daemon reconcile "$TLS_CONNECTION_PORT"
```

`reconcile` executes only `service.sh status && health-publisher.sh ensure` and
clears pending only on success. If status is stopped, failed or unknown, the
latch remains; diagnose the frozen base service through its own reviewed CLI.
Do not delete the latch just to retry blindly. After successful reconciliation,
use the fork's existing Enable confirmation to clear `safetyPaused` (or
`userStopped`); reconciliation does not silently re-enable its guardian.

## Independent shell-owned publisher

From an already authorized UID-2000 shell, always use the fixed absolute path:

```sh
/system/bin/sh /data/local/tmp/private-adbd/health-publisher.sh ensure
/system/bin/sh /data/local/tmp/private-adbd/health-publisher.sh status
/system/bin/sh /data/local/tmp/private-adbd/health-publisher.sh stop
```

`ensure` detaches one `watch` under its own kernel flock. The protected record
`health.watch` contains PID, starttime and boot; identity also requires exact
exe/argv/UID/context and a second starttime check. A live mismatch or unknown
lock/record fails closed. `stop` only sends TERM after immediately revalidating
that publisher identity, never signals daemon/watch records, and never
escalates to KILL. `status`: 0 exact locked publisher, 1 absent/dead, 2 unsafe or
unknown. Disabling the app guardian does not stop the daemon or publisher.
Disable the guardian before intentionally stopping these shell processes.

The publisher polls `service.sh status`; **healthy** requires exit 0 plus its
canonical `watch=exact child=exact lock=yes failure=no` snapshot, matching boot,
UID and context. Heartbeat PIDs are the **manager's actual watch and child**,
not the publisher PID. Nonhealthy results publish failure/stopped with zero
PIDs when due. No daemon process records are sourced or changed. This is an
advisory identity snapshot, not authenticated protocol readiness.

`run-as com.termux /system/bin/sh -c <fixed writer>` drops to the existing app
UID. JSON is stdin data only. The writer rejects unsafe app paths/destination,
exclusively opens a 0600 temporary, retains its FD, then atomically renames.
Only the stdin-transfer child is timed out, **after UID drop**, so the app shell
can still clean its owned temp. File validation/metadata operations are not a
hard real-time deadline. A completely externally killed writer can leave its
own temporary; it must not delete another writer's pre-existing collision.

Every publication attempt, including failures and terminal states, shares a
15-second fractional-uptime cap. Milliseconds are concatenated rather than
multiplied in mksh int32 arithmetic; uptime seconds above 999999999 are rejected.
Run-as/write/clock failures are advisory, cannot stop or mutate the daemon, and
produce no persistent publisher log. Owned ordinary failed-write temporaries
are removed. If the publisher dies, no healthy sample is refreshed; the
unchanged app's boot/freshness policy makes the old sample stale naturally.

## Host verification and limits

`tests/test_integration.py` requires Linux, Python 3, real mksh/toybox, root for
wrong-owner fixtures, and isolated Linux-permission-capable scratch storage:

```sh
export MKSH=/absolute/path/to/mksh TOYBOX=/absolute/path/to/toybox
export INTEGRATION_WORK=/absolute/path/to/isolated-linux-scratch
export PYTHONDONTWRITEBYTECODE=1
python3 integrations/termux/tests/test_integration.py
```

The fixtures adapt fixed Android paths, UID/context and clock only inside their
private scratch copies. They exercise real /proc identities, ELF processes,
kernel flocks, detach/signal/staleness, mksh exclusive writes, toybox timeout,
canonical status parsing, byte-canonical serial rejection, ADB argv/env/FDs,
and no-replay after a killed bootstrap. A smoke test calls the **unmodified
frozen lifecycle's** own real-process fixture, kills its watch and checks that
the separate publisher can no longer refresh healthy for its surviving child.

ADB and run-as are fixture shims: these tests are **not** acceptance of APK
permissions, Android SELinux/UID transitions, native TLS pairing/binding,
private two-key authorization, NSD, Wi-Fi/cellular behavior, or battery policy.
Those remain the parent deployment's explicit real-device tests.
