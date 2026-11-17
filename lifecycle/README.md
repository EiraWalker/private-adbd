# Optional Android shell lifecycle manager

`service.sh` supervises the existing daemon without changing its Go core, keys,
listener, system adbd, apps, VPN, or network configuration. It requires an already
authorized **UID 2000**, **`u:r:shell:s0`**, **SELinux Enforcing** session. A Termux
app UID cannot invoke it directly. There is no privilege elevation or enrollment.

## Installation contract

Use an independent, authorized recovery connection. Stop any old manager and
verify its watch and daemon have actually exited before installing. Never replace
a running script or ELF, including by rename. Do not adopt unknown processes or
delete unknown locks to force installation.

The manager intentionally has one fixed, device-neutral layout:

| Path under `/data/local/tmp/private-adbd` | Owner | Mode | Content |
| --- | --- | --- | --- |
| Directory itself | 2000 | 0700 | Real directory; trusted, non-symlink ancestors |
| `private-adbd` | 2000 | 0700 | Previously built and verified daemon ELF |
| `service.sh` | 2000 | 0700 | This manager, installed with LF line endings |
| `authorized_keys` | 2000 | 0600 | Existing verified, nonempty public-key policy |
| `service.serial` | 2000 | 0600 | Exact observed `ro.serialno` plus one LF |

All files must be regular, non-symlink, with link count 1. Existing known `v2.*`
state/lock/log files must also be owner-2000, mode 0600, link count 1. The manager
validates these conditions; it does not provision or repair permissions.

`service.serial` is **data**, never shell code. It has no default, comments,
assignments, CRLF, or additional lines. Verify the intended physical device's
identity independently, then create this file from that observed value. Do not
silently enroll whichever device happens to be connected. Do not change the
serial file, base path, script or ELF while the service is running. Keep device
configuration outside Git (`service.serial` is ignored).

Required Android commands: `toybox flock`, `toybox setsid`, `stat -c`,
`readlink -f`, `od`, `tr`, `wc`, `awk`, `grep -Fx`, `ps -A -o PID,NAME`, `date`,
`mv`, `rm`, `sleep`, `id`, `getprop`, `getenforce`, and `/system/bin/sh`.
The shell must be able to read its managed processes' `/proc` stat, exe, cmdline,
status, SELinux context, boot ID, and monotonic uptime.

## Commands (from the verified Android shell session)

```sh
/system/bin/sh /data/local/tmp/private-adbd/service.sh start
/system/bin/sh /data/local/tmp/private-adbd/service.sh status
/system/bin/sh /data/local/tmp/private-adbd/service.sh stop
/system/bin/sh /data/local/tmp/private-adbd/service.sh restart
```

`start` detaches through `toybox setsid`; repeated/concurrent controls use kernel
locks. `watch` is the foreground supervisor entrypoint. `_child` is internal and
requires the inherited birth-lock descriptor. Invoke only by the exact absolute
path above, explicitly through `/system/bin/sh`.

- A child exit gets at most five retries after the first launch, with backoff
  1, 2, 4, 8, 8 seconds. Sixty monotonic seconds with an exact live child resets
  the retry budget. Exit 2 latches immediately; exhausted retries latch too.
- `start` refuses a failure latch. Repair the cause first, then use explicit
  `restart`; `stop` alone does not clear the latch.
- PID, starttime, boot ID, exact executable and argv, all four UIDs and SELinux
  context are checked before signals. Unknown live identities are refused.
- A subsequent authorized `start` can reclaim an exactly identified surviving
  child after watch death. The watch does **not** resurrect itself.
- Never delete lock files: kernel flock ownership, not file presence, is the
  authority. Legacy `run.lock` and unknown files are left untouched.
- Only `v2.current.log` and `v2.previous.log` are written as lifecycle logs, each
  bounded to 32768 bytes. Daemon stdout/stderr are discarded. Status/logs contain
  operational identity data; redact before sharing.

Status returns 0 for exact live watch + exact live child + held watch lock;
1 for transitioning/degraded; 2 for preflight/latched failure; 3 for stopped;
4 for unknown/invalid state. A start/control timeout may also return 1.
**Status is not listener, TLS, ADB, relay, or cellular readiness acceptance.**

For an update: retain independent recovery access; record the exact identities;
run `stop`; independently verify both identities and the loopback listener are
gone; only then replace files and read back hashes/ownership/modes; start and
perform real authenticated control tests. If identity has drifted, stop automated
cleanup and investigate. Do not rename/overwrite live ELF files or use broad
process-name/port kills.

## Local regression tests

Linux with Python 3.9+ (pidfd support), dash and normal Unix file permissions:

```sh
# Use fresh, explicitly chosen directories OUTSIDE this repository.
export FIXTURE_WORK=/absolute/linux-filesystem/private-adbd-test-work
export FIXTURE_EVIDENCE=/absolute/private-adbd-test-evidence
mkdir -p "$FIXTURE_WORK" "$FIXTURE_EVIDENCE"
python3 lifecycle/tests/test_service.py
python3 lifecycle/tests/test_serial.py
python3 lifecycle/tests/test_budget.py
```

Repeat with `FIXTURE_SHELL=/absolute/path/to/mksh` and
`FIXTURE_TOYBOX=/absolute/path/to/toybox`. The latter substitutes actual toybox
applets, including flock/setsid. On WSL DrvFS without chmod metadata, use an
isolated Linux-permission scratch mount rather than weakening production checks.
No root is needed on a normal writable Linux filesystem. The fixtures copy a
native Python ELF, map Android UID/context/property probes and daemon argv, and
exercise real processes, `/proc`, signals, locks, file modes and exec handoffs.
The budget tests additionally map only the uptime clock. They do not contact ADB,
open a listener, or validate Android SELinux/device behavior. Run these scripts
directly; subclass-specific entrypoints deliberately select focused cases.

## Remaining boundaries

This is a transplant of an existing shell lifecycle design, not an independent
security audit. Shell `/proc` validation plus PID-based signaling is not atomic:
a final PID-reuse race remains. A concurrent malicious UID-2000 writer is outside
the file-check boundary. State publication uses rename, not power-loss fsync
journaling. Android/OEM process killing, Doze, reboot and network/relay recovery
remain separate device acceptance gates. There is no app-private heartbeat,
Termux/guardian integration, boot hook, installer, or watch self-recovery here;
an external authorized guardian can invoke these commands, but its privilege
bootstrap and acceptance are outside this repository.
