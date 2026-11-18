# Same-UID maintenance host client (v1)

**Engine integration is wired and under host verification; independent review,
full platform and Android/device acceptance remain pending.** The opt-in Engine
uses this client and private schema-2 lifecycle intents. It neither installs an
API bootstrap APK nor permits an API-less/old APK upgrade. The existing local
owner handoff remains necessary; an owner handoff, a Stop action, or a new PID
is not an app maintenance ack.

## Producer contract actually consumed

The fixed CLI contract is implemented by the Termux sources
`MaintenanceProtocol`, `MaintenanceLease`, `MaintenanceCoordinator`,
`MaintenanceCli`, `MaintenanceSocket`, `MaintenanceTransport`, `MaintenanceWire`,
and `contrib/private-adb/maintenance`. The normal app service owns a fixed abstract
AF_UNIX endpoint; both ends require exact same-UID peer credentials. There is no
exported provider, reflective framework bootstrap, extra permission or alternate
wire fallback. Host consumer tests do not establish that an installed APK exposes
this endpoint or that Android SELinux permits the connection.

* Fixed class: `com.termux.app.privateadb.MaintenanceCli`; one literal verb:
  `request`, `status`, or `release`. No configurable class, package, URI, helper,
  runtime, executable, or CLASSPATH override is exposed.
* The eight request fields are exactly `version`, `token`, `boot`,
  `deadlineElapsedMs`, `profileSha256`, `releaseSha256`, `baselineVersion`,
  `targetVersion`. `version` is integer 1; hashes/token are 64 lowercase hex;
  boot is a lowercase UUID. Numeric fields are positive signed-int64 integers;
  target is not below baseline. Booleans/floats are not integers.
* Status/release stdin has exactly `version` and the **original** `token`.
  JSON is compact UTF-8 with EOF and a trailing LF, at most 2048 bytes. Tokens
  never enter argv or generated shell source.
* Coordinator replies have exactly `{version, phase}` when no lease is returned,
  or all **ten** fields: the eight request fields plus `phase` and `ownerUid`.
  Only a ten-field `active` reply matching every request binding and exact app
  UID can authorize work. Duplicate decoded keys, unknown/missing fields,
  non-integer numbers, overflow, BOM, invalid UTF-8, trailing documents, wrong
  owner/bindings and unknown phases fail closed.
* A valid `pending` is the only pollable phase. `cleanup_pending`,
  `blocked_unknown_dispatch`, revoked/expired/version mismatch, busy, unsupported
  and every other negative/unknown result terminate that call. They are not
  retried until something happens to become green.

## Explicit lifecycle scope, not a read-only probe

**Status is not a read-only guarantee.** `MaintenanceCoordinator.validate` may
persist expiry, revocation or a version mismatch. The currently reviewed producer
excludes status from `startIfEnabled` service startup and avoids startup after an
active request response; those restrictions do not remove validation writes.
Never call
this module from generic probe/inspect/verify, an observation retry handler, or a
non-execute plan. Every device operation requires `remote.t.execute is True`,
the real `Authorization.check()` and `Inputs.unchanged()` before and after slow
observations/IPC. Original profile/release byte hashes and in-memory policy and
transport bindings are checked as well. `checkpoint()` merely returns a private
defensive copy; constructor/checkpoint validation never contacts a device.

Each IPC independently:

1. Observes the installed package through `AndroidRemote.package()`; requires
   exact app UID, a release-approved version/hash pair, and one safe base-APK
   path. Only the request's baseline/target versions are allowed after prepare.
2. Rechecks `late_control()`, reads actual device boot ID and `/proc/uptime`,
   rechecks late control and original authorization/inputs. Stop/safety, native
   lease, pending-dispatch, heartbeat, wireless-debugging and SELinux restrictions
   from the existing remote are **not weakened**. The captured control binding
   must remain exact; an ordinary new PID is no exemption.
3. Uses `run-as com.termux /system/bin/sh -c ...` with the **observed, approved**
   APK as CLASSPATH and the fixed `/system/bin/app_process /system/bin` entry.
   The shell checks its UID, current `pm path`, non-symlink/readable regular APK
   and exact hash before invoking Java. This is a cooperating-writer check, not
   kernel-atomic package selection/class loading.
4. Checks original host authority again, validates the exact reply, and repeats
   package/control/clock checks. A package replacement across the reply is not a
   fresh ack from the replacement app, even if both APKs are approved.

The one fixed IPC uses `remote.t.app(..., mutating=False)` **only to avoid
recursive** `Engine.guard -> assert_active -> Transport.before_mutation ->
Engine.guard`. That transport flag does NOT classify this operation as read-only:
this client supplies an independent mandatory lifecycle gate. It never removes,
monkeypatches or bypasses the generic guard for upgrade mutations. The existing
`control` event label is reused; normal `PrivateOutput.event` stores only stdout/
stderr byte counts and hashes. Java/framework stderr is suppressed. Replies and
checkpoint data contain the token: keep them private; do not print them.

## Parent Engine integration contract

```python
client = MaintenanceClient(remote, authorization)
lease_record = client.prepare(ttl_ms=600000)
# Parent: durably bind lease_record into the real private Engine checkpoint;
# publish the acquire/request intent before the next call. No fake save here.
reply = client.request_once()
if reply['phase'] == 'pending':
    client.wait_active(max_attempts=3, poll_ms=250, timeout_ms=10000)
# Parent: durably publish active confirmation only after a real fresh ack.

# Immediately before EACH bounded upgrade mutation, in the real Engine guard:
client.assert_active(minimum_remaining_ms=operation_budget_ms + safety_margin_ms)
# Preserve all independent runtime/file/identity gates; then dispatch the one
# journaled mutation. Do not cache an old ack for later operations.

# Parent: publish a release intent, and only if no release was already attempted:
client.release_once()
# Parent: save release confirmation only after exact released readback.
```

`prepare()` performs observations but no maintenance request. It mints a fresh
256-bit token and derives deadline from the **actual device** elapsed clock,
never host wall time, guessed SDK data, or a supplied profile clock. TTL is at
most 600000 ms. One client cannot prepare again, request twice, or release twice.
Its checkpoint record is exactly `{request, control}` and accessors return copies.
**The parent owns durability and cross-process at-most-once intents.** The client
cannot prove the parent saved a checkpoint. Do not expose the token/record as
public receipt fields or treat an in-memory attempted flag as a durable journal.

`assert_active()` defaults to a conservative **30000 ms** minimum remaining
budget. The parent must pass a larger budget for a long operation (for example,
the entire bounded install plus margin), including intervening work. It refuses
near-expiry acks before AND after IPC. Every invocation samples device boot/time
anew; the whole clock-read round trip and subsequent late checks plus the
centisecond truncation uncertainty are subtracted. No host monotonic value is
serialized. `wait_active()` is acquisition/reconciliation only; its return does
not substitute for the next mutation's budgeted `assert_active()`.

Polling is bounded by attempt count and a host acceptance/dispatch deadline;
each CLI IPC has at most five seconds, further capped by remaining lease/poll
budget. Existing compound `late_control()` observations have their own finite
transport timeouts and cannot be preempted through the current public seam.
Therefore `timeout_ms` is **not a hard wall-time SLA**: over-budget observations
refuse rather than authorize or dispatch another IPC. A future strictly shared
observation budget would require the AndroidRemote owner to add a deadline-aware
control seam; this change deliberately does not modify that file.

## Unknown outcomes and explicit resume

* `MaintenanceUncertain` is a `Refusal`, **not** `ObservationUnavailable`. A CLI
  transport timeout/unavailable/error is never a read-only retry signal. No API
  automatically replays request/release, renews the token, or extends deadline.
* Retain the original checkpoint and unresolved request/release intent on every
  failure, including a malformed reply or post-IPC gate failure. Do not publish
  active/released based solely on transport success.
* A fresh explicitly authorized resume must verify the parent's exact checkpoint
  hash and original inputs, then construct:
  `MaintenanceClient(remote, authorization, checkpoint=original_lease_record)`.
  This constructor disables request replay. Explicit `status()` or `wait_active()`
  can reconcile only that original token/request. Device time is read again.
* A resumed instance has no knowledge of prior release intents outside its
  record. **The parent must refuse `release_once()` if its durable journal says
  release was already attempted/unknown**. Per-instance one-shot flags are not
  cross-process replay protection.
* Only an unresolved original `maintenance-release` intent can use
  `reconcile_release(checkpoint_hash=original_checkpoint_sha256)`. The restored
  client requires the real `Authorization` with a fresh valid handoff bound to
  that hash, the exact original private checkpoint/record, explicit execute and
  the exact target APK version/hash/UID. The Engine first validates checkpoint
  schema/hash, phase, ordered prefix and all original progress/runtime gates.
  The client verifies original authority/checkpoint before and after observations
  and IPC; same boot, Stop/safety/control and package checks remain mandatory.
* This restricted seam sends one fixed `status` with the original token (IPC
  timeout at most five seconds), and accepts only the strict ten-field bound
  `released` response. Unlike ordinary status, only this terminal observation
  may run after the original elapsed deadline. Active/pending, unbound released,
  expired/revoked, unknown and all wrong bindings refuse without polling. A
  timeout stays uncertain; another attempt requires a separately authorized
  explicit resume, not a loop in the client. No release is repeated, and the
  original request field bytes/types, token and deadline are not rewritten.
  Terminal proof never grants active authority or permission for any mutation.
  Ordinary request/status/wait/assert-active/release still require their original
  deadline. Each read remains bounded by its existing transport timeout; this
  is not a new compound-read hard wall-time SLA.
* A terminal status raises `MaintenanceRejected`, never authorizes continued
  work and never enters the pending retry loop. Its credential-free `.phase`
  contains only an allowlisted producer phase. `.bound` is true only when the
  full ten-field reply, original request and owner UID matched; a two-field
  `not_owner` (or other terminal envelope) has `.bound == False`. For an unknown
  release, the Engine instead uses the restricted `reconcile_release()` seam,
  which returns only exact released after its postflight, then independently
  retains original runtime/package/material and final late Stop checks before
  recording done/clearing intent. A terminal exception from ordinary status is
  not that completed proof. Wrong bindings/unknown phases remain refusals.
* Expired/revoked/boot-changed/control-changed leases are not renewed. A new
  maintenance session requires a separately reviewed explicit parent flow; this
  module does not silently create one on resume.
* `MaintenanceUnsupported` is terminal. The fixed shell maps absent old-APK CLI
  classes and incompatible runtime/provider environments to a fixed unsupported
  envelope. No wireless/root/`am`/`content`/legacy fallback or bootstrap exists.

## Focused host verification

From repository root:

```sh
python -m unittest discover -s install/tests -p test_maintenance.py -v
python -m unittest discover -s install/tests -p test_engine_maintenance.py -v
```

The pre-existing local-handoff test is retained (the requested test filename was
already tracked, not a new file). The added tracer runs the actual `Transport`
stdin/argv subprocess path against a fictional host protocol producer. Focused
negative tests cover strict bindings/schema, near-expiry budgets, device clocks,
late Stop, APK replacement, bounded pending, original-input/authorization drift,
explicit resume and actual host subprocess timeouts with no replay. Real Engine
plus actual client fixtures also cover a processed release with lost response
after expiry, terminal-only strict schema, unchanged original request, no
mutation/request/release replay, original checkpoint authority and final late Stop.
These checks do not establish Android compatibility. An additional
host-shell fixture executes the generated fixed script with only test-local
Android path/tool substitutions and verifies that a fake old-class runtime was
actually reached before its failure becomes unsupported. It discovers the real
host shell's path/interpreter convention; it is not Android mksh acceptance.

No device/ADB operation, Go/Gradle/full-platform test, install, commit or push is
part of these tests. Host `OfflineSDK` fixtures do not claim SDK/APK-signature
acceptance. Real minified entrypoint retention, same-UID LocalSocket access,
app-worker quiescence, OEM/SELinux behavior and release lifecycle still
require separately authorized physical-device acceptance.
