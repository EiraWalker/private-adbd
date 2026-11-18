# Existing-deployment upgrader

**Supported installer computer: Windows. Installation target: Android.**
Linux-desktop installer support is outside the current delivery scope. Tests that
exercise Unix permissions or Android shell behavior do not make Linux a required
installer host. Android UID, SELinux, permission and authentication checks remain
mandatory.

For daemon installation without a Termux APK upgrade, start with the
[standalone core bootstrap](CORE-BOOTSTRAP.md). The APK-upgrade workflow below is
a separate optional path, not a prerequisite for installing private-adbd.

Python **3.11+**, standard library only. Entry point:

```sh
python -S install/installer.py --help
python -m unittest discover -s install/tests -v
```

This is a **forward-only upgrader**, not an enrollment or repair tool. Its upgrade commands require an already provisioned, debuggable `com.termux` fork, a healthy existing private-adbd shell supervisor, and an explicitly selected, already authorized controller transport. No APKs, keys, device identities or release receipts are bundled.

See the [Android adaptation guide and acceptance matrix](ADAPTATION.md) for mode
selection, transport/artifact/owner prerequisites and unverified platform boundaries.

## Read-only capability probe

`probe` is a separate explicit device-read command. It does **not** require a
profile, known app UID, release/APK, SDK tool, maintenance record or `--execute`:

```sh
python -S install/installer.py probe \
  --transport-argv '["adb"]' --transport-kind adb \
  --transport-serial FICTIONAL-USB-001 \
  --output /private/evidence/new-probe

# Or an already endpoint-bound trusted controller implementing shell CODE:
python -S install/installer.py probe \
  --transport-kind controller --transport-argv '["/trusted/fixed-controller"]' \
  --expected-serial FICTIONAL-PHONE-001 \
  --output /private/evidence/new-controller-probe
```

ADB accepts exactly one executable and always receives `-s EXACT_SELECTOR shell
-T CODE`. The selector is not `ro.serialno`; optional `--expected-serial` binds
that independently observed property exactly. Discovery without that option records
an identity, **not a configured-serial match or authorization**; upgrade commands
still require and prove their profile's expected serial. Controller argv must already bind
one intended endpoint; it cannot also take `--transport-serial`. No first-device
selection, scan, connect, root, pairing, app launch or Android write is performed.
All reads are fixed allowlisted shell text, with `shell=False` on the host and a
15-second timeout per transport call. These trusted executables are operator
configuration, never untrusted device-provided callbacks.

New private `device.json` and `capability.json` record only serial/shell identity
(UID 2000, exact `u:r:shell:s0`, Enforcing), boot ID, Android SDK, ABI properties,
current Android user, selected command presence, and scoped `com.termux` package
UID/version/debuggable/path/split/run-as observations. Package queries explicitly
cover **primary user 0**; the existing fixed Termux prefix cannot support other
current users. Missing Termux is reported without inventing an app UID. Missing
commands, unknown primary ABI, non-primary current user, nondebuggable/split APKs
and denied `run-as` are explicit unsupported reasons; ambiguous or conflicting
identity/output refuses. Identifiers are never trimmed or repaired; CRLF line
terminators alone are accepted. No full property dump, app/process inventory,
user files, logs or keys are read. Command discovery reports paths without ever
executing a device-returned path.

Stdout contains only a summary, actual `device_calls`, and `read_only: true`.
ABI-to-Go architecture mapping and SDK reporting are **not Android/OEM/ABI
certification**, install readiness, initial provisioning or maintenance authority:
`compatibility_verified` stays false and unverified release/runtime/authorization
gates remain explicit. `probe --execute`, release/SDK/maintenance flags on probe,
and probe transport flags on existing commands are errors, not silently ignored.
All existing upgrade commands still require real profile/release/SDK validation;
local-only plan/apply/resume remain zero-device-call operations.


## What it does not do

- No Play/stock Termux to fork migration, initial provisioning, permissions or battery exemptions.
- No root, VPN/relay configuration, key generation, pairing, wireless-debugging window, NSD discovery, `connect`, shared-server shutdown, Stop/Enable repair or raw preference edits.
- No downgrade, rollback, arbitrary shell callback, shell `eval`, or automatic replay after uncertain mutation.
- No claim that source-revision metadata proves a signed build, remote publication, method-level APK behavior, or device compatibility. Signature and manifest verification do **not** audit fork Java methods. Review and test the fork's fixed `MANAGER`, heartbeat and guardian lifecycle contract separately.
- No unattended recovery promise. If package replacement leaves the guardian temporarily unhealthy, this tool stops. Let the authorized owner establish health, inspect, then authorize an exact checkpoint resume; do not clear latches.

## Inputs and default behavior

Copy `examples/*.example.json` **outside the repository**, replace the fictional fields, and keep both manifests and APK/payload files in a protected local workspace. Examples deliberately have invalid artifact hashes, a nonexistent transport, expired maintenance dates, and `ready: false`.

```sh
python -S install/installer.py plan \
  --profile /private/upgrade/profile.json \
  --release /private/upgrade/release.json \
  --output /private/evidence/new-plan

# Still local-only, no maintenance approval needed and no remote constructed:
python -S install/installer.py apply \
  --profile /private/upgrade/profile.json \
  --release /private/upgrade/release.json \
  --output /private/evidence/new-dry-run
```

`plan`, default `apply`, and default `resume` validate local manifest schemas, artifact bytes, APK signature and manifest. They return `device_calls: 0` and **never construct a remote transport**. SDK subprocesses are local/offline and are not counted as device calls. A dry-run output must be a new directory; it does not reuse or alter a failed execution's evidence.

Android SDK `apksigner` and `aapt` are required for all artifact checks. Supply trusted executable argv prefixes as JSON; they are invoked with `shell=False`, never interpolated into a host shell:

```sh
# Append these options to an upgrade command (not probe; use your own SDK paths):
--apksigner-argv '["java", "-jar", "/opt/android/build-tools/lib/apksigner.jar"]' \
--aapt-argv '["/opt/android/build-tools/aapt"]'
```

The installer appends `verify --print-certs APK` and `dump badging APK`. On Windows prefer Java plus the JAR rather than a `.bat` launcher. Local executables and argv are trusted operator configuration: do not accept manifests, tool paths or controller executables from an untrusted party.

### Profile contract

Unknown JSON keys, duplicate JSON fields, unsafe paths, invalid identities and ambiguous transports are refused.

- `serial` is the expected **`ro.serialno`**, not the ADB transport identifier. There is no device default.
- `app_uid` is the existing fork's UID. The device independently has to prove shell UID 2000, `u:r:shell:s0`, SELinux Enforcing, and the expected `run-as com.termux` UID.
- `package` is fixed to `com.termux`; this is not a generic package installer.
- `base` is an existing, single private directory below `/data/local/tmp`, owned by UID 2000.
- `native_port` is the existing app-owned local ADB server port, distinct from 27184. `native_home` is the existing app home or the fixed STATE `native-home`. Its `.android/adbkey` and `.pub` must already exist with reviewed permissions. They are **only stat'ed**, never read or hashed.
- `publisher` is `embedded` or `independent`. Both core PID records have seven fields. An independent publisher has a three-field record, and its actual executable, fixed producer argv, UID, SELinux context and starttime are independently validated.
- Ancestors reject symlinks and group/other writes. The only mode-0771 exception is Android-managed `/data/data/com.termux/files` and `/data/data/com.termux/shared_prefs`, with **both** owner UID and GID equal to `app_uid` (compatible with AOSP `ContextImpl` private-directory creation). Unknown directories, shell BASE/staging and world-write modes receive no exception. Native key directories and STATE still require exact 0700; keys still require exact 0600. No device permission is changed.
- Process labels are read from the exact `/proc/PID/attr/current` using the already authorized shell identity, because some SELinux policies deny this observation to `run-as`. Native status, executable, argv and inode observations remain app-domain reads, and all existing UID, label, identity and loopback checks remain mandatory. A denied shell label read is a refusal, never an assumed label or an SELinux change.
- `transport` is either `{"kind":"controller","argv":["/trusted/fixed-controller","--wait","15"]}` or `{"kind":"adb","argv":["/trusted/adb"],"serial":"FICTIONAL-existing-transport"}`. The controller must implement `shell CODE` and `push LOCAL REMOTE` with byte-clean stdout and inherited stdin; `status`/`pull` are accepted transport operations. A controller must already bind the intended endpoint. Its assertions do not replace device identity checks. Official ADB always receives `-s`; no first-device fallback, scanning, pairing or `kill-server` exists.

### Release contract

- `apk` is a nonsymlink relative path inside the release manifest directory. `sha256`, target `version`, `package`, single `signer_sha256`, and `debuggable: true` must match actual SDK verification.
- `baselines` explicitly lists allowed installed APK version/hash pairs. Every version must be strictly lower than the target. The installed APK is privately backed up and its signature/manifest verified before any mutation. Split APK installations are refused. Consistent repeated `userId`/`appId` declarations are accepted; conflicts are refused.
- `source_revision` is optional **unverified operator metadata** only.
- `payloads: []` supports pure APK upgrades. Optional payloads have exactly `path`, `source`, `sha256`, `before_sha256` (digest or `null` for absence), `mode`, and `phase` (`before_apk` or `after_apk`). Sources are byte/hash pinned relative local files, not transform expressions.
- Reviewed destination allowlist: `files/usr/bin/private-adbd`, `tablet-guardian`, `tablet` (0700), `files/home/.bashrc` and `.config/tablet-daemon/autostart.json` (0600), all below `/data/data/com.termux`. No arbitrary destination, preferences, key file, heartbeat, credential or STATE write is accepted. Existing mode must equal the declared mode; mode migration is out of scope.
- An `autostart.json` candidate may change **only** `managerPath` to `/data/data/com.termux/files/usr/bin/private-adbd`; every other field, including `expectedSerial`, `enabled` and `heartbeatPath`, must remain identical. STATE remains `.config/tablet-daemon`.
- `remove_legacy` may contain only an exact `{path, sha256, mode}` entry for the old `files/usr/bin/tablet-daemon` command, mode `700`. It is removed only after target APK, payload, heartbeat, native client and runtime invariants have been read back successfully. Unknown paths are never deleted.

Example optional payload entry (replace its fictional hash with reviewed bytes):

```json
{
  "path": "/data/data/com.termux/files/usr/bin/private-adbd",
  "source": "reviewed/private-adbd",
  "sha256": "0000000000000000000000000000000000000000000000000000000000000000",
  "before_sha256": null,
  "mode": "700",
  "phase": "before_apk"
}
```

## Ownership and execution

`inspect` is an **explicit device-read command**, never a dry-run alias:

```sh
python -S install/installer.py inspect \
  --profile /private/upgrade/profile.json --release /private/upgrade/release.json \
  --output /private/evidence/new-inspection
```

Before mutation, obtain an actual maintenance handoff from the current device/native-window owner. The JSON is a local operator attestation, **not authentication of another human or session**. The installer cannot manufacture or independently prove that attestation. Keep it protected. Bind it to the SHA-256 of the **exact manifest file bytes**, expected serial, and a real nonempty owner/session identifier; set `ready`, `released`, `no_parallel` true only after that owner actually released the device. Both dates require explicit timezones, a current validity window, and at most 30 minutes lifetime. Hashes of the manifests are displayed in a local dry-run's `bindings`.

```sh
python -S install/installer.py apply --execute \
  --profile /private/upgrade/profile.json --release /private/upgrade/release.json \
  --maintenance /private/upgrade/maintenance.json \
  --output /private/evidence/new-execution
```

Every mutation rereads the **same unchanged** valid maintenance record, local artifact bytes, device identity, false Stop/safety flags, unowned native lease, native Wi-Fi debugging `0`, absent `start.pending`, fresh healthy heartbeat, process identities, shell-file hashes, key metadata, wrapper state, and scoped loopback listeners. The transport also enforces the late gate immediately before dispatch. Any gate failure is nonzero; no flag repair, rollback or background retry occurs.

Device lock and shell-UID staging directory have unique token-owned marker files. APK transfer and an independently checkpointed `stage-seal` are separate operations: Windows/controller pushes may produce 0644/0666 files inside the 0700 staging directory; only exact owned bytes can be sealed to 0600 before `pm install -r`. No downgrade flag is emitted.

APK replacement is an **app-UID process lifecycle boundary**. Shell watch/child identities must remain unchanged. If the original native server survives, it is not restarted. If it is absent and its scoped port is empty, the installer may make **one** bounded `start-server` with the original HOME, existing keys, TMPDIR and port. A different PID and strictly greater starttime must be proved with unchanged executable, full argv hash, all four Linux UID fields, executable inode and loopback listener. Unknown replacements or listeners are refused. The argv comparison is intentionally strict, including reply-fd bytes: a different platform convention is a compatibility refusal, not grounds to weaken the gate.

**Checkpoint-bound SELinux launch identity:** every real snapshot independently executes the fixed read-only `run-as com.termux id -u` and `run-as com.termux id -Z`. The UID must equal the profile app UID; the observed context must be a legal `runas_app` label with exactly the original native server's MCS suffix. Exact observed `{uid, context}` evidence is saved as `before.native_launch`, not supplied or overridden by a profile/release field. Missing, denied or ambiguous observations refuse. Snapshot observation may describe `untrusted_app` / `untrusted_app_N` or the exact current captured launch label, but observation is **not adoption** of an unknown replacement, and `allow_missing_native` does not authorize any context change.

Only a confirmed target APK plus the durable, correctly ordered `native-start` intent can authorize the original app context to change to the **exact baseline-captured** launch context. That same explicit policy validates immediate readback, uncertain-start reconciliation and saved `native_after` on checkpoint load. Every ordinary guard still requires the original PID/starttime/context or the already-confirmed exact `native_after`; it compares launch evidence even when the native server is absent. The transport's late gate rereads launch identity after the snapshot and immediately before mutation dispatch, alongside Stop/lease/boot and maintenance. Confirmation retains the actual after-context only after all runtime, key, file, listener and late control gates pass. Root/system/shell labels, different categories or any other identity drift are refused, with no restart fallback.

This captures the authorized launch-shell identity, **not proof of an Android native exec transition**. Real post-start readback must still prove the actual server. Host fixtures model the controlled transition and are not Android acceptance. No restart should be performed merely to manufacture launch evidence.

### Same-UID maintenance-aware upgrades (explicit opt-in)

A reviewed release may add **`"maintenance_api": 1`** to release schema 1. Only
integer 1 is accepted (not `true`, `1.0`, a string or an unknown version). Missing
this field retains the original strict schema-1 workflow; API unsupported never
selects that legacy path automatically. A separately reviewed first capability
bootstrap from an API-less APK and a subsequent genuinely changing API-aware
upgrade are distinct acceptance steps. An old failed checkpoint cannot be
rebased, converted to schema 2, or reported as successful bootstrap.

The same original host owner handoff, profile/release hashes, SDK signature and
manifest verification, execute flag, serial/UID/SELinux policy and all runtime,
PID/material/key/listener checks remain mandatory. The maintenance API is an
additional gate, not permission to adopt a different guardian/watch/child/native
process, enable anything, clear Stop/safety, open a window or renew a lease.

API-aware execution uses **checkpoint schema 2**, with the original private
`maintenance: {request, control}` record. The record binds a fresh token, actual
device boot/elapsed deadline (at most ten minutes), exact profile/release hashes,
baseline/target versions and existing control state. It is persisted together
with the acquisition intent **before** request dispatch. It is never copied to
public result fields or replaced on resume. Ordered checkpoints are:

1. `maintenance-acquire`: full original checks, one fixed same-UID request, and
   an exact ten-field active owner acknowledgement **before** lock, payload,
   staging or install. Unsupported old helpers stop here, before those writes.
2. Existing lock/payload/stage/seal and **one** bounded APK install; exact target
   package readback must succeed.
3. `maintenance-reack`: fresh status from the replacement APK/process using the
   **same** request and remaining deadline. A lost static ack across replacement
   is expected; it is not permission to request again. Only acquire and this
   APK-confirmed stage may bounded-poll a valid pending reply (three attempts,
   250 ms between attempts, ten-second acceptance deadline).
4. Existing after-APK files, exact native transition, postchecks, any scoped
   legacy removal, token-owned staging/lock cleanup, and complete readback.
5. `maintenance-release`: durable intent, fresh full checks and one release.
   Only exact bound released readback completes this step; expired is not
   released. A receipt appears only after this step.

Each real upgrade mutation still goes through the actual bound
`Transport.before_mutation -> Engine.guard` immediately before subprocess
execution. Schema 2 alone eliminates the duplicate earlier full guard: quick
host authorization/input checks precede the durable intent, then the transport
performs one full package/runtime/material guard. No guard is detached and no
snapshot or ack is cached. The guard obtains a fresh active status after slow
snapshots, reserves the actual timeout (180 seconds for push/install, 15 for
native start, 45 for other writes), 30 seconds for acknowledgement/final gates,
and another 30-second dispatch margin. Ack plus the final original late
Stop/lease/boot/launch/host-authority gates must finish within that first
30-second allowance or dispatch refuses. Slow observations are not a reason to
weaken the deadline or identity checks.

An explicit checkpoint-hash-bound resume constructs the real client from the
original record. Unknown acquire/reack outcomes can use status only; unknown
install/native-start outcomes retain their exact postcondition-only/no-replay
rules. An unknown release may reconcile only an exact full bound released status
against its existing release intent; pending, active, wrong ownership/bindings,
unsupported, expired and unknown replies never authorize another release or turn
failure green. For that existing release intent alone, `reconcile_release()`
uses a fresh real checkpoint-hash-bound handoff and the exact target APK to make
one fixed, at-most-five-second status IPC, even after the original deadline.
It accepts only a strict ten-field reply matching the original request, exact
owner UID and `released`, then retains the original runtime/material and final
late gates. This terminal
observation grants no active lease or mutation authority; it neither polls nor
repeats release. Ordinary request/status/wait/assert-active/release retain their
original deadline. Original token, request field types and deadline are never
changed, and expired/revoked are never interpreted as released.

Once release is durably confirmed, completed/post-release resume and postchecks
retain all original package/runtime/material and late Stop checks but do not
require an active lease or issue lifecycle IPC. A fresh already-current apply
performs no maintenance request and returns `already-current`, not evidence of a
newly accepted upgrade. API request/status/release are explicit lifecycle IPCs;
none are used by probe, inspect, verify or offline plan. Local plan/default
apply/default resume still construct no remote and report `device_calls: 0`.

`test_engine_maintenance.py` combines the real Engine and MaintenanceClient with
a fictional two-version runtime and actual local Python transport subprocesses.
It covers journal-before-request, post-install fresh reack, no-replay recovery,
release response loss, strict bindings, Stop, deadline budgets and malformed
checkpoints. This is host implementation evidence, **not Android same-UID socket,
PackageManager, app quiescence, native TLS or OEM acceptance**. See
[MAINTENANCE.md](MAINTENANCE.md) for the fixed client/wire contract; real producer
and deployed-APK acceptance remain separate.

### Checked replacement, not kernel CAS

App payload publication uses same-directory exclusive temporary files, fixed-owner/link/mode/hash checks, symlink-free ancestors, a repeat pre-rename baseline check, and atomic rename. Android shell locking uses **inline FD 9** (not `exec 9` followed by another `exec`). Temporary cleanup requires owned inode/hash identity.

**The check and rename are not a kernel atomic compare-and-swap.** This assumes cooperating writers honor the existing `session.lock` and the actual maintenance handoff. Noncooperating same-UID writers, root, a malicious controller or compromised SDK/host/device remain outside this guarantee. A process may always be killed between remote shell instructions. Unknown partial state is retained for inspection rather than guessed at or recursively deleted.

## Checkpoints and resume

Every mutation gets a durable private `operation-intent` checkpoint **before** dispatch, then a completed checkpoint only after readback. POSIX fsyncs both file and directory; Windows flushes files and uses same-volume replace, but does not claim POSIX directory-fsync crash guarantees. A host OS lock prevents parallel resume of the same evidence directory and is released by process exit; its small lock file is intentionally retained. A different output cannot steal the existing device lock.

On error, retain the entire output. `failure.json` identifies the last phase and exact `checkpoint.json` SHA-256. The failure file is diagnostic; **the checkpoint hash is the resume authority binding**. Use a separate `inspect` output, review current bytes/processes, obtain a **new actual owner handoff**, and add its `checkpoint_sha256` field containing that exact current checkpoint hash:

```sh
python -S install/installer.py resume --execute \
  --profile /private/upgrade/profile.json --release /private/upgrade/release.json \
  --maintenance /private/upgrade/new-maintenance.json \
  --checkpoint-sha256 REPLACE_WITH_REVIEWED_CHECKPOINT_SHA256 \
  --output /private/evidence/original-execution
```

Resume validates exact manifest bindings, operation prefix, backup names and bytes, token-owned stage/lock, installed APK, payload progress and original runtime checkpoint. It does not treat a device merely having the target version as another task's approval.

Legacy schema-1 checkpoints without `before.native_launch` retain the old exact-context/same-domain path only. They cannot authorize a context change, infer launch evidence from the current device, or rebase the original identity. Do not edit an old checkpoint to add evidence; a blocked legacy operation requires separately reviewed owner recovery. New schema-1 checkpoints carry the optional launch-evidence field, validated on load and preserved through completed read-only resume.

- A successful push with lost response is acknowledged only from exact staged bytes/ownership; it is not pushed again. Sealing is a distinct authorized operation.
- An uncertain install is acknowledged only if the exact target APK and its owned staged APK are present. If the baseline still appears or state is ambiguous, resume refuses: **it never repeats the uncertain install**.
- An uncertain native start is inspected for the exact new server identity. If absent or unknown, resume refuses and never starts it a second time.
- An uncertain payload/cleanup is acknowledged only when its exact postcondition is observed. Otherwise it is not replayed, even if the old state happens still to appear. An interrupted operation with no confirmed postcondition needs separately reviewed manual recovery outside this tool.
- Known-completed operations are not repeated. A complete checkpoint resumes with read-only validation and returns `already-current`. A fresh `apply --execute` also returns read-only `already-current` only when APK, all payloads and legacy absence already match. A target APK with incomplete payloads requires its original checkpoint.

Exit 0 means local dry-run, read-only inspection, verified already-current, or completed readback, as identified by `result`. Refused safety gates exit 2; unexpected host failures exit 3. A success receipt is emitted **only** after full readback and exact cleanup. No receipt means do not assume success.

## Evidence and tests

Output must be a **new directory outside the source checkout**, beneath an existing protected parent. Resume reuses its original directory. Symlink/reparse ancestors and hardlinked output files are refused. POSIX output/files are 0700/0600 and owned by the current user. Windows requires `whoami`, `icacls` and Windows PowerShell; the exact protected DACL must allow only the current user SID and SYSTEM. Network filesystems without those guarantees are unsupported. Do not publish this output: backups, snapshots and checkpoints are private.

`events.jsonl` is the only shareable-by-design stream: fixed allowlisted operation labels, UTC time, exit/timeout code and stdout/stderr byte lengths and hashes. It contains no commands, paths, file contents or raw transport output. Review even sanitized hashes before disclosure. Other JSON files and APK/code/config backups are **not** public logs.

Tests use freshly generated **FICTIONAL** identifiers and bytes. SDK and fixed-controller argv are exercised through real local Python subprocesses. Lifecycle tests inject a documented synthetic wire/device-state model; those are not Android compatibility tests. Real POSIX tests exercise exclusive temp collision, stale baseline, symlink rejection, pre-rename drift, flock, permissions and host cross-process exclusion. Real mksh tests skip if mksh is unavailable; Windows skips POSIX-only coverage. Run on a genuine POSIX filesystem (DrvFS without metadata does not implement 0700/0600 correctly). No test needs a device, personal inventory, private operational files, external server, APK or secret.

Real Android package-manager behavior, fork lifecycle/guardian behavior, controller implementations, native ADB launch conventions, OEM/SELinux compatibility, NSD/TLS windows and reboot/network acceptance must be validated separately under an actual owner protocol. Offline/model tests are **not** a deployment receipt.
