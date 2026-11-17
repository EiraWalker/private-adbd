# Existing-deployment upgrader

Python **3.11+**, standard library only. Entry point:

```sh
python -S install/installer.py --help
python -m unittest discover -s install/tests -v
```

This is a **forward-only upgrader**, not an enrollment or repair tool. It requires an already provisioned, debuggable `com.termux` fork, a healthy existing private-adbd shell supervisor, and an explicitly selected, already authorized controller transport. No APKs, keys, device identities or release receipts are bundled.

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
# Append these options to any command (use your own SDK paths):
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

APK replacement is an **app-UID process lifecycle boundary**. Shell watch/child identities must remain unchanged. If the original native server survives, it is not restarted. If it is absent and its scoped port is empty, the installer may make **one** bounded `start-server` with the original HOME, existing keys, TMPDIR and port. A new PID/starttime must be proved with unchanged executable, argv hash, UID, context, executable inode and loopback listener. Unknown replacements or listeners are refused. The argv comparison is intentionally strict, including reply-fd bytes: a different platform convention is a compatibility refusal, not grounds to weaken the gate.

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
