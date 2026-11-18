# Android adaptation and installation paths

The supported installer host is **Windows**; the target device is **Android**.
Linux-desktop installer compatibility is not a release requirement. Android's
Linux kernel, shell UID, SELinux and filesystem rules are device-side security
requirements, not a second kind of phone or a requirement to use a Linux computer.
Core installation does not require a Termux APK upgrade.

Development status: the component implementations have host-fixture coverage.
The integrated maintenance-aware release, corrected APK and real upgrade acceptance
are still under verification. Do not interpret this document as OEM certification
or as authorization to change a device.

## Choose the right path

| Situation | Entry point | Required inputs and authority | Important boundary |
| --- | --- | --- | --- |
| Discover an already authorized device | `installer.py probe` | Explicit trusted ADB selector or endpoint-bound controller; a new protected output directory | Fixed metadata reads only. No profile, APK, SDK or `--execute`. A capability report is not installation authority. |
| First core installation, without Termux | `core_bootstrap.py plan/apply` | Official authorized ADB, exact device identity, pinned ELF/service/public-key bundle and a real owner handoff | Fresh-only. Never overwrites an existing deployment or occupied fixed listener. |
| Check a fresh-core receipt | `core_bootstrap.py verify --execute` | Original protected receipt, unchanged profile/bundle and fresh bound owner handoff | Does not redeploy or start the daemon; may finish exact owned cleanup and manage its own temporary forward. This is not a zero-write observer. |
| Inspect an existing Termux deployment | `installer.py inspect` | Real profile/release and local SDK verification | Device observations, not repair or maintenance acquisition. |
| Observe stability of an installed exact target | `installer.py verify` | Real profile/release, local SDK verification and a new protected output directory | Read-only. Requires an actual measured observation interval and unchanged validated runtime; it cannot certify a new upgrade that was never performed. |
| Upgrade a supported existing Termux fork | `installer.py apply --execute` | Exact existing-deployment profile, pinned signed release, real owner handoff and required app maintenance API | No pairing, permission repair, unknown-process adoption or API-less fallback. |
| Reconcile an interrupted upgrade | `installer.py resume --execute` | Original evidence/checkpoint, its exact hash and a new checkpoint-bound owner handoff | Reads the original operation's exact postcondition. Unknown installs/starts/lease mutations are not automatically replayed. |

These entry points serve different prerequisites. They are not interchangeable
fallbacks. In particular, missing Termux blocks the Termux upgrade path but is
normal for fresh-core installation. A fresh-core script is not a Termux migration,
APK installer or automatic guardian setup.

## Discover facts without inventing a profile

For example, with **fictional** and deliberately different transport/device tokens:

```sh
python -S install/installer.py probe \
  --transport-kind adb --transport-argv '["/absolute/trusted/platform-tools/adb"]' \
  --transport-serial FICTIONAL-USB-001 --expected-serial FICTIONAL-PHONE-001 \
  --output /private/evidence/new-probe
```

On Windows use an absolute native `adb.exe` path, with JSON-escaped backslashes or
forward slashes. A trusted controller may instead bind its endpoint in its own
configuration; do not add an ADB selector to controller mode.

The ADB selector identifies a transport; `ro.serialno` identifies the Android
installation. Neither a network endpoint nor a USB transport label is silently
substituted for the expected device serial. An invalid supplied token is refused,
not repaired. The actual shell must be UID 2000, `u:r:shell:s0`, Enforcing.

The report observes SDK, ABI, kernel page size, current user, fixed tool availability and scoped
Termux metadata/run-as access. Unknown or conflicting observations are not guessed.
ABI-to-Go mappings do not prove that an ELF executes on the device. The Termux
path currently supports primary Android user 0 and the fixed `com.termux` prefix;
split APKs, denied run-as and a nondebuggable distribution are not repaired.

## Trusted artifacts and per-device policy

Keep profiles, release/bundle manifests, APKs, public-key policies, owner handoffs
and execution receipts **outside Git**, in a protected local directory. Examples
in this repository are fictional templates, not usable authorizations.

Separate these two sources of truth:

- **Per-device facts:** exact serial and selected transport, observed app UID,
  existing BASE/native ADB port/home, publisher variant and existing file hashes.
- **Reviewed software/artifacts:** allowed package/signer, target version and APK
  hash, ABI-specific ELF/hash, reviewed service source, destination allowlist and
  fixed maintenance wire contract.

Supply real local SDK tools for APK signature/manifest verification. Do not use a
dummy SDK object, fabricated UID, guessed Android version or another device's
profile to pass validation. The core-only path needs no APK SDK tool but still
requires trusted, hash-pinned artifacts. Public-key inputs are Android adbkey.pub
format, never a private key. Fresh bootstrap currently requires exactly its
selected controller public key; the matching private key stays in the existing
host ADB setup and is not read by the installer.

Input bindings hash the **original JSON bytes**. Reformatting a manifest changes
its binding and requires a new actual handoff. A local `ready: true` field is an
owner assertion checked with the rest of the contract, not evidence of device
health or a cryptographic grant from Android.

## Native page-size scope

The current Termux APK family retains native ELF load segments with 4 KiB
alignment. Passing an APK ZIP 16 KiB alignment check does **not** establish
native ELF 16 KiB compatibility. The supported scope of the existing-Termux
workflow is therefore a device kernel page size of exactly 4096 bytes.

Device checks must obtain the actual value with the fixed `getconf PAGE_SIZE`
metadata command. An Android SDK level, phone brand, previously installed APK
or owner assertion is not a substitute. Missing, malformed, uncertain or other
page sizes must refuse before an APK workflow mutation; there is no automatic
OS compatibility-mode switch. The guard is implemented with component host
coverage; full integration, platform and device acceptance remain pending.

This is a limit of the current Termux APK workflow, not a blanket 4 KiB
restriction on the independent fresh-core mode. That mode still needs a suitable
trusted ELF and actual device acceptance; it is not certified for 16 KiB here.

## Maintenance-aware upgrade contract

A release declaring `maintenance_api: 1` requires the real installed app protocol.
The normal app service, not the CLI process, owns the same-UID maintenance socket
and serialized recovery worker. The host must durably bind its original request
before sending it and obtain a fresh exact `active` acknowledgement before a
bounded upgrade mutation. An owner handoff alone, historical healthy heartbeat or
new PID is not such an acknowledgement.

APK replacement is an expected app-process boundary: the replacement must freshly
acknowledge the **same** request and remaining deadline before further mutations.
The host cannot renew the original request, change its token, adopt an unrelated
runtime epoch, clear Stop/safety or treat pending/expired/released as active.
Completion includes release and owned-artifact cleanup, not only PackageManager
success. See [the maintenance contract](MAINTENANCE.md) and
[existing-deployment inputs and recovery](README.md).

For an original uncertain release intent, a fresh checkpoint-hash-bound handoff
may authorize one fixed terminal status observation even after the original
deadline. Only the complete original-bound `released` response can finish that
intent. It cannot renew the lease, authorize a mutation or replay release; any
other or uncertain result remains unresolved.

An older APK without this API needs a separately authorized and separately
reported capability-bootstrap step. The legacy strict upgrader does not become
maintenance-aware because it installed the new APK; its partial/failed result
must remain intact. Never retry an already installed exact APK or reset its old
checkpoint baseline to manufacture a completed upgrade.

## Failure and acceptance boundaries

- Unavailable transport: stop device work. Use a separately verified, already
  authorized alternate transport only when genuinely available. Do not reset the
  shared ADB server, scan, pair or enable wireless debugging as an implicit repair.
- Unsupported permission, user, package, ABI or path: retain the refusal and
  identify the unmet prerequisite; no chmod, root or guessed fallback.
- Unknown mutation outcome: retain the original checkpoint and bytes, inspect,
  then use the exact supported reconciliation path. A plausible partial stdout
  or correct UID accompanied by nonzero exit is not successful verification.
- Read-only package availability retries are bounded and limited to their precise
  post-success install scope. Permission/identity/schema/hash/version rejections
  and arbitrary nonzero exits are terminal, not transient by default.
- A stable observer requires at least three validated samples over an actual
  measured 120-second default window, unchanged package/runtime identity, fresh
  heartbeat progress, foreground guardian and final late-control checks. An epoch
  change refuses; the observer does not reset its baseline until it turns green.
- Report host tests, artifact/source verification, actual installation, authenticated
  private-channel health, stability and guardian recovery separately. Current
  reachability does not establish reboot, unattended, all-OEM or physical-input
  acceptance.

See [fresh-core inputs and limits](CORE-BOOTSTRAP.md) for the standalone workflow.
Neither fresh-core authentication nor the Termux upgrade configures a VPN/relay or
grants a public listener. The core listener remains fixed loopback `127.0.0.1:27184`;
this is a software security boundary, not a personal-device value to guess.
