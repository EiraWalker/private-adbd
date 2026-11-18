# Fresh core bootstrap (standalone, experimental)

The supported installer computer is **Windows**, running Python 3.11+ and the
official `adb.exe`. The target is an Android device. Linux-desktop installer
support is outside scope; all Android-side security checks below still apply.
No Termux APK upgrade is needed for this core-only installation path.

See [ACCEPTANCE.md](ACCEPTANCE.md) for the bounded Windows and physical Android
acceptance results. One accepted device does not certify every Android/OEM/ABI.

`core_bootstrap.py` installs the daemon and the reviewed shell supervisor through
**one already authorized, explicitly selected official ADB transport**. It needs no
Termux, APK, root, wireless-debugging changes, permission grants, VPN or relay.
It does not create an authorized bootstrap connection. It does not install an APK,
enroll keys, configure networking, replace system adbd, or provide reboot persistence.

This is **fresh-only**, not an update mode. It accepts an absent base, or an empty,
non-symlink UID-2000 directory already at mode 0700. Existing contents, unknown
owners, staging collisions, and an existing fixed-port listener cause refusal.
Never clear an existing deployment to make it pass. Use the maintenance-aware
upgrader for supported existing deployments instead.

## Trusted local inputs

Keep all inputs, artifacts and receipts outside this checkout. Python 3.11+ and
its standard library suffice, including `python -S`. No SDK/APK tool is required.

The profile has exactly these fields (all identifiers here are fictional):

```json
{
  "schema": 1,
  "serial": "FIXTURE-SERIAL-001",
  "base": "/data/local/tmp/fixture-core",
  "transport": {
    "kind": "adb",
    "argv": ["C:/Android/platform-tools/adb.exe"],
    "serial": "FIXTURE-AUTHORIZED-TRANSPORT"
  }
}
```

On Windows, use the absolute native `adb.exe` path in the one-element argv.
The executable must come from a separately trusted official platform-tools install;
this tool does **not** certify an arbitrary executable merely because it is named
ADB. Command prefixes, automatic device selection, discovery and SSH are excluded.
Every ADB invocation includes `-s` and the exact supplied transport selector.
Only the specifically allocated acceptance endpoint uses a different selector.
The profile's independent `serial` is exact `ro.serialno`, **not** the transport
selector. Tokens are validated, never trimmed or repaired. The base must be one
safe, non-hidden component directly under `/data/local/tmp`.

A local bundle manifest binds all payload bytes. Replace the illustrative digest
placeholders with lowercase SHA-256 values of the actual local files:

```json
{
  "schema": 1,
  "artifacts": [
    {"abi": "arm64-v8a", "source": "private-adbd-arm64", "sha256": "REPLACE_WITH_64_LOWERCASE_HEX"}
  ],
  "service": {"source": "service.sh", "sha256": "REPLACE_WITH_64_LOWERCASE_HEX"},
  "keys": {"source": "authorized.pub", "sha256": "REPLACE_WITH_64_LOWERCASE_HEX"},
  "controller": {"source": "controller.pub", "sha256": "REPLACE_WITH_64_LOWERCASE_HEX"}
}
```

Sources are regular, single-link files relative to the bundle manifest; host
symlinks, junctions, reparse points and traversal are rejected. Supply a trusted
locally built ELF for every ABI you intend to support. The installer checks each
pinned asset's ELF class, little-endian/version/type and `e_machine`, and selects
only the actual `ro.product.cpu.abi`. Supported header mappings are `arm64-v8a`,
`armeabi-v7a`, `x86_64`, and `x86`. Missing or unknown ABI means refusal, not a
fallback. Header validation is **not** proof that a binary will execute on Android
or that these architectures/OEMs have been device-certified.

`service.sh` must be a byte-exact copy of this checkout's reviewed
`lifecycle/service.sh`, with its own manifest hash. The tool substitutes only the
unique exact `BASE=/data/local/tmp/private-adbd` line for the validated base.
It preserves the fixed service/self/daemon argv and fixed loopback port 27184.
It never evaluates, sources or invents scripts from device data.

Both key inputs are **public Android adbkey.pub format**, not PEM/private keys or
SSH public keys. Never point either field at a private key. The bootstrap is
intentionally narrower than the daemon's two-key rotation policy: its allowlist
must contain exactly the one public key selected by `controller` (comments may
differ). This lets successful private-channel authentication establish possession
of that exact controller key, rather than some other key in a two-key list.
The matching private key must **already be loaded in the existing host ADB
server**. The installer never reads, creates or copies a private key, changes the
host environment, registers a key, restarts the server or runs `kill-server`.

## Plan and authorize

```powershell
python -S install/core_bootstrap.py plan --profile C:/private/profile.json --bundle C:/private/bundle.json
python -S install/core_bootstrap.py --help
```

Planning is entirely local, including `apply` or `verify` **without** `--execute`:
zero ADB calls, no output directory created, and no readiness claim. Plans return
SHA-256 bindings of the **exact input JSON bytes**. This is not canonicalized JSON.

Before execution, the responsible owner supplies a local short-lived handoff with
this existing schema. It is an operator/cooperating-writer assertion, not a
cryptographic owner signature or a device-wide lock:

```json
{
  "schema": 1,
  "profile_sha256": "EXACT_PROFILE_BYTES_SHA256_FROM_PLAN",
  "release_sha256": "EXACT_BUNDLE_BYTES_SHA256_FROM_PLAN",
  "serial": "FIXTURE-SERIAL-001",
  "owner": "authorized-owner",
  "ready": true,
  "released": true,
  "no_parallel": true,
  "issued_at": "REPLACE_WITH_CURRENT_TIME_WITH_TIMEZONE",
  "expires_at": "REPLACE_WITH_EXPIRY_WITH_TIMEZONE"
}
```

The validity interval must contain the current host time and be at most 30 minutes.
Changing either JSON file's bytes requires a new handoff. Execution checks this
binding before any device access and again at deployment transition boundaries.
Keep it valid for the entire operation. Owner handoff must cover the target shell
namespace: do not run other publishers, lifecycle controls or same-UID writers.

```powershell
python -S install/core_bootstrap.py apply --execute --profile C:/private/profile.json --bundle C:/private/bundle.json --maintenance C:/private/handoff.json --output C:/private/new-core-receipt
```

The evidence directory must be new, outside the repository, under an existing
parent, and private to its owner (Windows ACLs are checked using the shared output
helper). Stdout contains a small JSON result; stderr contains fixed refusal gates,
not command text, key contents or device identifiers.

## Deployment and acceptance boundary

1. Read actual UID 2000, `u:r:shell:s0`, Enforcing, independent serial and ABI;
   check required shell/toybox tools, ancestors, empty/absent base, and absence of
   any pre-existing listener on the one fixed port. There is no port scan.
2. Reserve an exclusive sibling lock and random-token sibling staging directory,
   both 0700, each with a 0600 token marker. No recursive mkdir/removal occurs.
3. Transfer four pinned snapshots: ELF, reviewed/rebased service, public allowlist,
   and exact verified serial plus one LF in `service.serial`. Each push target
   must be absent in the owned namespace. Check exact file set, hashes, UID,
   regular-file type and link counts before sealing. Executable/service modes
   are 0700; allowlist/serial modes are 0600. No unknown content is chmodded.
4. Recheck and publish by same-parent, no-clobber, non-nesting rename. An approved
   empty base is removed only by `rmdir`, never recursive deletion. Exact marker,
   payload hashes, permissions and staging absence are read back.
5. Dispatch the fixed reviewed service's `start` once. A missing/failed response
   is not retried. Prove the exact recorded child executable/inode/hash/argv,
   UID/context/boot/starttime and socket-FD ownership of the one IPv4 loopback
   listener; also require healthy supervisor status. `/proc` visibility denial
   is an explicit unsupported acceptance boundary, not a positive result.
6. Through the selected official transport allocate this round's `tcp:0` forward
   to `tcp:27184`. Verify the exact newly allocated tuple and inspect the host's
   allocated listener addresses: only `127.0.0.1` / `::1` are accepted (never an
   all-interface listener from a shared ADB server started with `-a`). This local
   inspection uses Windows PowerShell `Get-NetTCPConnection` or Linux `/proc`;
   unavailable/unsupported inspection fails acceptance. Refuse an existing
   transport at its endpoint, then connect only `127.0.0.1:<allocated-port>`.
   Read independent serial, UID 2000, shell context, Enforcing and ABI **through
   that private authenticated channel**. A listener, start exit code or ADB
   `connect` message alone is never enough.
7. Before disconnect/removal, recheck that the forward tuple is still ours.
   Disconnect only that round's endpoint, read back its absence, remove only
   that exact forward and read back absence. Other forwards/devices are untouched.
   Recheck child/listener binding and payloads, then remove only the exact
   token-owned lock. The deployment marker remains inside the published base.

This is a cooperating-writer protocol, **not** a kernel atomic compare-and-swap or
protection from another hostile process sharing Android shell UID. The shared ADB
server and the selected bootstrap device path remain trusted prerequisites.
No new daemon port flag is introduced. Private TLS acceptance requires the
existing host server's matching key; if it is not loaded, authentication fails,
the deployment is retained, and `ready` is not claimed. Arrange key loading
separately without this tool restarting a shared server.

## Lost responses and verification

Every subprocess dispatch has a durable intent and a bounded timeout. Receipts
store exit status, output lengths and hashes, not raw command output. Unknown
push/publication/start outcomes are **never automatically replayed**. No rollback,
key rotation, service kill, stage scavenger or overwrite path exists.

```powershell
python -S install/core_bootstrap.py verify --execute --profile C:/private/profile.json --bundle C:/private/bundle.json --maintenance C:/private/current-handoff.json --output C:/private/existing-core-receipt
```

Verify requires the original private receipt and bound input bytes. It reconstructs
payload policy from those inputs rather than trusting receipt-supplied filenames
or hashes. It does not push, republish or start. It repeats exact published-file,
child/listener and authenticated channel checks, and can finish exact owned-lock
cleanup after acceptance. It invokes supervisor `status` (which takes its normal
locks); it is not a claim of zero device writes. `--execute` explicitly authorizes
these status locks, the ephemeral forward/connect/disconnect and owned cleanup.

If publication never happened, the service is not alive, an old forward's outcome
is unknown, or ownership cannot be established, verify refuses and leaves the
scene for owner inspection. It does not make an incomplete deployment succeed.
Do not rerun apply with a new output directory as an uncertainty workaround.

## Host verification is not device acceptance

```powershell
python -m unittest discover -s install/tests -p test_core_bootstrap.py -v
python -S install/core_bootstrap.py --help
```

The suite uses fictional serials, synthetic public numbers and ELF headers. Its
fake-ADB process is a real separate host subprocess via a test-only executable
adapter; it models Android responses, not Android itself. It exercises CLI
planning, selected argv, identity/ABI/key gates, handoff binding, publication/start
failure policy, authentication failure and ownership-safe forward cleanup.
Generated shell scripts are also syntax-checked when a host shell exists.
Genuine POSIX namespace/hash/mode/link tests are explicitly skipped on Windows.
None of these tests establishes Android mksh/toybox, SELinux, native TLS, daemon
execution or broad OEM acceptance. Real fresh-device acceptance must be separately
authorized on a genuinely empty target; never clear an existing device for a test.
