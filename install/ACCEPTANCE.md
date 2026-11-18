# Windows installer acceptance

## Scope

The supported installer computer is Windows. The installation target is Android.
The executed core source is commit `8123873aaa11bd3fdc6208300a49eb719a9b1251`.
Later documentation-only commits do not change this source binding.

This record covers one real Android arm64 device with 4096-byte kernel pages.
It does not certify every Android version, OEM, ABI, or page size.
The installer uses an existing authorized ADB connection and an explicit public-key policy.
It does not require Termux, an APK upgrade, root, new pairing, or network enrollment.

## Host results

- Windows 11 with Python 3.14.9 and site packages disabled (`-B -S`).
- Complete installer suite: 264 executed, 257 passed, seven POSIX-specific skips, zero failures or errors.
- Runtime input hashes matched before and after the complete run.

- Independent Standards and Spec reviews found no unresolved issues in the Windows compatibility changes.
- Daemon Go sources did not change. Their existing source-bound test, vet, and arm64 build results remain separate evidence.

The seven skipped tests are not passing POSIX coverage.
An earlier foreground run exceeded its tool deadline and remains an incomplete run.
The final complete run used a tracked background process and exited zero.
Linux-desktop installer support is outside this delivery scope.

## Physical installation results

1. Select a genuinely absent namespace without removing the existing deployment.
2. Run the published `core_bootstrap.py apply --execute` with pinned inputs and current owner authorization.
3. Check the installed files, permissions, process identities, and loopback listener ownership.
4. Authenticate through the private channel and verify device identity, shell UID2000, Enforcing, and ABI.
5. Disconnect and remove only the allocated acceptance endpoint and forward.

The final single-pass run exited zero and returned `ready=true`.
The installer did not require a Termux APK upgrade.
An earlier deployment used the same pinned daemon and supervisor bundle.
Its process identities remained unchanged across 11 samples.
The measured observation had a duration lower bound of 124 seconds.
These observations cover a limited interval, not overnight use or reboot recovery.

## Compatibility corrections and recovery

Initial physical runs exposed two host-text assumptions:

- Windows ADB returned CRLF identity and postcondition text.
- ADB returned a list terminator, including a blank terminator for an empty forward list.

The parser now accepts only the specified LF/CRLF representations and one permitted list terminator.
Identity fields, three-field forward rows, and ownership checks remain strict.
Malformed framing and noise still cause refusal. Binary output remains unchanged.

After a post-start observation failed, the original receipt and token completed `verify` successfully.
Verify did not repeat deployment or start.
A later fresh namespace tested the final code through one complete apply operation.
The failed runs remain recorded separately from these successful results.

## Cleanup and existing environment

Both test deployments stopped through their supported controls.
The operator verified ownership before removing their files, namespaces, staging areas, locks, and forwards.
The existing deployment did not become an artificial empty target.

The operator restored the existing environment in a separate procedure.
Its reviewed publisher update and supported native reconcile completed.
The operator did not replace an APK or edit Stop, safety, or pending preferences directly.
The user completed the existing Enable confirmation.
Subsequent checks confirmed:

- `userStopped=false` and `safetyPaused=false`.
- A foreground guardian with phase `healthy`.
- Three advancing healthy samples with unchanged core process identities.
- An authenticated shell through the formal private-network entrypoint.
- System Wireless debugging disabled and no owned native lease.
- No pending start marker or remaining test namespaces and locks.

These restoration steps are not bootstrap features or additional bootstrap prerequisites.
The bootstrap still refuses occupied targets and unknown ownership.

## Limits

Unattended reboot recovery, pure-cellular cold bootstrap, and other Android/OEM/ABI combinations were not accepted by this run.
No physical test covered a 16KiB-page device.
Optional APK-maintenance upgrades remain a separate workflow and do not inherit this core-install result.

Use [CORE-BOOTSTRAP.md](CORE-BOOTSTRAP.md) for Windows commands and input requirements.
Use [ADAPTATION.md](ADAPTATION.md) for mode boundaries and capability checks.
