# Optional Termux maintenance source package

**private-adbd is the authoritative source for this maintenance extension.**
Termux is its compilation/integration target: the Java classes still compile into
`com.termux`'s APK, not into the private daemon ELF. Source ownership and APK build
ownership are different. This is a source package, not a new AAR/Gradle module,
auto-installer, permission grant, or replacement for the Termux application.
The core private-adbd bootstrap does **not** require this optional APK extension.

## Contents and exact baseline

- `overlay/`: 16 unchanged source files (seven production Java classes, seven
  Java tests, the maintenance helper, and its protocol document).
- `patches/private-adb-service.patch`: the **only** existing-service change,
  exported as a full-index Git diff. Its blank context line has no space prefix
  so the stored patch also passes Git whitespace checks; real Git application
  still reconstructs the exact target bytes. No second full service source copy.
- `fixtures/PrivateAdbService.base.java`: exact **test-only** predecessor from
  the baseline below; never copy it into a production integration.
- `manifest.json`: provenance and SHA-256 identities for all 16 overlay files,
  the patch, the fixture, and all 17 reconstructed Termux targets. Git blob
  identities and original target modes are also retained.

Required Termux baseline: `b63c00ce197df08df707fe4da2e8d62d3973e5ff`.
Historical source: `15e90b14ec36fe4b107520ea6b237557b170ea6c`, whose parent is
that baseline. Reconstruction preserves every target byte, package/class name,
service behavior, protocol, deadline, flag and permission from that source.
Do not substitute an arbitrary upstream Termux checkout or apply to a checkout
that already includes the historical maintenance feature.

The baseline's existing `PrivateAdbService`, `AutostartConfig`, native-window and
NSD guardian code, component/activity hooks, and matching CLI/backend integration
are prerequisites. Keep its already documented debuggable `com.termux`, separately
authorized WSS grant, explicit battery exemption, local pairing, app-private
configuration and authenticated backend/heartbeat provisioning requirements.
This package provisions none of them and adds no personal infrastructure
requirement. It does not replace terminal/IME code, the manifest, permissions,
version metadata, user state, keys, or the existing backend.

The unchanged protocol and lifecycle limits are documented in
[overlay/contrib/private-adb/maintenance.md](overlay/contrib/private-adb/maintenance.md).
That document's implementation/build observations describe the historical source,
not a new build or device acceptance performed by this source migration.

## Manual integration (Windows PowerShell)

Use a **dedicated, disposable, clean checkout** at the exact baseline; never run
this against an active worktree, device, or SDK directory. Review the manifest
and patch first. Set the two paths to existing directories. These commands only
prepare host source; they do not build, install, commit or contact a device.
Per-file copying avoids PowerShell directory-copy nesting such as `app/app`.

```powershell
$ErrorActionPreference = 'Stop'
$module = (Resolve-Path 'PATH-TO-private-adbd/integrations/termux/maintenance-api').Path
$termux = (Resolve-Path 'PATH-TO-dedicated-clean-termux-checkout').Path
$m = Get-Content -LiteralPath (Join-Path $module 'manifest.json') -Raw | ConvertFrom-Json
$head = git -C $termux rev-parse HEAD
if ($LASTEXITCODE -ne 0 -or $head -ne $m.provenance.baselineCommit) { throw 'Wrong Termux baseline' }
$dirty = git -C $termux status --porcelain=v1 --untracked-files=all
if ($LASTEXITCODE -ne 0 -or $dirty) { throw 'Termux checkout must be clean' }
$patch = Join-Path $module $m.patch.source
if ((Get-FileHash -LiteralPath $patch -Algorithm SHA256).Hash -ine $m.patch.sha256) { throw 'Patch drift' }
foreach ($entry in $m.overlay) {
    $source = Join-Path $module $entry.source
    if ((Get-FileHash -LiteralPath $source -Algorithm SHA256).Hash -ine $entry.sha256) { throw 'Overlay drift' }
}
git -C $termux -c core.autocrlf=false -c core.eol=lf apply --check -- $patch
if ($LASTEXITCODE -ne 0) { throw 'Patch does not match baseline; stop' }
foreach ($entry in $m.overlay) {
    $source = Join-Path $module $entry.source
    $target = Join-Path $termux $entry.target
    $parent = Split-Path -Parent $target
    [System.IO.Directory]::CreateDirectory($parent) | Out-Null
    Copy-Item -LiteralPath $source -Destination $target
}
git -C $termux -c core.autocrlf=false -c core.eol=lf apply -- $patch
if ($LASTEXITCODE -ne 0) { throw 'Patch failed; inspect this disposable checkout, do not retry blindly' }
foreach ($entry in $m.targets) {
    $target = Join-Path $termux $entry.path
    if ((Get-FileHash -LiteralPath $target -Algorithm SHA256).Hash -ine $entry.sha256) { throw 'Final target byte drift' }
}
```

Do not normalize line endings or loosen the baseline if checks fail. The Git
configuration overrides above are command-local; no global or live-repository
configuration is changed. A nonmatching checkout must be investigated separately,
not repaired by replacing its entire service. Integrating these files into the
APK still uses the existing Termux build process and separately managed signing.

## Portable host verification

From the private-adbd repository root, with Python 3.9+ and Git on PATH:

```sh
python -B -S -m unittest discover -s integrations/termux/maintenance-api/tests -p test_overlay.py -v
```

The stdlib-only suite stages the exact baseline fixture and the overlay in
`tempfile` scratch directories, runs real `git apply --check` and `git apply`,
and checks all 17 SHA-256 and Git blob identities. It also rejects altered patch
context without changing the fixture, byte drift, inventory drift, unsafe paths,
and a rebased fixture. It does not need either historical source checkout, a Git
repository in the scratch directory, third-party Python packages, SDK, Gradle,
ADB, keys or a device. `TMPDIR`/`TEMP` may select an existing private scratch root.

The previous **297 host-test** result remains historical evidence, not rerun or
expanded by these packaging tests. Android maintenance API acceptance remains
pending: host reconstruction does not establish real socket/SELinux access,
peer credentials, APK replacement, expiry, Stop/safety or OEM lifecycle behavior.
No Android build or device operation is part of this source migration.

## License and provenance

The private-adbd repository's [MIT license](../../../LICENSE) is unchanged;
new packaging documentation and tests follow it. Imported historical Termux
source, the existing-service diff and the baseline test fixture retain their
original provenance. [LICENSE.termux.md](LICENSE.termux.md) preserves the original
Termux license declaration; its relative exception links refer to that historical
Termux tree. That repository declares GPLv3-only in `LICENSE.md` and
`contrib/private-adb/README.md`; this relocation does not
silently relicense that material as MIT. Preserve original notices and applicable
Termux distribution obligations when building or distributing the combined APK.
