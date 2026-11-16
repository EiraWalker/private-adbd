# Security policy

## Status and scope

private-adbd is experimental, security-sensitive software.
It has no independent security audit, support SLA, or broad device-compatibility certification.
The maintainer scope is the daemon core and its documented service subset.
No released-version support window is currently defined.

Do not use a successful build or unit test as proof of safe Android deployment.
Review device policy, host-key handling, relay identity, and lifecycle behavior for your environment.

## Trust boundaries

### Android shell, not a sandbox

The process must already run as UID 2000 in `u:r:shell:s0` with SELinux Enforcing.
The configured serial must match Android's `ro.serialno` property.
These checks do not grant privileges or establish a cryptographic device identity.

An authorized controller can execute arbitrary commands with the daemon's shell privileges.
File sync can access paths outside `/data/local/tmp`, subject to kernel permissions and SELinux.
The narrow service dispatcher is not a command filter or filesystem sandbox.

Other processes with the same shell UID can threaten the daemon and its policy files.
A compromised Android system or authorized controller is outside this protection boundary.
Do not run the daemon if you do not trust other shell-UID processes.

### Transport and endpoint identity

The executable binds only to IPv4 `127.0.0.1:27184`.
The initial ADB CNXN/STLS exchange precedes TLS and carries no authenticated service access.
There is no plaintext service fallback.

TLS requires version 1.3 and a client certificate with an exact allowlisted RSA public key.
The handshake also verifies private-key possession.
Certificate names, issuer signatures, and comments do not authorize a controller.
The server disables TLS session tickets.

The server creates an ephemeral certificate and private key in memory.
This implementation does not make stock ADB pin that server certificate.
Use an external authenticated tunnel that verifies the device endpoint and restricts controller access.
Do not publish the loopback listener through an unauthenticated public forward.

Peer identity, relay ACLs, VPN ownership, and relay availability belong to the deployment, not this repository.

### Allowlist files

`--keys` names an absolute path to an Android-format `adbkey.pub` allowlist.
The parser accepts one or two distinct RSA-2048 keys with exponent 65537.
An empty file, malformed entry, duplicate key, or oversized file fails closed.
No network request can enroll a new key.

On Unix, the daemon requires owner-only file permissions and rejects a writable-by-others immediate parent directory.
It rejects symlinks at the file and immediate-parent checks, and detects some concurrent file changes.
It does not validate every ancestor or the key-file owner's UID.
These checks do not protect against a malicious process that shares UID 2000.

Before launch, verify ownership as UID 2000 and use directory mode `0700` and file mode `0600`.
Keep all ancestors trusted and avoid symlinks throughout the path.
Windows unit tests cannot establish these Unix permission guarantees.

## Key rotation and revocation

Keep controller private keys on trusted hosts only.
Transfer public keys through an already trusted connection.
Do not publish real allowlists, key fingerprints tied to devices, or controller certificates as examples.

Install an owner-only replacement file from the trusted shell context.
The daemon polls every second.
Changed policy bytes, read failures, or invalid file state cancel the daemon context and close current sessions.
The daemon does not reload keys. Restart it to accept the new policy.

Polling introduces a revocation delay and depends on process scheduling.
Revocation cannot undo completed commands, transferred files, or side effects.
It cannot reliably remove descendants that deliberately escape the managed process group.
Rebuild trust separately after a controller or device compromise.

## Resource and lifecycle limits

The executable configures at most eight connections and sixteen streams per connection.
The transport bounds packet sizes and uses a handshake deadline.
These limits reduce selected resource risks. They do not establish denial-of-service resistance.

On Linux, shell cleanup targets the managed process group before it reaps the leader.
Descendants can escape through `setsid` or `setpgid`.
There is no boot service, restart supervisor, watchdog, root helper, or persistence guarantee in this source release.
Android and OEM power management can terminate the process.

The daemon does not implement PTYs, reverse forwarding, arbitrary TCP services, or wireless pairing.
Only bounded `scrcpy_*` abstract socket names can connect through the abstract-socket service.

## Logs and reports

The daemon does not intentionally log command arguments, screen data, or transferred file contents.
Startup logs contain the actual device serial.
Errors can contain local paths.
Redact operational logs before sharing them.

Never attach private keys, real allowlists, endpoint addresses, device identifiers, packet captures, or unredacted device output.
Use disposable generated keys and fictional identities in reproductions.

## Report a vulnerability

Do not disclose an exploitable vulnerability in a public issue.
Use GitHub private vulnerability reporting if the published repository enables it.
If it is unavailable, ask the maintainer for a private contact without disclosing exploit details.
This local source preparation does not imply that private reporting is already enabled.

Include a minimal reproduction, affected source revision, expected boundary, and observed behavior.
Describe your test environment without personal endpoints or identifiers.
Do not claim a repair until a regression test and the affected path verify it.

The MIT license gives no warranty.
