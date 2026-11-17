# Contributing

Keep this project a small, reviewable Android shell daemon.
Changes must preserve its security boundaries unless maintainers explicitly approve a different design.

## Before a change

- Describe the user-visible problem and the supported service that it affects.
- Check the current source and tests before proposing a new abstraction.
- Keep unrelated refactors, deployment scripts, and device-specific policy separate.
- Discuss any new dependency or protocol feature before implementation.

## Required boundaries

- Require UID 2000, an explicit matching device serial, and the SELinux shell context in Enforcing mode.
- Keep the listener fixed at `127.0.0.1:27184`.
- Require TLS 1.3 and exact allowlisted controller keys.
- Reject invalid configuration and unknown services rather than granting fallback access.
- Do not add root helpers, automatic enrollment, permissive file modes, or public listeners.
- Keep command text, file contents, private keys, and screen data out of logs.

## Tests

Use Go 1.25.0 or later.
Before submission, run:

```sh
gofmt -w cmd internal
go test -count=1 ./...
go vet ./...
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -trimpath -o build/private-adbd ./cmd/private-adbd
```

Run tests on Linux to cover abstract sockets, Unix permissions, signals, and process groups.
Report your host OS, Go version, exact commands, failures, and skipped tests.
Do not describe a cross-build as a device test.
Use generated disposable keys and clearly fictional serials, such as `FIXTURE-SERIAL-001`.
Do not add device integration tests that require personal infrastructure.

The optional host installer uses Python 3.11+ and the standard library. For installer
changes, also run its portable, fictional-fixture suite from the repository root:

```sh
python -m unittest discover -s install/tests -v
python -S install/installer.py --help
```

Keep device profiles, release inputs, maintenance records, SDK tools, APKs, private
backups, and execution receipts outside the repository. Offline/model tests do not
establish Android PackageManager, native TLS, lifecycle, or physical-input acceptance.

## Safe submissions

Review the complete diff, including new files.
Do not submit real keys, allowlists, endpoint addresses, device serials, APKs, binaries, or deployment receipts.
The ignore rules help prevent mistakes. They do not replace a source and secret review.

Use short, factual descriptions.
Explain the violated invariant and how the regression test exercises it.
Follow [docs/SECURITY.md](docs/SECURITY.md) for suspected vulnerabilities.

Contributions must be compatible with the repository's MIT license.
