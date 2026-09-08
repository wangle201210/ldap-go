# Pure-Go build portability audit

The supported release matrix is Linux amd64/arm64, Darwin amd64/arm64,
Windows amd64, and FreeBSD amd64. Build all targets with `CGO_ENABLED=0`.
Cross-platform checks compile production packages; they do not execute foreign
test binaries.

## Findings and enforcement

- Windows shutdown registration now includes `syscall.SIGTERM` for both the
  server and lloadd. Go delivers console close, logoff, and shutdown events using
  this signal. Registration gives cleanup an opportunity to run before Windows
  terminates the process. See the installed toolchain's `go doc os/signal`.
- Artifact builds and both N-1/current upgrade-gate builds already explicitly
  set `CGO_ENABLED=0`. Release-script checks now enforce that convention.
- Tagged release and pull-request release workflows explicitly disable cgo for
  core tests and browser tests, including the browser fixture's Go build.
  Local `make release-gate` also exports `CGO_ENABLED=0` to all prerequisites.
  The existing race gate remains a separate CI step; it was not run in this audit.
- `internal/buildcontract` inspects the production dependency graph for all six
  targets using `CGO_ENABLED=0 go list -deps -json ./...`. It rejects selected
  cgo/SWIG sources, C imports or `#cgo` in first-party production package sources,
  and unguarded C imports/directives in imported direct-dependency packages.
  Ignored direct-dependency sources are checked against each target's build tags,
  so disabling cgo cannot silently hide an unguarded C import.

## Dependency audit

All 22 direct modules declared in `go.mod` were scanned for C imports and `#cgo`.
The production graph imports 20 direct modules on Linux, Darwin, and Windows,
and 19 on FreeBSD. `creack/pty` and `modernc.org/sqlite` are test-only imports.
No selected production dependency requires cgo on these targets.

| Module containing C-related sources | Audit disposition |
| --- | --- |
| `golang.org/x/sys` | ABI generators are excluded by `ignore`; AIX/gccgo and Hurd sources do not match the release targets. |
| `golang.org/x/text` | C-backed collation comparison tools are outside the production graph; `cases/icu.go` requires the optional `icu` tag. |
| `github.com/tarantool/go-gostcrypto` | Valgrind instrumentation requires `ctgrind` in packages outside the imported `streebog` package. |
| `github.com/creack/pty` | Test-only dependency; C-based ABI generation files require `ignore`. |

The other 18 direct modules contain no C imports or `#cgo` directives in the
scanned Go sources. The source audit used the resolved module cache, not a newer
upstream version.

`github.com/slingdata-io/godbc` builds without cgo, but ODBC use still needs an
external driver manager and driver at runtime. The existing FreeBSD connector
stub reports that ODBC is unavailable. Pure-Go compilation does not promise
feature parity or absence of optional runtime native libraries.

## Verification commands

The six-target build matrix, six release archives, archive checksums, dependency
contract, release-script checks, and focused native lifecycle tests all passed.
Each archived binary's `CGO_ENABLED=0`, `GOOS`, and `GOARCH` build settings were
verified with `CGO_ENABLED=0 go version -m "$binary"` after extraction, without
executing the binaries.

Run from the repository root:

```sh
CGO_ENABLED=0 ./scripts/test-platform-builds.sh
CGO_ENABLED=0 go test ./internal/buildcontract -count=1 -v
CGO_ENABLED=0 ./scripts/release/test.sh
CGO_ENABLED=0 go test cmd/ldap-go/main_signals_windows.go cmd/ldap-go/lloadd_signals_windows.go cmd/ldap-go/shutdown_signals_test.go -count=1 -v
CGO_ENABLED=0 go test ./cmd/ldap-go -run '^(TestShutdownSignalContract|TestServeSIGHUPGracefulShutdown|TestServeGentleHUPPreservesExistingClient|Test.*PIDFile.*|TestServeSystemdSocketActivation)$' -count=1
CGO_ENABLED=0 RELEASE_VERSION=purego-portability-review ./scripts/release/build-artifacts.sh
```

The file-list signal test runs the Windows helper implementations on the host
using portable signal constants. It checks registration and separation of
management signals from shutdown signals; it does not simulate Windows console
events. Native lifecycle tests run on Darwin arm64. Foreign targets receive build
and dependency-graph validation only.

## Write set

This audit edits only:

- `cmd/ldap-go/main_signals_windows.go`
- `cmd/ldap-go/lloadd_signals_windows.go`
- `cmd/ldap-go/shutdown_signals_test.go`
- `internal/buildcontract/purego_test.go`
- `.github/workflows/release.yml`
- `.github/workflows/release-gate.yml`
- `Makefile`
- `scripts/release/test.sh`
- `docs/pure-go-builds.md`

Concurrent server, replication, rewrite, logging, monitor, converter, and client
failover edits are preserved. No commits or cgo additions are made.
