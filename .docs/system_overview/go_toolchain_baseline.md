# Go Toolchain Baseline

## 1. Current Status

Go 1.26.5 is the current Execution Substrate minimum Go version and the
supported scripted build/proof toolchain. This document describes current
repository behavior only with the implementation that raises `go.mod` to
`go 1.26.5`, updates the supported scripts, and regenerates the tracked
Dockerfile.

The reliable-submit persistence tranche selects one database dependency for
private admission-local source only: `modernc.org/sqlite v1.54.0`, with the
exact `modernc.org/libc v1.74.1` transitive coupling. No PostgreSQL dependency,
runtime database service, global ES configuration, or submit wiring is selected
by this toolchain baseline.

## 2. Module Policy

The module declares:

```go
go 1.26.5
```

The repository deliberately commits no explicit `toolchain` directive. The Go
baseline remains exact Go 1.26.5. Reliable-submit SQLite dependency changes are
owned by the reliable-submit persistence tranche, not by a Go-version upgrade.

## 3. Toolchain-Selection Policy

Supported build-bearing scripts invoke Go with `GOTOOLCHAIN=local` and check
that `go version` reports exactly `go1.26.5` before compiling repository Go
source. The supported scripts must not rely on hidden automatic toolchain
download.

An older local Go toolchain fails closed. A newer local Go toolchain is not
silently treated as the exact supported proof/build toolchain. Future Go patch
upgrades require a bounded baseline update that changes the module declaration,
script preflights, setup material, documentation, and validation evidence
together.

## 4. Supported Builds

The supported build surface includes host development/build commands,
CGO-free linux/amd64 builds, CGO-free linux/arm64 builds, and every command
package under `cmd/...`.

Remote Alpha payload builds preserve `CGO_ENABLED=0 GOOS=linux GOARCH=amd64`
for `cmd/es` and `cmd/es-runtime-support`. Supported-local proof paths preserve
their current CGO-free Linux build posture, including the documented arm64
proof build.

## 5. Setup And Docker Treatment

The supported Linux setup path installs exact official Go 1.26.5 archives under
`/usr/local/go` after SHA-256 verification. It supports only the documented
Linux amd64/x86_64 and arm64/aarch64 architecture mappings and fails closed for
unsupported Linux architectures.

The generated Control Plane build Dockerfile uses the exact official build
image `golang:1.26.5-alpine3.24` with `ENV GOTOOLCHAIN=local`. The tracked
`.out/Dockerfile` is generated output owned by
`scripts/generate_control_plane_dockerfile.sh`; it must not be hand-edited.
The Docker image is selected only as a build image. This tranche does not run,
pull, or deploy Docker images.

## 6. Offline Behavior

Warm-cache `GOPROXY=off` builds are supported when the exact Go 1.26.5
toolchain and current module dependencies are already available locally. A cold
cache requires explicit prior dependency and toolchain availability. This
baseline introduces no vendoring claim.

## 7. Compatibility And Runtime Limits

The Go 1 source compatibility promise does not replace repository validation.
Linux cross-build success is not Linux runtime proof. Process handling, signal
handling, filesystem ownership, TLS/SPIFFE behavior, and privilege-helper
runtime behavior still require later Linux runtime evidence.

## 8. Database Dependency Scope

The exact Go 1.26.5 baseline now supports the private reliable-submit SQLite
source using `modernc.org/sqlite v1.54.0` under the existing CGO-free build
requirements. The dependency is limited to
`es/admission/internal/reliablesubmit`; it is not runtime wiring, a public
storage API, a PostgreSQL client decision, or an external database operations
claim.

## 9. Rollback

Rollback of a Go baseline change still moves the `go.mod` baseline, script
preflights and setup material, generated Dockerfile, tests, and documentation
together. Rollback of the reliable-submit SQLite source is a separate
source/dependency rollback and must not imply runtime-state migration, schema
migration, or storage repair because the tranche remains unwired.

## 10. Explicit Non-Claims

- no runtime behavior change;
- no CI system introduced;
- no vendoring;
- no system-wide toolchain manager;
- no Linux runtime proof;
- no PostgreSQL dependency;
- no external database service;
- no deployment performed.
