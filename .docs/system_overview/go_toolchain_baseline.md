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

## 10. Continuous Integration

`.github/workflows/go.yml` runs on every pull request and on every push to
`trunk_dev`, on a GitHub-hosted `ubuntu-24.04` runner. It installs the Go
version that `go.mod` declares, with `GOTOOLCHAIN=local` and
`GOFLAGS=-mod=readonly`, restores no build or module cache, and runs
`go mod download`, `go mod verify`, `go build ./...`, `go vet ./...`, and the
tests of every package of the module. One more step runs
`GOOS=darwin GOARCH=arm64 go vet ./...`. It type-checks the files that build
only on macOS and runs no test.

Before the tests, the workflow installs Nomad 2.1.1, Vault 2.2.2 and
SPIRE 1.14.4 from release downloads that it checks against reviewed SHA-256
values, and pulls the container images that the tests run by reviewed digest.
It reads the SPIRE value from `scripts/internal/spire_release.sha256`, the pin
file that `scripts/72_supported_local_setup.sh` and
`scripts/73_supported_local_proof.sh` check SPIRE against, so CI and those
scripts accept the same SPIRE file.
So the `es/app` integration tests that start a Nomad agent with the Docker
driver, and the supported-local setup test that runs Vault and SPIRE, run on
that runner. The job sets `AWS_EC2_METADATA_DISABLED=true`: the runner's EC2
metadata endpoint does not answer, and Nomad's AWS fingerprinter would
otherwise fail the client of a test agent.

`.github/ci/environment-only-tests.txt` is the single statement of what the
test step excludes and of which tests exclude themselves on that runner. It
has two kinds of lines. An entry names a test or subtest that cannot pass on
that runner for host reasons. `.github/ci/go_test_gate.py` skips those entries,
each only in the package it names. A `skips-itself` line names a test or
subtest that skips itself on that runner. The test step fails the run unless
the tests that skipped themselves are exactly the tests that those lines name,
so a test that skips itself on the runner needs a line, and a line cannot
outlive its reason. The log of the step names every test that skipped itself.
For every package the step also fails the run unless every top-level test that
`go test` lists for the package, and that is not an entry, reported a verdict.

`go test` reads a test path as the start of a path, so the skip for a listed
subtest also covers every test whose path starts with the path of that entry,
and a skipped test leaves no trace in the output. The test step therefore runs
a package that has an entry for a subtest a second time, with a test binary
that writes down every test that `-skip` drops. It fails the run unless those
tests are exactly the entries of that package. For that one run
`go test -overlay` builds the test binary with a copy of
`src/testing/match.go` of the Go standard library, to which the gate adds the
call that writes the name down. The installed toolchain is not changed, and no
other run uses the copy. The gate makes the copy only from the file of the
exact Go version that it names, so a change of the Go baseline has to review
that file and change the gate in the same change. That run needs a Go
installation outside the module cache, as `actions/setup-go` makes one on the
runner: the `go` command does not let `-overlay` replace a file beneath
`GOMODCACHE`, so with a toolchain that the `go` command downloaded itself the
test step fails and shows that error.

A second blocking step judges every entry twice: in a run of its whole package
with nothing skipped, and in a `go test` of its own. It fails the run when an
entry no longer fails on the runner in one of the two, so an entry cannot
outlive its reason. An entry fails there only if the testing package reported
its failure. A test that was running when the test binary stopped has reported
none, so a test that ends the process without reporting, for example with
`os.Exit` or `log.Fatal`, cannot be listed. The run of a package has to come
to its end. When a listed test panics, the package runs again without it. The
step fails when a run stops and no listed test reported a failure as it
stopped: a test that is not listed, or the time limit of `go test`, stopped
it. It also fails the run when the run of an entry for a subtest starts
another test under the path of that entry.
Every `go test` of the gate that runs tests gives each test binary a time
limit of 20 minutes instead of the default of 10 of `go test`: the slowest
package has reached that default on a slow runner, and runners differ by up to
half in speed. A test binary that runs longer panics with the stacks of its
goroutines inside the job's own limit of 90 minutes, so the log shows where it
hung.
`.github/ci/go_test_gate_selftest.py` checks these behaviors on every run before
the tests. It also holds the workflow file by its SHA-256, so every edit of the
workflow has to change that value in the same change.

A green run is validation evidence for the committed tree on that runner
image. It is not design authority. It is not a macOS run, a race-detector run,
a Linux runtime proof, a Remote Alpha proof, or a supported-local proof, and it
does not replace the exact-Go preflights of the supported scripts. The Nomad,
Vault and SPIRE that a test starts there are throwaway test instances, not a
deployment. It does not show that a test named in the list passes: on that
runner those tests fail or skip themselves.

A second workflow, `.github/workflows/go-macos.yml`, runs on the same events
on a GitHub-hosted `macos-26` runner, because many tests of the
`execution-substrate/scripts` package also run on the operator's Mac, and a
change that breaks them only on macOS passes the Linux run. The runner runs
the same major version of macOS as the operator's Mac, so the tests meet the
tools that this version of macOS ships, such as `/bin/bash`, `stat`, `chmod`
and `/usr/bin/openssl`. It sets up Go the
same way, runs `go mod download` and `go mod verify`, and then runs the
self-check and the two gate steps for the packages that `./scripts/...` names,
with a list of its own: `.github/ci/environment-only-tests-macos.txt`, under
the same rules. `go_test_gate.py` takes that package pattern as an optional
third argument; without it the gate covers every package of the module. The
self-check holds that workflow file by its SHA-256 as well. A green macOS run
is validation evidence that the tests of those packages that its list does not
name pass on that runner image. It is not a run of the other packages on
macOS, and not a run on the operator's Mac.

## 11. Explicit Non-Claims

- no runtime behavior change;
- no CI claim beyond section 10;
- no vendoring;
- no system-wide toolchain manager;
- no Linux runtime proof;
- no PostgreSQL dependency;
- no external database service;
- no deployment performed.
