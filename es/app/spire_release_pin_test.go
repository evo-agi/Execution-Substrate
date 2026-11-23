package app_test

import (
	"archive/tar"
	"bufio"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// These tests pin that the supported-local scripts use a SPIRE release file
// only after its SHA-256 matches the line that
// scripts/internal/spire_release.sha256 holds for it: the shared helper
// scripts/internal/spire_release.sh, the setup script, which unpacks the file,
// and the proof wrapper, which stages it for the guest.

const (
	spireTestAMD64Asset = "spire-1.14.4-linux-amd64-musl.tar.gz"
	spireTestARM64Asset = "spire-1.14.4-linux-arm64-musl.tar.gz"
)

// spireTestDistribution writes a gzip tar laid out like a SPIRE release
// (spire-1.14.4/bin/spire-server and spire-agent) and returns its path and
// SHA-256. It is not a SPIRE release, so no repository pin matches it.
func spireTestDistribution(t *testing.T, dir string) (string, string) {
	t.Helper()
	var archive bytes.Buffer
	compressed := gzip.NewWriter(&archive)
	writer := tar.NewWriter(compressed)
	for _, name := range []string{"spire-1.14.4/", "spire-1.14.4/bin/"} {
		if err := writer.WriteHeader(&tar.Header{Name: name, Typeflag: tar.TypeDir, Mode: 0o755}); err != nil {
			t.Fatal(err)
		}
	}
	for _, name := range []string{"spire-server", "spire-agent"} {
		body := []byte("#!/bin/sh\necho synthetic " + name + "\n")
		if err := writer.WriteHeader(&tar.Header{Name: "spire-1.14.4/bin/" + name, Typeflag: tar.TypeReg, Mode: 0o755, Size: int64(len(body))}); err != nil {
			t.Fatal(err)
		}
		if _, err := writer.Write(body); err != nil {
			t.Fatal(err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	if err := compressed.Close(); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "synthetic-spire.tar.gz")
	if err := os.WriteFile(path, archive.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(archive.Bytes())
	return path, hex.EncodeToString(sum[:])
}

// spireTestSwappingCopy replaces cp with one that writes other bytes than
// the source's to the destination, as a source that changes between a check
// and a copy would.
const (
	spireTestSwappedCopy  = "not the file that was checked\n"
	spireTestSwappingCopy = `cp() {
  local destination
  for destination in "$@"; do :; done
  printf 'not the file that was checked\n' > "$destination"
}
`
)

func spireTestWritePins(t *testing.T, path, body string) string {
	t.Helper()
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func spireTestRepoPins(t *testing.T) map[string]string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(executionPlatformRepoRoot(t), "scripts", "internal", "spire_release.sha256"))
	if err != nil {
		t.Fatal(err)
	}
	pins := map[string]string{}
	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		sum, name, found := strings.Cut(scanner.Text(), "  ")
		if !found {
			t.Fatalf("malformed pin line %q", scanner.Text())
		}
		pins[name] = sum
	}
	if len(pins) == 0 {
		t.Fatal("the repository pins no SPIRE release file")
	}
	return pins
}

func spireTestHelper(t *testing.T) string {
	t.Helper()
	return filepath.Join(executionPlatformRepoRoot(t), "scripts", "internal", "spire_release.sh")
}

func TestSpireReleasePinLookup(t *testing.T) {
	helper := spireTestHelper(t)
	for name, sum := range spireTestRepoPins(t) {
		output, err := auditScriptSource(t, helper, `spire_release_pinned_sha256 "$ASSET"`, "ASSET="+name)
		if err != nil || string(output) != sum+"\n" {
			t.Fatalf("lookup of %s: err=%v output=%q, want %s", name, err, output, sum)
		}
	}
	for _, name := range []string{spireTestAMD64Asset, spireTestARM64Asset} {
		if _, ok := spireTestRepoPins(t)[name]; !ok {
			t.Fatalf("the repository does not pin %s, which CI or the supported-local scripts use by default", name)
		}
	}

	dir := t.TempDir()
	const sum = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	for _, test := range []struct {
		name, pins, asset, want string
	}{
		{"unpinned version", "", "spire-9.9.9-linux-amd64-musl.tar.gz",
			"no SHA-256 is pinned for the SPIRE release file spire-9.9.9-linux-amd64-musl.tar.gz"},
		{"empty name", "", "", "invalid SPIRE release file name: "},
		{"name with a directory", "", "../" + spireTestAMD64Asset, "invalid SPIRE release file name: ../"},
		{"name with a space", "", "spire x.tar.gz", "invalid SPIRE release file name: spire x.tar.gz"},
		{"two lines for one file", sum + "  a.tar.gz\n" + sum + "  a.tar.gz\n", "a.tar.gz",
			"the SPIRE release file a.tar.gz has more than one line in "},
		{"one space", sum + " a.tar.gz\n", "a.tar.gz", "malformed line in "},
		{"upper-case hex", strings.ToUpper(sum) + "  a.tar.gz\n", "a.tar.gz", "malformed line in "},
		{"short hash", sum[1:] + "  a.tar.gz\n", "a.tar.gz", "malformed line in "},
		{"trailing space", sum + "  a.tar.gz \n", "a.tar.gz", "malformed line in "},
		{"comment", "# pins\n" + sum + "  a.tar.gz\n", "a.tar.gz", "malformed line in "},
		{"empty line", sum + "  a.tar.gz\n\n", "a.tar.gz", "malformed line in "},
		{"malformed line for another file", sum + "  a.tar.gz\n" + sum + "  b.tar.gz x\n", "a.tar.gz", "malformed line in "},
	} {
		t.Run(test.name, func(t *testing.T) {
			body := `spire_release_pinned_sha256 "$ASSET"`
			overrides := []string{"ASSET=" + test.asset}
			if test.pins != "" {
				body = `SPIRE_RELEASE_PIN_FILE="$TEST_PINS"; ` + body
				overrides = append(overrides, "TEST_PINS="+spireTestWritePins(t, filepath.Join(dir, strings.ReplaceAll(test.name, " ", "-")), test.pins))
			}
			output, err := auditScriptSource(t, helper, body, overrides...)
			if err == nil || !strings.Contains(string(output), test.want) || strings.Contains(string(output), sum+"\n") {
				t.Fatalf("lookup was not refused as %q: err=%v output=%q", test.want, err, output)
			}
		})
	}

	t.Run("last line without a newline", func(t *testing.T) {
		pins := spireTestWritePins(t, filepath.Join(dir, "no-newline"), sum+"  a.tar.gz\n"+strings.Repeat("f", 64)+"  b.tar.gz")
		output, err := auditScriptSource(t, helper, `SPIRE_RELEASE_PIN_FILE="$TEST_PINS"; spire_release_pinned_sha256 b.tar.gz`, "TEST_PINS="+pins)
		if err != nil || string(output) != strings.Repeat("f", 64)+"\n" {
			t.Fatalf("last line was not read: err=%v output=%q", err, output)
		}
	})
	t.Run("missing pin file", func(t *testing.T) {
		output, err := auditScriptSource(t, helper, `SPIRE_RELEASE_PIN_FILE="$TEST_PINS"; spire_release_pinned_sha256 a.tar.gz`, "TEST_PINS="+filepath.Join(dir, "absent"))
		if err == nil || !strings.Contains(string(output), "SPIRE release pin file is not readable: ") {
			t.Fatalf("missing pin file was not refused: err=%v output=%q", err, output)
		}
	})
}

func TestSpireReleaseVerifyComparesTheFileWithItsPin(t *testing.T) {
	helper := spireTestHelper(t)
	dir := t.TempDir()
	tarball, sum := spireTestDistribution(t, dir)
	pins := spireTestWritePins(t, filepath.Join(dir, "pins"), sum+"  "+spireTestAMD64Asset+"\n")
	body := `SPIRE_RELEASE_PIN_FILE="$TEST_PINS"; spire_release_verify "$TEST_FILE" "$ASSET"`

	output, err := auditScriptSource(t, helper, body, "TEST_PINS="+pins, "TEST_FILE="+tarball, "ASSET="+spireTestAMD64Asset)
	if err != nil || len(output) != 0 {
		t.Fatalf("pinned file refused: err=%v output=%q", err, output)
	}

	other := filepath.Join(dir, "other.tar.gz")
	if err := os.WriteFile(other, []byte("not the pinned file"), 0o600); err != nil {
		t.Fatal(err)
	}
	otherSum := sha256.Sum256([]byte("not the pinned file"))
	output, err = auditScriptSource(t, helper, body, "TEST_PINS="+pins, "TEST_FILE="+other, "ASSET="+spireTestAMD64Asset)
	want := "SPIRE release file " + other + " has SHA-256 " + hex.EncodeToString(otherSum[:]) + ", not " + sum + ", which " + pins + " pins for " + spireTestAMD64Asset + "\n"
	if err == nil || string(output) != want {
		t.Fatalf("file that does not match its pin was accepted or reported otherwise: err=%v output=%q want=%q", err, output, want)
	}

	output, err = auditScriptSource(t, helper, body, "TEST_PINS="+pins, "TEST_FILE="+tarball, "ASSET="+spireTestARM64Asset)
	if err == nil || !strings.Contains(string(output), "no SHA-256 is pinned for the SPIRE release file "+spireTestARM64Asset) {
		t.Fatalf("file was accepted under a name with no pin: err=%v output=%q", err, output)
	}

	output, err = auditScriptSource(t, helper, body, "TEST_PINS="+pins, "TEST_FILE="+filepath.Join(dir, "absent"), "ASSET="+spireTestAMD64Asset)
	if err == nil || !strings.Contains(string(output), "cannot read the SPIRE release file "+filepath.Join(dir, "absent")) {
		t.Fatalf("missing file was not refused: err=%v output=%q", err, output)
	}
}

// The setup script's prepare_spire_distribution runs with the architecture
// fixed to amd64 and tar, curl and go replaced by recorders, so the test
// sees whether anything was downloaded or unpacked.
func TestSupportedLocalSetupUnpacksOnlyAPinnedSpireDistribution(t *testing.T) {
	repo := executionPlatformRepoRoot(t)
	script := filepath.Join(repo, "scripts", "72_supported_local_setup.sh")
	const fakes = `
spire_release_arch() { printf 'amd64\n'; }
go() { printf 'go %s\n' "$*" >> "$SPIRE_EVENTS"; return 97; }
tar() { printf 'tar %s\n' "$*" >> "$SPIRE_EVENTS"; command tar "$@"; }
curl() {
  printf 'curl %s\n' "$*" >> "$SPIRE_EVENTS"
  local output=""
  while [[ $# -gt 0 ]]; do
    if [[ "$1" == -o ]]; then output=$2; shift; fi
    shift
  done
  cp "$TEST_DOWNLOAD" "$output"
}
`
	type run struct {
		proof, events string
		output        string
		err           error
	}
	setup := func(t *testing.T, body string, overrides ...string) run {
		t.Helper()
		workspace := t.TempDir()
		proof := filepath.Join(workspace, "proof")
		if err := os.MkdirAll(filepath.Join(proof, "bin"), 0o700); err != nil {
			t.Fatal(err)
		}
		events := filepath.Join(workspace, "events")
		if err := os.WriteFile(events, nil, 0o600); err != nil {
			t.Fatal(err)
		}
		output, err := auditScriptSource(t, script, fakes+body+`
prepare_spire_distribution "$SUPPORTED_LOCAL_PROOF_DIR/downloads/spire.tar.gz" "$SUPPORTED_LOCAL_PROOF_DIR/spire/dist"`,
			append([]string{
				"EXECUTION_SUBSTRATE_REPO_ROOT=" + repo,
				"SUPPORTED_LOCAL_PROOF_DIR=" + proof,
				"SPIRE_EVENTS=" + events,
			}, overrides...)...)
		recorded, readErr := os.ReadFile(events)
		if readErr != nil {
			t.Fatal(readErr)
		}
		return run{proof: proof, events: string(recorded), output: string(output), err: err}
	}
	assertNothingUnpacked := func(t *testing.T, r run) {
		t.Helper()
		for _, name := range []string{"downloads/spire.tar.gz", "spire/dist", "bin/spire-server", "bin/spire-agent"} {
			if _, err := os.Lstat(filepath.Join(r.proof, name)); !os.IsNotExist(err) {
				t.Fatalf("refused SPIRE distribution left or produced %s: %v output=%q", name, err, r.output)
			}
		}
		if strings.Contains(r.events, "tar ") || strings.Contains(r.events, "go ") {
			t.Fatalf("refused SPIRE distribution was unpacked: events=%q output=%q", r.events, r.output)
		}
	}
	pinned := spireTestRepoPins(t)[spireTestAMD64Asset]

	t.Run("prebuilt file that does not match its pin", func(t *testing.T) {
		tarball, sum := spireTestDistribution(t, t.TempDir())
		r := setup(t, "", "SUPPORTED_LOCAL_PREBUILT_SPIRE_TARBALL="+tarball)
		if r.err == nil || !strings.Contains(r.output, " has SHA-256 "+sum+", not "+pinned+", which ") ||
			!strings.Contains(r.output, " pins for "+spireTestAMD64Asset+"\n") ||
			!strings.HasSuffix(r.output, "refused the SPIRE distribution; nothing was unpacked\n") {
			t.Fatalf("prebuilt file that does not match its pin was not refused: err=%v output=%q", r.err, r.output)
		}
		if r.events != "" {
			t.Fatalf("prebuilt path ran a recorded command: %q", r.events)
		}
		assertNothingUnpacked(t, r)
	})

	t.Run("download that does not match its pin", func(t *testing.T) {
		tarball, sum := spireTestDistribution(t, t.TempDir())
		r := setup(t, "", "TEST_DOWNLOAD="+tarball)
		if r.err == nil || !strings.Contains(r.output, " has SHA-256 "+sum+", not "+pinned+", which ") ||
			!strings.HasSuffix(r.output, "refused the SPIRE distribution; nothing was unpacked\n") {
			t.Fatalf("download that does not match its pin was not refused: err=%v output=%q", r.err, r.output)
		}
		if !strings.HasPrefix(r.events, "curl ") || !strings.Contains(r.events, " https://github.com/spiffe/spire/releases/download/v1.14.4/"+spireTestAMD64Asset+"\n") ||
			strings.Count(r.events, "\n") != 1 {
			t.Fatalf("download path did not download the release file once: %q", r.events)
		}
		assertNothingUnpacked(t, r)
	})

	t.Run("version with no pin is refused before the download", func(t *testing.T) {
		tarball, _ := spireTestDistribution(t, t.TempDir())
		r := setup(t, "", "TEST_DOWNLOAD="+tarball, "SUPPORTED_LOCAL_SPIRE_VERSION=9.9.9")
		if r.err == nil || !strings.Contains(r.output, "no SHA-256 is pinned for the SPIRE release file spire-9.9.9-linux-amd64-musl.tar.gz: ") {
			t.Fatalf("version with no pin was not refused: err=%v output=%q", r.err, r.output)
		}
		if r.events != "" {
			t.Fatalf("version with no pin was downloaded or unpacked: %q", r.events)
		}
		assertNothingUnpacked(t, r)
	})

	t.Run("prebuilt version with no pin is refused before the copy", func(t *testing.T) {
		tarball, _ := spireTestDistribution(t, t.TempDir())
		r := setup(t, "", "SUPPORTED_LOCAL_PREBUILT_SPIRE_TARBALL="+tarball, "SUPPORTED_LOCAL_SPIRE_VERSION=9.9.9")
		if r.err == nil || !strings.Contains(r.output, "no SHA-256 is pinned for the SPIRE release file spire-9.9.9-linux-amd64-musl.tar.gz: ") ||
			strings.Contains(r.output, "using prebuilt") {
			t.Fatalf("prebuilt version with no pin was not refused before the copy: err=%v output=%q", r.err, r.output)
		}
		assertNothingUnpacked(t, r)
	})

	// cp is replaced so that the copy differs from the prebuilt file, which
	// matches its pin: the copy is the file that is checked and unpacked.
	t.Run("the copy is checked, not the prebuilt file", func(t *testing.T) {
		dir := t.TempDir()
		tarball, sum := spireTestDistribution(t, dir)
		pins := spireTestWritePins(t, filepath.Join(dir, "pins"), sum+"  "+spireTestAMD64Asset+"\n")
		swapped := sha256.Sum256([]byte(spireTestSwappedCopy))
		r := setup(t, `SPIRE_RELEASE_PIN_FILE="$TEST_PINS"
`+spireTestSwappingCopy, "SUPPORTED_LOCAL_PREBUILT_SPIRE_TARBALL="+tarball, "TEST_PINS="+pins)
		if r.err == nil || !strings.Contains(r.output, " has SHA-256 "+hex.EncodeToString(swapped[:])+", not "+sum+", which ") ||
			!strings.HasSuffix(r.output, "refused the SPIRE distribution; nothing was unpacked\n") || r.events != "" {
			t.Fatalf("a copy that differs from the checked prebuilt file was not refused: err=%v output=%q events=%q", r.err, r.output, r.events)
		}
		assertNothingUnpacked(t, r)
	})

	t.Run("pinned file is unpacked and installed", func(t *testing.T) {
		dir := t.TempDir()
		tarball, sum := spireTestDistribution(t, dir)
		pins := spireTestWritePins(t, filepath.Join(dir, "pins"), sum+"  "+spireTestAMD64Asset+"\n")
		r := setup(t, `SPIRE_RELEASE_PIN_FILE="$TEST_PINS"`, "SUPPORTED_LOCAL_PREBUILT_SPIRE_TARBALL="+tarball, "TEST_PINS="+pins)
		if r.err != nil || !strings.HasPrefix(r.events, "tar -xzf ") || strings.Count(r.events, "\n") != 1 {
			t.Fatalf("pinned SPIRE distribution was not unpacked: err=%v output=%q events=%q", r.err, r.output, r.events)
		}
		for _, name := range []string{"spire-server", "spire-agent"} {
			data, err := os.ReadFile(filepath.Join(r.proof, "bin", name))
			if err != nil || string(data) != "#!/bin/sh\necho synthetic "+name+"\n" {
				t.Fatalf("pinned SPIRE distribution did not install %s: %v %q", name, err, data)
			}
		}
	})

	// cp copies faithfully and then changes the prebuilt file, as a source
	// that changes after the copy would: the checked copy is what is unpacked.
	t.Run("the checked copy is the file that is unpacked", func(t *testing.T) {
		dir := t.TempDir()
		tarball, sum := spireTestDistribution(t, dir)
		pins := spireTestWritePins(t, filepath.Join(dir, "pins"), sum+"  "+spireTestAMD64Asset+"\n")
		r := setup(t, `SPIRE_RELEASE_PIN_FILE="$TEST_PINS"
cp() { command cp "$@"; printf 'changed after the copy\n' > "$1"; }
`, "SUPPORTED_LOCAL_PREBUILT_SPIRE_TARBALL="+tarball, "TEST_PINS="+pins)
		wantTar := "tar -xzf " + filepath.Join(r.proof, "downloads", "spire.tar.gz") + " -C " + filepath.Join(r.proof, "spire", "dist") + "\n"
		if r.err != nil || r.events != wantTar {
			t.Fatalf("the checked copy was not the file unpacked: err=%v output=%q events=%q", r.err, r.output, r.events)
		}
		for _, name := range []string{"spire-server", "spire-agent"} {
			data, err := os.ReadFile(filepath.Join(r.proof, "bin", name))
			if err != nil || string(data) != "#!/bin/sh\necho synthetic "+name+"\n" {
				t.Fatalf("installed %s is not from the checked copy: %v %q", name, err, data)
			}
		}
	})
}

// The proof wrapper's stage_spire_distribution stages the release file in
// host bootstrap scratch for the guest, and prepare_host_tooling runs it as
// the spire-stage phase.
func TestSupportedLocalProofStagesOnlyAPinnedSpireDistribution(t *testing.T) {
	repo := executionPlatformRepoRoot(t)
	script := filepath.Join(repo, "scripts", "73_supported_local_proof.sh")
	const fakes = `
curl() {
  printf 'curl %s\n' "$*" >> "$SPIRE_EVENTS"
  local output=""
  while [[ $# -gt 0 ]]; do
    if [[ "$1" == -o ]]; then output=$2; shift; fi
    shift
  done
  cp "$TEST_DOWNLOAD" "$output"
}
`
	type run struct {
		bootstrap, host, events string
		output                  string
		err                     error
	}
	stage := func(t *testing.T, body string, overrides ...string) run {
		t.Helper()
		workspace := t.TempDir()
		bootstrap := filepath.Join(workspace, "bootstrap")
		host := filepath.Join(workspace, "host-proof")
		for _, dir := range []string{bootstrap, host} {
			if err := os.Mkdir(dir, 0o700); err != nil {
				t.Fatal(err)
			}
		}
		events := filepath.Join(workspace, "events")
		if err := os.WriteFile(events, nil, 0o600); err != nil {
			t.Fatal(err)
		}
		output, err := auditScriptSource(t, script, fakes+`
SUPPORTED_LOCAL_HOST_BOOTSTRAP_DIR="$TEST_BOOTSTRAP"
SUPPORTED_LOCAL_HOST_PROOF_DIR="$TEST_HOST"
`+body, append([]string{"TEST_BOOTSTRAP=" + bootstrap, "TEST_HOST=" + host, "SPIRE_EVENTS=" + events}, overrides...)...)
		recorded, readErr := os.ReadFile(events)
		if readErr != nil {
			t.Fatal(readErr)
		}
		return run{bootstrap: bootstrap, host: host, events: string(recorded), output: string(output), err: err}
	}
	const direct = `mkdir -m 0700 "$SUPPORTED_LOCAL_HOST_BOOTSTRAP_DIR/bin"
stage_spire_distribution`
	assertNotStaged := func(t *testing.T, r run) {
		t.Helper()
		if _, err := os.Lstat(filepath.Join(r.bootstrap, "bin", "spire.tar.gz")); !os.IsNotExist(err) {
			t.Fatalf("refused SPIRE distribution stayed staged for the guest: %v output=%q", err, r.output)
		}
	}
	pinned := spireTestRepoPins(t)[spireTestARM64Asset]

	t.Run("prebuilt file that does not match its pin", func(t *testing.T) {
		tarball, sum := spireTestDistribution(t, t.TempDir())
		r := stage(t, direct, "SUPPORTED_LOCAL_PREBUILT_SPIRE_TARBALL="+tarball)
		if r.err == nil || !strings.Contains(r.output, " has SHA-256 "+sum+", not "+pinned+", which ") ||
			!strings.Contains(r.output, " pins for "+spireTestARM64Asset+"\n") || r.events != "" {
			t.Fatalf("prebuilt file that does not match its pin was not refused: err=%v output=%q events=%q", r.err, r.output, r.events)
		}
		assertNotStaged(t, r)
	})

	t.Run("download that does not match its pin", func(t *testing.T) {
		tarball, sum := spireTestDistribution(t, t.TempDir())
		r := stage(t, direct, "TEST_DOWNLOAD="+tarball)
		if r.err == nil || !strings.Contains(r.output, " has SHA-256 "+sum+", not "+pinned+", which ") {
			t.Fatalf("download that does not match its pin was not refused: err=%v output=%q", r.err, r.output)
		}
		if !strings.HasPrefix(r.events, "curl ") || !strings.HasSuffix(r.events, " https://github.com/spiffe/spire/releases/download/v1.14.4/"+spireTestARM64Asset+"\n") ||
			strings.Count(r.events, "\n") != 1 {
			t.Fatalf("download path did not download the release file once: %q", r.events)
		}
		assertNotStaged(t, r)
	})

	t.Run("release file with no pin is refused before the download", func(t *testing.T) {
		tarball, _ := spireTestDistribution(t, t.TempDir())
		r := stage(t, direct, "TEST_DOWNLOAD="+tarball, "SUPPORTED_LOCAL_SPIRE_VERSION=9.9.9")
		if r.err == nil || !strings.Contains(r.output, "no SHA-256 is pinned for the SPIRE release file spire-9.9.9-linux-arm64-musl.tar.gz: ") || r.events != "" {
			t.Fatalf("release file with no pin was not refused before the download: err=%v output=%q events=%q", r.err, r.output, r.events)
		}
		assertNotStaged(t, r)
	})

	t.Run("the staged copy is checked, not the prebuilt file", func(t *testing.T) {
		dir := t.TempDir()
		tarball, sum := spireTestDistribution(t, dir)
		pins := spireTestWritePins(t, filepath.Join(dir, "pins"), sum+"  "+spireTestARM64Asset+"\n")
		swapped := sha256.Sum256([]byte(spireTestSwappedCopy))
		r := stage(t, `SPIRE_RELEASE_PIN_FILE="$TEST_PINS"
`+spireTestSwappingCopy+direct, "SUPPORTED_LOCAL_PREBUILT_SPIRE_TARBALL="+tarball, "TEST_PINS="+pins)
		if r.err == nil || !strings.Contains(r.output, " has SHA-256 "+hex.EncodeToString(swapped[:])+", not "+sum+", which ") {
			t.Fatalf("a staged copy that differs from the checked prebuilt file was not refused: err=%v output=%q", r.err, r.output)
		}
		assertNotStaged(t, r)
	})

	t.Run("pinned file is staged", func(t *testing.T) {
		dir := t.TempDir()
		tarball, sum := spireTestDistribution(t, dir)
		pins := spireTestWritePins(t, filepath.Join(dir, "pins"), sum+"  "+spireTestARM64Asset+"\n")
		r := stage(t, `SPIRE_RELEASE_PIN_FILE="$TEST_PINS"
`+direct, "SUPPORTED_LOCAL_PREBUILT_SPIRE_TARBALL="+tarball, "TEST_PINS="+pins)
		want, err := os.ReadFile(tarball)
		if err != nil {
			t.Fatal(err)
		}
		got, err := os.ReadFile(filepath.Join(r.bootstrap, "bin", "spire.tar.gz"))
		if r.err != nil || len(r.output) != 0 || err != nil || !bytes.Equal(got, want) {
			t.Fatalf("pinned SPIRE distribution was not staged: err=%v output=%q read=%v", r.err, r.output, err)
		}
	})

	// The spire-stage phase of prepare_host_tooling, with a go command that
	// builds nothing, fails and stages nothing.
	t.Run("spire-stage phase refuses a file that does not match its pin", func(t *testing.T) {
		dir := t.TempDir()
		tarball, _ := spireTestDistribution(t, dir)
		fakeBin := filepath.Join(dir, "bin")
		if err := os.Mkdir(fakeBin, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(fakeBin, "go"), []byte("#!/bin/sh\nexit 0\n"), 0o700); err != nil {
			t.Fatal(err)
		}
		r := stage(t, `require_supported_go_toolchain() { :; }
prepare_host_tooling`, "SUPPORTED_LOCAL_PREBUILT_SPIRE_TARBALL="+tarball,
			"PATH="+fakeBin+string(os.PathListSeparator)+auditSafeScriptPath(t))
		if build, err := os.ReadFile(filepath.Join(r.host, "phase-runtime-support-build.json")); err != nil || !strings.Contains(string(build), `"success":true`) {
			t.Fatalf("the runtime-support phase before spire-stage did not pass: %v %q output=%q", err, build, r.output)
		}
		if r.err == nil || r.output != "supported-local proof phase failed: spire-stage\n" {
			t.Fatalf("spire-stage phase did not fail: err=%v output=%q", r.err, r.output)
		}
		phase, err := os.ReadFile(filepath.Join(r.host, "phase-spire-stage.json"))
		if err != nil || !strings.Contains(string(phase), `"success":false`) {
			t.Fatalf("spire-stage phase was not recorded as failed: %v %q", err, phase)
		}
		assertNotStaged(t, r)
	})

	// cp copies faithfully and then changes the prebuilt file: the guest is
	// sent the staged copy that was checked.
	t.Run("the checked staged copy is the file sent to the guest", func(t *testing.T) {
		dir := t.TempDir()
		tarball, sum := spireTestDistribution(t, dir)
		want, err := os.ReadFile(tarball)
		if err != nil {
			t.Fatal(err)
		}
		pins := spireTestWritePins(t, filepath.Join(dir, "pins"), sum+"  "+spireTestARM64Asset+"\n")
		capture := filepath.Join(dir, "capture")
		if err := os.Mkdir(capture, 0o700); err != nil {
			t.Fatal(err)
		}
		r := stage(t, `SPIRE_RELEASE_PIN_FILE="$TEST_PINS"
cp() { command cp "$@"; printf 'changed after the copy\n' > "$1"; }
`+direct+`
printf 'runtime support\n' > "$SUPPORTED_LOCAL_HOST_BOOTSTRAP_DIR/bin/es-runtime-support"
test_calls=0
limactl() { cat > "$TEST_CAPTURE/call-$test_calls"; test_calls=$((test_calls + 1)); }
copy_tooling_to_guest`, "SUPPORTED_LOCAL_PREBUILT_SPIRE_TARBALL="+tarball, "TEST_PINS="+pins, "TEST_CAPTURE="+capture)
		got, err := os.ReadFile(filepath.Join(capture, "call-2"))
		if r.err != nil || err != nil || !bytes.Equal(got, want) {
			t.Fatalf("the guest was not sent the checked staged copy: err=%v output=%q read=%v got=%q", r.err, r.output, err, got)
		}
	})
}

// The pin file is the one next to the helper; an exported
// SPIRE_RELEASE_PIN_FILE does not replace it.
func TestSpireReleasePinFileIgnoresTheEnvironment(t *testing.T) {
	dir := t.TempDir()
	const sum = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	pins := spireTestWritePins(t, filepath.Join(dir, "pins"), sum+"  a.tar.gz\n")
	output, err := auditScriptSource(t, spireTestHelper(t), `spire_release_pinned_sha256 a.tar.gz`, "SPIRE_RELEASE_PIN_FILE="+pins)
	if err == nil || !strings.Contains(string(output), "no SHA-256 is pinned for the SPIRE release file a.tar.gz") || strings.Contains(string(output), sum) {
		t.Fatalf("an exported SPIRE_RELEASE_PIN_FILE was used: err=%v output=%q", err, output)
	}
}

// Setup refuses a SPIRE version with no pinned release file for any supported
// architecture in its preflight, before it changes the host. The first effect
// after the preflight, stopping the proof's old processes, is replaced by a
// recorder that ends the run, so a version that passes the preflight shows
// that it reached that point and a refused one shows that it did not.
func TestSupportedLocalSetupRefusesAnUnpinnedSpireVersionBeforeEffects(t *testing.T) {
	repo := executionPlatformRepoRoot(t)
	script := filepath.Join(repo, "scripts", "72_supported_local_setup.sh")
	const fakes = `
require_command() { :; }
require_supported_go_toolchain() { :; }
uname() { printf 'Linux\n'; }
sudo() { [[ "$1" == -n && "$2" == true ]]; }
go() { printf 'unexpected go %s\n' "$*" >> "$ROOT_EVENTS"; return 97; }
curl() { printf 'unexpected curl\n' >> "$ROOT_EVENTS"; return 97; }
docker() { printf 'unexpected docker\n' >> "$ROOT_EVENTS"; return 97; }
nomad() { printf 'unexpected nomad\n' >> "$ROOT_EVENTS"; return 97; }
vault() { printf 'unexpected vault\n' >> "$ROOT_EVENTS"; return 97; }
detect_docker_bridge_gateway() { printf 'unexpected bridge lookup\n' >> "$ROOT_EVENTS"; return 97; }
stop_background_process() { printf 'first effect\n' >> "$ROOT_EVENTS"; exit 97; }
`
	type run struct {
		proof, events, output string
		err                   error
	}
	setup := func(t *testing.T, body string, overrides ...string) run {
		t.Helper()
		workspace := t.TempDir()
		proof := filepath.Join(workspace, "proof")
		events := filepath.Join(workspace, "events")
		if err := os.WriteFile(events, nil, 0o600); err != nil {
			t.Fatal(err)
		}
		output, err := auditScriptSource(t, script, fakes+body+"\nsetup", append([]string{
			"EXECUTION_SUBSTRATE_REPO_ROOT=" + repo,
			"SUPPORTED_LOCAL_PROOF_DIR=" + proof,
			"SUPPORTED_LOCAL_PROOF_ID=fixture-proof",
			"SUPPORTED_LOCAL_RETAINED_RESULT_AUTH_STORE_ID=test_store",
			"SUPPORTED_LOCAL_RETAINED_RESULT_AUTH_KEY_ID=test_key",
			"SUPPORTED_LOCAL_RETAINED_RESULT_AUTH_KEY_FILE=" + filepath.Join(workspace, "external", "key"),
			"SUPPORTED_LOCAL_VAULT_PUBLIC_HOST=127.0.0.1",
			"SUPPORTED_LOCAL_VAULT_ROOT_TOKEN=synthetic-token",
			"SUPPORTED_LOCAL_VAULT_SECRET_VALUE=synthetic-value",
			"SUPPORTED_LOCAL_CODEX_CREDENTIAL_VALUE=synthetic-value",
			"ROOT_EVENTS=" + events,
		}, overrides...)...)
		recorded, readErr := os.ReadFile(events)
		if readErr != nil {
			t.Fatal(readErr)
		}
		if _, statErr := os.Lstat(proof); !os.IsNotExist(statErr) {
			t.Fatalf("setup created its proof root before the first effect: %v output=%q", statErr, output)
		}
		return run{proof: proof, events: string(recorded), output: string(output), err: err}
	}
	const sum = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

	t.Run("unpinned version", func(t *testing.T) {
		r := setup(t, "", "SUPPORTED_LOCAL_SPIRE_VERSION=9.9.9")
		if r.err == nil || r.events != "" || strings.Count(r.output, "\n") != 1 ||
			!strings.HasPrefix(r.output, "no SHA-256 is pinned for the SPIRE release file spire-9.9.9-linux-amd64-musl.tar.gz: ") {
			t.Fatalf("unpinned version was not refused before the first effect: err=%v output=%q events=%q", r.err, r.output, r.events)
		}
	})
	t.Run("malformed pin file", func(t *testing.T) {
		dir := t.TempDir()
		pins := spireTestWritePins(t, filepath.Join(dir, "pins"), sum+" spire-1.14.4-linux-amd64-musl.tar.gz\n")
		r := setup(t, `SPIRE_RELEASE_PIN_FILE="$TEST_PINS"`, "TEST_PINS="+pins)
		if r.err == nil || r.events != "" || !strings.HasPrefix(r.output, "malformed line in "+pins+": ") {
			t.Fatalf("malformed pin file was not refused before the first effect: err=%v output=%q events=%q", r.err, r.output, r.events)
		}
	})
	t.Run("pinned version reaches the first effect", func(t *testing.T) {
		r := setup(t, "")
		if r.err == nil || r.events != "first effect\n" || r.output != "" {
			t.Fatalf("pinned version did not pass the preflight: err=%v output=%q events=%q", r.err, r.output, r.events)
		}
	})
	t.Run("version pinned only for arm64 reaches the first effect", func(t *testing.T) {
		dir := t.TempDir()
		pins := spireTestWritePins(t, filepath.Join(dir, "pins"), sum+"  spire-2.0.0-linux-arm64-musl.tar.gz\n")
		r := setup(t, `SPIRE_RELEASE_PIN_FILE="$TEST_PINS"`, "TEST_PINS="+pins, "SUPPORTED_LOCAL_SPIRE_VERSION=2.0.0")
		if r.err == nil || r.events != "first effect\n" || r.output != "" {
			t.Fatalf("version pinned for one supported architecture did not pass the preflight: err=%v output=%q events=%q", r.err, r.output, r.events)
		}
	})
	t.Run("version pinned only for amd64 reaches the first effect", func(t *testing.T) {
		dir := t.TempDir()
		pins := spireTestWritePins(t, filepath.Join(dir, "pins"), sum+"  spire-2.0.0-linux-amd64-musl.tar.gz\n")
		r := setup(t, `SPIRE_RELEASE_PIN_FILE="$TEST_PINS"`, "TEST_PINS="+pins, "SUPPORTED_LOCAL_SPIRE_VERSION=2.0.0")
		if r.err == nil || r.events != "first effect\n" || r.output != "" {
			t.Fatalf("version pinned for one supported architecture did not pass the preflight: err=%v output=%q events=%q", r.err, r.output, r.events)
		}
	})
}

// The proof wrapper refuses a SPIRE release file with no pin before it
// creates its host proof directory, its first effect, which a recorder
// replaces here to end the run.
func TestSupportedLocalProofRefusesAnUnpinnedSpireReleaseFileBeforeEffects(t *testing.T) {
	repo := executionPlatformRepoRoot(t)
	script := filepath.Join(repo, "scripts", "73_supported_local_proof.sh")
	const body = `
require_command() { :; }
require_supported_go_toolchain() { :; }
create_private_host_proof_dir() { printf 'first effect\n' >> "$ROOT_EVENTS"; exit 97; }
run`
	type run struct {
		events, output string
		err            error
	}
	wrapper := func(t *testing.T, overrides ...string) run {
		t.Helper()
		workspace := t.TempDir()
		host := filepath.Join(workspace, "host-proof")
		events := filepath.Join(workspace, "events")
		if err := os.WriteFile(events, nil, 0o600); err != nil {
			t.Fatal(err)
		}
		output, err := auditScriptSource(t, script, body, append([]string{
			"SUPPORTED_LOCAL_PROOF_ID=spirepinfixture",
			"SUPPORTED_LOCAL_HOST_PROOF_DIR=" + host,
			"SUPPORTED_LOCAL_GUEST_PROOF_DIR=/tmp/es-proof-spirepinfixture",
			"SUPPORTED_LOCAL_GUEST_BOOTSTRAP_DIR=/tmp/es-proof-spirepinfixture.bootstrap",
			"SUPPORTED_LOCAL_GUEST_REPO_ROOT=/tmp/es-proof-spirepinfixture.bootstrap/repo",
			"SUPPORTED_LOCAL_RETAINED_RESULT_AUTH_STORE_ID=test_store",
			"SUPPORTED_LOCAL_RETAINED_RESULT_AUTH_KEY_ID=test_key",
			"SUPPORTED_LOCAL_RETAINED_RESULT_AUTH_KEY_FILE=/opt/external auth /keys/key",
			"ROOT_EVENTS=" + events,
		}, overrides...)...)
		recorded, readErr := os.ReadFile(events)
		if readErr != nil {
			t.Fatal(readErr)
		}
		for _, path := range []string{host, filepath.Join(filepath.Dir(repo), "es-proof-bootstrap-spirepinfixture")} {
			if _, statErr := os.Lstat(path); !os.IsNotExist(statErr) {
				t.Fatalf("the wrapper created %s before its first effect: %v output=%q", path, statErr, output)
			}
		}
		return run{events: string(recorded), output: string(output), err: err}
	}

	for _, test := range []struct{ name, variable, value, asset string }{
		{"unpinned version", "SUPPORTED_LOCAL_SPIRE_VERSION", "9.9.9", "spire-9.9.9-linux-arm64-musl.tar.gz"},
		{"unpinned asset", "SUPPORTED_LOCAL_SPIRE_ASSET", "spire-1.14.4-linux-riscv64-musl.tar.gz", "spire-1.14.4-linux-riscv64-musl.tar.gz"},
	} {
		t.Run(test.name, func(t *testing.T) {
			r := wrapper(t, test.variable+"="+test.value)
			if r.err == nil || r.events != "" || strings.Count(r.output, "\n") != 1 ||
				!strings.HasPrefix(r.output, "no SHA-256 is pinned for the SPIRE release file "+test.asset+": ") {
				t.Fatalf("unpinned release file was not refused before the first effect: err=%v output=%q events=%q", r.err, r.output, r.events)
			}
		})
	}
	t.Run("pinned release file reaches the first effect", func(t *testing.T) {
		r := wrapper(t)
		if r.err == nil || r.events != "first effect\n" || r.output != "" {
			t.Fatalf("pinned release file did not pass the preflight: err=%v output=%q events=%q", r.err, r.output, r.events)
		}
	})
}
