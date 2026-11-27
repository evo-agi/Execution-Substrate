package app_test

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
	"syscall"
	"testing"

	"execution-substrate/egs/app"
	"execution-substrate/egs/config"
)

// The revocation runbook (.runbooks/system/Governed Execution ES Revoke An
// Artifact Or Signer.md) carries three Python programs: step 1 lists the
// entries, step 2 changes one list, and the check reports problems in the
// lists. The tests below cut them out of the runbook byte for byte, run them
// the way the runbook does (python3 -I, the program on standard input, the
// same arguments), and load every result with EGS's own start path
// (config.Load, then app.New), so a change to the runbook's code that breaks
// a promise the runbook makes fails here.

const revocationRunbookPath = "../../.runbooks/system/Governed Execution ES Revoke An Artifact Or Signer.md"

// The command line of each program, as the runbook gives it. The tests pass
// the arguments in this order.
var revocationRunbookCommands = [3]string{
	`sudo python3 -I - /etc/execution-substrate/egs.json /etc/execution-substrate/ags.json <<'PY'`,
	`sudo python3 -I - /etc/execution-substrate/egs.json "$ACTION" "$KIND" "$VALUE" <<'PY'`,
	`sudo python3 -I - /etc/execution-substrate/egs.json <<'PY'`,
}

const (
	runbookDigestA = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	runbookDigestB = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	// A key ID that only the runbook's step 1 reads, from a stand-in ags.json.
	runbookAGSKeyID = "ags-key-1"
)

type revocationRunbookPrograms struct {
	step1, step2, check string
}

func loadRevocationRunbookPrograms(t *testing.T) revocationRunbookPrograms {
	t.Helper()
	raw, err := os.ReadFile(revocationRunbookPath)
	if err != nil {
		t.Fatalf("read runbook: %v", err)
	}
	blocks := regexp.MustCompile("(?ms)^```bash\n(?:[^\n]*\n)*?([^\n]*<<'PY')\n(.*?)\nPY\n```$").FindAllStringSubmatch(string(raw), -1)
	if len(blocks) != 3 {
		t.Fatalf("runbook has %d Python blocks, want 3 (step 1, step 2, the check)", len(blocks))
	}
	for i, block := range blocks {
		if block[1] != revocationRunbookCommands[i] {
			t.Fatalf("runbook Python block %d starts with\n%s\nwant\n%s\nUpdate this test with the runbook.", i+1, block[1], revocationRunbookCommands[i])
		}
	}
	// A program in another style (another fence language, another heredoc
	// word, python3 -c) is not cut out above. Every command line of a code
	// block that names Python has to be one of the three above, so such a
	// program fails here instead of going untested. The lines of a heredoc
	// are the program, not command lines.
	var pythonLines []string
	inBlock, heredocEnd := false, ""
	heredoc := regexp.MustCompile(`<<-?\s*['"]?(\w+)['"]?\s*$`)
	for _, line := range strings.Split(string(raw), "\n") {
		switch {
		case heredocEnd != "":
			if strings.TrimSpace(line) == heredocEnd {
				heredocEnd = ""
			}
		case strings.HasPrefix(strings.TrimSpace(line), "```"):
			inBlock = !inBlock
		case inBlock:
			if strings.Contains(strings.ToLower(line), "python") {
				pythonLines = append(pythonLines, line)
			}
			if m := heredoc.FindStringSubmatch(line); m != nil {
				heredocEnd = m[1]
			}
		}
	}
	if !reflect.DeepEqual(pythonLines, revocationRunbookCommands[:]) {
		t.Fatalf("the runbook's code blocks name Python on these lines:\n%s\nwant exactly the three command lines\n%s\nUpdate this test with the runbook.", strings.Join(pythonLines, "\n"), strings.Join(revocationRunbookCommands[:], "\n"))
	}
	return revocationRunbookPrograms{step1: blocks[0][2] + "\n", step2: blocks[1][2] + "\n", check: blocks[2][2] + "\n"}
}

type revocationRunbookRig struct {
	python     string
	programs   revocationRunbookPrograms
	base       map[string]any
	privateKey string
	agsPath    string
}

func newRevocationRunbookRig(t *testing.T) *revocationRunbookRig {
	t.Helper()
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Fatalf("the runbook's programs need python3: %v", err)
	}
	fixture := newTLSFixture(t)
	payload, err := json.Marshal(buildConfig(fixture))
	if err != nil {
		t.Fatalf("marshal config: %v", err)
	}
	var base map[string]any
	if err := json.Unmarshal(payload, &base); err != nil {
		t.Fatalf("unmarshal config: %v", err)
	}
	base["runtime_trust"] = map[string]any{
		"signer_policy":   map[string]any{"allowed_signers": []any{runbookAGSKeyID}, "revoked_signers": []any{}},
		"artifact_policy": map[string]any{"revoked_artifacts": []any{}},
	}

	agsKey := strings.Repeat("5a", 32)
	agsPayload, err := json.Marshal(map[string]any{"signer": map[string]any{"key_id": runbookAGSKeyID, "private_key_hex": agsKey}})
	if err != nil {
		t.Fatalf("marshal ags.json: %v", err)
	}
	agsPath := filepath.Join(t.TempDir(), "ags.json")
	if err := os.WriteFile(agsPath, agsPayload, 0o600); err != nil {
		t.Fatalf("write ags.json: %v", err)
	}
	return &revocationRunbookRig{
		python:     python,
		programs:   loadRevocationRunbookPrograms(t),
		base:       base,
		privateKey: fixture.privateKeyHex,
		agsPath:    agsPath,
	}
}

// doc returns a copy of the base config with runtime_trust replaced.
// A nil runtime_trust leaves the field out.
func (r *revocationRunbookRig) doc(runtimeTrust any) map[string]any {
	doc := map[string]any{}
	for key, value := range r.base {
		if key != "runtime_trust" {
			doc[key] = value
		}
	}
	if runtimeTrust != nil {
		doc["runtime_trust"] = runtimeTrust
	}
	return doc
}

// runbookLists is a runtime_trust whose revoked lists are the given ones.
func runbookLists(revokedSigners, revokedArtifacts any) map[string]any {
	return map[string]any{
		"signer_policy":   map[string]any{"allowed_signers": []any{runbookAGSKeyID}, "revoked_signers": revokedSigners},
		"artifact_policy": map[string]any{"revoked_artifacts": revokedArtifacts},
	}
}

func runbookAllowed(allowedSigners ...any) map[string]any {
	return map[string]any{
		"signer_policy":   map[string]any{"allowed_signers": allowedSigners, "revoked_signers": []any{"k9"}},
		"artifact_policy": map[string]any{"revoked_artifacts": []any{}},
	}
}

// write puts the document in its own directory with mode 0640, as on the box.
func (r *revocationRunbookRig) write(t *testing.T, doc any) string {
	t.Helper()
	payload, err := json.MarshalIndent(doc, "", "    ")
	if err != nil {
		t.Fatalf("marshal config: %v", err)
	}
	return r.writeRaw(t, string(payload))
}

func (r *revocationRunbookRig) writeRaw(t *testing.T, raw string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "egs.json")
	if err := os.WriteFile(path, []byte(raw), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	if err := os.Chmod(path, 0o640); err != nil {
		t.Fatalf("chmod config: %v", err)
	}
	return path
}

func (r *revocationRunbookRig) run(t *testing.T, program string, args ...string) (string, int) {
	t.Helper()
	cmd := exec.Command(r.python, append([]string{"-I", "-"}, args...)...)
	cmd.Stdin = strings.NewReader(program)
	cmd.Dir = t.TempDir()
	output, err := cmd.CombinedOutput()
	code := 0
	if err != nil {
		var exitErr *exec.ExitError
		if !errors.As(err, &exitErr) {
			t.Fatalf("run python3: %v", err)
		}
		code = exitErr.ExitCode()
	}
	text := string(output)
	if strings.Contains(text, r.privateKey) || strings.Contains(text, strings.Repeat("5a", 32)) {
		t.Fatalf("a runbook program printed a private key:\n%s", text)
	}
	if strings.Contains(text, "Traceback") {
		t.Fatalf("a runbook program crashed:\n%s", text)
	}
	return text, code
}

// egsStart loads the file the way cmd/egs/main.go does. It returns "" when EGS
// starts, or the error.
func egsStart(t *testing.T, path string) (string, config.Config) {
	t.Helper()
	cfg, err := config.Load(path)
	if err != nil {
		return err.Error(), config.Config{}
	}
	if _, err := app.New(cfg); err != nil {
		return err.Error(), config.Config{}
	}
	return "", cfg
}

type fileState struct {
	content  []byte
	mode     os.FileMode
	uid, gid uint32
}

func stateOf(t *testing.T, path string) fileState {
	t.Helper()
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat %s: %v", path, err)
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		t.Fatalf("stat %s: no owner", path)
	}
	return fileState{content: content, mode: info.Mode(), uid: st.Uid, gid: st.Gid}
}

func revokedListsOf(t *testing.T, path string) [2]any {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read config: %v", err)
	}
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("decode config: %v", err)
	}
	trust, _ := doc["runtime_trust"].(map[string]any)
	field := func(policy, name string) any {
		section, _ := trust[policy].(map[string]any)
		return section[name]
	}
	return [2]any{field("signer_policy", "revoked_signers"), field("artifact_policy", "revoked_artifacts")}
}

func allowedSignersOf(t *testing.T, path string) any {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read config: %v", err)
	}
	var doc struct {
		RuntimeTrust struct {
			SignerPolicy map[string]any `json:"signer_policy"`
		} `json:"runtime_trust"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("decode config: %v", err)
	}
	return doc.RuntimeTrust.SignerPolicy["allowed_signers"]
}

const egsAccepts = ""

// The kinds of file a case starts from, besides a runtime_trust object
// (map[string]any).
type (
	// runtimeTrustValue is a runtime_trust of another JSON type; nil is null.
	runtimeTrustValue struct{ value any }
	// noRuntimeTrust leaves runtime_trust out.
	noRuntimeTrust struct{}
	// rawFile is the whole file.
	rawFile string
)

func (r *revocationRunbookRig) file(t *testing.T, file any) string {
	t.Helper()
	switch file := file.(type) {
	case map[string]any:
		return r.write(t, r.doc(file))
	case runtimeTrustValue:
		doc := r.doc(nil)
		doc["runtime_trust"] = file.value
		return r.write(t, doc)
	case noRuntimeTrust:
		return r.write(t, r.doc(nil))
	case rawFile:
		return r.writeRaw(t, string(file))
	default:
		t.Fatalf("a case's file has type %T", file)
		return ""
	}
}

// step2Run is one run of step 2 and what it must leave behind.
type step2Run struct {
	action, kind, value string
	wantExit            int
	wantOutput          string // a substring of the output
	// wantEGS is egsAccepts or a substring of EGS's refusal after the run.
	wantEGS string
	// wantLists, when set, is revoked_signers and revoked_artifacts after the run.
	wantLists *[2]any
	// wantServedSigners and wantServedArtifacts, when set, are what EGS serves
	// after the run: the normalized lists ES enforces.
	wantServedSigners, wantServedArtifacts []string
	unchanged                              bool
}

func runbookRevoked(signers, artifacts any) *[2]any { return &[2]any{signers, artifacts} }

func (r *revocationRunbookRig) step2(t *testing.T, path string, run step2Run) string {
	t.Helper()
	before := stateOf(t, path)
	output, code := r.run(t, r.programs.step2, path, run.action, run.kind, run.value)
	if code != run.wantExit || !strings.Contains(output, run.wantOutput) {
		t.Fatalf("step 2 %s %s %q: exit %d, output\n%s\nwant exit %d and output containing %q", run.action, run.kind, run.value, code, output, run.wantExit, run.wantOutput)
	}
	after := stateOf(t, path)
	if after.mode != before.mode || after.uid != before.uid || after.gid != before.gid {
		t.Fatalf("step 2 changed the file's mode or owner: %v %d:%d, want %v %d:%d", after.mode, after.uid, after.gid, before.mode, before.uid, before.gid)
	}
	entries, err := os.ReadDir(filepath.Dir(path))
	if err != nil {
		t.Fatalf("read config directory: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("step 2 left %d files beside the config, want none", len(entries)-1)
	}
	if run.unchanged && string(after.content) != string(before.content) {
		t.Fatalf("step 2 changed the file; want it unchanged")
	}
	if run.wantLists != nil {
		if got := revokedListsOf(t, path); !reflect.DeepEqual(got, *run.wantLists) {
			t.Fatalf("revoked lists after step 2 = %#v, want %#v", got, *run.wantLists)
		}
	}
	refusal, cfg := egsStart(t, path)
	switch {
	case run.wantEGS == egsAccepts && refusal != "":
		t.Fatalf("EGS refuses the file after step 2: %s", refusal)
	case run.wantEGS != egsAccepts && !strings.Contains(refusal, run.wantEGS):
		t.Fatalf("EGS after step 2: %q, want a refusal containing %q", refusal, run.wantEGS)
	}
	if run.wantServedSigners != nil {
		if got := cfg.RuntimeTrust.Normalized().SignerPolicy.RevokedSigners; !reflect.DeepEqual(got, run.wantServedSigners) {
			t.Fatalf("EGS serves revoked_signers %q, want %q", got, run.wantServedSigners)
		}
	}
	if run.wantServedArtifacts != nil {
		if got := cfg.RuntimeTrust.Normalized().ArtifactPolicy.RevokedArtifacts; !reflect.DeepEqual(got, run.wantServedArtifacts) {
			t.Fatalf("EGS serves revoked_artifacts %q, want %q", got, run.wantServedArtifacts)
		}
	}
	return output
}

const (
	refusedDigest    = "runtime_trust.artifact_policy.revoked_artifacts must contain labeled sha256 digests"
	refusedDuplicate = "cannot contain duplicate values"
	refusedEmpty     = "cannot contain empty values"
	refusedType      = "decode config: json: cannot unmarshal"
)

func TestRevocationRunbookStep2KeepsItsPromises(t *testing.T) {
	t.Parallel()
	rig := newRevocationRunbookRig(t)
	padded := runbookDigestA + " "

	cases := []struct {
		name string
		// file is the config before the first run: a document, or raw text.
		file any
		// wantEGSBefore, when set, is a substring of EGS's refusal before the
		// first run, so the case shows that step 2 repairs what EGS refuses.
		wantEGSBefore string
		runs          []step2Run
	}{
		// add
		{name: "add a digest", file: runbookLists([]any{}, []any{}), runs: []step2Run{
			{action: "add", kind: "artifact", value: runbookDigestA, wantOutput: "added; the file keeps its owner and mode", wantLists: runbookRevoked([]any{}, []any{runbookDigestA}), wantServedArtifacts: []string{runbookDigestA}},
			{action: "add", kind: "artifact", value: runbookDigestA, wantOutput: "already revoked as '" + runbookDigestA + "'; the file is unchanged", unchanged: true},
		}},
		{name: "add refuses an upper-case digest", file: runbookLists([]any{}, []any{}), runs: []step2Run{
			{action: "add", kind: "artifact", value: "sha256:" + strings.Repeat("A", 64), wantExit: 1, wantOutput: "an artifact digest is sha256: followed by 64 lowercase hex characters; nothing changed", unchanged: true},
		}},
		{name: "add refuses a 63-character digest", file: runbookLists([]any{}, []any{}), runs: []step2Run{
			{action: "add", kind: "artifact", value: runbookDigestA[:len(runbookDigestA)-1], wantExit: 1, wantOutput: "64 lowercase hex characters; nothing changed", unchanged: true},
		}},
		{name: "add refuses an unlabeled digest", file: runbookLists([]any{}, []any{}), runs: []step2Run{
			{action: "add", kind: "artifact", value: strings.Repeat("a", 64), wantExit: 1, wantOutput: "64 lowercase hex characters; nothing changed", unchanged: true},
		}},
		{name: "add refuses a padded key ID", file: runbookLists([]any{}, []any{}), runs: []step2Run{
			{action: "add", kind: "signer", value: " k1", wantExit: 1, wantOutput: "give the key ID exactly, with no surrounding spaces; nothing changed", unchanged: true},
		}},
		{name: "add refuses an empty key ID", file: runbookLists([]any{}, []any{}), runs: []step2Run{
			{action: "add", kind: "signer", value: "", wantExit: 1, wantOutput: "give the key ID exactly", unchanged: true},
		}},
		{name: "add a key ID", file: runbookLists([]any{}, []any{}), runs: []step2Run{
			{action: "add", kind: "signer", value: "k1", wantOutput: "added", wantLists: runbookRevoked([]any{"k1"}, []any{}), wantServedSigners: []string{"k1"}},
		}},
		{name: "add replaces a padded key ID with its exact spelling", file: runbookLists([]any{"k2", " k1"}, []any{}), runs: []step2Run{
			{action: "add", kind: "signer", value: "k1", wantOutput: "replaced ' k1' with 'k1', its exact spelling", wantLists: runbookRevoked([]any{"k2", "k1"}, []any{})},
		}},
		{name: "add replaces a padded digest with the spelling ES matches", file: runbookLists([]any{}, []any{runbookDigestB, padded}), wantEGSBefore: refusedDigest, runs: []step2Run{
			{action: "add", kind: "artifact", value: runbookDigestA, wantOutput: "replaced '" + padded + "' with '" + runbookDigestA + "', the spelling ES matches", wantLists: runbookRevoked([]any{}, []any{runbookDigestB, runbookDigestA})},
		}},
		{name: "add collapses an exact and a padded copy", file: runbookLists([]any{}, []any{runbookDigestA, padded, runbookDigestB}), wantEGSBefore: refusedDuplicate, runs: []step2Run{
			{action: "add", kind: "artifact", value: runbookDigestA, wantOutput: "replaced '" + runbookDigestA + "', '" + padded + "' with '" + runbookDigestA + "'", wantLists: runbookRevoked([]any{}, []any{runbookDigestA, runbookDigestB})},
		}},
		{name: "add to null lists", file: map[string]any{"signer_policy": map[string]any{"allowed_signers": []any{runbookAGSKeyID}, "revoked_signers": nil}, "artifact_policy": nil}, runs: []step2Run{
			{action: "add", kind: "artifact", value: runbookDigestA, wantOutput: "added", wantLists: runbookRevoked(nil, []any{runbookDigestA})},
		}},
		{name: "add creates an absent runtime_trust", file: noRuntimeTrust{}, runs: []step2Run{
			{action: "remove", kind: "artifact", value: runbookDigestA, wantOutput: "not in the list; the file is unchanged", unchanged: true},
			{action: "drop-invalid", kind: "signer", wantOutput: "the file is unchanged", unchanged: true},
			{action: "add", kind: "artifact", value: runbookDigestA, wantOutput: "added", wantLists: runbookRevoked(nil, []any{runbookDigestA})},
			{action: "add", kind: "signer", value: "k1", wantOutput: "added", wantLists: runbookRevoked([]any{"k1"}, []any{runbookDigestA}), wantServedSigners: []string{"k1"}},
		}},
		{name: "add with a null runtime_trust", file: runtimeTrustValue{nil}, runs: []step2Run{
			{action: "add", kind: "artifact", value: runbookDigestA, wantOutput: "added", wantLists: runbookRevoked(nil, []any{runbookDigestA})},
		}},
		// remove
		{name: "remove a digest", file: runbookLists([]any{}, []any{runbookDigestA, runbookDigestB}), runs: []step2Run{
			{action: "remove", kind: "artifact", value: runbookDigestA, wantOutput: "removed; the file keeps its owner and mode", wantLists: runbookRevoked([]any{}, []any{runbookDigestB})},
		}},
		{name: "remove keeps one copy of a duplicated digest", file: runbookLists([]any{}, []any{runbookDigestA, runbookDigestA, runbookDigestB}), wantEGSBefore: refusedDuplicate, runs: []step2Run{
			{action: "remove", kind: "artifact", value: runbookDigestA, wantOutput: "listed 2 times; kept one copy, '" + runbookDigestA + "', so it stays revoked; run remove again to lift it", wantLists: runbookRevoked([]any{}, []any{runbookDigestA, runbookDigestB}), wantServedArtifacts: []string{runbookDigestA, runbookDigestB}},
			{action: "remove", kind: "artifact", value: runbookDigestA, wantOutput: "removed", wantLists: runbookRevoked([]any{}, []any{runbookDigestB})},
		}},
		{name: "remove keeps one of three copies", file: runbookLists([]any{"k1", "k1", "k1"}, []any{}), wantEGSBefore: refusedDuplicate, runs: []step2Run{
			{action: "remove", kind: "signer", value: "k1", wantOutput: "listed 3 times; kept one copy, 'k1', so it stays revoked", wantLists: runbookRevoked([]any{"k1"}, []any{})},
		}},
		{name: "remove keeps the exact digest when a padded copy comes first", file: runbookLists([]any{}, []any{padded, runbookDigestA}), wantEGSBefore: refusedDuplicate, runs: []step2Run{
			{action: "remove", kind: "artifact", value: padded, wantOutput: "listed 2 times; kept one copy, '" + runbookDigestA + "', so it stays revoked", wantLists: runbookRevoked([]any{}, []any{runbookDigestA}), wantServedArtifacts: []string{runbookDigestA}},
		}},
		{name: "remove says a padded digest it keeps is not a spelling ES matches", file: runbookLists([]any{}, []any{padded, padded}), wantEGSBefore: refusedDuplicate, runs: []step2Run{
			{action: "remove", kind: "artifact", value: runbookDigestA, wantOutput: "listed 2 times; kept one copy, '" + padded + "', which is not a spelling ES matches; run remove again to drop it", wantEGS: refusedDigest, wantLists: runbookRevoked([]any{}, []any{padded})},
			{action: "remove", kind: "artifact", value: runbookDigestA, wantOutput: "removed", wantLists: runbookRevoked([]any{}, []any{})},
		}},
		{name: "remove keeps a padded key ID, which stays revoked", file: runbookLists([]any{" k1", "k1 "}, []any{}), wantEGSBefore: refusedDuplicate, runs: []step2Run{
			{action: "remove", kind: "signer", value: "k1", wantOutput: "listed 2 times; kept one copy, ' k1', so it stays revoked; run remove again to lift it", wantLists: runbookRevoked([]any{" k1"}, []any{}), wantServedSigners: []string{"k1"}},
			{action: "remove", kind: "signer", value: "k1", wantOutput: "removed", wantLists: runbookRevoked([]any{}, []any{})},
		}},
		{name: "remove keeps the exact key ID when a padded copy comes first", file: runbookLists([]any{"k1 ", "k1"}, []any{}), wantEGSBefore: refusedDuplicate, runs: []step2Run{
			{action: "remove", kind: "signer", value: "k1", wantOutput: "kept one copy, 'k1', so it stays revoked", wantLists: runbookRevoked([]any{"k1"}, []any{})},
		}},
		{name: "remove matches a digest with spaces around it", file: runbookLists([]any{}, []any{" " + runbookDigestA}), wantEGSBefore: refusedDigest, runs: []step2Run{
			{action: "remove", kind: "artifact", value: runbookDigestA, wantOutput: "removed", wantLists: runbookRevoked([]any{}, []any{})},
		}},
		{name: "remove matches a digest with a trailing line break given without it", file: runbookLists([]any{}, []any{runbookDigestA + "\n", runbookDigestB}), wantEGSBefore: refusedDigest, runs: []step2Run{
			{action: "remove", kind: "artifact", value: runbookDigestA + `\n`, wantOutput: "not in the list; the file is unchanged", wantEGS: refusedDigest, unchanged: true},
			{action: "remove", kind: "artifact", value: runbookDigestA, wantOutput: "removed", wantLists: runbookRevoked([]any{}, []any{runbookDigestB})},
		}},
		{name: "remove matches a digest with a leading tab given without it", file: runbookLists([]any{}, []any{"\t" + runbookDigestA}), wantEGSBefore: refusedDigest, runs: []step2Run{
			{action: "remove", kind: "artifact", value: `\t` + runbookDigestA, wantOutput: "not in the list", wantEGS: refusedDigest, unchanged: true},
			{action: "remove", kind: "artifact", value: runbookDigestA, wantOutput: "removed", wantLists: runbookRevoked([]any{}, []any{})},
		}},
		{name: "remove matches a digest with a leading no-break space given without it", file: runbookLists([]any{}, []any{"\u00a0" + runbookDigestA}), wantEGSBefore: refusedDigest, runs: []step2Run{
			{action: "remove", kind: "artifact", value: `\xa0` + runbookDigestA, wantOutput: "not in the list", wantEGS: refusedDigest, unchanged: true},
			{action: "remove", kind: "artifact", value: runbookDigestA, wantOutput: "removed", wantLists: runbookRevoked([]any{}, []any{})},
		}},
		{name: "remove a spelling EGS refuses", file: runbookLists([]any{}, []any{"SHA256:ABC"}), wantEGSBefore: refusedDigest, runs: []step2Run{
			{action: "remove", kind: "artifact", value: "SHA256:ABC", wantOutput: "removed", wantLists: runbookRevoked([]any{}, []any{})},
		}},
		{name: "remove an absent value", file: runbookLists([]any{}, []any{runbookDigestB}), runs: []step2Run{
			{action: "remove", kind: "artifact", value: runbookDigestA, wantOutput: "not in the list; the file is unchanged", unchanged: true},
		}},
		{name: "remove from a null list", file: runbookLists(nil, nil), runs: []step2Run{
			{action: "remove", kind: "artifact", value: runbookDigestA, wantOutput: "not in the list", unchanged: true},
		}},
		{name: "remove refuses an empty value", file: runbookLists([]any{""}, []any{}), wantEGSBefore: refusedEmpty, runs: []step2Run{
			{action: "remove", kind: "signer", value: "", wantExit: 1, wantOutput: "VALUE is empty; to drop empty or non-string entries, use ACTION=drop-invalid; nothing changed", wantEGS: refusedEmpty, unchanged: true},
			{action: "remove", kind: "signer", value: "  ", wantExit: 1, wantOutput: "use ACTION=drop-invalid", wantEGS: refusedEmpty, unchanged: true},
		}},
		// drop-invalid
		{name: "drop-invalid drops entries that name nothing", file: runbookLists([]any{"", "k1", 5, nil, "  "}, []any{}), wantEGSBefore: refusedType, runs: []step2Run{
			{action: "drop-invalid", kind: "signer", wantOutput: "dropped '', 5, None, '  '; the file keeps its owner and mode", wantLists: runbookRevoked([]any{"k1"}, []any{})},
			{action: "drop-invalid", kind: "signer", wantOutput: "no empty, non-string or duplicate entries; the file is unchanged", unchanged: true},
		}},
		{name: "drop-invalid drops numbers and lists from the digests", file: runbookLists([]any{}, []any{5, runbookDigestA, []any{runbookDigestB}}), wantEGSBefore: refusedType, runs: []step2Run{
			{action: "drop-invalid", kind: "artifact", wantOutput: "dropped 5, ['" + runbookDigestB + "']", wantLists: runbookRevoked([]any{}, []any{runbookDigestA})},
		}},
		{name: "drop-invalid changes one list only", file: runbookLists([]any{"k1"}, []any{""}), wantEGSBefore: refusedEmpty, runs: []step2Run{
			{action: "drop-invalid", kind: "signer", wantOutput: "the file is unchanged", wantEGS: refusedEmpty, unchanged: true},
		}},
		{name: "drop-invalid leaves a malformed digest in place", file: runbookLists([]any{}, []any{"SHA256:ABC", ""}), wantEGSBefore: refusedEmpty, runs: []step2Run{
			{action: "drop-invalid", kind: "artifact", wantOutput: "dropped ''", wantEGS: refusedDigest, wantLists: runbookRevoked([]any{}, []any{"SHA256:ABC"})},
		}},
		{name: "drop-invalid keeps the exact copy of a duplicated digest", file: runbookLists([]any{}, []any{padded, runbookDigestB, runbookDigestA}), wantEGSBefore: refusedDuplicate, runs: []step2Run{
			{action: "drop-invalid", kind: "artifact", wantOutput: "dropped '" + padded + "'", wantLists: runbookRevoked([]any{}, []any{runbookDigestB, runbookDigestA})},
		}},
		{name: "drop-invalid drops an extra exact copy", file: runbookLists([]any{"k1", "k1", "k2"}, []any{}), wantEGSBefore: refusedDuplicate, runs: []step2Run{
			{action: "drop-invalid", kind: "signer", wantOutput: "dropped 'k1'", wantLists: runbookRevoked([]any{"k1", "k2"}, []any{})},
		}},
		{name: "drop-invalid trims only what EGS trims: U+001C", file: runbookLists([]any{"k1", "k1\u001c"}, []any{}), runs: []step2Run{
			{action: "drop-invalid", kind: "signer", wantOutput: "no empty, non-string or duplicate entries; the file is unchanged", unchanged: true},
			{action: "remove", kind: "signer", value: "k1", wantOutput: "removed", wantLists: runbookRevoked([]any{"k1\u001c"}, []any{})},
		}},
		{name: "drop-invalid trims what EGS trims: an ideographic space", file: runbookLists([]any{"\u3000k1", "k1"}, []any{}), wantEGSBefore: refusedDuplicate, runs: []step2Run{
			{action: "drop-invalid", kind: "signer", wantOutput: `dropped '\u3000k1'`, wantLists: runbookRevoked([]any{"k1"}, []any{})},
		}},
		{name: "drop-invalid drops an entry that is only white space EGS trims", file: runbookLists([]any{"k1", "\u2028\u00a0"}, []any{}), wantEGSBefore: refusedEmpty, runs: []step2Run{
			{action: "drop-invalid", kind: "signer", wantOutput: `dropped '\u2028\xa0'`, wantLists: runbookRevoked([]any{"k1"}, []any{})},
		}},
		// KIND=allowed
		{name: "allowed: drop-invalid drops a duplicate", file: runbookAllowed(runbookAGSKeyID, runbookAGSKeyID), wantEGSBefore: refusedDuplicate, runs: []step2Run{
			{action: "drop-invalid", kind: "allowed", wantOutput: "dropped '" + runbookAGSKeyID + "'", wantLists: runbookRevoked([]any{"k9"}, []any{})},
		}},
		{name: "allowed: drop-invalid drops an empty entry", file: runbookAllowed(runbookAGSKeyID, ""), wantEGSBefore: refusedEmpty, runs: []step2Run{
			{action: "drop-invalid", kind: "allowed", wantOutput: "dropped ''"},
		}},
		{name: "allowed: drop-invalid drops a number", file: runbookAllowed(runbookAGSKeyID, 5), wantEGSBefore: refusedType, runs: []step2Run{
			{action: "drop-invalid", kind: "allowed", wantOutput: "dropped 5"},
		}},
		{name: "allowed: drop-invalid drops a padded duplicate", file: runbookAllowed(" "+runbookAGSKeyID, runbookAGSKeyID), wantEGSBefore: refusedDuplicate, runs: []step2Run{
			{action: "drop-invalid", kind: "allowed", wantOutput: "dropped ' " + runbookAGSKeyID + "'"},
		}},
		{name: "allowed: a lone padded entry is left alone", file: runbookAllowed(" " + runbookAGSKeyID), runs: []step2Run{
			{action: "drop-invalid", kind: "allowed", wantOutput: "no empty, non-string or duplicate entries; the file is unchanged", unchanged: true},
		}},
		{name: "allowed: add and remove are refused", file: runbookAllowed(runbookAGSKeyID), runs: []step2Run{
			{action: "add", kind: "allowed", value: "k2", wantExit: 1, wantOutput: "KIND=allowed takes only ACTION=drop-invalid: this runbook never adds or removes an allowed signer; nothing changed", unchanged: true},
			{action: "remove", kind: "allowed", value: runbookAGSKeyID, wantExit: 1, wantOutput: "KIND=allowed takes only ACTION=drop-invalid", unchanged: true},
		}},
		// refusals
		{name: "a bad ACTION or KIND is refused", file: runbookLists([]any{}, []any{}), runs: []step2Run{
			{action: "bogus", kind: "artifact", value: runbookDigestA, wantExit: 1, wantOutput: "ACTION must be add, remove or drop-invalid; nothing changed", unchanged: true},
			{action: "add", kind: "bogus", value: runbookDigestA, wantExit: 1, wantOutput: "KIND must be artifact, signer or allowed; nothing changed", unchanged: true},
		}},
		{name: "a list that is a string is refused", file: runbookLists([]any{}, runbookDigestA), wantEGSBefore: refusedType, runs: []step2Run{
			{action: "add", kind: "artifact", value: runbookDigestB, wantExit: 1, wantOutput: "runtime_trust.artifact_policy.revoked_artifacts is not a list; repair the file with the tool that wrote it; nothing changed", wantEGS: refusedType, unchanged: true},
		}},
		{name: "a list that is an empty object is refused", file: runbookLists(map[string]any{}, []any{}), wantEGSBefore: refusedType, runs: []step2Run{
			{action: "add", kind: "signer", value: "k1", wantExit: 1, wantOutput: "is not a list", wantEGS: refusedType, unchanged: true},
		}},
		{name: "a policy that is not an object is refused before any write", file: map[string]any{"signer_policy": "x", "artifact_policy": map[string]any{"revoked_artifacts": []any{}}}, wantEGSBefore: refusedType, runs: []step2Run{
			{action: "add", kind: "artifact", value: runbookDigestA, wantExit: 1, wantOutput: "runtime_trust.signer_policy is not an object; repair the file with the tool that wrote it; nothing changed", wantEGS: refusedType, unchanged: true},
			{action: "add", kind: "signer", value: "k1", wantExit: 1, wantOutput: "runtime_trust.signer_policy is not an object", wantEGS: refusedType, unchanged: true},
		}},
		{name: "an artifact policy that is a list is refused before any write", file: map[string]any{"signer_policy": map[string]any{"allowed_signers": []any{runbookAGSKeyID}, "revoked_signers": []any{}}, "artifact_policy": []any{}}, wantEGSBefore: refusedType, runs: []step2Run{
			{action: "add", kind: "signer", value: "k1", wantExit: 1, wantOutput: "runtime_trust.artifact_policy is not an object", wantEGS: refusedType, unchanged: true},
		}},
		{name: "a runtime_trust that is not an object is refused", file: runtimeTrustValue{[]any{"x"}}, wantEGSBefore: refusedType, runs: []step2Run{
			{action: "add", kind: "artifact", value: runbookDigestA, wantExit: 1, wantOutput: "runtime_trust is not an object; repair the file with the tool that wrote it; nothing changed", wantEGS: refusedType, unchanged: true},
		}},
		{name: "a file that is not an object is refused", file: rawFile("[1, 2]"), wantEGSBefore: refusedType, runs: []step2Run{
			{action: "add", kind: "artifact", value: runbookDigestA, wantExit: 1, wantOutput: "the file is not a JSON object; repair it with the tool that wrote it; nothing changed", wantEGS: refusedType, unchanged: true},
		}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			path := rig.file(t, tc.file)
			refusal, _ := egsStart(t, path)
			switch {
			case tc.wantEGSBefore == egsAccepts && refusal != "":
				t.Fatalf("EGS refuses the file before step 2: %s", refusal)
			case tc.wantEGSBefore != egsAccepts && !strings.Contains(refusal, tc.wantEGSBefore):
				t.Fatalf("EGS before step 2: %q, want a refusal containing %q", refusal, tc.wantEGSBefore)
			}
			for _, run := range tc.runs {
				rig.step2(t, path, run)
			}
		})
	}

	t.Run("KIND=allowed prints allowed_signers and keeps the revoked lists", func(t *testing.T) {
		t.Parallel()
		path := rig.write(t, rig.doc(runbookAllowed(runbookAGSKeyID, runbookAGSKeyID)))
		output := rig.step2(t, path, step2Run{action: "drop-invalid", kind: "allowed", wantOutput: "allowed_signers:", wantLists: runbookRevoked([]any{"k9"}, []any{})})
		if got := allowedSignersOf(t, path); !reflect.DeepEqual(got, []any{runbookAGSKeyID}) {
			t.Fatalf("allowed_signers after drop-invalid = %#v, output\n%s", got, output)
		}
	})

	t.Run("a signer message never says a key ID is not a spelling ES matches", func(t *testing.T) {
		t.Parallel()
		path := rig.write(t, rig.doc(runbookLists([]any{" k1", "k1 "}, []any{})))
		output := rig.step2(t, path, step2Run{action: "remove", kind: "signer", value: "k1", wantOutput: "so it stays revoked"})
		if strings.Contains(output, "not a spelling") {
			t.Fatalf("step 2 says a padded key ID is not matched, but EGS and ES trim it:\n%s", output)
		}
	})

	t.Run("add puts the entry at the end, in two-space indentation, and keeps every other field", func(t *testing.T) {
		t.Parallel()
		// rig.write indents with four spaces, so the rewrite shows.
		path := rig.write(t, rig.doc(runbookLists([]any{"k2"}, []any{runbookDigestB})))
		before, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read config: %v", err)
		}
		rig.step2(t, path, step2Run{action: "add", kind: "artifact", value: runbookDigestA, wantOutput: "added", wantLists: runbookRevoked([]any{"k2"}, []any{runbookDigestB, runbookDigestA})})
		after, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read config: %v", err)
		}
		if text := string(after); !strings.HasPrefix(text, "{\n  \"") || !strings.HasSuffix(text, "\n}\n") {
			t.Fatalf("step 2 did not rewrite the file with two-space indentation and one final line break:\n%s", text)
		}
		var docBefore, docAfter map[string]any
		if err := json.Unmarshal(before, &docBefore); err != nil {
			t.Fatalf("decode config: %v", err)
		}
		if err := json.Unmarshal(after, &docAfter); err != nil {
			t.Fatalf("decode config: %v", err)
		}
		docAfter["runtime_trust"].(map[string]any)["artifact_policy"].(map[string]any)["revoked_artifacts"] = []any{runbookDigestB}
		if !reflect.DeepEqual(docBefore, docAfter) {
			t.Fatalf("step 2 changed a field other than the list:\nbefore %v\nafter  %v", docBefore, docAfter)
		}
		rig.step2(t, path, step2Run{action: "add", kind: "signer", value: "k1", wantOutput: "added", wantLists: runbookRevoked([]any{"k2", "k1"}, []any{runbookDigestB, runbookDigestA})})
	})

	t.Run("a symbolic link is refused", func(t *testing.T) {
		t.Parallel()
		target := rig.write(t, rig.doc(runbookLists([]any{}, []any{runbookDigestA})))
		link := filepath.Join(t.TempDir(), "egs.json")
		if err := os.Symlink(target, link); err != nil {
			t.Fatalf("symlink: %v", err)
		}
		before := stateOf(t, target)
		output, code := rig.run(t, rig.programs.step2, link, "remove", "artifact", runbookDigestA)
		if code != 1 || !strings.Contains(output, "is a symbolic link; run this command on the file it points to; nothing changed") {
			t.Fatalf("step 2 on a symbolic link: exit %d, output\n%s", code, output)
		}
		if after := stateOf(t, target); string(after.content) != string(before.content) {
			t.Fatalf("step 2 changed the file behind a symbolic link")
		}
	})
}

// TestRevocationRunbookStep2KeepsAnotherOwner starts from a file whose owner
// and group differ from those of a file step 2 creates, so keeping them takes
// step 2's chown. In the other runs of step 2 they are the same, and only the
// mode is shown.
func TestRevocationRunbookStep2KeepsAnotherOwner(t *testing.T) {
	t.Parallel()
	uid, gid := -1, -1
	if os.Geteuid() == 0 {
		// root can give the file any owner.
		uid, gid = 1234, 5678
	} else {
		groups, err := os.Getgroups()
		if err != nil {
			t.Fatalf("groups: %v", err)
		}
		for _, group := range groups {
			if group != os.Getegid() {
				gid = group
				break
			}
		}
		if gid < 0 {
			// The CI test gate fails on a test that skips itself unless the
			// list of environment-only tests names it.
			t.Skip("not root and no second group: a file step 2 creates would have the config's owner and group, so keeping them shows nothing")
		}
	}
	rig := newRevocationRunbookRig(t)
	path := rig.write(t, rig.doc(runbookLists([]any{}, []any{})))
	if err := os.Chown(path, uid, gid); err != nil {
		t.Fatalf("chown config: %v", err)
	}
	before := stateOf(t, path)
	if (uid >= 0 && before.uid != uint32(uid)) || before.gid != uint32(gid) {
		t.Fatalf("setup: config is %d:%d, want %d:%d", before.uid, before.gid, uid, gid)
	}
	// rig.step2 fails when the owner, group or mode changed.
	rig.step2(t, path, step2Run{action: "add", kind: "artifact", value: runbookDigestA, wantOutput: "added; the file keeps its owner and mode", wantLists: runbookRevoked([]any{}, []any{runbookDigestA})})
	rig.step2(t, path, step2Run{action: "remove", kind: "artifact", value: runbookDigestA, wantOutput: "the file keeps its owner and mode", wantLists: runbookRevoked([]any{}, []any{})})
}

// TestRevocationRunbookSpaceIsWhatGoTrims requires the white space that step 2
// and the check trim (their SPACE) to be exactly what strings.TrimSpace trims,
// the function EGS trims revoked entries with. A character missing would make
// remove miss an entry EGS matches; an extra one would make drop-invalid trim
// an entry EGS keeps as a value of its own.
func TestRevocationRunbookSpaceIsWhatGoTrims(t *testing.T) {
	t.Parallel()
	rig := newRevocationRunbookRig(t)
	want := map[rune]bool{}
	for r := rune(0); r <= 0x10FFFF; r++ {
		if r >= 0xD800 && r <= 0xDFFF {
			continue
		}
		if strings.TrimSpace(string(r)) == "" {
			want[r] = true
		}
	}
	assignment := regexp.MustCompile(`(?m)^SPACE = (".*")$`)
	for _, program := range []struct{ name, text string }{{"step 2", rig.programs.step2}, {"the check", rig.programs.check}} {
		found := assignment.FindAllStringSubmatch(program.text, -1)
		if len(found) != 1 || strings.Count(program.text, "SPACE =") != 1 {
			t.Fatalf("%s: %d SPACE assignments on a line of their own, want exactly one assignment", program.name, len(found))
		}
		cmd := exec.Command(rig.python, "-I", "-c", "import ast, json, sys; print(json.dumps([ord(c) for c in ast.literal_eval(sys.argv[1])]))", found[0][1])
		cmd.Dir = t.TempDir()
		output, err := cmd.Output()
		if err != nil {
			t.Fatalf("%s: decode SPACE: %v", program.name, err)
		}
		var points []rune
		if err := json.Unmarshal(output, &points); err != nil {
			t.Fatalf("%s: decode SPACE: %v", program.name, err)
		}
		got := map[rune]bool{}
		for _, point := range points {
			got[point] = true
		}
		if !reflect.DeepEqual(got, want) {
			t.Errorf("%s: SPACE is not what strings.TrimSpace trims: missing %s, extra %s", program.name, runeSetDifference(want, got), runeSetDifference(got, want))
		}
	}
}

// runeSetDifference lists, in order, the code points in a and not in b.
func runeSetDifference(a, b map[rune]bool) string {
	var out []string
	for r := rune(0); r <= 0x10FFFF; r++ {
		if a[r] && !b[r] {
			out = append(out, fmt.Sprintf("%U", r))
		}
	}
	return "[" + strings.Join(out, " ") + "]"
}

func TestRevocationRunbookStep1PrintsOnlyTheLists(t *testing.T) {
	t.Parallel()
	rig := newRevocationRunbookRig(t)
	cases := []struct {
		name string
		doc  map[string]any
		want []string
	}{
		{"lists", rig.doc(runbookLists([]any{"k1"}, []any{runbookDigestA})), []string{
			"allowed_signers:   ['" + runbookAGSKeyID + "']",
			"revoked_signers:   ['k1']",
			"revoked_artifacts: ['" + runbookDigestA + "']",
			"AGS signs now with key ID: " + runbookAGSKeyID,
		}},
		{"null lists", rig.doc(map[string]any{"signer_policy": map[string]any{"allowed_signers": []any{runbookAGSKeyID}, "revoked_signers": nil}, "artifact_policy": nil}), []string{
			"allowed_signers:   ['" + runbookAGSKeyID + "']",
			"revoked_signers:   []",
			"revoked_artifacts: []",
			"AGS signs now with key ID: " + runbookAGSKeyID,
		}},
		{"no runtime_trust", rig.doc(nil), []string{
			"allowed_signers:   []",
			"revoked_signers:   []",
			"revoked_artifacts: []",
			"AGS signs now with key ID: " + runbookAGSKeyID,
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			output, code := rig.run(t, rig.programs.step1, rig.write(t, tc.doc), rig.agsPath)
			if got := strings.Split(strings.TrimRight(output, "\n"), "\n"); code != 0 || !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("step 1: exit %d, lines %q, want exit 0 and %q", code, got, tc.want)
			}
		})
	}
}

type checkCaseEGS int

const (
	egsStarts checkCaseEGS = iota
	egsRefuses
)

func TestRevocationRunbookCheckReportsTheListProblems(t *testing.T) {
	t.Parallel()
	rig := newRevocationRunbookRig(t)
	upper := "sha256:" + strings.Repeat("A", 64)
	cases := []struct {
		name     string
		file     any
		want     []string
		wantExit int
		// egs is what EGS does with the file. A clean check does not prove
		// that EGS starts, but every case without a line here is one EGS
		// accepts.
		egs checkCaseEGS
	}{
		{"clean", runbookLists([]any{}, []any{}), []string{"check finished"}, 0, egsStarts},
		{"duplicate digest", runbookLists([]any{}, []any{runbookDigestA, runbookDigestA}), []string{"revoked_artifacts: duplicate: '" + runbookDigestA + "'", "check finished"}, 0, egsRefuses},
		{"duplicate with spaces", runbookLists([]any{"k1", " k1"}, []any{}), []string{"revoked_signers: duplicate: ' k1'", "check finished"}, 0, egsRefuses},
		{"duplicate with an ideographic space", runbookLists([]any{"\u3000k1", "k1"}, []any{}), []string{"revoked_signers: duplicate: 'k1'", "check finished"}, 0, egsRefuses},
		{"empty and non-string entries", runbookLists([]any{"", 5, nil}, []any{}), []string{"revoked_signers: empty entry: ''", "revoked_signers: not a string: 5", "revoked_signers: not a string: None", "check finished"}, 0, egsRefuses},
		{"upper-case digest", runbookLists([]any{}, []any{upper}), []string{"revoked_artifacts: not sha256: and 64 lowercase hex characters: '" + upper + "'", "check finished"}, 0, egsRefuses},
		{"digest with a trailing line break", runbookLists([]any{}, []any{runbookDigestA + "\n"}), []string{"revoked_artifacts: not sha256: and 64 lowercase hex characters: '" + runbookDigestA + `\n'`, "check finished"}, 0, egsRefuses},
		{"key ID ending in U+001C", runbookLists([]any{"k1", "k1\u001c"}, []any{}), []string{"check finished"}, 0, egsStarts},
		{"key ID of U+001F alone", runbookLists([]any{"\u001f"}, []any{}), []string{"check finished"}, 0, egsStarts},
		{"lists that are strings", map[string]any{"signer_policy": map[string]any{"allowed_signers": runbookAGSKeyID, "revoked_signers": []any{}}, "artifact_policy": map[string]any{"revoked_artifacts": runbookDigestA}}, []string{"allowed_signers: not a list", "revoked_artifacts: not a list", "check finished"}, 0, egsRefuses},
		{"list that is an empty object", runbookLists(map[string]any{}, []any{}), []string{"revoked_signers: not a list", "check finished"}, 0, egsRefuses},
		{"policy that is a list", map[string]any{"signer_policy": []any{"k1"}, "artifact_policy": map[string]any{"revoked_artifacts": []any{}}}, []string{"runtime_trust.signer_policy is not an object", "check finished"}, 0, egsRefuses},
		{"policy that is an empty list", map[string]any{"signer_policy": []any{}, "artifact_policy": map[string]any{"revoked_artifacts": []any{}}}, []string{"runtime_trust.signer_policy is not an object", "check finished"}, 0, egsRefuses},
		{"runtime_trust a string", runtimeTrustValue{"x"}, []string{"runtime_trust is not an object"}, 1, egsRefuses},
		{"runtime_trust an empty list", runtimeTrustValue{[]any{}}, []string{"runtime_trust is not an object"}, 1, egsRefuses},
		{"file that is an array", rawFile("[1, 2]"), []string{"the file is not a JSON object"}, 1, egsRefuses},
		{"duplicate allowed signer", runbookAllowed(runbookAGSKeyID, runbookAGSKeyID), []string{"allowed_signers: duplicate: '" + runbookAGSKeyID + "'", "check finished"}, 0, egsRefuses},
		{"unknown field", map[string]any{"signer_policy": map[string]any{"allowed_signers": []any{runbookAGSKeyID}, "revoked_signers": []any{}}, "artifact_policy": map[string]any{"revoked_artifacts": []any{}}, "extra": 1}, []string{"unknown field in runtime_trust: extra", "check finished"}, 0, egsRefuses},
		{"unknown field in signer_policy", map[string]any{"signer_policy": map[string]any{"allowed_signers": []any{runbookAGSKeyID}, "revoked_signers": []any{}, "extra": 1}, "artifact_policy": map[string]any{"revoked_artifacts": []any{}}}, []string{"unknown field in runtime_trust.signer_policy: extra", "check finished"}, 0, egsRefuses},
		{"unknown field in artifact_policy", map[string]any{"signer_policy": map[string]any{"allowed_signers": []any{runbookAGSKeyID}, "revoked_signers": []any{}}, "artifact_policy": map[string]any{"revoked_artifacts": []any{}, "extra": 1}}, []string{"unknown field in runtime_trust.artifact_policy: extra", "check finished"}, 0, egsRefuses},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			path := rig.file(t, tc.file)
			output, code := rig.run(t, rig.programs.check, path)
			if got := strings.Split(strings.TrimRight(output, "\n"), "\n"); code != tc.wantExit || !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("check: exit %d, lines %q, want exit %d and %q", code, got, tc.wantExit, tc.want)
			}
			refusal, _ := egsStart(t, path)
			if (tc.egs == egsStarts && refusal != "") || (tc.egs == egsRefuses && refusal == "") {
				t.Fatalf("EGS start: %q, want it to start: %v", refusal, tc.egs == egsStarts)
			}
		})
	}

	t.Run("invalid JSON", func(t *testing.T) {
		t.Parallel()
		payload, err := json.MarshalIndent(rig.doc(runbookLists([]any{}, []any{})), "", "  ")
		if err != nil {
			t.Fatalf("marshal config: %v", err)
		}
		path := rig.writeRaw(t, string(payload[:len(payload)-40])+`"unterminated`)
		output, code := rig.run(t, rig.programs.check, path)
		if code != 1 || !strings.HasPrefix(output, "not valid JSON: ") || !strings.Contains(output, ": line ") {
			t.Fatalf("check on invalid JSON: exit %d, output %q", code, output)
		}
	})
}
