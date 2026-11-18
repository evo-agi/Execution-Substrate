package app_test

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
)

func proofBoundaryHelper(t *testing.T, name string) string {
	t.Helper()
	return filepath.Join(executionPlatformRepoRoot(t), "scripts", "internal", name)
}

func runProofPython(t *testing.T, helper string, input []byte, args ...string) ([]byte, error) {
	t.Helper()
	command := exec.Command("python3", append([]string{proofBoundaryHelper(t, helper)}, args...)...)
	command.Dir = executionPlatformRepoRoot(t)
	command.Stdin = bytes.NewReader(input)
	command.Env = append(os.Environ(), "PYTHONDONTWRITEBYTECODE=1")
	return command.CombinedOutput()
}

func requireNoProofCanary(t *testing.T, data []byte) {
	t.Helper()
	for _, canary := range []string{proofRootTokenCanary, proofSecretCanary, proofAPIKeyCanary} {
		if bytes.Contains(data, []byte(canary)) {
			t.Fatal("synthetic secret canary entered proof evidence")
		}
	}
}

func TestSupportedLocalProofHostObservationProjections(t *testing.T) {
	fixtures := []struct {
		name, action, output string
		raw                  string
		keys                 []string
	}{
		{"agent", "host-agent", "nomad-agent-safe.json", `{"config":{"Version":"1.9.0","Region":"` + proofRootTokenCanary + `","Datacenter":"` + proofSecretCanary + `","NodeName":"` + proofAPIKeyCanary + `","DevMode":false,"Client":{"Enabled":true},"Server":{"Enabled":true},"Vault":{"Token":"` + proofRootTokenCanary + `"},"Telemetry":{"Token":"` + proofAPIKeyCanary + `"}},"ACL":{"ReplicationToken":"` + proofSecretCanary + `","IntroductionToken":"` + proofAPIKeyCanary + `"}}`, []string{"schema", "version", "region_present", "datacenter_present", "node_name_present", "dev_mode", "client_enabled", "server_enabled"}},
		{"nodes", "host-nodes", "nomad-nodes-safe.json", `[{"Status":"ready","SchedulingEligibility":"eligible","Meta":{"secret":"` + proofRootTokenCanary + `"},"Attributes":{"token":"` + proofSecretCanary + `"}}]`, []string{"schema", "node_count", "ready_count", "eligible_count"}},
		{"details", "host-node-details", "node-details-safe.json", `[{"Attributes":{"cpu.totalcompute":"2000","private":"` + proofSecretCanary + `"},"Drivers":{"docker":{"Healthy":true}},"Meta":{"api_key":"` + proofAPIKeyCanary + `"}}]`, []string{"schema", "detail_count", "positive_compute_count", "docker_healthy_count"}},
		{"systemd", "host-systemd", "nomad-service-safe.json", "Id=nomad.service\nLoadState=loaded\nActiveState=active\nSubState=running\nUnitFileState=enabled\nMainPID=123\nExecMainStatus=0\nJournal=" + proofSecretCanary + "\n", []string{"schema", "loaded", "active", "running", "enabled", "main_pid_positive", "exec_main_status_zero"}},
		{"docker", "host-docker", "docker-info-safe.json", `{"ServerVersion":"27.5.1","Architecture":"aarch64","Driver":"overlay2","CgroupVersion":"2","NCPU":4,"MemTotal":8589934592,"Plugins":{"Volume":["local"]},"Labels":["` + proofAPIKeyCanary + `"],"RegistryConfig":{"Auth":"` + proofRootTokenCanary + `"}}`, []string{"schema", "server_version", "architecture", "storage_driver", "cgroup_version", "cpu_count", "memory_bytes", "local_volume_capable"}},
		{"leader", "host-leader", "nomad-leader-safe.json", `"127.0.0.1:4647"`, []string{"schema", "leader_present"}},
		{"override", "host-compute-override", "nomad-compute-override-safe.json", "false\n", []string{"schema", "override_present"}},
	}
	for _, tc := range fixtures {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			path := filepath.Join(root, tc.output)
			output, err := runProofPython(t, "supported_local_proof_projection.py", []byte(tc.raw), tc.action, "-", path)
			if err != nil {
				t.Fatalf("safe projection failed: %v output=%q", err, output)
			}
			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			requireNoProofCanary(t, data)
			for _, forbidden := range []string{"Token", "Auth", "Meta", "Attributes", "Labels", "RegistryConfig", "Journal"} {
				if bytes.Contains(data, []byte(forbidden)) {
					t.Fatalf("unsafe field entered %s projection", tc.name)
				}
			}
			var fields map[string]any
			if err := json.Unmarshal(data, &fields); err != nil {
				t.Fatal(err)
			}
			if len(fields) != len(tc.keys) {
				t.Fatalf("projection field count: got=%v want=%v", fields, tc.keys)
			}
			for _, key := range tc.keys {
				if _, okay := fields[key]; !okay {
					t.Fatalf("fixed projection missing %q", key)
				}
			}
		})
	}
}

func TestSupportedLocalProofNodeDetailLoopbackAdmission(t *testing.T) {
	const nodeID = "01234567-89ab-cdef-0123-456789abcdef"
	var requests atomic.Int64
	var redirected atomic.Int64
	var redirect atomic.Bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		if redirect.Load() && r.URL.Path == "/v1/nodes" {
			w.Header().Set("Location", "/redirected")
			w.WriteHeader(http.StatusFound)
			return
		}
		if r.URL.Path == "/redirected" {
			redirected.Add(1)
		}
		switch r.URL.Path {
		case "/v1/nodes":
			fmt.Fprintf(w, `[{"ID":%q}]`, nodeID)
		case "/v1/node/" + nodeID:
			fmt.Fprintf(w, `{"Attributes":{"cpu.totalcompute":"2000","secret":%q},"Drivers":{"docker":{"Healthy":true}},"Meta":{"token":%q}}`, proofSecretCanary, proofRootTokenCanary)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	project := func(url string) ([]byte, error) {
		path := filepath.Join(t.TempDir(), "node-details-safe.json")
		output, err := runProofPython(t, "supported_local_proof_projection.py", nil, "fetch-node-details", url, path)
		if err != nil {
			if _, statErr := os.Lstat(path); !os.IsNotExist(statErr) {
				t.Fatal("failed node fetch published partial output")
			}
			return output, err
		}
		return os.ReadFile(path)
	}
	data, err := project(server.URL)
	if err != nil {
		t.Fatalf("valid loopback fetch failed: %v output=%q", err, data)
	}
	requireNoProofCanary(t, data)
	var projected map[string]any
	if err := json.Unmarshal(data, &projected); err != nil {
		t.Fatal(err)
	}
	if len(projected) != 4 || projected["schema"] != "supported-local-node-details-safe-v1" ||
		projected["detail_count"] != float64(1) || projected["positive_compute_count"] != float64(1) ||
		projected["docker_healthy_count"] != float64(1) {
		t.Fatalf("fixed node detail projection mismatch: %v", projected)
	}
	baseRequests := requests.Load()
	port := strings.TrimPrefix(server.URL, "http://127.0.0.1:")
	for _, bad := range []string{
		"http://user:password@127.0.0.1:" + port,
		"http://localhost:" + port,
		"http://127.0.0.1:" + port + "@localhost:" + port,
		server.URL + "?token=" + proofAPIKeyCanary,
		server.URL + "#fragment",
		server.URL + "/v1",
		"http://127.0.0.1:99999",
		"http://127.0.0.1.:" + port,
		"http://127.0.0.1:0" + port,
	} {
		if output, err := project(bad); err == nil || bytes.Contains(output, []byte(proofAPIKeyCanary)) {
			t.Fatalf("unsafe node URL accepted or leaked canary: %q", bad)
		}
		if requests.Load() != baseRequests {
			t.Fatal("rejected node URL contacted the synthetic server")
		}
	}
	redirect.Store(true)
	if output, err := project(server.URL); err == nil || bytes.Contains(output, []byte(proofSecretCanary)) || redirected.Load() != 0 {
		t.Fatal("loopback redirect was followed or published")
	}
}

func TestSupportedLocalProofNodeDetailAggregateBounds(t *testing.T) {
	var aggregate atomic.Bool
	var detailRequests atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/nodes" {
			count := 129
			if aggregate.Load() {
				count = 3
			}
			ids := make([]map[string]string, count)
			for i := range ids {
				ids[i] = map[string]string{"ID": fmt.Sprintf("%08x-89ab-cdef-0123-456789abcdef", i)}
			}
			_ = json.NewEncoder(w).Encode(ids)
			return
		}
		detailRequests.Add(1)
		fmt.Fprintf(w, `{"Attributes":{"cpu.totalcompute":"2000"},"Meta":{"padding":%q}}`, strings.Repeat("x", 3<<20))
	}))
	defer server.Close()
	path := filepath.Join(t.TempDir(), "node-details-safe.json")
	if output, err := runProofPython(t, "supported_local_proof_projection.py", nil, "fetch-node-details", server.URL, path); err == nil || bytes.Contains(output, []byte(proofSecretCanary)) {
		t.Fatal("node count above bound was accepted")
	}
	if detailRequests.Load() != 0 {
		t.Fatal("over-count node list caused detail requests")
	}
	aggregate.Store(true)
	if output, err := runProofPython(t, "supported_local_proof_projection.py", nil, "fetch-node-details", server.URL, path); err == nil || bytes.Contains(output, []byte(proofSecretCanary)) {
		t.Fatal("aggregate node bytes above bound were accepted")
	}
	if detailRequests.Load() != 3 {
		t.Fatalf("aggregate bound stopped at unexpected response count: %d", detailRequests.Load())
	}
	if _, err := os.Lstat(path); !os.IsNotExist(err) {
		t.Fatal("failed bounded node fetch published output")
	}
}

func gitFixture(t *testing.T, repo string, args ...string) {
	t.Helper()
	command := exec.Command("git", append([]string{"-C", repo}, args...)...)
	command.Env = append(os.Environ(), "GIT_OPTIONAL_LOCKS=0", "GIT_NO_LAZY_FETCH=1", "GIT_TERMINAL_PROMPT=0")
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("fixture Git failed: %v output=%q", err, output)
	}
}

func TestSupportedLocalProofGitBoundSnapshotAndBootstrapScratch(t *testing.T) {
	repo := filepath.Join(t.TempDir(), "repo")
	if err := os.Mkdir(repo, 0o700); err != nil {
		t.Fatal(err)
	}
	gitFixture(t, repo, "init", "-q")
	for name, body := range map[string]string{
		".gitignore":              ".env\n*.db\n*.tar.gz\n",
		"main.go":                 "package main\n",
		".out/Dockerfile":         "FROM scratch\n",
		"es/admission/new.go":     "package admission\n",
		"es/admission/secret.go":  proofSecretCanary,
		"es/admission/input.json": proofAPIKeyCanary,
		".env":                    proofRootTokenCanary,
		"ignored.db":              proofAPIKeyCanary,
		"ignored.tar.gz":          proofSecretCanary,
	} {
		writeProofEvidenceFile(t, repo, name, []byte(body))
	}
	gitFixture(t, repo, "add", "--", ".gitignore", "main.go", ".out/Dockerfile")
	var snapshots [][]byte
	for i := 0; i < 2; i++ {
		parent := t.TempDir()
		scratch := filepath.Join(parent, "bootstrap")
		evidence := filepath.Join(parent, "evidence")
		if err := os.Mkdir(evidence, 0o700); err != nil {
			t.Fatal(err)
		}
		created, err := runProofPython(t, "supported_local_proof_source_snapshot.py", nil, "create-scratch", scratch, "proof-fixture")
		if err != nil {
			t.Fatalf("create private scratch: %v output=%q", err, created)
		}
		identity := strings.TrimSpace(string(created))
		if output, err := runProofPython(t, "supported_local_proof_source_snapshot.py", nil, "snapshot", repo, scratch, evidence); err != nil {
			t.Fatalf("Git-bound snapshot: %v output=%q", err, output)
		}
		archive, err := os.ReadFile(filepath.Join(scratch, "host-repo-snapshot.tar.gz"))
		if err != nil {
			t.Fatal(err)
		}
		snapshots = append(snapshots, archive)
		manifest, err := os.ReadFile(filepath.Join(evidence, "source-manifest.json"))
		if err != nil {
			t.Fatal(err)
		}
		requireNoProofCanary(t, manifest)
		requireNoProofCanary(t, archive)
		var rows struct {
			Files []struct{ Path, Classification string } `json:"files"`
		}
		if err := json.Unmarshal(manifest, &rows); err != nil {
			t.Fatal(err)
		}
		got := make([]string, 0, len(rows.Files))
		for _, row := range rows.Files {
			got = append(got, row.Path)
		}
		want := []string{".gitignore", ".out/Dockerfile", "es/admission/new.go", "main.go"}
		if !sort.StringsAreSorted(got) || !equalProofStrings(got, want) {
			t.Fatalf("selected source paths: got=%v want=%v", got, want)
		}
		if rows.Files[1].Classification != "tracked" {
			t.Fatal("tracked .out/Dockerfile was not preserved explicitly")
		}
		if _, err := os.Stat(filepath.Join(evidence, "host-repo-snapshot.tar.gz")); !os.IsNotExist(err) {
			t.Fatal("transport snapshot entered host proof evidence")
		}
		if output, err := runProofPython(t, "supported_local_proof_source_snapshot.py", nil, "cleanup-scratch", scratch, identity); err != nil {
			t.Fatalf("exact scratch cleanup: %v output=%q", err, output)
		}
		if _, err := os.Lstat(scratch); !os.IsNotExist(err) {
			t.Fatal("task-owned bootstrap scratch was retained after exact cleanup")
		}
	}
	if !bytes.Equal(snapshots[0], snapshots[1]) {
		t.Fatal("Git-bound source snapshot bytes were nondeterministic")
	}
	link := filepath.Join(repo, "es", "admission", "link.go")
	if err := os.Symlink(filepath.Join(t.TempDir(), "outside"), link); err != nil {
		t.Fatal(err)
	}
	parent := t.TempDir()
	scratch := filepath.Join(parent, "bootstrap")
	evidence := filepath.Join(parent, "evidence")
	if err := os.Mkdir(evidence, 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := runProofPython(t, "supported_local_proof_source_snapshot.py", nil, "create-scratch", scratch, "proof-fixture"); err != nil {
		t.Fatal(err)
	}
	if _, err := runProofPython(t, "supported_local_proof_source_snapshot.py", nil, "snapshot", repo, scratch, evidence); err == nil {
		t.Fatal("selected source symlink was accepted")
	}
	if err := os.Remove(link); err != nil {
		t.Fatal(err)
	}
	selected := filepath.Join(repo, "main.go")
	if err := os.Chmod(selected, 0o4755); err != nil {
		t.Fatal(err)
	}
	if selectedInfo, err := os.Lstat(selected); err != nil {
		t.Fatal(err)
	} else if selectedInfo.Mode()&os.ModeSetuid != 0 {
		if _, err := runProofPython(t, "supported_local_proof_source_snapshot.py", nil, "snapshot", repo, scratch, evidence); err == nil {
			t.Fatal("source with setuid mode was accepted")
		}
	} else {
		t.Log("fixture filesystem did not retain setuid bit; source guard remains source checked")
	}
	if err := os.Chmod(selected, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Mkfifo(link, 0o600); err == nil {
		if _, err := runProofPython(t, "supported_local_proof_source_snapshot.py", nil, "snapshot", repo, scratch, evidence); err != nil {
			t.Fatalf("unselected FIFO changed Git-bound snapshot: %v", err)
		}
		listing, err := os.ReadFile(filepath.Join(evidence, "source-manifest.json"))
		if err != nil || bytes.Contains(listing, []byte("link.go")) {
			t.Fatal("unselected FIFO entered source manifest")
		}
	}
}

func equalProofStrings(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for i := range left {
		if left[i] != right[i] {
			return false
		}
	}
	return true
}

func TestSupportedLocalProofCompleteHostManifest(t *testing.T) {
	root := t.TempDir()
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatal(err)
	}
	writeProofEvidenceFile(t, root, "proof-metadata.json", []byte(`{"schema":"supported-local-proof-metadata-v2","proof_id":"fixture"}`))
	writeProofEvidenceFile(t, root, "guest-evidence/setup/guest-repo-snapshot.sha256", []byte(strings.Repeat("a", 64)+"\n"))
	writeProofEvidenceFile(t, root, "guest-evidence/setup/execution-roots-setup-safe.json", []byte(`{"schema":"supported-local-execution-roots-setup-safe-v1","profile":"service-root-v1","configured_root_uid":0,"configured_root_gid":0,"configured_root_mode":"0755","static_root_owner_mode_checked":true,"operator_write_access_required":false,"container_identity_or_behavioral_capability_proved":false}`))
	writeProofEvidenceFile(t, root, "guest-evidence/setup/safe-evidence-manifest.json", []byte(`{"schema":"supported-local-proof-safe-evidence-v1","files":[]}`))
	for _, directory := range []string{"guest-evidence", "guest-evidence/setup"} {
		if err := os.Chmod(filepath.Join(root, directory), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if output, err := runProofPython(t, "supported_local_proof_host_manifest.py", nil, "finalize", root); err != nil {
		t.Fatalf("complete host manifest: %v output=%q", err, output)
	}
	manifest, err := os.ReadFile(filepath.Join(root, "host-evidence-manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	var parsed struct {
		Files []struct {
			Path           string `json:"path"`
			Classification string `json:"classification"`
			Mode           string `json:"mode"`
			Size           int    `json:"size"`
			SHA256         string `json:"sha256"`
		} `json:"files"`
	}
	if err := json.Unmarshal(manifest, &parsed); err != nil {
		t.Fatal(err)
	}
	if len(parsed.Files) != 4 {
		t.Fatalf("complete host manifest omitted a retained file: %+v", parsed.Files)
	}
	for _, row := range parsed.Files {
		if row.Path == "guest-evidence/setup/execution-roots-setup-safe.json" && row.Classification != "proof_assertions" {
			t.Fatal("root setup projection lacks fixed host classification")
		}
		data, err := os.ReadFile(filepath.Join(root, row.Path))
		if err != nil {
			t.Fatal(err)
		}
		digest := sha256.Sum256(data)
		if row.Mode != "0600" || row.Size != len(data) || row.SHA256 != hex.EncodeToString(digest[:]) {
			t.Fatalf("host manifest row mismatch: %+v", row)
		}
	}
	bad := t.TempDir()
	if err := os.Chmod(bad, 0o700); err != nil {
		t.Fatal(err)
	}
	writeProofEvidenceFile(t, bad, "proof-metadata.json", []byte("safe"))
	writeProofEvidenceFile(t, bad, "unclassified.txt", []byte(proofSecretCanary))
	if output, err := runProofPython(t, "supported_local_proof_host_manifest.py", nil, "finalize", bad); err == nil || bytes.Contains(output, []byte(proofSecretCanary)) {
		t.Fatalf("unclassified host file did not fail closed: err=%v", err)
	}
}

func TestSupportedLocalProofHostManifestRootRecord(t *testing.T) {
	var manifests [][]byte
	for i := 0; i < 2; i++ {
		root := t.TempDir()
		if err := os.Chmod(root, 0o700); err != nil {
			t.Fatal(err)
		}
		writeProofEvidenceFile(t, root, "proof-metadata.json", []byte(`{"schema":"supported-local-proof-metadata-v2","proof_id":"fixture"}`))
		writeProofEvidenceFile(t, root, "guest-evidence/setup/guest-repo-snapshot.sha256", []byte(strings.Repeat("a", 64)+"\n"))
		writeProofEvidenceFile(t, root, "guest-evidence/setup/safe-evidence-manifest.json", []byte(`{"schema":"supported-local-proof-safe-evidence-v1","files":[]}`))
		for _, name := range []string{"guest-evidence", "guest-evidence/setup"} {
			if err := os.Chmod(filepath.Join(root, name), 0o700); err != nil {
				t.Fatal(err)
			}
		}
		output, err := runProofPython(t, "supported_local_proof_host_manifest.py", nil, "finalize", root)
		if err != nil {
			t.Fatalf("host root record: %v output=%q", err, output)
		}
		manifest, err := os.ReadFile(filepath.Join(root, "host-evidence-manifest.json"))
		if err != nil {
			t.Fatal(err)
		}
		manifests = append(manifests, manifest)
		digest := sha256.Sum256(manifest)
		if string(output) != hex.EncodeToString(digest[:])+"\n" {
			t.Fatal("reported host manifest digest does not match reopened final bytes")
		}
		var parsed struct {
			Schema       string `json:"schema"`
			RootRecord   bool   `json:"root_record"`
			SelfExcluded bool   `json:"self_excluded"`
			Files        []struct {
				Path string `json:"path"`
			} `json:"files"`
		}
		if err := json.Unmarshal(manifest, &parsed); err != nil {
			t.Fatal(err)
		}
		if parsed.Schema != "supported-local-host-evidence-manifest-v2" || !parsed.RootRecord || !parsed.SelfExcluded {
			t.Fatalf("host root-record contract missing: %+v", parsed)
		}
		actual := []string{}
		if err := filepath.WalkDir(root, func(path string, entry os.DirEntry, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			if entry.IsDir() {
				return nil
			}
			relative, err := filepath.Rel(root, path)
			if err != nil {
				return err
			}
			if relative != "host-evidence-manifest.json" {
				actual = append(actual, filepath.ToSlash(relative))
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
		sort.Strings(actual)
		rows := make([]string, 0, len(parsed.Files))
		for _, row := range parsed.Files {
			rows = append(rows, row.Path)
		}
		if !equalProofStrings(rows, actual) || len(actual) != 3 {
			t.Fatalf("manifest rows do not cover every other retained file: rows=%v actual=%v", rows, actual)
		}
	}
	if !bytes.Equal(manifests[0], manifests[1]) {
		t.Fatal("deterministic host root records differ")
	}
}

func TestSupportedLocalProofExecutionLineageSchema(t *testing.T) {
	const firstRun = "run-0123456789abcdef"
	const secondRun = "run-fedcba9876543210"
	const allocation = "01234567-89ab-cdef-0123-456789abcdef"
	writeLineage := func(t *testing.T, root, label, runID, jobID, allocationID string, extra bool) {
		t.Helper()
		summary := map[string]any{"ok": true, "message": "execution completed successfully", "run_id": runID,
			"spec_path": proofSecretCanary, "Meta": proofAPIKeyCanary}
		execution := map[string]any{"schema": "supported-local-nomad-execution-safe-v1", "run_id": runID,
			"job_id": jobID, "allocation_id": allocationID, "job_observed": true, "allocation_observed": true}
		if extra {
			execution["Attributes"] = proofRootTokenCanary
		}
		for name, value := range map[string]any{label + "-summary.json": summary, label + "-nomad-execution-safe.json": execution} {
			payload, err := json.Marshal(value)
			if err != nil {
				t.Fatal(err)
			}
			writeProofEvidenceFile(t, root, name, payload)
		}
	}
	root := t.TempDir()
	writeLineage(t, root, "runtime-identity-vault", firstRun, "exec-"+firstRun, allocation, false)
	writeLineage(t, root, "control-plane-normal-shell", secondRun, "exec-"+secondRun,
		"fedcba98-7654-3210-fedc-ba9876543210", false)
	archive, stderr, err := runProofEvidenceCollector(t, root)
	if err != nil {
		t.Fatalf("valid fixed execution lineage rejected: %v stderr=%q", err, stderr)
	}
	requireNoProofCanary(t, archive)
	files, _ := readProofEvidenceArchive(t, archive)
	for _, item := range []struct{ label, runID string }{{"runtime-identity-vault", firstRun}, {"control-plane-normal-shell", secondRun}} {
		var summary, execution map[string]any
		if err := json.Unmarshal(files[item.label+"-summary.json"], &summary); err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal(files[item.label+"-nomad-execution-safe.json"], &execution); err != nil {
			t.Fatal(err)
		}
		if summary["run_id"] != item.runID || len(summary) != 3 || len(execution) != 6 ||
			execution["run_id"] != item.runID || execution["job_id"] != "exec-"+item.runID {
			t.Fatalf("retained lineage schema mismatch: %s summary=%v execution=%v", item.label, summary, execution)
		}
	}
	for _, variant := range []struct {
		name, summaryRun, executionRun, jobID, allocationID string
		extra                                               bool
	}{
		{"invalid run grammar", "run-not-hex", "run-not-hex", "exec-run-not-hex", allocation, false},
		{"uppercase run", "run-0123456789ABCDEF", "run-0123456789ABCDEF", "exec-run-0123456789ABCDEF", allocation, false},
		{"mismatched job", firstRun, firstRun, "exec-" + secondRun, allocation, false},
		{"invalid allocation", firstRun, firstRun, "exec-" + firstRun, "allocation-proof", false},
		{"unknown execution field", firstRun, firstRun, "exec-" + firstRun, allocation, true},
		{"mismatched summary", firstRun, secondRun, "exec-" + secondRun, allocation, false},
	} {
		t.Run(variant.name, func(t *testing.T) {
			root := t.TempDir()
			writeLineage(t, root, "runtime-identity-vault", variant.summaryRun,
				variant.jobID, variant.allocationID, variant.extra)
			if variant.executionRun != variant.summaryRun {
				path := filepath.Join(root, "runtime-identity-vault-nomad-execution-safe.json")
				payload, err := os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
				var value map[string]any
				if err := json.Unmarshal(payload, &value); err != nil {
					t.Fatal(err)
				}
				value["run_id"] = variant.executionRun
				modified, err := json.Marshal(value)
				if err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(path, modified, 0o600); err != nil {
					t.Fatal(err)
				}
			}
			output, stderr, err := runProofEvidenceCollector(t, root)
			if err == nil || len(output) != 0 || strings.Contains(stderr, proofSecretCanary) {
				t.Fatal("invalid execution lineage was accepted or leaked")
			}
		})
	}
}

func TestSupportedLocalProofExclusiveGenerations(t *testing.T) {
	guest := t.TempDir()
	host := t.TempDir()
	if err := os.Chmod(host, 0o700); err != nil {
		t.Fatal(err)
	}
	writeProofEvidenceFile(t, guest, "guest-repo-snapshot.sha256", []byte(strings.Repeat("b", 64)+"\n"))
	first, stderr, err := runProofEvidenceCollector(t, guest)
	if err != nil {
		t.Fatalf("collect setup: %v stderr=%q", err, stderr)
	}
	receive := func(label string, payload []byte) error {
		command := exec.Command("bash", proofEvidenceHelper(t), "receive-safe", host, label)
		command.Stdin = bytes.NewReader(payload)
		command.Env = append(os.Environ(), "PYTHONDONTWRITEBYTECODE=1")
		output, err := command.CombinedOutput()
		if err != nil {
			t.Logf("receive %s failed: %v %q", label, err, output)
		}
		return err
	}
	if err := receive("setup", first); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(guest, "guest-repo-snapshot.sha256")); err != nil {
		t.Fatal(err)
	}
	second, _, err := runProofEvidenceCollector(t, guest)
	if err != nil || receive("final", second) != nil {
		t.Fatalf("collect exclusive final generation: %v", err)
	}
	if _, err := os.Stat(filepath.Join(host, "guest-evidence", "setup", "guest-repo-snapshot.sha256")); err != nil {
		t.Fatal("setup generation changed after final publication")
	}
	if _, err := os.Stat(filepath.Join(host, "guest-evidence", "final", "guest-repo-snapshot.sha256")); !os.IsNotExist(err) {
		t.Fatal("omitted file became stale in final generation")
	}
	if err := receive("setup", second); err == nil {
		t.Fatal("repeated setup generation overwrote prior evidence")
	}
	claim := filepath.Join(host, "guest-evidence", ".claim-failure")
	if err := os.WriteFile(claim, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := receive("failure", first); err == nil {
		t.Fatal("concurrent failure-generation claim was ignored")
	}
	if err := os.Remove(claim); err != nil {
		t.Fatal(err)
	}
	writeFailure := exec.Command("bash", "-c", `trap '' XFSZ; ulimit -f 0; exec bash "$PROOF_HELPER" receive-safe "$PROOF_HOST" failure`)
	writeFailure.Stdin = bytes.NewReader(first)
	writeFailure.Env = append(os.Environ(), "PROOF_HELPER="+proofEvidenceHelper(t), "PROOF_HOST="+host,
		"PYTHONDONTWRITEBYTECODE=1")
	if output, err := writeFailure.CombinedOutput(); err == nil || bytes.Contains(output, []byte(proofSecretCanary)) {
		t.Fatal("controlled receiver write failure did not fail closed")
	}
	if entries, err := os.ReadDir(filepath.Join(host, "guest-evidence")); err != nil {
		t.Fatal(err)
	} else {
		for _, entry := range entries {
			if strings.HasPrefix(entry.Name(), ".pending-") || strings.HasPrefix(entry.Name(), ".claim-") {
				t.Fatal("failed generation left unpublished staging material")
			}
		}
	}
	corrupt := append([]byte(nil), first...)
	corrupt[0] = 'X'
	if err := receive("failure", corrupt); err == nil {
		t.Fatal("invalid generation archive was accepted")
	}
	if _, err := os.Lstat(filepath.Join(host, "guest-evidence", "failure")); !os.IsNotExist(err) {
		t.Fatal("failed generation published a partial final directory")
	}
}

func TestSupportedLocalProofWrapperTransportUsesBootstrapScratch(t *testing.T) {
	parent := t.TempDir()
	scratch := filepath.Join(parent, "bootstrap")
	host := filepath.Join(parent, "host-proof")
	if err := os.Mkdir(scratch, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(host, 0o700); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"host-repo-snapshot.tar.gz", "bin/es-runtime-support", "bin/spire.tar.gz",
		"payload/runtime_identity_vault_login.tar.gz", "payload/control_plane_normal_shell_runtime.tar.gz",
		"runtime_identity_vault_success.input.json", "control_plane_normal_shell_runtime.input.json"} {
		writeProofEvidenceFile(t, scratch, name, []byte(proofSecretCanary))
	}
	logPath := filepath.Join(parent, "transport.log")
	shell := `source "$PROOF_SCRIPT"
SUPPORTED_LOCAL_HOST_BOOTSTRAP_DIR="$TEST_SCRATCH"
SUPPORTED_LOCAL_HOST_PROOF_DIR="$TEST_HOST"
limactl() { printf '%s\n' "$*" >> "$TEST_LOG"; cat >/dev/null; }
copy_repo_snapshot_to_guest
copy_tooling_to_guest
copy_inputs_to_guest
run_phase input-preparation true
run_phase snapshot-drop true`
	command := exec.Command("bash", "-c", shell)
	command.Dir = executionPlatformRepoRoot(t)
	command.Env = append(os.Environ(), "PROOF_SCRIPT="+filepath.Join(executionPlatformRepoRoot(t), "scripts", "73_supported_local_proof.sh"),
		"TEST_SCRATCH="+scratch, "TEST_HOST="+host, "TEST_LOG="+logPath)
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("fake wrapper transport: %v output=%q", err, output)
	}
	entries, err := os.ReadDir(host)
	if err != nil || len(entries) != 2 || entries[0].Name() != "phase-input-preparation.json" || entries[1].Name() != "phase-snapshot-drop.json" {
		t.Fatalf("transport material entered host proof evidence: entries=%v err=%v", entries, err)
	}
	for _, entry := range entries {
		data, err := os.ReadFile(filepath.Join(host, entry.Name()))
		if err != nil || !bytes.Contains(data, []byte(`"schema":"supported-local-proof-phase-v1"`)) {
			t.Fatalf("phase status was not a fixed safe projection: %s", entry.Name())
		}
		requireNoProofCanary(t, data)
	}
	log, err := os.ReadFile(logPath)
	if err != nil || bytes.Count(log, []byte("fake-proof")) != 0 || bytes.Count(log, []byte("shell")) < 7 {
		t.Fatalf("bounded fake transport did not exercise wrapper functions: err=%v", err)
	}
	requireNoProofCanary(t, append(output, log...))
}

func TestSupportedLocalProofFinalizerPreservesPrimaryStatusAcrossLocalFailures(t *testing.T) {
	parent := t.TempDir()
	scratch := filepath.Join(parent, "bootstrap")
	host := filepath.Join(parent, "host-proof")
	if err := os.Mkdir(host, 0o700); err != nil {
		t.Fatal(err)
	}
	identityBytes, err := runProofPython(t, "supported_local_proof_source_snapshot.py", nil, "create-scratch", scratch, "fixture")
	if err != nil {
		t.Fatal(err)
	}
	writeProofEvidenceFile(t, scratch, "unclassified.txt", []byte(proofSecretCanary))
	writeProofEvidenceFile(t, host, "unclassified.txt", []byte(proofAPIKeyCanary))
	shell := `source "$PROOF_SCRIPT"
SUPPORTED_LOCAL_HOST_BOOTSTRAP_DIR="$TEST_SCRATCH"
SUPPORTED_LOCAL_HOST_PROOF_DIR="$TEST_HOST"
HOST_BOOTSTRAP_IDENTITY="$TEST_IDENTITY"
GUEST_COLLECTION_READY=false
trap finalize EXIT
exit 37`
	command := exec.Command("bash", "-c", shell)
	command.Dir = executionPlatformRepoRoot(t)
	command.Env = append(os.Environ(), "PROOF_SCRIPT="+filepath.Join(executionPlatformRepoRoot(t), "scripts", "73_supported_local_proof.sh"),
		"TEST_SCRATCH="+scratch, "TEST_HOST="+host, "TEST_IDENTITY="+strings.TrimSpace(string(identityBytes)))
	output, err := command.CombinedOutput()
	var exitErr *exec.ExitError
	if !errors.As(err, &exitErr) || exitErr.ExitCode() != 37 {
		t.Fatalf("primary failure status changed: err=%v output=%q", err, output)
	}
	requireNoProofCanary(t, output)
	if _, err := os.Lstat(scratch); err != nil {
		t.Fatalf("unprovable bootstrap scratch was deleted: %v", err)
	}
	if _, err := os.Lstat(filepath.Join(host, "host-evidence-manifest.json")); !os.IsNotExist(err) {
		t.Fatal("unclassified host file was silently admitted to complete manifest")
	}
}

func TestSupportedLocalProofNestedPhaseFailureStopsInputPreparation(t *testing.T) {
	parent := t.TempDir()
	scratch := filepath.Join(parent, "bootstrap")
	host := filepath.Join(parent, "host-proof")
	if err := os.Mkdir(scratch, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(host, 0o700); err != nil {
		t.Fatal(err)
	}
	shell := `source "$PROOF_SCRIPT"
SUPPORTED_LOCAL_HOST_BOOTSTRAP_DIR="$TEST_SCRATCH"
SUPPORTED_LOCAL_HOST_PROOF_DIR="$TEST_HOST"
SUPPORTED_LOCAL_DIST_PAYLOAD="$TEST_SCRATCH/missing-payload.tar.gz"
run_phase input-preparation prepare_host_inputs`
	command := exec.Command("bash", "-c", shell)
	command.Dir = executionPlatformRepoRoot(t)
	command.Env = append(os.Environ(), "PROOF_SCRIPT="+filepath.Join(executionPlatformRepoRoot(t), "scripts", "73_supported_local_proof.sh"),
		"TEST_SCRATCH="+scratch, "TEST_HOST="+host)
	output, err := command.CombinedOutput()
	if err == nil {
		t.Fatal("nested package failure was treated as successful input preparation")
	}
	requireNoProofCanary(t, output)
	for _, phase := range []string{"package-identity", "input-preparation"} {
		data, err := os.ReadFile(filepath.Join(host, "phase-"+phase+".json"))
		if err != nil || !bytes.Contains(data, []byte(`"success":false`)) {
			t.Fatalf("nested phase failure was not projected: phase=%s err=%v", phase, err)
		}
	}
	if _, err := os.Lstat(filepath.Join(host, "payload")); !os.IsNotExist(err) {
		t.Fatal("transport payload entered host evidence after nested failure")
	}
}

type proofTarEntry struct {
	name string
	body []byte
	kind byte
	link string
}

func makeProofTarGz(t *testing.T, entries []proofTarEntry) []byte {
	t.Helper()
	var output bytes.Buffer
	gzipWriter := gzip.NewWriter(&output)
	archive := tar.NewWriter(gzipWriter)
	for _, entry := range entries {
		kind := entry.kind
		if kind == 0 {
			kind = tar.TypeReg
		}
		header := &tar.Header{Name: entry.name, Mode: 0o600, Typeflag: kind, Linkname: entry.link}
		if kind == tar.TypeReg {
			header.Size = int64(len(entry.body))
		}
		if err := archive.WriteHeader(header); err != nil {
			t.Fatal(err)
		}
		if kind == tar.TypeReg {
			if _, err := archive.Write(entry.body); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := archive.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gzipWriter.Close(); err != nil {
		t.Fatal(err)
	}
	return output.Bytes()
}

func proofJSON(t *testing.T, value any) []byte {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func proofResultFixture(t *testing.T, variant string) []byte {
	t.Helper()
	prompt := strings.Repeat("a", 64)
	realization := "supported-local-proof-codex-shim/v1"
	mutation := ".codex-proof/normal-shell-proof.txt"
	report := map[string]any{
		"credential_material_bytes": 12, "credential_material_present": true,
		"credential_source": "workload_vault", "profile": "control-plane-normal-shell/v1",
		"prompt_sha256": prompt, "realization": realization, "status": "ok",
		"workspace_mutation": mutation,
	}
	if variant == "wrong realization" {
		report["realization"] = "unexpected"
	}
	finalMessage := fmt.Sprintf("ES control-plane normal-shell proof completed prompt_sha256=%s mutation=%s\n", prompt, mutation)
	workspace := []proofTarEntry{
		{name: ".codex-proof/", kind: tar.TypeDir},
		{name: "README.md", body: []byte("Execution Substrate CP normal-shell proof workspace\n")},
		{name: ".codex-proof/codex-proof-result.json", body: proofJSON(t, report)},
		{name: mutation, body: []byte("ES_CONTROL_PLANE_NORMAL_SHELL_PROOF\nprofile=control-plane-normal-shell/v1\nrealization=" + realization + "\nprompt_sha256=" + prompt + "\ncredential_material_present=true\n")},
		{name: "codex-final-message.txt", body: []byte(finalMessage)},
	}
	if variant == "canary in workspace" {
		workspace[1].body = []byte(proofSecretCanary)
	}
	if variant == "extra workspace member" {
		workspace = append(workspace, proofTarEntry{name: "secret.txt", body: []byte(proofSecretCanary)})
	}
	workspaceArchive := makeProofTarGz(t, workspace)
	summary := map[string]any{
		"status": "ok", "profile": "control-plane-normal-shell/v1", "python": "Python 3.12.3",
		"git": "git version 2.43.0", "shell": "GNU bash, version 5.2.21(1)-release",
		"codex_cli":         "codex-proof-shim supported-local-proof-codex-shim/v1",
		"credential_source": "workload_vault", "credential_secret_path": "proof-secrets/data/codex-runtime-profile",
		"credential_secret_field": "api_key", "credential_material_bytes": 12,
		"codex":       report,
		"proof_claim": "supported-local CP remote normal-shell runtime contract without upstream Codex service",
	}
	if variant == "wrong status" {
		summary["status"] = "failed"
	}
	prettyReport, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	diffBodies := map[string]string{
		".codex-proof/codex-proof-result.json": string(prettyReport) + "\n",
		mutation:                               string(workspace[3].body),
		"codex-final-message.txt":              finalMessage,
	}
	var diffBuilder strings.Builder
	for _, name := range []string{".codex-proof/codex-proof-result.json", mutation, "codex-final-message.txt"} {
		lines := strings.Split(strings.TrimSuffix(diffBodies[name], "\n"), "\n")
		hunk := fmt.Sprintf("@@ -0,0 +1,%d @@", len(lines))
		if len(lines) == 1 {
			hunk = "@@ -0,0 +1 @@"
		}
		fmt.Fprintf(&diffBuilder, "diff --git a/%s b/%s\nnew file mode 100644\nindex 0000000..abcdef0\n--- /dev/null\n+++ b/%s\n%s\n", name, name, name, hunk)
		for _, line := range lines {
			fmt.Fprintf(&diffBuilder, "+%s\n", line)
		}
	}
	diff := diffBuilder.String()
	if variant == "wrong mutation marker" {
		diff = "diff --git a/.codex-proof/normal-shell-proof.txt b/.codex-proof/normal-shell-proof.txt\n+unexpected\n"
	}
	if variant == "canary in diff" {
		diff += "+" + proofRootTokenCanary + "\n"
	}
	if variant == "canary in removed diff line" {
		diff += "-" + proofSecretCanary + "\n"
	}
	if variant == "canary in diff context" {
		diff += " " + proofAPIKeyCanary + "\n"
	}
	stdout := "CODEX-PROOF-SHIM-START\n" + string(proofJSON(t, report)) + "\n" + finalMessage
	stderr := "codex-proof-shim: credential material acquired from workload_vault\n" +
		"codex-proof-shim: workspace mutated at .codex-proof/normal-shell-proof.txt\n"
	if variant == "canary in stdout" {
		stdout += proofAPIKeyCanary
	}
	if variant == "canary in stderr" {
		stderr += proofSecretCanary
	}
	if variant == "wrong final marker" {
		finalMessage = proofSecretCanary + "\n"
	}
	entries := []proofTarEntry{
		{name: "runtime-contract-proof.json", body: proofJSON(t, summary)},
		{name: "codex-stdout.txt", body: []byte(stdout)},
		{name: "codex-stderr.txt", body: []byte(stderr)},
		{name: "codex-final-message.txt", body: []byte(finalMessage)},
		{name: "workspace.diff", body: []byte(diff)},
		{name: "workspace.tar.gz", body: workspaceArchive},
	}
	switch variant {
	case "extra secret member":
		entries = append(entries, proofTarEntry{name: "secret.txt", body: []byte(proofSecretCanary)})
	case "symlink member":
		entries[2] = proofTarEntry{name: "codex-stderr.txt", kind: tar.TypeSymlink, link: "outside"}
	case "hardlink member":
		entries[2] = proofTarEntry{name: "codex-stderr.txt", kind: tar.TypeLink, link: "codex-stdout.txt"}
	case "special member":
		entries[2] = proofTarEntry{name: "codex-stderr.txt", kind: tar.TypeFifo}
	case "traversal member":
		entries[2].name = "../codex-stderr.txt"
	case "absolute member":
		entries[2].name = "/codex-stderr.txt"
	case "duplicate member":
		entries = append(entries, entries[1])
	case "oversized member":
		entries[2].body = bytes.Repeat([]byte("x"), (8<<20)+1)
	case "malformed proof JSON":
		entries[0].body = []byte("{")
	}
	result := makeProofTarGz(t, entries)
	if variant == "trailing gzip canary" {
		result = append(result, []byte(proofSecretCanary)...)
	}
	if variant == "second gzip member" {
		result = append(result, makeProofTarGz(t, []proofTarEntry{{name: "secret.txt", body: []byte(proofAPIKeyCanary)}})...)
	}
	return result
}

func TestSupportedLocalProofResultProjectionAdversarial(t *testing.T) {
	valid := proofResultFixture(t, "")
	root := t.TempDir()
	bundle := filepath.Join(root, "result.tar.gz")
	if err := os.WriteFile(bundle, valid, 0o600); err != nil {
		t.Fatal(err)
	}
	outputPath := filepath.Join(root, "control-plane-normal-shell-result-evidence.json")
	if output, err := runProofPython(t, "supported_local_proof_projection.py", nil, "result", bundle, outputPath); err != nil {
		t.Fatalf("valid exact proof bundle rejected: %v output=%q", err, output)
	}
	projected, err := os.ReadFile(outputPath)
	if err != nil {
		t.Fatal(err)
	}
	requireNoProofCanary(t, projected)
	var result struct {
		BundleSize int    `json:"bundle_size"`
		BundleSHA  string `json:"bundle_sha256"`
		Members    []struct {
			Path string `json:"path"`
		} `json:"members"`
		CredentialPresent bool `json:"credential_material_present"`
		CredentialBytes   int  `json:"credential_material_bytes"`
	}
	if err := json.Unmarshal(projected, &result); err != nil {
		t.Fatal(err)
	}
	hash := sha256.Sum256(valid)
	if result.BundleSize != len(valid) || result.BundleSHA != hex.EncodeToString(hash[:]) || len(result.Members) != 6 || !result.CredentialPresent || result.CredentialBytes != 12 {
		t.Fatalf("fixed result evidence mismatch: %+v", result)
	}
	guest := t.TempDir()
	writeProofEvidenceFile(t, guest, "control-plane-normal-shell-result-evidence.json", projected)
	writeProofEvidenceFile(t, guest, "control-plane-normal-shell-result.tar.gz", valid)
	archive, stderrText, err := runProofEvidenceCollector(t, guest)
	if err != nil {
		t.Fatalf("collect projected result: %v stderr=%q", err, stderrText)
	}
	files, _ := readProofEvidenceArchive(t, archive)
	if _, exists := files["control-plane-normal-shell-result-evidence.json"]; !exists {
		t.Fatal("result projection missing from safe collection")
	}
	if _, exists := files["control-plane-normal-shell-result.tar.gz"]; exists || bytes.Contains(archive, valid) {
		t.Fatal("raw result bundle entered host evidence archive")
	}
	for _, variant := range []string{"extra secret member", "symlink member", "hardlink member", "special member",
		"traversal member", "absolute member", "duplicate member", "oversized member", "canary in stdout",
		"canary in stderr", "canary in workspace", "canary in diff", "canary in removed diff line",
		"canary in diff context", "trailing gzip canary", "second gzip member", "extra workspace member",
		"malformed proof JSON", "wrong realization",
		"wrong status", "wrong mutation marker", "wrong final marker"} {
		t.Run(variant, func(t *testing.T) {
			parent := t.TempDir()
			input := filepath.Join(parent, "result.tar.gz")
			if err := os.WriteFile(input, proofResultFixture(t, variant), 0o600); err != nil {
				t.Fatal(err)
			}
			projection := filepath.Join(parent, "control-plane-normal-shell-result-evidence.json")
			output, err := runProofPython(t, "supported_local_proof_projection.py", nil, "result", input, projection)
			if err == nil || bytes.Contains(output, []byte(proofRootTokenCanary)) || bytes.Contains(output, []byte(proofSecretCanary)) || bytes.Contains(output, []byte(proofAPIKeyCanary)) {
				t.Fatalf("unsafe bundle variant was accepted or leaked canary: variant=%s err=%v", variant, err)
			}
			if _, err := os.Lstat(projection); !os.IsNotExist(err) {
				t.Fatal("failed result projection left output file")
			}
		})
	}
}
