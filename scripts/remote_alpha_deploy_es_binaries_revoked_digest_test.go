package scripts_test

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"execution-substrate/internal/testutil"
)

// TestRemoteAlphaESBinaryDeploymentStopsOnARevokedDigestTheNewESRefuses
// guards the Remote Alpha box's path to a later ES against one way of
// leaving ES down.
//
// The ES binary deployment (scripts/internal/remote_alpha_deploy_es_binaries.sh)
// installs es and es-runtime-support and restarts ES. It leaves EGS as it
// is. ES refuses a trust model whose revoked digests are not `sha256:` and
// 64 lower-case hex characters, even one that an older EGS accepted and
// serves, and it refuses it when it starts. The deployment has no automatic
// rollback, so ES would stay down until someone put the old binaries back.
//
// What stops this before anything is installed is the deployment's
// egsconfigcheck. It is EGS's own config.Load, built from the same tree as
// the ES it installs, and the deployment runs it on egs.json. EGS refuses
// that spelling for the same reason ES does. This test runs the deployment
// with the real check, built from this tree, in check-only and in apply
// mode. It fails if:
//   - the deployment stopped running the check;
//   - the deployment ran the check after installing anything;
//   - the deployment ran a payload without the check;
//   - the check stopped refusing that spelling;
//   - EGS's config.Load stopped refusing that spelling.
//
// A lower-case digest passes the same check, so the refusal comes from the
// spelling and from nothing else in the config.
func TestRemoteAlphaESBinaryDeploymentStopsOnARevokedDigestTheNewESRefuses(t *testing.T) {
	t.Parallel()
	egsConfigCheck, err := os.ReadFile(buildConfigCheck(t, "egsconfigcheck"))
	if err != nil {
		t.Fatal(err)
	}
	var example map[string]any
	if err := json.Unmarshal([]byte(testutil.Read(t, ".examples/config/egs.json")), &example); err != nil {
		t.Fatal(err)
	}
	example, err = jsonRoundTrip(testutil.WithFreshSigningKeys(t, example))
	if err != nil {
		t.Fatal(err)
	}
	egsJSON := func(t *testing.T, revoked []string) []byte {
		t.Helper()
		doc, err := jsonRoundTrip(example)
		if err != nil {
			t.Fatal(err)
		}
		doc["runtime_trust"].(map[string]any)["artifact_policy"].(map[string]any)["revoked_artifacts"] = revoked
		out, err := json.MarshalIndent(doc, "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		return out
	}

	hexDigits := strings.Repeat("0123456789abcdef", 4)
	lower := "sha256:" + hexDigits
	upper := "sha256:" + strings.ToUpper(hexDigits)
	otherLower := "sha256:" + strings.Repeat("ab", 32)
	oneUpperDigit := lower[:len(lower)-1] + "F"
	refusal := func(entry string) string {
		return "/config/egs.json, so nothing is installed: egs config refused: " +
			"runtime_trust.artifact_policy.revoked_artifacts must contain labeled sha256 digests in lower-case hex " +
			"(sha256: and 64 lower-case hex characters); got " + fmt.Sprintf("%q", entry)
	}

	cases := []struct {
		name       string
		revoked    []string
		noEGSCheck bool
		// scope and want name the blocker both modes must report; an empty
		// scope means check-only passes with the EGS check's own pass.
		scope string
		want  string
	}{
		{name: "a lower-case digest", revoked: []string{lower}},
		{name: "upper-case hex", revoked: []string{upper}, scope: "egs_config_check", want: refusal(upper)},
		{name: "one upper-case hex digit after a lower-case digest", revoked: []string{otherLower, oneUpperDigit},
			scope: "egs_config_check", want: refusal(oneUpperDigit)},
		{name: "upper-case hex, and the payload has no egsconfigcheck", revoked: []string{upper}, noEGSCheck: true,
			scope: "local_payload", want: "staged payload config checks are missing from the sealed helper payload directory: egsconfigcheck"},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			modes := []string{"check-only", "apply"}
			if tc.scope == "" {
				modes = modes[:1]
			}
			for _, mode := range modes {
				tmpDir := t.TempDir()
				fakeBin := filepath.Join(tmpDir, "bin")
				if err := os.MkdirAll(fakeBin, 0o755); err != nil {
					t.Fatal(err)
				}
				fixture := setupESBinaryDeploymentFixture(t, tmpDir)
				setupFakeESBinaryDeploymentCommands(t, fakeBin, fixture)
				// The real EGS config check in place of the fixture's fake,
				// on a real egs.json next to es.json.
				checkPath := filepath.Join(fixture.PayloadDir, "egsconfigcheck")
				if err := os.Remove(checkPath); err != nil {
					t.Fatal(err)
				}
				if !tc.noEGSCheck {
					if err := os.WriteFile(checkPath, egsConfigCheck, 0o755); err != nil {
						t.Fatal(err)
					}
				}
				egsPath := filepath.Join(filepath.Dir(fixture.ConfigPath), "egs.json")
				if err := os.WriteFile(egsPath, egsJSON(t, tc.revoked), 0o600); err != nil {
					t.Fatal(err)
				}

				summaryPath := filepath.Join(tmpDir, "summary.json")
				args := fmt.Sprintf("--summary-path %q", summaryPath)
				if mode == "apply" {
					args = "--apply " + args
				}
				output, runErr := runSourcedESBinaryDeploymentHelper(t, envWithPath(fakeBin,
					"REMOTE_ALPHA_TEST_MUTATION_LOG_PATH="+fixture.MutationLogPath,
					"REMOTE_ALPHA_TEST_BACKUP_ROOT="+filepath.Join(tmpDir, "backup-root"),
				), esBinaryDeploymentExpectedSliceShell(fixture)+"remote_alpha_deploy_es_binaries_main "+args+"\n")
				report := output
				if mode == "apply" {
					if report, err = os.ReadFile(summaryPath); err != nil {
						t.Fatalf("apply wrote no summary: %v\n%s", err, output)
					}
				}
				payload := parseESBinaryDeploymentOutput(t, report)

				if tc.scope == "" {
					egs := nestedMap(t, nestedMap(t, nestedMap(t, payload, "validation"), "config_checks"), "egs")
					if runErr != nil || egs["classification"] != "pass" || egs["config_path"] != egsPath ||
						egs["summary"] != "the new egs accepts "+egsPath {
						t.Fatalf("check-only with %v: %v, EGS check %v, blockers %v\n%s", tc.revoked, runErr, egs, payload["blockers"], output)
					}
					continue
				}

				if runErr == nil {
					t.Fatalf("%s passed with %v in egs.json:\n%s", mode, tc.revoked, output)
				}
				found := false
				for _, raw := range payload["blockers"].([]any) {
					blocker := raw.(map[string]any)
					summary := strings.Replace(fmt.Sprint(blocker["summary"]), tmpDir, "", 1)
					if blocker["scope"] == tc.scope && strings.Contains(summary, tc.want) {
						found = true
					}
				}
				if !found {
					t.Fatalf("%s: no %s blocker saying %q in %v", mode, tc.scope, tc.want, payload["blockers"])
				}
				if tc.scope == "egs_config_check" {
					egs := nestedMap(t, nestedMap(t, nestedMap(t, payload, "validation"), "config_checks"), "egs")
					if egs["classification"] != "blocker" || egs["exit_status"] != float64(1) || egs["config_path"] != egsPath {
						t.Fatalf("%s: EGS check %v", mode, egs)
					}
				}
				if live, _ := os.ReadFile(fixture.LiveESBinaryPath); string(live) != "old es live binary\n" {
					t.Fatalf("%s installed the es binary: %q", mode, live)
				}
				if live, _ := os.ReadFile(fixture.LiveRuntimePath); string(live) != "old runtime live binary\n" {
					t.Fatalf("%s installed the runtime support binary: %q", mode, live)
				}
				if _, err := os.Stat(fixture.MutationLogPath); !os.IsNotExist(err) {
					t.Fatalf("%s restarted the service: %s", mode, readIfExists(fixture.MutationLogPath))
				}
				if backups, _ := filepath.Glob(filepath.Join(tmpDir, "backup-root", "es-binary-deployment-*")); len(backups) != 0 {
					t.Fatalf("%s made a backup: %v", mode, backups)
				}
			}
		})
	}
}

// jsonRoundTrip returns a deep copy of a JSON object.
func jsonRoundTrip(doc map[string]any) (map[string]any, error) {
	data, err := json.Marshal(doc)
	if err != nil {
		return nil, err
	}
	var out map[string]any
	if err := json.Unmarshal(data, &out); err != nil {
		return nil, err
	}
	return out, nil
}
