package executionsubstrate_test

import (
	"io/fs"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// D2 re-derives Workstream D: the owner signs a standing policy that ES
// applies, EGS signs publisher admissions behind the owner's switch, and CGS
// is retired. These tests pin the contract that the later build steps
// implement, the Workstream D status line and exit criteria in PLANS.md that
// say when the workstream may close, and the rule that a working name is
// settled with the owner before code uses it.

const policyGovernanceContractPath = ".docs/system_overview/policy_governance_contract.md"

func TestPolicyGovernanceContractIsDocumented(t *testing.T) {
	raw := mustRead(t, policyGovernanceContractPath)
	section := func(start string, end string) string {
		return compactDocSection(t, raw, start, end)
	}

	assertContainsAll(t, "D2 status and decisions", section("## 1. Purpose and status", "## 2. Names"),
		"The project owner decided this design. Nothing in it is built yet.",
		"Until the step that lands a part merges, the current pages describe current behavior for that part",
		"Each step moves the matching current-behavior text to the new rule in the same change.",
		"CGS is retired.",
		"ES is the only writer of numbered revocations.",
		"A switch in the signed policy decides whether ES also requires EGS's admission. The switch is off at migration.",
		"with a printed recovery key whose only power is replacing it.",
	)

	assertContainsAll(t, "D2 standing policy", section("## 4. The standing policy", "## 5. Publisher classes"),
		"The two verifier keys ES loads and never uses, `verification.derivation_attestation` and `verification.workload_identity_binding`, are removed.",
		"moved out of `es.json` with their fields and matching unchanged, each inside a closed class.",
		"The signature covers the exact bytes delivered. Those bytes state the format name and version, the installation ID, the revision, and the SHA-256 of the previous revision's bytes.",
		"Decoding is strict: an unknown, repeated or differently spelled key is refused.",
		"Each revision is exactly the previous revision plus one.",
		"ES stores the new revision number durably before it first uses the new policy",
		"It never passes through another service.",
		"ES reloads it without a restart and applies the newest valid revision at once.",
		"refuses a different pin unless a revision introduced it that is signed by the new everyday key and by either the old everyday key or the recovery key.",
		"After losing the everyday key, the owner replaces it with a revision signed by the recovery key and the new everyday key. The old everyday key is not needed.",
		"The recovery key may sign only a revision whose single change is replacing the everyday key.",
		"Replacing the recovery key is a revision signed by the everyday key and the new recovery key.",
	)

	assertContainsAll(t, "D2 classes and application", section("## 5. Publisher classes", "## 7. Revocations"),
		"The class follows from the identity; nobody picks it",
		"No network and no named identities",
		"Networked publishers stay in closed classes",
		"Publishers that relay others' content",
		"It checks revocations first, then finds the publisher's class",
		"This is the grant matching of section 5B with classes added, not a new kind of decision.",
		"ES starts without EGS.",
	)

	assertContainsAll(t, "D2 revocations and state", section("## 7. Revocations", "## 9. EGS v2: signed admissions behind the owner's switch"),
		"One writer: ES.",
		"a payload digest (so that publishing the same bytes again under a new intent digest does not escape it)",
		"The owner's key cannot be revoked this way, so nobody can lock the owner out.",
		"Lifting names revocation numbers, never subjects.",
		"Caller names that the identity tooling revokes are written to the policy log too, so that a re-setup restores them",
		"Any other spelling is refused, never normalized.",
		"ES refuses to start when its policy state is missing or empty, except through a deliberate first-install step that is loud and logged.",
		"No backup or restore tool includes the floor or the revocation log in its file list, and a repository test pins that.",
		"An older ES binary that cannot read the stored policy state refuses to start. It never starts empty.",
	)

	assertContainsAll(t, "D2 EGS v2", section("## 9. EGS v2: signed admissions behind the owner's switch", "## 10. The policy log and its off-box copy"),
		"EGS v2 is a new versioned contract.",
		"Only the operator and ES may call EGS; publishers never do.",
		"The list holds open-class admissions only: no grants, which stay in the standing policy, and no revocations, which ES owns.",
		"No value in `es.json`, `egs.json` or any other host file changes it.",
		"It cannot admit anyone the class rules do not already cover, because ES requires both.",
		"A list signed by a key the current policy no longer names is dropped, even as last good.",
		"An unreachable EGS is not that case.",
		"EGS's key is created inside Vault's transit engine, not exportable and not deletable. It is never a key that was ever in a file",
		"The root token is revoked after setup, and Vault's audit log is on.",
	)

	assertContainsAll(t, "D2 policy log", section("## 10. The policy log and its off-box copy", "## 11. Reliable submit"),
		"`prev` (the SHA-256 of the previous line's exact bytes; 64 zeros for the first)",
		"sshd's `ForceCommand`, with no shell, terminal or forwarding.",
		"The program answers three requests: `head`, `after N M` (up to 1,000 entries after entry N) and `entry N`.",
		"in pages of up to 1,000. Each page continues from the last entry it accepted, until a page reaches the head that page's header reports, or a per-run cap is reached",
		"that no page goes beyond the head its header reports, and that a page reaching that head ends at the head's hash.",
		"The host's answer is only ever parsed as data.",
		"After an alert it stops pulling and keeps the bad answer as evidence.",
		"The workstation opens every connection.",
		"It does not prove that an entry was true when it was written",
	)

	assertContainsAll(t, "D2 reliable submit, evidence and recovery", section("## 11. Reliable submit", "## 14. What a compromised component can do"),
		"the reliable-submit admission digest covers only what a claim depends on",
		"The 30-second confirmation with EGS is dropped.",
		"The commissioning gate keeps both prerequisites listed until the integration step records them answered.",
		"AGS records the caller certificate's key hash and issuer in the evidence.",
		"ES accepts evidence with or without the new fields until every live artifact carries them.",
		"ES must be recoverable from a lost Vault unseal key and from a full re-setup.",
		"A test fails if a generated value equals a value in the repository.",
		"The unseal key stays in the owner's password manager only.",
		"`rehearsal-due` is raised once the last rehearsal is older than that.",
	)

	assertContainsAll(t, "D2 triggers, tests and delivery", section("## 15. Machine triggers", "## 18. What this contract does not change"),
		"needs a design and a red-team first.",
		"A repository test fails while section 2 marks a name as a working name and that name appears in Go code or scripts outside tests.",
		"Each test must fail on a version without the rule it covers.",
		"| 11 | AGS's signing key into Vault's transit engine, before step 10 |",
		"| 12 | Recovery (section 13), before step 10 |",
		"and Workstream D closed in `PLANS.md` in the same change, once its exit criteria hold |",
	)
}

var (
	workstreamDStatusLine = regexp.MustCompile(`(?m)^Workstream D status: (open|closed)\.$`)
	workstreamDCriterion  = regexp.MustCompile(`(?m)^- \[( |x)\] `)
)

func TestWorkstreamDStatusAndExitCriteria(t *testing.T) {
	plans := markedDocSection(t, "PLANS.md Workstream D", mustRead(t, "PLANS.md"), "### Workstream D - Policy And Authorization Reset", "### Workstream E - Lookup And Config Indirection Reset")

	assertContainsAll(t, "PLANS.md Workstream D pointer", compactText(plans),
		"D2 re-derives this workstream, as the project owner decided: CGS is retired, the owner signs a standing policy that ES applies, and EGS signs publisher admissions that ES requires only while the owner's signed switch is on.",
		"[`.docs/system_overview/policy_governance_contract.md`](.docs/system_overview/policy_governance_contract.md)",
	)

	statuses := workstreamDStatusLine.FindAllStringSubmatch(plans, -1)
	if len(statuses) != 1 {
		t.Fatalf("PLANS.md Workstream D must hold exactly one line \"Workstream D status: open.\" or \"Workstream D status: closed.\", found %d", len(statuses))
	}
	criteria := workstreamDCriterion.FindAllStringSubmatch(plans, -1)
	open := 0
	for _, criterion := range criteria {
		if criterion[1] == " " {
			open++
		}
	}
	switch statuses[0][1] {
	case "open":
		if open == 0 {
			t.Fatal("PLANS.md says Workstream D is open, but every exit criterion is ticked: close it in the change that rewrites README.md (build step 13)")
		}
	case "closed":
		if open != 0 {
			t.Fatalf("PLANS.md says Workstream D is closed, but %d exit criteria are not ticked", open)
		}
	}

	// The exit criteria name every gap the D2 review left open, so that the
	// repository, not a note outside it, says when Workstream D may close.
	required := []string{
		"CGS is retired [1].",
		"Revoking an artifact or a signer has a runbook, run once on the supported host.",
		"Cutting off one named workload passed WI-3's tests (`.docs/system_overview/runtime_identity_handoff.md`, section 11.7).",
		"Recovery from a lost Vault unseal key and from a full re-setup is built [12], and each CI rehearsal passed once.",
		"AGS's signing key is in Vault's transit engine [11].",
		"The owner's rules are signed and applied by ES, and no host file changes them [2, 4, 6, 7, 10].",
		"An older validly signed policy or EGS list cannot be confirmed as current (`CP-ROLLBACK`) [2, 4, 8].",
		"ES starts without EGS, and service certificates renew automatically [4, 9].",
		"ES loads no unused verifier key [4, 10].",
		"The policy log is copied off the host every hour [5, 6].",
		"The supported host runs steps 1 to 12; the migration run's report is linked here.",
		"`README.md` and its diagram describe this design, rewritten in the change that closes Workstream D [13].",
	}
	if len(criteria) != len(required) {
		t.Fatalf("PLANS.md Workstream D has %d exit criteria, want %d: change this list and the contract together", len(criteria), len(required))
	}
	compactPlans := compactText(plans)
	for _, criterion := range required {
		if !strings.Contains(compactPlans, criterion) {
			t.Errorf("PLANS.md Workstream D exit criteria lack %q", criterion)
		}
	}

	record := workstreamRecord(t, "D")
	assertContainsAll(t, "Workstream D record points to D2", record,
		"D2 supersedes the limits below that keep a future EGS contract to signer and artifact trust (D1b and D1c): EGS v2 signs publisher admissions under the owner's standing policy, as a new versioned contract.",
		"D2 retires CGS, so the future CGS v2 authorize contract that D1b describes is not built.",
		"The EGS v1 and CGS v1 surfaces below stay current behavior until D2's build steps 7 and 1 remove them.",
	)
}

// policyGovernanceWorkingNames maps each row of section 2 of the contract to
// the spellings code would use for it. While a row is there, the name is a
// working name and no Go code, script or configuration outside tests may use
// any of its spellings.
var policyGovernanceWorkingNames = map[string][]string{
	"standing policy":                  {"standing_policy", "StandingPolicy", "standingPolicy", "standing-policy"},
	"open class, closed class":         {"open_class", "closed_class", "OpenClass", "ClosedClass", "openClass", "closedClass"},
	"admission list":                   {"admission_list", "AdmissionList", "admissionList", "admission-list"},
	"`use_egs`":                        {"use_egs", "UseEGS", "useEGS"},
	"`es-owner`":                       {"es-owner"},
	"`es-log-reader`":                  {"es-log-reader", "es_log_reader"},
	"`es-policy-log-export/v1`":        {"es-policy-log-export", "es_policy_log_export"},
	"log anchor":                       {"log_anchor", "LogAnchor", "logAnchor", "log-anchor"},
	"`es-recover-vault`, `es-resetup`": {"es-recover-vault", "es_recover_vault", "es-resetup", "es_resetup"},
	"`rehearsal-due`":                  {"rehearsal-due", "rehearsal_due"},
}

var policyGovernanceScannedExtensions = map[string]bool{
	".go": true, ".sh": true, ".py": true, ".json": true, ".hcl": true,
	".yml": true, ".yaml": true, ".service": true, ".timer": true, ".plist": true,
	".toml": true, ".conf": true, ".tmpl": true,
}

func TestPolicyGovernanceWorkingNamesStayOutOfCode(t *testing.T) {
	names := markedDocSection(t, "D2 names", mustRead(t, policyGovernanceContractPath), "## 2. Names", "## 3. Who vouches for what")
	rows := map[string]bool{}
	for _, line := range strings.Split(names, "\n") {
		if !strings.HasPrefix(line, "| ") || strings.HasPrefix(line, "| Working name") || strings.HasPrefix(line, "| ---") {
			continue
		}
		cells := strings.Split(line, " | ")
		rows[strings.TrimPrefix(cells[0], "| ")] = true
	}
	if len(rows) > 0 && !strings.Contains(compactText(names), "The names below are working names.") {
		t.Fatal("section 2 of the D2 contract lists names but no longer says they are working names")
	}
	for row := range rows {
		if _, ok := policyGovernanceWorkingNames[row]; !ok {
			t.Errorf("section 2 of the D2 contract lists the working name %s: add its code spellings to policyGovernanceWorkingNames", row)
		}
	}
	for row := range policyGovernanceWorkingNames {
		if !rows[row] {
			t.Errorf("policyGovernanceWorkingNames lists %s, which section 2 of the D2 contract no longer lists: remove it here too", row)
		}
	}

	err := filepath.WalkDir(".", func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			switch entry.Name() {
			case ".git", ".docs", "testdata", "node_modules":
				return filepath.SkipDir
			}
			return nil
		}
		if strings.HasSuffix(path, "_test.go") || !policyGovernanceScannedExtensions[filepath.Ext(path)] {
			return nil
		}
		data := mustRead(t, path)
		for row := range rows {
			for _, spelling := range policyGovernanceWorkingNames[row] {
				if strings.Contains(data, spelling) {
					t.Errorf("%s uses %q, but %s is still a working name in section 2 of the D2 contract: settle the name with the owner first, then remove its row there and its entry in policyGovernanceWorkingNames, and update section 1's status in the same change", filepath.ToSlash(path), spelling, row)
				}
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk repository: %v", err)
	}
}
