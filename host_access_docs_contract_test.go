package executionsubstrate_test

import (
	"strings"
	"testing"
)

func TestRemoteAlphaAccessContract(t *testing.T) {
	plans := compactText(mustRead(t, "PLANS.md"))
	remoteAlpha := compactText(mustRead(t, ".docs/system_overview/remote_supported_host_alpha.md"))
	contractRaw := mustRead(t, ".docs/system_overview/remote_alpha_access_contract.md")
	contract := compactText(contractRaw)

	require := func(t *testing.T, label, text string, phrases ...string) {
		t.Helper()
		plain := strings.ReplaceAll(text, "`", "")
		for _, phrase := range phrases {
			if !strings.Contains(plain, strings.ReplaceAll(compactText(phrase), "`", "")) {
				t.Errorf("%s missing contract phrase %q", label, phrase)
			}
		}
	}

	t.Run("governing scope", func(t *testing.T) {
		require(t, "PLANS.md", plans,
			"Reopened redesign seam",
			"ES has no implemented Remote Alpha access-profile validator, access-status schema, or fixed identity-only access route",
			"es.remote-alpha.access-profile/v1",
			"es.remote-alpha.access-status/v1",
			"scheduled_execution_allowed=false",
			"as a producer-owned v1 constant",
			"host_to_remote_linux_m75q",
			"Temporary compatibility edge",
			"--ssh-target",
			"Access evidence cannot repair the contained ES-to-EGS TLS certificate-validity failure",
		)
		require(t, "Remote Alpha design", remoteAlpha,
			".docs/system_overview/remote_alpha_access_contract.md",
			"No validator, access-status emitter, fixed identity-only route",
			"reopened Tranche B implementation-contract decisions",
			"P0t",
			"P0v",
			"scheduled_execution_allowed=false",
			"Neither is an access-status route or a general Remote Alpha deployment/management interface",
		)
		require(t, "access contract", contract,
			"Tranche A does not implement a profile validator, access-status emitter, live route",
			"The exact static SSH parser and filesystem acceptance boundary are reopened Tranche B implementation-contract decisions",
			"P0t is not a write-free access check",
			"P0v",
			"ssh -F /dev/null",
		)
	})

	t.Run("profile and role separation", func(t *testing.T) {
		require(t, "access profile", contract,
			"es.remote-alpha.access-profile/v1",
			"profile_id",
			"operator",
			"monitor",
			"ssh_config_ref",
			"ssh_alias",
			"expected_account",
			"expected_uid",
			"host_identity_label",
			"configuration_generation",
			"scheduled_use_policy",
			"known_hosts_ref",
			"a dedicated reference is required for monitor",
			"host_to_remote_linux_m75q",
			"Key generation, host-key pinning, remote authorized_keys restrictions",
			"future sensitive effects",
			"implementation detail, not an immutable public protocol",
		)
		profile := compactText(accessContractSection(t, contractRaw, "## 2. Versioned profile and ownership"))
		require(t, "generation grammar", profile,
			"configuration_generation has type string and length 1 through 64 ASCII characters",
			"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$",
			"beginning with an alphanumeric character",
			"no whitespace, path separator, or shell metacharacter",
			"must not contain endpoint material, usernames, filenames, or credential material",
			"must not be derived from or equal to a private-key digest, host-key digest, endpoint, raw path, configuration content",
			"not signer identity, key identity, host identity, or freshness evidence",
			"reject an invalid or unprovably non-sensitive label as profile_invalid before emitting status evidence",
			"must never echo the rejected value",
		)
	})

	t.Run("contact-free fail-closed validation", func(t *testing.T) {
		static := compactText(accessContractSection(t, contractRaw, "## 3. Contact-free static validation target"))
		require(t, "validation", static,
			"supported static SSH configuration subset",
			"owner, regular-file type, restrictive mode, path confinement, and symlink posture",
			"one exact, unambiguous alias binding and one unambiguous identity selection",
			"deterministic existing-host-key binding",
			"BatchMode=yes",
			"StrictHostKeyChecking=yes",
			"UpdateHostKeys=no",
			"public-key-only authentication",
			"disabled password and keyboard-interactive fallback",
			"no agent/X11/local/ remote/dynamic forwarding",
			"no ControlMaster multiplexing",
			"must ultimately fail closed",
			"Match exec",
			"ProxyCommand",
			"LocalCommand",
			"KnownHostsCommand",
			"ProxyJump",
			"ambient monitor-agent dependence",
			"implicit SSH-certificate lifecycle",
			"configuration cannot weaken",
			"do not branch on OS labels or silently fall back",
			"exact supported OpenSSH directive grammar",
			"Include closure, ordering, and precedence",
			"effective interaction with system SSH configuration",
			"accepted operator-local filesystem roots",
			"exact file and directory modes",
			"component-by-component symlink policy",
			"Apple Keychain, agent, certificate, and platform-specific interpretation",
			"otherwise safe optional SSH directives",
			"Tranche B must freeze each decision in governing documentation and fake/static contract tests before implementing a validator",
			"no repository behavior may claim that a local profile conforms to the full v1 static subset",
			"present operator alias remains a compatibility edge and is not silently declared v1-conformant",
		)
	})

	t.Run("fixed check and compatibility", func(t *testing.T) {
		require(t, "live check", contract,
			"--access-profile <profile_id>",
			"no arbitrary --ssh-config escape hatch",
			"sole remote observations are fixed effective UID and account checks",
			"reject UID zero",
			"no sudo, TTY, remote write, service operation, TLS probe, or renewal",
			"retain no raw SSH stdout/stderr",
			"Current --ssh-target routes keep their existing bounded behavior as a temporary compatibility edge",
		)
	})

	t.Run("normative state matrix", func(t *testing.T) {
		status := compactText(accessContractSection(t, contractRaw, "## 5. Access-status evidence contract"))
		require(t, "status semantics", status,
			"es.remote-alpha.access-status/v1",
			"unavailable means a reviewed, bounded signal proved a specific blocking condition",
			"unknown means access readiness cannot be established",
			"reason field is always present: its exact JSON value is null for ready",
			"evidence_source exactly local_validation or live_check",
			"implementation/source revision",
			"UTC observation time",
			"bounded numeric command status",
			"freshness window or computed age",
			"Safe output must never include an endpoint, resolved IP or hostname, identity path/content/digest, host-key value/fingerprint, agent identity, raw SSH stdout/stderr, raw SSH config, credential, or command transcript containing sensitive values",
		)

		matrix := accessContractSection(t, contractRaw, "### Normative state matrix")
		rows := parseAccessContractMatrix(t, matrix)
		type expectedCells struct {
			evidence string
			nonClaim string
		}
		expected := map[string]expectedCells{
			"producer|local_validation|unavailable|profile_invalid":                 {"schema, field, or local-resource validation failure", "No live access was checked"},
			"producer|local_validation|unavailable|unsupported_dynamic_config":      {"unsupported, executable, dynamic, or ambiguous configuration", "No alternate parser or fallback"},
			"producer|local_validation|unknown|live_check_not_performed":            {"Contact-free validation passed", "not live readiness"},
			"producer|local_validation|unknown|configuration_changed":               {"Before/after observation found a change", "No ready evidence"},
			"producer|local_validation|unknown|unclassified":                        {"could not prove a more specific permitted reason", "No precise cause"},
			"producer|live_check|ready|null":                                        {"Static validation passed for the same profile and generation", "Ready does not permit scheduling"},
			"producer|live_check|unavailable|host_identity_unverified":              {"existing-host-key verification failure", "No physical host identity"},
			"producer|live_check|unavailable|authentication_unavailable":            {"public-key authentication failure", "No signer identity or custody"},
			"producer|live_check|unavailable|transport_unavailable":                 {"transport failure", "No service or TLS state"},
			"producer|live_check|unavailable|remote_identity_mismatch":              {"nonzero UID or account that differs", "No arbitrary remote-shell authority"},
			"producer|live_check|unavailable|root_login_blocked":                    {"effective UID 0; the check stopped immediately", "Root login is neither authorized nor normalized"},
			"producer|live_check|unavailable|check_failed":                          {"fixed UID/account check after transport and authentication", "No repair or retry fallback"},
			"producer|live_check|unknown|configuration_changed":                     {"Before/after observation found a change", "No ready evidence"},
			"producer|live_check|unknown|unclassified":                              {"No bounded signal proves a more specific permitted reason", "Raw SSH diagnostics"},
			"consumer|local_validation or live_check|unknown|stale_evidence":        {"Evidence age exceeds the versioned freshness window", "A prior ready result is not preserved"},
			"consumer|local_validation or live_check|unknown|configuration_changed": {"profile ID or generation differs from the current selected profile", "A prior ready result is not preserved"},
		}
		if len(rows) != len(expected) {
			t.Fatalf("state matrix has %d rows, want %d", len(rows), len(expected))
		}
		for key, want := range expected {
			row, ok := rows[key]
			if !ok {
				t.Errorf("state matrix missing %s", key)
				continue
			}
			if !strings.Contains(row.evidence, want.evidence) {
				t.Errorf("state matrix %s lacks required evidence %q", key, want.evidence)
			}
			if !strings.Contains(row.nonClaim, want.nonClaim) {
				t.Errorf("state matrix %s lacks non-claim %q", key, want.nonClaim)
			}
		}
		for key, row := range rows {
			if _, ok := expected[key]; !ok {
				t.Errorf("state matrix has unapproved row %s", key)
			}
			if row.source == "local_validation" && row.outcome == "ready" {
				t.Errorf("local validation must not be ready: %s", key)
			}
			if row.outcome == "ready" && (row.evaluation != "producer" || row.source != "live_check" || row.reason != "null") {
				t.Errorf("ready has invalid source or reason: %s", key)
			}
			if row.outcome != "ready" && row.reason == "null" {
				t.Errorf("non-ready row lacks reason: %s", key)
			}
		}
		ready := rows["producer|live_check|ready|null"]
		for _, proof := range []string{"strict existing-host-key verification succeeded", "effective UID matched the expected nonroot values", "UID was nonzero", "evidence is fresh", "no configuration change was observed"} {
			if !strings.Contains(ready.evidence, proof) {
				t.Errorf("ready row lacks proof %q", proof)
			}
		}
		require(t, "state consistency", status,
			"local_validation producer must never emit ready",
			"successful static validation yields unknown / live_check_not_performed",
			"producer must establish a before/after consistency observation for that profile and every local resource",
			"producer must emit unknown / configuration_changed, never ready",
			"generation label is not proof that local files stayed unchanged",
			"mismatch produces effective unknown / configuration_changed",
			"expiry produces effective unknown / stale_evidence",
			"configuration_changed takes precedence",
			"consumer may not promote local_validation evidence to ready",
		)
	})

	t.Run("v1 scheduling gate", func(t *testing.T) {
		gate := compactText(accessContractSection(t, contractRaw, "### V1 scheduling gate"))
		require(t, "v1 scheduling gate", gate,
			"scheduled_execution_allowed=false is a producer-owned constant in every v1 status, including ready",
			"not supplied or overridden by the local profile, inferred from ready, enabled by MA configuration or IM readiness",
			"successful foreground SSH or the current operator alias",
			"local scheduled_use_policy value cannot turn it on",
			"a versioned contract change",
			"separate implementation, host provisioning, validation, and audit",
			"ready never implies scheduled execution permission",
		)
		if strings.Contains(contractRaw, "scheduled_execution_allowed=true") {
			t.Error("v1 contract contains a scheduled-execution true claim")
		}
	})

	t.Run("non-authority and future ownership", func(t *testing.T) {
		require(t, "boundaries", contract,
			"SSH signer identity/custody",
			"application or service readiness",
			"TLS correctness",
			"sudo readiness",
			"installed-state correctness",
			"ES execution readiness",
			"governed execution",
			"incident acceptance",
			"repair authority",
			"MA may later consume and notify over that evidence",
			"owns no SSH credential generation/custody, raw SSH diagnostic interpretation, arbitrary remote shell, sudo password, or ES route semantics",
			"IM currently owns Remote Alpha profile, doctor, readiness, provenance, and diagnostic outputs",
			"Public-key SSH does not solve sudo authentication",
			"NOPASSWD: ALL",
			"passwordless sudo for a staged or user-writable helper",
			"widening fixed status into renewal or repair authority",
			"Access-status evidence does not inspect its TLS topology, repair certificates",
			"Tranche A edits neither repo",
		)
	})
}

type accessContractMatrixRow struct {
	evaluation string
	source     string
	outcome    string
	reason     string
	evidence   string
	nonClaim   string
}

func accessContractSection(t *testing.T, document, heading string) string {
	t.Helper()
	lines := strings.Split(strings.ReplaceAll(document, "\r\n", "\n"), "\n")
	start := -1
	for i, line := range lines {
		if line != heading {
			continue
		}
		if start >= 0 {
			t.Fatalf("duplicate contract heading %q", heading)
		}
		start = i
	}
	if start < 0 {
		t.Fatalf("missing contract heading %q", heading)
	}
	level := len(heading) - len(strings.TrimLeft(heading, "#"))
	end := len(lines)
	for i := start + 1; i < len(lines); i++ {
		line := lines[i]
		if !strings.HasPrefix(line, "#") {
			continue
		}
		lineLevel := len(line) - len(strings.TrimLeft(line, "#"))
		if lineLevel <= level && len(line) > lineLevel && line[lineLevel] == ' ' {
			end = i
			break
		}
	}
	return strings.Join(lines[start+1:end], "\n")
}

func parseAccessContractMatrix(t *testing.T, section string) map[string]accessContractMatrixRow {
	t.Helper()
	rows := make(map[string]accessContractMatrixRow)
	headerSeen := false
	separatorSeen := false
	for _, raw := range strings.Split(section, "\n") {
		line := strings.TrimSpace(raw)
		if !strings.HasPrefix(line, "|") {
			continue
		}
		if !strings.HasSuffix(line, "|") {
			t.Fatalf("unterminated state matrix row %q", line)
		}
		cells := strings.Split(line[1:len(line)-1], "|")
		if len(cells) != 6 {
			t.Fatalf("state matrix row has %d cells, want 6: %q", len(cells), line)
		}
		for i := range cells {
			cells[i] = strings.TrimSpace(strings.ReplaceAll(cells[i], "`", ""))
		}
		if !headerSeen {
			want := []string{"Evaluation", "Evidence source", "Outcome", "Reason", "Required evidence", "Explicit non-claim"}
			for i := range want {
				if cells[i] != want[i] {
					t.Fatalf("state matrix header cell %d is %q, want %q", i, cells[i], want[i])
				}
			}
			headerSeen = true
			continue
		}
		if !separatorSeen {
			for _, cell := range cells {
				if cell != "---" {
					t.Fatalf("state matrix separator is invalid: %q", line)
				}
			}
			separatorSeen = true
			continue
		}
		row := accessContractMatrixRow{
			evaluation: cells[0],
			source:     cells[1],
			outcome:    cells[2],
			reason:     cells[3],
			evidence:   cells[4],
			nonClaim:   cells[5],
		}
		if row.evidence == "" || row.nonClaim == "" {
			t.Fatalf("state matrix row lacks required evidence or non-claim: %q", line)
		}
		key := strings.Join(cells[:4], "|")
		if _, exists := rows[key]; exists {
			t.Fatalf("duplicate state matrix row %s", key)
		}
		rows[key] = row
	}
	if !headerSeen || !separatorSeen {
		t.Fatal("state matrix header or separator is missing")
	}
	return rows
}
