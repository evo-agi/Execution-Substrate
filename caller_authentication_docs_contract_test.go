package executionsubstrate_test

import "testing"

// The caller authentication contract is written once, in
// .docs/system_overview/contracts.md section 3A, and the service and
// lifecycle contracts refer to it.
func TestCallerAuthenticationContractIsDocumentedOnce(t *testing.T) {
	contractsRaw := mustRead(t, ".docs/system_overview/contracts.md")
	section := compactDocSection(t, contractsRaw, "## 3A. Caller Authentication Contract", "## 4. Workload-Zone Vault Runtime-Config Contract")
	assertContainsAll(t, "caller authentication contract", section,
		"ARS, AGS, EGS, CGS, and ES authenticate the caller of every route that checks a caller with the one shared package `internal/callerauth`.",
		"The verified chain must still be within its validity period at the time of each request, not only at the TLS handshake.",
		"A request has a caller identity only if at least one verified chain that starts with the leaf has every certificate between its `notBefore` and `notAfter` at the time the request is authenticated.",
		"The leaf must be an end-entity certificate. A leaf whose basic constraints mark it as a CA, or whose key usage includes `keyCertSign` or `cRLSign`, has no caller identity",
		"The leaf must carry exactly one URI SAN.",
		"A certificate with more than one URI SAN is refused even when one of them would be acceptable",
		"That URI must be a SPIFFE ID in the trust domain `execution.internal`",
		"every segment is one or more of `A-Z`, `a-z`, `0-9`, `.`, `-`, and `_` and is not `.` or `..`.",
		"Identity failures return `401` before the bootstrap-issuer rule runs.",
		"`401` plain text `Authenticated caller identity required`",
		"`403` plain text `Bootstrap PKI callers are not accepted; use a SPIRE-issued identity`",
		"Each service owns its authorization",
		"One trust domain is accepted.",
		"names fixed SPIFFE ID values in the trust domain `governed-execution.local`.",
	)

	contracts := compactText(contractsRaw)
	for _, sentence := range []string{
		"AGS requires authenticated SPIFFE caller identity and rejects bootstrap-PKI callers under the caller authentication contract in section 3A.",
		"ARS authenticates every read and write caller under the caller authentication contract in section 3A",
		"ES requires authenticated SPIFFE caller identity and rejects bootstrap-PKI callers under the caller authentication contract in section 3A.",
		"EGS authenticates `GET /v1/trust-model` callers under the caller authentication contract in section 3A",
		"CGS requires authenticated SPIFFE caller identity and rejects bootstrap-PKI callers under the caller authentication contract in section 3A. A caller identity from any trust domain other than `execution.internal` is refused with `401` before policy evaluation.",
		"`id.conf` loading refuses any other principal, because no authenticated caller could ever match it.",
	} {
		assertContainsAll(t, "service contract reference", contracts, sentence)
	}

	lifecycle := compactDocSection(t, mustRead(t, ".docs/execution_lifecycle/contracts.md"), "## 4. Caller authorization contract", "## 4A. Producer Contract Declaration")
	assertContainsAll(t, "lifecycle caller authorization contract", lifecycle,
		"caller authentication contract in `.docs/system_overview/contracts.md` section 3A",
		"is `401` before allowlist matching.",
	)

	// The operator healthcheck TLS status tool predicts whether ES accepts the
	// operator certificate, so it applies the same one-URI-SAN rule.
	status := compactText(mustRead(t, ".docs/remote_alpha_operator_healthcheck_noninteractive_status.md"))
	assertContainsAll(t, "operator healthcheck TLS status identity rule", status,
		"The identity passes only when the certificate carries exactly one URI SAN and that URI is `spiffe://execution.internal/operator/local`, because the caller authentication contract (`.docs/system_overview/contracts.md` section 3A) refuses a certificate with more than one URI SAN.",
		"Expected operator/local identity mismatch, legacy-only identity, more than one URI SAN, a leaf that is not an end-entity certificate, or a leaf whose extended key usage does not allow client authentication: `identity_mismatch`.",
		// Audit 11, A11-4: the tools refuse what ES refuses as a client certificate.
		"`identity_not_end_entity` when its basic constraints mark it as a CA or its key usage includes keyCertSign or cRLSign (section 3A), and `identity_not_for_client_auth` when it has an extended key usage that allows neither clientAuth nor anyExtendedKeyUsage, which Go's TLS server refuses.",
		// Red-team N1 and re-audit O7-1: OpenSSL's printed SAN text is ambiguous.
		"The collector reads the URI SAN entries from the certificate's own DER encoding, through the fixed `openssl x509 -outform DER` read of the public certificate, and never from OpenSSL's printed SAN text,",
		"The host-local renew helper's `--status` mode carries the same decoder, and a test keeps the two copies identical.",
		// Re-audit 13, N13-2: where the decoder stops mirroring Go.
		"The decoder reads only the subjectAltName, basicConstraints, keyUsage and extKeyUsage extensions, so a certificate that Go refuses for another malformed extension, such as certificatePolicies or authorityInfoAccess, can still show identity pass, and ES refuses it at the handshake.",
		"(including the fixed DER encoding of the public operator certificate, from which the URI SAN entries are decoded)",
	)

	boundaries := compactDocSection(t, mustRead(t, ".docs/system_overview/boundaries.md"), "## 11. Cross-cutting packages that are not service boundaries", "## 12. Boundary leaks and pressure points")
	assertContainsAll(t, "cross-cutting package table", boundaries,
		"| `internal/callerauth` |",
		"Authentication only; every allowlist, route, and policy decision (authorization) stays service-local.",
	)
}

// The allowlist-prefix rule that ARS, AGS, and ES share is written once, in
// contracts.md section 3A, owned by internal/callerallowlist, and the
// service sections, configuration reference, boundaries, architecture, and
// PLANS.md refer to it (PR 27 red-team R6).
func TestCallerAllowlistPrefixRuleIsDocumentedOnce(t *testing.T) {
	contractsRaw := mustRead(t, ".docs/system_overview/contracts.md")
	section := compactDocSection(t, contractsRaw, "## 3A. Caller Authentication Contract", "## 4. Workload-Zone Vault Runtime-Config Contract")
	assertContainsAll(t, "allowlist-prefix rule", section,
		"ARS, AGS, and ES check and match their path-prefix allowlists with the one shared package `internal/callerallowlist`.",
		"A configured prefix must be the path of a SPIFFE ID that this section accepts, without its leading slash, and must have at least two segments.",
		"Each of those services refuses any other prefix at startup",
		"so `operator/local` matches `operator/local/a` but not `operator/local-evil`. A prefix that fails the rule matches nothing.",
		"`internal/callerallowlist` owns only the shape of a valid path prefix and the prefix match that ARS, AGS, and ES share. It owns no allowlist content and no route",
	)

	contracts := compactText(contractsRaw)
	assertContainsAll(t, "service allowlist references", contracts,
		"AGS authorizes publish callers by configured SPIFFE path prefixes from `authorization.allowed_spiffe_path_prefixes`, checked at startup and matched under the allowlist-prefix rule in section 3A.",
		"ARS checks those prefixes at startup and matches them under the allowlist-prefix rule in section 3A.",
		"ES startup config validation rejects broad or malformed prefixes under the allowlist-prefix rule in section 3A, which ARS and AGS share.",
	)
	assertContainsAll(t, "lifecycle allowlist reference", compactText(mustRead(t, ".docs/execution_lifecycle/contracts.md")),
		"under the allowlist-prefix rule in `.docs/system_overview/contracts.md` section 3A.",
	)
	assertContainsAll(t, "configuration reference", compactText(mustRead(t, ".docs/system_overview/configuration.md")),
		"ARS validates each allowed SPIFFE path prefix at startup with the same rule as AGS and ES",
		"AGS validates each allowed SPIFFE path prefix at startup with the same rule as ARS and ES",
		"ARS, AGS, and ES share this rule through `internal/callerallowlist`.",
	)
	assertContainsAll(t, "cross-cutting package table", compactText(mustRead(t, ".docs/system_overview/boundaries.md")),
		"| `internal/callerallowlist` |",
		"Shape of a valid prefix and the match only; which prefixes each service configures and which routes they open stay service-local",
	)
	assertContainsAll(t, "architecture", compactText(mustRead(t, ".docs/system_overview/architecture.md")),
		"`internal/callerallowlist` is the cross-cutting path-prefix allowlist rule shared by ARS, AGS, and ES",
	)
	assertContainsAll(t, "PLANS.md record", compactText(mustRead(t, plansRecordPath)),
		"### One allowlist-prefix rule for ARS, AGS, and ES (2026-11-23)",
	)
	assertContainsAll(t, "PLANS.md", compactText(mustRead(t, "PLANS.md")),
		"ARS, AGS, and ES check their configured path-prefix allowlists at startup and match callers against them through the one shared package `internal/callerallowlist`",
	)
	assertContainsAll(t, "bring-up runbook", compactText(mustRead(t, ".runbooks/system/Governed Execution ES System Bring-Up.md")),
		"The current repo-owned AGS and ES configs keep `authorization.allowed_spiffe_path_prefixes=[\"operator/local\"]`",
	)
}

// The namespace issuer binding is written once, in contracts section 3A,
// and the Remote Alpha user identity docs say what holds the user CA to
// user/ before and after it, and the rule by which a recovery reissue may
// carry the user CA over (red-team RT70-2 and RT70-3 of ES PR #70).
func TestNamespaceIssuerBindingAndUserCATrustAreDocumented(t *testing.T) {
	section := compactDocSection(t, mustRead(t, ".docs/system_overview/contracts.md"), "## 3A. Caller Authentication Contract", "## 4. Workload-Zone Vault Runtime-Config Contract")
	assertContainsAll(t, "namespace issuer binding contract", section,
		"AGS and ES also apply namespace issuer bindings, configured in `security.namespace_issuers`.",
		"The binding holds in both directions. A CA bound to a namespace vouches for no path outside it, and a path in a bound namespace needs that namespace's CA:",
		"So a CA bound to `user` can never vouch for `operator/local`, and no other CA can vouch for `user/claude`. The rule runs after the bootstrap-issuer rule.",
		"An X.509 URI name constraint cannot do this: it can hold a CA to the trust domain but not to a path inside it.",
		"Startup does not check that a bound CA is in the client CA bundle",
		"ARS, EGS, and CGS have no such field and their client CA bundles must not hold a bound CA.",
	)

	users := compactDocSection(t, mustRead(t, ".docs/system_overview/remote_supported_host_alpha.md"), "## Remote Alpha User Caller Identities", "## Direct Remote Requirements")
	assertContainsAll(t, "Remote Alpha user identities", users,
		"The user CA key can sign a certificate for any identity in `execution.internal`, the operator's and the Control Plane's included",
		"What holds it to `user/` is the namespace binding that `allow` writes.",
		"a leaked user CA key can then pass as any `user/<name>` that is allowed, and as no other identity.",
		"the user CA key is as strong as the operator's certificate.",
		"`allow` never leaves that state: it writes the binding in the same change that installs the user CA",
		"it carries the user CA over only when both client CA files being replaced end with that exact certificate (`/etc/execution-substrate/user-ca/ca-cert.pem`), and otherwise installs the new external client CA alone.",
		"That the file exists is not enough",
		"`revoke` is forward-only.",
		"nothing is put back.",
		"a random 127-bit serial (126 random bits, top bit set)",
		"`GET /health`, which asks for no allowlist entry, stays readable with them until they expire or `revoke --remove-ca` removes the CA.",
	)

	runbook := compactText(mustRead(t, ".runbooks/system/Governed Execution ES Remote Alpha User Identity.md"))
	assertContainsAll(t, "user identity runbook", runbook,
		"Its external reissue carries the user CA over only when both client CA files being replaced end with that exact certificate (`/etc/execution-substrate/user-ca/ca-cert.pem`), and otherwise installs the new external client CA alone",
		"`revoke` never puts a removal back.",
		"The user CA key can sign a certificate for any identity in `execution.internal`, the operator's included.",
	)
}
