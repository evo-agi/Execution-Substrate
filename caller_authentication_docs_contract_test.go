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
		"Expected operator/local identity mismatch, legacy-only identity, or more than one URI SAN: `identity_mismatch`.",
	)

	boundaries := compactDocSection(t, mustRead(t, ".docs/system_overview/boundaries.md"), "## 11. Cross-cutting packages that are not service boundaries", "## 12. Boundary leaks and pressure points")
	assertContainsAll(t, "cross-cutting package table", boundaries,
		"| `internal/callerauth` |",
		"Authentication only; every allowlist, route, and policy decision (authorization) stays service-local.",
	)
}
