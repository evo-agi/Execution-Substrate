package config

import (
	"errors"
	"fmt"
	"strings"
	"unicode"
	"unicode/utf8"

	"execution-substrate/internal/callerallowlist"
	"execution-substrate/internal/callerauth"
)

// Workload grants are the owner's grants in ES deployment configuration:
// which runs may have a network (and, once named workload identities land,
// which identity a run gets). A rule names who published the artifact and
// who calls ES to run it, so a grant to one publisher is not a grant to every
// caller ES admits. The contract is .docs/execution_lifecycle/contracts.md,
// section 5B. Matching is exact and there is no setting that turns grants
// off: a configuration without grants admits only runs that request no
// network.

const (
	// MaxWorkloadGrantRules is the most grant rules a configuration may hold.
	MaxWorkloadGrantRules = 32
	// MaxWorkloadGrantRuleIDBytes is the longest rule ID.
	MaxWorkloadGrantRuleIDBytes = 64
	// MaxWorkloadGrantMatchValueBytes is the longest artifact type a rule
	// may match.
	MaxWorkloadGrantMatchValueBytes = 256
	// MaxWorkloadGrantNameBytes is the longest egress lane name.
	MaxWorkloadGrantNameBytes = 63

	// WorkloadEgressLaneUnrestricted is the only egress lane until egress
	// lanes land: the run keeps today's network, with no egress filter of
	// its own. It is a temporary compatibility edge that readiness reports as
	// workload_egress_unrestricted=true. Runtime realization alone maps it to
	// job values.
	WorkloadEgressLaneUnrestricted = "unrestricted"

	// WorkloadGrantRuntimeProfileDefault and
	// WorkloadGrantRuntimeProfileControlPlaneNormalShell are the runtime
	// profile names ES admits, the values a rule's runtime_profile may take.
	WorkloadGrantRuntimeProfileDefault                 = "static-script/default"
	WorkloadGrantRuntimeProfileControlPlaneNormalShell = "control-plane-normal-shell/v1"
)

// WorkloadGrantsConfig is admission_policy.workload_grants.
type WorkloadGrantsConfig struct {
	EgressLanes []WorkloadEgressLaneConfig `json:"egress_lanes"`
	Rules       []WorkloadGrantRuleConfig  `json:"rules"`
}

// WorkloadEgressLaneConfig names one egress lane. ReachesWorkloadVault is a
// pointer so that leaving it out is refused rather than read as false.
type WorkloadEgressLaneConfig struct {
	Name                 string `json:"name"`
	ReachesWorkloadVault *bool  `json:"reaches_workload_vault"`
}

// WorkloadGrantRuleConfig is one grant rule: five match fields, all
// required and compared byte for byte, and the grant. PublisherPrincipal is
// the SPIFFE ID that published the artifact through AGS, from its signed
// evidence; CallerPrincipal is the SPIFFE ID of the caller of ES :prepare or
// :submit, from the authenticated connection. EgressLane is empty when the
// rule grants no network.
type WorkloadGrantRuleConfig struct {
	ID                 string `json:"id"`
	PublisherPrincipal string `json:"publisher_principal"`
	CallerPrincipal    string `json:"caller_principal"`
	SignerKeyID        string `json:"signer_key_id"`
	ArtifactType       string `json:"artifact_type"`
	RuntimeProfile     string `json:"runtime_profile"`
	EgressLane         string `json:"egress_lane,omitempty"`
}

// MatchKey returns the rule's five match fields in a fixed order: publisher
// principal, caller principal, signer key ID, artifact type and runtime
// profile. ES admission builds a run's key in the same order and compares the
// two byte for byte.
func (r WorkloadGrantRuleConfig) MatchKey() [5]string {
	return [5]string{r.PublisherPrincipal, r.CallerPrincipal, r.SignerKeyID, r.ArtifactType, r.RuntimeProfile}
}

// Validate checks the grants on their own. Config.Validate also checks that
// every rule's signer key is the key ES verifies artifact evidence with and
// that every rule's caller is one ES's caller allowlist admits, because a
// rule naming another key or another caller could never match.
func (c WorkloadGrantsConfig) Validate(field string) error {
	lanes := map[string]bool{}
	for i, lane := range c.EgressLanes {
		laneField := fmt.Sprintf("%s.egress_lanes[%d]", field, i)
		if err := validateWorkloadGrantName(laneField+".name", lane.Name); err != nil {
			return err
		}
		if _, ok := lanes[lane.Name]; ok {
			return fmt.Errorf("%s.name must be unique", laneField)
		}
		if lane.ReachesWorkloadVault == nil {
			return fmt.Errorf("%s.reaches_workload_vault is required", laneField)
		}
		if lane.Name != WorkloadEgressLaneUnrestricted || !*lane.ReachesWorkloadVault {
			return fmt.Errorf("%s must be the lane %q with reaches_workload_vault true: it is the only egress lane until egress lanes land", laneField, WorkloadEgressLaneUnrestricted)
		}
		lanes[lane.Name] = *lane.ReachesWorkloadVault
	}

	if len(c.Rules) > MaxWorkloadGrantRules {
		return fmt.Errorf("%s.rules must not contain more than %d rules", field, MaxWorkloadGrantRules)
	}
	ids := map[string]struct{}{}
	matches := map[[5]string]string{}
	for i, rule := range c.Rules {
		ruleField := fmt.Sprintf("%s.rules[%d]", field, i)
		if err := rule.validate(ruleField); err != nil {
			return err
		}
		if _, ok := ids[rule.ID]; ok {
			return fmt.Errorf("%s.id must be unique", ruleField)
		}
		ids[rule.ID] = struct{}{}
		key := rule.MatchKey()
		if other, ok := matches[key]; ok {
			return fmt.Errorf("%s matches the same publisher_principal, caller_principal, signer_key_id, artifact_type and runtime_profile as rule %q: at most one rule may match a run", ruleField, other)
		}
		matches[key] = rule.ID
		if rule.EgressLane != "" {
			if _, ok := lanes[rule.EgressLane]; !ok {
				return fmt.Errorf("%s.egress_lane must name a lane listed in %s.egress_lanes", ruleField, field)
			}
		}
	}
	return nil
}

// validateAgainstConfig refuses a rule that could never match under the
// rest of ES's configuration. ES admits only evidence sealed with the
// provenance key, so a rule naming another signer key could never match; the
// verifier compares the trimmed key ID, so this check does too. ES admits
// only callers its caller allowlist matches, so a rule naming another caller
// could never match either.
func (c WorkloadGrantsConfig) validateAgainstConfig(field string, provenanceKeyID string, allowedCallerPrefixes []string) error {
	provenanceKeyID = strings.TrimSpace(provenanceKeyID)
	for i, rule := range c.Rules {
		if rule.SignerKeyID != provenanceKeyID {
			return fmt.Errorf("%s.rules[%d].signer_key_id must be verification.provenance.key_id, the only key ES admits artifact evidence from", field, i)
		}
		caller, err := callerauth.ParseSPIFFEID(rule.CallerPrincipal)
		if err != nil || !callerallowlist.MatchesAny(caller, allowedCallerPrefixes) {
			return fmt.Errorf("%s.rules[%d].caller_principal must be a caller authorization.allowed_spiffe_path_prefixes admits", field, i)
		}
	}
	return nil
}

func (r WorkloadGrantRuleConfig) validate(field string) error {
	if err := validateConfiguredStaticScriptLiteralDenyEntryID(field+".id", r.ID); err != nil {
		return err
	}
	if err := validateWorkloadGrantPrincipal(field+".publisher_principal", r.PublisherPrincipal); err != nil {
		return err
	}
	if err := validateWorkloadGrantPrincipal(field+".caller_principal", r.CallerPrincipal); err != nil {
		return err
	}
	if err := validateWorkloadGrantMatchValue(field+".signer_key_id", r.SignerKeyID); err != nil {
		return err
	}
	if err := validateWorkloadGrantMatchValue(field+".artifact_type", r.ArtifactType); err != nil {
		return err
	}
	switch r.RuntimeProfile {
	case WorkloadGrantRuntimeProfileDefault, WorkloadGrantRuntimeProfileControlPlaneNormalShell:
	default:
		return fmt.Errorf("%s.runtime_profile must be %q or %q", field, WorkloadGrantRuntimeProfileDefault, WorkloadGrantRuntimeProfileControlPlaneNormalShell)
	}
	if r.EgressLane != "" {
		if err := validateWorkloadGrantName(field+".egress_lane", r.EgressLane); err != nil {
			return err
		}
	}
	return nil
}

// validateWorkloadGrantPrincipal requires a caller SPIFFE ID written
// exactly in its canonical form, with at least as many path segments as the
// shortest prefix a caller allowlist may hold: AGS and ES admit no caller
// with fewer, so a rule naming one could never match. A workload identity
// is refused with its own message: the caller authentication contract gives
// it no caller identity at any service, so it is never a publisher or an ES
// caller.
func validateWorkloadGrantPrincipal(field string, value string) error {
	if err := validateWorkloadGrantMatchValue(field, value); err != nil {
		return err
	}
	id, err := callerauth.ParseSPIFFEID(value)
	if errors.Is(err, callerauth.ErrWorkloadIdentity) {
		return fmt.Errorf("%s must not be a workload identity: workload identities are never callers, so none publishes a run or asks ES for one", field)
	}
	if err != nil || id.String() != value || strings.Count(id.Path(), "/")+1 < callerallowlist.MinimumSegments {
		return fmt.Errorf("%s must be a caller SPIFFE ID in trust domain %s with at least %d path segments, written exactly in its canonical form", field, callerauth.TrustDomain, callerallowlist.MinimumSegments)
	}
	return nil
}

// validateWorkloadGrantMatchValue requires a non-empty value without
// surrounding white space, of printable UTF-8 text without control or
// format characters, at most MaxWorkloadGrantMatchValueBytes long. Values
// are compared byte for byte, so a value that differs only in white space
// or invisible characters would silently never match.
func validateWorkloadGrantMatchValue(field string, value string) error {
	if value == "" {
		return fmt.Errorf("%s is required", field)
	}
	if value != strings.TrimSpace(value) {
		return fmt.Errorf("%s must not contain leading or trailing whitespace", field)
	}
	if len(value) > MaxWorkloadGrantMatchValueBytes {
		return fmt.Errorf("%s must not exceed %d bytes", field, MaxWorkloadGrantMatchValueBytes)
	}
	if !utf8.ValidString(value) {
		return fmt.Errorf("%s must be valid UTF-8 text", field)
	}
	for _, r := range value {
		if !unicode.IsPrint(r) || unicode.Is(unicode.Cc, r) || unicode.Is(unicode.Cf, r) {
			return fmt.Errorf("%s must contain only printable non-control text", field)
		}
	}
	return nil
}

// validateWorkloadGrantName applies the name rule of egress lanes (and,
// later, workload identities): 1 to 63 characters from a-z, 0-9 and "-",
// starting with a letter or a digit.
func validateWorkloadGrantName(field string, name string) error {
	if name == "" {
		return fmt.Errorf("%s is required", field)
	}
	if len(name) > MaxWorkloadGrantNameBytes {
		return fmt.Errorf("%s must not exceed %d characters", field, MaxWorkloadGrantNameBytes)
	}
	for i := 0; i < len(name); i++ {
		b := name[i]
		switch {
		case b >= 'a' && b <= 'z', b >= '0' && b <= '9':
		case b == '-' && i > 0:
		default:
			return fmt.Errorf("%s must be 1 to %d characters from a-z, 0-9 and \"-\", starting with a letter or a digit", field, MaxWorkloadGrantNameBytes)
		}
	}
	return nil
}
