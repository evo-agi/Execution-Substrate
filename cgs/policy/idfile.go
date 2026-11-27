package policy

import (
	"bufio"
	"errors"
	"fmt"
	"net/url"
	"os"
	"strings"
	"time"

	"execution-substrate/internal/callerauth"
)

const policyVersion = "go-cgs-v2"

type Set struct {
	subjectsByKey       map[string]Subject
	subjectsByPrincipal map[string]Subject
}

type Workload struct {
	Type               string
	WorkloadIdentityID string
}

type Subject struct {
	Type      string
	ID        string
	Principal string
	Role      string
}

type Evaluation struct {
	Allowed     bool
	Role        string
	SubjectType string
	SubjectID   string
	Audit       AuditMetadata
	Reason      *Reason
	Constraints *Constraints
}

type AuditMetadata struct {
	DecisionID     string
	Reasons        []string
	PolicyVersion  string
	EvaluatedRules []string
}

type Reason struct {
	Code    string
	Message string
}

type Constraints struct {
	ForbiddenStages []string
	ExpiresAt       time.Time
}

func Load(path string) (*Set, error) {
	if strings.TrimSpace(path) == "" {
		return nil, fmt.Errorf("policy.id_conf_path is required")
	}

	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open id.conf: %w", err)
	}
	defer file.Close()

	info, err := file.Stat()
	if err != nil {
		return nil, fmt.Errorf("stat id.conf: %w", err)
	}
	if info.Size() == 0 {
		return nil, fmt.Errorf("id.conf is empty")
	}

	subjectsByKey := make(map[string]Subject)
	subjectsByPrincipal := make(map[string]Subject)

	scanner := bufio.NewScanner(file)
	lineNumber := 0
	var currentSubject *Subject

	for scanner.Scan() {
		lineNumber++
		line := stripInlineComment(scanner.Text())
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		if subjectID, ok := parseSubjectHeader(line); ok {
			if currentSubject != nil {
				return nil, fmt.Errorf("parse id.conf: nested subject block at line %d", lineNumber)
			}
			currentSubject = &Subject{ID: subjectID}
			continue
		}

		if line == "}" {
			if currentSubject == nil {
				return nil, fmt.Errorf("parse id.conf: unexpected closing brace at line %d", lineNumber)
			}
			if err := validateSubject(*currentSubject); err != nil {
				return nil, fmt.Errorf("parse id.conf: %w", err)
			}
			key := subjectKey(currentSubject.Type, currentSubject.ID)
			if _, exists := subjectsByKey[key]; exists {
				return nil, fmt.Errorf("parse id.conf: duplicate subject %s %s", currentSubject.Type, currentSubject.ID)
			}
			if existing, exists := subjectsByPrincipal[currentSubject.Principal]; exists {
				return nil, fmt.Errorf("parse id.conf: duplicate subject principal %s for %s %s and %s %s", currentSubject.Principal, existing.Type, existing.ID, currentSubject.Type, currentSubject.ID)
			}
			subjectsByKey[key] = *currentSubject
			subjectsByPrincipal[currentSubject.Principal] = *currentSubject
			currentSubject = nil
			continue
		}

		if currentSubject == nil {
			return nil, fmt.Errorf("parse id.conf: invalid subject declaration at line %d", lineNumber)
		}

		key, value, ok := parseMappingLine(line)
		if !ok {
			return nil, fmt.Errorf("parse id.conf: invalid subject field at line %d", lineNumber)
		}
		switch key {
		case "type":
			currentSubject.Type = value
		case "principal":
			currentSubject.Principal = value
		case "role":
			currentSubject.Role = value
		default:
			return nil, fmt.Errorf("parse id.conf: unsupported subject field %s at line %d", key, lineNumber)
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("read id.conf: %w", err)
	}
	if currentSubject != nil {
		return nil, fmt.Errorf("parse id.conf: unbalanced braces")
	}
	if len(subjectsByKey) == 0 {
		return nil, fmt.Errorf("id.conf does not define any subjects")
	}

	return &Set{
		subjectsByKey:       subjectsByKey,
		subjectsByPrincipal: subjectsByPrincipal,
	}, nil
}

func (s *Set) ValidateWorkload(workload Workload) error {
	workload.Type = strings.TrimSpace(workload.Type)
	switch workload.Type {
	case "service", "script":
	default:
		return fmt.Errorf("workload.type must be service or script")
	}

	workload.WorkloadIdentityID = strings.TrimSpace(workload.WorkloadIdentityID)
	if workload.WorkloadIdentityID == "" {
		return fmt.Errorf("workload.workload_identity_id is required")
	}

	subjectType, _, ok := SubjectFromSPIFFEID(workload.WorkloadIdentityID)
	if !ok {
		return fmt.Errorf("workload.workload_identity_id must be a valid SPIFFE URI")
	}
	if subjectType != workload.Type {
		return fmt.Errorf("workload.type does not match workload.workload_identity_id")
	}

	return nil
}

func (s *Set) Evaluate(decisionID string, workload Workload) Evaluation {
	workloadType, workloadSubjectID, principalValid := SubjectFromSPIFFEID(workload.WorkloadIdentityID)
	evaluatedRules := []string{"workload-principal", "subject-policy"}
	considerations := []string{validityMessage("Workload principal", principalValid)}
	mainReason := ""

	subject, subjectKnown := s.subjectsByPrincipal[strings.TrimSpace(workload.WorkloadIdentityID)]
	considerations = append(considerations, validityMessage("Policy subject", subjectKnown))
	if !principalValid {
		mainReason = "Workload principal is not valid"
	} else if !subjectKnown {
		mainReason = "Policy subject is not defined"
	} else if subject.Type != workloadType || subject.ID != workloadSubjectID {
		subjectKnown = false
		mainReason = "Policy subject does not match workload principal"
	}

	allowed := principalValid && subjectKnown

	audit := AuditMetadata{
		DecisionID:     decisionID,
		Reasons:        considerations,
		PolicyVersion:  policyVersion,
		EvaluatedRules: evaluatedRules,
	}

	if !allowed {
		return Evaluation{
			Allowed:     false,
			SubjectType: workload.Type,
			SubjectID:   workloadSubjectID,
			Audit:       audit,
			Reason: &Reason{
				Code:    "EVALUATION_FAILED",
				Message: mainReason,
			},
		}
	}

	expiry := time.Date(9999, 12, 31, 23, 59, 59, 0, time.UTC)
	constraints := &Constraints{
		ForbiddenStages: []string{"bootstrap"},
		ExpiresAt:       expiry,
	}

	return Evaluation{
		Allowed:     true,
		Role:        subject.Role,
		SubjectType: subject.Type,
		SubjectID:   subject.ID,
		Audit:       audit,
		Constraints: constraints,
	}
}

func (s *Set) SubjectFromWorkload(workload Workload) (string, string, bool) {
	subject, ok := s.subjectsByPrincipal[strings.TrimSpace(workload.WorkloadIdentityID)]
	if !ok {
		return "", "", false
	}
	return subject.Type, subject.ID, true
}

func parseMappingLine(line string) (string, string, bool) {
	parts := strings.SplitN(line, ":", 2)
	if len(parts) != 2 {
		return "", "", false
	}

	key := strings.TrimSpace(parts[0])
	key = strings.Trim(key, "\"")
	value := strings.TrimSpace(parts[1])
	value = strings.TrimSuffix(value, ",")
	value = strings.TrimSpace(value)
	if !strings.HasPrefix(value, "\"") || !strings.HasSuffix(value, "\"") {
		return "", "", false
	}
	value = strings.Trim(value, "\"")
	if key == "" || value == "" {
		return "", "", false
	}

	return key, value, true
}

func stripInlineComment(line string) string {
	var builder strings.Builder
	inQuotes := false
	for i := 0; i < len(line); i++ {
		ch := line[i]
		if ch == '"' {
			inQuotes = !inQuotes
		}
		if ch == '#' && !inQuotes {
			break
		}
		builder.WriteByte(ch)
	}
	return builder.String()
}

func validityMessage(subject string, valid bool) string {
	if valid {
		return subject + " is valid"
	}
	return subject + " is not valid"
}

func parseSubjectHeader(line string) (string, bool) {
	if !strings.HasSuffix(line, "{") {
		return "", false
	}
	header := strings.TrimSpace(strings.TrimSuffix(line, "{"))
	if !strings.HasPrefix(header, "subject ") {
		return "", false
	}
	identifier := strings.TrimSpace(strings.TrimPrefix(header, "subject "))
	if !strings.HasPrefix(identifier, "\"") || !strings.HasSuffix(identifier, "\"") {
		return "", false
	}
	identifier = strings.Trim(identifier, "\"")
	if strings.TrimSpace(identifier) == "" {
		return "", false
	}
	return identifier, true
}

func validateSubject(subject Subject) error {
	subject.Type = strings.TrimSpace(subject.Type)
	switch subject.Type {
	case "service", "script":
	default:
		return fmt.Errorf("subject %s has invalid type %q", subject.ID, subject.Type)
	}
	if strings.TrimSpace(subject.Principal) == "" {
		return fmt.Errorf("subject %s principal is required", subject.ID)
	}
	// Only an authenticated caller can match a principal, and caller
	// authentication accepts exactly the SPIFFE IDs that ParseSPIFFEID
	// accepts, in their only form. Any other principal could never match,
	// so it is refused here instead of loading as dead policy.
	if _, err := callerauth.ParseSPIFFEID(subject.Principal); err != nil {
		if errors.Is(err, callerauth.ErrWorkloadIdentity) {
			return fmt.Errorf("subject %s principal is a workload identity, and workload identities are never callers", subject.ID)
		}
		return fmt.Errorf("subject %s principal must be a conforming SPIFFE ID with a path in trust domain %s", subject.ID, callerauth.TrustDomain)
	}
	principalType, principalID, ok := SubjectFromSPIFFEID(subject.Principal)
	if !ok {
		return fmt.Errorf("subject %s principal must be a valid SPIFFE URI", subject.ID)
	}
	if principalType != subject.Type || principalID != subject.ID {
		return fmt.Errorf("subject %s principal does not match declared subject", subject.ID)
	}
	subject.Role = strings.TrimSpace(subject.Role)
	if subject.Role == "" {
		return fmt.Errorf("subject %s role is required", subject.ID)
	}
	return nil
}

func subjectKey(subjectType string, subjectID string) string {
	return strings.TrimSpace(subjectType) + ":" + strings.TrimSpace(subjectID)
}

func SubjectFromSPIFFEID(identityID string) (string, string, bool) {
	parsed, err := url.Parse(identityID)
	if err != nil || parsed.Scheme != "spiffe" || parsed.Host == "" {
		return "", "", false
	}

	segments := strings.Split(strings.Trim(parsed.Path, "/"), "/")
	if len(segments) != 2 {
		return "", "", false
	}
	if segments[0] != "service" && segments[0] != "script" {
		return "", "", false
	}
	if strings.TrimSpace(segments[1]) == "" {
		return "", "", false
	}

	return segments[0], segments[1], true
}
