package policy

import (
	"bufio"
	"fmt"
	"os"
	"strings"
	"time"
)

const policyVersion = "go-cgs-v1"
const deploymentServiceID = "deployment"

type Set struct {
	serviceModuleToID map[string]string
	scriptModuleToID  map[string]string
}

type Workload struct {
	Type               string
	ServiceName        string
	WorkloadIdentityID string
	ModulePath         string
	FilePath           string
	TargetPlatform     string
	Description        string
	Ephemeral          bool
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

	serviceMap := make(map[string]string)
	scriptMap := make(map[string]string)
	serviceIDs := make(map[string]string)
	scriptIDs := make(map[string]string)

	scanner := bufio.NewScanner(file)
	depth := 0
	currentSection := ""
	lineNumber := 0

	for scanner.Scan() {
		lineNumber++
		line := stripInlineComment(scanner.Text())
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		if strings.HasSuffix(line, "{") && !strings.Contains(line, ":") {
			sectionName := strings.TrimSpace(strings.TrimSuffix(line, "{"))
			sectionName = strings.Trim(sectionName, "\"")
			if depth == 0 {
				currentSection = sectionName
			}
			depth++
			continue
		}

		if line == "}" {
			if depth == 0 {
				return nil, fmt.Errorf("parse id.conf: unexpected closing brace at line %d", lineNumber)
			}
			depth--
			if depth == 0 {
				currentSection = ""
			}
			continue
		}

		if depth == 1 && (currentSection == "service_id" || currentSection == "approle") {
			key, value, ok := parseMappingLine(line)
			if !ok {
				return nil, fmt.Errorf("parse id.conf: invalid mapping at line %d", lineNumber)
			}
			if currentSection == "service_id" {
				if _, exists := serviceMap[key]; exists {
					return nil, fmt.Errorf("parse id.conf: duplicate service_id module_path mapping for %s", key)
				}
				if existingModulePath, exists := serviceIDs[value]; exists {
					return nil, fmt.Errorf("parse id.conf: duplicate service_id subject id %s for %s and %s", value, existingModulePath, key)
				}
				serviceMap[key] = value
				serviceIDs[value] = key
			} else {
				if _, exists := scriptMap[key]; exists {
					return nil, fmt.Errorf("parse id.conf: duplicate approle module_path mapping for %s", key)
				}
				if existingModulePath, exists := scriptIDs[value]; exists {
					return nil, fmt.Errorf("parse id.conf: duplicate approle subject id %s for %s and %s", value, existingModulePath, key)
				}
				scriptMap[key] = value
				scriptIDs[value] = key
			}
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("read id.conf: %w", err)
	}
	if depth != 0 {
		return nil, fmt.Errorf("parse id.conf: unbalanced braces")
	}
	if len(serviceMap) == 0 && len(scriptMap) == 0 {
		return nil, fmt.Errorf("id.conf does not define any service_id or approle mappings")
	}

	return &Set{
		serviceModuleToID: serviceMap,
		scriptModuleToID:  scriptMap,
	}, nil
}

func (s *Set) ValidateWorkload(workload Workload) error {
	workload.Type = strings.TrimSpace(workload.Type)
	switch workload.Type {
		case "service", "script":
		default:
			return fmt.Errorf("workload.type must be service or script")
	}

	modulePath := strings.TrimSpace(workload.ModulePath)
	filePath := strings.TrimSpace(workload.FilePath)
	if modulePath == "" && filePath == "" {
		return fmt.Errorf("must specify either workload.module_path or workload.file_path")
	}

	if filePath != "" {
		converted := filePathToModulePath(filePath)
		if converted == "" {
			return fmt.Errorf("workload.file_path is invalid")
		}
		if modulePath != "" && converted != modulePath {
			return fmt.Errorf("workload.module_path and workload.file_path do not match")
		}
	}

	if workload.Type == "service" {
		serviceName := strings.TrimSpace(workload.ServiceName)
		if serviceName != "" {
			if resolved, ok := s.lookupServiceID(workload); ok && resolved != serviceName {
				return fmt.Errorf("workload.service_name does not match module_path")
			}
		}
	}

	return nil
}

func (s *Set) Evaluate(decisionID string, workload Workload) Evaluation {
	location := s.determineSubjectLocation(workload)
	evaluatedRules := []string{}
	considerations := []string{}
	mainReason := ""

	subjectRole := "worker"
	subjectID, subjectIDValid := s.determineSubjectID(workload)
	locationValid := s.isLocationValid(workload.Type, location)

	switch workload.Type {
		case "service":
			evaluatedRules = append(evaluatedRules, "service-id", "service-location")
			considerations = append(considerations, validityMessage("Service ID", subjectIDValid))
			considerations = append(considerations, validityMessage("Service location", locationValid))
			if !subjectIDValid {
				mainReason = "Service ID is not valid"
			} else if !locationValid {
				mainReason = "Service location is not valid"
			}
		case "script":
			evaluatedRules = append(evaluatedRules, "script-id", "script-location")
			considerations = append(considerations, validityMessage("Script ID", subjectIDValid))
			considerations = append(considerations, validityMessage("Script location", locationValid))
			if !subjectIDValid {
				mainReason = "Script ID is not valid"
			} else if !locationValid {
				mainReason = "Script location is not valid"
			}
	}

	allowed := subjectIDValid && locationValid
	if allowed {
		considerations = append(considerations, "Workload SPIFFE identity is specified")
		evaluatedRules = append(evaluatedRules, "workload-identity")
	}

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
			SubjectID:   subjectID,
			Audit:       audit,
			Reason: &Reason{
				Code:    "EVALUATION_FAILED",
				Message: mainReason,
			},
		}
	}

	var constraints *Constraints
	if subjectID != deploymentServiceID {
		expiry := time.Date(9999, 12, 31, 23, 59, 59, 0, time.UTC)
		constraints = &Constraints{
			ForbiddenStages: []string{"bootstrap"},
			ExpiresAt:       expiry,
		}
	}

	return Evaluation{
		Allowed:     true,
		Role:        subjectRole,
		SubjectType: workload.Type,
		SubjectID:   subjectID,
		Audit:       audit,
		Constraints: constraints,
	}
}

func (s *Set) SubjectFromWorkload(workload Workload) (string, string, bool) {
	subjectID, ok := s.determineSubjectID(workload)
	if !ok {
		return "", "", false
	}
	return workload.Type, subjectID, true
}

func (s *Set) determineSubjectLocation(workload Workload) string {
	modulePath := strings.TrimSpace(workload.ModulePath)
	if modulePath != "" {
		return modulePath
	}
	return filePathToModulePath(workload.FilePath)
}

func (s *Set) determineSubjectID(workload Workload) (string, bool) {
	switch workload.Type {
		case "service":
			serviceName := strings.TrimSpace(workload.ServiceName)
			if serviceName != "" {
				return serviceName, s.isKnownServiceID(serviceName)
			}
			if resolved, ok := s.lookupServiceID(workload); ok {
				return resolved, true
			}
			return "", false
		case "script":
			location := s.determineSubjectLocation(workload)
			scriptID, ok := s.scriptModuleToID[location]
			if !ok || strings.TrimSpace(scriptID) == "" {
				return "", false
			}
			return scriptID, true
		default:
			return "", false
	}
}

func (s *Set) isLocationValid(workloadType string, location string) bool {
	if strings.TrimSpace(location) == "" {
		return false
	}
	switch workloadType {
		case "service":
			_, ok := s.serviceModuleToID[location]
			return ok
		case "script":
			_, ok := s.scriptModuleToID[location]
			return ok
		default:
			return false
	}
}

func (s *Set) lookupServiceID(workload Workload) (string, bool) {
	location := s.determineSubjectLocation(workload)
	serviceID, ok := s.serviceModuleToID[location]
	return serviceID, ok
}

func (s *Set) isKnownServiceID(serviceID string) bool {
	for _, known := range s.serviceModuleToID {
		if known == serviceID {
			return true
		}
	}
	return false
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

func filePathToModulePath(filePath string) string {
	trimmed := strings.TrimSpace(filePath)
	trimmed = strings.TrimPrefix(trimmed, "./")
	trimmed = strings.TrimSuffix(trimmed, ".py")
	trimmed = strings.Trim(trimmed, "/")
	if trimmed == "" {
		return ""
	}
	replacer := strings.NewReplacer("/", ".", "\\", ".")
	return replacer.Replace(trimmed)
}

func validityMessage(subject string, valid bool) string {
	if valid {
		return subject + " is valid"
	}
	return subject + " is not valid"
}
