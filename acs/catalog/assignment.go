package catalog

import (
	"encoding/json"
	"fmt"
	"strings"
)

type AssignmentKind string

const (
	AssignmentDeploymentStageConfig     AssignmentKind = "deployment_stage_config"
	AssignmentDeploymentServiceConfig   AssignmentKind = "deployment_service_config"
	AssignmentDeploymentStageDependency AssignmentKind = "deployment_stage_dependency"
	AssignmentServiceDockerConfig       AssignmentKind = "service_docker_config"
	AssignmentServiceApplicationConfig  AssignmentKind = "service_application_config"
	AssignmentServiceInstances          AssignmentKind = "service_instances"
	AssignmentSidecarDockerConfig       AssignmentKind = "sidecar_docker_config"
	AssignmentSidecarInstances          AssignmentKind = "sidecar_instances"
	AssignmentWorkloadZoneVault         AssignmentKind = "workload_zone_vault"
)

type AssignmentKey struct {
	IdentityKind AssignmentKind `json:"identity_kind"`
	Stage        string         `json:"stage,omitempty"`
	Service      string         `json:"service,omitempty"`
	Version      string         `json:"version,omitempty"`
	Instance     string         `json:"instance,omitempty"`
}

func RequiredWorkloadZoneVault() AssignmentKey {
	return AssignmentKey{IdentityKind: AssignmentWorkloadZoneVault}
}

func (a AssignmentKey) Validate() error {
	switch a.IdentityKind {
		case AssignmentDeploymentStageConfig:
			return validateShape(a, []string{"stage"}, nil)
		case AssignmentDeploymentServiceConfig:
			return validateShape(a, []string{"stage", "service", "version"}, []string{"instance"})
		case AssignmentDeploymentStageDependency:
			return validateShape(a, []string{"stage"}, []string{"service", "version", "instance"})
		case AssignmentServiceDockerConfig, AssignmentServiceApplicationConfig, AssignmentSidecarDockerConfig:
			return validateShape(a, []string{"service", "version", "instance"}, []string{"stage"})
		case AssignmentServiceInstances, AssignmentSidecarInstances:
			return validateShape(a, []string{"service", "version"}, []string{"stage", "instance"})
		case AssignmentWorkloadZoneVault:
			return validateShape(a, nil, []string{"stage", "service", "version", "instance"})
		default:
			return fmt.Errorf("unsupported identity_kind: %q", a.IdentityKind)
	}
}

func (a AssignmentKey) CanonicalJSON() (string, error) {
	if err := a.Validate(); err != nil {
		return "", err
	}

	payload, err := json.Marshal(a)
	if err != nil {
		return "", fmt.Errorf("marshal assignment: %w", err)
	}

	return string(payload), nil
}

func (a AssignmentKey) MustCanonicalJSON() string {
	value, err := a.CanonicalJSON()
	if err != nil {
		panic(err)
	}

	return value
}

func validateShape(a AssignmentKey, required []string, mustBeEmpty []string) error {
	values := map[string]string{
		"stage":    a.Stage,
		"service":  a.Service,
		"version":  a.Version,
		"instance": a.Instance,
	}

	for _, field := range required {
		if strings.TrimSpace(values[field]) == "" {
			return fmt.Errorf("%s requires %s", a.IdentityKind, field)
		}
	}

	for _, field := range mustBeEmpty {
		if strings.TrimSpace(values[field]) != "" {
			return fmt.Errorf("%s does not allow %s", a.IdentityKind, field)
		}
	}

	return nil
}
