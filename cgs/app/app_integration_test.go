package app_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"execution-platform/cgs/app"
	"execution-platform/cgs/config"
	"execution-platform/cgs/proof"
)

func TestLoadConfigRejectsMissingFile(t *testing.T) {
	t.Parallel()

	_, err := config.Load(filepath.Join(t.TempDir(), "missing.json"))
	if err == nil || !strings.Contains(err.Error(), "open config") {
		t.Fatalf("expected missing-file error, got %v", err)
	}
}

func TestLoadConfigRejectsMalformedJSON(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, []byte("{"), 0o600); err != nil {
		t.Fatalf("write malformed config: %v", err)
	}

	_, err := config.Load(path)
	if err == nil || !strings.Contains(err.Error(), "decode config") {
		t.Fatalf("expected malformed-json error, got %v", err)
	}
}

func TestLoadConfigRejectsTrailingData(t *testing.T) {
	t.Parallel()

	fixture := newTLSFixture(t)
	idConfPath := writeIDConf(t, validIDConf)
	cfg := buildConfig(fixture, idConfPath)
	payload, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		t.Fatalf("marshal config: %v", err)
	}

	path := filepath.Join(t.TempDir(), "cgs.json")
	payload = append(payload, []byte("\n{\"trailing\":true}\n")...)
	if err := os.WriteFile(path, payload, 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	_, err = config.Load(path)
	if err == nil || !strings.Contains(err.Error(), "trailing data after first JSON document") {
		t.Fatalf("expected trailing-data error, got %v", err)
	}
}

func TestNewRejectsMissingIDConf(t *testing.T) {
	t.Parallel()

	fixture := newTLSFixture(t)
	cfg := buildConfig(fixture, filepath.Join(t.TempDir(), "missing-id.conf"))
	cfgPath := writeConfig(t, cfg)

	loaded, err := config.Load(cfgPath)
	if err != nil {
		t.Fatalf("load config: %v", err)
	}

	_, err = app.New(loaded)
	if err == nil || !strings.Contains(err.Error(), "open id.conf") {
		t.Fatalf("expected missing id.conf error, got %v", err)
	}
}

func TestNewRejectsEmptyIDConf(t *testing.T) {
	t.Parallel()

	fixture := newTLSFixture(t)
	idConfPath := writeIDConf(t, "")
	cfgPath := writeConfig(t, buildConfig(fixture, idConfPath))

	loaded, err := config.Load(cfgPath)
	if err != nil {
		t.Fatalf("load config: %v", err)
	}

	_, err = app.New(loaded)
	if err == nil || !strings.Contains(err.Error(), "id.conf is empty") {
		t.Fatalf("expected empty id.conf error, got %v", err)
	}
}

func TestNewRejectsInvalidIDConf(t *testing.T) {
	t.Parallel()

	fixture := newTLSFixture(t)
	idConfPath := writeIDConf(t, "service_id {\ninvalid-line\n}\n")
	cfgPath := writeConfig(t, buildConfig(fixture, idConfPath))

	loaded, err := config.Load(cfgPath)
	if err != nil {
		t.Fatalf("load config: %v", err)
	}

	_, err = app.New(loaded)
	if err == nil || !strings.Contains(err.Error(), "parse id.conf") {
		t.Fatalf("expected invalid id.conf error, got %v", err)
	}
}

func TestNewRejectsMissingVaultRuntimeClientCert(t *testing.T) {
	t.Parallel()

	fixture := newTLSFixture(t)
	idConfPath := writeIDConf(t, validIDConf)
	cfg := buildConfig(fixture, idConfPath)
	cfg.VaultRuntime.ClientCertFile = filepath.Join(t.TempDir(), "missing-client.pem")
	cfgPath := writeConfig(t, cfg)

	loaded, err := config.Load(cfgPath)
	if err != nil {
		t.Fatalf("load config: %v", err)
	}

	_, err = app.New(loaded)
	if err == nil || !strings.Contains(err.Error(), "load vault_runtime client key pair") {
		t.Fatalf("expected unusable vault_runtime error, got %v", err)
	}
}

func TestLoadConfigRejectsBlankBootstrapIssuerConfig(t *testing.T) {
	t.Parallel()

	fixture := newTLSFixture(t)
	idConfPath := writeIDConf(t, validIDConf)
	cfg := buildConfig(fixture, idConfPath)
	cfg.Security.BootstrapIssuerCommonName = ""

	_, err := config.Load(writeConfig(t, cfg))
	if err == nil || !strings.Contains(err.Error(), "security.bootstrap_issuer_common_name is required") {
		t.Fatalf("expected bootstrap issuer validation error, got %v", err)
	}
}

func TestLoadConfigRejectsMissingBootstrapIssuerConfig(t *testing.T) {
	t.Parallel()

	fixture := newTLSFixture(t)
	idConfPath := writeIDConf(t, validIDConf)
	cfg := buildConfig(fixture, idConfPath)

	payload, err := json.MarshalIndent(map[string]any{
		"http": map[string]any{
			"bind_address":             cfg.HTTP.BindAddress,
			"port":                     cfg.HTTP.Port,
			"read_timeout_seconds":     cfg.HTTP.ReadTimeoutSeconds,
			"write_timeout_seconds":    cfg.HTTP.WriteTimeoutSeconds,
			"shutdown_timeout_seconds": cfg.HTTP.ShutdownTimeoutSeconds,
		},
		"tls": map[string]any{
			"cert_file":      cfg.TLS.CertFile,
			"key_file":       cfg.TLS.KeyFile,
			"client_ca_file": cfg.TLS.ClientCAFile,
		},
		"policy": map[string]any{
			"id_conf_path": cfg.Policy.IDConfPath,
		},
		"vault_runtime": map[string]any{
			"address":            cfg.VaultRuntime.Address,
			"auth_mount":         cfg.VaultRuntime.AuthMount,
			"auth_role":          cfg.VaultRuntime.AuthRole,
			"jwt_audience":       cfg.VaultRuntime.JWTAudience,
			"expected_spiffe_id": cfg.VaultRuntime.ExpectedSPIFFEID,
			"client_cert_file":   cfg.VaultRuntime.ClientCertFile,
			"client_key_file":    cfg.VaultRuntime.ClientKeyFile,
			"client_ca_file":     cfg.VaultRuntime.ClientCAFile,
			"timeout_seconds":    cfg.VaultRuntime.TimeoutSeconds,
		},
		"security": map[string]any{},
		"action_proof": map[string]any{
			"secret_key":    cfg.ActionProof.SecretKey,
			"hash_function": cfg.ActionProof.HashFunction,
		},
	}, "", "  ")
	if err != nil {
		t.Fatalf("marshal config: %v", err)
	}

	path := filepath.Join(t.TempDir(), "cgs-missing-bootstrap.json")
	if err := os.WriteFile(path, payload, 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	_, err = config.Load(path)
	if err == nil || !strings.Contains(err.Error(), "security.bootstrap_issuer_common_name is required") {
		t.Fatalf("expected bootstrap issuer validation error, got %v", err)
	}
}

func TestNewRejectsDuplicateServiceModuleMapping(t *testing.T) {
	t.Parallel()

	fixture := newTLSFixture(t)
	idConfPath := writeIDConf(t, `
service_id {
  services.execution.ExecutionServer: "execution"
  services.execution.ExecutionServer: "execution"
}
`)
	cfgPath := writeConfig(t, buildConfig(fixture, idConfPath))

	loaded, err := config.Load(cfgPath)
	if err != nil {
		t.Fatalf("load config: %v", err)
	}

	_, err = app.New(loaded)
	if err == nil || !strings.Contains(err.Error(), "duplicate service_id module_path mapping") {
		t.Fatalf("expected duplicate module mapping error, got %v", err)
	}
}

func TestNewRejectsDuplicateServiceIDMapping(t *testing.T) {
	t.Parallel()

	fixture := newTLSFixture(t)
	idConfPath := writeIDConf(t, `
service_id {
  services.execution.ExecutionServer: "execution"
  services.execution.OtherServer: "execution"
}
`)
	cfgPath := writeConfig(t, buildConfig(fixture, idConfPath))

	loaded, err := config.Load(cfgPath)
	if err != nil {
		t.Fatalf("load config: %v", err)
	}

	_, err = app.New(loaded)
	if err == nil || !strings.Contains(err.Error(), "duplicate service_id subject id") {
		t.Fatalf("expected duplicate service id error, got %v", err)
	}
}

func TestNewRejectsDuplicateScriptMapping(t *testing.T) {
	t.Parallel()

	fixture := newTLSFixture(t)
	idConfPath := writeIDConf(t, `
approle {
  scripts.vault.Run: "bot_test_privileged"
  scripts.vault.Run: "bot_test_privileged"
}
`)
	cfgPath := writeConfig(t, buildConfig(fixture, idConfPath))

	loaded, err := config.Load(cfgPath)
	if err != nil {
		t.Fatalf("load config: %v", err)
	}

	_, err = app.New(loaded)
	if err == nil || !strings.Contains(err.Error(), "duplicate approle module_path mapping") {
		t.Fatalf("expected duplicate script mapping error, got %v", err)
	}
}

func TestNewRejectsConflictingDuplicateServiceModuleMapping(t *testing.T) {
	t.Parallel()

	fixture := newTLSFixture(t)
	idConfPath := writeIDConf(t, `
service_id {
  services.execution.ExecutionServer: "execution"
  services.execution.ExecutionServer: "deployment"
}
`)
	cfgPath := writeConfig(t, buildConfig(fixture, idConfPath))

	loaded, err := config.Load(cfgPath)
	if err != nil {
		t.Fatalf("load config: %v", err)
	}

	_, err = app.New(loaded)
	if err == nil || !strings.Contains(err.Error(), "duplicate service_id module_path mapping") {
		t.Fatalf("expected conflicting duplicate module mapping error, got %v", err)
	}
}

func TestAuthorizeAllowsValidServiceWorkload(t *testing.T) {
	fixture := newTLSFixture(t)
	service := startTestApp(t, fixture, validIDConf, nil)

	body := map[string]any{
		"requested_by": map[string]any{
			"component": "execution-service",
			"platform":  "host",
			"user":      "runner",
		},
		"workload": map[string]any{
			"type":                 "service",
			"service_name":         "execution",
			"workload_identity_id": "spiffe://monolith.internal/service/execution",
			"module_path":          "services.execution.ExecutionServer",
			"target_platform":      "docker",
			"description":          "execution",
			"ephemeral":            false,
		},
		"requested_capabilities": []string{"vault:read"},
		"context": map[string]any{
			"run_id":        "run-1",
			"allocation_id": "alloc-1",
		},
	}

	response := doJSONRequest(t, service.Addr(), http.MethodPost, "/v1/credential/authorize", body, fixture.clientTLSConfig(t, "service/execution"))
	defer response.Body.Close()

	if response.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", response.StatusCode)
	}

	var payload struct {
		Allowed                bool   `json:"allowed"`
		RequestID              string `json:"request_id"`
		DecisionID             string `json:"decision_id"`
		CredentialPolicyDigest string `json:"credential_policy_digest"`
		WorkloadVaultDigest    string `json:"workload_vault_digest"`
		WorkloadVaultSource    string `json:"workload_vault_source"`
		RecordProof            string `json:"record_proof"`
		RecordProofExpiresAt   string `json:"record_proof_expires_at"`
		Credential             struct {
			Role       string `json:"role"`
			AuthMethod string `json:"auth_method"`
			AuthPlan   struct {
				WorkloadIdentityID string `json:"workload_identity_id"`
				VaultAddress       string `json:"vault_address"`
				AuthMount          string `json:"auth_mount"`
				AuthRole           string `json:"auth_role"`
				JWTAudience        string `json:"jwt_audience"`
			} `json:"auth_plan"`
			TokenConstraints struct {
				TTLSeconds int  `json:"ttl_seconds"`
				Renewable  bool `json:"renewable"`
			} `json:"token_constraints"`
		} `json:"credential"`
		Constraints struct {
			ForbiddenStages []string `json:"forbidden_stages"`
			ExpiresAt       string   `json:"expires_at"`
		} `json:"constraints"`
		Audit struct {
			DecisionID string   `json:"decision_id"`
			Reasons    []string `json:"reasons"`
		} `json:"audit"`
	}
	if err := json.NewDecoder(response.Body).Decode(&payload); err != nil {
		t.Fatalf("decode response: %v", err)
	}

	if !payload.Allowed {
		t.Fatalf("expected allowed response, got %+v", payload)
	}
	if payload.RequestID == "" || payload.DecisionID == "" {
		t.Fatalf("expected request and decision ids, got %+v", payload)
	}
	if payload.Credential.Role != "worker" || payload.Credential.AuthMethod != "spiffe" {
		t.Fatalf("unexpected credential payload: %+v", payload.Credential)
	}
	if payload.Credential.AuthPlan.WorkloadIdentityID != "spiffe://monolith.internal/service/execution" {
		t.Fatalf("unexpected auth plan workload identity: %+v", payload.Credential.AuthPlan)
	}
	if payload.Credential.AuthPlan.AuthMount != "jwt" || payload.Credential.AuthPlan.AuthRole != "service_execution" {
		t.Fatalf("unexpected auth plan: %+v", payload.Credential.AuthPlan)
	}
	if payload.Credential.TokenConstraints.TTLSeconds != 900 || !payload.Credential.TokenConstraints.Renewable {
		t.Fatalf("unexpected token constraints: %+v", payload.Credential.TokenConstraints)
	}
	if payload.CredentialPolicyDigest == "" || payload.WorkloadVaultDigest == "" {
		t.Fatalf("expected digests, got %+v", payload)
	}
	if payload.WorkloadVaultSource != "startup" {
		t.Fatalf("unexpected workload_vault_source: %q", payload.WorkloadVaultSource)
	}
	if payload.RecordProof == "" || payload.RecordProofExpiresAt == "" {
		t.Fatalf("expected record proof fields, got %+v", payload)
	}
	if len(payload.Constraints.ForbiddenStages) != 1 || payload.Constraints.ForbiddenStages[0] != "bootstrap" {
		t.Fatalf("unexpected constraints: %+v", payload.Constraints)
	}
	if payload.Audit.DecisionID != payload.DecisionID || len(payload.Audit.Reasons) == 0 {
		t.Fatalf("unexpected audit payload: %+v", payload.Audit)
	}

	claims := decodeRecordProofClaims(t, payload.RecordProof)
	assertMinimalRecordProofClaims(t, claims, payload.DecisionID, "spiffe://monolith.internal/service/execution")
}

func TestAuthorizeAllowsScriptWorkload(t *testing.T) {
	fixture := newTLSFixture(t)
	service := startTestApp(t, fixture, validIDConf, nil)

	body := map[string]any{
		"requested_by": map[string]any{
			"component": "execution-service",
			"platform":  "host",
			"user":      "runner",
		},
		"workload": map[string]any{
			"type":                 "script",
			"workload_identity_id": "spiffe://monolith.internal/script/bot_test_privileged",
			"module_path":          "scripts.vault.Run",
			"target_platform":      "docker",
		},
		"requested_capabilities": []string{"vault:read"},
		"context":                map[string]any{},
	}

	response := doJSONRequest(t, service.Addr(), http.MethodPost, "/v1/credential/authorize", body, fixture.clientTLSConfig(t, "script/bot_test_privileged"))
	defer response.Body.Close()

	if response.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", response.StatusCode)
	}

	var payload struct {
		Allowed    bool `json:"allowed"`
		Credential struct {
			AuthPlan struct {
				WorkloadIdentityID string `json:"workload_identity_id"`
			} `json:"auth_plan"`
		} `json:"credential"`
	}
	if err := json.NewDecoder(response.Body).Decode(&payload); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if !payload.Allowed || payload.Credential.AuthPlan.WorkloadIdentityID != "spiffe://monolith.internal/script/bot_test_privileged" {
		t.Fatalf("unexpected payload: %+v", payload)
	}
}

func TestAuthorizeAcceptsRequestedByForWireCompatibilityButIgnoresItForDecision(t *testing.T) {
	fixture := newTLSFixture(t)
	service := startTestApp(t, fixture, validIDConf, nil)

	body := map[string]any{
		"requested_by": map[string]any{
			"component": "unexpected-component",
			"platform":  "weird-platform",
			"user":      "not-trusted",
		},
		"workload": map[string]any{
			"type":                 "service",
			"service_name":         "execution",
			"workload_identity_id": "spiffe://monolith.internal/service/execution",
			"module_path":          "services.execution.ExecutionServer",
			"target_platform":      "docker",
		},
		"requested_capabilities": []string{"vault:read"},
		"context":                map[string]any{},
	}

	response := doJSONRequest(t, service.Addr(), http.MethodPost, "/v1/credential/authorize", body, fixture.clientTLSConfig(t, "service/execution"))
	defer response.Body.Close()

	if response.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", response.StatusCode)
	}

	var payload struct {
		Allowed bool `json:"allowed"`
	}
	if err := json.NewDecoder(response.Body).Decode(&payload); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if !payload.Allowed {
		t.Fatalf("expected requested_by to be accepted for compatibility, got %+v", payload)
	}
}

func TestAuthorizeRejectsUnsupportedRequestedCapabilities(t *testing.T) {
	fixture := newTLSFixture(t)
	service := startTestApp(t, fixture, validIDConf, nil)

	body := map[string]any{
		"requested_by": map[string]any{
			"component": "execution-service",
			"platform":  "host",
			"user":      "runner",
		},
		"workload": map[string]any{
			"type":                 "service",
			"service_name":         "execution",
			"workload_identity_id": "spiffe://monolith.internal/service/execution",
			"module_path":          "services.execution.ExecutionServer",
			"target_platform":      "docker",
		},
		"requested_capabilities": []string{"vault:write"},
		"context":                map[string]any{},
	}

	response := doJSONRequest(t, service.Addr(), http.MethodPost, "/v1/credential/authorize", body, fixture.clientTLSConfig(t, "service/execution"))
	defer response.Body.Close()

	if response.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", response.StatusCode)
	}

	assertErrorPayload(t, response, "requested_capabilities contains unsupported capability: vault:write")
}

func TestAuthorizeDeniesUnknownServiceWithStructuredResponse(t *testing.T) {
	fixture := newTLSFixture(t)
	service := startTestApp(t, fixture, validIDConf, nil)

	body := map[string]any{
		"requested_by": map[string]any{
			"component": "execution-service",
			"platform":  "host",
			"user":      "runner",
		},
		"workload": map[string]any{
			"type":                 "service",
			"workload_identity_id": "spiffe://monolith.internal/service/unknown",
			"module_path":          "services.unknown.Server",
			"target_platform":      "docker",
		},
		"requested_capabilities": []string{"vault:read"},
		"context":                map[string]any{},
	}

	response := doJSONRequest(t, service.Addr(), http.MethodPost, "/v1/credential/authorize", body, fixture.clientTLSConfig(t, "service/unknown"))
	defer response.Body.Close()

	if response.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", response.StatusCode)
	}

	var payload struct {
		Allowed    bool `json:"allowed"`
		Credential any  `json:"credential"`
		Reason     struct {
			Code    string `json:"code"`
			Message string `json:"message"`
		} `json:"reason"`
		Audit struct {
			Reasons []string `json:"reasons"`
		} `json:"audit"`
	}
	if err := json.NewDecoder(response.Body).Decode(&payload); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if payload.Allowed {
		t.Fatalf("expected deny response, got %+v", payload)
	}
	if payload.Credential != nil {
		t.Fatalf("expected denied response without credential, got %+v", payload)
	}
	if payload.Reason.Code != "EVALUATION_FAILED" || payload.Reason.Message == "" {
		t.Fatalf("unexpected denial reason: %+v", payload.Reason)
	}
	if len(payload.Audit.Reasons) == 0 {
		t.Fatalf("expected audit reasons, got %+v", payload.Audit)
	}
}

func TestAuthorizeRejectsMissingWorkloadIdentityID(t *testing.T) {
	fixture := newTLSFixture(t)
	service := startTestApp(t, fixture, validIDConf, nil)

	body := map[string]any{
		"requested_by": map[string]any{
			"component": "execution-service",
			"platform":  "host",
			"user":      "runner",
		},
		"workload": map[string]any{
			"type":            "service",
			"service_name":    "execution",
			"module_path":     "services.execution.ExecutionServer",
			"target_platform": "docker",
		},
		"requested_capabilities": []string{"vault:read"},
		"context":                map[string]any{},
	}

	response := doJSONRequest(t, service.Addr(), http.MethodPost, "/v1/credential/authorize", body, fixture.clientTLSConfig(t, "service/execution"))
	defer response.Body.Close()

	if response.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", response.StatusCode)
	}

	assertErrorPayload(t, response, "workload.workload_identity_id is required")
}

func TestAuthorizeRejectsInvalidDescriptorShape(t *testing.T) {
	fixture := newTLSFixture(t)
	service := startTestApp(t, fixture, validIDConf, nil)

	body := map[string]any{
		"requested_by": map[string]any{
			"component": "execution-service",
			"platform":  "host",
			"user":      "runner",
		},
		"workload": map[string]any{
			"type":                 "service",
			"service_name":         "deployment",
			"workload_identity_id": "spiffe://monolith.internal/service/deployment",
			"module_path":          "services.execution.ExecutionServer",
			"target_platform":      "docker",
		},
		"requested_capabilities": []string{"vault:read"},
		"context":                map[string]any{},
	}

	response := doJSONRequest(t, service.Addr(), http.MethodPost, "/v1/credential/authorize", body, fixture.clientTLSConfig(t, "service/deployment"))
	defer response.Body.Close()

	if response.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", response.StatusCode)
	}

	assertErrorPayload(t, response, "workload.service_name does not match module_path")
}

func TestAuthorizeRejectsMalformedJSON(t *testing.T) {
	fixture := newTLSFixture(t)
	service := startTestApp(t, fixture, validIDConf, nil)

	response := doRawRequest(t, service.Addr(), http.MethodPost, "/v1/credential/authorize", []byte("{"), fixture.clientTLSConfig(t, "service/execution"), "application/json")
	defer response.Body.Close()

	if response.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", response.StatusCode)
	}

	assertErrorPayload(t, response, "malformed JSON request body")
}

func TestAuthorizeWithoutClientCertReturnsUnauthorized(t *testing.T) {
	fixture := newTLSFixture(t)
	service := startTestApp(t, fixture, validIDConf, nil)

	response := doJSONRequest(t, service.Addr(), http.MethodPost, "/v1/credential/authorize", map[string]any{}, fixture.baseClientTLSConfig(t))
	defer response.Body.Close()

	if response.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", response.StatusCode)
	}
	if body := string(mustReadBody(t, response.Body)); body != "Authenticated caller identity required" {
		t.Fatalf("unexpected 401 body: %q", body)
	}
}

func TestAuthorizeRejectsCallerMismatch(t *testing.T) {
	fixture := newTLSFixture(t)
	service := startTestApp(t, fixture, validIDConf, nil)

	body := map[string]any{
		"requested_by": map[string]any{
			"component": "execution-service",
			"platform":  "host",
			"user":      "runner",
		},
		"workload": map[string]any{
			"type":                 "service",
			"service_name":         "execution",
			"workload_identity_id": "spiffe://monolith.internal/service/execution",
			"module_path":          "services.execution.ExecutionServer",
			"target_platform":      "docker",
		},
		"requested_capabilities": []string{"vault:read"},
		"context":                map[string]any{},
	}

	response := doJSONRequest(t, service.Addr(), http.MethodPost, "/v1/credential/authorize", body, fixture.clientTLSConfig(t, "service/deployment"))
	defer response.Body.Close()

	if response.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", response.StatusCode)
	}
	if body := string(mustReadBody(t, response.Body)); body != "Authenticated caller does not match requested workload principal" {
		t.Fatalf("unexpected 403 body: %q", body)
	}
}

func TestAuthorizeRejectsCallerMismatchWithValidModulePath(t *testing.T) {
	fixture := newTLSFixture(t)
	service := startTestApp(t, fixture, validIDConf, nil)

	body := map[string]any{
		"requested_by": map[string]any{
			"component": "execution-service",
			"platform":  "host",
			"user":      "runner",
		},
		"workload": map[string]any{
			"type":                 "service",
			"workload_identity_id": "spiffe://monolith.internal/service/deployment",
			"module_path":          "services.execution.ExecutionServer",
			"target_platform":      "docker",
		},
		"requested_capabilities": []string{"vault:read"},
		"context":                map[string]any{},
	}

	response := doJSONRequest(t, service.Addr(), http.MethodPost, "/v1/credential/authorize", body, fixture.clientTLSConfig(t, "service/deployment"))
	defer response.Body.Close()

	if response.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", response.StatusCode)
	}
	if body := string(mustReadBody(t, response.Body)); body != "Authenticated caller does not match workload descriptor subject" {
		t.Fatalf("unexpected 403 body: %q", body)
	}
}

func TestAuthorizeRejectsCallerMismatchWithValidServiceName(t *testing.T) {
	fixture := newTLSFixture(t)
	service := startTestApp(t, fixture, validIDConf, nil)

	body := map[string]any{
		"requested_by": map[string]any{
			"component": "execution-service",
			"platform":  "host",
			"user":      "runner",
		},
		"workload": map[string]any{
			"type":                 "service",
			"service_name":         "execution",
			"workload_identity_id": "spiffe://monolith.internal/service/deployment",
			"module_path":          "services.execution.ExecutionServer",
			"target_platform":      "docker",
		},
		"requested_capabilities": []string{"vault:read"},
		"context":                map[string]any{},
	}

	response := doJSONRequest(t, service.Addr(), http.MethodPost, "/v1/credential/authorize", body, fixture.clientTLSConfig(t, "service/deployment"))
	defer response.Body.Close()

	if response.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", response.StatusCode)
	}
	if body := string(mustReadBody(t, response.Body)); body != "Authenticated caller does not match workload descriptor subject" {
		t.Fatalf("unexpected 403 body: %q", body)
	}
}

func TestAuthorizeRejectsCallerMismatchWithValidScriptPath(t *testing.T) {
	fixture := newTLSFixture(t)
	service := startTestApp(t, fixture, validIDConf, nil)

	body := map[string]any{
		"requested_by": map[string]any{
			"component": "execution-service",
			"platform":  "host",
			"user":      "runner",
		},
		"workload": map[string]any{
			"type":                 "script",
			"workload_identity_id": "spiffe://monolith.internal/service/deployment",
			"module_path":          "scripts.vault.Run",
			"target_platform":      "docker",
		},
		"requested_capabilities": []string{"vault:read"},
		"context":                map[string]any{},
	}

	response := doJSONRequest(t, service.Addr(), http.MethodPost, "/v1/credential/authorize", body, fixture.clientTLSConfig(t, "service/deployment"))
	defer response.Body.Close()

	if response.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", response.StatusCode)
	}
	if body := string(mustReadBody(t, response.Body)); body != "Authenticated caller does not match workload descriptor subject" {
		t.Fatalf("unexpected 403 body: %q", body)
	}
}

func TestAuthorizeRejectsBootstrapPKICaller(t *testing.T) {
	fixture := newTLSFixture(t)
	service := startTestApp(t, fixture, validIDConf, nil)

	body := map[string]any{
		"requested_by": map[string]any{
			"component": "execution-service",
			"platform":  "host",
			"user":      "runner",
		},
		"workload": map[string]any{
			"type":                 "service",
			"service_name":         "execution",
			"workload_identity_id": "spiffe://monolith.internal/service/execution",
			"module_path":          "services.execution.ExecutionServer",
			"target_platform":      "docker",
		},
		"requested_capabilities": []string{"vault:read"},
		"context":                map[string]any{},
	}

	response := doJSONRequest(t, service.Addr(), http.MethodPost, "/v1/credential/authorize", body, fixture.bootstrapClientTLSConfig(t, "service/execution"))
	defer response.Body.Close()

	if response.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", response.StatusCode)
	}
	if body := string(mustReadBody(t, response.Body)); body != "Bootstrap PKI callers are not accepted; use a SPIRE-issued identity" {
		t.Fatalf("unexpected bootstrap 403 body: %q", body)
	}
}

func TestAuthorizeReturnsInternalServerErrorWhenProofMintingFails(t *testing.T) {
	fixture := newTLSFixture(t)
	service := startTestApp(t, fixture, validIDConf, &failingMinter{err: errors.New("boom")})

	body := map[string]any{
		"requested_by": map[string]any{
			"component": "execution-service",
			"platform":  "host",
			"user":      "runner",
		},
		"workload": map[string]any{
			"type":                 "service",
			"service_name":         "execution",
			"workload_identity_id": "spiffe://monolith.internal/service/execution",
			"module_path":          "services.execution.ExecutionServer",
			"target_platform":      "docker",
		},
		"requested_capabilities": []string{"vault:read"},
		"context":                map[string]any{},
	}

	response := doJSONRequest(t, service.Addr(), http.MethodPost, "/v1/credential/authorize", body, fixture.clientTLSConfig(t, "service/execution"))
	defer response.Body.Close()

	if response.StatusCode != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d", response.StatusCode)
	}
	assertErrorPayload(t, response, "failed to mint record proof")
}

type failingMinter struct {
	err error
}

func (f *failingMinter) MintRecordProof(proof.Input) (proof.MintedProof, error) {
	return proof.MintedProof{}, f.err
}

const validIDConf = `
service_id {
  services.catalog.ArtifactCatalogServer: "artifact-catalog"
  services.governance.CredentialGovernanceServer: "credential-governance"
  services.deployment.DeploymentServer: "deployment"
  services.execution.ExecutionServer: "execution"
}

approle {
  scripts.vault.Run: "bot_test_privileged"
}
`

type tlsFixture struct {
	serverTrustPath     string
	serverCertPath      string
	serverKeyPath       string
	vaultClientCertPath string
	vaultClientKeyPath  string
	vaultClientCAPath   string
	normalCACert        *x509.Certificate
	normalCAKey         *rsa.PrivateKey
	bootstrapCACert     *x509.Certificate
	bootstrapCAKey      *rsa.PrivateKey
	bootstrapBundlePath string
}

func newTLSFixture(t *testing.T) tlsFixture {
	t.Helper()

	dir := t.TempDir()

	normalCACert, normalCAKey, normalCAPEM := createCertificateAuthority(t, "Monolith Runtime CA")
	bootstrapCACert, bootstrapCAKey, bootstrapCAPEM := createCertificateAuthority(t, "Monolith Bootstrap CA (monolith.internal)")

	serverCertPEM, serverKeyPEM := createLeafCertificate(t, normalCACert, normalCAKey, certificateRequest{
		commonName: "credential-governance.internal",
		dnsNames:   []string{"localhost"},
		ipAddrs:    []net.IP{net.ParseIP("127.0.0.1")},
	})
	vaultCertPEM, vaultKeyPEM := createLeafCertificate(t, normalCACert, normalCAKey, certificateRequest{
		commonName: "vault-client",
		uris:       []string{"spiffe://monolith.internal/service/credential-governance"},
		clientAuth: true,
	})

	bundlePath := filepath.Join(dir, "client-ca-bundle.pem")
	writePEMFile(t, bundlePath, append(normalCAPEM, bootstrapCAPEM...))

	fixture := tlsFixture{
		serverTrustPath:     bundlePath,
		serverCertPath:      filepath.Join(dir, "server.pem"),
		serverKeyPath:       filepath.Join(dir, "server.key"),
		vaultClientCertPath: filepath.Join(dir, "vault-client.pem"),
		vaultClientKeyPath:  filepath.Join(dir, "vault-client.key"),
		vaultClientCAPath:   filepath.Join(dir, "vault-client-ca.pem"),
		normalCACert:        normalCACert,
		normalCAKey:         normalCAKey,
		bootstrapCACert:     bootstrapCACert,
		bootstrapCAKey:      bootstrapCAKey,
		bootstrapBundlePath: bundlePath,
	}

	writePEMFile(t, fixture.serverCertPath, serverCertPEM)
	writePEMFile(t, fixture.serverKeyPath, serverKeyPEM)
	writePEMFile(t, fixture.vaultClientCertPath, vaultCertPEM)
	writePEMFile(t, fixture.vaultClientKeyPath, vaultKeyPEM)
	writePEMFile(t, fixture.vaultClientCAPath, normalCAPEM)

	return fixture
}

func buildConfig(fixture tlsFixture, idConfPath string) config.Config {
	return config.Config{
		HTTP: config.HTTPConfig{
			BindAddress:            "127.0.0.1",
			Port:                   0,
			ReadTimeoutSeconds:     5,
			WriteTimeoutSeconds:    5,
			ShutdownTimeoutSeconds: 5,
		},
		TLS: config.TLSConfig{
			CertFile:     fixture.serverCertPath,
			KeyFile:      fixture.serverKeyPath,
			ClientCAFile: fixture.serverTrustPath,
		},
		Policy: config.PolicyConfig{
			IDConfPath: idConfPath,
		},
		VaultRuntime: config.VaultRuntimeConfig{
			Address:          "https://vault.internal:8200",
			AuthMount:        "jwt",
			AuthRole:         "service_execution",
			JWTAudience:      "vault",
			ExpectedSPIFFEID: "spiffe://monolith.internal/infrastructure/vault",
			ClientCertFile:   fixture.vaultClientCertPath,
			ClientKeyFile:    fixture.vaultClientKeyPath,
			ClientCAFile:     fixture.vaultClientCAPath,
			TimeoutSeconds:   30,
		},
		Security: config.SecurityConfig{
			BootstrapIssuerCommonName: "Monolith Bootstrap CA (monolith.internal)",
		},
		ActionProof: config.ActionProofConfig{
			SecretKey:    "integration-test-secret-key",
			HashFunction: "sha256",
		},
	}
}

func writeConfig(t *testing.T, cfg config.Config) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "cgs.json")
	payload, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		t.Fatalf("marshal config: %v", err)
	}
	if err := os.WriteFile(path, payload, 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	return path
}

func writeIDConf(t *testing.T, contents string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "id.conf")
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatalf("write id.conf: %v", err)
	}
	return path
}

func startTestApp(t *testing.T, fixture tlsFixture, idConfContents string, minter proof.Minter) *app.App {
	t.Helper()

	cfgPath := writeConfig(t, buildConfig(fixture, writeIDConf(t, idConfContents)))
	cfg, err := config.Load(cfgPath)
	if err != nil {
		t.Fatalf("load config: %v", err)
	}

	service, err := app.NewWithDependencies(cfg, app.Dependencies{ProofMinter: minter})
	if err != nil {
		t.Fatalf("build app: %v", err)
	}

	if _, err := service.Start(context.Background()); err != nil {
		t.Fatalf("start app: %v", err)
	}

	waitForAuthorizeReady(t, service.Addr(), fixture.clientTLSConfig(t, "service/execution"))
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := service.Shutdown(ctx); err != nil {
			t.Fatalf("shutdown app: %v", err)
		}
	})

	return service
}

func waitForAuthorizeReady(t *testing.T, addr string, tlsConfig *tls.Config) {
	t.Helper()

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		response, err := doRequestRaw(addr, http.MethodPost, "/v1/credential/authorize", []byte("{"), tlsConfig, "application/json")
		if err == nil {
			_ = response.Body.Close()
			return
		}
		time.Sleep(25 * time.Millisecond)
	}

	t.Fatalf("authorize endpoint did not become ready at %s", addr)
}

func (f tlsFixture) baseClientTLSConfig(t *testing.T) *tls.Config {
	t.Helper()

	pool := x509.NewCertPool()
	pemBytes, err := os.ReadFile(f.serverTrustPath)
	if err != nil {
		t.Fatalf("read server trust bundle: %v", err)
	}
	if !pool.AppendCertsFromPEM(pemBytes) {
		t.Fatal("append trust bundle: no valid certificates found")
	}

	return &tls.Config{
		RootCAs:    pool,
		ServerName: "localhost",
		MinVersion: tls.VersionTLS12,
	}
}

func (f tlsFixture) clientTLSConfig(t *testing.T, spiffePath string) *tls.Config {
	t.Helper()
	return f.clientTLSConfigWithCA(t, spiffePath, f.normalCACert, f.normalCAKey)
}

func (f tlsFixture) bootstrapClientTLSConfig(t *testing.T, spiffePath string) *tls.Config {
	t.Helper()
	return f.clientTLSConfigWithCA(t, spiffePath, f.bootstrapCACert, f.bootstrapCAKey)
}

func (f tlsFixture) clientTLSConfigWithCA(t *testing.T, spiffePath string, caCert *x509.Certificate, caKey *rsa.PrivateKey) *tls.Config {
	t.Helper()

	certPEM, keyPEM := createLeafCertificate(t, caCert, caKey, certificateRequest{
		commonName: "client",
		uris:       []string{"spiffe://monolith.internal/" + spiffePath},
		clientAuth: true,
	})

	certificate, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatalf("load client key pair: %v", err)
	}

	cfg := f.baseClientTLSConfig(t)
	cfg.Certificates = []tls.Certificate{certificate}
	return cfg
}

func doJSONRequest(t *testing.T, addr string, method string, path string, body any, tlsConfig *tls.Config) *http.Response {
	t.Helper()

	payload, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal request body: %v", err)
	}
	return doRawRequest(t, addr, method, path, payload, tlsConfig, "application/json")
}

func doRawRequest(t *testing.T, addr string, method string, path string, body []byte, tlsConfig *tls.Config, contentType string) *http.Response {
	t.Helper()

	response, err := doRequestRaw(addr, method, path, body, tlsConfig, contentType)
	if err != nil {
		t.Fatalf("perform request: %v", err)
	}
	return response
}

func doRequestRaw(addr string, method string, path string, body []byte, tlsConfig *tls.Config, contentType string) (*http.Response, error) {
	transport := &http.Transport{
		TLSClientConfig: tlsConfig,
	}
	client := &http.Client{
		Transport: transport,
		Timeout:   5 * time.Second,
	}

	request, err := http.NewRequest(method, "https://"+addr+path, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	if contentType != "" {
		request.Header.Set("Content-Type", contentType)
	}

	return client.Do(request)
}

func assertErrorPayload(t *testing.T, response *http.Response, expected string) {
	t.Helper()

	var payload struct {
		Success bool   `json:"success"`
		Error   string `json:"error"`
	}
	if err := json.NewDecoder(response.Body).Decode(&payload); err != nil {
		t.Fatalf("decode error payload: %v", err)
	}
	if payload.Success {
		t.Fatalf("expected success=false, got %+v", payload)
	}
	if payload.Error != expected {
		t.Fatalf("unexpected error payload: %+v", payload)
	}
}

func decodeRecordProofClaims(t *testing.T, token string) map[string]any {
	t.Helper()

	parts := strings.Split(token, ".")
	if len(parts) != 2 {
		t.Fatalf("unexpected record_proof format: %q", token)
	}

	payload, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		t.Fatalf("decode proof payload: %v", err)
	}

	var claims map[string]any
	if err := json.Unmarshal(payload, &claims); err != nil {
		t.Fatalf("unmarshal proof payload: %v", err)
	}
	return claims
}

func assertMinimalRecordProofClaims(t *testing.T, claims map[string]any, decisionID string, workloadIdentityID string) {
	t.Helper()

	if got := claims["version"]; got != float64(1) {
		t.Fatalf("unexpected proof version: %#v", got)
	}
	if got := claims["purpose"]; got != "record" {
		t.Fatalf("unexpected proof purpose: %#v", got)
	}
	if got := claims["decision_id"]; got != decisionID {
		t.Fatalf("unexpected proof decision_id: %#v", got)
	}
	if got := claims["caller_identity_id"]; got != workloadIdentityID {
		t.Fatalf("unexpected proof caller_identity_id: %#v", got)
	}
	if got := claims["workload_identity_id"]; got != workloadIdentityID {
		t.Fatalf("unexpected proof workload_identity_id: %#v", got)
	}
	if _, ok := claims["issued_at"]; !ok {
		t.Fatalf("expected issued_at in proof claims: %+v", claims)
	}
	if _, ok := claims["expires_at"]; !ok {
		t.Fatalf("expected expires_at in proof claims: %+v", claims)
	}
	if got := claims["jti"]; got == "" || got == nil {
		t.Fatalf("expected non-empty jti in proof claims: %+v", claims)
	}
	if _, ok := claims["run_id"]; ok {
		t.Fatalf("expected run_id to be absent from minimal proof claims: %+v", claims)
	}
	if _, ok := claims["allocation_id"]; ok {
		t.Fatalf("expected allocation_id to be absent from minimal proof claims: %+v", claims)
	}
}

func mustReadBody(t *testing.T, body io.ReadCloser) []byte {
	t.Helper()
	data, err := io.ReadAll(body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	return data
}

type certificateRequest struct {
	commonName string
	dnsNames   []string
	ipAddrs    []net.IP
	uris       []string
	clientAuth bool
}

func createCertificateAuthority(t *testing.T, commonName string) (*x509.Certificate, *rsa.PrivateKey, []byte) {
	t.Helper()

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate CA key: %v", err)
	}

	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		t.Fatalf("generate CA serial: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName: commonName,
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	if err != nil {
		t.Fatalf("create CA certificate: %v", err)
	}

	cert, err := x509.ParseCertificate(derBytes)
	if err != nil {
		t.Fatalf("parse CA certificate: %v", err)
	}

	return cert, privateKey, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
}

func createLeafCertificate(t *testing.T, caCert *x509.Certificate, caKey *rsa.PrivateKey, request certificateRequest) ([]byte, []byte) {
	t.Helper()

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate leaf key: %v", err)
	}

	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		t.Fatalf("generate leaf serial: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName: request.commonName,
		},
		NotBefore:   time.Now().Add(-1 * time.Hour),
		NotAfter:    time.Now().Add(24 * time.Hour),
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		DNSNames:    append([]string(nil), request.dnsNames...),
		IPAddresses: append([]net.IP(nil), request.ipAddrs...),
	}

	for _, value := range request.uris {
		uri, err := url.Parse(value)
		if err != nil {
			t.Fatalf("parse uri %q: %v", value, err)
		}
		template.URIs = append(template.URIs, uri)
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, template, caCert, &privateKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("create leaf certificate: %v", err)
	}

	keyBytes := x509.MarshalPKCS1PrivateKey(privateKey)
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes}),
		pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: keyBytes})
}

func writePEMFile(t *testing.T, path string, pemBytes []byte) {
	t.Helper()
	if err := os.WriteFile(path, pemBytes, 0o600); err != nil {
		t.Fatalf("write pem file: %v", err)
	}
}
