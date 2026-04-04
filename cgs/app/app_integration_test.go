package app_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"execution-platform/cgs/app"
	"execution-platform/cgs/config"
	"execution-platform/cgs/policy"
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
	idConfPath := writeIDConf(t, checkedInIDConfContents(t))
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
	idConfPath := writeIDConf(t, "subject \"execution\" {\ninvalid-line\n}\n")
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

func TestLoadConfigRejectsRemovedCompatibilityConfigGroups(t *testing.T) {
	t.Parallel()

	fixture := newTLSFixture(t)
	idConfPath := writeIDConf(t, checkedInIDConfContents(t))
	payload, err := json.MarshalIndent(map[string]any{
		"http": map[string]any{
			"bind_address":             "127.0.0.1",
			"port":                     0,
			"read_timeout_seconds":     5,
			"write_timeout_seconds":    5,
			"shutdown_timeout_seconds": 5,
		},
		"tls": map[string]any{
			"cert_file":      fixture.serverCertPath,
			"key_file":       fixture.serverKeyPath,
			"client_ca_file": fixture.serverTrustPath,
		},
		"policy": map[string]any{
			"id_conf_path": idConfPath,
		},
		"security": map[string]any{
			"bootstrap_issuer_common_name": "Bootstrap SPIFFE Test CA",
		},
		"vault_runtime": map[string]any{
			"address": "https://vault.internal:8200",
		},
	}, "", "  ")
	if err != nil {
		t.Fatalf("marshal config: %v", err)
	}

	path := filepath.Join(t.TempDir(), "cgs-removed-groups.json")
	if err := os.WriteFile(path, payload, 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	_, err = config.Load(path)
	if err == nil || !strings.Contains(err.Error(), "unknown field \"vault_runtime\"") {
		t.Fatalf("expected removed-group validation error, got %v", err)
	}
}

func TestLoadConfigRejectsBlankBootstrapIssuerConfig(t *testing.T) {
	t.Parallel()

	fixture := newTLSFixture(t)
	idConfPath := writeIDConf(t, checkedInIDConfContents(t))
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
	idConfPath := writeIDConf(t, checkedInIDConfContents(t))
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
		"security": map[string]any{},
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

func TestNewRejectsDuplicateSubject(t *testing.T) {
	t.Parallel()

	fixture := newTLSFixture(t)
	idConfPath := writeIDConf(t, `
subject "execution" {
  type: "service"
  principal: "spiffe://monolith.internal/service/execution"
  role: "worker"
}
subject "execution" {
  type: "service"
  principal: "spiffe://monolith.internal/service/execution"
  role: "worker"
}
`)
	cfgPath := writeConfig(t, buildConfig(fixture, idConfPath))

	loaded, err := config.Load(cfgPath)
	if err != nil {
		t.Fatalf("load config: %v", err)
	}

	_, err = app.New(loaded)
	if err == nil || !strings.Contains(err.Error(), "duplicate subject service execution") {
		t.Fatalf("expected duplicate subject error, got %v", err)
	}
}

func TestNewRejectsInvalidSubjectType(t *testing.T) {
	t.Parallel()

	fixture := newTLSFixture(t)
	idConfPath := writeIDConf(t, `
subject "other" {
  type: "job"
  principal: "spiffe://monolith.internal/service/other"
  role: "worker"
}
`)
	cfgPath := writeConfig(t, buildConfig(fixture, idConfPath))

	loaded, err := config.Load(cfgPath)
	if err != nil {
		t.Fatalf("load config: %v", err)
	}

	_, err = app.New(loaded)
	if err == nil || !strings.Contains(err.Error(), "invalid type") {
		t.Fatalf("expected invalid subject type error, got %v", err)
	}
}

func TestNewRejectsSubjectPrincipalMismatch(t *testing.T) {
	t.Parallel()

	fixture := newTLSFixture(t)
	idConfPath := writeIDConf(t, `
subject "execution" {
  type: "service"
  principal: "spiffe://monolith.internal/service/deployment"
  role: "worker"
}
`)
	cfgPath := writeConfig(t, buildConfig(fixture, idConfPath))

	loaded, err := config.Load(cfgPath)
	if err != nil {
		t.Fatalf("load config: %v", err)
	}

	_, err = app.New(loaded)
	if err == nil || !strings.Contains(err.Error(), "principal does not match declared subject") {
		t.Fatalf("expected subject principal mismatch error, got %v", err)
	}
}

func TestNewRejectsUnsupportedSubjectField(t *testing.T) {
	t.Parallel()

	fixture := newTLSFixture(t)
	idConfPath := writeIDConf(t, `
subject "execution" {
  type: "service"
  principal: "spiffe://monolith.internal/service/execution"
  module_path: "services.execution.ExecutionServer"
  role: "worker"
}
`)
	cfgPath := writeConfig(t, buildConfig(fixture, idConfPath))

	loaded, err := config.Load(cfgPath)
	if err != nil {
		t.Fatalf("load config: %v", err)
	}

	_, err = app.New(loaded)
	if err == nil || !strings.Contains(err.Error(), "unsupported subject field module_path") {
		t.Fatalf("expected unsupported subject field error, got %v", err)
	}
}

func TestAuthorizeAllowsValidServiceWorkload(t *testing.T) {
	fixture := newTLSFixture(t)
	service := startTestApp(t, fixture, checkedInIDConfContents(t))

	body := map[string]any{
		"workload": map[string]any{
			"type":                 "service",
			"workload_identity_id": "spiffe://monolith.internal/service/execution",
		},
		"requested_capabilities": []string{"vault:read"},
	}

	response := doJSONRequest(t, service.Addr(), http.MethodPost, "/v1/credential/authorize", body, fixture.clientTLSConfig(t, "service/execution"))
	defer response.Body.Close()

	if response.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", response.StatusCode)
	}

	var payload map[string]any
	if err := json.NewDecoder(response.Body).Decode(&payload); err != nil {
		t.Fatalf("decode response: %v", err)
	}

	if allowed, _ := payload["allowed"].(bool); !allowed {
		t.Fatalf("expected allowed response, got %+v", payload)
	}
	requestID, _ := payload["request_id"].(string)
	decisionID, _ := payload["decision_id"].(string)
	if requestID == "" || decisionID == "" {
		t.Fatalf("expected request and decision ids, got %+v", payload)
	}
	decision, ok := payload["decision"].(map[string]any)
	if !ok {
		t.Fatalf("expected decision payload, got %+v", payload)
	}
	if role, _ := decision["role"].(string); role != "worker" {
		t.Fatalf("unexpected decision role: %+v", decision)
	}
	constraints, ok := decision["constraints"].(map[string]any)
	if !ok {
		t.Fatalf("expected decision constraints, got %+v", decision)
	}
	forbiddenStages, ok := constraints["forbidden_stages"].([]any)
	if !ok || len(forbiddenStages) != 1 || forbiddenStages[0] != "bootstrap" {
		t.Fatalf("unexpected constraints: %+v", constraints)
	}
	audit, ok := payload["audit"].(map[string]any)
	if !ok {
		t.Fatalf("expected audit payload, got %+v", payload)
	}
	if got, _ := audit["decision_id"].(string); got != decisionID {
		t.Fatalf("unexpected audit decision id: %+v", audit)
	}
	reasons, ok := audit["reasons"].([]any)
	if !ok || len(reasons) == 0 {
		t.Fatalf("unexpected audit payload: %+v", audit)
	}
	for _, removed := range []string{"credential", "constraints", "credential_policy_digest", "workload_vault_digest", "workload_vault_source", "record_proof", "record_proof_expires_at"} {
		if _, exists := payload[removed]; exists {
			t.Fatalf("expected %s to be absent from core response: %+v", removed, payload)
		}
	}
}

func TestAuthorizeAllowsScriptWorkload(t *testing.T) {
	fixture := newTLSFixture(t)
	service := startTestApp(t, fixture, checkedInIDConfContents(t))

	body := map[string]any{
		"workload": map[string]any{
			"type":                 "script",
			"workload_identity_id": "spiffe://monolith.internal/script/bot_test_privileged",
		},
		"requested_capabilities": []string{"vault:read"},
	}

	response := doJSONRequest(t, service.Addr(), http.MethodPost, "/v1/credential/authorize", body, fixture.clientTLSConfig(t, "script/bot_test_privileged"))
	defer response.Body.Close()

	if response.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", response.StatusCode)
	}

	var payload struct {
		Allowed  bool `json:"allowed"`
		Decision struct {
			Role string `json:"role"`
		} `json:"decision"`
	}
	if err := json.NewDecoder(response.Body).Decode(&payload); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if !payload.Allowed || payload.Decision.Role != "worker" {
		t.Fatalf("unexpected payload: %+v", payload)
	}
}

func TestAuthorizeRejectsRemovedRequestedByField(t *testing.T) {
	fixture := newTLSFixture(t)
	service := startTestApp(t, fixture, checkedInIDConfContents(t))

	body := map[string]any{
		"requested_by": map[string]any{
			"component": "unexpected-component",
			"platform":  "weird-platform",
			"user":      "not-trusted",
		},
		"workload": map[string]any{
			"type":                 "service",
			"workload_identity_id": "spiffe://monolith.internal/service/execution",
		},
		"requested_capabilities": []string{"vault:read"},
	}

	response := doJSONRequest(t, service.Addr(), http.MethodPost, "/v1/credential/authorize", body, fixture.clientTLSConfig(t, "service/execution"))
	defer response.Body.Close()

	if response.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", response.StatusCode)
	}
	assertErrorPayload(t, response, "malformed JSON request body")
}

func TestAuthorizeRejectsUnsupportedRequestedCapabilities(t *testing.T) {
	fixture := newTLSFixture(t)
	service := startTestApp(t, fixture, checkedInIDConfContents(t))

	body := map[string]any{
		"workload": map[string]any{
			"type":                 "service",
			"workload_identity_id": "spiffe://monolith.internal/service/execution",
		},
		"requested_capabilities": []string{"vault:write"},
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
	service := startTestApp(t, fixture, checkedInIDConfContents(t))

	body := map[string]any{
		"workload": map[string]any{
			"type":                 "service",
			"workload_identity_id": "spiffe://monolith.internal/service/unknown",
		},
		"requested_capabilities": []string{"vault:read"},
	}

	response := doJSONRequest(t, service.Addr(), http.MethodPost, "/v1/credential/authorize", body, fixture.clientTLSConfig(t, "service/unknown"))
	defer response.Body.Close()

	if response.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", response.StatusCode)
	}

	var payload struct {
		Allowed  bool `json:"allowed"`
		Decision any  `json:"decision"`
		Reason   struct {
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
	if payload.Decision != nil {
		t.Fatalf("expected denied response without decision payload, got %+v", payload)
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
	service := startTestApp(t, fixture, checkedInIDConfContents(t))

	body := map[string]any{
		"workload": map[string]any{
			"type": "service",
		},
		"requested_capabilities": []string{"vault:read"},
	}

	response := doJSONRequest(t, service.Addr(), http.MethodPost, "/v1/credential/authorize", body, fixture.clientTLSConfig(t, "service/execution"))
	defer response.Body.Close()

	if response.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", response.StatusCode)
	}

	assertErrorPayload(t, response, "workload.workload_identity_id is required")
}

func TestAuthorizeRejectsRemovedDescriptorConvenienceFields(t *testing.T) {
	fixture := newTLSFixture(t)
	service := startTestApp(t, fixture, checkedInIDConfContents(t))

	body := map[string]any{
		"workload": map[string]any{
			"type":                 "service",
			"workload_identity_id": "spiffe://monolith.internal/service/deployment",
			"module_path":          "services.execution.ExecutionServer",
			"service_name":         "deployment",
		},
		"requested_capabilities": []string{"vault:read"},
	}

	response := doJSONRequest(t, service.Addr(), http.MethodPost, "/v1/credential/authorize", body, fixture.clientTLSConfig(t, "service/deployment"))
	defer response.Body.Close()

	if response.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", response.StatusCode)
	}

	assertErrorPayload(t, response, "malformed JSON request body")
}

func TestAuthorizeRejectsTypeMismatchWithWorkloadPrincipal(t *testing.T) {
	fixture := newTLSFixture(t)
	service := startTestApp(t, fixture, checkedInIDConfContents(t))

	body := map[string]any{
		"workload": map[string]any{
			"type":                 "service",
			"workload_identity_id": "spiffe://monolith.internal/script/bot_test_privileged",
		},
		"requested_capabilities": []string{"vault:read"},
	}

	response := doJSONRequest(t, service.Addr(), http.MethodPost, "/v1/credential/authorize", body, fixture.clientTLSConfig(t, "script/bot_test_privileged"))
	defer response.Body.Close()

	if response.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", response.StatusCode)
	}

	assertErrorPayload(t, response, "workload.type does not match workload.workload_identity_id")
}

func TestAuthorizeRejectsMalformedJSON(t *testing.T) {
	fixture := newTLSFixture(t)
	service := startTestApp(t, fixture, checkedInIDConfContents(t))

	response := doRawRequest(t, service.Addr(), http.MethodPost, "/v1/credential/authorize", []byte("{"), fixture.clientTLSConfig(t, "service/execution"), "application/json")
	defer response.Body.Close()

	if response.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", response.StatusCode)
	}

	assertErrorPayload(t, response, "malformed JSON request body")
}

func TestAuthorizeWithoutClientCertReturnsUnauthorized(t *testing.T) {
	fixture := newTLSFixture(t)
	service := startTestApp(t, fixture, checkedInIDConfContents(t))

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
	service := startTestApp(t, fixture, checkedInIDConfContents(t))

	body := map[string]any{
		"workload": map[string]any{
			"type":                 "service",
			"workload_identity_id": "spiffe://monolith.internal/service/execution",
		},
		"requested_capabilities": []string{"vault:read"},
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

func TestAuthorizeDeniesUnknownPolicySubjectAfterPrincipalMatch(t *testing.T) {
	fixture := newTLSFixture(t)
	service := startTestApp(t, fixture, checkedInIDConfContents(t))

	body := map[string]any{
		"workload": map[string]any{
			"type":                 "service",
			"workload_identity_id": "spiffe://monolith.internal/service/deployment",
		},
		"requested_capabilities": []string{"vault:read"},
	}

	response := doJSONRequest(t, service.Addr(), http.MethodPost, "/v1/credential/authorize", body, fixture.clientTLSConfig(t, "service/deployment"))
	defer response.Body.Close()

	if response.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", response.StatusCode)
	}

	var payload struct {
		Allowed bool `json:"allowed"`
		Reason  struct {
			Code string `json:"code"`
		} `json:"reason"`
	}
	if err := json.NewDecoder(response.Body).Decode(&payload); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if payload.Allowed || payload.Reason.Code != "EVALUATION_FAILED" {
		t.Fatalf("unexpected deny payload: %+v", payload)
	}
}

func TestAuthorizeRejectsRemovedServiceNameField(t *testing.T) {
	fixture := newTLSFixture(t)
	service := startTestApp(t, fixture, checkedInIDConfContents(t))

	body := map[string]any{
		"workload": map[string]any{
			"type":                 "service",
			"service_name":         "execution",
			"workload_identity_id": "spiffe://monolith.internal/service/execution",
		},
		"requested_capabilities": []string{"vault:read"},
	}

	response := doJSONRequest(t, service.Addr(), http.MethodPost, "/v1/credential/authorize", body, fixture.clientTLSConfig(t, "service/execution"))
	defer response.Body.Close()

	if response.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", response.StatusCode)
	}
	assertErrorPayload(t, response, "malformed JSON request body")
}

func TestAuthorizeRejectsRemovedFilePathField(t *testing.T) {
	fixture := newTLSFixture(t)
	service := startTestApp(t, fixture, checkedInIDConfContents(t))

	body := map[string]any{
		"workload": map[string]any{
			"type":                 "script",
			"workload_identity_id": "spiffe://monolith.internal/script/bot_test_privileged",
			"file_path":            "./scripts/vault/Run.py",
		},
		"requested_capabilities": []string{"vault:read"},
	}

	response := doJSONRequest(t, service.Addr(), http.MethodPost, "/v1/credential/authorize", body, fixture.clientTLSConfig(t, "script/bot_test_privileged"))
	defer response.Body.Close()

	if response.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", response.StatusCode)
	}
	assertErrorPayload(t, response, "malformed JSON request body")
}

func TestAuthorizeRejectsBootstrapPKICaller(t *testing.T) {
	fixture := newTLSFixture(t)
	service := startTestApp(t, fixture, checkedInIDConfContents(t))

	body := map[string]any{
		"workload": map[string]any{
			"type":                 "service",
			"workload_identity_id": "spiffe://monolith.internal/service/execution",
		},
		"requested_capabilities": []string{"vault:read"},
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

func TestAuthorizeRejectsRemovedContextField(t *testing.T) {
	fixture := newTLSFixture(t)
	service := startTestApp(t, fixture, checkedInIDConfContents(t))

	body := map[string]any{
		"workload": map[string]any{
			"type":                 "service",
			"workload_identity_id": "spiffe://monolith.internal/service/execution",
		},
		"requested_capabilities": []string{"vault:read"},
		"context":                map[string]any{},
	}

	response := doJSONRequest(t, service.Addr(), http.MethodPost, "/v1/credential/authorize", body, fixture.clientTLSConfig(t, "service/execution"))
	defer response.Body.Close()

	if response.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", response.StatusCode)
	}
	assertErrorPayload(t, response, "malformed JSON request body")
}

func TestCheckedInIDConfBaselineParsesAndMapsCurrentSubjects(t *testing.T) {
	t.Parallel()

	set, err := policy.Load(checkedInIDConfPath(t))
	if err != nil {
		t.Fatalf("load checked-in id.conf baseline: %v", err)
	}

	serviceType, serviceID, ok := set.SubjectFromWorkload(policy.Workload{
		Type:               "service",
		WorkloadIdentityID: "spiffe://monolith.internal/service/execution",
	})
	if !ok || serviceType != "service" || serviceID != "execution" {
		t.Fatalf("unexpected service subject mapping: type=%q id=%q ok=%v", serviceType, serviceID, ok)
	}

	scriptType, scriptID, ok := set.SubjectFromWorkload(policy.Workload{
		Type:               "script",
		WorkloadIdentityID: "spiffe://monolith.internal/script/bot_test_privileged",
	})
	if !ok || scriptType != "script" || scriptID != "bot_test_privileged" {
		t.Fatalf("unexpected script subject mapping: type=%q id=%q ok=%v", scriptType, scriptID, ok)
	}
}

type tlsFixture struct {
	serverTrustPath     string
	serverCertPath      string
	serverKeyPath       string
	normalCACert        *x509.Certificate
	normalCAKey         *rsa.PrivateKey
	bootstrapCACert     *x509.Certificate
	bootstrapCAKey      *rsa.PrivateKey
	bootstrapBundlePath string
}

func newTLSFixture(t *testing.T) tlsFixture {
	t.Helper()

	dir := t.TempDir()

	normalCACert, normalCAKey, normalCAPEM := createCertificateAuthority(t, "Runtime Test CA")
	bootstrapCACert, bootstrapCAKey, bootstrapCAPEM := createCertificateAuthority(t, "Bootstrap SPIFFE Test CA")

	serverCertPEM, serverKeyPEM := createLeafCertificate(t, normalCACert, normalCAKey, certificateRequest{
		commonName: "credential-governance.internal",
		dnsNames:   []string{"localhost"},
		ipAddrs:    []net.IP{net.ParseIP("127.0.0.1")},
	})
	bundlePath := filepath.Join(dir, "client-ca-bundle.pem")
	writePEMFile(t, bundlePath, append(normalCAPEM, bootstrapCAPEM...))

	fixture := tlsFixture{
		serverTrustPath:     bundlePath,
		serverCertPath:      filepath.Join(dir, "server.pem"),
		serverKeyPath:       filepath.Join(dir, "server.key"),
		normalCACert:        normalCACert,
		normalCAKey:         normalCAKey,
		bootstrapCACert:     bootstrapCACert,
		bootstrapCAKey:      bootstrapCAKey,
		bootstrapBundlePath: bundlePath,
	}

	writePEMFile(t, fixture.serverCertPath, serverCertPEM)
	writePEMFile(t, fixture.serverKeyPath, serverKeyPEM)

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
		Security: config.SecurityConfig{
			BootstrapIssuerCommonName: "Bootstrap SPIFFE Test CA",
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

func checkedInIDConfPath(t *testing.T) string {
	t.Helper()

	_, currentFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("resolve current test file path")
	}
	path := filepath.Clean(filepath.Join(filepath.Dir(currentFile), "..", "policy", "id.conf"))
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("stat checked-in id.conf baseline: %v", err)
	}
	return path
}

func checkedInIDConfContents(t *testing.T) string {
	t.Helper()

	bytes, err := os.ReadFile(checkedInIDConfPath(t))
	if err != nil {
		t.Fatalf("read checked-in id.conf baseline: %v", err)
	}
	return string(bytes)
}

func startTestApp(t *testing.T, fixture tlsFixture, idConfContents string) *app.App {
	t.Helper()

	cfgPath := writeConfig(t, buildConfig(fixture, writeIDConf(t, idConfContents)))
	cfg, err := config.Load(cfgPath)
	if err != nil {
		t.Fatalf("load config: %v", err)
	}

	service, err := app.New(cfg)
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
