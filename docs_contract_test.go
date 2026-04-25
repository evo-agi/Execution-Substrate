package executionsubstrate_test

import (
	"os"
	"strings"
	"testing"
)

func mustRead(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return string(data)
}

func compactText(text string) string {
	return strings.Join(strings.Fields(text), " ")
}

func TestSupportedLocalCPConsumerRunbookPreservesControlPlaneBoundaries(t *testing.T) {
	readme := compactText(mustRead(t, "README.md"))
	runbook := compactText(mustRead(t, ".docs/supported_local_cp_consumer_runbook.md"))

	for _, required := range []string{
		"Control Plane long-running operator mode contract",
		"ES provider run ids",
		"not Control Plane orchestration truth",
		"ES retained results remain opaque output material",
		"semantic validation and any review, checkpoint, hold/resume/reject, or terminal run decision",
		"GET /v1/executions:contract",
		"governed-execution-producer/v1",
		"POST /v1/executions:prepare",
		"POST /v1/executions:submit",
		"GET /v1/executions/{run_id}/status",
		"GET /v1/executions/{run_id}/logs",
		"GET /v1/executions/{run_id}/result",
		"POST /v1/executions/{run_id}:cancel",
		"submit-ready: true",
		"not a registry guarantee",
		"The selected profile changes the runtime image and injects non-secret runtime metadata. It does not add ES-owned CP lifecycle, review, checkpoint, or finalization semantics.",
	} {
		if !strings.Contains(runbook, required) {
			t.Fatalf("supported-local CP consumer runbook missing %q", required)
		}
	}

	for _, required := range []string{
		"proves only admission-oriented service health",
		"ES must not widen this supported-local surface into CP orchestration",
	} {
		if !strings.Contains(readme, required) {
			t.Fatalf("README missing %q", required)
		}
	}
}

func TestPrimaryMilestoneRealignmentPreservesESOwnership(t *testing.T) {
	plans := compactText(mustRead(t, "PLANS.md"))
	architecture := compactText(mustRead(t, ".docs/system_overview/architecture.md"))
	boundaries := compactText(mustRead(t, ".docs/system_overview/boundaries.md"))
	contracts := compactText(mustRead(t, ".docs/system_overview/contracts.md"))
	lifecycle := compactText(mustRead(t, ".docs/execution_lifecycle/contracts.md"))
	runbook := compactText(mustRead(t, ".docs/supported_local_cp_consumer_runbook.md"))

	for _, required := range []string{
		"Execution Substrate is the primary program in this repository.",
		"ES Admission And Runtime Boundary Realignment",
		"Control Plane is an important first non-operator consumer",
		"Control Plane documents may describe how CP consumes accepted ES surfaces; they must not widen ES admission, lifecycle, runtime-profile, runtime-identity, result-retention, or readiness ownership.",
		"Workstream A and Workstream B are gates that keep ES input contracts honest; Workstream C is the delivered ES milestone.",
		"keeping the current `execution_substrate.runtime_profile` annotation and `control-plane-normal-shell/v1` profile as accepted bounded compatibility",
		"ES may expose a bounded lifecycle projection revision on status responses as an opaque read-coordination fact derived from Nomad observation.",
	} {
		if !strings.Contains(plans, required) {
			t.Fatalf("PLANS missing %q", required)
		}
	}

	for _, required := range []string{
		"Execution Substrate is the primary governed execution system in this repository.",
		"Control Plane is a first non-operator consumer, not an owner of ES core contracts.",
	} {
		if !strings.Contains(architecture, required) {
			t.Fatalf("architecture doc missing %q", required)
		}
	}

	for _, required := range []string{
		"Control Plane is a consumer of accepted AGS and ES surfaces, not an owner of ES core contracts.",
		"Current CP compatibility for publish -> prepare -> submit -> status/logs/result/cancel is a retained consumer edge.",
	} {
		if !strings.Contains(boundaries, required) {
			t.Fatalf("boundaries doc missing %q", required)
		}
	}

	for _, required := range []string{
		"Stable semantic contracts for the ES Admission And Runtime Boundary Realignment package",
		"Compatibility edges to preserve during the next package unless a coordinated migration/versioning note says otherwise",
		"Implementation details and current slice constraints must not be promoted into stable cross-service semantics",
		"GET /v1/executions:contract",
		"lifecycle_projection",
	} {
		if !strings.Contains(contracts, required) {
			t.Fatalf("contracts doc missing %q", required)
		}
	}

	if !strings.Contains(lifecycle, "CP documents, probes, examples, and proof harnesses do not define ES lifecycle contracts.") {
		t.Fatalf("lifecycle contracts doc missing ES ownership authority note")
	}
	for _, required := range []string{
		"`lifecycle_projection.source` is `nomad`",
		"`lifecycle_projection.revision` is an opaque equality token",
		"Callers must not parse or order `lifecycle_projection.revision`",
	} {
		if !strings.Contains(lifecycle, required) {
			t.Fatalf("lifecycle contracts doc missing %q", required)
		}
	}

	if !strings.Contains(runbook, "This runbook documents how CP consumes an accepted ES-owned surface; it is not the source of truth for ES core contracts.") {
		t.Fatalf("CP consumer runbook missing ES ownership authority note")
	}
	if !strings.Contains(runbook, "Status responses include `lifecycle_projection.source` and") {
		t.Fatalf("CP consumer runbook missing lifecycle projection consumption note")
	}
	if !strings.Contains(runbook, "`GET /v1/executions:contract` is the current producer-side compatibility") {
		t.Fatalf("CP consumer runbook missing producer contract gate note")
	}
}

func TestGoldenProducerProofPathIsDocumented(t *testing.T) {
	runbook := compactText(mustRead(t, ".docs/supported_local_cp_consumer_runbook.md"))
	lifecycleContracts := compactText(mustRead(t, ".docs/execution_lifecycle/contracts.md"))
	capabilityProbing := compactText(mustRead(t, ".docs/system_overview/capability_probing.md"))

	for _, required := range []string{
		"Golden producer proof path",
		"`GET /v1/executions:contract`",
		"`schema_version = \"execution-substrate.producer-contract/v1\"`",
		"`service = \"execution\"`",
		"`governed_execution.contract = \"governed-execution-producer/v1\"`",
		"`governed_execution.enabled = true`",
		"`control-plane-normal-shell/v1`",
		"`invocation.annotations[\"execution_substrate.runtime_profile\"] = \"control-plane-normal-shell/v1\"`",
		"`authority_handoff`",
		"`status.lifecycle_projection.revision`",
		"`outcome_evidence`",
		"`Content-Type: text/plain; charset=utf-8`",
		"`Content-Type: application/gzip`",
		"`Execution-Substrate-Outcome-*` headers",
		"A passing static contract check without supported-local readiness is not a live runtime proof.",
		"A passing Docker/Nomad-backed proof without the producer declaration above is not current governed-execution producer compatibility.",
	} {
		if !strings.Contains(runbook, required) {
			t.Fatalf("supported-local CP consumer runbook missing golden producer proof phrase %q", required)
		}
	}

	for _, required := range []string{
		"status JSON to include `outcome_evidence`",
		"cancel JSON to include `outcome_evidence`",
		"successful logs responses to preserve `text/plain; charset=utf-8`",
		"successful result responses to preserve `application/gzip`",
		"`authority_handoff` is additive and read-only.",
		"No claim that a JWT-SVID, Vault token, Codex token, or lease exists or is still valid.",
	} {
		if !strings.Contains(lifecycleContracts, required) {
			t.Fatalf("execution lifecycle contract missing producer proof phrase %q", required)
		}
	}

	if !strings.Contains(capabilityProbing, "Read-only producer contract declarations, such as ES `GET /v1/executions:contract`, are not runtime capability probes.") {
		t.Fatalf("capability probing doc missing static producer declaration boundary")
	}
}

func TestProducerFailurePathDistinctionsAreDocumented(t *testing.T) {
	contracts := compactText(mustRead(t, ".docs/system_overview/contracts.md"))
	lifecycleContracts := compactText(mustRead(t, ".docs/execution_lifecycle/contracts.md"))
	runbook := compactText(mustRead(t, ".docs/supported_local_cp_consumer_runbook.md"))

	for _, required := range []string{
		"`disabled_reason = \"submit_not_configured\"`",
		"`disabled_reason = \"profile_not_enabled\"`",
		"`not_run_existence_proof`",
		"`execution_not_found` is a lifecycle observation absence",
		"not a producer declaration incompatibility",
		"not, by itself, a submit-readiness or substrate-health result",
	} {
		if !strings.Contains(lifecycleContracts, required) {
			t.Fatalf("execution lifecycle contract missing failure-path distinction %q", required)
		}
	}

	for _, required := range []string{
		"`submit_not_configured`",
		"`profile_not_enabled`",
		"`not_run_existence_proof`",
		"static compatibility metadata for live lifecycle observation",
	} {
		if !strings.Contains(contracts, required) {
			t.Fatalf("system contracts doc missing producer failure-path distinction %q", required)
		}
	}

	for _, required := range []string{
		"producer declaration incompatibility",
		"runtime/live substrate readiness failure",
		"missing mandatory outcome-evidence support",
		"required runtime profile is unavailable",
		"run lifecycle observation absence",
		"not producer declaration incompatibility or submit readiness",
	} {
		if !strings.Contains(runbook, required) {
			t.Fatalf("CP consumer runbook missing producer failure-path distinction %q", required)
		}
	}
}

func TestRemoteSupportedHostAlphaDirectBoundaryIsDocumented(t *testing.T) {
	remote := compactText(mustRead(t, ".docs/system_overview/remote_supported_host_alpha.md"))
	runbook := compactText(mustRead(t, ".docs/supported_local_cp_consumer_runbook.md"))

	for _, required := range []string{
		"Remote Supported-Host Alpha 0.3 is an intermediate alpha",
		"Control Plane profile diagnostics and Infrastructure Manager remote-doctor output",
		"not the final commercial deployment target",
		"Control Plane API, UI, worker, and Temporal remain on the Mac",
		"ES, AGS, ARS, EGS, Docker, Nomad, SPIRE, Vault, and runtime support run on one remote Linux host.",
		"CP connects to AGS and ES over direct routable HTTPS with mTLS.",
		"No shared filesystem is assumed between Mac and remote host.",
		"Bridge or tunnel mode is a temporary compatibility edge",
		"AGS and ES listeners can bind routable interfaces",
		"server certificates include DNS or IP SANs matching the Control Plane profile endpoint hosts",
		"mTLS accepts the Control Plane service identity",
		"ES `/health`",
		"ES `GET /v1/executions:contract`",
		"AGS `POST /v1/artifacts:publish`",
		"ES `POST /v1/executions:prepare`",
		"ES `POST /v1/executions:submit`",
		"ES `GET /v1/executions/{run_id}/status`",
		"ES `GET /v1/executions/{run_id}/logs`",
		"ES `GET /v1/executions/{run_id}/result`",
		"ES `POST /v1/executions/{run_id}:cancel`",
		"`execution-substrate.producer-contract/v1`",
		"`governed-execution-producer/v1`",
		"`control-plane-normal-shell/v1`",
		"Nomad APIs",
		"Vault APIs",
		"SPIRE sockets",
		"ES staging root paths",
		"ES results root paths",
		"remote filesystem paths",
		"Infrastructure Manager may emit profile, doctor, support-bundle, and combined readiness-report outputs",
		"Direct HTTPS/mTLS with matching DNS/IP SANs is the acceptance posture",
	} {
		if !strings.Contains(remote, required) {
			t.Fatalf("remote supported-host alpha doc missing %q", required)
		}
	}

	if !strings.Contains(runbook, "Remote Supported-Host Alpha 0.3") {
		t.Fatalf("supported-local CP consumer runbook missing remote alpha link")
	}
}

func TestRemoteSupportedHostAlphaDoctorVocabularyIsDocumented(t *testing.T) {
	remote := compactText(mustRead(t, ".docs/system_overview/remote_supported_host_alpha.md"))

	for _, required := range []string{
		"Doctor And Support-Bundle Vocabulary",
		"`remote_host_reachable`",
		"`docker_ready`",
		"`nomad_ready`",
		"`runtime_profile_ready`",
		"`es_services_healthy`",
		"`cert_trust_ok`",
		"`producer_contract_compatible`",
		"`ags_publish_probe`",
		"`es_prepare_probe`",
		"`submit_ready`",
		"`retained_result_fetch`",
		"`cp_profile_usable`",
		"operator diagnostics, readiness-report inputs, and support-bundle provenance",
		"not ES core lifecycle contracts",
		"not Control Plane run-control authority",
		"product blocker codes",
		"not surface script numbers, Lima implementation details, bridge ports, proof-harness names, or remote filesystem paths",
	} {
		if !strings.Contains(remote, required) {
			t.Fatalf("remote supported-host alpha doc missing doctor vocabulary phrase %q", required)
		}
	}
}

func TestRemoteSupportedHostAlphaSupportBundleSummarySectionsAreDocumented(t *testing.T) {
	remote := compactText(mustRead(t, ".docs/system_overview/remote_supported_host_alpha.md"))

	for _, required := range []string{
		"Support-Bundle Summary Sections",
		"`evidence/execution-substrate/producer-contract-summary.json`",
		"`evidence/execution-substrate/health-readiness-summary.json`",
		"`evidence/execution-substrate/probe-summaries.json`",
		"`execution-substrate.producer-contract-summary.v1`",
		"`execution-substrate.health-readiness-summary.v1`",
		"`execution-substrate.probe-summaries.v1`",
		"bounded summary evidence",
		"AGS publish probe summary",
		"ES prepare, submit, status, and result summaries",
		"Nomad, Docker, Vault, and SPIRE structured status summaries",
		"must not contribute: - raw logs",
		"raw retained-result bundles",
		"do not change ES lifecycle semantics",
		"or the producer declaration boundary",
	} {
		if !strings.Contains(remote, required) {
			t.Fatalf("remote supported-host alpha doc missing support-bundle phrase %q", required)
		}
	}
}

func TestRemoteSupportedHostAlphaVaultWorkloadAuthSummarySchemaIsDocumented(t *testing.T) {
	remote := compactText(mustRead(t, ".docs/system_overview/remote_supported_host_alpha.md"))
	configuration := compactText(mustRead(t, ".docs/system_overview/configuration.md"))

	for _, required := range []string{
		"`execution-substrate.remote-alpha.vault-workload-auth-summary.v1`",
		"`sudo scripts/remote_alpha_vault_workload_auth_check.sh`",
		"bounded host-local audit record",
		"not an ES lifecycle or readiness surface",
		"`vault_workload_auth_smoke`",
		"`host_identity`",
		"`vault.address`",
		"`vault.auth_mount`",
		"`vault.role`",
		"`vault.audience`",
		"`vault.policy_names`",
		"`vault.initialized`",
		"`vault.sealed`",
		"`vault.storage`",
		"`spire.trust_domain`",
		"`spire.socket_path`",
		"`workload.spiffe_id`",
		"`workload.registration_selector_scope`",
		"`workload.registration_alpha_only`",
		"`auth_smoke.jwt_fetch`",
		"`auth_smoke.vault_login`",
		"`auth_smoke.token_lookup`",
		"`auth_smoke.proof_read`",
		"`auth_smoke.proof_runtime_secret`",
		"`auth_smoke.token_revoked`",
		"`auth_smoke_requirements.token_lookup_required`",
		"`auth_smoke_requirements.proof_read_required`",
		"`auth_smoke_requirements.proof_runtime_secret_required`",
		"`auth_smoke_requirements.token_revoked_required`",
		"`auth_smoke_requirements.proof_read_path`",
		"`auth_smoke_requirements.proof_runtime_secret_path`",
		"`auth_smoke_requirements.proof_runtime_secret_field`",
		"`proof_runtime_secret.status`",
		"`proof_runtime_secret.path`",
		"`proof_runtime_secret.field`",
		"`proof_runtime_secret.field_present`",
		"`proof_runtime_secret.field_nonempty`",
		"`proof_runtime_secret.field_shape`",
		"`proof-secrets/data/runtime-identity-vault-login`",
		"`proof-secrets/data/codex-runtime-profile`",
		"`api_key`",
		"`GET /auth/token/lookup-self`",
		"`security.ds_not_in_docker_group`",
		"`security.passwordless_sudo_for_ds`",
		"`security.raw_spire_socket_access_ds`",
		"`security.raw_spire_socket_access_uid_10000`",
		"`redaction.jwt_persisted`",
		"`redaction.vault_client_token_persisted`",
		"`redaction.root_token_persisted`",
		"`redaction.secret_payload_persisted`",
		"`readiness_not_claimed.runtime_profile_ready`",
		"`readiness_not_claimed.submit_ready`",
		"`readiness_not_claimed.es_services_healthy`",
		"`readiness_not_claimed.producer_contract_compatible`",
		"`readiness_not_claimed.retained_result_fetch`",
		"`https://172.17.0.1:8200/v1/sys/health`",
		"`/etc/execution-substrate/vault/workload-zone-vault-config.json`",
		"must not print or persist JWT-SVIDs, Vault client tokens, root tokens, unseal keys, private keys, or secret payloads",
	} {
		if !strings.Contains(remote, required) && !strings.Contains(configuration, required) {
			t.Fatalf("remote Vault/workload-auth schema docs missing %q", required)
		}
	}
}

func TestRemoteSupportedHostAlphaNormalShellRuntimeImageSummarySchemaIsDocumented(t *testing.T) {
	remote := compactText(mustRead(t, ".docs/system_overview/remote_supported_host_alpha.md"))
	configuration := compactText(mustRead(t, ".docs/system_overview/configuration.md"))

	for _, required := range []string{
		"Remote Normal-Shell Runtime Image Slice",
		"`execution-substrate.remote-alpha.normal-shell-runtime-image-summary.v1`",
		"`sudo scripts/remote_alpha_normal_shell_runtime_image_check.sh`",
		"`/var/tmp/execution-substrate-remote-alpha/normal-shell-runtime-image-summary.json`",
		"`execution-substrate/control-plane-normal-shell:supported-local`",
		"`sudo scripts/remote_alpha_build_normal_shell_runtime_image.sh`",
		"`scripts/remote_alpha_build_normal_shell_runtime_image.sh`",
		"`scripts/build_control_plane_normal_shell_image.sh`",
		"`/usr/local/bin/codex`",
		"`CONTROL_PLANE_NORMAL_SHELL_IMAGE=execution-substrate/control-plane-normal-shell:supported-local`",
		"`es/runtimeprofiles/control_plane_normal_shell/Dockerfile`",
		"`CONTROL_PLANE_NORMAL_SHELL_CODEX_CLI_PATH=/usr/local/bin/codex`",
		"`CONTROL_PLANE_NORMAL_SHELL_CODEX_REALIZATION=proof`",
		"`image.ref`",
		"`image.present`",
		"`image.image_id`",
		"`build.expected_recipe_script`",
		"`build.expected_recipe_script_present`",
		"`build.expected_recipe_script_sha256`",
		"`build.build_context_files`",
		"`build.recipe_matches_slice`",
		"`build.codex_realization`",
		"`build.codex_credential_posture`",
		"`build.real_codex_credentials_required_for_build`",
		"`host.docker_service_active`",
		"`host.nomad_ready`",
		"`validation.image_present`",
		"`validation.docker_info_ok`",
		"`validation.minimal_container_run.status`",
		"`validation.codex_realization_expected`",
		"`security.ds_not_in_docker_group`",
		"`security.passwordless_sudo_for_ds`",
		"`security.no_real_codex_credentials_in_build_context`",
		"`security.no_api_keys_or_tokens_printed`",
		"`readiness_not_claimed.runtime_profile_ready`",
		"`readiness_not_claimed.submit_ready`",
		"`readiness_not_claimed.es_services_healthy`",
		"`readiness_not_claimed.producer_contract_compatible`",
		"`readiness_not_claimed.retained_result_fetch`",
		"does not build or rebuild the image by default",
		"does not install or start ES, AGS, ARS, or EGS",
		"not an ES lifecycle or readiness surface",
		"not yet: - an Infrastructure Manager doctor stage payload",
		"fail fast instead of silently honoring a different image ref, Dockerfile, Codex CLI path, or Codex realization",
		"must not accept `REMOTE_ALPHA_RUNTIME_IMAGE_REF`, `REMOTE_ALPHA_CODEX_CLI_PATH`, `REMOTE_ALPHA_BUILD_SCRIPT`, `--image-ref`, or `--codex-cli-path` as mutable inputs",
		"not runtime-profile readiness",
		"not submit readiness",
		"not producer-contract compatibility",
		"not retained-result proof",
		"`build.recipe_matches_slice`: `true` only when the current repo snapshot still carries the expected repo-owned wrapper for this slice",
		"`build.codex_realization`: literal `proof` for the current repo-owned slice",
		"`placeholder` is not the current repo-owned slice posture",
		"does not, by itself, prove that the current image was historically built through that wrapper",
		"must not persist: - OpenAI or Codex credentials",
		"raw build logs",
		"raw retained-result bundles",
	} {
		if !strings.Contains(remote, required) && !strings.Contains(configuration, required) {
			t.Fatalf("remote normal-shell runtime image schema docs missing %q", required)
		}
	}
}

func TestRemoteSupportedHostAlphaAGSServiceHardeningSliceIsDocumented(t *testing.T) {
	plans := compactText(mustRead(t, "PLANS.md"))
	remote := compactText(mustRead(t, ".docs/system_overview/remote_supported_host_alpha.md"))
	configuration := compactText(mustRead(t, ".docs/system_overview/configuration.md"))

	for _, required := range []string{
		"`AGS sealed + ARS de-root + EGS de-root`",
		"AGS is already de-rooted and sealed",
		"ARS is already de-rooted",
		"EGS is the only service being moved off root in this slice",
		"must not move ES off root",
		"must not change ES public contracts",
		"does not widen into broader proof expansion",
	} {
		if !strings.Contains(plans, required) && !strings.Contains(remote, required) && !strings.Contains(configuration, required) {
			t.Fatalf("remote alpha tranche docs missing %q", required)
		}
	}

	for _, required := range []string{
		"Remote AGS Sealed + ARS De-root + EGS De-root Hardening Tranche",
		"Landed AGS Seal Step",
		"The AGS step in this tranche is already landed.",
		"preserving direct HTTPS/mTLS from the Mac to AGS `/health` and `POST /v1/artifacts:publish`",
		"preserving AGS publication to ARS over the current loopback/internal HTTPS dependency path",
		"must leave `ars.service`, `egs.service`, and `es.service` in their then-current posture for that step",
		"leaving the current SPIRE selector model unchanged",
		"`sudo scripts/remote_alpha_harden_ags_service.sh`",
		"`execution-substrate.remote-alpha.ags-service-hardening-summary.v1`",
		"`/var/tmp/execution-substrate-remote-alpha/ags-service-hardening-summary.json`",
		"`slice.classification`",
		"`slice.not_a_new_happy_path_proof`",
		"`service.user`",
		"`service.group`",
		"`service.binary_path`",
		"`service.config_path`",
		"`/etc/execution-substrate/healthcheck.env`",
		"`dependencies.artifact_registry.base_url`",
		"`dependencies.server_tls.cert_file`",
		"`dependencies.server_tls.key_file`",
		"`dependencies.server_tls.client_ca_file`",
		"`dependencies.artifact_registry.client_cert_file`",
		"`dependencies.artifact_registry.client_key_file`",
		"`dependencies.artifact_registry.root_ca_file`",
		"`dependencies.signer.material_location`",
		"`dependencies.local_state_paths`",
		"`dependencies.log_sink`",
		"`ownership_model.config_file`",
		"`ownership_model.tls_directory`",
		"`ownership_model.tls_files`",
		"`ownership_model.systemd_dropin`",
		"`validation.local_health`",
		"`validation.local_publish_probe`",
		"`validation.ars_service_posture`",
		"`validation.egs_service_posture`",
		"`validation.es_service_posture`",
		"`validation.mac_health_probe`",
		"`validation.mac_publish_probe`",
		"`preserved_remote_path.direct_https_mtls`",
		"`preserved_remote_path.no_bridge`",
		"`preserved_remote_path.no_shared_filesystem`",
		"`security.ds_not_in_docker_group`",
		"`security.passwordless_sudo_for_ds`",
		"`not_claimed.es_runtime_hardening`",
		"`not_claimed.submit_runtime_profile_changes`",
		"`not_claimed.spire_selector_model_changes`",
		"`not_claimed.new_remote_happy_path_proof`",
		"`/usr/local/lib/execution-substrate/bin/ags`",
		"`/etc/execution-substrate/ags.json`",
		"`/etc/execution-substrate/tls/ags-server-cert.pem`",
		"`/etc/execution-substrate/tls/ags-server-key.pem`",
		"`/etc/execution-substrate/tls/combined-service-ca-bundle.pem`",
		"`/etc/execution-substrate/tls/ags-client-cert.pem`",
		"`/etc/execution-substrate/tls/ags-client-key.pem`",
		"`/etc/execution-substrate/tls/runtime-ca.pem`",
		"`/etc/systemd/system/ags.service`",
		"`/etc/systemd/system/ags.service.d`",
		"`/etc/systemd/system/ags.service.d/10-account.conf`",
		"`root:ags` mode `0640`",
		"`root:ags` mode `0710`",
		"must not accept `REMOTE_ALPHA_SERVICE_NAME`, `REMOTE_ALPHA_SERVICE_USER`, `REMOTE_ALPHA_SERVICE_GROUP`, `REMOTE_ALPHA_BINARY_PATH`, `REMOTE_ALPHA_CONFIG_PATH`, `REMOTE_ALPHA_HEALTHCHECK_ENV_PATH`, `REMOTE_ALPHA_SERVICE_UNIT_PATH`, `REMOTE_ALPHA_SERVICE_DROPIN_DIR`, `REMOTE_ALPHA_SERVICE_DROPIN_PATH`, `--service-name`, `--service-user`, `--service-group`, `--binary-path`, `--config-path`, `--healthcheck-env-path`, `--service-unit-path`, `--service-dropin-dir`, or `--service-dropin-path` as mutable inputs",
		"Only `--summary-path` and `REMOTE_ALPHA_SUMMARY_PATH` may vary for output placement",
		"must not introduce a shared `execution-substrate` account model",
		"must not change ES public contracts",
		"must not change the SPIRE selector model",
		"must not persist: - signer private-key bytes",
		"raw retained-result bundles",
	} {
		if !strings.Contains(remote, required) && !strings.Contains(configuration, required) {
			t.Fatalf("remote AGS hardening docs missing %q", required)
		}
	}
}

func TestRemoteSupportedHostAlphaARSServiceHardeningSliceIsDocumented(t *testing.T) {
	remote := compactText(mustRead(t, ".docs/system_overview/remote_supported_host_alpha.md"))
	configuration := compactText(mustRead(t, ".docs/system_overview/configuration.md"))

	for _, required := range []string{
		"Remote AGS Sealed + ARS De-root + EGS De-root Hardening Tranche",
		"Landed ARS De-root Step",
		"The ARS step in this tranche is already landed.",
		"preserving the landed `ars.service` non-root `ars:ars` account",
		"preserving the current ARS internal-only loopback listener at `https://127.0.0.1:8442`",
		"preserving AGS local `/health` plus a focused `POST /v1/artifacts:publish` probe through the existing AGS -> ARS loopback dependency path",
		"preserving the current AGS `ags:ags` posture",
		"leaving `egs.service` and `es.service` in their then-current posture for that step",
		"leaving the current SPIRE selector model unchanged",
		"`sudo scripts/remote_alpha_harden_ars_service.sh`",
		"`execution-substrate.remote-alpha.ars-service-hardening-summary.v1`",
		"`/var/tmp/execution-substrate-remote-alpha/ars-service-hardening-summary.json`",
		"`slice.classification`",
		"`slice.not_a_new_happy_path_proof`",
		"`service.user`",
		"`service.group`",
		"`service.binary_path`",
		"`service.config_path`",
		"`/etc/execution-substrate/healthcheck.env`",
		"`dependencies.server_tls.cert_file`",
		"`dependencies.server_tls.key_file`",
		"`dependencies.server_tls.client_ca_file`",
		"`dependencies.blob_root`",
		"`dependencies.index_file`",
		"`dependencies.local_state_paths`",
		"`dependencies.log_sink`",
		"`ownership_model.config_file`",
		"`ownership_model.tls_directory`",
		"`ownership_model.tls_files`",
		"`ownership_model.state_root`",
		"`ownership_model.blob_root`",
		"`ownership_model.index_file`",
		"`ownership_model.systemd_dropin`",
		"`validation.local_ars_health`",
		"`validation.local_ags_health`",
		"`validation.local_ags_publish_probe`",
		"`validation.state_ownership`",
		"`validation.ags_service_posture`",
		"`validation.egs_service_posture`",
		"`validation.es_service_posture`",
		"`preserved_remote_path.ars_loopback_only`",
		"`preserved_remote_path.direct_https_mtls`",
		"`preserved_remote_path.no_bridge`",
		"`preserved_remote_path.no_shared_filesystem`",
		"`security.ds_not_in_docker_group`",
		"`security.passwordless_sudo_for_ds`",
		"`not_claimed.es_or_egs_hardening`",
		"`not_claimed.es_public_contract_changes`",
		"`not_claimed.spire_selector_model_changes`",
		"`not_claimed.new_remote_happy_path_proof`",
		"`/usr/local/lib/execution-substrate/bin/ars`",
		"`/etc/execution-substrate/ars.json`",
		"`/etc/execution-substrate/tls/ars-server-cert.pem`",
		"`/etc/execution-substrate/tls/ars-server-key.pem`",
		"`/etc/execution-substrate/tls/runtime-ca.pem`",
		"`/etc/execution-substrate/ars-tls`",
		"`/etc/execution-substrate/ars-tls/ars-server-cert.pem`",
		"`/etc/execution-substrate/ars-tls/ars-server-key.pem`",
		"`/etc/execution-substrate/ars-tls/runtime-ca.pem`",
		"`/var/lib/execution-substrate/ars/blobs`",
		"`/var/lib/execution-substrate/ars/index.json`",
		"`/etc/systemd/system/ars.service`",
		"`/etc/systemd/system/ars.service.d`",
		"`/etc/systemd/system/ars.service.d/10-account.conf`",
		"`root:ars` mode `0640`",
		"`root:ars` mode `0710`",
		"`ars:ars` mode `0750`",
		"`ars:ars` mode `0600`",
		"`UMask=0027`",
		"must not widen `/etc/execution-substrate/tls`",
		"must not accept `REMOTE_ALPHA_SERVICE_NAME`, `REMOTE_ALPHA_SERVICE_USER`, `REMOTE_ALPHA_SERVICE_GROUP`, `REMOTE_ALPHA_BINARY_PATH`, `REMOTE_ALPHA_CONFIG_PATH`, `REMOTE_ALPHA_HEALTHCHECK_ENV_PATH`, `REMOTE_ALPHA_SERVICE_UNIT_PATH`, `REMOTE_ALPHA_SERVICE_DROPIN_DIR`, `REMOTE_ALPHA_SERVICE_DROPIN_PATH`, `--service-name`, `--service-user`, `--service-group`, `--binary-path`, `--config-path`, `--healthcheck-env-path`, `--service-unit-path`, `--service-dropin-dir`, or `--service-dropin-path` as mutable inputs",
		"Only `--summary-path` and `REMOTE_ALPHA_SUMMARY_PATH` may vary for output placement",
		"must not introduce a shared `execution-substrate` account model",
		"must not change ES public contracts",
		"must not change the SPIRE selector model",
		"must not persist JWT-SVIDs, Vault tokens, TLS private-key PEM bodies, API keys, private keys, or secret payloads",
	} {
		if !strings.Contains(remote, required) && !strings.Contains(configuration, required) {
			t.Fatalf("remote ARS hardening docs missing %q", required)
		}
	}
}

func TestRemoteSupportedHostAlphaEGSServiceHardeningSliceIsDocumented(t *testing.T) {
	remote := compactText(mustRead(t, ".docs/system_overview/remote_supported_host_alpha.md"))
	configuration := compactText(mustRead(t, ".docs/system_overview/configuration.md"))

	for _, required := range []string{
		"Remote AGS Sealed + ARS De-root + EGS De-root Hardening Tranche",
		"EGS De-root Step",
		"The EGS step in this tranche is the service-account move still to apply on the remote host.",
		"moving only `egs.service` from the default root service context to a dedicated non-root `egs:egs` account",
		"preserving the current EGS internal-only loopback listener at `https://127.0.0.1:8443`",
		"preserving AGS local `/health` plus a focused `POST /v1/artifacts:publish` probe through the existing AGS -> ARS loopback dependency path",
		"preserving local ES `/health` plus `GET /v1/executions:contract` through the current direct HTTPS/mTLS path",
		"preserving the current AGS `ags:ags` posture",
		"preserving the current ARS `ars:ars` posture",
		"leaving `es.service` in its current root posture for this tranche",
		"leaving the current SPIRE selector model unchanged",
		"If the target host already has an `egs` user/group",
		"At minimum, that check must confirm primary group `egs`, no supplementary groups, and no unexpected extra members in the `egs` group itself",
		"`sudo scripts/remote_alpha_harden_egs_service.sh`",
		"`execution-substrate.remote-alpha.egs-service-hardening-summary.v2`",
		"`/var/tmp/execution-substrate-remote-alpha/egs-service-hardening-summary.json`",
		"`slice.classification`",
		"`slice.not_a_new_happy_path_proof`",
		"`service.user`",
		"`service.group`",
		"`service.binary_path`",
		"`service.config_path`",
		"`/etc/execution-substrate/healthcheck.env`",
		"`dependencies.server_tls.cert_file`",
		"`dependencies.server_tls.key_file`",
		"`dependencies.server_tls.client_ca_file`",
		"`dependencies.signer.material_location`",
		"`dependencies.runtime_trust.material_location`",
		"`dependencies.publication.material_location`",
		"`dependencies.local_state_paths`",
		"`dependencies.log_sink`",
		"`ownership_model.config_file`",
		"`ownership_model.tls_directory`",
		"`ownership_model.tls_files`",
		"`ownership_model.runtime_state`",
		"`ownership_model.systemd_dropin`",
		"`validation.local_egs_health`",
		"`validation.local_ags_health`",
		"`validation.local_ags_publish_probe`",
		"`validation.local_es_health`",
		"`validation.local_es_contract_probe`",
		"`validation.service_account_narrowness`",
		"`ownership_model.account.group_members`",
		"`validation.service_account_narrowness.group_members`",
		"`validation.service_account_narrowness.unexpected_group_members`",
		"`validation.ownership`",
		"`validation.ags_service_posture`",
		"`validation.ars_service_posture`",
		"`validation.es_service_posture`",
		"`preserved_remote_path.egs_loopback_only`",
		"`preserved_remote_path.direct_https_mtls`",
		"`preserved_remote_path.no_bridge`",
		"`preserved_remote_path.no_shared_filesystem`",
		"`security.ds_not_in_docker_group`",
		"`security.passwordless_sudo_for_ds`",
		"`security.shared_unix_account_model_introduced`",
		"`not_claimed.es_de_root`",
		"`not_claimed.es_public_contract_changes`",
		"`not_claimed.spire_selector_model_changes`",
		"`not_claimed.new_remote_happy_path_proof`",
		"`/usr/local/lib/execution-substrate/bin/egs`",
		"`/etc/execution-substrate/egs.json`",
		"`/etc/execution-substrate/tls/egs-server-cert.pem`",
		"`/etc/execution-substrate/tls/egs-server-key.pem`",
		"`/etc/execution-substrate/tls/runtime-ca.pem`",
		"`/etc/execution-substrate/egs-tls`",
		"`/etc/execution-substrate/egs-tls/egs-server-cert.pem`",
		"`/etc/execution-substrate/egs-tls/egs-server-key.pem`",
		"`/etc/execution-substrate/egs-tls/runtime-ca.pem`",
		"`/etc/systemd/system/egs.service`",
		"`/etc/systemd/system/egs.service.d`",
		"`/etc/systemd/system/egs.service.d/10-account.conf`",
		"`root:egs` mode `0640`",
		"`root:egs` mode `0710`",
		"`UMask=0027`",
		"must not widen `/etc/execution-substrate/tls`",
		"must not accept `REMOTE_ALPHA_SERVICE_NAME`, `REMOTE_ALPHA_SERVICE_USER`, `REMOTE_ALPHA_SERVICE_GROUP`, `REMOTE_ALPHA_BINARY_PATH`, `REMOTE_ALPHA_CONFIG_PATH`, `REMOTE_ALPHA_HEALTHCHECK_ENV_PATH`, `REMOTE_ALPHA_SERVICE_UNIT_PATH`, `REMOTE_ALPHA_SERVICE_DROPIN_DIR`, `REMOTE_ALPHA_SERVICE_DROPIN_PATH`, `--service-name`, `--service-user`, `--service-group`, `--binary-path`, `--config-path`, `--healthcheck-env-path`, `--service-unit-path`, `--service-dropin-dir`, or `--service-dropin-path` as mutable inputs",
		"Only `--summary-path` and `REMOTE_ALPHA_SUMMARY_PATH` may vary for output placement",
		"must not introduce a shared Unix-account model",
		"`preserved_remote_path.direct_https_mtls` must be an inference record",
		"not a Mac-side reachability proof",
		"`preserved_remote_path.no_bridge` and `preserved_remote_path.no_shared_filesystem` must be explicit operator assertion records",
		"`security.shared_unix_account_model_introduced` must be derived from `validation.service_account_narrowness`",
		"`validation.service_account_narrowness` must record the actual primary group, supplementary groups, and effective `egs` group members",
		"It must not report `false` unless the helper has proved the EGS account remained narrow for this slice.",
		"must not change ES public contracts",
		"must not change the SPIRE selector model",
		"must not persist: - signer private-key bytes",
		"raw retained-result bundles",
	} {
		if !strings.Contains(remote, required) && !strings.Contains(configuration, required) {
			t.Fatalf("remote EGS hardening docs missing %q", required)
		}
	}
}

func TestRemoteSupportedHostAlphaESConfigTLSPrepSliceIsDocumented(t *testing.T) {
	remote := compactText(mustRead(t, ".docs/system_overview/remote_supported_host_alpha.md"))
	configuration := compactText(mustRead(t, ".docs/system_overview/configuration.md"))
	plans := compactText(mustRead(t, "PLANS.md"))

	for _, required := range []string{
		"Current Remote Alpha ES Config/TLS Ownership Prep Slice",
		"Remote Supported-Host Alpha may now extend the current host-local hardening work with one separate ES config/TLS ownership prep slice",
		"introduces a dedicated ES-readable config ownership model and a dedicated ES-readable TLS directory",
		"may create a narrow dedicated `es:es` prep account",
		"must keep the live `es.service` user/group posture unchanged",
		"must not change ES public contracts, the current SPIRE selector posture, current SPIRE socket traversal, Vault/runtime-helper semantics, or Nomad task user model",
		"must not move ES writable state, including staging and retained results ownership",
		"preserves the current AGS, ARS, and EGS service postures plus the direct Mac -> ES HTTPS+mTLS posture",
		"bounded host-local config/TLS ownership preparation only",
		"the ES config/TLS ownership prep bridge where live `es.service` stays `root(default)` while dedicated `root:es` readable config/TLS material is staged for a later ES de-root slice",
	} {
		if !strings.Contains(plans, required) && !strings.Contains(remote, required) && !strings.Contains(configuration, required) {
			t.Fatalf("remote ES prep docs missing %q", required)
		}
	}

	for _, required := range []string{
		"Remote ES Config/TLS Ownership Prep Slice",
		"`Bounded slice rule`: this slice prepares only ES-readable config/TLS ownership for a later non-root ES step.",
		"`Temporary compatibility edge`: the live `es.service` user/group remain `root(default)` while the ES config file and dedicated ES TLS directory are prepared under `root:es` readability for a later de-root slice.",
		"preserving the current direct HTTPS/mTLS ES `/health` and `GET /v1/executions:contract` path",
		"preserving the current SPIRE selector posture, SPIRE socket traversal, and Vault/runtime-helper semantics",
		"preserving the current Nomad task user model",
		"leaving ES staging and retained-results ownership untouched",
		"`scripts/remote_alpha_prepare_es_config_tls.sh`",
		"`execution-substrate.remote-alpha.es-config-tls-prep-summary.v1`",
		"`/var/tmp/execution-substrate-remote-alpha/es-config-tls-prep-summary.json`",
		"`slice.classification`",
		"`slice.not_a_new_happy_path_proof`",
		"`slice.temporary_compatibility_edge`",
		"`mode.name`",
		"`mode.non_mutating`",
		"`mode.output`",
		"`service.live_user`",
		"`service.live_group`",
		"`service.binary_path`",
		"`service.config_path`",
		"`service.health_url`",
		"`service.contract_url`",
		"`dependencies.server_tls.cert_file`",
		"`dependencies.server_tls.key_file`",
		"`dependencies.server_tls.client_ca_file`",
		"`dependencies.artifact_registry.base_url`",
		"`dependencies.artifact_registry.client_cert_file`",
		"`dependencies.artifact_registry.client_key_file`",
		"`dependencies.artifact_registry.root_ca_file`",
		"`dependencies.execution_governance.base_url`",
		"`dependencies.execution_governance.client_cert_file`",
		"`dependencies.execution_governance.client_key_file`",
		"`dependencies.execution_governance.root_ca_file`",
		"`dependencies.local_state_paths`",
		"`dependencies.log_sink`",
		"`plan.paths_read`",
		"`plan.paths_written`",
		"`plan.ownership_changes`",
		"`plan.prep_account`",
		"`plan.service_identity_would_remain_root_default`",
		"`plan.restart_required_in_apply_mode`",
		"`plan.warnings`",
		"`plan.blockers`",
		"`backup.status`",
		"`backup.parent_dir`",
		"`backup.path`",
		"`backup.pre_apply_config_copy`",
		"`backup.snapshot_manifest_path`",
		"`backup.pre_apply_source_tls`",
		"`backup.pre_apply_prep_account`",
		"`backup.pre_apply_service`",
		"`backup.rollback_notes`",
		"`ownership_model.prep_account`",
		"`ownership_model.config_file`",
		"`ownership_model.tls_directory`",
		"`ownership_model.tls_files`",
		"`ownership_model.live_service_posture`",
		"`ownership_model.writable_state`",
		"`validation.local_es_health`",
		"`validation.local_es_contract_probe`",
		"`validation.prep_account_narrowness`",
		"`validation.ownership`",
		"`validation.config_rewrite_scope`",
		"`validation.ags_service_posture`",
		"`validation.ars_service_posture`",
		"`validation.egs_service_posture`",
		"`validation.es_service_posture`",
		"`preserved_remote_path.direct_https_mtls`",
		"`preserved_remote_path.no_bridge`",
		"`preserved_remote_path.no_shared_filesystem`",
		"`security.ds_not_in_docker_group`",
		"`security.passwordless_sudo_for_ds`",
		"`security.shared_unix_account_model_introduced`",
		"`not_claimed.es_de_root`",
		"`not_claimed.es_public_contract_changes`",
		"`not_claimed.spire_selector_model_changes`",
		"`not_claimed.spire_socket_traversal_changes`",
		"`not_claimed.nomad_task_user_model_changes`",
		"`not_claimed.vault_runtime_helper_changes`",
		"`not_claimed.staging_or_results_ownership_changes`",
		"`not_claimed.new_remote_happy_path_proof`",
		"`result.status`",
		"`result.ok`",
		"`result.non_mutating`",
		"`sudo /var/tmp/execution-substrate-remote-alpha/helper-staging/scripts/remote_alpha_prepare_es_config_tls.sh --check-only`",
		"`--dry-run` is an accepted alias",
		"required first step before any live apply",
		"machine-readable JSON plan/report to stdout",
		"must not create users or",
		"groups, call `chown` or `chmod`",
		"rewrite `/etc/execution-substrate/es.json`",
		"create or replace `/etc/execution-substrate/es-tls`",
		"create a backup directory under `/var/tmp/execution-substrate-remote-alpha/`",
		"restart `es.service`",
		"Before any apply-mode mutation primitive runs, the helper must create a timestamped backup directory under",
		"`/var/tmp/execution-substrate-remote-alpha/`",
		"`pre-apply-snapshot.json`",
		"record the pre-apply source TLS path, size, owner, group, mode, and sha256",
		"record whether the `es` prep user and group existed before apply",
		"record the current `es.service` `User`, `Group`, `ActiveState`, and `SubState` before apply",
		"record rollback notes for restoring the pre-apply ES config/TLS posture",
		"If the target host already has an `es` user/group",
		"At minimum, that check must confirm primary group `es` and no supplementary groups",
		"must not accept `REMOTE_ALPHA_SERVICE_NAME`, `REMOTE_ALPHA_PREP_USER`, `REMOTE_ALPHA_PREP_GROUP`, `REMOTE_ALPHA_BINARY_PATH`, `REMOTE_ALPHA_CONFIG_PATH`, `REMOTE_ALPHA_HEALTHCHECK_ENV_PATH`, `REMOTE_ALPHA_SERVICE_UNIT_PATH`, `--service-name`, `--prep-user`, `--prep-group`, `--binary-path`, `--config-path`, `--healthcheck-env-path`, or `--service-unit-path` as mutable inputs",
		"Only `--summary-path` and `REMOTE_ALPHA_SUMMARY_PATH` may vary for output placement",
		"`/usr/local/lib/execution-substrate/bin/es`",
		"`/etc/execution-substrate/es.json`",
		"`/etc/execution-substrate/healthcheck.env`",
		"`/etc/systemd/system/es.service`",
		"`/etc/execution-substrate/tls/es-server-cert.pem`",
		"`/etc/execution-substrate/tls/es-server-key.pem`",
		"`/etc/execution-substrate/tls/runtime-ca.pem`",
		"`/etc/execution-substrate/tls/es-client-cert.pem`",
		"`/etc/execution-substrate/tls/es-client-key.pem`",
		"`/etc/execution-substrate/es-tls`",
		"`/etc/execution-substrate/es-tls/es-server-cert.pem`",
		"`/etc/execution-substrate/es-tls/es-server-key.pem`",
		"`/etc/execution-substrate/es-tls/server-client-ca.pem`",
		"`/etc/execution-substrate/es-tls/artifact-registry-client-cert.pem`",
		"`/etc/execution-substrate/es-tls/artifact-registry-client-key.pem`",
		"`/etc/execution-substrate/es-tls/artifact-registry-root-ca.pem`",
		"`/etc/execution-substrate/es-tls/execution-governance-client-cert.pem`",
		"`/etc/execution-substrate/es-tls/execution-governance-client-key.pem`",
		"`/etc/execution-substrate/es-tls/execution-governance-root-ca.pem`",
		"`root:es` mode `0640`",
		"`root:es` mode `0710`",
		"current staging and retained-results ownership remain unchanged in this slice",
		"`validation.config_rewrite_scope` must prove that only ES config/TLS path fields changed",
		"`validation.es_service_posture` must show the live service still runs as `root(default)` after the prep apply",
		"`preserved_remote_path.direct_https_mtls` must be an inference record",
		"not a Mac-side reachability proof",
		"`preserved_remote_path.no_bridge` and `preserved_remote_path.no_shared_filesystem` must be explicit operator assertion records",
		"`security.ds_not_in_docker_group` and `security.passwordless_sudo_for_ds` are host-posture observations recorded in the summary",
		"must not, by themselves, turn an otherwise-valid ES config/TLS ownership prep apply into a failed slice result",
		"`security.shared_unix_account_model_introduced` must be derived from `validation.prep_account_narrowness`",
		"must not persist TLS private-key PEM bodies, client-cert private keys, JWT-SVIDs, Vault tokens, API keys, private keys, secret payloads, or raw retained-result bundles",
	} {
		if !strings.Contains(remote, required) && !strings.Contains(configuration, required) && !strings.Contains(plans, required) {
			t.Fatalf("remote ES prep docs missing %q", required)
		}
	}
}

func TestRemoteSupportedHostAlphaESConfigTLSPrepOperatorStagingFlowIsDocumented(t *testing.T) {
	remote := compactText(mustRead(t, ".docs/system_overview/remote_supported_host_alpha.md"))
	configuration := compactText(mustRead(t, ".docs/system_overview/configuration.md"))

	for _, required := range []string{
		"The remote host does not need a full Execution Substrate repo checkout for this slice.",
		"transient helper staging from the operator repo into a root-owned staging tree under `/var/tmp/execution-substrate-remote-alpha/helper-staging/`",
		"the operator must stage the repo-owned wrapper `scripts/remote_alpha_prepare_es_config_tls.sh` and its sourced helper `scripts/internal/remote_alpha_prepare_es_config_tls.sh`",
		"`/var/tmp/execution-substrate-remote-alpha/helper-staging/scripts/remote_alpha_prepare_es_config_tls.sh`",
		"Execution must run from that root-owned staged tree, not from a user-writable upload path.",
		"Any user-scoped upload directory is transport only and must not be used as the execution path for the live helper invocation.",
		"The required operator-staged provenance record for that transient helper tree must include:",
		"the local git commit when available",
		"the sha256 of each staged helper file",
		"the remote staged path",
		"the remote owner/mode proving the staged tree is root-owned rather than a user-writable upload path",
		"The required operator-staged flow for this slice is:",
		"Copy only the minimal helper tree from the local operator repo snapshot; a full remote repo checkout is not required.",
		"Run the staged wrapper with `--check-only` before any live apply.",
		"Apply may proceed only when `result.ok=true`, `plan.blockers` is empty, `plan.service_identity_would_remain_root_default=true`, and `validation.config_rewrite_scope.status=pass`",
		"the planned writes must stay limited to `/etc/execution-substrate/es.json`, `/etc/execution-substrate/es-tls`, the files beneath that dedicated TLS directory, and the configured summary path.",
		"Preserve the apply summary, backup path, rollback notes, live `es.service` identity, and post-apply `/health` plus `GET /v1/executions:contract` status as the bounded post-apply evidence set.",
		"Remove the transient helper staging tree after that bounded evidence is collected, while preserving the apply backup and summaries under `/var/tmp/execution-substrate-remote-alpha/`.",
		"Do not run governed proof as part of this staged operator flow.",
		"This operator-staged flow is ownership prep only. It is not ES de-rooting.",
		"`sudo /var/tmp/execution-substrate-remote-alpha/helper-staging/scripts/remote_alpha_prepare_es_config_tls.sh --check-only`",
		"`sudo /var/tmp/execution-substrate-remote-alpha/helper-staging/scripts/remote_alpha_prepare_es_config_tls.sh`",
	} {
		if !strings.Contains(remote, required) && !strings.Contains(configuration, required) {
			t.Fatalf("remote ES prep operator-staging docs missing %q", required)
		}
	}
}
