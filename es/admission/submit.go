package admission

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	esconfig "execution-substrate/es/config"
	"execution-substrate/internal/observability"
)

const (
	defaultSubmitCPU               = 10
	defaultSubmitMemoryMB          = 128
	platformStateOwnerUIDEnvKey    = "EXEC_PLATFORM_STATE_OWNER_UID"
	platformStateOwnerGIDEnvKey    = "EXEC_PLATFORM_STATE_OWNER_GID"
	platformStateOwnerSchemaEnvKey = "EXEC_PLATFORM_STATE_OWNER_SCHEMA"
	platformStateOwnerSchemaV1     = "v1"
)

type nomadClient struct {
	baseURL    *url.URL
	datacenter string
	// token is ES's Nomad ACL client token secret, read once at startup from
	// nomad.token_file. It is sent only in the X-Nomad-Token header.
	token  string
	client *http.Client
}

type nomadJobRegisterResponse struct {
	EvalID string `json:"EvalID"`
}

func (s *Service) Submit(ctx context.Context, req PrepareRequest) (SubmitResult, *Error) {
	resolved, resolveErr := s.resolveExecutionForSubmit(ctx, req)
	if resolveErr != nil {
		return SubmitResult{}, resolveErr
	}
	if accessErr := s.nomadClient.verifyAccessControl(ctx); accessErr != nil {
		return SubmitResult{}, accessErr
	}
	locator, locatorErr := newExecutionLocator()
	if locatorErr != nil {
		return SubmitResult{}, &Error{
			Status:  http.StatusInternalServerError,
			Code:    codeSubmissionFailed,
			Message: "generate run id failed",
		}
	}
	run := newResolvedRunProjection(resolved.plan, resolved.host, locator)
	roots, rootsErr := qualifyExecutionRoots(resolved.custodyPlacement.stagingRootDir, resolved.custodyPlacement.resultsRootDir, nil)
	if rootsErr != nil {
		return SubmitResult{}, stagingClaimSubmissionError(rootsErr)
	}
	defer func() {
		_ = roots.close()
	}()
	rootOwner, rootsErr := roots.owner()
	if rootsErr != nil || rootOwner != resolved.host.owner {
		return SubmitResult{}, stagingClaimSubmissionError(rootsErr)
	}
	if rootsErr := roots.reobserve(); rootsErr != nil {
		return SubmitResult{}, stagingClaimSubmissionError(rootsErr)
	}
	stagingRoot, rootsErr := roots.takeStagingQualifiedDirectory()
	if rootsErr != nil {
		return SubmitResult{}, stagingClaimSubmissionError(rootsErr)
	}
	custody, custodyErr := claimStagingCustodyFromQualifiedRoot(stagingRoot, locator.RunID, resolved.host.owner)
	if custodyErr != nil {
		return SubmitResult{}, stagingClaimSubmissionError(custodyErr)
	}
	if closeErr := roots.close(); closeErr != nil {
		_ = custody.close()
		return SubmitResult{}, stagingClaimSubmissionError(closeErr)
	}
	defer func() {
		_ = custody.close()
	}()

	// Every post-claim return closes descriptors and retains the visible run
	// root. Close errors never replace the primary failure or a successful Nomad
	// receipt. The reserved runtime-identity workspace is provisioned as tmpfs
	// and is not host-backed by the submit path.

	stage, stageErr := materializeExecutionInputs(custody, run, resolved.material)
	if stageErr != nil {
		return SubmitResult{}, stageErr
	}
	authorityHandoff := buildResolvedExecutionAuthorityHandoff(run.authorityHandoff)
	jobSpec := buildNomadJobSpec(run.nomadJobProjection(stage.mounts))
	if err := custody.revalidateBeforeHandoff(); err != nil {
		return SubmitResult{}, &Error{
			Status:  http.StatusInternalServerError,
			Code:    codeSubmissionFailed,
			Message: "stage artifact payload failed",
		}
	}

	_, submitErr := s.nomadClient.submitJob(ctx, jobSpec)
	if submitErr != nil {
		return SubmitResult{}, &Error{
			Status:  http.StatusServiceUnavailable,
			Code:    codeSubmissionFailed,
			Message: "execution submission failed",
		}
	}
	return SubmitResult{
		Success:          true,
		Submitted:        true,
		RunID:            locator.RunID,
		Status:           "submitted",
		AuthorityHandoff: &authorityHandoff,
	}, nil
}

func stagingClaimSubmissionError(_ error) *Error {
	return &Error{
		Status:  http.StatusInternalServerError,
		Code:    codeSubmissionFailed,
		Message: "claim execution staging root failed",
	}
}

func (s *Service) fetchPayloadBytes(ctx context.Context, payloadDigest string) ([]byte, *Error) {
	payload, _, publicErr := s.fetchPayloadBytesWithin(ctx, payloadDigest, maxPrimaryPayloadBytes)
	return payload, publicErr
}

// fetchPayloadBytesWithin returns payload bytes only after they hash to the
// signed payload digest; see fetchVerifiedARSBlob.
func (s *Service) fetchPayloadBytesWithin(ctx context.Context, payloadDigest string, limit int64) ([]byte, error, *Error) {
	payload, fetchErr := s.fetchVerifiedARSBlob(ctx, payloadDigest, arsBlobViewBytes, limit)
	if fetchErr == nil {
		return payload, nil, nil
	}
	unavailable := func(message string) *Error {
		return &Error{
			Status:  http.StatusServiceUnavailable,
			Code:    codePayloadUnavailable,
			Message: message,
		}
	}
	switch fetchErr.failure {
	case arsBlobRequestFailed, arsBlobReadFailed:
		return nil, fetchErr.cause, unavailable("artifact payload read failed")
	case arsBlobUnexpectedStatus:
		return nil, nil, unavailable(fmt.Sprintf("artifact payload read returned status %d", fetchErr.status))
	case arsBlobDigestMismatch:
		return nil, fetchErr.cause, unavailable(artifactPayloadDigestMismatchMessage)
	default:
		return nil, nil, unavailable("artifact payload is unavailable")
	}
}

func resolveTaskResources(resources *ExecutionResources) (cpu int, memoryMB int) {
	if resources == nil {
		return defaultSubmitCPU, defaultSubmitMemoryMB
	}
	return resources.CPU, resources.MemoryMB
}

func buildNomadJobSpec(projection resolvedNomadJobProjection) map[string]any {
	jobMeta := executionAuthorityMetadata(projection.authorityMetadata)
	jobMeta["run_id"] = projection.runID

	taskConfig := map[string]any{
		"image":        projection.runtimeImage,
		"command":      projection.runtimeCommand.executable,
		"args":         copyStringSlice(projection.runtimeCommand.arguments),
		"privileged":   projection.jobEnvelope.privileged,
		"security_opt": copyStringSlice(projection.jobEnvelope.securityOptions),
	}

	taskConfig["mounts"] = projection.layout.runtimeMountSpecs(projection.runtimeMountInputs, projection.stagedMounts)
	taskConfig["network_mode"] = projection.networkMode

	return map[string]any{
		"Job": map[string]any{
			"ID":          projection.jobID,
			"Name":        projection.jobID,
			"Namespace":   nomadSubmitNamespace,
			"Meta":        jobMeta,
			"Type":        projection.jobEnvelope.jobType,
			"Datacenters": copyStringSlice(projection.datacenters),
			"TaskGroups": []any{
				map[string]any{
					"Name":  projection.jobEnvelope.groupName,
					"Count": projection.jobEnvelope.groupCount,
					"RestartPolicy": map[string]any{
						"Attempts": projection.jobEnvelope.restartPolicy.attempts,
						"Mode":     projection.jobEnvelope.restartPolicy.mode,
						"Interval": projection.jobEnvelope.restartPolicy.interval,
						"Delay":    projection.jobEnvelope.restartPolicy.delay,
					},
					"ReschedulePolicy": map[string]any{
						"Attempts":      projection.jobEnvelope.reschedulePolicy.attempts,
						"Unlimited":     projection.jobEnvelope.reschedulePolicy.unlimited,
						"Delay":         projection.jobEnvelope.reschedulePolicy.delay,
						"DelayFunction": projection.jobEnvelope.reschedulePolicy.delayFunction,
						"MaxDelay":      projection.jobEnvelope.reschedulePolicy.maxDelay,
					},
					"Tasks": []any{
						map[string]any{
							"Name":   projection.jobEnvelope.taskName,
							"Driver": projection.jobEnvelope.driver,
							"User":   projection.jobEnvelope.user,
							"Config": taskConfig,
							"Env":    copyStringMap(projection.environment),
							"Resources": map[string]any{
								"CPU":      projection.resources.cpu,
								"MemoryMB": projection.resources.memoryMB,
							},
							"Meta": map[string]any{
								"run_id":                 projection.runID,
								"artifact_digest":        projection.artifactDigest,
								"derivation_spec_digest": projection.derivationDigest,
								"output_id":              projection.outputID,
							},
						},
					},
				},
			},
		},
	}
}

func newNomadClient(cfg esconfig.NomadConfig) (*nomadClient, error) {
	baseURL, err := url.Parse(cfg.BaseURL)
	if err != nil {
		return nil, err
	}
	token, err := loadNomadToken(cfg.TokenFile)
	if err != nil {
		return nil, err
	}

	return &nomadClient{
		baseURL:    baseURL,
		datacenter: strings.TrimSpace(cfg.Datacenter),
		token:      token,
		client: &http.Client{
			Timeout: time.Duration(cfg.TimeoutSeconds) * time.Second,
			// TODO: Nomad is treated as an external execution dependency in this
			// 		 slice, so traceparent propagation remains disabled explicitly.
			// 		 Future external dependencies must make the same propagation decision
			// 		 deliberately rather than inheriting internal behavior silently.
			Transport:     observability.WrapRoundTripper("execution", "nomad", false, newNomadTransport()),
			CheckRedirect: refuseNomadRedirect,
		},
	}, nil
}

// newNomadTransport is the transport for every request that carries ES's
// Nomad token. It uses no proxy, so the token reaches only the configured
// Nomad address.
func newNomadTransport() *http.Transport {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	return transport
}

// refuseNomadRedirect keeps a redirect answer as the response instead of
// following it: following would send ES's token to whatever the redirect
// names. Every Nomad call then sees a non-200 status and fails closed.
func refuseNomadRedirect(*http.Request, []*http.Request) error {
	return http.ErrUseLastResponse
}

func (c *nomadClient) submitJob(ctx context.Context, jobSpec map[string]any) (string, error) {
	body, err := json.Marshal(jobSpec)
	if err != nil {
		return "", fmt.Errorf("marshal nomad job: %w", err)
	}

	request, err := c.newJobRequest(ctx, http.MethodPost, "/v1/jobs", nil, strings.NewReader(string(body)))
	if err != nil {
		return "", err
	}
	request.Header.Set("Content-Type", "application/json")

	response, err := c.client.Do(request)
	if err != nil {
		return "", fmt.Errorf("submit nomad job: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return "", fmt.Errorf("submit nomad job: unexpected status %d", response.StatusCode)
	}

	var payload nomadJobRegisterResponse
	if err := decodeBoundedCompatibleJSONDocumentResponse(response, &payload); err != nil {
		return "", fmt.Errorf("decode nomad submit response: %w", err)
	}
	if strings.TrimSpace(payload.EvalID) == "" {
		return "", fmt.Errorf("submit nomad job: missing eval id")
	}
	return strings.TrimSpace(payload.EvalID), nil
}
