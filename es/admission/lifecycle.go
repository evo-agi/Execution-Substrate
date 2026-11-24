package admission

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"strings"
)

const nomadTaskName = "task"

const (
	executionLifecycleStatusSubmitted       = "submitted"
	executionLifecycleStatusRunning         = "running"
	executionLifecycleStatusTerminal        = "terminal"
	executionLifecycleStatusCancelRequested = "cancel_requested"
	lifecycleProjectionSourceNomad          = "nomad"
)

type nomadJobSummary struct {
	ID          string              `json:"ID"`
	Status      string              `json:"Status"`
	ModifyIndex uint64              `json:"ModifyIndex"`
	Meta        map[string]string   `json:"Meta"`
	TaskGroups  []nomadJobTaskGroup `json:"TaskGroups"`
}

type nomadJobTaskGroup struct {
	Tasks []nomadJobTask `json:"Tasks"`
}

type nomadJobTask struct {
	Name string            `json:"Name"`
	Env  map[string]string `json:"Env"`
}

type nomadAllocationListEntry struct {
	ID          string `json:"ID"`
	ModifyIndex uint64 `json:"ModifyIndex"`
}

type nomadAllocationDetail struct {
	ID           string                    `json:"ID"`
	ClientStatus string                    `json:"ClientStatus"`
	ModifyIndex  uint64                    `json:"ModifyIndex"`
	TaskStates   map[string]nomadTaskState `json:"TaskStates"`
}

type nomadTaskState struct {
	State  string           `json:"State"`
	Failed bool             `json:"Failed"`
	Events []nomadTaskEvent `json:"Events"`
}

type nomadTaskEvent struct {
	Type     string `json:"Type"`
	ExitCode int    `json:"ExitCode"`
}

func (s nomadTaskState) exitCode() (int, bool) {
	for i := len(s.Events) - 1; i >= 0; i-- {
		if s.Events[i].Type == "Terminated" {
			return s.Events[i].ExitCode, true
		}
	}
	return 0, false
}

func (s *Service) Status(ctx context.Context, runID string) (ExecutionStatusResult, *Error) {
	locator, err := resolveExecutionLocator(runID)
	if err != nil {
		return ExecutionStatusResult{}, err
	}
	if err := s.lifecycleRuntimeUnavailableError(); err != nil {
		return ExecutionStatusResult{}, err
	}

	job, err := s.nomadClient.fetchJob(ctx, locator.JobID())
	if err != nil {
		return ExecutionStatusResult{}, err
	}

	result := ExecutionStatusResult{
		Success:             true,
		RunID:               locator.RunID,
		Status:              executionLifecycleStatusSubmitted,
		LifecycleProjection: lifecycleProjectionFromNomad(job.ModifyIndex),
	}
	if authorityHandoff, ok := authorityHandoffFromNomadJob(job); ok {
		result.AuthorityHandoff = authorityHandoff
	}

	allocation, err := s.nomadClient.fetchProjectedAllocation(ctx, locator.JobID())
	if err != nil {
		return ExecutionStatusResult{}, err
	}
	if allocation == nil {
		result.Terminal = strings.TrimSpace(job.Status) == "dead"
		if result.Terminal {
			result.Status = executionLifecycleStatusTerminal
			if _, retainErr := s.retainTerminalResult(locator); retainErr != nil {
				log.Printf("es result retention failed run_id=%s", locator.RunID)
			}
		}
		result.OutcomeEvidence = statusOutcomeEvidence(outcomeObservationNomadJobProjection, result.LifecycleProjection, result.Terminal)
		return result, nil
	}
	result.LifecycleProjection = lifecycleProjectionFromNomad(job.ModifyIndex, allocation.ModifyIndex)

	result.Status = executionLifecycleStatusRunning
	result.Terminal = isTerminalAllocationStatus(strings.TrimSpace(allocation.ClientStatus))
	observation := outcomeObservationNomadProjectedAllocation

	taskState, ok := allocation.TaskStates[nomadTaskName]
	if !ok {
		if result.Terminal {
			result.Status = executionLifecycleStatusTerminal
			s.maybeRetainTerminalResult(locator, allocation)
		}
		result.OutcomeEvidence = statusOutcomeEvidence(observation, result.LifecycleProjection, result.Terminal)
		return result, nil
	}
	observation = outcomeObservationNomadTaskStateProjection
	if !result.Terminal && strings.TrimSpace(taskState.State) == "dead" {
		result.Terminal = true
	}
	if result.Terminal {
		result.Status = executionLifecycleStatusTerminal
	}
	if exitCode, ok := taskState.exitCode(); ok {
		result.ExitCode = &exitCode
	}
	if result.Terminal {
		s.maybeRetainTerminalResult(locator, allocation)
	}
	result.OutcomeEvidence = statusOutcomeEvidence(observation, result.LifecycleProjection, result.Terminal)

	return result, nil
}

func authorityHandoffFromNomadJob(job nomadJobSummary) (*ExecutionAuthorityHandoff, bool) {
	if strings.TrimSpace(job.Meta[executionAuthorityMetadataSchemaKey]) != executionAuthorityMetadataSchemaVersion {
		return nil, false
	}
	task, ok := job.task(nomadTaskName)
	if !ok {
		return nil, false
	}
	return executionAuthorityHandoffFromSubmittedRuntimeSpec(
		job.Meta[executionAuthorityMetadataRuntimeProfileKey],
		job.Meta[executionAuthorityMetadataWorkloadZoneVaultConfigKey],
		task.Env,
	)
}

func (j nomadJobSummary) task(name string) (nomadJobTask, bool) {
	for _, group := range j.TaskGroups {
		for _, task := range group.Tasks {
			if strings.TrimSpace(task.Name) == name {
				return task, true
			}
		}
	}
	return nomadJobTask{}, false
}

func (s *Service) Logs(ctx context.Context, runID string) (ExecutionLogsResult, *Error) {
	locator, err := resolveExecutionLocator(runID)
	if err != nil {
		return ExecutionLogsResult{}, err
	}
	if err := s.lifecycleRuntimeUnavailableError(); err != nil {
		return ExecutionLogsResult{}, err
	}

	if _, err := s.nomadClient.fetchJob(ctx, locator.JobID()); err != nil {
		return ExecutionLogsResult{}, err
	}

	allocation, err := s.nomadClient.fetchProjectedAllocation(ctx, locator.JobID())
	if err != nil {
		return ExecutionLogsResult{}, err
	}
	if allocation == nil {
		return ExecutionLogsResult{}, &Error{
			Status:  http.StatusConflict,
			Code:    codeLogsUnavailable,
			Message: "execution allocation is not ready",
		}
	}

	taskState, ok := allocation.TaskStates[nomadTaskName]
	if !ok {
		return ExecutionLogsResult{}, &Error{
			Status:  http.StatusConflict,
			Code:    codeLogsUnavailable,
			Message: "execution allocation is not ready",
		}
	}
	switch taskState.State {
	case "running", "dead":
	default:
		return ExecutionLogsResult{}, &Error{
			Status:  http.StatusConflict,
			Code:    codeLogsUnavailable,
			Message: "execution logs are not available yet",
		}
	}

	logs, err := s.nomadClient.fetchTaskLogs(ctx, allocation.ID, nomadTaskName)
	if err != nil {
		return ExecutionLogsResult{}, err
	}
	terminalObserved := allocationTerminal(allocation)
	if terminalObserved {
		s.maybeRetainTerminalResult(locator, allocation)
	}
	return ExecutionLogsResult{
		OutcomeEvidence: logsOutcomeEvidence(terminalObserved),
		Payload:         logs,
	}, nil
}

func (s *Service) Cancel(ctx context.Context, runID string) (ExecutionCancelResult, *Error) {
	locator, err := resolveExecutionLocator(runID)
	if err != nil {
		return ExecutionCancelResult{}, err
	}
	if err := s.lifecycleRuntimeUnavailableError(); err != nil {
		return ExecutionCancelResult{}, err
	}

	if _, err := s.nomadClient.fetchJob(ctx, locator.JobID()); err != nil {
		return ExecutionCancelResult{}, err
	}

	if err := s.nomadClient.stopJob(ctx, locator.JobID()); err != nil {
		return ExecutionCancelResult{}, err
	}

	return ExecutionCancelResult{
		Success:         true,
		RunID:           locator.RunID,
		Status:          executionLifecycleStatusCancelRequested,
		OutcomeEvidence: cancelOutcomeEvidence(),
	}, nil
}

func (s *Service) lifecycleRuntimeUnavailableError() *Error {
	if s.nomadClient == nil || !s.cfg.SubmitConfigured() {
		return nomadUnavailableError("execution runtime is unavailable")
	}
	return nil
}

func isTerminalAllocationStatus(status string) bool {
	switch strings.TrimSpace(status) {
	case "complete", "failed", "lost":
		return true
	default:
		return false
	}
}

func (c *nomadClient) fetchJob(ctx context.Context, jobID string) (nomadJobSummary, *Error) {
	response, err := c.get(ctx, "/v1/job/"+jobID, nil)
	if err != nil {
		return nomadJobSummary{}, nomadUnavailableError("execution runtime is unavailable")
	}
	defer response.Body.Close()

	switch response.StatusCode {
	case http.StatusOK:
		var payload nomadJobSummary
		if err := decodeCompatibleJSONDocument(response.Body, &payload); err != nil {
			return nomadJobSummary{}, nomadUnavailableError("execution runtime returned an invalid job response")
		}
		return payload, nil
	case http.StatusNotFound:
		return nomadJobSummary{}, &Error{
			Status:  http.StatusNotFound,
			Code:    codeExecutionNotFound,
			Message: "execution was not found",
		}
	default:
		return nomadJobSummary{}, nomadUnavailableError(fmt.Sprintf("execution runtime returned status %d", response.StatusCode))
	}
}

func (c *nomadClient) fetchProjectedAllocation(ctx context.Context, jobID string) (*nomadAllocationDetail, *Error) {
	response, err := c.get(ctx, "/v1/job/"+jobID+"/allocations", nil)
	if err != nil {
		return nil, nomadUnavailableError("execution runtime is unavailable")
	}
	defer response.Body.Close()

	if response.StatusCode != http.StatusOK {
		return nil, nomadUnavailableError(fmt.Sprintf("execution runtime returned status %d", response.StatusCode))
	}

	var payload []nomadAllocationListEntry
	if err := decodeBoundedCompatibleJSONDocumentResponse(response, &payload); err != nil {
		return nil, nomadUnavailableError("execution runtime returned an invalid allocation response")
	}
	selected, ok := currentLifecycleProjectionPolicy{}.selectAllocation(payload)
	if !ok {
		return nil, nil
	}

	detail, errResult := c.fetchAllocation(ctx, strings.TrimSpace(selected.ID))
	if errResult != nil {
		return nil, errResult
	}
	if selected.ModifyIndex > detail.ModifyIndex {
		detail.ModifyIndex = selected.ModifyIndex
	}
	return &detail, nil
}

func lifecycleProjectionFromNomad(indices ...uint64) LifecycleProjection {
	hasher := sha256.New()
	_, _ = hasher.Write([]byte("nomad-lifecycle-projection/v1\n"))
	for _, index := range indices {
		_, _ = fmt.Fprintf(hasher, "%d\n", index)
	}
	sum := hasher.Sum(nil)
	return LifecycleProjection{
		Source:   lifecycleProjectionSourceNomad,
		Revision: hex.EncodeToString(sum),
	}
}

func (c *nomadClient) fetchAllocation(ctx context.Context, allocationID string) (nomadAllocationDetail, *Error) {
	response, err := c.get(ctx, "/v1/allocation/"+allocationID, nil)
	if err != nil {
		return nomadAllocationDetail{}, nomadUnavailableError("execution runtime is unavailable")
	}
	defer response.Body.Close()

	switch response.StatusCode {
	case http.StatusOK:
		var payload nomadAllocationDetail
		if err := decodeBoundedCompatibleJSONDocumentResponse(response, &payload); err != nil {
			return nomadAllocationDetail{}, nomadUnavailableError("execution runtime returned an invalid allocation response")
		}
		return payload, nil
	case http.StatusNotFound:
		return nomadAllocationDetail{}, &Error{
			Status:  http.StatusConflict,
			Code:    codeLogsUnavailable,
			Message: "execution allocation is not ready",
		}
	default:
		return nomadAllocationDetail{}, nomadUnavailableError(fmt.Sprintf("execution runtime returned status %d", response.StatusCode))
	}
}

func (c *nomadClient) fetchTaskLogs(ctx context.Context, allocationID string, taskName string) ([]byte, *Error) {
	query := url.Values{}
	query.Set("task", taskName)
	query.Set("follow", "false")
	query.Set("type", "stdout")
	query.Set("offset", "0")
	query.Set("origin", "start")
	query.Set("plain", "true")

	response, err := c.get(ctx, "/v1/client/fs/logs/"+allocationID, query)
	if err != nil {
		return nil, nomadUnavailableError("execution runtime is unavailable")
	}
	defer response.Body.Close()

	switch response.StatusCode {
	case http.StatusOK:
		payload, readErr := io.ReadAll(response.Body)
		if readErr != nil {
			return nil, nomadUnavailableError("execution logs read failed")
		}
		return payload, nil
	case http.StatusNotFound:
		return nil, &Error{
			Status:  http.StatusConflict,
			Code:    codeLogsUnavailable,
			Message: "execution logs are not available",
		}
	default:
		return nil, nomadUnavailableError(fmt.Sprintf("execution logs returned status %d", response.StatusCode))
	}
}

func (c *nomadClient) stopJob(ctx context.Context, jobID string) *Error {
	request, err := c.newJobRequest(ctx, http.MethodDelete, "/v1/job/"+jobID, url.Values{"purge": []string{"false"}}, nil)
	if err != nil {
		return nomadUnavailableError("execution runtime is unavailable")
	}
	response, err := c.client.Do(request)
	if err != nil {
		return nomadUnavailableError("execution runtime is unavailable")
	}
	defer response.Body.Close()

	switch response.StatusCode {
	case http.StatusOK:
		return nil
	case http.StatusNotFound:
		return &Error{
			Status:  http.StatusNotFound,
			Code:    codeExecutionNotFound,
			Message: "execution was not found",
		}
	default:
		return nomadUnavailableError(fmt.Sprintf("execution cancel returned status %d", response.StatusCode))
	}
}

func (c *nomadClient) get(ctx context.Context, requestPath string, query url.Values) (*http.Response, error) {
	request, err := c.newJobRequest(ctx, http.MethodGet, requestPath, query, nil)
	if err != nil {
		return nil, err
	}
	return c.client.Do(request)
}

func nomadUnavailableError(message string) *Error {
	return &Error{
		Status:  http.StatusServiceUnavailable,
		Code:    codeExecutionRuntimeUnavailable,
		Message: message,
	}
}
