package admission

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"path"
	"strings"
)

const nomadTaskName = "task"

const (
	executionLifecycleStatusSubmitted       = "submitted"
	executionLifecycleStatusRunning         = "running"
	executionLifecycleStatusTerminal        = "terminal"
	executionLifecycleStatusCancelRequested = "cancel_requested"
)

type nomadJobSummary struct {
	ID     string `json:"ID"`
	Status string `json:"Status"`
}

type nomadAllocationListEntry struct {
	ID          string `json:"ID"`
	ModifyIndex uint64 `json:"ModifyIndex"`
}

type nomadAllocationDetail struct {
	ID           string                    `json:"ID"`
	ClientStatus string                    `json:"ClientStatus"`
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

	job, err := s.nomadClient.fetchJob(ctx, locator.JobID())
	if err != nil {
		return ExecutionStatusResult{}, err
	}

	result := ExecutionStatusResult{
		Success: true,
		RunID:   locator.RunID,
		Status:  executionLifecycleStatusSubmitted,
	}

	allocation, err := s.nomadClient.fetchProjectedAllocation(ctx, locator.JobID())
	if err != nil {
		return ExecutionStatusResult{}, err
	}
	if allocation == nil {
		result.Terminal = strings.TrimSpace(job.Status) == "dead"
		if result.Terminal {
			result.Status = executionLifecycleStatusTerminal
		}
		return result, nil
	}

	result.Status = executionLifecycleStatusRunning
	result.Terminal = isTerminalAllocationStatus(strings.TrimSpace(allocation.ClientStatus))

	taskState, ok := allocation.TaskStates[nomadTaskName]
	if !ok {
		if result.Terminal {
			result.Status = executionLifecycleStatusTerminal
		}
		return result, nil
	}
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
		s.maybeCleanupSuccessfulStageRoot(locator, allocation)
	}

	return result, nil
}

func (s *Service) Logs(ctx context.Context, runID string) ([]byte, *Error) {
	locator, err := resolveExecutionLocator(runID)
	if err != nil {
		return nil, err
	}

	if _, err := s.nomadClient.fetchJob(ctx, locator.JobID()); err != nil {
		return nil, err
	}

	allocation, err := s.nomadClient.fetchProjectedAllocation(ctx, locator.JobID())
	if err != nil {
		return nil, err
	}
	if allocation == nil {
		return nil, &Error{
			Status:  http.StatusConflict,
			Code:    codeLogsUnavailable,
			Message: "execution allocation is not ready",
		}
	}

	taskState, ok := allocation.TaskStates[nomadTaskName]
	if !ok {
		return nil, &Error{
			Status:  http.StatusConflict,
			Code:    codeLogsUnavailable,
			Message: "execution allocation is not ready",
		}
	}
	switch taskState.State {
	case "running", "dead":
	default:
		return nil, &Error{
			Status:  http.StatusConflict,
			Code:    codeLogsUnavailable,
			Message: "execution logs are not available yet",
		}
	}

	logs, err := s.nomadClient.fetchTaskLogs(ctx, allocation.ID, nomadTaskName)
	if err != nil {
		return nil, err
	}
	s.maybeCleanupSuccessfulStageRoot(locator, allocation)
	return logs, nil
}

func (s *Service) Cancel(ctx context.Context, runID string) (ExecutionCancelResult, *Error) {
	locator, err := resolveExecutionLocator(runID)
	if err != nil {
		return ExecutionCancelResult{}, err
	}

	if _, err := s.nomadClient.fetchJob(ctx, locator.JobID()); err != nil {
		return ExecutionCancelResult{}, err
	}

	if err := s.nomadClient.stopJob(ctx, locator.JobID()); err != nil {
		return ExecutionCancelResult{}, err
	}

	return ExecutionCancelResult{
		Success: true,
		RunID:   locator.RunID,
		Status:  executionLifecycleStatusCancelRequested,
	}, nil
}

func isTerminalAllocationStatus(status string) bool {
	switch strings.TrimSpace(status) {
		case "complete", "failed", "lost":
			return true
		default:
			return false
	}
}

func (s *Service) maybeCleanupSuccessfulStageRoot(locator executionLocator, allocation *nomadAllocationDetail) {
	if !representsTerminalSuccess(allocation) {
		return
	}

	layout := newExecutionPackageLayout(s.cfg, locator)
	if err := os.RemoveAll(layout.stageRootDir); err != nil {
		log.Printf("es successful stage cleanup failed run_id=%s path=%s err=%v", locator.RunID, layout.stageRootDir, err)
	}
}

func representsTerminalSuccess(allocation *nomadAllocationDetail) bool {
	if allocation == nil {
		return false
	}

	taskState, ok := allocation.TaskStates[nomadTaskName]
	if !ok {
		return false
	}

	taskTerminal := strings.TrimSpace(taskState.State) == "dead" || isTerminalAllocationStatus(strings.TrimSpace(allocation.ClientStatus))
	if !taskTerminal {
		return false
	}

	exitCode, ok := taskState.exitCode()
	if !ok {
		return false
	}
	return exitCode == 0
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
			if err := json.NewDecoder(response.Body).Decode(&payload); err != nil {
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
	if err := json.NewDecoder(response.Body).Decode(&payload); err != nil {
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
	return &detail, nil
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
			if err := json.NewDecoder(response.Body).Decode(&payload); err != nil {
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
	query := url.Values{}
	query.Set("purge", "false")

	response, err := c.delete(ctx, "/v1/job/"+jobID, query)
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

func (c *nomadClient) purgeJob(ctx context.Context, jobID string) error {
	query := url.Values{}
	query.Set("purge", "true")

	response, err := c.delete(ctx, "/v1/job/"+jobID, query)
	if err != nil {
		return err
	}
	defer response.Body.Close()

	switch response.StatusCode {
		case http.StatusOK, http.StatusNotFound:
			return nil
		default:
			payload, _ := io.ReadAll(response.Body)
			return fmt.Errorf("purge nomad job: unexpected status %d: %s", response.StatusCode, strings.TrimSpace(string(payload)))
	}
}

func (c *nomadClient) get(ctx context.Context, requestPath string, query url.Values) (*http.Response, error) {
	requestURL := c.baseURL.ResolveReference(&url.URL{Path: path.Clean(requestPath)})
	if query != nil {
		requestURL.RawQuery = query.Encode()
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, requestURL.String(), nil)
	if err != nil {
		return nil, err
	}
	return c.client.Do(request)
}

func (c *nomadClient) delete(ctx context.Context, requestPath string, query url.Values) (*http.Response, error) {
	requestURL := c.baseURL.ResolveReference(&url.URL{Path: path.Clean(requestPath)})
	if query != nil {
		requestURL.RawQuery = query.Encode()
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodDelete, requestURL.String(), nil)
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
