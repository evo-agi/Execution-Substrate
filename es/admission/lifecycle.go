package admission

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path"
	"regexp"
	"sort"
	"strings"
)

const nomadTaskName = "task"

var runIDPattern = regexp.MustCompile(`^run-[0-9a-f]{16}$`)

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
	jobID, err := resolveRunID(runID)
	if err != nil {
		return ExecutionStatusResult{}, err
	}

	job, err := s.nomadClient.fetchJob(ctx, jobID)
	if err != nil {
		return ExecutionStatusResult{}, err
	}

	result := ExecutionStatusResult{
		Success:    true,
		RunID:      runID,
		NomadJobID: jobID,
		JobStatus:  strings.TrimSpace(job.Status),
	}

	allocation, err := s.nomadClient.latestAllocation(ctx, jobID)
	if err != nil {
		return ExecutionStatusResult{}, err
	}
	if allocation == nil {
		result.Terminal = result.JobStatus == "dead"
		return result, nil
	}

	result.AllocationID = strings.TrimSpace(allocation.ID)
	result.AllocationClientStatus = strings.TrimSpace(allocation.ClientStatus)
	result.Terminal = isTerminalAllocationStatus(result.AllocationClientStatus)

	taskState, ok := allocation.TaskStates[nomadTaskName]
	if !ok {
		return result, nil
	}
	result.TaskState = strings.TrimSpace(taskState.State)
	if !result.Terminal && result.TaskState == "dead" {
		result.Terminal = true
	}
	if exitCode, ok := taskState.exitCode(); ok {
		result.ExitCode = &exitCode
	}

	return result, nil
}

func (s *Service) Logs(ctx context.Context, runID string) ([]byte, *Error) {
	jobID, err := resolveRunID(runID)
	if err != nil {
		return nil, err
	}

	if _, err := s.nomadClient.fetchJob(ctx, jobID); err != nil {
		return nil, err
	}

	allocation, err := s.nomadClient.latestAllocation(ctx, jobID)
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

	return s.nomadClient.fetchTaskLogs(ctx, allocation.ID, nomadTaskName)
}

func (s *Service) Cancel(ctx context.Context, runID string) (ExecutionCancelResult, *Error) {
	jobID, err := resolveRunID(runID)
	if err != nil {
		return ExecutionCancelResult{}, err
	}

	if _, err := s.nomadClient.fetchJob(ctx, jobID); err != nil {
		return ExecutionCancelResult{}, err
	}

	if err := s.nomadClient.stopJob(ctx, jobID); err != nil {
		return ExecutionCancelResult{}, err
	}

	return ExecutionCancelResult{
		Success:    true,
		RunID:      runID,
		NomadJobID: jobID,
		Status:     "cancel_requested",
	}, nil
}

func resolveRunID(runID string) (string, *Error) {
	runID = strings.TrimSpace(runID)
	if !runIDPattern.MatchString(runID) {
		return "", &Error{
			Status:  http.StatusBadRequest,
			Code:    codeInvalidRunID,
			Message: "run_id is invalid",
		}
	}
	return "exec-" + runID, nil
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

func (c *nomadClient) latestAllocation(ctx context.Context, jobID string) (*nomadAllocationDetail, *Error) {
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
	if len(payload) == 0 {
		return nil, nil
	}

	sort.SliceStable(payload, func(i, j int) bool {
		return payload[i].ModifyIndex > payload[j].ModifyIndex
	})

	detail, errResult := c.fetchAllocation(ctx, strings.TrimSpace(payload[0].ID))
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
