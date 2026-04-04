package admission

import (
	"crypto/rand"
	"encoding/hex"
	"net/http"
	"regexp"
	"strings"
)

var runIDPattern = regexp.MustCompile(`^run-[0-9a-f]{16}$`)

// executionLocator localizes the current ES-owned mapping between public run
// IDs and the Nomad job IDs used for the bounded lifecycle slice.
type executionLocator struct {
	RunID string
	jobID string
}

func newExecutionLocator() (executionLocator, error) {
	var random [8]byte
	if _, err := rand.Read(random[:]); err != nil {
		return executionLocator{}, err
	}
	return newExecutionLocatorFromRunID("run-" + hex.EncodeToString(random[:])), nil
}

func resolveExecutionLocator(runID string) (executionLocator, *Error) {
	runID = strings.TrimSpace(runID)
	if !runIDPattern.MatchString(runID) {
		return executionLocator{}, &Error{
			Status:  http.StatusBadRequest,
			Code:    codeInvalidRunID,
			Message: "run_id is invalid",
		}
	}
	return newExecutionLocatorFromRunID(runID), nil
}

func newExecutionLocatorFromRunID(runID string) executionLocator {
	runID = strings.TrimSpace(runID)
	return executionLocator{
		RunID: runID,
		jobID: "exec-" + runID,
	}
}

func (l executionLocator) JobID() string {
	return l.jobID
}
