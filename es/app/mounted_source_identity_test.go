package app_test

// This file is a test-owned witness. It does not alter ES admission, Nomad job
// construction, or the runtime. A live result is evidence for one allocation.

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

const (
	mountedSourceTarget      = "/execution/mounts/config"
	mountedSourceFile        = "app.conf"
	mountedSourceReleasePath = "/execution/run/result/.mount-observer-release"
	mountedSourceReadyPath   = "/execution/run/result/.mount-observer-ready"
	mountedSourceReadyText   = "MOUNT-OBSERVER-READY\n"
	mountedSourceText        = "MOUNT-CONTENT\n"
	mountedRegisterLimit     = 512 * 1024
	mountedCommandLimit      = 16 * 1024
)

type mountedObjectIdentity struct {
	Dev  uint64 `json:"dev"`
	Ino  uint64 `json:"ino"`
	Mode uint32 `json:"mode"`
	UID  uint32 `json:"uid"`
	GID  uint32 `json:"gid"`
	Size int64  `json:"size"`
}

func mountedIdentity(info os.FileInfo) (mountedObjectIdentity, error) {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return mountedObjectIdentity{}, errors.New("mount witness: Unix object coordinates unavailable")
	}
	return mountedObjectIdentity{
		Dev: uint64(stat.Dev), Ino: uint64(stat.Ino), Mode: uint32(stat.Mode),
		UID: uint32(stat.Uid), GID: uint32(stat.Gid), Size: info.Size(),
	}, nil
}

func sameMountedIdentity(a, b mountedObjectIdentity, file bool) bool {
	const modeMask = syscall.S_IFMT | 0o7777
	if a.Dev != b.Dev || a.Ino != b.Ino || a.Mode&modeMask != b.Mode&modeMask || a.UID != b.UID || a.GID != b.GID {
		return false
	}
	return !file || a.Size == b.Size
}

type heldMountedSource struct {
	dir         *os.File
	file        *os.File
	sourcePath  string // private host-absolute path; never serialized
	sourceRel   string
	runID       string
	jobID       string
	taskName    string
	directory   mountedObjectIdentity
	regularFile mountedObjectIdentity
	contentHash string
	acquiredAt  time.Time
	closed      bool
}

func openHeldMountedSource(sourcePath, sourceRel, runID, jobID, taskName string) (*heldMountedSource, error) {
	dir, err := os.Open(sourcePath)
	if err != nil {
		return nil, errors.New("mount witness: staged directory unavailable")
	}
	file, err := os.Open(filepath.Join(sourcePath, mountedSourceFile))
	if err != nil {
		_ = dir.Close()
		return nil, errors.New("mount witness: staged file unavailable")
	}
	h := &heldMountedSource{dir: dir, file: file, sourcePath: sourcePath, sourceRel: sourceRel, runID: runID, jobID: jobID, taskName: taskName, acquiredAt: time.Now().UTC()}
	dirInfo, dirErr := dir.Stat()
	fileInfo, fileErr := file.Stat()
	if dirErr != nil || fileErr != nil || !dirInfo.IsDir() || !fileInfo.Mode().IsRegular() || fileInfo.Size() != int64(len(mountedSourceText)) {
		_ = h.close()
		return nil, errors.New("mount witness: staged object shape mismatch")
	}
	h.directory, err = mountedIdentity(dirInfo)
	if err != nil {
		_ = h.close()
		return nil, err
	}
	h.regularFile, err = mountedIdentity(fileInfo)
	if err != nil {
		_ = h.close()
		return nil, err
	}
	content := make([]byte, len(mountedSourceText))
	if _, err := file.ReadAt(content, 0); err != nil || string(content) != mountedSourceText {
		_ = h.close()
		return nil, errors.New("mount witness: staged synthetic content mismatch")
	}
	h.contentHash = fmt.Sprintf("%x", sha256.Sum256(content))
	if err := h.verifyVisibleBinding(); err != nil {
		_ = h.close()
		return nil, err
	}
	return h, nil
}

func (h *heldMountedSource) verifyVisibleBinding() error {
	if h == nil || h.closed {
		return errors.New("mount witness: source handle unavailable")
	}
	dirHeld, err := h.dir.Stat()
	if err != nil {
		return errors.New("mount witness: held directory unavailable")
	}
	fileHeld, err := h.file.Stat()
	if err != nil {
		return errors.New("mount witness: held file unavailable")
	}
	dirVisible, err := os.Lstat(h.sourcePath)
	if err != nil || !dirVisible.IsDir() || !os.SameFile(dirHeld, dirVisible) {
		return errors.New("mount witness: staged directory binding changed")
	}
	fileVisible, err := os.Lstat(filepath.Join(h.sourcePath, mountedSourceFile))
	if err != nil || !fileVisible.Mode().IsRegular() || !os.SameFile(fileHeld, fileVisible) {
		return errors.New("mount witness: staged file binding changed")
	}
	for _, pair := range []struct {
		info os.FileInfo
		want mountedObjectIdentity
		file bool
	}{
		{dirHeld, h.directory, false}, {dirVisible, h.directory, false},
		{fileHeld, h.regularFile, true}, {fileVisible, h.regularFile, true},
	} {
		got, err := mountedIdentity(pair.info)
		if err != nil || !sameMountedIdentity(got, pair.want, pair.file) {
			return errors.New("mount witness: staged object metadata drift")
		}
	}
	content := make([]byte, len(mountedSourceText))
	if _, err := h.file.ReadAt(content, 0); err != nil || fmt.Sprintf("%x", sha256.Sum256(content)) != h.contentHash {
		return errors.New("mount witness: staged file content drift")
	}
	return nil
}

func (h *heldMountedSource) close() error {
	if h == nil || h.closed {
		return nil
	}
	h.closed = true
	fileErr := h.file.Close()
	dirErr := h.dir.Close()
	if fileErr != nil || dirErr != nil {
		return errors.New("mount witness: source handle close failed")
	}
	return nil
}

type mountedSourceRegistrationCapture struct {
	mu    sync.Mutex
	count int
	held  *heldMountedSource
}

func (c *mountedSourceRegistrationCapture) acquire(stagingRoot string, body []byte) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.count++
	if c.count != 1 {
		return errors.New("mount witness: duplicate provider registration")
	}
	var request struct {
		Job struct {
			ID         string            `json:"ID"`
			Meta       map[string]string `json:"Meta"`
			TaskGroups []struct {
				Tasks []struct {
					Name   string            `json:"Name"`
					Meta   map[string]string `json:"Meta"`
					Config struct {
						Mounts []struct {
							Type     string `json:"type"`
							Source   string `json:"source"`
							Target   string `json:"target"`
							ReadOnly bool   `json:"readonly"`
						} `json:"mounts"`
					} `json:"Config"`
				} `json:"Tasks"`
			} `json:"TaskGroups"`
		} `json:"Job"`
	}
	if err := json.Unmarshal(body, &request); err != nil || len(request.Job.TaskGroups) != 1 || len(request.Job.TaskGroups[0].Tasks) != 1 {
		return errors.New("mount witness: malformed provider registration")
	}
	runID := request.Job.Meta["run_id"]
	jobID := request.Job.ID
	task := request.Job.TaskGroups[0].Tasks[0]
	if !validMountedRunID(runID) || jobID != "exec-"+runID || task.Name != "task" || task.Meta["run_id"] != runID {
		return errors.New("mount witness: provider registration identity mismatch")
	}
	wantSource := filepath.Join(stagingRoot, runID, "mounts", "00", "contents")
	matching := 0
	for _, mount := range task.Config.Mounts {
		if mount.Target == mountedSourceTarget {
			matching++
			if mount.Type != "bind" || mount.Source != wantSource || !mount.ReadOnly {
				return errors.New("mount witness: provider mount declaration mismatch")
			}
		}
	}
	if matching != 1 {
		return errors.New("mount witness: ambiguous provider mount declaration")
	}
	held, err := openHeldMountedSource(wantSource, "mounts/00/contents", runID, jobID, task.Name)
	if err != nil {
		return err
	}
	c.held = held // acquired after ES handoff validation and before forwarding
	return nil
}

func (c *mountedSourceRegistrationCapture) require(runID string) (*heldMountedSource, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.count != 1 || c.held == nil || c.held.runID != runID {
		return nil, errors.New("mount witness: registration source binding unavailable")
	}
	return c.held, nil
}

func (c *mountedSourceRegistrationCapture) close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.held.close()
}

func (c *mountedSourceRegistrationCapture) boundJobID() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.count < 1 || c.held == nil {
		return ""
	}
	return c.held.jobID
}

func validMountedRunID(value string) bool {
	return regexp.MustCompile(`^run-[0-9a-f]{16}$`).MatchString(value)
}

type mountedRegistrationTransport struct {
	next        http.RoundTripper
	stagingRoot string
	capture     *mountedSourceRegistrationCapture
}

func (transport *mountedRegistrationTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	if request.Method == http.MethodPost && request.URL.Path == "/v1/jobs" {
		body, err := io.ReadAll(io.LimitReader(request.Body, mountedRegisterLimit+1))
		if err != nil || len(body) > mountedRegisterLimit {
			return nil, errors.New("mount witness: bounded provider request unavailable")
		}
		_ = request.Body.Close()
		request.Body = io.NopCloser(bytes.NewReader(body))
		request.ContentLength = int64(len(body))
		if err := transport.capture.acquire(transport.stagingRoot, body); err != nil {
			return nil, err
		}
	}
	return transport.next.RoundTrip(request)
}

// The proxy presents the test Nomad's own certificate, so ES's pinned HTTPS
// checks pass through it, and reaches that Nomad trusting only its CA.
func newMountedSourceRegistrationProxy(nomadURL string, nomadTLS nomadTLSMaterial, stagingRoot string, capture *mountedSourceRegistrationCapture) (*httptest.Server, error) {
	target, err := url.Parse(nomadURL)
	if err != nil || target.Scheme != "https" || target.Hostname() != "127.0.0.1" || capture == nil {
		return nil, errors.New("mount witness: test-owned Nomad target unavailable")
	}
	proxy := httputil.NewSingleHostReverseProxy(target)
	proxy.Transport = &mountedRegistrationTransport{next: nomadTLS.transport(), stagingRoot: stagingRoot, capture: capture}
	proxy.ErrorHandler = func(writer http.ResponseWriter, _ *http.Request, _ error) {
		http.Error(writer, "test-owned provider registration refused", http.StatusBadGateway)
	}
	return nomadTLS.startTLSServer(proxy)
}

type mountedSourceObservation struct {
	runID, jobID, taskName, allocationID, containerID string
	allocationRunning, containerRunning               bool
	containerCount, mountCount                        int
	dockerAllocationLabel, dockerTaskLabel            string
	dockerSource, dockerTarget                        string
	dockerReadOnly                                    bool
	localDockerSocket, sameKernel                     bool
	allocationObserved, dockerLabelsObserved          bool
	dockerMountInspected, containerStatObserved       bool
	containerContentObserved, sourceBindingObserved   bool
	directory, regularFile                            mountedObjectIdentity
	contentHash                                       string
	observedAt                                        time.Time
}

func compareMountedSourceIdentity(anchor *heldMountedSource, observed mountedSourceObservation) error {
	if err := anchor.verifyVisibleBinding(); err != nil {
		return err
	}
	if observed.runID != anchor.runID || observed.jobID != anchor.jobID || observed.taskName != anchor.taskName ||
		observed.allocationID == "" || observed.containerID == "" ||
		observed.dockerAllocationLabel != observed.allocationID || observed.dockerTaskLabel != anchor.taskName {
		return errors.New("mount witness: run, job, task, allocation or container correlation failed")
	}
	if !observed.allocationRunning || !observed.containerRunning || observed.containerCount != 1 {
		return errors.New("mount witness: unique live governed container unavailable")
	}
	if observed.mountCount != 1 || observed.dockerSource != anchor.sourcePath || observed.dockerTarget != mountedSourceTarget || !observed.dockerReadOnly {
		return errors.New("mount witness: installed read-only mount mismatch")
	}
	if !observed.localDockerSocket || !observed.sameKernel {
		return errors.New("mount witness: common filesystem identity domain unproved")
	}
	if !observed.allocationObserved || !observed.dockerLabelsObserved || !observed.dockerMountInspected ||
		!observed.containerStatObserved || !observed.containerContentObserved || !observed.sourceBindingObserved {
		return errors.New("mount witness: direct installed-object observation incomplete")
	}
	if !sameMountedIdentity(anchor.directory, observed.directory, false) || !sameMountedIdentity(anchor.regularFile, observed.regularFile, true) {
		return errors.New("mount witness: container-visible backing object differs")
	}
	if observed.contentHash != anchor.contentHash {
		return errors.New("mount witness: container-visible synthetic content differs")
	}
	return anchor.verifyVisibleBinding()
}

type mountedNomadMount struct {
	Type     string `json:"type"`
	Source   string `json:"source"`
	Target   string `json:"target"`
	ReadOnly bool   `json:"readonly"`
}

type mountedNomadJob struct {
	ID         string            `json:"ID"`
	Meta       map[string]string `json:"Meta"`
	TaskGroups []struct {
		Tasks []struct {
			Name   string            `json:"Name"`
			Meta   map[string]string `json:"Meta"`
			Config struct {
				Mounts []mountedNomadMount `json:"mounts"`
			} `json:"Config"`
		} `json:"Tasks"`
	} `json:"TaskGroups"`
}

func validateMountedSourceJob(job mountedNomadJob, anchor *heldMountedSource) error {
	if job.ID != anchor.jobID || job.Meta["run_id"] != anchor.runID || len(job.TaskGroups) != 1 || len(job.TaskGroups[0].Tasks) != 1 {
		return errors.New("mount witness: observed Nomad job identity mismatch")
	}
	task := job.TaskGroups[0].Tasks[0]
	if task.Name != anchor.taskName || task.Meta["run_id"] != anchor.runID {
		return errors.New("mount witness: observed Nomad task mismatch")
	}
	count := 0
	for _, mount := range task.Config.Mounts {
		if mount.Target == mountedSourceTarget {
			count++
			if mount.Type != "bind" || mount.Source != anchor.sourcePath || !mount.ReadOnly {
				return errors.New("mount witness: observed Nomad mount mismatch")
			}
		}
	}
	if count != 1 {
		return errors.New("mount witness: ambiguous observed Nomad mount")
	}
	return nil
}

func (n *nomadHarness) mountedNomadEndpoint() (string, error) {
	target, err := url.Parse(n.addr)
	if err != nil || target.Scheme != "https" || target.Hostname() != "127.0.0.1" || target.Port() == "" ||
		target.User != nil || target.Path != "" || target.RawQuery != "" || target.Fragment != "" {
		return "", errors.New("mount witness: test-owned Nomad endpoint unavailable")
	}
	return n.addr, nil
}

func (n *nomadHarness) mountedLocalNomadClient() *http.Client {
	client := n.httpClient(2 * time.Second)
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return client
}

func (n *nomadHarness) mountedNomadRead(ctx context.Context, path string, limit int64) ([]byte, int, error) {
	base, err := n.mountedNomadEndpoint()
	if err != nil {
		return nil, 0, err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, base+path, nil)
	if err != nil {
		return nil, 0, errors.New("mount witness: Nomad observation request unavailable")
	}
	response, err := n.mountedLocalNomadClient().Do(request)
	if err != nil {
		return nil, 0, errors.New("mount witness: Nomad observation unavailable")
	}
	data, err := readMountedBounded(response.Body, limit)
	if err != nil {
		return nil, 0, err
	}
	return data, response.StatusCode, nil
}

func (n *nomadHarness) fetchMountedSourceJob(ctx context.Context, anchor *heldMountedSource) (mountedNomadJob, error) {
	for ctx.Err() == nil {
		data, status, err := n.mountedNomadRead(ctx, "/v1/job/"+url.PathEscape(anchor.jobID), 64*1024)
		if err != nil {
			return mountedNomadJob{}, err
		}
		if status == http.StatusOK {
			var job mountedNomadJob
			if json.Unmarshal(data, &job) != nil {
				return mountedNomadJob{}, errors.New("mount witness: malformed Nomad job observation")
			}
			if err := validateMountedSourceJob(job, anchor); err != nil {
				return mountedNomadJob{}, err
			}
			return job, nil
		}
		if status != http.StatusNotFound {
			return mountedNomadJob{}, errors.New("mount witness: Nomad job observation refused")
		}
		select {
		case <-ctx.Done():
		case <-time.After(100 * time.Millisecond):
		}
	}
	return mountedNomadJob{}, errors.New("mount witness: Nomad job observation timed out")
}

func readMountedBounded(body io.ReadCloser, limit int64) ([]byte, error) {
	defer body.Close()
	data, err := io.ReadAll(io.LimitReader(body, limit+1))
	if err != nil || int64(len(data)) > limit {
		return nil, errors.New("mount witness: bounded response unavailable")
	}
	return data, nil
}

func (n *nomadHarness) waitForUniqueRunningMountedAllocation(jobID, taskName string, timeout time.Duration) (nomadAllocationSummary, error) {
	base, err := n.mountedNomadEndpoint()
	if err != nil {
		return nomadAllocationSummary{}, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	client := n.mountedLocalNomadClient()
	for ctx.Err() == nil {
		request, err := http.NewRequestWithContext(ctx, http.MethodGet, base+"/v1/job/"+jobID+"/allocations", nil)
		if err != nil {
			return nomadAllocationSummary{}, errors.New("mount witness: allocation request unavailable")
		}
		response, err := client.Do(request)
		if err == nil {
			data, readErr := readMountedBounded(response.Body, 64*1024)
			if readErr != nil {
				return nomadAllocationSummary{}, readErr
			}
			if response.StatusCode == http.StatusOK {
				var list []nomadAllocationSummary
				if err := json.Unmarshal(data, &list); err != nil {
					return nomadAllocationSummary{}, errors.New("mount witness: malformed allocation list")
				}
				if len(list) > 1 {
					return nomadAllocationSummary{}, errors.New("mount witness: ambiguous allocations")
				}
				if len(list) == 1 {
					if list[0].ID == "" || list[0].JobID != jobID {
						return nomadAllocationSummary{}, errors.New("mount witness: allocation job mismatch")
					}
					detailRequest, reqErr := http.NewRequestWithContext(ctx, http.MethodGet, base+"/v1/allocation/"+url.PathEscape(list[0].ID), nil)
					if reqErr != nil {
						return nomadAllocationSummary{}, errors.New("mount witness: allocation detail request unavailable")
					}
					detailResponse, detailErr := client.Do(detailRequest)
					if detailErr == nil {
						detailData, boundedErr := readMountedBounded(detailResponse.Body, 64*1024)
						if boundedErr != nil {
							return nomadAllocationSummary{}, boundedErr
						}
						if detailResponse.StatusCode == http.StatusOK {
							var detail nomadAllocationSummary
							if err := json.Unmarshal(detailData, &detail); err != nil || detail.ID != list[0].ID || detail.JobID != jobID {
								return nomadAllocationSummary{}, errors.New("mount witness: allocation detail mismatch")
							}
							if detail.ClientStatus == "complete" || detail.ClientStatus == "failed" || detail.ClientStatus == "lost" {
								return nomadAllocationSummary{}, errors.New("mount witness: allocation ended before observation")
							}
							if detail.ClientStatus == "running" {
								if len(detail.TaskStates) != 1 || detail.TaskStates[taskName].State != "running" {
									return nomadAllocationSummary{}, errors.New("mount witness: governed task mismatch")
								}
								return detail, nil
							}
						}
					}
				}
			}
		}
		select {
		case <-ctx.Done():
		case <-time.After(100 * time.Millisecond):
		}
	}
	return nomadAllocationSummary{}, errors.New("mount witness: running allocation observation timed out")
}

func (n *nomadHarness) verifyUniqueMountedAllocation(jobID, allocationID string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, n.addr+"/v1/job/"+jobID+"/allocations", nil)
	if err != nil {
		return errors.New("mount witness: terminal allocation request unavailable")
	}
	response, err := n.httpClient(2 * time.Second).Do(request)
	if err != nil {
		return errors.New("mount witness: terminal allocation list unavailable")
	}
	data, err := readMountedBounded(response.Body, 64*1024)
	if err != nil || response.StatusCode != http.StatusOK {
		return errors.New("mount witness: terminal allocation list unavailable")
	}
	var list []nomadAllocationSummary
	if err := json.Unmarshal(data, &list); err != nil || len(list) != 1 || list[0].ID != allocationID || list[0].JobID != jobID {
		return errors.New("mount witness: terminal allocation is ambiguous")
	}
	return nil
}

type mountedTerminalAllocation struct {
	ID           string `json:"ID"`
	JobID        string `json:"JobID"`
	ClientStatus string `json:"ClientStatus"`
	TaskStates   map[string]struct {
		State  string `json:"State"`
		Failed bool   `json:"Failed"`
		Events []struct {
			Type     string `json:"Type"`
			ExitCode *int   `json:"ExitCode"`
		} `json:"Events"`
	} `json:"TaskStates"`
}

func (n *nomadHarness) waitForMountedTerminalAllocation(anchor *heldMountedSource, allocationID string, timeout time.Duration) (time.Time, error) {
	if allocationID == "" || anchor == nil {
		return time.Time{}, errors.New("mount witness: terminal binding unavailable")
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	for ctx.Err() == nil {
		listBytes, status, err := n.mountedNomadRead(ctx, "/v1/job/"+url.PathEscape(anchor.jobID)+"/allocations", 64*1024)
		if err != nil || status != http.StatusOK {
			return time.Time{}, errors.New("mount witness: terminal allocation list unavailable")
		}
		var list []struct {
			ID    string `json:"ID"`
			JobID string `json:"JobID"`
		}
		if json.Unmarshal(listBytes, &list) != nil || len(list) != 1 || list[0].ID != allocationID || list[0].JobID != anchor.jobID {
			return time.Time{}, errors.New("mount witness: terminal allocation binding mismatch")
		}
		detailBytes, status, err := n.mountedNomadRead(ctx, "/v1/allocation/"+url.PathEscape(allocationID), 64*1024)
		if err != nil || status != http.StatusOK {
			return time.Time{}, errors.New("mount witness: terminal allocation detail unavailable")
		}
		var detail mountedTerminalAllocation
		if json.Unmarshal(detailBytes, &detail) != nil || detail.ID != allocationID || detail.JobID != anchor.jobID {
			return time.Time{}, errors.New("mount witness: terminal allocation detail mismatch")
		}
		switch detail.ClientStatus {
		case "complete":
			if len(detail.TaskStates) != 1 {
				return time.Time{}, errors.New("mount witness: terminal governed task missing")
			}
			task, ok := detail.TaskStates[anchor.taskName]
			if !ok || task.State != "dead" || task.Failed {
				return time.Time{}, errors.New("mount witness: terminal governed task failed")
			}
			terminations := 0
			for _, event := range task.Events {
				if event.Type == "Terminated" {
					terminations++
					if event.ExitCode == nil || *event.ExitCode != 0 {
						return time.Time{}, errors.New("mount witness: terminal governed task exit failed")
					}
				}
			}
			if terminations != 1 {
				return time.Time{}, errors.New("mount witness: terminal exit evidence missing or ambiguous")
			}
			return time.Now().UTC(), nil
		case "failed", "lost":
			return time.Time{}, errors.New("mount witness: terminal allocation failed")
		case "pending", "running":
		default:
			return time.Time{}, errors.New("mount witness: terminal allocation status malformed")
		}
		select {
		case <-ctx.Done():
		case <-time.After(100 * time.Millisecond):
		}
	}
	return time.Time{}, errors.New("mount witness: terminal allocation observation timed out")
}

func (n *nomadHarness) cancelMountedJob(jobID string) error {
	if !strings.HasPrefix(jobID, "exec-") || !validMountedRunID(strings.TrimPrefix(jobID, "exec-")) {
		return errors.New("mount witness: job cancellation identity unavailable")
	}
	if _, err := n.mountedNomadEndpoint(); err != nil {
		return errors.New("mount witness: test-owned Nomad cancellation target unavailable")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	request, err := http.NewRequestWithContext(ctx, http.MethodDelete, n.addr+"/v1/job/"+url.PathEscape(jobID)+"?purge=true", nil)
	if err != nil {
		return errors.New("mount witness: test-owned job cancellation request unavailable")
	}
	response, err := n.mountedLocalNomadClient().Do(request)
	if err != nil {
		return errors.New("mount witness: test-owned job cancellation failed")
	}
	if _, err := readMountedBounded(response.Body, 1024); err != nil || (response.StatusCode != http.StatusOK && response.StatusCode != http.StatusNoContent) {
		return errors.New("mount witness: test-owned job cancellation failed")
	}
	return nil
}

type mountedBoundedCapture struct {
	data     []byte
	limit    int
	overflow bool
}

func (capture *mountedBoundedCapture) Write(data []byte) (int, error) {
	available := capture.limit - len(capture.data)
	if available > 0 {
		keep := len(data)
		if keep > available {
			keep = available
		}
		capture.data = append(capture.data, data[:keep]...)
	}
	if len(data) > available {
		capture.overflow = true
	}
	return len(data), nil // drain excess without buffering or exposing it
}

func runMountedBoundedCommand(ctx context.Context, name string, args ...string) ([]byte, error) {
	command := exec.CommandContext(ctx, name, args...)
	command.WaitDelay = 2 * time.Second
	stdout := &mountedBoundedCapture{limit: mountedCommandLimit}
	stderr := &mountedBoundedCapture{limit: 1024}
	command.Stdout, command.Stderr = stdout, stderr
	err := command.Run()
	if ctx.Err() != nil {
		return nil, errors.New("mount witness: observer command timed out")
	}
	if stdout.overflow || stderr.overflow {
		return nil, errors.New("mount witness: observer command output exceeded cap")
	}
	if err != nil {
		return nil, errors.New("mount witness: observer command exited nonzero")
	}
	return stdout.data, nil
}

func runMountedDocker(ctx context.Context, args ...string) ([]byte, error) {
	return runMountedBoundedCommand(ctx, "docker", append([]string{"--host", "unix:///var/run/docker.sock"}, args...)...)
}

func parseMountedDockerSelection(output []byte) (string, int, error) {
	trimmed := strings.TrimSpace(string(output))
	if trimmed == "" {
		return "", 0, nil
	}
	lines := strings.Split(trimmed, "\n")
	if len(lines) != 1 || !regexp.MustCompile(`^[0-9a-f]{64}$`).MatchString(lines[0]) {
		return "", len(lines), errors.New("mount witness: ambiguous or malformed Docker selection")
	}
	return lines[0], 1, nil
}

func parseMountedDockerLabels(output []byte) (string, bool, string, string, error) {
	parts := strings.Split(strings.TrimSpace(string(output)), "\t")
	if len(parts) != 4 || !regexp.MustCompile(`^[0-9a-f]{64}$`).MatchString(parts[0]) || (parts[1] != "true" && parts[1] != "false") {
		return "", false, "", "", errors.New("mount witness: malformed Docker label observation")
	}
	return parts[0], parts[1] == "true", parts[2], parts[3], nil
}

func parseMountedDockerMounts(output []byte) (string, string, bool, int, error) {
	var source, target string
	readonly := false
	count := 0
	for _, line := range strings.Split(strings.TrimSpace(string(output)), "\n") {
		if line == "" {
			continue
		}
		parts := strings.Split(line, "\t")
		if len(parts) != 4 || (parts[3] != "true" && parts[3] != "false") {
			return "", "", false, 0, errors.New("mount witness: malformed Docker mount observation")
		}
		if parts[2] == mountedSourceTarget {
			count++
			if parts[0] != "bind" {
				return "", "", false, count, errors.New("mount witness: installed mount is not a bind")
			}
			source, target, readonly = parts[1], parts[2], parts[3] == "false"
		}
	}
	return source, target, readonly, count, nil
}

func parseMountedStatLine(line string) (mountedObjectIdentity, error) {
	fields := strings.Fields(line)
	if len(fields) != 6 {
		return mountedObjectIdentity{}, errors.New("mount witness: malformed container stat")
	}
	values := make([]uint64, len(fields))
	for i, field := range fields {
		base := 10
		if i == 4 {
			base = 16
		}
		parsed, err := strconv.ParseUint(field, base, 64)
		if err != nil {
			return mountedObjectIdentity{}, errors.New("mount witness: malformed container stat")
		}
		values[i] = parsed
	}
	if values[2] > 1<<32-1 || values[3] > 1<<32-1 || values[4] > 1<<32-1 || values[5] > 1<<63-1 {
		return mountedObjectIdentity{}, errors.New("mount witness: container stat out of bounds")
	}
	return mountedObjectIdentity{Dev: values[0], Ino: values[1], UID: uint32(values[2]), GID: uint32(values[3]), Mode: uint32(values[4]), Size: int64(values[5])}, nil
}

func parseMountedDockerStats(output []byte) (mountedObjectIdentity, mountedObjectIdentity, error) {
	lines := strings.Split(strings.TrimSpace(string(output)), "\n")
	if len(lines) != 2 {
		return mountedObjectIdentity{}, mountedObjectIdentity{}, errors.New("mount witness: missing container object stat")
	}
	directory, err := parseMountedStatLine(lines[0])
	if err != nil {
		return mountedObjectIdentity{}, mountedObjectIdentity{}, err
	}
	file, err := parseMountedStatLine(lines[1])
	if err != nil {
		return mountedObjectIdentity{}, mountedObjectIdentity{}, err
	}
	return directory, file, nil
}

func readMountedBootID() (string, error) {
	file, err := os.Open("/proc/sys/kernel/random/boot_id")
	if err != nil {
		return "", errors.New("mount witness: native host boot identity unavailable")
	}
	data, err := readMountedBounded(file, 128)
	if err != nil || strings.TrimSpace(string(data)) == "" {
		return "", errors.New("mount witness: native host boot identity unavailable")
	}
	return strings.TrimSpace(string(data)), nil
}

type mountedSourceWitnessSession struct {
	capture           *mountedSourceRegistrationCapture
	containerID       string
	readyObserved     bool
	readyAt           time.Time
	released          bool
	completed         bool
	releasedAt        time.Time
	terminalObserved  bool
	terminalAt        time.Time
	cleanupResult     string
	stopResult        string
	jobCancelResult   string
	handleCloseResult string
	releaseFunc       func(string) error
	stopFunc          func(string) error
	cancelFunc        func(string) error
}

func newMountedSourceWitnessSession(capture *mountedSourceRegistrationCapture) *mountedSourceWitnessSession {
	session := &mountedSourceWitnessSession{capture: capture}
	session.releaseFunc = func(containerID string) error {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_, err := runMountedDocker(ctx, "exec", containerID, "/bin/sh", "-c", "printf x > "+mountedSourceReleasePath)
		return err
	}
	session.stopFunc = func(containerID string) error {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_, err := runMountedDocker(ctx, "stop", "--time", "1", containerID)
		return err
	}
	return session
}

func (session *mountedSourceWitnessSession) setContainer(containerID string) error {
	if session.containerID != "" || !regexp.MustCompile(`^[0-9a-f]{64}$`).MatchString(containerID) {
		return errors.New("mount witness: container selection changed")
	}
	session.containerID = containerID
	return nil
}

func (session *mountedSourceWitnessSession) markReady() error {
	if session.containerID == "" || session.readyObserved {
		return errors.New("mount witness: ready acknowledgement lacks admitted container")
	}
	session.readyObserved = true
	session.readyAt = time.Now().UTC()
	return nil
}

func (session *mountedSourceWitnessSession) release() error {
	if session.released {
		return nil
	}
	if session.containerID == "" || !session.readyObserved || session.releaseFunc == nil {
		return errors.New("mount witness: barrier release unavailable")
	}
	if err := session.releaseFunc(session.containerID); err != nil {
		return err
	}
	session.released = true
	session.releasedAt = time.Now().UTC()
	return nil
}

func (session *mountedSourceWitnessSession) markTerminal(at time.Time) error {
	if !session.released || session.terminalObserved || at.Before(session.releasedAt) {
		return errors.New("mount witness: terminal observation ordering invalid")
	}
	session.terminalObserved = true
	session.terminalAt = at.UTC()
	return nil
}

func (session *mountedSourceWitnessSession) complete() error {
	if !session.readyObserved || !session.released || !session.terminalObserved {
		return errors.New("mount witness: ready, release or terminal evidence missing")
	}
	if err := session.capture.close(); err != nil {
		return err
	}
	session.completed = true
	session.cleanupResult = "barrier_released_handles_closed"
	return nil
}

func (session *mountedSourceWitnessSession) teardown() {
	if session.completed {
		return
	}
	if session.containerID != "" && !session.released {
		if session.readyObserved {
			if err := session.release(); err == nil {
				session.cleanupResult = "release_request_succeeded_on_failure"
			} else {
				session.cleanupResult = "release_request_failed_stop_attempted"
			}
		} else {
			session.cleanupResult = "not_ready_stop_attempted"
		}
		if !session.released {
			if session.stopFunc != nil {
				if err := session.stopFunc(session.containerID); err != nil {
					session.stopResult = "request_failed"
				} else {
					session.stopResult = "request_succeeded"
				}
			} else {
				session.stopResult = "request_unavailable"
			}
		}
	}
	if session.capture != nil {
		if jobID := session.capture.boundJobID(); jobID != "" {
			if session.cancelFunc == nil || session.cancelFunc(jobID) != nil {
				session.jobCancelResult = "request_failed"
			} else {
				session.jobCancelResult = "request_succeeded"
			}
		}
		if err := session.capture.close(); err != nil {
			session.handleCloseResult = "failed"
		} else {
			session.handleCloseResult = "succeeded"
		}
	}
	if session.cleanupResult == "" {
		if session.released {
			session.cleanupResult = "release_request_succeeded_terminal_or_lifecycle_unproved"
		} else {
			session.cleanupResult = "handles_closed_no_admitted_container"
		}
	}
}

type mountedDockerCommand func(context.Context, ...string) ([]byte, error)

type admittedMountedContainer struct {
	id, allocationLabel, taskLabel string
}

func selectAndAdmitMountedContainer(ctx context.Context, allocation nomadAllocationSummary, taskName string, session *mountedSourceWitnessSession, docker mountedDockerCommand) (admittedMountedContainer, error) {
	selectionCtx, cancel := context.WithTimeout(ctx, 45*time.Second)
	defer cancel()
	for selectionCtx.Err() == nil {
		output, err := docker(selectionCtx, "ps", "--no-trunc", "--filter", "label=com.hashicorp.nomad.alloc_id="+allocation.ID, "--format", "{{.ID}}")
		if err != nil {
			return admittedMountedContainer{}, err
		}
		candidate, count, err := parseMountedDockerSelection(output)
		if err != nil {
			return admittedMountedContainer{}, err
		}
		if count == 1 {
			labelFormat := `{{.Id}}{{printf "\t"}}{{.State.Running}}{{printf "\t"}}{{index .Config.Labels "com.hashicorp.nomad.alloc_id"}}{{printf "\t"}}{{index .Config.Labels "com.hashicorp.nomad.task_name"}}`
			labels, err := docker(selectionCtx, "inspect", "--format", labelFormat, candidate)
			if err != nil {
				return admittedMountedContainer{}, err
			}
			id, running, allocationLabel, taskLabel, err := parseMountedDockerLabels(labels)
			if err != nil || id != candidate || !running || allocationLabel != allocation.ID || taskLabel != taskName {
				return admittedMountedContainer{}, errors.New("mount witness: Docker candidate admission refused")
			}
			if err := session.setContainer(candidate); err != nil {
				return admittedMountedContainer{}, err
			}
			return admittedMountedContainer{id: candidate, allocationLabel: allocationLabel, taskLabel: taskLabel}, nil
		}
		select {
		case <-selectionCtx.Done():
		case <-time.After(100 * time.Millisecond):
		}
	}
	return admittedMountedContainer{}, errors.New("mount witness: governed container selection timed out")
}

func waitForMountedWorkloadReady(ctx context.Context, session *mountedSourceWitnessSession, docker mountedDockerCommand) error {
	if session.containerID == "" {
		return errors.New("mount witness: ready observation lacks admitted container")
	}
	readyCtx, cancel := context.WithTimeout(ctx, 45*time.Second)
	defer cancel()
	readyScript := `if [ -f ` + mountedSourceReadyPath + ` ]; then cat ` + mountedSourceReadyPath + `; else printf 'MISSING\n'; fi`
	for readyCtx.Err() == nil {
		running, err := docker(readyCtx, "inspect", "--format", "{{.State.Running}}", session.containerID)
		if err != nil || string(running) == "false\n" {
			return errors.New("mount witness: admitted container exited before readiness")
		}
		if string(running) != "true\n" {
			return errors.New("mount witness: malformed admitted container state")
		}
		marker, err := docker(readyCtx, "exec", session.containerID, "/bin/sh", "-c", readyScript)
		if err != nil {
			return errors.New("mount witness: ready acknowledgement unavailable")
		}
		if string(marker) == mountedSourceReadyText {
			return session.markReady()
		}
		if string(marker) != "MISSING\n" {
			return errors.New("mount witness: malformed ready acknowledgement")
		}
		select {
		case <-readyCtx.Done():
		case <-time.After(100 * time.Millisecond):
		}
	}
	return errors.New("mount witness: workload readiness timed out")
}

func observeMountedSourceWithCommands(ctx context.Context, anchor *heldMountedSource, allocation nomadAllocationSummary, session *mountedSourceWitnessSession, hostBootID string, docker mountedDockerCommand) (mountedSourceObservation, error) {
	if err := anchor.verifyVisibleBinding(); err != nil {
		return mountedSourceObservation{}, err
	}
	admitted, err := selectAndAdmitMountedContainer(ctx, allocation, anchor.taskName, session, docker)
	if err != nil {
		return mountedSourceObservation{}, err
	}
	if err := waitForMountedWorkloadReady(ctx, session, docker); err != nil {
		return mountedSourceObservation{}, err
	}
	mountFormat := `{{range .Mounts}}{{.Type}}{{printf "\t"}}{{.Source}}{{printf "\t"}}{{.Destination}}{{printf "\t"}}{{.RW}}{{println}}{{end}}`
	mountOutput, err := docker(ctx, "inspect", "--format", mountFormat, admitted.id)
	if err != nil {
		return mountedSourceObservation{}, err
	}
	source, target, readonly, mountCount, err := parseMountedDockerMounts(mountOutput)
	if err != nil {
		return mountedSourceObservation{}, err
	}
	containerBootOutput, err := docker(ctx, "exec", admitted.id, "cat", "/proc/sys/kernel/random/boot_id")
	if err != nil {
		return mountedSourceObservation{}, err
	}
	statOutput, err := docker(ctx, "exec", admitted.id, "stat", "-c", "%d %i %u %g %f %s", mountedSourceTarget, mountedSourceTarget+"/"+mountedSourceFile)
	if err != nil {
		return mountedSourceObservation{}, err
	}
	directory, regularFile, err := parseMountedDockerStats(statOutput)
	if err != nil {
		return mountedSourceObservation{}, err
	}
	content, err := docker(ctx, "exec", admitted.id, "cat", mountedSourceTarget+"/"+mountedSourceFile)
	if err != nil {
		return mountedSourceObservation{}, err
	}
	if err := anchor.verifyVisibleBinding(); err != nil {
		return mountedSourceObservation{}, err
	}
	return mountedSourceObservation{
		runID: anchor.runID, jobID: anchor.jobID, taskName: anchor.taskName,
		allocationID: allocation.ID, containerID: admitted.id,
		allocationRunning: allocation.ClientStatus == "running" && allocation.TaskStates[anchor.taskName].State == "running",
		containerRunning:  true, containerCount: 1, mountCount: mountCount,
		dockerAllocationLabel: admitted.allocationLabel, dockerTaskLabel: admitted.taskLabel,
		dockerSource: source, dockerTarget: target, dockerReadOnly: readonly,
		localDockerSocket: true, sameKernel: strings.TrimSpace(string(containerBootOutput)) == hostBootID,
		allocationObserved: true, dockerLabelsObserved: true, dockerMountInspected: true,
		containerStatObserved: true, containerContentObserved: true, sourceBindingObserved: true,
		directory: directory, regularFile: regularFile,
		contentHash: fmt.Sprintf("%x", sha256.Sum256(content)), observedAt: time.Now().UTC(),
	}, nil
}

func observeMountedSourceIdentity(anchor *heldMountedSource, allocation nomadAllocationSummary, session *mountedSourceWitnessSession) (mountedSourceObservation, error) {
	socketInfo, err := os.Lstat("/var/run/docker.sock")
	if err != nil || socketInfo.Mode()&os.ModeSocket == 0 {
		return mountedSourceObservation{}, errors.New("mount witness: local Docker Unix socket unavailable")
	}
	hostBootID, err := readMountedBootID()
	if err != nil {
		return mountedSourceObservation{}, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Second)
	defer cancel()
	return observeMountedSourceWithCommands(ctx, anchor, allocation, session, hostBootID, runMountedDocker)
}

type mountedWitnessEnvelope struct {
	SourceManifestSHA256 string `json:"source_manifest_sha256"`
	TrackedDiffSHA256    string `json:"tracked_diff_sha256"`
	RecipeEnvelopeSHA256 string `json:"recipe_envelope_sha256"`
	CommandID            string `json:"command_id"`
}

func requireMountedSourceWitnessEnvelope(t *testing.T) mountedWitnessEnvelope {
	t.Helper()
	envelope := mountedWitnessEnvelope{
		SourceManifestSHA256: os.Getenv("ES_MOUNT_WITNESS_SOURCE_MANIFEST_SHA256"),
		TrackedDiffSHA256:    os.Getenv("ES_MOUNT_WITNESS_TRACKED_DIFF_SHA256"),
		RecipeEnvelopeSHA256: os.Getenv("ES_MOUNT_WITNESS_RECIPE_ENVELOPE_SHA256"),
		CommandID:            os.Getenv("ES_MOUNT_WITNESS_COMMAND_ID"),
	}
	for _, value := range []string{envelope.SourceManifestSHA256, envelope.TrackedDiffSHA256, envelope.RecipeEnvelopeSHA256} {
		if len(value) != 64 || strings.ToLower(value) != value {
			t.Fatal("mount witness: source envelope is incomplete")
		}
		if _, err := hex.DecodeString(value); err != nil {
			t.Fatal("mount witness: source envelope is invalid")
		}
	}
	if !regexp.MustCompile(`^[a-z0-9-]{1,64}$`).MatchString(envelope.CommandID) {
		t.Fatal("mount witness: command binding is incomplete")
	}
	return envelope
}

func encodeMountedSourceWitnessEvidence(envelope mountedWitnessEnvelope, anchor *heldMountedSource, observed mountedSourceObservation, session *mountedSourceWitnessSession, mode string) ([]byte, error) {
	if mode != "native-live" && mode != "synthetic-model" {
		return nil, errors.New("mount witness: unsupported evidence mode")
	}
	if !session.completed || session.cleanupResult != "barrier_released_handles_closed" || !anchor.closed ||
		!session.readyObserved || !session.terminalObserved || session.readyAt.Before(anchor.acquiredAt) ||
		observed.observedAt.Before(session.readyAt) || session.releasedAt.Before(observed.observedAt) ||
		session.terminalAt.Before(session.releasedAt) {
		return nil, errors.New("mount witness: completed cleanup is required before evidence")
	}
	evidence := struct {
		Schema              string                 `json:"schema"`
		ObservationMode     string                 `json:"observation_mode"`
		SourceBinding       mountedWitnessEnvelope `json:"source_binding"`
		RunID               string                 `json:"run_id"`
		JobID               string                 `json:"job_id"`
		TaskName            string                 `json:"task_name"`
		AllocationID        string                 `json:"allocation_id"`
		ContainerID         string                 `json:"container_id"`
		SourceRelative      string                 `json:"source_relative"`
		Target              string                 `json:"target"`
		DirectoryHost       mountedObjectIdentity  `json:"directory_host"`
		DirectoryView       mountedObjectIdentity  `json:"directory_container"`
		FileHost            mountedObjectIdentity  `json:"file_host"`
		FileView            mountedObjectIdentity  `json:"file_container"`
		ContentSHA256       string                 `json:"synthetic_content_sha256"`
		Assertions          map[string]bool        `json:"assertions"`
		Statuses            map[string]bool        `json:"direct_observation_statuses"`
		AnchorAt            string                 `json:"anchor_at"`
		ReadyAt             string                 `json:"ready_at"`
		ObservedAt          string                 `json:"observed_at"`
		ReleasedAt          string                 `json:"released_at"`
		TerminalAt          string                 `json:"terminal_at"`
		AnchorToReadyMillis int64                  `json:"anchor_to_ready_millis"`
		HoldMillis          int64                  `json:"hold_millis"`
		CleanupResult       string                 `json:"cleanup_result"`
	}{
		Schema: "execution-substrate.test-mounted-source-identity/v2", ObservationMode: mode,
		SourceBinding: envelope, RunID: anchor.runID, JobID: anchor.jobID, TaskName: anchor.taskName,
		AllocationID: observed.allocationID, ContainerID: observed.containerID,
		SourceRelative: anchor.sourceRel, Target: mountedSourceTarget,
		DirectoryHost: anchor.directory, DirectoryView: observed.directory,
		FileHost: anchor.regularFile, FileView: observed.regularFile,
		ContentSHA256: anchor.contentHash,
		Assertions:    map[string]bool{"local_docker_socket": observed.localDockerSocket, "common_kernel": observed.sameKernel, "exact_directory": true, "exact_file": true, "readonly": observed.dockerReadOnly, "synthetic_content": true, "terminal_complete": mode == "native-live", "status_and_logs": mode == "native-live"},
		Statuses: map[string]bool{
			"workload_ready_observed":    session.readyObserved,
			"allocation_observed":        observed.allocationObserved,
			"docker_labels_observed":     observed.dockerLabelsObserved,
			"installed_mount_inspected":  observed.dockerMountInspected,
			"container_stat_observed":    observed.containerStatObserved,
			"container_content_observed": observed.containerContentObserved,
			"visible_source_revalidated": observed.sourceBindingObserved,
			"terminal_observed":          session.terminalObserved,
		},
		AnchorAt: anchor.acquiredAt.Format(time.RFC3339Nano), ReadyAt: session.readyAt.Format(time.RFC3339Nano),
		ObservedAt: observed.observedAt.Format(time.RFC3339Nano), ReleasedAt: session.releasedAt.Format(time.RFC3339Nano),
		TerminalAt: session.terminalAt.Format(time.RFC3339Nano), AnchorToReadyMillis: session.readyAt.Sub(anchor.acquiredAt).Milliseconds(),
		HoldMillis:    session.releasedAt.Sub(session.readyAt).Milliseconds(),
		CleanupResult: session.cleanupResult,
	}
	encoded, err := json.Marshal(evidence)
	if err != nil {
		return nil, errors.New("mount witness: safe evidence encoding failed")
	}
	return encoded, nil
}

func logMountedSourceWitnessEvidence(t *testing.T, envelope mountedWitnessEnvelope, anchor *heldMountedSource, observed mountedSourceObservation, session *mountedSourceWitnessSession) {
	t.Helper()
	encoded, err := encodeMountedSourceWitnessEvidence(envelope, anchor, observed, session, "native-live")
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("MOUNTED-SOURCE-IDENTITY %s", encoded)
}

func modeledMountedAnchor(t *testing.T) *heldMountedSource {
	t.Helper()
	root := filepath.Join(t.TempDir(), "SYNTHETIC_SECRET_CANARY")
	runID := "run-0123456789abcdef"
	source := filepath.Join(root, runID, "mounts", "00", "contents")
	if err := os.MkdirAll(source, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(source, mountedSourceFile), []byte(mountedSourceText), 0o644); err != nil {
		t.Fatal(err)
	}
	anchor, err := openHeldMountedSource(source, "mounts/00/contents", runID, "exec-"+runID, "task")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = anchor.close() })
	return anchor
}

func modeledMountedObservation(anchor *heldMountedSource) mountedSourceObservation {
	allocationID := "allocation-model"
	return mountedSourceObservation{
		runID: anchor.runID, jobID: anchor.jobID, taskName: anchor.taskName,
		allocationID: allocationID, containerID: strings.Repeat("a", 64),
		allocationRunning: true, containerRunning: true, containerCount: 1, mountCount: 1,
		dockerAllocationLabel: allocationID, dockerTaskLabel: anchor.taskName,
		dockerSource: anchor.sourcePath, dockerTarget: mountedSourceTarget, dockerReadOnly: true,
		localDockerSocket: true, sameKernel: true,
		allocationObserved: true, dockerLabelsObserved: true, dockerMountInspected: true,
		containerStatObserved: true, containerContentObserved: true, sourceBindingObserved: true,
		directory: anchor.directory, regularFile: anchor.regularFile, contentHash: anchor.contentHash,
		observedAt: time.Now().UTC(),
	}
}

func modeledMountedJob(t *testing.T, anchor *heldMountedSource) mountedNomadJob {
	t.Helper()
	data, err := json.Marshal(map[string]any{"ID": anchor.jobID, "Meta": map[string]string{"run_id": anchor.runID}, "TaskGroups": []any{map[string]any{"Tasks": []any{map[string]any{"Name": anchor.taskName, "Meta": map[string]string{"run_id": anchor.runID}, "Config": map[string]any{"mounts": []any{map[string]any{"type": "bind", "source": anchor.sourcePath, "target": mountedSourceTarget, "readonly": true}}}}}}}})
	if err != nil {
		t.Fatal(err)
	}
	var job mountedNomadJob
	if err := json.Unmarshal(data, &job); err != nil {
		t.Fatal(err)
	}
	return job
}

func TestMountedSourceIdentityWitnessAcceptsExactBinding(t *testing.T) {
	anchor := modeledMountedAnchor(t)
	observed := modeledMountedObservation(anchor)
	if err := compareMountedSourceIdentity(anchor, observed); err != nil {
		t.Fatalf("exact modeled binding rejected: %v", err)
	}
	job := modeledMountedJob(t, anchor)
	if err := validateMountedSourceJob(job, anchor); err != nil {
		t.Fatalf("exact modeled Nomad binding rejected: %v", err)
	}
}

func TestMountedSourceIdentityWitnessRejectsChangedBackingObject(t *testing.T) {
	anchor := modeledMountedAnchor(t)
	other := modeledMountedAnchor(t) // same synthetic bytes, distinct real temp objects
	for _, test := range []struct {
		name   string
		change func(*mountedSourceObservation)
	}{
		{"different directory inode", func(o *mountedSourceObservation) { o.directory = other.directory; o.regularFile = other.regularFile }},
		{"different selected file inode", func(o *mountedSourceObservation) { o.regularFile = other.regularFile }},
	} {
		t.Run(test.name, func(t *testing.T) {
			observed := modeledMountedObservation(anchor)
			test.change(&observed)
			if err := compareMountedSourceIdentity(anchor, observed); err == nil || !strings.Contains(err.Error(), "backing object differs") {
				t.Fatalf("equal-content replacement was not refused: %v", err)
			}
		})
	}
	if anchor.directory.Ino == other.directory.Ino && anchor.directory.Dev == other.directory.Dev {
		t.Fatal("modeled directory replacement did not have a distinct identity")
	}
	if anchor.regularFile.Ino == other.regularFile.Ino && anchor.regularFile.Dev == other.regularFile.Dev {
		t.Fatal("modeled file replacement did not have a distinct identity")
	}
}

func TestMountedSourceIdentityWitnessRejectsUnboundObservation(t *testing.T) {
	anchor := modeledMountedAnchor(t)
	for _, test := range []struct {
		name   string
		change func(*mountedSourceObservation)
	}{
		{"wrong run", func(o *mountedSourceObservation) { o.runID = "run-ffffffffffffffff" }},
		{"wrong job", func(o *mountedSourceObservation) { o.jobID = "exec-run-ffffffffffffffff" }},
		{"wrong task", func(o *mountedSourceObservation) { o.taskName = "probe" }},
		{"wrong allocation", func(o *mountedSourceObservation) { o.allocationID = "another-allocation" }},
		{"probe container", func(o *mountedSourceObservation) { o.dockerTaskLabel = "probe" }},
		{"duplicate containers", func(o *mountedSourceObservation) { o.containerCount = 2 }},
		{"container gone", func(o *mountedSourceObservation) { o.containerRunning = false }},
		{"allocation gone", func(o *mountedSourceObservation) { o.allocationRunning = false }},
		{"missing installed mount", func(o *mountedSourceObservation) { o.mountCount = 0 }},
		{"ambiguous installed mounts", func(o *mountedSourceObservation) { o.mountCount = 2 }},
		{"wrong target", func(o *mountedSourceObservation) { o.dockerTarget = "/execution/mounts/other" }},
		{"wrong source", func(o *mountedSourceObservation) { o.dockerSource = "/synthetic/copy" }},
		{"writable", func(o *mountedSourceObservation) { o.dockerReadOnly = false }},
		{"remote Docker domain", func(o *mountedSourceObservation) { o.localDockerSocket = false }},
		{"different kernel domain", func(o *mountedSourceObservation) { o.sameKernel = false }},
		{"missing direct stat", func(o *mountedSourceObservation) { o.containerStatObserved = false }},
	} {
		t.Run(test.name, func(t *testing.T) {
			observed := modeledMountedObservation(anchor)
			test.change(&observed)
			if err := compareMountedSourceIdentity(anchor, observed); err == nil {
				t.Fatal("unbound modeled observation was accepted")
			}
		})
	}
	if _, _, _, _, err := parseMountedDockerMounts([]byte("bind\t/source\t/execution/mounts/config")); err == nil {
		t.Fatal("truncated installed mount record was accepted")
	}
	if _, _, err := parseMountedDockerStats([]byte("1 2 3")); err == nil {
		t.Fatal("malformed container stat was accepted")
	}
	if _, _, err := parseMountedDockerSelection([]byte(strings.Repeat("a", 64) + "\n" + strings.Repeat("b", 64))); err == nil {
		t.Fatal("ambiguous Docker selection was accepted")
	}
	if err := os.Rename(anchor.sourcePath, anchor.sourcePath+"-old"); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(anchor.sourcePath, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(anchor.sourcePath, mountedSourceFile), []byte(mountedSourceText), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := compareMountedSourceIdentity(anchor, modeledMountedObservation(anchor)); err == nil || !strings.Contains(err.Error(), "binding changed") {
		t.Fatalf("visible source displacement was not refused: %v", err)
	}
	metadataAnchor := modeledMountedAnchor(t)
	if err := os.Chmod(filepath.Join(metadataAnchor.sourcePath, mountedSourceFile), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := compareMountedSourceIdentity(metadataAnchor, modeledMountedObservation(metadataAnchor)); err == nil || !strings.Contains(err.Error(), "metadata drift") {
		t.Fatalf("metadata drift was not refused: %v", err)
	}
}

type mountedRoundTripFunc func(*http.Request) (*http.Response, error)

func (fn mountedRoundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return fn(request)
}

func TestMountedSourceIdentityCaptureBoundsAndTeardown(t *testing.T) {
	anchor := modeledMountedAnchor(t)
	stagingRoot := filepath.Dir(filepath.Dir(filepath.Dir(filepath.Dir(anchor.sourcePath))))
	requestBody, err := json.Marshal(map[string]any{"Job": map[string]any{"ID": anchor.jobID, "Meta": map[string]string{"run_id": anchor.runID}, "TaskGroups": []any{map[string]any{"Tasks": []any{map[string]any{"Name": anchor.taskName, "Meta": map[string]string{"run_id": anchor.runID}, "Config": map[string]any{"mounts": []any{map[string]any{"type": "bind", "source": anchor.sourcePath, "target": mountedSourceTarget, "readonly": true}}}}}}}}})
	if err != nil {
		t.Fatal(err)
	}
	capture := &mountedSourceRegistrationCapture{}
	forwarded := 0
	transport := &mountedRegistrationTransport{stagingRoot: stagingRoot, capture: capture, next: mountedRoundTripFunc(func(request *http.Request) (*http.Response, error) {
		forwarded++
		body, readErr := io.ReadAll(request.Body)
		if readErr != nil || !bytes.Equal(body, requestBody) {
			t.Fatal("test-owned proxy changed registration request bytes")
		}
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(`{"EvalID":"synthetic"}`)), Header: make(http.Header), Request: request}, nil
	})}
	newRequest := func(body []byte) *http.Request {
		request, reqErr := http.NewRequest(http.MethodPost, "http://127.0.0.1/v1/jobs", bytes.NewReader(body))
		if reqErr != nil {
			t.Fatal(reqErr)
		}
		return request
	}
	response, err := transport.RoundTrip(newRequest(requestBody))
	if err != nil || response.StatusCode != http.StatusOK || forwarded != 1 {
		t.Fatalf("bounded registration forwarding failed: %v", err)
	}
	_ = response.Body.Close()
	held, err := capture.require(anchor.runID)
	if err != nil || held == nil || !held.acquiredAt.Before(time.Now().Add(time.Second)) {
		t.Fatalf("pre-forward source capture missing: %v", err)
	}
	if _, err := transport.RoundTrip(newRequest(requestBody)); err == nil || forwarded != 1 {
		t.Fatal("duplicate registration was forwarded")
	}
	tooLarge := &mountedRegistrationTransport{stagingRoot: stagingRoot, capture: &mountedSourceRegistrationCapture{}, next: transport.next}
	if _, err := tooLarge.RoundTrip(newRequest(bytes.Repeat([]byte("x"), mountedRegisterLimit+1))); err == nil || forwarded != 1 {
		t.Fatal("oversized registration was forwarded")
	}
	for _, test := range []struct {
		name   string
		script string
		limit  bool
	}{
		{"oversized command output", "#!/bin/sh\nprintf '%020000d' 0\n", true},
		{"nonzero with synthetic canary", "#!/bin/sh\nprintf SYNTHETIC_SECRET_CANARY >&2\nexit 7\n", false},
		{"timeout", "#!/bin/sh\nwhile :; do :; done\n", false},
	} {
		t.Run(test.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "fake-observer")
			if err := os.WriteFile(path, []byte(test.script), 0o755); err != nil {
				t.Fatal(err)
			}
			timeout := time.Second
			if test.name == "timeout" {
				timeout = 20 * time.Millisecond
			}
			ctx, cancel := context.WithTimeout(context.Background(), timeout)
			defer cancel()
			_, err := runMountedBoundedCommand(ctx, path)
			if err == nil || strings.Contains(err.Error(), "SYNTHETIC_SECRET_CANARY") {
				t.Fatalf("observer command did not fail safely: %v", err)
			}
		})
	}
	session := newMountedSourceWitnessSession(capture)
	if err := session.setContainer(strings.Repeat("b", 64)); err != nil {
		t.Fatal(err)
	}
	releases, stops, cancellations := 0, 0, 0
	session.releaseFunc = func(string) error { releases++; return nil }
	session.stopFunc = func(string) error { stops++; return nil }
	session.cancelFunc = func(jobID string) error {
		if jobID != anchor.jobID {
			t.Fatal("failure cancellation selected the wrong job")
		}
		cancellations++
		return nil
	}
	if err := session.markReady(); err != nil {
		t.Fatal(err)
	}
	session.teardown()
	if releases != 1 || stops != 0 || cancellations != 1 || session.jobCancelResult != "request_succeeded" || !held.closed {
		t.Fatal("failed witness did not release barrier and close source handles")
	}
	if _, err := held.dir.Stat(); !errors.Is(err, os.ErrClosed) {
		t.Fatalf("held directory descriptor remained open: %v", err)
	}
	if _, err := held.file.Stat(); !errors.Is(err, os.ErrClosed) {
		t.Fatalf("held file descriptor remained open: %v", err)
	}
	stopAnchor := modeledMountedAnchor(t)
	stopCapture := &mountedSourceRegistrationCapture{count: 1, held: stopAnchor}
	stopSession := newMountedSourceWitnessSession(stopCapture)
	_ = stopSession.setContainer(strings.Repeat("c", 64))
	stopSession.releaseFunc = func(string) error { return errors.New("synthetic release failure") }
	stopSession.stopFunc = func(string) error { stops++; return nil }
	stopSession.cancelFunc = func(jobID string) error {
		if jobID != stopAnchor.jobID {
			t.Fatal("stop fallback selected the wrong job")
		}
		cancellations++
		return nil
	}
	if err := stopSession.markReady(); err != nil {
		t.Fatal(err)
	}
	stopSession.teardown()
	if stops != 1 || cancellations != 2 || !stopAnchor.closed || stopSession.cleanupResult != "release_request_failed_stop_attempted" || stopSession.stopResult != "request_succeeded" {
		t.Fatal("failed barrier release did not trigger task-owned teardown")
	}
	noContainerAnchor := modeledMountedAnchor(t)
	noContainerSession := newMountedSourceWitnessSession(&mountedSourceRegistrationCapture{count: 1, held: noContainerAnchor})
	noContainerSession.cancelFunc = func(jobID string) error {
		if jobID != noContainerAnchor.jobID {
			t.Fatal("missing-container fallback selected the wrong job")
		}
		cancellations++
		return nil
	}
	noContainerSession.teardown()
	if cancellations != 3 || noContainerSession.jobCancelResult != "request_succeeded" || !noContainerAnchor.closed {
		t.Fatal("missing container did not trigger exact job cancellation and handle closure")
	}
	cancelRequests := 0
	localNomad, localNomadTLS := startNomadTLSStandIn(t, http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodDelete || request.URL.Path != "/v1/job/"+anchor.jobID || request.URL.Query().Get("purge") != "true" {
			writer.WriteHeader(http.StatusBadRequest)
			return
		}
		cancelRequests++
		writer.WriteHeader(http.StatusOK)
		_, _ = writer.Write([]byte(`{"EvalID":"synthetic"}`))
	}))
	if err := (&nomadHarness{addr: localNomad.URL, tls: localNomadTLS}).cancelMountedJob(anchor.jobID); err != nil || cancelRequests != 1 {
		t.Fatalf("bounded exact test-owned job cancellation failed: %v", err)
	}
	evidenceAnchor := modeledMountedAnchor(t)
	evidenceSession := newMountedSourceWitnessSession(&mountedSourceRegistrationCapture{count: 1, held: evidenceAnchor})
	if err := evidenceSession.setContainer(strings.Repeat("a", 64)); err != nil {
		t.Fatal(err)
	}
	if err := evidenceSession.markReady(); err != nil {
		t.Fatal(err)
	}
	evidenceObservation := modeledMountedObservation(evidenceAnchor)
	evidenceSession.releaseFunc = func(string) error { return nil }
	if err := evidenceSession.release(); err != nil {
		t.Fatal(err)
	}
	if err := evidenceSession.markTerminal(time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	if err := evidenceSession.complete(); err != nil {
		t.Fatal(err)
	}
	encoded, err := encodeMountedSourceWitnessEvidence(mountedWitnessEnvelope{CommandID: "modeled"}, evidenceAnchor, evidenceObservation, evidenceSession, "synthetic-model")
	if err != nil || bytes.Contains(encoded, []byte("SYNTHETIC_SECRET_CANARY")) || bytes.Contains(encoded, []byte(evidenceAnchor.sourcePath)) || bytes.Contains(encoded, []byte(`"observation_mode":"native-live"`)) || !bytes.Contains(encoded, []byte(`"terminal_complete":false`)) || !bytes.Contains(encoded, []byte(`"schema":"execution-substrate.test-mounted-source-identity/v2"`)) {
		t.Fatalf("modeled evidence escaped its safe scope: %v", err)
	}
}

func modeledMountedAllocation(anchor *heldMountedSource) nomadAllocationSummary {
	return nomadAllocationSummary{ID: "allocation-model", JobID: anchor.jobID, ClientStatus: "running", TaskStates: map[string]nomadTaskState{anchor.taskName: {State: "running"}}}
}

func TestMountedSourceIdentityReadyBarrierOrdering(t *testing.T) {
	t.Run("running before reset then ready observe release terminal", func(t *testing.T) {
		anchor := modeledMountedAnchor(t)
		allocation := modeledMountedAllocation(anchor)
		containerID := strings.Repeat("a", 64)
		session := newMountedSourceWitnessSession(&mountedSourceRegistrationCapture{count: 1, held: anchor})
		releases, stops, cancellations, markerPolls := 0, 0, 0, 0
		events := []string{}
		session.releaseFunc = func(id string) error {
			if id != containerID || !session.readyObserved {
				t.Fatal("release preceded admitted workload readiness")
			}
			releases++
			events = append(events, "release")
			return nil
		}
		session.stopFunc = func(string) error { stops++; return nil }
		session.cancelFunc = func(string) error { cancellations++; return nil }
		resultDir := filepath.Join(t.TempDir(), "result")
		if err := os.Mkdir(resultDir, 0o755); err != nil {
			t.Fatal(err)
		}
		docker := mountedDockerCommand(func(_ context.Context, args ...string) ([]byte, error) {
			switch {
			case args[0] == "ps":
				events = append(events, "candidate")
				return []byte(containerID + "\n"), nil
			case args[0] == "inspect" && strings.Contains(args[2], "com.hashicorp.nomad.alloc_id"):
				events = append(events, "admit")
				return []byte(containerID + "\ttrue\t" + allocation.ID + "\t" + anchor.taskName + "\n"), nil
			case args[0] == "inspect" && args[2] == "{{.State.Running}}":
				return []byte("true\n"), nil
			case args[0] == "exec" && args[2] == "/bin/sh":
				markerPolls++
				if markerPolls == 1 {
					if err := session.release(); err == nil || releases != 0 {
						t.Fatal("pre-ready release reached the effect target")
					}
					if err := os.RemoveAll(resultDir); err != nil {
						t.Fatal(err)
					}
					if err := os.Mkdir(resultDir, 0o755); err != nil {
						t.Fatal(err)
					}
					if err := os.WriteFile(filepath.Join(resultDir, ".mount-observer-ready"), []byte(mountedSourceReadyText), 0o644); err != nil {
						t.Fatal(err)
					}
					events = append(events, "result-reset")
					return []byte("MISSING\n"), nil
				}
				data, err := os.ReadFile(filepath.Join(resultDir, ".mount-observer-ready"))
				return data, err
			case args[0] == "inspect" && strings.Contains(args[2], ".Mounts"):
				if !session.readyObserved {
					t.Fatal("installed mount observed before readiness")
				}
				events = append(events, "observe")
				return []byte("bind\t" + anchor.sourcePath + "\t" + mountedSourceTarget + "\tfalse\n"), nil
			case args[0] == "exec" && args[2] == "cat" && args[3] == "/proc/sys/kernel/random/boot_id":
				return []byte("boot-model\n"), nil
			case args[0] == "exec" && args[2] == "stat":
				line := func(object mountedObjectIdentity) string {
					return fmt.Sprintf("%d %d %d %d %x %d\n", object.Dev, object.Ino, object.UID, object.GID, object.Mode, object.Size)
				}
				return []byte(line(anchor.directory) + line(anchor.regularFile)), nil
			case args[0] == "exec" && args[2] == "cat" && args[3] == mountedSourceTarget+"/"+mountedSourceFile:
				return []byte(mountedSourceText), nil
			default:
				t.Fatalf("unexpected modeled Docker command category: %s", args[0])
				return nil, errors.New("unexpected modeled command")
			}
		})
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		observed, err := observeMountedSourceWithCommands(ctx, anchor, allocation, session, "boot-model", docker)
		if err != nil || markerPolls != 2 || !session.readyObserved {
			t.Fatalf("two-way modeled observation failed: %v", err)
		}
		if err := compareMountedSourceIdentity(anchor, observed); err != nil {
			t.Fatal(err)
		}
		if err := session.release(); err != nil {
			t.Fatal(err)
		}
		events = append(events, "terminal")
		if err := session.markTerminal(time.Now().UTC()); err != nil {
			t.Fatal(err)
		}
		if err := session.complete(); err != nil {
			t.Fatal(err)
		}
		session.teardown()
		if releases != 1 || stops != 0 || cancellations != 0 || !anchor.closed || strings.Join(events, ",") != "candidate,admit,result-reset,observe,release,terminal" {
			t.Fatalf("modeled ready/effect order incorrect: %v", events)
		}
	})
	for _, test := range []struct {
		name, marker, state string
		timeout             time.Duration
	}{
		{"missing acknowledgement timeout", "MISSING\n", "true\n", 25 * time.Millisecond},
		{"malformed acknowledgement", "WRONG\n", "true\n", time.Second},
		{"container exits before readiness", "MISSING\n", "false\n", time.Second},
	} {
		t.Run(test.name, func(t *testing.T) {
			anchor := modeledMountedAnchor(t)
			session := newMountedSourceWitnessSession(&mountedSourceRegistrationCapture{count: 1, held: anchor})
			if err := session.setContainer(strings.Repeat("b", 64)); err != nil {
				t.Fatal(err)
			}
			releases, stops, cancellations := 0, 0, 0
			session.releaseFunc = func(string) error { releases++; return nil }
			session.stopFunc = func(string) error { stops++; return nil }
			session.cancelFunc = func(string) error { cancellations++; return nil }
			ctx, cancel := context.WithTimeout(context.Background(), test.timeout)
			defer cancel()
			docker := mountedDockerCommand(func(_ context.Context, args ...string) ([]byte, error) {
				if args[0] == "inspect" {
					return []byte(test.state), nil
				}
				if args[0] == "exec" {
					return []byte(test.marker), nil
				}
				t.Fatal("unexpected modeled command before readiness")
				return nil, nil
			})
			if err := waitForMountedWorkloadReady(ctx, session, docker); err == nil {
				t.Fatal("invalid ready state was accepted")
			}
			session.teardown()
			if releases != 0 || stops != 1 || cancellations != 1 || session.readyObserved || !anchor.closed || session.stopResult != "request_succeeded" {
				t.Fatal("unready workload was released or cleanup was incomplete")
			}
		})
	}
}

func TestMountedSourceIdentityContainerAdmissionBeforeEffects(t *testing.T) {
	containerID := strings.Repeat("a", 64)
	for _, test := range []struct {
		name, selection, inspected string
		accept                     bool
	}{
		{"wrong inspected ID", containerID + "\n", strings.Repeat("b", 64) + "\ttrue\tallocation-model\ttask\n", false},
		{"wrong allocation label", containerID + "\n", containerID + "\ttrue\tother\ttask\n", false},
		{"wrong task label", containerID + "\n", containerID + "\ttrue\tallocation-model\tprobe\n", false},
		{"missing task label", containerID + "\n", containerID + "\ttrue\tallocation-model\t\n", false},
		{"stopped container", containerID + "\n", containerID + "\tfalse\tallocation-model\ttask\n", false},
		{"malformed selection", "not-an-id\n", "", false},
		{"multiple candidates", containerID + "\n" + strings.Repeat("b", 64) + "\n", "", false},
		{"valid admission", containerID + "\n", containerID + "\ttrue\tallocation-model\ttask\n", true},
	} {
		t.Run(test.name, func(t *testing.T) {
			anchor := modeledMountedAnchor(t)
			session := newMountedSourceWitnessSession(&mountedSourceRegistrationCapture{count: 1, held: anchor})
			execs, releases, stops, cancellations := 0, 0, 0, 0
			session.releaseFunc = func(string) error { releases++; return nil }
			session.stopFunc = func(string) error { stops++; return nil }
			session.cancelFunc = func(jobID string) error {
				if jobID != anchor.jobID {
					t.Fatal("wrong cancellation target")
				}
				cancellations++
				return nil
			}
			docker := mountedDockerCommand(func(_ context.Context, args ...string) ([]byte, error) {
				switch args[0] {
				case "ps":
					if len(args) != 6 || args[1] != "--no-trunc" || args[2] != "--filter" || args[3] != "label=com.hashicorp.nomad.alloc_id=allocation-model" || args[4] != "--format" || args[5] != "{{.ID}}" {
						t.Fatal("Docker candidate selection command changed")
					}
					return []byte(test.selection), nil
				case "inspect":
					if len(args) != 4 || args[1] != "--format" || !strings.Contains(args[2], "com.hashicorp.nomad.alloc_id") || !strings.Contains(args[2], "com.hashicorp.nomad.task_name") || args[3] != containerID {
						t.Fatal("Docker candidate inspection command changed")
					}
					return []byte(test.inspected), nil
				case "exec":
					execs++
					return nil, errors.New("unexpected pre-admission exec")
				default:
					t.Fatal("unexpected candidate command")
					return nil, nil
				}
			})
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			admitted, err := selectAndAdmitMountedContainer(ctx, modeledMountedAllocation(anchor), anchor.taskName, session, docker)
			if test.accept != (err == nil) {
				t.Fatalf("admission outcome mismatch: %v", err)
			}
			if test.accept && admitted.id != containerID {
				t.Fatal("wrong admitted container")
			}
			if !test.accept && (session.containerID != "" || session.readyObserved) {
				t.Fatal("rejected candidate adopted")
			}
			session.teardown()
			wantStops := 0
			if test.accept {
				wantStops = 1
			}
			if execs != 0 || releases != 0 || stops != wantStops || cancellations != 1 || !anchor.closed || session.jobCancelResult != "request_succeeded" {
				t.Fatal("candidate admission caused an effect or skipped exact cleanup")
			}
			if _, err := encodeMountedSourceWitnessEvidence(mountedWitnessEnvelope{}, anchor, modeledMountedObservation(anchor), session, "synthetic-model"); err == nil {
				t.Fatal("admission-only attempt emitted success evidence")
			}
		})
	}
}

// The launch callback inspects the same file that nomad agent -config would
// consume, then withholds process start. These are synthetic config checks.
func captureMountedNomadAgentConfig(t *testing.T, opts nomadHarnessOptions) string {
	t.Helper()
	t.Setenv("NOMAD_CLIENT_CPU_TOTAL_COMPUTE", "")
	rootDir := t.TempDir()
	configPath := filepath.Join(rootDir, "nomad.hcl")
	const stopped = "fixture launch withheld"
	var captured []byte
	launch := func(cmd *exec.Cmd) error {
		if len(cmd.Args) != 4 || cmd.Args[0] != "nomad" || cmd.Args[1] != "agent" || cmd.Args[2] != "-dev" || cmd.Args[3] != "-config="+configPath {
			t.Fatal("Nomad launch did not use the written task-owned config")
		}
		info, err := os.Stat(configPath)
		if err != nil || info.Mode().Perm() != 0o600 {
			t.Fatal("Nomad launch config was absent or had wrong mode")
		}
		captured, err = os.ReadFile(configPath)
		if err != nil {
			t.Fatal("read Nomad launch config:", err)
		}
		return errors.New(stopped)
	}
	harness, reason := startNomadHarnessForCapabilityProbeWithOptions(rootDir, opts, launch)
	if harness != nil || reason != "start nomad agent: "+stopped || len(captured) == 0 {
		t.Fatal("fake launch boundary did not withhold the agent")
	}
	return string(captured)
}

func TestMountedSourceIdentityNomadTaskLabelProfileLaunchConfig(t *testing.T) {
	const canary = "SYNTHETIC_SECRET_CANARY_PRIVATE_CONFIG"
	defaultOptions := submitStackOptions{}.nomadHarnessOptions()
	if defaultOptions.dockerTaskNameLabel {
		t.Fatal("ordinary stack implicitly enabled the task-label profile")
	}
	defaultConfig := captureMountedNomadAgentConfig(t, defaultOptions)
	if strings.Count(defaultConfig, supportedNomadDockerPluginBlock) != 1 ||
		strings.Count(defaultConfig, `plugin "docker"`) != 1 ||
		!strings.Contains(defaultConfig, supportedNomadClientOptions) ||
		len(nomadNetworkInterfaceSetting.FindAllString(defaultConfig, -1)) != 1 ||
		!strings.Contains(defaultConfig, "\n"+supportedNomadClientNetworkInterface+"\n") ||
		strings.Contains(defaultConfig, `extra_labels`) ||
		strings.Contains(defaultConfig, `"docker.cleanup.image"`) || strings.Contains(defaultConfig, `"docker.volumes.enabled"`) {
		t.Fatal("default/capability-probe Nomad config changed")
	}
	witnessOptions := submitStackOptions{mountedSourceDockerTaskNameLabel: true, workloadVaultAddress: canary}.nomadHarnessOptions()
	if !witnessOptions.dockerTaskNameLabel {
		t.Fatal("installed-identity stack did not forward the task-label option")
	}
	witnessConfig := captureMountedNomadAgentConfig(t, witnessOptions)
	if strings.Count(witnessConfig, `plugin "docker"`) != 1 ||
		strings.Count(witnessConfig, `extra_labels = ["task_name"]`) != 1 ||
		strings.Count(witnessConfig, `extra_labels`) != 1 ||
		strings.Count(witnessConfig, supportedNomadDockerPluginBlockWithTaskNameLabel()) != 1 ||
		!strings.Contains(witnessConfig, supportedNomadClientOptions) ||
		strings.Contains(witnessConfig, `"docker.cleanup.image"`) ||
		strings.Contains(witnessConfig, `"docker.volumes.enabled"`) ||
		strings.Contains(witnessConfig, `job_id`) || strings.Contains(witnessConfig, `extra_labels = ["*"]`) ||
		strings.Contains(witnessConfig, canary) {
		t.Fatal("installed-identity Nomad profile is missing or ambiguous")
	}
}

// This fake driver models only the documented extra_labels switch. It is not
// evidence that a native Nomad version emits the task label.
func TestMountedSourceIdentityModeledTaskLabelPrerequisite(t *testing.T) {
	containerID := strings.Repeat("a", 64)
	for _, test := range []struct {
		name, config, taskLabelOverride string
		accept                          bool
	}{
		{"default profile refuses missing label", captureMountedNomadAgentConfig(t, submitStackOptions{}.nomadHarnessOptions()), "", false},
		{"witness profile admits driver label", captureMountedNomadAgentConfig(t, submitStackOptions{mountedSourceDockerTaskNameLabel: true}.nomadHarnessOptions()), "", true},
		{"witness profile refuses wrong canary label", captureMountedNomadAgentConfig(t, submitStackOptions{mountedSourceDockerTaskNameLabel: true}.nomadHarnessOptions()), "SYNTHETIC_SECRET_CANARY_PRIVATE_CONFIG", false},
	} {
		t.Run(test.name, func(t *testing.T) {
			anchor := modeledMountedAnchor(t)
			session := newMountedSourceWitnessSession(&mountedSourceRegistrationCapture{count: 1, held: anchor})
			execs, releases, stops, cancellations := 0, 0, 0, 0
			session.releaseFunc = func(string) error { releases++; return nil }
			session.stopFunc = func(string) error { stops++; return nil }
			session.cancelFunc = func(jobID string) error {
				if jobID != anchor.jobID {
					t.Fatal("wrong cancellation target")
				}
				cancellations++
				return nil
			}
			driverTaskLabel := ""
			if strings.Contains(test.config, `extra_labels = ["task_name"]`) {
				driverTaskLabel = anchor.taskName
			}
			if test.taskLabelOverride != "" {
				driverTaskLabel = test.taskLabelOverride
			}
			docker := mountedDockerCommand(func(_ context.Context, args ...string) ([]byte, error) {
				switch args[0] {
				case "ps":
					return []byte(containerID + "\n"), nil
				case "inspect":
					return []byte(containerID + "\ttrue\tallocation-model\t" + driverTaskLabel + "\n"), nil
				case "exec":
					execs++
					return nil, errors.New("unexpected exec")
				default:
					t.Fatal("unexpected Docker command")
					return nil, nil
				}
			})
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			admitted, err := selectAndAdmitMountedContainer(ctx, modeledMountedAllocation(anchor), anchor.taskName, session, docker)
			if test.accept != (err == nil) || (test.accept && admitted.id != containerID) || (!test.accept && session.containerID != "") {
				t.Fatal("modeled driver-label admission mismatch")
			}
			if !test.accept && (err == nil || err.Error() != "mount witness: Docker candidate admission refused" || strings.Contains(err.Error(), "SYNTHETIC_SECRET_CANARY_PRIVATE_CONFIG") || strings.Contains(err.Error(), anchor.sourcePath)) {
				t.Fatal("missing or wrong label was not refused with the fixed safe error")
			}
			session.teardown()
			wantStops := 0
			if test.accept {
				wantStops = 1
			}
			if execs != 0 || releases != 0 || stops != wantStops || cancellations != 1 || !anchor.closed {
				t.Fatal("modeled admission caused an effect or skipped exact cleanup")
			}
			if !test.accept {
				evidence, evidenceErr := encodeMountedSourceWitnessEvidence(mountedWitnessEnvelope{}, anchor, modeledMountedObservation(anchor), session, "synthetic-model")
				if len(evidence) != 0 || evidenceErr == nil || strings.Contains(evidenceErr.Error(), "SYNTHETIC_SECRET_CANARY_PRIVATE_CONFIG") || strings.Contains(evidenceErr.Error(), anchor.sourcePath) {
					t.Fatal("rejected observation leaked or emitted success evidence")
				}
			}
		})
	}
}

func TestMountedSourceIdentitySafeNomadFailureDiagnostics(t *testing.T) {
	anchor := modeledMountedAnchor(t)
	const canary = "SYNTHETIC_SECRET_CANARY_PRIVATE_CONFIG"
	jobBytes, err := json.Marshal(modeledMountedJob(t, anchor))
	if err != nil {
		t.Fatal(err)
	}
	nomadTLS, err := issueNomadTLSMaterial(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name    string
		status  int
		body    []byte
		success bool
	}{
		{"non-OK job with private response", http.StatusInternalServerError, []byte(canary + anchor.sourcePath), false},
		{"oversized job response", http.StatusOK, []byte(strings.Repeat("x", 64*1024) + canary), false},
		{"malformed job response", http.StatusOK, []byte(`{"ID":` + canary), false},
		{"valid selected job", http.StatusOK, jobBytes, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			server, err := nomadTLS.startTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
				if request.URL.Path != "/v1/job/"+anchor.jobID {
					writer.WriteHeader(http.StatusNotFound)
					return
				}
				writer.WriteHeader(test.status)
				_, _ = writer.Write(test.body)
			}))
			if err != nil {
				t.Fatal(err)
			}
			defer server.Close()
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			job, err := (&nomadHarness{addr: server.URL, tls: nomadTLS}).fetchMountedSourceJob(ctx, anchor)
			if test.success != (err == nil) {
				t.Fatalf("selected job observation outcome mismatch: %v", err)
			}
			if err != nil && (strings.Contains(err.Error(), canary) || strings.Contains(err.Error(), anchor.sourcePath)) {
				t.Fatal("raw job diagnostic escaped")
			}
			if test.success && job.ID != anchor.jobID {
				t.Fatal("wrong selected job")
			}
		})
	}
	allocationID := "allocation-model"
	list := func(id, jobID string) []byte {
		data, _ := json.Marshal([]any{map[string]any{"ID": id, "JobID": jobID}})
		return data
	}
	multipleList, err := json.Marshal([]any{map[string]any{"ID": allocationID, "JobID": anchor.jobID}, map[string]any{"ID": "other", "JobID": anchor.jobID}})
	if err != nil {
		t.Fatal(err)
	}
	detail := func(status string, failed bool, events []any) []byte {
		data, _ := json.Marshal(map[string]any{"ID": allocationID, "JobID": anchor.jobID, "ClientStatus": status, "TaskStates": map[string]any{anchor.taskName: map[string]any{"State": "dead", "Failed": failed, "Events": events, "Message": canary}}})
		return data
	}
	validEvent := []any{map[string]any{"Type": "Terminated", "ExitCode": 0, "DisplayMessage": canary}}
	for _, test := range []struct {
		name         string
		list, detail []byte
		timeout      time.Duration
		success      bool
	}{
		{"terminal timeout with private daemon log", list(allocationID, anchor.jobID), detail("running", false, nil), 25 * time.Millisecond, false},
		{"wrong allocation record", list("other", anchor.jobID), detail("complete", false, validEvent), time.Second, false},
		{"wrong job record", list(allocationID, "other"), detail("complete", false, validEvent), time.Second, false},
		{"multiple allocation records", multipleList, detail("complete", false, validEvent), time.Second, false},
		{"oversized allocation detail", list(allocationID, anchor.jobID), []byte(strings.Repeat("x", 64*1024) + canary), time.Second, false},
		{"malformed allocation detail", list(allocationID, anchor.jobID), []byte(`{"ID":` + canary), time.Second, false},
		{"failed terminal task", list(allocationID, anchor.jobID), detail("complete", true, []any{map[string]any{"Type": "Terminated", "ExitCode": 1, "Message": canary}}), time.Second, false},
		{"missing terminal exit evidence", list(allocationID, anchor.jobID), detail("complete", false, nil), time.Second, false},
		{"valid complete exit zero", list(allocationID, anchor.jobID), detail("complete", false, validEvent), time.Second, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			requests := 0
			server, err := nomadTLS.startTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
				requests++
				switch request.URL.Path {
				case "/v1/job/" + anchor.jobID + "/allocations":
					_, _ = writer.Write(test.list)
				case "/v1/allocation/" + allocationID:
					_, _ = writer.Write(test.detail)
				default:
					writer.WriteHeader(http.StatusNotFound)
				}
			}))
			if err != nil {
				t.Fatal(err)
			}
			defer server.Close()
			privateLog := filepath.Join(t.TempDir(), "nomad-private-log")
			if err := os.WriteFile(privateLog, []byte(canary+anchor.sourcePath), 0o600); err != nil {
				t.Fatal(err)
			}
			at, err := (&nomadHarness{addr: server.URL, outputPath: privateLog, tls: nomadTLS}).waitForMountedTerminalAllocation(anchor, allocationID, test.timeout)
			if test.success != (err == nil) || test.success == at.IsZero() {
				t.Fatalf("selected terminal observation outcome mismatch: %v", err)
			}
			if err != nil && (strings.Contains(err.Error(), canary) || strings.Contains(err.Error(), anchor.sourcePath) || strings.Contains(err.Error(), "Message")) {
				t.Fatal("raw terminal diagnostic escaped")
			}
			if requests == 0 || requests > 4 {
				t.Fatal("terminal waiter did not bound selected request work")
			}
		})
	}
}
