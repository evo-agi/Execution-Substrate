package api

import (
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"execution-platform/acs/audit"
	"execution-platform/acs/catalog"
	"execution-platform/observability"
)

const serviceName = "artifact-catalog"

type Server struct {
	store               catalog.Store
	auditSink           audit.Sink
	allowedPathPrefixes []string
	isStarted           func() bool
}

func NewServer(store catalog.Store, auditSink audit.Sink, allowedPathPrefixes []string, isStarted func() bool) *Server {
	return &Server{
		store:               store,
		auditSink:           auditSink,
		allowedPathPrefixes: append([]string(nil), allowedPathPrefixes...),
		isStarted:           isStarted,
	}
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	// TODO: Empty path segments can currently trigger HTTP redirects before these
	// handlers run because Go's ServeMux canonicalizes certain paths. This is NOT
	// part of the ACS contract and should not be relied upon. Ignore for the
	// frozen ACS slice unless a critical bug requires explicit normalization later.
	mux.HandleFunc("GET /health", s.handleHealth)
	mux.HandleFunc("GET /v1/configuration/", s.handleConfigurationLookup)
	return observability.WrapHandler(serviceName, mux)
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	seedDigest := s.store.SeedDigest()
	snapshotDigest := s.store.SnapshotDigest()

	cacheReady := s.store.Ready()
	requiredReady := cacheReady
	auditHealthy := s.auditSink.Healthy()
	started := false
	if s.isStarted != nil {
		started = s.isStarted()
	}

	ready := started && auditHealthy && cacheReady && requiredReady && seedDigest != "" && snapshotDigest != ""
	status := "unhealthy"
	if ready {
		status = "healthy"
	}

	response := HealthResponse{
		Status:                status,
		Ready:                 ready,
		Service:               serviceName,
		CacheEntries:          s.store.EntryCount(),
		CatalogSeedDigest:     stringPtr(seedDigest),
		CatalogSnapshotDigest: stringPtr(snapshotDigest),
		AdditionalProperties: HealthAdditionalProperties{
			Dependencies: HealthDependencies{
				Audit: healthLabel(auditHealthy),
			},
			Readiness: HealthReadiness{
				CacheInitialized:        readyLabel(cacheReady),
				RequiredSeedAssignments: readyLabel(requiredReady),
				CatalogSeedDigest:       readyLabel(seedDigest != ""),
				CatalogSnapshotDigest:   readyLabel(snapshotDigest != ""),
			},
		},
	}

	writeJSON(w, http.StatusOK, response)
}

func (s *Server) handleConfigurationLookup(w http.ResponseWriter, r *http.Request) {
	if handled := s.requireAuthorizedCaller(w, r); handled {
		return
	}

	assignment, status, err := parseAssignmentFromPath(r.URL.EscapedPath())
	if err != nil {
		http.Error(w, err.Error(), status)
		return
	}

	digest, found, err := s.store.Lookup(assignment)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	snapshotDigest := s.store.SnapshotDigest()

	if !found {
		errorMessage := fmt.Sprintf(
			"No artifact digest mapping found for assignment: %s",
			assignment.MustCanonicalJSON(),
		)
		writeJSON(w, http.StatusNotFound, LookupResponse{
			Success:               false,
			Assignment:            &assignment,
			CatalogSnapshotDigest: stringPtr(snapshotDigest),
			Error:                 &errorMessage,
		})
		return
	}

	writeJSON(w, http.StatusOK, LookupResponse{
		Success:               true,
		Digest:                &digest,
		Assignment:            &assignment,
		CatalogSnapshotDigest: stringPtr(snapshotDigest),
	})
}

func (s *Server) requireAuthorizedCaller(w http.ResponseWriter, r *http.Request) bool {
	path, ok := callerSPIFFEPath(r)
	if !ok {
		writeText(w, http.StatusUnauthorized, "Authenticated caller identity required")
		return true
	}

	for _, prefix := range s.allowedPathPrefixes {
		if matchesAuthorizedPathPrefix(path, prefix) {
			return false
		}
	}

	writeText(w, http.StatusForbidden, "Caller not authorized for this operation")
	return true
}

func callerSPIFFEPath(r *http.Request) (string, bool) {
	if r.TLS == nil || len(r.TLS.VerifiedChains) == 0 {
		return "", false
	}

	cert := r.TLS.VerifiedChains[0][0]
	if cert == nil {
		return "", false
	}

	return spiffePathFromCertificate(cert)
}

func spiffePathFromCertificate(cert *x509.Certificate) (string, bool) {
	// TODO: Do not mention "monolith" or "internal"
	const prefix = "spiffe://monolith.internal/"

	for _, uri := range cert.URIs {
		value := uri.String()
		if strings.HasPrefix(value, prefix) {
			return strings.TrimPrefix(value, prefix), true
		}
	}

	return "", false
}

func matchesAuthorizedPathPrefix(path string, prefix string) bool {
	normalizedPath := strings.Trim(path, "/")
	normalizedPrefix := strings.Trim(prefix, "/")

	if normalizedPath == "" || normalizedPrefix == "" {
		return false
	}

	return normalizedPath == normalizedPrefix || strings.HasPrefix(normalizedPath, normalizedPrefix+"/")
}

func parseAssignmentFromPath(path string) (catalog.AssignmentKey, int, error) {
	const prefix = "/v1/configuration/"
	if !strings.HasPrefix(path, prefix) {
		return catalog.AssignmentKey{}, http.StatusNotFound, fmt.Errorf("not found")
	}

	relative := strings.TrimPrefix(path, prefix)
	segments := strings.Split(relative, "/")
	if len(segments) == 0 {
		return catalog.AssignmentKey{}, http.StatusNotFound, fmt.Errorf("not found")
	}

	switch segments[0] {
		case "workload-zone":
			if len(segments) == 2 && segments[1] == "vault" {
				return catalog.RequiredWorkloadZoneVault(), http.StatusOK, nil
			}
		case "deployment":
			return parseDeploymentAssignment(segments)
		case "service":
			return parseServiceAssignment(segments)
		case "sidecar":
			return parseSidecarAssignment(segments)
	}

	return catalog.AssignmentKey{}, http.StatusNotFound, fmt.Errorf("not found")
}

func parseDeploymentAssignment(segments []string) (catalog.AssignmentKey, int, error) {
	if len(segments) == 3 && segments[1] == "stage" {
		stage, err := url.PathUnescape(segments[2])
		if err != nil {
			return catalog.AssignmentKey{}, http.StatusBadRequest, fmt.Errorf("invalid stage path segment")
		}
		return catalog.AssignmentKey{
			IdentityKind: catalog.AssignmentDeploymentStageConfig,
			Stage:        stage,
		}, http.StatusOK, nil
	}

	if len(segments) == 3 && segments[1] == "dependency" {
		stage, err := url.PathUnescape(segments[2])
		if err != nil {
			return catalog.AssignmentKey{}, http.StatusBadRequest, fmt.Errorf("invalid stage path segment")
		}
		return catalog.AssignmentKey{
			IdentityKind: catalog.AssignmentDeploymentStageDependency,
			Stage:        stage,
		}, http.StatusOK, nil
	}

	if len(segments) == 5 && segments[1] == "service" {
		stage, err := url.PathUnescape(segments[2])
		if err != nil {
			return catalog.AssignmentKey{}, http.StatusBadRequest, fmt.Errorf("invalid stage path segment")
		}
		service, err := url.PathUnescape(segments[3])
		if err != nil {
			return catalog.AssignmentKey{}, http.StatusBadRequest, fmt.Errorf("invalid service path segment")
		}
		version, err := url.PathUnescape(segments[4])
		if err != nil {
			return catalog.AssignmentKey{}, http.StatusBadRequest, fmt.Errorf("invalid version path segment")
		}
		return catalog.AssignmentKey{
			IdentityKind: catalog.AssignmentDeploymentServiceConfig,
			Stage:        stage,
			Service:      service,
			Version:      version,
		}, http.StatusOK, nil
	}

	return catalog.AssignmentKey{}, http.StatusNotFound, fmt.Errorf("not found")
}

func parseServiceAssignment(segments []string) (catalog.AssignmentKey, int, error) {
	if len(segments) == 3 && strings.HasSuffix(segments[2], ":instances") {
		service, err := url.PathUnescape(segments[1])
		if err != nil {
			return catalog.AssignmentKey{}, http.StatusBadRequest, fmt.Errorf("invalid service path segment")
		}
		version, err := url.PathUnescape(strings.TrimSuffix(segments[2], ":instances"))
		if err != nil {
			return catalog.AssignmentKey{}, http.StatusBadRequest, fmt.Errorf("invalid version path segment")
		}
		return catalog.AssignmentKey{
			IdentityKind: catalog.AssignmentServiceInstances,
			Service:      service,
			Version:      version,
		}, http.StatusOK, nil
	}

	if len(segments) == 4 {
		service, err := url.PathUnescape(segments[1])
		if err != nil {
			return catalog.AssignmentKey{}, http.StatusBadRequest, fmt.Errorf("invalid service path segment")
		}

		version, err := url.PathUnescape(segments[2])
		if err != nil {
			return catalog.AssignmentKey{}, http.StatusBadRequest, fmt.Errorf("invalid version path segment")
		}

		switch {
			case strings.HasSuffix(segments[3], ":docker"):
				instance, err := url.PathUnescape(strings.TrimSuffix(segments[3], ":docker"))
				if err != nil {
					return catalog.AssignmentKey{}, http.StatusBadRequest, fmt.Errorf("invalid instance path segment")
				}
				return catalog.AssignmentKey{
					IdentityKind: catalog.AssignmentServiceDockerConfig,
					Service:      service,
					Version:      version,
					Instance:     instance,
				}, http.StatusOK, nil
			case strings.HasSuffix(segments[3], ":application"):
				instance, err := url.PathUnescape(strings.TrimSuffix(segments[3], ":application"))
				if err != nil {
					return catalog.AssignmentKey{}, http.StatusBadRequest, fmt.Errorf("invalid instance path segment")
				}
				return catalog.AssignmentKey{
					IdentityKind: catalog.AssignmentServiceApplicationConfig,
					Service:      service,
					Version:      version,
					Instance:     instance,
				}, http.StatusOK, nil
		}
	}

	return catalog.AssignmentKey{}, http.StatusNotFound, fmt.Errorf("not found")
}

func parseSidecarAssignment(segments []string) (catalog.AssignmentKey, int, error) {
	if len(segments) == 3 && strings.HasSuffix(segments[2], ":instances") {
		service, err := url.PathUnescape(segments[1])
		if err != nil {
			return catalog.AssignmentKey{}, http.StatusBadRequest, fmt.Errorf("invalid service path segment")
		}
		version, err := url.PathUnescape(strings.TrimSuffix(segments[2], ":instances"))
		if err != nil {
			return catalog.AssignmentKey{}, http.StatusBadRequest, fmt.Errorf("invalid version path segment")
		}
		return catalog.AssignmentKey{
			IdentityKind: catalog.AssignmentSidecarInstances,
			Service:      service,
			Version:      version,
		}, http.StatusOK, nil
	}

	if len(segments) == 4 && strings.HasSuffix(segments[3], ":docker") {
		service, err := url.PathUnescape(segments[1])
		if err != nil {
			return catalog.AssignmentKey{}, http.StatusBadRequest, fmt.Errorf("invalid service path segment")
		}
		version, err := url.PathUnescape(segments[2])
		if err != nil {
			return catalog.AssignmentKey{}, http.StatusBadRequest, fmt.Errorf("invalid version path segment")
		}
		instance, err := url.PathUnescape(strings.TrimSuffix(segments[3], ":docker"))
		if err != nil {
			return catalog.AssignmentKey{}, http.StatusBadRequest, fmt.Errorf("invalid instance path segment")
		}
		return catalog.AssignmentKey{
			IdentityKind: catalog.AssignmentSidecarDockerConfig,
			Service:      service,
			Version:      version,
			Instance:     instance,
		}, http.StatusOK, nil
	}

	return catalog.AssignmentKey{}, http.StatusNotFound, fmt.Errorf("not found")
}

func readyLabel(ready bool) string {
	if ready {
		return "ready"
	}
	return "missing"
}

func healthLabel(healthy bool) string {
	if healthy {
		return "healthy"
	}
	return "unhealthy"
}

func stringPtr(value string) *string {
	if value == "" {
		return nil
	}
	return &value
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	encoder := json.NewEncoder(w)
	encoder.SetEscapeHTML(false)
	_ = encoder.Encode(value)
}

func writeText(w http.ResponseWriter, status int, value string) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(status)
	_, _ = io.WriteString(w, value)
}
