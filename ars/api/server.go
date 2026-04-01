package api

import (
	"crypto/x509"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"os"
	"slices"
	"strconv"
	"strings"

	"execution-platform/ars/index"
	"execution-platform/ars/store"
)

const serviceName = "artifact-registry"

type Server struct {
	blobStore           store.BlobStore
	artifactIndex       index.Lookup
	allowedPathPrefixes []string
	isStarted           func() bool
}

func NewServer(blobStore store.BlobStore, artifactIndex index.Lookup, allowedPathPrefixes []string, isStarted func() bool) *Server {
	return &Server{
		blobStore:           blobStore,
		artifactIndex:       artifactIndex,
		allowedPathPrefixes: append([]string(nil), allowedPathPrefixes...),
		isStarted:           isStarted,
	}
}

func (s *Server) Handler() http.Handler {
	// TODO: ACS exposed an HTTP 307 for some empty-segment paths because Go's
	// ServeMux canonicalizes paths before handler dispatch. That behavior is an
	// infrastructure artifact, NOT part of the intended contract, and should not
	// be relied upon. ARS keeps manual routing here so invalid paths remain an
	// explicit service concern. Revisit only if a future shared router can do the
	// same without reintroducing implicit redirects.
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.EscapedPath()

		switch {
		case path == "/health":
			if r.Method != http.MethodGet {
				writeMethodNotAllowed(w, http.MethodGet)
				return
			}
			s.handleHealth(w, r)
		case strings.HasPrefix(path, "/v1/blobs/"):
			if handled := s.requireAuthorizedCaller(w, r); handled {
				return
			}
			s.routeBlobRequest(w, r, path)
		case strings.HasPrefix(path, "/v1/artifacts/"):
			if handled := s.requireAuthorizedCaller(w, r); handled {
				return
			}
			s.routeArtifactRequest(w, r, path)
		default:
			http.NotFound(w, r)
		}
	})
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	_ = r

	storageHealthy := false
	if info, err := os.Stat(s.blobStore.RootDir()); err == nil && info.IsDir() {
		storageHealthy = true
	}

	indexHealthy := false
	if info, err := os.Stat(s.artifactIndex.Path()); err == nil && !info.IsDir() {
		indexHealthy = true
	}

	started := false
	if s.isStarted != nil {
		started = s.isStarted()
	}

	ready := started && storageHealthy && indexHealthy
	status := "unhealthy"
	if ready {
		status = "healthy"
	}

	writeJSON(w, http.StatusOK, HealthResponse{
		Status:  status,
		Ready:   ready,
		Service: serviceName,
		AdditionalProperties: HealthAdditionalProperties{
			Dependencies: HealthDependencies{
				Storage: healthLabel(storageHealthy),
				Index:   healthLabel(indexHealthy),
			},
			Readiness: HealthReadiness{
				Storage:       readyLabel(storageHealthy),
				Index:         readyLabel(indexHealthy),
				ServerStarted: readyLabel(started),
			},
		},
	})
}

func (s *Server) routeBlobRequest(w http.ResponseWriter, r *http.Request, path string) {
	const prefix = "/v1/blobs/"
	rest := strings.TrimPrefix(path, prefix)

	switch {
	case isSingleSegment(rest) && !strings.HasSuffix(rest, ":bytes") && !strings.HasSuffix(rest, ":json"):
		if r.Method != http.MethodHead {
			writeMethodNotAllowed(w, http.MethodHead)
			return
		}
		s.handleBlobExists(w, rest)
	case strings.HasSuffix(rest, ":bytes") && isSingleSegment(strings.TrimSuffix(rest, ":bytes")):
		if r.Method != http.MethodGet {
			writeMethodNotAllowed(w, http.MethodGet)
			return
		}
		s.handleBlobBytes(w, strings.TrimSuffix(rest, ":bytes"))
	case strings.HasSuffix(rest, ":json") && isSingleSegment(strings.TrimSuffix(rest, ":json")):
		if r.Method != http.MethodGet {
			writeMethodNotAllowed(w, http.MethodGet)
			return
		}
		s.handleBlobJSON(w, strings.TrimSuffix(rest, ":json"))
	default:
		http.NotFound(w, r)
	}
}

func (s *Server) routeArtifactRequest(w http.ResponseWriter, r *http.Request, path string) {
	const prefix = "/v1/artifacts/"
	rest := strings.TrimPrefix(path, prefix)
	segments := strings.Split(rest, "/")
	if len(segments) != 2 {
		http.NotFound(w, r)
		return
	}

	kind, ok := index.ParseKind(segments[1])
	if !ok {
		http.NotFound(w, r)
		return
	}

	if r.Method != http.MethodGet {
		writeMethodNotAllowed(w, http.MethodGet)
		return
	}

	s.handleArtifactRead(w, segments[0], kind)
}

func (s *Server) handleBlobExists(w http.ResponseWriter, rawDigest string) {
	digest, ok := decodeDigestSegment(rawDigest)
	if !ok {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	// TODO: HEAD now verifies blob integrity by reading and hashing the full
	// blob before returning 200. That is part of the current ARS correctness
	// contract because existence without integrity is misleading for a
	// content-addressed registry. Revisit only when streaming verification or an
	// explicit read-limit strategy is introduced.
	_, err := s.blobStore.Read(digest)
	if err != nil {
		if isInvalidDigest(err) {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		var corrupt store.BlobCorruptError
		switch {
		case errors.Is(err, store.ErrBlobNotFound):
			w.WriteHeader(http.StatusNotFound)
		case errors.As(err, &corrupt):
			w.WriteHeader(http.StatusInternalServerError)
		default:
			w.WriteHeader(http.StatusInternalServerError)
		}
		return
	}

	w.Header().Set("Content-Digest", digest)
	w.WriteHeader(http.StatusOK)
}

func (s *Server) handleBlobBytes(w http.ResponseWriter, rawDigest string) {
	digest, ok := decodeDigestSegment(rawDigest)
	if !ok {
		writeJSON(w, http.StatusBadRequest, BlobErrorResponse{
			Error:  "invalid digest",
			Digest: rawDigest,
		})
		return
	}

	data, err := s.blobStore.Read(digest)
	if err != nil {
		s.writeBlobReadError(w, digest, err)
		return
	}

	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Digest", digest)
	w.Header().Set("Content-Length", intToString(len(data)))
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(data)
}

func (s *Server) handleBlobJSON(w http.ResponseWriter, rawDigest string) {
	digest, ok := decodeDigestSegment(rawDigest)
	if !ok {
		writeJSON(w, http.StatusBadRequest, BlobErrorResponse{
			Error:  "invalid digest",
			Digest: rawDigest,
		})
		return
	}

	data, err := s.blobStore.Read(digest)
	if err != nil {
		s.writeBlobReadError(w, digest, err)
		return
	}

	if !json.Valid(data) {
		writeJSON(w, http.StatusBadRequest, BlobErrorResponse{
			Error:  "blob is not valid JSON",
			Digest: digest,
		})
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Digest", digest)
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(data)
}

func (s *Server) handleArtifactRead(w http.ResponseWriter, rawArtifactDigest string, kind index.Kind) {
	artifactDigest, ok := decodeDigestSegment(rawArtifactDigest)
	if !ok {
		writeJSON(w, http.StatusBadRequest, ArtifactErrorResponse{
			Error:          "invalid artifact digest",
			ArtifactDigest: rawArtifactDigest,
		})
		return
	}

	entry, found, err := s.artifactIndex.Lookup(artifactDigest)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, ArtifactErrorResponse{
			Error:          "invalid artifact digest",
			ArtifactDigest: artifactDigest,
		})
		return
	}
	if !found {
		writeJSON(w, http.StatusNotFound, ArtifactErrorResponse{
			Error:          "artifact not found",
			ArtifactDigest: artifactDigest,
		})
		return
	}

	referencedDigest := entry.DigestFor(kind)
	data, err := s.blobStore.Read(referencedDigest)
	if err != nil {
		var corrupt store.BlobCorruptError
		switch {
		case errors.Is(err, store.ErrBlobNotFound):
			writeJSON(w, http.StatusNotFound, ArtifactErrorResponse{
				Error:          "referenced blob not found",
				ArtifactDigest: artifactDigest,
				Digest:         referencedDigest,
			})
		case errors.As(err, &corrupt):
			writeJSON(w, http.StatusInternalServerError, ArtifactErrorResponse{
				Error:          "stored blob digest mismatch",
				ArtifactDigest: artifactDigest,
				Digest:         corrupt.Digest,
			})
		default:
			writeJSON(w, http.StatusInternalServerError, ArtifactErrorResponse{
				Error:          "internal server error",
				ArtifactDigest: artifactDigest,
				Digest:         referencedDigest,
			})
		}
		return
	}

	if !json.Valid(data) {
		writeJSON(w, http.StatusInternalServerError, ArtifactErrorResponse{
			Error:          "referenced blob is not valid JSON",
			ArtifactDigest: artifactDigest,
			Digest:         referencedDigest,
		})
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Digest", referencedDigest)
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(data)
}

func (s *Server) writeBlobReadError(w http.ResponseWriter, digest string, err error) {
	var corrupt store.BlobCorruptError
	switch {
	case isInvalidDigest(err):
		writeJSON(w, http.StatusBadRequest, BlobErrorResponse{
			Error:  "invalid digest",
			Digest: digest,
		})
	case errors.Is(err, store.ErrBlobNotFound):
		writeJSON(w, http.StatusNotFound, BlobErrorResponse{
			Error:  "blob not found",
			Digest: digest,
		})
	case errors.As(err, &corrupt):
		writeJSON(w, http.StatusInternalServerError, BlobErrorResponse{
			Error:  "stored blob digest mismatch",
			Digest: corrupt.Digest,
		})
	default:
		writeJSON(w, http.StatusInternalServerError, BlobErrorResponse{
			Error:  "internal server error",
			Digest: digest,
		})
	}
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

func decodeDigestSegment(raw string) (string, bool) {
	value, err := url.PathUnescape(raw)
	if err != nil {
		return "", false
	}
	return value, true
}

func isSingleSegment(value string) bool {
	return !strings.Contains(value, "/")
}

func isInvalidDigest(err error) bool {
	var invalid store.InvalidDigestError
	return errors.As(err, &invalid)
}

func healthLabel(healthy bool) string {
	if healthy {
		return "healthy"
	}
	return "unhealthy"
}

func readyLabel(ready bool) string {
	if ready {
		return "ready"
	}
	return "missing"
}

func intToString(value int) string {
	return strconv.Itoa(value)
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

func writeMethodNotAllowed(w http.ResponseWriter, methods ...string) {
	allowed := append([]string(nil), methods...)
	slices.Sort(allowed)
	w.Header().Set("Allow", strings.Join(allowed, ", "))
	w.WriteHeader(http.StatusMethodNotAllowed)
}
