package api

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"execution-substrate/ars/index"
	"execution-substrate/ars/store"
	"execution-substrate/internal/callerallowlist"
	"execution-substrate/internal/callerauth"
	"execution-substrate/internal/httpx"
	"execution-substrate/internal/observability"
)

const (
	serviceName        = "artifact-registry"
	writerSPIFFEPath   = "service/artifact-governance"
	registerPath       = "/v1/artifacts:register"
	blobPathPrefix     = "/v1/blobs/"
	artifactPathPrefix = "/v1/artifacts/"
)

type Server struct {
	blobStore           store.BlobStore
	artifactIndex       index.Lookup
	allowedPathPrefixes []string
	callers             callerauth.Authenticator
	isStarted           func() bool
}

func NewServer(blobStore store.BlobStore, artifactIndex index.Lookup, allowedPathPrefixes []string, bootstrapIssuerCN string, isStarted func() bool) *Server {
	return &Server{
		blobStore:           blobStore,
		artifactIndex:       artifactIndex,
		allowedPathPrefixes: append([]string(nil), allowedPathPrefixes...),
		callers:             callerauth.NewAuthenticator(bootstrapIssuerCN),
		isStarted:           isStarted,
	}
}

func (s *Server) Handler() http.Handler {
	// TODO: ACS exposed an HTTP 307 for some empty-segment paths because Go's
	// 		 ServeMux canonicalizes paths before handler dispatch. That behavior is an
	// 		 infrastructure artifact, NOT part of the intended contract, and should not
	// 		 be relied upon. ARS keeps manual routing here so invalid paths remain an
	// 		 explicit service concern. Revisit only if a future shared router can do the
	// 		 same without reintroducing implicit redirects.
	return observability.WrapHandler(serviceName, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.EscapedPath()

		switch {
		case path == "/health":
			if r.Method != http.MethodGet {
				writeMethodNotAllowed(w, http.MethodGet)
				return
			}
			s.handleHealth(w, r)
		case path == registerPath:
			if r.Method != http.MethodPost {
				writeMethodNotAllowed(w, http.MethodPost)
				return
			}
			if handled := s.requireWriterCaller(w, r); handled {
				return
			}
			s.handleArtifactRegister(w, r)
		case strings.HasPrefix(path, blobPathPrefix):
			s.routeBlobRequest(w, r, path)
		case strings.HasPrefix(path, artifactPathPrefix):
			s.routeArtifactRequest(w, r, path)
		default:
			http.NotFound(w, r)
		}
	}))
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
	rest := strings.TrimPrefix(path, blobPathPrefix)

	switch {
	case isSingleSegment(rest) && !strings.HasSuffix(rest, ":bytes") && !strings.HasSuffix(rest, ":json"):
		switch r.Method {
		case http.MethodHead:
			if handled := s.requireAuthorizedCaller(w, r); handled {
				return
			}
			s.handleBlobExists(w, rest)
		case http.MethodPut:
			if handled := s.requireWriterCaller(w, r); handled {
				return
			}
			s.handleBlobUpload(w, r, rest)
		default:
			writeMethodNotAllowed(w, http.MethodHead, http.MethodPut)
		}
	case strings.HasSuffix(rest, ":bytes") && isSingleSegment(strings.TrimSuffix(rest, ":bytes")):
		if r.Method != http.MethodGet {
			writeMethodNotAllowed(w, http.MethodGet)
			return
		}
		if handled := s.requireAuthorizedCaller(w, r); handled {
			return
		}
		s.handleBlobBytes(w, strings.TrimSuffix(rest, ":bytes"))
	case strings.HasSuffix(rest, ":json") && isSingleSegment(strings.TrimSuffix(rest, ":json")):
		if r.Method != http.MethodGet {
			writeMethodNotAllowed(w, http.MethodGet)
			return
		}
		if handled := s.requireAuthorizedCaller(w, r); handled {
			return
		}
		s.handleBlobJSON(w, strings.TrimSuffix(rest, ":json"))
	default:
		http.NotFound(w, r)
	}
}

func (s *Server) routeArtifactRequest(w http.ResponseWriter, r *http.Request, path string) {
	rest := strings.TrimPrefix(path, artifactPathPrefix)
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
	if handled := s.requireAuthorizedCaller(w, r); handled {
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
	// 		 blob before returning 200. That is part of the current ARS correctness
	// 		 contract because existence without integrity is misleading for a
	// 		 content-addressed registry. Revisit only when streaming verification or an
	// 		 explicit read-limit strategy is introduced.
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

func (s *Server) handleBlobUpload(w http.ResponseWriter, r *http.Request, rawDigest string) {
	digest, ok := decodeDigestSegment(rawDigest)
	if !ok {
		writeJSON(w, http.StatusBadRequest, BlobErrorResponse{
			Error:  "invalid digest",
			Digest: rawDigest,
		})
		return
	}

	data, err := io.ReadAll(r.Body)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, BlobErrorResponse{
			Error:  "internal server error",
			Digest: digest,
		})
		return
	}

	created, err := s.blobStore.Write(digest, data)
	if err != nil {
		var mismatch store.BlobDigestMismatchError
		var corrupt store.BlobCorruptError
		switch {
		case isInvalidDigest(err):
			writeJSON(w, http.StatusBadRequest, BlobErrorResponse{
				Error:  "invalid digest",
				Digest: digest,
			})
		case errors.As(err, &mismatch):
			writeJSON(w, http.StatusConflict, BlobErrorResponse{
				Error:  "blob digest does not match request path",
				Digest: mismatch.Digest,
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
		return
	}

	w.Header().Set("Content-Digest", digest)
	if created {
		w.WriteHeader(http.StatusCreated)
		return
	}
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

	discovery, discoveryDigest, data, response, status, ok := s.loadArtifactDiscovery(artifactDigest, entry.DiscoveryDigest)
	if !ok {
		writeJSON(w, status, response)
		return
	}

	referencedDigest := discoveryDigest
	switch kind {
	case index.KindDiscovery:
		// The primary runtime-facing discoverability surface is the discovery record itself.
	case index.KindDescriptor:
		if strings.TrimSpace(entry.DescriptorDigest) == "" {
			writeJSON(w, http.StatusNotFound, ArtifactErrorResponse{
				Error:          "artifact data not registered",
				ArtifactDigest: artifactDigest,
			})
			return
		}
		_, referencedDigest, data, response, status, ok = s.loadArtifactDescriptor(artifactDigest, entry.DescriptorDigest)
		if !ok {
			writeJSON(w, status, response)
			return
		}
	case index.KindEvidence:
		referencedDigest = strings.TrimSpace(discovery.Evidence.Digest)
		if referencedDigest == "" {
			writeJSON(w, http.StatusNotFound, ArtifactErrorResponse{
				Error:          "artifact data not registered",
				ArtifactDigest: artifactDigest,
			})
			return
		}
		data, response, status, ok = s.readArtifactJSONBlob(artifactDigest, referencedDigest)
		if !ok {
			writeJSON(w, status, response)
			return
		}
	case index.KindManifest:
		if strings.TrimSpace(entry.DescriptorDigest) == "" {
			writeJSON(w, http.StatusNotFound, ArtifactErrorResponse{
				Error:          "artifact data not registered",
				ArtifactDigest: artifactDigest,
			})
			return
		}
		descriptor, _, _, response, status, ok := s.loadArtifactDescriptor(artifactDigest, entry.DescriptorDigest)
		if !ok {
			writeJSON(w, status, response)
			return
		}
		referencedDigest, ok = descriptorSupportingDigest(descriptor, "manifest")
		if !ok {
			writeJSON(w, http.StatusNotFound, ArtifactErrorResponse{
				Error:          "artifact data not registered",
				ArtifactDigest: artifactDigest,
			})
			return
		}
		data, response, status, ok = s.readArtifactJSONBlob(artifactDigest, referencedDigest)
		if !ok {
			writeJSON(w, status, response)
			return
		}
	default:
		w.WriteHeader(http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Digest", referencedDigest)
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(data)
}

func (s *Server) handleArtifactRegister(w http.ResponseWriter, r *http.Request) {
	var request RegisterArtifactRequest
	if err := decodeStrictJSONBody(r.Body, &request); err != nil {
		writeJSON(w, http.StatusBadRequest, ArtifactErrorResponse{
			Error: "invalid registration request",
		})
		return
	}

	if err := store.ValidateDigest(request.DiscoveryDigest); err != nil {
		writeJSON(w, http.StatusBadRequest, ArtifactErrorResponse{
			Error:  "invalid referenced digest",
			Digest: request.DiscoveryDigest,
		})
		return
	}
	if descriptorDigest := strings.TrimSpace(request.DescriptorDigest); descriptorDigest != "" {
		if err := store.ValidateDigest(descriptorDigest); err != nil {
			writeJSON(w, http.StatusBadRequest, ArtifactErrorResponse{
				Error:  "invalid referenced digest",
				Digest: descriptorDigest,
			})
			return
		}
	}

	discovery, _, response, status, ok := s.loadDiscoveryForRegistration(request.DiscoveryDigest)
	if !ok {
		writeJSON(w, status, response)
		return
	}
	if descriptorDigest := strings.TrimSpace(request.DescriptorDigest); descriptorDigest != "" {
		descriptor, _, response, status, ok := s.loadDescriptorForRegistration(descriptorDigest)
		if !ok {
			writeJSON(w, status, response)
			return
		}
		if response, status, ok := validateDescriptorMatchesDiscovery(descriptorDigest, discovery, descriptor); !ok {
			writeJSON(w, status, response)
			return
		}
	}
	entry := index.Entry{
		ArtifactDigest:   discovery.Artifact.ArtifactDigest,
		DiscoveryDigest:  request.DiscoveryDigest,
		DescriptorDigest: strings.TrimSpace(request.DescriptorDigest),
		CreatedAt:        time.Now().UTC().Format(time.RFC3339),
	}

	created, err := s.artifactIndex.Register(entry)
	if err != nil {
		var conflict index.ConflictError
		switch {
		case errors.As(err, &conflict):
			writeJSON(w, http.StatusConflict, ArtifactErrorResponse{
				Error:          "artifact already registered with different digests",
				ArtifactDigest: conflict.ArtifactDigest,
			})
		default:
			writeJSON(w, http.StatusInternalServerError, ArtifactErrorResponse{
				Error:          "internal server error",
				ArtifactDigest: entry.ArtifactDigest,
			})
		}
		return
	}

	statusCode := http.StatusCreated
	if !created {
		statusCode = http.StatusOK
	}
	writeJSON(w, statusCode, RegisterArtifactResponse{
		Registered:       true,
		Created:          created,
		ArtifactDigest:   entry.ArtifactDigest,
		DiscoveryDigest:  entry.DiscoveryDigest,
		DescriptorDigest: entry.DescriptorDigest,
	})
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
	caller, ok := s.callers.Authenticate(w, r)
	if !ok {
		return true
	}

	if callerallowlist.MatchesAny(caller.ID(), s.allowedPathPrefixes) {
		return false
	}

	writeText(w, http.StatusForbidden, "Caller not authorized for this operation")
	return true
}

func (s *Server) requireWriterCaller(w http.ResponseWriter, r *http.Request) bool {
	caller, ok := s.callers.Authenticate(w, r)
	if !ok {
		return true
	}

	if callerallowlist.Matches(caller.ID(), writerSPIFFEPath) {
		return false
	}

	writeText(w, http.StatusForbidden, "Caller not authorized for this operation")
	return true
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
	httpx.WriteJSONNoEscapeHTML(w, status, value)
}

func writeText(w http.ResponseWriter, status int, value string) {
	httpx.WriteText(w, status, value)
}

func writeMethodNotAllowed(w http.ResponseWriter, methods ...string) {
	httpx.WriteMethodNotAllowed(w, methods...)
}

func decodeStrictJSONBody(body io.Reader, target any) error {
	return httpx.DecodeStrictJSON(body, target)
}

func (s *Server) loadDiscoveryForRegistration(discoveryDigest string) (ArtifactDiscovery, []byte, ArtifactErrorResponse, int, bool) {
	discovery, _, discoveryBytes, response, status, ok := s.loadArtifactDiscovery("", discoveryDigest)
	if !ok {
		return ArtifactDiscovery{}, nil, response, remapArtifactRegistrationStatus(response, status), false
	}

	referencedDigests := []struct {
		digest     string
		expectJSON bool
	}{
		{digest: discovery.Evidence.Digest, expectJSON: true},
		{digest: discovery.Payload.Digest, expectJSON: false},
	}
	for _, referenced := range referencedDigests {
		if strings.TrimSpace(referenced.digest) == "" {
			continue
		}
		if _, response, status, ok := s.readArtifactBlob(discovery.Artifact.ArtifactDigest, referenced.digest, referenced.expectJSON); !ok {
			return ArtifactDiscovery{}, nil, response, remapArtifactRegistrationStatus(response, status), false
		}
	}

	return discovery, discoveryBytes, ArtifactErrorResponse{}, 0, true
}

func (s *Server) loadDescriptorForRegistration(descriptorDigest string) (ArtifactDescriptor, []byte, ArtifactErrorResponse, int, bool) {
	descriptor, _, descriptorBytes, response, status, ok := s.loadArtifactDescriptor("", descriptorDigest)
	if !ok {
		return ArtifactDescriptor{}, nil, response, remapArtifactRegistrationStatus(response, status), false
	}

	referencedDigests := []struct {
		digest     string
		expectJSON bool
	}{
		{digest: descriptor.Package.Evidence.Digest, expectJSON: true},
		{digest: descriptor.Package.Payload.Digest, expectJSON: false},
	}
	for _, support := range descriptor.Package.Supporting {
		referencedDigests = append(referencedDigests, struct {
			digest     string
			expectJSON bool
		}{
			digest:     support.Digest,
			expectJSON: support.Name == "manifest",
		})
	}

	for _, referenced := range referencedDigests {
		if strings.TrimSpace(referenced.digest) == "" {
			continue
		}
		data, response, status, ok := s.readArtifactBlob(descriptor.Artifact.ArtifactDigest, referenced.digest, referenced.expectJSON)
		if !ok {
			return ArtifactDescriptor{}, nil, response, remapArtifactRegistrationStatus(response, status), false
		}

		if referenced.expectJSON && referenced.digest == descriptor.Package.Evidence.Digest {
			var evidenceEnvelope any
			if err := json.Unmarshal(data, &evidenceEnvelope); err != nil {
				return ArtifactDescriptor{}, nil, ArtifactErrorResponse{
					Error:          "referenced blob is not valid JSON",
					ArtifactDigest: descriptor.Artifact.ArtifactDigest,
					Digest:         referenced.digest,
				}, http.StatusConflict, false
			}
		}
	}

	return descriptor, descriptorBytes, ArtifactErrorResponse{}, 0, true
}

func remapArtifactRegistrationStatus(response ArtifactErrorResponse, status int) int {
	switch response.Error {
	case "referenced blob not found", "stored blob digest mismatch", "referenced blob is not valid JSON":
		return http.StatusConflict
	default:
		return status
	}
}

func (s *Server) loadArtifactDiscovery(artifactDigest string, discoveryDigest string) (ArtifactDiscovery, string, []byte, ArtifactErrorResponse, int, bool) {
	if strings.TrimSpace(discoveryDigest) == "" {
		return ArtifactDiscovery{}, "", nil, ArtifactErrorResponse{
			Error:          "artifact data not registered",
			ArtifactDigest: artifactDigest,
		}, http.StatusNotFound, false
	}
	data, response, status, ok := s.readArtifactJSONBlob(artifactDigest, discoveryDigest)
	if !ok {
		return ArtifactDiscovery{}, "", nil, response, status, false
	}

	var discovery ArtifactDiscovery
	if err := json.Unmarshal(data, &discovery); err != nil {
		return ArtifactDiscovery{}, "", nil, ArtifactErrorResponse{
			Error:          "referenced blob is not valid JSON",
			ArtifactDigest: artifactDigest,
			Digest:         discoveryDigest,
		}, http.StatusInternalServerError, false
	}
	if response, status, ok := validateArtifactDiscovery(discoveryDigest, artifactDigest, discovery); !ok {
		return ArtifactDiscovery{}, "", nil, response, status, false
	}
	return discovery, discoveryDigest, data, ArtifactErrorResponse{}, 0, true
}

func (s *Server) loadArtifactDescriptor(artifactDigest string, descriptorDigest string) (ArtifactDescriptor, string, []byte, ArtifactErrorResponse, int, bool) {
	if strings.TrimSpace(descriptorDigest) == "" {
		return ArtifactDescriptor{}, "", nil, ArtifactErrorResponse{
			Error:          "artifact data not registered",
			ArtifactDigest: artifactDigest,
		}, http.StatusNotFound, false
	}
	data, response, status, ok := s.readArtifactJSONBlob(artifactDigest, descriptorDigest)
	if !ok {
		return ArtifactDescriptor{}, "", nil, response, status, false
	}

	var descriptor ArtifactDescriptor
	if err := json.Unmarshal(data, &descriptor); err != nil {
		return ArtifactDescriptor{}, "", nil, ArtifactErrorResponse{
			Error:          "referenced blob is not valid JSON",
			ArtifactDigest: artifactDigest,
			Digest:         descriptorDigest,
		}, http.StatusInternalServerError, false
	}
	if response, status, ok := validateArtifactDescriptor(descriptorDigest, artifactDigest, descriptor); !ok {
		return ArtifactDescriptor{}, "", nil, response, status, false
	}
	return descriptor, descriptorDigest, data, ArtifactErrorResponse{}, 0, true
}

func validateArtifactDiscovery(discoveryDigest string, requestedArtifactDigest string, discovery ArtifactDiscovery) (ArtifactErrorResponse, int, bool) {
	if strings.TrimSpace(discovery.SchemaVersion) != ArtifactDiscoverySchemaVersion {
		return ArtifactErrorResponse{
			Error:          "invalid registration request",
			ArtifactDigest: requestedArtifactDigest,
			Digest:         discoveryDigest,
		}, http.StatusBadRequest, false
	}
	artifactDigest := strings.TrimSpace(discovery.Artifact.ArtifactDigest)
	if artifactDigest == "" {
		return ArtifactErrorResponse{
			Error:          "invalid registration request",
			ArtifactDigest: requestedArtifactDigest,
			Digest:         discoveryDigest,
		}, http.StatusBadRequest, false
	}
	if err := store.ValidateDigest(artifactDigest); err != nil {
		return ArtifactErrorResponse{
			Error:          "invalid artifact digest",
			ArtifactDigest: artifactDigest,
		}, http.StatusBadRequest, false
	}
	if requestedArtifactDigest != "" && artifactDigest != requestedArtifactDigest {
		return ArtifactErrorResponse{
			Error:          "artifact data not registered",
			ArtifactDigest: requestedArtifactDigest,
		}, http.StatusNotFound, false
	}
	if strings.TrimSpace(discovery.Artifact.ArtifactType) == "" {
		return ArtifactErrorResponse{
			Error:          "invalid registration request",
			ArtifactDigest: artifactDigest,
			Digest:         discoveryDigest,
		}, http.StatusBadRequest, false
	}
	if err := store.ValidateDigest(strings.TrimSpace(discovery.Artifact.IntentDigest)); err != nil {
		return ArtifactErrorResponse{
			Error:          "invalid referenced digest",
			ArtifactDigest: artifactDigest,
			Digest:         strings.TrimSpace(discovery.Artifact.IntentDigest),
		}, http.StatusBadRequest, false
	}
	if err := validateArtifactBlobRef(artifactDigest, discovery.Evidence, discoveryDigest); err != nil {
		return err.response, err.status, false
	}
	if err := validateArtifactBlobRef(artifactDigest, discovery.Payload, discoveryDigest); err != nil {
		return err.response, err.status, false
	}

	return ArtifactErrorResponse{}, 0, true
}

func validateArtifactDescriptor(descriptorDigest string, requestedArtifactDigest string, descriptor ArtifactDescriptor) (ArtifactErrorResponse, int, bool) {
	if strings.TrimSpace(descriptor.SchemaVersion) != ArtifactDescriptorSchemaVersion {
		return ArtifactErrorResponse{
			Error:          "invalid registration request",
			ArtifactDigest: requestedArtifactDigest,
			Digest:         descriptorDigest,
		}, http.StatusBadRequest, false
	}
	artifactDigest := strings.TrimSpace(descriptor.Artifact.ArtifactDigest)
	if artifactDigest == "" {
		return ArtifactErrorResponse{
			Error:          "invalid registration request",
			ArtifactDigest: requestedArtifactDigest,
			Digest:         descriptorDigest,
		}, http.StatusBadRequest, false
	}
	if err := store.ValidateDigest(artifactDigest); err != nil {
		return ArtifactErrorResponse{
			Error:          "invalid artifact digest",
			ArtifactDigest: artifactDigest,
		}, http.StatusBadRequest, false
	}
	if requestedArtifactDigest != "" && artifactDigest != requestedArtifactDigest {
		return ArtifactErrorResponse{
			Error:          "artifact data not registered",
			ArtifactDigest: requestedArtifactDigest,
		}, http.StatusNotFound, false
	}
	if strings.TrimSpace(descriptor.Artifact.ArtifactType) == "" {
		return ArtifactErrorResponse{
			Error:          "invalid registration request",
			ArtifactDigest: artifactDigest,
			Digest:         descriptorDigest,
		}, http.StatusBadRequest, false
	}
	if err := store.ValidateDigest(strings.TrimSpace(descriptor.Artifact.IntentDigest)); err != nil {
		return ArtifactErrorResponse{
			Error:          "invalid referenced digest",
			ArtifactDigest: artifactDigest,
			Digest:         strings.TrimSpace(descriptor.Artifact.IntentDigest),
		}, http.StatusBadRequest, false
	}
	if err := validateArtifactBlobRef(artifactDigest, descriptor.Package.Evidence, descriptorDigest); err != nil {
		return err.response, err.status, false
	}
	if err := validateArtifactBlobRef(artifactDigest, descriptor.Package.Payload, descriptorDigest); err != nil {
		return err.response, err.status, false
	}

	seenSupporting := make(map[string]struct{}, len(descriptor.Package.Supporting))
	for _, support := range descriptor.Package.Supporting {
		name := strings.TrimSpace(support.Name)
		if name == "" {
			return ArtifactErrorResponse{
				Error:          "invalid registration request",
				ArtifactDigest: artifactDigest,
				Digest:         descriptorDigest,
			}, http.StatusBadRequest, false
		}
		if _, exists := seenSupporting[name]; exists {
			return ArtifactErrorResponse{
				Error:          "invalid registration request",
				ArtifactDigest: artifactDigest,
				Digest:         descriptorDigest,
			}, http.StatusBadRequest, false
		}
		seenSupporting[name] = struct{}{}
		if err := validateArtifactBlobRef(artifactDigest, ArtifactBlobRef{
			Digest:    support.Digest,
			MediaType: support.MediaType,
		}, descriptorDigest); err != nil {
			return err.response, err.status, false
		}
	}

	return ArtifactErrorResponse{}, 0, true
}

func validateDescriptorMatchesDiscovery(descriptorDigest string, discovery ArtifactDiscovery, descriptor ArtifactDescriptor) (ArtifactErrorResponse, int, bool) {
	artifactDigest := strings.TrimSpace(discovery.Artifact.ArtifactDigest)
	if strings.TrimSpace(descriptor.Artifact.ArtifactDigest) != artifactDigest {
		return ArtifactErrorResponse{
			Error:          "invalid registration request",
			ArtifactDigest: artifactDigest,
			Digest:         descriptorDigest,
		}, http.StatusBadRequest, false
	}
	if strings.TrimSpace(descriptor.Artifact.ArtifactType) != strings.TrimSpace(discovery.Artifact.ArtifactType) {
		return ArtifactErrorResponse{
			Error:          "invalid registration request",
			ArtifactDigest: artifactDigest,
			Digest:         descriptorDigest,
		}, http.StatusBadRequest, false
	}
	if strings.TrimSpace(descriptor.Artifact.IntentDigest) != strings.TrimSpace(discovery.Artifact.IntentDigest) {
		return ArtifactErrorResponse{
			Error:          "invalid registration request",
			ArtifactDigest: artifactDigest,
			Digest:         descriptorDigest,
		}, http.StatusBadRequest, false
	}
	if strings.TrimSpace(descriptor.Package.Evidence.Digest) != strings.TrimSpace(discovery.Evidence.Digest) {
		return ArtifactErrorResponse{
			Error:          "invalid registration request",
			ArtifactDigest: artifactDigest,
			Digest:         descriptorDigest,
		}, http.StatusBadRequest, false
	}
	if strings.TrimSpace(descriptor.Package.Payload.Digest) != strings.TrimSpace(discovery.Payload.Digest) {
		return ArtifactErrorResponse{
			Error:          "invalid registration request",
			ArtifactDigest: artifactDigest,
			Digest:         descriptorDigest,
		}, http.StatusBadRequest, false
	}
	return ArtifactErrorResponse{}, 0, true
}

type artifactDescriptorValidationError struct {
	response ArtifactErrorResponse
	status   int
}

func validateArtifactBlobRef(artifactDigest string, ref ArtifactBlobRef, descriptorDigest string) *artifactDescriptorValidationError {
	digest := strings.TrimSpace(ref.Digest)
	if digest == "" {
		return &artifactDescriptorValidationError{
			response: ArtifactErrorResponse{
				Error:          "invalid registration request",
				ArtifactDigest: artifactDigest,
				Digest:         descriptorDigest,
			},
			status: http.StatusBadRequest,
		}
	}
	if err := store.ValidateDigest(digest); err != nil {
		return &artifactDescriptorValidationError{
			response: ArtifactErrorResponse{
				Error:          "invalid referenced digest",
				ArtifactDigest: artifactDigest,
				Digest:         digest,
			},
			status: http.StatusBadRequest,
		}
	}
	return nil
}

func descriptorSupportingDigest(descriptor ArtifactDescriptor, name string) (string, bool) {
	for _, support := range descriptor.Package.Supporting {
		if strings.TrimSpace(support.Name) == name {
			digest := strings.TrimSpace(support.Digest)
			if digest == "" {
				return "", false
			}
			return digest, true
		}
	}
	return "", false
}

func (s *Server) readArtifactJSONBlob(artifactDigest string, digest string) ([]byte, ArtifactErrorResponse, int, bool) {
	return s.readArtifactBlob(artifactDigest, digest, true)
}

func (s *Server) readArtifactBlob(artifactDigest string, digest string, expectJSON bool) ([]byte, ArtifactErrorResponse, int, bool) {
	data, err := s.blobStore.Read(digest)
	if err != nil {
		var corrupt store.BlobCorruptError
		switch {
		case errors.Is(err, store.ErrBlobNotFound):
			return nil, ArtifactErrorResponse{
				Error:          "referenced blob not found",
				ArtifactDigest: artifactDigest,
				Digest:         digest,
			}, http.StatusNotFound, false
		case errors.As(err, &corrupt):
			return nil, ArtifactErrorResponse{
				Error:          "stored blob digest mismatch",
				ArtifactDigest: artifactDigest,
				Digest:         corrupt.Digest,
			}, http.StatusInternalServerError, false
		default:
			return nil, ArtifactErrorResponse{
				Error:          "internal server error",
				ArtifactDigest: artifactDigest,
				Digest:         digest,
			}, http.StatusInternalServerError, false
		}
	}
	if expectJSON && !json.Valid(data) {
		return nil, ArtifactErrorResponse{
			Error:          "referenced blob is not valid JSON",
			ArtifactDigest: artifactDigest,
			Digest:         digest,
		}, http.StatusInternalServerError, false
	}
	return data, ArtifactErrorResponse{}, 0, true
}
