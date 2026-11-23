package admission

import (
	"context"
	"errors"
	"net/http"
)

// arsBlobView names the ARS blob read view ES requests. Both views return the
// stored bytes unchanged; the JSON view additionally makes ARS refuse a blob
// that is not valid JSON.
type arsBlobView string

const (
	arsBlobViewBytes arsBlobView = ":bytes"
	arsBlobViewJSON  arsBlobView = ":json"
)

// arsBlobFetchFailure classifies why a verified ARS blob read returned no
// bytes. Each caller maps the class onto its own existing public error, so the
// classification never leaks into public grammar.
type arsBlobFetchFailure uint8

const (
	// arsBlobDigestNotCanonical: the digest is not exactly "sha256:" followed
	// by 64 lowercase hex digits. No request was sent.
	arsBlobDigestNotCanonical arsBlobFetchFailure = iota + 1
	// arsBlobRequestFailed: the request could not be made or answered.
	arsBlobRequestFailed
	// arsBlobNotFound: ARS answered 404.
	arsBlobNotFound
	// arsBlobUnexpectedStatus: ARS answered a status other than 200 or 404.
	arsBlobUnexpectedStatus
	// arsBlobReadFailed: the bounded body read failed (over the limit, length
	// mismatch, or transport error while reading).
	arsBlobReadFailed
	// arsBlobDigestMismatch: ARS answered 200 with bytes whose SHA-256 is not
	// the requested digest. The bytes are dropped.
	arsBlobDigestMismatch
)

// Public messages for a digest mismatch. Each keeps its call site's existing
// HTTP status and code; only the message names the integrity cause. None
// carries a digest, a byte count or any received bytes.
const (
	artifactPayloadDigestMismatchMessage       = "artifact payload bytes do not match the signed payload digest"
	artifactEvidenceDigestMismatchMessage      = "artifact evidence blob does not match its discovery digest"
	workloadZoneVaultBlobDigestMismatchMessage = "artifact registry workload-zone vault blob does not match its configured digest"
)

// errARSBlobDigestMismatch is the acquisition error carried for a digest
// mismatch, so callers that inspect acquisition errors see a distinct cause.
var errARSBlobDigestMismatch = errors.New("artifact registry blob bytes do not match the requested digest")

type arsBlobFetchError struct {
	failure arsBlobFetchFailure
	// status is the ARS response status for arsBlobUnexpectedStatus.
	status int
	// cause is the underlying acquisition error, when one exists.
	cause error
}

// fetchVerifiedARSBlob is the only ES read of an ARS blob by digest. It
// returns bytes only when the exact bytes it read, and nothing else, hash to
// the requested digest. Every caller uses the returned slice itself for
// decoding, policy inspection, archive parsing and staging, so the bytes that
// were verified are the bytes that are used. ARS's own read-path integrity
// check is not relied on.
//
// The digest must already be canonical; it is never trimmed or normalized
// here, because the string that is requested is the string that is verified.
func (s *Service) fetchVerifiedARSBlob(ctx context.Context, digest string, view arsBlobView, limit int64) ([]byte, *arsBlobFetchError) {
	if !labeledSHA256DigestPattern.MatchString(digest) {
		return nil, &arsBlobFetchError{failure: arsBlobDigestNotCanonical}
	}
	response, err := s.arsClient.get(ctx, "/v1/blobs/"+digest+string(view))
	if err != nil {
		return nil, &arsBlobFetchError{failure: arsBlobRequestFailed, cause: err}
	}
	defer response.Body.Close()

	switch response.StatusCode {
	case http.StatusOK:
	case http.StatusNotFound:
		return nil, &arsBlobFetchError{failure: arsBlobNotFound, status: response.StatusCode}
	default:
		return nil, &arsBlobFetchError{failure: arsBlobUnexpectedStatus, status: response.StatusCode}
	}

	payload, readErr := readBoundedResponseBody(response, limit)
	if readErr != nil {
		return nil, &arsBlobFetchError{failure: arsBlobReadFailed, cause: readErr}
	}
	if digestBytes(payload) != digest {
		return nil, &arsBlobFetchError{failure: arsBlobDigestMismatch, cause: errARSBlobDigestMismatch}
	}
	return payload, nil
}
