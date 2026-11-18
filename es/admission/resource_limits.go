package admission

import (
	"errors"
	"fmt"
	"io"
	"net/http"
)

const (
	maxDependencyJSONResponseBytes int64 = 256 << 10
	maxPrimaryPayloadBytes         int64 = 32 << 20
	maxRuntimeSupportBytes         int64 = 32 << 20
	maxWorkloadVaultCABytes        int64 = 256 << 10
	maxSystemCABundleBytes         int64 = 256 << 10
	maxWorkloadTLSBundleBytes      int64 = maxWorkloadVaultCABytes + maxSystemCABundleBytes + 1

	// The material owner retains the primary payload, runtime support, mount
	// compressed bytes, mount names and bodies governed by the whole-stream
	// budget, and the two workload trust files. The one-byte allowance is the
	// separator inserted into a non-empty combined PEM bundle.
	maxResolvedExecutionMaterialBytes int64 = maxPrimaryPayloadBytes +
		maxRuntimeSupportBytes +
		maxRuntimeMountTotalBytes +
		maxRuntimeMountTotalStreamBytes +
		maxWorkloadVaultCABytes +
		maxWorkloadTLSBundleBytes

	// Vault and system CA inputs are each normalized once. Combined-bundle
	// assembly consumes those normalized buffers directly, so the selected
	// system CA is the only temporary trust buffer that coexists with the final
	// resolved material owner.
	maxResolvedExecutionTemporaryMaterialBytes int64 = maxSystemCABundleBytes
	maxResolvedExecutionAccountedPeakBytes     int64 = maxResolvedExecutionMaterialBytes + maxResolvedExecutionTemporaryMaterialBytes
)

type boundedResponseError string

func (e boundedResponseError) Error() string {
	return string(e)
}

const (
	errBoundedResponseTooLarge       boundedResponseError = "response body exceeds configured limit"
	errBoundedResponseLengthMismatch boundedResponseError = "response body does not match content length"
)

// readBoundedResponseBody performs the transport boundary check before any
// caller-specific decoding. A known oversized Content-Length is rejected
// without reading the body. Unknown/chunked lengths and dishonest lengths are
// resolved with one limit-plus-one read. A fixed-length truncation or surplus
// is rejected rather than being accepted as a different payload.
func readBoundedResponseBody(response *http.Response, limit int64) ([]byte, error) {
	if response == nil || response.Body == nil {
		return nil, fmt.Errorf("response body is unavailable")
	}
	if limit < 0 {
		return nil, fmt.Errorf("response body limit is invalid")
	}
	if response.ContentLength > limit {
		return nil, errBoundedResponseTooLarge
	}

	reader := &io.LimitedReader{R: response.Body, N: limit + 1}
	payload, err := io.ReadAll(reader)
	if err != nil {
		return nil, err
	}
	if int64(len(payload)) > limit {
		return nil, errBoundedResponseTooLarge
	}
	if response.ContentLength >= 0 && int64(len(payload)) != response.ContentLength {
		return nil, errBoundedResponseLengthMismatch
	}
	return payload, nil
}

func boundedResponseTooLarge(err error) bool {
	return errors.Is(err, errBoundedResponseTooLarge)
}

func addWithinLimit(current int64, amount int64, limit int64) (int64, bool) {
	if current < 0 || amount < 0 || current > limit || amount > limit-current {
		return current, false
	}
	return current + amount, true
}

func minInt64(left int64, right int64) int64 {
	if left < right {
		return left
	}
	return right
}
