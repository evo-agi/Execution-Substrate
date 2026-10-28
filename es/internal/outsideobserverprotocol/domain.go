package outsideobserverprotocol

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strconv"
)

func hashDomain(domain string, raw []byte) string {
	h := sha256.New()
	h.Write([]byte(domain))
	h.Write([]byte{0})
	h.Write(raw)
	return hex.EncodeToString(h.Sum(nil))
}

// ComputeJournalSegmentID hashes only the selected four-field core. Its output
// describes untrusted values and is never a verified session or permit.
func ComputeJournalSegmentID(runID, sourceInstanceID string, epoch int64, endpointNonce string) (string, error) {
	if !validASCIIID(runID) || !validASCIIID(sourceInstanceID) || epoch < 1 || !validHex32(endpointNonce) {
		return "", fmt.Errorf("journal segment: invalid structural input")
	}
	core := map[string]any{
		"run_id":             runID,
		"source_instance_id": sourceInstanceID,
		"epoch":              canonicalInteger(strconv.FormatInt(epoch, 10)),
		"endpoint_nonce":     endpointNonce,
	}
	encoded, err := encodeCanonicalV2(core)
	if err != nil {
		return "", fmt.Errorf("journal segment: invalid canonical core")
	}
	return hashDomain("R6J-OBS-JOURNAL-SEGMENT/v1", encoded), nil
}
