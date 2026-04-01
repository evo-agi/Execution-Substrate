package proof

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"hash"
	"strings"
	"time"
)

const (
	proofVersion            = 1
	recordPurpose           = "record"
	defaultRecordTTLSeconds = 600
)

type Minter interface {
	MintRecordProof(input Input) (MintedProof, error)
}

type Input struct {
	DecisionID         string
	CallerIdentityID   string
	WorkloadIdentityID string
	RunID              string
	AllocationID       string
}

type MintedProof struct {
	Token     string
	ExpiresAt time.Time
}

type HMACMinter struct {
	secretKey    []byte
	hashFunction func() hash.Hash
}

func NewHMACMinter(secretKey string, hashFunction string) (*HMACMinter, error) {
	if strings.TrimSpace(secretKey) == "" {
		return nil, fmt.Errorf("action_proof.secret_key is required")
	}

	var constructor func() hash.Hash
	switch strings.ToLower(strings.TrimSpace(hashFunction)) {
	case "sha256":
		constructor = sha256.New
	case "sha512":
		constructor = sha512.New
	default:
		return nil, fmt.Errorf("unsupported action proof hash function")
	}

	return &HMACMinter{
		secretKey:    []byte(secretKey),
		hashFunction: constructor,
	}, nil
}

func (m *HMACMinter) MintRecordProof(input Input) (MintedProof, error) {
	now := time.Now().UTC()
	expiresAt := now.Add(defaultRecordTTLSeconds * time.Second)
	jti, err := randomToken(16)
	if err != nil {
		return MintedProof{}, fmt.Errorf("generate proof id: %w", err)
	}

	payload := map[string]any{
		"version":              proofVersion,
		"purpose":              recordPurpose,
		"decision_id":          input.DecisionID,
		"caller_identity_id":   input.CallerIdentityID,
		"workload_identity_id": input.WorkloadIdentityID,
		"issued_at":            now.Unix(),
		"expires_at":           expiresAt.Unix(),
		"jti":                  jti,
	}
	// TODO: record_proof remains a provisional compatibility artifact. Keep the
	// signed claim set minimal for current consumers and do not treat optional
	// request context such as run_id or allocation_id as a stable CGS
	// responsibility. Future work must decide whether this proof belongs in ES
	// or a dedicated attestation boundary.
	_ = input.RunID
	_ = input.AllocationID

	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		return MintedProof{}, fmt.Errorf("marshal proof payload: %w", err)
	}

	mac := hmac.New(m.hashFunction, m.secretKey)
	if _, err := mac.Write(payloadBytes); err != nil {
		return MintedProof{}, fmt.Errorf("sign proof payload: %w", err)
	}
	signature := mac.Sum(nil)

	token := base64.RawURLEncoding.EncodeToString(payloadBytes) + "." + base64.RawURLEncoding.EncodeToString(signature)
	return MintedProof{
		Token:     token,
		ExpiresAt: expiresAt,
	}, nil
}

func randomToken(size int) (string, error) {
	buf := make([]byte, size)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}
