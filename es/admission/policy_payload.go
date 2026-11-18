package admission

import (
	"archive/tar"
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"unicode/utf8"

	"execution-substrate/es/internal/staticarchive"
)

const (
	maxAdmissionPolicyPayloadBytes          = 256 * 1024
	maxAdmissionPolicyStaticScriptTextBytes = 64 * 1024
	maxAdmissionPolicyStaticScriptEntries   = 64
	maxAdmissionPolicyDecodedArchiveBytes   = 16 * 1024 * 1024
	staticScriptEntrypointName              = "entrypoint"
)

func (s *Service) enforceAdmissionPolicy(ctx context.Context, req PrepareRequest, artifact preparedArtifact) ([]byte, bool, *Error) {
	evaluator := s.admissionPolicyEvaluator
	if evaluator == nil {
		evaluator = admissionPolicyEvaluatorFromConfig(s.cfg.AdmissionPolicy)
	}

	policyCtx := newAdmissionPolicyContext(req, artifact)
	requiredInputs := evaluator.RequiredInputClasses(policyCtx)
	var payloadBytes []byte
	var payloadFetched bool
	if admissionPolicyRequiresPayloadBytes(requiredInputs) {
		fetched, err := s.fetchAdmissionPolicyPayloadBytes(ctx, artifact.payloadDigest)
		if err != nil {
			return nil, false, err
		}
		payloadBytes = fetched
		payloadFetched = true
		policyCtx.PayloadByteCount = int64(len(fetched))
	}
	if admissionPolicyRequiresStaticScriptText(requiredInputs) {
		text, err := staticScriptPayloadTextForAdmissionPolicy(payloadBytes)
		if err != nil {
			return nil, false, err
		}
		policyCtx.StaticScriptPayloadText = text
		policyCtx.StaticScriptPayloadTextPresent = true
	}

	decision := evaluator.Evaluate(ctx, policyCtx)
	if !decision.Allow {
		return nil, false, policyDenialError(decision)
	}
	return payloadBytes, payloadFetched, nil
}

func admissionPolicyRequiresPayloadBytes(classes []AdmissionPolicyInputClass) bool {
	for _, class := range classes {
		switch class {
		case AdmissionPolicyInputPayloadDigestAndByteCount, AdmissionPolicyInputStaticScriptPayloadText:
			return true
		}
	}
	return false
}

func admissionPolicyRequiresStaticScriptText(classes []AdmissionPolicyInputClass) bool {
	for _, class := range classes {
		if class == AdmissionPolicyInputStaticScriptPayloadText {
			return true
		}
	}
	return false
}

func (s *Service) fetchAdmissionPolicyPayloadBytes(ctx context.Context, payloadDigest string) ([]byte, *Error) {
	response, err := s.arsClient.get(ctx, "/v1/blobs/"+payloadDigest+":bytes")
	if err != nil {
		return nil, admissionPolicyInputUnavailableError()
	}
	defer response.Body.Close()

	if response.StatusCode != http.StatusOK {
		return nil, admissionPolicyInputUnavailableError()
	}

	payload, readErr := readBoundedResponseBody(response, maxAdmissionPolicyPayloadBytes)
	if readErr != nil {
		return nil, admissionPolicyInputUnavailableError()
	}
	return payload, nil
}

func staticScriptPayloadTextForAdmissionPolicy(payload []byte) (string, *Error) {
	text, err := extractStaticScriptEntrypointText(payload)
	if err != nil {
		return "", admissionPolicyInputUnavailableError()
	}
	return text, nil
}

func extractStaticScriptEntrypointText(payload []byte) (string, error) {
	if len(payload) == 0 || len(payload) > maxAdmissionPolicyPayloadBytes {
		return "", fmt.Errorf("static-script payload is outside policy inspection bounds")
	}

	archive, err := staticarchive.Open(bytes.NewReader(payload), maxAdmissionPolicyDecodedArchiveBytes)
	if err != nil {
		return "", fmt.Errorf("static-script payload is not a supported archive")
	}
	defer archive.Close()

	var namespace staticarchive.Namespace
	entries := 0
	var entrypointText string
	var foundEntrypoint bool
	for {
		header, err := archive.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return "", fmt.Errorf("read static-script archive")
		}
		entries++
		if entries > maxAdmissionPolicyStaticScriptEntries {
			return "", fmt.Errorf("static-script archive exceeds policy entry bound")
		}

		name, err := namespace.Add(header)
		if err != nil {
			return "", err
		}
		switch header.Typeflag {
		case tar.TypeDir:
			continue
		default:
			if name != staticScriptEntrypointName {
				if _, err := io.Copy(io.Discard, archive); err != nil {
					return "", fmt.Errorf("read static-script archive body")
				}
				continue
			}
			if foundEntrypoint {
				return "", fmt.Errorf("static-script entrypoint is duplicated")
			}
			if header.Size < 0 || header.Size > maxAdmissionPolicyStaticScriptTextBytes {
				return "", fmt.Errorf("static-script text is outside policy inspection bounds")
			}
			textBytes, err := io.ReadAll(io.LimitReader(archive, maxAdmissionPolicyStaticScriptTextBytes+1))
			if err != nil {
				return "", fmt.Errorf("read static-script text")
			}
			if len(textBytes) > maxAdmissionPolicyStaticScriptTextBytes {
				return "", fmt.Errorf("static-script text exceeds policy inspection bounds")
			}
			if !utf8.Valid(textBytes) || bytes.ContainsRune(textBytes, '\x00') {
				return "", fmt.Errorf("static-script text is not safe UTF-8 text")
			}
			entrypointText = string(textBytes)
			foundEntrypoint = true
		}
	}
	if err := archive.Finish(); err != nil {
		return "", fmt.Errorf("finish static-script archive: %w", err)
	}
	if !foundEntrypoint {
		return "", fmt.Errorf("static-script entrypoint text unavailable")
	}
	return entrypointText, nil
}
