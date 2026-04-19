package httpx

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"slices"
	"strings"
)

func DecodeStrictJSON(reader io.Reader, target any) error {
	decoder := json.NewDecoder(reader)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	var trailing json.RawMessage
	if err := decoder.Decode(&trailing); err != io.EOF {
		return errors.New("trailing data after first JSON document")
	}
	return nil
}

func DecodeStrictJSONAndClose(body io.ReadCloser, target any) error {
	defer body.Close()
	return DecodeStrictJSON(body, target)
}

func WriteJSON(w http.ResponseWriter, status int, payload any) {
	writeJSON(w, status, payload, true)
}

func WriteJSONNoEscapeHTML(w http.ResponseWriter, status int, payload any) {
	writeJSON(w, status, payload, false)
}

func WriteText(w http.ResponseWriter, status int, body string) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(status)
	_, _ = io.WriteString(w, body)
}

func WriteMethodNotAllowed(w http.ResponseWriter, methods ...string) {
	allowed := append([]string(nil), methods...)
	slices.Sort(allowed)
	w.Header().Set("Allow", strings.Join(allowed, ", "))
	w.WriteHeader(http.StatusMethodNotAllowed)
}

func writeJSON(w http.ResponseWriter, status int, payload any, escapeHTML bool) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	encoder := json.NewEncoder(w)
	encoder.SetEscapeHTML(escapeHTML)
	_ = encoder.Encode(payload)
}
