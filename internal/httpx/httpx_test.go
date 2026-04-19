package httpx

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestDecodeStrictJSONRejectsUnknownFields(t *testing.T) {
	t.Parallel()

	var payload struct {
		Name string `json:"name"`
	}

	err := DecodeStrictJSON(strings.NewReader(`{"name":"ok","extra":true}`), &payload)
	if err == nil {
		t.Fatal("expected unknown field error")
	}
}

func TestDecodeStrictJSONRejectsTrailingData(t *testing.T) {
	t.Parallel()

	var payload struct {
		Name string `json:"name"`
	}

	err := DecodeStrictJSON(strings.NewReader(`{"name":"ok"}{"name":"again"}`), &payload)
	if err == nil || err.Error() != "trailing data after first JSON document" {
		t.Fatalf("expected trailing data error, got %v", err)
	}
}

func TestDecodeStrictJSONAndCloseClosesBody(t *testing.T) {
	t.Parallel()

	body := &trackingReadCloser{Reader: strings.NewReader(`{"name":"ok"}`)}
	var payload struct {
		Name string `json:"name"`
	}

	if err := DecodeStrictJSONAndClose(body, &payload); err != nil {
		t.Fatalf("DecodeStrictJSONAndClose returned error: %v", err)
	}
	if !body.closed {
		t.Fatal("expected body to be closed")
	}
}

func TestWriteJSONEscapesHTMLByDefault(t *testing.T) {
	t.Parallel()

	recorder := httptest.NewRecorder()
	WriteJSON(recorder, http.StatusCreated, map[string]string{"value": "<tag>"})

	if recorder.Code != http.StatusCreated {
		t.Fatalf("expected status %d, got %d", http.StatusCreated, recorder.Code)
	}
	if got := recorder.Header().Get("Content-Type"); got != "application/json" {
		t.Fatalf("unexpected content type %q", got)
	}
	if got := recorder.Body.String(); got != "{\"value\":\"\\u003ctag\\u003e\"}\n" {
		t.Fatalf("unexpected body %q", got)
	}
}

func TestWriteJSONNoEscapeHTMLPreservesHTML(t *testing.T) {
	t.Parallel()

	recorder := httptest.NewRecorder()
	WriteJSONNoEscapeHTML(recorder, http.StatusOK, map[string]string{"value": "<tag>"})

	if got := recorder.Body.String(); got != "{\"value\":\"<tag>\"}\n" {
		t.Fatalf("unexpected body %q", got)
	}
}

func TestWriteText(t *testing.T) {
	t.Parallel()

	recorder := httptest.NewRecorder()
	WriteText(recorder, http.StatusUnauthorized, "denied")

	if recorder.Code != http.StatusUnauthorized {
		t.Fatalf("expected status %d, got %d", http.StatusUnauthorized, recorder.Code)
	}
	if got := recorder.Header().Get("Content-Type"); got != "text/plain; charset=utf-8" {
		t.Fatalf("unexpected content type %q", got)
	}
	if got := recorder.Body.String(); got != "denied" {
		t.Fatalf("unexpected body %q", got)
	}
}

func TestWriteMethodNotAllowedSortsAllowHeader(t *testing.T) {
	t.Parallel()

	recorder := httptest.NewRecorder()
	WriteMethodNotAllowed(recorder, http.MethodPost, http.MethodGet)

	if recorder.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected status %d, got %d", http.StatusMethodNotAllowed, recorder.Code)
	}
	if got := recorder.Header().Get("Allow"); got != "GET, POST" {
		t.Fatalf("unexpected Allow header %q", got)
	}
}

type trackingReadCloser struct {
	io.Reader
	closed bool
}

func (r *trackingReadCloser) Close() error {
	r.closed = true
	return nil
}
