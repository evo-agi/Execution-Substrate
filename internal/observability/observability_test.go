package observability

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestInvalidTraceparentGeneratesNewTraceAndPropagates(t *testing.T) {
	capture := startObservabilityLogCapture(t)

	var downstreamTraceParent string
	downstream := httptest.NewServer(WrapHandler("downstream", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		downstreamTraceParent = r.Header.Get(TraceParentHeader)
		w.WriteHeader(http.StatusNoContent)
	})))
	defer downstream.Close()

	outboundClient := &http.Client{
		Timeout:   2 * time.Second,
		Transport: WrapRoundTripper("upstream", "downstream", true, downstream.Client().Transport),
	}

	upstream := httptest.NewServer(WrapHandler("upstream", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		request, err := http.NewRequestWithContext(r.Context(), http.MethodGet, downstream.URL+"/dep", nil)
		if err != nil {
			t.Fatalf("new outbound request: %v", err)
		}

		response, err := outboundClient.Do(request)
		if err != nil {
			t.Fatalf("outbound request failed: %v", err)
		}
		defer response.Body.Close()
		w.WriteHeader(http.StatusNoContent)
	})))
	defer upstream.Close()

	capture.Reset()

	request, err := http.NewRequest(http.MethodGet, upstream.URL+"/entry", nil)
	if err != nil {
		t.Fatalf("new inbound request: %v", err)
	}
	request.Header.Set(TraceParentHeader, "not-a-traceparent")

	response, err := upstream.Client().Do(request)
	if err != nil {
		t.Fatalf("do inbound request: %v", err)
	}
	defer response.Body.Close()

	if response.StatusCode != http.StatusNoContent {
		t.Fatalf("expected 204, got %d", response.StatusCode)
	}

	propagatedTraceID, ok := traceIDFromTraceParent(downstreamTraceParent)
	if !ok {
		t.Fatalf("expected valid propagated traceparent, got %q", downstreamTraceParent)
	}

	events := capture.Events(t)
	upstreamInbound := requireObservedEvent(t, events, "inbound_request_complete", "upstream", "", "GET /entry")
	upstreamOutbound := requireObservedEvent(t, events, "outbound_dependency_complete", "upstream", "downstream", "GET /dep")
	downstreamInbound := requireObservedEvent(t, events, "inbound_request_complete", "downstream", "", "GET /dep")

	for _, event := range []observedEvent{upstreamInbound, upstreamOutbound, downstreamInbound} {
		if event.TraceID != propagatedTraceID {
			t.Fatalf("expected propagated trace id %q, got %+v", propagatedTraceID, event)
		}
	}
}

func TestInboundFailureClassification(t *testing.T) {
	testCases := []struct {
		name           string
		statusCode     int
		expectedStatus string
	}{
		{name: "client error", statusCode: http.StatusNotFound, expectedStatus: "client_error"},
		{name: "server error", statusCode: http.StatusInternalServerError, expectedStatus: "server_error"},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			capture := startObservabilityLogCapture(t)

			handler := WrapHandler("svc", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if capture.BufferLen() != 0 {
					t.Fatalf("expected no logs before handler completion, got %q", capture.RawString())
				}
				http.Error(w, http.StatusText(testCase.statusCode), testCase.statusCode)
			}))

			server := httptest.NewServer(handler)
			defer server.Close()

			capture.Reset()

			response, err := server.Client().Get(server.URL + "/test")
			if err != nil {
				t.Fatalf("do request: %v", err)
			}
			defer response.Body.Close()
			_, _ = io.ReadAll(response.Body)

			events := capture.Events(t)
			if len(events) != 1 {
				t.Fatalf("expected exactly one inbound completion log, got %d: %+v", len(events), events)
			}
			if events[0].Event != "inbound_request_complete" {
				t.Fatalf("unexpected event: %+v", events[0])
			}
			if events[0].Status != testCase.expectedStatus {
				t.Fatalf("expected status %q, got %+v", testCase.expectedStatus, events[0])
			}
		})
	}
}

func TestOutboundFailureClassification(t *testing.T) {
	testCases := []struct {
		name           string
		roundTripper   http.RoundTripper
		expectedStatus string
	}{
		{
			name:           "timeout",
			roundTripper:   staticRoundTripper{err: timeoutError{}},
			expectedStatus: "timeout",
		},
		{
			name:           "dependency failure",
			roundTripper:   staticRoundTripper{err: errTransportFailure},
			expectedStatus: "dependency_failure",
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			capture := startObservabilityLogCapture(t)
			client := &http.Client{
				Transport: WrapRoundTripper("svc", "dep", true, testCase.roundTripper),
			}

			request, err := http.NewRequestWithContext(WithTraceContext(context.Background(), TraceContext{
				TraceID:   "0123456789abcdef0123456789abcdef",
				RequestID: "1111111111111111",
			}), http.MethodGet, "https://dependency.internal/path", nil)
			if err != nil {
				t.Fatalf("new request: %v", err)
			}

			capture.Reset()
			_, err = client.Do(request)
			if err == nil {
				t.Fatalf("expected dependency failure")
			}

			events := capture.Events(t)
			if len(events) != 1 {
				t.Fatalf("expected one dependency log, got %d: %+v", len(events), events)
			}
			event := events[0]
			if event.Event != "outbound_dependency_complete" {
				t.Fatalf("unexpected event: %+v", event)
			}
			if event.Status != testCase.expectedStatus {
				t.Fatalf("expected status %q, got %+v", testCase.expectedStatus, event)
			}
		})
	}
}

type observabilityLogCapture struct {
	buffer   bytes.Buffer
	previous io.Writer
	flags    int
}

type observedEvent struct {
	Event      string `json:"event"`
	TraceID    string `json:"trace_id"`
	RequestID  string `json:"request_id"`
	Service    string `json:"service"`
	Route      string `json:"route"`
	Dependency string `json:"dependency,omitempty"`
	Status     string `json:"status"`
	Duration   string `json:"duration"`
}

type staticRoundTripper struct {
	response *http.Response
	err      error
}

var errTransportFailure = net.UnknownNetworkError("transport failure")

func (s staticRoundTripper) RoundTrip(*http.Request) (*http.Response, error) {
	return s.response, s.err
}

type timeoutError struct{}

func (timeoutError) Error() string   { return "timeout" }
func (timeoutError) Timeout() bool   { return true }
func (timeoutError) Temporary() bool { return true }

func startObservabilityLogCapture(t *testing.T) *observabilityLogCapture {
	t.Helper()

	capture := &observabilityLogCapture{
		previous: log.Writer(),
		flags:    log.Flags(),
	}
	log.SetFlags(0)
	log.SetOutput(&capture.buffer)
	t.Cleanup(func() {
		log.SetOutput(capture.previous)
		log.SetFlags(capture.flags)
	})
	return capture
}

func (c *observabilityLogCapture) Reset() {
	c.buffer.Reset()
}

func (c *observabilityLogCapture) BufferLen() int {
	return c.buffer.Len()
}

func (c *observabilityLogCapture) RawString() string {
	return c.buffer.String()
}

func (c *observabilityLogCapture) Events(t *testing.T) []observedEvent {
	t.Helper()

	time.Sleep(25 * time.Millisecond)

	var events []observedEvent
	scanner := bufio.NewScanner(bytes.NewReader(c.buffer.Bytes()))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || !strings.HasPrefix(line, "{") {
			continue
		}
		var event observedEvent
		if err := json.Unmarshal([]byte(line), &event); err == nil && event.Event != "" {
			events = append(events, event)
		}
	}
	if err := scanner.Err(); err != nil {
		t.Fatalf("scan log output: %v", err)
	}
	return events
}

func requireObservedEvent(t *testing.T, events []observedEvent, eventName string, service string, dependency string, route string) observedEvent {
	t.Helper()

	for _, event := range events {
		if event.Event == eventName && event.Service == service && event.Dependency == dependency && event.Route == route {
			return event
		}
	}
	t.Fatalf("missing event %q service=%q dependency=%q route=%q in %+v", eventName, service, dependency, route, events)
	return observedEvent{}
}

var _ net.Error = timeoutError{}
var _ http.RoundTripper = staticRoundTripper{}
