package app_test

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestObservabilityPropagatesTraceparentAcrossServices(t *testing.T) {
	capture := startLogCapture(t)
	stack := startStack(t, stackOptions{})
	defer stack.shutdownAll(t)

	capture.Reset()

	const traceParent = "00-0123456789abcdef0123456789abcdef-1111111111111111-01"
	response := doRequestWithHeaders(t, stack.es.Addr(), http.MethodGet, "/health", stack.fixture.clientTLSConfigForServer(t, stack.fixture.esServerName, "operator", false), nil, map[string]string{
		"traceparent": traceParent,
	})
	defer response.Body.Close()

	if response.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", response.StatusCode, strings.TrimSpace(string(mustReadBody(t, response.Body))))
	}

	events := capture.Events(t)
	if len(events) == 0 {
		t.Fatalf("expected observability events")
	}

	traceID := "0123456789abcdef0123456789abcdef"
	esInbound := requireEvent(t, events, "inbound_request_complete", "execution", "", "GET /health")
	esToARS := requireEvent(t, events, "outbound_dependency_complete", "execution", "artifact-registry", "GET /health")
	arsInbound := requireEvent(t, events, "inbound_request_complete", "artifact-registry", "", "GET /health")

	for _, event := range []loggedEvent{esInbound, esToARS, arsInbound} {
		if event.TraceID != traceID {
			t.Fatalf("expected trace_id %q, got %+v", traceID, event)
		}
		if strings.TrimSpace(event.RequestID) == "" {
			t.Fatalf("expected request_id in %+v", event)
		}
		if strings.TrimSpace(event.Service) == "" {
			t.Fatalf("expected service in %+v", event)
		}
		if strings.TrimSpace(event.Route) == "" {
			t.Fatalf("expected route in %+v", event)
		}
		if strings.TrimSpace(event.Status) == "" {
			t.Fatalf("expected status in %+v", event)
		}
		if strings.TrimSpace(event.Duration) == "" {
			t.Fatalf("expected duration in %+v", event)
		}
	}

	if esToARS.Dependency != "artifact-registry" {
		t.Fatalf("unexpected dependency event: %+v", esToARS)
	}

	seenRequestIDs := map[string]struct{}{}
	for _, event := range []loggedEvent{esInbound, esToARS, arsInbound} {
		if _, ok := seenRequestIDs[event.RequestID]; ok {
			t.Fatalf("expected unique request ids per hop, duplicate %q in %+v", event.RequestID, event)
		}
		seenRequestIDs[event.RequestID] = struct{}{}
	}
}

func TestObservabilityDoesNotEmitBusinessLogicLogs(t *testing.T) {
	capture := startLogCapture(t)
	stack := startStack(t, stackOptions{})
	defer stack.shutdownAll(t)

	capture.Reset()

	response := doRequestWithHeaders(t, stack.egs.Addr(), http.MethodGet, "/v1/trust-model", stack.fixture.clientTLSConfigForServer(t, stack.fixture.egsServerName, "service/execution", false), nil, nil)
	defer response.Body.Close()

	if response.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", response.StatusCode, strings.TrimSpace(string(mustReadBody(t, response.Body))))
	}

	events := capture.Events(t)
	if len(events) != 1 {
		t.Fatalf("expected exactly one edge log event, got %d: %+v", len(events), events)
	}

	event := events[0]
	if event.Event != "inbound_request_complete" {
		t.Fatalf("expected only inbound request completion event, got %+v", event)
	}
	if event.Service != "execution-governance" {
		t.Fatalf("unexpected service: %+v", event)
	}
	if event.Route != "GET /v1/trust-model" {
		t.Fatalf("unexpected route: %+v", event)
	}
}

type logCapture struct {
	buffer   bytes.Buffer
	previous io.Writer
	flags    int
}

type loggedEvent struct {
	Event      string `json:"event"`
	TraceID    string `json:"trace_id"`
	RequestID  string `json:"request_id"`
	Service    string `json:"service"`
	Route      string `json:"route"`
	Dependency string `json:"dependency,omitempty"`
	Status     string `json:"status"`
	Duration   string `json:"duration"`
}

func startLogCapture(t *testing.T) *logCapture {
	t.Helper()

	capture := &logCapture{
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

func (c *logCapture) Reset() {
	c.buffer.Reset()
}

func (c *logCapture) Events(t *testing.T) []loggedEvent {
	t.Helper()

	// Let any final handler-deferred log writes flush into the buffer.
	time.Sleep(25 * time.Millisecond)

	var events []loggedEvent
	scanner := bufio.NewScanner(bytes.NewReader(c.buffer.Bytes()))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || !strings.HasPrefix(line, "{") {
			continue
		}
		var event loggedEvent
		if err := json.Unmarshal([]byte(line), &event); err == nil && event.Event != "" {
			events = append(events, event)
		}
	}
	if err := scanner.Err(); err != nil {
		t.Fatalf("scan log output: %v", err)
	}
	return events
}

func requireEvent(t *testing.T, events []loggedEvent, eventName string, service string, dependency string, route string) loggedEvent {
	t.Helper()

	for _, event := range events {
		if event.Event == eventName && event.Service == service && event.Dependency == dependency && event.Route == route {
			return event
		}
	}
	t.Fatalf("missing event %q service=%q dependency=%q route=%q in %+v", eventName, service, dependency, route, events)
	return loggedEvent{}
}

func doRequestWithHeaders(t *testing.T, addr string, method string, requestPath string, tlsConfig *tls.Config, body []byte, headers map[string]string) *http.Response {
	t.Helper()

	client := &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: tlsConfig,
		},
	}

	request, err := http.NewRequest(method, "https://"+addr+requestPath, bytes.NewReader(body))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	for key, value := range headers {
		request.Header.Set(key, value)
	}

	response, err := client.Do(request)
	if err != nil {
		t.Fatalf("do request: %v", err)
	}
	return response
}
