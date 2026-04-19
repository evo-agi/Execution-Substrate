package observability

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"log"
	"net"
	"net/http"
	"strings"
	"time"
)

const TraceParentHeader = "traceparent"

type TraceContext struct {
	TraceID   string
	RequestID string
}

type contextKey string

const traceContextKey contextKey = "observability-trace-context"

type requestCompleteEvent struct {
	Event     string `json:"event"`
	TraceID   string `json:"trace_id"`
	RequestID string `json:"request_id"`
	Service   string `json:"service"`
	Route     string `json:"route"`
	Status    string `json:"status"`
	Duration  string `json:"duration"`
}

type dependencyCallEvent struct {
	Event      string `json:"event"`
	TraceID    string `json:"trace_id"`
	RequestID  string `json:"request_id"`
	Service    string `json:"service"`
	Route      string `json:"route"`
	Dependency string `json:"dependency"`
	Status     string `json:"status"`
	Duration   string `json:"duration"`
}

type loggingRoundTripper struct {
	service          string
	dependency       string
	propagateTrace   bool
	baseRoundTripper http.RoundTripper
}

type statusCapturingResponseWriter struct {
	http.ResponseWriter
	statusCode int
}

func WithTraceContext(ctx context.Context, trace TraceContext) context.Context {
	return context.WithValue(ctx, traceContextKey, trace)
}

func TraceContextFromContext(ctx context.Context) (TraceContext, bool) {
	trace, ok := ctx.Value(traceContextKey).(TraceContext)
	if !ok {
		return TraceContext{}, false
	}
	if trace.TraceID == "" || trace.RequestID == "" {
		return TraceContext{}, false
	}
	return trace, true
}

func WrapHandler(service string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		traceID, ok := traceIDFromTraceParent(r.Header.Get(TraceParentHeader))
		if !ok {
			traceID = newTraceID()
		}
		requestID := newRequestID()
		ctx := WithTraceContext(r.Context(), TraceContext{
			TraceID:   traceID,
			RequestID: requestID,
		})

		responseWriter := &statusCapturingResponseWriter{
			ResponseWriter: w,
			statusCode:     http.StatusOK,
		}

		startedAt := time.Now()

		// TODO: inbound completion log is skipped on panic because this slice does
		// 		 not include panic recovery. Evaluate whether to add bounded panic
		// 		 recovery plus completion logging in a future slice.
		next.ServeHTTP(responseWriter, r.WithContext(ctx))

		emit(requestCompleteEvent{
			Event:     "inbound_request_complete",
			TraceID:   traceID,
			RequestID: requestID,
			Service:   service,
			Route:     routeLabel(r.Method, r.URL.EscapedPath()),
			Status:    classifyInboundStatus(responseWriter.statusCode),
			Duration:  time.Since(startedAt).String(),
		})
	})
}

func WrapRoundTripper(service string, dependency string, propagateTrace bool, base http.RoundTripper) http.RoundTripper {
	if base == nil {
		base = http.DefaultTransport
	}
	return &loggingRoundTripper{
		service:          service,
		dependency:       dependency,
		propagateTrace:   propagateTrace,
		baseRoundTripper: base,
	}
}

func (w *statusCapturingResponseWriter) WriteHeader(statusCode int) {
	w.statusCode = statusCode
	w.ResponseWriter.WriteHeader(statusCode)
}

func (t *loggingRoundTripper) RoundTrip(request *http.Request) (*http.Response, error) {
	trace, ok := TraceContextFromContext(request.Context())
	if !ok {
		// TODO: a new root trace can be created here when no inbound request
		// 		 context exists. That can happen during startup-time or other
		// 		 request-unscoped dependency calls in this slice.
		trace = TraceContext{
			TraceID:   newTraceID(),
			RequestID: newRequestID(),
		}
	}

	outboundRequestID := newRequestID()
	if t.propagateTrace {
		// TODO: external propagation is currently controlled manually by the
		// 		 caller through propagateTrace. Future external dependencies must make
		// 		 an explicit propagation decision instead of inheriting one silently.
		request = cloneRequestWithHeader(request, TraceParentHeader, formatTraceParent(trace.TraceID, outboundRequestID))
	}

	// TODO: outbound dependency logging begins at RoundTrip. Failures while
	// 		 constructing the request or before client.Do reaches this wrapper are not
	// 		 observed in this slice.
	startedAt := time.Now()
	response, err := t.baseRoundTripper.RoundTrip(request)
	status := classifyDependencyStatus(response, err)

	emit(dependencyCallEvent{
		Event:      "outbound_dependency_complete",
		TraceID:    trace.TraceID,
		RequestID:  outboundRequestID,
		Service:    t.service,
		Route:      routeLabel(request.Method, request.URL.EscapedPath()),
		Dependency: t.dependency,
		Status:     status,
		Duration:   time.Since(startedAt).String(),
	})

	return response, err
}

func cloneRequestWithHeader(request *http.Request, key string, value string) *http.Request {
	cloned := request.Clone(request.Context())
	cloned.Header = request.Header.Clone()
	cloned.Header.Set(key, value)
	return cloned
}

func traceIDFromTraceParent(value string) (string, bool) {
	parts := strings.Split(strings.TrimSpace(value), "-")
	if len(parts) != 4 {
		return "", false
	}
	if parts[0] != "00" {
		return "", false
	}
	if len(parts[1]) != 32 || len(parts[2]) != 16 || len(parts[3]) != 2 {
		return "", false
	}
	if _, err := hex.DecodeString(parts[1]); err != nil {
		return "", false
	}
	if _, err := hex.DecodeString(parts[2]); err != nil {
		return "", false
	}
	if _, err := hex.DecodeString(parts[3]); err != nil {
		return "", false
	}
	return parts[1], true
}

func formatTraceParent(traceID string, requestID string) string {
	return "00-" + traceID + "-" + requestID + "-01"
}

func newTraceID() string {
	return randomHex(16)
}

func newRequestID() string {
	// TODO: request_id uniqueness is probabilistic in this slice because it is
	// 		 derived from random bytes rather than a stronger uniqueness contract.
	return randomHex(8)
}

func randomHex(size int) string {
	bytes := make([]byte, size)
	if _, err := rand.Read(bytes); err != nil {
		panic(err)
	}
	return hex.EncodeToString(bytes)
}

func routeLabel(method string, path string) string {
	method = strings.TrimSpace(method)
	path = strings.TrimSpace(path)
	if path == "" {
		path = "/"
	}
	if method == "" {
		return path
	}
	return method + " " + path
}

func classifyInboundStatus(statusCode int) string {
	switch {
		case statusCode >= 200 && statusCode < 400:
			return "success"
		case statusCode >= 400 && statusCode < 500:
			return "client_error"
		default:
			return "server_error"
	}
}

func classifyDependencyStatus(response *http.Response, err error) string {
	if err != nil {
		if isTimeout(err) {
			return "timeout"
		}
		return "dependency_failure"
	}
	return classifyInboundStatus(response.StatusCode)
}

func isTimeout(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return true
	}
	var netError net.Error
	return errors.As(err, &netError) && netError.Timeout()
}

func emit(payload any) {
	data, err := json.Marshal(payload)
	if err != nil {
		return
	}
	log.Print(string(data))
}
