package admission

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"execution-substrate/es/admission/internal/reliablesubmit"
)

const operationalCorrelation = "es_operational_correlation_v1"

var errOperationalEvidence = errors.New("operational handoff evidence inconclusive")

func operationalFrame(b, value []byte) []byte {
	return append(binary.BigEndian.AppendUint32(b, uint32(len(value))), value...)
}

func operationalLocator(realm operationalRealm, job string) [32]byte {
	b := append([]byte("ESOHLOC1"), realm.installation[:]...)
	b = binary.BigEndian.AppendUint64(b, realm.epoch)
	b = append(b, realm.provider[:]...)
	b = append(b, realm.spki[:]...)
	b = operationalFrame(b, []byte(realm.host))
	b = binary.BigEndian.AppendUint16(b, realm.port)
	for _, value := range []string{realm.region, realm.datacenter, operationalNamespace, job} {
		b = operationalFrame(b, []byte(value))
	}
	b = append(b, realm.build[:]...)
	b = append(b, realm.template[:]...)
	return sha256.Sum256(b)
}

func operationalDigest(domain string, raw []byte) [32]byte {
	return sha256.Sum256(operationalFrame([]byte(domain), raw))
}

type operationalJSONReader struct{ privateJSONParser }

func parseOperationalJSON(raw []byte, limit int) (any, error) {
	if len(raw) == 0 || len(raw) > limit || !utf8.Valid(raw) {
		return nil, errOperationalEvidence
	}
	p := &operationalJSONReader{privateJSONParser{raw: raw}}
	result, err := p.read(1)
	p.space()
	if err != nil || p.offset != len(raw) {
		return nil, errOperationalEvidence
	}
	return result, nil
}

func (p *operationalJSONReader) take(ch byte) bool {
	p.space()
	if p.offset == len(p.raw) || p.raw[p.offset] != ch {
		return false
	}
	p.offset++
	return true
}

func (p *operationalJSONReader) read(depth int) (any, error) {
	p.space()
	if depth > 16 || p.nodes >= 8192 || p.offset >= len(p.raw) {
		return nil, errOperationalEvidence
	}
	p.nodes++
	switch p.raw[p.offset] {
	case '{':
		p.offset++
		result := map[string]any{}
		if p.take('}') {
			return result, nil
		}
		for {
			p.space()
			if p.offset >= len(p.raw) || p.raw[p.offset] != '"' || p.nodes >= 8192 {
				return nil, errOperationalEvidence
			}
			p.nodes++
			key, err := p.string()
			if _, duplicate := result[key]; err != nil || duplicate || len(key) > 65536 || !p.take(':') {
				return nil, errOperationalEvidence
			}
			value, err := p.read(depth + 1)
			if err != nil {
				return nil, err
			}
			result[key] = value
			if p.take('}') {
				return result, nil
			}
			if !p.take(',') {
				return nil, errOperationalEvidence
			}
		}
	case '[':
		p.offset++
		array := []any{}
		if p.take(']') {
			return array, nil
		}
		for {
			value, err := p.read(depth + 1)
			if err != nil {
				return nil, err
			}
			array = append(array, value)
			if p.take(']') {
				return array, nil
			}
			if !p.take(',') {
				return nil, errOperationalEvidence
			}
		}
	case '"':
		value, err := p.string()
		if err != nil || len(value) > 65536 {
			return nil, errOperationalEvidence
		}
		return value, nil
	case 't':
		if p.literal("true") {
			return true, nil
		}
	case 'f':
		if p.literal("false") {
			return false, nil
		}
	case 'n':
		if p.literal("null") {
			return nil, nil
		}
	default:
		start := p.offset
		if p.raw[p.offset] == '-' {
			p.offset++
		}
		if p.offset == len(p.raw) || p.raw[p.offset] < '0' || p.raw[p.offset] > '9' {
			return nil, errOperationalEvidence
		}
		positive, err := p.number()
		if err != nil || len(positive) > 20 {
			return nil, errOperationalEvidence
		}
		number := string(p.raw[start:p.offset])
		if number[0] == '-' {
			if _, err := strconv.ParseInt(number, 10, 64); err != nil || number == "-0" {
				return nil, errOperationalEvidence
			}
		} else if _, err := strconv.ParseUint(number, 10, 64); err != nil {
			return nil, errOperationalEvidence
		}
		return privateJSONNumber(number), nil
	}
	return nil, errOperationalEvidence
}

func appendOperationalJSONString(out []byte, s string) []byte {
	const hexDigits = "0123456789abcdef"
	out = append(out, '"')
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch c {
		case '"', '\\':
			out = append(out, '\\', c)
		case '\b':
			out = append(out, '\\', 'b')
		case '\f':
			out = append(out, '\\', 'f')
		case '\n':
			out = append(out, '\\', 'n')
		case '\r':
			out = append(out, '\\', 'r')
		case '\t':
			out = append(out, '\\', 't')
		default:
			if c < 32 {
				out = append(out, '\\', 'u', '0', '0', hexDigits[c>>4], hexDigits[c&15])
			} else {
				out = append(out, c)
			}
		}
	}
	return append(out, '"')
}

func appendOperationalJSON(out []byte, value any) []byte {
	switch v := value.(type) {
	case nil:
		return append(out, "null"...)
	case bool:
		return strconv.AppendBool(out, v)
	case string:
		return appendOperationalJSONString(out, v)
	case privateJSONNumber:
		return append(out, string(v)...)
	case []any:
		out = append(out, '[')
		for i, elem := range v {
			if i > 0 {
				out = append(out, ',')
			}
			out = appendOperationalJSON(out, elem)
		}
		return append(out, ']')
	case map[string]any:
		keys := make([]string, 0, len(v))
		for k := range v {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		out = append(out, '{')
		for i, k := range keys {
			if i > 0 {
				out = append(out, ',')
			}
			out = appendOperationalJSONString(out, k)
			out = appendOperationalJSON(append(out, ':'), v[k])
		}
		return append(out, '}')
	default:
		panic("operational JSON must be parsed before canonical rendering")
	}
}

func operationalPointer(path, step string) string {
	return path + "/" + strings.ReplaceAll(strings.ReplaceAll(step, "~", "~0"), "/", "~1")
}

func operationalWholeLeaf(path string) bool {
	switch path {
	case "/Meta", "/Datacenters", "/TaskGroups/0/Tasks/0/Env",
		"/TaskGroups/0/Tasks/0/Config/args", "/TaskGroups/0/Tasks/0/Config/mounts",
		"/TaskGroups/0/Tasks/0/Config/security_opt":
		return true
	default:
		return false
	}
}

func operationalLiteral(value any) bool {
	switch v := value.(type) {
	case []any:
		for _, x := range v {
			if !operationalLiteral(x) {
				return false
			}
		}
	case map[string]any:
		for k, x := range v {
			if strings.Contains(k, "$") || !operationalLiteral(x) {
				return false
			}
		}
	}
	return true
}

func renderOperationalTemplate(template, job any, path string) (any, error) {
	if !operationalWholeLeaf(path) {
		switch source := job.(type) {
		case []any:
			items, ok := template.([]any)
			if !ok || len(items) != len(source) {
				return nil, errOperationalEvidence
			}
			out := make([]any, len(items))
			for i := range items {
				v, err := renderOperationalTemplate(items[i], source[i], operationalPointer(path, strconv.Itoa(i)))
				if err != nil {
					return nil, err
				}
				out[i] = v
			}
			return out, nil
		case map[string]any:
			obj, ok := template.(map[string]any)
			if !ok {
				return nil, errOperationalEvidence
			}
			out := make(map[string]any, len(obj))
			for k, v := range obj {
				if strings.Contains(k, "$") {
					return nil, errOperationalEvidence
				}
				if _, ok := source[k]; !ok {
					if !operationalLiteral(v) {
						return nil, errOperationalEvidence
					}
					out[k] = v
				}
			}
			for k, v := range source {
				placement, ok := obj[k]
				if !ok {
					return nil, errOperationalEvidence
				}
				rendered, err := renderOperationalTemplate(placement, v, operationalPointer(path, k))
				if err != nil {
					return nil, err
				}
				out[k] = rendered
			}
			return out, nil
		}
	}
	slot, ok := template.(map[string]any)
	if !ok || len(slot) != 1 || slot["$job0"] != path {
		return nil, errOperationalEvidence
	}
	return job, nil
}

type operationalProvider struct {
	privateExecutionValue
	realm    operationalRealm
	target   netip.AddrPort
	roots    *x509.CertPool
	template any
	// token is ES's Nomad ACL client token, from the same startup custody as
	// the ordinary client's (nomad.token_file, loadNomadToken). prepareExchange
	// sets it on every request, in the header only.
	token         string
	exchangeEntry func(string) // Nil except for instance-scoped transport-entry proof.
}

func newOperationalLoopbackProvider(realm operationalRealm, target netip.AddrPort, roots *x509.CertPool, template []byte, token string) (*operationalProvider, error) {
	if !target.Addr().IsLoopback() || target.Port() != realm.port || roots == nil || realm.host == "" || realm.spki == [32]byte{} {
		return nil, errOperationalEvidence
	}
	if parsed, ok := parseNomadTokenFileContent([]byte(token)); !ok || parsed != token {
		return nil, errOperationalEvidence
	}
	t, err := parseOperationalJSON(template, 65536)
	if err != nil || operationalDigest("ESOHJTPL1", appendOperationalJSON(nil, t)) != realm.template {
		return nil, errOperationalEvidence
	}
	if _, ok := t.(map[string]any); !ok {
		return nil, errOperationalEvidence
	}
	return &operationalProvider{realm: realm, target: target, roots: roots.Clone(), template: t, token: token}, nil
}

type operationalJob struct {
	privateExecutionValue
	name             string
	job              map[string]any
	project, locator [32]byte
	expected         []byte
}

// operationalJobLimit bounds Job0 as Go's encoding/json writes it, with each
// '<', '>', '&' and control byte as a six-byte escape. That form is at least as
// long as the one Nomad's API writes when it returns the job (Nomad writes
// HTML characters as they are), so the expanded job that GET Job returns stays
// well within its own bound. operationalBodyLimit bounds the canonical
// complete POST body, which is what ES sends.
const (
	operationalJobLimit  = 65536
	operationalBodyLimit = 131072
)

func (p *operationalProvider) project(run resolvedRunProjection, name string) (operationalJob, error) {
	nomad := run.nomadJobProjection(nil)
	nomad.jobID = name
	job := buildNomadJobSpec(nomad)["Job"].(map[string]any)
	job["Region"], job["Namespace"], job["Priority"] = p.realm.region, operationalNamespace, 50
	raw, err := json.Marshal(job)
	if err != nil {
		return operationalJob{}, errOperationalEvidence
	}
	parsed, err := parseOperationalJSON(raw, operationalJobLimit)
	if err != nil {
		return operationalJob{}, err
	}
	closed := parsed.(map[string]any)
	normalized, err := renderOperationalTemplate(p.template, closed, "")
	if err != nil {
		return operationalJob{}, err
	}
	match := appendOperationalJSON(nil, normalized)
	identity := operationalLocator(p.realm, name)
	domain := append([]byte("ESOHJOB1"), identity[:]...)
	digest := sha256.Sum256(operationalFrame(domain, appendOperationalJSON(nil, closed)))
	return operationalJob{name: name, job: closed, project: digest, locator: identity, expected: match}, nil
}

func (j operationalJob) carrier(key [32]byte, p reliablesubmit.OperationalProjection) string {
	_, _, _, marker, _ := p.Bindings()
	return j.carrierForMarker(key, p, marker)
}

func (j operationalJob) carrierForMarker(key [32]byte, p reliablesubmit.OperationalProjection, marker [32]byte) string {
	original, _, stage, _, _ := p.Bindings()
	run, _, _ := p.Locator()
	mac := hmac.New(sha256.New, key[:])
	b := append([]byte("ESOHCOR1"), original[:]...)
	b = operationalFrame(b, []byte(run))
	b = append(b, stage[:]...)
	b = append(b, marker[:]...)
	b = append(b, j.project[:]...)
	b = append(b, j.locator[:]...)
	_, _ = mac.Write(b)
	return hex.EncodeToString(mac.Sum(nil))
}

func (j operationalJob) request(carrier string) ([]byte, error) {
	closed := make(map[string]any, len(j.job))
	for k, v := range j.job {
		closed[k] = v
	}
	meta := make(map[string]any)
	for k, v := range j.job["Meta"].(map[string]any) {
		meta[k] = v
	}
	meta[operationalCorrelation] = carrier
	closed["Meta"] = meta
	body := appendOperationalJSON(nil, map[string]any{"Job": closed, "EnforceIndex": true, "JobModifyIndex": privateJSONNumber("0")})
	if len(body) > operationalBodyLimit {
		return nil, errOperationalEvidence
	}
	return body, nil
}

// fits reports whether the job of this resolution can be projected and sent
// once a run is assigned: Job0 and the canonical complete POST body stay
// within their bounds. It projects the job with a stage, a job name
// and a correlation value of the real lengths, so it is asked before the claim
// is stored, and a request that does not fit takes no claim and no
// reservation.
func (p *operationalProvider) fits(resolved resolvedExecution) bool {
	stage, name := reliablesubmit.OperationalLocatorShape()
	job, err := p.project(newResolvedRunProjection(resolved.plan, resolved.host, executionLocator{RunID: stage, jobID: name}), name)
	if err != nil {
		return false
	}
	// The correlation value is the hex HMAC-SHA256 that carrierForMarker writes.
	_, err = job.request(strings.Repeat("0", 2*sha256.Size))
	return err == nil
}

type operationalResponse struct {
	value  any
	index  uint64
	status int
}

type preparedOperationalExchange struct {
	request   *http.Request
	transport *http.Transport
	cancel    context.CancelFunc
}

// prepareRegister prepares the one registration request, POST /v1/jobs.
func (p *operationalProvider) prepareRegister(ctx context.Context, body []byte) (preparedOperationalExchange, error) {
	return p.prepareExchange(ctx, http.MethodPost, "/v1/jobs", body)
}

// prepareExchange builds every request the provider sends to Nomad. Each one
// carries ES's Nomad token in the X-Nomad-Token header, never in the URL, and
// names the operational region and namespace. The transport follows no
// redirect, so the token reaches only the pinned Nomad. Like ES's ordinary
// Nomad client (newNomadTLSConfig), it speaks TLS 1.3 only, the one version
// the supported Nomad serves.
func (p *operationalProvider) prepareExchange(ctx context.Context, method, path string, body []byte) (preparedOperationalExchange, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	query := "region=" + p.realm.region + "&namespace=" + operationalNamespace
	u := url.URL{Scheme: "https", Host: net.JoinHostPort(p.realm.host, strconv.Itoa(int(p.realm.port))), Path: path, RawQuery: query}
	var reader io.Reader
	if body != nil {
		reader = io.NopCloser(bytes.NewReader(body))
	}
	req, err := http.NewRequestWithContext(ctx, method, u.String(), reader)
	if err != nil {
		cancel()
		return preparedOperationalExchange{}, errOperationalEvidence
	}
	req.Close = true
	req.Header.Set(nomadTokenHeader, p.token)
	req.Header.Set("Accept-Encoding", "identity")
	if body != nil {
		req.ContentLength = int64(len(body))
		req.Header.Set("Content-Type", "application/json")
	}
	dialer := net.Dialer{Timeout: time.Second}
	transport := &http.Transport{
		DisableKeepAlives: true, DisableCompression: true, MaxResponseHeaderBytes: 16384, TLSHandshakeTimeout: 2 * time.Second,
		TLSNextProto: map[string]func(string, *tls.Conn) http.RoundTripper{},
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			if network != "tcp" || addr != u.Host {
				return nil, errOperationalEvidence
			}
			return dialer.DialContext(ctx, "tcp", p.target.String())
		},
		TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13, ServerName: p.realm.host, RootCAs: p.roots,
			VerifyConnection: func(state tls.ConnectionState) error {
				if len(state.VerifiedChains) == 0 || len(state.PeerCertificates) == 0 || sha256.Sum256(state.PeerCertificates[0].RawSubjectPublicKeyInfo) != p.realm.spki {
					return errOperationalEvidence
				}
				return nil
			}},
	}
	return preparedOperationalExchange{request: req, transport: transport, cancel: cancel}, nil
}

func (p *operationalProvider) exchange(prepared preparedOperationalExchange, limit int) (operationalResponse, reliablesubmit.OperationalReason) {
	if p.exchangeEntry != nil {
		p.exchangeEntry(prepared.request.Method)
	}
	r, err := prepared.transport.RoundTrip(prepared.request)
	defer prepared.transport.CloseIdleConnections()
	if err != nil {
		return operationalResponse{}, operationalExchangeFailure(err)
	}
	defer r.Body.Close()
	if r.StatusCode != http.StatusOK {
		return operationalResponse{status: r.StatusCode}, reliablesubmit.OperationalHTTPRefusal
	}
	if !operationalJSONHeaders(r.Header) {
		return operationalResponse{}, reliablesubmit.OperationalMalformed
	}
	index, ok := operationalHeaderIndex(r.Header)
	if !ok {
		return operationalResponse{}, reliablesubmit.OperationalContinuity
	}
	if prepared.request.Method == http.MethodGet && (!operationalSingleHeader(r.Header, "X-Nomad-KnownLeader", "true") ||
		!operationalSingleHeader(r.Header, "X-Nomad-LastContact", "0") || len(r.Header.Values("X-Nomad-NextToken")) != 0) {
		return operationalResponse{}, reliablesubmit.OperationalContinuity
	}
	raw, err := io.ReadAll(io.LimitReader(r.Body, int64(limit)+1))
	if err != nil {
		return operationalResponse{}, operationalExchangeFailure(err)
	}
	decoded, err := parseOperationalJSON(raw, limit)
	if err != nil {
		return operationalResponse{}, reliablesubmit.OperationalMalformed
	}
	return operationalResponse{value: decoded, index: index}, reliablesubmit.OperationalReasonNone
}

func operationalExchangeFailure(err error) reliablesubmit.OperationalReason {
	var timeout net.Error
	switch {
	case errors.Is(err, context.Canceled):
		return reliablesubmit.OperationalCanceled
	case errors.Is(err, context.DeadlineExceeded), errors.As(err, &timeout) && timeout.Timeout():
		return reliablesubmit.OperationalTimeout
	case errors.Is(err, errOperationalEvidence):
		return reliablesubmit.OperationalContinuity
	default:
		return reliablesubmit.OperationalIO
	}
}

func operationalSingleHeader(h http.Header, name, value string) bool {
	v := h.Values(name)
	return len(v) == 1 && v[0] == value
}

func operationalJSONHeaders(h http.Header) bool {
	content := h.Values("Content-Type")
	if len(content) != 1 {
		return false
	}
	typ, params, err := mime.ParseMediaType(content[0])
	return err == nil && typ == "application/json" &&
		(len(params) == 0 || len(params) == 1 && strings.EqualFold(params["charset"], "utf-8")) &&
		(len(h.Values("Content-Encoding")) == 0 || operationalSingleHeader(h, "Content-Encoding", "identity"))
}

func operationalHeaderIndex(h http.Header) (uint64, bool) {
	values := h.Values("X-Nomad-Index")
	if len(values) != 1 {
		return 0, false
	}
	n, err := strconv.ParseUint(values[0], 10, 64)
	return n, err == nil && n != 0 && strconv.FormatUint(n, 10) == values[0]
}

func operationalUint(value any) (uint64, bool) {
	n, ok := value.(privateJSONNumber)
	if !ok {
		return 0, false
	}
	k, err := strconv.ParseUint(string(n), 10, 64)
	return k, err == nil
}

func operationalEvalID(value any) ([16]byte, bool) {
	var id [16]byte
	s, ok := value.(string)
	if !ok || len(s) != 36 || s != strings.ToLower(s) || s[8] != '-' || s[13] != '-' || s[18] != '-' || s[23] != '-' {
		return id, false
	}
	n, err := hex.Decode(id[:], []byte(strings.ReplaceAll(s, "-", "")))
	return id, err == nil && n == 16 && id != [16]byte{}
}

type operationalAck struct {
	index      uint64
	evaluation [16]byte
	collision  bool
	refused    bool
	reason     reliablesubmit.OperationalReason
}

func (p *operationalProvider) register(prepared preparedOperationalExchange) operationalAck {
	result, reason := p.exchange(prepared, 16384)
	if result.status == http.StatusConflict {
		return operationalAck{collision: true, reason: reason}
	}
	if reason != reliablesubmit.OperationalReasonNone {
		return operationalAck{reason: reason}
	}
	object, ok := result.value.(map[string]any)
	if !ok || len(object) != 8 {
		return operationalAck{reason: reliablesubmit.OperationalMalformed}
	}
	id, ok := operationalEvalID(object["EvalID"])
	index, i := operationalUint(object["Index"])
	job, j := operationalUint(object["JobModifyIndex"])
	eval, e := operationalUint(object["EvalCreateIndex"])
	contact, c := operationalUint(object["LastContact"])
	if !ok || !i || !j || !e || !c || contact != 0 || index == 0 || index != job || index != eval || index != result.index ||
		object["Warnings"] != "" || object["NextToken"] != "" || object["KnownLeader"] != false {
		return operationalAck{reason: reliablesubmit.OperationalContinuity}
	}
	return operationalAck{index: index, evaluation: id}
}

type verifiedOperationalObservation struct {
	privateExecutionValue
	self       *verifiedOperationalObservation
	issuer     *operationalProvider
	binding    operationalDispatchBinding
	intent     [32]byte
	index      uint64
	evaluation [16]byte
}

func (p *operationalProvider) observe(ctx context.Context, j operationalJob, projection reliablesubmit.OperationalProjection, key [32]byte, ack operationalAck) (*verifiedOperationalObservation, reliablesubmit.OperationalReason) {
	original, intent, stamp, marker, _ := projection.Bindings()
	run, jobID, ok := projection.Locator()
	if !ok || projection.Revision() != 5 || jobID != j.name || j.locator != operationalLocator(p.realm, j.name) {
		return nil, reliablesubmit.OperationalIntegrity
	}
	carrier := j.carrier(key, projection)
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	request, err := p.prepareExchange(ctx, http.MethodGet, "/v1/job/"+j.name, nil)
	if err != nil {
		return nil, reliablesubmit.OperationalUnavailable
	}
	defer request.cancel()
	resp, reason := p.exchange(request, 262144)
	if reason != reliablesubmit.OperationalReasonNone {
		return nil, reason
	}
	job, ok := resp.value.(map[string]any)
	if !ok {
		return nil, reliablesubmit.OperationalMalformed
	}
	registration, ok := operationalUint(job["CreateIndex"])
	modified, m := operationalUint(job["ModifyIndex"])
	spec, s := operationalUint(job["JobModifyIndex"])
	version, v := operationalUint(job["Version"])
	submitted, u := operationalUint(job["SubmitTime"])
	desc, d := job["StatusDescription"].(string)
	_, stable := job["Stable"].(bool)
	status := job["Status"]
	meta, metadata := job["Meta"].(map[string]any)
	tag, tagged := meta[operationalCorrelation].(string)
	if !ok || !m || !s || !v || !u || !d || !stable || !metadata || !tagged || !hmac.Equal([]byte(tag), []byte(carrier)) ||
		registration == 0 || spec != registration || modified < spec || resp.index != modified || version != 0 ||
		submitted == 0 || submitted > 1<<63-1 || len(desc) > 4096 || (status != "pending" && status != "running" && status != "dead") {
		return nil, reliablesubmit.OperationalContinuity
	}
	for _, key := range []string{"CreateIndex", "JobModifyIndex", "ModifyIndex", "Version", "Status", "StatusDescription", "Stable", "SubmitTime"} {
		delete(job, key)
	}
	delete(meta, operationalCorrelation)
	if !hmac.Equal(appendOperationalJSON(nil, job), j.expected) {
		return nil, reliablesubmit.OperationalContinuity
	}
	evalRequest, err := p.prepareExchange(ctx, http.MethodGet, "/v1/job/"+j.name+"/evaluations", nil)
	if err != nil {
		return nil, reliablesubmit.OperationalUnavailable
	}
	defer evalRequest.cancel()
	evals, reason := p.exchange(evalRequest, 262144)
	if reason != reliablesubmit.OperationalReasonNone {
		return nil, reason
	}
	list, ok := evals.value.([]any)
	if !ok || len(list) > 64 {
		return nil, reliablesubmit.OperationalMalformed
	}
	if len(list) == 0 {
		return nil, reliablesubmit.OperationalInconclusive
	}
	if evals.index < registration {
		return nil, reliablesubmit.OperationalContinuity
	}
	found := operationalAck{}
	seen := map[[16]byte]bool{}
	for _, v := range list {
		object, ok := v.(map[string]any)
		id, idOK := operationalEvalID(object["ID"])
		trigger, t := object["TriggeredBy"].(string)
		priority, q := operationalUint(object["Priority"])
		created, c := operationalUint(object["CreateIndex"])
		modified, m := operationalUint(object["ModifyIndex"])
		spec, s := operationalUint(object["JobModifyIndex"])
		if !ok || !idOK || seen[id] || !t || len(trigger) == 0 || len(trigger) > 64 || !q || priority > 100 ||
			!c || !m || !s || created == 0 || spec == 0 || modified < created || modified > evals.index ||
			object["JobID"] != j.name || object["Namespace"] != operationalNamespace || object["Type"] != "batch" {
			return nil, reliablesubmit.OperationalContinuity
		}
		for i := range trigger {
			if trigger[i] > 127 || trigger[i] < 32 {
				return nil, reliablesubmit.OperationalMalformed
			}
		}
		seen[id] = true
		if trigger == "job-register" {
			if found.index != 0 || priority != 50 || created != registration || spec != registration {
				return nil, reliablesubmit.OperationalContinuity
			}
			found = operationalAck{index: registration, evaluation: id}
		}
	}
	if found.index == 0 {
		return nil, reliablesubmit.OperationalInconclusive
	}
	if ack.index != 0 && (found.index != ack.index || found.evaluation != ack.evaluation) {
		return nil, reliablesubmit.OperationalContinuity
	}
	verified := &verifiedOperationalObservation{
		issuer: p, intent: intent, index: found.index, evaluation: found.evaluation,
		binding: operationalDispatchBinding{original: original, run: run, stamp: stamp, marker: marker,
			project: j.project, locator: j.locator},
	}
	verified.self = verified
	return verified, reliablesubmit.OperationalReasonNone
}

func (v *verifiedOperationalObservation) bindOperationalObservation(p *operationalProvider, a *reliablesubmit.OperationalAccess,
	projection reliablesubmit.OperationalProjection, job operationalJob, key [32]byte) (*reliablesubmit.OperationalPositiveProof, error) {
	original, intent, stamp, marker, _ := projection.Bindings()
	run, jobID, ok := projection.Locator()
	binding := operationalDispatchBinding{original: original, run: run, stamp: stamp, marker: marker,
		project: job.project, locator: job.locator}
	if v == nil || v.self != v || v.issuer != p || !ok || job.name != jobID || v.binding != binding || v.intent != intent {
		return nil, errOperationalEvidence
	}
	preimage := operationalFrame(bytes.Clone(original[:]), []byte(run))
	for _, value := range [][32]byte{stamp, marker, job.project, job.locator} {
		preimage = append(preimage, value[:]...)
	}
	preimage = binary.BigEndian.AppendUint64(preimage, v.index)
	preimage = append(preimage, v.evaluation[:]...)
	mac := hmac.New(sha256.New, key[:])
	_, _ = mac.Write([]byte("ESOHEVD1"))
	_, _ = mac.Write(preimage)
	var witness [32]byte
	copy(witness[:], mac.Sum(nil))
	return a.BindVerifiedOperationalObservation(projection, job.project, job.locator, preimage, witness)
}
