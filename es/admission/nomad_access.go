package admission

import (
	"context"
	"crypto/subtle"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"

	"golang.org/x/sys/unix"
)

// Nomad access control (ACL) contract for the current submit path.
//
// ES authenticates every Nomad request with one ACL client token whose policy
// grants only submit-job, read-job and read-logs in nomadSubmitNamespace.
// Before each submission ES checks that Nomad enforces access control: Nomad
// must resolve ES's token as a client token, and Nomad must hold no policy
// for anonymous requests. Nomad's own ACL enforcement is what keeps other
// local callers out; the check makes ES refuse to submit on a Nomad that would
// also accept jobs from them.
const (
	// nomadSubmitNamespace is the only Nomad namespace that the current submit
	// path registers, reads, logs and stops jobs in.
	nomadSubmitNamespace = "es-submit-v1"
	nomadTokenHeader     = "X-Nomad-Token"
	// nomadAnonymousPolicyName is the policy Nomad applies to requests that
	// carry no token. Its absence means anonymous requests hold no capability.
	nomadAnonymousPolicyName = "anonymous"
	nomadTokenSecretIDBytes  = 36
	// nomadAccessControlCheckFailedMessage is the fixed public message for
	// every refused access-control check. It names no cause.
	nomadAccessControlCheckFailedMessage = "execution runtime access control check failed"
)

// loadNomadToken reads ES's Nomad ACL client token from path with the same
// custody rules as the retained-result key: the parent directory belongs to
// ES's effective user or root and is not group- or world-writable, and the
// file is a regular file with one link, owned by ES's effective user, mode
// 0400 or 0600. Its content is one canonical lower-case UUID (Nomad's SecretID
// form), optionally followed by one line feed. No error names the token.
func loadNomadToken(tokenPath string) (string, error) {
	if tokenPath == "" || !filepath.IsAbs(tokenPath) || filepath.Clean(tokenPath) != tokenPath {
		return "", fmt.Errorf("nomad token file must be a clean absolute path")
	}
	parent, err := openQualifiedDirectoryExact(filepath.Dir(tokenPath))
	if err != nil {
		return "", fmt.Errorf("nomad token file is unavailable")
	}
	defer parent.close()
	parentIdentity := parent.identity
	if !custodyIdentityIsDirectory(parentIdentity) ||
		(parentIdentity.UID != os.Geteuid() && parentIdentity.UID != 0) ||
		os.FileMode(parentIdentity.Mode).Perm()&0o022 != 0 {
		return "", fmt.Errorf("nomad token file parent is unsafe")
	}
	name := filepath.Base(tokenPath)
	var visible unix.Stat_t
	if err := unix.Fstatat(parent.fd, name, &visible, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return "", fmt.Errorf("nomad token file is unavailable")
	}
	if err := validateNomadTokenFileStat(visible); err != nil {
		return "", err
	}
	fd, err := platformOpenAtNoFollow(parent.fd, name, unix.O_RDONLY, 0, false)
	if err != nil {
		return "", fmt.Errorf("nomad token file is unavailable")
	}
	file := os.NewFile(uintptr(fd), "nomad token file")
	if file == nil {
		_ = unix.Close(fd)
		return "", fmt.Errorf("nomad token file is unavailable")
	}
	defer file.Close()
	var before unix.Stat_t
	if err := unix.Fstat(fd, &before); err != nil ||
		!sameCustodyObject(custodyIdentityFromStat(visible), custodyIdentityFromStat(before)) {
		return "", fmt.Errorf("nomad token file changed during opening")
	}
	if err := validateNomadTokenFileStat(before); err != nil {
		return "", err
	}
	data, err := io.ReadAll(io.LimitReader(file, nomadTokenSecretIDBytes+2))
	if err != nil {
		return "", fmt.Errorf("nomad token file is unavailable")
	}
	var after unix.Stat_t
	if err := unix.Fstat(fd, &after); err != nil || !platformStatSnapshotStable(before, after) {
		return "", fmt.Errorf("nomad token file changed during reading")
	}
	var afterVisible unix.Stat_t
	if err := unix.Fstatat(parent.fd, name, &afterVisible, unix.AT_SYMLINK_NOFOLLOW); err != nil ||
		!sameCustodyObject(custodyIdentityFromStat(before), custodyIdentityFromStat(afterVisible)) ||
		parent.verifyVisible() != nil {
		return "", fmt.Errorf("nomad token file path changed during reading")
	}
	token, ok := parseNomadTokenFileContent(data)
	if !ok {
		return "", fmt.Errorf("nomad token file must contain exactly one Nomad ACL token secret ID")
	}
	return token, nil
}

func validateNomadTokenFileStat(st unix.Stat_t) error {
	identity := custodyIdentityFromStat(st)
	mode := os.FileMode(identity.Mode).Perm()
	if !custodyIdentityIsRegular(identity) || identity.Links != 1 || identity.UID != os.Geteuid() ||
		(mode != 0o400 && mode != 0o600) ||
		(st.Size != nomadTokenSecretIDBytes && st.Size != nomadTokenSecretIDBytes+1) {
		return fmt.Errorf("nomad token file has unsafe identity, access or length")
	}
	return nil
}

// parseNomadTokenFileContent accepts exactly a canonical lower-case UUID,
// 8-4-4-4-12 hexadecimal digits, optionally followed by one line feed.
func parseNomadTokenFileContent(data []byte) (string, bool) {
	if len(data) == nomadTokenSecretIDBytes+1 {
		if data[nomadTokenSecretIDBytes] != '\n' {
			return "", false
		}
		data = data[:nomadTokenSecretIDBytes]
	}
	if len(data) != nomadTokenSecretIDBytes {
		return "", false
	}
	for i, b := range data {
		switch i {
		case 8, 13, 18, 23:
			if b != '-' {
				return "", false
			}
		default:
			if (b < '0' || b > '9') && (b < 'a' || b > 'f') {
				return "", false
			}
		}
	}
	return string(data), true
}

// newJobRequest builds an authenticated request for a Nomad job, allocation
// or client endpoint, scoped to nomadSubmitNamespace.
func (c *nomadClient) newJobRequest(ctx context.Context, method string, requestPath string, query url.Values, body io.Reader) (*http.Request, error) {
	values := url.Values{}
	for key, entries := range query {
		values[key] = append([]string(nil), entries...)
	}
	values.Set("namespace", nomadSubmitNamespace)
	requestURL := c.baseURL.ResolveReference(&url.URL{Path: path.Clean(requestPath), RawQuery: values.Encode()})
	request, err := http.NewRequestWithContext(ctx, method, requestURL.String(), body)
	if err != nil {
		return nil, err
	}
	request.Header.Set(nomadTokenHeader, c.token)
	return request, nil
}

type nomadACLTokenSelf struct {
	AccessorID string `json:"AccessorID"`
	SecretID   string `json:"SecretID"`
	Type       string `json:"Type"`
}

// verifyAccessControl is the check before every submission. It refuses
// unless (1) Nomad resolves ES's token to itself as a client token, which
// fails when Nomad's ACL system is disabled (Nomad then answers with a
// placeholder token that does not carry ES's secret) and when Nomad does not
// know the token, and (2) Nomad holds no anonymous policy, so a request
// without a token holds no capability in any namespace.
func (c *nomadClient) verifyAccessControl(ctx context.Context) *Error {
	selfURL := c.baseURL.ResolveReference(&url.URL{Path: "/v1/acl/token/self"})
	selfRequest, err := http.NewRequestWithContext(ctx, http.MethodGet, selfURL.String(), nil)
	if err != nil {
		return nomadUnavailableError("execution runtime is unavailable")
	}
	selfRequest.Header.Set(nomadTokenHeader, c.token)
	selfResponse, err := c.client.Do(selfRequest)
	if err != nil {
		return nomadUnavailableError("execution runtime is unavailable")
	}
	var self nomadACLTokenSelf
	selfOK := selfResponse.StatusCode == http.StatusOK &&
		decodeBoundedCompatibleJSONDocumentResponse(selfResponse, &self) == nil
	_ = selfResponse.Body.Close()
	if !selfOK || len(self.SecretID) != len(c.token) ||
		subtle.ConstantTimeCompare([]byte(self.SecretID), []byte(c.token)) != 1 ||
		self.Type != "client" || self.AccessorID == "" {
		return nomadUnavailableError(nomadAccessControlCheckFailedMessage)
	}

	anonymousURL := c.baseURL.ResolveReference(&url.URL{Path: "/v1/acl/policy/" + nomadAnonymousPolicyName})
	anonymousRequest, err := http.NewRequestWithContext(ctx, http.MethodGet, anonymousURL.String(), nil)
	if err != nil {
		return nomadUnavailableError("execution runtime is unavailable")
	}
	anonymousResponse, err := c.client.Do(anonymousRequest)
	if err != nil {
		return nomadUnavailableError("execution runtime is unavailable")
	}
	anonymousStatus := anonymousResponse.StatusCode
	_ = anonymousResponse.Body.Close()
	if anonymousStatus != http.StatusNotFound {
		return nomadUnavailableError(nomadAccessControlCheckFailedMessage)
	}
	return nil
}
