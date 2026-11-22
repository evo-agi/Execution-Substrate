package admissionstate

import (
	"encoding/hex"
	"reflect"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
	"unsafe"

	egsmodel "execution-substrate/egs/model"
	"execution-substrate/es/admission/internal/reliablesubmit"
)

// The tests in this file need no admission token. A token that names a realm
// and a digest comes only from the store, so installing, confirming equal
// content and the refusals of Install are tested with real tokens in the
// package es/admission (TestOperationalAdmissionState and the tests of the
// handoff). Where a view is needed here, the test writes one into the state
// directly, with the zero token.

const (
	selectedPolicy   = "execution-substrate.admission.selected-destructive-shell-command/v1"
	configuredPolicy = "execution-substrate.admission.configured-static-script-literal-deny/v1"
	goldenArtifact   = "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
)

func goldenTrust() egsmodel.RuntimeTrustPolicy {
	return egsmodel.RuntimeTrustPolicy{
		SignerPolicy:   egsmodel.SignerPolicy{AllowedSigners: []string{"signer-a", "signer-b"}, RevokedSigners: []string{"signer-c"}},
		ArtifactPolicy: egsmodel.ArtifactPolicy{RevokedArtifacts: []string{goldenArtifact}},
	}
}

func goldenKey() []byte {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i + 1)
	}
	return key
}

func goldenContent() Content {
	return Content{
		Trust:    goldenTrust(),
		Verifier: Verifier{Algorithm: "ed25519", KeyID: "key-1", PublicKey: goldenKey()},
		Policies: []Policy{
			{ID: selectedPolicy},
			{ID: configuredPolicy, Entries: []PolicyEntry{{ID: "rule-1", Literal: "rm -rf /"}, {ID: "rule-2", Literal: "curl | sh"}}},
		},
	}
}

// The digest decides whether a restarted process joins the stored generation.
// It moved into this package from es/admission. These values were computed by
// the function it replaces, at the last audited commit, over the same inputs:
// a database written before the move is joined by a process built after it.
func TestDigestGoldenVectors(t *testing.T) {
	selected := goldenContent()
	selected.Policies = selected.Policies[:1]
	emptyTrust := Content{Verifier: Verifier{Algorithm: "ed25519", KeyID: "k", PublicKey: []byte(strings.Repeat("\xaa", 32))},
		Policies: []Policy{{ID: selectedPolicy}}}
	unordered := goldenContent()
	unordered.Trust.SignerPolicy.AllowedSigners = []string{"signer-b", "signer-a"}
	oneEntry := Content{Trust: goldenTrust(), Verifier: Verifier{Algorithm: "other"},
		Policies: []Policy{{ID: selectedPolicy}, {ID: configuredPolicy, Entries: []PolicyEntry{{ID: "", Literal: "x"}}}}}
	for _, tc := range []struct {
		name    string
		content Content
		want    string
	}{
		{"selected policy only", selected, "04560e9588865c202225325b34080e433ee6c9c840133499d783313c62d57f7d"},
		{"selected and configured", goldenContent(), "b6e2de007cf008905d2855b504dd14ba697b300643b0096a966c17c18c9a0c48"},
		{"empty trust lists", emptyTrust, "53a78a6d7da3b8e179dbf0bed9d6dff31f83aec583ff9236fb93a0617d4df1df"},
		// The trust lists are hashed in their canonical order.
		{"lists in another order", unordered, "b6e2de007cf008905d2855b504dd14ba697b300643b0096a966c17c18c9a0c48"},
		{"empty key id, no key, one entry with an empty id", oneEntry, "57d39c018abed4fff845c4c06cc8d91b5c41b3358e0f26f871a9c125af939578"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := Digest(tc.content)
			if !ok || hex.EncodeToString(got[:]) != tc.want {
				t.Fatalf("digest=%x ok=%t, want %s", got, ok, tc.want)
			}
		})
	}
	t.Run("content without a digest", func(t *testing.T) {
		none := goldenContent()
		none.Policies = nil
		empty := goldenContent()
		empty.Policies = []Policy{}
		repeated := goldenContent()
		repeated.Trust.SignerPolicy.AllowedSigners = []string{"signer-a", "signer-a"}
		unlabeled := goldenContent()
		unlabeled.Trust.ArtifactPolicy.RevokedArtifacts = []string{"0123"}
		for name, content := range map[string]Content{"no policy list": none, "empty policy list": empty,
			"trust with a repeated signer": repeated, "trust with an unlabeled artifact": unlabeled} {
			if got, ok := Digest(content); ok || got != [32]byte{} {
				t.Fatalf("%s: digest=%x ok=%t", name, got, ok)
			}
		}
	})
}

// Every field of the content reaches the digest: a change of one field alone
// changes it. A digest that left a field out would let a process with other
// content join the stored generation.
func TestDigestCoversEveryField(t *testing.T) {
	base, ok := Digest(goldenContent())
	if !ok {
		t.Fatal("control: the base content has no digest")
	}
	for name, change := range map[string]func(*Content){
		"allowed signer": func(c *Content) { c.Trust.SignerPolicy.AllowedSigners[0] = "signer-z" },
		"allowed signer more": func(c *Content) {
			c.Trust.SignerPolicy.AllowedSigners = append(c.Trust.SignerPolicy.AllowedSigners, "x")
		},
		"revoked signer":      func(c *Content) { c.Trust.SignerPolicy.RevokedSigners[0] = "signer-z" },
		"revoked signer gone": func(c *Content) { c.Trust.SignerPolicy.RevokedSigners = nil },
		"revoked artifact": func(c *Content) {
			c.Trust.ArtifactPolicy.RevokedArtifacts[0] = "sha256:" + strings.Repeat("f", 64)
		},
		"revoked artifact gone":   func(c *Content) { c.Trust.ArtifactPolicy.RevokedArtifacts = nil },
		"verifier algorithm":      func(c *Content) { c.Verifier.Algorithm = "ed448" },
		"verifier key id":         func(c *Content) { c.Verifier.KeyID = "key-2" },
		"verifier key byte":       func(c *Content) { c.Verifier.PublicKey[31] ^= 1 },
		"verifier key shorter":    func(c *Content) { c.Verifier.PublicKey = c.Verifier.PublicKey[:31] },
		"policy id":               func(c *Content) { c.Policies[0].ID += "x" },
		"policy removed":          func(c *Content) { c.Policies = c.Policies[:1] },
		"policies in other order": func(c *Content) { c.Policies[0], c.Policies[1] = c.Policies[1], c.Policies[0] },
		"entry id":                func(c *Content) { c.Policies[1].Entries[0].ID = "rule-9" },
		"entry literal":           func(c *Content) { c.Policies[1].Entries[1].Literal = "curl|sh" },
		"entry removed":           func(c *Content) { c.Policies[1].Entries = c.Policies[1].Entries[:1] },
		"entries in other order":  func(c *Content) { e := c.Policies[1].Entries; e[0], e[1] = e[1], e[0] },
		"entry moved to the other policy": func(c *Content) {
			c.Policies[0].Entries, c.Policies[1].Entries = c.Policies[1].Entries[:1], c.Policies[1].Entries[1:]
		},
	} {
		t.Run(name, func(t *testing.T) {
			content := goldenContent()
			change(&content)
			if got, ok := Digest(content); !ok || got == base {
				t.Fatalf("a change of this field alone kept the digest: ok=%t", ok)
			}
		})
	}
}

// The fourth audit's 7.5, moved here with the digest. Two parts of the digest
// are constant in every content a Service can commission today: the
// verifier's algorithm, and the id and entry count of the configured policy.
// Behaviour cannot tell whether they are hashed, so the function is asked
// directly: two inputs that differ only there must not share a digest.
func TestDigestFramesItsConstantParts(t *testing.T) {
	digest := func(verifier Verifier, policies []Policy) [32]byte {
		t.Helper()
		sum, ok := Digest(Content{Trust: goldenTrust(), Verifier: verifier, Policies: policies})
		if !ok || sum == [32]byte{} {
			t.Fatal("digest input was refused")
		}
		return sum
	}
	held := goldenContent()
	if digest(held.Verifier, held.Policies) != digest(held.Verifier, held.Policies) {
		t.Fatal("control: equal inputs gave different digests")
	}
	t.Run("verifier algorithm", func(t *testing.T) {
		other := held.Verifier
		other.Algorithm = "ed448"
		if digest(held.Verifier, held.Policies) == digest(other, held.Policies) {
			t.Fatal("two verifiers that differ only in the algorithm share a digest")
		}
		// The algorithm and the key id are framed apart, and so are the key id
		// and the key.
		left, right := held.Verifier, held.Verifier
		left.Algorithm, left.KeyID = "ab", "c"
		right.Algorithm, right.KeyID = "a", "bc"
		if digest(left, held.Policies) == digest(right, held.Policies) {
			t.Fatal("the algorithm and the key id are not framed apart")
		}
		left, right = held.Verifier, held.Verifier
		left.KeyID, left.PublicKey = "ab", []byte("c")
		right.KeyID, right.PublicKey = "a", []byte("bc")
		if digest(left, held.Policies) == digest(right, held.Policies) {
			t.Fatal("the key id and the key are not framed apart")
		}
	})
	t.Run("configured policy id and entry count", func(t *testing.T) {
		entry := PolicyEntry{ID: "entry", Literal: "literal"}
		empty := Policy{ID: configuredPolicy}
		one := Policy{ID: configuredPolicy, Entries: []PolicyEntry{entry}}
		// The same entries in the same order, divided differently between
		// two configured policies: only the counts tell them apart.
		if digest(held.Verifier, []Policy{empty, one}) == digest(held.Verifier, []Policy{one, empty}) {
			t.Fatal("two policy lists that differ only in their entry counts share a digest")
		}
		// A configured policy without entries and the selected policy differ
		// only in the id.
		if digest(held.Verifier, []Policy{{ID: selectedPolicy}}) == digest(held.Verifier, []Policy{empty}) {
			t.Fatal("two policies that differ only in the id share a digest")
		}
		// The id and the literal of an entry are framed apart.
		left := Policy{ID: configuredPolicy, Entries: []PolicyEntry{{ID: "ab", Literal: "c"}}}
		right := Policy{ID: configuredPolicy, Entries: []PolicyEntry{{ID: "a", Literal: "bc"}}}
		if digest(held.Verifier, []Policy{left}) == digest(held.Verifier, []Policy{right}) {
			t.Fatal("the id and the literal of an entry are not framed apart")
		}
	})
}

// shiftWallClock returns at with its wall-clock reading moved by whole
// seconds and its monotonic reading untouched, which is what a stepped or
// suspended host clock produces and what no time API will construct. It
// checks its own result, so a change of the runtime's layout fails loudly.
func shiftWallClock(t *testing.T, at time.Time, seconds int64) time.Time {
	t.Helper()
	type layout struct {
		wall uint64
		ext  int64
		loc  *time.Location
	}
	forged := at
	if unsafe.Sizeof(forged) != unsafe.Sizeof(layout{}) {
		t.Fatal("time.Time layout changed; rewrite this forgery")
	}
	fields := (*layout)(unsafe.Pointer(&forged))
	if fields.wall>>63 != 1 {
		t.Fatal("the time to forge carries no monotonic reading")
	}
	// With a monotonic reading present, wall seconds start at bit 30.
	fields.wall = uint64(int64(fields.wall) + seconds<<30)
	if forged.Sub(at) != 0 || forged.Round(0).Sub(at.Round(0)) != time.Duration(seconds)*time.Second {
		t.Fatalf("forged time is not a pure wall-clock step: monotonic=%s wall=%s", forged.Sub(at), forged.Round(0).Sub(at.Round(0)))
	}
	return forged
}

func TestConfirmationDeadlineArithmetic(t *testing.T) {
	limit := ConfirmationLimit
	if limit != 30*time.Second {
		t.Fatalf("confirmation limit is %s; the contract says 30 seconds", limit)
	}
	confirmed := time.Now()
	wall := func(at time.Time, seconds int64) time.Time { return shiftWallClock(t, at, seconds) }
	skewed := func(d time.Duration) func() time.Duration { return func() time.Duration { return d } }
	for _, tc := range []struct {
		name      string
		confirmed time.Time
		now       time.Time
		skew      func() time.Duration
		want      bool
	}{
		{"never confirmed", time.Time{}, confirmed, nil, false},
		{"same instant", confirmed, confirmed, nil, true},
		{"one nanosecond inside the limit", confirmed, confirmed.Add(limit - 1), nil, true},
		{"exactly the limit", confirmed, confirmed.Add(limit), nil, false},
		{"past the limit", confirmed, confirmed.Add(limit + time.Hour), nil, false},
		{"both clocks before the confirmation", confirmed, confirmed.Add(-1), nil, false},
		// The two clocks disagree: either one refuses alone.
		{"wall clock at the limit, monotonic inside", confirmed, wall(confirmed.Add(time.Second), 29), nil, false},
		{"wall clock inside, monotonic at the limit", confirmed, wall(confirmed.Add(limit), -29), nil, false},
		{"wall clock moved backwards", confirmed, wall(confirmed.Add(time.Second), -2), nil, false},
		{"control: both clocks inside after a wall step", confirmed, wall(confirmed.Add(time.Second), 28), nil, true},
		// The proof seam only adds elapsed time.
		{"skew just inside", confirmed, confirmed.Add(10 * time.Second), skewed(limit - 10*time.Second - 1), true},
		{"skew reaches the limit", confirmed, confirmed.Add(10 * time.Second), skewed(limit - 10*time.Second), false},
		{"skew reaches the limit on the wall clock only", confirmed, wall(confirmed.Add(time.Second), 9), skewed(limit - 10*time.Second), false},
		{"skew beyond any limit", confirmed, confirmed, skewed(1<<63 - 1), false},
		{"negative skew cannot buy time", confirmed, confirmed.Add(limit - 1), skewed(-time.Hour), false},
		{"negative skew refuses even inside the limit", confirmed, confirmed, skewed(-1), false},
		{"zero skew", confirmed, confirmed, skewed(0), true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := fresh(tc.confirmed, tc.now, tc.skew); got != tc.want {
				t.Fatalf("fresh=%t, want %t", got, tc.want)
			}
		})
	}
	t.Run("a view that was never confirmed does not ask the proof seam", func(t *testing.T) {
		asked := false
		if fresh(time.Time{}, confirmed, func() time.Duration { asked = true; return 0 }) || asked {
			t.Fatalf("an unconfirmed state was fresh or asked the seam: asked=%t", asked)
		}
	})
}

// The shape that makes a bypass fail to compile, stated as a test: the two
// handles are exported structs with one unexported pointer field each, to
// unexported struct types none of whose fields is exported. The compile
// probes of the guard show the same from outside.
func TestHandlesExposeNothing(t *testing.T) {
	for _, handle := range []reflect.Type{reflect.TypeOf(State{}), reflect.TypeOf(View{})} {
		if handle.NumField() != 1 || handle.NumMethod() == 0 {
			t.Fatalf("%s: fields=%d", handle, handle.NumField())
		}
		field := handle.Field(0)
		if field.IsExported() || field.Anonymous || field.Type.Kind() != reflect.Pointer {
			t.Fatalf("%s.%s is exported, embedded or not a pointer", handle, field.Name)
		}
		held := field.Type.Elem()
		if held.Kind() != reflect.Struct || held.PkgPath() != handle.PkgPath() || held.Name() == "" ||
			strings.ToLower(held.Name()[:1]) != held.Name()[:1] {
			t.Fatalf("%s holds %s, which is not an unexported struct of this package", handle, held)
		}
		for i := 0; i < held.NumField(); i++ {
			if inner := held.Field(i); inner.IsExported() || inner.Anonymous {
				t.Fatalf("%s.%s is exported or embedded", held, inner.Name)
			}
		}
		// The methods of the pointer type are those of the value type: no
		// method takes the address of a handle.
		if reflect.PointerTo(handle).NumMethod() != handle.NumMethod() {
			t.Fatalf("%s has a method with a pointer receiver", handle)
		}
	}
	want := map[string][]string{
		"state": {"mu", "owner", "view", "withdrawn", "superseded", "confirmed"},
		"view":  {"installation", "epoch", "token", "content", "proof", "skew"},
	}
	for _, held := range []reflect.Type{reflect.TypeOf(state{}), reflect.TypeOf(view{})} {
		var got []string
		for i := 0; i < held.NumField(); i++ {
			got = append(got, held.Field(i).Name)
		}
		if !slices.Equal(got, want[held.Name()]) {
			t.Fatalf("%s fields are %v, want %v: a new field needs its own tests and its place in the owner document", held.Name(), got, want[held.Name()])
		}
	}
}

// The content types are plain data, and the copies and the digest are written
// field by field. A new field in any of them, or in the trust model of EGS,
// fails here until the copy and the digest cover it.
func TestContentFieldSetIsCovered(t *testing.T) {
	text := reflect.TypeOf("")
	texts := reflect.TypeOf([]string(nil))
	for _, tc := range []struct {
		typ  reflect.Type
		want map[string]reflect.Type
	}{
		{reflect.TypeOf(Content{}), map[string]reflect.Type{"Trust": reflect.TypeOf(egsmodel.RuntimeTrustPolicy{}),
			"Verifier": reflect.TypeOf(Verifier{}), "Policies": reflect.TypeOf([]Policy(nil))}},
		{reflect.TypeOf(Verifier{}), map[string]reflect.Type{"Algorithm": text, "KeyID": text, "PublicKey": reflect.TypeOf([]byte(nil))}},
		{reflect.TypeOf(Policy{}), map[string]reflect.Type{"ID": text, "Entries": reflect.TypeOf([]PolicyEntry(nil))}},
		{reflect.TypeOf(PolicyEntry{}), map[string]reflect.Type{"ID": text, "Literal": text}},
		{reflect.TypeOf(egsmodel.RuntimeTrustPolicy{}), map[string]reflect.Type{"SignerPolicy": reflect.TypeOf(egsmodel.SignerPolicy{}),
			"ArtifactPolicy": reflect.TypeOf(egsmodel.ArtifactPolicy{})}},
		{reflect.TypeOf(egsmodel.SignerPolicy{}), map[string]reflect.Type{"AllowedSigners": texts, "RevokedSigners": texts}},
		{reflect.TypeOf(egsmodel.ArtifactPolicy{}), map[string]reflect.Type{"RevokedArtifacts": texts}},
	} {
		got := make(map[string]reflect.Type)
		for i := 0; i < tc.typ.NumField(); i++ {
			got[tc.typ.Field(i).Name] = tc.typ.Field(i).Type
		}
		if !reflect.DeepEqual(got, tc.want) {
			t.Fatalf("%s fields are %v, want %v", tc.typ, got, tc.want)
		}
	}
}

// sharesMemory reports whether two values of the same type reach one backing
// array through any slice.
func sharesMemory(a, b reflect.Value) bool {
	switch a.Kind() {
	case reflect.Slice:
		if a.Len() > 0 && b.Len() > 0 && a.Pointer() == b.Pointer() {
			return true
		}
		for i := 0; i < a.Len() && i < b.Len(); i++ {
			if sharesMemory(a.Index(i), b.Index(i)) {
				return true
			}
		}
	case reflect.Struct:
		for i := 0; i < a.NumField(); i++ {
			if sharesMemory(a.Field(i), b.Field(i)) {
				return true
			}
		}
	}
	return false
}

func TestContentIsCopied(t *testing.T) {
	original := goldenContent()
	t.Run("the copies are deep and equal", func(t *testing.T) {
		copied := Content{Trust: cloneTrust(original.Trust), Verifier: cloneVerifier(original.Verifier), Policies: clonePolicies(original.Policies)}
		if !reflect.DeepEqual(copied, original) || sharesMemory(reflect.ValueOf(copied), reflect.ValueOf(original)) {
			t.Fatal("a copy differs from its original or shares memory with it")
		}
		if !sharesMemory(reflect.ValueOf(original), reflect.ValueOf(original)) {
			t.Fatal("control: the sharing check does not see a value share memory with itself")
		}
		// Control for each list: sharing one of them alone is seen.
		for name, share := range map[string]func(*Content){
			"allowed signers": func(c *Content) { c.Trust.SignerPolicy.AllowedSigners = original.Trust.SignerPolicy.AllowedSigners },
			"revoked signers": func(c *Content) { c.Trust.SignerPolicy.RevokedSigners = original.Trust.SignerPolicy.RevokedSigners },
			"revoked artifacts": func(c *Content) {
				c.Trust.ArtifactPolicy.RevokedArtifacts = original.Trust.ArtifactPolicy.RevokedArtifacts
			},
			"public key": func(c *Content) { c.Verifier.PublicKey = original.Verifier.PublicKey },
			"policies":   func(c *Content) { c.Policies = original.Policies },
			"entries":    func(c *Content) { c.Policies[1].Entries = original.Policies[1].Entries },
		} {
			shared := Content{Trust: cloneTrust(original.Trust), Verifier: cloneVerifier(original.Verifier), Policies: clonePolicies(original.Policies)}
			share(&shared)
			if !sharesMemory(reflect.ValueOf(shared), reflect.ValueOf(original)) {
				t.Fatalf("control: shared %s were not seen", name)
			}
		}
	})
	t.Run("absent lists stay absent and empty lists stay empty", func(t *testing.T) {
		if clonePolicies(nil) != nil || cloneVerifier(Verifier{}).PublicKey != nil ||
			!reflect.DeepEqual(cloneTrust(egsmodel.RuntimeTrustPolicy{}), egsmodel.RuntimeTrustPolicy{}) {
			t.Fatal("a copy of absent lists is not absent")
		}
		empty := Content{Trust: egsmodel.RuntimeTrustPolicy{SignerPolicy: egsmodel.SignerPolicy{AllowedSigners: []string{}, RevokedSigners: []string{}},
			ArtifactPolicy: egsmodel.ArtifactPolicy{RevokedArtifacts: []string{}}}, Verifier: Verifier{PublicKey: []byte{}},
			Policies: []Policy{{ID: selectedPolicy, Entries: []PolicyEntry{}}}}
		copied := Content{Trust: cloneTrust(empty.Trust), Verifier: cloneVerifier(empty.Verifier), Policies: clonePolicies(empty.Policies)}
		if !reflect.DeepEqual(copied, empty) {
			t.Fatalf("a copy of empty lists differs: %#v", copied)
		}
		if got := clonePolicies([]Policy{}); got == nil || len(got) != 0 {
			t.Fatal("a copy of an empty policy list is absent")
		}
	})
	t.Run("a view hands out copies", func(t *testing.T) {
		held := Content{Trust: cloneTrust(original.Trust), Verifier: cloneVerifier(original.Verifier), Policies: clonePolicies(original.Policies)}
		handle := View{v: &view{content: held}}
		for i := 0; i < 2; i++ {
			out := Content{Trust: handle.Trust(), Verifier: handle.Verifier(), Policies: handle.Policies()}
			if !reflect.DeepEqual(out, original) || sharesMemory(reflect.ValueOf(out), reflect.ValueOf(held)) {
				t.Fatalf("read %d: the view handed out its own memory or other content", i)
			}
			// A write to the copy reaches neither the view nor the next copy.
			out.Trust.SignerPolicy.AllowedSigners[0] = "written"
			out.Trust.SignerPolicy.RevokedSigners[0] = "written"
			out.Trust.ArtifactPolicy.RevokedArtifacts[0] = "written"
			out.Verifier.PublicKey[0] ^= 0xff
			out.Policies[0].ID = "written"
			out.Policies[1].Entries[0].Literal = "written"
		}
		if !reflect.DeepEqual(held, original) {
			t.Fatal("a write to a copy reached the view")
		}
	})
}

func TestNoViewAnswersNothing(t *testing.T) {
	var none View
	if none.Installed() || none.Token() != (reliablesubmit.OperationalAdmissionToken{}) || none.Token().Valid() ||
		!reflect.DeepEqual(none.Trust(), egsmodel.RuntimeTrustPolicy{}) || !reflect.DeepEqual(none.Verifier(), Verifier{}) ||
		none.Policies() != nil || none.Proof() != nil {
		t.Fatal("the zero view handle answers as a view")
	}
	a, b := &view{}, &view{}
	if (View{v: a}) != (View{v: a}) || (View{v: a}) == (View{v: b}) || (View{v: a}) == none || !(View{v: a}).Installed() {
		t.Fatal("two view handles are not equal exactly when they name one view")
	}
	type marker struct{ n int }
	proof := &marker{7}
	if got := (View{v: &view{proof: proof}}).Proof(); got != any(proof) {
		t.Fatalf("the proof value was not handed back as given: %v", got)
	}
}

type testOwner struct{ name string }

// installed writes a view into a state directly. It stands for a view that
// Install accepted; the token is the zero token.
func installed(t *testing.T, h State, installation [32]byte, epoch uint64) View {
	t.Helper()
	if h.s == nil {
		t.Fatal("no state to install into")
	}
	h.s.mu.Lock()
	defer h.s.mu.Unlock()
	h.s.view = &view{installation: installation, epoch: epoch, content: goldenContent()}
	return View{v: h.s.view}
}

// allClosed asks every question of a handle as one owner and requires that
// none is answered and nothing changes.
func allClosed(t *testing.T, what string, h State, owner any, installation [32]byte, epoch uint64) {
	t.Helper()
	var before state
	if h.s != nil {
		h.s.mu.RLock()
		before.view, before.withdrawn, before.superseded, before.confirmed = h.s.view, h.s.withdrawn, h.s.superseded, h.s.confirmed
		h.s.mu.RUnlock()
	}
	if h.Installable(owner) {
		t.Fatalf("%s: open", what)
	}
	if h.Install(owner, installation, epoch, reliablesubmit.OperationalAdmissionToken{}, goldenContent(), nil, nil) {
		t.Fatalf("%s: installed", what)
	}
	if token, ok := h.Withdraw(owner, installation, epoch); ok || token.Valid() {
		t.Fatalf("%s: withdrew", what)
	}
	if got, ok := h.Confirmable(owner); ok || got.Installed() {
		t.Fatalf("%s: confirmable", what)
	}
	if got, ok := h.Current(owner, installation, epoch); ok || got.Installed() {
		t.Fatalf("%s: current", what)
	}
	if got := h.Inspect(owner); got != (Status{}) {
		t.Fatalf("%s: inspected %+v", what, got)
	}
	if h.s != nil {
		// A confirmation by someone who is not the owner changes nothing,
		// with the installed view in hand and trust that differs.
		h.Confirm(owner, View{v: h.s.view}, egsmodel.RuntimeTrustPolicy{}, time.Now().Add(time.Hour))
		h.s.mu.RLock()
		defer h.s.mu.RUnlock()
		if h.s.view != before.view || h.s.withdrawn != before.withdrawn || h.s.superseded != before.superseded ||
			!h.s.confirmed.Equal(before.confirmed) {
			t.Fatalf("%s: a closed handle changed the state", what)
		}
	}
}

func TestZeroAndForeignHandlesAreClosed(t *testing.T) {
	installation, epoch := [32]byte{1}, uint64(1)
	owner := &testOwner{"owner"}
	t.Run("the zero handle", func(t *testing.T) {
		var zero State
		if zero.Commissioned() {
			t.Fatal("the zero handle is commissioned")
		}
		allClosed(t, "zero handle", zero, owner, installation, epoch)
		allClosed(t, "zero handle, no owner", zero, nil, installation, epoch)
	})
	t.Run("no owner gets the zero handle", func(t *testing.T) {
		if New(nil) != (State{}) {
			t.Fatal("a state was made for no owner")
		}
		if a, b := New(owner), New(owner); a.s == nil || a == b || a.s.owner != any(owner) {
			t.Fatal("New did not make a state of its own for the owner")
		}
	})
	t.Run("another owner, a copy of the owner and no owner", func(t *testing.T) {
		h := New(owner)
		view := installed(t, h, installation, epoch)
		h.s.confirmed = time.Now()
		// The control: the owner is answered.
		if got, ok := h.Current(owner, installation, epoch); !ok || got != view {
			t.Fatal("control: the owner's own view is not current")
		}
		copied := *owner
		for what, other := range map[string]any{"another owner": &testOwner{"owner"}, "a copy of the owner": &copied,
			"the owner's value": *owner, "no owner": nil, "an owner of another type": "owner"} {
			allClosed(t, what, h, other, installation, epoch)
		}
		// The one question that asks no owner.
		if !h.Commissioned() {
			t.Fatal("a state with a view is not commissioned")
		}
		if got, ok := h.Current(owner, installation, epoch); !ok || got != view {
			t.Fatal("the questions of others changed the owner's view")
		}
	})
	t.Run("a state without an owner serves nobody", func(t *testing.T) {
		// New makes no such state. Should one ever exist, no owner matches
		// it: the absent owner is not an identity that can be presented.
		bare := State{s: &state{}}
		allClosed(t, "a state without an owner and without a view, asked by no owner", bare, nil, installation, epoch)
		allClosed(t, "a state without an owner and without a view, asked by an owner", bare, owner, installation, epoch)
		h := State{s: &state{}}
		installed(t, h, installation, epoch)
		h.s.confirmed = time.Now()
		allClosed(t, "a state without an owner, asked by no owner", h, nil, installation, epoch)
		allClosed(t, "a state without an owner, asked by an owner", h, owner, installation, epoch)
		// The control: the same state with an owner answers that owner.
		h.s.owner = owner
		if got, ok := h.Current(owner, installation, epoch); !ok || !got.Installed() {
			t.Fatal("control: the same state with an owner does not answer its owner")
		}
	})
}

func TestStateLatchesAndRealm(t *testing.T) {
	installation, epoch := [32]byte{1}, uint64(3)
	otherInstallation := installation
	otherInstallation[31] ^= 1
	owner := &testOwner{"owner"}
	newState := func(t *testing.T) (State, View) {
		t.Helper()
		h := New(owner)
		if !h.Installable(owner) || h.Commissioned() {
			t.Fatal("a new state is not open, or is commissioned")
		}
		if _, ok := h.Confirmable(owner); ok {
			t.Fatal("a state without a view is confirmable")
		}
		if _, ok := h.Current(owner, installation, epoch); ok {
			t.Fatal("a state without a view is current")
		}
		if _, ok := h.Withdraw(owner, installation, epoch); ok || h.Commissioned() {
			t.Fatal("a state without a view was withdrawn")
		}
		view := installed(t, h, installation, epoch)
		if h.Installable(owner) || !h.Commissioned() {
			t.Fatal("a state with a view is open, or is not commissioned")
		}
		return h, view
	}
	t.Run("a view is not current before its first confirmation", func(t *testing.T) {
		h, view := newState(t)
		if _, ok := h.Current(owner, installation, epoch); ok {
			t.Fatal("an unconfirmed view is current")
		}
		if got, ok := h.Confirmable(owner); !ok || got != view {
			t.Fatal("an installed view is not confirmable")
		}
		if got := h.Inspect(owner); got.View != view || got.Withdrawn || got.Superseded || !got.Confirmed.IsZero() {
			t.Fatalf("status of an installed, unconfirmed view: %+v", got)
		}
	})
	t.Run("current for its own realm only", func(t *testing.T) {
		h, view := newState(t)
		h.s.confirmed = time.Now()
		if got, ok := h.Current(owner, installation, epoch); !ok || got != view {
			t.Fatal("control: a confirmed view is not current for its realm")
		}
		for what, realm := range map[string]struct {
			installation [32]byte
			epoch        uint64
		}{"another installation": {otherInstallation, epoch}, "a later epoch": {installation, epoch + 1},
			"an earlier epoch": {installation, epoch - 1}, "the zero realm": {}} {
			if got, ok := h.Current(owner, realm.installation, realm.epoch); ok || got.Installed() {
				t.Fatalf("the view is current for %s", what)
			}
			if token, ok := h.Withdraw(owner, realm.installation, realm.epoch); ok || token.Valid() || h.Inspect(owner).Withdrawn {
				t.Fatalf("the view was withdrawn through %s", what)
			}
		}
		if got, ok := h.Current(owner, installation, epoch); !ok || got != view {
			t.Fatal("questions for other realms changed the view")
		}
	})
	t.Run("the deadline and the proof seam", func(t *testing.T) {
		h := New(owner)
		var skew time.Duration
		asked := 0
		h.s.view = &view{installation: installation, epoch: epoch, content: goldenContent(),
			skew: func() time.Duration { asked++; return skew }}
		h.s.confirmed = time.Now()
		if _, ok := h.Current(owner, installation, epoch); !ok || asked != 1 {
			t.Fatalf("control: fresh view not current, or the seam was asked %d times", asked)
		}
		skew = ConfirmationLimit
		if _, ok := h.Current(owner, installation, epoch); ok || asked != 2 {
			t.Fatal("a view past its deadline is current")
		}
		skew = 0
		h.s.confirmed = time.Now().Add(-ConfirmationLimit)
		if _, ok := h.Current(owner, installation, epoch); ok {
			t.Fatal("a confirmation one limit old is current")
		}
		// A deadline that passed is not a latch: the next confirmation brings
		// the view back.
		h.s.confirmed = time.Now()
		if _, ok := h.Current(owner, installation, epoch); !ok {
			t.Fatal("a view was not current again after a new confirmation")
		}
		// The seam is not asked for a realm the view does not name.
		asked = 0
		if _, ok := h.Current(owner, otherInstallation, epoch); ok || asked != 0 {
			t.Fatalf("the seam was asked %d times for another realm", asked)
		}
	})
	t.Run("the proof seam runs outside the lock", func(t *testing.T) {
		h := New(owner)
		done := make(chan bool, 1)
		h.s.view = &view{installation: installation, epoch: epoch, content: goldenContent(), skew: func() time.Duration {
			// A write lock taken here would wait for ever if Current still
			// held its read lock.
			_, ok := h.Withdraw(owner, installation, epoch)
			done <- ok
			return 0
		}}
		h.s.confirmed = time.Now()
		result := make(chan bool, 1)
		go func() {
			_, ok := h.Current(owner, installation, epoch)
			result <- ok
		}()
		select {
		case ok := <-result:
			// The sample was taken before the withdrawal; the next one sees it.
			if !ok || !<-done {
				t.Fatal("the sample taken before the withdrawal was refused, or the withdrawal failed")
			}
		case <-time.After(10 * time.Second):
			t.Fatal("Current called the proof seam while it held the lock")
		}
		if _, ok := h.Current(owner, installation, epoch); ok {
			t.Fatal("a withdrawn view is current")
		}
	})
	t.Run("withdrawal is a latch", func(t *testing.T) {
		h, view := newState(t)
		h.s.confirmed = time.Now()
		for i := 0; i < 2; i++ {
			if token, ok := h.Withdraw(owner, installation, epoch); !ok || token != view.Token() {
				t.Fatalf("withdrawal %d was refused or returned another token", i)
			}
		}
		if _, ok := h.Current(owner, installation, epoch); ok {
			t.Fatal("a withdrawn view is current")
		}
		if _, ok := h.Confirmable(owner); ok {
			t.Fatal("a withdrawn view is confirmable")
		}
		if got := h.Inspect(owner); !got.Withdrawn || got.Superseded || got.View != view {
			t.Fatalf("status after withdrawal: %+v", got)
		}
		// Nothing clears the latch: not a confirmation, and no view can be
		// installed after it. (The view holds the zero token, so this
		// confirmation finds other content and sets the second latch too.)
		h.Confirm(owner, view, goldenTrust(), time.Now())
		if got := h.Inspect(owner); !got.Withdrawn || got.View != view || h.Installable(owner) || !h.Commissioned() {
			t.Fatalf("status after a confirmation of a withdrawn state: %+v", got)
		}
	})
	t.Run("a state that lost its view stays commissioned and closed", func(t *testing.T) {
		// No method removes a view. Should one ever be gone, the latch still
		// answers: withdrawn means commissioned, and nothing can be installed.
		h, _ := newState(t)
		h.s.withdrawn, h.s.view = true, nil
		if !h.Commissioned() || h.Installable(owner) {
			t.Fatal("a withdrawn state without a view is open or uncommissioned")
		}
		h.s.withdrawn, h.s.superseded = false, true
		if h.Commissioned() || h.Installable(owner) {
			t.Fatal("a superseded state without a view is open, or counts as commissioned")
		}
	})
	t.Run("trust that differs latches supersession", func(t *testing.T) {
		h, view := newState(t)
		confirmed := time.Now().Add(-time.Second)
		h.s.confirmed = confirmed
		// The view holds the zero token, which names no content, so every
		// trust EGS could serve differs from what the token names.
		h.Confirm(owner, view, goldenTrust(), time.Now())
		got := h.Inspect(owner)
		if !got.Superseded || got.Withdrawn || !got.Confirmed.Equal(confirmed) {
			t.Fatalf("status after different trust: %+v", got)
		}
		if _, ok := h.Current(owner, installation, epoch); ok {
			t.Fatal("a superseded view is current")
		}
		if _, ok := h.Confirmable(owner); ok {
			t.Fatal("a superseded view is confirmable")
		}
		if h.Installable(owner) || !h.Commissioned() {
			t.Fatal("a superseded state is open, or lost its view")
		}
		// The withdrawal of a superseded state still works: it is how the
		// domain is stopped.
		if _, ok := h.Withdraw(owner, installation, epoch); !ok || !h.Inspect(owner).Withdrawn || !h.Inspect(owner).Superseded {
			t.Fatal("a superseded state could not be withdrawn, or the withdrawal cleared the latch")
		}
	})
	t.Run("a confirmation that cannot be judged changes nothing", func(t *testing.T) {
		h, view := newState(t)
		confirmed := time.Now().Add(-time.Second)
		h.s.confirmed = confirmed
		unchanged := func(what string) {
			t.Helper()
			if got := h.Inspect(owner); got.Superseded || got.Withdrawn || !got.Confirmed.Equal(confirmed) || got.View != view {
				t.Fatalf("%s changed the state: %+v", what, got)
			}
		}
		// Trust that has no canonical form has no digest.
		invalid := goldenTrust()
		invalid.SignerPolicy.AllowedSigners = []string{"signer-a", "signer-a"}
		h.Confirm(owner, view, invalid, time.Now())
		unchanged("trust without a digest")
		h.Confirm(owner, View{}, goldenTrust(), time.Now())
		unchanged("no view")
		// A view that is not the installed one: of another state, with the
		// same realm and content.
		other := installed(t, New(owner), installation, epoch)
		h.Confirm(owner, other, goldenTrust(), time.Now())
		unchanged("the view of another state")
	})
}

// The state is safe under concurrent use: readers, a confirmation that
// supersedes and a withdrawal run together under the race detector, and once
// a latch is seen it is never seen cleared.
func TestStateConcurrentUse(t *testing.T) {
	installation, epoch := [32]byte{9}, uint64(1)
	owner := &testOwner{"owner"}
	h := New(owner)
	view := installed(t, h, installation, epoch)
	h.s.confirmed = time.Now()
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			stopped := false
			for n := 0; n < 2000; n++ {
				_, ok := h.Current(owner, installation, epoch)
				status := h.Inspect(owner)
				if stopped && (ok || !(status.Withdrawn || status.Superseded)) {
					t.Errorf("reader %d: a latch was cleared", i)
					return
				}
				stopped = stopped || status.Withdrawn || status.Superseded
				h.Commissioned()
				h.Installable(owner)
				h.Confirmable(owner)
				if n == 500 && i == 0 {
					h.Confirm(owner, view, goldenTrust(), time.Now())
				}
				if n == 1000 && i == 1 {
					h.Withdraw(owner, installation, epoch)
				}
			}
		}(i)
	}
	close(start)
	wg.Wait()
	if got := h.Inspect(owner); !got.Withdrawn || !got.Superseded {
		t.Fatalf("final status: %+v", got)
	}
}
