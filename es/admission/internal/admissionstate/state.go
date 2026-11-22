// Package admissionstate owns the private operational admission state of one
// Service: the installed view, the withdrawal and supersession latches and the
// time of the last confirmation.
//
// The state is reachable only through the two handles State and View. Each
// holds one unexported pointer to an unexported struct, so no other package
// can name a field of the state, write a struct type of its shape, or copy,
// overwrite or restore its value: none of those compiles outside this package.
// What another package can do is call the methods below. Content goes in and
// comes out by deep copy, so no caller holds memory that a view enforces.
//
// The package has no reflection, no unsafe and no cgo, and performs no I/O.
// While it holds its lock it calls no function that a caller supplied.
package admissionstate

import (
	"crypto/sha256"
	"encoding/binary"
	"slices"
	"sync"
	"time"

	egsmodel "execution-substrate/egs/model"
	"execution-substrate/es/admission/internal/reliablesubmit"
)

// ConfirmationLimit is how long a view may be used after the last
// confirmation that EGS still serves the commissioned trust.
const ConfirmationLimit = 30 * time.Second

// Verifier is the evidence verifier a view enforces, as plain data.
type Verifier struct {
	Algorithm string
	KeyID     string
	PublicKey []byte
}

// PolicyEntry is one configured entry of a built-in policy.
type PolicyEntry struct {
	ID      string
	Literal string
}

// Policy names one selected built-in policy and its configured entries.
type Policy struct {
	ID      string
	Entries []PolicyEntry
}

// Content is the admission content: the normalized trust lists, the evidence
// verifier and the selected built-in policies with every configured entry. It
// is plain data. A view holds its own copy and hands out copies.
type Content struct {
	Trust    egsmodel.RuntimeTrustPolicy
	Verifier Verifier
	Policies []Policy
}

func cloneTrust(trust egsmodel.RuntimeTrustPolicy) egsmodel.RuntimeTrustPolicy {
	return egsmodel.RuntimeTrustPolicy{
		SignerPolicy: egsmodel.SignerPolicy{
			AllowedSigners: slices.Clone(trust.SignerPolicy.AllowedSigners),
			RevokedSigners: slices.Clone(trust.SignerPolicy.RevokedSigners),
		},
		ArtifactPolicy: egsmodel.ArtifactPolicy{
			RevokedArtifacts: slices.Clone(trust.ArtifactPolicy.RevokedArtifacts),
		},
	}
}

func cloneVerifier(verifier Verifier) Verifier {
	return Verifier{Algorithm: verifier.Algorithm, KeyID: verifier.KeyID, PublicKey: slices.Clone(verifier.PublicKey)}
}

func clonePolicies(policies []Policy) []Policy {
	if policies == nil {
		return nil
	}
	out := make([]Policy, 0, len(policies))
	for _, policy := range policies {
		out = append(out, Policy{ID: policy.ID, Entries: slices.Clone(policy.Entries)})
	}
	return out
}

func frame(b, value []byte) []byte {
	return append(binary.BigEndian.AppendUint32(b, uint32(len(value))), value...)
}

// Digest names admission content. It is taken over the values a view holds,
// so what is hashed is what is enforced. It does not cover the compiled
// behaviour of a built-in policy; two releases with equal configuration
// present one digest.
func Digest(content Content) ([32]byte, bool) {
	canonical, err := content.Trust.CanonicalBytes()
	if err != nil || len(content.Policies) == 0 {
		return [32]byte{}, false
	}
	b := frame([]byte("ESOHADM1"), canonical)
	b = frame(b, []byte(content.Verifier.Algorithm))
	b = frame(b, []byte(content.Verifier.KeyID))
	b = frame(b, content.Verifier.PublicKey)
	b = binary.BigEndian.AppendUint32(b, uint32(len(content.Policies)))
	for _, policy := range content.Policies {
		b = frame(b, []byte(policy.ID))
		b = binary.BigEndian.AppendUint32(b, uint32(len(policy.Entries)))
		for _, entry := range policy.Entries {
			b = frame(b, []byte(entry.ID))
			b = frame(b, []byte(entry.Literal))
		}
	}
	return sha256.Sum256(b), true
}

// state is the protected state. Its lock covers every field but owner, which
// is set once before the state is shared.
type state struct {
	mu    sync.RWMutex
	owner any
	view  *view
	// withdrawn and superseded are latches: nothing clears them. superseded
	// is set when EGS serves trust that differs from the commissioned
	// content. confirmed is the time of the last confirmation that found it
	// equal; zero means never. It only moves forward.
	withdrawn  bool
	superseded bool
	confirmed  time.Time
}

// view is immutable from the moment it is installed.
type view struct {
	installation [32]byte
	epoch        uint64
	token        reliablesubmit.OperationalAdmissionToken
	content      Content
	proof        any
	skew         func() time.Duration
}

// State is the handle of one Service's admission state. The zero value holds
// no state: it is closed and stays closed. A State is made once by New for
// one owner, and every method but Commissioned serves that owner only, so a
// copy of the Service that holds the handle borrows nothing.
type State struct{ s *state }

// View is the handle of an installed view: an immutable copy of the admission
// content together with the token of the admission row it was commissioned or
// advanced under. The zero value is no view. Two handles are equal exactly
// when they name the same installed view.
type View struct{ v *view }

// New makes the state of one owner. The owner is an identity, compared with
// ==: the pointer to the Service that will hold the handle. A nil owner gets
// the closed zero handle.
func New(owner any) State {
	if owner == nil {
		return State{}
	}
	return State{s: &state{owner: owner}}
}

func (h State) held(owner any) *state {
	if h.s == nil || owner == nil || h.s.owner != owner {
		return nil
	}
	return h.s
}

// Commissioned reports whether a view was installed or the state was
// withdrawn. It is the one question that asks no owner: a copy of a
// commissioned Service is answered like the original.
func (h State) Commissioned() bool {
	if h.s == nil {
		return false
	}
	h.s.mu.RLock()
	defer h.s.mu.RUnlock()
	return h.s.view != nil || h.s.withdrawn
}

// Installable reports whether a view can still be installed: none is, and
// neither latch is set.
func (h State) Installable(owner any) bool {
	st := h.held(owner)
	if st == nil {
		return false
	}
	st.mu.RLock()
	defer st.mu.RUnlock()
	return st.view == nil && !st.withdrawn && !st.superseded
}

// Install installs the one view of this state and reports whether it did. The
// token must name exactly this installation, this epoch and the digest of
// this content, so a view cannot name a realm or hold content that its token
// does not. The content is copied. proof and skew are the proof seam: both
// are nil in production. proof is carried and handed back unread. skew adds
// elapsed time to the confirmation deadline; it cannot remove any.
func (h State) Install(owner any, installation [32]byte, epoch uint64, token reliablesubmit.OperationalAdmissionToken,
	content Content, proof any, skew func() time.Duration) bool {
	st := h.held(owner)
	if st == nil || installation == [32]byte{} || epoch == 0 {
		return false
	}
	held := Content{Trust: cloneTrust(content.Trust), Verifier: cloneVerifier(content.Verifier), Policies: clonePolicies(content.Policies)}
	digest, ok := Digest(held)
	if !ok || !token.Names(installation, epoch, digest) {
		return false
	}
	st.mu.Lock()
	defer st.mu.Unlock()
	if st.view != nil || st.withdrawn || st.superseded {
		return false
	}
	st.view = &view{installation: installation, epoch: epoch, token: token, content: held, proof: proof, skew: skew}
	return true
}

// Withdraw sets the withdrawal latch of a state whose view names this
// installation and epoch, and returns the token to withdraw in the store. It
// may be repeated.
func (h State) Withdraw(owner any, installation [32]byte, epoch uint64) (reliablesubmit.OperationalAdmissionToken, bool) {
	st := h.held(owner)
	if st == nil {
		return reliablesubmit.OperationalAdmissionToken{}, false
	}
	st.mu.Lock()
	defer st.mu.Unlock()
	installed := st.view
	if installed == nil || installed.installation != installation || installed.epoch != epoch {
		return reliablesubmit.OperationalAdmissionToken{}, false
	}
	st.withdrawn = true
	return installed.token, true
}

// Confirmable returns the installed view while a confirmation can still
// change something: the state is neither withdrawn nor superseded.
func (h State) Confirmable(owner any) (View, bool) {
	st := h.held(owner)
	if st == nil {
		return View{}, false
	}
	st.mu.RLock()
	defer st.mu.RUnlock()
	if st.view == nil || st.withdrawn || st.superseded {
		return View{}, false
	}
	return View{v: st.view}, true
}

// Confirm compares the trust EGS served with the content of the view, through
// the admission digest. Equal content records started, the time sampled
// before the request was sent, unless a later time is already recorded.
// Different content latches supersession for the life of the state. Trust
// that has no digest, and a view that is not the installed one, change
// nothing.
func (h State) Confirm(owner any, confirmed View, trust egsmodel.RuntimeTrustPolicy, started time.Time) {
	st := h.held(owner)
	if st == nil || confirmed.v == nil {
		return
	}
	digest, ok := Digest(Content{Trust: trust, Verifier: confirmed.v.content.Verifier, Policies: confirmed.v.content.Policies})
	if !ok {
		return
	}
	st.mu.Lock()
	defer st.mu.Unlock()
	if st.view != confirmed.v {
		return
	}
	if !confirmed.v.token.Names(confirmed.v.installation, confirmed.v.epoch, digest) {
		st.superseded = true
		return
	}
	if started.After(st.confirmed) {
		st.confirmed = started
	}
}

// fresh requires a confirmation, and less than the limit elapsed since it on
// both the monotonic and the wall clock, with neither reading negative. The
// proof seam can only add elapsed time; a negative skew refuses.
func fresh(confirmed, now time.Time, skew func() time.Duration) bool {
	if confirmed.IsZero() {
		return false
	}
	var added time.Duration
	if skew != nil {
		if added = skew(); added < 0 {
			return false
		}
	}
	for _, elapsed := range [2]time.Duration{now.Sub(confirmed), now.Round(0).Sub(confirmed.Round(0))} {
		if elapsed < 0 || elapsed >= ConfirmationLimit || added >= ConfirmationLimit-elapsed {
			return false
		}
	}
	return true
}

// Current returns the view only while it may be used: it is installed for
// this installation and epoch, the state is neither withdrawn nor
// superseded, and its last confirmation is within the limit. Every sample
// point inherits all of it. The clock and the proof seam are read outside
// the lock.
func (h State) Current(owner any, installation [32]byte, epoch uint64) (View, bool) {
	st := h.held(owner)
	if st == nil {
		return View{}, false
	}
	st.mu.RLock()
	installed := st.view
	stopped := installed == nil || st.withdrawn || st.superseded ||
		installed.installation != installation || installed.epoch != epoch
	confirmed := st.confirmed
	st.mu.RUnlock()
	if stopped || !fresh(confirmed, time.Now(), installed.skew) {
		return View{}, false
	}
	return View{v: installed}, true
}

// Status is a copy of what a state holds at one moment. It grants nothing and
// changes nothing. Production code does not ask for it.
type Status struct {
	View       View
	Withdrawn  bool
	Superseded bool
	Confirmed  time.Time
}

// Inspect returns the status of the state for tests: the installed view
// whether or not it may be used, both latches and the confirmation time.
func (h State) Inspect(owner any) Status {
	st := h.held(owner)
	if st == nil {
		return Status{}
	}
	st.mu.RLock()
	defer st.mu.RUnlock()
	return Status{View: View{v: st.view}, Withdrawn: st.withdrawn, Superseded: st.superseded, Confirmed: st.confirmed}
}

// Installed reports whether the handle names a view.
func (v View) Installed() bool { return v.v != nil }

// Token returns the token of the admission row the view was installed under,
// or the zero token for no view.
func (v View) Token() reliablesubmit.OperationalAdmissionToken {
	if v.v == nil {
		return reliablesubmit.OperationalAdmissionToken{}
	}
	return v.v.token
}

// Trust returns a copy of the trust lists the view enforces.
func (v View) Trust() egsmodel.RuntimeTrustPolicy {
	if v.v == nil {
		return egsmodel.RuntimeTrustPolicy{}
	}
	return cloneTrust(v.v.content.Trust)
}

// Verifier returns a copy of the evidence verifier the view enforces.
func (v View) Verifier() Verifier {
	if v.v == nil {
		return Verifier{}
	}
	return cloneVerifier(v.v.content.Verifier)
}

// Policies returns a copy of the selected built-in policies of the view.
func (v View) Policies() []Policy {
	if v.v == nil {
		return nil
	}
	return clonePolicies(v.v.content.Policies)
}

// Proof returns the value given to Install as proof, unread. Nil in
// production.
func (v View) Proof() any {
	if v.v == nil {
		return nil
	}
	return v.v.proof
}
