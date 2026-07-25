// Package reliablesubmit contains the first pure ES reliable-submit model.
//
// The model is transport-neutral and persistence-neutral. It validates phase shapes and one transition against one supplied current snapshot only. An
// assigned snapshot carries exactly one immutable RunRef; reassignment with
// the same RunRef is idempotent, and reassignment with a different RunRef fails
// closed. This package cannot prevent two stale copied pre-assignment values
// from being assigned independently by two callers. One winning caller/key claim and one globally authoritative assignment require a later durable uniqueness and compare-and-swap layer.
//
// The types do not stage, submit, reconcile provider state, choose public
// request or response fields, choose a final digest, or define a final run
// identity format.
package reliablesubmit

import (
	"bytes"
	"errors"
	"fmt"
)

var (
	ErrInvalidCallerRef                     = errors.New("reliable submit model: invalid caller reference")
	ErrInvalidSubmitKeyRef                  = errors.New("reliable submit model: invalid submit key reference")
	ErrInvalidClaimID                       = errors.New("reliable submit model: invalid claim identity")
	ErrInvalidPlanBinding                   = errors.New("reliable submit model: invalid plan binding")
	ErrInvalidEffectivePlanCategory         = errors.New("reliable submit model: invalid effective plan category")
	ErrInvalidEffectivePlanWitness          = errors.New("reliable submit model: invalid effective plan witness")
	ErrDuplicateEffectivePlanCategory       = errors.New("reliable submit model: duplicate effective plan category")
	ErrMissingEffectivePlanCategory         = errors.New("reliable submit model: missing effective plan category")
	ErrInapplicableEffectivePlanCategory    = errors.New("reliable submit model: inapplicable effective plan category")
	ErrInvalidBoundPlan                     = errors.New("reliable submit model: invalid bound plan")
	ErrInvalidRunRef                        = errors.New("reliable submit model: invalid run reference")
	ErrInvalidReceiptRef                    = errors.New("reliable submit model: invalid receipt reference")
	ErrInvalidPhase                         = errors.New("reliable submit model: invalid phase")
	ErrRunAssignmentMismatch                = errors.New("reliable submit model: run assignment mismatch")
	ErrPlanBindingConflict                  = errors.New("reliable submit model: plan binding conflict")
	ErrInvalidReplay                        = errors.New("reliable submit model: invalid replay")
	ErrInvalidRecoveredAccepted             = errors.New("reliable submit model: invalid recovered accepted")
	ErrInvalidReliableSubmitDecision        = errors.New("reliable submit model: invalid decision")
	ErrInvalidProviderOutcomeCandidatePhase = errors.New("reliable submit model: invalid provider outcome candidate phase")
)

type opaqueRef struct {
	value []byte
}

func newOpaqueRef(input []byte, invalid error) (opaqueRef, error) {
	if len(input) == 0 {
		return opaqueRef{}, invalid
	}
	copied := make([]byte, len(input))
	copy(copied, input)
	return opaqueRef{value: copied}, nil
}

func (r opaqueRef) valid() bool {
	return len(r.value) > 0
}

func (r opaqueRef) equal(other opaqueRef) bool {
	return r.valid() && other.valid() && bytes.Equal(r.value, other.value)
}

func (r opaqueRef) clone() opaqueRef {
	if !r.valid() {
		return opaqueRef{}
	}
	copied := make([]byte, len(r.value))
	copy(copied, r.value)
	return opaqueRef{value: copied}
}

func formatOpaque(state fmt.State, typeName string, valid bool) {
	status := "invalid"
	if valid {
		status = "opaque"
	}
	_, _ = state.Write([]byte(typeName))
	_, _ = state.Write([]byte("{"))
	_, _ = state.Write([]byte(status))
	_, _ = state.Write([]byte("}"))
}

// CallerRef is an opaque safe reference to an authenticated caller namespace.
// It is not a certificate, session object, or raw caller payload.
type CallerRef struct {
	ref opaqueRef
}

func NewCallerRef(value []byte) (CallerRef, error) {
	ref, err := newOpaqueRef(value, ErrInvalidCallerRef)
	if err != nil {
		return CallerRef{}, err
	}
	return CallerRef{ref: ref}, nil
}

func (r CallerRef) Valid() bool {
	return r.ref.valid()
}

func (r CallerRef) Equal(other CallerRef) bool {
	return r.ref.equal(other.ref)
}

func (r CallerRef) clone() CallerRef {
	return CallerRef{ref: r.ref.clone()}
}

func (r CallerRef) Format(state fmt.State, verb rune) {
	formatOpaque(state, "CallerRef", r.Valid())
}

// SubmitKeyRef is a safe private submit-key representation. Constructor input
// bytes are copied and are not exposed again by this model.
type SubmitKeyRef struct {
	ref opaqueRef
}

func NewSubmitKeyRef(value []byte) (SubmitKeyRef, error) {
	ref, err := newOpaqueRef(value, ErrInvalidSubmitKeyRef)
	if err != nil {
		return SubmitKeyRef{}, err
	}
	return SubmitKeyRef{ref: ref}, nil
}

func (r SubmitKeyRef) Valid() bool {
	return r.ref.valid()
}

func (r SubmitKeyRef) Equal(other SubmitKeyRef) bool {
	return r.ref.equal(other.ref)
}

func (r SubmitKeyRef) clone() SubmitKeyRef {
	return SubmitKeyRef{ref: r.ref.clone()}
}

func (r SubmitKeyRef) Format(state fmt.State, verb rune) {
	formatOpaque(state, "SubmitKeyRef", r.Valid())
}

// ClaimID binds a caller namespace reference to a safe submit-key reference.
// It is equality-only and has no public serialization role.
type ClaimID struct {
	caller    CallerRef
	submitKey SubmitKeyRef
}

func NewClaimID(caller CallerRef, submitKey SubmitKeyRef) (ClaimID, error) {
	if !caller.Valid() || !submitKey.Valid() {
		return ClaimID{}, ErrInvalidClaimID
	}
	return ClaimID{
		caller:    caller,
		submitKey: submitKey,
	}, nil
}

func (id ClaimID) Valid() bool {
	return id.caller.Valid() && id.submitKey.Valid()
}

func (id ClaimID) Equal(other ClaimID) bool {
	return id.Valid() && other.Valid() &&
		id.caller.Equal(other.caller) &&
		id.submitKey.Equal(other.submitKey)
}

func (id ClaimID) clone() ClaimID {
	return ClaimID{
		caller:    id.caller.clone(),
		submitKey: id.submitKey.clone(),
	}
}

func (id ClaimID) Format(state fmt.State, verb rune) {
	formatOpaque(state, "ClaimID", id.Valid())
}

// PlanBinding is an opaque private binding over an already resolved effective
// execution plan or immutable references sufficient for exact replay. This
// package does not select the derivation algorithm.
type PlanBinding struct {
	ref opaqueRef
}

func NewPlanBinding(value []byte) (PlanBinding, error) {
	ref, err := newOpaqueRef(value, ErrInvalidPlanBinding)
	if err != nil {
		return PlanBinding{}, err
	}
	return PlanBinding{ref: ref}, nil
}

func (b PlanBinding) Valid() bool {
	return b.ref.valid()
}

func (b PlanBinding) Equal(other PlanBinding) bool {
	return b.ref.equal(other.ref)
}

func (b PlanBinding) clone() PlanBinding {
	return PlanBinding{ref: b.ref.clone()}
}

func (b PlanBinding) Format(state fmt.State, verb rune) {
	formatOpaque(state, "PlanBinding", b.Valid())
}

type EffectivePlanCategory uint8

const (
	EffectivePlanCategoryRequestSchemaOrVersion EffectivePlanCategory = iota + 1
	EffectivePlanCategoryExecutionMode
	EffectivePlanCategoryTimeoutSemantics
	EffectivePlanCategoryCPU
	EffectivePlanCategoryMemory
	EffectivePlanCategoryRuntimeProfile
	EffectivePlanCategoryArtifactIdentity
	EffectivePlanCategoryDerivationSpecIdentity
	EffectivePlanCategoryOutputIdentity
	EffectivePlanCategoryCommandAndArgv
	EffectivePlanCategoryEnvironmentAdditions
	EffectivePlanCategoryMounts
	EffectivePlanCategoryNetworkPosture
	EffectivePlanCategoryAuthorityHandoffApplicability
)

const effectivePlanCategoryCount = int(EffectivePlanCategoryAuthorityHandoffApplicability)

var allEffectivePlanCategories = [...]EffectivePlanCategory{
	EffectivePlanCategoryRequestSchemaOrVersion,
	EffectivePlanCategoryExecutionMode,
	EffectivePlanCategoryTimeoutSemantics,
	EffectivePlanCategoryCPU,
	EffectivePlanCategoryMemory,
	EffectivePlanCategoryRuntimeProfile,
	EffectivePlanCategoryArtifactIdentity,
	EffectivePlanCategoryDerivationSpecIdentity,
	EffectivePlanCategoryOutputIdentity,
	EffectivePlanCategoryCommandAndArgv,
	EffectivePlanCategoryEnvironmentAdditions,
	EffectivePlanCategoryMounts,
	EffectivePlanCategoryNetworkPosture,
	EffectivePlanCategoryAuthorityHandoffApplicability,
}

func AllEffectivePlanCategories() []EffectivePlanCategory {
	categories := make([]EffectivePlanCategory, len(allEffectivePlanCategories))
	copy(categories, allEffectivePlanCategories[:])
	return categories
}

func (c EffectivePlanCategory) valid() bool {
	return c >= EffectivePlanCategoryRequestSchemaOrVersion &&
		c <= EffectivePlanCategoryAuthorityHandoffApplicability
}

type EffectivePlanResolution uint8

const (
	EffectivePlanResolutionInvalid EffectivePlanResolution = iota
	EffectivePlanResolved
	EffectivePlanExplicitlyInapplicable
)

type EffectivePlanCategoryCompleteness struct {
	category                    EffectivePlanCategory
	resolution                  EffectivePlanResolution
	outputInapplicablePermitted bool
}

func ResolvedCategory(category EffectivePlanCategory) (EffectivePlanCategoryCompleteness, error) {
	if !category.valid() {
		return EffectivePlanCategoryCompleteness{}, ErrInvalidEffectivePlanCategory
	}
	return EffectivePlanCategoryCompleteness{
		category:   category,
		resolution: EffectivePlanResolved,
	}, nil
}

func ExplicitlyInapplicableCategory(category EffectivePlanCategory) (EffectivePlanCategoryCompleteness, error) {
	if !category.valid() {
		return EffectivePlanCategoryCompleteness{}, ErrInvalidEffectivePlanCategory
	}
	if category != EffectivePlanCategoryAuthorityHandoffApplicability {
		return EffectivePlanCategoryCompleteness{}, ErrInapplicableEffectivePlanCategory
	}
	return EffectivePlanCategoryCompleteness{
		category:   category,
		resolution: EffectivePlanExplicitlyInapplicable,
	}, nil
}

func OutputIdentityExplicitlyInapplicableForPermittedExecutionKind() EffectivePlanCategoryCompleteness {
	return EffectivePlanCategoryCompleteness{
		category:                    EffectivePlanCategoryOutputIdentity,
		resolution:                  EffectivePlanExplicitlyInapplicable,
		outputInapplicablePermitted: true,
	}
}

func (c EffectivePlanCategoryCompleteness) valid() bool {
	return c.category.valid() && c.resolution != EffectivePlanResolutionInvalid
}

// EffectivePlanWitness proves category completeness only. It stores no
// execution values, caller request bytes, environment values, command material,
// mounts, or mutable caller-owned maps. Empty argv additions, environment additions, and mounts are represented by the corresponding resolved categories.
type EffectivePlanWitness struct {
	resolutions [effectivePlanCategoryCount]EffectivePlanResolution
	valid       bool
}

func NewEffectivePlanWitness(categories ...EffectivePlanCategoryCompleteness) (EffectivePlanWitness, error) {
	var seen [effectivePlanCategoryCount]bool
	var resolutions [effectivePlanCategoryCount]EffectivePlanResolution

	for _, category := range categories {
		if !category.valid() {
			return EffectivePlanWitness{}, ErrInvalidEffectivePlanWitness
		}
		index := int(category.category) - 1
		if seen[index] {
			return EffectivePlanWitness{}, ErrDuplicateEffectivePlanCategory
		}
		if !categoryResolutionAllowed(category) {
			return EffectivePlanWitness{}, ErrInapplicableEffectivePlanCategory
		}
		seen[index] = true
		resolutions[index] = category.resolution
	}

	for _, category := range allEffectivePlanCategories {
		index := int(category) - 1
		if !seen[index] {
			return EffectivePlanWitness{}, ErrMissingEffectivePlanCategory
		}
	}

	return EffectivePlanWitness{
		resolutions: resolutions,
		valid:       true,
	}, nil
}

func categoryResolutionAllowed(category EffectivePlanCategoryCompleteness) bool {
	if category.resolution == EffectivePlanResolved {
		return true
	}
	if category.resolution != EffectivePlanExplicitlyInapplicable {
		return false
	}
	switch category.category {
	case EffectivePlanCategoryOutputIdentity:
		return category.outputInapplicablePermitted
	case EffectivePlanCategoryAuthorityHandoffApplicability:
		return true
	default:
		return false
	}
}

func (w EffectivePlanWitness) Valid() bool {
	if !w.valid {
		return false
	}
	for _, category := range allEffectivePlanCategories {
		resolution := w.resolutions[int(category)-1]
		if resolution == EffectivePlanResolutionInvalid {
			return false
		}
	}
	return true
}

func (w EffectivePlanWitness) CategoryCount() int {
	if !w.Valid() {
		return 0
	}
	return len(allEffectivePlanCategories)
}

func (w EffectivePlanWitness) Resolution(category EffectivePlanCategory) (EffectivePlanResolution, error) {
	if !w.Valid() || !category.valid() {
		return EffectivePlanResolutionInvalid, ErrInvalidEffectivePlanWitness
	}
	return w.resolutions[int(category)-1], nil
}

func (w EffectivePlanWitness) Format(state fmt.State, verb rune) {
	formatOpaque(state, "EffectivePlanWitness", w.Valid())
}

// BoundPlan binds an opaque effective-plan binding to the completeness witness
// required before any effect-capable assignment.
type BoundPlan struct {
	binding PlanBinding
	witness EffectivePlanWitness
}

func NewBoundPlan(binding PlanBinding, witness EffectivePlanWitness) (BoundPlan, error) {
	if !binding.Valid() || !witness.Valid() {
		return BoundPlan{}, ErrInvalidBoundPlan
	}
	return BoundPlan{
		binding: binding,
		witness: witness,
	}, nil
}

func (p BoundPlan) Valid() bool {
	return p.binding.Valid() && p.witness.Valid()
}

func (p BoundPlan) Binding() PlanBinding {
	if !p.Valid() {
		return PlanBinding{}
	}
	return p.binding
}

func (p BoundPlan) Witness() EffectivePlanWitness {
	if !p.Valid() {
		return EffectivePlanWitness{}
	}
	return p.witness
}

func (p BoundPlan) EqualBinding(binding PlanBinding) bool {
	return p.Valid() && binding.Valid() && p.binding.Equal(binding)
}

func (p BoundPlan) clone() BoundPlan {
	return BoundPlan{
		binding: p.binding.clone(),
		witness: p.witness,
	}
}

func (p BoundPlan) Format(state fmt.State, verb rune) {
	formatOpaque(state, "BoundPlan", p.Valid())
}

// RunRef is an opaque ES-assigned execution reference. This model does not
// define its format, generation strategy, scheduler identity, or provider
// lookup mapping.
type RunRef struct {
	ref opaqueRef
}

func NewRunRef(value []byte) (RunRef, error) {
	ref, err := newOpaqueRef(value, ErrInvalidRunRef)
	if err != nil {
		return RunRef{}, err
	}
	return RunRef{ref: ref}, nil
}

func (r RunRef) Valid() bool {
	return r.ref.valid()
}

func (r RunRef) Equal(other RunRef) bool {
	return r.ref.equal(other.ref)
}

func (r RunRef) clone() RunRef {
	return RunRef{ref: r.ref.clone()}
}

func (r RunRef) Format(state fmt.State, verb rune) {
	formatOpaque(state, "RunRef", r.Valid())
}

// ReceiptRef is an opaque bounded submit-receipt identity or binding. It is
// required for accepted and recovered-accepted outcomes.
type ReceiptRef struct {
	ref opaqueRef
}

func NewReceiptRef(value []byte) (ReceiptRef, error) {
	ref, err := newOpaqueRef(value, ErrInvalidReceiptRef)
	if err != nil {
		return ReceiptRef{}, err
	}
	return ReceiptRef{ref: ref}, nil
}

func (r ReceiptRef) Valid() bool {
	return r.ref.valid()
}

func (r ReceiptRef) Equal(other ReceiptRef) bool {
	return r.ref.equal(other.ref)
}

func (r ReceiptRef) clone() ReceiptRef {
	return ReceiptRef{ref: r.ref.clone()}
}

func (r ReceiptRef) Format(state fmt.State, verb rune) {
	formatOpaque(state, "ReceiptRef", r.Valid())
}

type Kind uint8

const (
	KindInvalid Kind = iota
	KindPendingBeforeAssignment
	KindAmbiguousBeforeAssignment
	KindEffectCapableAssigned
	KindPendingAfterAssignment
	KindAmbiguousAfterAssignment
	KindAccepted
	KindProvablyNotAcceptedAfterAssignment
	KindRecoveredAccepted
	KindExactReplay
	KindConflict
	KindUnauthorized
	KindExpiredUnavailable
)

type RunRefDisclosurePolicy uint8

const (
	RunRefDisclosureForbidden RunRefDisclosurePolicy = iota
	RunRefDisclosureRequiredForSameAuthorizedCaller
	RunRefDisclosureOpenForLaterTransportContract
)

type ClaimPhase interface {
	reliableSubmitObservation()
	reliableSubmitPhase()
	Kind() Kind
	Valid() bool
	ClaimID() (ClaimID, bool)
	BoundPlan() (BoundPlan, bool)
	HasAssignedRunRef() bool
	AssignedRunRef() (RunRef, bool)
	ReceiptRef() (ReceiptRef, bool)
	SameCallerRunRefDisclosure() RunRefDisclosurePolicy
	AcceptedSubmissionReferenceAvailable() bool
}

type PreAssignmentPhase interface {
	ClaimPhase
	reliableSubmitPreAssignment()
}

type AssignedRunPhase interface {
	ClaimPhase
	reliableSubmitAssignedRun()
}

type ProviderOutcomeCandidatePhase interface {
	AssignedRunPhase
	reliableSubmitProviderOutcomeCandidate()
}

func normalizeClaimPhase(phase ClaimPhase, invalid error) (ClaimPhase, error) {
	switch current := phase.(type) {
	case PendingBeforeAssignment:
		snapshot := current.clone()
		if !snapshot.Valid() {
			return nil, invalid
		}
		return snapshot, nil
	case AmbiguousBeforeAssignment:
		snapshot := current.clone()
		if !snapshot.Valid() {
			return nil, invalid
		}
		return snapshot, nil
	case EffectCapableAssigned:
		snapshot := current.clone()
		if !snapshot.Valid() {
			return nil, invalid
		}
		return snapshot, nil
	case PendingAfterAssignment:
		snapshot := current.clone()
		if !snapshot.Valid() {
			return nil, invalid
		}
		return snapshot, nil
	case AmbiguousAfterAssignment:
		snapshot := current.clone()
		if !snapshot.Valid() {
			return nil, invalid
		}
		return snapshot, nil
	case Accepted:
		snapshot := current.clone()
		if !snapshot.Valid() {
			return nil, invalid
		}
		return snapshot, nil
	case ProvablyNotAcceptedAfterAssignment:
		snapshot := current.clone()
		if !snapshot.Valid() {
			return nil, invalid
		}
		return snapshot, nil
	default:
		return nil, invalid
	}
}

func normalizePreAssignmentPhase(phase PreAssignmentPhase) (claimCore, error) {
	normalized, err := normalizeClaimPhase(phase, ErrInvalidPhase)
	if err != nil {
		return claimCore{}, err
	}
	switch current := normalized.(type) {
	case PendingBeforeAssignment:
		return current.core, nil
	case AmbiguousBeforeAssignment:
		return current.core, nil
	default:
		return claimCore{}, ErrInvalidPhase
	}
}

func normalizeAssignedRunPhase(phase AssignedRunPhase) (assignedCore, error) {
	normalized, err := normalizeClaimPhase(phase, ErrInvalidPhase)
	if err != nil {
		return assignedCore{}, err
	}
	switch current := normalized.(type) {
	case EffectCapableAssigned:
		return current.core, nil
	case PendingAfterAssignment:
		return current.core, nil
	case AmbiguousAfterAssignment:
		return current.core, nil
	case Accepted:
		return current.core, nil
	case ProvablyNotAcceptedAfterAssignment:
		return current.core, nil
	default:
		return assignedCore{}, ErrInvalidPhase
	}
}

func normalizeProviderOutcomeCandidatePhase(phase ProviderOutcomeCandidatePhase, invalid error) (assignedCore, error) {
	normalized, err := normalizeClaimPhase(phase, invalid)
	if err != nil {
		return assignedCore{}, err
	}
	switch current := normalized.(type) {
	case EffectCapableAssigned:
		return current.core, nil
	case PendingAfterAssignment:
		return current.core, nil
	case AmbiguousAfterAssignment:
		return current.core, nil
	default:
		return assignedCore{}, invalid
	}
}

type claimCore struct {
	claim ClaimID
	plan  BoundPlan
}

func newClaimCore(claim ClaimID, plan BoundPlan) (claimCore, error) {
	if !claim.Valid() || !plan.Valid() {
		return claimCore{}, ErrInvalidPhase
	}
	return claimCore{
		claim: claim,
		plan:  plan,
	}, nil
}

func (c claimCore) valid() bool {
	return c.claim.Valid() && c.plan.Valid()
}

func (c claimCore) claimID() (ClaimID, bool) {
	if !c.valid() {
		return ClaimID{}, false
	}
	return c.claim, true
}

func (c claimCore) boundPlan() (BoundPlan, bool) {
	if !c.valid() {
		return BoundPlan{}, false
	}
	return c.plan, true
}

func (c claimCore) clone() claimCore {
	return claimCore{
		claim: c.claim.clone(),
		plan:  c.plan.clone(),
	}
}

type assignedCore struct {
	claimCore claimCore
	run       RunRef
}

func newAssignedCore(core claimCore, run RunRef) (assignedCore, error) {
	if !core.valid() || !run.Valid() {
		return assignedCore{}, ErrInvalidPhase
	}
	return assignedCore{
		claimCore: core,
		run:       run,
	}, nil
}

func (c assignedCore) valid() bool {
	return c.claimCore.valid() && c.run.Valid()
}

func (c assignedCore) claimID() (ClaimID, bool) {
	if !c.valid() {
		return ClaimID{}, false
	}
	return c.claimCore.claimID()
}

func (c assignedCore) boundPlan() (BoundPlan, bool) {
	if !c.valid() {
		return BoundPlan{}, false
	}
	return c.claimCore.boundPlan()
}

func (c assignedCore) assignedRunRef() (RunRef, bool) {
	if !c.valid() {
		return RunRef{}, false
	}
	return c.run, true
}

func (c assignedCore) clone() assignedCore {
	return assignedCore{
		claimCore: c.claimCore.clone(),
		run:       c.run.clone(),
	}
}

type PendingBeforeAssignment struct {
	core claimCore
}

func NewPendingBeforeAssignment(claim ClaimID, plan BoundPlan) (PendingBeforeAssignment, error) {
	core, err := newClaimCore(claim, plan)
	if err != nil {
		return PendingBeforeAssignment{}, err
	}
	return PendingBeforeAssignment{core: core}, nil
}

func (p PendingBeforeAssignment) reliableSubmitObservation()   {}
func (p PendingBeforeAssignment) reliableSubmitPhase()         {}
func (p PendingBeforeAssignment) reliableSubmitPreAssignment() {}
func (p PendingBeforeAssignment) Kind() Kind {
	if !p.Valid() {
		return KindInvalid
	}
	return KindPendingBeforeAssignment
}
func (p PendingBeforeAssignment) Valid() bool { return p.core.valid() }
func (p PendingBeforeAssignment) ClaimID() (ClaimID, bool) {
	return p.core.claimID()
}
func (p PendingBeforeAssignment) BoundPlan() (BoundPlan, bool) {
	return p.core.boundPlan()
}
func (p PendingBeforeAssignment) HasAssignedRunRef() bool { return false }
func (p PendingBeforeAssignment) AssignedRunRef() (RunRef, bool) {
	return RunRef{}, false
}
func (p PendingBeforeAssignment) ReceiptRef() (ReceiptRef, bool) {
	return ReceiptRef{}, false
}
func (p PendingBeforeAssignment) SameCallerRunRefDisclosure() RunRefDisclosurePolicy {
	return RunRefDisclosureForbidden
}
func (p PendingBeforeAssignment) AcceptedSubmissionReferenceAvailable() bool {
	return false
}

func (p PendingBeforeAssignment) clone() PendingBeforeAssignment {
	return PendingBeforeAssignment{core: p.core.clone()}
}

func (p PendingBeforeAssignment) Format(state fmt.State, verb rune) {
	formatOpaque(state, "PendingBeforeAssignment", p.Valid())
}

type AmbiguousBeforeAssignment struct {
	core claimCore
}

func NewAmbiguousBeforeAssignment(claim ClaimID, plan BoundPlan) (AmbiguousBeforeAssignment, error) {
	core, err := newClaimCore(claim, plan)
	if err != nil {
		return AmbiguousBeforeAssignment{}, err
	}
	return AmbiguousBeforeAssignment{core: core}, nil
}

func (a AmbiguousBeforeAssignment) reliableSubmitObservation()   {}
func (a AmbiguousBeforeAssignment) reliableSubmitPhase()         {}
func (a AmbiguousBeforeAssignment) reliableSubmitPreAssignment() {}
func (a AmbiguousBeforeAssignment) Kind() Kind {
	if !a.Valid() {
		return KindInvalid
	}
	return KindAmbiguousBeforeAssignment
}
func (a AmbiguousBeforeAssignment) Valid() bool { return a.core.valid() }
func (a AmbiguousBeforeAssignment) ClaimID() (ClaimID, bool) {
	return a.core.claimID()
}
func (a AmbiguousBeforeAssignment) BoundPlan() (BoundPlan, bool) {
	return a.core.boundPlan()
}
func (a AmbiguousBeforeAssignment) HasAssignedRunRef() bool { return false }
func (a AmbiguousBeforeAssignment) AssignedRunRef() (RunRef, bool) {
	return RunRef{}, false
}
func (a AmbiguousBeforeAssignment) ReceiptRef() (ReceiptRef, bool) {
	return ReceiptRef{}, false
}
func (a AmbiguousBeforeAssignment) SameCallerRunRefDisclosure() RunRefDisclosurePolicy {
	return RunRefDisclosureForbidden
}
func (a AmbiguousBeforeAssignment) AcceptedSubmissionReferenceAvailable() bool {
	return false
}

func (a AmbiguousBeforeAssignment) clone() AmbiguousBeforeAssignment {
	return AmbiguousBeforeAssignment{core: a.core.clone()}
}

func (a AmbiguousBeforeAssignment) Format(state fmt.State, verb rune) {
	formatOpaque(state, "AmbiguousBeforeAssignment", a.Valid())
}

type EffectCapableAssigned struct {
	core assignedCore
}

func AssignRun(phase PreAssignmentPhase, run RunRef) (EffectCapableAssigned, error) {
	if !run.Valid() {
		return EffectCapableAssigned{}, ErrInvalidPhase
	}

	core, err := normalizePreAssignmentPhase(phase)
	if err != nil {
		return EffectCapableAssigned{}, err
	}

	assigned, err := newAssignedCore(core, run.clone())
	if err != nil {
		return EffectCapableAssigned{}, err
	}
	return EffectCapableAssigned{core: assigned}, nil
}

func ValidateRunAssignment(phase AssignedRunPhase, run RunRef) error {
	if !run.Valid() {
		return ErrInvalidPhase
	}
	assigned, err := normalizeAssignedRunPhase(phase)
	if err != nil {
		return err
	}
	if assigned.run.Equal(run) {
		return nil
	}
	return ErrRunAssignmentMismatch
}

func ValidatePlanBinding(phase ClaimPhase, binding PlanBinding) error {
	if !binding.Valid() {
		return ErrInvalidPhase
	}
	normalized, err := normalizeClaimPhase(phase, ErrInvalidPhase)
	if err != nil {
		return err
	}
	plan, ok := normalized.BoundPlan()
	if !ok || !plan.Valid() {
		return ErrInvalidPhase
	}
	if plan.EqualBinding(binding) {
		return nil
	}
	return ErrPlanBindingConflict
}

func (e EffectCapableAssigned) reliableSubmitObservation()              {}
func (e EffectCapableAssigned) reliableSubmitPhase()                    {}
func (e EffectCapableAssigned) reliableSubmitAssignedRun()              {}
func (e EffectCapableAssigned) reliableSubmitProviderOutcomeCandidate() {}
func (e EffectCapableAssigned) Kind() Kind {
	if !e.Valid() {
		return KindInvalid
	}
	return KindEffectCapableAssigned
}
func (e EffectCapableAssigned) Valid() bool { return e.core.valid() }
func (e EffectCapableAssigned) ClaimID() (ClaimID, bool) {
	return e.core.claimID()
}
func (e EffectCapableAssigned) BoundPlan() (BoundPlan, bool) {
	return e.core.boundPlan()
}
func (e EffectCapableAssigned) HasAssignedRunRef() bool { return e.Valid() }
func (e EffectCapableAssigned) AssignedRunRef() (RunRef, bool) {
	return e.core.assignedRunRef()
}
func (e EffectCapableAssigned) ReceiptRef() (ReceiptRef, bool) {
	return ReceiptRef{}, false
}
func (e EffectCapableAssigned) SameCallerRunRefDisclosure() RunRefDisclosurePolicy {
	if !e.Valid() {
		return RunRefDisclosureForbidden
	}
	return RunRefDisclosureOpenForLaterTransportContract
}
func (e EffectCapableAssigned) AcceptedSubmissionReferenceAvailable() bool {
	return false
}

func (e EffectCapableAssigned) clone() EffectCapableAssigned {
	return EffectCapableAssigned{core: e.core.clone()}
}

func (e EffectCapableAssigned) Format(state fmt.State, verb rune) {
	formatOpaque(state, "EffectCapableAssigned", e.Valid())
}

type PendingAfterAssignment struct {
	core assignedCore
}

func NewPendingAfterAssignment(assigned EffectCapableAssigned) (PendingAfterAssignment, error) {
	if !assigned.Valid() {
		return PendingAfterAssignment{}, ErrInvalidPhase
	}
	return PendingAfterAssignment{core: assigned.core}, nil
}

func (p PendingAfterAssignment) reliableSubmitObservation()              {}
func (p PendingAfterAssignment) reliableSubmitPhase()                    {}
func (p PendingAfterAssignment) reliableSubmitAssignedRun()              {}
func (p PendingAfterAssignment) reliableSubmitProviderOutcomeCandidate() {}
func (p PendingAfterAssignment) Kind() Kind {
	if !p.Valid() {
		return KindInvalid
	}
	return KindPendingAfterAssignment
}
func (p PendingAfterAssignment) Valid() bool { return p.core.valid() }
func (p PendingAfterAssignment) ClaimID() (ClaimID, bool) {
	return p.core.claimID()
}
func (p PendingAfterAssignment) BoundPlan() (BoundPlan, bool) {
	return p.core.boundPlan()
}
func (p PendingAfterAssignment) HasAssignedRunRef() bool { return p.Valid() }
func (p PendingAfterAssignment) AssignedRunRef() (RunRef, bool) {
	return p.core.assignedRunRef()
}
func (p PendingAfterAssignment) ReceiptRef() (ReceiptRef, bool) {
	return ReceiptRef{}, false
}
func (p PendingAfterAssignment) SameCallerRunRefDisclosure() RunRefDisclosurePolicy {
	if !p.Valid() {
		return RunRefDisclosureForbidden
	}
	return RunRefDisclosureRequiredForSameAuthorizedCaller
}
func (p PendingAfterAssignment) AcceptedSubmissionReferenceAvailable() bool {
	return false
}

func (p PendingAfterAssignment) clone() PendingAfterAssignment {
	return PendingAfterAssignment{core: p.core.clone()}
}

func (p PendingAfterAssignment) Format(state fmt.State, verb rune) {
	formatOpaque(state, "PendingAfterAssignment", p.Valid())
}

type AmbiguousAfterAssignment struct {
	core assignedCore
}

func NewAmbiguousAfterAssignment(assigned EffectCapableAssigned) (AmbiguousAfterAssignment, error) {
	if !assigned.Valid() {
		return AmbiguousAfterAssignment{}, ErrInvalidPhase
	}
	return AmbiguousAfterAssignment{core: assigned.core}, nil
}

func (a AmbiguousAfterAssignment) reliableSubmitObservation()              {}
func (a AmbiguousAfterAssignment) reliableSubmitPhase()                    {}
func (a AmbiguousAfterAssignment) reliableSubmitAssignedRun()              {}
func (a AmbiguousAfterAssignment) reliableSubmitProviderOutcomeCandidate() {}
func (a AmbiguousAfterAssignment) Kind() Kind {
	if !a.Valid() {
		return KindInvalid
	}
	return KindAmbiguousAfterAssignment
}
func (a AmbiguousAfterAssignment) Valid() bool { return a.core.valid() }
func (a AmbiguousAfterAssignment) ClaimID() (ClaimID, bool) {
	return a.core.claimID()
}
func (a AmbiguousAfterAssignment) BoundPlan() (BoundPlan, bool) {
	return a.core.boundPlan()
}
func (a AmbiguousAfterAssignment) HasAssignedRunRef() bool { return a.Valid() }
func (a AmbiguousAfterAssignment) AssignedRunRef() (RunRef, bool) {
	return a.core.assignedRunRef()
}
func (a AmbiguousAfterAssignment) ReceiptRef() (ReceiptRef, bool) {
	return ReceiptRef{}, false
}
func (a AmbiguousAfterAssignment) SameCallerRunRefDisclosure() RunRefDisclosurePolicy {
	if !a.Valid() {
		return RunRefDisclosureForbidden
	}
	return RunRefDisclosureRequiredForSameAuthorizedCaller
}
func (a AmbiguousAfterAssignment) AcceptedSubmissionReferenceAvailable() bool {
	return false
}

func (a AmbiguousAfterAssignment) clone() AmbiguousAfterAssignment {
	return AmbiguousAfterAssignment{core: a.core.clone()}
}

func (a AmbiguousAfterAssignment) Format(state fmt.State, verb rune) {
	formatOpaque(state, "AmbiguousAfterAssignment", a.Valid())
}

type Accepted struct {
	core    assignedCore
	receipt ReceiptRef
}

func NewAccepted(phase ProviderOutcomeCandidatePhase, receipt ReceiptRef) (Accepted, error) {
	if !receipt.Valid() {
		return Accepted{}, ErrInvalidPhase
	}
	core, err := providerOutcomeCandidateCore(phase)
	if err != nil {
		return Accepted{}, err
	}
	return Accepted{
		core:    core,
		receipt: receipt.clone(),
	}, nil
}

func providerOutcomeCandidateCore(phase ProviderOutcomeCandidatePhase) (assignedCore, error) {
	return normalizeProviderOutcomeCandidatePhase(phase, ErrInvalidProviderOutcomeCandidatePhase)
}

func (a Accepted) reliableSubmitObservation() {}
func (a Accepted) reliableSubmitPhase()       {}
func (a Accepted) reliableSubmitAssignedRun() {}
func (a Accepted) Kind() Kind {
	if !a.Valid() {
		return KindInvalid
	}
	return KindAccepted
}
func (a Accepted) Valid() bool { return a.core.valid() && a.receipt.Valid() }
func (a Accepted) ClaimID() (ClaimID, bool) {
	return a.core.claimID()
}
func (a Accepted) BoundPlan() (BoundPlan, bool) {
	return a.core.boundPlan()
}
func (a Accepted) HasAssignedRunRef() bool { return a.Valid() }
func (a Accepted) AssignedRunRef() (RunRef, bool) {
	return a.core.assignedRunRef()
}
func (a Accepted) ReceiptRef() (ReceiptRef, bool) {
	if !a.Valid() {
		return ReceiptRef{}, false
	}
	return a.receipt, true
}
func (a Accepted) SameCallerRunRefDisclosure() RunRefDisclosurePolicy {
	if !a.Valid() {
		return RunRefDisclosureForbidden
	}
	return RunRefDisclosureRequiredForSameAuthorizedCaller
}
func (a Accepted) AcceptedSubmissionReferenceAvailable() bool {
	return a.Valid()
}

func (a Accepted) clone() Accepted {
	return Accepted{
		core:    a.core.clone(),
		receipt: a.receipt.clone(),
	}
}

func (a Accepted) Format(state fmt.State, verb rune) {
	formatOpaque(state, "Accepted", a.Valid())
}

type ProvablyNotAcceptedAfterAssignment struct {
	core assignedCore
}

func NewProvablyNotAcceptedAfterAssignment(phase ProviderOutcomeCandidatePhase) (ProvablyNotAcceptedAfterAssignment, error) {
	core, err := providerOutcomeCandidateCore(phase)
	if err != nil {
		return ProvablyNotAcceptedAfterAssignment{}, err
	}
	return ProvablyNotAcceptedAfterAssignment{core: core}, nil
}

func (p ProvablyNotAcceptedAfterAssignment) reliableSubmitObservation() {}
func (p ProvablyNotAcceptedAfterAssignment) reliableSubmitPhase()       {}
func (p ProvablyNotAcceptedAfterAssignment) reliableSubmitAssignedRun() {}
func (p ProvablyNotAcceptedAfterAssignment) Kind() Kind {
	if !p.Valid() {
		return KindInvalid
	}
	return KindProvablyNotAcceptedAfterAssignment
}
func (p ProvablyNotAcceptedAfterAssignment) Valid() bool { return p.core.valid() }
func (p ProvablyNotAcceptedAfterAssignment) ClaimID() (ClaimID, bool) {
	return p.core.claimID()
}
func (p ProvablyNotAcceptedAfterAssignment) BoundPlan() (BoundPlan, bool) {
	return p.core.boundPlan()
}
func (p ProvablyNotAcceptedAfterAssignment) HasAssignedRunRef() bool { return p.Valid() }
func (p ProvablyNotAcceptedAfterAssignment) AssignedRunRef() (RunRef, bool) {
	return p.core.assignedRunRef()
}
func (p ProvablyNotAcceptedAfterAssignment) ReceiptRef() (ReceiptRef, bool) {
	return ReceiptRef{}, false
}
func (p ProvablyNotAcceptedAfterAssignment) SameCallerRunRefDisclosure() RunRefDisclosurePolicy {
	if !p.Valid() {
		return RunRefDisclosureForbidden
	}
	return RunRefDisclosureOpenForLaterTransportContract
}
func (p ProvablyNotAcceptedAfterAssignment) AcceptedSubmissionReferenceAvailable() bool {
	return false
}

func (p ProvablyNotAcceptedAfterAssignment) clone() ProvablyNotAcceptedAfterAssignment {
	return ProvablyNotAcceptedAfterAssignment{core: p.core.clone()}
}

func (p ProvablyNotAcceptedAfterAssignment) Format(state fmt.State, verb rune) {
	formatOpaque(state, "ProvablyNotAcceptedAfterAssignment", p.Valid())
}

type RecoveredAccepted struct {
	accepted Accepted
}

func NewRecoveredAccepted(accepted Accepted) (RecoveredAccepted, error) {
	if !accepted.Valid() {
		return RecoveredAccepted{}, ErrInvalidRecoveredAccepted
	}
	return RecoveredAccepted{accepted: accepted.clone()}, nil
}

func (r RecoveredAccepted) reliableSubmitObservation() {}
func (r RecoveredAccepted) Kind() Kind {
	if !r.Valid() {
		return KindInvalid
	}
	return KindRecoveredAccepted
}
func (r RecoveredAccepted) Valid() bool { return r.accepted.Valid() }
func (r RecoveredAccepted) ClaimID() (ClaimID, bool) {
	return r.accepted.ClaimID()
}
func (r RecoveredAccepted) HasAssignedRunRef() bool { return r.Valid() }
func (r RecoveredAccepted) AssignedRunRef() (RunRef, bool) {
	return r.accepted.AssignedRunRef()
}
func (r RecoveredAccepted) ReceiptRef() (ReceiptRef, bool) {
	return r.accepted.ReceiptRef()
}
func (r RecoveredAccepted) SameCallerRunRefDisclosure() RunRefDisclosurePolicy {
	if !r.Valid() {
		return RunRefDisclosureForbidden
	}
	return RunRefDisclosureRequiredForSameAuthorizedCaller
}
func (r RecoveredAccepted) AcceptedSubmissionReferenceAvailable() bool {
	return r.Valid()
}

func (r RecoveredAccepted) Format(state fmt.State, verb rune) {
	formatOpaque(state, "RecoveredAccepted", r.Valid())
}

type exactReplayPhaseSnapshot struct {
	kind            Kind
	pendingBefore   PendingBeforeAssignment
	ambiguousBefore AmbiguousBeforeAssignment
	assigned        EffectCapableAssigned
	pendingAfter    PendingAfterAssignment
	ambiguousAfter  AmbiguousAfterAssignment
	accepted        Accepted
	notAccepted     ProvablyNotAcceptedAfterAssignment
}

func newExactReplayPhaseSnapshot(phase ClaimPhase) (exactReplayPhaseSnapshot, error) {
	normalized, err := normalizeClaimPhase(phase, ErrInvalidReplay)
	if err != nil {
		return exactReplayPhaseSnapshot{}, err
	}
	switch current := normalized.(type) {
	case PendingBeforeAssignment:
		return exactReplayPhaseSnapshot{kind: KindPendingBeforeAssignment, pendingBefore: current}, nil
	case AmbiguousBeforeAssignment:
		return exactReplayPhaseSnapshot{kind: KindAmbiguousBeforeAssignment, ambiguousBefore: current}, nil
	case EffectCapableAssigned:
		return exactReplayPhaseSnapshot{kind: KindEffectCapableAssigned, assigned: current}, nil
	case PendingAfterAssignment:
		return exactReplayPhaseSnapshot{kind: KindPendingAfterAssignment, pendingAfter: current}, nil
	case AmbiguousAfterAssignment:
		return exactReplayPhaseSnapshot{kind: KindAmbiguousAfterAssignment, ambiguousAfter: current}, nil
	case Accepted:
		return exactReplayPhaseSnapshot{kind: KindAccepted, accepted: current}, nil
	case ProvablyNotAcceptedAfterAssignment:
		return exactReplayPhaseSnapshot{kind: KindProvablyNotAcceptedAfterAssignment, notAccepted: current}, nil
	default:
		return exactReplayPhaseSnapshot{}, ErrInvalidReplay
	}
}

func (s exactReplayPhaseSnapshot) validPhase() (ClaimPhase, bool) {
	switch s.kind {
	case KindPendingBeforeAssignment:
		if !s.pendingBefore.Valid() {
			return nil, false
		}
		return s.pendingBefore, true
	case KindAmbiguousBeforeAssignment:
		if !s.ambiguousBefore.Valid() {
			return nil, false
		}
		return s.ambiguousBefore, true
	case KindEffectCapableAssigned:
		if !s.assigned.Valid() {
			return nil, false
		}
		return s.assigned, true
	case KindPendingAfterAssignment:
		if !s.pendingAfter.Valid() {
			return nil, false
		}
		return s.pendingAfter, true
	case KindAmbiguousAfterAssignment:
		if !s.ambiguousAfter.Valid() {
			return nil, false
		}
		return s.ambiguousAfter, true
	case KindAccepted:
		if !s.accepted.Valid() {
			return nil, false
		}
		return s.accepted, true
	case KindProvablyNotAcceptedAfterAssignment:
		if !s.notAccepted.Valid() {
			return nil, false
		}
		return s.notAccepted, true
	default:
		return nil, false
	}
}

type ExactReplay struct {
	underlying exactReplayPhaseSnapshot
}

func NewExactReplay(phase ClaimPhase) (ExactReplay, error) {
	snapshot, err := newExactReplayPhaseSnapshot(phase)
	if err != nil {
		return ExactReplay{}, err
	}
	return ExactReplay{underlying: snapshot}, nil
}

func (r ExactReplay) reliableSubmitObservation() {}
func (r ExactReplay) Kind() Kind {
	if !r.Valid() {
		return KindInvalid
	}
	return KindExactReplay
}
func (r ExactReplay) Valid() bool {
	_, ok := r.underlying.validPhase()
	return ok
}
func (r ExactReplay) UnderlyingKind() Kind {
	if !r.Valid() {
		return KindInvalid
	}
	return r.underlying.kind
}
func (r ExactReplay) ClaimID() (ClaimID, bool) {
	phase, ok := r.underlying.validPhase()
	if !ok {
		return ClaimID{}, false
	}
	return phase.ClaimID()
}
func (r ExactReplay) HasAssignedRunRef() bool {
	phase, ok := r.underlying.validPhase()
	return ok && phase.HasAssignedRunRef()
}
func (r ExactReplay) AssignedRunRef() (RunRef, bool) {
	phase, ok := r.underlying.validPhase()
	if !ok {
		return RunRef{}, false
	}
	return phase.AssignedRunRef()
}
func (r ExactReplay) ReceiptRef() (ReceiptRef, bool) {
	phase, ok := r.underlying.validPhase()
	if !ok {
		return ReceiptRef{}, false
	}
	return phase.ReceiptRef()
}
func (r ExactReplay) SameCallerRunRefDisclosure() RunRefDisclosurePolicy {
	phase, ok := r.underlying.validPhase()
	if !ok {
		return RunRefDisclosureForbidden
	}
	return phase.SameCallerRunRefDisclosure()
}
func (r ExactReplay) AcceptedSubmissionReferenceAvailable() bool {
	phase, ok := r.underlying.validPhase()
	return ok && phase.AcceptedSubmissionReferenceAvailable()
}

func (r ExactReplay) Format(state fmt.State, verb rune) {
	formatOpaque(state, "ExactReplay", r.Valid())
}

type Conflict struct {
	valid bool
}

func NewConflict() (Conflict, error) {
	return Conflict{valid: true}, nil
}

func (c Conflict) reliableSubmitObservation() {}
func (c Conflict) Kind() Kind {
	if !c.Valid() {
		return KindInvalid
	}
	return KindConflict
}
func (c Conflict) Valid() bool { return c.valid }
func (c Conflict) ClaimID() (ClaimID, bool) {
	return ClaimID{}, false
}
func (c Conflict) HasAssignedRunRef() bool { return false }
func (c Conflict) AssignedRunRef() (RunRef, bool) {
	return RunRef{}, false
}
func (c Conflict) ReceiptRef() (ReceiptRef, bool) {
	return ReceiptRef{}, false
}
func (c Conflict) SameCallerRunRefDisclosure() RunRefDisclosurePolicy {
	return RunRefDisclosureForbidden
}
func (c Conflict) AcceptedSubmissionReferenceAvailable() bool {
	return false
}

func (c Conflict) Format(state fmt.State, verb rune) {
	formatOpaque(state, "Conflict", c.Valid())
}

type Unauthorized struct {
	valid bool
}

func NewUnauthorized() (Unauthorized, error) {
	return Unauthorized{valid: true}, nil
}

func (u Unauthorized) reliableSubmitObservation() {}
func (u Unauthorized) Kind() Kind {
	if !u.Valid() {
		return KindInvalid
	}
	return KindUnauthorized
}
func (u Unauthorized) Valid() bool { return u.valid }
func (u Unauthorized) ClaimID() (ClaimID, bool) {
	return ClaimID{}, false
}
func (u Unauthorized) HasAssignedRunRef() bool { return false }
func (u Unauthorized) AssignedRunRef() (RunRef, bool) {
	return RunRef{}, false
}
func (u Unauthorized) ReceiptRef() (ReceiptRef, bool) {
	return ReceiptRef{}, false
}
func (u Unauthorized) SameCallerRunRefDisclosure() RunRefDisclosurePolicy {
	return RunRefDisclosureForbidden
}
func (u Unauthorized) AcceptedSubmissionReferenceAvailable() bool {
	return false
}

func (u Unauthorized) Format(state fmt.State, verb rune) {
	formatOpaque(state, "Unauthorized", u.Valid())
}

type ExpiredUnavailable struct {
	valid bool
}

func NewExpiredUnavailable() (ExpiredUnavailable, error) {
	return ExpiredUnavailable{valid: true}, nil
}

func (e ExpiredUnavailable) reliableSubmitObservation() {}
func (e ExpiredUnavailable) Kind() Kind {
	if !e.Valid() {
		return KindInvalid
	}
	return KindExpiredUnavailable
}
func (e ExpiredUnavailable) Valid() bool { return e.valid }
func (e ExpiredUnavailable) ClaimID() (ClaimID, bool) {
	return ClaimID{}, false
}
func (e ExpiredUnavailable) HasAssignedRunRef() bool { return false }
func (e ExpiredUnavailable) AssignedRunRef() (RunRef, bool) {
	return RunRef{}, false
}
func (e ExpiredUnavailable) ReceiptRef() (ReceiptRef, bool) {
	return ReceiptRef{}, false
}
func (e ExpiredUnavailable) SameCallerRunRefDisclosure() RunRefDisclosurePolicy {
	return RunRefDisclosureForbidden
}
func (e ExpiredUnavailable) AcceptedSubmissionReferenceAvailable() bool {
	return false
}

func (e ExpiredUnavailable) Format(state fmt.State, verb rune) {
	formatOpaque(state, "ExpiredUnavailable", e.Valid())
}
