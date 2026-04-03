package admission

import signingv1 "execution-platform/legacy/contracts/signing/v1"

func cloneStringsPreserveShape(values []string) []string {
	if values == nil {
		return nil
	}
	return append([]string{}, values...)
}

func provenanceClaimsFromDTO(provenance Provenance) signingv1.ProvenanceClaims {
	decisions := make([]signingv1.PolicyDecisionEntry, 0, len(provenance.PolicyDecisions))
	for _, decision := range provenance.PolicyDecisions {
		decisions = append(decisions, signingv1.PolicyDecisionEntry{
			Rule:   decision.Rule,
			Result: decision.Result,
		})
	}

	return signingv1.ProvenanceClaims{
		ArtifactDigest:   provenance.ArtifactDigest,
		BuilderService:   provenance.BuilderService,
		InvokerService:   provenance.Invoker.Service,
		InvokerPrincipal: provenance.Invoker.Principal,
		PolicyDecisions:  decisions,
		BuildLogDigest:   provenance.BuildLogDigest,
	}
}

func derivationClaimsFromDTO(attestation DerivationAttestation) signingv1.DerivationAttestationClaims {
	return signingv1.DerivationAttestationClaims{
		Subject: signingv1.DerivationSubjectClaims{
			ArtifactDigest:       attestation.ArtifactDigest,
			DerivationSpecDigest: attestation.DerivationSpecDigest,
			OutputID:             attestation.OutputID,
		},
		Constraints: signingv1.DerivationConstraintsClaims{
			AllowedToolchains:      cloneStringsPreserveShape(attestation.Constraints.AllowedToolchains),
			ForbiddenToolchains:    cloneStringsPreserveShape(attestation.Constraints.ForbiddenToolchains),
			OS:                     attestation.Constraints.OS,
			Arch:                   attestation.Constraints.Arch,
			NetworkAccess:          attestation.Constraints.NetworkAccess,
			WritablePaths:          cloneStringsPreserveShape(attestation.Constraints.WritablePaths),
			ForbiddenPaths:         cloneStringsPreserveShape(attestation.Constraints.ForbiddenPaths),
			DeterminismExpectation: attestation.Constraints.DeterminismExpectation,
		},
		Policy: signingv1.DerivationPolicyClaims{
			Version:              attestation.PolicyVersion,
			ExpectedArtifactType: attestation.ExpectedArtifactType,
		},
	}
}

func workloadIdentityClaimsFromDTO(binding WorkloadIdentityBinding) signingv1.WorkloadIdentityBindingClaims {
	return signingv1.WorkloadIdentityBindingClaims{
		Subject: signingv1.WorkloadIdentitySubjectClaims{
			ArtifactClass:        binding.ArtifactClass,
			ArtifactDigest:       binding.ArtifactDigest,
			DerivationSpecDigest: binding.DerivationSpecDigest,
			OutputID:             binding.OutputID,
			PolicyVersion:        binding.PolicyVersion,
		},
		Descriptor: signingv1.WorkloadDescriptorClaims{
			WorkloadType:       binding.WorkloadType,
			ModulePath:         binding.ModulePath,
			ServiceName:        binding.ServiceName,
			TargetPlatform:     binding.TargetPlatform,
			Description:        binding.Description,
			WorkloadIdentityID: binding.WorkloadIdentityID,
		},
	}
}

func detachedEnvelopeFromDTO(info SignatureInfo) signingv1.DetachedEnvelope {
	return signingv1.DetachedEnvelope{
		PayloadDigest:    info.PayloadDigest,
		CanonicalSpecB64: info.CanonicalSpecB64,
		SignatureValue:   info.SignatureValue,
		KeyID:            info.KeyID,
		Algorithm:        info.Algorithm,
	}
}
