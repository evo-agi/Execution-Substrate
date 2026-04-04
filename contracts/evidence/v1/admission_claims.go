package evidencev1

type AdmissionClaims struct {
	Authorization AuthorizationClaims `json:"authorization"`
	Execution     ExecutionClaims     `json:"execution"`
}

type canonicalAdmissionClaims struct {
	Authorization canonicalAuthorizationClaims `json:"authorization"`
	Execution     canonicalExecutionClaims     `json:"execution"`
}

func (a AdmissionClaims) validate(artifactType string) error {
	if err := a.Authorization.validate(artifactType); err != nil {
		return err
	}
	if err := a.Execution.validate(); err != nil {
		return err
	}
	return nil
}

func (a AdmissionClaims) canonicalize() canonicalAdmissionClaims {
	return canonicalAdmissionClaims{
		Authorization: a.Authorization.canonicalize(),
		Execution:     a.Execution.canonicalize(),
	}
}
