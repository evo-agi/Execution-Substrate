package admission

// Regression test for RT74-2 (red-team report 19 on PR #74).
//
// Reliable submit keeps a caller's request next to the signed evidence it was
// admitted under and judges the pair again when it writes them to custody and
// when it reads them back. That second judgement must apply the caller
// declaration rule: a caller sets only the environment keys the signed
// artifact declares, and never a reserved key. On this path nothing else
// looks at the retained caller environment.

import (
	"encoding/json"
	"testing"

	evidencev1 "execution-substrate/internal/contracts/evidence/v1"
)

func TestOperationalRetainedRequestEnvIsJudgedByTheSignedDeclaration(t *testing.T) {
	f := makeOperationalFixture(t, "")
	original := operationalV2Original(t, f)

	var evidence evidencev1.ArtifactEvidence
	if err := json.Unmarshal([]byte(f.expectedEvidence), &evidence); err != nil {
		t.Fatal(err)
	}
	if !operationalEvidenceMatchesOriginal(evidence, original, f.domain.realm) {
		t.Fatal("control: the unchanged retained original does not match its own evidence")
	}
	t.Logf("retained evidence declares environment_variables=%q mount_targets=%q",
		evidence.Claims.Admission.Execution.Runtime.EnvironmentVariables,
		evidence.Claims.Admission.Execution.Runtime.MountTargets)

	for _, key := range []string{"UNDECLARED_KEY", "LD_PRELOAD", "BASH_ENV", "PATH"} {
		t.Run(key, func(t *testing.T) {
			candidate := original
			candidate.delivery.request.Invocation.Env = map[string]string{key: "x"}
			candidate.delivery.originalIntent.env = replayPresence[map[string]string]{present: true, value: map[string]string{key: "x"}}

			if operationalEvidenceMatchesOriginal(evidence, candidate, f.domain.realm) {
				t.Errorf("a retained request that sets %s matched evidence that declares no such key", key)
			}
			if wire, err := encodeOperationalOriginal(candidate.delivery, candidate.resolved, candidate.assessment,
				f.domain.keys, f.domain.realm); err == nil {
				t.Errorf("a retained request that sets %s was written to custody (%d bytes)", key, len(wire))
			}
		})
	}
}
