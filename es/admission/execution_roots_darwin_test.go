//go:build darwin

package admission

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDarwinExecutionRootPresentationUsesFGETPATHAndFstatfsIdentity(t *testing.T) {
	parent := physicalTestTempDir(t)
	staging := filepath.Join(parent, "staging")
	results := filepath.Join(parent, "results")
	for _, root := range []string{staging, results} {
		if err := os.Mkdir(root, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	roots, err := qualifyExecutionRoots(staging, results, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer roots.close()
	presentation, err := darwinDescriptorPath(roots.staging.existingFD)
	if err != nil {
		t.Fatal(err)
	}
	if roots.staging.platform.presentation != presentation || roots.staging.platform.filesystemID == "" || roots.staging.platform.mountedOn == "" {
		t.Fatalf("Darwin observation did not bind F_GETPATH and fstatfs identity: %+v", roots.staging.platform)
	}
}

func TestDarwinExecutionRootsAcceptSamePresentationSiblings(t *testing.T) {
	left := &executionRootPlan{platform: executionRootPlatformObservation{presentation: "/volume/staging", filesystemID: "1:2", mountedOn: "/volume"}}
	right := &executionRootPlan{platform: executionRootPlatformObservation{presentation: "/volume/results", filesystemID: "1:2", mountedOn: "/volume"}}
	if err := classifyExecutionRootPlatformObservations(left, right); err != nil {
		t.Fatalf("same-presentation siblings rejected: %v", err)
	}
}

func TestDarwinExecutionRootsRejectSameFSIDDifferentPresentations(t *testing.T) {
	left := &executionRootPlan{platform: executionRootPlatformObservation{presentation: "/left/staging", filesystemID: "1:2", mountedOn: "/left"}}
	right := &executionRootPlan{platform: executionRootPlatformObservation{presentation: "/right/results", filesystemID: "1:2", mountedOn: "/right"}}
	if err := classifyExecutionRootPlatformObservations(left, right); err == nil {
		t.Fatal("same-FSID distinct presentations were accepted")
	}
}

func TestDarwinExecutionRootsRejectDescriptorAncestryAndCaseAlias(t *testing.T) {
	testCases := []struct {
		name  string
		left  string
		right string
	}{
		{name: "forward canonical ancestry", left: "/volume/Area", right: "/volume/Area/results"},
		{name: "reverse canonical ancestry", left: "/volume/area/staging", right: "/volume/area"},
		{name: "canonical equality from case alias", left: "/volume/Area", right: "/volume/Area"},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			left := &executionRootPlan{platform: executionRootPlatformObservation{presentation: testCase.left, filesystemID: "1:2", mountedOn: "/volume"}}
			right := &executionRootPlan{platform: executionRootPlatformObservation{presentation: testCase.right, filesystemID: "1:2", mountedOn: "/volume"}}
			if err := classifyExecutionRootPlatformObservations(left, right); err == nil {
				t.Fatal("canonical descriptor ancestry was accepted")
			}
		})
	}
}

func TestDarwinExecutionRootsRejectCanonicallyDescendantMountpoint(t *testing.T) {
	records := []darwinMountRecord{
		{filesystemID: "1:2", mountedOn: "/volume"},
		{filesystemID: "3:4", mountedOn: "/volume/Area/child"},
	}
	if !darwinHasDescendantMount("/volume/Area", records) {
		t.Fatal("canonical descendant mountpoint was not detected")
	}
	if darwinHasDescendantMount("/volume/area", records) {
		t.Fatal("case-sensitive sibling control was treated as ancestry")
	}
}

func TestDarwinExecutionRootAncestryFailsClosedWhenUnprovable(t *testing.T) {
	left := &executionRootPlan{platform: executionRootPlatformObservation{presentation: "/volume/staging", filesystemID: "1:2", mountedOn: "/volume"}}
	right := &executionRootPlan{platform: executionRootPlatformObservation{presentation: "/volume/results"}}
	if err := classifyExecutionRootPlatformObservations(left, right); err == nil {
		t.Fatal("incomplete Darwin identity evidence was accepted")
	}
}
