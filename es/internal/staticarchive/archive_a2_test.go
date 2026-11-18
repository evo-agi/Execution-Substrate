package staticarchive_test

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"testing"

	"execution-substrate/es/internal/staticarchive"
	"execution-substrate/es/internal/staticarchive/testcorpus"
)

// Next may parse bounded sparse metadata. The namespace check must then refuse
// the returned header without a call to the logical body reader.
func TestA2SparseNamespaceRejectsBeforeBody(t *testing.T) {
	for _, fixture := range testcorpus.SparseCases() {
		t.Run(fixture.Name, func(t *testing.T) {
			payload, err := testcorpus.Archive(fixture.Entries, nil)
			if err != nil {
				t.Fatal(err)
			}
			gz, err := gzip.NewReader(bytes.NewReader(payload))
			if err != nil {
				t.Fatal(err)
			}
			defer gz.Close()
			reader := tar.NewReader(gz)
			var namespace staticarchive.Namespace
			for _, entry := range fixture.Entries {
				header, nextErr := reader.Next()
				if nextErr != nil {
					t.Fatal(nextErr)
				}
				_, addErr := namespace.Add(header)
				if entry.Sparse != "" {
					if addErr == nil {
						t.Fatal("sparse header accepted before body read")
					}
					return
				}
				if addErr != nil {
					t.Fatalf("ordinary preceding entry rejected: %v", addErr)
				}
			}
			t.Fatal("sparse fixture did not contain a sparse member")
		})
	}
}

func TestA2OnceOnlyNamespaceNames(t *testing.T) {
	for _, fixture := range testcorpus.OnceOnlyCases() {
		t.Run(fixture.Name, func(t *testing.T) {
			payload, err := testcorpus.Archive(fixture.Entries, nil)
			if err != nil {
				t.Fatal(err)
			}
			gz, err := gzip.NewReader(bytes.NewReader(payload))
			if err != nil {
				t.Fatal(err)
			}
			defer gz.Close()
			reader := tar.NewReader(gz)
			var namespace staticarchive.Namespace
			seen := map[string]bool{}
			for range fixture.Entries {
				header, nextErr := reader.Next()
				if nextErr != nil {
					t.Fatal(nextErr)
				}
				name, addErr := namespace.Add(header)
				if addErr != nil {
					t.Fatal(addErr)
				}
				seen[name] = true
			}
			if !seen["entrypoint"] {
				t.Fatal("entrypoint namespace key absent")
			}
			for literal := range fixture.WantFiles {
				if !seen[literal] {
					t.Fatalf("literal namespace key %q absent", literal)
				}
			}
			for _, literal := range fixture.WantDirs {
				if !seen[literal] {
					t.Fatalf("literal directory namespace key %q absent", literal)
				}
			}
		})
	}
}
