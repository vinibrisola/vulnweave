package main

import (
	"archive/zip"
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func makeJar(t *testing.T, entries map[string][]byte) []byte {
	t.Helper()
	var b bytes.Buffer
	zw := zip.NewWriter(&b)
	for name, data := range entries {
		w, err := zw.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = w.Write(data); err != nil {
			t.Fatal(err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

func TestArtifactInventoryFindsNestedMavenCoordinates(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "target")
	if err := os.MkdirAll(target, 0755); err != nil {
		t.Fatal(err)
	}
	nested := makeJar(t, map[string][]byte{"META-INF/maven/com.fasterxml.jackson.core/jackson-core/pom.properties": []byte("groupId=com.fasterxml.jackson.core\nartifactId=jackson-core\nversion=2.18.2\n")})
	outer := makeJar(t, map[string][]byte{"BOOT-INF/lib/jackson-core-2.18.2.jar": nested})
	if err := os.WriteFile(filepath.Join(target, "app.jar"), outer, 0644); err != nil {
		t.Fatal(err)
	}
	deps, warnings := collectArtifactDependencies(root)
	if len(warnings) > 0 && len(deps) == 0 {
		t.Fatalf("unexpected warnings: %v", warnings)
	}
	found := false
	for _, d := range deps {
		if d.Name == "com.fasterxml.jackson.core:jackson-core" && d.Version == "2.18.2" {
			found = true
			if len(d.ArtifactPaths) == 0 {
				t.Fatal("expected artifact path")
			}
		}
	}
	if !found {
		t.Fatalf("nested component not found: %#v", deps)
	}
}

func TestArtifactInventoryDoesNotTouchRemediationEligibility(t *testing.T) {
	r := &ScanReport{Metadata: map[string]interface{}{}, Sources: map[string]string{}, Reconciliation: map[string]int{}, Dependencies: []Dependency{{Name: "g:a", Version: "1.0.0", Ecosystem: "Maven"}}, Findings: []RiskItem{{Package: "g:a", CurrentVersion: "1.0.0", Ecosystem: "Maven", AutoRemediationEligible: true}}}
	reconcileEvidenceSummary(r)
	if !r.Findings[0].AutoRemediationEligible {
		t.Fatal("canonical remediation eligibility changed")
	}
}

func TestOSVScannerEvidenceReconcilesWithoutCreatingAutoFix(t *testing.T) {
	r := &ScanReport{Metadata: map[string]interface{}{}, Sources: map[string]string{}, Findings: []RiskItem{{Package: "g:a", CurrentVersion: "1.0.0", Ecosystem: "Maven", Sources: []string{"OSV"}, AutoRemediationEligible: true}}}
	raw := []byte(`{"results":[{"source":{"path":"pom.xml","type":"lockfile"},"packages":[{"package":{"name":"g:a","version":"1.0.0","ecosystem":"Maven"},"vulnerabilities":[{"id":"GHSA-test","summary":"test"}]}]}]}`)
	if err := importOSVScannerEvidence(r, raw); err != nil {
		t.Fatal(err)
	}
	if len(r.AuxiliaryFindings) != 0 {
		t.Fatalf("expected reconciliation into canonical finding: %#v", r.AuxiliaryFindings)
	}
	if !r.Findings[0].AutoRemediationEligible {
		t.Fatal("canonical remediation eligibility changed")
	}
	found := false
	for _, s := range r.Findings[0].Sources {
		if s == "OSV-Scanner" {
			found = true
		}
	}
	if !found {
		t.Fatalf("OSV-Scanner evidence missing: %#v", r.Findings[0].Sources)
	}
}

func TestOSVScannerUnmatchedStaysReadOnly(t *testing.T) {
	r := &ScanReport{Metadata: map[string]interface{}{}, Sources: map[string]string{}}
	raw := []byte(`{"results":[{"source":{"path":"target/app.jar","type":"sbom"},"packages":[{"package":{"name":"g:embedded","version":"2.0.0","ecosystem":"Maven"},"vulnerabilities":[{"id":"GHSA-embedded","summary":"embedded"}]}]}]}`)
	if err := importOSVScannerEvidence(r, raw); err != nil {
		t.Fatal(err)
	}
	if len(r.AuxiliaryFindings) != 1 {
		t.Fatalf("expected scanner-only finding, got %#v", r.AuxiliaryFindings)
	}
	if r.AuxiliaryFindings[0].AutoRemediationEligible {
		t.Fatal("scanner-only evidence must never authorize auto remediation")
	}
}
