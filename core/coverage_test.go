package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestSpringTrivyRegression(t *testing.T) {
	data, err := os.ReadFile("testdata/trivy-spring-regression.json")
	if err != nil {
		t.Fatal(err)
	}
	r := &ScanReport{}
	if err := importTrivyEvidence(r, data); err != nil {
		t.Fatal(err)
	}
	if len(r.AuxiliaryFindings) != 4 {
		t.Fatalf("want 4 components, got %d", len(r.AuxiliaryFindings))
	}
	counts := map[string]int{}
	total := 0
	for _, f := range r.AuxiliaryFindings {
		for _, a := range f.Advisories {
			counts[a.Severity]++
			total++
		}
	}
	if total != 10 || counts["CRITICAL"] != 3 || counts["HIGH"] != 2 || counts["MEDIUM"] != 5 {
		t.Fatal(counts, total)
	}
	if !auxiliaryHasUnresolvedEvidence(r) {
		t.Fatal("unmatched evidence must block a clean verdict")
	}
	r.Findings = append([]RiskItem{}, r.AuxiliaryFindings...)
	if auxiliaryHasUnresolvedEvidence(r) {
		t.Fatal("matched evidence must correlate")
	}
	if err := importTrivyEvidence(r, data); err != nil {
		t.Fatal(err)
	}
	if len(r.AuxiliaryFindings) != 4 {
		t.Fatal("import must be idempotent")
	}
	if dest := os.Getenv("VULNWEAVE_TEST_REPORT"); dest != "" {
		r.Findings = nil
		r.CoverageStatus = "incomplete"
		r.Metadata = map[string]interface{}{"dependencyCount": 3}
		r.Warnings = []string{"Maven dependency:tree falhou: The network path was not found."}
		r.Project = ProjectInfo{Name: "spring-petclinic", Ecosystem: "Maven"}
		if err := writeJSON(dest, r); err != nil {
			t.Fatal(err)
		}
	}
}

func TestCoverageAndInventory(t *testing.T) {
	deps := []Dependency{{Name: "org.example:healthy", Version: "1.0.0", Ecosystem: "Maven"}}
	if graphCoverage(nil, nil) != "incomplete" || graphCoverage(deps, []string{"failed"}) != "incomplete" || graphCoverage(deps, nil) != "complete" {
		t.Fatal("incorrect coverage")
	}
	var bom struct{ Components []json.RawMessage }
	if err := json.Unmarshal([]byte(renderCycloneDX(&ScanReport{Dependencies: deps})), &bom); err != nil {
		t.Fatal(err)
	}
	if len(bom.Components) != 1 {
		t.Fatal("SBOM must include healthy resolved dependencies")
	}
}

func TestFailedAuxiliaryJSONDoesNotCountAsSuccess(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("uses Unix executable fixture")
	}
	root := t.TempDir()
	bin := t.TempDir()
	t.Setenv("PATH", bin)
	t.Setenv("VULNWEAVE_CMD_OSV_SCANNER", filepath.Join(bin, "osv-scanner"))
	t.Setenv("VULNWEAVE_CMD_TRIVY", filepath.Join(bin, "trivy"))
	for name, script := range map[string]string{"osv-scanner": "#!/bin/sh\nprintf '{\"results\":[]}'\nexit 127\n", "trivy": "#!/bin/sh\nprintf '{\"Results\":[]}'\n"} {
		if err := os.WriteFile(filepath.Join(bin, name), []byte(script), 0700); err != nil {
			t.Fatal(err)
		}
	}
	r := &ScanReport{CoverageStatus: "complete", Sources: map[string]string{}, Artifacts: map[string]string{}}
	deepScan(root, r)
	if r.Sources["OSV-Scanner"] != "degraded" || r.CoverageStatus != "complete" {
		t.Fatalf("auxiliary failure must not downgrade canonical coverage: %+v", r)
	}
	if !auxiliarySourcesDegraded(r) {
		t.Fatal("degraded auxiliary source must remain visible")
	}
}

func TestMavenFailurePreservesDiagnostic(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("uses Unix wrapper fixture")
	}
	root := t.TempDir()
	os.WriteFile(filepath.Join(root, "pom.xml"), []byte(`<project><dependencies><dependency><groupId>org.example</groupId><artifactId>managed</artifactId></dependency></dependencies></project>`), 0600)
	os.WriteFile(filepath.Join(root, "mvnw"), []byte("#!/bin/sh\necho 'The network path was not found.'\nexit 1\n"), 0700)
	deps, warnings := collectMavenDependencies(ProjectInfo{Root: root, Manifest: filepath.Join(root, "pom.xml"), Ecosystem: "Maven"})
	if len(deps) != 0 || !strings.Contains(strings.Join(warnings, " "), "network path") {
		t.Fatal(deps, warnings)
	}
	var result CommandResult
	if err := readJSON(filepath.Join(root, ".vulnweave", "reports", "maven-resolution.json"), &result); err != nil {
		t.Fatal(err)
	}
	if result.Success || !strings.Contains(result.Command, "dependency:tree") || !strings.Contains(result.Output, "network path") {
		t.Fatal(result)
	}
}

func TestAuxiliaryTargetEvidenceIsScopedToRemediationTarget(t *testing.T) {
	r := &ScanReport{AuxiliaryFindings: []RiskItem{
		{Package: "org.example:target", CurrentVersion: "2.0.0", Ecosystem: "Maven", Advisories: []Advisory{{ID: "CVE-2099-0001"}}},
		{Package: "org.example:other", CurrentVersion: "9.0.0", Ecosystem: "Maven", Advisories: []Advisory{{ID: "CVE-2099-0002"}}},
	}}
	if !auxiliaryHasTargetEvidence(r, "org.example:target", "2.0.0") {
		t.Fatal("target-specific auxiliary evidence must block the target remediation")
	}
	if auxiliaryHasTargetEvidence(r, "org.example:target", "2.0.1") {
		t.Fatal("evidence for another version must not block the candidate version")
	}
	if auxiliaryHasTargetEvidence(r, "org.example:missing", "1.0.0") {
		t.Fatal("unrelated auxiliary evidence must not block another remediation target")
	}
}

func TestRemediationRescanAllowsApplyIgnoresUnrelatedAuxiliaryDegradation(t *testing.T) {
	r := &ScanReport{
		CoverageStatus:    "complete",
		Sources:           map[string]string{"OSV": "healthy", "Trivy": "degraded"},
		AuxiliaryFindings: []RiskItem{{Package: "org.example:other", CurrentVersion: "9.0.0", Ecosystem: "Maven", Advisories: []Advisory{{ID: "CVE-2099-0999"}}}},
	}
	if !remediationRescanAllowsApply(r, "org.example:target", "2.0.0") {
		t.Fatal("unrelated/degraded auxiliary evidence must not invalidate a complete canonical target rescan")
	}
	r.CoverageStatus = "incomplete"
	if remediationRescanAllowsApply(r, "org.example:target", "2.0.0") {
		t.Fatal("incomplete canonical coverage must remain fail-closed")
	}
	r.CoverageStatus = "complete"
	r.AuxiliaryFindings = append(r.AuxiliaryFindings, RiskItem{Package: "org.example:target", CurrentVersion: "2.0.0", Ecosystem: "Maven", Advisories: []Advisory{{ID: "CVE-2099-0001"}}})
	if remediationRescanAllowsApply(r, "org.example:target", "2.0.0") {
		t.Fatal("target-specific auxiliary vulnerability evidence must remain fail-closed")
	}
}
