package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestVersionChangeType(t *testing.T) {
	cases := map[string]string{
		"1.2.3->1.2.4": "patch",
		"1.2.3->1.3.0": "minor",
		"1.2.3->2.0.0": "major",
		"0.2.3->0.3.0": "pre-1.0-minor",
	}
	for in, want := range cases {
		var a, b string
		for i := 0; i < len(in)-1; i++ {
			if in[i:i+2] == "->" {
				a = in[:i]
				b = in[i+2:]
				break
			}
		}
		if got := versionChangeType(a, b); got != want {
			t.Fatalf("%s: got %s want %s", in, got, want)
		}
	}
}

func TestTestExecutionSummaryMaven(t *testing.T) {
	r := CommandResult{Success: true, Output: "Tests run: 3, Failures: 0, Errors: 0, Skipped: 1\nTests run: 42, Failures: 0, Errors: 0, Skipped: 2"}
	s := testExecutionSummary(r)
	if !s.Known || s.Total != 42 || s.Passed != 40 || s.Skipped != 2 || s.Failed != 0 || s.Errors != 0 {
		t.Fatalf("unexpected summary: %#v", s)
	}
}

func TestCompatibilityReportBlockedDoesNotOverrideRemediation(t *testing.T) {
	plan := &FixPlan{Package: "org.example:demo", Ecosystem: "Maven", CurrentVersion: "1.0.0", TargetVersion: "1.0.1"}
	before := &RiskItem{Package: plan.Package, CurrentVersion: plan.CurrentVersion, Direct: true, Runtime: true}
	res := &FixExecution{
		ReadyToApply:   false,
		LockResolution: CommandResult{Success: false, Reason: "graph failed"},
		Build:          CommandResult{Skipped: true, Reason: "waiting"},
		Tests:          CommandResult{Skipped: true, Reason: "waiting"},
	}
	got := buildCompatibilityIntelligence(plan, before, res)
	if got.Confidence != "blocked" {
		t.Fatalf("confidence=%s", got.Confidence)
	}
	if res.ReadyToApply {
		t.Fatal("compatibility intelligence must never mutate ReadyToApply")
	}
}

func TestCompatibilityReportHighForStrongPatchEvidence(t *testing.T) {
	plan := &FixPlan{Package: "org.example:demo", Ecosystem: "npm", CurrentVersion: "1.0.0", TargetVersion: "1.0.1"}
	before := &RiskItem{Package: plan.Package, CurrentVersion: plan.CurrentVersion, Direct: false, Runtime: true, DependencyPath: []string{"root", "org.example:demo"}}
	res := &FixExecution{
		ReadyToApply:   true,
		LockResolution: CommandResult{Success: true, Command: "resolve"},
		Build:          CommandResult{Success: true, Command: "build"},
		Tests:          CommandResult{Success: true, Command: "test", Output: "Tests: 20 passed, 20 total"},
		Rescan:         &ScanReport{CoverageStatus: "complete", Dependencies: []Dependency{{Name: plan.Package, Version: plan.TargetVersion, Ecosystem: "npm"}}},
	}
	got := buildCompatibilityIntelligence(plan, before, res)
	if got.Confidence != "high" {
		t.Fatalf("confidence=%s signals=%#v", got.Confidence, got.Signals)
	}
	if got.Tests == nil || !got.Tests.Known || got.Tests.Total != 20 {
		t.Fatalf("tests=%#v", got.Tests)
	}
}

func TestBinaryAPIComparatorDetectsRemovedMember(t *testing.T) {
	if _, err := exec.LookPath("javac"); err != nil {
		t.Skip("javac unavailable")
	}
	if _, err := exec.LookPath("jar"); err != nil {
		t.Skip("jar unavailable")
	}
	root := t.TempDir()
	repo := filepath.Join(root, "repo")
	t.Setenv("VULNWEAVE_M2_REPO", repo)
	build := func(version, src string) {
		dir := filepath.Join(root, "build", version)
		if err := os.MkdirAll(filepath.Join(dir, "org", "example"), 0o755); err != nil {
			t.Fatal(err)
		}
		source := filepath.Join(dir, "org", "example", "Demo.java")
		if err := os.WriteFile(source, []byte(src), 0o600); err != nil {
			t.Fatal(err)
		}
		cmd := exec.Command("javac", source)
		cmd.Dir = dir
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("javac: %v %s", err, out)
		}
		target := filepath.Join(repo, "org", "example", "demo", version, "demo-"+version+".jar")
		if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
			t.Fatal(err)
		}
		cmd = exec.Command("jar", "cf", target, "org/example/Demo.class")
		cmd.Dir = dir
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("jar: %v %s", err, out)
		}
	}
	build("1.0.0", `package org.example; public class Demo { public void keep(){} public void removed(){} protected int value; }`)
	build("1.0.1", `package org.example; public class Demo { public void keep(){} }`)
	got := compareMavenBinaryAPI("org.example:demo", "1.0.0", "1.0.1")
	if !got.Available {
		t.Fatalf("unavailable: %#v", got)
	}
	if got.RemovedMembers < 2 {
		t.Fatalf("expected method+field removals, got %#v", got)
	}
}
