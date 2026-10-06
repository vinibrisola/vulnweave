package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestCVSSVectorScoreCritical(t *testing.T) {
	got := cvssVectorScore("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
	if got != 9.8 {
		t.Fatalf("expected 9.8, got %.1f", got)
	}
}

func TestCompatibilityDelta(t *testing.T) {
	level, _ := compatibilityDelta("1.2.3", "1.2.4")
	if level != "low" {
		t.Fatalf("patch expected low, got %s", level)
	}
	level, _ = compatibilityDelta("1.2.3", "1.3.0")
	if level != "medium" {
		t.Fatalf("minor expected medium, got %s", level)
	}
	level, _ = compatibilityDelta("1.2.3", "2.0.0")
	if level != "high" {
		t.Fatalf("major expected high, got %s", level)
	}
}

func TestPatchPackageJSONPreservesRange(t *testing.T) {
	in := []byte(`{
  "dependencies": {
    "lodash": "^4.17.20"
  }
}`)
	out, control, can, _, err := patchPackageJSON(in, "lodash", "4.17.21", "")
	if err != nil {
		t.Fatal(err)
	}
	if !can {
		t.Fatal("expected automatic control point")
	}
	if control != "package.json > dependencies > lodash" {
		t.Fatalf("bad control point: %s", control)
	}
	if !strings.Contains(string(out), `"lodash": "^4.17.21"`) {
		t.Fatalf("range was not preserved: %s", out)
	}
}

func TestPatchPackageJSONTransitiveDoesNotInventOverride(t *testing.T) {
	in := []byte(`{"dependencies":{"express":"4.18.2"}}`)
	out, control, can, notes, err := patchPackageJSON(in, "minimist", "1.2.8", "")
	if err != nil {
		t.Fatal(err)
	}
	if can {
		t.Fatal("transitive dependency must not be auto-mutated")
	}
	if control != "transitive" {
		t.Fatalf("unexpected control point: %s", control)
	}
	if string(out) != string(in) {
		t.Fatal("manifest changed for transitive dependency")
	}
	if len(notes) == 0 {
		t.Fatal("expected explanatory note")
	}
}

func TestPatchPomLiteralAndProperty(t *testing.T) {
	literal := []byte(`<project><dependencies><dependency><groupId>org.example</groupId><artifactId>lib</artifactId><version>1.0.0</version></dependency></dependencies></project>`)
	out, control, can, _, err := patchPom(literal, "org.example:lib", "1.0.1")
	if err != nil {
		t.Fatal(err)
	}
	if !can || !strings.Contains(string(out), "<version>1.0.1</version>") {
		t.Fatalf("literal update failed: %s", out)
	}

	prop := []byte(`<project><properties><lib.version>1.0.0</lib.version></properties><dependencies><dependency><groupId>org.example</groupId><artifactId>lib</artifactId><version>${lib.version}</version></dependency></dependencies></project>`)
	out, control, can, _, err = patchPom(prop, "org.example:lib", "1.1.0")
	if err != nil {
		t.Fatal(err)
	}
	if !can {
		t.Fatal("expected property control point")
	}
	if control != "pom.xml property ${lib.version}" {
		t.Fatalf("unexpected control point: %s", control)
	}
	if !strings.Contains(string(out), "<lib.version>1.1.0</lib.version>") {
		t.Fatalf("property update failed: %s", out)
	}
}

func TestFixedVersionNeverDowngrades(t *testing.T) {
	v := osvVuln{Affected: []osvAffected{{}}}
	v.Affected[0].Package.Name = "@angular/core"
	v.Affected[0].Ranges = []osvRange{{Events: []osvEvent{{Fixed: "19.2.20"}, {Fixed: "20.3.20"}}}}
	got := vulnFixedVersion(v, "@angular/core", "20.3.17")
	if got != "20.3.20" {
		t.Fatalf("expected upgrade 20.3.20, got %s", got)
	}

	onlyOld := osvVuln{Affected: []osvAffected{{}}}
	onlyOld.Affected[0].Package.Name = "@angular/core"
	onlyOld.Affected[0].Ranges = []osvRange{{Events: []osvEvent{{Fixed: "19.2.20"}}}}
	if got := vulnFixedVersion(onlyOld, "@angular/core", "20.3.17"); got != "" {
		t.Fatalf("downgrade candidate must be discarded, got %s", got)
	}
}

func TestSemverCompare(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"20.3.20", "20.3.17", 1},
		{"19.2.20", "20.3.17", -1},
		{"1.0.0", "1.0.0", 0},
		{"1.0.0", "1.0.0-beta.1", 1},
	}
	for _, c := range cases {
		got := cmpVersion(c.a, c.b)
		if got != c.want {
			t.Fatalf("cmpVersion(%s,%s)=%d want %d", c.a, c.b, got, c.want)
		}
	}
}

func TestHydratedOSVAdvisoryHasHumanDataAndFix(t *testing.T) {
	v := osvVuln{
		ID:               "GHSA-48r7-hpm6-gfxm",
		Aliases:          []string{"CVE-2026-54268"},
		Summary:          "@angular/common: Denial of Service in date formatting",
		DatabaseSpecific: map[string]interface{}{"severity": "HIGH"},
		Affected:         []osvAffected{{}},
	}
	v.Severity = append(v.Severity, struct {
		Type  string `json:"type"`
		Score string `json:"score"`
	}{Type: "CVSS_V3", Score: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H"})
	v.Affected[0].Package.Name = "@angular/common"
	v.Affected[0].Ranges = []osvRange{{Type: "SEMVER", Events: []osvEvent{{Introduced: "20.0.0-next.0"}, {Fixed: "20.3.25"}}}}

	a := advisoryFromOSV(v, "@angular/common", "20.3.17")
	if a.Summary == "" || a.Summary == "Advisory sem resumo" {
		t.Fatalf("expected hydrated human summary, got %q", a.Summary)
	}
	if a.Severity != "HIGH" {
		t.Fatalf("expected HIGH severity, got %s", a.Severity)
	}
	if a.CVSS != 7.5 {
		t.Fatalf("expected CVSS 7.5 from real vector, got %.1f", a.CVSS)
	}
	if a.FixedVersion != "20.3.25" {
		t.Fatalf("expected fixed version 20.3.25, got %s", a.FixedVersion)
	}
}

func TestQualitativeSeverityDoesNotInventNumericCVSS(t *testing.T) {
	v := osvVuln{DatabaseSpecific: map[string]interface{}{"severity": "CRITICAL"}}
	if got := vulnCVSS(v); got != 0 {
		t.Fatalf("qualitative severity must not be fabricated as CVSS, got %.1f", got)
	}
	if got := vulnQualitativeSeverity(v, 0); got != "CRITICAL" {
		t.Fatalf("expected CRITICAL qualitative severity, got %s", got)
	}
}

func TestCandidateRequiresFixForEveryAdvisory(t *testing.T) {
	candidate, why := deriveCandidate([]Advisory{
		{ID: "GHSA-a", FixedVersion: "20.3.25"},
		{ID: "GHSA-b", FixedVersion: "20.3.27"},
	})
	if candidate != "20.3.27" {
		t.Fatalf("expected aggregated candidate 20.3.27, got %s", candidate)
	}
	if why == "" {
		t.Fatal("expected candidate explanation")
	}

	candidate, why = deriveCandidate([]Advisory{
		{ID: "GHSA-a", FixedVersion: "20.3.25"},
		{ID: "GHSA-no-fix"},
	})
	if candidate != "" {
		t.Fatalf("must not suggest candidate when one advisory has no known fix, got %s", candidate)
	}
	if strings.Contains(why, "GHSA-") || !strings.Contains(why, "1 advisory") {
		t.Fatalf("expected human explanation without raw GHSA IDs, got %s", why)
	}
}

func TestQueryOSVHydratesBatchReferences(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/querybatch", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"results":[{"vulns":[{"id":"GHSA-test-1111","modified":"2026-09-30T00:00:00Z"}]}]}`))
	})
	mux.HandleFunc("/v1/vulns/GHSA-test-1111", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
			"id":"GHSA-test-1111",
			"aliases":["CVE-2026-99999"],
			"summary":"Hydrated advisory summary",
			"severity":[{"type":"CVSS_V3","score":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}],
			"database_specific":{"severity":"CRITICAL"},
			"affected":[{"package":{"name":"demo","ecosystem":"npm"},"ranges":[{"type":"SEMVER","events":[{"introduced":"1.0.0"},{"fixed":"1.2.4"}]}]}]
		}`))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()
	old := osvBaseURL
	osvBaseURL = srv.URL
	defer func() { osvBaseURL = old }()

	got, err := queryOSV([]Dependency{{Name: "demo", Version: "1.2.3", Ecosystem: "npm"}})
	if err != nil {
		t.Fatal(err)
	}
	vs := got["npm|demo|1.2.3"]
	if len(vs) != 1 {
		t.Fatalf("expected one hydrated advisory, got %d", len(vs))
	}
	if vs[0].Summary != "Hydrated advisory summary" {
		t.Fatalf("querybatch reference was not hydrated: %+v", vs[0])
	}
	a := advisoryFromOSV(vs[0], "demo", "1.2.3")
	if a.FixedVersion != "1.2.4" || a.CVSS != 9.8 || a.Severity != "CRITICAL" {
		t.Fatalf("unexpected hydrated advisory: %+v", a)
	}
}

func TestNpmLockKeepsMultipleVersionsAndDirectness(t *testing.T) {
	dir := t.TempDir()
	pkg := `{"name":"demo-app","dependencies":{"foo":"^2.0.0","parent":"1.0.0"}}`
	lock := `{
	  "lockfileVersion": 3,
	  "packages": {
	    "": {"name":"demo-app","dependencies":{"foo":"^2.0.0","parent":"1.0.0"}},
	    "node_modules/foo": {"version":"2.1.0"},
	    "node_modules/parent": {"version":"1.0.0"},
	    "node_modules/parent/node_modules/foo": {"version":"1.9.9"}
	  }
	}`
	if err := os.WriteFile(filepath.Join(dir, "package.json"), []byte(pkg), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "package-lock.json"), []byte(lock), 0o600); err != nil {
		t.Fatal(err)
	}
	p := ProjectInfo{Root: dir, Name: "demo-app", Ecosystem: "npm", Manifest: filepath.Join(dir, "package.json"), Lockfile: filepath.Join(dir, "package-lock.json")}
	deps, warnings := collectNpmDependencies(p)
	if len(warnings) != 0 {
		t.Fatalf("unexpected warnings: %v", warnings)
	}
	var rootFoo, nestedFoo *Dependency
	for i := range deps {
		d := &deps[i]
		if d.Name == "foo" && d.Version == "2.1.0" {
			rootFoo = d
		}
		if d.Name == "foo" && d.Version == "1.9.9" {
			nestedFoo = d
		}
	}
	if rootFoo == nil || !rootFoo.Direct {
		t.Fatalf("root foo should be direct: %+v", rootFoo)
	}
	if nestedFoo == nil || nestedFoo.Direct {
		t.Fatalf("nested foo should be retained as transitive: %+v", nestedFoo)
	}
	if got := strings.Join(nestedFoo.DependencyPath, " -> "); got != "parent -> foo" {
		t.Fatalf("unexpected nested dependency path: %s", got)
	}
}

func TestXlsxTrustedVendorRemediation(t *testing.T) {
	opt := deriveRemediation("xlsx", "0.18.5", "npm", []Advisory{
		{ID: "GHSA-4r6h-8v6p-xvw6", Summary: "Prototype Pollution"},
		{ID: "GHSA-5pgg-2g8v-p4x9", Summary: "ReDoS"},
	})
	if opt.Version != "0.20.3" || opt.Kind != "vendor-tarball" || !opt.Trusted || !opt.AutoPlan {
		t.Fatalf("unexpected trusted vendor remediation: %+v", opt)
	}
	if !strings.HasPrefix(opt.InstallSpec, "https://cdn.sheetjs.com/xlsx-0.20.3/") {
		t.Fatalf("unexpected official install spec: %s", opt.InstallSpec)
	}
}

func TestPackageJSONVendorSpecIsLiteralAndDropsRange(t *testing.T) {
	orig := []byte(`{"dependencies":{"xlsx":"^0.18.5"}}`)
	spec := "https://cdn.sheetjs.com/xlsx-0.20.3/xlsx-0.20.3.tgz"
	out, _, ok, _, err := patchPackageJSON(orig, "xlsx", "0.20.3", spec)
	if err != nil || !ok {
		t.Fatalf("patch failed: ok=%v err=%v", ok, err)
	}
	if !strings.Contains(string(out), `"xlsx":"`+spec+`"`) {
		t.Fatalf("vendor spec not written literally: %s", out)
	}
	if strings.Contains(string(out), "^https://") {
		t.Fatalf("range operator must not prefix vendor URL: %s", out)
	}
}

func TestPreOneMinorUpgradeIsHighCompatibilityRisk(t *testing.T) {
	level, _ := compatibilityDelta("0.18.5", "0.20.3")
	if level != "high" {
		t.Fatalf("expected high for pre-1.0 minor jump, got %s", level)
	}
}

func TestPrivateNpmScopePolicy(t *testing.T) {
	t.Setenv("VULNWEAVE_PRIVATE_NPM_SCOPES", `["@corp"]`)
	if !isPrivatePackage("npm", "@corp/internal") {
		t.Fatal("expected private scoped package")
	}
	if isPrivatePackage("npm", "@angular/core") {
		t.Fatal("public package must not be classified private")
	}
}

func TestExecLookPathHonorsRuntimeOverride(t *testing.T) {
	old := os.Getenv("VULNWEAVE_CMD_NPM")
	defer os.Setenv("VULNWEAVE_CMD_NPM", old)
	fake := filepath.Join(t.TempDir(), "npm-fake")
	if err := os.WriteFile(fake, []byte("fake"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Setenv("VULNWEAVE_CMD_NPM", fake); err != nil {
		t.Fatal(err)
	}
	got, err := execLookPath("npm")
	if err != nil {
		t.Fatal(err)
	}
	if got != fake {
		t.Fatalf("expected override %s, got %s", fake, got)
	}
}

func TestNodePackageManagerUsesPackageManagerFieldAndLockfile(t *testing.T) {
	dir := t.TempDir()
	manifest := filepath.Join(dir, "package.json")
	if err := os.WriteFile(manifest, []byte(`{"packageManager":"pnpm@9.15.0","scripts":{"build":"echo ok","test":"echo ok"}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	p := ProjectInfo{Root: dir, Ecosystem: "npm", Manifest: manifest, Lockfile: filepath.Join(dir, "package-lock.json")}
	if got := nodePackageManager(p); got != "pnpm" {
		t.Fatalf("expected pnpm from packageManager, got %s", got)
	}
	if err := os.WriteFile(manifest, []byte(`{"scripts":{"build":"echo ok","test":"echo ok"}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	p.Lockfile = filepath.Join(dir, "yarn.lock")
	if got := nodePackageManager(p); got != "yarn" {
		t.Fatalf("expected yarn from lockfile, got %s", got)
	}
}

func TestMavenCommandPrefersProjectWrapper(t *testing.T) {
	dir := t.TempDir()
	name := "mvnw"
	if runtime.GOOS == "windows" {
		name = "mvnw.cmd"
	}
	wrapper := filepath.Join(dir, name)
	if err := os.WriteFile(wrapper, []byte("echo wrapper"), 0o700); err != nil {
		t.Fatal(err)
	}
	p := ProjectInfo{Root: dir, Ecosystem: "Maven"}
	if got := mavenCommand(p); got != wrapper {
		t.Fatalf("expected wrapper %s, got %s", wrapper, got)
	}
}

func TestRunCmdSupportsCommandPrefix(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("portable echo-path test runs on Unix CI")
	}
	oldCmd := os.Getenv("VULNWEAVE_CMD_PNPM")
	oldPrefix := os.Getenv("VULNWEAVE_CMD_PREFIX_PNPM")
	defer os.Setenv("VULNWEAVE_CMD_PNPM", oldCmd)
	defer os.Setenv("VULNWEAVE_CMD_PREFIX_PNPM", oldPrefix)
	if err := os.Setenv("VULNWEAVE_CMD_PNPM", "/bin/echo"); err != nil {
		t.Fatal(err)
	}
	if err := os.Setenv("VULNWEAVE_CMD_PREFIX_PNPM", `["pnpm"]`); err != nil {
		t.Fatal(err)
	}
	got := runCmd(t.TempDir(), "prefix-test", "pnpm", []string{"install"})
	if !got.Success || !strings.Contains(got.Output, "pnpm install") {
		t.Fatalf("expected prefixed command output, got %+v", got)
	}
}

func TestWindowsBatchCommandLineQuotesPathWithSpaces(t *testing.T) {
	got, err := windowsBatchCommandLine(`C:\Program Files\nodejs\npm.cmd`, []string{"install", "--ignore-scripts", "--no-audit"})
	if err != nil {
		t.Fatal(err)
	}
	want := `""C:\Program Files\nodejs\npm.cmd" "install" "--ignore-scripts" "--no-audit""`
	if got != want {
		t.Fatalf("unexpected command line\nwant: %s\n got: %s", want, got)
	}
	if strings.HasPrefix(got, `"C:\Program `) && !strings.HasPrefix(got, `""C:\Program Files`) {
		t.Fatalf("batch command path was not protected from cmd.exe space splitting: %s", got)
	}
}

func TestWindowsBatchCommandLineRejectsEmbeddedQuote(t *testing.T) {
	if _, err := windowsBatchCommandLine(`C:\Tools\npm.cmd`, []string{`bad"arg`}); err == nil {
		t.Fatal("expected embedded quote to be rejected")
	}
}

func TestSandboxPathUsesConfiguredLocalRoot(t *testing.T) {
	root := t.TempDir()
	old := os.Getenv("VULNWEAVE_SANDBOX_ROOT")
	defer os.Setenv("VULNWEAVE_SANDBOX_ROOT", old)
	if err := os.Setenv("VULNWEAVE_SANDBOX_ROOT", root); err != nil {
		t.Fatal(err)
	}
	plan := &FixPlan{ID: "plan-123", ProjectRoot: t.TempDir()}
	got, err := sandboxPathForPlan(plan)
	if err != nil {
		t.Fatal(err)
	}
	want := filepath.Join(root, "plan-123")
	if filepath.Clean(got) != filepath.Clean(want) {
		t.Fatalf("want %s got %s", want, got)
	}
}

func TestDirectNpmInvocationBypassesBatchShim(t *testing.T) {
	base := t.TempDir()
	node := filepath.Join(base, "node.exe")
	npmCmd := filepath.Join(base, "npm.cmd")
	cli := filepath.Join(base, "node_modules", "npm", "bin", "npm-cli.js")
	if err := os.MkdirAll(filepath.Dir(cli), 0o755); err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{node, npmCmd, cli} {
		if err := os.WriteFile(f, []byte("stub"), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	old := os.Getenv("VULNWEAVE_CMD_NODE")
	defer os.Setenv("VULNWEAVE_CMD_NODE", old)
	if err := os.Setenv("VULNWEAVE_CMD_NODE", node); err != nil {
		t.Fatal(err)
	}
	exe, args, ok := directNodePackageManagerInvocationForOS("windows", "npm", npmCmd, []string{"install", "--ignore-scripts"})
	if !ok {
		t.Fatal("expected direct npm invocation")
	}
	if exe != node {
		t.Fatalf("expected node %s got %s", node, exe)
	}
	if len(args) < 3 || args[0] != cli || args[1] != "install" {
		t.Fatalf("unexpected args: %#v", args)
	}
}

func TestClassifyNetworkNameFailure(t *testing.T) {
	got := classifyExecutionFailure("The specified network name is no longer available.")
	if !strings.Contains(got, "ERROR_NETNAME_DELETED") {
		t.Fatalf("unexpected classification: %s", got)
	}
}

func TestNpmPeerCohortAlignsExactAngularPeers(t *testing.T) {
	dir := t.TempDir()
	manifest := filepath.Join(dir, "package.json")
	lockfile := filepath.Join(dir, "package-lock.json")
	pkg := `{
  "dependencies": {
    "@angular/common": "^20.0.3",
    "@angular/compiler": "^20.0.3",
    "@angular/core": "^20.0.3",
    "@angular/platform-browser": "^20.0.3",
    "@angular/platform-browser-dynamic": "^20.0.3"
  },
  "devDependencies": {
    "@angular/compiler-cli": "^20.0.3"
  }
}`
	lock := `{
  "lockfileVersion": 3,
  "packages": {
    "": {"name":"demo"},
    "node_modules/@angular/compiler": {"version":"20.3.17"},
    "node_modules/@angular/compiler-cli": {"version":"20.3.17","peerDependencies":{"@angular/compiler":"20.3.17"}},
    "node_modules/@angular/core": {"version":"20.3.17","peerDependencies":{"@angular/compiler":"20.3.17"}},
    "node_modules/@angular/platform-browser-dynamic": {"version":"20.3.17","peerDependencies":{"@angular/common":"20.3.17","@angular/compiler":"20.3.17","@angular/core":"20.3.17","@angular/platform-browser":"20.3.17"}},
    "node_modules/@angular/common": {"version":"20.3.17","peerDependencies":{"@angular/core":"20.3.17"}},
    "node_modules/@angular/platform-browser": {"version":"20.3.17","peerDependencies":{"@angular/common":"20.3.17","@angular/core":"20.3.17"}}
  }
}`
	if err := os.WriteFile(manifest, []byte(pkg), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(lockfile, []byte(lock), 0o600); err != nil {
		t.Fatal(err)
	}
	p := ProjectInfo{Root: dir, Ecosystem: "npm", Manifest: manifest, Lockfile: lockfile}
	out, control, can, notes, changes, strategy, err := patchPackageJSONAligned(p, []byte(pkg), "@angular/compiler", "20.3.17", "20.3.28", "")
	if err != nil {
		t.Fatal(err)
	}
	if !can || strategy != "peer-cohort-exact" {
		t.Fatalf("expected peer cohort plan: can=%v strategy=%s control=%s notes=%v", can, strategy, control, notes)
	}
	for _, name := range []string{"@angular/compiler", "@angular/compiler-cli", "@angular/core", "@angular/common", "@angular/platform-browser", "@angular/platform-browser-dynamic"} {
		if !strings.Contains(string(out), `"`+name+`": "20.3.28"`) {
			t.Fatalf("%s was not aligned:\n%s", name, out)
		}
	}
	if len(changes) < 6 {
		t.Fatalf("expected related changes, got %d", len(changes))
	}
}

func TestAngularReleaseTrainPinsAllExactPeersButNotBroadPeers(t *testing.T) {
	dir := t.TempDir()
	manifest := filepath.Join(dir, "package.json")
	lockfile := filepath.Join(dir, "package-lock.json")
	pkg := `{
  "dependencies": {
    "@angular/animations": "^20.3.17",
    "@angular/cdk": "^20.2.14",
    "@angular/common": "^20.0.3",
    "@angular/compiler": "^20.0.3",
    "@angular/core": "^20.0.3",
    "@angular/forms": "^20.0.3",
    "@angular/material": "^20.0.0",
    "@angular/platform-browser": "^20.0.3",
    "@angular/platform-browser-dynamic": "^20.0.3",
    "@angular/router": "^20.0.3"
  },
  "devDependencies": {
    "@angular/build": "^20.0.2",
    "@angular/cli": "^20.0.2",
    "@angular/compiler-cli": "^20.0.3"
  }
}`
	lock := `{
  "lockfileVersion": 3,
  "packages": {
    "": {"name":"sbcweb"},
    "node_modules/@angular/animations": {"version":"20.3.17","peerDependencies":{"@angular/core":"20.3.17"}},
    "node_modules/@angular/common": {"version":"20.3.17","peerDependencies":{"@angular/core":"20.3.17"}},
    "node_modules/@angular/compiler": {"version":"20.3.17"},
    "node_modules/@angular/core": {"version":"20.3.17","peerDependencies":{"@angular/compiler":"20.3.17"}},
    "node_modules/@angular/forms": {"version":"20.3.17","peerDependencies":{"@angular/common":"20.3.17","@angular/core":"20.3.17","@angular/platform-browser":"20.3.17"}},
    "node_modules/@angular/platform-browser": {"version":"20.3.17","peerDependencies":{"@angular/animations":"20.3.17","@angular/common":"20.3.17","@angular/core":"20.3.17"}},
    "node_modules/@angular/platform-browser-dynamic": {"version":"20.3.17","peerDependencies":{"@angular/common":"20.3.17","@angular/compiler":"20.3.17","@angular/core":"20.3.17","@angular/platform-browser":"20.3.17"}},
    "node_modules/@angular/router": {"version":"20.3.17","peerDependencies":{"@angular/common":"20.3.17","@angular/core":"20.3.17","@angular/platform-browser":"20.3.17"}},
    "node_modules/@angular/compiler-cli": {"version":"20.3.17","peerDependencies":{"@angular/compiler":"20.3.17"}},
    "node_modules/@angular/build": {"version":"20.3.19","peerDependencies":{"@angular/compiler":"^20.0.0","@angular/compiler-cli":"^20.0.0","@angular/core":"^20.0.0","@angular/platform-browser":"^20.0.0"}},
    "node_modules/@angular/cdk": {"version":"20.2.14","peerDependencies":{"@angular/common":"^20.0.0 || ^21.0.0","@angular/core":"^20.0.0 || ^21.0.0"}},
    "node_modules/@angular/material": {"version":"20.2.14","peerDependencies":{"@angular/cdk":"20.2.14","@angular/common":"^20.0.0 || ^21.0.0","@angular/core":"^20.0.0 || ^21.0.0"}}
  }
}`
	if err := os.WriteFile(manifest, []byte(pkg), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(lockfile, []byte(lock), 0o600); err != nil {
		t.Fatal(err)
	}
	p := ProjectInfo{Root: dir, Ecosystem: "npm", Manifest: manifest, Lockfile: lockfile}
	out, _, can, notes, changes, strategy, err := patchPackageJSONAligned(p, []byte(pkg), "@angular/compiler", "20.3.17", "20.3.28", "")
	if err != nil {
		t.Fatal(err)
	}
	if !can || strategy != "peer-cohort-exact" {
		t.Fatalf("expected exact peer cohort, got can=%v strategy=%s notes=%v", can, strategy, notes)
	}
	for _, name := range []string{"@angular/animations", "@angular/common", "@angular/compiler", "@angular/core", "@angular/forms", "@angular/platform-browser", "@angular/platform-browser-dynamic", "@angular/router", "@angular/compiler-cli"} {
		if !strings.Contains(string(out), `"`+name+`": "20.3.28"`) {
			t.Fatalf("%s not exact-pinned:\n%s", name, out)
		}
	}
	for _, untouched := range []string{`"@angular/build": "^20.0.2"`, `"@angular/cdk": "^20.2.14"`, `"@angular/material": "^20.0.0"`} {
		if !strings.Contains(string(out), untouched) {
			t.Fatalf("broad-compatible dependency unexpectedly changed: %s\n%s", untouched, out)
		}
	}
	if len(changes) != 9 {
		t.Fatalf("expected 9 coordinated changes, got %d", len(changes))
	}
}

func TestMavenExplicitReleaseCohortAlignment(t *testing.T) {
	orig := []byte(`<project><dependencies>
<dependency><groupId>org.demo</groupId><artifactId>core</artifactId><version>1.2.3</version></dependency>
<dependency><groupId>org.demo</groupId><artifactId>api</artifactId><version>1.2.3</version></dependency>
<dependency><groupId>other.group</groupId><artifactId>other</artifactId><version>1.2.3</version></dependency>
</dependencies></project>`)
	p := ProjectInfo{Ecosystem: "Maven"}
	out, _, can, _, changes, strategy, err := patchPomAligned(p, orig, "org.demo:core", "1.2.3", "1.2.4")
	if err != nil {
		t.Fatal(err)
	}
	if !can || strategy != "maven-release-cohort" {
		t.Fatalf("unexpected plan can=%v strategy=%s", can, strategy)
	}
	if !strings.Contains(string(out), `<artifactId>api</artifactId><version>1.2.4</version>`) {
		t.Fatalf("same-group cohort not aligned: %s", out)
	}
	if !strings.Contains(string(out), `<artifactId>other</artifactId><version>1.2.3</version>`) {
		t.Fatalf("unrelated group was changed: %s", out)
	}
	if len(changes) != 2 {
		t.Fatalf("expected 2 changes, got %d", len(changes))
	}
}

func TestTruncateHeadTailPreservesFinalFailure(t *testing.T) {
	input := strings.Repeat("A", 200) + "\nFINAL-ERROR: analyze-and-sync failed"
	got := truncateHeadTail(input, 100)
	if !strings.Contains(got, "FINAL-ERROR") {
		t.Fatalf("final failure was lost: %s", got)
	}
}

func TestPeerOverrideIsNotAcceptedAsSafeGraph(t *testing.T) {
	r := CommandResult{Name: "resolver", Success: true, ExitCode: 0, Output: "npm warn ERESOLVE overriding peer dependency\nnpm warn Could not resolve dependency:"}
	got := enforcePeerClean(r)
	if got.Success || got.ExitCode == 0 || !strings.Contains(got.Reason, "peerDependencies") {
		t.Fatalf("peer override should fail closed: %+v", got)
	}
}

func TestMavenDependencyManagementControlPoint(t *testing.T) {
	orig := []byte(`<project>
<properties><demo.version>1.2.3</demo.version></properties>
<dependencyManagement><dependencies><dependency><groupId>org.demo</groupId><artifactId>core</artifactId><version>${demo.version}</version></dependency></dependencies></dependencyManagement>
<dependencies><dependency><groupId>org.demo</groupId><artifactId>core</artifactId></dependency></dependencies>
</project>`)
	p := ProjectInfo{Ecosystem: "Maven"}
	out, control, can, _, _, strategy, err := patchPomAligned(p, orig, "org.demo:core", "1.2.3", "1.2.4")
	if err != nil {
		t.Fatal(err)
	}
	if !can {
		t.Fatalf("expected managed control point, control=%s strategy=%s", control, strategy)
	}
	if !strings.Contains(string(out), `<demo.version>1.2.4</demo.version>`) {
		t.Fatalf("managed property not updated: %s", out)
	}
}

func TestVerifyNpmResolvedPlanRejectsCohortDrift(t *testing.T) {
	dir := t.TempDir()
	lockfile := filepath.Join(dir, "package-lock.json")
	lock := `{"lockfileVersion":3,"packages":{"":{"name":"demo"},"node_modules/@angular/compiler":{"version":"20.3.28"},"node_modules/@angular/core":{"version":"20.3.33","peerDependencies":{"@angular/compiler":"20.3.33"}}}}`
	if err := os.WriteFile(lockfile, []byte(lock), 0o600); err != nil {
		t.Fatal(err)
	}
	p := ProjectInfo{Root: dir, Ecosystem: "npm", Lockfile: lockfile}
	plan := &FixPlan{Strategy: "peer-cohort-exact", TargetVersion: "20.3.28", RelatedChanges: []PlannedDependencyChange{{Package: "@angular/compiler"}, {Package: "@angular/core"}}}
	if err := verifyNpmResolvedPlan(p, plan); err == nil || !strings.Contains(err.Error(), "desalinhado") {
		t.Fatalf("expected cohort drift rejection, got %v", err)
	}
}

func TestVerifyNpmResolvedPlanAcceptsExactCohort(t *testing.T) {
	dir := t.TempDir()
	lockfile := filepath.Join(dir, "package-lock.json")
	lock := `{"lockfileVersion":3,"packages":{"":{"name":"demo"},"node_modules/@angular/compiler":{"version":"20.3.28"},"node_modules/@angular/core":{"version":"20.3.28","peerDependencies":{"@angular/compiler":"20.3.28"}}}}`
	if err := os.WriteFile(lockfile, []byte(lock), 0o600); err != nil {
		t.Fatal(err)
	}
	p := ProjectInfo{Root: dir, Ecosystem: "npm", Lockfile: lockfile}
	plan := &FixPlan{Strategy: "peer-cohort-exact", TargetVersion: "20.3.28", RelatedChanges: []PlannedDependencyChange{{Package: "@angular/compiler"}, {Package: "@angular/core"}}}
	if err := verifyNpmResolvedPlan(p, plan); err != nil {
		t.Fatalf("expected exact cohort acceptance, got %v", err)
	}
}

func TestParseMavenTreeVersions(t *testing.T) {
	out := `[INFO] +- org.demo:core:jar:1.2.4:compile
[INFO] \\- org.demo:api:jar:1.2.4:runtime`
	got := parseMavenTreeVersions(out)
	if !got["org.demo:core"]["1.2.4"] || !got["org.demo:api"]["1.2.4"] {
		t.Fatalf("unexpected Maven tree parse: %#v", got)
	}
}

func TestAngularMixedPatchLockIsAligned(t *testing.T) {
	dir := t.TempDir()
	orig := []byte(`{"dependencies":{"@angular/compiler":"^20.3.28","@angular/core":"20.3.17","@angular/animations":"~20.3.18","@angular/material":"^20.2.14"},"devDependencies":{"@angular/compiler-cli":"20.3.17","@angular/build":"^20.0.2"}}`)
	lock := `{"lockfileVersion":3,"packages":{"node_modules/@angular/compiler":{"version":"20.3.28"},"node_modules/@angular/core":{"version":"20.3.17","peerDependencies":{"@angular/compiler":"20.3.17"}},"node_modules/@angular/animations":{"version":"20.3.18","peerDependencies":{"@angular/core":"20.3.18"}},"node_modules/@angular/compiler-cli":{"version":"20.3.17","peerDependencies":{"@angular/compiler":"20.3.17"}}}}`
	p := ProjectInfo{Lockfile: filepath.Join(dir, "package-lock.json")}
	os.WriteFile(p.Lockfile, []byte(lock), 0600)
	out, _, can, notes, changes, _, err := patchPackageJSONAligned(p, orig, "@angular/compiler", "20.3.28", "20.3.29", "")
	if err != nil || !can {
		t.Fatalf("alignment failed: %v %v", err, notes)
	}
	for _, name := range []string{"@angular/core", "@angular/animations", "@angular/compiler", "@angular/compiler-cli"} {
		if !strings.Contains(string(out), `"`+name+`":"20.3.29"`) {
			t.Fatalf("missing %s: %s", name, out)
		}
	}
	if !strings.Contains(string(out), `"@angular/material":"^20.2.14"`) || !strings.Contains(string(out), `"@angular/build":"^20.0.2"`) {
		t.Fatal("independent release train changed")
	}
	for _, ch := range changes {
		if ch.Package == "@angular/animations" && ch.CurrentVersion != "20.3.18" {
			t.Fatal("incorrect original version")
		}
	}
}

func TestAngularUnsafeAlignmentBlocked(t *testing.T) {
	for _, version := range []string{"20.3.33", "20.2.17", ""} {
		t.Run(version, func(t *testing.T) {
			dir := t.TempDir()
			p := ProjectInfo{Lockfile: filepath.Join(dir, "package-lock.json")}
			orig := []byte(`{"dependencies":{"@angular/compiler":"^20.3.17","@angular/core":"^20.3.17"}}`)
			if version != "" {
				os.WriteFile(p.Lockfile, []byte(`{"packages":{"node_modules/@angular/compiler":{"version":"20.3.17"},"node_modules/@angular/core":{"version":"`+version+`"}}}`), 0600)
			}
			out, _, can, _, _, _, err := patchPackageJSONAligned(p, orig, "@angular/compiler", "20.3.17", "20.3.28", "")
			if err != nil || can || string(out) != string(orig) {
				t.Fatalf("unsafe alignment accepted: %v %v %s", err, can, out)
			}
		})
	}
}

func TestPrepareNpmCohortLockPreservesOtherPackages(t *testing.T) {
	for _, lockVersion := range []int{2, 3} {
		t.Run(fmtInt(lockVersion), func(t *testing.T) {
			dir := t.TempDir()
			p := ProjectInfo{Root: dir, Ecosystem: "npm", Manifest: filepath.Join(dir, "package.json"), Lockfile: filepath.Join(dir, "package-lock.json")}
			manifest := []byte(`{"dependencies":{"@angular/core":"20.3.28","unrelated":"^1.0.0"},"devDependencies":{"@angular/compiler-cli":"20.3.28"}}`)
			os.WriteFile(p.Manifest, manifest, 0600)
			lock := map[string]interface{}{"lockfileVersion": lockVersion, "packages": map[string]interface{}{
				"":                                   map[string]interface{}{"name": "example", "dependencies": map[string]string{"@angular/core": "^20.0.0", "unrelated": "^1.0.0"}, "devDependencies": map[string]string{"@angular/compiler-cli": "^20.0.0"}},
				"node_modules/@angular/core":         map[string]string{"version": "20.3.17", "integrity": "old-core"},
				"node_modules/@angular/compiler-cli": map[string]string{"version": "20.3.17"},
				"node_modules/@angular/core/node_modules/subtree": map[string]string{"version": "1.0.0"},
				"node_modules/unrelated":                          map[string]string{"version": "1.2.0", "integrity": "unchanged"},
				"node_modules/owner/node_modules/@angular/core":   map[string]string{"version": "19.0.0"},
			}, "dependencies": map[string]interface{}{"@angular/core": map[string]string{"version": "20.3.17"}, "unrelated": map[string]string{"version": "1.2.0"}}}
			raw, _ := json.Marshal(lock)
			os.WriteFile(p.Lockfile, raw, 0600)
			plan := &FixPlan{Strategy: "peer-cohort-exact", ProposedHash: bytesHash(manifest), TargetVersion: "20.3.28", RelatedChanges: []PlannedDependencyChange{{Package: "@angular/core", ToSpec: "20.3.28"}, {Package: "@angular/compiler-cli", ToSpec: "20.3.28"}}}
			count, err := prepareNpmCohortLock(p, plan)
			if err != nil || count != 3 {
				t.Fatalf("failed %d %v", count, err)
			}
			var after struct {
				Packages     map[string]json.RawMessage
				Dependencies map[string]json.RawMessage
			}
			b, _ := os.ReadFile(p.Lockfile)
			json.Unmarshal(b, &after)
			if _, ok := after.Packages["node_modules/@angular/core"]; ok {
				t.Fatal("stale cohort entry retained")
			}
			if _, ok := after.Packages["node_modules/owner/node_modules/@angular/core"]; !ok {
				t.Fatal("unrelated nested instance removed")
			}
			if _, ok := after.Dependencies["@angular/core"]; ok {
				t.Fatal("v2 stale entry retained")
			}
			if !strings.Contains(string(after.Packages["node_modules/unrelated"]), "unchanged") {
				t.Fatal("unrelated metadata changed")
			}
			var root struct {
				Dependencies    map[string]string
				DevDependencies map[string]string
			}
			json.Unmarshal(after.Packages[""], &root)
			if root.Dependencies["@angular/core"] != "20.3.28" || root.DevDependencies["@angular/compiler-cli"] != "20.3.28" {
				t.Fatal("root constraints not synchronized")
			}
			got, _ := os.ReadFile(p.Manifest)
			if string(got) != string(manifest) {
				t.Fatal("manifest changed")
			}
		})
	}
}

func fmtInt(n int) string {
	if n == 2 {
		return "v2"
	}
	return "v3"
}

func TestPrepareNpmCohortLockRejectsUnapprovedManifest(t *testing.T) {
	dir := t.TempDir()
	p := ProjectInfo{Root: dir, Ecosystem: "npm", Manifest: filepath.Join(dir, "package.json"), Lockfile: filepath.Join(dir, "package-lock.json")}
	os.WriteFile(p.Manifest, []byte(`{"dependencies":{}}`), 0600)
	original := []byte(`{"lockfileVersion":3,"packages":{"":{"name":"example"}}}`)
	os.WriteFile(p.Lockfile, original, 0600)
	_, err := prepareNpmCohortLock(p, &FixPlan{Strategy: "peer-cohort-exact", ProposedHash: "invalid"})
	if err == nil {
		t.Fatal("unapproved manifest accepted")
	}
	after, _ := os.ReadFile(p.Lockfile)
	if string(after) != string(original) {
		t.Fatal("lock changed on error")
	}
}

func TestPatchPomNeverCrossesDependencyBoundary(t *testing.T) {
	orig := []byte(`<project>
<properties>
  <netty-codec.version>4.1.100.Final</netty-codec.version>
  <postgresql.version>42.7.11</postgresql.version>
</properties>
<dependencies>
  <dependency>
    <groupId>io.netty</groupId>
    <artifactId>netty-codec</artifactId>
    <version>${netty-codec.version}</version>
  </dependency>
  <dependency>
    <groupId>org.postgresql</groupId>
    <artifactId>postgresql</artifactId>
    <version>${postgresql.version}</version>
  </dependency>
</dependencies>
</project>`)
	p := ProjectInfo{Ecosystem: "Maven"}
	out, control, can, _, changes, strategy, err := patchPomAligned(p, orig, "org.postgresql:postgresql", "42.7.11", "42.7.12")
	if err != nil {
		t.Fatal(err)
	}
	if !can {
		t.Fatalf("expected safe control point, got %s (%s)", control, strategy)
	}
	if control != "pom.xml property ${postgresql.version}" {
		t.Fatalf("wrong Maven control point selected: %s", control)
	}
	text := string(out)
	if !strings.Contains(text, `<postgresql.version>42.7.12</postgresql.version>`) {
		t.Fatalf("postgresql property was not updated: %s", text)
	}
	if !strings.Contains(text, `<netty-codec.version>4.1.100.Final</netty-codec.version>`) {
		t.Fatalf("unrelated netty property was modified: %s", text)
	}
	if len(changes) != 1 || changes[0].Package != "org.postgresql:postgresql" {
		t.Fatalf("unexpected blast radius: %+v", changes)
	}
}

func TestPatchPomIgnoresTargetCoordinatesInsideExclusion(t *testing.T) {
	orig := []byte(`<project><dependencies>
<dependency><groupId>org.example</groupId><artifactId>wrapper</artifactId><version>1.0.0</version>
  <exclusions><exclusion><groupId>org.postgresql</groupId><artifactId>postgresql</artifactId></exclusion></exclusions>
</dependency>
<dependency><groupId>org.postgresql</groupId><artifactId>postgresql</artifactId><version>42.7.11</version></dependency>
</dependencies></project>`)
	out, control, can, _, err := patchPom(orig, "org.postgresql:postgresql", "42.7.12")
	if err != nil {
		t.Fatal(err)
	}
	if !can || control != "pom.xml dependency org.postgresql:postgresql" {
		t.Fatalf("target dependency not isolated correctly: can=%v control=%s", can, control)
	}
	text := string(out)
	if !strings.Contains(text, `<artifactId>wrapper</artifactId><version>1.0.0</version>`) {
		t.Fatalf("wrapper dependency was altered: %s", text)
	}
	if !strings.Contains(text, `<artifactId>postgresql</artifactId><version>42.7.12</version>`) {
		t.Fatalf("postgresql dependency was not updated: %s", text)
	}
}

func TestMavenTransitiveDependencyGetsLocalDependencyManagementOverride(t *testing.T) {
	orig := []byte(`<project>
  <modelVersion>4.0.0</modelVersion>
  <groupId>org.demo</groupId><artifactId>app</artifactId><version>1.0.0</version>
  <dependencies>
    <dependency><groupId>org.demo</groupId><artifactId>starter</artifactId><version>2.0.0</version></dependency>
  </dependencies>
</project>`)
	p := ProjectInfo{Ecosystem: "Maven"}
	out, control, can, notes, changes, strategy, err := patchPomAligned(p, orig, "org.example:transitive-lib", "11.0.22", "11.0.25")
	if err != nil {
		t.Fatal(err)
	}
	if !can {
		t.Fatalf("expected safe prepared override, control=%s strategy=%s notes=%v", control, strategy, notes)
	}
	if strategy != "maven-transitive-dm-override" {
		t.Fatalf("unexpected strategy: %s", strategy)
	}
	if control != "pom.xml dependencyManagement override org.example:transitive-lib" {
		t.Fatalf("unexpected control point: %s", control)
	}
	text := string(out)
	if !strings.Contains(text, `<dependencyManagement>`) || !strings.Contains(text, `<artifactId>transitive-lib</artifactId>`) || !strings.Contains(text, `<version>11.0.25</version>`) {
		t.Fatalf("override not prepared correctly: %s", text)
	}
	if len(changes) != 1 || changes[0].Package != "org.example:transitive-lib" {
		t.Fatalf("unexpected changes: %+v", changes)
	}
}

func TestMavenTransitiveOverrideUsesExistingDependencyManagement(t *testing.T) {
	orig := []byte(`<project>
  <dependencyManagement>
    <dependencies>
      <dependency><groupId>org.demo</groupId><artifactId>bom</artifactId><version>1.0.0</version><type>pom</type><scope>import</scope></dependency>
    </dependencies>
  </dependencyManagement>
  <dependencies><dependency><groupId>org.demo</groupId><artifactId>starter</artifactId><version>1.0.0</version></dependency></dependencies>
</project>`)
	out, control, can, notes, err := patchPomTransitiveManagedOverride(orig, "org.example:transitive-lib", "3.2.1")
	if err != nil {
		t.Fatal(err)
	}
	if !can {
		t.Fatalf("expected override, control=%s notes=%v", control, notes)
	}
	text := string(out)
	if strings.Count(text, `<dependencyManagement>`) != 1 {
		t.Fatalf("created duplicate dependencyManagement: %s", text)
	}
	if !strings.Contains(text, `<groupId>org.example</groupId>`) || !strings.Contains(text, `<artifactId>transitive-lib</artifactId>`) || !strings.Contains(text, `<version>3.2.1</version>`) {
		t.Fatalf("missing override: %s", text)
	}
}

func TestMavenParserIgnoresPluginDependencies(t *testing.T) {
	orig := []byte(`<project>
  <build><plugins><plugin><groupId>org.demo</groupId><artifactId>plugin</artifactId><dependencies>
    <dependency><groupId>org.example</groupId><artifactId>target</artifactId><version>1.0.0</version></dependency>
  </dependencies></plugin></plugins></build>
  <dependencies><dependency><groupId>org.demo</groupId><artifactId>starter</artifactId><version>2.0.0</version></dependency></dependencies>
</project>`)
	matches := exactPomDependencyBlocks(orig, "org.example", "target")
	if len(matches) != 0 {
		t.Fatalf("plugin dependency must not be considered a project dependency: %+v", matches)
	}
}

func TestMavenProjectPropertyDoesNotPatchProfileProperty(t *testing.T) {
	orig := []byte(`<project>
  <profiles><profile><id>dev</id><properties><lib.version>1.0.0</lib.version></properties></profile></profiles>
  <dependencies><dependency><groupId>org.example</groupId><artifactId>lib</artifactId><version>${lib.version}</version></dependency></dependencies>
</project>`)
	_, _, can, notes, err := patchPom(orig, "org.example:lib", "1.0.1")
	if err != nil {
		t.Fatal(err)
	}
	if can {
		t.Fatalf("profile-only property must not be patched as a root project property")
	}
	if len(notes) == 0 {
		t.Fatal("expected explanatory note")
	}
}

func TestMaterializeSandboxManifestWritesAndVerifiesCandidate(t *testing.T) {
	root := t.TempDir()
	pom := `<project><modelVersion>4.0.0</modelVersion><groupId>demo</groupId><artifactId>app</artifactId><version>1</version><dependencies><dependency><groupId>org.postgresql</groupId><artifactId>postgresql</artifactId><version>42.7.11</version></dependency></dependencies></project>`
	if err := os.WriteFile(filepath.Join(root, "pom.xml"), []byte(pom), 0o644); err != nil {
		t.Fatal(err)
	}
	plan, err := planFix(root, "org.postgresql:postgresql", "42.7.11", "42.7.12", "", "registry", "test")
	if err != nil {
		t.Fatal(err)
	}
	if err := validatePlanProposal(plan); err != nil {
		t.Fatalf("plan should reconstruct exactly: %v", err)
	}
	sandbox := filepath.Join(root, "sandbox-test")
	if err := copyProject(root, sandbox); err != nil {
		t.Fatal(err)
	}
	manifest, gotHash, err := materializeSandboxManifest(plan, sandbox)
	if err != nil {
		t.Fatal(err)
	}
	if gotHash != plan.ProposedHash {
		t.Fatalf("sandbox hash mismatch: got=%s want=%s", gotHash, plan.ProposedHash)
	}
	b, err := os.ReadFile(manifest)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), `<version>42.7.12</version>`) {
		t.Fatalf("candidate version was not materialized: %s", string(b))
	}
	if err := verifySandboxManifestStable(manifest, plan); err != nil {
		t.Fatalf("fresh sandbox manifest must verify: %v", err)
	}
	if err := os.WriteFile(manifest, []byte(pom), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := verifySandboxManifestStable(manifest, plan); err == nil {
		t.Fatal("expected tampered sandbox manifest to be rejected")
	}
}

func TestValidatePlanProposalRejectsTamperedProposedContent(t *testing.T) {
	root := t.TempDir()
	pom := `<project><modelVersion>4.0.0</modelVersion><groupId>demo</groupId><artifactId>app</artifactId><version>1</version><dependencies><dependency><groupId>org.postgresql</groupId><artifactId>postgresql</artifactId><version>42.7.11</version></dependency></dependencies></project>`
	if err := os.WriteFile(filepath.Join(root, "pom.xml"), []byte(pom), 0o644); err != nil {
		t.Fatal(err)
	}
	plan, err := planFix(root, "org.postgresql:postgresql", "42.7.11", "42.7.12", "", "registry", "test")
	if err != nil {
		t.Fatal(err)
	}
	plan.ProposedContent = strings.Replace(plan.ProposedContent, "42.7.12", "42.7.13", 1)
	plan.ProposedHash = bytesHash([]byte(plan.ProposedContent))
	if err := validatePlanProposal(plan); err == nil {
		t.Fatal("tampered plan must not reconstruct successfully")
	}
}

func TestMavenWrapperOnLinuxDoesNotRequireExecutableBit(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("unix-specific")
	}
	dir := t.TempDir()
	wrapper := filepath.Join(dir, "mvnw")
	if err := os.WriteFile(wrapper, []byte("#!/bin/sh\nprintf 'wrapper-ok\\n'\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	p := ProjectInfo{Root: dir}
	if got := mavenCommand(p); got != wrapper {
		t.Fatalf("expected Maven wrapper %q, got %q", wrapper, got)
	}
	res := runCmd(dir, "linux wrapper smoke", wrapper, nil)
	if !res.Success || !strings.Contains(res.Output, "wrapper-ok") {
		t.Fatalf("expected non-executable mvnw to run through /bin/sh: %+v", res)
	}
}

func TestMavenWrapperBootstrapFallbackUsesMatchingSystemMaven(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("portable fallback fixture uses shell scripts")
	}
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "pom.xml"), []byte("<project/>"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "mvnw"), []byte("#!/bin/sh\necho 'Error: Could not find or load main class org.apache.maven.wrapper.MavenWrapperMain' >&2\nexit 1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	props := filepath.Join(root, ".mvn", "wrapper")
	if err := os.MkdirAll(props, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(props, "maven-wrapper.properties"), []byte("distributionUrl=https://repo.example/apache-maven-3.9.9-bin.zip\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	bin := filepath.Join(root, "bin")
	if err := os.MkdirAll(bin, 0o700); err != nil {
		t.Fatal(err)
	}
	fake := filepath.Join(bin, "mvn")
	if err := os.WriteFile(fake, []byte("#!/bin/sh\nif [ \"$1\" = \"-v\" ]; then echo 'Apache Maven 3.9.9'; exit 0; fi\necho SYSTEM_MAVEN_FALLBACK_OK\nexit 0\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	p := ProjectInfo{Root: root, Ecosystem: "Maven", Manifest: filepath.Join(root, "pom.xml")}
	r := runMaven(p, "resolver grafo Maven", []string{"-q", "dependency:resolve"})
	if !r.Success {
		t.Fatalf("expected fallback success, got %+v", r)
	}
	if !strings.Contains(r.Output, "SYSTEM_MAVEN_FALLBACK_OK") || !strings.Contains(r.Output, "fallback seguro") {
		t.Fatalf("expected fallback evidence, got %q", r.Output)
	}
}

func TestMavenWrapperBootstrapFallbackRejectsVersionMismatch(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("portable fallback fixture uses shell scripts")
	}
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "pom.xml"), []byte("<project/>"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "mvnw"), []byte("#!/bin/sh\necho 'Error: Could not find or load main class org.apache.maven.wrapper.MavenWrapperMain' >&2\nexit 1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	props := filepath.Join(root, ".mvn", "wrapper")
	if err := os.MkdirAll(props, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(props, "maven-wrapper.properties"), []byte("distributionUrl=https://repo.example/apache-maven-3.9.9-bin.zip\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	bin := filepath.Join(root, "bin")
	if err := os.MkdirAll(bin, 0o700); err != nil {
		t.Fatal(err)
	}
	fake := filepath.Join(bin, "mvn")
	if err := os.WriteFile(fake, []byte("#!/bin/sh\necho 'Apache Maven 3.8.8'\nexit 0\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	p := ProjectInfo{Root: root, Ecosystem: "Maven", Manifest: filepath.Join(root, "pom.xml")}
	r := runMaven(p, "resolver grafo Maven", []string{"-q", "dependency:resolve"})
	if r.Success {
		t.Fatalf("expected mismatch to remain blocked, got %+v", r)
	}
	if !strings.Contains(r.Reason, "Maven do sistema é 3.8.8") || !strings.Contains(r.Reason, "reprodutibilidade") {
		t.Fatalf("expected version mismatch reason, got %q", r.Reason)
	}
}

func TestHydrateMavenSandboxSupportCopiesWrapperFiles(t *testing.T) {
	root := t.TempDir()
	sandbox := t.TempDir()
	wrapper := filepath.Join(root, ".mvn", "wrapper")
	if err := os.MkdirAll(wrapper, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(wrapper, "maven-wrapper.properties"), []byte("distributionUrl=https://repo.example/apache-maven-3.9.9-bin.zip\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(wrapper, "maven-wrapper.jar"), []byte("wrapper-jar"), 0o644); err != nil {
		t.Fatal(err)
	}
	copied, err := hydrateMavenSandboxSupport(root, sandbox)
	if err != nil {
		t.Fatal(err)
	}
	if len(copied) != 2 {
		t.Fatalf("expected two Maven wrapper files copied, got %v", copied)
	}
	for _, rel := range []string{".mvn/wrapper/maven-wrapper.properties", ".mvn/wrapper/maven-wrapper.jar"} {
		if _, err := os.Stat(filepath.Join(sandbox, filepath.FromSlash(rel))); err != nil {
			t.Fatalf("expected %s in sandbox: %v", rel, err)
		}
	}
}

func TestMavenWrapperBootstrapFallbackWithoutPinnedVersionUsesSystemMaven(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("portable fallback fixture uses shell scripts")
	}
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "pom.xml"), []byte("<project/>"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "mvnw"), []byte("#!/bin/sh\necho './.mvn/wrapper/maven-wrapper.properties: No such file or directory' >&2\necho 'Error: Could not find or load main class org.apache.maven.wrapper.MavenWrapperMain' >&2\nexit 1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	bin := filepath.Join(root, "bin")
	if err := os.MkdirAll(bin, 0o700); err != nil {
		t.Fatal(err)
	}
	fake := filepath.Join(bin, "mvn")
	if err := os.WriteFile(fake, []byte("#!/bin/sh\nif [ \"$1\" = \"-v\" ]; then echo 'Apache Maven 3.9.9'; exit 0; fi\necho SYSTEM_MAVEN_UNPINNED_FALLBACK_OK\nexit 0\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	p := ProjectInfo{Root: root, Ecosystem: "Maven", Manifest: filepath.Join(root, "pom.xml")}
	r := runMaven(p, "resolver grafo Maven", []string{"-q", "dependency:resolve"})
	if !r.Success {
		t.Fatalf("expected controlled fallback success, got %+v", r)
	}
	if !strings.Contains(r.Output, "SYSTEM_MAVEN_UNPINNED_FALLBACK_OK") || !strings.Contains(r.Output, "sem versão pinada verificável") {
		t.Fatalf("expected unpinned fallback evidence, got %q", r.Output)
	}
}
