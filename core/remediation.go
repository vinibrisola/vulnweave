package main

import (
	"bytes"
	"context"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"time"
	"unicode/utf8"
)

func planFix(root, pkg, current, target, targetSpec, targetKind, targetSource string) (*FixPlan, error) {
	current = cleanVersion(current)
	target = cleanVersion(target)
	if current != "" && cmpVersion(target, current) <= 0 {
		return nil, fmt.Errorf("versão alvo %s não é upgrade de %s; remediação automática bloqueada", target, current)
	}
	p, err := detectProject(root)
	if err != nil {
		return nil, err
	}
	orig, err := os.ReadFile(p.Manifest)
	if err != nil {
		return nil, err
	}
	proposed := append([]byte(nil), orig...)
	control := ""
	canApply := false
	notes := []string{}
	related := []PlannedDependencyChange{}
	strategy := "single-dependency"
	if p.Ecosystem == "npm" {
		proposed, control, canApply, notes, related, strategy, err = patchPackageJSONAligned(p, orig, pkg, current, target, targetSpec)
	} else {
		proposed, control, canApply, notes, related, strategy, err = patchPomAligned(p, orig, pkg, current, target)
	}
	if err != nil {
		return nil, err
	}
	id := fmt.Sprintf("%d-%s", time.Now().UnixNano(), safeName(pkg))
	origHash := bytesHash(orig)
	propHash := bytesHash(proposed)
	originalFiles := map[string]string{relOrAbs(p.Root, p.Manifest): origHash}
	if p.Lockfile != "" {
		if h, e := fileHash(p.Lockfile); e == nil {
			originalFiles[relOrAbs(p.Root, p.Lockfile)] = h
		}
	}
	if targetKind == "vendor-tarball" {
		notes = append(notes, "A correção usa um artefato do canal oficial do fornecedor; o install spec será validado antes da execução e o lockfile será regenerado na cópia isolada.")
	}
	plan := &FixPlan{SchemaVersion: "vulnweave.fixplan/2", ID: id, CreatedAt: time.Now().UTC(), ProjectRoot: p.Root, Package: pkg, Ecosystem: p.Ecosystem, CurrentVersion: cleanVersion(current), TargetVersion: cleanVersion(target), TargetSpec: targetSpec, TargetKind: targetKind, TargetSource: targetSource, ControlPoint: control, CanApply: canApply, ManifestPath: p.Manifest, OriginalHash: origHash, ProposedHash: propHash, OriginalContent: string(orig), ProposedContent: string(proposed), Diff: simpleUnifiedDiff(filepath.Base(p.Manifest), string(orig), string(proposed)), OriginalFiles: originalFiles, Notes: notes, RelatedChanges: related, Strategy: strategy}
	planDir := filepath.Join(p.Root, ".vulnweave", "plans")
	if err := os.MkdirAll(planDir, 0o755); err != nil {
		return nil, err
	}
	plan.PlanPath = filepath.Join(planDir, id+".json")
	if err := writeJSON(plan.PlanPath, plan); err != nil {
		return nil, err
	}
	return plan, nil
}

func safeName(s string) string {
	re := regexp.MustCompile(`[^A-Za-z0-9._-]+`)
	x := re.ReplaceAllString(s, "-")
	if len(x) > 50 {
		x = x[:50]
	}
	return strings.Trim(x, "-")
}

type npmManifestDecl struct {
	Section string
	Spec    string
}

type npmLockPackage struct {
	Version          string            `json:"version"`
	PeerDependencies map[string]string `json:"peerDependencies"`
}

func npmManifestDeclarations(orig []byte) (map[string]npmManifestDecl, error) {
	var data map[string]interface{}
	if err := json.Unmarshal(orig, &data); err != nil {
		return nil, err
	}
	out := map[string]npmManifestDecl{}
	for _, sec := range []string{"dependencies", "devDependencies", "peerDependencies", "optionalDependencies"} {
		m, _ := data[sec].(map[string]interface{})
		for name, raw := range m {
			if spec, ok := raw.(string); ok {
				out[name] = npmManifestDecl{Section: sec, Spec: spec}
			}
		}
	}
	return out, nil
}

func npmRootLockPackages(lockfile string) (map[string]npmLockPackage, error) {
	if lockfile == "" || !strings.HasSuffix(strings.ToLower(lockfile), "package-lock.json") {
		return nil, nil
	}
	b, err := os.ReadFile(lockfile)
	if err != nil {
		return nil, err
	}
	var lock struct {
		Packages map[string]npmLockPackage `json:"packages"`
	}
	if err := json.Unmarshal(b, &lock); err != nil {
		return nil, err
	}
	out := map[string]npmLockPackage{}
	for lockPath, entry := range lock.Packages {
		p := filepath.ToSlash(lockPath)
		if !strings.HasPrefix(p, "node_modules/") {
			continue
		}
		rest := strings.TrimPrefix(p, "node_modules/")
		if strings.Contains(rest, "/node_modules/") {
			continue
		}
		// Scoped package paths contain one slash as part of the package name.
		if strings.HasPrefix(rest, "@") {
			if strings.Count(rest, "/") != 1 {
				continue
			}
		} else if strings.Contains(rest, "/") {
			continue
		}
		out[rest] = entry
	}
	return out, nil
}

func exactPeerPinsVersion(spec, version string) bool {
	s := strings.TrimSpace(spec)
	v := cleanVersion(version)
	if v == "" || s == "" {
		return false
	}
	if strings.HasPrefix(s, "=") {
		s = strings.TrimSpace(strings.TrimPrefix(s, "="))
	}
	return s == v || s == "v"+v
}

func patchJSONDependencyLiteral(orig []byte, pkg, oldSpec, newSpec string) ([]byte, error) {
	pattern := regexp.MustCompile(`(?m)(["']` + regexp.QuoteMeta(pkg) + `["']\s*:\s*["'])` + regexp.QuoteMeta(oldSpec) + `(["'])`)
	matches := pattern.FindAllSubmatchIndex(orig, -1)
	if len(matches) != 1 {
		return nil, fmt.Errorf("declaração de %s não é inequívoca no package.json (%d ocorrências)", pkg, len(matches))
	}
	m := matches[0]
	out := make([]byte, 0, len(orig)+len(newSpec)-len(oldSpec))
	out = append(out, orig[:m[3]]...)
	out = append(out, []byte(newSpec)...)
	out = append(out, orig[m[4]:]...)
	return out, nil
}

func specForTarget(old, target string) string {
	trim := strings.TrimSpace(old)
	prefix := ""
	if strings.HasPrefix(trim, "^") {
		prefix = "^"
	} else if strings.HasPrefix(trim, "~") {
		prefix = "~"
	}
	return prefix + cleanVersion(target)
}

// Angular framework packages share exact release peers. CLI/build and
// Material/CDK have independent release trains and must not be blanket-pinned.
func angularFrameworkPackage(name string) bool {
	switch name {
	case "@angular/animations", "@angular/common", "@angular/compiler", "@angular/core", "@angular/forms", "@angular/platform-browser", "@angular/platform-browser-dynamic", "@angular/platform-server", "@angular/router", "@angular/compiler-cli", "@angular/localize", "@angular/service-worker", "@angular/upgrade", "@angular/elements":
		return true
	}
	return false
}

func sameReleaseLine(a, b string) bool {
	x, y := strings.Split(cleanVersion(a), "."), strings.Split(cleanVersion(b), ".")
	return len(x) == 3 && len(y) == 3 && x[0] == y[0] && x[1] == y[1]
}

// patchPackageJSONAligned upgrades the vulnerable package and, when package-lock
// proves an exact peer-version cohort, upgrades the directly declared cohort as
// one unit. This avoids accepting npm's ERESOLVE "overriding peer dependency"
// warnings as a safe remediation (Angular framework packages are a common case).
func patchPackageJSONAligned(p ProjectInfo, orig []byte, pkg, current, target, targetSpec string) ([]byte, string, bool, []string, []PlannedDependencyChange, string, error) {
	base, control, can, notes, err := patchPackageJSON(orig, pkg, target, targetSpec)
	if err != nil || !can || strings.TrimSpace(targetSpec) != "" {
		return base, control, can, notes, nil, "single-dependency", err
	}
	decls, err := npmManifestDeclarations(orig)
	if err != nil {
		return nil, "", false, nil, nil, "single-dependency", err
	}
	primary, ok := decls[pkg]
	if !ok {
		return base, control, can, notes, nil, "single-dependency", nil
	}
	lockPkgs, lockErr := npmRootLockPackages(p.Lockfile)
	if lockErr != nil || len(lockPkgs) == 0 {
		if angularFrameworkPackage(pkg) {
			return orig, control, false, append(notes, "O conjunto Angular exige package-lock.json v2/v3 legível para revisar as versões relacionadas. Gere um lockfile válido antes de preparar a correção."), nil, "peer-cohort-exact", nil
		}
		return base, control, can, append(notes, "Não foi possível inferir um cohort de peerDependencies a partir do package-lock; a validação estrita do grafo continuará sendo o gate."), nil, "single-dependency", nil
	}
	cur := cleanVersion(current)
	cohort := map[string]bool{pkg: true}
	if angularFrameworkPackage(pkg) {
		if !sameReleaseLine(cur, target) {
			return orig, control, false, append(notes, "Mudança de major/minor Angular exige ng update e revisão das migrations; a troca automática de patch foi bloqueada."), nil, "peer-cohort-exact", nil
		}
		for name, decl := range decls {
			if !angularFrameworkPackage(name) {
				continue
			}
			entry, exists := lockPkgs[name]
			if !exists || !sameReleaseLine(entry.Version, target) || cmpVersion(entry.Version, target) > 0 || !regexp.MustCompile(`^[~^=]?v?\d+\.\d+\.\d+$`).MatchString(decl.Spec) {
				return orig, control, false, append(notes, "Não foi possível alinhar "+name+" com segurança: lock ausente, linha de release diferente, downgrade ou declaração especial. Revise o conjunto Angular antes de continuar."), nil, "peer-cohort-exact", nil
			}
			cohort[name] = true
		}
	}
	changed := true
	for changed {
		changed = false
		// Direction 1: packages already in the cohort can exact-pin other direct peers.
		for member := range cohort {
			entry, ok := lockPkgs[member]
			if !ok {
				continue
			}
			for peer, spec := range entry.PeerDependencies {
				_, direct := decls[peer]
				if !direct || cohort[peer] {
					continue
				}
				if lp, exists := lockPkgs[peer]; exists && exactPeerPinsVersion(spec, lp.Version) && sameReleaseLine(lp.Version, target) && cmpVersion(lp.Version, target) <= 0 {
					cohort[peer] = true
					changed = true
				}
			}
		}
		// Direction 2: direct packages that exact-pin a cohort member belong to the same release set.
		for owner := range decls {
			if cohort[owner] {
				continue
			}
			entry, ok := lockPkgs[owner]
			if !ok || !sameReleaseLine(entry.Version, target) || cmpVersion(entry.Version, target) > 0 {
				continue
			}
			for peer, spec := range entry.PeerDependencies {
				if cohort[peer] && exactPeerPinsVersion(spec, lockPkgs[peer].Version) {
					cohort[owner] = true
					changed = true
					break
				}
			}
		}
	}

	out := base
	members := make([]string, 0, len(cohort))
	for name := range cohort {
		if name != pkg {
			members = append(members, name)
		}
	}
	sort.Strings(members)

	// Tight peer cohorts (Angular framework packages are a canonical example)
	// must be validated at ONE exact release. Preserving a caret here lets the
	// package manager independently choose a newer patch for each root package
	// (for example 20.3.33 while the security target is 20.3.28), which can make
	// exact peerDependencies impossible to satisfy. Single-package remediations
	// still preserve the project's original ^/~ policy; coordinated cohorts are
	// deliberately pinned to the validated patch for deterministic resolution.
	if len(members) > 0 {
		exact := cleanVersion(target)
		primaryPatched := specForTarget(primary.Spec, target)
		var patchErr error
		out, patchErr = patchJSONDependencyLiteral(out, pkg, primaryPatched, exact)
		if patchErr != nil {
			return orig, control, false, append(notes, "O pacote principal do cohort não pôde ser fixado de forma determinística: "+patchErr.Error()), nil, "peer-cohort", nil
		}
		related := []PlannedDependencyChange{{Package: pkg, FromSpec: primary.Spec, ToSpec: exact, CurrentVersion: cur, TargetVersion: exact, Reason: "dependência vulnerável; pin exato para validar o release cohort"}}
		for _, name := range members {
			decl := decls[name]
			out, patchErr = patchJSONDependencyLiteral(out, name, decl.Spec, exact)
			if patchErr != nil {
				return orig, control, false, append(notes, "O cohort de peerDependencies foi detectado, mas não pôde ser alterado de forma inequívoca: "+patchErr.Error()), related, "peer-cohort", nil
			}
			related = append(related, PlannedDependencyChange{Package: name, FromSpec: decl.Spec, ToSpec: exact, CurrentVersion: cleanVersion(lockPkgs[name].Version), TargetVersion: exact, Reason: "pacote do conjunto de compatibilidade; pin determinístico"})
		}
		notes = append(notes, fmt.Sprintf("Remediação coordenada determinística: %d pacote(s) relacionado(s) + %s foram fixados exatamente em %s. Isso impede que ranges ^/~ selecionem patches diferentes durante a validação. O grafo resolvido será conferido antes de build/testes.", len(members), pkg, exact))
		return out, "package.json > exact peer dependency cohort > " + pkg, true, notes, related, "peer-cohort-exact", nil
	}
	related := []PlannedDependencyChange{{Package: pkg, FromSpec: primary.Spec, ToSpec: specForTarget(primary.Spec, target), CurrentVersion: cur, TargetVersion: cleanVersion(target), Reason: "dependência vulnerável selecionada"}}
	return out, control, true, notes, related, "single-dependency", nil
}

func patchPackageJSON(orig []byte, pkg, target, targetSpec string) ([]byte, string, bool, []string, error) {
	var data map[string]interface{}
	if err := json.Unmarshal(orig, &data); err != nil {
		return nil, "", false, nil, err
	}
	sections := []string{"dependencies", "devDependencies", "peerDependencies", "optionalDependencies"}
	found := ""
	old := ""
	for _, sec := range sections {
		if m, ok := data[sec].(map[string]interface{}); ok {
			if v, ok := m[pkg].(string); ok {
				found = sec
				old = v
				break
			}
		}
	}
	if found == "" {
		return orig, "transitive", false, []string{"A dependência não é declarada diretamente no package.json. O VulnWeave não adiciona overrides automaticamente porque isso pode alterar o grafo de forma incompatível."}, nil
	}
	prefix := ""
	trim := strings.TrimSpace(old)
	if strings.HasPrefix(trim, "^") {
		prefix = "^"
	} else if strings.HasPrefix(trim, "~") {
		prefix = "~"
	}
	// Preserve formatting by replacing only the exact property value in the source.
	pattern := regexp.MustCompile(`(?m)(["']` + regexp.QuoteMeta(pkg) + `["']\s*:\s*["'])` + regexp.QuoteMeta(old) + `(["'])`)
	if !pattern.Match(orig) {
		return nil, "", false, nil, fmt.Errorf("não foi possível localizar a declaração exata de %s no package.json", pkg)
	}
	newValue := prefix + cleanVersion(target)
	notes := []string{"O operador de range original foi preservado quando era ^ ou ~. O lockfile continuará sendo a versão efetivamente reproduzível."}
	if strings.TrimSpace(targetSpec) != "" {
		newValue = strings.TrimSpace(targetSpec)
		notes = []string{"A declaração será alterada para um install spec de fornecedor previamente confiado; ranges ^/~ não são preservados para URLs de artefato."}
	}
	loc := pattern.FindSubmatchIndex(orig)
	if loc == nil {
		return nil, "", false, nil, fmt.Errorf("não foi possível localizar a declaração exata de %s no package.json", pkg)
	}
	// Build the replacement with literal bytes. Never feed user/vendor values into regexp replacement expansion ($1, $2 semantics).
	out := make([]byte, 0, len(orig)+len(newValue)-len(old))
	out = append(out, orig[:loc[3]]...)
	out = append(out, []byte(newValue)...)
	out = append(out, orig[loc[4]:]...)
	return out, "package.json > " + found + " > " + pkg, true, notes, nil
}

type pomDependencyBlock struct {
	Start, End      int
	Group, Artifact string
	Version         string
	HasVersion      bool
	Kind            string // direct | managed
}

type pomXMLFrame struct {
	Name  string
	Start int
	Kind  string
}

// parsePomDependencyBlocks uses the XML token stream to keep dependency blocks
// inside their real Maven scope. It intentionally ignores plugin dependencies,
// exclusions, profiles and unrelated nested <dependency> elements. The previous
// regexp-only parser could not distinguish those locations reliably.
func parsePomDependencyBlocks(orig []byte) []pomDependencyBlock {
	dec := xml.NewDecoder(bytes.NewReader(orig))
	stack := []pomXMLFrame{}
	out := []pomDependencyBlock{}
	for {
		start := int(dec.InputOffset())
		tok, err := dec.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			break
		}
		end := int(dec.InputOffset())
		switch t := tok.(type) {
		case xml.StartElement:
			name := t.Name.Local
			kind := ""
			if name == "dependency" {
				if len(stack) == 2 && stack[0].Name == "project" && stack[1].Name == "dependencies" {
					kind = "direct"
				} else if len(stack) == 3 && stack[0].Name == "project" && stack[1].Name == "dependencyManagement" && stack[2].Name == "dependencies" {
					kind = "managed"
				}
			}
			stack = append(stack, pomXMLFrame{Name: name, Start: start, Kind: kind})
		case xml.EndElement:
			if len(stack) == 0 {
				continue
			}
			f := stack[len(stack)-1]
			stack = stack[:len(stack)-1]
			if f.Name != "dependency" || f.Kind == "" || f.Start < 0 || end > len(orig) || f.Start >= end {
				continue
			}
			raw := orig[f.Start:end]
			var d pomDependency
			if err := xml.Unmarshal(raw, &d); err != nil {
				continue
			}
			g := strings.TrimSpace(d.GroupID)
			a := strings.TrimSpace(d.ArtifactID)
			if g == "" || a == "" {
				continue
			}
			v := strings.TrimSpace(d.Version)
			out = append(out, pomDependencyBlock{Start: f.Start, End: end, Group: g, Artifact: a, Version: v, HasVersion: v != "", Kind: f.Kind})
		}
	}
	return out
}

func exactPomDependencyBlocks(orig []byte, group, artifact string, kinds ...string) []pomDependencyBlock {
	allowed := map[string]bool{}
	for _, k := range kinds {
		allowed[k] = true
	}
	out := []pomDependencyBlock{}
	for _, b := range parsePomDependencyBlocks(orig) {
		if b.Group == group && b.Artifact == artifact && (len(allowed) == 0 || allowed[b.Kind]) {
			out = append(out, b)
		}
	}
	return out
}

func topLevelPomElementRange(orig []byte, element string) (int, int, bool) {
	dec := xml.NewDecoder(bytes.NewReader(orig))
	stack := []pomXMLFrame{}
	for {
		start := int(dec.InputOffset())
		tok, err := dec.Token()
		if err == io.EOF {
			return 0, 0, false
		}
		if err != nil {
			return 0, 0, false
		}
		end := int(dec.InputOffset())
		switch t := tok.(type) {
		case xml.StartElement:
			name := t.Name.Local
			stack = append(stack, pomXMLFrame{Name: name, Start: start})
		case xml.EndElement:
			if len(stack) == 0 {
				continue
			}
			f := stack[len(stack)-1]
			stack = stack[:len(stack)-1]
			if f.Name == element && len(stack) == 1 && stack[0].Name == "project" {
				return f.Start, end, true
			}
		}
	}
}

func projectPropertyMatch(orig []byte, prop string) ([]int, bool) {
	start, end, ok := topLevelPomElementRange(orig, "properties")
	if !ok || start < 0 || end > len(orig) || start >= end {
		return nil, false
	}
	block := orig[start:end]
	re := regexp.MustCompile(`(?s)(<` + regexp.QuoteMeta(prop) + `>\s*)([^<]+?)(\s*</` + regexp.QuoteMeta(prop) + `>)`)
	matches := re.FindAllSubmatchIndex(block, -1)
	if len(matches) != 1 {
		return nil, false
	}
	m := append([]int(nil), matches[0]...)
	for i := range m {
		if m[i] >= 0 {
			m[i] += start
		}
	}
	return m, true
}

func replaceProjectProperty(orig []byte, prop, target string) ([]byte, bool) {
	m, ok := projectPropertyMatch(orig, prop)
	if !ok {
		return orig, false
	}
	out := make([]byte, 0, len(orig)+len(target))
	out = append(out, orig[:m[4]]...)
	out = append(out, []byte(cleanVersion(target))...)
	out = append(out, orig[m[5]:]...)
	return out, true
}

func newlineFor(orig []byte) string {
	if bytes.Contains(orig, []byte("\r\n")) {
		return "\r\n"
	}
	return "\n"
}

func lineIndentStart(orig []byte, pos int) int {
	if pos < 0 {
		return pos
	}
	if pos > len(orig) {
		pos = len(orig)
	}
	i := pos
	for i > 0 && (orig[i-1] == ' ' || orig[i-1] == '\t') {
		i--
	}
	if i == 0 || orig[i-1] == '\n' || orig[i-1] == '\r' {
		return i
	}
	return pos
}

// patchPomTransitiveManagedOverride creates a local dependencyManagement override
// for a dependency that is only transitive or is managed exclusively by an
// external Parent/BOM. Maven documents dependencyManagement as the supported
// mechanism for controlling versions of transitive dependencies. This only
// prepares a diff; the change is never applied until dependency:tree, build,
// tests and a complete rescan all pass in the isolated copy.
func patchPomTransitiveManagedOverride(orig []byte, pkg, target string) ([]byte, string, bool, []string, error) {
	parts := strings.SplitN(pkg, ":", 2)
	if len(parts) != 2 || strings.TrimSpace(parts[0]) == "" || strings.TrimSpace(parts[1]) == "" {
		return orig, "transitive-or-managed", false, nil, fmt.Errorf("coordenada Maven inválida: %s", pkg)
	}
	group, artifact := strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1])
	if len(exactPomDependencyBlocks(orig, group, artifact, "managed")) > 0 {
		return orig, "dependencyManagement/ambiguous", false, []string{"Já existe controle local em dependencyManagement; o VulnWeave não criará uma segunda declaração."}, nil
	}
	nl := newlineFor(orig)
	entry := "      <dependency>" + nl +
		"        <groupId>" + group + "</groupId>" + nl +
		"        <artifactId>" + artifact + "</artifactId>" + nl +
		"        <version>" + cleanVersion(target) + "</version>" + nl +
		"      </dependency>"

	if dmStart, dmEnd, ok := topLevelPomElementRange(orig, "dependencyManagement"); ok {
		block := orig[dmStart:dmEnd]
		depsRe := regexp.MustCompile(`(?s)<dependencies(?:\s[^>]*)?>(.*?)</dependencies>`)
		loc := depsRe.FindSubmatchIndex(block)
		if loc == nil {
			return orig, "dependencyManagement/invalid", false, []string{"dependencyManagement local existe, mas não contém um bloco <dependencies> inequívoco."}, nil
		}
		// loc[3] is the end of the inner capture, immediately before </dependencies>.
		insertAt := lineIndentStart(orig, dmStart+loc[3])
		insert := []byte(entry + nl + "    ")
		out := make([]byte, 0, len(orig)+len(insert))
		out = append(out, orig[:insertAt]...)
		out = append(out, insert...)
		out = append(out, orig[insertAt:]...)
		return out, "pom.xml dependencyManagement override " + pkg, true, []string{
			"A dependência é transitiva ou herdada de Parent/BOM; o VulnWeave preparou um override local explícito em dependencyManagement em vez de adicionar uma dependência direta.",
			"Esse override pode afetar todos os caminhos do grafo que usam o artefato. dependency:tree, build, testes e rescan completo são obrigatórios antes de qualquer aplicação.",
		}, nil
	}

	insertAt := -1
	if depsStart, _, ok := topLevelPomElementRange(orig, "dependencies"); ok {
		insertAt = lineIndentStart(orig, depsStart)
	} else if idx := bytes.LastIndex(orig, []byte("</project>")); idx >= 0 {
		insertAt = lineIndentStart(orig, idx)
	}
	if insertAt < 0 {
		return orig, "pom.xml/invalid", false, []string{"Não foi possível localizar um ponto seguro para inserir dependencyManagement no POM."}, nil
	}
	block := "  <dependencyManagement>" + nl +
		"    <dependencies>" + nl + entry + nl +
		"    </dependencies>" + nl +
		"  </dependencyManagement>" + nl + nl
	out := make([]byte, 0, len(orig)+len(block))
	out = append(out, orig[:insertAt]...)
	out = append(out, []byte(block)...)
	out = append(out, orig[insertAt:]...)
	return out, "pom.xml dependencyManagement override " + pkg, true, []string{
		"A dependência é transitiva ou herdada de Parent/BOM e não havia dependencyManagement local; o VulnWeave preparou um override local explícito.",
		"Esse override pode afetar todos os caminhos do grafo que usam o artefato. dependency:tree, build, testes e rescan completo são obrigatórios antes de qualquer aplicação.",
	}, nil
}

func patchPom(orig []byte, pkg, target string) ([]byte, string, bool, []string, error) {
	parts := strings.SplitN(pkg, ":", 2)
	if len(parts) != 2 {
		return nil, "", false, nil, fmt.Errorf("coordenada Maven inválida: %s", pkg)
	}
	group, artifact := parts[0], parts[1]
	matches := exactPomDependencyBlocks(orig, group, artifact, "direct")
	if len(matches) == 0 {
		return orig, "transitive-or-managed", false, []string{"A dependência não tem um ponto de controle direto inequívoco neste pom.xml. Ela pode vir de Parent/BOM/dependencyManagement/transitividade; não será alterada automaticamente."}, nil
	}
	if len(matches) != 1 {
		return orig, "dependencyManagement/ambiguous", false, []string{fmt.Sprintf("A coordenada %s aparece em %d blocos Maven; o VulnWeave não escolhe um bloco por posição. Será tentado um único controle gerenciado inequívoco.", pkg, len(matches))}, nil
	}
	match := matches[0]
	block := string(orig[match.Start:match.End])
	versionRe := regexp.MustCompile(`(?s)<version>\s*([^<]+?)\s*</version>`)
	vm := versionRe.FindStringSubmatch(block)
	if vm == nil {
		return orig, "dependencyManagement/parent", false, []string{"A dependência está declarada sem <version>; a versão é controlada fora deste bloco (dependencyManagement, BOM ou Parent). O VulnWeave não força uma versão local silenciosamente."}, nil
	}
	old := strings.TrimSpace(vm[1])
	if strings.HasPrefix(old, "${") && strings.HasSuffix(old, "}") {
		prop := strings.TrimSuffix(strings.TrimPrefix(old, "${"), "}")
		out, ok := replaceProjectProperty(orig, prop, target)
		if !ok {
			return orig, "property:" + prop, false, []string{fmt.Sprintf("A propriedade %s não foi localizada de forma única em <project><properties>; revisão manual necessária.", prop)}, nil
		}
		return out, "pom.xml property ${" + prop + "}", true, []string{"A propriedade Maven que controla a versão será alterada. Revise o blast radius: outras dependências podem reutilizar a mesma propriedade."}, nil
	}
	newBlock := versionRe.ReplaceAllString(block, "<version>"+cleanVersion(target)+"</version>")
	out := append([]byte{}, orig[:match.Start]...)
	out = append(out, []byte(newBlock)...)
	out = append(out, orig[match.End:]...)
	return out, "pom.xml dependency " + pkg, true, nil, nil
}

func pomDependencyBlocks(orig []byte) []struct {
	Group, Artifact, Version string
} {
	blocks := []struct{ Group, Artifact, Version string }{}
	for _, b := range parsePomDependencyBlocks(orig) {
		if !b.HasVersion {
			continue
		}
		blocks = append(blocks, struct{ Group, Artifact, Version string }{b.Group, b.Artifact, b.Version})
	}
	return blocks
}

func patchPomArtifactLiteral(orig []byte, group, artifact, oldVersion, target string) ([]byte, error) {
	matches := exactPomDependencyBlocks(orig, group, artifact, "direct")
	if len(matches) != 1 {
		return nil, fmt.Errorf("dependência Maven %s:%s não é inequívoca (%d blocos)", group, artifact, len(matches))
	}
	loc := matches[0]
	block := orig[loc.Start:loc.End]
	verRe := regexp.MustCompile(`(?s)(<version>\s*)` + regexp.QuoteMeta(oldVersion) + `(\s*</version>)`)
	vm := verRe.FindAllSubmatchIndex(block, -1)
	if len(vm) != 1 {
		return nil, fmt.Errorf("versão explícita de %s:%s não é inequívoca", group, artifact)
	}
	m := vm[0]
	newBlock := make([]byte, 0, len(block)+len(target)-len(oldVersion))
	newBlock = append(newBlock, block[:m[3]]...)
	newBlock = append(newBlock, []byte(cleanVersion(target))...)
	newBlock = append(newBlock, block[m[4]:]...)
	out := append([]byte{}, orig[:loc.Start]...)
	out = append(out, newBlock...)
	out = append(out, orig[loc.End:]...)
	return out, nil
}

func patchPomManagedControl(orig []byte, pkg, target string) ([]byte, string, bool, []string, error) {
	parts := strings.SplitN(pkg, ":", 2)
	if len(parts) != 2 {
		return orig, "transitive-or-managed", false, nil, nil
	}
	group, artifact := parts[0], parts[1]
	matches := exactPomDependencyBlocks(orig, group, artifact, "managed")
	withVersion := []pomDependencyBlock{}
	for _, m := range matches {
		if m.HasVersion {
			withVersion = append(withVersion, m)
		}
	}
	if len(withVersion) != 1 {
		return orig, "dependencyManagement/parent", false, []string{"A versão é gerenciada fora da dependência direta e não há um único ponto de controle local inequívoco; Parent/BOM externo continua exigindo revisão manual."}, nil
	}
	c := withVersion[0]
	if strings.HasPrefix(c.Version, "${") && strings.HasSuffix(c.Version, "}") {
		prop := strings.TrimSuffix(strings.TrimPrefix(c.Version, "${"), "}")
		out, ok := replaceProjectProperty(orig, prop, target)
		if !ok {
			return orig, "dependencyManagement property ${" + prop + "}", false, []string{"A propriedade que controla dependencyManagement não foi localizada de forma única em <project><properties>."}, nil
		}
		return out, "pom.xml dependencyManagement property ${" + prop + "}", true, []string{"A dependência herda a versão de dependencyManagement; a propriedade gerenciada local será alterada e o Maven validará o modelo efetivo."}, nil
	}
	block := string(orig[c.Start:c.End])
	versionRe := regexp.MustCompile(`(?s)<version>\s*([^<]+?)\s*</version>`)
	newBlock := versionRe.ReplaceAllString(block, "<version>"+cleanVersion(target)+"</version>")
	out := append([]byte{}, orig[:c.Start]...)
	out = append(out, []byte(newBlock)...)
	out = append(out, orig[c.End:]...)
	return out, "pom.xml dependencyManagement " + pkg, true, []string{"A dependência direta herda a versão de dependencyManagement; o ponto de controle gerenciado será alterado e validado no modelo efetivo."}, nil
}

// patchPomAligned preserves Maven's central version controls. When the selected
// dependency is controlled by a property, changing that property naturally aligns
// every consumer. When versions are explicit, artifacts from the same groupId at
// the exact same current version are treated as a release cohort and validated
// together by Maven dependency resolution + build + tests.

func patchPomAligned(p ProjectInfo, orig []byte, pkg, current, target string) ([]byte, string, bool, []string, []PlannedDependencyChange, string, error) {
	base, control, can, notes, err := patchPom(orig, pkg, target)
	if err != nil {
		return base, control, can, notes, nil, "maven-single-or-managed", err
	}
	if !can {
		managed, managedControl, managedCan, managedNotes, managedErr := patchPomManagedControl(orig, pkg, target)
		if managedErr != nil {
			return nil, managedControl, false, managedNotes, nil, "maven-managed", managedErr
		}
		if !managedCan {
			override, overrideControl, overrideCan, overrideNotes, overrideErr := patchPomTransitiveManagedOverride(orig, pkg, target)
			if overrideErr != nil {
				return nil, overrideControl, false, overrideNotes, nil, "maven-transitive-dm-override", overrideErr
			}
			if !overrideCan {
				return base, control, false, append(append(notes, managedNotes...), overrideNotes...), nil, "maven-single-or-managed", nil
			}
			base, control, can, notes = override, overrideControl, true, overrideNotes
			return base, control, can, notes, []PlannedDependencyChange{{Package: pkg, CurrentVersion: cleanVersion(current), TargetVersion: cleanVersion(target), Reason: "override local de dependência transitiva/gerenciada externamente"}}, "maven-transitive-dm-override", nil
		}
		base, control, can, notes = managed, managedControl, true, append(notes, managedNotes...)
	}
	parts := strings.SplitN(pkg, ":", 2)
	if len(parts) != 2 {
		return base, control, can, notes, nil, "maven-single", nil
	}
	group, artifact := parts[0], parts[1]
	cur := cleanVersion(current)
	related := []PlannedDependencyChange{{Package: pkg, CurrentVersion: cur, TargetVersion: cleanVersion(target), Reason: "dependência vulnerável selecionada"}}
	if strings.HasPrefix(control, "pom.xml property ${") {
		prop := strings.TrimSuffix(strings.TrimPrefix(control, "pom.xml property ${"), "}")
		for _, d := range pomDependencyBlocks(orig) {
			coord := d.Group + ":" + d.Artifact
			if coord != pkg && d.Version == "${"+prop+"}" {
				related = append(related, PlannedDependencyChange{Package: coord, FromSpec: d.Version, ToSpec: d.Version, CurrentVersion: cur, TargetVersion: cleanVersion(target), Reason: "usa a mesma propriedade Maven " + prop})
			}
		}
		notes = append(notes, "A propriedade Maven compartilhada será alterada como unidade de alinhamento; todos os consumidores da propriedade entram no blast radius e serão validados juntos.")
		return base, control, can, notes, related, "maven-shared-property", nil
	}
	out := base
	count := 0
	seen := map[string]bool{artifact: true}
	for _, d := range pomDependencyBlocks(orig) {
		if d.Group != group || d.Artifact == artifact || seen[d.Artifact] {
			continue
		}
		if cleanVersion(d.Version) != cur || strings.Contains(d.Version, "${") {
			continue
		}
		var patchErr error
		out, patchErr = patchPomArtifactLiteral(out, group, d.Artifact, d.Version, target)
		if patchErr != nil {
			return orig, control, false, append(notes, "O release cohort Maven foi detectado, mas não pôde ser alterado de forma inequívoca: "+patchErr.Error()), related, "maven-release-cohort", nil
		}
		seen[d.Artifact] = true
		count++
		related = append(related, PlannedDependencyChange{Package: group + ":" + d.Artifact, FromSpec: d.Version, ToSpec: cleanVersion(target), CurrentVersion: cur, TargetVersion: cleanVersion(target), Reason: "mesmo groupId e mesma versão explícita do release cohort"})
	}
	if count > 0 {
		notes = append(notes, fmt.Sprintf("Remediação Maven coordenada: %d artefato(s) do mesmo groupId/release foram alinhados. dependency:resolve, build e testes continuam obrigatórios.", count))
		return out, "pom.xml > Maven release cohort > " + group, true, notes, related, "maven-release-cohort", nil
	}
	return out, control, can, notes, related, "maven-single", nil
}

func resolveBaselineGraph(p ProjectInfo) CommandResult {
	if p.Ecosystem == "npm" {
		if strings.TrimSpace(p.Lockfile) == "" {
			return CommandResult{Name: "baseline grafo/lockfile", Skipped: true, Success: false, Reason: "lockfile não encontrado"}
		}
		pm := nodePackageManager(p)
		switch pm {
		case "pnpm":
			return runCmd(p.Root, "baseline grafo/lockfile", "pnpm", []string{"install", "--frozen-lockfile", "--ignore-scripts"})
		case "yarn":
			if _, err := os.Stat(filepath.Join(p.Root, ".yarnrc.yml")); err == nil {
				return runCmd(p.Root, "baseline grafo/lockfile", "yarn", []string{"install", "--immutable", "--mode=skip-builds"})
			}
			return runCmd(p.Root, "baseline grafo/lockfile", "yarn", []string{"install", "--frozen-lockfile", "--ignore-scripts"})
		case "bun":
			return runCmd(p.Root, "baseline grafo/lockfile", "bun", []string{"install", "--frozen-lockfile", "--ignore-scripts"})
		default:
			return runCmd(p.Root, "baseline grafo/lockfile", "npm", []string{"ci", "--ignore-scripts", "--no-audit", "--no-fund"})
		}
	}
	return runMaven(p, "baseline grafo Maven", []string{"-q", "-DskipTests", "dependency:resolve"})
}

func compareFailedBuildWithBaseline(plan *FixPlan, candidateRoot string) (*CommandResult, string) {
	baselineRoot := candidateRoot + "-baseline"
	_ = os.RemoveAll(baselineRoot)
	defer os.RemoveAll(baselineRoot)
	if err := copyProject(plan.ProjectRoot, baselineRoot); err != nil {
		return nil, "comparação com baseline indisponível: não foi possível criar a cópia original"
	}
	p, err := detectProject(baselineRoot)
	if err != nil {
		return nil, "comparação com baseline indisponível: projeto original não pôde ser detectado"
	}
	lock := resolveBaselineGraph(p)
	if !lock.Success || lock.Skipped {
		return nil, "comparação com baseline indisponível: o grafo original não pôde ser reproduzido"
	}
	b := runDefaultBuild(p)
	if b.Success && !b.Skipped {
		return &b, "regressão provável: o build do baseline original passa e o build com a correção falha"
	}
	return &b, "inconclusivo: o build do baseline original também falha; a falha não pode ser atribuída automaticamente à correção"
}

type remediationProgress struct {
	Stage               string    `json:"stage"`
	Message             string    `json:"message"`
	Step                int       `json:"step"`
	Total               int       `json:"total"`
	SandboxRoot         string    `json:"sandboxRoot,omitempty"`
	SandboxManifestPath string    `json:"sandboxManifestPath,omitempty"`
	PatchVerified       bool      `json:"patchVerified"`
	UpdatedAt           time.Time `json:"updatedAt"`
}

func executionProgressPath(planPath string) string {
	ext := filepath.Ext(planPath)
	if ext == "" {
		return planPath + ".progress.json"
	}
	return strings.TrimSuffix(planPath, ext) + ".progress.json"
}

func writeRemediationProgress(planPath, stage, message string, step, total int, sandboxRoot, manifestPath string, patchVerified bool) {
	progress := remediationProgress{
		Stage: stage, Message: message, Step: step, Total: total,
		SandboxRoot: sandboxRoot, SandboxManifestPath: manifestPath,
		PatchVerified: patchVerified, UpdatedAt: time.Now().UTC(),
	}
	path := executionProgressPath(planPath)
	tmp := path + ".tmp"
	if err := writeJSON(tmp, &progress); err != nil {
		return
	}
	_ = os.Remove(path)
	_ = os.Rename(tmp, path)
}

func validatePlanProposal(plan *FixPlan) error {
	p, err := detectProject(plan.ProjectRoot)
	if err != nil {
		return err
	}
	if filepath.Clean(p.Manifest) != filepath.Clean(plan.ManifestPath) {
		return fmt.Errorf("manifesto do plano não corresponde ao projeto detectado")
	}
	orig, err := os.ReadFile(p.Manifest)
	if err != nil {
		return err
	}
	if bytesHash(orig) != plan.OriginalHash {
		return fmt.Errorf("manifesto original divergiu do hash do plano")
	}
	var proposed []byte
	var control, strategy string
	var can bool
	if p.Ecosystem == "npm" {
		proposed, control, can, _, _, strategy, err = patchPackageJSONAligned(p, orig, plan.Package, plan.CurrentVersion, plan.TargetVersion, plan.TargetSpec)
	} else {
		proposed, control, can, _, _, strategy, err = patchPomAligned(p, orig, plan.Package, plan.CurrentVersion, plan.TargetVersion)
	}
	if err != nil {
		return fmt.Errorf("não foi possível reconstruir a proposta do plano: %w", err)
	}
	if !can {
		return fmt.Errorf("a proposta reconstruída não possui ponto de controle automático seguro")
	}
	if control != plan.ControlPoint || strategy != plan.Strategy {
		return fmt.Errorf("metadados do plano divergiram da proposta reconstruída")
	}
	if !bytes.Equal(proposed, []byte(plan.ProposedContent)) || bytesHash(proposed) != plan.ProposedHash {
		return fmt.Errorf("conteúdo proposto do plano divergiu da proposta reconstruída; gere um novo plano")
	}
	if plan.ProposedHash == plan.OriginalHash {
		return fmt.Errorf("o plano não contém alteração material no manifesto")
	}
	return nil
}

func materializeSandboxManifest(plan *FixPlan, tmpBase string) (string, string, error) {
	if bytesHash([]byte(plan.ProposedContent)) != plan.ProposedHash {
		return "", "", fmt.Errorf("hash do conteúdo proposto é inválido")
	}
	tmpManifest := filepath.Join(tmpBase, relOrAbs(plan.ProjectRoot, plan.ManifestPath))
	if !pathWithin(tmpBase, tmpManifest) {
		return "", "", fmt.Errorf("manifesto candidato escapou da sandbox")
	}
	if err := os.MkdirAll(filepath.Dir(tmpManifest), 0o755); err != nil {
		return "", "", err
	}
	candidateTmp := tmpManifest + ".vulnweave-candidate"
	f, err := os.OpenFile(candidateTmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return "", "", err
	}
	if _, err = f.Write([]byte(plan.ProposedContent)); err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err == nil {
		err = closeErr
	}
	if err != nil {
		_ = os.Remove(candidateTmp)
		return "", "", err
	}
	if err := os.Remove(tmpManifest); err != nil && !os.IsNotExist(err) {
		_ = os.Remove(candidateTmp)
		return "", "", err
	}
	if err := os.Rename(candidateTmp, tmpManifest); err != nil {
		_ = os.Remove(candidateTmp)
		return "", "", err
	}
	h, err := fileHash(tmpManifest)
	if err != nil {
		return "", "", err
	}
	if h != plan.ProposedHash {
		return "", h, fmt.Errorf("o patch não foi materializado corretamente na sandbox: hash esperado %s, obtido %s", plan.ProposedHash, h)
	}
	return tmpManifest, h, nil
}

func verifySandboxManifestStable(path string, plan *FixPlan) error {
	h, err := fileHash(path)
	if err != nil {
		return fmt.Errorf("não foi possível reler o manifesto da sandbox: %w", err)
	}
	if h != plan.ProposedHash {
		return fmt.Errorf("o manifesto da sandbox mudou após a materialização do patch (esperado %s, obtido %s)", plan.ProposedHash, h)
	}
	return nil
}

func copySandboxSupportFile(srcRoot, dstRoot, rel string) (bool, error) {
	src := filepath.Join(srcRoot, filepath.FromSlash(rel))
	st, err := os.Stat(src)
	if err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, err
	}
	if st.IsDir() {
		return false, nil
	}
	b, err := os.ReadFile(src)
	if err != nil {
		return false, err
	}
	dst := filepath.Join(dstRoot, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return false, err
	}
	mode := st.Mode().Perm()
	if mode == 0 {
		mode = 0o644
	}
	if err := os.WriteFile(dst, b, mode); err != nil {
		return false, err
	}
	return true, nil
}

// hydrateMavenSandboxSupport repairs the small set of Maven support files that
// may be represented by symlinks or otherwise omitted by the generic sandbox
// copier. We deliberately copy only Maven wrapper/configuration files instead
// of following arbitrary project symlinks.
func hydrateMavenSandboxSupport(srcRoot, dstRoot string) ([]string, error) {
	rels := []string{
		".mvn/wrapper/maven-wrapper.properties",
		".mvn/wrapper/maven-wrapper.jar",
		".mvn/wrapper/MavenWrapperDownloader.java",
		".mvn/jvm.config",
		".mvn/maven.config",
		".mvn/extensions.xml",
	}
	copied := []string{}
	for _, rel := range rels {
		dst := filepath.Join(dstRoot, filepath.FromSlash(rel))
		if st, err := os.Stat(dst); err == nil && !st.IsDir() {
			continue
		}
		ok, err := copySandboxSupportFile(srcRoot, dstRoot, rel)
		if err != nil {
			return copied, fmt.Errorf("não foi possível preservar %s na sandbox: %w", rel, err)
		}
		if ok {
			copied = append(copied, rel)
		}
	}
	return copied, nil
}

func executePlan(planPath string, runBuild, runTests bool) (*FixExecution, error) {
	var plan FixPlan
	if err := readJSON(planPath, &plan); err != nil {
		return nil, err
	}
	writeRemediationProgress(planPath, "preflight", "Validando integridade do plano e do baseline…", 0, 6, "", "", false)
	if !plan.CanApply {
		writeRemediationProgress(planPath, "failed", "Plano sem ponto de controle automático seguro.", 0, 6, "", "", false)
		return nil, fmt.Errorf("plano não possui ponto de controle automático seguro: %s", plan.ControlPoint)
	}
	if !pathWithin(plan.ProjectRoot, plan.ManifestPath) {
		writeRemediationProgress(planPath, "failed", "Manifesto fora do project root.", 0, 6, "", "", false)
		return nil, fmt.Errorf("manifesto do plano está fora do project root")
	}
	expectedPlanDir := filepath.Join(plan.ProjectRoot, ".vulnweave", "plans")
	if !pathWithin(expectedPlanDir, planPath) {
		writeRemediationProgress(planPath, "failed", "Arquivo de plano fora do diretório permitido.", 0, 6, "", "", false)
		return nil, fmt.Errorf("arquivo de plano fora do diretório permitido")
	}
	if h, err := fileHash(plan.ManifestPath); err != nil || h != plan.OriginalHash {
		writeRemediationProgress(planPath, "failed", "O manifesto mudou desde a prévia.", 0, 6, "", "", false)
		return nil, fmt.Errorf("o manifesto mudou desde a prévia; gere um novo plano antes de continuar")
	}
	if err := validatePlanProposal(&plan); err != nil {
		writeRemediationProgress(planPath, "failed", "A proposta salva não corresponde ao plano reconstruído.", 0, 6, "", "", false)
		return nil, err
	}
	tmpBase, err := sandboxPathForPlan(&plan)
	if err != nil {
		writeRemediationProgress(planPath, "failed", "Não foi possível determinar a sandbox.", 0, 6, "", "", false)
		return nil, err
	}
	writeRemediationProgress(planPath, "sandbox", "Criando sandbox isolada…", 1, 6, tmpBase, "", false)
	_ = os.RemoveAll(tmpBase)
	if err := copyProject(plan.ProjectRoot, tmpBase); err != nil {
		writeRemediationProgress(planPath, "failed", "Falha ao copiar o projeto para a sandbox.", 1, 6, tmpBase, "", false)
		return nil, err
	}
	mavenSupportCopied, hydrateErr := hydrateMavenSandboxSupport(plan.ProjectRoot, tmpBase)
	if hydrateErr != nil {
		writeRemediationProgress(planPath, "failed", "Falha ao preservar arquivos de suporte do Maven Wrapper na sandbox.", 1, 6, tmpBase, "", false)
		return nil, hydrateErr
	}
	tmpManifest, sandboxHash, err := materializeSandboxManifest(&plan, tmpBase)
	if err != nil {
		writeRemediationProgress(planPath, "failed", "Falha ao materializar o patch no manifesto da sandbox.", 1, 6, tmpBase, tmpManifest, false)
		return nil, err
	}
	writeRemediationProgress(planPath, "patch", "Patch materializado e verificado no manifesto da sandbox.", 2, 6, tmpBase, tmpManifest, true)
	res := &FixExecution{SchemaVersion: "vulnweave.fixexecution/3", PlanID: plan.ID, TempRoot: tmpBase, SandboxManifestPath: tmpManifest, SandboxManifestHash: sandboxHash, SandboxPatchVerified: true}
	if len(mavenSupportCopied) > 0 {
		res.Warnings = append(res.Warnings, "sandbox: arquivos de suporte do Maven Wrapper foram restaurados da árvore original: "+strings.Join(mavenSupportCopied, ", "))
	}
	p, err := detectProject(tmpBase)
	if err != nil {
		writeRemediationProgress(planPath, "failed", "Projeto candidato não pôde ser detectado na sandbox.", 2, 6, tmpBase, tmpManifest, true)
		return nil, err
	}
	writeRemediationProgress(planPath, "resolve", "Resolvendo grafo / lockfile com o patch candidato…", 3, 6, tmpBase, tmpManifest, true)
	if prepared, prepErr := prepareNpmCohortLock(p, &plan); prepErr != nil {
		res.LockResolution = CommandResult{Name: "preparar lockfile candidato", Success: false, ExitCode: 3, Reason: prepErr.Error()}
	} else {
		res.LockResolution = resolveLockGraph(p)
		if prepared > 0 {
			res.LockResolution = appendCommandEvidence(res.LockResolution, fmt.Sprintf("VulnWeave: %d entrada(s) antigas do conjunto coordenado foram invalidadas somente no lockfile da cópia isolada; as demais entradas foram preservadas como entrada da resolução.", prepared))
		}
	}
	if strings.Contains(res.LockResolution.Output, "sem versão pinada verificável") {
		res.Warnings = append(res.Warnings, "Maven Wrapper incompleto: a validação usou o Maven disponível no ambiente porque o projeto não fornece .mvn/wrapper/maven-wrapper.properties. A versão efetiva foi registrada no log e a reprodutibilidade do wrapper ficou degradada.")
	}
	if res.LockResolution.Success && !res.LockResolution.Skipped {
		if stableErr := verifySandboxManifestStable(tmpManifest, &plan); stableErr != nil {
			res.SandboxPatchVerified = false
			res.LockResolution.Success = false
			res.LockResolution.ExitCode = 3
			res.LockResolution.Reason = "manifesto candidato divergiu após a resolução: " + stableErr.Error()
			res.LockResolution = appendCommandEvidence(res.LockResolution, "VulnWeave sandbox manifest verification: "+stableErr.Error())
		}
	}
	if res.LockResolution.Success && !res.LockResolution.Skipped {
		if verifyErr := verifyResolvedPlan(p, &plan); verifyErr != nil {
			res.LockResolution.Success = false
			res.LockResolution.ExitCode = 3
			res.LockResolution.Reason = "grafo resolvido, porém a verificação de coerência falhou: " + verifyErr.Error()
			res.LockResolution = appendCommandEvidence(res.LockResolution, "VulnWeave graph verification: "+verifyErr.Error())
		} else {
			res.LockResolution = appendCommandEvidence(res.LockResolution, "VulnWeave graph verification: OK")
		}
	}
	if !res.LockResolution.Success || res.LockResolution.Skipped {
		res.Build = CommandResult{Name: "build", Skipped: true, Success: false, Reason: "aguardando: resolução do grafo/lockfile não passou"}
		res.Tests = CommandResult{Name: "tests", Skipped: true, Success: false, Reason: "aguardando: resolução do grafo/lockfile não passou"}
	} else {
		writeRemediationProgress(planPath, "build", "Grafo confirmado. Executando build no sandbox candidato…", 4, 6, tmpBase, tmpManifest, res.SandboxPatchVerified)
		if runBuild {
			res.Build = runDefaultBuild(p)
		} else {
			res.Build = CommandResult{Name: "build", Skipped: true, Success: true, Reason: "não solicitado"}
		}
		if !res.Build.Success || res.Build.Skipped {
			if runBuild && !res.Build.Skipped {
				res.BaselineBuild, res.BuildAssessment = compareFailedBuildWithBaseline(&plan, tmpBase)
				if res.BuildAssessment != "" {
					if res.Build.Reason == "" {
						res.Build.Reason = res.BuildAssessment
					} else {
						res.Build.Reason += "; " + res.BuildAssessment
					}
					res.Warnings = append(res.Warnings, res.BuildAssessment)
				}
			}
			res.Tests = CommandResult{Name: "tests", Skipped: true, Success: false, Reason: "aguardando: build não passou"}
		} else if runTests {
			writeRemediationProgress(planPath, "tests", "Build concluído. Executando testes no sandbox candidato…", 5, 6, tmpBase, tmpManifest, res.SandboxPatchVerified)
			res.Tests = runDefaultTests(p)
		} else {
			res.Tests = CommandResult{Name: "tests", Skipped: true, Success: true, Reason: "não solicitado"}
		}
	}
	if res.LockResolution.Success && !res.LockResolution.Skipped && res.Build.Success && !res.Build.Skipped && res.Tests.Success && !res.Tests.Skipped {
		if stableErr := verifySandboxManifestStable(tmpManifest, &plan); stableErr != nil {
			res.SandboxPatchVerified = false
			res.Warnings = append(res.Warnings, "manifesto da sandbox divergiu antes do rescan: "+stableErr.Error())
		} else {
			writeRemediationProgress(planPath, "rescan", "Build e testes concluídos. Executando rescan completo do sandbox…", 6, 6, tmpBase, tmpManifest, true)
		}
		if res.SandboxPatchVerified {
			if scan, err := scanProject(tmpBase, "full"); err == nil {
				res.Rescan = scan
				res.After = findRiskVersion(scan, plan.Package, plan.TargetVersion)
			} else {
				res.Warnings = append(res.Warnings, "novo scan falhou: "+err.Error())
			}
		}
	} else {
		res.Warnings = append(res.Warnings, "novo scan não foi executado porque lock/build/testes não passaram.")
	}
	// Load baseline if available, without forcing a new full scan of the original workspace.
	baseline := filepath.Join(plan.ProjectRoot, ".vulnweave", "reports", "vulnweave-scan.json")
	var base ScanReport
	if readJSON(baseline, &base) == nil {
		res.Before = findRiskVersion(&base, plan.Package, plan.CurrentVersion)
	} else {
		res.Warnings = append(res.Warnings, "baseline anterior não encontrado; o comparativo 'antes' depende do último scan do workspace.")
	}
	// Determine files changed in isolated copy.
	files := []string{relOrAbs(plan.ProjectRoot, plan.ManifestPath)}
	origProject, _ := detectProject(plan.ProjectRoot)
	if origProject.Lockfile != "" {
		tmpLock := filepath.Join(tmpBase, relOrAbs(plan.ProjectRoot, origProject.Lockfile))
		if _, e := os.Stat(tmpLock); e == nil {
			oh, _ := fileHash(origProject.Lockfile)
			th, _ := fileHash(tmpLock)
			if oh != th {
				files = append(files, relOrAbs(plan.ProjectRoot, origProject.Lockfile))
			}
		}
	}
	sort.Strings(files)
	res.ChangedFiles = files
	targetAuxiliaryEvidence := auxiliaryHasTargetEvidence(res.Rescan, plan.Package, plan.TargetVersion)
	res.ReadyToApply = res.Before != nil && res.SandboxPatchVerified &&
		res.LockResolution.Success && !res.LockResolution.Skipped &&
		res.Build.Success && !res.Build.Skipped &&
		res.Tests.Success && !res.Tests.Skipped &&
		remediationRescanAllowsApply(res.Rescan, plan.Package, plan.TargetVersion) && res.After == nil // canonical finding removed and no auxiliary evidence contradicts the target version
	if !res.SandboxPatchVerified {
		res.Blockers = append(res.Blockers, "sandbox: o manifesto candidato não corresponde mais ao patch aprovado no plano")
	}
	if res.Before == nil {
		res.Blockers = append(res.Blockers, "baseline do finding indisponível; comparação antes/depois não é confiável")
	}
	if !res.LockResolution.Success || res.LockResolution.Skipped {
		reason := strings.TrimSpace(res.LockResolution.Reason)
		if reason == "" {
			reason = "resolução do grafo/lockfile não passou"
		}
		res.Blockers = append(res.Blockers, "grafo/lockfile: "+reason)
	}
	if !res.Build.Success || res.Build.Skipped {
		reason := strings.TrimSpace(res.Build.Reason)
		if reason == "" {
			reason = "build não passou"
		}
		res.Blockers = append(res.Blockers, "build: "+reason)
	}
	if !res.Tests.Success || res.Tests.Skipped {
		reason := strings.TrimSpace(res.Tests.Reason)
		if reason == "" {
			reason = "testes não passaram"
		}
		res.Blockers = append(res.Blockers, "testes: "+reason)
	}
	if res.Rescan == nil {
		res.Blockers = append(res.Blockers, "rescan: não foi concluído")
	} else {
		if res.Rescan.CoverageStatus != "complete" {
			res.Blockers = append(res.Blockers, "rescan: cobertura "+res.Rescan.CoverageStatus+"; evidência incompleta não autoriza aplicação")
		}
		if targetAuxiliaryEvidence {
			res.Blockers = append(res.Blockers, "rescan: scanner auxiliar ainda reporta vulnerabilidade para "+plan.Package+"@"+plan.TargetVersion)
		} else if auxiliaryHasUnresolvedEvidence(res.Rescan) {
			res.Warnings = append(res.Warnings, "rescan: há evidência auxiliar não correlacionada em outros componentes; isso mantém a policy global em revisão, mas não invalida por si só a remediação do alvo")
		}
		if auxiliarySourcesDegraded(res.Rescan) {
			res.Warnings = append(res.Warnings, "rescan: um scanner auxiliar falhou ou ficou degradado; como o grafo canônico foi resolvido, OSV concluiu e o finding alvo desapareceu, a falha auxiliar é registrada como warning e não como blocker")
		}
	}
	if res.After != nil {
		res.Blockers = append(res.Blockers, "rescan: o finding alvo continua presente após a versão candidata")
	}
	res.Blockers = uniqueStrings(res.Blockers)
	if res.Before == nil {
		res.Warnings = append(res.Warnings, "baseline anterior do finding não está disponível; aplicação automática bloqueada porque não há comparação antes/depois confiável")
	}
	if res.LockResolution.Skipped || res.Build.Skipped || res.Tests.Skipped {
		res.Warnings = append(res.Warnings, "um ou mais gates obrigatórios (grafo/lockfile, build, testes) foram pulados; aplicação automática permanece bloqueada")
	}
	if res.Rescan != nil && res.After != nil {
		res.Warnings = append(res.Warnings, "a dependência ainda possui finding(s) após a versão candidata; não aplique automaticamente.")
	}
	compatibility := buildCompatibilityIntelligence(&plan, res.Before, res)
	res.Compatibility = &compatibility
	res.ExecutionPath = filepath.Join(plan.ProjectRoot, ".vulnweave", "plans", plan.ID+".execution.json")
	if err := writeJSON(res.ExecutionPath, res); err != nil {
		writeRemediationProgress(planPath, "failed", "Falha ao persistir a evidência da execução.", 6, 6, tmpBase, tmpManifest, res.SandboxPatchVerified)
		return nil, err
	}
	status := "Validação concluída. Revise os gates antes de aplicar."
	if res.ReadyToApply {
		status = "Validação concluída: patch da sandbox confirmado e todos os gates passaram."
	}
	writeRemediationProgress(planPath, "complete", status, 6, 6, tmpBase, tmpManifest, res.SandboxPatchVerified)
	return res, nil
}

func isUNCPath(p string) bool {
	clean := strings.TrimSpace(p)
	return strings.HasPrefix(clean, `\\`) || strings.HasPrefix(clean, `//`)
}

func sandboxPathForPlan(plan *FixPlan) (string, error) {
	roots := []string{}
	if configured := strings.TrimSpace(os.Getenv("VULNWEAVE_SANDBOX_ROOT")); configured != "" {
		roots = append(roots, configured)
	}
	if runtime.GOOS == "windows" {
		if local := strings.TrimSpace(os.Getenv("LOCALAPPDATA")); local != "" {
			roots = append(roots, filepath.Join(local, "VulnWeave", "sandboxes"))
		}
	}
	// Project-local fallback keeps the sandbox on the same volume as the project
	// while copyProject excludes .vulnweave, preventing recursive self-copy.
	roots = append(roots, filepath.Join(plan.ProjectRoot, ".vulnweave", "sandboxes"))
	roots = append(roots, filepath.Join(os.TempDir(), "vulnweave"))
	for _, root := range roots {
		root = strings.TrimSpace(root)
		if root == "" || !filepath.IsAbs(root) {
			continue
		}
		if runtime.GOOS == "windows" && isUNCPath(root) {
			continue
		}
		if err := os.MkdirAll(root, 0o755); err != nil {
			continue
		}
		return filepath.Join(root, plan.ID), nil
	}
	return "", fmt.Errorf("não foi possível criar um diretório local seguro para a validação isolada")
}

func directNodePackageManagerInvocationForOS(goos, cmd, resolved string, args []string) (string, []string, bool) {
	if goos != "windows" || !isWindowsBatchFile(resolved) {
		return "", nil, false
	}
	name := strings.ToLower(strings.TrimSpace(cmd))
	if name != "npm" {
		return "", nil, false
	}
	// npm.cmd is only a shim. Executing node.exe + npm-cli.js directly avoids an
	// unnecessary cmd.exe layer and its quoting/current-directory edge cases.
	nodePath, err := execLookPath("node")
	if err != nil || strings.TrimSpace(nodePath) == "" {
		return "", nil, false
	}
	candidates := []string{
		filepath.Join(filepath.Dir(resolved), "node_modules", "npm", "bin", "npm-cli.js"),
		filepath.Join(filepath.Dir(nodePath), "node_modules", "npm", "bin", "npm-cli.js"),
	}
	for _, cli := range candidates {
		if st, statErr := os.Stat(cli); statErr == nil && !st.IsDir() {
			outArgs := append([]string{cli}, args...)
			return nodePath, outArgs, true
		}
	}
	return "", nil, false
}

func directNodePackageManagerInvocation(cmd, resolved string, args []string) (string, []string, bool) {
	return directNodePackageManagerInvocationForOS(runtime.GOOS, cmd, resolved, args)
}

func classifyExecutionFailure(output string) string {
	v := strings.ToLower(output)
	switch {
	case strings.Contains(v, "the specified network name is no longer available"), strings.Contains(v, "error_netname_deleted"):
		return "falha de ambiente/rede do Windows (ERROR_NETNAME_DELETED); nenhuma conclusão de compatibilidade foi inferida"
	case strings.Contains(v, "enotfound"), strings.Contains(v, "econnreset"), strings.Contains(v, "etimedout"), strings.Contains(v, "unable to get local issuer certificate"):
		return "falha de conectividade/registry; nenhuma conclusão de compatibilidade foi inferida"
	case strings.Contains(v, "eresolve") && strings.Contains(v, "peer"):
		return "conflito de peerDependencies: o grafo não é coerente para a correção proposta; o VulnWeave não aceita override silencioso de peers"
	case strings.Contains(v, "application bundle generation complete"):
		return "o bundle principal foi gerado, mas o comando de build terminou com erro em uma etapa posterior do script; o final do log foi preservado para diagnóstico"
	default:
		return ""
	}
}

func enforcePeerClean(r CommandResult) CommandResult {
	v := strings.ToLower(r.Output)
	peerWarning := strings.Contains(v, "eresolve overriding peer dependency") ||
		strings.Contains(v, "could not resolve dependency") ||
		strings.Contains(v, "unmet peer dependency") ||
		strings.Contains(v, "incorrect peer dependency") ||
		strings.Contains(v, "unmet peer dependencies") ||
		strings.Contains(v, "yn0002") || strings.Contains(v, "yn0060")
	if r.Success && peerWarning {
		r.Success = false
		r.ExitCode = 2
		r.Reason = "o package manager reportou peerDependencies incompatíveis; esse grafo não é aceito como validação segura"
	}
	return r
}

func nodePackageManager(p ProjectInfo) string {
	var pkg map[string]interface{}
	if readJSON(p.Manifest, &pkg) == nil {
		if raw, ok := pkg["packageManager"].(string); ok {
			v := strings.ToLower(strings.TrimSpace(raw))
			for _, pm := range []string{"npm", "pnpm", "yarn", "bun"} {
				if strings.HasPrefix(v, pm+"@") || v == pm {
					return pm
				}
			}
		}
	}
	lf := strings.ToLower(p.Lockfile)
	switch {
	case strings.HasSuffix(lf, "pnpm-lock.yaml"):
		return "pnpm"
	case strings.HasSuffix(lf, "yarn.lock"):
		return "yarn"
	case strings.HasSuffix(lf, "bun.lock"), strings.HasSuffix(lf, "bun.lockb"):
		return "bun"
	default:
		return "npm"
	}
}

func mavenCommand(p ProjectInfo) string {
	if runtime.GOOS == "windows" {
		for _, name := range []string{"mvnw.cmd", "mvnw.bat", "mvnw"} {
			candidate := filepath.Join(p.Root, name)
			if st, err := os.Stat(candidate); err == nil && !st.IsDir() {
				return candidate
			}
		}
	} else {
		candidate := filepath.Join(p.Root, "mvnw")
		if st, err := os.Stat(candidate); err == nil && !st.IsDir() {
			// On Unix we intentionally do not chmod the repository file. runCmd
			// invokes Maven Wrapper through /bin/sh, so read permission is enough and
			// the workspace remains byte-for-byte unchanged during discovery.
			return candidate
		}
	}
	return "mvn"
}

func isMavenWrapperCommand(cmd string) bool {
	base := strings.ToLower(filepath.Base(strings.TrimSpace(cmd)))
	return base == "mvnw" || base == "mvnw.cmd" || base == "mvnw.bat"
}

func mavenWrapperBootstrapFailure(r CommandResult) bool {
	if r.Success {
		return false
	}
	v := strings.ToLower(r.Output + " " + r.Reason)
	return strings.Contains(v, "org.apache.maven.wrapper.mavenwrappermain") ||
		(strings.Contains(v, "could not find or load main class") && strings.Contains(v, "mavenwrapper")) ||
		strings.Contains(v, "maven-wrapper.jar") && (strings.Contains(v, "not found") || strings.Contains(v, "não encontrado")) ||
		(strings.Contains(v, "blocked by group policy") && strings.Contains(v, "mavenwrapper")) ||
		(strings.Contains(v, "bloqueado por uma política de grupo") && strings.Contains(v, "mavenwrapper"))
}

func expectedWrapperMavenVersion(root string) string {
	b, err := os.ReadFile(filepath.Join(root, ".mvn", "wrapper", "maven-wrapper.properties"))
	if err != nil {
		return ""
	}
	re := regexp.MustCompile(`(?i)apache-maven-([0-9]+(?:\.[0-9]+){1,3}(?:[-.][0-9A-Za-z]+)*)-bin\.(?:zip|tar\.gz)`)
	m := re.FindStringSubmatch(string(b))
	if len(m) == 2 {
		return strings.TrimSpace(m[1])
	}
	return ""
}

func parseMavenVersion(output string) string {
	re := regexp.MustCompile(`(?im)^Apache Maven\s+([^\s]+)`)
	m := re.FindStringSubmatch(output)
	if len(m) == 2 {
		return strings.TrimSpace(m[1])
	}
	return ""
}

func compatibleSystemMaven(root string) (string, string) {
	expected := expectedWrapperMavenVersion(root)
	resolved, err := execLookPath("mvn")
	if err != nil || strings.TrimSpace(resolved) == "" {
		return "", "Maven Wrapper falhou e nenhum Maven do sistema foi localizado para fallback"
	}
	probe := runCmd(root, "Maven do sistema: versão", "mvn", []string{"-v"})
	if !probe.Success {
		return "", "Maven Wrapper falhou e o Maven do sistema também não pôde ser executado: " + strings.TrimSpace(probe.Reason)
	}
	actual := parseMavenVersion(probe.Output)
	if actual == "" {
		return "", "Maven do sistema foi localizado, mas a versão não pôde ser confirmada; fallback automático bloqueado"
	}
	if expected == "" {
		return "mvn", fmt.Sprintf("fallback controlado: Maven Wrapper incompleto e sem versão pinada verificável; usando Maven do sistema %s. A reprodutibilidade exata do wrapper não pôde ser confirmada", actual)
	}
	if actual != expected {
		return "", fmt.Sprintf("Maven Wrapper requer %s, mas o Maven do sistema é %s; fallback automático bloqueado para preservar reprodutibilidade", expected, actual)
	}
	return "mvn", fmt.Sprintf("fallback seguro: Maven Wrapper indisponível; usando Maven do sistema %s, igual à versão fixada pelo wrapper", actual)
}

func runMaven(p ProjectInfo, name string, args []string) CommandResult {
	primary := mavenCommand(p)
	first := runCmd(p.Root, name, primary, args)
	if first.Success || !isMavenWrapperCommand(primary) || !mavenWrapperBootstrapFailure(first) {
		return first
	}
	fallback, evidence := compatibleSystemMaven(p.Root)
	if fallback == "" {
		first.Reason = "Maven Wrapper não inicializou (MavenWrapperMain/bootstrap). " + evidence
		return appendCommandEvidence(first, "VulnWeave: "+first.Reason)
	}
	second := runCmd(p.Root, name, fallback, args)
	second.Name = name
	second.Command = first.Command + " → " + second.Command
	second.Output = "--- Maven Wrapper falhou ---\n" + first.Output + "\n--- Fallback VulnWeave ---\n" + evidence + "\n" + second.Output
	if second.Success {
		second.Reason = ""
		return second
	}
	if strings.TrimSpace(second.Reason) == "" {
		second.Reason = "Maven do sistema falhou após fallback seguro"
	}
	second.Reason = "Maven Wrapper não inicializou; " + evidence + "; fallback também falhou: " + second.Reason
	return second
}

func javaExecutableForHome(home string) string {
	home = strings.TrimSpace(home)
	if home == "" {
		return ""
	}
	name := "java"
	if runtime.GOOS == "windows" {
		name = "java.exe"
	}
	p := filepath.Join(home, "bin", name)
	if st, err := os.Stat(p); err == nil && !st.IsDir() {
		return p
	}
	return ""
}

func parseJavaHome(output string) string {
	re := regexp.MustCompile(`(?m)^\s*java\.home\s*=\s*(.+?)\s*$`)
	m := re.FindStringSubmatch(output)
	if len(m) != 2 {
		return ""
	}
	home := strings.TrimSpace(m[1])
	if javaExecutableForHome(home) == "" {
		return ""
	}
	return home
}

func probeJavaHome(javaCmd string) string {
	javaCmd = strings.TrimSpace(javaCmd)
	if javaCmd == "" {
		return ""
	}
	resolved, err := execLookPath(javaCmd)
	if err != nil || strings.TrimSpace(resolved) == "" {
		return ""
	}
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	c := exec.CommandContext(ctx, resolved, "-XshowSettings:properties", "-version")
	// A java launcher does not need JAVA_HOME to start. Remove an inherited stale
	// value so Oracle javapath/IDE shims can reveal their real java.home cleanly.
	env := make([]string, 0, len(os.Environ()))
	for _, item := range os.Environ() {
		key := item
		if i := strings.IndexByte(item, '='); i >= 0 {
			key = item[:i]
		}
		if strings.EqualFold(key, "JAVA_HOME") {
			continue
		}
		env = append(env, item)
	}
	c.Env = env
	out, err := c.CombinedOutput()
	if ctx.Err() != nil || err != nil {
		return ""
	}
	return parseJavaHome(string(out))
}

func normalizedJavaHome() string {
	// Prefer the exact java command supplied by the adapter. This prevents an
	// invalid inherited JAVA_HOME from winning over a valid IDE/project JDK.
	if override := strings.TrimSpace(os.Getenv(commandOverrideKey("java"))); override != "" {
		if home := probeJavaHome(override); home != "" {
			return home
		}
	}
	if inherited := strings.TrimSpace(os.Getenv("JAVA_HOME")); inherited != "" {
		if javaExecutableForHome(inherited) != "" {
			if home := probeJavaHome(javaExecutableForHome(inherited)); home != "" {
				return home
			}
			return inherited
		}
	}
	if home := probeJavaHome("java"); home != "" {
		return home
	}
	return ""
}

func replaceEnvValue(env []string, key, value string) []string {
	out := make([]string, 0, len(env)+1)
	for _, item := range env {
		name := item
		if i := strings.IndexByte(item, '='); i >= 0 {
			name = item[:i]
		}
		if strings.EqualFold(name, key) {
			continue
		}
		out = append(out, item)
	}
	if strings.TrimSpace(value) != "" {
		out = append(out, key+"="+value)
	}
	return out
}

func appendCommandEvidence(r CommandResult, line string) CommandResult {
	line = strings.TrimSpace(line)
	if line == "" {
		return r
	}
	if strings.TrimSpace(r.Output) != "" {
		r.Output += "\n"
	}
	r.Output += line
	return r
}

// verifyNpmResolvedPlan validates the concrete package-lock result after the
// package manager has resolved the candidate. For an exact peer cohort, every
// coordinated root package must resolve to exactly the validated target. This
// catches partial upgrades and release-train drift even when the package manager
// exits successfully.
func verifyNpmResolvedPlan(p ProjectInfo, plan *FixPlan) error {
	if plan == nil || !strings.HasPrefix(plan.Strategy, "peer-cohort") {
		return nil
	}
	if !strings.HasSuffix(strings.ToLower(p.Lockfile), "package-lock.json") {
		return nil
	}
	pkgs, err := npmRootLockPackages(p.Lockfile)
	if err != nil {
		return fmt.Errorf("não foi possível conferir o package-lock resolvido: %w", err)
	}
	expected := cleanVersion(plan.TargetVersion)
	for _, ch := range plan.RelatedChanges {
		entry, ok := pkgs[ch.Package]
		if !ok {
			return fmt.Errorf("cohort incompleto: %s não apareceu no package-lock resolvido", ch.Package)
		}
		if cleanVersion(entry.Version) != expected {
			return fmt.Errorf("release cohort desalinhado: %s resolveu %s, esperado %s", ch.Package, cleanVersion(entry.Version), expected)
		}
	}
	// Validate exact peer edges among coordinated packages against the concrete
	// versions in the regenerated lockfile.
	cohort := map[string]bool{}
	for _, ch := range plan.RelatedChanges {
		cohort[ch.Package] = true
	}
	for _, ch := range plan.RelatedChanges {
		entry := pkgs[ch.Package]
		for peer, spec := range entry.PeerDependencies {
			if !cohort[peer] {
				continue
			}
			if exactPeerPinsVersion(spec, expected) {
				continue
			}
			// Broad compatible ranges are allowed; only an exact semver pin to a
			// different release is a deterministic conflict.
			ps := parseSemverish(strings.TrimPrefix(strings.TrimSpace(spec), "="))
			if ps.ok && !strings.ContainsAny(spec, "^~*<>| ") && cleanVersion(spec) != expected {
				return fmt.Errorf("peer incompatível após resolução: %s exige %s@%s enquanto o cohort foi fixado em %s", ch.Package, peer, spec, expected)
			}
		}
	}
	return nil
}

func parseMavenTreeVersions(output string) map[string]map[string]bool {
	out := map[string]map[string]bool{}
	re := regexp.MustCompile(`([A-Za-z0-9_.-]+):([A-Za-z0-9_.-]+):[^:\s]+:([^:\s]+):(?:compile|runtime|test|provided|system|import)`)
	for _, m := range re.FindAllStringSubmatch(output, -1) {
		key := m[1] + ":" + m[2]
		if out[key] == nil {
			out[key] = map[string]bool{}
		}
		out[key][cleanVersion(m[3])] = true
	}
	return out
}

// verifyMavenResolvedPlan checks the effective dependency tree rather than only
// trusting that dependency:resolve returned zero. Shared-property/BOM plans verify
// the selected vulnerable artifact; explicit release cohorts verify every member.
func verifyMavenResolvedPlan(p ProjectInfo, plan *FixPlan) error {
	if plan == nil || p.Ecosystem != "Maven" {
		return nil
	}
	tmp, err := os.CreateTemp("", "vulnweave-maven-verify-*.txt")
	if err != nil {
		return err
	}
	name := tmp.Name()
	tmp.Close()
	defer os.Remove(name)
	r := runMaven(p, "verificar grafo Maven", []string{"dependency:tree", "-DoutputType=text", "-DappendOutput=false", "-DoutputFile=" + name, "-DskipTests"})
	if !r.Success || r.Skipped {
		return fmt.Errorf("dependency:tree não pôde confirmar o grafo efetivo: %s %s", r.Reason, r.Output)
	}
	b, err := os.ReadFile(name)
	if err != nil {
		return err
	}
	versions := parseMavenTreeVersions(string(b))
	expected := cleanVersion(plan.TargetVersion)
	check := []string{plan.Package}
	if plan.Strategy == "maven-release-cohort" {
		check = check[:0]
		for _, ch := range plan.RelatedChanges {
			check = append(check, ch.Package)
		}
	}
	seen := map[string]bool{}
	for _, coord := range check {
		if seen[coord] {
			continue
		}
		seen[coord] = true
		vs := versions[coord]
		if len(vs) == 0 {
			return fmt.Errorf("%s não apareceu no dependency:tree efetivo", coord)
		}
		if !vs[expected] {
			return fmt.Errorf("%s não resolveu para %s no grafo Maven efetivo", coord, expected)
		}
		if len(vs) != 1 {
			return fmt.Errorf("%s aparece com múltiplas versões no grafo Maven efetivo; esperado somente %s", coord, expected)
		}
	}
	return nil
}

func verifyResolvedPlan(p ProjectInfo, plan *FixPlan) error {
	if p.Ecosystem == "npm" {
		return verifyNpmResolvedPlan(p, plan)
	}
	if p.Ecosystem == "Maven" {
		return verifyMavenResolvedPlan(p, plan)
	}
	return nil
}

// prepareNpmCohortLock runs only on executePlan's isolated copy. npm can retain
// the OLD exact peer edges from a locked cohort even when all manifest members
// were upgraded atomically. Invalidate that cohort's root subtrees, not the whole
// lockfile, and let npm resolve fresh metadata under strict peer validation.
func prepareNpmCohortLock(p ProjectInfo, plan *FixPlan) (int, error) {
	if plan == nil || p.Ecosystem != "npm" || nodePackageManager(p) != "npm" || !strings.HasPrefix(plan.Strategy, "peer-cohort") {
		return 0, nil
	}
	manifest, err := os.ReadFile(p.Manifest)
	if err != nil {
		return 0, err
	}
	if bytesHash(manifest) != plan.ProposedHash {
		return 0, fmt.Errorf("manifesto candidato não corresponde ao diff aprovado")
	}
	decls, err := npmManifestDeclarations(manifest)
	if err != nil {
		return 0, err
	}
	data, err := os.ReadFile(p.Lockfile)
	if err != nil {
		return 0, err
	}
	var lock map[string]json.RawMessage
	if err = json.Unmarshal(data, &lock); err != nil {
		return 0, err
	}
	var version int
	if err = json.Unmarshal(lock["lockfileVersion"], &version); err != nil || (version != 2 && version != 3) {
		return 0, fmt.Errorf("a resolução coordenada npm exige package-lock v2/v3")
	}
	var packages map[string]json.RawMessage
	if err = json.Unmarshal(lock["packages"], &packages); err != nil || len(packages) == 0 {
		return 0, fmt.Errorf("package-lock candidato não possui grafo packages válido")
	}
	var root map[string]json.RawMessage
	if err = json.Unmarshal(packages[""], &root); err != nil || root == nil {
		return 0, fmt.Errorf("package-lock não possui metadados do projeto raiz")
	}
	var legacy map[string]json.RawMessage
	if raw, ok := lock["dependencies"]; ok {
		if err = json.Unmarshal(raw, &legacy); err != nil {
			return 0, err
		}
	}
	removed := 0
	for _, change := range plan.RelatedChanges {
		decl, ok := decls[change.Package]
		if !ok || decl.Spec != change.ToSpec || decl.Spec != cleanVersion(plan.TargetVersion) {
			return 0, fmt.Errorf("declaração candidata de %s não corresponde ao conjunto exato aprovado", change.Package)
		}
		prefix := "node_modules/" + change.Package
		if _, exists := packages[prefix]; !exists {
			return 0, fmt.Errorf("entrada original de %s ausente no lockfile", change.Package)
		}
		for key := range packages {
			if key == prefix || strings.HasPrefix(key, prefix+"/node_modules/") {
				delete(packages, key)
				removed++
			}
		}
		// Synchronize root constraints; never synthesize version/integrity metadata.
		var section map[string]string
		if raw, exists := root[decl.Section]; exists {
			if err = json.Unmarshal(raw, &section); err != nil {
				return 0, err
			}
		}
		if section == nil {
			section = map[string]string{}
		}
		section[change.Package] = decl.Spec
		root[decl.Section], err = json.Marshal(section)
		if err != nil {
			return 0, err
		}
		delete(legacy, change.Package)
	}
	packages[""], err = json.Marshal(root)
	if err != nil {
		return 0, err
	}
	lock["packages"], err = json.Marshal(packages)
	if err != nil {
		return 0, err
	}
	if legacy != nil {
		lock["dependencies"], err = json.Marshal(legacy)
		if err != nil {
			return 0, err
		}
	}
	out, err := json.MarshalIndent(lock, "", "  ")
	if err != nil {
		return 0, err
	}
	return removed, os.WriteFile(p.Lockfile, append(out, '\n'), 0o600)
}

func resolveLockGraph(p ProjectInfo) CommandResult {
	if p.Ecosystem == "npm" {
		if strings.TrimSpace(p.Lockfile) == "" {
			return CommandResult{Name: "resolver grafo/lockfile", Skipped: true, Success: false, Reason: "lockfile não encontrado; a remediação automática exige um grafo reproduzível"}
		}
		pm := nodePackageManager(p)
		switch pm {
		case "pnpm":
			return enforcePeerClean(runCmd(p.Root, "resolver grafo/lockfile", "pnpm", []string{"install", "--ignore-scripts", "--no-frozen-lockfile", "--strict-peer-dependencies"}))
		case "yarn":
			if _, err := os.Stat(filepath.Join(p.Root, ".yarnrc.yml")); err == nil {
				return enforcePeerClean(runCmd(p.Root, "resolver grafo/lockfile", "yarn", []string{"install", "--mode=skip-builds"}))
			}
			return enforcePeerClean(runCmd(p.Root, "resolver grafo/lockfile", "yarn", []string{"install", "--ignore-scripts"}))
		case "bun":
			return enforcePeerClean(runCmd(p.Root, "resolver grafo/lockfile", "bun", []string{"install", "--ignore-scripts"}))
		default:
			lock := enforcePeerClean(runCmd(p.Root, "resolver grafo/lockfile", "npm", []string{"install", "--package-lock-only", "--ignore-scripts", "--no-audit", "--no-fund", "--strict-peer-deps", "--legacy-peer-deps=false", "--force=false"}))
			if !lock.Success || lock.Skipped {
				return lock
			}
			installed := enforcePeerClean(runCmd(p.Root, "instalar grafo validado", "npm", []string{"ci", "--ignore-scripts", "--no-audit", "--no-fund", "--strict-peer-deps", "--legacy-peer-deps=false", "--force=false"}))
			installed.Output = lock.Output + "\n--- npm ci: reprodução do lockfile candidato ---\n" + installed.Output
			installed.Command = lock.Command + " → " + installed.Command
			return installed
		}
	}
	return runMaven(p, "resolver grafo Maven", []string{"-q", "-DskipTests", "dependency:resolve"})
}

func runDefaultBuild(p ProjectInfo) CommandResult {
	if p.Ecosystem == "Maven" {
		return runMaven(p, "build", []string{"-q", "-DskipTests", "package"})
	}
	var pkg map[string]interface{}
	if readJSON(p.Manifest, &pkg) != nil {
		return CommandResult{Name: "build", Skipped: true, Success: false, Reason: "package.json inválido"}
	}
	scripts, _ := pkg["scripts"].(map[string]interface{})
	if _, ok := scripts["build"]; !ok {
		return CommandResult{Name: "build", Skipped: true, Success: false, Reason: "script build não definido; não há gate reproduzível"}
	}
	pm := nodePackageManager(p)
	return runCmd(p.Root, "build", pm, []string{"run", "build"})
}

func runDefaultTests(p ProjectInfo) CommandResult {
	if p.Ecosystem == "Maven" {
		return runMaven(p, "tests", []string{"-q", "test"})
	}
	var pkg map[string]interface{}
	if readJSON(p.Manifest, &pkg) != nil {
		return CommandResult{Name: "tests", Skipped: true, Success: false, Reason: "package.json inválido"}
	}
	scripts, _ := pkg["scripts"].(map[string]interface{})
	testRaw, ok := scripts["test"]
	if !ok {
		return CommandResult{Name: "tests", Skipped: true, Success: false, Reason: "script test não definido; não há gate reproduzível"}
	}
	pm := nodePackageManager(p)
	args := []string{"run", "test"}
	if strings.Contains(strings.ToLower(fmt.Sprint(testRaw)), "ng test") {
		args = append(args, "--", "--watch=false")
	}
	return runCmdEnv(p.Root, "tests", pm, args, map[string]string{"CI": "true"})
}

func isWindowsBatchFile(p string) bool {
	lower := strings.ToLower(strings.TrimSpace(p))
	return strings.HasSuffix(lower, ".cmd") || strings.HasSuffix(lower, ".bat")
}

func windowsCmdQuoteArg(v string) (string, error) {
	if strings.ContainsAny(v, "\x00\r\n") {
		return "", fmt.Errorf("argumento de runtime contém caractere de controle")
	}
	// cmd.exe expands percent variables even inside double quotes. Reject them;
	// doubling is not a reliable literal escape for a /C command line.
	if strings.Contains(v, "%") {
		return "", fmt.Errorf("argumento de runtime contém expansão de variável não suportada")
	}
	// Quotes cannot be represented safely in this narrow batch-runner contract.
	// Runtime paths discovered by the extension and the fixed gate arguments never
	// require them, so reject instead of guessing and opening a shell-injection gap.
	if strings.Contains(v, `"`) {
		return "", fmt.Errorf("argumento de runtime contém aspas não suportadas")
	}
	return `"` + v + `"`, nil
}

func windowsBatchCommandLine(resolved string, args []string) (string, error) {
	qexe, err := windowsCmdQuoteArg(resolved)
	if err != nil {
		return "", err
	}
	parts := []string{qexe}
	for _, a := range args {
		qa, err := windowsCmdQuoteArg(a)
		if err != nil {
			return "", err
		}
		parts = append(parts, qa)
	}
	// With cmd.exe /S /C, wrapping the complete command in one extra quote pair is
	// the canonical form for an executable/batch path that itself starts quoted:
	//   ""C:\\Program Files\\nodejs\\npm.cmd" "install" ..."
	return `"` + strings.Join(parts, " ") + `"`, nil
}

func decodeCommandOutput(out []byte) string {
	if utf8.Valid(out) {
		return string(out)
	}
	if runtime.GOOS != "windows" {
		return string(bytes.ToValidUTF8(out, []byte("?")))
	}
	// cmd.exe and some corporate endpoint controls still emit the active OEM
	// console code page even when Java itself uses UTF-8. CP850 is the common
	// Western-European Windows console page and covers the Portuguese diagnostics
	// seen in enterprise environments. Decoding here is display-only; exit codes
	// remain the source of truth for gates.
	const cp850High = "\u00c7\u00fc\u00e9\u00e2\u00e4\u00e0\u00e5\u00e7\u00ea\u00eb\u00e8\u00ef\u00ee\u00ec\u00c4\u00c5\u00c9\u00e6\u00c6\u00f4\u00f6\u00f2\u00fb\u00f9\u00ff\u00d6\u00dc\u00f8\u00a3\u00d8\u00d7\u0192\u00e1\u00ed\u00f3\u00fa\u00f1\u00d1\u00aa\u00ba\u00bf\u00ae\u00ac\u00bd\u00bc\u00a1\u00ab\u00bb\u2591\u2592\u2593\u2502\u2524\u00c1\u00c2\u00c0\u00a9\u2563\u2551\u2557\u255d\u00a2\u00a5\u2510\u2514\u2534\u252c\u251c\u2500\u253c\u00e3\u00c3\u255a\u2554\u2569\u2566\u2560\u2550\u256c\u00a4\u00f0\u00d0\u00ca\u00cb\u00c8\u0131\u00cd\u00ce\u00cf\u2518\u250c\u2588\u2584\u00a6\u00cc\u2580\u00d3\u00df\u00d4\u00d2\u00f5\u00d5\u00b5\u00fe\u00de\u00da\u00db\u00d9\u00fd\u00dd\u00af\u00b4\u00ad\u00b1\u2017\u00be\u00b6\u00a7\u00f7\u00b8\u00b0\u00a8\u00b7\u00b9\u00b3\u00b2\u25a0\u00a0"
	table := []rune(cp850High)
	runes := make([]rune, 0, len(out))
	for _, b := range out {
		if b < 0x80 {
			runes = append(runes, rune(b))
		} else {
			runes = append(runes, table[int(b)-0x80])
		}
	}
	return string(runes)
}

func runCmd(dir, name, cmd string, args []string) CommandResult {
	return runCmdEnv(dir, name, cmd, args, nil)
}
func runCmdEnv(dir, name, cmd string, args []string, extra map[string]string) CommandResult {
	limit := 10 * time.Minute
	if name == "Maven dependency tree" {
		limit = 3 * time.Minute
	}
	ctx, cancel := context.WithTimeout(context.Background(), limit)
	defer cancel()
	resolved, err := execLookPath(cmd)
	if err != nil {
		return CommandResult{Name: name, Command: cmd + " " + strings.Join(args, " "), ExitCode: -1, Success: false, Skipped: true, Reason: cmd + " não localizado pelo resolver de runtime"}
	}
	prefix := []string{}
	if raw := strings.TrimSpace(os.Getenv(commandPrefixKey(cmd))); raw != "" {
		_ = json.Unmarshal([]byte(raw), &prefix)
	}
	allArgs := append(append([]string{}, prefix...), args...)
	var c *exec.Cmd
	if directExe, directArgs, ok := directNodePackageManagerInvocation(cmd, resolved, allArgs); ok {
		c = exec.CommandContext(ctx, directExe, directArgs...)
	} else if runtime.GOOS != "windows" && filepath.Base(resolved) == "mvnw" {
		// Project wrappers frequently lose the executable bit when repositories are
		// copied from Windows or extracted from archives. Execute through /bin/sh
		// instead of mutating the repository with chmod. This also works on noexec
		// workspaces because the shell reads the wrapper as data.
		if raw, readErr := os.ReadFile(resolved); readErr == nil && bytes.Contains(raw, []byte("\r\n")) {
			return CommandResult{Name: name, Command: cmd + " " + strings.Join(allArgs, " "), ExitCode: -1, Success: false, Skipped: true, Reason: "mvnw usa finais de linha CRLF; normalize o Maven Wrapper para LF no Linux antes de executar"}
		}
		shArgs := append([]string{resolved}, allArgs...)
		c = exec.CommandContext(ctx, "/bin/sh", shArgs...)
	} else if runtime.GOOS == "windows" && isWindowsBatchFile(resolved) {
		// Generic Windows wrappers (mvnw.cmd, gradlew.bat, pnpm/yarn shims) still
		// require cmd.exe. The whole command is quoted as one /C payload. npm is
		// handled above by node.exe + npm-cli.js whenever possible.
		commandLine, buildErr := windowsBatchCommandLine(resolved, allArgs)
		if buildErr != nil {
			return CommandResult{Name: name, Command: cmd + " " + strings.Join(allArgs, " "), ExitCode: -1, Success: false, Skipped: true, Reason: buildErr.Error()}
		}
		c = exec.CommandContext(ctx, "cmd.exe")
		configureBatchCommand(c, commandLine)
	} else {
		c = exec.CommandContext(ctx, resolved, allArgs...)
	}
	configureProcessCancellation(c)
	c.WaitDelay = 2 * time.Second
	c.Dir = dir
	c.Env = os.Environ()
	// Maven Wrapper refuses to start when JAVA_HOME points at a launcher/shim
	// directory instead of a real Java home. Normalize it from the Java launcher
	// itself before every child process. This is intentionally defensive even if
	// the IDE adapter already performed preflight validation.
	if home := normalizedJavaHome(); home != "" {
		c.Env = replaceEnvValue(c.Env, "JAVA_HOME", home)
	} else if inherited := strings.TrimSpace(os.Getenv("JAVA_HOME")); inherited != "" && javaExecutableForHome(inherited) == "" {
		c.Env = replaceEnvValue(c.Env, "JAVA_HOME", "")
	}
	for k, v := range extra {
		c.Env = replaceEnvValue(c.Env, k, v)
	}
	out, runErr := c.CombinedOutput()
	code := 0
	if runErr != nil {
		code = 1
		if ee, ok := runErr.(*exec.ExitError); ok {
			code = ee.ExitCode()
		}
	}
	cleanOutput := stripANSI(decodeCommandOutput(out))
	if ctx.Err() != nil {
		cleanOutput += "\nTempo limite excedido: " + limit.String()
		runErr = ctx.Err()
	}
	output := truncateHeadTail(cleanOutput, 20000)
	reason := ""
	if runErr != nil {
		reason = classifyExecutionFailure(cleanOutput + " " + runErr.Error())
	}
	return CommandResult{Name: name, Command: cmd + " " + strings.Join(allArgs, " "), ExitCode: code, Success: runErr == nil, Output: output, Reason: reason}
}

func applyPlan(planPath, executionPath string) (map[string]interface{}, error) {
	var plan FixPlan
	if err := readJSON(planPath, &plan); err != nil {
		return nil, err
	}
	var ex FixExecution
	if err := readJSON(executionPath, &ex); err != nil {
		return nil, err
	}
	if ex.PlanID != plan.ID {
		return nil, fmt.Errorf("execution não corresponde ao plano")
	}
	if !pathWithin(plan.ProjectRoot, plan.ManifestPath) {
		return nil, fmt.Errorf("manifesto do plano está fora do project root")
	}
	expectedPlanDir := filepath.Join(plan.ProjectRoot, ".vulnweave", "plans")
	if !pathWithin(expectedPlanDir, planPath) || !pathWithin(expectedPlanDir, executionPath) {
		return nil, fmt.Errorf("plano/execution fora do diretório permitido")
	}
	expectedTemp, err := sandboxPathForPlan(&plan)
	if err != nil {
		return nil, err
	}
	if filepath.Clean(ex.TempRoot) != filepath.Clean(expectedTemp) {
		return nil, fmt.Errorf("temp root da execução não corresponde ao plano")
	}
	if !ex.ReadyToApply || !ex.SandboxPatchVerified || !remediationRescanAllowsApply(ex.Rescan, plan.Package, plan.TargetVersion) {
		return nil, fmt.Errorf("validação isolada não está pronta para aplicação")
	}
	tmpManifest := filepath.Join(ex.TempRoot, relOrAbs(plan.ProjectRoot, plan.ManifestPath))
	if filepath.Clean(ex.SandboxManifestPath) != filepath.Clean(tmpManifest) {
		return nil, fmt.Errorf("manifesto registrado da sandbox não corresponde ao plano")
	}
	if err := verifySandboxManifestStable(tmpManifest, &plan); err != nil {
		return nil, fmt.Errorf("patch validado da sandbox mudou antes da aplicação: %w", err)
	}
	// Recheck every original tracked file before copying anything.
	for rel, expected := range plan.OriginalFiles {
		if !safeRelativePath(rel) {
			return nil, fmt.Errorf("caminho rastreado inválido: %s", rel)
		}
		real := filepath.Join(plan.ProjectRoot, filepath.FromSlash(rel))
		if !pathWithin(plan.ProjectRoot, real) {
			return nil, fmt.Errorf("caminho rastreado fora do projeto: %s", rel)
		}
		h, err := fileHash(real)
		if err != nil || h != expected {
			return nil, fmt.Errorf("%s mudou desde a prévia; aplicação abortada", rel)
		}
	}
	actualProject, err := detectProject(plan.ProjectRoot)
	if err != nil {
		return nil, err
	}
	allowed := map[string]bool{relOrAbs(plan.ProjectRoot, actualProject.Manifest): true}
	if actualProject.Lockfile != "" {
		allowed[relOrAbs(plan.ProjectRoot, actualProject.Lockfile)] = true
	}
	changed := []string{}
	for _, rel := range ex.ChangedFiles {
		if !safeRelativePath(rel) || !allowed[filepath.ToSlash(rel)] {
			return nil, fmt.Errorf("arquivo alterado não permitido: %s", rel)
		}
		src := filepath.Join(ex.TempRoot, filepath.FromSlash(rel))
		dst := filepath.Join(plan.ProjectRoot, filepath.FromSlash(rel))
		if !pathWithin(ex.TempRoot, src) || !pathWithin(plan.ProjectRoot, dst) {
			return nil, fmt.Errorf("path traversal bloqueado: %s", rel)
		}
		if _, err := os.Stat(src); err != nil {
			return nil, fmt.Errorf("arquivo validado ausente: %s", src)
		}
		b, err := os.ReadFile(src)
		if err != nil {
			return nil, err
		}
		mode := os.FileMode(0o644)
		if info, statErr := os.Stat(dst); statErr == nil {
			mode = info.Mode().Perm()
		}
		tmp := dst + ".vulnweave.tmp"
		if err := os.WriteFile(tmp, b, mode); err != nil {
			return nil, err
		}
		if err := os.Rename(tmp, dst); err != nil {
			_ = os.Remove(tmp)
			return nil, err
		}
		changed = append(changed, rel)
	}
	return map[string]interface{}{"applied": true, "planId": plan.ID, "files": changed, "message": "Correção aplicada somente após diff, resolução do grafo/lockfile, build/testes e novo scan em cópia isolada."}, nil
}

// keep encoding/xml referenced by go vet across build tags when parsing POM plan helpers evolves
var _ = xml.Name{}
var _ = bytes.NewBuffer
