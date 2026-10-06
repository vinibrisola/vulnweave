package main

import (
	"archive/zip"
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

const (
	maxArtifactFiles        = 40
	maxArchiveEntries       = 12000
	maxNestedJarBytes int64 = 96 << 20
)

// collectArtifactDependencies performs a read-only inventory of Java build artifacts.
// It is deliberately additive: the Maven/Node source graph remains canonical for
// remediation. Artifact-only components can create findings, but never an automatic fix.
func collectArtifactDependencies(root string) ([]Dependency, []string) {
	paths, warnings := discoverJavaArtifacts(root)
	seen := map[string]Dependency{}
	for _, artifact := range paths {
		rel := relOrAbs(root, artifact)
		deps, err := inspectJavaArchive(artifact, rel)
		if err != nil {
			warnings = append(warnings, fmt.Sprintf("Artifact inventory: %s não pôde ser inspecionado: %v", rel, err))
			continue
		}
		for _, d := range deps {
			key := d.Ecosystem + "|" + d.Name + "|" + cleanVersion(d.Version)
			if d.Name == "" || d.Version == "" || d.Ecosystem == "" {
				continue
			}
			if prev, ok := seen[key]; ok {
				prev.ArtifactPaths = uniqueStrings(append(prev.ArtifactPaths, d.ArtifactPaths...))
				prev.Evidence = uniqueStrings(append(prev.Evidence, d.Evidence...))
				seen[key] = prev
			} else {
				seen[key] = d
			}
		}
	}
	out := make([]Dependency, 0, len(seen))
	for _, d := range seen {
		out = append(out, d)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Name != out[j].Name {
			return out[i].Name < out[j].Name
		}
		return cmpVersion(out[i].Version, out[j].Version) < 0
	})
	if len(paths) == 0 {
		warnings = append(warnings, "Artifact inventory: nenhum JAR/WAR/EAR de build foi encontrado em target/, build/libs/ ou diretórios de distribuição; o scan de artefato não reduz a cobertura canônica do grafo.")
	}
	return out, warnings
}

func discoverJavaArtifacts(root string) ([]string, []string) {
	var out []string
	var warnings []string
	rootAbs, err := filepath.Abs(root)
	if err != nil {
		rootAbs = root
	}
	err = filepath.WalkDir(rootAbs, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			name := d.Name()
			if name == ".git" || name == ".idea" || name == ".vulnweave" || name == "node_modules" || name == ".gradle" {
				return filepath.SkipDir
			}
			return nil
		}
		if len(out) >= maxArtifactFiles {
			return nil
		}
		ext := strings.ToLower(filepath.Ext(path))
		if ext != ".jar" && ext != ".war" && ext != ".ear" {
			return nil
		}
		rel, _ := filepath.Rel(rootAbs, path)
		slash := "/" + filepath.ToSlash(rel)
		lower := strings.ToLower(slash)
		// Restrict native artifact inspection to normal build outputs. This avoids
		// scanning source caches and vendored repositories by accident.
		if !strings.Contains(lower, "/target/") && !strings.Contains(lower, "/build/libs/") && !strings.Contains(lower, "/dist/") && !strings.Contains(lower, "/build/distributions/") {
			return nil
		}
		base := strings.ToLower(filepath.Base(path))
		if strings.Contains(base, "-sources.") || strings.Contains(base, "-javadoc.") || strings.Contains(base, "-tests.") || strings.Contains(base, "-test.") {
			return nil
		}
		out = append(out, path)
		return nil
	})
	if err != nil {
		warnings = append(warnings, "Artifact inventory: falha ao enumerar build outputs: "+err.Error())
	}
	if len(out) >= maxArtifactFiles {
		warnings = append(warnings, fmt.Sprintf("Artifact inventory limitado aos primeiros %d arquivos para manter o scan responsivo.", maxArtifactFiles))
	}
	sort.Strings(out)
	return out, warnings
}

func inspectJavaArchive(path, displayPath string) ([]Dependency, error) {
	zr, err := zip.OpenReader(path)
	if err != nil {
		return nil, err
	}
	defer zr.Close()
	return inspectZipFiles(zr.File, displayPath, 0), nil
}

func inspectZipFiles(files []*zip.File, container string, depth int) []Dependency {
	if depth > 2 {
		return nil
	}
	out := []Dependency{}
	entries := 0
	for _, f := range files {
		entries++
		if entries > maxArchiveEntries {
			break
		}
		name := filepath.ToSlash(f.Name)
		lower := strings.ToLower(name)
		if strings.HasSuffix(lower, "/pom.properties") && strings.Contains(lower, "meta-inf/maven/") {
			rc, err := f.Open()
			if err != nil {
				continue
			}
			b, _ := io.ReadAll(io.LimitReader(rc, 256<<10))
			_ = rc.Close()
			group, artifact, version := parsePomProperties(string(b))
			if group != "" && artifact != "" && version != "" {
				out = append(out, Dependency{
					Name: group + ":" + artifact, Version: cleanVersion(version), Ecosystem: "Maven",
					Direct: false, Scope: "artifact", Manifest: container, ControlHint: "artifact-only",
					DependencyPath: []string{container, group + ":" + artifact}, Evidence: []string{"artifact"},
					ArtifactPaths: []string{container}, DetectionStatus: "artifact",
				})
			}
			continue
		}
		if depth < 2 && strings.HasSuffix(lower, ".jar") && (strings.Contains(lower, "boot-inf/lib/") || strings.Contains(lower, "web-inf/lib/") || strings.HasPrefix(lower, "lib/")) {
			if f.UncompressedSize64 == 0 || f.UncompressedSize64 > uint64(maxNestedJarBytes) {
				continue
			}
			rc, err := f.Open()
			if err != nil {
				continue
			}
			b, err := io.ReadAll(io.LimitReader(rc, maxNestedJarBytes+1))
			_ = rc.Close()
			if err != nil || int64(len(b)) > maxNestedJarBytes {
				continue
			}
			nested, err := zip.NewReader(bytes.NewReader(b), int64(len(b)))
			if err != nil {
				continue
			}
			nestedContainer := container + "!" + name
			nestedDeps := inspectZipFiles(nested.File, nestedContainer, depth+1)
			if len(nestedDeps) == 0 {
				// Fallback only for inventory display. Without a groupId we must not
				// send a guessed Maven coordinate to public vulnerability services.
				if artifact, version := jarNameVersion(filepath.Base(name)); artifact != "" && version != "" {
					nestedDeps = append(nestedDeps, Dependency{
						Name: artifact, Version: cleanVersion(version), Ecosystem: "Artifact-Java",
						Scope: "artifact", Manifest: nestedContainer, ControlHint: "artifact-unresolved-coordinate",
						DependencyPath: []string{container, filepath.Base(name)}, Evidence: []string{"artifact-filename"},
						ArtifactPaths: []string{nestedContainer}, DetectionStatus: "artifact-unresolved",
					})
				}
			}
			out = append(out, nestedDeps...)
		}
	}
	return out
}

func parsePomProperties(raw string) (group, artifact, version string) {
	for _, line := range strings.Split(strings.ReplaceAll(raw, "\r\n", "\n"), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		kv := strings.SplitN(line, "=", 2)
		if len(kv) != 2 {
			continue
		}
		key, value := strings.TrimSpace(kv[0]), strings.TrimSpace(kv[1])
		switch key {
		case "groupId":
			group = value
		case "artifactId":
			artifact = value
		case "version":
			version = value
		}
	}
	return
}

func jarNameVersion(base string) (string, string) {
	base = strings.TrimSuffix(base, filepath.Ext(base))
	parts := strings.Split(base, "-")
	for i := len(parts) - 1; i > 0; i-- {
		candidate := strings.Join(parts[i:], "-")
		if parseSemverish(candidate).ok {
			return strings.Join(parts[:i], "-"), candidate
		}
	}
	return "", ""
}

func reconcileArtifactEvidence(r *ScanReport, deps []Dependency) {
	if r == nil {
		return
	}
	r.ArtifactDependencies = deps
	if r.Reconciliation == nil {
		r.Reconciliation = map[string]int{}
	}
	if len(deps) == 0 {
		r.Reconciliation["artifactComponents"] = 0
		return
	}
	canonicalDeps := map[string]bool{}
	for _, d := range r.Dependencies {
		canonicalDeps[d.Ecosystem+"|"+d.Name+"|"+cleanVersion(d.Version)] = true
	}
	confirmedInventory := 0
	unresolvedCoordinates := 0
	public := []Dependency{}
	for _, d := range deps {
		key := d.Ecosystem + "|" + d.Name + "|" + cleanVersion(d.Version)
		if canonicalDeps[key] {
			confirmedInventory++
		}
		if d.Ecosystem == "Maven" && !isPrivatePackage(d.Ecosystem, d.Name) {
			public = append(public, d)
		}
		if d.Ecosystem == "Artifact-Java" {
			unresolvedCoordinates++
		}
	}
	r.Reconciliation["artifactComponents"] = len(deps)
	r.Reconciliation["artifactConfirmedInGraph"] = confirmedInventory
	r.Reconciliation["artifactUnresolvedCoordinates"] = unresolvedCoordinates
	r.Metadata["artifactInventorySemantics"] = "read-only inventory of built JAR/WAR/EAR and nested Java libraries; artifact-only evidence never authorizes automatic remediation"

	if len(public) == 0 {
		return
	}
	scanStage("Correlacionando componentes empacotados com OSV…")
	osv, err := queryOSV(public)
	if err != nil {
		r.Warnings = append(r.Warnings, "Artifact OSV correlation indisponível; inventário do artefato foi preservado sem rebaixar a cobertura canônica: "+truncate(err.Error(), 400))
		r.Sources["Artifact OSV"] = "degraded: " + truncate(err.Error(), 180)
		return
	}
	r.Sources["Artifact inventory"] = fmt.Sprintf("healthy · %d component(s) discovered in build artifacts", len(deps))
	r.Sources["Artifact OSV"] = "healthy · read-only correlation"

	canonicalFindings := map[string]int{}
	for i := range r.Findings {
		canonicalFindings[r.Findings[i].Ecosystem+"|"+r.Findings[i].Package+"|"+cleanVersion(r.Findings[i].CurrentVersion)] = i
	}
	artifactItems := map[string]*RiskItem{}
	for _, d := range public {
		key := d.Ecosystem + "|" + d.Name + "|" + cleanVersion(d.Version)
		vs := osv[key]
		if len(vs) == 0 {
			continue
		}
		if idx, ok := canonicalFindings[key]; ok {
			r.Findings[idx].Sources = uniqueStrings(append(r.Findings[idx].Sources, "Artifact inventory"))
			r.Findings[idx].ArtifactPaths = uniqueStrings(append(r.Findings[idx].ArtifactPaths, d.ArtifactPaths...))
			r.Findings[idx].DetectionStatus = "confirmed"
			r.Findings[idx].AutoRemediationEligible = true
			continue
		}
		item := artifactItems[key]
		if item == nil {
			item = &RiskItem{
				Package: d.Name, CurrentVersion: cleanVersion(d.Version), Ecosystem: d.Ecosystem,
				Direct: false, Scope: "artifact", Runtime: true, Sources: []string{"Artifact inventory", "OSV"},
				DependencyPath: d.DependencyPath, Manifest: d.Manifest, ControlHint: "artifact-only",
				ArtifactPaths: d.ArtifactPaths, DetectionStatus: "artifact-only", AutoRemediationEligible: false,
				Origin: "packaged-artifact", Why: "Encontrado no artefato empacotado, mas não no grafo canônico. Investigue a origem antes de qualquer alteração automática.",
			}
			artifactItems[key] = item
		}
		existing := map[string]bool{}
		for _, a := range item.Advisories {
			existing[a.ID] = true
		}
		for _, v := range vs {
			if !existing[v.ID] {
				item.Advisories = append(item.Advisories, advisoryFromOSV(v, d.Name, d.Version))
				existing[v.ID] = true
			}
		}
		item.ArtifactPaths = uniqueStrings(append(item.ArtifactPaths, d.ArtifactPaths...))
	}
	for _, item := range artifactItems {
		maxCVSS := 0.0
		maxSeverity := "UNKNOWN"
		for _, a := range item.Advisories {
			if a.CVSS > maxCVSS {
				maxCVSS = a.CVSS
			}
			if severityRank(a.Severity) > severityRank(maxSeverity) {
				maxSeverity = a.Severity
			}
		}
		item.CVSS = maxCVSS
		item.Severity = maxSeverity
		item.Priority = priorityFor(item.Severity, item.CVSS, 0, false, false, true)
		r.ArtifactFindings = append(r.ArtifactFindings, *item)
	}
	sort.Slice(r.ArtifactFindings, func(i, j int) bool {
		if severityRank(r.ArtifactFindings[i].Severity) != severityRank(r.ArtifactFindings[j].Severity) {
			return severityRank(r.ArtifactFindings[i].Severity) > severityRank(r.ArtifactFindings[j].Severity)
		}
		return r.ArtifactFindings[i].Package+"|"+r.ArtifactFindings[i].CurrentVersion < r.ArtifactFindings[j].Package+"|"+r.ArtifactFindings[j].CurrentVersion
	})
	r.Reconciliation["artifactOnlyVulnerable"] = len(r.ArtifactFindings)
}
