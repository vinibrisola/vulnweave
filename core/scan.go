package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"math"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

var osvBaseURL = "https://api.osv.dev"

type osvQuery struct {
	Package struct {
		Name      string `json:"name"`
		Ecosystem string `json:"ecosystem"`
	} `json:"package"`
	Version string `json:"version"`
}
type osvBatchReq struct {
	Queries []osvQuery `json:"queries"`
}
type osvEvent struct {
	Introduced   string `json:"introduced,omitempty"`
	Fixed        string `json:"fixed,omitempty"`
	LastAffected string `json:"last_affected,omitempty"`
	Limit        string `json:"limit,omitempty"`
}
type osvRange struct {
	Type   string     `json:"type"`
	Events []osvEvent `json:"events"`
}
type osvAffected struct {
	Package struct {
		Name      string `json:"name"`
		Ecosystem string `json:"ecosystem"`
	} `json:"package"`
	Ranges   []osvRange `json:"ranges"`
	Versions []string   `json:"versions"`
}
type osvVuln struct {
	ID       string   `json:"id"`
	Modified string   `json:"modified,omitempty"`
	Aliases  []string `json:"aliases"`
	Summary  string   `json:"summary"`
	Details  string   `json:"details"`
	Severity []struct {
		Type  string `json:"type"`
		Score string `json:"score"`
	} `json:"severity"`
	Affected   []osvAffected `json:"affected"`
	References []struct {
		Type string `json:"type"`
		URL  string `json:"url"`
	} `json:"references"`
	DatabaseSpecific map[string]interface{} `json:"database_specific"`
}

// IMPORTANT: /v1/querybatch intentionally returns only vulnerability ID + modified.
// Full advisory metadata must be hydrated through GET /v1/vulns/{id}.
type osvVulnRef struct {
	ID       string `json:"id"`
	Modified string `json:"modified,omitempty"`
}
type osvResult struct {
	Vulns []osvVulnRef `json:"vulns"`
}
type osvBatchResp struct {
	Results []osvResult `json:"results"`
}

func queryOSV(deps []Dependency) (map[string][]osvVuln, error) {
	// OSV querybatch is used only as an efficient index lookup. Per the OSV API
	// contract it returns ID + modified, not summary/CVSS/affected ranges.
	// Hydrating the IDs is mandatory before risk scoring or remediation.
	refsByDependency := map[string][]string{}
	allIDs := map[string]bool{}
	const batch = 100
	for start := 0; start < len(deps); start += batch {
		end := start + batch
		if end > len(deps) {
			end = len(deps)
		}
		req := osvBatchReq{}
		for _, d := range deps[start:end] {
			q := osvQuery{Version: cleanVersion(d.Version)}
			q.Package.Name = d.Name
			q.Package.Ecosystem = d.Ecosystem
			req.Queries = append(req.Queries, q)
		}
		var resp osvBatchResp
		if err := postJSON(osvBaseURL+"/v1/querybatch", req, map[string]string{"User-Agent": "VulnWeave/" + engineVersion}, &resp); err != nil {
			return nil, err
		}
		for i, r := range resp.Results {
			if i >= end-start {
				break
			}
			d := deps[start+i]
			key := d.Ecosystem + "|" + d.Name + "|" + cleanVersion(d.Version)
			for _, ref := range r.Vulns {
				if ref.ID == "" {
					continue
				}
				refsByDependency[key] = append(refsByDependency[key], ref.ID)
				allIDs[ref.ID] = true
			}
		}
	}

	ids := make([]string, 0, len(allIDs))
	for id := range allIDs {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	full := make(map[string]osvVuln, len(ids))
	for _, id := range ids {
		var v osvVuln
		u := osvBaseURL + "/v1/vulns/" + url.PathEscape(id)
		if err := getJSONRetry(u, map[string]string{"User-Agent": "VulnWeave/" + engineVersion}, &v, 3); err != nil {
			return nil, fmt.Errorf("hidratação OSV de %s falhou: %w", id, err)
		}
		if v.ID == "" {
			return nil, fmt.Errorf("hidratação OSV de %s retornou registro sem id", id)
		}
		full[id] = v
	}

	out := map[string][]osvVuln{}
	for key, refs := range refsByDependency {
		seen := map[string]bool{}
		for _, id := range refs {
			if seen[id] {
				continue
			}
			seen[id] = true
			if v, ok := full[id]; ok {
				out[key] = append(out[key], v)
			}
		}
	}
	return out, nil
}

func vulnFixedVersion(v osvVuln, packageName, current string) string {
	best := ""
	for _, a := range v.Affected {
		if a.Package.Name != "" && a.Package.Name != packageName {
			continue
		}
		for _, r := range a.Ranges {
			for _, e := range r.Events {
				if e.Fixed != "" && (current == "" || cmpVersion(e.Fixed, current) > 0) {
					if best == "" || cmpVersion(e.Fixed, best) < 0 {
						best = e.Fixed
					}
				}
			}
		}
	}
	return best
}
func vulnCVSS(v osvVuln) float64 {
	best := 0.0
	for _, s := range v.Severity {
		score := cvssVectorScore(s.Score)
		if score > best {
			best = score
		}
	}
	if best > 0 {
		return best
	}
	// Some OSV producers expose an explicit numeric score in database_specific.
	// Do not invent a numeric CVSS from a qualitative label.
	if x, ok := v.DatabaseSpecific["cvss"].(map[string]interface{}); ok {
		if n, ok := x["score"].(float64); ok && n > best {
			best = n
		}
	}
	return best
}

func vulnQualitativeSeverity(v osvVuln, cvss float64) string {
	best := severityFromCVSS(cvss)
	if n, ok := v.DatabaseSpecific["severity"].(string); ok {
		candidate := strings.ToUpper(strings.TrimSpace(n))
		if candidate == "MODERATE" {
			candidate = "MEDIUM"
		}
		if severityRank(candidate) > severityRank(best) {
			best = candidate
		}
	}
	return best
}

func severityRank(s string) int {
	switch strings.ToUpper(s) {
	case "CRITICAL":
		return 4
	case "HIGH":
		return 3
	case "MEDIUM", "MODERATE":
		return 2
	case "LOW":
		return 1
	default:
		return 0
	}
}

func cvssVectorScore(vector string) float64 {
	if !strings.HasPrefix(vector, "CVSS:3.") {
		return 0
	}
	m := map[string]string{}
	for _, p := range strings.Split(vector, "/")[1:] {
		kv := strings.SplitN(p, ":", 2)
		if len(kv) == 2 {
			m[kv[0]] = kv[1]
		}
	}
	av := map[string]float64{"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}[m["AV"]]
	ac := map[string]float64{"L": 0.77, "H": 0.44}[m["AC"]]
	scope := m["S"]
	pr := 0.0
	if scope == "U" {
		pr = map[string]float64{"N": 0.85, "L": 0.62, "H": 0.27}[m["PR"]]
	} else {
		pr = map[string]float64{"N": 0.85, "L": 0.68, "H": 0.5}[m["PR"]]
	}
	ui := map[string]float64{"N": 0.85, "R": 0.62}[m["UI"]]
	c := map[string]float64{"H": 0.56, "L": 0.22, "N": 0}[m["C"]]
	i := map[string]float64{"H": 0.56, "L": 0.22, "N": 0}[m["I"]]
	a := map[string]float64{"H": 0.56, "L": 0.22, "N": 0}[m["A"]]
	if av == 0 || ac == 0 || pr == 0 || ui == 0 {
		return 0
	}
	iss := 1 - (1-c)*(1-i)*(1-a)
	impact := 0.0
	if scope == "U" {
		impact = 6.42 * iss
	} else {
		impact = 7.52*(iss-0.029) - 3.25*math.Pow(iss-0.02, 15)
	}
	if impact <= 0 {
		return 0
	}
	exploit := 8.22 * av * ac * pr * ui
	base := 0.0
	if scope == "U" {
		base = math.Min(impact+exploit, 10)
	} else {
		base = math.Min(1.08*(impact+exploit), 10)
	}
	return math.Ceil(base*10-1e-9) / 10
}

func advisoryFromOSV(v osvVuln, pkg, current string) Advisory {
	a := Advisory{ID: v.ID, Aliases: uniqueStrings(v.Aliases), Summary: v.Summary, Details: truncate(v.Details, 1200), CVSS: vulnCVSS(v), FixedVersion: vulnFixedVersion(v, pkg, current)}
	a.Severity = vulnQualitativeSeverity(v, a.CVSS)
	for _, r := range v.References {
		if r.URL != "" {
			a.References = append(a.References, r.URL)
		}
	}
	return a
}

func deriveCandidate(advisories []Advisory) (string, string) {
	if len(advisories) == 0 {
		return "", "nenhum advisory associado ao componente"
	}
	cand := ""
	missing := 0
	for _, a := range advisories {
		if a.FixedVersion == "" {
			missing++
			continue
		}
		cand = maxVersion(cand, a.FixedVersion)
	}
	if missing > 0 {
		return "", fmt.Sprintf("%d advisory(s) não publicam uma versão corrigida no registry/ecossistema padrão; será tentada uma rota oficial de fornecedor antes de exigir investigação manual", missing)
	}
	if cand == "" {
		return "", "nenhuma candidata automática segura foi derivada dos ranges publicados"
	}
	return cand, fmt.Sprintf("menor versão agregada acima da atual que cobre os fixed ranges publicados dos %d advisories; será revalidada contra OSV antes do plano", len(advisories))
}

func deriveRemediation(pkg, current, ecosystem string, advisories []Advisory) RemediationOption {
	if cand, why := deriveCandidate(advisories); cand != "" && cmpVersion(cand, current) > 0 {
		source := "OSV + GitHub Advisory Database"
		return RemediationOption{Version: cand, Kind: "registry", Source: source, Trusted: true, AutoPlan: true, Why: why}
	}
	if vendor := trustedVendorOption(ecosystem, pkg, current, advisories); vendor != nil {
		return *vendor
	}
	return RemediationOption{Kind: "manual", Source: "OSV + GitHub Advisory Database", Trusted: true, AutoPlan: false, Why: "Nenhuma versão corrigida automatizável foi publicada nas fontes estruturadas consultadas e não há uma rota de fornecedor curada para este pacote. O VulnWeave não inventa versões ou bibliotecas substitutas."}
}

func collectCVEs(vs []osvVuln) []string {
	var out []string
	for _, v := range vs {
		if strings.HasPrefix(v.ID, "CVE-") {
			out = append(out, v.ID)
		}
		for _, a := range v.Aliases {
			if strings.HasPrefix(a, "CVE-") {
				out = append(out, a)
			}
		}
	}
	return uniqueStrings(out)
}

func queryEPSS(cves []string) (map[string]float64, error) {
	out := map[string]float64{}
	if len(cves) == 0 {
		return out, nil
	}
	for start := 0; start < len(cves); start += 50 {
		end := start + 50
		if end > len(cves) {
			end = len(cves)
		}
		var resp struct {
			Data []struct {
				CVE  string `json:"cve"`
				EPSS string `json:"epss"`
			} `json:"data"`
		}
		u := "https://api.first.org/data/v1/epss?cve=" + url.QueryEscape(strings.Join(cves[start:end], ","))
		if err := getJSON(u, map[string]string{"User-Agent": "VulnWeave/" + engineVersion}, &resp); err != nil {
			return out, err
		}
		for _, d := range resp.Data {
			var x float64
			fmt.Sscanf(d.EPSS, "%f", &x)
			out[d.CVE] = x
		}
	}
	return out, nil
}
func queryKEV() (map[string]bool, error) {
	var resp struct {
		Vulnerabilities []struct {
			CVE string `json:"cveID"`
		} `json:"vulnerabilities"`
	}
	err := getJSON("https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json", map[string]string{"User-Agent": "VulnWeave/" + engineVersion}, &resp)
	if err != nil {
		return nil, err
	}
	out := map[string]bool{}
	for _, v := range resp.Vulnerabilities {
		out[v.CVE] = true
	}
	return out, nil
}

func scanProject(root, mode string) (*ScanReport, error) {
	p, err := detectProject(root)
	if err != nil {
		return nil, err
	}
	scanStage("Resolvendo dependências do projeto…")
	deps, warnings := collectDependencies(p)
	if len(deps) == 0 {
		warnings = append(warnings, "Nenhuma dependência com versão resolvida; análise incompleta.")
	}
	generatedAt := time.Now().UTC()
	depBytes, _ := json.Marshal(deps)
	graphHash := bytesHash(depBytes)
	baselineSeed := fmt.Sprintf("%s|%s|%s", p.Root, generatedAt.Format(time.RFC3339Nano), graphHash)
	baselineID := bytesHash([]byte(baselineSeed))[:12]
	report := &ScanReport{SchemaVersion: "vulnweave.scan/2", EngineVersion: engineVersion, BaselineID: baselineID, GeneratedAt: generatedAt, Mode: "full", Project: p, Sources: map[string]string{}, Artifacts: map[string]string{}, Warnings: warnings, Metadata: map[string]interface{}{
		"dependencyCount":       len(deps),
		"dependencyGraphHash":   graphHash,
		"requestedMode":         mode,
		"findingCountSemantics": "unique vulnerable components from the canonical resolved dependency graph; auxiliary scanners enrich evidence and do not inflate the count",
		"osvAdvisoryHydration":  "querybatch IDs are hydrated through GET /v1/vulns/{id} before scoring and remediation",
	}}
	publicDeps := make([]Dependency, 0, len(deps))
	report.CoverageStatus = graphCoverage(deps, warnings)
	report.Dependencies = deps
	if p.Ecosystem == "Maven" {
		report.Artifacts["mavenResolution"] = filepath.Join(root, ".vulnweave", "reports", "maven-resolution.json")
	}
	privateCount := 0
	for _, d := range deps {
		if isPrivatePackage(d.Ecosystem, d.Name) {
			privateCount++
			continue
		}
		publicDeps = append(publicDeps, d)
	}
	if privateCount > 0 {
		report.Metadata["privateDependenciesExcludedFromPublicLookups"] = privateCount
		report.Warnings = append(report.Warnings, fmt.Sprintf("%d dependência(s) privada(s) foram excluídas de OSV/npm/Maven Central conforme a política local de privacidade", privateCount))
	}
	scanStage("Consultando vulnerabilidades OSV…")
	osv, err := queryOSV(publicDeps)
	if err != nil {
		return nil, fmt.Errorf("OSV: %w", err)
	}
	report.Sources["OSV"] = "healthy · querybatch index + full advisory hydration"
	allCVEs := []string{}
	for _, vs := range osv {
		allCVEs = append(allCVEs, collectCVEs(vs)...)
	}
	allCVEs = uniqueStrings(allCVEs)
	epss := map[string]float64{}
	if len(allCVEs) > 0 {
		if x, e := queryEPSS(allCVEs); e == nil {
			epss = x
			report.Sources["FIRST EPSS"] = "healthy"
		} else {
			report.Sources["FIRST EPSS"] = "degraded: " + e.Error()
			report.Warnings = append(report.Warnings, "EPSS indisponível: "+e.Error())
		}
	}
	kev := map[string]bool{}
	if x, e := queryKEV(); e == nil {
		kev = x
		report.Sources["CISA KEV"] = "healthy"
	} else {
		report.Sources["CISA KEV"] = "degraded: " + e.Error()
		report.Warnings = append(report.Warnings, "CISA KEV indisponível: "+e.Error())
	}
	for _, d := range deps {
		key := d.Ecosystem + "|" + d.Name + "|" + cleanVersion(d.Version)
		vs := osv[key]
		if len(vs) == 0 {
			continue
		}
		item := RiskItem{Package: d.Name, CurrentVersion: cleanVersion(d.Version), DeclaredVersion: d.Declared, Ecosystem: d.Ecosystem, Direct: d.Direct, Scope: d.Scope, Runtime: runtimeScope(d.Scope), Sources: []string{"OSV"}, DependencyPath: d.DependencyPath, Manifest: relOrAbs(p.Root, d.Manifest), ControlHint: d.ControlHint}
		for _, v := range vs {
			item.Advisories = append(item.Advisories, advisoryFromOSV(v, d.Name, d.Version))
		}
		if enriched, used, ghWarnings := enrichFromGitHubAdvisory(d.Name, d.Ecosystem, item.Advisories); used || len(ghWarnings) > 0 {
			item.Advisories = enriched
			if used {
				item.Sources = append(item.Sources, "GitHub Advisory Database")
				report.Sources["GitHub Advisory Database"] = "fallback para metadados/fixed versions ausentes no OSV"
			}
			for _, w := range ghWarnings {
				report.Warnings = append(report.Warnings, w)
			}
		}
		maxCVSS := 0.0
		maxSeverity := "UNKNOWN"
		maxEPSS := 0.0
		anyKEV := false
		for _, a := range item.Advisories {
			if a.CVSS > maxCVSS {
				maxCVSS = a.CVSS
			}
			if severityRank(a.Severity) > severityRank(maxSeverity) {
				maxSeverity = a.Severity
			}
			for _, id := range append([]string{a.ID}, a.Aliases...) {
				if !strings.HasPrefix(id, "CVE-") {
					continue
				}
				if epss[id] > maxEPSS {
					maxEPSS = epss[id]
				}
				if kev[id] {
					anyKEV = true
				}
			}
		}
		item.CVSS = maxCVSS
		item.Severity = maxSeverity
		item.EPSS = maxEPSS
		item.KEV = anyKEV
		remediation := deriveRemediation(item.Package, item.CurrentVersion, item.Ecosystem, item.Advisories)
		item.RemediationOptions = []RemediationOption{remediation}
		item.CandidateVersion = remediation.Version
		item.CandidateWhy = remediation.Why
		item.CandidateKind = remediation.Kind
		item.CandidateSpec = remediation.InstallSpec
		item.CandidateSource = remediation.Source
		item.CandidateEvidenceURL = remediation.EvidenceURL
		item.Priority = priorityFor(item.Severity, item.CVSS, item.EPSS, item.KEV, item.Direct, item.Runtime)
		directText := "dependência transitiva"
		if item.Direct {
			directText = "dependência direta"
		}
		runtimeText := "fora de runtime"
		if item.Runtime {
			runtimeText = "presente em runtime"
		}
		item.Why = fmt.Sprintf("severidade %s · %s · %s", strings.ToLower(item.Severity), runtimeText, directText)
		if len(epss) > 0 {
			item.Sources = append(item.Sources, "FIRST EPSS")
		}
		if len(kev) > 0 {
			item.Sources = append(item.Sources, "CISA KEV")
		}
		item.Sources = uniqueStrings(item.Sources)
		report.Findings = append(report.Findings, item)
	}
	// Highest-risk first, then package name.
	rank := map[string]int{"P0": 0, "P1": 1, "P2": 2, "P3": 3, "P4": 4}
	sort.Slice(report.Findings, func(i, j int) bool {
		ri, rj := rank[report.Findings[i].Priority], rank[report.Findings[j].Priority]
		if ri != rj {
			return ri < rj
		}
		if report.Findings[i].CVSS != report.Findings[j].CVSS {
			return report.Findings[i].CVSS > report.Findings[j].CVSS
		}
		return report.Findings[i].Package < report.Findings[j].Package
	})
	for _, f := range report.Findings {
		report.Summary.Total++
		switch f.Severity {
		case "CRITICAL":
			report.Summary.Critical++
		case "HIGH":
			report.Summary.High++
		case "MEDIUM":
			report.Summary.Medium++
		case "LOW":
			report.Summary.Low++
		}
		if f.Priority == "P0" {
			report.Summary.P0++
			report.PolicyBlocked = true
		}
		if f.Priority == "P1" {
			report.Summary.P1++
			report.PolicyBlocked = true
		}
	}
	// 0.11 adds a read-only artifact inventory. It is intentionally separated from
	// remediation: only the canonical source graph can authorize automatic changes.
	if p.Ecosystem == "Maven" {
		scanStage("Inspecionando artefatos Java empacotados…")
		artifactDeps, artifactWarnings := collectArtifactDependencies(root)
		for _, w := range artifactWarnings {
			report.Warnings = append(report.Warnings, w)
		}
		if len(artifactDeps) == 0 {
			report.Sources["Artifact inventory"] = "not available · no JAR/WAR/EAR build output found"
		}
		reconcileArtifactEvidence(report, artifactDeps)
	}
	// Auxiliary tools enrich evidence; the canonical remediation contract remains
	// the resolved dependency graph + OSV.
	deepScan(root, report)
	reconcileEvidenceSummary(report)
	if len(report.ArtifactFindings) > 0 {
		report.PolicyBlocked = true
		report.Metadata["artifactEvidenceStatus"] = "review-required"
		report.Warnings = append(report.Warnings, fmt.Sprintf("%d componente(s) vulnerável(is) foram encontrados no artefato empacotado fora do grafo canônico; a remediação automática permanece desabilitada até a origem ser correlacionada.", len(report.ArtifactFindings)))
	}
	if auxiliaryHasUnresolvedEvidence(report) {
		// Auxiliary disagreement is a review signal, not a statement that the
		// canonical resolved graph + OSV scan is incomplete. Keep the canonical
		// coverage result intact while preventing an overall clean-policy verdict.
		report.PolicyBlocked = true
		report.Metadata["auxiliaryEvidenceStatus"] = "review-required"
		report.Warnings = append(report.Warnings, "Trivy encontrou evidências ainda não correlacionadas ao grafo principal. A cobertura canônica permanece separada; revise os achados auxiliares.")
	} else if auxiliarySourcesDegraded(report) {
		report.Metadata["auxiliaryEvidenceStatus"] = "degraded"
	} else {
		report.Metadata["auxiliaryEvidenceStatus"] = "healthy-or-not-required"
	}
	if report.CoverageStatus != "complete" {
		report.PolicyBlocked = true
	}
	scanStage("Gravando relatório e evidências…")
	if err := writeArtifacts(report); err != nil {
		report.Warnings = append(report.Warnings, "falha ao gravar artefatos: "+err.Error())
	}
	return report, nil
}

func writeArtifacts(r *ScanReport) error {
	dir := filepath.Join(r.Project.Root, ".vulnweave", "reports")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	scan := filepath.Join(dir, "vulnweave-scan.json")
	if err := writeJSON(scan, r); err != nil {
		return err
	}
	r.Artifacts["scanJson"] = scan
	md := renderMarkdown(r)
	mdp := filepath.Join(dir, "vulnweave-scan.md")
	_ = os.WriteFile(mdp, []byte(md), 0o600)
	r.Artifacts["scanMarkdown"] = mdp
	sbom := renderCycloneDX(r)
	sp := filepath.Join(dir, "source-bom.cdx.json")
	_ = os.WriteFile(sp, []byte(sbom), 0o600)
	r.Artifacts["sbom"] = sp
	sarif := renderSARIF(r)
	sap := filepath.Join(dir, "vulnweave.sarif")
	_ = os.WriteFile(sap, []byte(sarif), 0o600)
	r.Artifacts["sarif"] = sap
	vex := renderVEX(r)
	vp := filepath.Join(dir, "vex.cdx.json")
	_ = os.WriteFile(vp, []byte(vex), 0o600)
	r.Artifacts["vex"] = vp
	return writeJSON(scan, r)
}
func renderMarkdown(r *ScanReport) string {
	var b strings.Builder
	fmt.Fprintf(&b, "# VulnWeave %s\n\nProjeto: `%s`  \nModo: **%s**  \nPolicy blocked: **%v**\n\n", r.EngineVersion, r.Project.Name, r.Mode, r.PolicyBlocked)
	for _, f := range r.Findings {
		fmt.Fprintf(&b, "## %s %s\n\n- Prioridade: %s\n- Severidade/CVSS: %s %.1f\n- EPSS: %.2f%%\n- KEV: %v\n- Dependência: %s / %s\n- Candidata: %s\n\n", f.Package, f.CurrentVersion, f.Priority, f.Severity, f.CVSS, f.EPSS*100, f.KEV, map[bool]string{true: "direta", false: "transitiva"}[f.Direct], f.Scope, f.CandidateVersion)
		for _, a := range f.Advisories {
			fmt.Fprintf(&b, "  - `%s` %s\n", a.ID, a.Summary)
		}
	}
	fmt.Fprintf(&b, "\nCobertura: %s\n", r.CoverageStatus)
	for _, w := range r.Warnings {
		fmt.Fprintf(&b, "- Aviso: %s\n", w)
	}
	for _, f := range r.ArtifactFindings {
		fmt.Fprintf(&b, "\n## Artifact-only: %s %s\n\n- Fontes: %s\n- Auto-remediação: não\n", f.Package, f.CurrentVersion, strings.Join(f.Sources, ", "))
		for _, p := range f.ArtifactPaths {
			fmt.Fprintf(&b, "- Artefato: `%s`\n", p)
		}
		for _, a := range f.Advisories {
			fmt.Fprintf(&b, "- %s · %s · %s\n", a.ID, a.Severity, a.Summary)
		}
	}
	for _, f := range r.AuxiliaryFindings {
		fmt.Fprintf(&b, "\n## Evidência auxiliar: %s %s\n\n- Fontes: %s\n", f.Package, f.CurrentVersion, strings.Join(f.Sources, ", "))
		for _, a := range f.Advisories {
			fmt.Fprintf(&b, "- %s · %s · %s\n", a.ID, a.Severity, a.Summary)
		}
	}
	return b.String()
}
func renderCycloneDX(r *ScanReport) string {
	components := []map[string]interface{}{}
	seen := map[string]bool{}
	inventory := []Dependency{}
	inventory = append(inventory, r.Dependencies...)
	inventory = append(inventory, r.ArtifactDependencies...)
	if len(inventory) == 0 {
		for _, f := range r.Findings {
			inventory = append(inventory, Dependency{Name: f.Package, Version: f.CurrentVersion, Ecosystem: f.Ecosystem})
		}
	}
	for _, d := range inventory {
		if d.Name == "" || d.Version == "" {
			continue
		}
		key := d.Ecosystem + "|" + d.Name + "|" + cleanVersion(d.Version)
		if seen[key] {
			continue
		}
		seen[key] = true
		purl := ""
		if d.Ecosystem == "npm" {
			purl = "pkg:npm/" + url.PathEscape(d.Name) + "@" + d.Version
		}
		if d.Ecosystem == "Maven" {
			parts := strings.SplitN(d.Name, ":", 2)
			if len(parts) == 2 {
				purl = "pkg:maven/" + parts[0] + "/" + parts[1] + "@" + d.Version
			}
		}
		component := map[string]interface{}{"type": "library", "name": d.Name, "version": d.Version}
		if purl != "" {
			component["purl"] = purl
		}
		if len(d.ArtifactPaths) > 0 {
			component["properties"] = []map[string]string{{"name": "vulnweave:evidence", "value": "artifact"}, {"name": "vulnweave:artifactPath", "value": d.ArtifactPaths[0]}}
		}
		components = append(components, component)
	}
	doc := map[string]interface{}{"bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1, "metadata": map[string]interface{}{"timestamp": r.GeneratedAt, "tools": []map[string]interface{}{{"vendor": "VulnWeave", "name": "engine", "version": engineVersion}}}, "components": components}
	b, _ := json.MarshalIndent(doc, "", "  ")
	return string(b)
}

func renderSARIF(r *ScanReport) string {
	results := []map[string]interface{}{}
	allFindings := append([]RiskItem{}, r.Findings...)
	allFindings = append(allFindings, r.ArtifactFindings...)
	for _, f := range allFindings {
		for _, a := range f.Advisories {
			lvl := "warning"
			if f.Severity == "CRITICAL" || f.Severity == "HIGH" {
				lvl = "error"
			}
			results = append(results, map[string]interface{}{"ruleId": a.ID, "level": lvl, "message": map[string]string{"text": fmt.Sprintf("%s %s vulnerável; candidata %s", f.Package, f.CurrentVersion, f.CandidateVersion)}})
		}
	}
	doc := map[string]interface{}{"version": "2.1.0", "$schema": "https://json.schemastore.org/sarif-2.1.0.json", "runs": []map[string]interface{}{{"tool": map[string]interface{}{"driver": map[string]interface{}{"name": "VulnWeave", "version": engineVersion}}, "results": results}}}
	b, _ := json.MarshalIndent(doc, "", "  ")
	return string(b)
}
func renderVEX(r *ScanReport) string {
	vulns := []map[string]interface{}{}
	for _, f := range r.Findings {
		for _, a := range f.Advisories {
			vulns = append(vulns, map[string]interface{}{"id": a.ID, "analysis": map[string]interface{}{"state": "in_triage", "detail": "SCA detectou presença; reachability não foi provada."}})
		}
	}
	doc := map[string]interface{}{"bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1, "vulnerabilities": vulns}
	b, _ := json.MarshalIndent(doc, "", "  ")
	return string(b)
}

func deepScan(root string, r *ScanReport) {
	dir := filepath.Join(root, ".vulnweave", "reports")
	_ = os.MkdirAll(dir, 0o755)
	summary := map[string]interface{}{
		"canonicalEngine": "native dependency graph + OSV + EPSS + CISA KEV",
		"countPolicy":     "auxiliary scanner results never create duplicate component cards or mutate the canonical finding count",
		"trivy":           "not installed",
		"osvScanner":      "not installed",
	}

	if privateRulesPresent() {
		r.Sources["OSV-Scanner"] = "skipped · private package policy prevents auxiliary public lookups"
		summary["osvScanner"] = map[string]interface{}{"status": "skipped", "reason": "private package policy"}
	} else if commandExists("osv-scanner") {
		scanStage("Executando OSV-Scanner auxiliar (limite: 5 minutos)…")
		out, stderr, exit, err := runDeepJSONTool(root, 5*time.Minute, "osv-scanner", []string{"scan", "source", "--format=json", "--recursive", root})
		if (exit == 0 || exit == 1) && json.Valid(out) {
			if e := importOSVScannerEvidence(r, out); e != nil {
				r.Warnings = append(r.Warnings, "Falha ao importar evidência do OSV-Scanner: "+e.Error())
			}
			p := filepath.Join(dir, "osv-scanner.json")
			_ = os.WriteFile(p, out, 0o600)
			r.Artifacts["osvScanner"] = p
			r.Sources["OSV-Scanner"] = "executed and reconciled as auxiliary corroboration"
			summary["osvScanner"] = map[string]interface{}{"status": "executed", "exitCode": exit, "artifact": p, "imported": true}
		} else {
			r.Sources["OSV-Scanner"] = "degraded"
			summary["osvScanner"] = map[string]interface{}{"status": "failed", "exitCode": exit, "error": truncate(errString(err, stderr), 600)}
			r.Warnings = append(r.Warnings, "OSV-Scanner auxiliar não concluiu com JSON válido; a cobertura canônica (grafo resolvido + OSV) não foi rebaixada por essa falha auxiliar: "+truncate(errString(err, stderr), 400))
		}
	} else {
		r.Sources["OSV-Scanner"] = "not installed; canonical scan unaffected"
	}

	if commandExists("trivy") {
		scanStage("Executando Trivy auxiliar (limite: 7 minutos)…")
		out, stderr, exit, err := runDeepJSONTool(root, 7*time.Minute, "trivy", []string{"fs", "--scanners", "vuln", "--format", "json", "--quiet", root})
		if exit == 0 && json.Valid(out) {
			if e := importTrivyEvidence(r, out); e != nil {
				r.Warnings = append(r.Warnings, "Falha ao interpretar Trivy auxiliar; a cobertura canônica permanece separada: "+e.Error())
			}
			p := filepath.Join(dir, "trivy-vulnerabilities.json")
			_ = os.WriteFile(p, out, 0o600)
			r.Artifacts["trivy"] = p
			r.Sources["Trivy"] = "executed as auxiliary corroboration"
			summary["trivy"] = map[string]interface{}{"status": "executed", "exitCode": exit, "artifact": p}
		} else {
			r.Sources["Trivy"] = "degraded"
			summary["trivy"] = map[string]interface{}{"status": "failed", "exitCode": exit, "error": truncate(errString(err, stderr), 600)}
			r.Warnings = append(r.Warnings, "Trivy auxiliar não concluiu com JSON válido; a cobertura canônica (grafo resolvido + OSV) não foi rebaixada por essa falha auxiliar: "+truncate(errString(err, stderr), 400))
		}
	} else {
		r.Sources["Trivy"] = "not installed; canonical scan unaffected"
	}

	p := filepath.Join(dir, "deep-scan-summary.json")
	_ = writeJSON(p, summary)
	r.Artifacts["deepSummary"] = p
}

type cappedBuffer struct {
	b    bytes.Buffer
	max  int
	over bool
}

func (w *cappedBuffer) Write(p []byte) (int, error) {
	orig := len(p)
	remaining := w.max - w.b.Len()
	if remaining <= 0 {
		w.over = true
		return orig, nil
	}
	if len(p) > remaining {
		w.over = true
		_, _ = w.b.Write(p[:remaining])
		return orig, nil
	}
	_, _ = w.b.Write(p)
	return orig, nil
}
func (w *cappedBuffer) Bytes() []byte  { return w.b.Bytes() }
func (w *cappedBuffer) String() string { return w.b.String() }

func runDeepJSONTool(root string, timeout time.Duration, name string, args []string) ([]byte, string, int, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	path, err := exec.LookPath(name)
	if err != nil {
		return nil, "", -1, err
	}
	cmd := exec.CommandContext(ctx, path, args...)
	cmd.Dir = root
	stdout := &cappedBuffer{max: 64 << 20}
	stderr := &cappedBuffer{max: 2 << 20}
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	err = cmd.Run()
	exit := 0
	if err != nil {
		exit = 1
		if ee, ok := err.(*exec.ExitError); ok {
			exit = ee.ExitCode()
		}
	}
	if ctx.Err() == context.DeadlineExceeded {
		return stdout.Bytes(), stderr.String(), -1, fmt.Errorf("%s excedeu o timeout de %s", name, timeout)
	}
	if stdout.over {
		return stdout.Bytes(), stderr.String(), -1, fmt.Errorf("%s excedeu o limite de 64 MiB de saída JSON", name)
	}
	return stdout.Bytes(), stderr.String(), exit, err
}

func errString(err error, stderr string) string {
	parts := []string{}
	if err != nil {
		parts = append(parts, err.Error())
	}
	if strings.TrimSpace(stderr) != "" {
		parts = append(parts, strings.TrimSpace(stderr))
	}
	if len(parts) == 0 {
		return "saída não reconhecida"
	}
	return strings.Join(parts, ": ")
}

func findRisk(r *ScanReport, pkg string) *RiskItem {
	for i := range r.Findings {
		if r.Findings[i].Package == pkg {
			return &r.Findings[i]
		}
	}
	return nil
}

func findRiskVersion(r *ScanReport, pkg, version string) *RiskItem {
	version = cleanVersion(version)
	for i := range r.Findings {
		if r.Findings[i].Package == pkg && cleanVersion(r.Findings[i].CurrentVersion) == version {
			return &r.Findings[i]
		}
	}
	return nil
}
