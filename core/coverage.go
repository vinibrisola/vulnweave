package main

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
)

func scanStage(message string) { fmt.Fprintln(os.Stderr, "VULNWEAVE_STAGE:"+message) }

func graphCoverage(deps []Dependency, warnings []string) string {
	if len(deps) == 0 || len(warnings) > 0 {
		return "incomplete"
	}
	return "complete"
}

func findArtifactRiskVersion(r *ScanReport, pkg, version, ecosystem string) *RiskItem {
	version = cleanVersion(version)
	for i := range r.ArtifactFindings {
		if r.ArtifactFindings[i].Package == pkg && cleanVersion(r.ArtifactFindings[i].CurrentVersion) == version && (ecosystem == "" || r.ArtifactFindings[i].Ecosystem == ecosystem) {
			return &r.ArtifactFindings[i]
		}
	}
	return nil
}

func mergeAdvisory(item *RiskItem, a Advisory) {
	if item == nil || a.ID == "" {
		return
	}
	for i := range item.Advisories {
		if item.Advisories[i].ID == a.ID {
			item.Advisories[i].Aliases = uniqueStrings(append(item.Advisories[i].Aliases, a.Aliases...))
			if item.Advisories[i].Summary == "" {
				item.Advisories[i].Summary = a.Summary
			}
			if a.CVSS > item.Advisories[i].CVSS {
				item.Advisories[i].CVSS = a.CVSS
			}
			if item.Advisories[i].FixedVersion == "" {
				item.Advisories[i].FixedVersion = a.FixedVersion
			}
			item.Advisories[i].References = uniqueStrings(append(item.Advisories[i].References, a.References...))
			return
		}
	}
	item.Advisories = append(item.Advisories, a)
}

func mergeAuxiliaryRisk(r *ScanReport, item RiskItem) {
	key := item.Ecosystem + "|" + item.Package + "|" + cleanVersion(item.CurrentVersion)
	for i := range r.AuxiliaryFindings {
		x := &r.AuxiliaryFindings[i]
		if x.Ecosystem+"|"+x.Package+"|"+cleanVersion(x.CurrentVersion) != key {
			continue
		}
		x.Sources = uniqueStrings(append(x.Sources, item.Sources...))
		x.ArtifactPaths = uniqueStrings(append(x.ArtifactPaths, item.ArtifactPaths...))
		for _, a := range item.Advisories {
			mergeAdvisory(x, a)
		}
		if severityRank(item.Severity) > severityRank(x.Severity) {
			x.Severity = item.Severity
		}
		return
	}
	r.AuxiliaryFindings = append(r.AuxiliaryFindings, item)
}

// Auxiliary evidence remains separate from the resolved graph and is never
// eligible for automatic remediation. When it matches a canonical/artifact
// component, it is attached as corroborating evidence instead of duplicated.
func importTrivyEvidence(r *ScanReport, data []byte) error {
	var doc struct {
		Results []struct {
			Target          string
			Type            string
			Packages        []struct{ Name, Version string }
			Vulnerabilities []struct {
				VulnerabilityID  string
				PkgName          string
				InstalledVersion string
				Severity         string
				Title            string
				FixedVersion     string
				PrimaryURL       string
			}
		}
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		return err
	}
	items := map[string]*RiskItem{}
	for _, result := range doc.Results {
		ecosystem := ""
		switch result.Type {
		case "pom", "jar", "gradle", "java-archive":
			ecosystem = "Maven"
		case "npm", "node-pkg":
			ecosystem = "npm"
		default:
			continue
		}
		for _, v := range result.Vulnerabilities {
			if v.PkgName == "" || v.InstalledVersion == "" || v.VulnerabilityID == "" {
				continue
			}
			key := ecosystem + "|" + v.PkgName + "|" + cleanVersion(v.InstalledVersion)
			item := items[key]
			if item == nil {
				item = &RiskItem{Package: v.PkgName, CurrentVersion: cleanVersion(v.InstalledVersion), Ecosystem: ecosystem, Severity: "UNKNOWN", Sources: []string{"Trivy"}, ControlHint: "auxiliary-only", Manifest: result.Target, Why: "Evidência auxiliar; grafo e aplicabilidade precisam de validação.", DetectionStatus: "scanner-only", AutoRemediationEligible: false}
				if result.Type == "jar" || result.Type == "java-archive" {
					item.ArtifactPaths = []string{result.Target}
					item.Origin = "packaged-artifact"
				}
				items[key] = item
			}
			refs := []string{}
			if v.PrimaryURL != "" {
				refs = append(refs, v.PrimaryURL)
			}
			sev := strings.ToUpper(v.Severity)
			mergeAdvisory(item, Advisory{ID: v.VulnerabilityID, Summary: v.Title, Severity: sev, FixedVersion: v.FixedVersion, References: refs})
			if severityWeight(sev) > severityWeight(item.Severity) {
				item.Severity = sev
			}
		}
	}
	for _, item := range items {
		if canonical := findRiskVersion(r, item.Package, item.CurrentVersion); canonical != nil && canonical.Ecosystem == item.Ecosystem {
			canonical.Sources = uniqueStrings(append(canonical.Sources, "Trivy"))
			canonical.ArtifactPaths = uniqueStrings(append(canonical.ArtifactPaths, item.ArtifactPaths...))
			if canonical.DetectionStatus == "" {
				canonical.DetectionStatus = "confirmed"
			}
			for _, a := range item.Advisories {
				mergeAdvisory(canonical, a)
			}
			continue
		}
		if artifact := findArtifactRiskVersion(r, item.Package, item.CurrentVersion, item.Ecosystem); artifact != nil {
			artifact.Sources = uniqueStrings(append(artifact.Sources, "Trivy"))
			artifact.ArtifactPaths = uniqueStrings(append(artifact.ArtifactPaths, item.ArtifactPaths...))
			artifact.DetectionStatus = "artifact-only"
			for _, a := range item.Advisories {
				mergeAdvisory(artifact, a)
			}
			continue
		}
		mergeAuxiliaryRisk(r, *item)
	}
	sortAuxiliary(r)
	return nil
}

// importOSVScannerEvidence consumes OSV-Scanner v2 JSON output. Its result is
// corroborating evidence only. This importer closes the previous gap where the
// scanner ran successfully but its findings were never represented in the UI.
func importOSVScannerEvidence(r *ScanReport, data []byte) error {
	var raw struct {
		Results []struct {
			Source   map[string]interface{} `json:"source"`
			Packages []struct {
				Package struct {
					Name      string `json:"name"`
					Version   string `json:"version"`
					Ecosystem string `json:"ecosystem"`
				} `json:"package"`
				Vulnerabilities []osvVuln `json:"vulnerabilities"`
			} `json:"packages"`
		} `json:"results"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	for _, result := range raw.Results {
		sourcePath, _ := result.Source["path"].(string)
		for _, p := range result.Packages {
			eco := p.Package.Ecosystem
			if strings.EqualFold(eco, "npm") {
				eco = "npm"
			}
			if strings.EqualFold(eco, "Maven") {
				eco = "Maven"
			}
			if p.Package.Name == "" || p.Package.Version == "" || len(p.Vulnerabilities) == 0 {
				continue
			}
			item := RiskItem{Package: p.Package.Name, CurrentVersion: cleanVersion(p.Package.Version), Ecosystem: eco, Severity: "UNKNOWN", Sources: []string{"OSV-Scanner"}, Manifest: sourcePath, ControlHint: "auxiliary-only", Why: "OSV-Scanner encontrou evidência adicional; remediação exige correlação com o grafo canônico.", DetectionStatus: "scanner-only", AutoRemediationEligible: false}
			for _, v := range p.Vulnerabilities {
				a := advisoryFromOSV(v, p.Package.Name, p.Package.Version)
				mergeAdvisory(&item, a)
				if severityRank(a.Severity) > severityRank(item.Severity) {
					item.Severity = a.Severity
				}
				if a.CVSS > item.CVSS {
					item.CVSS = a.CVSS
				}
			}
			if canonical := findRiskVersion(r, item.Package, item.CurrentVersion); canonical != nil && canonical.Ecosystem == item.Ecosystem {
				canonical.Sources = uniqueStrings(append(canonical.Sources, "OSV-Scanner"))
				if canonical.DetectionStatus == "" {
					canonical.DetectionStatus = "confirmed"
				}
				for _, a := range item.Advisories {
					mergeAdvisory(canonical, a)
				}
				continue
			}
			if artifact := findArtifactRiskVersion(r, item.Package, item.CurrentVersion, item.Ecosystem); artifact != nil {
				artifact.Sources = uniqueStrings(append(artifact.Sources, "OSV-Scanner"))
				for _, a := range item.Advisories {
					mergeAdvisory(artifact, a)
				}
				continue
			}
			mergeAuxiliaryRisk(r, item)
		}
	}
	sortAuxiliary(r)
	return nil
}

func sortAuxiliary(r *ScanReport) {
	sort.Slice(r.AuxiliaryFindings, func(i, j int) bool {
		a, b := r.AuxiliaryFindings[i], r.AuxiliaryFindings[j]
		if severityWeight(a.Severity) != severityWeight(b.Severity) {
			return severityWeight(a.Severity) > severityWeight(b.Severity)
		}
		return a.Package+"|"+a.CurrentVersion < b.Package+"|"+b.CurrentVersion
	})
}

func reconcileEvidenceSummary(r *ScanReport) {
	if r == nil {
		return
	}
	if r.Reconciliation == nil {
		r.Reconciliation = map[string]int{}
	}
	confirmed := 0
	for i := range r.Findings {
		if len(r.Findings[i].Sources) > 1 || len(r.Findings[i].ArtifactPaths) > 0 {
			confirmed++
		}
	}
	r.Reconciliation["canonicalVulnerable"] = len(r.Findings)
	r.Reconciliation["confirmedByMultipleSources"] = confirmed
	r.Reconciliation["artifactOnlyVulnerable"] = len(r.ArtifactFindings)
	r.Reconciliation["scannerOnlyVulnerable"] = len(r.AuxiliaryFindings)
	r.Metadata["reconciliationModel"] = "canonical graph findings + read-only artifact findings + unmatched scanner evidence; only canonical findings are automatically remediable"
}

func severityWeight(s string) int {
	return map[string]int{"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}[strings.ToUpper(s)]
}

func remediationRescanAllowsApply(r *ScanReport, packageName, targetVersion string) bool {
	return r != nil && r.CoverageStatus == "complete" && !auxiliaryHasTargetEvidence(r, packageName, targetVersion)
}

func auxiliaryHasTargetEvidence(r *ScanReport, packageName, targetVersion string) bool {
	if r == nil {
		return false
	}
	targetVersion = cleanVersion(targetVersion)
	groups := [][]RiskItem{r.AuxiliaryFindings, r.ArtifactFindings}
	for _, group := range groups {
		for _, a := range group {
			if a.Package != packageName {
				continue
			}
			if targetVersion != "" && cleanVersion(a.CurrentVersion) != targetVersion {
				continue
			}
			if len(a.Advisories) > 0 {
				return true
			}
		}
	}
	return false
}

func auxiliarySourcesDegraded(r *ScanReport) bool {
	if r == nil {
		return false
	}
	for name, status := range r.Sources {
		if name != "Trivy" && name != "OSV-Scanner" {
			continue
		}
		if strings.Contains(strings.ToLower(status), "degraded") {
			return true
		}
	}
	return false
}
func auxiliaryHasUnresolvedEvidence(r *ScanReport) bool {
	for _, a := range r.AuxiliaryFindings {
		for _, adv := range a.Advisories {
			found := false
			for _, f := range r.Findings {
				if f.Package != a.Package || f.CurrentVersion != a.CurrentVersion || f.Ecosystem != a.Ecosystem {
					continue
				}
				for _, known := range f.Advisories {
					if known.ID == adv.ID {
						found = true
					}
					for _, alias := range known.Aliases {
						if alias == adv.ID {
							found = true
						}
					}
				}
			}
			for _, f := range r.ArtifactFindings {
				if f.Package != a.Package || f.CurrentVersion != a.CurrentVersion || f.Ecosystem != a.Ecosystem {
					continue
				}
				for _, known := range f.Advisories {
					if known.ID == adv.ID {
						found = true
					}
					for _, alias := range known.Aliases {
						if alias == adv.ID {
							found = true
						}
					}
				}
			}
			if !found {
				return true
			}
		}
	}
	return false
}
