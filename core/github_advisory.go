package main

import (
	"fmt"
	"strings"
)

type githubGlobalAdvisory struct {
	GHSAID         string `json:"ghsa_id"`
	CVEID          string `json:"cve_id"`
	Summary        string `json:"summary"`
	Severity       string `json:"severity"`
	CVSSSeverities struct {
		V3 struct {
			Score float64 `json:"score"`
		} `json:"cvss_v3"`
		V4 struct {
			Score float64 `json:"score"`
		} `json:"cvss_v4"`
	} `json:"cvss_severities"`
	Vulnerabilities []struct {
		Package struct {
			Ecosystem string `json:"ecosystem"`
			Name      string `json:"name"`
		} `json:"package"`
		FirstPatchedVersion *struct {
			Identifier string `json:"identifier"`
		} `json:"first_patched_version"`
	} `json:"vulnerabilities"`
}

func githubEcosystem(ecosystem string) string {
	switch strings.ToLower(ecosystem) {
	case "npm":
		return "npm"
	case "maven":
		return "maven"
	default:
		return strings.ToLower(ecosystem)
	}
}

// enrichFromGitHubAdvisory is a best-effort fallback for fields missing in OSV.
// It queries only by GHSA ID, so package names are not sent in the request URL.
func enrichFromGitHubAdvisory(pkg, ecosystem string, in []Advisory) ([]Advisory, bool, []string) {
	out := append([]Advisory(nil), in...)
	used := false
	warnings := []string{}
	calls := 0
	for i := range out {
		if calls >= 8 {
			warnings = append(warnings, "GitHub Advisory fallback limitado a 8 advisories por componente para evitar excesso de chamadas")
			break
		}
		a := &out[i]
		ghsa := ""
		if strings.HasPrefix(a.ID, "GHSA-") {
			ghsa = a.ID
		}
		if ghsa == "" {
			for _, alias := range a.Aliases {
				if strings.HasPrefix(alias, "GHSA-") {
					ghsa = alias
					break
				}
			}
		}
		if ghsa == "" || (a.FixedVersion != "" && a.Summary != "" && a.CVSS > 0) {
			continue
		}
		calls++
		var ga githubGlobalAdvisory
		u := "https://api.github.com/advisories/" + ghsa
		err := getJSON(u, map[string]string{
			"Accept":               "application/vnd.github+json",
			"X-GitHub-Api-Version": "2026-03-10",
			"User-Agent":           "VulnWeave/" + engineVersion,
		}, &ga)
		if err != nil {
			warnings = append(warnings, fmt.Sprintf("GitHub Advisory fallback indisponível para %s: %v", ghsa, err))
			continue
		}
		used = true
		if a.Summary == "" && ga.Summary != "" {
			a.Summary = ga.Summary
		}
		if ga.CVEID != "" {
			a.Aliases = uniqueStrings(append(a.Aliases, ga.CVEID))
		}
		score := ga.CVSSSeverities.V4.Score
		if ga.CVSSSeverities.V3.Score > score {
			score = ga.CVSSSeverities.V3.Score
		}
		if a.CVSS == 0 && score > 0 {
			a.CVSS = score
		}
		if a.Severity == "" || a.Severity == "UNKNOWN" {
			sev := strings.ToUpper(ga.Severity)
			if sev == "MODERATE" {
				sev = "MEDIUM"
			}
			if sev != "" {
				a.Severity = sev
			}
		}
		if a.FixedVersion == "" {
			for _, v := range ga.Vulnerabilities {
				if strings.EqualFold(v.Package.Ecosystem, githubEcosystem(ecosystem)) && v.Package.Name == pkg && v.FirstPatchedVersion != nil {
					candidate := cleanVersion(v.FirstPatchedVersion.Identifier)
					if candidate != "" {
						a.FixedVersion = candidate
						break
					}
				}
			}
		}
	}
	return out, used, warnings
}
