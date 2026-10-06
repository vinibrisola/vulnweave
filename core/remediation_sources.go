package main

import (
	"fmt"
	"net/http"
	"strings"
	"time"
)

// trustedVendorRemediation is deliberately curated. We never execute arbitrary URLs
// discovered in advisory text. Vendor routes are added only after validating the
// authoritative distribution channel and remediation guidance.
type trustedVendorRemediation struct {
	Ecosystem   string
	Package     string
	Version     string
	InstallSpec string
	Source      string
	EvidenceURL string
	Why         string
}

var trustedVendorRemediations = []trustedVendorRemediation{
	{
		Ecosystem:   "npm",
		Package:     "xlsx",
		Version:     "0.20.3",
		InstallSpec: "https://cdn.sheetjs.com/xlsx-0.20.3/xlsx-0.20.3.tgz",
		Source:      "SheetJS Community Edition — authoritative CDN",
		EvidenceURL: "https://docs.sheetjs.com/docs/getting-started/installation/nodejs/",
		Why:         "O pacote xlsx do npm ficou no endpoint legado 0.18.5. O fornecedor publica as versões corrigidas no CDN oficial; 0.20.3 está acima dos marcos de correção 0.19.3 (Prototype Pollution) e 0.20.2 (ReDoS).",
	},
}

func trustedVendorOption(ecosystem, pkg, current string, advisories []Advisory) *RemediationOption {
	for _, r := range trustedVendorRemediations {
		if r.Ecosystem != ecosystem || r.Package != pkg {
			continue
		}
		if current != "" && cmpVersion(r.Version, current) <= 0 {
			continue
		}
		// Only offer the curated route when the component is actually vulnerable.
		if len(advisories) == 0 {
			continue
		}
		return &RemediationOption{
			Version:     r.Version,
			InstallSpec: r.InstallSpec,
			Kind:        "vendor-tarball",
			Source:      r.Source,
			EvidenceURL: r.EvidenceURL,
			Trusted:     true,
			AutoPlan:    true,
			Why:         r.Why,
		}
	}
	return nil
}

func trustedVendorForTarget(ecosystem, pkg, version string) *RemediationOption {
	for _, r := range trustedVendorRemediations {
		if r.Ecosystem == ecosystem && r.Package == pkg && cleanVersion(version) == cleanVersion(r.Version) {
			return &RemediationOption{
				Version:     r.Version,
				InstallSpec: r.InstallSpec,
				Kind:        "vendor-tarball",
				Source:      r.Source,
				EvidenceURL: r.EvidenceURL,
				Trusted:     true,
				AutoPlan:    true,
				Why:         r.Why,
			}
		}
	}
	return nil
}

func checkTrustedVendorArtifact(opt RemediationOption) (bool, error) {
	if !opt.Trusted || opt.Kind != "vendor-tarball" || opt.InstallSpec == "" {
		return false, fmt.Errorf("rota de fornecedor não é confiável ou está incompleta")
	}
	if !strings.HasPrefix(opt.InstallSpec, "https://cdn.sheetjs.com/") {
		return false, fmt.Errorf("host de fornecedor não autorizado")
	}
	client := &http.Client{
		Timeout: 15 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 3 {
				return fmt.Errorf("muitos redirecionamentos")
			}
			if req.URL.Scheme != "https" || req.URL.Hostname() != "cdn.sheetjs.com" {
				return fmt.Errorf("redirecionamento para host não autorizado: %s", req.URL.Hostname())
			}
			return nil
		},
	}
	req, err := http.NewRequest(http.MethodHead, opt.InstallSpec, nil)
	if err != nil {
		return false, err
	}
	req.Header.Set("User-Agent", "VulnWeave/"+engineVersion)
	resp, err := client.Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()
	return resp.StatusCode >= 200 && resp.StatusCode < 400, nil
}
