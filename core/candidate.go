package main

import (
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

var (
	mavenCentralBaseURL = "https://repo.maven.apache.org/maven2"
	npmRegistryBaseURL  = "https://registry.npmjs.org"
)

type repositoryCheck struct {
	Exists            bool      `json:"exists"`
	Status            string    `json:"status"` // confirmed | not_found | inconclusive
	HTTPStatus        int       `json:"httpStatus,omitempty"`
	RetryAfterSeconds int       `json:"retryAfterSeconds,omitempty"`
	Error             string    `json:"error,omitempty"`
	CheckedAt         time.Time `json:"checkedAt"`
	FromCache         bool      `json:"fromCache,omitempty"`
}

type repositoryCacheRecord struct {
	Check     repositoryCheck `json:"check"`
	ExpiresAt time.Time       `json:"expiresAt"`
}

func validateCandidate(root, pkg, current, target, ecosystem string) (*CandidateValidation, error) {
	if ecosystem == "" {
		p, err := detectProject(root)
		if err != nil {
			return nil, err
		}
		ecosystem = p.Ecosystem
	}
	v := &CandidateValidation{
		Package:          pkg,
		CurrentVersion:   cleanVersion(current),
		CandidateVersion: cleanVersion(target),
		Ecosystem:        ecosystem,
		CheckedAt:        time.Now().UTC(),
		FullScanExecuted: false,
		OSVStatus:        "pending",
		RepositoryStatus: "pending",
		ValidationStatus: "pending",
	}
	if v.CandidateVersion == "" {
		return nil, fmt.Errorf("versão candidata vazia")
	}

	v.Compatibility, v.CompatibilityWhy = compatibilityDelta(v.CurrentVersion, v.CandidateVersion)
	isUpgrade := v.CurrentVersion == "" || cmpVersion(v.CandidateVersion, v.CurrentVersion) > 0

	if isPrivatePackage(ecosystem, pkg) {
		v.Warnings = append(v.Warnings, "pacote classificado como privado: validação em OSV/npm/Maven Central foi bloqueada para evitar envio de nome/versão a serviços públicos")
		v.CandidateKind = "private"
		v.CandidateSource = "private registry (not queried)"
		v.RepositoryStatus = "skipped_private"
		v.OSVStatus = "skipped_private"
		v.ValidationStatus = "private"
		return v, nil
	}

	vendor := trustedVendorForTarget(ecosystem, pkg, v.CandidateVersion)
	if vendor != nil {
		exists, err := checkTrustedVendorArtifact(*vendor)
		if err != nil {
			v.RepositoryStatus = "inconclusive"
			v.RepositoryError = err.Error()
			v.Warnings = append(v.Warnings, "não foi possível confirmar o artefato no fornecedor oficial: "+err.Error())
		} else if exists {
			v.Exists = true
			v.RepositoryStatus = "confirmed"
		} else {
			v.RepositoryStatus = "not_found"
		}
		v.InstallSpec = vendor.InstallSpec
		v.CandidateKind = vendor.Kind
		v.CandidateSource = vendor.Source
		v.EvidenceURL = vendor.EvidenceURL
	} else {
		check, err := candidateExists(ecosystem, pkg, v.CandidateVersion)
		if err != nil {
			return nil, err
		}
		v.Exists = check.Exists
		v.RepositoryStatus = check.Status
		v.RepositoryHTTPStatus = check.HTTPStatus
		v.RepositoryError = check.Error
		v.RepositoryFromCache = check.FromCache
		v.RetryAfterSeconds = check.RetryAfterSeconds
		v.CandidateKind = "registry"
		if ecosystem == "npm" {
			v.CandidateSource = "npm registry"
		} else {
			v.CandidateSource = "Maven Central"
		}
		if check.Status == "inconclusive" {
			msg := "não foi possível confirmar temporariamente a versão no registry/repository"
			if check.HTTPStatus == http.StatusTooManyRequests {
				msg = "o repositório limitou temporariamente a consulta (HTTP 429); isso não significa que a versão seja inválida"
			}
			if check.Error != "" {
				msg += ": " + check.Error
			}
			v.Warnings = append(v.Warnings, msg)
		}
	}

	// A definitive 404/not-found is enough to reject the candidate and avoids an
	// unnecessary OSV call for a version that cannot be installed.
	if v.RepositoryStatus == "not_found" {
		v.OSVStatus = "skipped"
		v.ValidationStatus = "rejected"
		v.Warnings = append(v.Warnings, "a versão candidata não foi encontrada na fonte de artefatos configurada")
		if !isUpgrade {
			v.Warnings = append(v.Warnings, "a versão candidata não é um upgrade em relação à versão atual; downgrades e versões iguais são bloqueados para remediação automática")
		}
		return v, nil
	}

	deps := []Dependency{{Name: pkg, Version: v.CandidateVersion, Ecosystem: ecosystem, Direct: true, Scope: "runtime"}}
	osv, err := queryOSV(deps)
	if err != nil {
		v.OSVStatus = "inconclusive"
		v.OSVError = err.Error()
		v.ValidationStatus = "inconclusive"
		v.Warnings = append(v.Warnings, "não foi possível concluir a consulta OSV: "+err.Error())
		if !isUpgrade {
			v.Warnings = append(v.Warnings, "a versão candidata não é um upgrade em relação à versão atual; downgrades e versões iguais são bloqueados para remediação automática")
		}
		return v, nil
	}
	v.OSVStatus = "confirmed"
	key := ecosystem + "|" + pkg + "|" + v.CandidateVersion
	for _, ov := range osv[key] {
		v.Advisories = append(v.Advisories, advisoryFromOSV(ov, pkg, v.CandidateVersion))
	}
	v.Vulnerable = len(v.Advisories) > 0

	if !isUpgrade {
		v.Warnings = append(v.Warnings, "a versão candidata não é um upgrade em relação à versão atual; downgrades e versões iguais são bloqueados para remediação automática")
	}
	if v.Vulnerable {
		v.Warnings = append(v.Warnings, "a candidata ainda possui advisories conhecidos no OSV")
	}

	// Transport/provider uncertainty must never be collapsed into "not found".
	// Automatic remediation is fail-closed, while the UI can accurately explain
	// that the evidence is inconclusive instead of declaring the version invalid.
	if v.RepositoryStatus == "inconclusive" {
		v.ValidationStatus = "inconclusive"
		v.Recommended = false
		return v, nil
	}

	v.Recommended = v.Exists && !v.Vulnerable && isUpgrade
	if v.Recommended {
		v.ValidationStatus = "confirmed"
	} else {
		v.ValidationStatus = "rejected"
	}
	return v, nil
}

func candidateExists(ecosystem, pkg, version string) (repositoryCheck, error) {
	if ecosystem != "npm" && ecosystem != "Maven" {
		return repositoryCheck{}, fmt.Errorf("ecossistema não suportado: %s", ecosystem)
	}
	if ecosystem == "Maven" {
		parts := strings.SplitN(pkg, ":", 2)
		if len(parts) != 2 || strings.TrimSpace(parts[0]) == "" || strings.TrimSpace(parts[1]) == "" {
			return repositoryCheck{}, fmt.Errorf("coordenada Maven inválida: %s", pkg)
		}
	}

	if cached, ok := loadRepositoryCheckCache(ecosystem, pkg, version); ok {
		return cached, nil
	}

	var u string
	if ecosystem == "npm" {
		packagePath := strings.ReplaceAll(url.PathEscape(pkg), "%2F", "%2f")
		u = strings.TrimRight(npmRegistryBaseURL, "/") + "/" + packagePath + "/" + url.PathEscape(version)
	} else {
		parts := strings.SplitN(pkg, ":", 2)
		groupPath := strings.ReplaceAll(parts[0], ".", "/")
		artifact := url.PathEscape(parts[1])
		ver := url.PathEscape(version)
		// Checking the exact POM is much cheaper than repeatedly downloading the
		// complete maven-metadata.xml version list, and maps directly to Maven's
		// repository layout for the requested GAV coordinate.
		u = strings.TrimRight(mavenCentralBaseURL, "/") + "/" + groupPath + "/" + artifact + "/" + ver + "/" + artifact + "-" + ver + ".pom"
	}

	check := fetchRepositoryExistence(u)
	storeRepositoryCheckCache(ecosystem, pkg, version, check)
	return check, nil
}

func fetchRepositoryExistence(u string) repositoryCheck {
	const maxAttempts = 2
	var last repositoryCheck
	for attempt := 0; attempt < maxAttempts; attempt++ {
		req, err := http.NewRequest(http.MethodGet, u, nil)
		if err != nil {
			return repositoryCheck{Status: "inconclusive", Error: err.Error(), CheckedAt: time.Now().UTC()}
		}
		req.Header.Set("User-Agent", "VulnWeave/"+engineVersion)
		req.Header.Set("Accept", "application/xml, application/json;q=0.9, */*;q=0.1")
		resp, err := httpClient.Do(req)
		if err != nil {
			last = repositoryCheck{Status: "inconclusive", Error: err.Error(), CheckedAt: time.Now().UTC()}
			if attempt == 0 {
				time.Sleep(650 * time.Millisecond)
				continue
			}
			return last
		}
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 32<<10))
		resp.Body.Close()

		last = repositoryCheck{HTTPStatus: resp.StatusCode, CheckedAt: time.Now().UTC()}
		switch resp.StatusCode {
		case http.StatusOK:
			last.Exists = true
			last.Status = "confirmed"
			return last
		case http.StatusNotFound:
			last.Status = "not_found"
			return last
		case http.StatusTooManyRequests:
			last.Status = "inconclusive"
			last.Error = "HTTP 429 Too Many Requests"
			last.RetryAfterSeconds = parseRetryAfter(resp.Header.Get("Retry-After"))
			// Sonatype explicitly recommends reducing traffic rather than retrying
			// aggressively. Only one bounded retry is allowed, and only when the
			// server supplied a very short Retry-After window.
			if attempt == 0 && last.RetryAfterSeconds > 0 && last.RetryAfterSeconds <= 3 {
				time.Sleep(time.Duration(last.RetryAfterSeconds) * time.Second)
				continue
			}
			return last
		case http.StatusBadGateway, http.StatusServiceUnavailable, http.StatusGatewayTimeout:
			last.Status = "inconclusive"
			last.Error = fmt.Sprintf("HTTP %d", resp.StatusCode)
			if attempt == 0 {
				time.Sleep(750 * time.Millisecond)
				continue
			}
			return last
		default:
			last.Status = "inconclusive"
			last.Error = fmt.Sprintf("HTTP %d", resp.StatusCode)
			return last
		}
	}
	if last.Status == "" {
		last.Status = "inconclusive"
		last.CheckedAt = time.Now().UTC()
	}
	return last
}

func parseRetryAfter(raw string) int {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return 0
	}
	if n, err := strconv.Atoi(raw); err == nil && n > 0 {
		return n
	}
	if t, err := http.ParseTime(raw); err == nil {
		seconds := int(time.Until(t).Seconds())
		if seconds > 0 {
			return seconds
		}
	}
	return 0
}

func repositoryCacheBaseDir() string {
	if configured := strings.TrimSpace(os.Getenv("VULNWEAVE_CACHE_DIR")); configured != "" {
		return filepath.Join(configured, "candidate-existence")
	}
	if userCache, err := os.UserCacheDir(); err == nil && userCache != "" {
		return filepath.Join(userCache, "VulnWeave", "candidate-existence")
	}
	return ""
}

func repositoryCachePath(ecosystem, pkg, version string) string {
	base := repositoryCacheBaseDir()
	if base == "" {
		return ""
	}
	key := bytesHash([]byte(ecosystem + "|" + pkg + "|" + version))
	return filepath.Join(base, key+".json")
}

func loadRepositoryCheckCache(ecosystem, pkg, version string) (repositoryCheck, bool) {
	p := repositoryCachePath(ecosystem, pkg, version)
	if p == "" {
		return repositoryCheck{}, false
	}
	var rec repositoryCacheRecord
	if err := readJSON(p, &rec); err != nil || rec.ExpiresAt.IsZero() || time.Now().UTC().After(rec.ExpiresAt) {
		return repositoryCheck{}, false
	}
	check := rec.Check
	check.FromCache = true
	if check.Status == "inconclusive" {
		remaining := int(time.Until(rec.ExpiresAt).Seconds())
		if remaining > check.RetryAfterSeconds {
			check.RetryAfterSeconds = remaining
		}
	}
	return check, true
}

func storeRepositoryCheckCache(ecosystem, pkg, version string, check repositoryCheck) {
	p := repositoryCachePath(ecosystem, pkg, version)
	if p == "" || check.Status == "" {
		return
	}
	ttl := 10 * time.Minute
	switch check.Status {
	case "confirmed":
		ttl = 24 * time.Hour
	case "not_found":
		ttl = 10 * time.Minute
	case "inconclusive":
		ttl = 2 * time.Minute
		if check.RetryAfterSeconds > 0 {
			retryTTL := time.Duration(check.RetryAfterSeconds) * time.Second
			if retryTTL > ttl {
				ttl = retryTTL
			}
		}
	}
	// Do not persist a transient transport failure for more than a day even if a
	// malformed intermediary returns an extreme Retry-After value.
	if ttl > 24*time.Hour {
		ttl = 24 * time.Hour
	}
	rec := repositoryCacheRecord{Check: check, ExpiresAt: time.Now().UTC().Add(ttl)}
	_ = writeJSON(p, &rec)
}
