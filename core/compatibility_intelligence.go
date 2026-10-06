package main

import (
	"archive/zip"
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// Compatibility Intelligence is deliberately advisory. It explains how much
// evidence supports an upgrade without changing the existing remediation gates.
// ReadyToApply continues to be decided exclusively by the guarded remediation
// pipeline in remediation.go.
type classAPI struct {
	Name    string
	Members map[string]bool
}

type cpEntry struct {
	utf8      string
	nameIndex uint16
}

func versionChangeType(current, target string) string {
	a, b := parseSemverish(current), parseSemverish(target)
	if !a.ok || !b.ok {
		return "unknown"
	}
	if a.major != b.major {
		return "major"
	}
	if a.minor != b.minor {
		if a.major == 0 {
			return "pre-1.0-minor"
		}
		return "minor"
	}
	if a.patch != b.patch {
		return "patch"
	}
	return "same"
}

func changeRiskLabel(change string) (status, summary string) {
	switch change {
	case "patch":
		return "pass", "Versão de correção (patch): menor alcance semântico, ainda sujeita às verificações de compilação e testes."
	case "minor":
		return "warn", "Versão menor: pode adicionar ou alterar comportamento; valide API, grafo, compilação e testes."
	case "pre-1.0-minor":
		return "warn", "Pacote pré-1.0: uma mudança menor pode conter alterações incompatíveis equivalentes a uma mudança maior."
	case "major":
		return "warn", "Versão maior: alterações incompatíveis são plausíveis mesmo quando o grafo resolve."
	default:
		return "info", "A mudança de versão não pôde ser classificada semanticamente."
	}
}

func testExecutionSummary(r CommandResult) TestExecutionSummary {
	out := TestExecutionSummary{Known: false}
	if r.Skipped {
		out.Framework = "not-run"
		return out
	}
	text := strings.ReplaceAll(r.Output, "\r\n", "\n")
	// Maven Surefire/Failsafe. Keep the LAST aggregate summary because command
	// output may contain one line per test class followed by the aggregate line.
	re := regexp.MustCompile(`(?m)Tests run:\s*(\d+)\s*,\s*Failures:\s*(\d+)\s*,\s*Errors:\s*(\d+)\s*,\s*Skipped:\s*(\d+)`)
	matches := re.FindAllStringSubmatch(text, -1)
	if len(matches) > 0 {
		m := matches[len(matches)-1]
		total, _ := strconv.Atoi(m[1])
		failures, _ := strconv.Atoi(m[2])
		errorsN, _ := strconv.Atoi(m[3])
		skipped, _ := strconv.Atoi(m[4])
		passed := total - failures - errorsN - skipped
		if passed < 0 {
			passed = 0
		}
		return TestExecutionSummary{Known: true, Framework: "Maven Surefire/Failsafe", Total: total, Passed: passed, Failed: failures, Errors: errorsN, Skipped: skipped}
	}

	// Common Jest summary form: "Tests: 2 failed, 18 passed, 20 total".
	jest := regexp.MustCompile(`(?mi)^Tests:\s*(?:(\d+)\s+failed,\s*)?(?:(\d+)\s+passed,\s*)?(\d+)\s+total`)
	jm := jest.FindAllStringSubmatch(text, -1)
	if len(jm) > 0 {
		m := jm[len(jm)-1]
		failed, _ := strconv.Atoi(zeroIfEmpty(m[1]))
		passed, _ := strconv.Atoi(zeroIfEmpty(m[2]))
		total, _ := strconv.Atoi(zeroIfEmpty(m[3]))
		return TestExecutionSummary{Known: true, Framework: "Jest", Total: total, Passed: passed, Failed: failed}
	}

	// Vitest/Jasmine-like compact line: "Tests  24 passed (24)".
	vitest := regexp.MustCompile(`(?mi)^\s*Tests\s+(\d+)\s+passed\s*\((\d+)\)`)
	vm := vitest.FindAllStringSubmatch(text, -1)
	if len(vm) > 0 {
		m := vm[len(vm)-1]
		passed, _ := strconv.Atoi(m[1])
		total, _ := strconv.Atoi(m[2])
		return TestExecutionSummary{Known: true, Framework: "Vitest/Jasmine", Total: total, Passed: passed}
	}
	return out
}

func zeroIfEmpty(v string) string {
	if strings.TrimSpace(v) == "" {
		return "0"
	}
	return v
}

func artifactVersionEvidence(scan *ScanReport, pkg, current, target string) ArtifactCompatibilityEvidence {
	e := ArtifactCompatibilityEvidence{}
	if scan == nil {
		e.Detail = "Rescan indisponível; o artefato final não pôde ser inspecionado."
		return e
	}
	if len(scan.ArtifactDependencies) == 0 {
		e.Detail = "Nenhum JAR/WAR/EAR de build foi inventariado; a compatibilidade continua sustentada pelos demais gates."
		return e
	}
	e.Checked = true
	for _, d := range scan.ArtifactDependencies {
		if d.Name != pkg {
			continue
		}
		v := cleanVersion(d.Version)
		if v == cleanVersion(target) {
			e.TargetPresent = true
			e.TargetPaths = uniqueStrings(append(e.TargetPaths, d.ArtifactPaths...))
		}
		if v == cleanVersion(current) {
			e.OldPresent = true
			e.OldPaths = uniqueStrings(append(e.OldPaths, d.ArtifactPaths...))
		}
	}
	switch {
	case e.TargetPresent && !e.OldPresent:
		e.Detail = "O artefato construído contém a versão alvo e não contém a versão vulnerável anterior."
	case e.TargetPresent && e.OldPresent:
		e.Detail = "O artefato contém a versão alvo, mas a versão anterior também continua empacotada."
	case !e.TargetPresent && e.OldPresent:
		e.Detail = "A versão anterior ainda está empacotada e a versão alvo não foi confirmada no artefato."
	default:
		e.Detail = "O inventário do artefato não correlacionou esta coordenada; pode haver shading, metadata ausente ou artefato não representado por pom.properties."
	}
	return e
}

func graphDuplicateVersions(scan *ScanReport) []string {
	if scan == nil {
		return nil
	}
	versions := map[string]map[string]bool{}
	for _, d := range scan.Dependencies {
		if d.Name == "" || d.Version == "" {
			continue
		}
		m := versions[d.Ecosystem+"|"+d.Name]
		if m == nil {
			m = map[string]bool{}
			versions[d.Ecosystem+"|"+d.Name] = m
		}
		m[cleanVersion(d.Version)] = true
	}
	var out []string
	for key, vs := range versions {
		if len(vs) <= 1 {
			continue
		}
		names := make([]string, 0, len(vs))
		for v := range vs {
			names = append(names, v)
		}
		sort.Strings(names)
		pkg := strings.SplitN(key, "|", 2)
		display := key
		if len(pkg) == 2 {
			display = pkg[1]
		}
		out = append(out, display+" ["+strings.Join(names, ", ")+"]")
	}
	sort.Strings(out)
	if len(out) > 12 {
		out = append(out[:12], fmt.Sprintf("+%d conflito(s) adicional(is)", len(out)-12))
	}
	return out
}

func locateMavenArtifactJar(pkg, version string) string {
	parts := strings.SplitN(pkg, ":", 2)
	if len(parts) != 2 || strings.TrimSpace(parts[0]) == "" || strings.TrimSpace(parts[1]) == "" || cleanVersion(version) == "" {
		return ""
	}
	group, artifact, version := strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1]), cleanVersion(version)
	roots := []string{}
	if x := strings.TrimSpace(os.Getenv("VULNWEAVE_M2_REPO")); x != "" {
		roots = append(roots, x)
	}
	if x := strings.TrimSpace(os.Getenv("M2_REPO")); x != "" {
		roots = append(roots, x)
	}
	if x := strings.TrimSpace(os.Getenv("MAVEN_USER_HOME")); x != "" {
		roots = append(roots, filepath.Join(x, "repository"))
	}
	if home, err := os.UserHomeDir(); err == nil && home != "" {
		roots = append(roots, filepath.Join(home, ".m2", "repository"))
		settings := filepath.Join(home, ".m2", "settings.xml")
		if raw, err := os.ReadFile(settings); err == nil {
			re := regexp.MustCompile(`(?s)<localRepository>\s*([^<]+?)\s*</localRepository>`)
			if m := re.FindStringSubmatch(string(raw)); len(m) == 2 {
				candidate := strings.TrimSpace(os.ExpandEnv(m[1]))
				if candidate != "" {
					roots = append([]string{candidate}, roots...)
				}
			}
		}
	}
	rel := filepath.Join(filepath.FromSlash(strings.ReplaceAll(group, ".", "/")), artifact, version, artifact+"-"+version+".jar")
	for _, root := range uniqueStrings(roots) {
		p := filepath.Join(root, rel)
		if st, err := os.Stat(p); err == nil && !st.IsDir() {
			return p
		}
	}
	return ""
}

func compareMavenBinaryAPI(pkg, current, target string) BinaryAPICompatibility {
	out := BinaryAPICompatibility{}
	oldJar := locateMavenArtifactJar(pkg, current)
	newJar := locateMavenArtifactJar(pkg, target)
	out.CurrentJar = oldJar
	out.TargetJar = newJar
	if oldJar == "" || newJar == "" {
		out.Detail = "Comparação binária indisponível: os JARs atual e candidato não estão ambos disponíveis no repositório Maven local."
		return out
	}
	oldAPI, err := publicJarAPI(oldJar)
	if err != nil {
		out.Detail = "Não foi possível ler a API pública do JAR atual: " + truncate(err.Error(), 240)
		return out
	}
	newAPI, err := publicJarAPI(newJar)
	if err != nil {
		out.Detail = "Não foi possível ler a API pública do JAR candidato: " + truncate(err.Error(), 240)
		return out
	}
	out.Available = true
	out.CurrentPublicTypes = len(oldAPI)
	out.TargetPublicTypes = len(newAPI)
	var removedTypes, removedMembers, addedTypes, addedMembers []string
	for name, oldClass := range oldAPI {
		newClass, ok := newAPI[name]
		if !ok {
			removedTypes = append(removedTypes, name)
			continue
		}
		for member := range oldClass.Members {
			if !newClass.Members[member] {
				removedMembers = append(removedMembers, name+" :: "+member)
			}
		}
		for member := range newClass.Members {
			if !oldClass.Members[member] {
				addedMembers = append(addedMembers, name+" :: "+member)
			}
		}
	}
	for name := range newAPI {
		if _, ok := oldAPI[name]; !ok {
			addedTypes = append(addedTypes, name)
		}
	}
	sort.Strings(removedTypes)
	sort.Strings(removedMembers)
	sort.Strings(addedTypes)
	sort.Strings(addedMembers)
	out.RemovedTypes = len(removedTypes)
	out.RemovedMembers = len(removedMembers)
	out.AddedTypes = len(addedTypes)
	out.AddedMembers = len(addedMembers)
	out.SampleRemoved = sampleStrings(append(removedTypes, removedMembers...), 8)
	if out.RemovedTypes == 0 && out.RemovedMembers == 0 {
		out.Detail = fmt.Sprintf("Nenhuma remoção foi detectada na superfície public/protected (%d tipos atuais → %d tipos candidatos).", out.CurrentPublicTypes, out.TargetPublicTypes)
	} else {
		out.Detail = fmt.Sprintf("A candidata remove/alterou %d tipo(s) e %d membro(s) public/protected; o build comprova apenas os usos compilados pela aplicação.", out.RemovedTypes, out.RemovedMembers)
	}
	return out
}

func sampleStrings(in []string, max int) []string {
	if len(in) <= max {
		return append([]string(nil), in...)
	}
	return append([]string(nil), in[:max]...)
}

func publicJarAPI(path string) (map[string]classAPI, error) {
	zr, err := zip.OpenReader(path)
	if err != nil {
		return nil, err
	}
	defer zr.Close()
	if len(zr.File) > 30000 {
		return nil, fmt.Errorf("arquivo possui entradas demais para comparação responsiva")
	}
	out := map[string]classAPI{}
	classCount := 0
	for _, f := range zr.File {
		name := filepath.ToSlash(f.Name)
		if !strings.HasSuffix(name, ".class") || strings.HasPrefix(name, "META-INF/versions/") || strings.HasSuffix(name, "module-info.class") || strings.HasSuffix(name, "package-info.class") {
			continue
		}
		classCount++
		if classCount > 6000 {
			return nil, fmt.Errorf("JAR possui mais de 6000 classes; comparação binária foi limitada para manter o IDE responsivo")
		}
		rc, err := f.Open()
		if err != nil {
			continue
		}
		b, err := io.ReadAll(io.LimitReader(rc, 8<<20))
		_ = rc.Close()
		if err != nil || len(b) >= 8<<20 {
			continue
		}
		c, err := parsePublicClassAPI(b)
		if err != nil || c.Name == "" {
			continue
		}
		out[c.Name] = c
	}
	return out, nil
}

func parsePublicClassAPI(data []byte) (classAPI, error) {
	r := bytes.NewReader(data)
	var magic uint32
	if err := binary.Read(r, binary.BigEndian, &magic); err != nil || magic != 0xCAFEBABE {
		return classAPI{}, fmt.Errorf("classfile inválido")
	}
	var minor, major uint16
	if binary.Read(r, binary.BigEndian, &minor) != nil || binary.Read(r, binary.BigEndian, &major) != nil {
		return classAPI{}, fmt.Errorf("classfile truncado")
	}
	_ = minor
	_ = major
	var cpCount uint16
	if binary.Read(r, binary.BigEndian, &cpCount) != nil {
		return classAPI{}, fmt.Errorf("constant pool ausente")
	}
	cp := make([]cpEntry, int(cpCount))
	for i := 1; i < int(cpCount); i++ {
		tag, err := r.ReadByte()
		if err != nil {
			return classAPI{}, err
		}
		switch tag {
		case 1:
			var n uint16
			if binary.Read(r, binary.BigEndian, &n) != nil {
				return classAPI{}, io.ErrUnexpectedEOF
			}
			b := make([]byte, int(n))
			if _, err := io.ReadFull(r, b); err != nil {
				return classAPI{}, err
			}
			cp[i].utf8 = string(b)
		case 7:
			if binary.Read(r, binary.BigEndian, &cp[i].nameIndex) != nil {
				return classAPI{}, io.ErrUnexpectedEOF
			}
		case 3, 4:
			if _, err := r.Seek(4, io.SeekCurrent); err != nil {
				return classAPI{}, err
			}
		case 5, 6:
			if _, err := r.Seek(8, io.SeekCurrent); err != nil {
				return classAPI{}, err
			}
			i++
		case 8, 16, 19, 20:
			if _, err := r.Seek(2, io.SeekCurrent); err != nil {
				return classAPI{}, err
			}
		case 9, 10, 11, 12, 17, 18:
			if _, err := r.Seek(4, io.SeekCurrent); err != nil {
				return classAPI{}, err
			}
		case 15:
			if _, err := r.Seek(3, io.SeekCurrent); err != nil {
				return classAPI{}, err
			}
		default:
			return classAPI{}, fmt.Errorf("constant pool tag não suportado: %d", tag)
		}
	}
	var access, thisClass, super uint16
	if binary.Read(r, binary.BigEndian, &access) != nil || binary.Read(r, binary.BigEndian, &thisClass) != nil || binary.Read(r, binary.BigEndian, &super) != nil {
		return classAPI{}, io.ErrUnexpectedEOF
	}
	_ = super
	const accPublic = 0x0001
	if access&accPublic == 0 {
		return classAPI{}, fmt.Errorf("classe não pública")
	}
	if int(thisClass) >= len(cp) || cp[thisClass].nameIndex == 0 || int(cp[thisClass].nameIndex) >= len(cp) {
		return classAPI{}, fmt.Errorf("nome de classe inválido")
	}
	name := strings.ReplaceAll(cp[cp[thisClass].nameIndex].utf8, "/", ".")
	var interfaces uint16
	if binary.Read(r, binary.BigEndian, &interfaces) != nil {
		return classAPI{}, io.ErrUnexpectedEOF
	}
	if _, err := r.Seek(int64(interfaces)*2, io.SeekCurrent); err != nil {
		return classAPI{}, err
	}
	members := map[string]bool{}
	if err := readAPIMembers(r, cp, "field", members); err != nil {
		return classAPI{}, err
	}
	if err := readAPIMembers(r, cp, "method", members); err != nil {
		return classAPI{}, err
	}
	return classAPI{Name: name, Members: members}, nil
}

func readAPIMembers(r *bytes.Reader, cp []cpEntry, kind string, out map[string]bool) error {
	var count uint16
	if binary.Read(r, binary.BigEndian, &count) != nil {
		return io.ErrUnexpectedEOF
	}
	const accPublic = 0x0001
	const accProtected = 0x0004
	const accSynthetic = 0x1000
	const accBridge = 0x0040
	for i := 0; i < int(count); i++ {
		var access, nameIdx, descIdx, attrCount uint16
		if binary.Read(r, binary.BigEndian, &access) != nil || binary.Read(r, binary.BigEndian, &nameIdx) != nil || binary.Read(r, binary.BigEndian, &descIdx) != nil || binary.Read(r, binary.BigEndian, &attrCount) != nil {
			return io.ErrUnexpectedEOF
		}
		include := access&(accPublic|accProtected) != 0 && access&accSynthetic == 0
		if kind == "method" && access&accBridge != 0 {
			include = false
		}
		if include && int(nameIdx) < len(cp) && int(descIdx) < len(cp) {
			n, d := cp[nameIdx].utf8, cp[descIdx].utf8
			visibility := "protected"
			if access&accPublic != 0 {
				visibility = "public"
			}
			if n != "" && d != "" {
				out[visibility+" "+kind+" "+n+d] = true
			}
		}
		for a := 0; a < int(attrCount); a++ {
			var attrName uint16
			var size uint32
			if binary.Read(r, binary.BigEndian, &attrName) != nil || binary.Read(r, binary.BigEndian, &size) != nil {
				return io.ErrUnexpectedEOF
			}
			_ = attrName
			if _, err := r.Seek(int64(size), io.SeekCurrent); err != nil {
				return err
			}
		}
	}
	return nil
}

func buildCompatibilityIntelligence(plan *FixPlan, before *RiskItem, res *FixExecution) CompatibilityReport {
	report := CompatibilityReport{
		ChangeType:  versionChangeType(plan.CurrentVersion, plan.TargetVersion),
		Confidence:  "blocked",
		GeneratedBy: "deterministic",
	}
	changeStatus, changeSummary := changeRiskLabel(report.ChangeType)
	report.Signals = append(report.Signals, CompatibilitySignal{ID: "version", Label: "Mudança de versão", Status: changeStatus, Summary: changeSummary, Detail: plan.CurrentVersion + " → " + plan.TargetVersion})

	blast := []string{}
	if before != nil {
		if before.Direct {
			blast = append(blast, "dependência direta")
		} else {
			blast = append(blast, "dependência transitiva")
		}
		if before.Runtime {
			blast = append(blast, "tempo de execução")
		} else if before.Scope != "" {
			blast = append(blast, before.Scope)
		}
		if len(before.DependencyPath) > 1 {
			blast = append(blast, fmt.Sprintf("cadeia com %d salto(s)", len(before.DependencyPath)-1))
		}
	}
	if len(plan.RelatedChanges) > 1 {
		blast = append(blast, fmt.Sprintf("%d mudanças coordenadas", len(plan.RelatedChanges)))
	}
	if len(blast) == 0 {
		blast = append(blast, "alcance da mudança não inferido")
	}
	report.BlastRadius = strings.Join(blast, " · ")

	if res.LockResolution.Success && !res.LockResolution.Skipped {
		report.Signals = append(report.Signals, CompatibilitySignal{ID: "graph", Label: "Grafo de dependências", Status: "pass", Summary: "A versão candidata resolveu e o VulnWeave confirmou o plano no grafo efetivo.", Detail: truncate(res.LockResolution.Reason, 320)})
	} else {
		report.Signals = append(report.Signals, CompatibilitySignal{ID: "graph", Label: "Grafo de dependências", Status: "fail", Summary: "O grafo candidato não produziu evidência suficiente.", Detail: firstNonBlankGo(res.LockResolution.Reason, "resolução não concluída")})
	}

	if res.Rescan != nil {
		dup := graphDuplicateVersions(res.Rescan)
		if len(dup) == 0 {
			report.Signals = append(report.Signals, CompatibilitySignal{ID: "convergence", Label: "Convergência", Status: "pass", Summary: "Nenhuma multiplicidade de versão foi observada no grafo resolvido reportado.", Detail: "Comparação baseada no grafo efetivo coletado pelo VulnWeave."})
		} else {
			report.Signals = append(report.Signals, CompatibilitySignal{ID: "convergence", Label: "Convergência", Status: "warn", Summary: "O grafo contém componentes representados por múltiplas versões.", Detail: strings.Join(dup, "; ")})
		}
	}

	if strings.EqualFold(plan.Ecosystem, "Maven") {
		apiValue := compareMavenBinaryAPI(plan.Package, plan.CurrentVersion, plan.TargetVersion)
		report.BinaryAPI = &apiValue
		api := report.BinaryAPI
		if api.Available {
			if api.RemovedTypes == 0 && api.RemovedMembers == 0 {
				report.Signals = append(report.Signals, CompatibilitySignal{ID: "binary-api", Label: "API binária Java", Status: "pass", Summary: "Nenhuma remoção public/protected foi detectada entre os JARs atual e candidato.", Detail: api.Detail})
			} else {
				report.Signals = append(report.Signals, CompatibilitySignal{ID: "binary-api", Label: "API binária Java", Status: "warn", Summary: fmt.Sprintf("%d tipo(s) e %d membro(s) public/protected foram removidos ou alterados.", api.RemovedTypes, api.RemovedMembers), Detail: api.Detail})
			}
		} else {
			report.Signals = append(report.Signals, CompatibilitySignal{ID: "binary-api", Label: "API binária Java", Status: "info", Summary: "Comparação binária não disponível nesta execução.", Detail: api.Detail})
		}
	}

	if res.Build.Success && !res.Build.Skipped {
		report.Signals = append(report.Signals, CompatibilitySignal{ID: "build", Label: "Compilação", Status: "pass", Summary: "A aplicação compilou e foi empacotada com a versão candidata.", Detail: truncate(res.Build.Command, 320)})
	} else {
		report.Signals = append(report.Signals, CompatibilitySignal{ID: "build", Label: "Compilação", Status: "fail", Summary: "A compilação não passou com a versão candidata.", Detail: firstNonBlankGo(res.Build.Reason, "compilação não concluída")})
	}

	ts := testExecutionSummary(res.Tests)
	report.Tests = &ts
	if res.Tests.Success && !res.Tests.Skipped {
		detail := "Comando de testes concluiu com sucesso."
		if ts.Known {
			detail = fmt.Sprintf("%s: %d total · %d passaram · %d falharam · %d erros · %d ignorados.", ts.Framework, ts.Total, ts.Passed, ts.Failed, ts.Errors, ts.Skipped)
		}
		report.Signals = append(report.Signals, CompatibilitySignal{ID: "tests", Label: "Testes", Status: "pass", Summary: "A suíte configurada passou no sandbox candidato.", Detail: detail})
	} else {
		report.Signals = append(report.Signals, CompatibilitySignal{ID: "tests", Label: "Testes", Status: "fail", Summary: "Os testes obrigatórios não produziram evidência positiva.", Detail: firstNonBlankGo(res.Tests.Reason, "testes não concluídos")})
	}

	artifact := artifactVersionEvidence(res.Rescan, plan.Package, plan.CurrentVersion, plan.TargetVersion)
	report.Artifact = &artifact
	if artifact.Checked {
		status := "info"
		summary := "O artefato foi inspecionado, mas a coordenada alvo não foi confirmada."
		if artifact.TargetPresent && !artifact.OldPresent {
			status = "pass"
			summary = "O artefato final contém a versão alvo e não contém a versão anterior."
		}
		if artifact.OldPresent {
			status = "warn"
			summary = "A versão anterior ainda aparece no artefato produzido."
		}
		report.Signals = append(report.Signals, CompatibilitySignal{ID: "artifact", Label: "Artefato final", Status: status, Summary: summary, Detail: artifact.Detail})
	} else {
		report.Signals = append(report.Signals, CompatibilitySignal{ID: "artifact", Label: "Artefato final", Status: "info", Summary: "Não houve evidência de artefato correlacionável para este componente.", Detail: artifact.Detail})
	}

	if res.Rescan != nil && res.Rescan.CoverageStatus == "complete" && res.After == nil {
		report.Signals = append(report.Signals, CompatibilitySignal{ID: "security", Label: "Nova análise de segurança", Status: "pass", Summary: "O achado alvo não reapareceu na nova análise canônica da cópia isolada.", Detail: "Cobertura canônica completa para a decisão de remediação."})
	} else if res.After != nil {
		report.Signals = append(report.Signals, CompatibilitySignal{ID: "security", Label: "Nova análise de segurança", Status: "fail", Summary: "O achado alvo continua presente após a alteração.", Detail: "A versão candidata não eliminou a evidência canônica do risco."})
	} else {
		report.Signals = append(report.Signals, CompatibilitySignal{ID: "security", Label: "Nova análise de segurança", Status: "fail", Summary: "A nova análise não produziu cobertura canônica completa.", Detail: "Sem uma nova análise confiável, o VulnWeave não trata a atualização como validada."})
	}

	// Residual risks are explicit rather than hidden behind a pseudo-precise score.
	report.ResidualRisks = append(report.ResidualRisks, "Caminhos de tempo de execução não exercitados pelos testes podem continuar contendo incompatibilidades comportamentais.")
	report.ResidualRisks = append(report.ResidualRisks, "Integrações externas, configuração de produção e uso por reflexão/carregamento dinâmico não são totalmente comprovados pela compilação e pelos testes locais.")
	if ts.Known == false && res.Tests.Success && !res.Tests.Skipped {
		report.ResidualRisks = append(report.ResidualRisks, "A suíte passou, mas o VulnWeave não conseguiu extrair contagem estruturada de testes do runner.")
	}
	if report.BinaryAPI != nil && !report.BinaryAPI.Available {
		report.ResidualRisks = append(report.ResidualRisks, "A comparação de API binária Java não ficou disponível; compilação e testes permanecem a principal evidência de compatibilidade.")
	}
	if artifact.Checked == false {
		report.ResidualRisks = append(report.ResidualRisks, "A versão física no artefato final não foi comprovada para esta coordenada.")
	}

	if !res.ReadyToApply {
		report.Confidence = "blocked"
		report.Headline = "Ainda não há evidência suficiente para aplicar a atualização."
		return report
	}

	warnCount := 0
	failCount := 0
	for _, s := range report.Signals {
		if s.Status == "warn" {
			warnCount++
		}
		if s.Status == "fail" {
			failCount++
		}
	}
	if failCount > 0 {
		report.Confidence = "blocked"
		report.Headline = "Um sinal determinístico ainda contradiz a compatibilidade da atualização."
		return report
	}

	apiStrong := report.BinaryAPI == nil || (report.BinaryAPI.Available && report.BinaryAPI.RemovedTypes == 0 && report.BinaryAPI.RemovedMembers == 0)
	artifactStrong := !artifact.Checked || (artifact.TargetPresent && !artifact.OldPresent)
	if warnCount == 0 && apiStrong && artifactStrong && (report.ChangeType == "patch" || report.ChangeType == "minor") {
		report.Confidence = "high"
		report.Headline = "Compatibilidade bem sustentada pelas evidências locais."
	} else {
		report.Confidence = "medium"
		report.Headline = "A atualização passou pelos gates, mas ainda há risco residual que merece revisão."
	}
	return report
}

func firstNonBlankGo(values ...string) string {
	for _, v := range values {
		if strings.TrimSpace(v) != "" {
			return strings.TrimSpace(v)
		}
	}
	return ""
}
