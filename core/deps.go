package main

import (
	"encoding/json"
	"encoding/xml"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

func collectDependencies(p ProjectInfo) ([]Dependency, []string) {
	if p.Ecosystem == "npm" {
		return collectNpmDependencies(p)
	}
	return collectMavenDependencies(p)
}

func collectNpmDependencies(p ProjectInfo) ([]Dependency, []string) {
	warnings := []string{}
	b, err := os.ReadFile(p.Manifest)
	if err != nil {
		return nil, []string{err.Error()}
	}
	var pkg struct {
		Dependencies         map[string]string `json:"dependencies"`
		DevDependencies      map[string]string `json:"devDependencies"`
		PeerDependencies     map[string]string `json:"peerDependencies"`
		OptionalDependencies map[string]string `json:"optionalDependencies"`
	}
	if err := json.Unmarshal(b, &pkg); err != nil {
		return nil, []string{err.Error()}
	}
	direct := map[string]Dependency{}
	add := func(m map[string]string, scope string) {
		for n, v := range m {
			direct[n] = Dependency{Name: n, Version: cleanVersion(v), Declared: v, Ecosystem: "npm", Direct: true, Scope: scope, Manifest: p.Manifest, ControlHint: "package.json", DependencyPath: []string{n}}
		}
	}
	add(pkg.Dependencies, "runtime")
	add(pkg.DevDependencies, "dev")
	add(pkg.PeerDependencies, "peer")
	add(pkg.OptionalDependencies, "optional")

	// Prefer resolved versions from package-lock v2/v3. Unlike the previous
	// implementation, keep distinct package-version nodes: npm can legitimately
	// install multiple versions of the same package at different paths.
	if strings.HasSuffix(p.Lockfile, "package-lock.json") {
		lb, err := os.ReadFile(p.Lockfile)
		if err == nil {
			var lock struct {
				Packages map[string]struct {
					Version  string `json:"version"`
					Dev      bool   `json:"dev"`
					Optional bool   `json:"optional"`
					Name     string `json:"name"`
				} `json:"packages"`
			}
			if json.Unmarshal(lb, &lock) == nil && len(lock.Packages) > 0 {
				all := map[string]Dependency{}
				for lockPath, entry := range lock.Packages {
					if lockPath == "" || entry.Version == "" || !strings.Contains(filepath.ToSlash(lockPath), "node_modules/") {
						continue
					}
					chain := npmDependencyPath(lockPath)
					if len(chain) == 0 {
						continue
					}
					name := chain[len(chain)-1]
					if entry.Name != "" {
						name = entry.Name
					}
					resolved := cleanVersion(entry.Version)
					if resolved == "" {
						continue
					}
					normalized := filepath.ToSlash(lockPath)
					rootPath := "node_modules/" + name
					isRootDirect := normalized == rootPath
					scope := "runtime"
					if entry.Dev {
						scope = "dev"
					}
					if entry.Optional {
						scope = "optional"
					}
					d := Dependency{Name: name, Version: resolved, Ecosystem: "npm", Direct: false, Scope: scope, Manifest: p.Manifest, ControlHint: "transitive", DependencyPath: chain}
					if declared, ok := direct[name]; ok && isRootDirect {
						d = declared
						d.Version = resolved
						d.Direct = true
						d.DependencyPath = []string{name}
					}
					key := name + "|" + resolved
					if prev, exists := all[key]; exists {
						// Prefer direct evidence, otherwise keep the shortest known path.
						if d.Direct && !prev.Direct {
							all[key] = d
						} else if d.Direct == prev.Direct && len(d.DependencyPath) > 0 && (len(prev.DependencyPath) == 0 || len(d.DependencyPath) < len(prev.DependencyPath)) {
							all[key] = d
						}
					} else {
						all[key] = d
					}
				}
				// Direct declarations that are not represented in lock.packages are still
				// retained with their clean declared version.
				for _, d := range direct {
					if d.Version == "" {
						continue
					}
					key := d.Name + "|" + cleanVersion(d.Version)
					foundDirect := false
					for _, x := range all {
						if x.Name == d.Name && x.Direct {
							foundDirect = true
							break
						}
					}
					if !foundDirect {
						all[key] = d
					}
				}
				out := make([]Dependency, 0, len(all))
				for _, d := range all {
					if d.Version != "" {
						out = append(out, d)
					}
				}
				sort.Slice(out, func(i, j int) bool {
					if out[i].Name != out[j].Name {
						return out[i].Name < out[j].Name
					}
					return cmpVersion(out[i].Version, out[j].Version) < 0
				})
				return out, warnings
			}
		}
	}
	out := make([]Dependency, 0, len(direct))
	for _, d := range direct {
		if d.Version != "" {
			out = append(out, d)
		}
	}
	if p.Lockfile != "" && !strings.HasSuffix(p.Lockfile, "package-lock.json") {
		warnings = append(warnings, "Lockfile detectado, mas a resolução transitiva detalhada nesta build é nativa apenas para package-lock.json; o scanner ainda cobre dependências diretas e scanners profundos externos podem complementar.")
	}
	return out, warnings
}

func npmDependencyPath(lockPath string) []string {
	p := filepath.ToSlash(strings.TrimSpace(lockPath))
	p = strings.TrimPrefix(p, "./")
	p = strings.TrimPrefix(p, "node_modules/")
	if p == "" {
		return nil
	}
	parts := strings.Split(p, "/node_modules/")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.Trim(part, "/")
		if part != "" {
			out = append(out, part)
		}
	}
	return out
}

type pomDependency struct {
	GroupID    string `xml:"groupId"`
	ArtifactID string `xml:"artifactId"`
	Version    string `xml:"version"`
	Scope      string `xml:"scope"`
	Type       string `xml:"type"`
}
type pomProject struct {
	XMLName    xml.Name `xml:"project"`
	ArtifactID string   `xml:"artifactId"`
	Properties struct {
		Inner string `xml:",innerxml"`
	} `xml:"properties"`
	Dependencies         []pomDependency `xml:"dependencies>dependency"`
	DependencyManagement struct {
		Dependencies []pomDependency `xml:"dependencies>dependency"`
	} `xml:"dependencyManagement"`
}

func parseProperties(inner string) map[string]string {
	out := map[string]string{}
	dec := xml.NewDecoder(strings.NewReader("<root>" + inner + "</root>"))
	var current string
	for {
		tok, err := dec.Token()
		if err != nil {
			break
		}
		switch t := tok.(type) {
		case xml.StartElement:
			if t.Name.Local != "root" {
				current = t.Name.Local
			}
		case xml.CharData:
			if current != "" {
				v := strings.TrimSpace(string(t))
				if v != "" {
					out[current] = v
				}
			}
		case xml.EndElement:
			if t.Name.Local == current {
				current = ""
			}
		}
	}
	return out
}
func resolvePomVersion(v string, props map[string]string) string {
	v = strings.TrimSpace(v)
	if strings.HasPrefix(v, "${") && strings.HasSuffix(v, "}") {
		k := strings.TrimSuffix(strings.TrimPrefix(v, "${"), "}")
		if x := props[k]; x != "" {
			return x
		}
	}
	return v
}

func collectMavenDependencies(p ProjectInfo) ([]Dependency, []string) {
	warnings := []string{}
	b, err := os.ReadFile(p.Manifest)
	if err != nil {
		return nil, []string{err.Error()}
	}
	var pom pomProject
	if err := xml.Unmarshal(b, &pom); err != nil {
		return nil, []string{err.Error()}
	}
	props := parseProperties(pom.Properties.Inner)
	managed := map[string]string{}
	for _, d := range pom.DependencyManagement.Dependencies {
		managed[d.GroupID+":"+d.ArtifactID] = resolvePomVersion(d.Version, props)
	}
	direct := map[string]Dependency{}
	for _, d := range pom.Dependencies {
		name := d.GroupID + ":" + d.ArtifactID
		v := resolvePomVersion(d.Version, props)
		if v == "" {
			v = managed[name]
		}
		scope := d.Scope
		if scope == "" {
			scope = "compile"
		}
		direct[name] = Dependency{Name: name, Version: cleanVersion(v), Declared: d.Version, Ecosystem: "Maven", Direct: true, Scope: scope, Manifest: p.Manifest, ControlHint: "pom.xml", DependencyPath: []string{name}}
	}
	// Maven dependency:tree gives effective, transitive versions. Prefer the project Maven Wrapper when present.
	if _, lookupErr := execLookPath(mavenCommand(p)); lookupErr == nil {
		tmp, err := os.CreateTemp("", "vulnweave-mvn-tree-*.txt")
		if err == nil {
			tmp.Close()
			defer os.Remove(tmp.Name())
			cmdResult := runMaven(p, "Maven dependency tree", []string{"-B", "-ntp", "dependency:tree", "-DoutputType=text", "-DappendOutput=false", "-DoutputFile=" + tmp.Name(), "-DskipTests"})
			logDir := filepath.Join(p.Root, ".vulnweave", "reports")
			if os.MkdirAll(logDir, 0o700) == nil {
				_ = writeJSON(filepath.Join(logDir, "maven-resolution.json"), cmdResult)
			}
			if cmdResult.Success {
				lines, _ := readLines(tmp.Name())
				all := map[string]Dependency{}
				re := regexp.MustCompile(`(?:\+\-|\\-)?\s*([^:\s]+):([^:\s]+):([^:\s]+):([^:\s]+):([^:\s]+)(?::[^\s]+)?`)
				for _, line := range lines {
					m := re.FindStringSubmatch(strings.TrimSpace(line))
					if m == nil {
						continue
					}
					name := m[1] + ":" + m[2]
					ver := m[4]
					scope := m[5]
					d, ok := direct[name]
					if ok {
						d.Version = ver
						d.Scope = scope
						all[name] = d
					} else {
						all[name] = Dependency{Name: name, Version: ver, Ecosystem: "Maven", Direct: false, Scope: scope, Manifest: p.Manifest, ControlHint: "transitive"}
					}
				}
				for n, d := range direct {
					if _, ok := all[n]; !ok && d.Version != "" {
						all[n] = d
					}
				}
				res := []Dependency{}
				for _, d := range all {
					if d.Version != "" {
						res = append(res, d)
					}
				}
				if len(res) > 0 {
					return res, warnings
				}
				warnings = append(warnings, "Maven terminou sem um grafo de dependências utilizável; cobertura incompleta.")
			} else {
				warnings = append(warnings, "mvn dependency:tree falhou; usando dependências diretas resolvíveis do pom.xml: "+truncate(cmdResult.Output, 500))
			}
		} else {
			warnings = append(warnings, "Falha ao criar arquivo temporário do Maven: "+err.Error())
		}
	} else {
		warnings = append(warnings, "Maven/Maven Wrapper não localizado pelo resolver de runtime; dependências transitivas serão completadas por OSV-Scanner/Trivy quando disponíveis.")
	}
	out := []Dependency{}
	for _, d := range direct {
		if d.Version != "" && !strings.Contains(d.Version, "${") {
			out = append(out, d)
		} else {
			warnings = append(warnings, fmt.Sprintf("Versão de %s não pôde ser resolvida localmente (%s).", d.Name, d.Declared))
		}
	}
	return out, warnings
}
