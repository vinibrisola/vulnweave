package main

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"
)

const engineVersion = "0.12.4"

const maxJSONBytes int64 = 32 << 20

var httpClient = &http.Client{
	Timeout: 20 * time.Second,
	CheckRedirect: func(req *http.Request, via []*http.Request) error {
		if len(via) >= 5 {
			return fmt.Errorf("muitos redirecionamentos")
		}
		if req.URL.Scheme != "https" {
			return fmt.Errorf("redirecionamento não-HTTPS bloqueado: %s", req.URL.String())
		}
		return nil
	},
}

func writeJSON(path string, v interface{}) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, b, 0o600)
}

func readJSON(path string, v interface{}) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	if st, err := f.Stat(); err == nil && st.Size() > maxJSONBytes {
		return fmt.Errorf("JSON excede limite de %d bytes: %s", maxJSONBytes, path)
	}
	dec := json.NewDecoder(io.LimitReader(f, maxJSONBytes+1))
	return dec.Decode(v)
}

func fileHash(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func bytesHash(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

func cleanVersion(v string) string {
	v = strings.TrimSpace(v)
	v = strings.TrimPrefix(v, "v")
	v = strings.TrimLeft(v, "^~<>= ")
	if i := strings.IndexAny(v, " |,"); i >= 0 {
		v = v[:i]
	}
	return strings.TrimSpace(v)
}

type semverish struct {
	major, minor, patch int
	pre                 string
	ok                  bool
}

func parseSemverish(v string) semverish {
	v = cleanVersion(v)
	re := regexp.MustCompile(`^(\d+)(?:\.(\d+))?(?:\.(\d+))?(?:[-+]([^\s]+))?$`)
	m := re.FindStringSubmatch(v)
	if m == nil {
		return semverish{}
	}
	atoi := func(s string) int {
		if s == "" {
			return 0
		}
		n, _ := strconv.Atoi(s)
		return n
	}
	return semverish{atoi(m[1]), atoi(m[2]), atoi(m[3]), m[4], true}
}
func cmpVersion(a, b string) int {
	x, y := parseSemverish(a), parseSemverish(b)
	if !x.ok || !y.ok {
		return strings.Compare(cleanVersion(a), cleanVersion(b))
	}
	if x.major != y.major {
		if x.major < y.major {
			return -1
		}
		return 1
	}
	if x.minor != y.minor {
		if x.minor < y.minor {
			return -1
		}
		return 1
	}
	if x.patch != y.patch {
		if x.patch < y.patch {
			return -1
		}
		return 1
	}
	if x.pre == y.pre {
		return 0
	}
	if x.pre == "" {
		return 1
	}
	if y.pre == "" {
		return -1
	}
	return strings.Compare(x.pre, y.pre)
}
func maxVersion(vs ...string) string {
	out := ""
	for _, v := range vs {
		if v == "" {
			continue
		}
		if out == "" || cmpVersion(v, out) > 0 {
			out = v
		}
	}
	return out
}
func compatibilityDelta(current, target string) (string, string) {
	a, b := parseSemverish(current), parseSemverish(target)
	if !a.ok || !b.ok {
		return "unknown", "Não foi possível comparar semanticamente as versões; valide build e testes."
	}
	if b.major != a.major {
		return "high", fmt.Sprintf("Mudança de major %d → %d; risco elevado de breaking changes.", a.major, b.major)
	}
	if b.minor != a.minor {
		if a.major == 0 {
			return "high", fmt.Sprintf("Pacote pré-1.0: mudança 0.%d → 0.%d pode conter breaking changes; trate como risco elevado até build/testes confirmarem.", a.minor, b.minor)
		}
		return "medium", fmt.Sprintf("Mudança de minor %d.%d → %d.%d; pode introduzir alterações comportamentais.", a.major, a.minor, b.major, b.minor)
	}
	return "low", fmt.Sprintf("Mudança de patch %s → %s; ainda requer build/testes.", cleanVersion(current), cleanVersion(target))
}

func severityFromCVSS(score float64) string {
	switch {
	case score >= 9:
		return "CRITICAL"
	case score >= 7:
		return "HIGH"
	case score >= 4:
		return "MEDIUM"
	case score > 0:
		return "LOW"
	default:
		return "UNKNOWN"
	}
}
func priorityFor(sev string, cvss, epss float64, kev, direct, runtimeDep bool) string {
	if kev {
		return "P0"
	}
	if sev == "CRITICAL" && (direct || runtimeDep) {
		return "P0"
	}
	if sev == "CRITICAL" {
		return "P1"
	}
	if sev == "HIGH" && direct && runtimeDep {
		return "P1"
	}
	if sev == "HIGH" && epss >= 0.10 {
		return "P1"
	}
	if sev == "HIGH" {
		return "P2"
	}
	if sev == "MEDIUM" {
		return "P3"
	}
	return "P4"
}
func runtimeScope(scope string) bool {
	s := strings.ToLower(scope)
	return !(s == "dev" || s == "test" || s == "provided")
}
func uniqueStrings(in []string) []string {
	m := map[string]bool{}
	out := []string{}
	for _, s := range in {
		if s != "" && !m[s] {
			m[s] = true
			out = append(out, s)
		}
	}
	sort.Strings(out)
	return out
}

var ansiEscapeRe = regexp.MustCompile(`\x1b\[[0-9;?]*[ -/]*[@-~]`)

func stripANSI(s string) string {
	return ansiEscapeRe.ReplaceAllString(s, "")
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "\n…[truncated]"
}

// truncateHeadTail preserves the end of command output where build tools usually
// print the actual failure. The previous implementation kept only the beginning,
// which could show a successful Angular bundle while hiding a failing post-build step.
func truncateHeadTail(s string, n int) string {
	if len(s) <= n {
		return s
	}
	if n < 40 {
		return truncate(s, n)
	}
	head := n / 2
	tail := n - head
	return s[:head] + "\n…[middle truncated; final output preserved]…\n" + s[len(s)-tail:]
}
func relOrAbs(root, p string) string {
	if r, err := filepath.Rel(root, p); err == nil {
		return filepath.ToSlash(r)
	}
	return p
}

func getJSON(url string, headers map[string]string, out interface{}) error {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return err
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("GET %s: HTTP %d: %s", url, resp.StatusCode, strings.TrimSpace(string(b)))
	}
	return json.NewDecoder(io.LimitReader(resp.Body, maxJSONBytes)).Decode(out)
}

func getJSONRetry(url string, headers map[string]string, out interface{}, attempts int) error {
	if attempts < 1 {
		attempts = 1
	}
	var last error
	for i := 0; i < attempts; i++ {
		if i > 0 {
			time.Sleep(time.Duration(i) * 350 * time.Millisecond)
		}
		if err := getJSON(url, headers, out); err != nil {
			last = err
			continue
		}
		return nil
	}
	return last
}

func postJSON(url string, body interface{}, headers map[string]string, out interface{}) error {
	b, _ := json.Marshal(body)
	req, err := http.NewRequest("POST", url, strings.NewReader(string(b)))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		x, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("POST %s: HTTP %d: %s", url, resp.StatusCode, strings.TrimSpace(string(x)))
	}
	return json.NewDecoder(io.LimitReader(resp.Body, maxJSONBytes)).Decode(out)
}

func envStringList(name string) []string {
	raw := strings.TrimSpace(os.Getenv(name))
	if raw == "" {
		return nil
	}
	var out []string
	if json.Unmarshal([]byte(raw), &out) == nil {
		for i := range out {
			out[i] = strings.TrimSpace(out[i])
		}
		return uniqueStrings(out)
	}
	for _, x := range strings.Split(raw, ",") {
		x = strings.TrimSpace(x)
		if x != "" {
			out = append(out, x)
		}
	}
	return uniqueStrings(out)
}

func privateRulesPresent() bool {
	return len(envStringList("VULNWEAVE_PRIVATE_NPM_SCOPES")) > 0 || len(envStringList("VULNWEAVE_PRIVATE_MAVEN_PREFIXES")) > 0
}

func isPrivatePackage(ecosystem, pkg string) bool {
	switch strings.ToLower(ecosystem) {
	case "npm":
		for _, scope := range envStringList("VULNWEAVE_PRIVATE_NPM_SCOPES") {
			scope = strings.TrimSuffix(scope, "/")
			if strings.HasPrefix(pkg, scope+"/") || pkg == scope {
				return true
			}
		}
	case "maven":
		group := pkg
		if i := strings.Index(pkg, ":"); i >= 0 {
			group = pkg[:i]
		}
		for _, prefix := range envStringList("VULNWEAVE_PRIVATE_MAVEN_PREFIXES") {
			prefix = strings.TrimSuffix(prefix, ".")
			if group == prefix || strings.HasPrefix(group, prefix+".") {
				return true
			}
		}
	}
	return false
}

func pathWithin(root, child string) bool {
	r, err := filepath.Abs(root)
	if err != nil {
		return false
	}
	c, err := filepath.Abs(child)
	if err != nil {
		return false
	}
	rel, err := filepath.Rel(r, c)
	if err != nil {
		return false
	}
	return rel == "." || (rel != ".." && !strings.HasPrefix(rel, ".."+string(os.PathSeparator)) && !filepath.IsAbs(rel))
}

func safeRelativePath(rel string) bool {
	if rel == "" || filepath.IsAbs(rel) {
		return false
	}
	c := filepath.Clean(filepath.FromSlash(rel))
	return c != "." && c != ".." && !strings.HasPrefix(c, ".."+string(os.PathSeparator))
}

func detectProject(root string) (ProjectInfo, error) {
	rootAbs, err := filepath.Abs(root)
	if err != nil {
		return ProjectInfo{}, err
	}
	pkg := filepath.Join(rootAbs, "package.json")
	pom := filepath.Join(rootAbs, "pom.xml")
	if _, err := os.Stat(pkg); err == nil {
		p := ProjectInfo{Root: rootAbs, Ecosystem: "npm", Manifest: pkg}
		var data struct {
			Name string `json:"name"`
		}
		_ = readJSON(pkg, &data)
		p.Name = data.Name
		for _, lf := range []string{"package-lock.json", "pnpm-lock.yaml", "yarn.lock", "bun.lockb", "bun.lock"} {
			q := filepath.Join(rootAbs, lf)
			if _, e := os.Stat(q); e == nil {
				p.Lockfile = q
				break
			}
		}
		return p, nil
	}
	if _, err := os.Stat(pom); err == nil {
		return ProjectInfo{Root: rootAbs, Name: filepath.Base(rootAbs), Ecosystem: "Maven", Manifest: pom}, nil
	}
	return ProjectInfo{}, fmt.Errorf("nenhum projeto suportado encontrado em %s (esperado package.json ou pom.xml)", rootAbs)
}

func simpleUnifiedDiff(name string, before, after string) string {
	if before == after {
		return "(sem alteração)"
	}
	bl := strings.Split(strings.ReplaceAll(before, "\r\n", "\n"), "\n")
	al := strings.Split(strings.ReplaceAll(after, "\r\n", "\n"), "\n")
	// Focus on changed region; compact deterministic diff for manifest updates.
	start := 0
	for start < len(bl) && start < len(al) && bl[start] == al[start] {
		start++
	}
	be, ae := len(bl)-1, len(al)-1
	for be >= start && ae >= start && bl[be] == al[ae] {
		be--
		ae--
	}
	ctx := 3
	bs := start - ctx
	if bs < 0 {
		bs = 0
	}
	as := bs
	bend := be + ctx
	if bend >= len(bl) {
		bend = len(bl) - 1
	}
	aend := ae + ctx
	if aend >= len(al) {
		aend = len(al) - 1
	}
	var sb strings.Builder
	fmt.Fprintf(&sb, "--- a/%s\n+++ b/%s\n", name, name)
	fmt.Fprintf(&sb, "@@ -%d,%d +%d,%d @@\n", bs+1, bend-bs+1, as+1, aend-as+1)
	for i := bs; i < start && i < len(bl); i++ {
		sb.WriteString(" " + bl[i] + "\n")
	}
	for i := start; i <= be && i < len(bl); i++ {
		sb.WriteString("-" + bl[i] + "\n")
	}
	for i := start; i <= ae && i < len(al); i++ {
		sb.WriteString("+" + al[i] + "\n")
	}
	for i := be + 1; i <= bend && i < len(bl); i++ {
		sb.WriteString(" " + bl[i] + "\n")
	}
	return sb.String()
}

func copyProject(src, dst string) error {
	excluded := map[string]bool{".git": true, "node_modules": true, "target": true, "dist": true, "build": true, ".gradle": true, ".idea": true, ".vscode": true, ".vulnweave": true}
	return filepath.Walk(src, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(src, path)
		if err != nil {
			return err
		}
		if rel == "." {
			return os.MkdirAll(dst, 0o755)
		}
		parts := strings.Split(filepath.ToSlash(rel), "/")
		if excluded[parts[0]] {
			if info.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		out := filepath.Join(dst, rel)
		if info.IsDir() {
			return os.MkdirAll(out, info.Mode().Perm())
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return nil
		}
		in, err := os.Open(path)
		if err != nil {
			return err
		}
		defer in.Close()
		if err := os.MkdirAll(filepath.Dir(out), 0o755); err != nil {
			return err
		}
		o, err := os.OpenFile(out, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, info.Mode().Perm())
		if err != nil {
			return err
		}
		_, cpErr := io.Copy(o, in)
		closeErr := o.Close()
		if cpErr != nil {
			return cpErr
		}
		return closeErr
	})
}

func commandExists(name string) bool { _, err := execLookPath(name); return err == nil }

func commandOverrideKey(file string) string {
	var b strings.Builder
	for _, r := range strings.ToUpper(file) {
		if (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') {
			b.WriteRune(r)
		} else {
			b.WriteByte('_')
		}
	}
	return "VULNWEAVE_CMD_" + b.String()
}

func commandPrefixKey(file string) string {
	return strings.Replace(commandOverrideKey(file), "VULNWEAVE_CMD_", "VULNWEAVE_CMD_PREFIX_", 1)
}

var execLookPath = func(file string) (string, error) {
	if override := strings.TrimSpace(os.Getenv(commandOverrideKey(file))); override != "" {
		if st, err := os.Stat(override); err == nil && !st.IsDir() {
			return override, nil
		}
	}
	if runtime.GOOS == "windows" && !strings.HasSuffix(strings.ToLower(file), ".exe") {
		for _, suffix := range []string{".cmd", ".exe", ".bat"} {
			if p, err := findOnPath(file + suffix); err == nil {
				return p, nil
			}
		}
	}
	return findOnPath(file)
}

func findOnPath(file string) (string, error) {
	if strings.ContainsAny(file, `/\\`) {
		if _, err := os.Stat(file); err == nil {
			return file, nil
		}
		return "", os.ErrNotExist
	}
	for _, dir := range filepath.SplitList(os.Getenv("PATH")) {
		if dir == "" {
			continue
		}
		p := filepath.Join(dir, file)
		if st, err := os.Stat(p); err == nil && !st.IsDir() {
			return p, nil
		}
	}
	return "", fmt.Errorf("%s não encontrado no PATH", file)
}

func readLines(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var out []string
	s := bufio.NewScanner(f)
	for s.Scan() {
		out = append(out, s.Text())
	}
	return out, s.Err()
}
