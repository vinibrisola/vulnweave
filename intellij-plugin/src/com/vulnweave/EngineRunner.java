package com.vulnweave;

import com.intellij.openapi.project.Project;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.*;
import java.util.concurrent.*;

final class EngineRunner {
    static final String VERSION = "0.12.4";
    private final Project project;
    private final SettingsStore settings;

    EngineRunner(Project project) { this(project, null); }
    EngineRunner(Project project, SettingsStore settings) { this.project = project; this.settings = settings; }

    String root() {
        String p = project.getBasePath();
        if (p == null || p.isBlank()) throw new IllegalStateException("Project base path unavailable");
        return p;
    }

    Map<String,Object> scan() throws Exception {
        return run("scan", "--project", root(), "--mode", "full");
    }

    Map<String,Object> validate(String pkg, String current, String target, String ecosystem) throws Exception {
        return run("validate-candidate", "--project", root(), "--package", pkg, "--current", current,
                "--target", target, "--ecosystem", ecosystem == null ? "" : ecosystem);
    }

    Map<String,Object> plan(String pkg, String current, String target, String targetSpec,
                            String targetKind, String targetSource) throws Exception {
        return run("plan-fix", "--project", root(), "--package", pkg, "--current", current,
                "--target", target,
                "--target-spec", targetSpec == null ? "" : targetSpec,
                "--target-kind", targetKind == null || targetKind.isBlank() ? "registry" : targetKind,
                "--target-source", targetSource == null ? "" : targetSource);
    }

    Map<String,Object> execute(String planPath) throws Exception { return execute(planPath, true, true); }

    Map<String,Object> execute(String planPath, boolean runBuild, boolean runTests) throws Exception {
        return run("execute-plan", "--plan", planPath, "--build=" + runBuild, "--tests=" + runTests);
    }

    Map<String,Object> executionProgress(String planPath) {
        try {
            Path plan = Paths.get(planPath);
            String name = plan.getFileName().toString();
            int dot = name.lastIndexOf('.');
            String stem = dot > 0 ? name.substring(0, dot) : name;
            Path progress = plan.resolveSibling(stem + ".progress.json");
            if (!Files.isRegularFile(progress)) return new LinkedHashMap<>();
            String raw = Files.readString(progress, StandardCharsets.UTF_8);
            Object parsed = MiniJson.parse(raw);
            return new LinkedHashMap<>(MiniJson.map(parsed));
        } catch (Exception ignored) {
            return new LinkedHashMap<>();
        }
    }

    Map<String,Object> apply(String planPath, String executionPath) throws Exception {
        return run("apply-plan", "--plan", planPath, "--execution", executionPath);
    }

    String version() throws Exception { return runText("version").trim(); }

    Map<String,Object> preflight() throws Exception {
        Path r = Paths.get(root());
        Map<String,Object> out = new LinkedHashMap<>();
        List<Object> tools = new ArrayList<>();
        List<Object> missing = new ArrayList<>();
        List<Object> notes = new ArrayList<>();
        String ecosystem = "unknown", packageManager = "", managerSource = "";

        if (Files.isRegularFile(r.resolve("pom.xml"))) {
            ecosystem = "Java / Maven"; packageManager = "mvn";
            Path wrapper = mavenWrapper(r);
            String javaPath = resolveCommand("java", setting("runtime.java"));
            if (!"não encontrado".equals(javaPath)) javaPath = canonicalJavaCommand(javaPath);
            String inheritedJavaHome = System.getenv("JAVA_HOME");
            if (inheritedJavaHome != null && !inheritedJavaHome.isBlank()) {
                try {
                    if (javaExecutableForHome(Paths.get(inheritedJavaHome)) == null)
                        notes.add("JAVA_HOME do processo da IDE é inválido e será ignorado: " + inheritedJavaHome + ". O VulnWeave derivará java.home executando o Java detectado.");
                } catch (Exception ignored) {}
            }
            String mvnPath = wrapper != null ? wrapper.toString() : resolveCommand("mvn", setting("runtime.mvn"));
            managerSource = wrapper != null ? "Maven Wrapper" : "Maven";
            addTool(tools, missing, "Java", javaPath, "não encontrado".equals(javaPath) ? "" : "JDK validado (java.home)");
            addTool(tools, missing, "Maven", mvnPath, wrapper != null ? "wrapper do projeto" : ("não encontrado".equals(mvnPath) ? "" : "ambiente detectado"));
        } else if (Files.isRegularFile(r.resolve("package.json"))) {
            ecosystem = "Node";
            packageManager = detectNodePackageManager(r);
            managerSource = "lockfile / package.json";
            String nodePath = resolveCommand("node", setting("runtime.node"));
            String managerOverride = setting("runtime." + packageManager);
            String managerPath = resolveCommand(packageManager, managerOverride);
            addTool(tools, missing, "Node.js", nodePath, "não encontrado".equals(nodePath) ? "" : "ambiente detectado");
            addTool(tools, missing, packageManager, managerPath, "não encontrado".equals(managerPath) ? "" : "ambiente detectado");
            Path lock = firstExisting(r, "package-lock.json", "npm-shrinkwrap.json", "pnpm-lock.yaml", "yarn.lock", "bun.lock", "bun.lockb");
            addTool(tools, missing, "Lockfile", lock == null ? "não encontrado" : lock.toString(), lock == null ? "" : "arquivo do projeto");
            try {
                Map<String,Object> pkg = MiniJson.map(MiniJson.parse(Files.readString(r.resolve("package.json"), StandardCharsets.UTF_8)));
                Map<String,Object> scripts = MiniJson.map(pkg.get("scripts"));
                String build = MiniJson.str(scripts, "build"), test = MiniJson.str(scripts, "test");
                addTool(tools, missing, "Script build", build.isBlank() ? "não encontrado" : "package.json#scripts.build", build.isBlank() ? "" : build);
                addTool(tools, missing, "Script test", test.isBlank() ? "não encontrado" : "package.json#scripts.test", test.isBlank() ? "" : test);
                if (build.isBlank()) notes.add("package.json não define script build; o gate de build ficará bloqueado até existir um comando reproduzível.");
                if (test.isBlank()) notes.add("package.json não define script test; o gate de testes ficará bloqueado até existir um comando reproduzível.");
            } catch (Exception ex) {
                notes.add("Não foi possível interpretar package.json para confirmar os scripts de build/testes: " + ex.getMessage());
            }
        } else {
            notes.add("O projeto não possui pom.xml ou package.json na raiz selecionada.");
        }
        String platform = System.getProperty("os.name") + " / " + System.getProperty("os.arch");
        notes.add("Plataforma: " + platform + ". O engine é nativo e os gates executam no mesmo sistema operacional da IDE.");
        if (isLinux()) {
            String trivy = resolveCommand("trivy", ""), osv = resolveCommand("osv-scanner", "");
            notes.add("Linux: sandbox fora do workspace para reduzir pressão de inotify. Trivy auxiliar: " + ("não encontrado".equals(trivy) ? "não instalado (não bloqueia cobertura canônica)" : trivy) + "; OSV-Scanner auxiliar: " + ("não encontrado".equals(osv) ? "não instalado (não bloqueia cobertura canônica)" : osv) + ".");
            String watches = readLinuxSysctl("/proc/sys/fs/inotify/max_user_watches");
            String instances = readLinuxSysctl("/proc/sys/fs/inotify/max_user_instances");
            if (!watches.isBlank() || !instances.isBlank()) {
                notes.add("Linux inotify: max_user_watches=" + (watches.isBlank()?"?":watches) + ", max_user_instances=" + (instances.isBlank()?"?":instances) + ". Isso afeta o refresh da IDE, não a leitura direta do engine.");
                try {
                    long w = Long.parseLong(watches);
                    if (w < 524288L) notes.add("Atenção: o limite de inotify está baixo para projetos grandes. O VulnWeave mantém sandboxes fora do workspace; ajuste do sysctl deve ser feito pela administração da máquina, não pelo plugin.");
                } catch (Exception ignored) {}
            }
        }
        out.put("root", root()); out.put("ecosystem", ecosystem); out.put("packageManager", packageManager); out.put("managerSource", managerSource);
        out.put("tools", tools); out.put("missing", missing); out.put("notes", notes); out.put("ready", !tools.isEmpty() && missing.isEmpty());
        return out;
    }

    private void addTool(List<Object> tools, List<Object> missing, String label, String path, String source) {
        Map<String,Object> t = new LinkedHashMap<>();
        boolean present = path != null && !path.isBlank() && !"não encontrado".equals(path);
        t.put("label", label); t.put("path", present ? path : ""); t.put("source", source == null ? "" : source); t.put("present", present);
        tools.add(t); if (!present) missing.add(label);
    }

    private String detectNodePackageManager(Path root) {
        if (Files.exists(root.resolve("pnpm-lock.yaml"))) return "pnpm";
        if (Files.exists(root.resolve("yarn.lock"))) return "yarn";
        if (Files.exists(root.resolve("bun.lock")) || Files.exists(root.resolve("bun.lockb"))) return "bun";
        try {
            Map<String,Object> pkg = MiniJson.map(MiniJson.parse(Files.readString(root.resolve("package.json"), StandardCharsets.UTF_8)));
            String pm = MiniJson.str(pkg, "packageManager");
            int at = pm.indexOf('@'); if (at > 0) pm = pm.substring(0, at);
            if (pm.equals("pnpm") || pm.equals("yarn") || pm.equals("bun") || pm.equals("npm")) return pm;
        } catch (Exception ignored) {}
        return "npm";
    }

    String diagnoseEnvironment() {
        StringBuilder out = new StringBuilder();
        Path r = Paths.get(root());
        boolean maven = Files.exists(r.resolve("pom.xml"));
        boolean node = Files.exists(r.resolve("package.json"));
        out.append("Tipo: ").append(maven ? "Maven" : node ? "Node/npm" : "não detectado").append('\n');
        if (maven) {
            Path wrapper = mavenWrapper(r);
            out.append("Maven wrapper: ").append(wrapper == null ? "não encontrado" : wrapper).append('\n');
            out.append("mvn: ").append(resolveCommand("mvn", setting("runtime.mvn"))).append('\n');
            String javaDetected = resolveCommand("java", setting("runtime.java"));
            out.append("java: ").append("não encontrado".equals(javaDetected) ? javaDetected : canonicalJavaCommand(javaDetected)).append('\n');
            String inherited = System.getenv("JAVA_HOME");
            if (inherited != null && !inherited.isBlank()) out.append("JAVA_HOME herdado: ").append(inherited).append(javaExecutableForHome(Paths.get(inherited)) == null ? " [INVÁLIDO — ignorado]" : " [válido]").append('\n');
            Path effective = "não encontrado".equals(javaDetected) ? null : validatedJavaHome(javaDetected);
            if (effective != null) out.append("JAVA_HOME efetivo: ").append(effective).append(" [derivado de java.home]\n");
        }
        if (node) {
            out.append("node: ").append(resolveCommand("node", setting("runtime.node"))).append('\n');
            out.append("npm: ").append(resolveCommand("npm", setting("runtime.npm"))).append('\n');
            for (String lock : new String[]{"package-lock.json","pnpm-lock.yaml","yarn.lock","bun.lockb","bun.lock"})
                if (Files.exists(r.resolve(lock))) out.append("lockfile: ").append(lock).append('\n');
        }
        String extra = setting("runtime.extraPaths");
        if (!extra.isBlank()) out.append("PATH extra: ").append(extra).append('\n');
        String npmScopes = setting("privacy.npmScopes"), mavenPrefixes = setting("privacy.mavenPrefixes");
        if (!npmScopes.isBlank()) out.append("Scopes npm privados: ").append(npmScopes).append('\n');
        if (!mavenPrefixes.isBlank()) out.append("Prefixes Maven privados: ").append(mavenPrefixes).append('\n');
        return out.toString();
    }

    private boolean isWindows() { return System.getProperty("os.name", "").toLowerCase(Locale.ROOT).contains("win"); }
    private boolean isLinux() { return System.getProperty("os.name", "").toLowerCase(Locale.ROOT).contains("linux"); }

    private String readLinuxSysctl(String file) {
        try {
            Path p = Paths.get(file);
            return Files.isRegularFile(p) ? Files.readString(p, StandardCharsets.UTF_8).trim() : "";
        } catch (Exception ignored) { return ""; }
    }

    private Path firstExisting(Path root, String... names) {
        for (String n : names) { Path p = root.resolve(n); if (Files.isRegularFile(p)) return p; }
        return null;
    }

    private Path mavenWrapper(Path root) {
        return isWindows() ? firstExisting(root, "mvnw.cmd", "mvnw.bat", "mvnw") : firstExisting(root, "mvnw");
    }

    private void addDir(List<String> dirs, String raw) {
        if (raw == null || raw.isBlank()) return;
        try {
            Path p = Paths.get(raw).toAbsolutePath().normalize();
            if (Files.isDirectory(p) && dirs.stream().noneMatch(x -> x.equals(p.toString()))) dirs.add(p.toString());
        } catch (Exception ignored) {}
    }

    private List<String> runtimeSearchDirs() {
        List<String> dirs = new ArrayList<>();
        String extra = setting("runtime.extraPaths");
        if (!extra.isBlank()) for (String d : extra.split(java.util.regex.Pattern.quote(File.pathSeparator))) addDir(dirs, d);
        String envPath = System.getenv("PATH");
        if (envPath != null) for (String d : envPath.split(java.util.regex.Pattern.quote(File.pathSeparator))) addDir(dirs, d);
        addDir(dirs, pathEnv("JAVA_HOME", "bin"));
        addDir(dirs, pathEnv("MAVEN_HOME", "bin"));
        addDir(dirs, pathEnv("M2_HOME", "bin"));
        addDir(dirs, pathEnv("NODE_HOME", "bin"));
        if (!isWindows()) {
            String home = System.getProperty("user.home", "");
            addDir(dirs, "/usr/local/bin"); addDir(dirs, "/usr/bin"); addDir(dirs, "/bin");
            addDir(dirs, home + "/.local/bin"); addDir(dirs, home + "/bin");
            addDir(dirs, home + "/.sdkman/candidates/java/current/bin");
            addDir(dirs, home + "/.sdkman/candidates/maven/current/bin");
            addDir(dirs, home + "/.volta/bin"); addDir(dirs, home + "/.nvm/current/bin");
            Path jvms = Paths.get("/usr/lib/jvm");
            try (DirectoryStream<Path> stream = Files.newDirectoryStream(jvms)) {
                for (Path jvm : stream) addDir(dirs, jvm.resolve("bin").toString());
            } catch (Exception ignored) {}
        }
        return dirs;
    }

    private String pathEnv(String key, String child) {
        String v = System.getenv(key);
        return v == null || v.isBlank() ? "" : Paths.get(v, child).toString();
    }

    private String resolveCommand(String name, String override) {
        if (override != null && !override.isBlank()) {
            try { if (Files.isRegularFile(Paths.get(override))) return Paths.get(override).toAbsolutePath().normalize().toString(); } catch (Exception ignored) {}
        }
        List<String> names = new ArrayList<>(); names.add(name);
        if (isWindows()) { names.add(name+".cmd"); names.add(name+".exe"); names.add(name+".bat"); }
        for (String d : runtimeSearchDirs()) for (String n : names) {
            try { Path p=Paths.get(d,n); if(Files.isRegularFile(p)) return p.toString(); } catch(Exception ignored){}
        }
        // IDE runtime is a fallback only. On Linux in particular we prefer JAVA_HOME/PATH/SDKMAN
        // so Maven does not silently run under the JetBrains Runtime when the project uses another JDK.
        if ("java".equals(name)) {
            String exe = isWindows() ? "java.exe" : "java";
            try { Path bundled = Paths.get(System.getProperty("java.home"), "bin", exe); if (Files.isRegularFile(bundled)) return bundled.toString(); } catch (Exception ignored) {}
        }
        return "não encontrado";
    }

    private String setting(String key) { return settings == null ? "" : settings.get(key); }

    private Path javaExecutableForHome(Path home) {
        if (home == null) return null;
        String exe = isWindows() ? "java.exe" : "java";
        Path p = home.resolve("bin").resolve(exe);
        return Files.isRegularFile(p) ? p.toAbsolutePath().normalize() : null;
    }

    private Path probeJavaHome(String javaExe) {
        if (javaExe == null || javaExe.isBlank() || "não encontrado".equals(javaExe)) return null;
        try {
            Path exe = Paths.get(javaExe).toAbsolutePath().normalize();
            if (!Files.isRegularFile(exe)) return null;
            ProcessBuilder pb = new ProcessBuilder(exe.toString(), "-XshowSettings:properties", "-version");
            pb.redirectErrorStream(true);
            // java.exe does not require JAVA_HOME to start. Removing a stale value
            // prevents corporate Oracle javapath shims from leaking an invalid root
            // into the probe itself.
            pb.environment().remove("JAVA_HOME");
            Process proc = pb.start();
            if (!proc.waitFor(8, TimeUnit.SECONDS)) { proc.destroyForcibly(); return null; }
            String text = new String(proc.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
            for (String line : text.split("\\R")) {
                String t = line.trim();
                if (!t.startsWith("java.home")) continue;
                int eq = t.indexOf('=');
                if (eq < 0) continue;
                String raw = t.substring(eq + 1).trim();
                if (raw.isBlank()) continue;
                Path home = Paths.get(raw).toAbsolutePath().normalize();
                if (javaExecutableForHome(home) != null) return home;
            }
        } catch (Exception ignored) {}
        return null;
    }

    private Path validatedJavaHome(String javaExe) {
        Path probed = probeJavaHome(javaExe);
        if (probed != null) return probed;
        try {
            Path exe = Paths.get(javaExe).toAbsolutePath().normalize();
            Path bin = exe.getParent();
            Path home = bin == null ? null : bin.getParent();
            if (javaExecutableForHome(home) != null) return home;
        } catch (Exception ignored) {}
        return null;
    }

    private String canonicalJavaCommand(String javaExe) {
        Path home = validatedJavaHome(javaExe);
        Path canonical = javaExecutableForHome(home);
        return canonical == null ? javaExe : canonical.toString();
    }

    private void configureEnvironment(Map<String,String> env) {
        List<String> search = runtimeSearchDirs();
        String current = env.getOrDefault("PATH", System.getenv("PATH"));
        LinkedHashSet<String> all = new LinkedHashSet<>(search);
        if (current != null && !current.isBlank()) all.addAll(Arrays.asList(current.split(java.util.regex.Pattern.quote(File.pathSeparator))));
        env.put("PATH", String.join(File.pathSeparator, all));

        String javaExe = resolveCommand("java", setting("runtime.java"));
        if (!"não encontrado".equals(javaExe)) {
            Path javaHome = validatedJavaHome(javaExe);
            if (javaHome != null) {
                env.put("JAVA_HOME", javaHome.toString());
                Path canonical = javaExecutableForHome(javaHome);
                if (canonical != null) env.put("VULNWEAVE_CMD_JAVA", canonical.toString());
            } else {
                // Never propagate a JAVA_HOME inferred only from the parent directory
                // of a shim such as C:\Program Files (x86)\Common Files\Oracle\Java\javapath\java.exe.
                // Maven Wrapper rejects that value because JAVA_HOME\bin\java.exe does not exist.
                env.remove("JAVA_HOME");
            }
        } else {
            String inherited = env.get("JAVA_HOME");
            if (inherited != null && javaExecutableForHome(Paths.get(inherited)) == null) env.remove("JAVA_HOME");
        }
        String home = System.getProperty("user.home", "");
        if (!home.isBlank()) {
            env.putIfAbsent("VULNWEAVE_SANDBOX_ROOT", Paths.get(home, ".vulnweave", "sandboxes").toString());
            env.putIfAbsent("VULNWEAVE_CACHE_DIR", Paths.get(home, ".vulnweave", "cache").toString());
        }
        if (settings == null) return;
        putEnv(env, "VULNWEAVE_PRIVATE_NPM_SCOPES", setting("privacy.npmScopes"));
        putEnv(env, "VULNWEAVE_PRIVATE_MAVEN_PREFIXES", setting("privacy.mavenPrefixes"));
        putEnv(env, "VULNWEAVE_CMD_MVN", setting("runtime.mvn"));
        putEnv(env, "VULNWEAVE_CMD_JAVA", setting("runtime.java"));
        putEnv(env, "VULNWEAVE_CMD_NODE", setting("runtime.node"));
        putEnv(env, "VULNWEAVE_CMD_NPM", setting("runtime.npm"));
        putEnv(env, "VULNWEAVE_CMD_PNPM", setting("runtime.pnpm"));
        putEnv(env, "VULNWEAVE_CMD_YARN", setting("runtime.yarn"));
        putEnv(env, "VULNWEAVE_CMD_BUN", setting("runtime.bun"));
    }

    private static void putEnv(Map<String,String> env, String key, String value) { if (value != null && !value.isBlank()) env.put(key, value.trim()); }

    private Process start(String... args) throws Exception {
        Path bin = extractEngine();
        List<String> cmd = new ArrayList<>(); cmd.add(bin.toString()); cmd.addAll(Arrays.asList(args));
        ProcessBuilder pb = new ProcessBuilder(cmd); pb.directory(new File(root())); pb.redirectErrorStream(false); configureEnvironment(pb.environment());
        return pb.start();
    }

    private Map<String,Object> run(String... args) throws Exception {
        String out = runText(args);
        if (out.isBlank()) throw new IOException("VulnWeave engine returned an empty response");
        return MiniJson.map(MiniJson.parse(out));
    }

    private String runText(String... args) throws Exception {
        Process p = start(args);
        ExecutorService io = Executors.newFixedThreadPool(2, r -> { Thread t = new Thread(r, "vulnweave-engine-io"); t.setDaemon(true); return t; });
        Future<byte[]> stdout = io.submit(() -> p.getInputStream().readAllBytes());
        Future<byte[]> stderr = io.submit(() -> p.getErrorStream().readAllBytes());
        try {
            long timeoutMinutes = (args.length > 0 && "execute-plan".equals(args[0])) ? 40L : (args.length > 0 && "scan".equals(args[0])) ? 25L : 12L;
            if (!p.waitFor(timeoutMinutes, TimeUnit.MINUTES)) {
                p.destroy(); if (!p.waitFor(3, TimeUnit.SECONDS)) p.destroyForcibly(); throw new IOException("VulnWeave engine timeout after " + timeoutMinutes + " minutes");
            }
            String out = new String(stdout.get(10, TimeUnit.SECONDS), StandardCharsets.UTF_8).trim();
            String err = new String(stderr.get(10, TimeUnit.SECONDS), StandardCharsets.UTF_8).trim();
            if (p.exitValue() != 0) throw new IOException(err.isBlank() ? "Engine failed with exit " + p.exitValue() : err);
            return out;
        } finally { io.shutdownNow(); }
    }

    private Path extractEngine() throws Exception {
        String os = System.getProperty("os.name").toLowerCase(Locale.ROOT), arch = System.getProperty("os.arch").toLowerCase(Locale.ROOT);
        String name;
        if (os.contains("win") && (arch.contains("amd64") || arch.contains("x86_64"))) name = "vulnweave-engine-windows-amd64.exe";
        else if (os.contains("linux") && (arch.contains("amd64") || arch.contains("x86_64"))) name = "vulnweave-engine-linux-amd64";
        else if (os.contains("linux") && (arch.contains("aarch64") || arch.contains("arm64"))) name = "vulnweave-engine-linux-arm64";
        else if (os.contains("mac") && (arch.contains("aarch64") || arch.contains("arm64"))) name = "vulnweave-engine-darwin-arm64";
        else if (os.contains("mac")) name = "vulnweave-engine-darwin-amd64";
        else throw new IOException("Unsupported platform: " + os + "/" + arch);
        Path dir = Paths.get(System.getProperty("user.home"), ".vulnweave", "engine", VERSION); Files.createDirectories(dir); Path dst = dir.resolve(name);
        try (InputStream in = getClass().getResourceAsStream("/bin/" + name)) {
            if (in == null) throw new FileNotFoundException("Bundled engine " + name);
            Path tmp = dir.resolve(name + ".tmp"); Files.copy(in, tmp, StandardCopyOption.REPLACE_EXISTING);
            try { Files.move(tmp, dst, StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE); }
            catch (AtomicMoveNotSupportedException ex) { Files.move(tmp, dst, StandardCopyOption.REPLACE_EXISTING); }
        }
        if (!os.contains("win")) {
            dst.toFile().setExecutable(true, true);
            if (!Files.isExecutable(dst)) throw new IOException("Engine extraído sem permissão de execução. Verifique se " + dir + " está em filesystem noexec ou sem permissão de execução.");
        }
        return dst;
    }
}
