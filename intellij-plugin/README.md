# VulnWeave Dependency Intelligence 0.12.4


## Linux / IntelliJ

A distribuição 0.12.2 inclui engines nativos Linux x86_64 e ARM64. No Linux, o adaptador JetBrains usa `mvnw` (não `mvnw.cmd`), executa o Maven Wrapper por `/bin/sh` sem alterar permissões do repositório e mantém sandboxes em `~/.vulnweave/sandboxes` para não ampliar a árvore observada pela IDE. O diagnóstico exibe os limites atuais de `inotify`; o plugin não altera `sysctl`. Java/Maven são resolvidos a partir de overrides explícitos, PATH/JAVA_HOME/MAVEN_HOME/M2_HOME e instalações Linux conhecidas, usando o JBR da IDE apenas como fallback.

VulnWeave is a developer-facing SCA / dependency-remediation workbench for Node/Angular and Java/Maven. VS Code and JetBrains adapters share the same native Go engine.

## 0.9.9 — advisory hydration + deterministic remediation target

This release fixes a data-quality defect present in 0.9.2: OSV `POST /v1/querybatch` returns only vulnerability IDs and modification timestamps. 0.9.2 incorrectly consumed those lightweight records as if they contained the full advisory. That caused symptoms such as:

- `UNKNOWN` severity;
- `CVSS 0.0`;
- missing advisory summaries;
- missing CVE aliases / EPSS correlation;
- blank remediation target even when a patched version existed;
- findings falling to P4 because the scoring inputs were empty.

0.9.9 uses `querybatch` only to discover advisory IDs and then hydrates every unique ID through `GET /v1/vulns/{id}` before scoring, prioritization or remediation.

### Remediation target

When all advisories affecting the current package version publish a `fixed` version above the installed version, the engine derives one aggregate target: the highest minimum fixed version needed to cover every advisory. That target is shown automatically in the Workbench.

If any currently applicable advisory has no known fixed version above the installed version, VulnWeave does **not** claim an automatic safe target. A manual version can still be investigated, but it must pass repository existence + OSV validation before a diff can be prepared.

### One analysis pipeline

There is only one project analysis: **Analisar projeto**. Trivy and OSV-Scanner, when locally available, are auxiliary corroborators. Their findings do not inflate the canonical component count.

`Validar recomendação` / candidate validation is read-only with respect to the project baseline. It checks only the selected package/version against the registry/repository and OSV and returns `fullScanExecuted: false`.

### Baseline compatibility

A 0.9.2 baseline is rejected by 0.9.9 because it may contain non-hydrated advisories. Opening the dashboard prompts for a new analysis instead of silently reusing the stale report.

### npm graph correctness

`package-lock.json` v2/v3 parsing now keeps distinct package-version nodes. Multiple versions of the same package can coexist in an npm graph; 0.9.2 collapsed them by package name and could lose a vulnerable nested version or mark a nested copy as direct. Workbench identity now includes package + version.

## Safe remediation contract

1. Resolve the canonical dependency graph.
2. Discover vulnerable package/version nodes.
3. Hydrate complete advisory metadata.
4. Derive a candidate only when fixed-version evidence is complete.
5. Revalidate the candidate without changing the baseline.
6. Show the manifest diff before mutation.
7. Copy the project to an isolated temporary directory.
8. Resolve lockfile / Maven graph.
9. Run build and tests.
10. Run a complete verification analysis in the isolated copy.
11. Compare before/after for the specific package + version being remediated.
12. Enable application only after deterministic gates pass and the developer confirms.

AI remains advisory and is never used as proof of compatibility.

## IDEs

- VS Code: VSIX package.
- IntelliJ IDEA / compatible JetBrains IDEs: plugin ZIP.

## Build / test

```bash
cd core
go test ./...
../scripts/build-core.sh
```

See `docs/GUIA_IA.md`, `docs/VERACODE_INTEGRATION.md`, `docs/ARCHITECTURE.md` and `docs/INSTALL.md`.

## Maven Wrapper corporativo — 0.12.2
Se `mvnw`/`mvnw.cmd` existir mas não inicializar por `MavenWrapperMain` ausente ou bloqueio corporativo, o engine tenta um Maven do sistema/configurado somente quando sua versão coincide exatamente com a versão fixada em `.mvn/wrapper/maven-wrapper.properties`. Divergência de versão permanece bloqueante e aparece nos blockers.

## Scan 0.11 — evidence-first

A análise 0.11 preserva o grafo canônico para remediação e adiciona uma camada read-only de evidências: artifact inventory Java (JAR/WAR/EAR + nested JAR), importação real do JSON do OSV-Scanner e reconciliação com Trivy. Findings encontrados apenas em artefato ou scanner são exibidos para investigação, mas nunca autorizam alteração automática.
