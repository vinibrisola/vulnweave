# VulnWeave Dependency Intelligence 0.12.4

## 0.10.3 — resolução do lockfile Angular reproduzida

Corrige ERESOLVE confirmado com o grafo real sbcweb: invalida somente as entradas antigas do conjunto coordenado no lockfile da cópia isolada antes da resolução estrita. O npm regenera os metadados reais e npm ci reproduz o resultado. O projeto original continua protegido pelos gates existentes. Veja SECURITY_REVIEW_0.10.3.md. Instale 0.10.3, recarregue o VS Code e gere uma nova prévia.

## 0.10.2 — Angular misturado, npm reproduzível e diagnóstico visual

Framework Angular declarado com patches misturados é alinhado como conjunto na mesma linha major/minor, sem downgrade. CLI/build e CDK/Material mantêm suas próprias versões. O npm gera o lockfile candidato com `--package-lock-only` e depois o reproduz com `npm ci`, mantendo peers estritos e scripts de instalação desabilitados. A interface oferece busca por componente/CVE, filtro de severidade e diagnóstico do primeiro gate bloqueado.

Instale o VSIX 0.10.2, recarregue o VS Code e gere uma nova prévia; planos antigos não recebem as novas regras automaticamente. Consulte `SECURITY_REVIEW_0.10.2.md` para evidência e limites.

## 0.10.1 — deterministic dependency cohorts

This release fixes a false-safe remediation pattern exposed by real Angular peer resolution: a security target such as `20.3.28` must not be expressed as `^20.3.28` for a tightly coupled release cohort, because the package manager may independently choose a newer patch (for example `20.3.33`) for some members while other exact peers are still resolving. VulnWeave now pins exact versions for peer-coupled cohorts during the proposed remediation and validates the concrete resolved graph before build/test gates.

Node behavior:

- `package-lock.json`: exact peer cohorts are discovered from lockfile peer metadata; every coordinated direct member is pinned to the same validated target and the regenerated root lock entries are verified one-by-one.
- npm: `--strict-peer-deps` remains mandatory and ERESOLVE peer overrides are rejected.
- pnpm: strict peer resolution is enforced and peer warnings are fail-closed.
- Yarn/Bun: peer-conflict warning signatures are treated as unsafe even when the package manager exits zero.
- single-package remediations that are not part of a proven exact peer cohort continue to preserve the original `^`/`~` policy.

Maven behavior:

- shared properties and local `dependencyManagement` remain preferred control points;
- explicit same-group release cohorts are updated together;
- after `dependency:resolve`, the effective `dependency:tree` is checked so the selected artifact (and explicit cohort members) must actually resolve to the target version before build/tests can run.

The remediation pipeline remains fail-safe: graph → build → tests → full rescan → before/after → developer confirmation. No peer override, forced install, `legacy-peer-deps`, or inferred success is accepted as proof of compatibility.

VulnWeave is a developer-facing SCA / dependency-remediation workbench for Node/Angular and Java/Maven. VS Code and JetBrains adapters share the same native Go engine.

## 0.10.1 — hardened remediation + authoritative-source fallback

### Trusted remediation source hierarchy

Remediation no longer stops at “no fixed version” when the public registry is known to be stale. The engine uses a strict evidence hierarchy:

1. complete OSV fixed ranges;
2. GitHub Advisory Database structured fallback for missing CVE/severity/fixed-version metadata;
3. curated authoritative vendor distribution routes for known registry exceptions;
4. manual investigation when none of the trusted sources can prove a safe target.

For `xlsx`, SheetJS documents the public npm package as a legacy endpoint at `0.18.5` and publishes current releases through the official SheetJS CDN. VulnWeave therefore proposes the curated official `0.20.3` tarball instead of incorrectly claiming that no remediation exists. It never replaces a library with a different package automatically.

Raw GHSA identifiers are now treated as secondary technical identifiers in the UI. CVEs and human-readable advisory summaries are shown first.

### Security hardening

0.10.1 also includes a focused extension security review: private package names are kept out of public lookups according to configured scope/prefix policy; webviews have stricter CSP/resource roots; tool downloads are pinned, size-bounded and reverified; HTTP/scanner outputs are bounded; remediation apply paths are allowlisted; AI evidence is isolated as untrusted data. See `SECURITY_REVIEW_0.10.1.md`.

### Workbench UX

The remediation workbench now separates the deterministic remediation workflow from supplemental intelligence.

Main workflow:

1. recommended remediation target;
2. candidate validation;
3. manifest diff;
4. isolated dependency/lock resolution;
5. build + tests;
6. complete verification scan;
7. before/after comparison;
8. explicit developer confirmation.

A sticky **Contexto e integrações** rail appears on the right on wide screens. It contains:

- **Analisar impacto / Revisar diff / Revisar resultado com IA** — label changes with the evidence available;
- **Verificar no Veracode** — read-only correlation with corporate SCA evidence/policy;
- **Preparar para Amazon Q** — cria Project Rule em `.amazonq/rules` e exporta contexto sanitizado;
- compact decision evidence (advisory count, CVSS, EPSS, target and baseline);
- the current technical-gate state.

On narrow screens the rail becomes a normal responsive section below the workflow.

### One VSIX, no manual scanner installation on Windows x64

The VulnWeave core engine is already shipped inside the VSIX. From 0.10.1, the extension can also provision its auxiliary scanners automatically on first use. Developers do not need to download or install Trivy or OSV-Scanner themselves.

For Windows x64 the extension pins and verifies:

- OSV-Scanner 2.6.0 — SHA-256 `e0ed7644118b717b028c249ee9d3515024e55e8510747ca08906eb96765354d6`;
- Trivy 0.74.0 Windows x64 archive — SHA-256 `94c40e0696e4b907a74b7b2e1438d5d72ebaca83115817407f568a002d520842`.

Provisioning rules:

- tools are stored under the VS Code extension `globalStorageUri`, not in the repository and not in system directories;
- every downloaded artifact is SHA-256 verified before use;
- Trivy is extracted only after its archive checksum passes;
- the extension prepends only its private tool directory to the child engine `PATH`;
- if provisioning is unavailable or blocked by a corporate proxy, the canonical VulnWeave core analysis still runs and external scanners are treated only as missing corroborators;
- `VulnWeave: Preparar scanners locais` can be run manually for diagnostics/retry;
- `vulnweave.tools.autoProvision` can disable automatic provisioning.

The application runtime/toolchain is a separate concern: remediation build/tests still need what the project itself requires (for example Node/npm, JDK/Maven or project wrappers). VulnWeave does not install a JDK or Node runtime on the developer machine.

### Data quality retained from 0.9.4

OSV `POST /v1/querybatch` is used only for advisory discovery. Every advisory ID is hydrated through `GET /v1/vulns/{id}` before severity, CVSS, aliases, fixed ranges, EPSS correlation, prioritization or remediation decisions are calculated.

When all applicable advisories publish fixed versions, VulnWeave derives the aggregate remediation target. Candidate validation remains read-only with respect to the frozen baseline.

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


## Remediação coordenada e validação diferencial — 0.10.1

A versão 0.10.1 deixa de tratar toda correção como troca isolada de um único pacote.

- Node/package-lock: o engine identifica cohorts acoplados por `peerDependencies` exatas e prepara a atualização coordenada dos pacotes diretamente declarados. O gate npm usa `--strict-peer-deps`; warnings `ERESOLVE overriding peer dependency` não são aceitos como um grafo seguro.
- Maven: propriedades compartilhadas, `dependencyManagement` local e artefatos do mesmo `groupId`/release explícito podem ser tratados como um conjunto coordenado. Parent/BOM externo sem ponto de controle local inequívoco continua bloqueado para correção automática.
- Build: o log preserva início e final e remove ANSI antes de renderizar. Se o build candidato falhar, o VulnWeave tenta reproduzir o build do baseline original em outra sandbox para distinguir regressão provável de falha preexistente/inconclusiva.
- Segurança: build/testes/rescan continuam obrigatórios para aplicação automática; uma comparação inconclusiva nunca libera aplicação.

## Maven Wrapper corporativo — 0.12.2
Se `mvnw`/`mvnw.cmd` existir mas não inicializar por `MavenWrapperMain` ausente ou bloqueio corporativo, o engine tenta um Maven do sistema/configurado somente quando sua versão coincide exatamente com a versão fixada em `.mvn/wrapper/maven-wrapper.properties`. Divergência de versão permanece bloqueante e aparece nos blockers.

## Scan 0.11 — evidence-first

A análise 0.11 preserva o grafo canônico para remediação e adiciona uma camada read-only de evidências: artifact inventory Java (JAR/WAR/EAR + nested JAR), importação real do JSON do OSV-Scanner e reconciliação com Trivy. Findings encontrados apenas em artefato ou scanner são exibidos para investigação, mas nunca autorizam alteração automática.
