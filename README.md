# VulnWeave Dependency Intelligence

VulnWeave is an IDE-native Software Composition Analysis (SCA) and guarded dependency-remediation project for **VS Code** and **JetBrains/IntelliJ**. It combines dependency discovery, vulnerability intelligence, risk context, compatibility evidence and an explicit remediation state machine.

> **Repository status**: the source archive provided for publication contains the **0.12.4 core and JetBrains source baseline**. The uploaded VS Code package exposes the **0.12.5 adapter source**, which is represented here. The exact 0.12.5 native-engine and JetBrains source used to build the uploaded binaries was not present in the supplied source archive, so this repository does not claim byte-for-byte reproducibility of those two 0.12.5 binaries. See `docs/SOURCE_PROVENANCE.md`.

## What it does

- Discovers Maven and Node/Angular dependency graphs.
- Correlates vulnerability intelligence from OSV and GitHub Security Advisories.
- Enriches findings with EPSS and CISA KEV context.
- Supports deep corroboration with OSV-Scanner and Trivy where provisioned.
- Produces SBOM/SARIF/VEX-oriented evidence.
- Distinguishes direct/transitive and runtime/test/dev dependency context where available.
- Validates candidate versions before remediation.
- Uses Compatibility Intelligence as evidence, not as a blind upgrade recommender.
- Generates a guarded remediation plan and diff before touching the real workspace.
- Validates changes in an isolated copy through dependency resolution, build, tests and rescan.
- Requires developer confirmation before applying an accepted plan.
- Supports optional AI review through GitHub Copilot, Anthropic Direct and Amazon Q Developer handoff/context.
- Supports read-only Veracode SCA correlation as corporate evidence.

## Architecture

```text
IDE adapter (VS Code / JetBrains)
            |
            v
      VulnWeave Core
        Go engine
            |
   +--------+---------+-------------------+
   |        |         |                   |
 dependency OSV/GHSA EPSS/CISA KEV   remediation
 discovery   intel    risk context      gates
   |                                      |
   +------------------+-------------------+
                      v
              compatibility evidence
                      |
                      v
             isolated validation
          resolve -> build -> test -> rescan
                      |
                      v
              developer confirmation
```

See `docs/ARCHITECTURE.md` for the technical model.

## Repository layout

```text
core/                Go native engine source baseline
vscode-extension/    VS Code adapter source
intellij-plugin/     JetBrains/IntelliJ adapter source baseline
scripts/             build and verification scripts
docs/                architecture, security and integration docs
.github/              CI and repository governance
```

Compiled engines, VSIX packages, JAR/ZIP distributions, local reports and secrets are deliberately excluded from source control.

## Quick verification

Requirements: Go 1.23+, Node.js 22+ and Java 21+ for JetBrains development.

```bash
./scripts/verify.sh
```

The current verification script runs Go tests/vet plus VS Code syntax/UI regression checks. JetBrains packaging requires Gradle and the IntelliJ Platform dependencies described in `intellij-plugin/build.gradle.kts`.

## Safe remediation model

The intended state transition is:

```text
finding
  -> candidate_checked
  -> plan_previewed
  -> isolated_validation
  -> ready_to_apply
  -> developer_confirmed
  -> applied
```

There is no supported direct transition from a candidate recommendation to workspace modification. AI output and registry metadata are advisory inputs; they do not satisfy compatibility gates.

## Security and privacy

Before using VulnWeave on confidential projects, review:

- `SECURITY.md`
- `PRIVACY.md`
- `docs/SECURITY_MODEL.md`
- `docs/AI_INTEGRATIONS.md`
- `docs/VERACODE_INTEGRATION.md`

Do not commit or paste real API keys, Veracode credentials, AI-provider tokens, private certificates or customer data into this repository.

## License

This repository is **source-available, not open source**. See `LICENSE`.
