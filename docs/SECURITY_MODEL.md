# Security Model

## Assets

- source code and manifests in the developer workspace;
- dependency and vulnerability reports;
- IDE-stored credentials;
- remediation plans/diffs;
- build and test output;
- corporate SCA context.

## Trust boundaries

1. **Workspace** — potentially untrusted project files and scripts.
2. **External intelligence** — OSV, GHSA, EPSS, KEV and package registries return untrusted network data.
3. **AI providers** — optional third-party processing boundary.
4. **Veracode** — authenticated enterprise API boundary.
5. **Sandbox execution** — isolated copy of the project, but not a hardened container/security boundary.

## Controls

- Workspace Trust before tool execution in VS Code.
- SecretStorage/PasswordSafe for credentials.
- no secret values in reports or logs by design;
- HTML escaping/CSP in WebView rendering;
- private-package filtering controls;
- deterministic remediation state machine;
- diff preview before execution;
- manifest hash/staleness checks;
- isolated dependency resolution/build/tests/rescan;
- explicit developer confirmation before real-workspace mutation.

## Non-goals

VulnWeave is an SCA/remediation assistant. It does not prove code-path reachability, replace SAST/DAST/pentesting, or make AI output a security control.
