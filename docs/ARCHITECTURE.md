# Architecture

## Components

### Core engine

The Go core owns dependency discovery, vulnerability enrichment, candidate semantics, compatibility evidence, remediation planning, isolated execution and machine-readable reports. IDE adapters call the engine through a stable JSON CLI boundary.

Primary commands:

- `scan`
- `validate-candidate`
- `plan-fix`
- `execute-plan`
- `apply-plan`
- `detect`
- `version`

### VS Code adapter

The Node/VS Code adapter owns WebView UX, Workspace Trust enforcement, SecretStorage, optional AI-provider orchestration, tool provisioning and Veracode configuration/correlation.

### JetBrains adapter

The Java/Swing adapter owns Tool Window UX, PasswordSafe integration, engine process orchestration, AI handoff/direct-provider configuration and Veracode correlation.

## Evidence pipeline

```text
manifest / lockfile / packaged artifacts
              |
              v
       dependency discovery
              |
      +-------+---------+
      |                 |
      v                 v
  OSV / GHSA      corroborating scanners
      |            OSV-Scanner / Trivy
      +-------+---------+
              |
              v
       CVSS / EPSS / KEV
              |
              v
    directness / scope / path
              |
              v
   Compatibility Intelligence
              |
              v
       candidate validation
              |
              v
       remediation plan
              |
              v
  isolated resolve/build/test/rescan
              |
              v
      developer confirmation
```

## State machine

`finding -> candidate_checked -> plan_previewed -> isolated_validation -> ready_to_apply -> developer_confirmed -> applied`

No AI response, advisory metadata or registry lookup can jump directly to `ready_to_apply` or `applied`.

## Fail-safe design

Ambiguous control points, incomplete dependency resolution, peer conflicts, build failures, test failures, stale manifests or incomplete scan coverage are treated as blockers/inconclusive evidence rather than silently accepted compatibility.
