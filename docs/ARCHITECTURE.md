# VulnWeave Architecture

VulnWeave provides dependency intelligence and remediation assistance inside developer IDEs.

## Target IDEs

- Visual Studio Code
- JetBrains / IntelliJ IDEA

## Security intelligence sources

The platform may consume vulnerability and exploitation intelligence from sources such as:

- OSV
- GitHub Security Advisories
- EPSS
- CISA KEV
- deps.dev
- Veracode, when configured

## High-level flow

```
Project manifest / lockfile
        |
        v
Dependency discovery
        |
        v
Vulnerability enrichment
        |
        +--> OSV / GHSA
        +--> EPSS
        +--> CISA KEV
        +--> deps.dev
        +--> Veracode (optional)
        |
        v
Risk prioritization
        |
        v
Compatibility intelligence
        |
        v
Remediation recommendation
        |
        v
Developer review
        |
        v
Build / test / rescan
```

## Local-first principle

Project source code should remain local unless a feature explicitly requires communication with an external provider. Integrations must minimize transmitted data and must not expose secrets in logs.
