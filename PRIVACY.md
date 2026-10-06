# Privacy and Data Flow

VulnWeave is designed around local project analysis, but some features query external services. Users must evaluate organizational policy before running the tool on confidential repositories.

## Local processing

The engine reads dependency manifests, lockfiles, project metadata and tool output required for dependency analysis and guarded remediation. Local reports and remediation state are normally stored under `.vulnweave/`.

## External vulnerability intelligence

Depending on the selected operation, package names, versions, ecosystems and vulnerability identifiers may be sent to public services such as OSV, GitHub Advisory, FIRST/EPSS, CISA KEV feeds and package registries. Private package identifiers can themselves be sensitive.

The VS Code adapter exposes configuration for private npm scopes and private Maven prefixes so those identifiers can be excluded from public lookups where the implementation supports it.

## AI integrations

AI is optional. GitHub Copilot uses the VS Code Language Model API when selected. Anthropic Direct requires an API key stored in the IDE secret store. Amazon Q Developer uses project rules and a sanitized local context handoff rather than a VulnWeave-managed API key.

Structured evidence can include package names, versions, advisories, candidate-validation results, remediation diffs and build/test output. Review organizational data-handling requirements before transmitting any of this information to a third party.

## Veracode

Veracode integration is read-only in the current design. Credentials are stored in the IDE secret store and are used to obtain an OAuth token and query SCA findings for the configured application. Findings are correlated locally with VulnWeave evidence.

## Retention

Local reports remain until the user or project automation removes them. Uninstalling an IDE plugin may not remove `.vulnweave/` content or credentials already stored by the IDE. External-provider retention follows the terms of those providers.
