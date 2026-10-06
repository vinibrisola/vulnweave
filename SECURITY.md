# Security Policy

## Reporting security issues

Do not publish exploitable vulnerabilities, credentials, customer data or sensitive integration details in a public GitHub issue. Use a private, authorized communication channel with the maintainer.

## Secrets

Never commit:

- Veracode client IDs/secrets or API credentials;
- AI provider API keys;
- GitHub/CI tokens;
- passwords;
- private keys/certificates;
- `.env` files containing real values;
- customer identifiers, internal URLs or confidential reports.

Runtime integrations should use the IDE secret stores or an approved enterprise secret-management mechanism.

## Trust boundaries

Dependency names, versions, advisories, build logs and manifest content are treated as untrusted data. AI prompts must not interpret embedded package/advisory text as instructions. Generated remediation must still pass deterministic technical gates.

## Public-repository release gate

Before publishing a binary release:

1. run secret scanning over source and packaged artifacts;
2. search binaries/docs for customer names and project-specific paths;
3. verify source/binary version alignment;
4. run tests and package validation;
5. generate SHA-256 checksums;
6. review third-party notices and data-flow documentation.
