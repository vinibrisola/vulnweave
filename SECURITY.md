# Security Policy

## Reporting vulnerabilities

Do not disclose security vulnerabilities, API keys, credentials, customer data, or sensitive integration details through public GitHub Issues.

Report security concerns directly to the project maintainers through an approved private channel.

## Secret handling

The repository must not contain:

- Veracode API credentials
- AI provider API keys
- GitHub or CI/CD tokens
- passwords
- private keys or certificates
- production URLs containing credentials
- .env files with real values
- customer or internal infrastructure data

Use environment variables, IDE secure storage, GitHub Secrets, or enterprise secret-management mechanisms.

## Dependency security

Dependencies should be reviewed and scanned before release. Security fixes should be validated through build/test and a new vulnerability scan before publication.
