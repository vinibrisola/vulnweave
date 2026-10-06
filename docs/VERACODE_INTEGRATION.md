# Veracode SCA Integration

## Purpose

Veracode is used as **corporate SCA evidence** alongside VulnWeave's local analysis. It is not used as proof that a proposed dependency upgrade is compatible.

## Authentication

The current adapters use OAuth 2.0 Client Credentials for the configured Veracode region. Credentials are stored in the IDE secret store.

## Flow

1. Configure region, OAuth Client ID and Client Secret.
2. Associate the workspace with an Application Profile/GUID.
3. Obtain an OAuth access token.
4. Query SCA findings for the application.
5. Correlate VulnWeave findings primarily by CVE and available component/version evidence.
6. Surface corporate status/policy context in the workbench.

## Read-only boundary

The integration is intentionally read-only. It does not:

- start a Veracode scan;
- upload binaries;
- approve mitigations or waivers;
- change finding state;
- modify policies;
- replace local resolution/build/test/rescan validation.
