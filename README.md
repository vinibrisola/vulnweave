# VulnWeave

VulnWeave is an IDE-native dependency security and remediation project for VS Code and JetBrains IDEs.

## Repository layout

- `vscode-extension/` — VS Code extension source
- `intellij-plugin/` — JetBrains/IntelliJ plugin source
- `docs/` — architecture and integration documentation
- `.github/` — repository automation and CI workflows

## Security

Do not commit API keys, Veracode credentials, AI provider tokens, private certificates, `.env` files, local caches, build outputs, or IDE-local configuration.

## Distribution

Compiled extension packages should be published through GitHub Releases rather than committed to the source tree.

## License

No open-source license is granted by this repository unless a license file is added explicitly.
