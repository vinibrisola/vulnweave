# Development and Installation

## Source prerequisites

- Go 1.23+
- Node.js 22+
- Java 21+
- Gradle for JetBrains plugin development

## Verify source

```bash
./scripts/verify.sh
```

## Build native engines

```bash
./scripts/build-core.sh
```

This creates platform binaries and copies them into the adapter packaging directories. Build outputs are intentionally ignored by Git.

## VS Code

After the engine binaries are present under `vscode-extension/bin/`, package the extension with the standard VS Code extension tooling used by your release process. Packaged `.vsix` files belong in GitHub Releases, not in normal source commits.

## JetBrains

The JetBrains adapter is configured in `intellij-plugin/build.gradle.kts`. Build/package with an approved Gradle environment and validate against the target IntelliJ Platform before release.
