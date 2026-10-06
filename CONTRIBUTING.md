# Contributing

1. Create a branch from `main`.
2. Do not commit secrets, customer-specific identifiers, generated reports or packaged binaries.
3. Run `./scripts/verify.sh` before opening a pull request.
4. Keep remediation fail-safe: recommendations must never bypass resolution/build/test/rescan gates.
5. Treat external advisory text, package metadata and AI output as untrusted input.
6. Document new outbound network calls and update `PRIVACY.md` when data flow changes.
7. Document release-impacting behavior in `CHANGELOG.md` or `docs/releases/`.
