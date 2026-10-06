# Public Release Checklist

Before publishing a VSIX or JetBrains ZIP:

- [ ] exact source version exists in the repository;
- [ ] source and package version strings match;
- [ ] Go tests and `go vet` pass;
- [ ] VS Code syntax/UI tests pass;
- [ ] JetBrains plugin compiles and Plugin Verifier is reviewed;
- [ ] no customer/project-specific names or paths exist in source, docs, binaries or strings;
- [ ] no secrets/credentials exist in source or packaged artifacts;
- [ ] third-party notices are current;
- [ ] privacy/data-flow documentation matches outbound calls;
- [ ] SHA-256 hashes are generated for release artifacts;
- [ ] release notes describe security-impacting changes;
- [ ] a clean install test succeeds on each supported IDE/platform class.
