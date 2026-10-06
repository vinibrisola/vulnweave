# Compatibility Intelligence

Compatibility Intelligence is the evidence layer used to answer a narrower question than vulnerability detection: **is the proposed dependency version a defensible candidate to validate?**

It is not a machine-learning score that automatically proves an upgrade safe.

## Inputs

Depending on ecosystem and available evidence, the engine can consider:

- current and candidate versions;
- vulnerability fixed versions;
- package-registry availability;
- dependency graph position and direct/transitive status;
- peer dependency constraints;
- Maven property/parent/BOM control points;
- known coordinated release cohorts such as tightly coupled Angular packages;
- build and test outcomes;
- rescan results;
- corroborating vulnerability sources.

## Validation model

A candidate passes through separate phases:

1. **Candidate eligibility** — version exists and does not represent an unsafe downgrade.
2. **Control-point analysis** — the tool must know which manifest/property it can safely change.
3. **Plan preview** — the proposed diff is shown before execution.
4. **Isolated resolution** — lockfile/dependency graph must resolve coherently.
5. **Build and tests** — project-defined gates execute in the sandbox when enabled.
6. **Rescan** — a fresh scan checks the candidate state.
7. **Apply gate** — only a successful, stable execution becomes `readyToApply`.
8. **Developer confirmation** — the real workspace is changed only after explicit confirmation.

## Role of AI

AI can review blast radius, potential breaking changes and missing tests. It is advisory. Compatibility is established by deterministic project evidence, not by an LLM saying that an upgrade "looks safe".
