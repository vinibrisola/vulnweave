# Source and Artifact Provenance

This repository was prepared from three supplied artifacts:

| Artifact | Version | SHA-256 | Publication status |
|---|---:|---|---|
| Source archive | 0.12.4 | `2cb25f30c6aed4fd17efccadcaa2ce44f8d8a15957d4e362dbc5b34626b59c61` | Source baseline imported |
| VS Code VSIX | 0.12.5 | `a9e4b585c1995c5972d36391ae557a62ecfa0ce252a6107899ee64ca8e6aee58` | Adapter source inspected; binary not committed |
| JetBrains Marketplace ZIP | 0.12.5 | `51e983df4289c10054d98188738fcfd7c6c0ec28183e8868542cc5bde6eaebae` | Binary inspected; binary not committed |

## Version-alignment finding

The provided source archive identifies the native engine and JetBrains adapter as 0.12.4. The uploaded 0.12.5 VSIX contains a 0.12.5 adapter and different native-engine binaries. The uploaded JetBrains package also identifies itself as 0.12.5.

Because the exact 0.12.5 engine/JetBrains source was not supplied, the repository does **not** relabel the 0.12.4 source as 0.12.5. Doing so would create false provenance.

## Public-release gate

The supplied 0.12.5 binary packages were intentionally not committed to the public source tree. Review found a customer/project-specific path marker embedded in the packaged engine. A sanitized rebuild from source should be produced before those binaries are published as public release assets.
