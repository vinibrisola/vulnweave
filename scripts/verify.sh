#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
(cd "$ROOT/core" && go test ./... && go vet ./...)
node --check "$ROOT/vscode-extension/extension.js"
node "$ROOT/vscode-extension/ui-test.js"
python -m json.tool "$ROOT/vscode-extension/package.json" >/dev/null
echo "Core tests/vet + VS Code syntax checks passed."
