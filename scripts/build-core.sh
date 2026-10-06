#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT/core"
go test ./...
mkdir -p dist
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -buildvcs=false -trimpath -ldflags='-s -w' -o dist/vulnweave-engine-linux-amd64 .
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -buildvcs=false -trimpath -ldflags='-s -w' -o dist/vulnweave-engine-linux-arm64 .
CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -buildvcs=false -trimpath -ldflags='-s -w' -o dist/vulnweave-engine-windows-amd64.exe .
CGO_ENABLED=0 GOOS=darwin GOARCH=amd64 go build -buildvcs=false -trimpath -ldflags='-s -w' -o dist/vulnweave-engine-darwin-amd64 .
CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 go build -buildvcs=false -trimpath -ldflags='-s -w' -o dist/vulnweave-engine-darwin-arm64 .
cp -f dist/* "$ROOT/vscode-extension/bin/"
cp -f dist/* "$ROOT/intellij-plugin/resources/bin/"
