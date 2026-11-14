#!/bin/zsh
# Builds and runs the unit tests for Sources/Shared (Tests/main.swift is the runner).
# Exits non-zero if the build or any check fails.
set -euo pipefail
cd "$(dirname "$0")/.."

mkdir -p build
swiftc -sdk "$(xcrun --show-sdk-path)" -module-name MacTokenBridgeTests \
	Sources/Shared/*.swift Tests/*.swift \
	-o build/tests
build/tests
