#!/bin/zsh
# Builds MacTokenBridge from source and installs it for the current user (no admin rights needed).
# Extra arguments go to "MacTokenBridge install", e.g.: scripts/install.sh --module /path/to/pkcs11.dylib
set -euo pipefail
cd "$(dirname "$0")/.."

DEST=~/Applications/MacTokenBridge.app
LSREGISTER=/System/Library/Frameworks/CoreServices.framework/Frameworks/LaunchServices.framework/Support/lsregister

scripts/build.sh
mkdir -p ~/Applications
if [[ -x $DEST/Contents/MacOS/MacTokenBridge ]]; then
	# Stop the old helper cleanly before replacing its binary.
	launchctl bootout "gui/$(id -u)/io.github.masterrok.MacTokenBridge.Helper" 2>/dev/null || true
fi
rm -rf "$DEST"
cp -R build/MacTokenBridge.app "$DEST"
"$LSREGISTER" -f "$DEST"
pluginkit -a "$DEST/Contents/PlugIns/MacTokenBridgeToken.appex"
sleep 2
"$DEST/Contents/MacOS/MacTokenBridge" install "$@"
