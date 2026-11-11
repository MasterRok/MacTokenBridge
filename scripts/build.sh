#!/bin/zsh
# Builds build/MacTokenBridge.app (universal: arm64 + x86_64) with the Command Line Tools only.
#
# Signing:
#   SIGN_IDENTITY unset  -> ad-hoc signature, fine for building and using it on this Mac
#   SIGN_IDENTITY="Developer ID Application: Name (TEAMID)" -> hardened runtime + timestamp,
#                           ready for notarization (see scripts/package.sh)
set -euo pipefail
cd "$(dirname "$0")/.."

APP=build/MacTokenBridge.app
APPEX=$APP/Contents/PlugIns/MacTokenBridgeToken.appex
OBJ=build/obj
SDK=$(xcrun --show-sdk-path)
ARCHS=(arm64 x86_64)
MIN_MACOS=14.0
VERSION=$(cat VERSION)
BUILD_NUMBER=$(git rev-list --count HEAD 2>/dev/null || echo 1)
TOKEN_ID=io.github.masterrok.MacTokenBridge.Token
IDENTITY=${SIGN_IDENTITY:--}

if [[ $IDENTITY == "-" ]]; then
	SIGN_FLAGS=()
else
	SIGN_FLAGS=(--options runtime --timestamp)
	TEAM_ID=$(print -r -- "$IDENTITY" | sed -n 's/.*(\([A-Z0-9]*\))$/\1/p')
	if [[ -z $TEAM_ID ]]; then
		echo "cannot read the team ID from SIGN_IDENTITY: $IDENTITY" >&2
		exit 1
	fi
fi

rm -rf "$APP" "$OBJ"
mkdir -p "$APP/Contents/MacOS" "$APPEX/Contents/MacOS" "$OBJ/gen"

plist() {
	sed -e "s/__VERSION__/$VERSION/" -e "s/__BUILD__/$BUILD_NUMBER/" "$1" > "$2"
}

# Token extension: sandboxed, runs inside macOS's CryptoTokenKit.
for arch in $ARCHS; do
	swiftc -O -sdk "$SDK" -target "$arch-apple-macos$MIN_MACOS" \
		-application-extension -module-name MacTokenBridgeToken \
		-Xlinker -e -Xlinker _NSExtensionMain \
		Sources/Token/*.swift Sources/Shared/*.swift \
		-o "$OBJ/token-$arch"
done
lipo -create "${ARCHS[@]/#/$OBJ/token-}" -output "$APPEX/Contents/MacOS/MacTokenBridgeToken"
plist Resources/Token/Info.plist "$APPEX/Contents/Info.plist"
codesign --force --sign "$IDENTITY" "${SIGN_FLAGS[@]}" --entitlements Resources/Token/Token.entitlements "$APPEX"

# The helper accepts XPC connections only from this extension.
if [[ $IDENTITY == "-" ]]; then
	# Ad-hoc code has no signing authority, so pin the exact build (one code hash per architecture).
	HASHES=()
	for arch in $ARCHS; do
		HASHES+=("cdhash H\\\"$(codesign -dvvv --arch "$arch" "$APPEX" 2>&1 | sed -n 's/^CDHash=//p')\\\"")
	done
	REQUIREMENT="identifier \\\"$TOKEN_ID\\\" and (${(j: or :)HASHES})"
else
	REQUIREMENT="anchor apple generic and identifier \\\"$TOKEN_ID\\\" and certificate leaf[subject.OU] = \\\"$TEAM_ID\\\""
fi
print -r -- "let tokenCodeRequirement = \"$REQUIREMENT\"" > "$OBJ/gen/BuildInfo.swift"

# App: installer, command line tool and the helper launchd runs.
for arch in $ARCHS; do
	clang -O2 -Wall -I Vendor -isysroot "$SDK" -target "$arch-apple-macos$MIN_MACOS" -c Sources/PKCS11/p11.c -o "$OBJ/p11-$arch.o"
	swiftc -O -sdk "$SDK" -target "$arch-apple-macos$MIN_MACOS" \
		-module-name MacTokenBridge \
		-import-objc-header Sources/PKCS11/p11.h \
		Sources/App/*.swift Sources/Shared/*.swift "$OBJ/gen/BuildInfo.swift" "$OBJ/p11-$arch.o" \
		-o "$OBJ/app-$arch"
done
lipo -create "${ARCHS[@]/#/$OBJ/app-}" -output "$APP/Contents/MacOS/MacTokenBridge"
plist Resources/App/Info.plist "$APP/Contents/Info.plist"
codesign --force --sign "$IDENTITY" "${SIGN_FLAGS[@]}" --entitlements Resources/App/App.entitlements "$APP"

codesign --verify --strict --verbose=1 "$APP"
echo "built $APP ($VERSION, signed by: $IDENTITY)"
