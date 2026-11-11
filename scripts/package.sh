#!/bin/zsh
# Builds a signed, notarized disk image: build/MacTokenBridge-<version>.dmg
#
# Needs, in the login keychain:
#   APP_IDENTITY    e.g. "Developer ID Application: Name (TEAMID)"
# and a notarytool profile (default name: MacTokenBridge), created once with
#   xcrun notarytool store-credentials MacTokenBridge --apple-id ... --team-id ...
# SKIP_NOTARIZE=1 builds and signs the image without notarizing (for local testing only).
set -euo pipefail
cd "$(dirname "$0")/.."

: ${APP_IDENTITY:?set APP_IDENTITY to your "Developer ID Application: ..." identity}
NOTARY_PROFILE=${NOTARY_PROFILE:-MacTokenBridge}
VERSION=$(cat VERSION)
STAGE=build/dmg
DMG=build/MacTokenBridge-$VERSION.dmg

SIGN_IDENTITY="$APP_IDENTITY" scripts/build.sh

rm -rf "$STAGE" "$DMG"
mkdir -p "$STAGE"
ditto build/MacTokenBridge.app "$STAGE/MacTokenBridge.app"
ln -s /Applications "$STAGE/Applications"
hdiutil create -quiet -volname "MacTokenBridge $VERSION" -srcfolder "$STAGE" -fs HFS+ -format UDZO "$DMG"
codesign --force --sign "$APP_IDENTITY" --timestamp "$DMG"

if [[ ${SKIP_NOTARIZE:-0} == 1 ]]; then
	echo "not notarized (SKIP_NOTARIZE=1): $DMG"
	exit 0
fi
xcrun notarytool submit "$DMG" --keychain-profile "$NOTARY_PROFILE" --wait
xcrun stapler staple "$DMG"
spctl --assess --type open --context context:primary-signature --verbose "$DMG"
shasum -a 256 "$DMG"
echo "ready: $DMG"
