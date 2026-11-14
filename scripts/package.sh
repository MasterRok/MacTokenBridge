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
RW_DMG=build/dmg-rw.dmg
DMG=build/MacTokenBridge-$VERSION.dmg

SIGN_IDENTITY="$APP_IDENTITY" scripts/build.sh

rm -rf "$STAGE" "$RW_DMG" "$DMG"
mkdir -p "$STAGE"
ditto build/MacTokenBridge.app "$STAGE/MacTokenBridge.app"
ln -s /Applications "$STAGE/Applications"
cp Resources/App/AppIcon.icns "$STAGE/.VolumeIcon.icns"

# Finder shows .VolumeIcon.icns only if the volume's root folder is flagged as having a custom icon,
# and hdiutil does not carry that flag over from the source folder. So: make a writable image,
# set the flag on the mounted volume, then compress it.
hdiutil create -quiet -volname "MacTokenBridge $VERSION" -srcfolder "$STAGE" -fs HFS+ -format UDRW "$RW_DMG"
MOUNT=$(mktemp -d)
hdiutil attach -quiet -nobrowse -noautoopen -mountpoint "$MOUNT" "$RW_DMG"
SetFile -a C "$MOUNT"
hdiutil detach -quiet "$MOUNT"
rmdir "$MOUNT"
hdiutil convert -quiet "$RW_DMG" -format UDZO -o "$DMG"
rm "$RW_DMG"
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
