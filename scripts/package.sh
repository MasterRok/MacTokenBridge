#!/bin/zsh
# Builds a signed and notarized installer: build/MacTokenBridge-<version>.pkg
#
# Needs, in the login keychain:
#   APP_IDENTITY        e.g. "Developer ID Application: Name (TEAMID)"
#   INSTALLER_IDENTITY  e.g. "Developer ID Installer: Name (TEAMID)"
# and a notarytool profile (default name: MacTokenBridge), created once with
#   xcrun notarytool store-credentials MacTokenBridge --apple-id ... --team-id ...
set -euo pipefail
cd "$(dirname "$0")/.."

: ${APP_IDENTITY:?set APP_IDENTITY to your "Developer ID Application: ..." identity}
: ${INSTALLER_IDENTITY:?set INSTALLER_IDENTITY to your "Developer ID Installer: ..." identity}
NOTARY_PROFILE=${NOTARY_PROFILE:-MacTokenBridge}
VERSION=$(cat VERSION)
ROOT=build/pkgroot
COMPONENT=build/component.pkg
COMPONENT_PLIST=build/component.plist
PKG=build/MacTokenBridge-$VERSION.pkg

SIGN_IDENTITY="$APP_IDENTITY" scripts/build.sh

rm -rf "$ROOT" "$COMPONENT" "$COMPONENT_PLIST" "$PKG"
mkdir -p "$ROOT/Applications"
ditto build/MacTokenBridge.app "$ROOT/Applications/MacTokenBridge.app"

# Always install into /Applications, even if another copy of the app exists elsewhere.
pkgbuild --analyze --root "$ROOT" "$COMPONENT_PLIST"
plutil -replace 0.BundleIsRelocatable -bool NO "$COMPONENT_PLIST"

pkgbuild --root "$ROOT" --component-plist "$COMPONENT_PLIST" \
	--identifier io.github.masterrok.MacTokenBridge.pkg --version "$VERSION" \
	--scripts Resources/Installer --install-location / "$COMPONENT"
productbuild --package "$COMPONENT" --sign "$INSTALLER_IDENTITY" "$PKG"

xcrun notarytool submit "$PKG" --keychain-profile "$NOTARY_PROFILE" --wait
xcrun stapler staple "$PKG"
spctl --assess --type install --verbose "$PKG"
shasum -a 256 "$PKG"
echo "ready: $PKG"
