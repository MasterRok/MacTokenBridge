#!/bin/zsh
# Rebuilds Resources/App/AppIcon.icns from the SVG artwork in Resources/Icon.
# Run it after editing the artwork and commit the result; scripts/build.sh only copies the .icns.
#
# AppIcon.svg is the master. The two smallest pixel sizes have their own simplified drawings,
# because the master turns to mud when scaled that far down.
set -euo pipefail
cd "$(dirname "$0")/.."

SRC=Resources/Icon
SET=build/AppIcon.iconset
OUT=Resources/App/AppIcon.icns

rm -rf "$SET"
mkdir -p "$SET"

# iconset file name -> pixel size
SIZES=(
	icon_16x16 16 icon_16x16@2x 32
	icon_32x32 32 icon_32x32@2x 64
	icon_128x128 128 icon_128x128@2x 256
	icon_256x256 256 icon_256x256@2x 512
	icon_512x512 512 icon_512x512@2x 1024
)
JOBS=()
for name px in $SIZES; do
	case $px in
		16) art=$SRC/AppIcon-16.svg ;;
		32) art=$SRC/AppIcon-32.svg ;;
		*) art=$SRC/AppIcon.svg ;;
	esac
	JOBS+=("$art" "$SET/$name.png" "$px")
done
swift scripts/render-svg.swift "${JOBS[@]}"

iconutil --convert icns --output "$OUT" "$SET"
echo "built $OUT"
