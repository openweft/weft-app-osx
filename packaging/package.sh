#!/usr/bin/env -S pkgx bash
# Assemble Weft.app from a built weft-app-osx binary.
#
# Usage:  packaging/package.sh [output-dir]
#
# Produces <output-dir>/Weft.app — a menu-bar agent bundle (LSUIElement).
# Code-signing and notarization are intentionally left to CI (they need
# secrets); this script only assembles the bundle, so it runs unsigned for
# local testing.
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
root="$(cd "$here/.." && pwd)"
out="${1:-$root/dist}"
app="$out/Weft.app"

echo "==> building binary"
ver="$(cd "$root" && git describe --tags --always --dirty 2>/dev/null || echo dev)"
commit="$(cd "$root" && git rev-parse --short HEAD 2>/dev/null || echo none)"
date="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
( cd "$root" && CGO_ENABLED=1 go build \
    -ldflags "-X main.version=$ver -X main.commit=$commit -X main.date=$date" \
    -o "$root/weft-app-osx" . )

echo "==> assembling $app"
rm -rf "$app"
mkdir -p "$app/Contents/MacOS" "$app/Contents/Resources"

cp "$here/Info.plist" "$app/Contents/Info.plist"
cp "$root/weft-app-osx" "$app/Contents/MacOS/weft-app-osx"
printf 'APPL????' > "$app/Contents/PkgInfo"

# icon.png -> icon.icns via a proper .iconset (iconutil is the reliable
# path; `sips -s format icns` fails on large/ARGB sources). Falls back to
# copying the png if the tools are unavailable.
if command -v iconutil >/dev/null 2>&1 && command -v sips >/dev/null 2>&1; then
  iconset="$(mktemp -d)/icon.iconset"
  mkdir -p "$iconset"
  for s in 16 32 128 256 512; do
    sips -z "$s" "$s" "$root/assets/icon.png" --out "$iconset/icon_${s}x${s}.png" >/dev/null
    d=$((s * 2))
    sips -z "$d" "$d" "$root/assets/icon.png" --out "$iconset/icon_${s}x${s}@2x.png" >/dev/null
  done
  iconutil -c icns "$iconset" -o "$app/Contents/Resources/icon.icns"
  rm -rf "$(dirname "$iconset")"
else
  cp "$root/assets/icon.png" "$app/Contents/Resources/icon.png"
fi

echo "==> done: $app"
echo "    code-sign + notarize in CI, e.g.:"
echo "    codesign --deep --options runtime --sign \"Developer ID Application: …\" \"$app\""
echo "    xcrun notarytool submit … && xcrun stapler staple \"$app\""
