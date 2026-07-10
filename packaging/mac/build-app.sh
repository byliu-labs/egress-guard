#!/usr/bin/env bash
# Assemble bin/EgressGuard.app: an unsigned (Tier A) menu-bar bundle.
# To upgrade to Tier C (signed + notarized) later, fill in DEVELOPER_ID and
# uncomment the codesign / notarytool blocks below; no other change needed.
set -euo pipefail
cd "$(dirname "$0")/../.."

APP="bin/EgressGuard.app"
RES="$APP/Contents/Resources"
MACOS="$APP/Contents/MacOS"

[ -x bin/egress-guard ]     || { echo "build bin/egress-guard first (make build)"; exit 1; }
[ -x bin/egress-guard-bar ] || { echo "build bin/egress-guard-bar first (make bar)"; exit 1; }

if [ -e "$APP" ]; then
  mv "$APP" "/tmp/EgressGuard.app.previous.$$"
fi
mkdir -p "$RES" "$MACOS"
cp packaging/mac/Info.plist "$APP/Contents/Info.plist"
cp bin/egress-guard-bar "$MACOS/egress-guard-bar"
cp bin/egress-guard     "$RES/egress-guard"
cp bin/egress-guard-bar "$RES/egress-guard-bar"
chmod +x "$MACOS/egress-guard-bar" "$RES/egress-guard" "$RES/egress-guard-bar"

# ---- Tier C hooks (require a paid Apple Developer ID; leave disabled for now) ----
# DEVELOPER_ID="Developer ID Application: Your Name (TEAMID)"
# codesign --force --deep --options runtime --sign "$DEVELOPER_ID" "$APP"
# ditto -c -k --keepParent "$APP" bin/EgressGuard.zip
# xcrun notarytool submit bin/EgressGuard.zip --keychain-profile eg-notary --wait
# xcrun stapler staple "$APP"
# ---------------------------------------------------------------------------------

echo "Built $APP (unsigned: first launch needs right-click -> Open once)"
