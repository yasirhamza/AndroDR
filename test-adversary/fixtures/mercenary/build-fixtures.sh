#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"

JAVA_HOME="${JAVA_HOME:-/home/yasir/Applications/android-studio/jbr}"
export JAVA_HOME
export PATH="$JAVA_HOME/bin:$PATH"

# Create local.properties if missing
if [ ! -f local.properties ]; then
    if [ -z "${ANDROID_HOME:-}" ]; then
        echo "ERROR: ANDROID_HOME not set and no local.properties found" >&2
        exit 1
    fi
    echo "sdk.dir=$ANDROID_HOME" > local.properties
    echo "Created local.properties with sdk.dir=$ANDROID_HOME"
fi

# Generate cert-hash-ioc signing key if it doesn't exist
KEYSTORE="cert-hash-ioc-keystore.jks"
if [ ! -f "$KEYSTORE" ]; then
    echo "Generating signing key for cert-hash-ioc fixture..."
    keytool -genkeypair -v \
        -keystore "$KEYSTORE" \
        -alias cert-hash-test \
        -keyalg RSA -keysize 2048 \
        -validity 10000 \
        -storepass adversary-test \
        -keypass adversary-test \
        -dname "CN=Adversary Test, O=AndroDR Fixtures"
fi

# Build all modules
echo "Building fixture APKs..."
./gradlew assembleDebug --quiet 2>/dev/null || ./gradlew assembleDebug

# Copy APKs and print SHA256 hashes
MODULES=(
    "spyware-package-name"
    "cert-hash-ioc"
    "accessibility-abuse"
    "device-admin-abuse"
    "surveillance-permissions"
    "system-name-disguise"
    "impersonation-play-store"
    "multi-abuse-combo"
    "firmware-implant-sim"
    "notification-listener-abuse"
)

echo ""
echo "=== Fixture APKs ==="
for mod in "${MODULES[@]}"; do
    src="${mod}/build/outputs/apk/debug/${mod}-debug.apk"
    dest="${mod}.apk"
    if [ -f "$src" ]; then
        cp "$src" "$dest"
        hash=$(sha256sum "$dest" | awk '{print $1}')
        echo "$dest  sha256:$hash"
    else
        echo "WARNING: $src not found" >&2
    fi
done

# Print cert hash for cert-hash-ioc APK
echo ""
echo "=== Cert Hash for IOC DB Seeding ==="
keytool -printcert -jarfile cert-hash-ioc.apk 2>/dev/null | grep "SHA256:" | head -1 || \
    echo "WARNING: Could not extract cert hash from cert-hash-ioc.apk"

echo ""
echo "Done. Update manifest.yml sha256 fields with the hashes above."
