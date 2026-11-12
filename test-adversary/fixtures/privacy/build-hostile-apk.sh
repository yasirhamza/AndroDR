#!/usr/bin/env bash
# Builds the privacy-scan adversary fixtures: small signed APKs that a privacy scan must report
# correctly, including ones built to break the dex reader. See README.md for the expected results.
#
#   ANDROID_HOME=~/Android/Sdk JAVA_HOME=<jdk21> ./build-hostile-apk.sh   -> out/*.apk
set -euo pipefail
cd "$(dirname "$0")"

: "${ANDROID_HOME:?set ANDROID_HOME}"
BT="${BUILD_TOOLS:-$(ls -d "$ANDROID_HOME"/build-tools/* | sort -V | tail -1)}"
PLATFORM="${PLATFORM_JAR:-$(ls -d "$ANDROID_HOME"/platforms/android-* | sort -V | tail -1)/android.jar}"
KEYSTORE="${KEYSTORE:-$HOME/.android/debug.keystore}"
JAVAC="${JAVA_HOME:+$JAVA_HOME/bin/}javac"

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
rm -rf out && mkdir -p out

# manifest <dir> <package> <label>
manifest() {
    cat > "$1/AndroidManifest.xml" <<EOF
<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="$2">
    <uses-sdk android:minSdkVersion="26" android:targetSdkVersion="34" />
    <application android:label="$3" />
</manifest>
EOF
}

# dex_of <outdir> <class FQN>...  -> <outdir>/classes.dex holding one empty class per name
dex_of() {
    local out="$1"; shift
    local src="$WORK/src-$RANDOM" cls="$WORK/cls-$RANDOM"
    mkdir -p "$src" "$cls" "$out"
    for fqn in "$@"; do
        local pkg="${fqn%.*}" name="${fqn##*.}"
        mkdir -p "$src/${pkg//.//}"
        printf 'package %s;\npublic class %s {}\n' "$pkg" "$name" > "$src/${pkg//.//}/$name.java"
    done
    find "$src" -name '*.java' -print0 | xargs -0 "$JAVAC" --release 8 -nowarn -d "$cls" 2>/dev/null
    find "$cls" -name '*.class' -print0 | xargs -0 "$BT/d8" --min-api 26 --output "$out"
}

# apk <name> <package> <label> <dex-dir> [extra-file-in-zip:as-name]...
apk() {
    local name="$1" pkg="$2" label="$3" dexdir="$4"; shift 4
    local d="$WORK/$name"
    mkdir -p "$d/zip"
    manifest "$d" "$pkg" "$label"
    "$BT/aapt2" link --manifest "$d/AndroidManifest.xml" -I "$PLATFORM" -o "$d/base.apk"
    cp "$dexdir"/classes*.dex "$d/zip/"
    for extra in "$@"; do cp "${extra%%:*}" "$d/zip/${extra##*:}"; done
    (cd "$d/zip" && zip -q -X "$d/base.apk" classes*.dex)
    "$BT/zipalign" -f -p 4 "$d/base.apk" "$d/aligned.apk"
    "$BT/apksigner" sign --ks "$KEYSTORE" --ks-pass pass:android --key-pass pass:android \
        --out "out/$name.apk" "$d/aligned.apk"
    echo "built out/$name.apk"
}

# 1. Positive: Facebook Ads (Advertisement, refused by default) + Firebase Analytics in code.
dex_of "$WORK/dex-pos" com.facebook.ads.internal.AdLoader com.google.firebase.analytics.FirebaseAnalytics \
    com.androdr.fixture.trackers.Main
apk privacy-positive com.androdr.fixture.privacy.positive "Privacy Fixture Trackers" "$WORK/dex-pos"

# 2. Negative: no registry tracker in code.
dex_of "$WORK/dex-neg" com.androdr.fixture.clean.Main com.androdr.fixture.clean.util.Helper
apk privacy-negative com.androdr.fixture.privacy.negative "Privacy Fixture Clean" "$WORK/dex-neg"

# 3. Corrupt second dex: a valid classes.dex with a tracker + a classes2.dex that is a dex header followed by junk.
python3 -I - "$WORK/corrupt.dex" <<'PY'
import os, sys
with open(sys.argv[1], "wb") as f:
    f.write(b"dex\n035\x00" + os.urandom(4096))
PY
dex_of "$WORK/dex-cor" com.facebook.ads.internal.AdLoader com.androdr.fixture.corrupt.Main
apk privacy-corrupt-dex com.androdr.fixture.privacy.corrupt "Privacy Fixture Corrupt Dex" "$WORK/dex-cor" \
    "$WORK/corrupt.dex:classes2.dex"

# 4. Dex bomb: a 40 MiB classes2.dex of zeros (compresses to ~40 KiB) behind a valid classes.dex with a tracker.
python3 -I - "$WORK/bomb.dex" <<'PY'
import sys
with open(sys.argv[1], "wb") as f:
    f.write(b"dex\n035\x00")
    f.write(b"\x00" * (40 * 1024 * 1024))
PY
dex_of "$WORK/dex-bomb" com.facebook.ads.internal.AdLoader com.androdr.fixture.bomb.Main
apk privacy-dex-bomb com.androdr.fixture.privacy.bomb "Privacy Fixture Dex Bomb" "$WORK/dex-bomb" \
    "$WORK/bomb.dex:classes2.dex"


# 5. Hostile label: a right-to-left override and a line break in the label, worded like a warning, with a
#    tracker in code. Every screen and the Timeline must show it cleaned ("Bankevil Spyware detected").
dex_of "$WORK/dex-label" com.facebook.ads.internal.AdLoader com.androdr.fixture.label.Main
apk privacy-hostile-label com.androdr.fixture.privacy.label "Bank&#x202E;evil&#10;Spyware detected" "$WORK/dex-label"

# 6. Flood: no tracker in code. seed-dns-flood.sh gives it 25,000 junk tracker lookups in the DNS log.
dex_of "$WORK/dex-flood" com.androdr.fixture.flood.Main
apk privacy-flood com.androdr.fixture.privacy.flood "Privacy Fixture Flood" "$WORK/dex-flood"

sha256sum out/*.apk
