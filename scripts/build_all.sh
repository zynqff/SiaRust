#!/bin/bash
# build_all.sh — Build GuardLib for all supported targets
#
# Requirements:
#   - Rust toolchain (rustup)
#   - Android NDK (for Android targets) — set ANDROID_NDK_HOME
#   - Xcode (for iOS targets) — macOS only
#   - cross (optional, for easier cross-compilation): cargo install cross
#
# Usage:
#   ./scripts/build_all.sh              # Build for host only
#   ./scripts/build_all.sh android      # Android only
#   ./scripts/build_all.sh ios          # iOS only (macOS required)
#   ./scripts/build_all.sh all          # All platforms

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
OUT_DIR="$PROJECT_DIR/dist"

echo "═══════════════════════════════════════════════════════"
echo "  GuardLib Build System"
echo "═══════════════════════════════════════════════════════"
echo ""

mkdir -p "$OUT_DIR"

TARGET="${1:-host}"

# ── Host (current machine) ────────────────────────────────────────────────────

build_host() {
    echo "▶ Building for host..."
    cd "$PROJECT_DIR"
    cargo build --release
    local ext
    case "$(uname -s)" in
        Linux)  ext="so" ;;
        Darwin) ext="dylib" ;;
        CYGWIN*|MINGW*) ext="dll" ;;
    esac
    mkdir -p "$OUT_DIR/host"
    cp "target/release/libguardlib.$ext" "$OUT_DIR/host/" 2>/dev/null || \
    cp "target/release/guardlib.$ext" "$OUT_DIR/host/" 2>/dev/null || true
    cp "target/release/libguardlib.a" "$OUT_DIR/host/" 2>/dev/null || true
    echo "✅ Host build done → dist/host/"
}

# ── Android ───────────────────────────────────────────────────────────────────

build_android() {
    echo "▶ Building for Android..."

    if [ -z "$ANDROID_NDK_HOME" ]; then
        echo "❌ ANDROID_NDK_HOME not set. Export it first:"
        echo "   export ANDROID_NDK_HOME=/path/to/ndk"
        exit 1
    fi

    # Add targets
    rustup target add \
        aarch64-linux-android \
        armv7-linux-androideabi \
        x86_64-linux-android \
        i686-linux-android 2>/dev/null || true

    # Configure linkers via .cargo/config.toml (see scripts/setup_android_linkers.sh)
    if [ ! -f "$PROJECT_DIR/.cargo/config.toml" ]; then
        echo "⚠️  .cargo/config.toml not found. Run: ./scripts/setup_android_linkers.sh"
        exit 1
    fi

    cd "$PROJECT_DIR"

    local targets=(
        "aarch64-linux-android:arm64-v8a"
        "armv7-linux-androideabi:armeabi-v7a"
        "x86_64-linux-android:x86_64"
        "i686-linux-android:x86"
    )

    for entry in "${targets[@]}"; do
        local rust_target="${entry%%:*}"
        local android_abi="${entry##*:}"
        echo "  Building $android_abi ($rust_target)..."
        cargo build --release --target "$rust_target"
        mkdir -p "$OUT_DIR/android/jniLibs/$android_abi"
        cp "target/$rust_target/release/libguardlib.so" \
           "$OUT_DIR/android/jniLibs/$android_abi/libguardlib.so"
        echo "  ✅ $android_abi done"
    done

    echo "✅ Android build done → dist/android/jniLibs/"
    echo ""
    echo "   Copy to your project:"
    echo "   cp -r dist/android/jniLibs/ android/app/src/main/"
}

# ── iOS ───────────────────────────────────────────────────────────────────────

build_ios() {
    echo "▶ Building for iOS..."

    if [[ "$(uname -s)" != "Darwin" ]]; then
        echo "❌ iOS build requires macOS"
        exit 1
    fi

    rustup target add \
        aarch64-apple-ios \
        aarch64-apple-ios-sim \
        x86_64-apple-ios 2>/dev/null || true

    cd "$PROJECT_DIR"

    echo "  Building device (aarch64-apple-ios)..."
    cargo build --release --target aarch64-apple-ios

    echo "  Building simulator (aarch64-apple-ios-sim)..."
    cargo build --release --target aarch64-apple-ios-sim

    echo "  Building simulator x86_64 (aarch64-apple-ios-sim)..."
    cargo build --release --target x86_64-apple-ios

    mkdir -p "$OUT_DIR/ios"

    # Device library
    cp "target/aarch64-apple-ios/release/libguardlib.a" "$OUT_DIR/ios/libguardlib-device.a"

    # Simulator fat binary (arm64 sim + x86_64 sim)
    lipo -create \
        "target/aarch64-apple-ios-sim/release/libguardlib.a" \
        "target/x86_64-apple-ios/release/libguardlib.a" \
        -output "$OUT_DIR/ios/libguardlib-simulator.a"

    # Create XCFramework (recommended for distribution)
    rm -rf "$OUT_DIR/ios/GuardLib.xcframework"
    xcodebuild -create-xcframework \
        -library "$OUT_DIR/ios/libguardlib-device.a" \
        -headers "$PROJECT_DIR" \
        -library "$OUT_DIR/ios/libguardlib-simulator.a" \
        -headers "$PROJECT_DIR" \
        -output "$OUT_DIR/ios/GuardLib.xcframework"

    echo "✅ iOS build done → dist/ios/"
    echo "   Add GuardLib.xcframework to your Xcode project."
}

# ── Linux server ──────────────────────────────────────────────────────────────

build_linux() {
    echo "▶ Building for Linux (x86_64)..."
    cd "$PROJECT_DIR"
    cargo build --release --target x86_64-unknown-linux-gnu 2>/dev/null || \
    cargo build --release
    mkdir -p "$OUT_DIR/linux"
    cp target/release/libguardlib.so "$OUT_DIR/linux/" 2>/dev/null || \
    cp target/x86_64-unknown-linux-gnu/release/libguardlib.so "$OUT_DIR/linux/" 2>/dev/null || true
    echo "✅ Linux build done → dist/linux/"
}

# ── Windows ───────────────────────────────────────────────────────────────────

build_windows() {
    echo "▶ Building for Windows (x86_64)..."
    rustup target add x86_64-pc-windows-gnu 2>/dev/null || true
    cd "$PROJECT_DIR"
    cargo build --release --target x86_64-pc-windows-gnu
    mkdir -p "$OUT_DIR/windows"
    cp "target/x86_64-pc-windows-gnu/release/guardlib.dll" "$OUT_DIR/windows/"
    echo "✅ Windows build done → dist/windows/"
}

# ── Copy headers ──────────────────────────────────────────────────────────────

copy_headers() {
    cp "$PROJECT_DIR/guardlib.h" "$OUT_DIR/"
    echo "📄 guardlib.h copied to dist/"
}

# ── Main ──────────────────────────────────────────────────────────────────────

case "$TARGET" in
    "android") build_android ;;
    "ios")     build_ios ;;
    "linux")   build_linux ;;
    "windows") build_windows ;;
    "host")    build_host ;;
    "all")
        build_host
        build_android
        if [[ "$(uname -s)" == "Darwin" ]]; then build_ios; fi
        build_linux
        ;;
    *) echo "Usage: $0 [host|android|ios|linux|windows|all]"; exit 1 ;;
esac

copy_headers

echo ""
echo "═══════════════════════════════════════════════════════"
echo "  Build complete. Output in: dist/"
ls -la "$OUT_DIR"
echo "═══════════════════════════════════════════════════════"
