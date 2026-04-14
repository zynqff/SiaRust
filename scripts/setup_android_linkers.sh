#!/bin/bash
# setup_android_linkers.sh — Configure Rust cross-compilation linkers for Android
#
# Run this ONCE before building for Android.
# Requires ANDROID_NDK_HOME to be set.

set -e

if [ -z "$ANDROID_NDK_HOME" ]; then
    echo "❌ ANDROID_NDK_HOME not set."
    echo "   On macOS (typical path):"
    echo "   export ANDROID_NDK_HOME=\$HOME/Library/Android/sdk/ndk/<version>"
    echo "   On Linux:"
    echo "   export ANDROID_NDK_HOME=\$HOME/Android/Sdk/ndk/<version>"
    exit 1
fi

# Detect host OS for NDK toolchain path
case "$(uname -s)" in
    Linux)  HOST_TAG="linux-x86_64" ;;
    Darwin) HOST_TAG="darwin-x86_64" ;;
    *)      echo "❌ Unsupported host OS"; exit 1 ;;
esac

TOOLCHAIN="$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/$HOST_TAG/bin"

if [ ! -d "$TOOLCHAIN" ]; then
    echo "❌ Toolchain not found at: $TOOLCHAIN"
    echo "   Check your ANDROID_NDK_HOME path."
    exit 1
fi

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
mkdir -p "$PROJECT_DIR/.cargo"

cat > "$PROJECT_DIR/.cargo/config.toml" << EOF
[target.aarch64-linux-android]
linker = "$TOOLCHAIN/aarch64-linux-android21-clang"

[target.armv7-linux-androideabi]
linker = "$TOOLCHAIN/armv7a-linux-androideabi21-clang"

[target.x86_64-linux-android]
linker = "$TOOLCHAIN/x86_64-linux-android21-clang"

[target.i686-linux-android]
linker = "$TOOLCHAIN/i686-linux-android21-clang"
EOF

echo "✅ .cargo/config.toml written"
echo "   Linkers configured for Android API 21+"
echo ""
echo "Now run: ./scripts/build_all.sh android"
