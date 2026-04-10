

set -e

TARGET="x86_64-unknown-linux-gnu"

echo "Checking prerequisites for cross-compilation..."

if ! command -v zig &> /dev/null; then
    echo "Error: zig is not installed."
    echo "Please install it using: brew install zig"
    exit 1
fi

if ! command -v cargo-zigbuild &> /dev/null; then
    echo "Installing cargo-zigbuild..."
    cargo install cargo-zigbuild
fi

if ! rustup target list | grep -q "${TARGET} (installed)"; then
    echo "Adding rust target ${TARGET}..."
    rustup target add ${TARGET}
fi

echo "Building ${TARGET}..."
cargo zigbuild --target ${TARGET} --release

echo ""
echo "Build complete! The binaries are located at:"
echo "- target/${TARGET}/release/envcrypt"
