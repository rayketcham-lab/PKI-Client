#!/usr/bin/env bash
set -euo pipefail

# ============================================================================
# PKI-Client Installer
#
# Downloads the latest pre-built static binary from GitHub Releases.
# No build tools, no Rust toolchain, no dependencies required.
#
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/rayketcham-lab/PKI-Client/main/install.sh | bash
#   # or specify a version:
#   curl -fsSL https://raw.githubusercontent.com/rayketcham-lab/PKI-Client/main/install.sh | bash -s -- v0.3.0-beta.3
# ============================================================================

REPO="rayketcham-lab/PKI-Client"
INSTALL_DIR="${INSTALL_DIR:-/usr/local/bin}"
VERSION="${1:-latest}"

echo "PKI-Client Installer"
echo "===================="

# Detect platform
OS=$(uname -s | tr '[:upper:]' '[:lower:]')
ARCH=$(uname -m)

case "$OS" in
    linux)  PLATFORM="x86_64-linux" ;;
    *)
        echo "ERROR: Unsupported OS: $OS"
        echo "Pre-built binaries are available for Linux x86_64 only."
        exit 1
        ;;
esac

case "$ARCH" in
    x86_64|amd64) ;; # supported
    *)
        echo "ERROR: Unsupported architecture: $ARCH"
        echo "Pre-built binaries are available for x86_64 only."
        exit 1
        ;;
esac

# Resolve version
if [ "$VERSION" = "latest" ]; then
    echo "Fetching latest release..."
    VERSION=$(curl -fsSL "https://api.github.com/repos/$REPO/releases/latest" | grep '"tag_name"' | cut -d'"' -f4)
    if [ -z "$VERSION" ]; then
        echo "ERROR: Could not determine latest version."
        echo "Download manually from: https://github.com/$REPO/releases"
        exit 1
    fi
fi

echo "Version:  $VERSION"
echo "Platform: $PLATFORM"
echo "Install:  $INSTALL_DIR/pki"
echo ""

# Download
FILENAME="pki-${VERSION}-${PLATFORM}.tar.gz"
URL="https://github.com/$REPO/releases/download/$VERSION/$FILENAME"
CHECKSUM_URL="https://github.com/$REPO/releases/download/$VERSION/SHA256SUMS.txt"

TMPDIR=$(mktemp -d)
trap 'rm -rf "$TMPDIR"' EXIT

echo "Downloading $FILENAME..."
if ! curl -fSL -o "$TMPDIR/$FILENAME" "$URL"; then
    echo "ERROR: Download failed."
    echo "Check available releases: https://github.com/$REPO/releases"
    exit 1
fi

# Verify checksum
echo "Verifying checksum..."
curl -fsSL -o "$TMPDIR/SHA256SUMS.txt" "$CHECKSUM_URL" 2>/dev/null || true
if [ -f "$TMPDIR/SHA256SUMS.txt" ]; then
    EXPECTED=$(grep "$FILENAME" "$TMPDIR/SHA256SUMS.txt" | cut -d' ' -f1)
    ACTUAL=$(sha256sum "$TMPDIR/$FILENAME" | cut -d' ' -f1)
    if [ "$EXPECTED" = "$ACTUAL" ]; then
        echo "Checksum: OK"
    else
        echo "ERROR: Checksum mismatch!"
        echo "  Expected: $EXPECTED"
        echo "  Got:      $ACTUAL"
        exit 1
    fi
else
    echo "Checksum: skipped (no SHA256SUMS.txt)"
fi

# Extract and install
echo "Installing to $INSTALL_DIR..."
tar xzf "$TMPDIR/$FILENAME" -C "$TMPDIR"

if [ -w "$INSTALL_DIR" ]; then
    mv "$TMPDIR/pki" "$INSTALL_DIR/pki"
else
    sudo mv "$TMPDIR/pki" "$INSTALL_DIR/pki"
fi
chmod +x "$INSTALL_DIR/pki"

echo ""
echo "Done! Installed pki $VERSION to $INSTALL_DIR/pki"
echo ""
"$INSTALL_DIR/pki" --version 2>/dev/null || true
