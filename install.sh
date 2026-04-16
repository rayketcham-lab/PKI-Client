#!/usr/bin/env bash
set -euo pipefail

# ============================================================================
# PKI-Client Installer / Upgrader / Uninstaller
#
# Install:    curl -fsSL https://raw.githubusercontent.com/rayketcham-lab/PKI-Client/main/install.sh | bash
# Upgrade:    curl -fsSL https://raw.githubusercontent.com/rayketcham-lab/PKI-Client/main/install.sh | bash -s -- upgrade
# Uninstall:  curl -fsSL https://raw.githubusercontent.com/rayketcham-lab/PKI-Client/main/install.sh | bash -s -- uninstall
# Pin version: curl -fsSL ... | bash -s -- v0.8.0
# ============================================================================

REPO="rayketcham-lab/PKI-Client"
INSTALL_DIR="${INSTALL_DIR:-/usr/local/bin}"
ACTION="${1:-install}"

# ── Uninstall ────────────────────────────────────────────────────────────────

if [[ "$ACTION" == "uninstall" ]]; then
    echo "PKI-Client Uninstaller"
    echo "======================"

    if [[ ! -f "$INSTALL_DIR/pki" ]]; then
        echo "pki is not installed at $INSTALL_DIR/pki"
        exit 0
    fi

    CURRENT=$("$INSTALL_DIR/pki" --version 2>/dev/null || echo "unknown")
    echo "Removing: $CURRENT"
    echo "Location: $INSTALL_DIR/pki"

    if rm -f "$INSTALL_DIR/pki" 2>/dev/null; then
        true
    elif sudo rm -f "$INSTALL_DIR/pki" 2>/dev/null; then
        true
    else
        echo "ERROR: Cannot remove $INSTALL_DIR/pki — try: sudo bash -s -- uninstall"
        exit 1
    fi

    echo ""
    echo "Done! pki has been uninstalled."
    exit 0
fi

# ── Upgrade detection ────────────────────────────────────────────────────────

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
if [[ "$ACTION" == "upgrade" ]] || [[ "$ACTION" == "install" ]]; then
    VERSION="latest"
elif [[ "$ACTION" == v* ]]; then
    # User passed a version tag directly (e.g., v0.5.0-beta.4)
    VERSION="$ACTION"
else
    VERSION="$ACTION"
fi

if [[ "$VERSION" == "latest" ]]; then
    echo "Fetching latest release..."
    VERSION=$(curl -fsSL "https://api.github.com/repos/$REPO/releases/latest" | grep '"tag_name"' | cut -d'"' -f4)
    if [[ -z "$VERSION" ]]; then
        echo "ERROR: Could not determine latest version."
        echo "Download manually from: https://github.com/$REPO/releases"
        exit 1
    fi
fi

# Check if already installed and up to date
CURRENT_VERSION=""
if [[ -f "$INSTALL_DIR/pki" ]]; then
    CURRENT_VERSION=$("$INSTALL_DIR/pki" --version 2>/dev/null | awk '{print $2}' || echo "")
    LATEST_CLEAN="${VERSION#v}"  # strip leading 'v'

    if [[ "$CURRENT_VERSION" == "$LATEST_CLEAN" ]]; then
        echo "Already up to date: pki $CURRENT_VERSION"
        exit 0
    fi

    if [[ -n "$CURRENT_VERSION" ]]; then
        echo "Upgrade:  $CURRENT_VERSION -> $LATEST_CLEAN"
    fi
else
    echo "Fresh install"
fi

echo "Version:  $VERSION"
echo "Platform: $PLATFORM"
echo "Install:  $INSTALL_DIR/pki"
echo ""

# ── Download ─────────────────────────────────────────────────────────────────

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

# ── Verify checksum ──────────────────────────────────────────────────────────

echo "Verifying checksum..."
curl -fsSL -o "$TMPDIR/SHA256SUMS.txt" "$CHECKSUM_URL" 2>/dev/null || true
if [[ -f "$TMPDIR/SHA256SUMS.txt" ]]; then
    EXPECTED=$(grep "$FILENAME" "$TMPDIR/SHA256SUMS.txt" | cut -d' ' -f1)
    ACTUAL=$(sha256sum "$TMPDIR/$FILENAME" | cut -d' ' -f1)
    if [[ "$EXPECTED" == "$ACTUAL" ]]; then
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

# ── Extract and install ──────────────────────────────────────────────────────

echo "Installing to $INSTALL_DIR..."
tar xzf "$TMPDIR/$FILENAME" -C "$TMPDIR"

if mv "$TMPDIR/pki" "$INSTALL_DIR/pki" 2>/dev/null; then
    true
elif sudo mv "$TMPDIR/pki" "$INSTALL_DIR/pki" 2>/dev/null; then
    true
else
    echo "ERROR: Cannot install to $INSTALL_DIR — try: sudo bash"
    exit 1
fi
chmod +x "$INSTALL_DIR/pki" 2>/dev/null || sudo chmod +x "$INSTALL_DIR/pki"

echo ""
if [[ -n "$CURRENT_VERSION" ]]; then
    echo "Done! Upgraded pki $CURRENT_VERSION -> $VERSION at $INSTALL_DIR/pki"
else
    echo "Done! Installed pki $VERSION to $INSTALL_DIR/pki"
fi
echo ""
"$INSTALL_DIR/pki" --version 2>/dev/null || true
