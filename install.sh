#!/usr/bin/env bash
set -euo pipefail

# ============================================================================
# PKI-Client Installer / Upgrader / Uninstaller
#
# Downloads the statically-linked musl binary (single artifact, zero runtime
# deps). Works on any x86_64 Linux distro — Debian, Ubuntu, RHEL, Rocky,
# Alma, Fedora, Alpine — because the binary depends on nothing at runtime.
#
# Install:     curl -fsSL https://raw.githubusercontent.com/rayketcham-lab/PKI-Client/main/install.sh | sudo bash
# Upgrade:     curl -fsSL .../install.sh | sudo bash -s -- upgrade
# Uninstall:   curl -fsSL .../install.sh | sudo bash -s -- uninstall
# Pin version: curl -fsSL .../install.sh | sudo bash -s -- v0.9.3
# ============================================================================

REPO="rayketcham-lab/PKI-Client"
ACTION="${1:-install}"
INSTALL_PATH="${PKI_INSTALL_PATH:-/usr/local/bin/pki}"

# ── Uninstall ────────────────────────────────────────────────────────────────

if [[ "$ACTION" == "uninstall" ]]; then
    echo "PKI-Client Uninstaller"
    echo "======================"
    if [[ -f "$INSTALL_PATH" ]]; then
        rm -f "$INSTALL_PATH"
        echo "Removed $INSTALL_PATH"
    else
        echo "$INSTALL_PATH not present — nothing to remove."
    fi
    exit 0
fi

# ── Install / Upgrade ────────────────────────────────────────────────────────

echo "PKI-Client Installer"
echo "===================="

# Platform check
OS="$(uname -s | tr '[:upper:]' '[:lower:]')"
ARCH="$(uname -m)"

if [[ "$OS" != "linux" ]]; then
    echo "ERROR: Unsupported OS: $OS (Linux only)"
    exit 1
fi

case "$ARCH" in
    x86_64|amd64) ;;
    *)
        echo "ERROR: Unsupported architecture: $ARCH (x86_64 only)"
        exit 1
        ;;
esac

# Resolve version
if [[ "$ACTION" == "upgrade" || "$ACTION" == "install" ]]; then
    VERSION="latest"
else
    VERSION="$ACTION"
fi

if [[ "$VERSION" == "latest" ]]; then
    echo "Fetching latest release tag..."
    VERSION="$(curl -fsSL "https://api.github.com/repos/$REPO/releases/latest" | grep '"tag_name"' | cut -d'"' -f4)"
    if [[ -z "$VERSION" ]]; then
        echo "ERROR: Could not determine latest version."
        exit 1
    fi
fi

VERSION_NUM="${VERSION#v}"
FILENAME="pki-${VERSION_NUM}-linux-x86_64-musl"
URL="https://github.com/$REPO/releases/download/${VERSION}/${FILENAME}"
CHECKSUM_URL="https://github.com/$REPO/releases/download/${VERSION}/SHA256SUMS.txt"

echo "Version:  $VERSION"
echo "Asset:    $FILENAME"
echo "Install:  $INSTALL_PATH"
echo ""

WORKDIR="$(mktemp -d)"
trap 'rm -rf "$WORKDIR"' EXIT

echo "Downloading $FILENAME..."
if ! curl -fSL -o "$WORKDIR/$FILENAME" "$URL"; then
    echo "ERROR: Download failed from $URL"
    exit 1
fi

# ── Verify checksum ──────────────────────────────────────────────────────────

echo "Verifying checksum..."
if ! curl -fsSL -o "$WORKDIR/SHA256SUMS.txt" "$CHECKSUM_URL"; then
    echo "ERROR: SHA256SUMS.txt download failed — refusing to install unverified binary."
    exit 1
fi

EXPECTED="$(grep " ${FILENAME}\$" "$WORKDIR/SHA256SUMS.txt" | cut -d' ' -f1)"
if [[ -z "$EXPECTED" ]]; then
    echo "ERROR: $FILENAME not listed in SHA256SUMS.txt — refusing to install."
    exit 1
fi
ACTUAL="$(sha256sum "$WORKDIR/$FILENAME" | cut -d' ' -f1)"
if [[ "$EXPECTED" != "$ACTUAL" ]]; then
    echo "ERROR: Checksum mismatch!"
    echo "  Expected: $EXPECTED"
    echo "  Got:      $ACTUAL"
    exit 1
fi
echo "Checksum: OK"

# ── Install ──────────────────────────────────────────────────────────────────

echo "Installing to $INSTALL_PATH..."
chmod +x "$WORKDIR/$FILENAME"
mkdir -p "$(dirname "$INSTALL_PATH")"
mv "$WORKDIR/$FILENAME" "$INSTALL_PATH"

echo ""
echo "Done! Installed pki $VERSION"
"$INSTALL_PATH" --version
