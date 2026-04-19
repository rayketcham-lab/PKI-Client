#!/usr/bin/env bash
set -euo pipefail

# ============================================================================
# PKI-Client Installer / Upgrader / Uninstaller
#
# Detects the host distro and installs the appropriate native package:
#   Debian/Ubuntu  -> .deb  (installed with dpkg)
#   RHEL/Fedora/etc -> .rpm (installed with dnf/yum)
#
# Install:     curl -fsSL https://raw.githubusercontent.com/rayketcham-lab/PKI-Client/main/install.sh | sudo bash
# Upgrade:     curl -fsSL .../install.sh | sudo bash -s -- upgrade
# Uninstall:   curl -fsSL .../install.sh | sudo bash -s -- uninstall
# Pin version: curl -fsSL .../install.sh | sudo bash -s -- v0.9.1
# ============================================================================

REPO="rayketcham-lab/PKI-Client"
ACTION="${1:-install}"

# ── Detect package format ────────────────────────────────────────────────────

detect_pkg_format() {
    if command -v dpkg >/dev/null 2>&1 && command -v apt-get >/dev/null 2>&1; then
        echo "deb"
    elif command -v rpm >/dev/null 2>&1 && (command -v dnf >/dev/null 2>&1 || command -v yum >/dev/null 2>&1); then
        echo "rpm"
    else
        echo "unsupported"
    fi
}

PKG_FORMAT="$(detect_pkg_format)"

# ── Uninstall ────────────────────────────────────────────────────────────────

if [[ "$ACTION" == "uninstall" ]]; then
    echo "PKI-Client Uninstaller"
    echo "======================"

    case "$PKG_FORMAT" in
        deb)
            if dpkg -s pki-client >/dev/null 2>&1; then
                apt-get remove -y pki-client
            else
                echo "pki-client is not installed (dpkg)."
            fi
            ;;
        rpm)
            if rpm -q pki-client >/dev/null 2>&1; then
                if command -v dnf >/dev/null 2>&1; then
                    dnf remove -y pki-client
                else
                    yum remove -y pki-client
                fi
            else
                echo "pki-client is not installed (rpm)."
            fi
            ;;
        *)
            echo "ERROR: Unsupported distro — no dpkg or rpm detected."
            exit 1
            ;;
    esac

    echo ""
    echo "Done! pki-client has been uninstalled."
    exit 0
fi

# ── Install / Upgrade ────────────────────────────────────────────────────────

echo "PKI-Client Installer"
echo "===================="

# Platform check
OS="$(uname -s | tr '[:upper:]' '[:lower:]')"
ARCH="$(uname -m)"

if [[ "$OS" != "linux" ]]; then
    echo "ERROR: Unsupported OS: $OS (Linux only for pre-built installers)"
    exit 1
fi

case "$ARCH" in
    x86_64|amd64) ;;
    *)
        echo "ERROR: Unsupported architecture: $ARCH (x86_64 only)"
        exit 1
        ;;
esac

if [[ "$PKG_FORMAT" == "unsupported" ]]; then
    echo "ERROR: No supported package manager found."
    echo "Supported: dpkg+apt (Debian/Ubuntu) or rpm+dnf/yum (RHEL/Fedora/Rocky/Alma)."
    echo "Download assets manually from: https://github.com/$REPO/releases"
    exit 1
fi

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

case "$PKG_FORMAT" in
    deb) FILENAME="pki-client_${VERSION_NUM}_amd64.deb" ;;
    rpm) FILENAME="pki-client-${VERSION_NUM}-1.x86_64.rpm" ;;
esac

URL="https://github.com/$REPO/releases/download/${VERSION}/${FILENAME}"
CHECKSUM_URL="https://github.com/$REPO/releases/download/${VERSION}/SHA256SUMS.txt"

echo "Version:  $VERSION"
echo "Package:  $FILENAME ($PKG_FORMAT)"
echo ""

TMPDIR="$(mktemp -d)"
trap 'rm -rf "$TMPDIR"' EXIT

echo "Downloading $FILENAME..."
if ! curl -fSL -o "$TMPDIR/$FILENAME" "$URL"; then
    echo "ERROR: Download failed from $URL"
    exit 1
fi

# ── Verify checksum ──────────────────────────────────────────────────────────

echo "Verifying checksum..."
curl -fsSL -o "$TMPDIR/SHA256SUMS.txt" "$CHECKSUM_URL" 2>/dev/null || true
if [[ -f "$TMPDIR/SHA256SUMS.txt" ]]; then
    EXPECTED="$(grep "$FILENAME" "$TMPDIR/SHA256SUMS.txt" | cut -d' ' -f1)"
    ACTUAL="$(sha256sum "$TMPDIR/$FILENAME" | cut -d' ' -f1)"
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

# ── Install ──────────────────────────────────────────────────────────────────

echo "Installing $FILENAME..."
case "$PKG_FORMAT" in
    deb)
        dpkg -i "$TMPDIR/$FILENAME" || {
            echo "dpkg reported unmet deps — attempting apt-get -f install"
            apt-get install -f -y
        }
        ;;
    rpm)
        if command -v dnf >/dev/null 2>&1; then
            dnf install -y "$TMPDIR/$FILENAME"
        else
            yum install -y "$TMPDIR/$FILENAME"
        fi
        ;;
esac

echo ""
echo "Done! Installed pki-client $VERSION"
pki --version 2>/dev/null || echo "(pki binary not yet on PATH in this shell; open a new shell or check /usr/bin/pki)"
