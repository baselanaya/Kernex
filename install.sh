#!/usr/bin/env bash
# install.sh — Kernex installer
#
# Usage:
#   curl -fsSL https://kernex.sh/install | bash
#   curl -fsSL https://kernex.sh/install | KERNEX_VERSION=v1.2.3 bash
#   bash install.sh [--version v1.2.3] [--install-dir /usr/local/bin]
#
# Environment variables:
#   KERNEX_VERSION    Pin a specific release tag (e.g. v1.2.3).  Default: latest.
#   KERNEX_INSTALL_DIR  Installation directory.  Default: /usr/local/bin.
#   KERNEX_NO_SUDO    Set to 1 to skip sudo even if the target dir needs it.
#
# Supported platforms:
#   Linux  x86_64   (static musl binary — zero runtime dependencies)
#   macOS  x86_64 / arm64  (universal binary)
#
# The installer verifies the SHA256 checksum of every downloaded binary against
# the checksums.txt file published alongside the release.  It will never install
# a binary whose checksum does not match.

set -euo pipefail

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

REPO="kernex-io/kernex"
RELEASES_URL="https://github.com/${REPO}/releases"
API_URL="https://api.github.com/repos/${REPO}/releases/latest"
DEFAULT_INSTALL_DIR="/usr/local/bin"
BINARY_NAME="kernex"

# ---------------------------------------------------------------------------
# Colour helpers (disabled when not a TTY or NO_COLOR is set)
# ---------------------------------------------------------------------------

if [ -t 1 ] && [ -z "${NO_COLOR:-}" ]; then
    RED='\033[0;31m'
    YELLOW='\033[0;33m'
    GREEN='\033[0;32m'
    RESET='\033[0m'
else
    RED='' YELLOW='' GREEN='' RESET=''
fi

info()    { printf "  ${GREEN}→${RESET}  %s\n" "$*"; }
warn()    { printf "  ${YELLOW}⚠${RESET}  %s\n" "$*" >&2; }
success() { printf "  ${GREEN}✓${RESET}  %s\n" "$*"; }
err()     { printf "  ${RED}✗${RESET}  %s\n" "$*" >&2; exit 1; }

# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------

VERSION="${KERNEX_VERSION:-}"
INSTALL_DIR="${KERNEX_INSTALL_DIR:-$DEFAULT_INSTALL_DIR}"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --version)   VERSION="$2";     shift 2 ;;
        --version=*) VERSION="${1#*=}"; shift   ;;
        --install-dir)   INSTALL_DIR="$2";     shift 2 ;;
        --install-dir=*) INSTALL_DIR="${1#*=}"; shift   ;;
        -h|--help)
            sed -n '2,20p' "$0" | grep '^#' | sed 's/^# \?//'
            exit 0 ;;
        *) err "Unknown argument: $1.  Run with --help for usage." ;;
    esac
done

# ---------------------------------------------------------------------------
# Platform detection
# ---------------------------------------------------------------------------

OS="$(uname -s)"
ARCH="$(uname -m)"

case "$OS" in
    Linux)
        case "$ARCH" in
            x86_64) ASSET="kernex-x86_64-unknown-linux-musl" ;;
            *)       err "Unsupported Linux architecture: ${ARCH}.  Only x86_64 is supported." ;;
        esac
        SHA256_CMD="sha256sum"
        ;;
    Darwin)
        case "$ARCH" in
            x86_64|arm64|aarch64) ASSET="kernex-universal-apple-darwin" ;;
            *) err "Unsupported macOS architecture: ${ARCH}." ;;
        esac
        SHA256_CMD="shasum -a 256"
        ;;
    *)
        err "Unsupported operating system: ${OS}.  Kernex supports Linux and macOS."
        ;;
esac

# ---------------------------------------------------------------------------
# Dependency check
# ---------------------------------------------------------------------------

need() {
    command -v "$1" >/dev/null 2>&1 || \
        err "Required tool not found: $1.  Please install it and retry."
}

need curl
need "$( echo "$SHA256_CMD" | awk '{print $1}' )"  # sha256sum or shasum

# ---------------------------------------------------------------------------
# Version resolution
# ---------------------------------------------------------------------------

if [ -z "$VERSION" ]; then
    info "Fetching latest release version..."
    VERSION="$(
        curl -fsSL \
            -H "Accept: application/vnd.github+json" \
            -H "X-GitHub-Api-Version: 2022-11-28" \
            "$API_URL" \
        | grep '"tag_name"' \
        | head -1 \
        | sed 's/.*"tag_name": *"\([^"]*\)".*/\1/'
    )"
    [ -n "$VERSION" ] || err "Could not determine latest release version.  Set KERNEX_VERSION and retry."
fi

# Strip a leading 'v' for display, keep original for URLs.
VERSION_DISPLAY="${VERSION#v}"
info "Installing Kernex ${VERSION_DISPLAY} (${OS}/${ARCH})"

# ---------------------------------------------------------------------------
# Temporary directory — cleaned up on exit
# ---------------------------------------------------------------------------

TMP_DIR="$(mktemp -d)"
cleanup() { rm -rf "$TMP_DIR"; }
trap cleanup EXIT

BINARY_PATH="${TMP_DIR}/${ASSET}"
CHECKSUMS_PATH="${TMP_DIR}/checksums.txt"

BASE_URL="${RELEASES_URL}/download/${VERSION}"

# ---------------------------------------------------------------------------
# Download binary
# ---------------------------------------------------------------------------

info "Downloading ${ASSET}..."
curl -fsSL --progress-bar \
    "${BASE_URL}/${ASSET}" \
    -o "$BINARY_PATH" \
|| err "Download failed: ${BASE_URL}/${ASSET}"

# ---------------------------------------------------------------------------
# Download checksums.txt
# ---------------------------------------------------------------------------

info "Downloading checksums.txt..."
curl -fsSL \
    "${BASE_URL}/checksums.txt" \
    -o "$CHECKSUMS_PATH" \
|| err "Download failed: ${BASE_URL}/checksums.txt"

# ---------------------------------------------------------------------------
# Checksum verification — HARD FAIL on mismatch
# ---------------------------------------------------------------------------

info "Verifying SHA256 checksum..."

# Extract the expected hash for our specific asset from checksums.txt.
# Format: "<hash>  <filename>"  (two spaces, as emitted by sha256sum)
EXPECTED_LINE="$(grep -F "${ASSET}" "$CHECKSUMS_PATH" || true)"

if [ -z "$EXPECTED_LINE" ]; then
    err "checksums.txt does not contain an entry for '${ASSET}'.
     Downloaded checksums.txt:
$(cat "$CHECKSUMS_PATH" | sed 's/^/       /')"
fi

EXPECTED_HASH="$(echo "$EXPECTED_LINE" | awk '{print $1}')"

# Compute the actual hash of the downloaded binary.
ACTUAL_HASH="$( $SHA256_CMD "$BINARY_PATH" | awk '{print $1}' )"

if [ "$ACTUAL_HASH" != "$EXPECTED_HASH" ]; then
    printf "\n"
    printf "  ${RED}✗${RESET}  CHECKSUM MISMATCH — refusing to install.\n" >&2
    printf "     File:     %s\n" "$ASSET"             >&2
    printf "     Expected: %s\n" "$EXPECTED_HASH"     >&2
    printf "     Actual:   %s\n" "$ACTUAL_HASH"       >&2
    printf "\n"
    printf "  The downloaded binary does not match the published checksum.\n"  >&2
    printf "  This may indicate a network corruption or a compromised download.\n" >&2
    printf "  Do NOT proceed.  Report this at: %s/issues\n" \
        "https://github.com/${REPO}" >&2
    exit 1
fi

success "Checksum verified: ${ACTUAL_HASH:0:16}..."

# ---------------------------------------------------------------------------
# Installation
# ---------------------------------------------------------------------------

chmod +x "$BINARY_PATH"
TARGET="${INSTALL_DIR}/${BINARY_NAME}"

# Determine whether sudo is needed to write to the install directory.
USE_SUDO=0
if [ "${KERNEX_NO_SUDO:-0}" = "1" ]; then
    USE_SUDO=0
elif [ ! -w "$INSTALL_DIR" ]; then
    if command -v sudo >/dev/null 2>&1; then
        warn "Writing to ${INSTALL_DIR} requires elevated privileges — will use sudo."
        USE_SUDO=1
    else
        err "Cannot write to ${INSTALL_DIR} and sudo is not available.
     Set KERNEX_INSTALL_DIR to a directory you own, or run as root."
    fi
fi

info "Installing to ${TARGET}..."

if [ "$USE_SUDO" = "1" ]; then
    sudo install -m 0755 "$BINARY_PATH" "$TARGET"
else
    install -m 0755 "$BINARY_PATH" "$TARGET"
fi

# ---------------------------------------------------------------------------
# Post-install verification
# ---------------------------------------------------------------------------

if ! command -v kernex >/dev/null 2>&1; then
    warn "Installed to ${TARGET}, but 'kernex' is not in your PATH."
    warn "Add ${INSTALL_DIR} to your PATH, or run: ${TARGET}"
fi

INSTALLED_VERSION="$( "$TARGET" --version 2>/dev/null | head -1 || echo "(unknown)" )"

success "Kernex ${VERSION_DISPLAY} installed successfully."
info    "  Binary:  ${TARGET}"
info    "  Version: ${INSTALLED_VERSION}"
info    ""
info    "Get started:"
info    "  kernex init                        # generate kernex.yaml"
info    "  kernex audit -- <your agent cmd>   # profile before enforcing"
info    "  kernex run   -- <your agent cmd>   # run under full enforcement"
