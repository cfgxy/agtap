#!/bin/sh
set -eu

REPO="zhebrak/agtap"
INSTALL_DIR="${INSTALL_DIR:-/usr/local/bin}"

# Check platform
ARCH=$(uname -m)
OS=$(uname -s)

if [ "$OS" != "Linux" ]; then
  echo "Error: agtap only supports Linux (detected: $OS)" >&2
  exit 1
fi

case "$ARCH" in
  x86_64)  ARCH_SUFFIX="x86_64" ;;
  aarch64|arm64) ARCH_SUFFIX="aarch64" ;;
  *)
    echo "Error: unsupported architecture (detected: $ARCH). agtap provides x86_64 and aarch64 binaries." >&2
    exit 1
    ;;
esac

# Check dependencies
for cmd in curl tar sha256sum; do
  if ! command -v "$cmd" > /dev/null 2>&1; then
    echo "Error: required command '$cmd' not found" >&2
    exit 1
  fi
done

# Check install dir is writable before downloading
if [ ! -w "$INSTALL_DIR" ]; then
  echo "Error: $INSTALL_DIR is not writable. Run with sudo or set INSTALL_DIR." >&2
  exit 1
fi

# Fetch latest release tarball URL
TARBALL_URL=$(curl -fsSL "https://api.github.com/repos/${REPO}/releases/latest" \
  | grep -o "\"browser_download_url\": *\"[^\"]*linux-${ARCH_SUFFIX}\\.tar\\.gz\"" \
  | head -1 \
  | sed 's/"browser_download_url": *"//;s/"$//')

if [ -z "$TARBALL_URL" ]; then
  echo "Error: could not find a release artifact for linux-${ARCH_SUFFIX}" >&2
  exit 1
fi

CHECKSUM_URL="${TARBALL_URL}.sha256"
ARCHIVE_NAME=$(basename "$TARBALL_URL")

# Download to temp dir
WORK_DIR=$(mktemp -d)
trap 'rm -rf "$WORK_DIR"' EXIT

echo "Downloading agtap..."
curl -fsSL -o "$WORK_DIR/$ARCHIVE_NAME" "$TARBALL_URL"
curl -fsSL -o "$WORK_DIR/$ARCHIVE_NAME.sha256" "$CHECKSUM_URL"

# Verify checksum
echo "Verifying checksum..."
(cd "$WORK_DIR" && sha256sum -c "$ARCHIVE_NAME.sha256")

# Extract and install
tar xzf "$WORK_DIR/$ARCHIVE_NAME" -C "$WORK_DIR"

mv "$WORK_DIR/agtap" "$INSTALL_DIR/agtap"
chmod +x "$INSTALL_DIR/agtap"

echo "Installed agtap to $INSTALL_DIR/agtap"
echo "Run 'agtap --version' to verify."
