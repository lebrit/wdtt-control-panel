#!/usr/bin/env bash
set -Eeuo pipefail

REPOSITORY="${WDTT_PANEL_REPOSITORY:-lebrit/wdtt-control-panel}"
BRANCH="${WDTT_PANEL_BRANCH:-main}"
ARCHIVE_URL="https://github.com/${REPOSITORY}/archive/refs/heads/${BRANCH}.tar.gz"
WORK_DIR="$(mktemp -d)"

cleanup() {
  rm -rf "$WORK_DIR"
}
trap cleanup EXIT

if [ "$(id -u)" -ne 0 ]; then
  echo "Run as root: curl -fsSL https://raw.githubusercontent.com/${REPOSITORY}/${BRANCH}/bootstrap.sh | sudo bash" >&2
  exit 1
fi

command -v curl >/dev/null 2>&1 || {
  echo "curl is required" >&2
  exit 1
}
command -v tar >/dev/null 2>&1 || {
  echo "tar is required" >&2
  exit 1
}

echo "[wdtt-panel] Downloading ${REPOSITORY}@${BRANCH}"
curl -fsSL --retry 3 "$ARCHIVE_URL" | tar -xz -C "$WORK_DIR"
SOURCE_DIR="$(find "$WORK_DIR" -mindepth 1 -maxdepth 1 -type d | head -n 1)"
[ -f "$SOURCE_DIR/install.sh" ] || {
  echo "Invalid project archive: install.sh not found" >&2
  exit 1
}

exec bash "$SOURCE_DIR/install.sh" "${1:-install}"
