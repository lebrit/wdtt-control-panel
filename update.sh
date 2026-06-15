#!/usr/bin/env bash
set -Eeuo pipefail

URL="${WDTT_PANEL_BOOTSTRAP_URL:-https://raw.githubusercontent.com/lebrit/wdtt-control-panel/main/bootstrap.sh}"
TMP_FILE="$(mktemp)"
trap 'rm -f "$TMP_FILE"' EXIT

[ "$(id -u)" -eq 0 ] || {
  echo "Run as root: curl -fsSL https://raw.githubusercontent.com/lebrit/wdtt-control-panel/main/update.sh | sudo bash" >&2
  exit 1
}

curl -fsSL --retry 3 "$URL" -o "$TMP_FILE"
bash "$TMP_FILE" update
