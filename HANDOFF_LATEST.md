# WDTT Control Panel 0.13.0

## Changes

- Fixed issues from screenshots: local systemd administrative socket, GeoFiles up to 128 MiB, WDTT network detection, journal retention save button, disk/inode preflight, HTTP root returns 404, extended user limit, VLESS TLS profiles.
- Web process remains sandboxed with NoNewPrivileges and ProtectSystem=strict. Administrative socket is root:wdtt-panel, mode 0660, with an action allowlist.
- WDTT extension v10 targets official server v1.4.3. It preserves existing databases and supports up to 65023 passwords; capacity depends on server resources. Bulk creation is capped at 100 per request.
- VLESS requires managed Xray and a trusted panel TLS certificate. Local firewall rules are managed; the provider firewall must allow the selected TCP port.

## Verification

- Windows: 96 Python tests passed, 3 Linux-specific tests skipped; official source patch regression included.
- Bash syntax checked for all four scripts; JavaScript syntax and git diff checks passed.
- Desktop/mobile browser regression covered retention persistence and VLESS create/copy/delete, without page errors or horizontal overflow.
- Linux workflow additionally checks the real systemd socket from a readonly web namespace and compiles/tests the patched Go server.
- No production server was modified. Android is unchanged.

## Deployment

- Run the bootstrap menu and choose update (2).
- Save gateway/cascade settings after updating to apply the corrected network rules.
- The extended limit becomes available only after the extension build succeeds; until then the old limit is retained.
- Graphify artifacts, attachments, local tools and secrets must not be published.
