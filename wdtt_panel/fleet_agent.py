from __future__ import annotations

import json
import subprocess
import sys
import time
from datetime import datetime, timezone
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from . import __version__
from .fleet import PROTOCOL_VERSION, FLEET_AGENT_CONFIG, FleetValidationError, load_config, remember_completion, save_config


ADMIN_COMMAND = ["/usr/bin/sudo", "-n", "/usr/local/sbin/wdtt-panel-admin"]
SAFE_ERROR_CODES = {"local_validation_failed", "local_operation_failed", "center_unavailable", "center_rejected", "command_expired"}


class FleetAgent:
    def __init__(self) -> None:
        self.config = load_config()

    def request(self, method: str, path: str, payload: dict[str, Any] | None = None, authenticated: bool = True) -> dict[str, Any]:
        endpoint = str(self.config.get("endpoint") or "").rstrip("/")
        if not endpoint:
            raise FleetValidationError("center_unavailable")
        data = json.dumps(payload or {}, separators=(",", ":")).encode("utf-8") if method == "POST" else None
        headers = {"Accept": "application/json"}
        if data is not None:
            headers["Content-Type"] = "application/json"
        if authenticated:
            token = str(self.config.get("agent_token") or "")
            if not token:
                raise FleetValidationError("center_rejected")
            headers["Authorization"] = f"Bearer {token}"
        request = Request(f"{endpoint}/{path.lstrip('/')}", data=data, headers=headers, method=method)
        try:
            with urlopen(request, timeout=20) as response:
                decoded = json.loads(response.read().decode("utf-8"))
        except HTTPError as exc:
            raise FleetValidationError("center_rejected" if 400 <= exc.code < 500 else "center_unavailable") from exc
        except (URLError, TimeoutError, ValueError) as exc:
            raise FleetValidationError("center_unavailable") from exc
        if not isinstance(decoded, dict):
            raise FleetValidationError("center_rejected")
        return decoded

    @staticmethod
    def local_admin(action: str, payload: dict[str, Any]) -> dict[str, Any]:
        request = json.dumps({"action": action, "payload": payload}, ensure_ascii=False)
        try:
            completed = subprocess.run(ADMIN_COMMAND, input=request, text=True, capture_output=True, timeout=60)
            response = json.loads(completed.stdout)
        except (OSError, subprocess.TimeoutExpired, ValueError, json.JSONDecodeError) as exc:
            raise FleetValidationError("local_operation_failed") from exc
        if not isinstance(response, dict) or not response.get("ok"):
            raise FleetValidationError("local_validation_failed")
        result = response.get("result")
        return result if isinstance(result, dict) else {}

    def enroll(self) -> None:
        response = self.request(
            "POST",
            "v1/agent/enroll",
            {
                "token": self.config.get("enrollment_grant"),
                "identityFingerprint": self.config.get("identity_fingerprint"),
            },
            authenticated=False,
        )
        node = response.get("node") or {}
        token = response.get("agentToken")
        if not isinstance(node.get("id"), str) or not isinstance(token, str) or len(token) < 32:
            raise FleetValidationError("center_rejected")
        self.config["node_id"] = node["id"]
        self.config["agent_token"] = token
        self.config["enrollment_grant"] = ""
        save_config(self.config)

    @staticmethod
    def command_is_expired(command: dict[str, Any]) -> bool:
        value = command.get("expiresAt")
        if not isinstance(value, str):
            return True
        try:
            return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(timezone.utc) <= datetime.now(timezone.utc)
        except ValueError:
            return True

    def receipt(self, command_id: str, status: str, error_code: str = "") -> None:
        payload: dict[str, Any] = {"protocolVersion": PROTOCOL_VERSION, "commandId": command_id, "status": status}
        if status == "failed":
            payload["errorCode"] = error_code if error_code in SAFE_ERROR_CODES else "local_operation_failed"
        self.request("POST", "v1/agent/command-receipts", payload)

    def process_commands(self) -> None:
        response = self.request("GET", "v1/agent/commands")
        commands = response.get("commands")
        if not isinstance(commands, list):
            raise FleetValidationError("center_rejected")
        for command in commands:
            if not isinstance(command, dict) or not isinstance(command.get("id"), str):
                continue
            command_id = command["id"]
            completed = (self.config.get("completed_commands") or {}).get(command_id)
            if isinstance(completed, dict):
                self.receipt(command_id, str(completed.get("status") or "failed"), str(completed.get("error_code") or ""))
                continue
            if self.command_is_expired(command):
                self.receipt(command_id, "failed", "command_expired")
                remember_completion(self.config, command_id, "failed", "command_expired")
                save_config(self.config)
                continue
            self.receipt(command_id, "delivered")
            try:
                self.local_admin("fleet.command", {"kind": command.get("kind"), "payload": command.get("payload")})
                self.receipt(command_id, "succeeded")
                remember_completion(self.config, command_id, "succeeded")
            except FleetValidationError as exc:
                error_code = str(exc) if str(exc) in SAFE_ERROR_CODES else "local_operation_failed"
                self.receipt(command_id, "failed", error_code)
                remember_completion(self.config, command_id, "failed", error_code)
            save_config(self.config)

    def run_once(self) -> None:
        if not self.config.get("enabled"):
            return
        if not self.config.get("agent_token"):
            self.enroll()
        heartbeat = {
            "protocolVersion": PROTOCOL_VERSION,
            "agentVersion": __version__,
            "panelAdapterVersion": "wdtt-control-panel/v1",
        }
        self.request("POST", "v1/agent/heartbeat", heartbeat)
        snapshot = self.local_admin("fleet.snapshot", {})
        self.request("POST", "v1/agent/snapshots", snapshot)
        self.process_commands()
        self.config["last_success_at"] = int(time.time())
        self.config["last_error_code"] = ""
        self.config["agent_version"] = __version__
        save_config(self.config)

    def run(self) -> None:
        while True:
            self.config = load_config()
            try:
                self.run_once()
            except FleetValidationError as exc:
                self.config["last_error_code"] = str(exc) if str(exc) in SAFE_ERROR_CODES else "local_operation_failed"
                save_config(self.config)
            except Exception:
                self.config["last_error_code"] = "local_operation_failed"
                save_config(self.config)
            interval = int(self.config.get("poll_interval_seconds") or 15)
            time.sleep(max(5, min(interval, 300)))


def main() -> int:
    try:
        FleetAgent().run()
    except KeyboardInterrupt:
        return 0
    return 0


if __name__ == "__main__":
    sys.exit(main())
