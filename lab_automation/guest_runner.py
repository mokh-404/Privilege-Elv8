"""GuestRunner interface with SSH/SCP and optional QEMU guest-agent backends."""
from __future__ import annotations

import base64
import json
import re
import shutil
import subprocess
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

_WRAPPER_PID_RE = re.compile(r"^WRAPPER_PID=(\d+)\s*$", re.MULTILINE)


@dataclass
class CommandResult:
    returncode: int
    stdout: str
    stderr: str
    wrapper_pid: int | None = None


def parse_wrapper_pid(stdout: str) -> int | None:
    m = _WRAPPER_PID_RE.search(stdout or "")
    return int(m.group(1)) if m else None


class GuestRunner(ABC):
    """Abstract interface for running commands and transferring files with a guest VM."""

    @abstractmethod
    def wait_ready(self, timeout_s: int = 180, poll_interval_s: float = 3.0) -> float:
        """Block until the guest accepts commands; return elapsed seconds."""

    @abstractmethod
    def run_powershell(self, script_text: str, timeout_s: int = 180) -> CommandResult:
        """Execute a PowerShell script via neutral stdin/command execution."""

    @abstractmethod
    def upload_file(self, local_path: Path, remote_path: str, timeout_s: int = 60) -> None:
        """Copy a host file to the guest."""

    @abstractmethod
    def download_dir(self, remote_dir: str, local_dir: Path, timeout_s: int = 120) -> None:
        """Copy a guest directory recursively to the host."""


def _win_scp_path(remote_path: str) -> str:
    """Normalize Windows paths for OpenSSH SCP/SFTP (`C:/dir/file` -> `/C:/dir/file` or `C:/dir/file`)."""
    p = remote_path.replace("\\", "/")
    if re.match(r"^[A-Za-z]:/", p):
        return "/" + p
    return p


class SSHGuestRunner(GuestRunner):
    """OpenSSH client (`ssh` / `scp`) runner over an isolated libvirt network."""

    def __init__(
        self,
        host: str,
        user: str,
        key_path: str | Path,
        port: int = 22,
        run_cmd: Callable[..., subprocess.CompletedProcess] = subprocess.run,
    ):
        self.host = host
        self.user = user
        self.key_path = str(Path(key_path).expanduser())
        self.port = int(port)
        self._run = run_cmd

    def _base_ssh_opts(self, port_flag: str = "-p") -> list[str]:
        return [
            "-i", self.key_path,
            port_flag, str(self.port),
            "-o", "BatchMode=yes",
            "-o", "StrictHostKeyChecking=no",
            "-o", "UserKnownHostsFile=/dev/null",
            "-o", "ConnectTimeout=10",
            "-o", "LogLevel=ERROR",
        ]

    def ssh_cmd(self, remote_cmd: str) -> list[str]:
        return ["ssh", *self._base_ssh_opts("-p"), f"{self.user}@{self.host}", remote_cmd]

    def scp_upload_cmd(self, local_path: Path, remote_path: str) -> list[str]:
        return ["scp", *self._base_ssh_opts("-P"), str(local_path), f"{self.user}@{self.host}:{_win_scp_path(remote_path)}"]

    def scp_download_cmd(self, remote_dir: str, local_dir: Path) -> list[str]:
        return ["scp", "-r", *self._base_ssh_opts("-P"), f"{self.user}@{self.host}:{_win_scp_path(remote_dir)}", str(local_dir)]

    def wait_ready(self, timeout_s: int = 180, poll_interval_s: float = 3.0) -> float:
        t0 = time.monotonic()
        deadline = t0 + timeout_s
        last_err = ""
        while time.monotonic() < deadline:
            try:
                cp = self._run(
                    self.ssh_cmd("powershell.exe -NoProfile -NonInteractive -Command \"Write-Output READY\""),
                    capture_output=True, text=True, timeout=15,
                )
                if cp.returncode == 0 and "READY" in (cp.stdout or ""):
                    return time.monotonic() - t0
                last_err = (cp.stderr or cp.stdout or f"rc={cp.returncode}").strip()
            except Exception as exc:
                last_err = str(exc)
            time.sleep(poll_interval_s)
        raise TimeoutError(f"Guest SSH {self.user}@{self.host}:{self.port} not ready within {timeout_s}s: {last_err}")

    def run_powershell(self, script_text: str, timeout_s: int = 180) -> CommandResult:
        # Read entire stdin as one compiled scriptblock so PowerShell 5.1 does not split on blank lines
        # (and without -EncodedCommand, Invoke-Expression, or temp files on disk).
        cmd = self.ssh_cmd(
            'powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass '
            '-Command "Invoke-Command -ScriptBlock ([scriptblock]::Create([Console]::In.ReadToEnd()))"'
        )
        cp = self._run(cmd, input=script_text, capture_output=True, text=True, timeout=timeout_s)
        return CommandResult(
            returncode=cp.returncode,
            stdout=cp.stdout or "",
            stderr=cp.stderr or "",
            wrapper_pid=parse_wrapper_pid(cp.stdout or ""),
        )

    def upload_file(self, local_path: Path, remote_path: str, timeout_s: int = 60) -> None:
        cp = self._run(self.scp_upload_cmd(local_path, remote_path), capture_output=True, text=True, timeout=timeout_s)
        if cp.returncode != 0:
            raise RuntimeError(f"scp upload failed ({local_path} -> {remote_path}): {cp.stderr}")

    def download_dir(self, remote_dir: str, local_dir: Path, timeout_s: int = 120) -> None:
        local_dir = Path(local_dir)
        local_dir.mkdir(parents=True, exist_ok=True)
        remote_clean = remote_dir.rstrip("\\/")
        stage_dir = local_dir.parent / f".stage_{local_dir.name}"
        if stage_dir.exists():
            shutil.rmtree(stage_dir)
        stage_dir.mkdir(parents=True, exist_ok=True)
        try:
            cp = self._run(self.scp_download_cmd(remote_clean, stage_dir), capture_output=True, text=True, timeout=timeout_s)
            if cp.returncode != 0:
                raise RuntimeError(f"scp download failed ({remote_dir} -> {local_dir}): {cp.stderr}")
            # `scp -r host:/C:/collector_out stage_dir` places files in `stage_dir/collector_out/`
            remote_name = Path(remote_clean.replace("\\", "/")).name
            inner = stage_dir / remote_name
            src_root = inner if inner.is_dir() else stage_dir
            for item in src_root.iterdir():
                dest = local_dir / item.name
                if dest.exists():
                    if dest.is_dir():
                        shutil.rmtree(dest)
                    else:
                        dest.unlink()
                shutil.move(str(item), str(dest))
        finally:
            if stage_dir.exists():
                shutil.rmtree(stage_dir, ignore_errors=True)


class QemuGuestAgentRunner(GuestRunner):
    """Optional `virsh qemu-agent-command` runner behind the same GuestRunner interface."""

    def __init__(
        self,
        domain: str,
        uri: str = "qemu:///system",
        run_cmd: Callable[..., subprocess.CompletedProcess] = subprocess.run,
    ):
        self.domain = domain
        self.uri = uri
        self._run = run_cmd

    def _qga(self, payload: dict, timeout_s: int = 30) -> dict:
        cmd = ["virsh", "-c", self.uri, "qemu-agent-command", self.domain, json.dumps(payload)]
        cp = self._run(cmd, capture_output=True, text=True, timeout=timeout_s)
        if cp.returncode != 0:
            raise RuntimeError(f"qemu-agent-command failed: {cp.stderr}")
        return json.loads(cp.stdout).get("return", {})

    def wait_ready(self, timeout_s: int = 180, poll_interval_s: float = 3.0) -> float:
        t0 = time.monotonic()
        deadline = t0 + timeout_s
        while time.monotonic() < deadline:
            try:
                self._qga({"execute": "guest-ping"}, timeout_s=10)
                return time.monotonic() - t0
            except Exception:
                time.sleep(poll_interval_s)
        raise TimeoutError(f"QEMU guest agent for {self.domain} not ready within {timeout_s}s")

    def run_powershell(self, script_text: str, timeout_s: int = 180) -> CommandResult:
        res = self._qga({
            "execute": "guest-exec",
            "arguments": {
                "path": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                "arg": ["-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", "-"],
                "input-data": base64.b64encode(script_text.encode("utf-8")).decode("ascii"),
                "capture-output": True,
            },
        })
        pid = res["pid"]
        deadline = time.monotonic() + timeout_s
        while time.monotonic() < deadline:
            st = self._qga({"execute": "guest-exec-status", "arguments": {"pid": pid}})
            if st.get("exited"):
                out = base64.b64decode(st.get("out-data", "")).decode("utf-8", errors="replace")
                err = base64.b64decode(st.get("err-data", "")).decode("utf-8", errors="replace")
                return CommandResult(
                    returncode=int(st.get("exitcode", 1)),
                    stdout=out,
                    stderr=err,
                    wrapper_pid=parse_wrapper_pid(out),
                )
            time.sleep(0.5)
        raise TimeoutError(f"QGA guest-exec pid={pid} timed out after {timeout_s}s")

    def upload_file(self, local_path: Path, remote_path: str, timeout_s: int = 60) -> None:
        handle = self._qga({"execute": "guest-file-open", "arguments": {"path": remote_path, "mode": "wb"}})
        try:
            data = Path(local_path).read_bytes()
            for off in range(0, len(data), 32768):
                chunk = base64.b64encode(data[off : off + 32768]).decode("ascii")
                self._qga({"execute": "guest-file-write", "arguments": {"handle": handle, "buf-b64": chunk}})
        finally:
            self._qga({"execute": "guest-file-close", "arguments": {"handle": handle}})

    def download_dir(self, remote_dir: str, local_dir: Path, timeout_s: int = 120) -> None:
        raise NotImplementedError("Use SSHGuestRunner (scp) for directory transfers; QGA is command-fallback only.")
