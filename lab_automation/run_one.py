"""Single-run Windows 11 libvirt orchestrator (Prompt E + Win11 UEFI/TPM overlay design).

Per run:
1. Ensure persistent domain `win11` on `qemu:///system` is shut off (`virsh destroy` if needed).
2. Remove any old overlay qcow2, create fresh copy-on-write overlay backed by read-only
   `base_image`, `chown nobody:nobody` the overlay, and copy `nvram_base` -> `nvram_live`
   (using only passwordless sudo binaries when `use_sudo_for_libvirt_files=true`; never
   touches `base_image`, never uses `virsh create` transient domains).
3. `virsh -c qemu:///system start win11`, wait for SSH, then sleep `post_ssh_settle_seconds` (20s).
4. Record guest `sshd` PIDs, then in control mode wait `control_wait_seconds`, or in attack mode
   launch `benign_noise.ps1` and the rendered neutral attack script on two parallel SSH sessions
   with seeded start offsets in [0, 20]s and seeded step ordering.
5. Wait `post_launchers_flush_seconds` (5s), upload & run `collector/Collect-Artifacts.ps1`
   with captured `-ExcludePids` (wrapper + sshd PIDs), download output via `scp`.
6. Guaranteed cleanup in `finally`: `virsh shutdown` (then `destroy` on timeout) and
   delete `overlay_image`. Writes host-side provenance JSONL strictly on the host.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import threading
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Sequence

import numpy as np
import yaml

from lab_automation.guest_runner import CommandResult, GuestRunner, SSHGuestRunner
from src import config
from src.data.sanitize import assert_clean


BENIGN_STEPS = [
    "workspace_doc",
    "ps_diag",
    "backup_task",
    "run_note",
    "cmd_archive",
    "sysinternals_check",
]

_SUDO_BIN_MAP = {
    "virsh": "/usr/bin/virsh",
    "qemu-img": "/usr/bin/qemu-img",
    "chown": "/usr/bin/chown",
    "cp": "/usr/bin/cp",
    "rm": "/usr/bin/rm",
}


@dataclass
class LabConfig:
    libvirt_uri: str = "qemu:///system"
    domain_name: str = "win11"
    base_image: str = "/var/lib/libvirt/images/win11_base.qcow2"
    overlay_image: str = "/var/lib/libvirt/images/win11_overlay.qcow2"
    overlay_owner: str = "nobody:nobody"
    nvram_base: str = "/var/lib/libvirt/qemu/nvram/win11_VARS.fd.base"
    nvram_live: str = "/var/lib/libvirt/qemu/nvram/win11_VARS.fd"
    network_name: str = "win11-isolated"
    guest_mac: str = "52:54:00:ba:30:f3"
    guest_ip: str = "192.168.150.50"
    ssh_user: str = "mokh"
    ssh_key_path: str = "/home/fsociety/.ssh/id_ed25519"
    ssh_port: int = 22
    boot_timeout_seconds: int = 180
    post_ssh_settle_seconds: int = 20
    post_launchers_flush_seconds: int = 5
    shutdown_timeout_seconds: int = 90
    launcher_timeout_seconds: int = 180
    control_wait_seconds: int = 45
    min_free_disk_gb: float = 30.0
    use_sudo_for_libvirt_files: bool = False
    guest_collector_out: str = r"C:\collector_out"
    run_output_dir: str = str(config.RAW_RUNS_DIR)
    dry_run_output_dir: str = str(config.DATA_DIR / "raw" / "dry_runs")
    dry_run_provenance_dir: str = str(config.PROVENANCE_DIR / "dry_runs")

    @property
    def nvram_active(self) -> str:
        return self.nvram_live

    @classmethod
    def from_yaml(cls, path: str | Path) -> "LabConfig":
        data = dict(yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {})
        if "nvram_active" in data and "nvram_live" not in data:
            data["nvram_live"] = data.pop("nvram_active")
        valid = {f for f in cls.__dataclass_fields__}
        filtered = {k: v for k, v in data.items() if k in valid}
        return cls(**filtered)


@dataclass
class InterleavingSchedule:
    seed: int
    benign_offset_s: float
    attack_offset_s: float
    benign_order: list[str]
    attack_order: list[int]


def _maybe_sudo(cmd: list[str], use_sudo: bool) -> list[str]:
    if not use_sudo:
        return cmd
    exe = _SUDO_BIN_MAP.get(cmd[0], cmd[0])
    return ["sudo", "-n", exe, *cmd[1:]]


def build_virsh_cmd(uri: str, *args: str, use_sudo: bool = False) -> list[str]:
    return _maybe_sudo(["virsh", "-c", uri, *args], use_sudo=use_sudo)


def build_overlay_cmd(base_image: str, overlay_image: str, use_sudo: bool = False) -> list[str]:
    return _maybe_sudo(
        ["qemu-img", "create", "-f", "qcow2", "-F", "qcow2", "-b", base_image, overlay_image],
        use_sudo=use_sudo,
    )


def prepare_fresh_win11_state(
    cfg: LabConfig,
    run_cmd: Callable[..., subprocess.CompletedProcess] = subprocess.run,
) -> None:
    """Reset persistent Win11 state: destroy if running -> rm -> qemu-img -> chown -> cp NVRAM."""
    state_cp = run_cmd(build_virsh_cmd(cfg.libvirt_uri, "domstate", cfg.domain_name),
                       capture_output=True, text=True, timeout=15)
    state = (state_cp.stdout or "").strip().lower()
    if state and state != "shut off":
        run_cmd(build_virsh_cmd(cfg.libvirt_uri, "destroy", cfg.domain_name),
                capture_output=True, text=True, timeout=30, check=True)

    run_cmd(_maybe_sudo(["rm", "-f", cfg.overlay_image], cfg.use_sudo_for_libvirt_files),
            capture_output=True, text=True, timeout=30, check=True)
    run_cmd(build_overlay_cmd(cfg.base_image, cfg.overlay_image, cfg.use_sudo_for_libvirt_files),
            capture_output=True, text=True, timeout=30, check=True)
    if cfg.overlay_owner:
        run_cmd(_maybe_sudo(["chown", cfg.overlay_owner, cfg.overlay_image], cfg.use_sudo_for_libvirt_files),
                capture_output=True, text=True, timeout=30, check=True)
    run_cmd(_maybe_sudo(["cp", cfg.nvram_base, cfg.nvram_live], cfg.use_sudo_for_libvirt_files),
            capture_output=True, text=True, timeout=30, check=True)


def shutdown_and_cleanup_win11(
    cfg: LabConfig,
    run_cmd: Callable[..., subprocess.CompletedProcess] = subprocess.run,
    sleep_fn: Callable[[float], None] = time.sleep,
) -> None:
    """Graceful virsh shutdown with destroy fallback, then delete throw-away overlay."""
    try:
        run_cmd(build_virsh_cmd(cfg.libvirt_uri, "shutdown", cfg.domain_name),
                capture_output=True, text=True, timeout=20)
        deadline = time.monotonic() + cfg.shutdown_timeout_seconds
        while time.monotonic() < deadline:
            cp = run_cmd(build_virsh_cmd(cfg.libvirt_uri, "domstate", cfg.domain_name),
                         capture_output=True, text=True, timeout=15)
            if (cp.stdout or "").strip().lower() == "shut off":
                break
            sleep_fn(2.0)
        else:
            run_cmd(build_virsh_cmd(cfg.libvirt_uri, "destroy", cfg.domain_name),
                    capture_output=True, text=True, timeout=30)
    finally:
        run_cmd(_maybe_sudo(["rm", "-f", cfg.overlay_image], cfg.use_sudo_for_libvirt_files),
                capture_output=True, text=True, timeout=30)


def build_interleaving_schedule(
    seed: int,
    benign_steps: Sequence[str] = BENIGN_STEPS,
    n_attack_steps: int = 1,
) -> InterleavingSchedule:
    """Seeded random start offsets in [0, 20]s and seeded step orderings for both launchers."""
    rng = np.random.default_rng(seed)
    b_off = round(float(rng.uniform(0.0, 20.0)), 3)
    a_off = round(float(rng.uniform(0.0, 20.0)), 3)
    b_order = [str(x) for x in rng.permutation(list(benign_steps))]
    a_order = [int(x) for x in rng.permutation(n_attack_steps)]
    return InterleavingSchedule(
        seed=int(seed),
        benign_offset_s=b_off,
        attack_offset_s=a_off,
        benign_order=b_order,
        attack_order=a_order,
    )


def render_attack_script(
    variant_spec: dict[str, Any],
    seed: int,
    step_order: Sequence[int] | None = None,
) -> str:
    """Render a neutral PowerShell wrapper script for a technique variant (FE-08 sanitized)."""
    steps = list(variant_spec["steps"])
    expected = list(variant_spec.get("expected_artifact_keys", []))
    order = list(step_order) if step_order is not None else list(range(len(steps)))

    lines = [
        "$ErrorActionPreference = 'Continue'",
        "$SelfPid = $PID",
        'Write-Output ("WRAPPER_PID={0}" -f $SelfPid)',
    ]
    for idx in order:
        st = steps[idx]
        action = str(st["action"])
        cmd = str(st["cmd"]).rstrip()
        exp_json = json.dumps(expected)
        lines.append(cmd)
        lines.append(
            "$prov = [ordered]@{"
            "launcher='attack';"
            f"action='{action}';"
            "timestamp_utc=[DateTime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ssZ');"
            f"expected_artifact_keys=@(ConvertFrom-Json '{exp_json}');"
            "wrapper_pid=$SelfPid;"
            f"seed={int(seed)}"
            "}"
        )
        lines.append('Write-Output ("PROVENANCE:" + ($prov | ConvertTo-Json -Depth 4 -Compress))')

    script = "\n".join(lines) + "\n"
    import pandas as pd
    assert_clean(pd.DataFrame([{"artifact_key": "rendered_attack", "command_line": script}]),
                 fields=("command_line",), report_path=None)
    return script


def render_benign_script(benign_ps1_path: Path, seed: int, order: Sequence[str]) -> str:
    body = benign_ps1_path.read_text(encoding="utf-8")
    order_str = ",".join(order)
    return (
        f"$__seed = {int(seed)}\n"
        f"$__order = '{order_str}'\n"
        "& {\n"
        f"{body}\n"
        "} -Seed $__seed -Order $__order\n"
    )


def _extract_provenance(stdout: str, run_id: str, technique_id: str | None, variant: int | None) -> list[dict]:
    out = []
    for line in (stdout or "").splitlines():
        if line.startswith("PROVENANCE:"):
            rec = json.loads(line[len("PROVENANCE:"):])
            rec["run_id"] = run_id
            rec["technique_id"] = technique_id
            rec["variant"] = variant
            out.append(rec)
    return out


def _query_sshd_pids(runner: GuestRunner) -> list[int]:
    try:
        res = runner.run_powershell(
            "$p = @(Get-CimInstance Win32_Process | "
            "Where-Object { $_.Name -in @('sshd.exe','sshd-session.exe','ssh-agent.exe') } | "
            "Select-Object -ExpandProperty ProcessId); "
            "Write-Output ('SSHD_PIDS=' + ($p -join ','))",
            timeout_s=30,
        )
        m = re.search(r"SSHD_PIDS=([0-9,]*)", res.stdout or "")
        if m and m.group(1):
            return sorted({int(x) for x in m.group(1).split(",") if x.strip()})
    except Exception:
        pass
    return []


def write_provenance_jsonl(records: Sequence[dict], path: Path) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        for r in records:
            f.write(json.dumps(r, sort_keys=True) + "\n")
    return path


def _safe_file_size(path: str | Path) -> int:
    try:
        return int(os.stat(path).st_size)
    except OSError:
        return 0


def _dir_size_bytes(path: Path) -> int:
    if not path.exists():
        return 0
    return sum(p.stat().st_size for p in path.rglob("*") if p.is_file())


def run_single(
    cfg: LabConfig,
    run_id: str,
    mode: str = "attack",
    technique: dict[str, Any] | None = None,
    variant_spec: dict[str, Any] | None = None,
    seed: int = config.SEED,
    runner: GuestRunner | None = None,
    run_cmd: Callable[..., subprocess.CompletedProcess] = subprocess.run,
    sleep_fn: Callable[[float], None] = time.sleep,
    provenance_dir: Path = config.PROVENANCE_DIR,
    collector_script: Path = config.REPO_ROOT / "collector" / "Collect-Artifacts.ps1",
    benign_script: Path = config.LAB_DIR / "benign_noise.ps1",
) -> dict[str, Any]:
    """Execute one full isolated Win11 run (control or attack) with guaranteed cleanup."""
    t_start = time.monotonic()
    if runner is None:
        runner = SSHGuestRunner(
            host=cfg.guest_ip, user=cfg.ssh_user, key_path=cfg.ssh_key_path,
            port=cfg.ssh_port, run_cmd=run_cmd,
        )

    out_dir = Path(cfg.run_output_dir) / run_id
    prov_path = Path(provenance_dir) / f"{run_id}.jsonl"
    wrapper_pids: list[int] = []
    sshd_pids: list[int] = []
    provenance_rows: list[dict] = []
    timings: dict[str, float] = {}
    overlay_size_bytes = 0

    t0 = time.monotonic()
    prepare_fresh_win11_state(cfg, run_cmd=run_cmd)
    timings["reset_s"] = round(time.monotonic() - t0, 3)

    try:
        t0 = time.monotonic()
        run_cmd(build_virsh_cmd(cfg.libvirt_uri, "start", cfg.domain_name),
                capture_output=True, text=True, timeout=60, check=True)
        runner.wait_ready(timeout_s=cfg.boot_timeout_seconds)
        timings["boot_to_ssh_s"] = round(time.monotonic() - t0, 3)

        t0 = time.monotonic()
        sleep_fn(cfg.post_ssh_settle_seconds)
        timings["settle_s"] = round(time.monotonic() - t0, 3)

        sshd_pids = _query_sshd_pids(runner)

        t0 = time.monotonic()
        if mode == "control":
            provenance_rows.append({
                "run_id": run_id,
                "launcher": "control",
                "action": "idle_baseline_window",
                "timestamp_utc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                "expected_artifact_keys": [],
                "seed": int(seed),
            })
            sleep_fn(cfg.control_wait_seconds)
        elif mode == "attack":
            assert technique is not None and variant_spec is not None
            sched = build_interleaving_schedule(seed, BENIGN_STEPS, n_attack_steps=len(variant_spec["steps"]))
            b_script = render_benign_script(benign_script, seed, sched.benign_order)
            a_script = render_attack_script(variant_spec, seed)

            results: dict[str, CommandResult] = {}
            errors: dict[str, BaseException] = {}
            barrier = threading.Barrier(2)

            def _worker(tag: str, offset_s: float, script_body: str) -> None:
                try:
                    barrier.wait(timeout=30)
                    sleep_fn(offset_s)
                    results[tag] = runner.run_powershell(script_body, timeout_s=cfg.launcher_timeout_seconds)
                except BaseException as exc:  # pragma: no cover
                    errors[tag] = exc

            tb = threading.Thread(target=_worker, args=("benign", sched.benign_offset_s, b_script))
            ta = threading.Thread(target=_worker, args=("attack", sched.attack_offset_s, a_script))
            tb.start()
            ta.start()
            tb.join()
            ta.join()

            if errors:
                raise RuntimeError(f"Launcher thread error(s) in {run_id}: {errors}")
            for tag, res in results.items():
                if res.wrapper_pid is not None:
                    wrapper_pids.append(res.wrapper_pid)
                if res.returncode != 0:
                    raise RuntimeError(f"{tag} launcher exited {res.returncode} in {run_id}: {res.stderr}")
                provenance_rows.extend(_extract_provenance(
                    res.stdout, run_id, technique["technique_id"], int(variant_spec["variant"]),
                ))
        else:
            raise ValueError(f"Unknown mode: {mode!r}")
        timings["launchers_s"] = round(time.monotonic() - t0, 3)

        exclude_pids = sorted(set(wrapper_pids) | set(sshd_pids))
        provenance_rows.append({
            "run_id": run_id,
            "launcher": "runner_meta",
            "action": "captured_runner_pids",
            "timestamp_utc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "expected_artifact_keys": [],
            "wrapper_pids": wrapper_pids,
            "sshd_pids": sshd_pids,
            "exclude_pids": exclude_pids,
            "seed": int(seed),
        })
        write_provenance_jsonl(provenance_rows, prov_path)

        t0 = time.monotonic()
        sleep_fn(cfg.post_launchers_flush_seconds)
        timings["flush_s"] = round(time.monotonic() - t0, 3)

        t0 = time.monotonic()
        guest_out = cfg.guest_collector_out.rstrip("\\")
        runner.run_powershell(f"[void][System.IO.Directory]::CreateDirectory('{guest_out}')", timeout_s=30)
        remote_collector = f"{guest_out}\\Collect-Artifacts.ps1"
        runner.upload_file(collector_script, remote_collector)

        excl_arg = f"-ExcludePids @({','.join(str(p) for p in exclude_pids)})" if exclude_pids else ""
        collect_cmd = f"& '{remote_collector}' -OutDir '{guest_out}' {excl_arg}".strip()
        col_res = runner.run_powershell(collect_cmd, timeout_s=180)
        if col_res.returncode != 0:
            raise RuntimeError(f"Collector failed in {run_id} (rc={col_res.returncode}): {col_res.stderr}")
        timings["collection_s"] = round(time.monotonic() - t0, 3)

        t0 = time.monotonic()
        runner.download_dir(guest_out, out_dir)
        timings["scp_s"] = round(time.monotonic() - t0, 3)
        overlay_size_bytes = _safe_file_size(cfg.overlay_image)
    finally:
        t0 = time.monotonic()
        shutdown_and_cleanup_win11(cfg, run_cmd=run_cmd, sleep_fn=sleep_fn)
        timings["teardown_s"] = round(time.monotonic() - t0, 3)

    timings["total_s"] = round(time.monotonic() - t_start, 2)
    overlay_deleted = not Path(cfg.overlay_image).exists()
    output_size_bytes = _dir_size_bytes(out_dir)

    return {
        "run_id": run_id,
        "mode": mode,
        "technique_id": technique["technique_id"] if technique else "CONTROL",
        "variant": int(variant_spec["variant"]) if variant_spec else 0,
        "split": technique["split"] if technique else "control",
        "status": "success",
        "duration_s": timings["total_s"],
        "timings": timings,
        "wrapper_pids": wrapper_pids,
        "sshd_pids": sshd_pids,
        "overlay_size_mb": round(overlay_size_bytes / (1024 ** 2), 2),
        "output_size_mb": round(output_size_bytes / (1024 ** 2), 2),
        "overlay_deleted": overlay_deleted,
        "provenance_path": str(prov_path),
        "output_dir": str(out_dir),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Execute one isolated Win11 run.")
    parser.add_argument("--config", type=Path, default=config.LAB_DIR / "lab_config.yaml")
    parser.add_argument("--techniques", type=Path, default=config.TECHNIQUES_YAML)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--mode", choices=["control", "attack"], default="attack")
    parser.add_argument("--technique-id", default=None)
    parser.add_argument("--variant", type=int, default=1)
    parser.add_argument("--seed", type=int, default=config.SEED)
    args = parser.parse_args(argv)

    cfg = LabConfig.from_yaml(args.config)
    tech = None
    vspec = None
    if args.mode == "attack":
        cat = yaml.safe_load(args.techniques.read_text(encoding="utf-8"))
        tech = next(t for t in cat["techniques"] if t["technique_id"] == args.technique_id)
        vspec = next(v for v in tech["variants"] if int(v["variant"]) == args.variant)

    res = run_single(cfg, run_id=args.run_id, mode=args.mode, technique=tech, variant_spec=vspec, seed=args.seed)
    print(json.dumps(res, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
