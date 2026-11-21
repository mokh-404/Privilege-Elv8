"""Single-run Windows 11 libvirt orchestrator (Prompt E + Win11 UEFI/TPM overlay design).

Per run:
1. Ensure persistent domain `win11` on `qemu:///system` is shut off (`virsh destroy` if needed).
2. Remove any old overlay qcow2, create fresh copy-on-write overlay backed by read-only
   `base_image`, and restore UEFI `nvram_active` from `nvram_base` (never touches `base_image`,
   never uses `virsh create` transient domains).
3. `virsh -c qemu:///system start win11`, wait for SSH, then sleep `post_ssh_settle_seconds` (20s).
4. Control mode: wait `control_wait_seconds`.
   Attack mode: launch `benign_noise.ps1` and the rendered neutral attack script on two
   parallel SSH sessions with seeded start offsets in [0, 20]s and seeded step ordering.
5. Wait `post_launchers_flush_seconds` (5s), upload & run `collector/Collect-Artifacts.ps1`
   with captured `-ExcludePids`, download output via `scp` to `data/raw/runs/<run_id>/`.
6. Guaranteed cleanup in `finally`: `virsh shutdown` (then `destroy` on timeout) and
   delete `overlay_image`. Writes host-side provenance JSONL strictly on the host.
"""
from __future__ import annotations

import argparse
import json
import shlex
import subprocess
import threading
import time
from dataclasses import dataclass, field
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


@dataclass
class LabConfig:
    libvirt_uri: str = "qemu:///system"
    domain_name: str = "win11"
    base_image: str = "/var/lib/libvirt/images/win11_base.qcow2"
    overlay_image: str = "/var/lib/libvirt/images/win11_overlay.qcow2"
    nvram_base: str = "/var/lib/libvirt/qemu/nvram/win11_VARS.fd.base"
    nvram_active: str = "/var/lib/libvirt/qemu/nvram/win11_VARS.fd"
    network_name: str = "isolated-lab"
    guest_mac: str = "52:54:00:ba:30:f3"
    guest_ip: str = "192.168.100.10"
    ssh_user: str = "Administrator"
    ssh_key_path: str = "~/.ssh/win11_lab_ed25519"
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

    @classmethod
    def from_yaml(cls, path: str | Path) -> "LabConfig":
        data = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}
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


def build_virsh_cmd(uri: str, *args: str) -> list[str]:
    return ["virsh", "-c", uri, *args]


def build_overlay_cmd(base_image: str, overlay_image: str, use_sudo: bool = False) -> list[str]:
    cmd = ["qemu-img", "create", "-f", "qcow2", "-F", "qcow2", "-b", base_image, overlay_image]
    return (["sudo", *cmd] if use_sudo else cmd)


def _fs_cmd(args: list[str], use_sudo: bool) -> list[str]:
    return (["sudo", *args] if use_sudo else args)


def prepare_fresh_win11_state(
    cfg: LabConfig,
    run_cmd: Callable[..., subprocess.CompletedProcess] = subprocess.run,
) -> None:
    """Shut off win11 if needed, recreate throw-away overlay from base, and restore NVRAM."""
    state_cp = run_cmd(build_virsh_cmd(cfg.libvirt_uri, "domstate", cfg.domain_name),
                       capture_output=True, text=True, timeout=15)
    state = (state_cp.stdout or "").strip().lower()
    if state and state != "shut off":
        run_cmd(build_virsh_cmd(cfg.libvirt_uri, "destroy", cfg.domain_name),
                capture_output=True, text=True, timeout=30, check=True)

    run_cmd(_fs_cmd(["rm", "-f", cfg.overlay_image], cfg.use_sudo_for_libvirt_files),
            capture_output=True, text=True, timeout=30, check=True)
    run_cmd(build_overlay_cmd(cfg.base_image, cfg.overlay_image, cfg.use_sudo_for_libvirt_files),
            capture_output=True, text=True, timeout=30, check=True)
    run_cmd(_fs_cmd(["cp", "-f", cfg.nvram_base, cfg.nvram_active], cfg.use_sudo_for_libvirt_files),
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
        run_cmd(_fs_cmd(["rm", "-f", cfg.overlay_image], cfg.use_sudo_for_libvirt_files),
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
            f"expected_artifact_keys=(ConvertFrom-Json '{exp_json}');"
            "wrapper_pid=$SelfPid;"
            f"seed={int(seed)}"
            "}"
        )
        lines.append('Write-Output ("PROVENANCE:" + ($prov | ConvertTo-Json -Depth 4 -Compress))')

    script = "\n".join(lines) + "\n"
    # Hard FE-08 check BEFORE anything touches the guest
    import pandas as pd
    assert_clean(pd.DataFrame([{"artifact_key": "rendered_attack", "command_line": script}]),
                 fields=("command_line",), report_path=None)
    return script


def render_benign_script(benign_ps1_path: Path, seed: int, order: Sequence[str]) -> str:
    body = benign_ps1_path.read_text(encoding="utf-8")
    order_str = ",".join(order)
    # Invoke inline with explicit parameters via a function wrapper so no file needs staging
    wrapped = (
        f"$__seed = {int(seed)}\n"
        f"$__order = '{order_str}'\n"
        "& {\n"
        f"{body}\n"
        "} -Seed $__seed -Order $__order\n"
    )
    return wrapped


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


def write_provenance_jsonl(records: Sequence[dict], path: Path) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        for r in records:
            f.write(json.dumps(r, sort_keys=True) + "\n")
    return path


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
    provenance_rows: list[dict] = []

    prepare_fresh_win11_state(cfg, run_cmd=run_cmd)
    try:
        run_cmd(build_virsh_cmd(cfg.libvirt_uri, "start", cfg.domain_name),
                capture_output=True, text=True, timeout=60, check=True)
        runner.wait_ready(timeout_s=cfg.boot_timeout_seconds)
        sleep_fn(cfg.post_ssh_settle_seconds)

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
            # Keep attack steps ordered deterministically inside variant while interleaved against benign
            a_script = render_attack_script(variant_spec, seed)

            results: dict[str, CommandResult] = {}
            errors: dict[str, BaseException] = {}
            barrier = threading.Barrier(2)

            def _worker(tag: str, offset_s: float, script_body: str) -> None:
                try:
                    barrier.wait(timeout=30)
                    sleep_fn(offset_s)
                    results[tag] = runner.run_powershell(script_body, timeout_s=cfg.launcher_timeout_seconds)
                except BaseException as exc:  # pragma: no cover - verified via test_launcher_error
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

        write_provenance_jsonl(provenance_rows, prov_path)
        sleep_fn(cfg.post_launchers_flush_seconds)

        # Ensure guest collector folder exists, upload collector, execute, scp back
        guest_out = cfg.guest_collector_out.rstrip("\\")
        runner.run_powershell(f"[void][System.IO.Directory]::CreateDirectory('{guest_out}')", timeout_s=30)
        remote_collector = f"{guest_out}\\Collect-Artifacts.ps1"
        runner.upload_file(collector_script, remote_collector)

        excl_arg = f"-ExcludePids @({','.join(str(p) for p in wrapper_pids)})" if wrapper_pids else ""
        collect_cmd = f"& '{remote_collector}' -OutDir '{guest_out}' {excl_arg}".strip()
        col_res = runner.run_powershell(collect_cmd, timeout_s=180)
        if col_res.returncode != 0:
            raise RuntimeError(f"Collector failed in {run_id} (rc={col_res.returncode}): {col_res.stderr}")

        runner.download_dir(guest_out, out_dir)
    finally:
        shutdown_and_cleanup_win11(cfg, run_cmd=run_cmd, sleep_fn=sleep_fn)

    duration = round(time.monotonic() - t_start, 2)
    return {
        "run_id": run_id,
        "mode": mode,
        "technique_id": technique["technique_id"] if technique else "CONTROL",
        "variant": int(variant_spec["variant"]) if variant_spec else 0,
        "split": technique["split"] if technique else "control",
        "status": "success",
        "duration_s": duration,
        "wrapper_pids": wrapper_pids,
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
