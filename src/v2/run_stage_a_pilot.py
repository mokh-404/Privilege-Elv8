"""Stage A Pilot & Collection Orchestrator (`OD-V2-05`, `OD-V2-07`, `OD-V2-20`).

Safety & execution invariants:
- Enforces strict Gate 0 (`05_quarantine_vault_setup.sh preflight` + `GATE0_SIGNED_OFF`),
  ransomware/wiper/worm exclusion (`validate_stage_run_spec`), and `--canary` supervised
  smoke-test stamp (`CANARY_PASSED`) before any unattended malware batch runs.
- Arms a crash-surviving detached host watchdog (`arm-watchdog`) BEFORE `virsh start win11`
  covering BOTH `win11` and `inetsim-vm`.
- Runs per-run `virbr1` firewall position & packet-counter egress audit (`check-egress`) and
  fast immutability verification (`verify-base-fast` inside `try ... finally:`) every run,
  plus full `win11_base.qcow2` `sha256sum -c` (`verify-base`) at batch start/end/abort and every 25 runs.
- Supports safe 1-lane pipelining (`--pipelined`) by renaming closed Run i overlay to
  `win11_overlay_<run_id>.qcow2` before Run i+1 creates a fresh `win11_overlay.qcow2`.
"""
from __future__ import annotations

import argparse
from concurrent.futures import Future, ThreadPoolExecutor
from dataclasses import asdict
from datetime import datetime, timedelta, timezone
import hashlib
import json
import math
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import time
from typing import Any, Callable, Mapping, Sequence

import numpy as np
import pandas as pd

from scripts.verify_stratified_shortcuts import check_template_quantization
from src import config
from src.data import features as F
from src.utils.repro import utc_now_iso
from src.v2.ablations_v2 import split_feature_types
from src.v2.labeler_v2 import (
    AMBIGUOUS_LABEL,
    build_multi_control_baseline,
    label_dormant_batch_run,
    label_dormant_run,
    label_executed_run,
)
from src.v2.offline_extractor import GOLDEN_BASE_IMAGE_SHA256, summarize_extraction_and_refgraph
from src.v2.pilot_staging import (
    PilotStagingError,
    StageRunSpec,
    build_dormant_batch_bundle,
    build_stage_bundle,
    validate_stage_run_spec,
)
from src.v2.stats_v2 import compute_lofo_table, cross_stratum_execution_delta
from src.v2.training import run_nested_family_cv


CANARY_STAMP_TTL_SECONDS = 24 * 3600
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$", re.I)


def build_create_overlay_command(base_qcow2: str | Path, overlay_qcow2: str | Path) -> list[str]:
    """Return a `qemu-img create` command using a relative `-b` backing filename so dissect resolves it cleanly."""
    base_resolved = Path(base_qcow2).resolve()
    overlay_dir = Path(overlay_qcow2).resolve().parent
    rel_backing = os.path.relpath(base_resolved, overlay_dir)
    return [
        "qemu-img",
        "create",
        "-f",
        "qcow2",
        "-F",
        "qcow2",
        "-b",
        rel_backing,
        str(overlay_qcow2),
    ]


def build_container_extraction_command(
    overlay_qcow2: str | Path,
    run_out_dir: str | Path,
    run_id: str,
    base_cache_path: str | Path | None = Path("/var/lib/dfir-quarantine-vault/win11_base_cache.json.gz"),
    runner_script: str | Path | None = None,
) -> tuple[list[str], dict[str, str]]:
    """Build the unprivileged `06_unprivileged_container_runner.sh` argv and env with `BASE_CACHE_PATH`."""
    repo_root = Path(__file__).resolve().parent.parent.parent
    script_p = (
        Path(runner_script)
        if runner_script is not None
        else (repo_root / "docs" / "v2" / "hardening" / "06_unprivileged_container_runner.sh")
    )
    cache_arg = str(base_cache_path) if base_cache_path is not None else "none"
    cmd = [
        str(script_p),
        str(overlay_qcow2),
        str(run_out_dir),
        str(run_id),
        cache_arg,
    ]
    env = {"BASE_CACHE_PATH": cache_arg}
    return cmd, env


def build_inetsim_lifecycle_commands(
    domain: str = "inetsim-vm",
    libvirt_uri: str = "qemu:///system",
) -> dict[str, list[str]]:
    """Return allowed libvirt commands to start/stop/inspect `inetsim-vm` (`never virsh create`)."""
    return {
        "domstate": ["sudo", "virsh", "-c", libvirt_uri, "domstate", domain],
        "start": ["sudo", "virsh", "-c", libvirt_uri, "start", domain],
        "destroy": ["sudo", "virsh", "-c", libvirt_uri, "destroy", domain],
    }


def _invoke_cmd(
    run_cmd: Callable[..., int] | None,
    cmd: list[str],
    env_overrides: Mapping[str, str] | None = None,
    dry_run: bool = False,
) -> int:
    if dry_run:
        return 0
    if run_cmd is not None:
        try:
            return int(run_cmd(cmd, env_overrides))
        except TypeError:
            return int(run_cmd(cmd))
    merged_env = dict(os.environ)
    if env_overrides:
        merged_env.update({str(k): str(v) for k, v in env_overrides.items()})
    return int(subprocess.run(cmd, env=merged_env, check=False).returncode)


def _invoke_cmd_capture(
    run_cmd: Callable[..., int] | None,
    cmd_output_fn: Callable[[list[str], Mapping[str, str] | None], tuple[int, str]] | None,
    cmd: list[str],
    env_overrides: Mapping[str, str] | None = None,
    dry_run: bool = False,
) -> tuple[int, str]:
    if dry_run:
        return 0, ""
    if cmd_output_fn is not None:
        rc, out = cmd_output_fn(cmd, env_overrides)
        return int(rc), str(out or "")
    if run_cmd is not None:
        return _invoke_cmd(run_cmd, cmd, env_overrides=env_overrides, dry_run=False), ""
    merged_env = dict(os.environ)
    if env_overrides:
        merged_env.update({str(k): str(v) for k, v in env_overrides.items()})
    cp = subprocess.run(cmd, env=merged_env, check=False, capture_output=True, text=True)
    return int(cp.returncode), (cp.stdout or "")


def evaluate_egress_delta(
    before: Mapping[str, Any] | None,
    after: Mapping[str, Any] | None,
    max_in_drop_burst: int = 2000,
) -> dict[str, Any]:
    """Compare pre/post-run `virbr1` snapshots and flag invalid rules or cross-interface egress."""
    if not before or not after:
        return {"passed": True, "mock_skipped": True}
    b_ok = bool(before.get("firewall_rules_valid", False))
    a_ok = bool(after.get("firewall_rules_valid", False))
    fwd_pkts_delta = int(after.get("fwd_drop_pkts", 0)) - int(before.get("fwd_drop_pkts", 0))
    fwd_bytes_delta = int(after.get("fwd_drop_bytes", 0)) - int(before.get("fwd_drop_bytes", 0))
    in_drop_delta = int(after.get("in_drop_pkts", 0)) - int(before.get("in_drop_pkts", 0))
    errors: list[str] = []
    if not b_ok or not a_ok:
        errors.append(f"invalid_virbr1_firewall_position(before={b_ok}, after={a_ok})")
    if fwd_pkts_delta > 0 or fwd_bytes_delta > 0:
        errors.append(f"cross_interface_forward_egress_detected(pkts={fwd_pkts_delta}, bytes={fwd_bytes_delta})")
    if in_drop_delta > int(max_in_drop_burst):
        errors.append(f"anomalous_in_drop_burst(pkts={in_drop_delta} > {max_in_drop_burst})")
    return {
        "passed": len(errors) == 0,
        "firewall_rules_valid_before": b_ok,
        "firewall_rules_valid_after": a_ok,
        "fwd_drop_pkts_delta": fwd_pkts_delta,
        "fwd_drop_bytes_delta": fwd_bytes_delta,
        "in_drop_pkts_delta": in_drop_delta,
        "errors": errors,
    }


def _parse_json_snapshot(raw_stdout: str) -> dict[str, Any] | None:
    txt = str(raw_stdout or "").strip()
    if not txt:
        return None
    for line in reversed(txt.splitlines()):
        s = line.strip()
        if s.startswith("{") and s.endswith("}"):
            return dict(json.loads(s))
    return None


def compute_batch_json_sha256(
    batch_json_path: str | Path | None = None,
    batch_runs: Sequence[Mapping[str, Any]] | None = None,
) -> str:
    """Return lowercase SHA-256 of the batch JSON file (or canonical serialized `batch_runs`)."""
    if batch_json_path is not None:
        p = Path(batch_json_path)
        if not p.is_file():
            raise PilotStagingError(f"Batch JSON file not found for SHA-256 binding: {p}")
        return hashlib.sha256(p.read_bytes()).hexdigest().lower()

    normalized: list[dict[str, Any]] = []
    for entry in batch_runs or ():
        e = dict(entry)
        sp = e.get("spec")
        if isinstance(sp, StageRunSpec):
            e["spec"] = asdict(sp)
        normalized.append(e)
    payload = json.dumps(normalized, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")
    return hashlib.sha256(payload).hexdigest().lower()


def get_git_head_state(repo_root: str | Path) -> dict[str, Any]:
    """Return `{'git_head': <commit_sha>, 'git_dirty': <bool>}` for `repo_root`."""
    rpath = str(repo_root)
    head_cp = subprocess.run(["git", "-C", rpath, "rev-parse", "HEAD"], capture_output=True, text=True)
    if head_cp.returncode != 0 or not head_cp.stdout.strip():
        return {"git_head": "unknown", "git_dirty": True}
    st_cp = subprocess.run(["git", "-C", rpath, "status", "--porcelain"], capture_output=True, text=True)
    dirty = (st_cp.returncode != 0) or bool(st_cp.stdout.strip())
    return {"git_head": head_cp.stdout.strip().lower(), "git_dirty": bool(dirty)}


def resolve_base_image_sha256(
    base_qcow2: str | Path,
    hash_file: str | Path = "/var/lib/libvirt/images/v2_base_hashes.sha256",
    explicit_base_sha256: str | None = None,
) -> str:
    """Resolve expected 64-hex SHA-256 for `base_qcow2` (explicit -> `HASH_FILE` -> `GOLDEN_BASE_IMAGE_SHA256`)."""
    if explicit_base_sha256 is not None:
        cand = str(explicit_base_sha256).strip().lower()
        if not _SHA256_RE.match(cand):
            raise PilotStagingError(f"Invalid explicit base_image_sha256: {explicit_base_sha256!r}")
        return cand

    hpath = Path(hash_file)
    tgt_str = str(base_qcow2)
    tgt_name = Path(base_qcow2).name
    if hpath.is_file():
        for line in hpath.read_text(encoding="utf-8", errors="ignore").splitlines():
            parts = line.strip().split(maxsplit=1)
            if len(parts) != 2:
                continue
            digest, fname = parts[0].strip().lower(), parts[1].lstrip("*").strip()
            if _SHA256_RE.match(digest) and (fname == tgt_str or Path(fname).name == tgt_name):
                return digest
    return GOLDEN_BASE_IMAGE_SHA256.lower()


def _parse_utc_iso(raw: Any, field_name: str) -> datetime:
    if not isinstance(raw, str) or not raw.strip():
        raise PilotStagingError(f"BLOCKED (--canary gate): Canary stamp missing {field_name!r}")
    s = raw.strip()
    if s.endswith("Z"):
        s = s[:-1] + "+00:00"
    try:
        dt = datetime.fromisoformat(s)
    except ValueError as exc:
        raise PilotStagingError(f"BLOCKED (--canary gate): Invalid {field_name!r} timestamp {raw!r}") from exc
    if dt.tzinfo is None:
        raise PilotStagingError(f"BLOCKED (--canary gate): Timezone-naive timestamp in {field_name!r}: {raw!r}")
    return dt.astimezone(timezone.utc)


def verify_canary_run_outputs(
    results_log: Sequence[Mapping[str, Any]],
    runs_out_dir: str | Path,
    stamp_path: str | Path,
    *,
    batch_json_sha256: str,
    base_image_sha256: str,
    git_head: str,
    git_dirty: bool,
    now_utc: datetime | None = None,
    ttl_seconds: int = CANARY_STAMP_TTL_SECONDS,
) -> dict[str, Any]:
    """Validate `--canary` outputs (control+dormant+executed, Sysmon EVTX) & write cryptographically bound stamp."""
    if not _SHA256_RE.match(str(batch_json_sha256 or "")):
        raise PilotStagingError(f"CANARY FAILED: Invalid batch_json_sha256={batch_json_sha256!r}")
    if not _SHA256_RE.match(str(base_image_sha256 or "")):
        raise PilotStagingError(f"CANARY FAILED: Invalid base_image_sha256={base_image_sha256!r}")
    if not git_head or not str(git_head).strip():
        raise PilotStagingError("CANARY FAILED: Invalid git_head for canary stamp binding")
    if int(ttl_seconds) <= 0:
        raise PilotStagingError(f"CANARY FAILED: ttl_seconds must be positive, got {ttl_seconds}")

    out_root = Path(runs_out_dir)
    strata_seen = {str(r.get("stratum") or "") for r in results_log}
    missing_strata = [s for s in ("control", "dormant", "executed") if s not in strata_seen]
    if missing_strata:
        raise PilotStagingError(
            f"CANARY FAILED: --canary requires control, dormant, and executed runs; missing={missing_strata}"
        )

    exec_sysmon_total = 0
    for rec in results_log:
        rdir = Path(rec["out_dir"])
        man_path = rdir / "extraction_manifest.json"
        if not man_path.is_file():
            raise PilotStagingError(f"CANARY FAILED: Missing extraction_manifest.json for run {rec['run_id']!r}")
        man = json.loads(man_path.read_text(encoding="utf-8"))
        if int(man.get("total_records") or 0) <= 0:
            raise PilotStagingError(f"CANARY FAILED: Zero extracted records for run {rec['run_id']!r}")
        if rec.get("stratum") == "executed":
            if not man.get("sysmon_evtx_present") or int(man.get("sysmon_events_count") or 0) <= 0:
                raise PilotStagingError(
                    f"CANARY FAILED: Executed canary run {rec['run_id']!r} yielded 0 Sysmon EVTX events"
                )
            exec_sysmon_total += int(man.get("sysmon_events_count") or 0)

    verified_dt = (now_utc or datetime.now(timezone.utc)).astimezone(timezone.utc)
    expires_dt = verified_dt + timedelta(seconds=int(ttl_seconds))
    stamp_payload = {
        "status": "PASS",
        "verified_at_utc": verified_dt.isoformat(),
        "expires_at_utc": expires_dt.isoformat(),
        "ttl_seconds": int(ttl_seconds),
        "batch_json_sha256": str(batch_json_sha256).lower(),
        "base_image_sha256": str(base_image_sha256).lower(),
        "git_head": str(git_head).strip().lower(),
        "git_dirty": bool(git_dirty),
        "runs_out_dir": str(out_root),
        "n_canary_runs": len(results_log),
        "run_ids": [r["run_id"] for r in results_log],
        "executed_sysmon_events_total": exec_sysmon_total,
    }
    sp = Path(stamp_path)
    sp.parent.mkdir(parents=True, exist_ok=True)
    sp.write_text(json.dumps(stamp_payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return stamp_payload


def validate_canary_stamp(
    stamp_path: str | Path,
    *,
    expected_batch_sha256: str,
    expected_base_sha256: str,
    expected_git_head: str,
    expected_git_dirty: bool,
    now_utc: datetime | None = None,
    ttl_seconds: int = CANARY_STAMP_TTL_SECONDS,
    reject_dirty: bool = True,
) -> dict[str, Any]:
    """Fail-closed validation of `CANARY_PASSED` stamp binding, git cleanliness, and 24h expiry."""
    sp = Path(stamp_path)
    if not sp.is_file():
        raise PilotStagingError(
            f"BLOCKED (--canary gate): Required canary stamp missing at {sp}. "
            "Run with --canary first before unattended malware execution."
        )
    try:
        stamp_data = json.loads(sp.read_text(encoding="utf-8"))
    except Exception as exc:
        raise PilotStagingError(f"BLOCKED (--canary gate): Invalid canary stamp {sp}: {exc}") from exc
    if not isinstance(stamp_data, dict):
        raise PilotStagingError(f"BLOCKED (--canary gate): Canary stamp {sp} is not a JSON object.")

    if stamp_data.get("status") != "PASS":
        raise PilotStagingError(
            f"BLOCKED (--canary gate): Canary stamp status is {stamp_data.get('status')!r}, expected 'PASS'."
        )

    st_batch = str(stamp_data.get("batch_json_sha256") or "").strip().lower()
    if not _SHA256_RE.match(st_batch) or st_batch != str(expected_batch_sha256).strip().lower():
        raise PilotStagingError(
            f"BLOCKED (--canary gate): Canary stamp batch_json_sha256 mismatch "
            f"(stamp={st_batch or 'missing'}, current={str(expected_batch_sha256).lower()}). Re-run --canary."
        )

    st_base = str(stamp_data.get("base_image_sha256") or "").strip().lower()
    if not _SHA256_RE.match(st_base) or st_base != str(expected_base_sha256).strip().lower():
        raise PilotStagingError(
            f"BLOCKED (--canary gate): Canary stamp base_image_sha256 mismatch "
            f"(stamp={st_base or 'missing'}, current={str(expected_base_sha256).lower()}). Re-run --canary."
        )

    st_head = str(stamp_data.get("git_head") or "").strip().lower()
    cur_head = str(expected_git_head or "").strip().lower()
    if not st_head or st_head == "unknown" or cur_head == "unknown" or st_head != cur_head:
        raise PilotStagingError(
            f"BLOCKED (--canary gate): Canary stamp git_head mismatch "
            f"(stamp={st_head or 'missing'}, current={cur_head or 'missing'}). Commit & re-run --canary."
        )

    if not isinstance(stamp_data.get("git_dirty"), bool):
        raise PilotStagingError("BLOCKED (--canary gate): Canary stamp missing boolean 'git_dirty' field.")
    st_dirty = bool(stamp_data["git_dirty"])
    if st_dirty != bool(expected_git_dirty):
        raise PilotStagingError(
            f"BLOCKED (--canary gate): Git working tree dirty state changed since canary "
            f"(stamp git_dirty={st_dirty}, current git_dirty={bool(expected_git_dirty)}). Re-run --canary."
        )
    if reject_dirty and (st_dirty or bool(expected_git_dirty)):
        raise PilotStagingError(
            "BLOCKED (--canary gate): Unattended malware runs refuse dirty git working trees "
            f"(stamp git_dirty={st_dirty}, current git_dirty={bool(expected_git_dirty)}). Commit changes & re-run --canary."
        )

    verified_dt = _parse_utc_iso(stamp_data.get("verified_at_utc"), "verified_at_utc")
    expires_dt = _parse_utc_iso(stamp_data.get("expires_at_utc"), "expires_at_utc")
    cur_now = (now_utc or datetime.now(timezone.utc)).astimezone(timezone.utc)
    if verified_dt > cur_now + timedelta(seconds=60):
        raise PilotStagingError(
            f"BLOCKED (--canary gate): Canary stamp verified_at_utc is in the future ({verified_dt.isoformat()})."
        )
    age_sec = (cur_now - verified_dt).total_seconds()
    if age_sec > float(ttl_seconds) or cur_now > expires_dt:
        raise PilotStagingError(
            f"BLOCKED (--canary gate): Canary stamp EXPIRED (verified={verified_dt.isoformat()}, "
            f"expires={expires_dt.isoformat()}, age={age_sec:.0f}s > {ttl_seconds}s). Re-run --canary."
        )

    if int(stamp_data.get("n_canary_runs") or 0) < 3 or int(stamp_data.get("executed_sysmon_events_total") or 0) <= 0:
        raise PilotStagingError(
            "BLOCKED (--canary gate): Canary stamp lacks valid >=3 runs and Sysmon EVTX verification."
        )
    return stamp_data


def _append_jsonl(path: Path, row: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(dict(row), sort_keys=True) + "\n")


def _load_completed_run_ids(checkpoint_path: Path) -> set[str]:
    done: set[str] = set()
    if not checkpoint_path.is_file():
        return done
    for line in checkpoint_path.read_text(encoding="utf-8").splitlines():
        s = line.strip()
        if not s:
            continue
        try:
            rec = json.loads(s)
            if rec.get("run_id"):
                done.add(str(rec["run_id"]))
        except json.JSONDecodeError:
            continue
    return done


def execute_stage_a_pilot_batch(
    batch_runs: Sequence[Mapping[str, Any]],
    runs_out_dir: str | Path,
    base_qcow2: str | Path = "/var/lib/libvirt/images/win11_base.qcow2",
    overlay_qcow2: str | Path = "/var/lib/libvirt/images/win11_overlay.qcow2",
    base_cache_path: str | Path | None = "/var/lib/dfir-quarantine-vault/win11_base_cache.json.gz",
    vault_root: str | Path = "~/.quarantine_vault_dfir_v2",
    win_domain: str = "win11",
    inetsim_domain: str = "inetsim-vm",
    libvirt_uri: str = "qemu:///system",
    inetsim_wait_seconds: int = 8,
    keep_inetsim_warm: bool = True,
    watchdog_grace_seconds: int = 180,
    dry_run: bool = False,
    run_cmd: Callable[..., int] | None = None,
    sleep_fn: Callable[[float], None] = time.sleep,
    canary_mode: bool = False,
    require_canary_stamp: bool = False,
    canary_stamp_path: str | Path | None = None,
    full_base_hash_every: int = 25,
    enable_pipelining: bool = False,
    resume: bool = True,
    benign_pools_root: str | Path | None = None,
    max_in_drop_burst: int = 2000,
    cmd_output_fn: Callable[[list[str], Mapping[str, str] | None], tuple[int, str]] | None = None,
    batch_json_path: str | Path | None = None,
    batch_json_sha256: str | None = None,
    base_image_sha256: str | None = None,
    canary_ttl_seconds: int = CANARY_STAMP_TTL_SECONDS,
    reject_dirty_git: bool = True,
    git_state_fn: Callable[[Path], Mapping[str, Any]] | None = None,
    now_fn: Callable[[], datetime] | None = None,
    confirm_input_fn: Callable[[str], str] = input,
    stage: str = "a",
    require_real_pools: bool | None = None,
) -> list[dict[str, Any]]:
    """Execute or dry-run a Stage A/B batch with detached watchdog, egress checks, base checks & optional pipelining."""
    st_stage = str(stage or "a").strip().lower()
    if st_stage not in ("a", "b"):
        raise ValueError(f"stage must be 'a' or 'b', got {stage!r}")
    eff_require_real_pools = (st_stage == "b") if require_real_pools is None else bool(require_real_pools)

    repo_root = Path(__file__).resolve().parent.parent.parent
    watchdog_script = repo_root / "docs" / "v2" / "hardening" / "04_watchdog_and_base_hash.sh"
    bake_script = repo_root / "docs" / "v2" / "hardening" / "00_bake_v2_base_image.sh"
    vault_script = repo_root / "docs" / "v2" / "hardening" / "05_quarantine_vault_setup.sh"
    out_root = Path(runs_out_dir)
    out_root.mkdir(parents=True, exist_ok=True)
    stage_tmp_root = out_root / "_staging_iso"
    stage_tmp_root.mkdir(parents=True, exist_ok=True)
    vroot = Path(vault_root).expanduser()
    eff_canary_stamp = Path(canary_stamp_path) if canary_stamp_path is not None else (out_root / "CANARY_PASSED")
    checkpoint_path = out_root / "completed_runs.jsonl"
    egress_audit_path = out_root / "egress_audit.jsonl"

    eff_batch_sha256 = (
        str(batch_json_sha256).strip().lower()
        if batch_json_sha256 is not None
        else compute_batch_json_sha256(batch_json_path=batch_json_path, batch_runs=batch_runs)
    )
    eff_base_sha256 = resolve_base_image_sha256(base_qcow2, explicit_base_sha256=base_image_sha256)
    git_state = dict(git_state_fn(repo_root) if git_state_fn is not None else get_git_head_state(repo_root))
    eff_git_head = str(git_state.get("git_head") or "unknown").strip().lower()
    eff_git_dirty = bool(git_state.get("git_dirty", True))

    parsed_entries: list[tuple[StageRunSpec, Mapping[str, Any]]] = []
    has_malware_run = False
    for entry in batch_runs:
        raw_spec = entry["spec"]
        spec = raw_spec if isinstance(raw_spec, StageRunSpec) else StageRunSpec(**dict(raw_spec))
        validate_stage_run_spec(spec)
        if spec.stratum in ("dormant", "executed", "dormant_batch"):
            has_malware_run = True
        parsed_entries.append((spec, entry))

    if canary_mode:
        canary_strata = {spec.stratum for spec, _ in parsed_entries}
        if not {"control", "dormant", "executed"}.issubset(canary_strata):
            raise PilotStagingError(
                f"canary_mode requires at least 1 control, 1 dormant, and 1 executed run (got {sorted(canary_strata)})"
            )
        if eff_git_dirty and not dry_run:
            print(
                "WARNING: Working tree has uncommitted changes (git_dirty=True); unattended batches will reject this canary stamp.",
                file=sys.stderr,
            )

    if has_malware_run and not dry_run:
        if not (vroot / "GATE0_SIGNED_OFF").is_file():
            raise PilotStagingError(
                f"BLOCKED (OD-V2-07): Gate 0 marker missing at {vroot / 'GATE0_SIGNED_OFF'}."
            )
        rc_pre = _invoke_cmd(run_cmd, ["bash", str(vault_script), "preflight"], {"VAULT_ROOT": str(vroot)})
        if rc_pre != 0:
            raise PilotStagingError(f"Vault preflight failed with exit code {rc_pre}")
        if require_canary_stamp and not canary_mode:
            validate_canary_stamp(
                eff_canary_stamp,
                expected_batch_sha256=eff_batch_sha256,
                expected_base_sha256=eff_base_sha256,
                expected_git_head=eff_git_head,
                expected_git_dirty=eff_git_dirty,
                now_utc=(now_fn() if now_fn is not None else None),
                ttl_seconds=canary_ttl_seconds,
                reject_dirty=reject_dirty_git,
            )

    completed_ids = _load_completed_run_ids(checkpoint_path) if (resume and not canary_mode and not dry_run) else set()
    pending_entries = [(spec, entry) for spec, entry in parsed_entries if spec.run_id not in completed_ids]

    inetsim_cmds = build_inetsim_lifecycle_commands(domain=inetsim_domain, libvirt_uri=libvirt_uri)
    verify_full_cmd = ["bash", str(watchdog_script), "verify-base"]
    verify_fast_cmd = ["bash", str(watchdog_script), "verify-base-fast"]
    prep_cmd = ["bash", str(bake_script), "prepare-overlay", str(base_qcow2), str(overlay_qcow2)]
    egress_snap_cmd = ["bash", str(watchdog_script), "check-egress", "snapshot"]

    if pending_entries and not dry_run:
        rc_start = _invoke_cmd(run_cmd, verify_full_cmd, dry_run=dry_run)
        if rc_start != 0:
            raise RuntimeError(f"Initial full base-image SHA-256 check failed (rc={rc_start})")

    results_log: list[dict[str, Any]] = []
    pool_exec = ThreadPoolExecutor(max_workers=1) if enable_pipelining else None
    pending_future: Future[dict[str, Any]] | None = None

    def _run_extract_and_cleanup(target_overlay: Path, rdir: Path, spec_obj: StageRunSpec, inet_booted: bool) -> dict[str, Any]:
        ext_cmd, ext_env = build_container_extraction_command(
            overlay_qcow2=target_overlay,
            run_out_dir=rdir,
            run_id=spec_obj.run_id,
            base_cache_path=base_cache_path,
        )
        rc_ext = _invoke_cmd(run_cmd, ext_cmd, env_overrides=ext_env, dry_run=dry_run)
        if rc_ext != 0:
            raise RuntimeError(f"Offline container extraction failed for run {spec_obj.run_id!r} (rc={rc_ext})")
        _invoke_cmd(run_cmd, ["sudo", "rm", "-f", str(target_overlay)], dry_run=dry_run)
        rec_out = {
            "run_id": spec_obj.run_id,
            "stratum": spec_obj.stratum,
            "sample_family": spec_obj.sample_family,
            "pair_group_id": spec_obj.pair_group_id,
            "inetsim_booted": bool(inet_booted),
            "out_dir": str(rdir),
            "dry_run": bool(dry_run),
            "completed_at_utc": utc_now_iso(),
        }
        if not dry_run:
            _append_jsonl(checkpoint_path, rec_out)
        return rec_out

    detonate_confirmed = False
    inetsim_warm = False
    try:
        for run_idx, (spec, entry) in enumerate(pending_entries, start=1):
            if spec.stratum != "executed" and inetsim_warm:
                # Tear down warm INetSim before non-executed runs so control/dormant baselines stay isolated.
                _invoke_cmd(run_cmd, inetsim_cmds["destroy"], dry_run=dry_run)
                inetsim_warm = False

            if canary_mode and not dry_run and spec.stratum == "executed" and not detonate_confirmed:
                prompt = (
                    f"[CANARY SAFETY CONFIRMATION] About to boot INetSim + Win11 VM and DETONATE malware "
                    f"(run_id={spec.run_id!r}, family={spec.sample_family!r}, sha256={spec.sample_sha256!r}). "
                    "Type DETONATE to proceed: "
                )
                try:
                    ans = str(confirm_input_fn(prompt)).strip()
                except (EOFError, KeyboardInterrupt) as exc:
                    raise PilotStagingError("CANARY ABORTED: Missing operator 'DETONATE' confirmation.") from exc
                if ans != "DETONATE":
                    raise PilotStagingError(
                        f"CANARY ABORTED: Expected exact confirmation 'DETONATE', got {ans!r}."
                    )
                detonate_confirmed = True

            run_dir = out_root / spec.run_id
            stage_dir = stage_tmp_root / spec.run_id
            iso_path = stage_dir / f"run_stage_{spec.run_id}.iso"
            lease_file = stage_tmp_root / f"wd_{spec.run_id}.lease"
            inetsim_started = False
            run_failed = False

            rc_eg_pre, out_eg_pre = _invoke_cmd_capture(run_cmd, cmd_output_fn, egress_snap_cmd, dry_run=dry_run)
            if rc_eg_pre != 0:
                raise RuntimeError(f"Pre-run virbr1 egress firewall check failed before {spec.run_id!r} (rc={rc_eg_pre})")
            eg_before = _parse_json_snapshot(out_eg_pre)

            rc_prep = _invoke_cmd(run_cmd, prep_cmd, dry_run=dry_run)
            if rc_prep != 0:
                raise RuntimeError(f"prepare-overlay failed for run {spec.run_id!r} (rc={rc_prep})")

            vault_file = entry.get("vault_file")
            vault_files = entry.get("vault_files")
            raw_ben_script = entry.get("benign_script_text")
            if spec.stratum == "dormant_batch":
                if not dry_run or vault_files is not None:
                    build_dormant_batch_bundle(
                        spec=spec,
                        out_dir=stage_dir,
                        sample_vault_files=vault_files or (),
                        benign_script_text=raw_ben_script,
                        archive_password=entry.get("archive_password", "infected"),
                        benign_pools_root=benign_pools_root,
                        require_real_pools=eff_require_real_pools,
                    )
            elif not dry_run or spec.stratum == "control" or (vault_file is not None and Path(vault_file).exists()):
                build_stage_bundle(
                    spec=spec,
                    out_dir=stage_dir,
                    sample_vault_file=vault_file,
                    benign_script_text=raw_ben_script,
                    archive_password=entry.get("archive_password", "infected"),
                    benign_pools_root=benign_pools_root,
                    require_real_pools=eff_require_real_pools,
                )

            attach_cmd = [
                "sudo", "virsh", "-c", libvirt_uri, "attach-disk",
                win_domain, str(iso_path), "sdc", "--type", "cdrom", "--mode", "readonly", "--config",
            ]
            if _invoke_cmd(run_cmd, attach_cmd, dry_run=dry_run) != 0:
                raise RuntimeError(f"Failed to attach DFIR_STAGE ISO for run {spec.run_id!r}")

            arm_sec = int(spec.dwell_seconds) + int(watchdog_grace_seconds) + 30
            arm_cmd = [
                "bash", str(watchdog_script), "arm-watchdog",
                str(arm_sec), str(lease_file), win_domain, inetsim_domain,
            ]
            if _invoke_cmd(run_cmd, arm_cmd, dry_run=dry_run) != 0:
                raise RuntimeError(f"Failed to arm detached host watchdog before starting {spec.run_id!r}")

            base_err_msg: str | None = None
            egress_err_msg: str | None = None
            try:
                if spec.stratum == "executed":
                    need_start = True
                    if keep_inetsim_warm and inetsim_warm:
                        if run_cmd is None and cmd_output_fn is None and not dry_run:
                            rc_dom, out_dom = _invoke_cmd_capture(
                                None, None, inetsim_cmds["domstate"], dry_run=False
                            )
                            if rc_dom == 0 and out_dom.strip().lower() == "running":
                                need_start = False
                            else:
                                print(
                                    f"WARNING: warm {inetsim_domain} state={out_dom.strip()!r} (rc={rc_dom}); restarting cleanly.",
                                    file=sys.stderr,
                                )
                                inetsim_warm = False
                        else:
                            need_start = False

                    if need_start:
                        rc_inet = _invoke_cmd(run_cmd, inetsim_cmds["start"], dry_run=dry_run)
                        if rc_inet != 0:
                            raise RuntimeError(f"Failed to start {inetsim_domain} for executed run {spec.run_id!r}")
                        if not dry_run and inetsim_wait_seconds > 0:
                            sleep_fn(float(inetsim_wait_seconds))
                    inetsim_started = True
                    inetsim_warm = bool(keep_inetsim_warm)

                start_win = ["sudo", "virsh", "-c", libvirt_uri, "start", win_domain]
                if _invoke_cmd(run_cmd, start_win, dry_run=dry_run) != 0:
                    raise RuntimeError(f"Failed to start {win_domain} for run {spec.run_id!r}")

                wd_cmd = ["bash", str(watchdog_script), "watchdog", str(int(spec.dwell_seconds) + int(watchdog_grace_seconds))]
                rc_wd = _invoke_cmd(run_cmd, wd_cmd, dry_run=dry_run)
                if rc_wd not in (0, 124):
                    raise RuntimeError(f"Watchdog aborted run {spec.run_id!r} unexpectedly (rc={rc_wd})")
            except Exception:
                run_failed = True
                raise
            finally:
                _invoke_cmd(run_cmd, ["sudo", "virsh", "-c", libvirt_uri, "destroy", win_domain], dry_run=dry_run)
                if (inetsim_started or inetsim_warm) and (run_failed or not keep_inetsim_warm):
                    _invoke_cmd(run_cmd, inetsim_cmds["destroy"], dry_run=dry_run)
                    inetsim_warm = False
                _invoke_cmd(run_cmd, ["bash", str(watchdog_script), "disarm-watchdog", str(lease_file)], dry_run=dry_run)
                _invoke_cmd(
                    run_cmd,
                    ["sudo", "virsh", "-c", libvirt_uri, "detach-disk", win_domain, "sdc", "--config"],
                    dry_run=dry_run,
                )
                shutil.rmtree(stage_dir, ignore_errors=True)

                rc_eg_post, out_eg_post = _invoke_cmd_capture(run_cmd, cmd_output_fn, egress_snap_cmd, dry_run=dry_run)
                eg_after = _parse_json_snapshot(out_eg_post)
                eg_delta = evaluate_egress_delta(eg_before, eg_after, max_in_drop_burst=max_in_drop_burst)
                if rc_eg_post != 0:
                    egress_err_msg = f"Post-run virbr1 egress firewall check failed after {spec.run_id!r} (rc={rc_eg_post})"
                elif not eg_delta["passed"]:
                    egress_err_msg = f"Unauthorized virbr1 egress/rule drift after {spec.run_id!r}: {eg_delta['errors']}"
                if not dry_run:
                    _append_jsonl(egress_audit_path, {
                        "run_id": spec.run_id,
                        "checked_at_utc": utc_now_iso(),
                        "rc_before": rc_eg_pre,
                        "rc_after": rc_eg_post,
                        **eg_delta,
                    })

                do_full_hash = run_failed or (int(full_base_hash_every) > 0 and (run_idx % int(full_base_hash_every) == 0))
                b_cmd = verify_full_cmd if do_full_hash else verify_fast_cmd
                rc_base = _invoke_cmd(run_cmd, b_cmd, dry_run=dry_run)
                if rc_base != 0:
                    base_err_msg = f"Base immutability/hash check ({b_cmd[1]}) failed after run {spec.run_id!r} (rc={rc_base})"

                if not run_failed:
                    if egress_err_msg:
                        raise RuntimeError(egress_err_msg)
                    if base_err_msg:
                        raise RuntimeError(base_err_msg)

            if enable_pipelining and pool_exec is not None:
                if pending_future is not None:
                    results_log.append(pending_future.result())
                    pending_future = None
                overlay_p = Path(overlay_qcow2)
                renamed_overlay = overlay_p.with_name(f"win11_overlay_{spec.run_id}.qcow2")
                if _invoke_cmd(run_cmd, ["sudo", "mv", "-f", str(overlay_p), str(renamed_overlay)], dry_run=dry_run) != 0:
                    raise RuntimeError(f"Failed to rename overlay for pipelined extraction: {overlay_p} -> {renamed_overlay}")
                pending_future = pool_exec.submit(_run_extract_and_cleanup, renamed_overlay, run_dir, spec, inetsim_started)
            else:
                results_log.append(_run_extract_and_cleanup(Path(overlay_qcow2), run_dir, spec, inetsim_started))

        if pending_future is not None:
            results_log.append(pending_future.result())
            pending_future = None
    finally:
        try:
            if pending_future is not None:
                results_log.append(pending_future.result())
        finally:
            if pool_exec is not None:
                pool_exec.shutdown(wait=True)
            if inetsim_warm:
                _invoke_cmd(run_cmd, inetsim_cmds["destroy"], dry_run=dry_run)
                inetsim_warm = False
            if pending_entries and not dry_run:
                rc_end = _invoke_cmd(run_cmd, verify_full_cmd, dry_run=dry_run)
                if rc_end != 0:
                    raise RuntimeError(f"Final full base-image SHA-256 verification failed (rc={rc_end})")

    if canary_mode and not dry_run:
        verify_canary_run_outputs(
            results_log,
            out_root,
            eff_canary_stamp,
            batch_json_sha256=eff_batch_sha256,
            base_image_sha256=eff_base_sha256,
            git_head=eff_git_head,
            git_dirty=eff_git_dirty,
            now_utc=(now_fn() if now_fn is not None else None),
            ttl_seconds=canary_ttl_seconds,
        )

    return results_log


def compute_od_v2_20_pilot_gate(df: pd.DataFrame, threshold_pct: float = 50.0) -> dict[str, Any]:
    """Compute the pre-scoring `OD-V2-20` go/no-go gate on pilot persistence/execution artifacts."""
    summary = summarize_extraction_and_refgraph(df, disk_id="stage_a_pilot")
    cov = summary.get("refgraph_coverage", {})
    pe_rows = int(cov.get("persistence_exec_rows", 0))
    pe_res = int(cov.get("persistence_exec_resolved_rows", 0))
    pe_pct = float(cov.get("persistence_exec_resolved_pct", 0.0))
    passed = pe_pct >= float(threshold_pct)
    return {
        "gate_id": "OD-V2-20",
        "computed_before_model_scoring": True,
        "threshold_pct": float(threshold_pct),
        "persistence_exec_rows": pe_rows,
        "persistence_exec_resolved_rows": pe_res,
        "persistence_exec_resolved_pct": pe_pct,
        "gate_passed": bool(passed),
        "v2_refgraph_status": "confirmatory_secondary" if passed else "exploratory_only",
        "per_type": cov.get("per_type", {}),
    }


def compute_empirical_family_power_table(
    lofo_df: pd.DataFrame,
    arm_a: str = "xgb",
    arm_b: str = "rf",
    f_test_candidates: Sequence[int] = (10, 15, 22, 25),
) -> dict[str, Any]:
    """Compute empirical between-family paired PR-AUC difference SD `sigma_delta_family` and 80%-power MDE."""
    piv = lofo_df.pivot(index="family", columns="model", values="pr_auc")
    if arm_a not in piv.columns or arm_b not in piv.columns:
        cols = list(piv.columns)
        if len(cols) >= 2:
            arm_a, arm_b = str(cols[0]), str(cols[1])
        else:
            return {
                "arm_a": arm_a,
                "arm_b": arm_b,
                "n_pilot_families": int(len(piv)),
                "sigma_delta_family": 0.0,
                "mde_by_f_test": {},
            }

    diffs = (piv[arm_a] - piv[arm_b]).dropna().to_numpy(dtype=float)
    sigma_f = float(np.std(diffs, ddof=1)) if len(diffs) > 1 else 0.0
    # Step-1 Holm-Bonferroni over m=10 fixed contrasts at two-sided alpha=0.05 -> alpha'=0.005 -> z=2.807
    # z_{0.80} = 0.8416 -> z_sum = 3.649
    z_step1 = 3.649
    z_step10 = 2.802

    mde_map: dict[int, dict[str, float]] = {}
    for f_test in f_test_candidates:
        ft = int(f_test)
        mde_map[ft] = {
            "mde_80pct_holm_step1": round(float(z_step1 * sigma_f / math.sqrt(ft)), 4),
            "mde_80pct_holm_step10": round(float(z_step10 * sigma_f / math.sqrt(ft)), 4),
        }

    return {
        "arm_a": arm_a,
        "arm_b": arm_b,
        "n_pilot_families": int(len(diffs)),
        "mean_paired_diff": round(float(np.mean(diffs)) if len(diffs) else 0.0, 4),
        "sigma_delta_family": round(sigma_f, 4),
        "mde_by_f_test": mde_map,
    }


def _ensure_feature_columns(df: pd.DataFrame) -> pd.DataFrame:
    out = df.copy()
    missing = [f for f in config.FEATURES if f not in out.columns]
    if not missing:
        return out
    feat_rows = [F.row_features(rec) for rec in out.to_dict(orient="records")]
    feat_df = pd.DataFrame(feat_rows, index=out.index)
    for col in missing:
        out[col] = feat_df[col]
    return out


def evaluate_stage_a_pilot_runs(
    control_runs: Sequence[pd.DataFrame],
    pilot_runs: Sequence[Mapping[str, Any]],
    arms: Sequence[str] = ("rf", "xgb", "iforest"),
    n_outer: int = 3,
    n_inner: int = 2,
    n_trials: int = 2,
    seed: int = config.SEED,
) -> dict[str, Any]:
    """Run the full Stage A Pilot evaluation pipeline over control boots + paired dormant/executed runs."""
    if len(control_runs) < 1:
        raise ValueError("Stage A pilot requires >= 1 clean control run to build multi-control baseline")

    for item in pilot_runs:
        spec = item["spec"]
        if not isinstance(spec, StageRunSpec):
            spec = StageRunSpec(**dict(spec))
        validate_stage_run_spec(spec)

    baseline_idx = build_multi_control_baseline(control_runs)

    labeled_dfs: list[pd.DataFrame] = []
    run_yield_rows: list[dict[str, Any]] = []

    for item in pilot_runs:
        spec: StageRunSpec = item["spec"] if isinstance(item["spec"], StageRunSpec) else StageRunSpec(**dict(item["spec"]))
        raw_df = item["df"].copy()
        sysmon_evs = list(item.get("sysmon_events") or [])
        ben_man = item.get("benign_manifest")
        sample_meta = {
            "sample_sha256": spec.sample_sha256,
            "sample_family": spec.sample_family,
            "pair_group_id": spec.pair_group_id,
            "run_duration_s": spec.dwell_seconds,
            "detonation_exit_status": item.get("detonation_exit_status", "clean_exit"),
            "packer_cluster": item.get("packer_cluster", f"pkr_{spec.sample_family}"),
        }

        if spec.stratum == "dormant":
            ldf = label_dormant_run(
                run_df=raw_df,
                baseline_index=baseline_idx,
                staged_manifest=[{"staged_path": spec.staging_target_path, "sample_sha256": spec.sample_sha256}],
                run_id=spec.run_id,
                sysmon_events=sysmon_evs,
                benign_manifest=ben_man,
                sample_meta=sample_meta,
            )
        elif spec.stratum == "dormant_batch":
            batch_items = [
                {
                    **dict(bm),
                    "packer_cluster": bm.get("packer_cluster") or f"pkr_{bm.get('sample_family')}",
                }
                for bm in spec.batch_samples
            ]
            ldf = label_dormant_batch_run(
                run_df=raw_df,
                baseline_index=baseline_idx,
                batch_manifest=batch_items,
                run_id=spec.run_id,
                sysmon_events=sysmon_evs,
                benign_manifest=ben_man,
                split_pool=spec.split_pool,
            )
        elif spec.stratum == "executed":
            ldf = label_executed_run(
                run_df=raw_df,
                baseline_index=baseline_idx,
                sysmon_events=sysmon_evs,
                run_id=spec.run_id,
                malware_root_hashes=[spec.sample_sha256] if spec.sample_sha256 else (),
                malware_root_guids=list(item.get("malware_root_guids") or ()),
                benign_scheduler_guids=list(item.get("benign_scheduler_guids") or ()),
                benign_manifest=ben_man,
                sample_meta=sample_meta,
            )
        else:
            raise PilotStagingError(
                f"Unsupported stratum in evaluate_stage_a_pilot_runs for run {spec.run_id!r}: {spec.stratum!r}"
            )

        ldf["split_pool"] = "dev"
        ldf = _ensure_feature_columns(ldf)
        labeled_dfs.append(ldf)

        vc = ldf[config.LABEL_COL].value_counts().to_dict()
        n_pos = int(vc.get(config.POSITIVE_LABEL, 0))
        n_amb = int(vc.get(AMBIGUOUS_LABEL, 0))
        n_drift = int(vc.get("benign_drift", 0))
        eff_fam = (
            ",".join(sorted({str(it.get("sample_family") or "") for it in spec.batch_samples if it.get("sample_family")})) or None
            if spec.stratum == "dormant_batch"
            else spec.sample_family
        )
        eff_pair = (
            spec.pair_group_id or f"batch_{spec.run_id}"
            if spec.stratum == "dormant_batch"
            else spec.pair_group_id
        )
        run_yield_rows.append({
            "run_id": spec.run_id,
            "stratum": spec.stratum,
            "sample_family": eff_fam,
            "pair_group_id": eff_pair,
            "total_rows": len(ldf),
            "attacker_induced": n_pos,
            "benign_drift": n_drift,
            "ambiguous_unattributed": n_amb,
            "detonation_success": bool(n_pos >= 1),
        })

    full_pilot_df = pd.concat(labeled_dfs, ignore_index=True)

    od_v2_20_gate = compute_od_v2_20_pilot_gate(full_pilot_df, threshold_pct=50.0)

    ben_files = full_pilot_df[
        (full_pilot_df[config.LABEL_COL].isin(["benign_drift", "baseline", "benign_baseline"]))
        & (full_pilot_df["artifact_type"] == "file")
    ]
    quant_check = (
        check_template_quantization(ben_files)
        if len(ben_files) >= 5
        else {"passed": True, "note": "insufficient_benign_files_in_fixture"}
    )

    eval_df = full_pilot_df[full_pilot_df[config.LABEL_COL] != AMBIGUOUS_LABEL].reset_index(drop=True)
    y_eval = (eval_df[config.LABEL_COL].astype(str) == config.POSITIVE_LABEL).astype(int).to_numpy()
    cat_cols, num_cols, bin_cols = split_feature_types(config.FEATURES)

    cv_res = run_nested_family_cv(
        dev_df=eval_df,
        y_dev=y_eval,
        arms=arms,
        cat_cols=cat_cols,
        num_cols=num_cols,
        bin_cols=bin_cols,
        n_outer=n_outer,
        n_inner=n_inner,
        n_trials=n_trials,
        seed=seed,
    )
    for arm_name, oof_arr in cv_res["outer_oof_scores"].items():
        eval_df[f"oof_{arm_name}"] = oof_arr

    score_cols = [f"oof_{a}" for a in arms]
    lofo_df = compute_lofo_table(eval_df, score_cols=score_cols)
    primary_arm = f"oof_{arms[0]}"
    exec_delta = cross_stratum_execution_delta(eval_df, score_col=primary_arm, n_boot=200, seed=seed)
    power_note = compute_empirical_family_power_table(
        lofo_df,
        arm_a=f"oof_{arms[1]}" if len(arms) > 1 else primary_arm,
        arm_b=primary_arm,
    )

    yield_df = pd.DataFrame(run_yield_rows)
    exec_yield = yield_df[yield_df["stratum"] == "executed"]
    dorm_yield = yield_df[yield_df["stratum"].isin(["dormant", "dormant_batch"])]

    return {
        "generated_at_utc": utc_now_iso(),
        "n_control_boots": len(control_runs),
        "n_pilot_runs": len(pilot_runs),
        "n_total_labeled_rows": len(full_pilot_df),
        "n_eval_rows_excluding_ambiguous": len(eval_df),
        "ambiguous_rate_pct": round(100.0 * float((full_pilot_df[config.LABEL_COL] == AMBIGUOUS_LABEL).mean()), 2),
        "executed_detonation_success_rate_pct": round(100.0 * float(exec_yield["detonation_success"].mean()), 2) if len(exec_yield) else 0.0,
        "executed_mean_positives_per_run": round(float(exec_yield["attacker_induced"].mean()), 2) if len(exec_yield) else 0.0,
        "dormant_mean_positives_per_run": round(float(dorm_yield["attacker_induced"].mean()), 2) if len(dorm_yield) else 0.0,
        "od_v2_20_gate": od_v2_20_gate,
        "template_quantization_gate": quant_check,
        "outer_oof_pr_auc": cv_res["outer_oof_pr_auc"],
        "cross_stratum_execution_delta": {k: v for k, v in exec_delta.items() if k != "per_sample_df"},
        "statistical_power_calibration": power_note,
        "yield_table": run_yield_rows,
    }


def write_stage_a_pilot_report(summary: Mapping[str, Any], out_md: str | Path) -> Path:
    """Format and write `STAGE_A_PILOT_REPORT.md` from `evaluate_stage_a_pilot_runs` output."""
    gate = summary["od_v2_20_gate"]
    pwr = summary["statistical_power_calibration"]
    delta = summary["cross_stratum_execution_delta"]
    lines = [
        "# Stage A Pilot Report (`OD-V2-05`, `OD-V2-20` Gate & Power Calibration)",
        "",
        f"**Generated UTC:** `{summary['generated_at_utc']}`  ",
        f"**Control Boots:** `{summary['n_control_boots']}` | **Paired Pilot Runs:** `{summary['n_pilot_runs']}` | "
        f"**Total Labeled Rows:** `{summary['n_total_labeled_rows']}`",
        "",
        "## 1. Pre-Scoring `OD-V2-20` Exploratory Diagnostic",
        f"- **Computed Before Model Scoring:** `{gate['computed_before_model_scoring']}`",
        f"- **Persistence/Execution Artifacts (`task`, `service`, `run_key`, `wmi_subscription`, `prefetch`):** "
        f"`{gate['persistence_exec_resolved_rows']} / {gate['persistence_exec_rows']}` (**`{gate['persistence_exec_resolved_pct']:.2f}%`** vs `{gate['threshold_pct']:.1f}%` threshold)",
        f"- **Diagnostic Status:** **`{gate['v2_refgraph_status']}`** (`gate_passed = {gate['gate_passed']}`)",
        "",
        "## 2. Empirical Yield & Quarantine Summary",
        f"- **Executed Detonation Success Rate:** `{summary['executed_detonation_success_rate_pct']:.2f}%`",
        f"- **Mean `attacker_induced` Positives / Run:** Executed = `{summary['executed_mean_positives_per_run']}`, Dormant = `{summary['dormant_mean_positives_per_run']}`",
        f"- **`ambiguous_unattributed` Quarantine Rate:** `{summary['ambiguous_rate_pct']:.2f}%`",
        "",
        "## 3. Cross-Stratum Execution Delta (`OD-V2-15`) & Nested Dev OOF PR-AUC",
        f"- **Nested OOF PR-AUC:** `{json.dumps(summary['outer_oof_pr_auc'], sort_keys=True)}`",
        f"- **`PR-AUC(executed)` vs `PR-AUC(dormant)`:** `{delta['pr_auc_executed']:.4f}` vs `{delta['pr_auc_dormant']:.4f}` "
        f"(`Delta_exec = {delta['delta_exec_pr_auc']:+.4f}`, median `Delta_first_hit = {delta['delta_first_hit_median']:+.1f}` ranks)",
        "",
        "## 4. Empirical Statistical-Power Calibration (`FINAL_EVAL_PLAN_v2_SKELETON.md` §6)",
        f"- **Pilot Families Evaluated:** `{pwr['n_pilot_families']}` (`{pwr['arm_a']}` vs `{pwr['arm_b']}`)",
        f"- **Empirical Between-Family Paired-Difference SD (`sigma_delta_family`):** **`{pwr['sigma_delta_family']:.4f}`**",
        f"- **80%-Power Minimum Detectable Effect (`MDE`) by Blind-Test Family Count `F_test`:** `{json.dumps(pwr['mde_by_f_test'], sort_keys=True)}`",
    ]
    out_p = Path(out_md)
    out_p.parent.mkdir(parents=True, exist_ok=True)
    out_p.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return out_p


def _select_canary_subset(runs: Sequence[Mapping[str, Any]]) -> list[dict[str, Any]]:
    """Slice a batch deterministically to `[first_control, first_executed, paired_or_first_dormant]` for `--canary`."""
    items = [dict(r) for r in runs]

    def _stratum(item: Mapping[str, Any]) -> str:
        spec = item.get("spec")
        if isinstance(spec, Mapping):
            return str(spec.get("stratum") or "").strip().lower()
        return str(getattr(spec, "stratum", "") or "").strip().lower()

    def _pair(item: Mapping[str, Any]) -> str:
        spec = item.get("spec")
        if isinstance(spec, Mapping):
            return str(spec.get("pair_group_id") or "").strip()
        return str(getattr(spec, "pair_group_id", "") or "").strip()

    first_ctrl = next((r for r in items if _stratum(r) == "control"), None)
    first_exec = next((r for r in items if _stratum(r) == "executed"), None)
    exec_pair = _pair(first_exec) if first_exec is not None else ""
    paired_dorm = next(
        (r for r in items if _stratum(r) == "dormant" and exec_pair and _pair(r) == exec_pair),
        None,
    )
    first_dorm = paired_dorm or next((r for r in items if _stratum(r) == "dormant"), None)
    chosen = [r for r in (first_ctrl, first_exec, first_dorm) if r is not None]
    if len(chosen) < 3:
        raise PilotStagingError(
            f"--canary requires at least 1 control, 1 executed, and 1 dormant run in batch (got {[_stratum(r) for r in chosen]})"
        )
    return chosen


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Unattended Stage A Pilot & collection orchestrator.")
    parser.add_argument("--batch-json", type=Path, required=True, help="Path to batch JSON (e.g., stage_a_pilot_batch.json)")
    parser.add_argument("--runs-out-dir", type=Path, required=True, help="Output directory for per-run extracted JSONL")
    parser.add_argument("--base-qcow2", type=Path, default=Path("/var/lib/libvirt/images/win11_base.qcow2"))
    parser.add_argument("--overlay-qcow2", type=Path, default=Path("/var/lib/libvirt/images/win11_overlay.qcow2"))
    parser.add_argument(
        "--base-cache-path",
        type=Path,
        default=Path("/var/lib/dfir-quarantine-vault/win11_base_cache.json.gz"),
    )
    parser.add_argument("--vault-root", type=Path, default=Path("~/.quarantine_vault_dfir_v2"))
    parser.add_argument("--benign-pools-root", type=Path, default=Path("/var/lib/dfir-quarantine-vault/benign_pools"))
    parser.add_argument("--canary-stamp-path", type=Path, default=None)
    parser.add_argument("--inetsim-wait-seconds", type=int, default=8)
    parser.add_argument(
        "--keep-inetsim-warm",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="Keep inetsim-vm warm across consecutive executed runs to skip redundant restart/wait cycles (default: True)",
    )
    parser.add_argument("--full-base-hash-every", type=int, default=25)
    parser.add_argument("--stage", choices=("a", "b"), default="a", help="Pipeline stage ('a' allows fallback unless --require-real-pools; 'b' enforces real pools by default)")
    parser.add_argument(
        "--require-real-pools",
        action=argparse.BooleanOptionalAction,
        default=None,
        help="Fail fatally if benign pool synthetic fallback would be used (default: off for Stage A, on for Stage B)",
    )
    parser.add_argument("--canary", action="store_true", help="Run supervised 3-boot canary check and write CANARY_PASSED stamp")
    parser.add_argument("--pipelined", action="store_true", help="Enable safe 1-lane pipelined container extraction")
    parser.add_argument("--no-resume", action="store_true", help="Do not skip runs already listed in completed_runs.jsonl")
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args(list(argv) if argv is not None else None)

    payload = json.loads(args.batch_json.read_text(encoding="utf-8"))
    runs = list(payload["runs"]) if isinstance(payload, dict) and "runs" in payload else list(payload)
    if args.canary:
        runs = _select_canary_subset(runs)
    executed = execute_stage_a_pilot_batch(
        batch_runs=runs,
        runs_out_dir=args.runs_out_dir,
        base_qcow2=args.base_qcow2,
        overlay_qcow2=args.overlay_qcow2,
        base_cache_path=args.base_cache_path,
        vault_root=args.vault_root,
        inetsim_wait_seconds=args.inetsim_wait_seconds,
        keep_inetsim_warm=args.keep_inetsim_warm,
        dry_run=args.dry_run,
        canary_mode=args.canary,
        require_canary_stamp=(not args.canary and not args.dry_run),
        canary_stamp_path=args.canary_stamp_path,
        full_base_hash_every=args.full_base_hash_every,
        enable_pipelining=args.pipelined,
        resume=not args.no_resume,
        benign_pools_root=args.benign_pools_root,
        batch_json_path=args.batch_json,
        stage=args.stage,
        require_real_pools=args.require_real_pools,
    )
    print(json.dumps({"completed_runs": len(executed), "runs": executed}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
