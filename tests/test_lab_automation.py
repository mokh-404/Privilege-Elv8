"""Unit tests for Step 6 (techniques catalog sanitization, Win11 overlay lifecycle, interleaving, resume)."""
import json
import subprocess
from collections import namedtuple
from pathlib import Path

import pytest
import yaml

from lab_automation import run_all, run_one
from lab_automation.guest_runner import CommandResult, GuestRunner
from src import config
from src.data.sanitize import find_forbidden


CATALOG_PATH = config.TECHNIQUES_YAML
BENIGN_PS1 = config.LAB_DIR / "benign_noise.ps1"


def _load_catalog():
    return yaml.safe_load(CATALOG_PATH.read_text(encoding="utf-8"))


# ---------------- Catalog & FE-08 sanitization checks ----------------
def test_techniques_catalog_structure_and_split():
    cat = _load_catalog()
    techs = cat["techniques"]
    assert len(techs) == 16
    tactics = {t["tactic"] for t in techs}
    assert len(tactics) == 6
    holdouts = [t for t in techs if t["split"] == "holdout"]
    devs = [t for t in techs if t["split"] == "dev"]
    assert len(holdouts) == 5
    assert len(devs) == 11
    assert len({t["tactic"] for t in holdouts}) >= config.MIN_HOLDOUT_TACTICS
    assert all(len(t["variants"]) == 3 for t in techs)

    # Verify YAML split matches seeded stratified draw (seed=42)
    proposed = run_all.propose_holdout_split(techs, seed=config.HOLDOUT_TECHNIQUE_DRAW_SEED)
    assert {t["technique_id"]: t["split"] for t in techs} == proposed


def test_all_48_rendered_variants_and_benign_script_have_zero_forbidden_tokens():
    cat = _load_catalog()
    for t in cat["techniques"]:
        for v in t["variants"]:
            script = run_one.render_attack_script(v, seed=42)
            assert find_forbidden(script) == [], f"Forbidden token in {t['technique_id']} v{v['variant']}"
            for key in v["expected_artifact_keys"]:
                assert find_forbidden(key) == [], f"Forbidden token in expected key {key!r}"
                assert config.ARTIFACT_KEY_SEP in key

    benign_src = BENIGN_PS1.read_text(encoding="utf-8")
    assert find_forbidden(benign_src) == []


def test_run_list_counts_full_and_dry_run():
    cat = _load_catalog()
    full = run_all.build_run_list(cat, dry_run=False, n_controls=3)
    assert len(full) == 51
    assert sum(1 for r in full if r["mode"] == "control") == 3
    assert sum(1 for r in full if r["mode"] == "attack") == 48

    dry = run_all.build_run_list(cat, dry_run=True)
    assert len(dry) == 3
    assert [r["split"] for r in dry] == ["control", "dev", "holdout"]


# ---------------- Interleaving determinism & Win11 overlay lifecycle ----------------
def test_interleaving_schedule_deterministic_and_bounded():
    s1 = run_one.build_interleaving_schedule(seed=42, n_attack_steps=2)
    s2 = run_one.build_interleaving_schedule(seed=42, n_attack_steps=2)
    assert s1 == s2
    assert 0.0 <= s1.benign_offset_s <= 20.0
    assert 0.0 <= s1.attack_offset_s <= 20.0
    assert set(s1.benign_order) == set(run_one.BENIGN_STEPS)
    assert s1.benign_offset_s != s1.attack_offset_s


def test_overlay_command_construction():
    assert run_one.build_overlay_cmd("/var/lib/libvirt/images/b.qcow2", "/var/lib/libvirt/images/o.qcow2") == [
        "qemu-img", "create", "-f", "qcow2", "-F", "qcow2", "-b",
        "/var/lib/libvirt/images/b.qcow2", "/var/lib/libvirt/images/o.qcow2",
    ]
    assert run_one.build_overlay_cmd("/b.qcow2", "/o.qcow2", use_sudo=True)[0] == "sudo"


class _FakeRunner(GuestRunner):
    def __init__(self, fail_attack: bool = False):
        self.fail_attack = fail_attack
        self.calls: list[str] = []
        self.uploaded: list[tuple[Path, str]] = []
        self.downloaded: list[tuple[str, Path]] = []

    def wait_ready(self, timeout_s: int = 180, poll_interval_s: float = 3.0) -> float:
        self.calls.append("wait_ready")
        return 0.5

    def run_powershell(self, script_text: str, timeout_s: int = 180) -> CommandResult:
        if script_text.strip().startswith("[void][System.IO.Directory]::CreateDirectory"):
            self.calls.append("mkdir_collector")
            return CommandResult(0, "", "", wrapper_pid=None)
        if "Collect-Artifacts.ps1" in script_text:
            self.calls.append(f"collect:{script_text}")
            return CommandResult(0, "COLLECTOR_DONE", "", wrapper_pid=None)
        if "$__order" in script_text:
            self.calls.append("benign")
            prov = json.dumps({
                "launcher": "benign", "action": "workspace_doc",
                "timestamp_utc": "2026-11-21T00:00:00Z", "expected_artifact_keys": ["file|a|b"],
                "wrapper_pid": 2001, "seed": 42,
            })
            return CommandResult(0, f"WRAPPER_PID=2001\nPROVENANCE:{prov}\n", "", wrapper_pid=2001)
        self.calls.append("attack")
        if self.fail_attack:
            return CommandResult(1, "WRAPPER_PID=2002\n", "simulated error", wrapper_pid=2002)
        prov = json.dumps({
            "launcher": "attack", "action": "stage_task_script",
            "timestamp_utc": "2026-11-21T00:00:01Z", "expected_artifact_keys": ["task|\\|x"],
            "wrapper_pid": 2002, "seed": 42,
        })
        return CommandResult(0, f"WRAPPER_PID=2002\nPROVENANCE:{prov}\n", "", wrapper_pid=2002)

    def upload_file(self, local_path: Path, remote_path: str, timeout_s: int = 60) -> None:
        self.uploaded.append((Path(local_path), remote_path))

    def download_dir(self, remote_dir: str, local_dir: Path, timeout_s: int = 120) -> None:
        self.downloaded.append((remote_dir, Path(local_dir)))
        Path(local_dir).mkdir(parents=True, exist_ok=True)
        (Path(local_dir) / "manifest.json").write_text('{"total_records": 1}', encoding="utf-8")


def test_win11_persistent_domain_lifecycle_and_cleanup(tmp_path):
    cmds: list[list[str]] = []
    dom_states = iter(["running", "shut off"])

    def fake_subproc(cmd, **kwargs):
        cmds.append(list(cmd))
        out = ""
        if "domstate" in cmd:
            out = next(dom_states, "shut off")
        return subprocess.CompletedProcess(cmd, 0, stdout=out, stderr="")

    cfg = run_one.LabConfig(
        run_output_dir=str(tmp_path / "runs"),
        post_ssh_settle_seconds=20,
        post_launchers_flush_seconds=5,
    )
    cat = _load_catalog()
    tech = cat["techniques"][0]
    runner = _FakeRunner()
    sleeps: list[float] = []

    res = run_one.run_single(
        cfg, run_id="run_test_01", mode="attack",
        technique=tech, variant_spec=tech["variants"][0], seed=42,
        runner=runner, run_cmd=fake_subproc, sleep_fn=sleeps.append,
        provenance_dir=tmp_path / "prov",
    )
    assert res["status"] == "success"
    assert set(res["wrapper_pids"]) == {2001, 2002}
    # Never uses transient `virsh create`
    assert not any("create" in c and "virsh" in c for c in cmds)
    # Must destroy running domain, rebuild overlay from base, restore NVRAM, start win11, shutdown, remove overlay
    assert ["virsh", "-c", "qemu:///system", "destroy", "win11"] in cmds
    assert ["qemu-img", "create", "-f", "qcow2", "-F", "qcow2", "-b", cfg.base_image, cfg.overlay_image] in cmds
    assert ["cp", "-f", cfg.nvram_base, cfg.nvram_active] in cmds
    assert ["virsh", "-c", "qemu:///system", "start", "win11"] in cmds
    assert ["virsh", "-c", "qemu:///system", "shutdown", "win11"] in cmds
    assert cmds[-1] == ["rm", "-f", cfg.overlay_image]

    # Settle (20s) + flush (5s) occurred
    assert 20 in sleeps and 5 in sleeps
    # Collector received both wrapper PIDs to exclude
    col_call = next(c for c in runner.calls if c.startswith("collect:"))
    assert "-ExcludePids @(2001,2002)" in col_call or "-ExcludePids @(2002,2001)" in col_call
    # Host provenance log contains both launchers
    prov_lines = [json.loads(l) for l in (tmp_path / "prov" / "run_test_01.jsonl").read_text().splitlines()]
    assert {r["launcher"] for r in prov_lines} == {"benign", "attack"}


def test_win11_cleanup_runs_on_launcher_failure(tmp_path):
    cmds: list[list[str]] = []

    def fake_subproc(cmd, **kwargs):
        cmds.append(list(cmd))
        return subprocess.CompletedProcess(cmd, 0, stdout="shut off", stderr="")

    cfg = run_one.LabConfig(run_output_dir=str(tmp_path / "runs"))
    cat = _load_catalog()
    runner = _FakeRunner(fail_attack=True)

    with pytest.raises(RuntimeError):
        run_one.run_single(
            cfg, run_id="run_fail", mode="attack",
            technique=cat["techniques"][0], variant_spec=cat["techniques"][0]["variants"][0],
            runner=runner, run_cmd=fake_subproc, sleep_fn=lambda _: None,
            provenance_dir=tmp_path / "prov",
        )
    assert ["virsh", "-c", "qemu:///system", "shutdown", "win11"] in cmds
    assert cmds[-1] == ["rm", "-f", cfg.overlay_image]


# ---------------- Resume, retry-once, and disk guard ----------------
def test_resume_and_retry_once(tmp_path):
    cat = _load_catalog()
    dry_runs = run_all.build_run_list(cat, dry_run=True)
    dev_rid = dry_runs[1]["run_id"]
    hold_rid = dry_runs[2]["run_id"]
    runs_dir = tmp_path / "runs"
    cfg = run_one.LabConfig(run_output_dir=str(runs_dir), min_free_disk_gb=30.0)
    run_table = tmp_path / "run_table.csv"

    attempts_seen: dict[str, int] = {}

    def flaky_runner(cfg_arg, run_id, mode, technique, variant_spec, seed):
        attempts_seen[run_id] = attempts_seen.get(run_id, 0) + 1
        # 2nd run fails once then succeeds on retry; 3rd run fails permanently
        if run_id == dev_rid and attempts_seen[run_id] == 1:
            raise RuntimeError("transient ssh glitch")
        if run_id == hold_rid:
            raise RuntimeError("persistent error")
        (runs_dir / run_id).mkdir(parents=True, exist_ok=True)
        (runs_dir / run_id / "manifest.json").write_text("{}", encoding="utf-8")
        return {"status": "success", "duration_s": 1.2}

    Disk = namedtuple("Disk", "total used free")
    ok_disk = lambda _p: Disk(500 * 1024**3, 100 * 1024**3, 400 * 1024**3)

    df1 = run_all.run_batch(cfg, cat, dry_run=True, resume=False, run_table_path=run_table,
                            single_runner=flaky_runner, disk_usage_fn=ok_disk)
    assert list(df1["status"]) == ["success", "success", "failed"]
    assert list(df1["attempts"]) == [1, 2, 2]

    # Resume should skip the 2 succeeded runs and only re-attempt the failed one
    attempts_seen.clear()
    df2 = run_all.run_batch(cfg, cat, dry_run=True, resume=True, run_table_path=run_table,
                            single_runner=flaky_runner, disk_usage_fn=ok_disk)
    assert set(attempts_seen) == {hold_rid}
    assert len(df2) == 3


def test_disk_guard_aborts_below_30gb(tmp_path):
    cat = _load_catalog()
    cfg = run_one.LabConfig(run_output_dir=str(tmp_path / "runs"), min_free_disk_gb=30.0)
    Disk = namedtuple("Disk", "total used free")
    low_disk = lambda _p: Disk(100 * 1024**3, 80 * 1024**3, 20 * 1024**3)
    with pytest.raises(RuntimeError, match="free disk"):
        run_all.run_batch(cfg, cat, dry_run=True, run_table_path=tmp_path / "rt.csv",
                          single_runner=lambda *a, **kw: {}, disk_usage_fn=low_disk)
