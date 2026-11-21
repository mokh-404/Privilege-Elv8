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
        if "SSHD_PIDS=" in script_text:
            self.calls.append("sshd_pids")
            return CommandResult(0, "SSHD_PIDS=1100,1104\n", "", wrapper_pid=None)
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
    assert res["sshd_pids"] == [1100, 1104]
    for k in ("reset_s", "boot_to_ssh_s", "settle_s", "launchers_s", "flush_s",
              "collection_s", "scp_s", "teardown_s", "total_s"):
        assert k in res["timings"]

    # Never uses transient `virsh create`
    assert not any("create" in c and "virsh" in c for c in cmds)
    # Exact reset order: destroy -> rm -f -> qemu-img create -> chown -> cp NVRAM -> virsh start -> shutdown -> rm -f
    expected_seq = [
        ["virsh", "-c", "qemu:///system", "destroy", "win11"],
        ["rm", "-f", cfg.overlay_image],
        ["qemu-img", "create", "-f", "qcow2", "-F", "qcow2", "-b", cfg.base_image, cfg.overlay_image],
        ["chown", cfg.overlay_owner, cfg.overlay_image],
        ["cp", cfg.nvram_base, cfg.nvram_live],
        ["virsh", "-c", "qemu:///system", "start", "win11"],
        ["virsh", "-c", "qemu:///system", "shutdown", "win11"],
        ["rm", "-f", cfg.overlay_image],
    ]
    indices = [cmds.index(c) if i < len(expected_seq) - 1 else len(cmds) - 1 - cmds[::-1].index(c)
               for i, c in enumerate(expected_seq)]
    assert indices == sorted(indices)
    assert cmds[-1] == ["rm", "-f", cfg.overlay_image]

    # Settle (20s) + flush (5s) occurred
    assert 20 in sleeps and 5 in sleeps
    # Collector received both sshd and wrapper PIDs to exclude
    col_call = next(c for c in runner.calls if c.startswith("collect:"))
    assert "-ExcludePids @(1100,1104,2001,2002)" in col_call
    # Host provenance log contains both launchers + runner_meta with sshd_pids & wrapper_pids
    prov_lines = [json.loads(l) for l in (tmp_path / "prov" / "run_test_01.jsonl").read_text().splitlines()]
    assert {r["launcher"] for r in prov_lines} == {"benign", "attack", "runner_meta"}
    meta_rec = next(r for r in prov_lines if r["launcher"] == "runner_meta")
    assert meta_rec["sshd_pids"] == [1100, 1104]
    assert set(meta_rec["wrapper_pids"]) == {2001, 2002}


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
    runs_dir = tmp_path / "dry_runs"
    cfg = run_one.LabConfig(
        run_output_dir=str(tmp_path / "runs"),
        dry_run_output_dir=str(runs_dir),
        dry_run_provenance_dir=str(tmp_path / "dry_prov"),
        min_free_disk_gb=30.0,
    )
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


def test_lab_config_from_yaml_win11_fields():
    cfg = run_one.LabConfig.from_yaml(config.LAB_DIR / "lab_config.example.yaml")
    assert cfg.nvram_live == "/var/lib/libvirt/qemu/nvram/win11_VARS.fd"
    assert cfg.nvram_active == cfg.nvram_live
    assert cfg.overlay_owner == "nobody:nobody"
    assert cfg.use_sudo_for_libvirt_files is True
    assert not hasattr(cfg, "domain_xml_template")


def test_sudo_reset_uses_only_five_allowed_binaries():
    cmds: list[list[str]] = []
    allowed_sudo_bins = {
        "/usr/bin/virsh",
        "/usr/bin/qemu-img",
        "/usr/bin/chown",
        "/usr/bin/cp",
        "/usr/bin/rm",
    }

    def fake_subproc(cmd, **kwargs):
        cmds.append(list(cmd))
        out = "running\n" if "domstate" in cmd and len(cmds) == 1 else "shut off\n"
        return subprocess.CompletedProcess(cmd, 0, stdout=out, stderr="")

    cfg = run_one.LabConfig(use_sudo_for_libvirt_files=True, overlay_owner="nobody:nobody")
    run_one.prepare_fresh_win11_state(cfg, run_cmd=fake_subproc)
    run_one.shutdown_and_cleanup_win11(cfg, run_cmd=fake_subproc, sleep_fn=lambda _: None)

    sudo_cmds = [c for c in cmds if c[0] == "sudo"]
    assert sudo_cmds, "Expected sudo commands when use_sudo_for_libvirt_files=True"
    for sc in sudo_cmds:
        assert sc[1] == "-n"
        assert sc[2] in allowed_sudo_bins
    assert not any("virsh" in " ".join(c) and "create" in c for c in cmds)

    expected_sudo_seq = [
        ["sudo", "-n", "/usr/bin/rm", "-f", cfg.overlay_image],
        ["sudo", "-n", "/usr/bin/qemu-img", "create", "-f", "qcow2", "-F", "qcow2", "-b", cfg.base_image, cfg.overlay_image],
        ["sudo", "-n", "/usr/bin/chown", "nobody:nobody", cfg.overlay_image],
        ["sudo", "-n", "/usr/bin/cp", cfg.nvram_base, cfg.nvram_live],
        ["sudo", "-n", "/usr/bin/rm", "-f", cfg.overlay_image],
    ]
    assert sudo_cmds == expected_sudo_seq


def test_dry_run_isolation_from_real_runs(tmp_path, monkeypatch):
    cat = _load_catalog()
    monkeypatch.setattr(config, "LOGS_DIR", tmp_path / "logs")
    real_dir = tmp_path / "real_runs"
    dry_dir = tmp_path / "dry_runs"
    cfg = run_one.LabConfig(
        run_output_dir=str(real_dir),
        dry_run_output_dir=str(dry_dir),
        dry_run_provenance_dir=str(tmp_path / "dry_prov"),
        min_free_disk_gb=30.0,
    )
    seen_out_dirs: list[str] = []

    def stub_runner(cfg_arg, run_id, mode, technique, variant_spec, seed):
        seen_out_dirs.append(cfg_arg.run_output_dir)
        out = Path(cfg_arg.run_output_dir) / run_id
        out.mkdir(parents=True, exist_ok=True)
        (out / "manifest.json").write_text("{}", encoding="utf-8")
        return {"status": "success", "duration_s": 2.0, "timings": {"boot_to_ssh_s": 1.0}}

    Disk = namedtuple("Disk", "total used free")
    ok_disk = lambda _p: Disk(500 * 1024**3, 100 * 1024**3, 400 * 1024**3)
    df = run_all.run_batch(cfg, cat, dry_run=True, resume=False, single_runner=stub_runner, disk_usage_fn=ok_disk)
    assert len(df) == 3
    assert seen_out_dirs == [str(dry_dir)] * 3
    assert not real_dir.exists()
    assert (tmp_path / "logs" / "dry_run_table.csv").exists()
    assert not (tmp_path / "logs" / "run_table.csv").exists()


def test_render_attack_uses_native_ps_array_and_ssh_uses_scriptblock():
    from lab_automation.guest_runner import SSHGuestRunner

    cat = _load_catalog()
    script = run_one.render_attack_script(cat["techniques"][0]["variants"][0], seed=42)
    assert "ConvertFrom-Json" not in script
    assert "expected_artifact_keys=@(" in script

    captured_cmds = []
    def fake_run(cmd, **kwargs):
        captured_cmds.append(cmd)
        return subprocess.CompletedProcess(cmd, 0, stdout="WRAPPER_PID=500\n", stderr="")

    runner = SSHGuestRunner("192.168.150.50", "mokh", "/tmp/id", run_cmd=fake_run)
    res = runner.run_powershell("Write-Output ok")
    assert res.wrapper_pid == 500
    assert "Invoke-Command -ScriptBlock ([scriptblock]::Create([Console]::In.ReadToEnd()))" in captured_cmds[0][-1]


def test_run_single_fails_if_benign_emits_no_provenance(tmp_path):
    class _SilentBenignRunner(_FakeRunner):
        def run_powershell(self, script_text: str, timeout_s: int = 180) -> CommandResult:
            if "$__order" in script_text:
                return CommandResult(0, "", "", wrapper_pid=None)
            return super().run_powershell(script_text, timeout_s=timeout_s)

    cfg = run_one.LabConfig(run_output_dir=str(tmp_path / "runs"))
    cat = _load_catalog()
    with pytest.raises(RuntimeError, match="did not emit WRAPPER_PID"):
        run_one.run_single(
            cfg, run_id="run_silent", mode="attack",
            technique=cat["techniques"][0], variant_spec=cat["techniques"][0]["variants"][0],
            runner=_SilentBenignRunner(),
            run_cmd=lambda cmd, **kw: subprocess.CompletedProcess(cmd, 0, stdout="shut off", stderr=""),
            sleep_fn=lambda _: None,
            provenance_dir=tmp_path / "prov",
        )
