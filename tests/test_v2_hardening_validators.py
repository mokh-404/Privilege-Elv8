"""Tests for Step D hardening kit: domain/network XML validator and shell script syntax."""
from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from docs.v2.hardening.check_domain_xml import validate_domain_xml, validate_network_xml


HARDENING_DIR = Path(__file__).resolve().parents[1] / "docs" / "v2" / "hardening"

VALID_DOMAIN_XML = """
<domain type='kvm'>
  <name>win11</name>
  <devices>
    <disk type='file' device='disk'>
      <driver name='qemu' type='qcow2'/>
      <source file='/var/lib/libvirt/images/win11_overlay.qcow2'/>
      <target dev='vda' bus='virtio'/>
    </disk>
    <interface type='network'>
      <mac address='52:54:00:ba:30:f3'/>
      <source network='win11-isolated'/>
      <model type='virtio'/>
    </interface>
    <graphics type='spice' listen='127.0.0.1'>
      <clipboard copypaste='no'/>
      <filetransfer enable='no'/>
    </graphics>
  </devices>
</domain>
"""

VALID_NET_XML = """
<network>
  <name>win11-isolated</name>
  <bridge name='virbr1' stp='on' delay='0'/>
  <ip address='192.168.150.1' netmask='255.255.255.0'/>
</network>
"""


def test_hardened_xml_passes():
    assert validate_domain_xml(VALID_DOMAIN_XML) == []
    assert validate_network_xml(VALID_NET_XML) == []


@pytest.mark.parametrize(
    "bad_xml,substr",
    [
        (VALID_DOMAIN_XML.replace("copypaste='no'", "copypaste='yes'"), "clipboard"),
        (VALID_DOMAIN_XML.replace("<clipboard copypaste='no'/>", ""), "clipboard"),
        (VALID_DOMAIN_XML.replace("enable='no'", "enable='yes'"), "filetransfer"),
        (VALID_DOMAIN_XML.replace("</devices>", "<channel type='spicevmc'><target type='virtio' name='com.redhat.spice.0'/></channel></devices>"), "Forbidden channel"),
        (VALID_DOMAIN_XML.replace("</devices>", "<filesystem type='mount'><source dir='/tmp'/><target dir='share'/></filesystem></devices>"), "filesystem"),
        (VALID_DOMAIN_XML.replace("</devices>", "<redirdev bus='usb' type='spicevmc'/></devices>"), "redirdev"),
        (VALID_DOMAIN_XML.replace("</devices>", "<hostdev mode='subsystem' type='usb'/></devices>"), "hostdev"),
        (VALID_DOMAIN_XML.replace("win11-isolated", "default"), "win11-isolated"),
    ],
)
def test_insecure_domain_xml_rejected(bad_xml, substr):
    errs = validate_domain_xml(bad_xml)
    assert errs
    assert any(substr.lower() in e.lower() for e in errs)


def test_network_xml_with_forward_rejected():
    bad_net = VALID_NET_XML.replace("</network>", "<forward mode='nat'/></network>")
    errs = validate_network_xml(bad_net)
    assert errs and any("forward" in e.lower() for e in errs)


def test_all_hardening_shell_scripts_pass_bash_n():
    scripts = sorted(HARDENING_DIR.glob("*.sh"))
    assert len(scripts) >= 5
    for sc in scripts:
        cp = subprocess.run(["bash", "-n", str(sc)], capture_output=True, text=True)
        assert cp.returncode == 0, f"bash -n failed for {sc.name}: {cp.stderr}"


def test_firewall_script_cleans_ufw_user_chains_and_inserts_at_position_1():
    fw_txt = (HARDENING_DIR / "01_firewall_win11_isolated.sh").read_text(encoding="utf-8")
    for uch in ("ufw-user-input", "ufw-user-output", "ufw-user-forward"):
        assert uch in fw_txt
    assert 'iptables -I INPUT 1 -i "$BRIDGE" -j V2_VIRBR1_IN' in fw_txt
    assert 'iptables -I FORWARD 1 -i "$BRIDGE" -j V2_VIRBR1_FWD' in fw_txt
    assert 'iptables -I FORWARD 2 -o "$BRIDGE" -j V2_VIRBR1_FWD' in fw_txt


def test_unprivileged_container_runner_mounts_overlay_backing_cache_and_build(tmp_path):
    import json
    import os
    import shutil

    runner = HARDENING_DIR / "06_unprivileged_container_runner.sh"
    dockerfile = HARDENING_DIR / "offline_extractor.Dockerfile"
    req_txt = (HARDENING_DIR / "requirements_extractor.txt").read_text(encoding="utf-8")
    df_txt = dockerfile.read_text(encoding="utf-8")
    assert "COPY src/utils/repro.py /app/src/utils/repro.py" in df_txt
    assert "/cache" in df_txt
    assert "scikit-learn" in req_txt

    qemu_img = shutil.which("qemu-img")
    assert qemu_img is not None

    img_dir = tmp_path / "imgs"
    img_dir.mkdir()
    base_img = img_dir / "win11_base.qcow2"
    overlay_img = img_dir / "win11_overlay.qcow2"
    subprocess.run([qemu_img, "create", "-f", "qcow2", str(base_img), "64K"], check=True, capture_output=True)
    subprocess.run(
        [qemu_img, "create", "-f", "qcow2", "-F", "qcow2", "-b", "win11_base.qcow2", str(overlay_img)],
        check=True,
        capture_output=True,
    )

    cache_file = tmp_path / "win11_base_cache.json.gz"
    cache_file.write_bytes(b"stub_cache")
    out_dir = tmp_path / "out_dir"
    log_json = tmp_path / "shim_argv.json"

    shim = tmp_path / "fake_docker.sh"
    mode_log = tmp_path / "out_mode.txt"
    shim.write_text(
        f"""#!/usr/bin/env python3
import json, stat, sys
from pathlib import Path
out_p = Path({str(out_dir)!r})
if len(sys.argv) > 1 and sys.argv[1] == "run":
    Path({str(mode_log)!r}).write_text(oct(stat.S_IMODE(out_p.stat().st_mode)))
Path({str(log_json)!r}).write_text(json.dumps(sys.argv[1:]))
""",
        encoding="utf-8",
    )
    shim.chmod(0o755)

    env = dict(os.environ, CONTAINER_RT=str(shim))
    cp_run = subprocess.run(
        ["bash", str(runner), str(overlay_img), str(out_dir), "test_run", str(cache_file)],
        env=env,
        capture_output=True,
        text=True,
        check=True,
    )
    assert cp_run.returncode == 0
    import stat

    # Must be 0777 during --cap-drop=ALL container run and restored to 0755 on exit
    assert mode_log.read_text(encoding="utf-8") == "0o777"
    assert stat.S_IMODE(out_dir.stat().st_mode) == 0o755
    argv = json.loads(log_json.read_text(encoding="utf-8"))
    for req_flag in ("--network=none", "--read-only", "--cap-drop=ALL", "--security-opt=no-new-privileges", "--user"):
        assert req_flag in argv
    assert f"{overlay_img.resolve()}:/input/win11_overlay.qcow2:ro" in argv
    assert f"{base_img.resolve()}:/input/win11_base.qcow2:ro" in argv
    assert f"{cache_file.resolve()}:/cache/base_cache.json.gz:ro" in argv
    assert "--qcow2" in argv and "/input/win11_overlay.qcow2" in argv
    assert "--out-dir" in argv and "/output" in argv
    assert "--run-id" in argv and "test_run" in argv
    assert "--base-cache-path" in argv and "/cache/base_cache.json.gz" in argv

    cp_build = subprocess.run(
        ["bash", str(runner), "--build"],
        env=env,
        capture_output=True,
        text=True,
        check=True,
    )
    assert cp_build.returncode == 0
    build_argv = json.loads(log_json.read_text(encoding="utf-8"))
    assert build_argv[0] == "build"
    assert "-f" in build_argv and str(dockerfile) in build_argv
    assert "-t" in build_argv and "dfir-v2-offline-extractor:latest" in build_argv


def test_inetsim_doc_uses_valid_inetsim_conf_directives():
    doc = (HARDENING_DIR / "03_inetsim_vm_setup.md").read_text(encoding="utf-8")
    assert "service_bind_address    192.168.150.10" in doc
    assert "start_service           dns" in doc
    assert "start_service           http" in doc
    assert "systemd-networkd-wait-online.service" in doc
    assert "service_run_services" not in doc


def _write_valid_gate0_marker(path: Path, mode: int = 0o400, override: str | None = None) -> None:
    if path.exists():
        path.chmod(0o600)
    text = override if override is not None else (
        "SIGNED_BY=Mokh\n"
        "DATE=2026-11-25\n"
        "SUPERVISOR_APPROVAL=Supervisor Marawan (AASTMT) 2026-11-25\n"
        "CONTAINMENT_CHECKS=NEG-01..NEG-10 PASS\n"
        "DEDICATED_USER_VERIFIED=true\n"
    )
    path.write_text(text, encoding="utf-8")
    path.chmod(mode)


def test_vault_gate0_strict_0400_fields_and_manifest_completeness(tmp_path):
    import os

    setup_sh = HARDENING_DIR / "05_quarantine_vault_setup.sh"
    vault = tmp_path / "vault"
    env = dict(os.environ, VAULT_ROOT=str(vault))
    subprocess.run(["bash", str(setup_sh), "init"], env=env, check=True, capture_output=True, text=True)

    # 1. Missing marker blocks preflight
    r_missing = subprocess.run(["bash", str(setup_sh), "preflight"], env=env, capture_output=True, text=True)
    assert r_missing.returncode != 0

    marker = vault / "GATE0_SIGNED_OFF"
    # 2. Empty marker even with 0400 blocks preflight
    _write_valid_gate0_marker(marker, mode=0o400, override="")
    r_empty = subprocess.run(["bash", str(setup_sh), "preflight"], env=env, capture_output=True, text=True)
    assert r_empty.returncode != 0

    # 3. Wrong permissions (0644) blocks preflight
    _write_valid_gate0_marker(marker, mode=0o644)
    r_mode = subprocess.run(["bash", str(setup_sh), "preflight"], env=env, capture_output=True, text=True)
    assert r_mode.returncode != 0 and "0400" in r_mode.stderr

    # 4. Placeholder / falsy required fields block preflight
    _write_valid_gate0_marker(
        marker,
        mode=0o400,
        override=(
            "SIGNED_BY=Mokh\n"
            "DATE=2026-11-25\n"
            "SUPERVISOR_APPROVAL=TBD\n"
            "CONTAINMENT_CHECKS=NEG-01..NEG-10 PASS\n"
            "DEDICATED_USER_VERIFIED=true\n"
        ),
    )
    r_tbd = subprocess.run(["bash", str(setup_sh), "preflight"], env=env, capture_output=True, text=True)
    assert r_tbd.returncode != 0

    _write_valid_gate0_marker(
        marker,
        mode=0o400,
        override=(
            "SIGNED_BY=Mokh\n"
            "DATE=2026-11-25\n"
            "SUPERVISOR_APPROVAL=Supervisor Marawan (AASTMT) 2026-11-25\n"
            "CONTAINMENT_CHECKS=NEG-01..NEG-10 PASS\n"
            "DEDICATED_USER_VERIFIED=false\n"
        ),
    )
    r_false = subprocess.run(["bash", str(setup_sh), "preflight"], env=env, capture_output=True, text=True)
    assert r_false.returncode != 0

    # 5. Valid 0400 marker passes empty vault preflight
    _write_valid_gate0_marker(marker, mode=0o400)
    r_ok = subprocess.run(["bash", str(setup_sh), "preflight"], env=env, capture_output=True, text=True)
    assert r_ok.returncode == 0

    # 6. Unmanifested 0400 archive in archives/ MUST fail preflight
    rogue_zip = vault / "archives" / ("a" * 64 + ".zip")
    rogue_zip.write_bytes(b"PK\x03\x04rogue_unmanifested")
    rogue_zip.chmod(0o400)
    r_unman = subprocess.run(["bash", str(setup_sh), "preflight"], env=env, capture_output=True, text=True)
    assert r_unman.returncode != 0

    # 7. Seal archive properly -> preflight passes again
    r_seal = subprocess.run(
        ["bash", str(setup_sh), "seal-archive", str(rogue_zip)], env=env, capture_output=True, text=True
    )
    assert r_seal.returncode == 0
    r_ok2 = subprocess.run(["bash", str(setup_sh), "preflight"], env=env, capture_output=True, text=True)
    assert r_ok2.returncode == 0


def test_watchdog_fast_verify_detached_timeout_and_egress_delta(tmp_path):
    import json
    import os
    import time

    wd_sh = HARDENING_DIR / "04_watchdog_and_base_hash.sh"
    base_img = tmp_path / "win11_base.qcow2"
    nvram = tmp_path / "win11_VARS.fd.base"
    inet_base = tmp_path / "inetsim_base.qcow2"
    hash_file = tmp_path / "v2_base_hashes.sha256"
    fast_meta = tmp_path / "v2_base_fast_meta.env"
    base_img.write_bytes(b"QCOW2_STUB_BASE_BYTES")
    nvram.write_bytes(b"NVRAM_STUB_BYTES")
    inet_base.write_bytes(b"INETSIM_STUB_BYTES")
    base_img.chmod(0o444)

    virsh_log = tmp_path / "virsh_calls.log"
    mock_virsh = tmp_path / "mock_virsh.sh"
    mock_virsh.write_text(
        f"""#!/usr/bin/env bash
echo "$*" >> {str(virsh_log)!r}
exit 0
""",
        encoding="utf-8",
    )
    mock_virsh.chmod(0o755)

    fw_mode_file = tmp_path / "fw_mode.txt"
    fw_mode_file.write_text("clean_0", encoding="utf-8")
    mock_ipt = tmp_path / "mock_ipt.sh"
    mock_ipt.write_text(
        f"""#!/usr/bin/env bash
mode="$(cat {str(fw_mode_file)!r})"
if [[ "$1" == "-S" && "$2" == "INPUT" ]]; then
  if [[ "$mode" == "bad_pos" ]]; then
    echo "-A INPUT -i eth0 -j ACCEPT"
  else
    echo "-A INPUT -i virbr1 -j V2_VIRBR1_IN"
  fi
elif [[ "$1" == "-S" && "$2" == "FORWARD" ]]; then
  echo "-A FORWARD -i virbr1 -j V2_VIRBR1_FWD"
  echo "-A FORWARD -o virbr1 -j V2_VIRBR1_FWD"
elif [[ "$1" == "-L" && "$2" == "V2_VIRBR1_FWD" ]]; then
  if [[ "$mode" == "egress_leak" ]]; then
    echo "    4 400 ACCEPT all -- * * virbr1 virbr1 0.0.0.0/0 0.0.0.0/0"
    echo "    3 180 DROP all -- * * virbr1 !virbr1 0.0.0.0/0 0.0.0.0/0"
  else
    echo "    4 400 ACCEPT all -- * * virbr1 virbr1 0.0.0.0/0 0.0.0.0/0"
    echo "    0 0 DROP all -- * * virbr1 !virbr1 0.0.0.0/0 0.0.0.0/0"
  fi
elif [[ "$1" == "-L" && "$2" == "V2_VIRBR1_IN" ]]; then
  echo "    2 120 ACCEPT all -- * * virbr1 * 0.0.0.0/0 0.0.0.0/0"
  echo "    1 60 DROP all -- * * virbr1 * 0.0.0.0/0 0.0.0.0/0"
fi
exit 0
""",
        encoding="utf-8",
    )
    mock_ipt.chmod(0o755)

    env = dict(
        os.environ,
        BASE_IMG=str(base_img),
        NVRAM_BASE=str(nvram),
        INETSIM_BASE=str(inet_base),
        HASH_FILE=str(hash_file),
        FAST_META_FILE=str(fast_meta),
        SKIP_LSATTR_CHECK="1",
        GOLDEN_BASE_SHA256=__import__("hashlib").sha256(b"QCOW2_STUB_BASE_BYTES").hexdigest(),
        VIRSH_BIN=str(mock_virsh),
        IPTABLES_BIN=str(mock_ipt),
        WATCHDOG_BACKEND="setsid",
    )

    subprocess.run(["bash", str(wd_sh), "record-base"], env=env, check=True, capture_output=True, text=True)
    assert subprocess.run(["bash", str(wd_sh), "verify-base-fast"], env=env, capture_output=True).returncode == 0

    # Tampering NVRAM fails fast verify
    nvram.write_bytes(b"NVRAM_CORRUPTED")
    assert subprocess.run(["bash", str(wd_sh), "verify-base-fast"], env=env, capture_output=True).returncode != 0
    nvram.write_bytes(b"NVRAM_STUB_BYTES")

    # Arm + immediate disarm cancels detached watchdog cleanly
    lease1 = tmp_path / "lease_cancel.env"
    subprocess.run(["bash", str(wd_sh), "arm-watchdog", "20", str(lease1), "win11", "inetsim-vm"], env=env, check=True)
    subprocess.run(["bash", str(wd_sh), "disarm-watchdog", str(lease1)], env=env, check=True)
    time.sleep(0.3)
    assert not (tmp_path / "lease_cancel.env.status").exists()
    assert not virsh_log.exists()

    # Arm with 1s deadline triggers TIMEOUT_KILLED over BOTH win11 and inetsim-vm
    lease2 = tmp_path / "lease_timeout.env"
    subprocess.run(["bash", str(wd_sh), "arm-watchdog", "1", str(lease2), "win11", "inetsim-vm"], env=env, check=True)
    deadline = time.time() + 4.5
    while time.time() < deadline and not (tmp_path / "lease_timeout.env.status").exists():
        time.sleep(0.15)
    assert (tmp_path / "lease_timeout.env.status").read_text(encoding="utf-8").strip() == "TIMEOUT_KILLED"
    calls = virsh_log.read_text(encoding="utf-8")
    assert "destroy win11" in calls and "destroy inetsim-vm" in calls

    # Egress snapshot + verify (clean vs leak vs bad rule position)
    snap_before = tmp_path / "eg_before.json"
    snap_after_ok = tmp_path / "eg_after_ok.json"
    snap_after_leak = tmp_path / "eg_after_leak.json"
    snap_after_badpos = tmp_path / "eg_after_badpos.json"

    r_b = subprocess.run(["bash", str(wd_sh), "check-egress", "snapshot"], env=env, capture_output=True, text=True, check=True)
    snap_before.write_text(r_b.stdout, encoding="utf-8")
    assert json.loads(r_b.stdout)["firewall_rules_valid"] is True

    r_ok = subprocess.run(["bash", str(wd_sh), "check-egress", "snapshot"], env=env, capture_output=True, text=True, check=True)
    snap_after_ok.write_text(r_ok.stdout, encoding="utf-8")
    assert subprocess.run(["bash", str(wd_sh), "check-egress", "verify", str(snap_before), str(snap_after_ok)], env=env).returncode == 0

    fw_mode_file.write_text("egress_leak", encoding="utf-8")
    r_leak = subprocess.run(["bash", str(wd_sh), "check-egress", "snapshot"], env=env, capture_output=True, text=True, check=True)
    snap_after_leak.write_text(r_leak.stdout, encoding="utf-8")
    assert subprocess.run(["bash", str(wd_sh), "check-egress", "verify", str(snap_before), str(snap_after_leak)], env=env).returncode != 0

    fw_mode_file.write_text("bad_pos", encoding="utf-8")
    r_bad = subprocess.run(["bash", str(wd_sh), "check-egress", "snapshot"], env=env, capture_output=True, text=True)
    assert r_bad.returncode != 0
    snap_after_badpos.write_text(r_bad.stdout, encoding="utf-8")
    assert subprocess.run(["bash", str(wd_sh), "check-egress", "verify", str(snap_before), str(snap_after_badpos)], env=env).returncode != 0


def test_container_runner_allows_pipelined_other_overlay_and_blocks_attached(tmp_path):
    import os
    import shutil

    runner = HARDENING_DIR / "06_unprivileged_container_runner.sh"
    qemu_img = shutil.which("qemu-img")
    assert qemu_img is not None

    base_img = tmp_path / "win11_base.qcow2"
    ov_done = tmp_path / "win11_overlay_run_01.qcow2"
    ov_active = tmp_path / "win11_overlay_run_02.qcow2"
    subprocess.run([qemu_img, "create", "-f", "qcow2", str(base_img), "64K"], check=True, capture_output=True)
    subprocess.run([qemu_img, "create", "-f", "qcow2", "-F", "qcow2", "-b", str(base_img), str(ov_done)], check=True, capture_output=True)
    subprocess.run([qemu_img, "create", "-f", "qcow2", "-F", "qcow2", "-b", str(base_img), str(ov_active)], check=True, capture_output=True)

    cache_file = tmp_path / "win11_base_cache.json.gz"
    cache_file.write_bytes(b"stub_cache")
    fake_rt = tmp_path / "fake_docker.sh"
    fake_rt.write_text("#!/usr/bin/env bash\nexit 0\n", encoding="utf-8")
    fake_rt.chmod(0o755)

    mock_virsh = tmp_path / "mock_virsh_blk.sh"
    mock_virsh.write_text(
        f"""#!/usr/bin/env bash
if [[ "$*" == *"domstate win11"* ]]; then
  echo "running"
elif [[ "$*" == *"domblklist win11"* ]]; then
  echo " Type  Device  Target  Source"
  echo " file  disk    vda     {str(ov_active.resolve())}"
fi
exit 0
""",
        encoding="utf-8",
    )
    mock_virsh.chmod(0o755)

    env = dict(os.environ, CONTAINER_RT=str(fake_rt), VIRSH_BIN=str(mock_virsh), FORCE_VM_CHECK="1")
    r_pipe_ok = subprocess.run(
        ["bash", str(runner), str(ov_done), str(tmp_path / "out_1"), "run_01", str(cache_file)],
        env=env,
        capture_output=True,
        text=True,
    )
    assert r_pipe_ok.returncode == 0

    r_attached_blocked = subprocess.run(
        ["bash", str(runner), str(ov_active), str(tmp_path / "out_2"), "run_02", str(cache_file)],
        env=env,
        capture_output=True,
        text=True,
    )
    assert r_attached_blocked.returncode != 0
    assert "is still attached" in r_attached_blocked.stderr


def test_container_runner_fast_code_refresh_and_full_build_override(tmp_path):
    import json
    import os

    runner = HARDENING_DIR / "06_unprivileged_container_runner.sh"
    req_file = HARDENING_DIR / "requirements_extractor.txt"
    dockerfile = HARDENING_DIR / "offline_extractor.Dockerfile"
    calls_log = tmp_path / "docker_calls.jsonl"
    tags_seen_file = tmp_path / "tags_seen.txt"
    tags_seen_file.write_text("", encoding="utf-8")

    fake_docker = tmp_path / "fake_docker_refresh.sh"
    fake_docker.write_text(
        f"""#!/usr/bin/env python3
import json, sys
from pathlib import Path

args = sys.argv[1:]
with Path({str(calls_log)!r}).open("a", encoding="utf-8") as fh:
    fh.write(json.dumps(args) + "\\n")

tags_p = Path({str(tags_seen_file)!r})
known_tags = set(tags_p.read_text(encoding="utf-8").splitlines())

if len(args) >= 2 and args[0] == "image" and args[1] == "inspect":
    tgt = args[-1]
    if tgt == "dfir-v2-offline-extractor:latest":
        print("sha256:existing_local_image")
        sys.exit(0)
    if tgt in known_tags:
        print(tgt)
        sys.exit(0)
    sys.exit(1)

if args and args[0] == "tag":
    known_tags.add(args[2])
    tags_p.write_text("\\n".join(sorted(known_tags)) + "\\n", encoding="utf-8")
    sys.exit(0)

if args and args[0] == "run" and "/app/requirements_extractor.txt" in args:
    sys.stdout.write(Path({str(req_file)!r}).read_text(encoding="utf-8"))
    sys.exit(0)

sys.exit(0)
""",
        encoding="utf-8",
    )
    fake_docker.chmod(0o755)
    env = dict(os.environ, CONTAINER_RT=str(fake_docker))

    # 1. Default --build with unchanged requirements_extractor.txt uses fast offline code-only refresh
    cp_fast = subprocess.run(["bash", str(runner), "--build"], env=env, capture_output=True, text=True, check=True)
    assert cp_fast.returncode == 0
    calls = [json.loads(ln) for ln in calls_log.read_text(encoding="utf-8").splitlines() if ln.strip()]
    assert any(c[0] == "tag" and c[2].startswith("dfir-v2-offline-extractor-deps:") for c in calls)
    build_fast = next(c for c in calls if c[0] == "build")
    assert "--pull=false" in build_fast
    assert str(dockerfile) not in build_fast

    # 2. --build --full bypasses fast refresh and builds directly from offline_extractor.Dockerfile
    calls_log.unlink()
    cp_full = subprocess.run(["bash", str(runner), "--build", "--full"], env=env, capture_output=True, text=True, check=True)
    assert cp_full.returncode == 0
    full_calls = [json.loads(ln) for ln in calls_log.read_text(encoding="utf-8").splitlines() if ln.strip()]
    assert len(full_calls) == 1
    assert full_calls[0][0] == "build"
    assert str(dockerfile) in full_calls[0]
    assert "--pull=false" not in full_calls[0]


def test_watchdog_golden_base_pin_no_overwrite_backup_and_nvram_warning(tmp_path):
    import hashlib
    import os

    wd_sh = HARDENING_DIR / "04_watchdog_and_base_hash.sh"
    wd_txt = wd_sh.read_text(encoding="utf-8")
    assert 'GOLDEN_BASE_SHA256="${GOLDEN_BASE_SHA256:-d2facced4255e3ae1cb821249d5e6330e380f639cee8a5aae19ef99be690835c}"' in wd_txt
    assert 'GOLDEN_NVRAM_SHA256="${GOLDEN_NVRAM_SHA256:-}"' in wd_txt

    base_img = tmp_path / "win11_base.qcow2"
    nvram = tmp_path / "win11_VARS.fd.base"
    hash_file = tmp_path / "v2_base_hashes.sha256"
    fast_meta = tmp_path / "v2_base_fast_meta.env"
    base_bytes = b"STUB_QCOW2_BASE_PIN_TEST"
    nvram_bytes = b"STUB_NVRAM_PIN_TEST"
    base_img.write_bytes(base_bytes)
    nvram.write_bytes(nvram_bytes)
    base_img.chmod(0o444)

    stub_base_sha = hashlib.sha256(base_bytes).hexdigest()
    stub_nvram_sha = hashlib.sha256(nvram_bytes).hexdigest()

    base_env = dict(
        os.environ,
        BASE_IMG=str(base_img),
        NVRAM_BASE=str(nvram),
        INETSIM_BASE=str(tmp_path / "missing_inetsim.qcow2"),
        HASH_FILE=str(hash_file),
        FAST_META_FILE=str(fast_meta),
        SKIP_LSATTR_CHECK="1",
    )

    # 1. Default pinned GOLDEN_BASE_SHA256 refuses mismatched base image without writing HASH_FILE
    r_bad_pin = subprocess.run(["bash", str(wd_sh), "record-base"], env=base_env, capture_output=True, text=True)
    assert r_bad_pin.returncode != 0
    assert "GOLDEN_BASE_SHA256" in r_bad_pin.stderr
    assert not hash_file.exists()

    # 2. Tampered HASH_FILE for a non-golden base image fails verify-base AND verify-base-fast
    hash_file.write_text(f"{stub_base_sha}  {base_img}\n{stub_nvram_sha}  {nvram}\n", encoding="utf-8")
    assert subprocess.run(["bash", str(wd_sh), "verify-base"], env=base_env, capture_output=True, text=True).returncode != 0
    assert subprocess.run(["bash", str(wd_sh), "verify-base-fast"], env=base_env, capture_output=True, text=True).returncode != 0
    hash_file.unlink()

    # 3. Matching GOLDEN_BASE_SHA256 + unset GOLDEN_NVRAM_SHA256 records hashes & warns loudly
    env_ok = dict(base_env, GOLDEN_BASE_SHA256=stub_base_sha, GOLDEN_NVRAM_SHA256="")
    r_rec = subprocess.run(["bash", str(wd_sh), "record-base"], env=env_ok, capture_output=True, text=True)
    assert r_rec.returncode == 0
    assert "WARNING:" in r_rec.stderr and "GOLDEN_NVRAM_SHA256" in r_rec.stderr
    assert hash_file.exists() and fast_meta.exists()

    # 4. Re-running record-base without FORCE_RECORD=1 refuses to overwrite HASH_FILE
    r_no_ow = subprocess.run(["bash", str(wd_sh), "record-base"], env=env_ok, capture_output=True, text=True)
    assert r_no_ow.returncode != 0
    assert "Refusing to overwrite" in r_no_ow.stderr
    assert not list(tmp_path.glob("v2_base_hashes.sha256.bak.*"))

    # 5. Mismatched GOLDEN_NVRAM_SHA256 refuses even with FORCE_RECORD=1 and writes no backup
    env_bad_nv = dict(env_ok, GOLDEN_NVRAM_SHA256="f" * 64, FORCE_RECORD="1")
    r_bad_nv = subprocess.run(["bash", str(wd_sh), "record-base"], env=env_bad_nv, capture_output=True, text=True)
    assert r_bad_nv.returncode != 0
    assert "GOLDEN_NVRAM_SHA256" in r_bad_nv.stderr
    assert not list(tmp_path.glob("v2_base_hashes.sha256.bak.*"))
    assert subprocess.run(["bash", str(wd_sh), "verify-base"], env=env_bad_nv, capture_output=True, text=True).returncode != 0

    # 6. FORCE_RECORD=1 with valid GOLDEN_NVRAM_SHA256 creates timestamped backup & passes verify-base
    env_pin_nv = dict(env_ok, GOLDEN_NVRAM_SHA256=stub_nvram_sha, FORCE_RECORD="1")
    r_force = subprocess.run(["bash", str(wd_sh), "record-base"], env=env_pin_nv, capture_output=True, text=True)
    assert r_force.returncode == 0
    assert "WARNING:" not in r_force.stderr
    assert len(list(tmp_path.glob("v2_base_hashes.sha256.bak.*"))) == 1
    assert len(list(tmp_path.glob("v2_base_fast_meta.env.bak.*"))) == 1
    assert subprocess.run(["bash", str(wd_sh), "verify-base"], env=env_pin_nv, capture_output=True, text=True).returncode == 0
