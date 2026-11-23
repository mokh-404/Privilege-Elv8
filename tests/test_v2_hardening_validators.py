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
