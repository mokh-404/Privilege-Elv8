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
