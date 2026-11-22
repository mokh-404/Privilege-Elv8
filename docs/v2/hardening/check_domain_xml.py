"""Read-only validator for libvirt domain & network XML hardening (Step D / IMP-01)."""
from __future__ import annotations

import argparse
import sys
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Iterable


def validate_domain_xml(
    xml_text: str,
    expected_network: str = "win11-isolated",
    expected_disk: str = "/var/lib/libvirt/images/win11_overlay.qcow2",
) -> list[str]:
    """Return a list of security policy violations found in a libvirt domain XML string."""
    errors: list[str] = []
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError as exc:
        return [f"Malformed domain XML: {exc}"]

    devices = root.find("devices")
    if devices is None:
        return ["Missing <devices> element in domain XML"]

    # 1. SPICE clipboard & filetransfer checks
    for gfx in devices.findall("graphics"):
        gtype = (gfx.attrib.get("type") or "").lower()
        listen = gfx.attrib.get("listen")
        if listen and listen not in ("127.0.0.1", "::1", "none"):
            errors.append(f"<graphics type='{gtype}'> listens on non-loopback address {listen!r}")
        if gtype == "spice":
            cb = gfx.find("clipboard")
            if cb is None or (cb.attrib.get("copypaste") or "").lower() != "no":
                errors.append("SPICE <clipboard copypaste='no'/> is missing or enabled")
            ft = gfx.find("filetransfer")
            if ft is None or (ft.attrib.get("enable") or "").lower() != "no":
                errors.append("SPICE <filetransfer enable='no'/> is missing or enabled")

    # 2. Forbidden guest-agent / spicevmc channels
    for ch in devices.findall("channel"):
        ctype = (ch.attrib.get("type") or "").lower()
        target = ch.find("target")
        tname = (target.attrib.get("name") or "").lower() if target is not None else ""
        if ctype == "spicevmc" or "spice" in tname or "qemu.guest_agent" in tname:
            errors.append(f"Forbidden channel present: type={ctype!r}, target={tname!r}")

    # 3. Shared folders & USB passthrough / redirection
    if devices.findall("filesystem"):
        errors.append("Forbidden <filesystem> shared folder present")
    if devices.findall("redirdev"):
        errors.append("Forbidden <redirdev> USB redirection device present")
    for hd in devices.findall("hostdev"):
        if (hd.attrib.get("type") or "").lower() == "usb":
            errors.append("Forbidden <hostdev type='usb'> USB passthrough device present")

    # 4. Network isolation
    ifaces = devices.findall("interface")
    if not ifaces:
        errors.append("No network <interface> found in domain XML")
    for iface in ifaces:
        itype = (iface.attrib.get("type") or "").lower()
        src = iface.find("source")
        net = src.attrib.get("network") if src is not None else None
        if itype != "network" or net != expected_network:
            errors.append(f"Interface must use network={expected_network!r}, got type={itype!r}, network={net!r}")

    # 5. Primary overlay disk
    disks = [d for d in devices.findall("disk") if (d.attrib.get("device") or "") == "disk"]
    disk_paths = [
        (d.find("source").attrib.get("file") if d.find("source") is not None else None)
        for d in disks
    ]
    if expected_disk not in disk_paths:
        errors.append(f"Expected overlay disk {expected_disk!r} not attached (found {disk_paths!r})")

    return errors


def validate_network_xml(net_xml_text: str, expected_name: str = "win11-isolated") -> list[str]:
    """Verify libvirt network XML has NO <forward> element and matches expected name."""
    errors: list[str] = []
    try:
        root = ET.fromstring(net_xml_text)
    except ET.ParseError as exc:
        return [f"Malformed network XML: {exc}"]
    name_el = root.find("name")
    if name_el is None or (name_el.text or "").strip() != expected_name:
        errors.append(f"Network name mismatch: expected {expected_name!r}")
    if root.find("forward") is not None:
        errors.append("Forbidden <forward> element present in isolated network XML")
    return errors


def main(argv: Iterable[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Validate libvirt domain/network XML hardening for v2.")
    parser.add_argument("domain_xml", type=Path, help="Path to dumped domain XML file (`virsh dumpxml win11`)")
    parser.add_argument("--net-xml", type=Path, default=None, help="Optional dumped network XML (`virsh net-dumpxml win11-isolated`)")
    parser.add_argument("--expected-network", default="win11-isolated")
    parser.add_argument("--expected-disk", default="/var/lib/libvirt/images/win11_overlay.qcow2")
    args = parser.parse_args(list(argv) if argv is not None else None)

    errs = validate_domain_xml(
        args.domain_xml.read_text(encoding="utf-8"),
        expected_network=args.expected_network,
        expected_disk=args.expected_disk,
    )
    if args.net_xml is not None:
        errs.extend(validate_network_xml(args.net_xml.read_text(encoding="utf-8"), expected_name=args.expected_network))

    if errs:
        print("HARDENING_XML_CHECK: FAIL")
        for e in errs:
            print(f" - {e}")
        return 1
    print("HARDENING_XML_CHECK: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
