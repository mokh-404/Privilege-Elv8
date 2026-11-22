# Libvirt Domain & Network XML Hardening Guide (`win11` & `win11-isolated`)

**Status:** `Runbook Only — Do NOT Apply Host XML Changes Until Ready for Pre-Pilot Verification`  
**Validator Script:** [`check_domain_xml.py`](check_domain_xml.py)  
**Target Domain:** `win11` on `qemu:///system` (backing `/var/lib/libvirt/images/win11_base.qcow2`, mode `0444`)

---

## 1. Verify Network XML (`win11-isolated`)

Confirm `/etc/libvirt/qemu/networks/win11-isolated.xml` contains **NO `<forward>` element**:

```bash
sudo virsh -c qemu:///system net-dumpxml win11-isolated > /tmp/win11_net.xml
grep -n "<forward" /tmp/win11_net.xml && echo "FAIL: <forward> found!" || echo "PASS: isolated network has no <forward>"
```

Ensure `host` DNS leakage via host `dnsmasq` is disabled during malware runs (see [`03_inetsim_vm_setup.md`](03_inetsim_vm_setup.md) so `win11` resolves DNS solely to `inetsim-vm` at `192.168.150.10`, and optionally set `<dns enable='no'/>` inside `<network>` if not relying on host dnsmasq).

---

## 2. Export & Inspect Current `win11` Domain XML

```bash
sudo virsh -c qemu:///system dumpxml win11 > /tmp/win11_before.xml
.venv/bin/python docs/v2/hardening/check_domain_xml.py /tmp/win11_before.xml
```

---

## 3. Exact `virsh edit win11` Modifications

Run `sudo virsh -c qemu:///system edit win11` and verify/apply ALL of the following:

1. **Disable SPICE Clipboard & Drag-and-Drop File Transfer (`IMP-01`):**
   Inside `<graphics type='spice' ...>` add:
   ```xml
   <clipboard copypaste='no'/>
   <filetransfer enable='no'/>
   ```
   Also **remove** any SPICE guest-agent channel that enables host-guest copy/paste or agent transport:
   ```xml
   <!-- REMOVE this block completely if present: -->
   <channel type='spicevmc'>
     <target type='virtio' name='com.redhat.spice.0'/>
   </channel>
   ```
   *(If you do not need graphical console interaction during automated offline extraction, switch `<graphics type='vnc' listen='127.0.0.1'>` or keep `spice` with `listen='127.0.0.1'`, `<clipboard copypaste='no'/>`, `<filetransfer enable='no'/>`, and NO `spicevmc`/`qemu-ga` channels.)*

2. **Remove ALL Shared Folders (`<filesystem>`):**
   Delete any `<filesystem ...>` (`virtiofs`, `9p`) stanzas under `<devices>`.

3. **Remove ALL USB Controllers / Host USB Passthrough / Redirection (`<hostdev>`, `<redirdev>`):**
   Delete any `<redirdev ... type='spicevmc'/>` (USB redirection) and `<hostdev ... type='usb'>` stanzas under `<devices>`.

4. **Disable QEMU Guest Agent Channel During Detonation:**
   If `<channel type='unix'><target type='virtio' name='org.qemu.guest_agent.0'/></channel>` exists, remove it before detonation runs so malware cannot abuse agent sockets.

5. **Enforce Isolated Network Interface & Backing Storage:**
   Confirm `<interface type='network'><source network='win11-isolated'/>...` is the **only** `<interface>` (zero `default`, `bridge`, `direct`, or `user` NICs), and `<disk type='file' device='disk'>` points to `/var/lib/libvirt/images/win11_overlay.qcow2`.

---

## 4. Validate Hardened XML (Mandatory Pass Before Pilot)

```bash
sudo virsh -c qemu:///system dumpxml win11 > /tmp/win11_after.xml
.venv/bin/python docs/v2/hardening/check_domain_xml.py /tmp/win11_after.xml --net-xml /tmp/win11_net.xml
```

Never boot a transient modified domain via `virsh create`; always use persistent `virsh define` / `virsh edit` + `virsh start`.
