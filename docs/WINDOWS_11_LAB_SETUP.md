# Windows 11 Automated Forensic Lab & Collection VM Reference

This document provides complete technical documentation for the Windows 11 analysis virtual machine configured on this Arch Linux (Omarchy) host, including hypervisor paths, network topology, guest modifications, and the fast-reset automation script.

---

## 1. Quick Reference & Core Status

| Parameter | Configuration |
| :--- | :--- |
| **Libvirt Domain Name** | `win11` |
| **Connection URI** | `qemu:///system` |
| **Guest OS Version** | Windows 11 Enterprise/Pro x64 (Build 26200 / 25H2) |
| **Guest Admin User** | `mokh` |
| **Guest IP Address** | `192.168.150.50` (Static DHCP Reservation) |
| **Network & Bridge** | `win11-isolated` on `virbr1` (`192.168.150.0/24`, no outbound internet) |
| **Guest MAC Address** | `52:54:00:ba:30:f3` |
| **SSH Authentication** | Passwordless key-based (`ed25519`), Admin privileges, default shell `powershell.exe` |
| **Base Storage Image** | `/var/lib/libvirt/images/win11_base.qcow2` (Mode `0444`, read-only) |
| **Runtime Storage Overlay**| `/var/lib/libvirt/images/win11_overlay.qcow2` (Writable CoW overlay) |
| **UEFI Firmware** | Code: `/usr/share/edk2/x86_64/OVMF_CODE.secboot.fd` (Secure Boot) |
| **UEFI NVRAM Variables** | Live: `/var/lib/libvirt/qemu/nvram/win11_VARS.fd`<br>Base Backup: `/var/lib/libvirt/qemu/nvram/win11_VARS.fd.base` |
| **TPM 2.0 Chip** | Emulated software TPM via `swtpm` (`tpm-crb` / Version 2.0) |

---

## 2. Network Topology: `win11-isolated`

The virtual machine is attached to a dedicated host-only virtual network with **no `<forward>` element**, guaranteeing that guest execution artifacts and malware traffic cannot leak to the LAN or internet.

* **Bridge Name:** `virbr1`
* **Subnet:** `192.168.150.0/24`
* **Host Gateway:** `192.168.150.1`
* **Static Host Reservation:** `192.168.150.50` mapped to `52:54:00:ba:30:f3`

### XML Definition (`/etc/libvirt/qemu/networks/win11-isolated.xml`):
```xml
<network>
  <name>win11-isolated</name>
  <bridge name='virbr1' stp='on' delay='0'/>
  <ip address='192.168.150.1' netmask='255.255.255.0'>
    <dhcp>
      <range start='192.168.150.2' end='192.168.150.254'/>
      <host mac='52:54:00:ba:30:f3' name='win11' ip='192.168.150.50'/>
    </dhcp>
  </ip>
</network>
```

### Host Firewall (`iptables`) Rules for `virbr1`:
Ensure traffic between the host and `virbr1` is accepted across reboots:
```bash
sudo iptables -I INPUT -i virbr1 -j ACCEPT
sudo iptables -I FORWARD -i virbr1 -j ACCEPT
sudo iptables -I FORWARD -o virbr1 -j ACCEPT
```

---

## 3. Windows 11 Guest Hardening & Software Baseline

The base image (`win11_base.qcow2`) has the following configurations permanently baked in:

1. **Microsoft Defender & Tamper Protection:**
   * Tamper Protection toggled **OFF** in Windows Security GUI.
   * `DisableAntiSpyware`, `DisableRealtimeMonitoring`, `DisableBehaviorMonitoring`, `DisableOnAccessProtection`, and `DisableScanOnRealtimeEnable` enabled via Group Policy / Registry (`HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender`).
   * Entire `C:\` drive added to Defender exclusion list.
2. **Windows Update Disabled:**
   * Services `wuauserv` and `UsoSvc` set to `Disabled` and stopped to prevent automatic reboots and background patching.
   * Policy `NoAutoUpdate` set to `1` in `HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU`.
3. **OpenSSH Server:**
   * Feature `OpenSSH.Server~~~~0.0.1.0` installed.
   * Service `sshd` configured with `Automatic` startup.
   * Firewall rule `OpenSSH-Server-In-TCP` (TCP port 22) active on all network profiles (`Any`).
   * Default interactive shell set to `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`.
   * PowerShell `ExecutionPolicy` set to `Bypass` globally.
4. **Key-Based Authentication:**
   * Host public key (`~/.ssh/id_ed25519.pub`) registered in `C:\ProgramData\ssh\administrators_authorized_keys`.
   * Strict ACL applied (`SYSTEM:(F)` and `Administrators:(F)` with inheritance disabled).
5. **Installed Benign / Analysis Tools:**
   * Python 3.12 (`winget install Python.Python.3.12`)
   * Git (`winget install Git.Git`)
   * 7-Zip (`winget install 7zip.7zip`)
   * Notepad++ (`winget install Notepad++.Notepad++`)
   * Microsoft Sysinternals Suite (installed to `C:\Sysinternals` and registered in machine `PATH`).
   * SPICE Guest Tools / VirtIO Drivers (bidirectional clipboard synchronization, dynamic display resizing).

---

## 4. SSH Client Configuration (Host)

Add this stanza to your host's `~/.ssh/config` to connect by simply typing `ssh win11`:

```sshconfig
Host win11
    HostName 192.168.150.50
    User mokh
    IdentityFile ~/.ssh/id_ed25519
    StrictHostKeyChecking accept-new
    BatchMode yes
```

### Verification Command:
```bash
ssh win11 "whoami /priv"
```

---

## 5. Automated Python/Bash Fast-Reset Script

Use this script in your automated pipeline to discard all changes, malware artifacts, or logs, and return the VM to the pristine baseline:

```bash
#!/usr/bin/env bash
set -e

VM_NAME="win11"
BASE_IMG="/var/lib/libvirt/images/win11_base.qcow2"
OVERLAY_IMG="/var/lib/libvirt/images/win11_overlay.qcow2"
NVRAM_LIVE="/var/lib/libvirt/qemu/nvram/win11_VARS.fd"
NVRAM_BASE="/var/lib/libvirt/qemu/nvram/win11_VARS.fd.base"

echo "[+] Shutting down $VM_NAME..."
sudo virsh shutdown "$VM_NAME" 2>/dev/null || true
while [ "$(sudo virsh domstate "$VM_NAME" 2>/dev/null)" != "shut off" ]; do
    sleep 1
done

echo "[+] Resetting writable overlay..."
sudo qemu-img create -f qcow2 -F qcow2 -b "$BASE_IMG" "$OVERLAY_IMG"
sudo chown nobody:nobody "$OVERLAY_IMG"

echo "[+] Restoring pristine UEFI NVRAM..."
sudo cp "$NVRAM_BASE" "$NVRAM_LIVE"

echo "[+] Booting fresh $VM_NAME instance..."
sudo virsh start "$VM_NAME"

echo "[+] Waiting for SSH collector readiness..."
until ssh -o BatchMode=yes -o ConnectTimeout=2 mokh@192.168.150.50 "whoami" >/dev/null 2>&1; do
    sleep 2
done

echo "[+] VM is ready for automated collection at 192.168.150.50!"
```

---

## 6. Python libvirt Integration Example

```python
import libvirt
import subprocess
import time

conn = libvirt.open("qemu:///system")
dom = conn.lookupByName("win11")

def reset_vm():
    if dom.isActive():
        dom.destroy()
    
    # Recreate overlay via qemu-img
    subprocess.run([
        "sudo", "qemu-img", "create", "-f", "qcow2", "-F", "qcow2",
        "-b", "/var/lib/libvirt/images/win11_base.qcow2",
        "/var/lib/libvirt/images/win11_overlay.qcow2"
    ], check=True)
    subprocess.run(["sudo", "chown", "nobody:nobody", "/var/lib/libvirt/images/win11_overlay.qcow2"], check=True)
    
    # Restore NVRAM
    subprocess.run([
        "sudo", "cp",
        "/var/lib/libvirt/qemu/nvram/win11_VARS.fd.base",
        "/var/lib/libvirt/qemu/nvram/win11_VARS.fd"
    ], check=True)
    
    dom.create()
    print("Clean VM booted successfully.")

if __name__ == "__main__":
    reset_vm()
```
