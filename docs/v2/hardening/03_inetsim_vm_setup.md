# Separate Isolated Linux INetSim VM Setup (`inetsim-vm` — `OD-V2-03`)

**Decision Reference:** `OD-V2-03` *(confirmed by Mokh 2026-11-23)*  
**Core Invariant:** `INetSim` runs **inside a dedicated isolated Linux VM (`inetsim-vm`)** attached strictly to `win11-isolated` (`virbr1`, `192.168.150.0/24`). Never install `inetsim` directly on the Linux host OS (`192.168.150.1`), and never run in-guest `FakeNet-NG` inside the Windows 11 target VM.

---

## 1. Network Addressing on `win11-isolated`

| Node | Role | Interface | Static IP / MAC | Outbound / Host Services |
| :--- | :--- | :--- | :--- | :--- |
| Host bridge `virbr1` | Hypervisor isolated switch | No `<forward>` | `192.168.150.1/24` | All guest-originating ports **`DROP`ped** by `01_firewall_win11_isolated.sh` |
| **`inetsim-vm`** | Dedicated Debian/Alpine Linux VM | **Single NIC on `win11-isolated` only** | **`192.168.150.10/24`** | DNS (`53`), HTTP (`80`), HTTPS (`443`), SMTP (`25`), FTP (`21`), NTP (`123`) handled solely by INetSim; SSH/other admin ports stopped during malware runs |
| **`win11`** | Windows 11 target VM | **Single NIC on `win11-isolated` only** | `192.168.150.50/24` (`52:54:00:ba:30:f3`) | Default gateway = `192.168.150.10`, Preferred DNS = `192.168.150.10` |

---

## 2. `inetsim-vm` Provisioning Steps (Operator Runbook)

1. **Create Lightweight Linux VM (`inetsim-vm`):**
   - Attach **only ONE network interface** (`<source network='win11-isolated'/>`), allocate ~`1–2 GiB` RAM, ~`8 GiB` disk (`inetsim_base.qcow2` snapshot/immutable mode during detonation so every malware batch uses a clean INetSim snapshot).
   - Remove SPICE clipboard (`copypaste='no'`), filetransfer (`enable='no'`), shared folders, and USB passthrough using [`check_domain_xml.py`](check_domain_xml.py).
2. **Disable External Interfaces & Host-Facing Listeners inside `inetsim-vm`:**
   - Remove any temporary NAT NIC used during initial apt/package installation **before** joining `win11-isolated`.
   - Disable `sshd` / extraneous daemons before starting live malware batches (or bind management access strictly before snapshot freeze).
3. **Configure `/etc/inetsim/inetsim.conf`:**
   ```ini
   service_bind_address    192.168.150.10
   service_run_services    dns http https smtp pop3 ftp tftp ntp
   dns_default_ip          192.168.150.10
   http_bind_port          80
   https_bind_port         443
   report_dir              /var/log/inetsim/report
   log_dir                 /var/log/inetsim/log
   data_dir                /var/lib/inetsim/data
   ```
   - Point Win11 guest DNS & default gateway to `192.168.150.10` (static TCP/IP config inside Win11 base image, OR disable libvirt host dnsmasq external forward and hand out `option:dns-server,192.168.150.10` + `option:router,192.168.150.10`).
4. **Reset Between Batches:**
   - Restore `inetsim-vm` from its clean QCOW2 snapshot (`inetsim_base.qcow2`) or flush `/var/log/inetsim/` cleanly between malware runs so INetSim logs can correlate guest C2 beacons (`inetsim_report_<run_id>.json`) without carrying state across runs.
