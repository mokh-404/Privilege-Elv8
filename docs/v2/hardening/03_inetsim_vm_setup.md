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
2. **Disable External Interfaces, Mask `systemd-networkd-wait-online`, & Lock Static IP (`192.168.150.10/24`):**
   - Remove any temporary NAT NIC used during initial apt/package installation **before** joining `win11-isolated`.
   - Configure static IP `192.168.150.10/24` on the sole NIC attached to `win11-isolated`, and mask `systemd-networkd-wait-online.service` (`sudo systemctl mask systemd-networkd-wait-online.service`) so headless boots with no upstream WAN DHCP never stall for 2 minutes.
   - Disable `sshd` / extraneous daemons before starting live malware batches (or bind management access strictly before snapshot freeze).
3. **Configure `/etc/inetsim/inetsim.conf` (Valid `inetsim.conf(5)` Directives):**
   ```ini
   service_bind_address    192.168.150.10
   dns_default_ip          192.168.150.10
   start_service           dns
   start_service           http
   start_service           https
   start_service           smtp
   start_service           pop3
   start_service           ftp
   start_service           tftp
   start_service           ntp
   http_bind_port          80
   https_bind_port         443
   ```
   *(Note: directory paths `--report-dir`, `--log-dir`, and `--data-dir` are CLI / init flags in INetSim rather than `inetsim.conf(5)` keys — use standard `/var/log/inetsim/` and `/var/lib/inetsim/data/` defaults.)*
   - On the Windows guest side, because `V2_VIRBR1_IN` drops DHCP (`UDP/67`) to the Linux host, every `DFIR_STAGE` ISO built by [`src/v2/pilot_staging.py`](../../../src/v2/pilot_staging.py) automatically prepends the `netsh` static IP configuration (`192.168.150.50/24`, gateway `192.168.150.10`, DNS `192.168.150.10`) without re-baking `win11_base.qcow2`.
4. **Reset Between Batches:**
   - Restore `inetsim-vm` from its clean QCOW2 snapshot (`inetsim_base.qcow2`) or flush `/var/log/inetsim/` cleanly between malware runs so INetSim logs can correlate guest C2 beacons (`inetsim_report_<run_id>.json`) without carrying state across runs.
