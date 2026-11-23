# Step D — Negative-Egress Verification Checklist & Exact Ordered Mokh Run/Sign List

**Status:** `Phase 1 Hardening Runbook — Written Supervisor Approval GRANTED (Supervisor Marawan, AASTMT, 2026-11-23); Gate 0 Execution & Sign-Off Remain PENDING`  
**Hard Rule:** Written supervisor approval was granted on **`2026-11-23`** by **Supervisor Marawan (AASTMT)** for *"Research Approval Request: Controlled Malware Analysis for DFIR Triage"* (confirming separate institutional/legal ethics review is *"Not Required — Waived by Supervisor"*), subject to three mandatory conditions:
1. **(a) Sole Governing Authorization:** Governed by Supervisor Marawan's (AASTMT) written approval dated `2026-11-23` (*"Not Required — Waived by Supervisor"*).
2. **(b) ASUS Host Machine Condition:** Zero personal credentials, zero sensitive data, and zero production workloads on the ASUS host, operated strictly under a **dedicated isolated user account**.
3. **(c) Hard Gate 0 Enforcement:** Zero malware sample acquisition, extraction, or execution until the Gate 0 checklist below (`NEG-01`..`NEG-10` + base hash + vault verify + dedicated isolated user check) is fully executed and signed by Mokh.

---

## Part 1: Negative-Egress & Containment Verification Checklist (Execute on Clean Test Boot Only)

Verify each condition empirically and record PASS/FAIL + packet-capture evidence:

| Check ID | Negative Test Target | Command / Action to Run | Expected Observation (PASS Criterion) | Status |
| :---: | :--- | :--- | :--- | :---: |
| **NEG-01** | Libvirt network `<forward>` absent | `sudo virsh -c qemu:///system net-dumpxml win11-isolated` | Zero `<forward>` element anywhere in network XML | `[ ]` |
| **NEG-02** | Host `iptables` `virbr1` default-DROP | `sudo docs/v2/hardening/01_firewall_win11_isolated.sh --status` | `V2_VIRBR1_IN` & `V2_VIRBR1_FWD` active; zero `virbr1 ... -j ACCEPT` legacy rules | `[ ]` |
| **NEG-03** | Domain XML hardening validator | `sudo virsh -c qemu:///system dumpxml win11 > /tmp/w11.xml && .venv/bin/python docs/v2/hardening/check_domain_xml.py /tmp/w11.xml` | Exit code `0` (`HARDENING_XML_CHECK: PASS`) | `[ ]` |
| **NEG-04** | Guest -> Internet DNS/ICMP/HTTPS blocked | Inside clean `win11`: `Test-NetConnection 1.1.1.1 -Port 443`, `ping -n 2 8.8.8.8` *(when `inetsim-vm` stopped first)* + `tcpdump -ni any host 1.1.1.1` on host | Guest fails to reach WAN; `0` packets forwarded out host WAN NIC | `[ ]` |
| **NEG-05** | Guest -> Linux Host services blocked | Inside clean `win11`: probe host bridge IP `Test-NetConnection 192.168.150.1 -Port 22` / `53` / `8080` while tailing host `dmesg` | Connections time out / drop; kernel logs `[V2-VIRBR1-DROP]` | `[ ]` |
| **NEG-06** | Guest -> `inetsim-vm` OK | Boot `inetsim-vm` (`192.168.150.10`) on `win11-isolated`; inside clean `win11`: `Resolve-DnsName example.test -Server 192.168.150.10` & `curl.exe http://192.168.150.10/` | Resolves locally to `192.168.150.10` and returns fake INetSim page with `0` WAN packets on host NIC | `[ ]` |
| **NEG-07** | Clipboard / drag-drop / USB negative test | Copy text on host clipboard -> paste inside `win11` SPICE viewer (and vice-versa); check Device Manager for shared folders/USB redirection | Clipboard does NOT cross host<->guest boundary; `0` shared folders / USB passthrough devices | `[ ]` |
| **NEG-08** | Base image read-only & SHA-256 unchanged | `./docs/v2/hardening/04_watchdog_and_base_hash.sh verify-base` after a clean boot + shutdown | Permission == `444` and `sha256sum -c` returns `OK` for `win11_base.qcow2` & `win11_VARS.fd.base` | `[ ]` |
| **NEG-09** | Unprivileged container extractor test | Close overlay (`virsh destroy win11`), run `./docs/v2/hardening/06_unprivileged_container_runner.sh /var/lib/libvirt/images/win11_overlay.qcow2 /tmp/test_ext clean_test` | Succeeds with `--network=none --read-only --cap-drop=ALL --security-opt=no-new-privileges`; zero executables written | `[ ]` |
| **NEG-10** | Emergency abort drill | Boot clean `win11`, trigger `./docs/v2/hardening/07_incident_abort.sh` | Both `win11` & `inetsim-vm` immediately destroyed, overlay deleted, base SHA-256 verified OK | `[ ]` |

---

## Part 2: Exact Ordered **"What Mokh Runs and Signs"** List (Critical Path Before Pilot)

> [!IMPORTANT]
> **Blocker Verified on Current `win11_base.qcow2` (`4,364` records):** Read-only inspection confirmed that **`Sysmon` / `Sysmon64` and `Microsoft-Windows-Sysmon%4Operational.evtx` are ABSENT**, **`C:\DFIR-Bootstrap\Invoke-StagePayload.ps1` and `\DFIR-StageRunner` are ABSENT**, and **`sshd` is still Auto-start (`Start = 2`)**. You **MUST** run **Step 0 (`00_bake_v2_base_image.sh` + `Install-V2BaseBootstrap.ps1`)** on a clean maintenance boot **BEFORE** running `chattr +i /var/lib/libvirt/images/win11_base.qcow2` or applying `01_firewall_win11_isolated.sh`.

Execute strictly **in this numbered order** (all host `sudo` operations executed manually by Mokh):

0. **One-Time Clean Base Image Bake (`Sysmon` + `\DFIR-StageRunner` + Disable `sshd`, BEFORE `chattr +i`):**
   - Create a fresh disposable overlay `/var/lib/libvirt/images/win11_overlay.qcow2` (`uid 956:956`, `0660`) + NVRAM so `win11` boots cleanly (`win11_base.qcow2` stays `0444` and `win11` domain XML points to `win11_overlay.qcow2`):
     `./docs/v2/hardening/00_bake_v2_base_image.sh prepare-overlay`
   - Build the read-only `DFIR_BAKE` maintenance ISO containing [`Install-V2BaseBootstrap.ps1`](Install-V2BaseBootstrap.ps1) and `Sysmon64.exe`:
     `./docs/v2/hardening/00_bake_v2_base_image.sh build-bake-iso /path/to/Sysmon64.exe /tmp/v2_base_bake.iso`
   - Boot the clean maintenance session of `win11` with `/tmp/v2_base_bake.iso` attached (or copy `Install-V2BaseBootstrap.ps1` + `Sysmon64.exe` over the existing v1 SSH channel before `sshd` is disabled) and run as Administrator inside the guest:
     `powershell.exe -NoProfile -ExecutionPolicy Bypass -File D:\INSTALL.PS1`
     *(Installs `Sysmon64` with the v2 config & 64 MB EVTX buffer, installs `C:\DFIR-Bootstrap\Invoke-StagePayload.ps1`, registers `\DFIR-StageRunner` as `SYSTEM` `ONSTART`, disables `sshd`, clears transient setup logs, flushes `C:`, and powers off cleanly).*
   - Once the guest powers off, run `seal-and-cache` to verify the baked overlay, commit it back into `win11_base.qcow2` (`qemu-img commit`), lock `chmod 0444` + `chattr +i`, record the new golden `win11_base.sha256`, rebuild `--build-base-cache`, and recreate a fresh clean `win11_overlay.qcow2`:
     `./docs/v2/hardening/00_bake_v2_base_image.sh seal-and-cache`
1. **Verify Sealed Base Hashes (`chmod 0444` & `chattr +i` Verified):**
   `./docs/v2/hardening/04_watchdog_and_base_hash.sh verify-base`
2. **Harden Host Firewall (`virbr1` Default-DROP):**
   `sudo ./docs/v2/hardening/01_firewall_win11_isolated.sh --apply`
3. **Provision & Verify Isolated `inetsim-vm` (`OD-V2-03`):**
   Follow [`03_inetsim_vm_setup.md`](03_inetsim_vm_setup.md) (`192.168.150.10`, single NIC on `win11-isolated`, no WAN NIC) and verify `check_domain_xml.py` on `inetsim-vm` too.
4. **Harden `win11` Domain XML & Re-Check Network XML:**
   Edit via `sudo virsh -c qemu:///system edit win11` per [`02_domain_xml_hardening.md`](02_domain_xml_hardening.md), then pass:
   `.venv/bin/python docs/v2/hardening/check_domain_xml.py /tmp/win11_after.xml --net-xml /tmp/win11_net.xml`
5. **Re-Verify Baked `win11_base.qcow2` Offline (`Sysmon` + `\DFIR-StageRunner` + `sshd=Disabled`):**
   `./docs/v2/hardening/00_bake_v2_base_image.sh verify-image`
6. **Build & Verify Offline Extractor Container Image (`Step F`):**
   Build `docs/v2/hardening/offline_extractor.Dockerfile` (`docker build`) and validate `06_unprivileged_container_runner.sh`.
7. **Run Negative-Egress Verification (`NEG-01`..`NEG-10`) on Clean Boot:**
   Complete the entire table above using a clean control overlay only (zero malware).
8. **Run Zero-SSH Clean-Image Feature Parity Comparator (`docs/v2/FEATURE_PARITY_AUDIT.md` §4 & `scripts/compare_v1_v2_parity.py`):**
   - Build the read-only `DFIR_STAGE` parity ISO (packages `collector/Collect-Artifacts.ps1` for `\DFIR-StageRunner`, zero SSH/scp):
     `.venv/bin/python scripts/compare_v1_v2_parity.py --build-parity-iso /tmp/v2_parity_stage`
   - Boot a clean disposable overlay `win11_overlay.qcow2` with `/tmp/v2_parity_stage/run_stage_clean_parity_test.iso` attached; once the guest writes `C:\collector_out_parity\artifacts.json` and powers off cleanly, run one command to extract `C:\collector_out_parity\artifacts.json` in user space, run the offline v2 extractor on the exact same closed overlay, and verify all 19 cold-disk features:
     `.venv/bin/python scripts/compare_v1_v2_parity.py --extract-v1-json-from-qcow2 /var/lib/libvirt/images/win11_overlay.qcow2 --base-cache-path /var/lib/dfir-quarantine-vault/win11_base_cache.json.gz --out-md docs/v2/CLEAN_IMAGE_PARITY_REPORT.md`
9. **Initialize Quarantine Vault & Verify Supervisor Approval Conditions (`OD-V2-07`):**
   Verify dedicated isolated host user account on the ASUS host (zero personal credentials/sensitive data/production workloads), run `./docs/v2/hardening/05_quarantine_vault_setup.sh init`, sign Gate 0 (`GATE0_SIGNED_OFF`), and verify `./docs/v2/hardening/05_quarantine_vault_setup.sh preflight` passes.
10. **Formal Operator Sign-Off (Complete Before Downloading/Executing Pilot Samples):**
    - `[x]` **Written Supervisor Approval Obtained (`OD-V2-07a`)** *(Date / Reference: `2026-11-23 — Supervisor Marawan (AASTMT), "Research Approval Request: Controlled Malware Analysis for DFIR Triage" (Institutional Ethics Review: Not Required — Waived by Supervisor)`)*
    - `[ ]` **ASUS Host Dedicated Isolated User & Zero Personal Credentials/Sensitive Data Verified (`OD-V2-07b`)** *(Operator Initials: `______`)*
    - `[ ]` **Containment (`NEG-01`..`NEG-10`), Base Hash & Vault Preflight All Passed (`OD-V2-07c`)** *(Operator Initials: `______`)*
    - `[ ]` **Clean-Image Feature Parity Passed** *(Operator Initials: `______`)*
    - `[ ]` **Gate 0 Signed Off (`OD-V2-07` Active)** *(Signed: Mokh / Date: `____________`)*
