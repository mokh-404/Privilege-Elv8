# Step D — Negative-Egress Verification Checklist & Exact Ordered Mokh Run/Sign List

**Status:** `Phase 1 Hardening Runbook — NO Changes Have Been Applied to Host Firewall, Libvirt XML, or VMs`  
**Hard Rule:** Gate 0 (`OD-V2-07`) and written professor/university approval remain **PENDING**. Complete **every** check below (using clean control images only) before acquiring or running any malware.

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

Execute strictly **in this numbered order** (all host `sudo` operations executed manually by Mokh):

1. **Record Base Hashes (`chmod 0444` Verified):**
   `./docs/v2/hardening/04_watchdog_and_base_hash.sh record-base`
2. **Harden Host Firewall (`virbr1` Default-DROP):**
   `sudo ./docs/v2/hardening/01_firewall_win11_isolated.sh --apply`
3. **Provision & Verify Isolated `inetsim-vm` (`OD-V2-03`):**
   Follow [`03_inetsim_vm_setup.md`](03_inetsim_vm_setup.md) (`192.168.150.10`, single NIC on `win11-isolated`, no WAN NIC) and verify `check_domain_xml.py` on `inetsim-vm` too.
4. **Harden `win11` Domain XML & Re-Check Network XML:**
   Edit via `sudo virsh -c qemu:///system edit win11` per [`02_domain_xml_hardening.md`](02_domain_xml_hardening.md), then pass:
   `.venv/bin/python docs/v2/hardening/check_domain_xml.py /tmp/win11_after.xml --net-xml /tmp/win11_net.xml`
5. **Install Sysmon + ETW Profile Inside `win11` Base Image (Clean Prep Boot, BEFORE Sealing Base):**
   Configure Sysmon logging (`EventID 1, 8, 11, 12, 13, 14, 19, 20, 21, 25`), re-seal `win11_base.qcow2` as `chmod 0444`, and re-run `04_watchdog_and_base_hash.sh record-base`.
6. **Build & Verify Offline Extractor Container Image (`Step F`):**
   Build `docs/v2/hardening/offline_extractor.Dockerfile` (`docker build`) and validate `06_unprivileged_container_runner.sh`.
7. **Run Negative-Egress Verification (`NEG-01`..`NEG-10`) on Clean Boot:**
   Complete the entire table above using a clean control overlay only (zero malware).
8. **Run Clean-Image Feature Parity Test (`docs/v2/FEATURE_PARITY_AUDIT.md` §4):**
   Compare live `Collect-Artifacts.ps1` vs offline extractor on the same clean overlay (`signature_state >= 98%`, exact features `100%`).
9. **Initialize Quarantine Vault & Obtain Institutional Approvals (`OD-V2-07`):**
   Run `./docs/v2/hardening/05_quarantine_vault_setup.sh init`, file written professor/university approval, sign Gate 0 (`GATE0_SIGNED_OFF`), and verify `./docs/v2/hardening/05_quarantine_vault_setup.sh preflight` passes.
10. **Formal Operator Sign-Off (Complete Before Downloading/Executing Pilot Samples):**
    - `[ ]` **Institutional / Professor Written Approval Obtained** *(Date / Reference: `____________`)*
    - `[ ]` **Containment (`NEG-01`..`NEG-10`) All Passed** *(Operator Initials: `______`)*
    - `[ ]` **Clean-Image Feature Parity Passed** *(Operator Initials: `______`)*
    - `[ ]` **Gate 0 Signed Off (`OD-V2-07` Active)** *(Signed: Mokh / Date: `____________`)*
