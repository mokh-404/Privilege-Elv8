# Stage A Pilot — Zero-SSH / Zero-Guest-Agent Offline Run Staging Specification

**Status:** `Implemented in src/v2/pilot_staging.py & Verified by Unit Tests`  
**Related Decisions:** [`OD-V2-03`](../OPERATOR_DECISIONS.md), [`OD-V2-04`](../OPERATOR_DECISIONS.md), [`OD-V2-05`](../OPERATOR_DECISIONS.md), [`OD-V2-07`](../OPERATOR_DECISIONS.md), [`OD-V2-09`](../OPERATOR_DECISIONS.md)  
**Implementation Modules:** [`src/v2/pilot_staging.py`](../../../src/v2/pilot_staging.py) | [`src/v2/run_stage_a_pilot.py`](../../../src/v2/run_stage_a_pilot.py) | [`00_bake_v2_base_image.sh`](00_bake_v2_base_image.sh) | [`Install-V2BaseBootstrap.ps1`](Install-V2BaseBootstrap.ps1)

---

## 1. Motivation & Containment Constraint

Under Phase v2 hardening:
1. [`01_firewall_win11_isolated.sh`](01_firewall_win11_isolated.sh) enforces a **default-DROP** policy on `virbr1` (`V2_VIRBR1_IN` and `V2_VIRBR1_FWD`), blocking all host-to-guest and guest-to-host TCP/UDP traffic (no SSH port `22`, no SMB, no HTTP).
2. [`02_domain_xml_hardening.md`](02_domain_xml_hardening.md) and [`check_domain_xml.py`](check_domain_xml.py) strip `qemu-guest-agent` (`org.qemu.guest_agent.0`), SPICE clipboard/file transfer (`com.redhat.spice.0`), shared folders (`<filesystem>`), and USB passthrough.

Consequently, **zero live SSH (`guest_runner.py`), zero `scp -r`, and zero `qemu-ga` channels** are available or permitted during Stage A pilot and Stage B collection runs.

---

## 2. Read-Only ISO-9660 Virtual CD-ROM (`DFIR_STAGE`) Architecture

Every VM run (`control`, `dormant`, or `executed`) receives its per-run configuration and staged inputs exclusively through a host-generated **read-only ISO-9660 virtual CD-ROM** (`run_stage_<run_id>.iso`, volume label **`DFIR_STAGE`**) built deterministically in user space by [`src/v2/pilot_staging.py`](../../../src/v2/pilot_staging.py):

### A. Pre-Baked Clean Base Image Bootstrapper (Prepared Once via `00_bake_v2_base_image.sh` Before Sealing `win11_base.qcow2` `0444`)
Read-only inspection of the unbaked v1 `win11_base.qcow2` (`4,364` records) confirmed that `Sysmon`, `C:\DFIR-Bootstrap\Invoke-StagePayload.ps1`, and `\DFIR-StageRunner` are **absent** while `sshd` is `Start=2`. Therefore, during Step 0 of [`08_NEGATIVE_EGRESS_AND_SIGN_OFF.md`](08_NEGATIVE_EGRESS_AND_SIGN_OFF.md) — **before** `chmod 0444`, `chattr +i`, and `01_firewall_win11_isolated.sh`:
1. Run [`00_bake_v2_base_image.sh`](00_bake_v2_base_image.sh) + [`Install-V2BaseBootstrap.ps1`](Install-V2BaseBootstrap.ps1) inside one clean maintenance boot to:
   - Install `Sysmon64` with the v2 process/file/registry/task/WMI config (`64 MB` EVTX buffer);
   - Install `C:\DFIR-Bootstrap\Invoke-StagePayload.ps1` and register `\DFIR-StageRunner` (`SYSTEM`, `ONSTART`);
   - Disable `sshd` (`Start=4`), clear setup logs, flush `C:`, and power off cleanly.
2. Run `./docs/v2/hardening/00_bake_v2_base_image.sh seal-and-cache` on the host to verify all three conditions via `dissect.target`, set `chmod 0444` + `chattr +i`, record the new golden `win11_base.sha256`, and rebuild `--build-base-cache`.

### B. Per-Run Host Staging Workflow (`build_stage_bundle`)
Before each run `run_id`:
1. **Gate 0 & Paired-Stratum Validation (`validate_stage_run_spec`):**
   - For `dormant` and `executed` runs, [`validate_stage_run_spec`](../../../src/v2/pilot_staging.py) enforces:
     - `gate0_signed_off == True` and `dedicated_host_user_verified == True` (verifying all three `OD-V2-07` conditions under Supervisor Marawan's `2026-11-23` AASTMT written approval);
     - Valid 64-hex `sample_sha256` matching the encrypted quarantine vault file on disk;
     - Non-empty `pair_group_id` and identical `staging_target_path` (`C:\...`) shared between the paired `dormant` and `executed` runs of the same binary (`OD-V2-05`, `OD-V2-09`);
     - `execute_payload == False` for `dormant` vs. `execute_payload == True` for `executed`.
2. **Read-Only ISO Bundle Generation (`run_stage_<run_id>.iso`):**
   - Generates `run_manifest.json`, `benign_workload.ps1`, `Invoke-StagePayload.ps1`, and (for `dormant`/`executed`) `payload.bin` inside `run_stage_<run_id>.iso` (`volume_label = "DFIR_STAGE"`), plus a read-only SATA CD-ROM device snippet (`cdrom_device.xml` with `<readonly/>`).
3. **Disposable Overlay Boot & Hard Watchdog Termination:**
   - Create fresh CoW overlay `win11_overlay.qcow2` backed by read-only `win11_base.qcow2`.
   - Attach `run_stage_<run_id>.iso` read-only (`virsh attach-disk win11 .../run_stage_<run_id>.iso sdc --type cdrom --mode readonly --config`).
   - Launch guest under the host-side wall-clock watchdog ([`04_watchdog_and_base_hash.sh`](04_watchdog_and_base_hash.sh)).
   - Inside the guest, `\DFIR-StageRunner` finds the `DFIR_STAGE` CD-ROM drive:
     - Runs `benign_workload.ps1` (`benign_profile_id`);
     - If `stratum in {"dormant", "executed"}`, copies `payload.bin` to `staging_target_path` (e.g., `C:\Users\Public\Downloads\...`), verifies `Get-FileHash -Algorithm SHA256 == sample_sha256`, and:
       - **`dormant`:** exits immediately **without** executing the binary;
       - **`executed`:** launches the binary from `staging_target_path` under Sysmon/ETW recording.
   - When the wall-clock timer expires, the host watchdog executes `virsh destroy win11` and detaches/deletes `run_stage_<run_id>.iso`.
4. **Cached User-Space Offline Extraction (`< 1 min` per run):**
   - Run [`src/v2/offline_extractor.py`](../../../src/v2/offline_extractor.py) with `--base-cache-path` ( inside [`06_unprivileged_container_runner.sh`](06_unprivileged_container_runner.sh)) on the closed `win11_overlay.qcow2`, then delete `win11_overlay.qcow2` and verify `win11_base.qcow2` SHA-256 is unchanged.
