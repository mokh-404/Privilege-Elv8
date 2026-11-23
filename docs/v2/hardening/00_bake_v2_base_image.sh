#!/usr/bin/env bash
# 00_bake_v2_base_image.sh — Deterministic One-Time Clean Base Image Bake & Verification Helper
#
# Why this script exists:
#   Read-only inspection of /var/lib/libvirt/images/win11_base.qcow2 (4,364 extracted records) confirmed:
#     - Sysmon / Sysmon64 / SysmonDrv and Microsoft-Windows-Sysmon%4Operational.evtx are ABSENT;
#     - C:\DFIR-Bootstrap\Invoke-StagePayload.ps1 and scheduled task \DFIR-StageRunner are ABSENT;
#     - OpenSSH Server (sshd) is PRESENT and set to Auto-start (Start=2).
#
#   Run this script BEFORE locking chattr +i on win11_base.qcow2 and BEFORE applying 01_firewall_win11_isolated.sh:
#     1. `verify-image` — Read-only user-space check of win11_base.qcow2 for Sysmon, \DFIR-StageRunner, and sshd Disabled.
#     2. `build-bake-iso <sysmon64_exe_path> [out_iso]` — Package Install-V2BaseBootstrap.ps1 + Sysmon64.exe into a read-only ISO (DFIR_BAKE).
#     3. `seal-and-cache` — After the clean maintenance boot shuts down: verify bake via dissect.target, set chmod 0444 + chattr +i,
#        record the new golden win11_base.sha256, and rebuild the immutable base-image cache (--build-base-cache).

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
BASE_IMG="${BASE_IMG:-/var/lib/libvirt/images/win11_base.qcow2}"
BASE_CACHE="${BASE_CACHE:-/var/lib/dfir-quarantine-vault/win11_base_cache.json.gz}"
PYTHON_BIN="${REPO_ROOT}/.venv/bin/python"

usage() {
    cat <<EOF
Usage:
  $0 verify-image [qcow2_path]
  $0 build-bake-iso <path_to_Sysmon64.exe> [out_iso_path]
  $0 seal-and-cache [qcow2_path] [base_cache_path]
EOF
}

verify_image_readonly() {
    local img="${1:-$BASE_IMG}"
    "${PYTHON_BIN}" - "$img" <<'PY'
import sys
from dissect.target import Target

img_path = sys.argv[1]
t = Target.open(img_path)
svc_root = t.registry.key(r"HKLM\SYSTEM\ControlSet001\Services")
svcs = {sk.name.lower(): {v.name: v.value for v in sk.values()} for sk in svc_root.subkeys()}

has_sysmon_svc = ("sysmon64" in svcs) or ("sysmon" in svcs)
has_sysmon_drv = "sysmondrv" in svcs
sshd_start = svcs.get("sshd", {}).get("Start")

has_evtx = t.fs.path(r"c:\Windows\System32\winevt\Logs\Microsoft-Windows-Sysmon%4Operational.evtx").exists()
has_bootstrap_ps1 = t.fs.path(r"c:\DFIR-Bootstrap\Invoke-StagePayload.ps1").exists()
has_task_xml = t.fs.path(r"c:\Windows\System32\Tasks\DFIR-StageRunner").exists()

tc_tree = t.registry.key(r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree")
has_task_tree = "dfir-stagerunner" in [sk.name.lower() for sk in tc_tree.subkeys()]

print(f"IMAGE: {img_path}")
print(f"  Sysmon service present     : {has_sysmon_svc}")
print(f"  SysmonDrv driver present   : {has_sysmon_drv}")
print(f"  Sysmon EVTX log present    : {has_evtx}")
print(f"  Invoke-StagePayload.ps1    : {has_bootstrap_ps1}")
print(f"  \\DFIR-StageRunner task     : {has_task_xml and has_task_tree} (xml={has_task_xml}, tree={has_task_tree})")
print(f"  sshd Start mode (4=Disabled): {sshd_start}")

ok = has_sysmon_svc and has_sysmon_drv and has_evtx and has_bootstrap_ps1 and has_task_xml and has_task_tree and (sshd_start in (4, None))
if not ok:
    print("V2_BASE_BAKE_VERIFY: FAIL (base image has not been baked with Sysmon + \\DFIR-StageRunner + sshd=Disabled yet)")
    sys.exit(1)
print("V2_BASE_BAKE_VERIFY: PASS")
PY
}

build_bake_iso() {
    local sysmon_bin="${1:?Path to Sysmon64.exe required}"
    local out_iso="${2:-/tmp/v2_base_bake.iso}"
    if [[ ! -f "$sysmon_bin" ]]; then
        echo "ERROR: Sysmon64.exe not found at: $sysmon_bin" >&2
        exit 1
    fi
    "${PYTHON_BIN}" - "$sysmon_bin" "$out_iso" "${REPO_ROOT}/docs/v2/hardening/Install-V2BaseBootstrap.ps1" <<'PY'
import sys
from pathlib import Path
from src.v2.pilot_staging import _build_minimal_iso9660

sysmon_p = Path(sys.argv[1])
out_p = Path(sys.argv[2])
ps1_p = Path(sys.argv[3])

files = {
    "SYSMON64.EXE": sysmon_p.read_bytes(),
    "INSTALL.PS1": ps1_p.read_bytes(),
}
out_p.write_bytes(_build_minimal_iso9660("DFIR_BAKE", files))
print(f"Built read-only DFIR_BAKE maintenance ISO: {out_p} ({out_p.stat().st_size} bytes)")
PY
}

seal_and_cache() {
    local img="${1:-$BASE_IMG}"
    local cache_p="${2:-$BASE_CACHE}"
    if [[ -n "$(pgrep -a qemu || true)" ]]; then
        echo "ERROR: Active QEMU process detected. Shut down the maintenance VM cleanly before sealing." >&2
        exit 1
    fi
    verify_image_readonly "$img"
    chmod 0444 "$img"
    sudo chattr +i "$img"
    "${REPO_ROOT}/docs/v2/hardening/04_watchdog_and_base_hash.sh" record-base "$img"
    local new_sha
    new_sha="$(sha256sum "$img" | awk '{print $1}')"
    echo "New sealed win11_base.qcow2 SHA-256: ${new_sha}"
    "${PYTHON_BIN}" -m src.v2.offline_extractor \
        --qcow2 "$img" \
        --out-dir /tmp/v2_baked_base_verify \
        --run-id baked_base_verify \
        --base-cache-path "$cache_p" \
        --build-base-cache \
        --expected-base-sha256 "$new_sha"
    rm -rf /tmp/v2_baked_base_verify
    echo "V2_BASE_SEAL_AND_CACHE: PASS (cache written to ${cache_p})"
}

cmd="${1:-}"
case "$cmd" in
    verify-image)
        verify_image_readonly "${2:-$BASE_IMG}"
        ;;
    build-bake-iso)
        build_bake_iso "${2:-}" "${3:-/tmp/v2_base_bake.iso}"
        ;;
    seal-and-cache)
        seal_and_cache "${2:-$BASE_IMG}" "${3:-$BASE_CACHE}"
        ;;
    *)
        usage
        exit 1
        ;;
esac
