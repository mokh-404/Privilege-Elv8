#!/usr/bin/env bash
# 00_bake_v2_base_image.sh — Deterministic One-Time Clean Base Image Bake, Overlay Prep & Seal Helper
#
# Why this script exists:
#   1. Libvirt domain `win11` boots from CoW overlay `/var/lib/libvirt/images/win11_overlay.qcow2`
#      backed by read-only `win11_base.qcow2` (0444). If no overlay exists (cleaned after last run),
#      virt-manager / virsh fails with "Cannot access storage file ... win11_overlay.qcow2: No such file or directory".
#   2. Read-only inspection of `/var/lib/libvirt/images/win11_base.qcow2` confirmed:
#      - Sysmon / Sysmon64 / SysmonDrv and Microsoft-Windows-Sysmon%4Operational.evtx are ABSENT;
#      - C:\DFIR-Bootstrap\Invoke-StagePayload.ps1 and scheduled task \DFIR-StageRunner are ABSENT;
#      - OpenSSH Server (sshd) is PRESENT and set to Auto-start (Start=2).
#
# Usage:
#   1. `prepare-overlay` — Create fresh `/var/lib/libvirt/images/win11_overlay.qcow2` (uid 956:956, 0660) + NVRAM.
#   2. `build-bake-iso <sysmon64_exe_path> [out_iso]` — Package Install-V2BaseBootstrap.ps1 + Sysmon64.exe into DFIR_BAKE ISO.
#   3. `seal-and-cache` — After clean maintenance boot shuts down: verify bake in overlay, commit overlay into
#      win11_base.qcow2 (`qemu-img commit`), verify base image, set 0444 + `chattr +i`, record win11_base.sha256,
#      rebuild `--build-base-cache`, and recreate a fresh clean overlay ready for `virsh start win11`.
#   4. `verify-image [qcow2_path]` — Read-only user-space check for Sysmon, \DFIR-StageRunner, and sshd Disabled.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
BASE_IMG="${BASE_IMG:-/var/lib/libvirt/images/win11_base.qcow2}"
OVERLAY_IMG="${OVERLAY_IMG:-/var/lib/libvirt/images/win11_overlay.qcow2}"
VARS_BASE="${VARS_BASE:-/var/lib/libvirt/qemu/nvram/win11_VARS.fd.base}"
VARS_LIVE="${VARS_LIVE:-/var/lib/libvirt/qemu/nvram/win11_VARS.fd}"
BASE_CACHE="${BASE_CACHE:-/var/lib/dfir-quarantine-vault/win11_base_cache.json.gz}"
PYTHON_BIN="${REPO_ROOT}/.venv/bin/python"

usage() {
    cat <<EOF
Usage:
  $0 prepare-overlay [base_qcow2] [overlay_qcow2]
  $0 verify-image [qcow2_path]
  $0 build-bake-iso <path_to_Sysmon64.exe> [out_iso_path]
  $0 seal-and-cache [base_qcow2] [base_cache_path]
EOF
}

prepare_overlay() {
    local base="${1:-$BASE_IMG}"
    local overlay="${2:-$OVERLAY_IMG}"
    if [[ -n "$(pgrep -a qemu || true)" ]]; then
        echo "ERROR: Active QEMU process detected. Shut down running VMs before modifying overlays." >&2
        exit 1
    fi
    if [[ ! -f "$base" ]]; then
        echo "ERROR: Base image not found at: $base" >&2
        exit 1
    fi
    if [[ -f "$overlay" ]]; then
        echo "Removing stale overlay before fresh CoW creation: $overlay"
        sudo rm -f "$overlay"
    fi
    local base_dir overlay_dir rel_base
    base_dir="$(cd "$(dirname "$base")" && pwd)"
    overlay_dir="$(cd "$(dirname "$overlay")" && pwd)"
    if [[ "$base_dir" == "$overlay_dir" ]]; then
        rel_base="$(basename "$base")"
    else
        rel_base="$(realpath --relative-to="$overlay_dir" "$base")"
    fi
    sudo qemu-img create -f qcow2 -F qcow2 -b "$rel_base" "$overlay"
    sudo chown 956:956 "$overlay"
    sudo chmod 0660 "$overlay"

    if [[ -f "$VARS_BASE" ]]; then
        sudo cp -f "$VARS_BASE" "$VARS_LIVE"
        sudo chown 956:956 "$VARS_LIVE"
        sudo chmod 0600 "$VARS_LIVE"
    fi
    ls -la "$overlay" "$VARS_LIVE"
    echo "OVERLAY_READY: $overlay (relative backing: $rel_base -> $base)"
}

verify_image_readonly() {
    local img="${1:-$BASE_IMG}"
    PYTHONPATH="${REPO_ROOT}" "${PYTHON_BIN}" - "$img" <<'PY'
import sys
from src.v2.offline_extractor import close_target_safely, open_qcow2_target_readonly

img_path = sys.argv[1]
t = open_qcow2_target_readonly(img_path)
try:
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
        print("V2_BASE_BAKE_VERIFY: FAIL (base image/overlay has not been baked with Sysmon + \\DFIR-StageRunner + sshd=Disabled yet)")
        sys.exit(1)
    print("V2_BASE_BAKE_VERIFY: PASS")
finally:
    close_target_safely(t)
PY
}

build_bake_iso() {
    local sysmon_bin="${1:?Path to Sysmon64.exe required}"
    local out_iso="${2:-/tmp/v2_base_bake.iso}"
    if [[ ! -f "$sysmon_bin" ]]; then
        echo "ERROR: Sysmon64.exe not found at: $sysmon_bin" >&2
        exit 1
    fi
    PYTHONPATH="${REPO_ROOT}" "${PYTHON_BIN}" - "$sysmon_bin" "$out_iso" "${REPO_ROOT}/docs/v2/hardening/Install-V2BaseBootstrap.ps1" <<'PY'
import sys
from pathlib import Path
from src.v2.pilot_staging import build_stage_iso

sysmon_p = Path(sys.argv[1])
out_p = Path(sys.argv[2])
ps1_p = Path(sys.argv[3])

files = {
    "Sysmon64.exe": sysmon_p.read_bytes(),
    "Install-V2BaseBootstrap.ps1": ps1_p.read_bytes(),
    "SYSMON64.EXE": sysmon_p.read_bytes(),
    "INSTALL.PS1": ps1_p.read_bytes(),
}
build_stage_iso(out_p, "DFIR_BAKE", files)
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

    # If changes were written into win11_overlay.qcow2 during the maintenance boot, verify & commit them to base
    if [[ -f "$OVERLAY_IMG" ]]; then
        echo "Verifying baked overlay before committing into base: $OVERLAY_IMG"
        verify_image_readonly "$OVERLAY_IMG"
        sudo chattr -i "$img" 2>/dev/null || true
        sudo chmod 0644 "$img"
        sudo qemu-img commit "$OVERLAY_IMG"
        sudo rm -f "$OVERLAY_IMG"
    fi

    verify_image_readonly "$img"
    sudo chmod 0444 "$img"
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
    prepare_overlay "$img" "$OVERLAY_IMG"
}

cmd="${1:-}"
case "$cmd" in
    prepare-overlay)
        prepare_overlay "${2:-$BASE_IMG}" "${3:-$OVERLAY_IMG}"
        ;;
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
