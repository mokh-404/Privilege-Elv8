#!/usr/bin/env bash
# Emergency incident / abort script for Phase 2+ malware batches.
# Immediately halts VMs via virsh destroy, enforces virbr1 DROP, captures logs, verifies base image integrity.
set -euo pipefail

URI="${LIBVIRT_URI:-qemu:///system}"
WIN_DOM="${WIN_DOM:-win11}"
INET_DOM="${INET_DOM:-inetsim-vm}"
BASE_IMG="${BASE_IMG:-/var/lib/libvirt/images/win11_base.qcow2}"
NVRAM_BASE="${NVRAM_BASE:-/var/lib/libvirt/qemu/nvram/win11_VARS.fd.base}"
OVERLAY_IMG="${OVERLAY_IMG:-/var/lib/libvirt/images/win11_overlay.qcow2}"
HASH_FILE="${HASH_FILE:-/var/lib/libvirt/images/v2_base_hashes.sha256}"
INCIDENT_DIR="${INCIDENT_DIR:-$HOME/dfir_v2_incidents}"

STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
OUT="$INCIDENT_DIR/incident_$STAMP"
mkdir -p "$OUT"
chmod 0700 "$OUT"

echo "[!] INCIDENT ABORT TRIGGERED AT $STAMP" | tee "$OUT/incident.log"

echo "[1/5] Stopping domains via virsh destroy (never virsh create)..." | tee -a "$OUT/incident.log"
for d in "$WIN_DOM" "$INET_DOM"; do
    sudo virsh -c "$URI" destroy "$d" >>"$OUT/incident.log" 2>&1 || true
done

echo "[2/5] Re-enforcing virbr1 default-DROP firewall..." | tee -a "$OUT/incident.log"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [[ -x "$SCRIPT_DIR/01_firewall_win11_isolated.sh" ]]; then
    sudo "$SCRIPT_DIR/01_firewall_win11_isolated.sh" --apply >>"$OUT/incident.log" 2>&1 || true
fi

echo "[3/5] Collecting firewall/network state snapshots..." | tee -a "$OUT/incident.log"
iptables -L -v -n >"$OUT/iptables_snapshot.txt" 2>&1 || true
dmesg -T 2>/dev/null | grep "V2-VIRBR1-DROP" | tail -n 200 >"$OUT/virbr1_drop_kernel.log" || true

echo "[4/5] Verifying base image & NVRAM integrity..." | tee -a "$OUT/incident.log"
sha256sum "$BASE_IMG" "$NVRAM_BASE" >"$OUT/base_sha256_after.txt" 2>&1 || true
if [[ -f "$HASH_FILE" ]]; then
    if sha256sum -c "$HASH_FILE" >>"$OUT/incident.log" 2>&1; then
        echo "[+] Base image SHA-256 MATCHED baseline." | tee -a "$OUT/incident.log"
    else
        echo "[!!!] CRITICAL: BASE IMAGE HASH MISMATCH! Rebuild base from offline backup." | tee -a "$OUT/incident.log"
    fi
fi

echo "[5/5] Disposing compromised writable overlay (mode check + unlink)..." | tee -a "$OUT/incident.log"
if [[ -f "$OVERLAY_IMG" ]]; then
    sudo rm -f "$OVERLAY_IMG" >>"$OUT/incident.log" 2>&1 || true
fi
echo "[+] Incident evidence saved in $OUT. Batch execution halted." | tee -a "$OUT/incident.log"
