#!/usr/bin/env bash
# Host-side wall-clock VM watchdog (hard virsh destroy) and base-image SHA-256 verifier.
# NEVER uses `virsh create` (transient domain creation is banned). Only permitted libvirt/file actions.
set -euo pipefail

URI="${LIBVIRT_URI:-qemu:///system}"
DOMAIN="${DOMAIN:-win11}"
BASE_IMG="${BASE_IMG:-/var/lib/libvirt/images/win11_base.qcow2}"
NVRAM_BASE="${NVRAM_BASE:-/var/lib/libvirt/qemu/nvram/win11_VARS.fd.base}"
HASH_FILE="${HASH_FILE:-/var/lib/libvirt/images/v2_base_hashes.sha256}"

cmd="${1:-}"
case "$cmd" in
    record-base)
        echo "[*] Verifying 0444 read-only mode on base image..."
        stat -c '%a %n' "$BASE_IMG" "$NVRAM_BASE"
        sha256sum "$BASE_IMG" "$NVRAM_BASE" | tee "$HASH_FILE"
        echo "[+] Recorded immutable baseline hashes to $HASH_FILE"
        ;;
    verify-base)
        if [[ ! -f "$HASH_FILE" ]]; then
            echo "ERROR: Hash baseline file missing: $HASH_FILE (run record-base first)" >&2
            exit 1
        fi
        perm="$(stat -c '%a' "$BASE_IMG")"
        if [[ "$perm" != "444" ]]; then
            echo "ERROR: Base image permissions drifted! Expected 444, got $perm on $BASE_IMG" >&2
            exit 1
        fi
        sha256sum -c "$HASH_FILE"
        echo "[+] Base image & NVRAM SHA-256 verification PASSED."
        ;;
    watchdog)
        MAX_SEC="${2:-}"
        if [[ -z "$MAX_SEC" || ! "$MAX_SEC" =~ ^[0-9]+$ ]]; then
            echo "Usage: $0 watchdog <max_wall_seconds>" >&2
            exit 2
        fi
        echo "[*] Arming host wall-clock watchdog: dom=$DOMAIN max=${MAX_SEC}s uri=$URI"
        start_ts=$(date +%s)
        while true; do
            state="$(sudo virsh -c "$URI" domstate "$DOMAIN" 2>/dev/null | tr '[:upper:]' '[:lower:]' | xargs || true)"
            if [[ -z "$state" || "$state" == "shut off" ]]; then
                echo "[+] Domain $DOMAIN is shut off; watchdog exiting cleanly."
                exit 0
            fi
            now_ts=$(date +%s)
            elapsed=$((now_ts - start_ts))
            if (( elapsed >= MAX_SEC )); then
                echo "[!] WATCHDOG TIMEOUT (${elapsed}s >= ${MAX_SEC}s): forcing virsh destroy $DOMAIN" >&2
                sudo virsh -c "$URI" destroy "$DOMAIN" || true
                exit 124
            fi
            sleep 2
        done
        ;;
    *)
        cat <<'EOF'
Usage:
  04_watchdog_and_base_hash.sh record-base
  04_watchdog_and_base_hash.sh verify-base
  04_watchdog_and_base_hash.sh watchdog <max_wall_seconds>
EOF
        exit 2
        ;;
esac
