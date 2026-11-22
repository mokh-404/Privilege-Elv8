#!/usr/bin/env bash
# Unprivileged offline extractor container runner (OD-V2-04, OD-V2-16).
# Parses closed QCOW2 overlay in pure user space with zero host-kernel mounts and zero network.
set -euo pipefail

IMAGE_NAME="${IMAGE_NAME:-dfir-v2-offline-extractor:latest}"
CONTAINER_RT="${CONTAINER_RT:-docker}"
OVERLAY_QCOW2="${1:-}"
RUN_OUT_DIR="${2:-}"
RUN_ID="${3:-offline_run}"

if [[ -z "$OVERLAY_QCOW2" || -z "$RUN_OUT_DIR" ]]; then
    echo "Usage: $0 <overlay_qcow2_path> <host_structured_output_dir> [run_id]" >&2
    exit 2
fi
if [[ ! -f "$OVERLAY_QCOW2" ]]; then
    echo "ERROR: QCOW2 image not found: $OVERLAY_QCOW2" >&2
    exit 1
fi
if ! command -v "$CONTAINER_RT" >/dev/null 2>&1; then
    echo "ERROR: Container runtime $CONTAINER_RT not found (note: podman is not installed on this host)." >&2
    exit 1
fi
if pgrep -x qemu-system-x86_64 >/dev/null 2>&1; then
    if sudo virsh -c qemu:///system domstate win11 2>/dev/null | grep -qi running; then
        echo "ABORT: win11 domain is still running! Run virsh destroy before offline overlay parsing." >&2
        exit 1
    fi
fi

mkdir -p "$RUN_OUT_DIR"
ABS_QCOW2="$(realpath "$OVERLAY_QCOW2")"
ABS_OUT="$(realpath "$RUN_OUT_DIR")"

echo "[*] Running unprivileged user-space extractor container on $ABS_QCOW2..."
exec "$CONTAINER_RT" run --rm \
    --network=none \
    --read-only \
    --cap-drop=ALL \
    --security-opt=no-new-privileges \
    --pids-limit=256 \
    --memory=4g \
    --cpus=2 \
    --user "$(id -u):$(id -g)" \
    --tmpfs /tmp:rw,noexec,nosuid,nodev,size=512m \
    -v "${ABS_QCOW2}:/input/disk.qcow2:ro" \
    -v "${ABS_OUT}:/output:rw" \
    "$IMAGE_NAME" \
    --qcow2 /input/disk.qcow2 \
    --out-dir /output \
    --run-id "$RUN_ID"
