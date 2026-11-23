#!/usr/bin/env bash
# Unprivileged offline extractor container runner (OD-V2-04, OD-V2-16).
# Parses closed QCOW2 overlay + backing base image in pure user space with zero host-kernel mounts and zero network.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../../.." && pwd)"
IMAGE_NAME="${IMAGE_NAME:-dfir-v2-offline-extractor:latest}"
DOCKERFILE_PATH="${DOCKERFILE_PATH:-${SCRIPT_DIR}/offline_extractor.Dockerfile}"
CONTAINER_RT="${CONTAINER_RT:-docker}"
DEFAULT_BASE_CACHE="/var/lib/dfir-quarantine-vault/win11_base_cache.json.gz"

usage() {
    cat <<EOF >&2
Usage:
  $0 --build
  $0 <overlay_qcow2_path> <host_structured_output_dir> [run_id] [base_cache_path|none]

Environment overrides:
  IMAGE_NAME       Container image tag (default: dfir-v2-offline-extractor:latest)
  CONTAINER_RT     Container runtime binary (default: docker)
  BASE_QCOW2       Optional explicit backing QCOW2 path if auto-detection cannot resolve it
  BASE_CACHE_PATH  Base-image cache .json.gz path (default: $DEFAULT_BASE_CACHE if present)
EOF
}

if [[ "${1:-}" == "--build" ]]; then
    if ! command -v "$CONTAINER_RT" >/dev/null 2>&1; then
        echo "ERROR: Container runtime $CONTAINER_RT not found (note: podman is not installed on this host)." >&2
        exit 1
    fi
    echo "[*] Building unprivileged offline extractor image $IMAGE_NAME from $DOCKERFILE_PATH..."
    exec "$CONTAINER_RT" build -f "$DOCKERFILE_PATH" -t "$IMAGE_NAME" "$REPO_ROOT"
fi

OVERLAY_QCOW2="${1:-}"
RUN_OUT_DIR="${2:-}"
RUN_ID="${3:-offline_run}"
BASE_CACHE_ARG="${4:-}"
BASE_CACHE_PATH="${BASE_CACHE_ARG:-${BASE_CACHE_PATH:-$DEFAULT_BASE_CACHE}}"

if [[ -z "$OVERLAY_QCOW2" || -z "$RUN_OUT_DIR" ]]; then
    usage
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
QCOW2_NAME="$(basename "$ABS_QCOW2")"
QCOW2_DIR="$(dirname "$ABS_QCOW2")"

PY_HELPER="python3"
if ! command -v "$PY_HELPER" >/dev/null 2>&1 && [[ -x "${REPO_ROOT}/.venv/bin/python" ]]; then
    PY_HELPER="${REPO_ROOT}/.venv/bin/python"
fi

ABS_BASE=""
RAW_BACKING=""
if [[ -n "${BASE_QCOW2:-}" ]]; then
    if [[ ! -f "$BASE_QCOW2" ]]; then
        echo "ERROR: Explicit BASE_QCOW2 not found: $BASE_QCOW2" >&2
        exit 1
    fi
    ABS_BASE="$(realpath "$BASE_QCOW2")"
elif command -v qemu-img >/dev/null 2>&1 && command -v "$PY_HELPER" >/dev/null 2>&1; then
    RAW_BACKING="$(
        qemu-img info --output=json "$ABS_QCOW2" 2>/dev/null \
            | "$PY_HELPER" -c 'import json,sys; d=json.load(sys.stdin); print(d.get("backing-filename") or "")' \
            2>/dev/null || true
    )"
    if [[ -n "$RAW_BACKING" ]]; then
        if [[ "$RAW_BACKING" == /* ]]; then
            CAND_BACKING="$RAW_BACKING"
        else
            CAND_BACKING="${QCOW2_DIR}/${RAW_BACKING}"
        fi
        if [[ -f "$CAND_BACKING" ]]; then
            ABS_BASE="$(realpath "$CAND_BACKING")"
        elif [[ -f "${QCOW2_DIR}/$(basename "$RAW_BACKING")" ]]; then
            ABS_BASE="$(realpath "${QCOW2_DIR}/$(basename "$RAW_BACKING")")"
        else
            echo "ERROR: Backing file '$RAW_BACKING' referenced by '$ABS_QCOW2' not found on host." >&2
            exit 1
        fi
    fi
elif [[ "$QCOW2_NAME" != "win11_base.qcow2" && -f "${QCOW2_DIR}/win11_base.qcow2" ]]; then
    ABS_BASE="$(realpath "${QCOW2_DIR}/win11_base.qcow2")"
fi

DOCKER_VOLS=(
    -v "${ABS_QCOW2}:/input/${QCOW2_NAME}:ro"
)
if [[ -n "$ABS_BASE" && "$ABS_BASE" != "$ABS_QCOW2" ]]; then
    BASE_NAME="$(basename "$ABS_BASE")"
    if [[ "$BASE_NAME" == "$QCOW2_NAME" ]]; then
        echo "ERROR: Overlay basename '$QCOW2_NAME' collides with backing basename '$BASE_NAME' under /input/." >&2
        exit 1
    fi
    DOCKER_VOLS+=(-v "${ABS_BASE}:/input/${BASE_NAME}:ro")
fi

EXTRACTOR_ARGS=(
    --qcow2 "/input/${QCOW2_NAME}"
    --out-dir /output
    --run-id "$RUN_ID"
)

if [[ -n "$BASE_CACHE_PATH" && "$BASE_CACHE_PATH" != "none" && -f "$BASE_CACHE_PATH" ]]; then
    ABS_CACHE="$(realpath "$BASE_CACHE_PATH")"
    DOCKER_VOLS+=(-v "${ABS_CACHE}:/cache/base_cache.json.gz:ro")
    EXTRACTOR_ARGS+=(--base-cache-path /cache/base_cache.json.gz)
fi

DOCKER_VOLS+=(-v "${ABS_OUT}:/output:rw")

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
    "${DOCKER_VOLS[@]}" \
    "$IMAGE_NAME" \
    "${EXTRACTOR_ARGS[@]}"
