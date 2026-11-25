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
  $0 --build [--full]
  $0 --refresh-code
  $0 <overlay_qcow2_path> <host_structured_output_dir> [run_id] [base_cache_path|none]

Environment overrides:
  IMAGE_NAME       Container image tag (default: dfir-v2-offline-extractor:latest)
  CONTAINER_RT     Container runtime binary (default: docker)
  FORCE_FULL_BUILD Set to 1 to force a full Dockerfile rebuild instead of code-only refresh
  BASE_QCOW2       Optional explicit backing QCOW2 path if auto-detection cannot resolve it
  BASE_CACHE_PATH  Base-image cache .json.gz path (default: $DEFAULT_BASE_CACHE if present)
EOF
}

if [[ "${1:-}" == "--build" || "${1:-}" == "--refresh-code" ]]; then
    BUILD_CMD="${1}"
    BUILD_OPT="${2:-}"
    if ! command -v "$CONTAINER_RT" >/dev/null 2>&1; then
        echo "ERROR: Container runtime $CONTAINER_RT not found (note: podman is not installed on this host)." >&2
        exit 1
    fi

    REQ_HOST_FILE="${REPO_ROOT}/docs/v2/hardening/requirements_extractor.txt"
    REQ_HOST_SHA="$(sha256sum "$REQ_HOST_FILE" | awk '{print $1}')"
    FULL_BUILD=0
    if [[ "$BUILD_CMD" == "--build" && ( "$BUILD_OPT" == "--full" || "${FORCE_FULL_BUILD:-0}" == "1" ) ]]; then
        FULL_BUILD=1
    fi

    if [[ "$FULL_BUILD" -eq 0 ]]; then
        IMG_ID="$("$CONTAINER_RT" image inspect --format '{{.Id}}' "$IMAGE_NAME" 2>/dev/null || true)"
        REQ_IMG_SHA=""
        if [[ -n "$IMG_ID" ]]; then
            if REQ_IMG_TXT="$("$CONTAINER_RT" run --rm --network=none --entrypoint cat "$IMAGE_NAME" /app/requirements_extractor.txt 2>/dev/null)" && [[ -n "$REQ_IMG_TXT" ]]; then
                REQ_IMG_SHA="$(printf '%s\n' "$REQ_IMG_TXT" | sha256sum | awk '{print $1}')"
            fi
        fi

        if [[ -n "$IMG_ID" && "$REQ_IMG_SHA" == "$REQ_HOST_SHA" ]]; then
            DEPS_TAG="dfir-v2-offline-extractor-deps:${REQ_HOST_SHA:0:12}"
            if ! "$CONTAINER_RT" image inspect "$DEPS_TAG" >/dev/null 2>&1; then
                "$CONTAINER_RT" tag "$IMAGE_NAME" "$DEPS_TAG"
            fi
            TMP_DF="$(mktemp /tmp/dfir_refresh_dockerfile.XXXXXX)"
            trap 'rm -f "$TMP_DF"' EXIT
            cat > "$TMP_DF" <<EOF
FROM ${DEPS_TAG}
USER 0:0
WORKDIR /app
COPY src/__init__.py /app/src/__init__.py
COPY src/config.py /app/src/config.py
COPY src/utils/__init__.py /app/src/utils/__init__.py
COPY src/utils/repro.py /app/src/utils/repro.py
COPY src/data/__init__.py /app/src/data/__init__.py
COPY src/data/sanitize.py /app/src/data/sanitize.py
COPY src/data/features.py /app/src/data/features.py
COPY src/models/__init__.py /app/src/models/__init__.py
COPY src/models/preprocess.py /app/src/models/preprocess.py
COPY src/v2/__init__.py /app/src/v2/__init__.py
COPY src/v2/refgraph.py /app/src/v2/refgraph.py
COPY src/v2/offline_extractor.py /app/src/v2/offline_extractor.py
USER 1000:1000
ENTRYPOINT ["python", "-m", "src.v2.offline_extractor"]
EOF
            echo "[*] Fast offline code refresh of $IMAGE_NAME from cached deps ($DEPS_TAG)..."
            "$CONTAINER_RT" build --pull=false -f "$TMP_DF" -t "$IMAGE_NAME" "$REPO_ROOT"
            exit $?
        fi

        if [[ "$BUILD_CMD" == "--refresh-code" ]]; then
            echo "ERROR: Cannot --refresh-code (local image missing or requirements_extractor.txt changed). Run: $0 --build --full" >&2
            exit 1
        fi
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

mkdir -p "$RUN_OUT_DIR"
ABS_QCOW2="$(realpath "$OVERLAY_QCOW2")"
ABS_OUT="$(realpath "$RUN_OUT_DIR")"

VIRSH_BIN="${VIRSH_BIN:-sudo virsh}"
read -r -a VIRSH_CMD <<< "$VIRSH_BIN"
if [[ "${FORCE_VM_CHECK:-0}" == "1" ]] || pgrep -x qemu-system-x86_64 >/dev/null 2>&1; then
    if "${VIRSH_CMD[@]}" -c qemu:///system domstate win11 2>/dev/null | grep -qi running; then
        if ! active_blk_out="$("${VIRSH_CMD[@]}" -c qemu:///system domblklist win11 2>/dev/null)"; then
            echo "ABORT: win11 is running and domblklist failed; refusing offline extraction of $ABS_QCOW2." >&2
            exit 1
        fi
        while IFS= read -r blk_path; do
            [[ -z "$blk_path" ]] && continue
            resolved_blk="$(realpath -m "$blk_path" 2>/dev/null || printf '%s' "$blk_path")"
            if [[ "$resolved_blk" == "$ABS_QCOW2" ]]; then
                echo "ABORT: Target overlay '$ABS_QCOW2' is still attached to running win11 domain! Run virsh destroy before offline parsing." >&2
                exit 1
            fi
        done < <(
            printf '%s\n' "$active_blk_out" \
                | awk '{for (i=1;i<=NF;i++) if ($i ~ /^\//) print $i}' || true
        )
    fi
fi

chmod 0777 "$ABS_OUT"

restore_out_perms() {
    chmod 0755 "$ABS_OUT" 2>/dev/null || true
    chmod a+r "$ABS_OUT"/* 2>/dev/null || true
}
trap restore_out_perms EXIT
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
rc=0
"$CONTAINER_RT" run --rm \
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
    "${EXTRACTOR_ARGS[@]}" || rc=$?
restore_out_perms
exit "$rc"
