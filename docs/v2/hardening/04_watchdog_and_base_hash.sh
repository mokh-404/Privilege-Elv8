#!/usr/bin/env bash
# Host-side wall-clock VM watchdog (detached + synchronous), base-image immutability/SHA-256 verifier,
# and virbr1 egress firewall & packet-counter guard.
# NEVER uses `virsh create` (transient domain creation is banned). Only permitted libvirt/file actions.
set -euo pipefail

URI="${LIBVIRT_URI:-qemu:///system}"
DOMAIN="${DOMAIN:-win11}"
INETSIM_DOMAIN="${INETSIM_DOMAIN:-inetsim-vm}"
BRIDGE="${BRIDGE:-virbr1}"
BASE_IMG="${BASE_IMG:-/var/lib/libvirt/images/win11_base.qcow2}"
NVRAM_BASE="${NVRAM_BASE:-/var/lib/libvirt/qemu/nvram/win11_VARS.fd.base}"
INETSIM_BASE="${INETSIM_BASE:-/var/lib/libvirt/images/inetsim_base.qcow2}"
HASH_FILE="${HASH_FILE:-/var/lib/libvirt/images/v2_base_hashes.sha256}"
FAST_META_FILE="${FAST_META_FILE:-/var/lib/libvirt/images/v2_base_fast_meta.env}"
VIRSH_BIN="${VIRSH_BIN:-sudo virsh}"
IPTABLES_BIN="${IPTABLES_BIN:-sudo iptables}"
MAX_IN_DROP_BURST="${MAX_IN_DROP_BURST:-2000}"
FORCE_RECORD="${FORCE_RECORD:-0}"

# Pinned golden SHA-256 of sealed win11_base.qcow2 (refused on mismatch in record-base/verify-base/verify-base-fast)
GOLDEN_BASE_SHA256="${GOLDEN_BASE_SHA256:-d2facced4255e3ae1cb821249d5e6330e380f639cee8a5aae19ef99be690835c}"
# Pinned golden SHA-256 of sealed win11_VARS.fd.base (verified in v2_base_fast_meta.env and v2_base_hashes.sha256)
GOLDEN_NVRAM_SHA256="${GOLDEN_NVRAM_SHA256-2aeb86356d8c160607a0f258d8b0044b2e30a592c510992b28cb5f5312dda6be}"

read -r -a VIRSH_CMD <<< "$VIRSH_BIN"
read -r -a IPTABLES_CMD <<< "$IPTABLES_BIN"

GOLDEN_BASE_SHA256_LC=""
GOLDEN_NVRAM_SHA256_LC=""

_validate_golden_pins() {
    if [[ -z "$GOLDEN_BASE_SHA256" || ! "$GOLDEN_BASE_SHA256" =~ ^[0-9a-fA-F]{64}$ ]]; then
        echo "ERROR: GOLDEN_BASE_SHA256 must be a valid 64-hex SHA-256 digest (got '${GOLDEN_BASE_SHA256}')." >&2
        exit 1
    fi
    GOLDEN_BASE_SHA256_LC="$(printf '%s' "$GOLDEN_BASE_SHA256" | tr '[:upper:]' '[:lower:]')"
    if [[ -z "$GOLDEN_NVRAM_SHA256" ]]; then
        echo "WARNING: GOLDEN_NVRAM_SHA256 is unset! Review win11_VARS.fd.base SHA-256 and pin GOLDEN_NVRAM_SHA256 in 04_watchdog_and_base_hash.sh before unattended malware collection." >&2
        GOLDEN_NVRAM_SHA256_LC=""
    elif [[ ! "$GOLDEN_NVRAM_SHA256" =~ ^[0-9a-fA-F]{64}$ ]]; then
        echo "ERROR: GOLDEN_NVRAM_SHA256 must be empty or a valid 64-hex SHA-256 digest (got '${GOLDEN_NVRAM_SHA256}')." >&2
        exit 1
    else
        GOLDEN_NVRAM_SHA256_LC="$(printf '%s' "$GOLDEN_NVRAM_SHA256" | tr '[:upper:]' '[:lower:]')"
    fi
}

_hash_file_entry_sha() {
    local tgt="$1"
    awk -v tgt="$tgt" -v bname="$(basename "$tgt")" '
        {
            f = $2; sub(/^\*/, "", f);
            if (f == tgt || f == bname) { print tolower($1); exit }
        }
    ' "$HASH_FILE"
}

_backup_existing_file() {
    local src="$1"
    if [[ ! -f "$src" ]]; then
        return 0
    fi
    local ts backup
    ts="$(date -u +%Y%m%dT%H%M%SZ)"
    backup="${src}.bak.${ts}"
    if [[ -e "$backup" ]]; then
        backup="${backup}.$$"
    fi
    cp -p "$src" "$backup"
    echo "[+] Backed up existing $src -> $backup"
}

_verify_base_immutability_and_nvram() {
    local check_lsattr="${1:-1}"
    _validate_golden_pins
    if [[ ! -f "$HASH_FILE" ]]; then
        echo "ERROR: Hash baseline file missing: $HASH_FILE (run record-base first)" >&2
        exit 1
    fi
    if [[ ! -f "$BASE_IMG" ]]; then
        echo "ERROR: Base image missing: $BASE_IMG" >&2
        exit 1
    fi
    if [[ ! -f "$NVRAM_BASE" ]]; then
        echo "ERROR: NVRAM baseline missing: $NVRAM_BASE" >&2
        exit 1
    fi
    local perm
    perm="$(stat -c '%a' "$BASE_IMG")"
    if [[ "$perm" != "444" ]]; then
        echo "ERROR: Base image permissions drifted! Expected 444, got $perm on $BASE_IMG" >&2
        exit 1
    fi
    if [[ "$check_lsattr" == "1" && "${SKIP_LSATTR_CHECK:-0}" != "1" ]]; then
        if ! command -v lsattr >/dev/null 2>&1; then
            echo "ERROR: lsattr command not found to verify +i immutable flag on $BASE_IMG" >&2
            exit 1
        fi
        local attr_flags
        attr_flags="$(lsattr -d "$BASE_IMG" 2>/dev/null | awk '{print $1}' || true)"
        if [[ "$attr_flags" != *i* ]]; then
            echo "ERROR: Base image immutable flag (+i) missing on $BASE_IMG (got '$attr_flags')" >&2
            exit 1
        fi
    fi

    local expected_base expected_nvram actual_nvram
    expected_base="$(_hash_file_entry_sha "$BASE_IMG")"
    if [[ -z "$expected_base" ]]; then
        echo "ERROR: Base image entry ($BASE_IMG) missing from $HASH_FILE" >&2
        exit 1
    fi
    if [[ "$expected_base" != "$GOLDEN_BASE_SHA256_LC" ]]; then
        echo "ERROR: HASH_FILE base SHA-256 mismatch vs pinned GOLDEN_BASE_SHA256! expected=$GOLDEN_BASE_SHA256_LC recorded=$expected_base" >&2
        exit 1
    fi

    # Verify full SHA-256 of NVRAM_BASE (528 KiB) against HASH_FILE and optional GOLDEN_NVRAM_SHA256 pin
    expected_nvram="$(_hash_file_entry_sha "$NVRAM_BASE")"
    if [[ -z "$expected_nvram" ]]; then
        echo "ERROR: NVRAM baseline entry ($NVRAM_BASE) missing from $HASH_FILE" >&2
        exit 1
    fi
    actual_nvram="$(sha256sum "$NVRAM_BASE" | awk '{print tolower($1)}')"
    if [[ "$actual_nvram" != "$expected_nvram" ]]; then
        echo "ERROR: NVRAM baseline SHA-256 mismatch! expected=$expected_nvram actual=$actual_nvram" >&2
        exit 1
    fi
    if [[ -n "$GOLDEN_NVRAM_SHA256_LC" && "$actual_nvram" != "$GOLDEN_NVRAM_SHA256_LC" ]]; then
        echo "ERROR: NVRAM SHA-256 mismatch vs pinned GOLDEN_NVRAM_SHA256! expected=$GOLDEN_NVRAM_SHA256_LC actual=$actual_nvram" >&2
        exit 1
    fi

    if [[ -f "$FAST_META_FILE" ]]; then
        # shellcheck disable=SC1090
        source "$FAST_META_FILE"
        local cur_base_stat
        cur_base_stat="$(stat -c '%i:%s:%b:%Y' "$BASE_IMG")"
        if [[ -n "${BASE_STAT:-}" && "$cur_base_stat" != "$BASE_STAT" ]]; then
            echo "ERROR: Base image stat drifted! expected=$BASE_STAT actual=$cur_base_stat ($BASE_IMG)" >&2
            exit 1
        fi
        if [[ -n "${INETSIM_STAT:-}" && -f "$INETSIM_BASE" ]]; then
            local cur_inet_stat
            cur_inet_stat="$(stat -c '%i:%s:%b:%Y' "$INETSIM_BASE")"
            if [[ "$cur_inet_stat" != "$INETSIM_STAT" ]]; then
                echo "ERROR: inetsim_base.qcow2 stat drifted! expected=$INETSIM_STAT actual=$cur_inet_stat" >&2
                exit 1
            fi
        fi
    fi
}

_egress_snapshot_json() {
    local in_rules fwd_rules ufw_err=0 fw_valid="true"
    local -a errs=()

    in_rules="$("${IPTABLES_CMD[@]}" -S INPUT 2>/dev/null || true)"
    fwd_rules="$("${IPTABLES_CMD[@]}" -S FORWARD 2>/dev/null || true)"

    local in_top fwd_top1 fwd_top2
    in_top="$(printf '%s\n' "$in_rules" | grep -E '^-A INPUT ' | head -n 1 || true)"
    fwd_top1="$(printf '%s\n' "$fwd_rules" | grep -E '^-A FORWARD ' | sed -n '1p' || true)"
    fwd_top2="$(printf '%s\n' "$fwd_rules" | grep -E '^-A FORWARD ' | sed -n '2p' || true)"

    if [[ ! "$in_top" =~ ^-A[[:space:]]INPUT[[:space:]]-i[[:space:]]${BRIDGE}([[:space:]]|$).*-[jg][[:space:]]V2_VIRBR1_IN$ ]]; then
        fw_valid="false"
        errs+=("INPUT_pos1_not_V2_VIRBR1_IN:${in_top}")
    fi
    if [[ ! "$fwd_top1" =~ ^-A[[:space:]]FORWARD[[:space:]]-i[[:space:]]${BRIDGE}([[:space:]]|$).*-[jg][[:space:]]V2_VIRBR1_FWD$ ]]; then
        fw_valid="false"
        errs+=("FORWARD_pos1_not_V2_VIRBR1_FWD_in:${fwd_top1}")
    fi
    if [[ ! "$fwd_top2" =~ ^-A[[:space:]]FORWARD[[:space:]]-o[[:space:]]${BRIDGE}([[:space:]]|$).*-[jg][[:space:]]V2_VIRBR1_FWD$ ]]; then
        fw_valid="false"
        errs+=("FORWARD_pos2_not_V2_VIRBR1_FWD_out:${fwd_top2}")
    fi

    for uch in ufw-user-input ufw-user-output ufw-user-forward; do
        local u_bad
        u_bad="$("${IPTABLES_CMD[@]}" -S "$uch" 2>/dev/null \
            | grep -E "(^|[[:space:]])(-i|-o)[[:space:]]+${BRIDGE}([[:space:]]|$)" \
            | grep -E -- "-j[[:space:]]+ACCEPT([[:space:]]|$)" || true)"
        if [[ -n "$u_bad" ]]; then
            fw_valid="false"
            errs+=("ufw_accept_present:${uch}")
        fi
    done

    local fwd_tbl in_tbl
    fwd_tbl="$("${IPTABLES_CMD[@]}" -L V2_VIRBR1_FWD -v -n -x 2>/dev/null || true)"
    in_tbl="$("${IPTABLES_CMD[@]}" -L V2_VIRBR1_IN -v -n -x 2>/dev/null || true)"
    if [[ -z "$fwd_tbl" || -z "$in_tbl" ]]; then
        fw_valid="false"
        errs+=("missing_V2_VIRBR1_chain")
    fi

    local fwd_counts in_counts
    fwd_counts="$(printf '%s\n' "$fwd_tbl" | awk -v br="$BRIDGE" '
        BEGIN { intra_p=0; intra_b=0; drop_p=0; drop_b=0 }
        /^[[:space:]]*[0-9]+/ {
            if ($3 == "ACCEPT" && $6 == br && $7 == br) { intra_p += $1; intra_b += $2 }
            else if ($3 == "DROP") { drop_p += $1; drop_b += $2 }
        }
        END { printf "%d %d %d %d", intra_p, intra_b, drop_p, drop_b }
    ')"
    in_counts="$(printf '%s\n' "$in_tbl" | awk '
        BEGIN { est_p=0; est_b=0; drop_p=0; drop_b=0 }
        /^[[:space:]]*[0-9]+/ {
            if ($3 == "ACCEPT") { est_p += $1; est_b += $2 }
            else if ($3 == "DROP") { drop_p += $1; drop_b += $2 }
        }
        END { printf "%d %d %d %d", est_p, est_b, drop_p, drop_b }
    ')"

    read -r fwd_intra_p fwd_intra_b fwd_drop_p fwd_drop_b <<< "$fwd_counts"
    read -r in_est_p in_est_b in_drop_p in_drop_b <<< "$in_counts"

    local errs_json="[]"
    if (( ${#errs[@]} > 0 )); then
        errs_json="["
        local first=1 e esc
        for e in "${errs[@]}"; do
            esc="${e//\\/\\\\}"
            esc="${esc//\"/\\\"}"
            if [[ "$first" -eq 1 ]]; then
                errs_json+="\"${esc}\""
                first=0
            else
                errs_json+=",\"${esc}\""
            fi
        done
        errs_json+="]"
    fi

    printf '{"bridge":"%s","firewall_rules_valid":%s,"fwd_intra_bridge_pkts":%s,"fwd_intra_bridge_bytes":%s,"fwd_drop_pkts":%s,"fwd_drop_bytes":%s,"in_established_pkts":%s,"in_established_bytes":%s,"in_drop_pkts":%s,"in_drop_bytes":%s,"errors":%s}\n' \
        "$BRIDGE" "$fw_valid" "$fwd_intra_p" "$fwd_intra_b" "$fwd_drop_p" "$fwd_drop_b" \
        "$in_est_p" "$in_est_b" "$in_drop_p" "$in_drop_b" "$errs_json"

    [[ "$fw_valid" == "true" ]]
}

_json_int_field() {
    local file="$1" key="$2"
    sed -n "s/.*\"${key}\":\([0-9][0-9]*\).*/\1/p" "$file" | head -n 1
}

_json_bool_field() {
    local file="$1" key="$2"
    sed -n "s/.*\"${key}\":\(true\|false\).*/\1/p" "$file" | head -n 1
}

cmd="${1:-}"
case "$cmd" in
    record-base)
        if [[ -n "${2:-}" ]]; then
            BASE_IMG="$2"
        fi
        _validate_golden_pins
        if [[ -f "$HASH_FILE" && "${FORCE_RECORD:-0}" != "1" ]]; then
            echo "ERROR: Refusing to overwrite existing $HASH_FILE (re-run with FORCE_RECORD=1 only after intentional base verification)." >&2
            exit 1
        fi
        if [[ ! -f "$BASE_IMG" ]]; then
            echo "ERROR: Base image missing: $BASE_IMG" >&2
            exit 1
        fi
        if [[ ! -f "$NVRAM_BASE" ]]; then
            echo "ERROR: NVRAM baseline missing: $NVRAM_BASE" >&2
            exit 1
        fi
        perm="$(stat -c '%a' "$BASE_IMG")"
        if [[ "$perm" != "444" ]]; then
            echo "ERROR: Base image permissions drifted! Expected 444, got $perm on $BASE_IMG" >&2
            exit 1
        fi
        echo "[*] Verifying 0444 read-only mode on base image and NVRAM..."
        stat -c '%a %n' "$BASE_IMG" "$NVRAM_BASE"
        echo "[*] Computing SHA-256 of $BASE_IMG and $NVRAM_BASE (15+ GiB base image may take ~60-90s)..." >&2
        actual_base_sha="$(sha256sum "$BASE_IMG" | awk '{print tolower($1)}')"
        actual_nvram_sha="$(sha256sum "$NVRAM_BASE" | awk '{print tolower($1)}')"

        if [[ "$actual_base_sha" != "$GOLDEN_BASE_SHA256_LC" ]]; then
            echo "ERROR: Base image SHA-256 mismatch vs pinned GOLDEN_BASE_SHA256! expected=$GOLDEN_BASE_SHA256_LC actual=$actual_base_sha ($BASE_IMG)" >&2
            exit 1
        fi
        if [[ -n "$GOLDEN_NVRAM_SHA256_LC" && "$actual_nvram_sha" != "$GOLDEN_NVRAM_SHA256_LC" ]]; then
            echo "ERROR: NVRAM SHA-256 mismatch vs pinned GOLDEN_NVRAM_SHA256! expected=$GOLDEN_NVRAM_SHA256_LC actual=$actual_nvram_sha ($NVRAM_BASE)" >&2
            exit 1
        fi
        if [[ -z "$GOLDEN_NVRAM_SHA256_LC" ]]; then
            echo "WARNING: Review and pin GOLDEN_NVRAM_SHA256=${actual_nvram_sha} in docs/v2/hardening/04_watchdog_and_base_hash.sh" >&2
        fi

        mkdir -p "$(dirname "$HASH_FILE")" "$(dirname "$FAST_META_FILE")"
        if [[ -f "$HASH_FILE" ]]; then
            _backup_existing_file "$HASH_FILE"
        fi
        if [[ -f "$FAST_META_FILE" ]]; then
            _backup_existing_file "$FAST_META_FILE"
        fi

        tmp_hash="$(mktemp "${HASH_FILE}.tmp.XXXXXX")"
        printf '%s  %s\n%s  %s\n' "$actual_base_sha" "$BASE_IMG" "$actual_nvram_sha" "$NVRAM_BASE" | tee "$tmp_hash"
        chmod 0644 "$tmp_hash"
        mv -f "$tmp_hash" "$HASH_FILE"

        tmp_meta="$(mktemp "${FAST_META_FILE}.tmp.XXXXXX")"
        {
            echo "BASE_IMG=$(printf '%q' "$BASE_IMG")"
            echo "BASE_STAT=$(stat -c '%i:%s:%b:%Y' "$BASE_IMG")"
            echo "NVRAM_BASE=$(printf '%q' "$NVRAM_BASE")"
            echo "NVRAM_SHA256=$actual_nvram_sha"
            if [[ -f "$INETSIM_BASE" ]]; then
                echo "INETSIM_BASE=$(printf '%q' "$INETSIM_BASE")"
                echo "INETSIM_STAT=$(stat -c '%i:%s:%b:%Y' "$INETSIM_BASE")"
            fi
        } > "$tmp_meta"
        chmod 0644 "$tmp_meta"
        mv -f "$tmp_meta" "$FAST_META_FILE"
        echo "[+] Recorded immutable baseline hashes to $HASH_FILE and fast metadata to $FAST_META_FILE"
        ;;
    verify-base)
        _validate_golden_pins
        if [[ ! -f "$HASH_FILE" ]]; then
            echo "ERROR: Hash baseline file missing: $HASH_FILE (run record-base first)" >&2
            exit 1
        fi
        if [[ ! -f "$BASE_IMG" ]]; then
            echo "ERROR: Base image missing: $BASE_IMG" >&2
            exit 1
        fi
        if [[ ! -f "$NVRAM_BASE" ]]; then
            echo "ERROR: NVRAM baseline missing: $NVRAM_BASE" >&2
            exit 1
        fi
        perm="$(stat -c '%a' "$BASE_IMG")"
        if [[ "$perm" != "444" ]]; then
            echo "ERROR: Base image permissions drifted! Expected 444, got $perm on $BASE_IMG" >&2
            exit 1
        fi
        expected_base="$(_hash_file_entry_sha "$BASE_IMG")"
        if [[ -z "$expected_base" || "$expected_base" != "$GOLDEN_BASE_SHA256_LC" ]]; then
            echo "ERROR: HASH_FILE base SHA-256 mismatch vs pinned GOLDEN_BASE_SHA256! expected=$GOLDEN_BASE_SHA256_LC recorded=${expected_base:-missing}" >&2
            exit 1
        fi
        sha256sum -c "$HASH_FILE"
        actual_base_sha="$(sha256sum "$BASE_IMG" | awk '{print tolower($1)}')"
        if [[ "$actual_base_sha" != "$GOLDEN_BASE_SHA256_LC" ]]; then
            echo "ERROR: Base image SHA-256 mismatch vs pinned GOLDEN_BASE_SHA256! expected=$GOLDEN_BASE_SHA256_LC actual=$actual_base_sha ($BASE_IMG)" >&2
            exit 1
        fi
        if [[ -n "$GOLDEN_NVRAM_SHA256_LC" ]]; then
            actual_nvram_sha="$(sha256sum "$NVRAM_BASE" | awk '{print tolower($1)}')"
            if [[ "$actual_nvram_sha" != "$GOLDEN_NVRAM_SHA256_LC" ]]; then
                echo "ERROR: NVRAM SHA-256 mismatch vs pinned GOLDEN_NVRAM_SHA256! expected=$GOLDEN_NVRAM_SHA256_LC actual=$actual_nvram_sha ($NVRAM_BASE)" >&2
                exit 1
            fi
        fi
        echo "[+] Base image & NVRAM full SHA-256 verification PASSED."
        ;;
    verify-base-fast)
        _verify_base_immutability_and_nvram 1
        echo "[+] Base image fast immutability (+i/0444/stat) & NVRAM SHA-256 verification PASSED."
        ;;
    arm-watchdog)
        MAX_SEC="${2:-}"
        LEASE_FILE="${3:-}"
        if [[ -z "$MAX_SEC" || ! "$MAX_SEC" =~ ^[0-9]+$ || -z "$LEASE_FILE" ]]; then
            echo "Usage: $0 arm-watchdog <max_wall_seconds> <lease_file> [domain1 domain2 ...]" >&2
            exit 2
        fi
        shift 3
        if (( $# > 0 )); then
            WATCH_DOMAINS=("$@")
        else
            WATCH_DOMAINS=("$DOMAIN" "$INETSIM_DOMAIN")
        fi
        mkdir -p "$(dirname "$LEASE_FILE")"
        rm -f "${LEASE_FILE}.status" "$LEASE_FILE"
        DEADLINE_EPOCH="$(( $(date +%s) + MAX_SEC ))"
        {
            echo "URI=$URI"
            echo "MAX_SEC=$MAX_SEC"
            echo "DEADLINE_EPOCH=$DEADLINE_EPOCH"
            echo "DOMAINS=${WATCH_DOMAINS[*]}"
        } > "$LEASE_FILE"

        BACKEND="${WATCHDOG_BACKEND:-setsid}"
        if [[ "$BACKEND" == "systemd" ]] && command -v systemd-run >/dev/null 2>&1; then
            UNIT_NAME="dfir-wd-$(date +%s)-$$"
            systemd-run --user --unit="$UNIT_NAME" --collect \
                /usr/bin/env URI="$URI" VIRSH_BIN="$VIRSH_BIN" LEASE_FILE="$LEASE_FILE" \
                DEADLINE_EPOCH="$DEADLINE_EPOCH" WATCH_DOMAINS_STR="${WATCH_DOMAINS[*]}" \
                bash -c '
                    read -r -a VCMD <<< "$VIRSH_BIN"
                    read -r -a DOMS <<< "$WATCH_DOMAINS_STR"
                    while [[ -f "$LEASE_FILE" ]]; do
                        if (( $(date +%s) >= DEADLINE_EPOCH )); then
                            for d in "${DOMS[@]}"; do
                                "${VCMD[@]}" -c "$URI" destroy "$d" >/dev/null 2>&1 || true
                            done
                            echo "TIMEOUT_KILLED" > "${LEASE_FILE}.status"
                            rm -f "$LEASE_FILE"
                            exit 124
                        fi
                        sleep 0.5
                    done
                ' >/dev/null 2>&1
            echo "UNIT_NAME=$UNIT_NAME" >> "$LEASE_FILE"
            echo "[+] Armed systemd user watchdog ($UNIT_NAME) deadline=$DEADLINE_EPOCH domains=${WATCH_DOMAINS[*]}"
        else
            setsid env URI="$URI" VIRSH_BIN="$VIRSH_BIN" LEASE_FILE="$LEASE_FILE" \
                DEADLINE_EPOCH="$DEADLINE_EPOCH" WATCH_DOMAINS_STR="${WATCH_DOMAINS[*]}" \
                bash -c '
                    read -r -a VCMD <<< "$VIRSH_BIN"
                    read -r -a DOMS <<< "$WATCH_DOMAINS_STR"
                    while [[ -f "$LEASE_FILE" ]]; do
                        if (( $(date +%s) >= DEADLINE_EPOCH )); then
                            for d in "${DOMS[@]}"; do
                                "${VCMD[@]}" -c "$URI" destroy "$d" >/dev/null 2>&1 || true
                            done
                            echo "TIMEOUT_KILLED" > "${LEASE_FILE}.status"
                            rm -f "$LEASE_FILE"
                            exit 124
                        fi
                        sleep 0.5
                    done
                ' < /dev/null > "${LEASE_FILE}.log" 2>&1 &
            WD_PID="$!"
            echo "WATCHDOG_PID=$WD_PID" >> "$LEASE_FILE"
            echo "[+] Armed detached setsid watchdog (pid=$WD_PID) deadline=$DEADLINE_EPOCH domains=${WATCH_DOMAINS[*]}"
        fi
        ;;
    disarm-watchdog)
        LEASE_FILE="${2:-}"
        if [[ -z "$LEASE_FILE" ]]; then
            echo "Usage: $0 disarm-watchdog <lease_file>" >&2
            exit 2
        fi
        WD_PID=""
        UNIT_NAME=""
        if [[ -f "$LEASE_FILE" ]]; then
            WD_PID="$(awk -F= '/^WATCHDOG_PID=/{print $2; exit}' "$LEASE_FILE" || true)"
            UNIT_NAME="$(awk -F= '/^UNIT_NAME=/{print $2; exit}' "$LEASE_FILE" || true)"
            rm -f "$LEASE_FILE"
        fi
        if [[ -n "$WD_PID" && "$WD_PID" =~ ^[0-9]+$ ]]; then
            kill "$WD_PID" 2>/dev/null || true
        fi
        if [[ -n "$UNIT_NAME" ]] && command -v systemctl >/dev/null 2>&1; then
            systemctl --user stop "$UNIT_NAME" 2>/dev/null || true
        fi
        echo "[+] Disarmed detached watchdog ($LEASE_FILE)."
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
            state="$("${VIRSH_CMD[@]}" -c "$URI" domstate "$DOMAIN" 2>/dev/null | tr '[:upper:]' '[:lower:]' | xargs || true)"
            if [[ -z "$state" || "$state" == "shut off" ]]; then
                echo "[+] Domain $DOMAIN is shut off; watchdog exiting cleanly."
                exit 0
            fi
            now_ts=$(date +%s)
            elapsed=$((now_ts - start_ts))
            if (( elapsed >= MAX_SEC )); then
                echo "[!] WATCHDOG TIMEOUT (${elapsed}s >= ${MAX_SEC}s): forcing virsh destroy $DOMAIN & $INETSIM_DOMAIN" >&2
                "${VIRSH_CMD[@]}" -c "$URI" destroy "$DOMAIN" || true
                "${VIRSH_CMD[@]}" -c "$URI" destroy "$INETSIM_DOMAIN" 2>/dev/null || true
                exit 124
            fi
            sleep 2
        done
        ;;
    check-egress)
        sub="${2:-snapshot}"
        case "$sub" in
            snapshot)
                _egress_snapshot_json
                ;;
            verify)
                before_f="${3:-}"
                after_f="${4:-}"
                if [[ ! -f "$before_f" || ! -f "$after_f" ]]; then
                    echo "Usage: $0 check-egress verify <before_json> <after_json>" >&2
                    exit 2
                fi
                b_ok="$(_json_bool_field "$before_f" "firewall_rules_valid")"
                a_ok="$(_json_bool_field "$after_f" "firewall_rules_valid")"
                if [[ "$b_ok" != "true" || "$a_ok" != "true" ]]; then
                    echo "ERROR: virbr1 firewall rules invalid (before=$b_ok after=$a_ok)" >&2
                    exit 1
                fi
                b_fp="$(_json_int_field "$before_f" "fwd_drop_pkts")"
                a_fp="$(_json_int_field "$after_f" "fwd_drop_pkts")"
                b_fb="$(_json_int_field "$before_f" "fwd_drop_bytes")"
                a_fb="$(_json_int_field "$after_f" "fwd_drop_bytes")"
                b_ip="$(_json_int_field "$before_f" "in_drop_pkts")"
                a_ip="$(_json_int_field "$after_f" "in_drop_pkts")"
                dfp=$(( ${a_fp:-0} - ${b_fp:-0} ))
                dfb=$(( ${a_fb:-0} - ${b_fb:-0} ))
                dip=$(( ${a_ip:-0} - ${b_ip:-0} ))
                if (( dfp > 0 || dfb > 0 )); then
                    echo "ERROR: Cross-interface FORWARD packet/byte egress attempt detected on $BRIDGE (pkts_delta=$dfp bytes_delta=$dfb)" >&2
                    exit 1
                fi
                if (( dip > MAX_IN_DROP_BURST )); then
                    echo "ERROR: Anomalous V2_VIRBR1_IN drop burst detected (in_drop_pkts_delta=$dip > $MAX_IN_DROP_BURST)" >&2
                    exit 1
                fi
                echo "{\"egress_passed\":true,\"fwd_drop_pkts_delta\":$dfp,\"fwd_drop_bytes_delta\":$dfb,\"in_drop_pkts_delta\":$dip}"
                ;;
            *)
                echo "Usage: $0 check-egress {snapshot|verify <before_json> <after_json>}" >&2
                exit 2
                ;;
        esac
        ;;
    *)
        cat <<'EOF'
Usage:
  04_watchdog_and_base_hash.sh record-base [base_qcow2]
  04_watchdog_and_base_hash.sh verify-base
  04_watchdog_and_base_hash.sh verify-base-fast
  04_watchdog_and_base_hash.sh arm-watchdog <max_wall_seconds> <lease_file> [domains...]
  04_watchdog_and_base_hash.sh disarm-watchdog <lease_file>
  04_watchdog_and_base_hash.sh watchdog <max_wall_seconds>
  04_watchdog_and_base_hash.sh check-egress {snapshot|verify <before_json> <after_json>}
EOF
        exit 2
        ;;
esac
