#!/usr/bin/env bash
# Encrypted non-executable quarantine vault setup & SHA-256 preflight check (OD-V2-07).
# HARD GATE: Refuses any operation unless a valid 0400 Gate 0 marker with required metadata exists.
set -euo pipefail

VAULT_ROOT="${VAULT_ROOT:-$HOME/.quarantine_vault_dfir_v2}"
GATE0_MARKER="$VAULT_ROOT/GATE0_SIGNED_OFF"
MANIFEST="$VAULT_ROOT/sample_manifest.sha256"

REQUIRED_GATE0_KEYS=(
    "SIGNED_BY"
    "DATE"
    "SUPERVISOR_APPROVAL"
    "CONTAINMENT_CHECKS"
    "DEDICATED_USER_VERIFIED"
)

_is_placeholder_or_falsy() {
    local val_lc
    val_lc="$(printf '%s' "$1" | tr '[:upper:]' '[:lower:]' | sed 's/^[[:space:]"\x27]*//; s/[[:space:]"\x27]*$//')"
    if [[ -z "$val_lc" ]]; then
        return 0
    fi
    if [[ "$val_lc" =~ ^[_-]+$ ]]; then
        return 0
    fi
    case "$val_lc" in
        tbd|todo|pending|none|null|false|no|0|fail|failed|unverified|na|n/a|unset|unknown)
            return 0
            ;;
    esac
    return 1
}

validate_gate0_marker() {
    if [[ ! -f "$GATE0_MARKER" ]]; then
        echo "BLOCKED: Gate 0 marker missing ($GATE0_MARKER). Do NOT acquire or inject malware (OD-V2-07)." >&2
        exit 1
    fi
    if [[ ! -s "$GATE0_MARKER" ]]; then
        echo "BLOCKED: Gate 0 marker is empty ($GATE0_MARKER). Valid signed metadata required (OD-V2-07)." >&2
        exit 1
    fi
    local gmode
    gmode="$(stat -c '%a' "$GATE0_MARKER")"
    if [[ "$gmode" != "400" ]]; then
        echo "BLOCKED: Gate 0 marker must have mode 0400, got $gmode on $GATE0_MARKER" >&2
        exit 1
    fi

    local key line raw_val trimmed_val
    for key in "${REQUIRED_GATE0_KEYS[@]}"; do
        line="$(grep -E "^[[:space:]]*${key}=" "$GATE0_MARKER" | tail -n 1 || true)"
        if [[ -z "$line" ]]; then
            echo "BLOCKED: Gate 0 marker ($GATE0_MARKER) missing required key '${key}='." >&2
            exit 1
        fi
        raw_val="${line#*=}"
        trimmed_val="$(printf '%s' "$raw_val" | sed 's/^[[:space:]"\x27]*//; s/[[:space:]"\x27]*$//')"
        if _is_placeholder_or_falsy "$trimmed_val"; then
            echo "BLOCKED: Gate 0 marker key '${key}' has empty/placeholder/falsy value: '${trimmed_val}'." >&2
            exit 1
        fi
    done

    local ded_val
    ded_val="$(grep -E "^[[:space:]]*DEDICATED_USER_VERIFIED=" "$GATE0_MARKER" | tail -n 1 | cut -d'=' -f2- | tr '[:upper:]' '[:lower:]' | sed 's/^[[:space:]"\x27]*//; s/[[:space:]"\x27]*$//')"
    if [[ "$ded_val" =~ ^(false|no|0|fail|failed|unverified|not_verified) ]]; then
        echo "BLOCKED: DEDICATED_USER_VERIFIED must be affirmative in $GATE0_MARKER (got '$ded_val')." >&2
        exit 1
    fi
}

cmd="${1:-init}"

case "$cmd" in
    init)
        install -d -m 0700 "$VAULT_ROOT"
        install -d -m 0700 "$VAULT_ROOT/archives" "$VAULT_ROOT/staging"
        echo "[+] Initialized vault directory at $VAULT_ROOT (mode 0700)."
        echo "[!] REMINDER: OD-V2-07 written supervisor approval & Gate 0 sign-off are REQUIRED before storing any samples."
        echo "    When approved and signed off, write these required fields to $GATE0_MARKER and run chmod 0400:"
        echo "      SIGNED_BY=Mokh"
        echo "      DATE=2026-11-25"
        echo "      SUPERVISOR_APPROVAL=Supervisor Marawan (AASTMT) 2026-11-25"
        echo "      CONTAINMENT_CHECKS=NEG-01..NEG-10 PASS"
        echo "      DEDICATED_USER_VERIFIED=true (fsociety)"
        ;;
    preflight)
        validate_gate0_marker
        mode="$(stat -c '%a' "$VAULT_ROOT")"
        if [[ "$mode" != "700" ]]; then
            echo "ERROR: Vault directory permissions must be 0700, got $mode" >&2
            exit 1
        fi
        if [[ ! -d "$VAULT_ROOT/archives" ]]; then
            echo "ERROR: Archives directory missing: $VAULT_ROOT/archives" >&2
            exit 1
        fi

        archive_names=()
        while IFS= read -r -d '' f; do
            fmode="$(stat -c '%a' "$f")"
            if [[ "$fmode" != "400" ]]; then
                echo "ERROR: Archive $f has mode $fmode (expected 0400)" >&2
                exit 1
            fi
            archive_names+=("$(basename "$f")")
        done < <(find "$VAULT_ROOT/archives" -maxdepth 1 -type f -print0)

        if (( ${#archive_names[@]} > 0 )); then
            if [[ ! -f "$MANIFEST" || ! -s "$MANIFEST" ]]; then
                echo "ERROR: Vault archives/ is non-empty (${#archive_names[@]} files) but $MANIFEST is missing or empty!" >&2
                exit 1
            fi
            (cd "$VAULT_ROOT/archives" && sha256sum -c "$MANIFEST")

            manifest_names="$(awk '{fn=$2; sub(/^\*/, "", fn); sub(/^\.\//, "", fn); print fn}' "$MANIFEST")"
            for aname in "${archive_names[@]}"; do
                if ! printf '%s\n' "$manifest_names" | grep -Fxq "$aname"; then
                    echo "ERROR: Archive '$aname' in $VAULT_ROOT/archives is NOT listed in $MANIFEST!" >&2
                    exit 1
                fi
            done
        elif [[ -s "$MANIFEST" ]]; then
            (cd "$VAULT_ROOT/archives" && sha256sum -c "$MANIFEST")
        fi

        echo "[+] Quarantine vault preflight check PASSED (archives=${#archive_names[@]})."
        ;;
    seal-archive)
        ARCHIVE_PATH="${2:-}"
        if [[ -z "$ARCHIVE_PATH" || ! -f "$ARCHIVE_PATH" ]]; then
            echo "Usage: $0 seal-archive <encrypted_archive_path>" >&2
            exit 2
        fi
        validate_gate0_marker
        chmod 0400 "$ARCHIVE_PATH"
        (cd "$(dirname "$ARCHIVE_PATH")" && sha256sum "$(basename "$ARCHIVE_PATH")" >> "$MANIFEST")
        echo "[+] Sealed $ARCHIVE_PATH at mode 0400 and appended SHA-256 to $MANIFEST."
        ;;
    *)
        echo "Usage: $0 {init|preflight|seal-archive <path>}" >&2
        exit 2
        ;;
esac
