#!/usr/bin/env bash
# Encrypted non-executable quarantine vault setup & SHA-256 preflight check (OD-V2-07).
# HARD GATE: Refuses any operation unless written approval + Gate 0 marker exist.
set -euo pipefail

VAULT_ROOT="${VAULT_ROOT:-$HOME/.quarantine_vault_dfir_v2}"
GATE0_MARKER="$VAULT_ROOT/GATE0_SIGNED_OFF"
MANIFEST="$VAULT_ROOT/sample_manifest.sha256"

cmd="${1:-init}"

case "$cmd" in
    init)
        install -d -m 0700 "$VAULT_ROOT"
        install -d -m 0700 "$VAULT_ROOT/archives" "$VAULT_ROOT/staging"
        echo "[+] Initialized vault directory at $VAULT_ROOT (mode 0700)."
        echo "[!] REMINDER: OD-V2-07 written institutional approval & Gate 0 sign-off are REQUIRED before storing any samples."
        echo "    When approved and signed off, record approval details into: $GATE0_MARKER"
        ;;
    preflight)
        if [[ ! -f "$GATE0_MARKER" ]]; then
            echo "BLOCKED: Gate 0 marker missing ($GATE0_MARKER). Do NOT acquire or inject malware (OD-V2-07)." >&2
            exit 1
        fi
        mode="$(stat -c '%a' "$VAULT_ROOT")"
        if [[ "$mode" != "700" ]]; then
            echo "ERROR: Vault directory permissions must be 0700, got $mode" >&2
            exit 1
        fi
        # Ensure all encrypted archives in archives/ are mode 0400 (non-executable, read-only)
        while IFS= read -r -d '' f; do
            fmode="$(stat -c '%a' "$f")"
            if [[ "$fmode" != "400" ]]; then
                echo "ERROR: Archive $f has mode $fmode (expected 0400)" >&2
                exit 1
            fi
        done < <(find "$VAULT_ROOT/archives" -maxdepth 1 -type f -print0)
        if [[ -f "$MANIFEST" ]]; then
            (cd "$VAULT_ROOT/archives" && sha256sum -c "$MANIFEST")
        else
            echo "WARN: No $MANIFEST yet."
        fi
        echo "[+] Quarantine vault preflight check PASSED."
        ;;
    seal-archive)
        ARCHIVE_PATH="${2:-}"
        if [[ -z "$ARCHIVE_PATH" || ! -f "$ARCHIVE_PATH" ]]; then
            echo "Usage: $0 seal-archive <encrypted_archive_path>" >&2
            exit 2
        fi
        if [[ ! -f "$GATE0_MARKER" ]]; then
            echo "BLOCKED: Gate 0 marker missing ($GATE0_MARKER)." >&2
            exit 1
        fi
        chmod 0400 "$ARCHIVE_PATH"
        (cd "$(dirname "$ARCHIVE_PATH")" && sha256sum "$(basename "$ARCHIVE_PATH")" >> "$MANIFEST")
        echo "[+] Sealed $ARCHIVE_PATH at mode 0400 and appended SHA-256 to $MANIFEST."
        ;;
    *)
        echo "Usage: $0 {init|preflight|seal-archive <path>}" >&2
        exit 2
        ;;
esac
