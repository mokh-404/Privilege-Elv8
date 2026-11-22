#!/usr/bin/env bash
# Harden virbr1 (win11-isolated) with default-DROP firewall rules before Phase 2/Gate 0.
# OPERATOR ACTION ONLY: Inspect carefully and run as Mokh (sudo required for iptables/nftables).
# Do NOT run on a live malware batch without running 08_NEGATIVE_EGRESS_AND_SIGN_OFF.md first.
set -euo pipefail

BRIDGE="${BRIDGE:-virbr1}"
SUBNET="${SUBNET:-192.168.150.0/24}"
HOST_IP="${HOST_IP:-192.168.150.1}"
GUEST_IP="${GUEST_IP:-192.168.150.50}"
INETSIM_IP="${INETSIM_IP:-192.168.150.10}"
ALLOW_DHCP_LEASE="${ALLOW_DHCP_LEASE:-0}" # Set to 1 ONLY if using libvirt DHCP before static IP config; 0 during malware detonation
LOG_PREFIX="[V2-VIRBR1-DROP] "

usage() {
    cat <<'EOF'
Usage: sudo ./01_firewall_win11_isolated.sh [--apply | --status | --nft-print]
  --apply      Replace permissive v1 ACCEPT rules on virbr1 with default-DROP detonation policy.
  --status     Show active iptables rules mentioning virbr1.
  --nft-print  Print equivalent standalone nftables policy (do not apply).
EOF
}

MODE="${1:---apply}"
case "$MODE" in
    --status)
        echo "=== iptables -S | grep -E 'virbr1|V2-VIRBR1' ==="
        iptables -S | grep -E "virbr1|V2-VIRBR1" || true
        exit 0
        ;;
    --nft-print)
        cat <<EOF
# Equivalent nftables table (save to /etc/nftables.d/win11_isolated.nft if using nftables directly)
table inet v2_win11_isolated {
    chain input {
        type filter hook input priority -10; policy accept;
        iifname "$BRIDGE" ct state established,related accept
        # Uncomment ONLY if DHCP needed during prep (disable during detonation):
        # iifname "$BRIDGE" udp sport 68 udp dport 67 accept
        iifname "$BRIDGE" limit rate 10/second log prefix "$LOG_PREFIX" drop
        iifname "$BRIDGE" drop
    }
    chain forward {
        type filter hook forward priority -10; policy accept;
        # Allow guest <-> inetsim-vm traffic isolated strictly inside $BRIDGE if routed via bridge netfilter,
        # block ALL cross-interface forwarding into or out of $BRIDGE:
        iifname "$BRIDGE" oifname != "$BRIDGE" limit rate 10/second log prefix "$LOG_PREFIX" drop
        iifname "$BRIDGE" oifname != "$BRIDGE" drop
        oifname "$BRIDGE" iifname != "$BRIDGE" drop
    }
}
EOF
        exit 0
        ;;
    --apply)
        ;;
    *)
        usage
        exit 2
        ;;
esac

if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
    echo "ERROR: Run with sudo as operator when applying iptables changes." >&2
    exit 1
fi

echo "[*] Removing legacy permissive v1 virbr1 ACCEPT rules if present..."
for pair in \
    "INPUT -i $BRIDGE -j ACCEPT" \
    "FORWARD -i $BRIDGE -j ACCEPT" \
    "FORWARD -o $BRIDGE -j ACCEPT" \
    "INPUT -i $BRIDGE -m state --state RELATED,ESTABLISHED -j ACCEPT"; do
    # shellcheck disable=SC2086
    while iptables -C $pair 2>/dev/null; do
        # shellcheck disable=SC2086
        iptables -D $pair
    done
done

echo "[*] Flushing any previous V2_VIRBR1_IN / V2_VIRBR1_FWD chains..."
for ch in V2_VIRBR1_IN V2_VIRBR1_FWD; do
    if iptables -L "$ch" -n >/dev/null 2>&1; then
        iptables -D INPUT -i "$BRIDGE" -j "$ch" 2>/dev/null || true
        iptables -D FORWARD -i "$BRIDGE" -j "$ch" 2>/dev/null || true
        iptables -D FORWARD -o "$BRIDGE" -j "$ch" 2>/dev/null || true
        iptables -F "$ch"
        iptables -X "$ch"
    fi
done

echo "[*] Creating strict default-DROP chains for $BRIDGE..."
iptables -N V2_VIRBR1_IN
iptables -N V2_VIRBR1_FWD

# INPUT chain: Host stays inaccessible from win11 / inetsim guests
iptables -A V2_VIRBR1_IN -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
if [[ "$ALLOW_DHCP_LEASE" == "1" ]]; then
    # Prep-only DHCP lease exception (MUST stay disabled when ALLOW_DHCP_LEASE=0 during detonation)
    iptables -A V2_VIRBR1_IN -p udp --dport 67 --sport 68 -j ACCEPT
fi
# Explicitly block host gateway management, DNS, SSH, SMB, and all other host ports from virbr1
iptables -A V2_VIRBR1_IN -m limit --limit 10/sec --limit-burst 20 -j LOG --log-prefix "$LOG_PREFIX" --log-level 4
iptables -A V2_VIRBR1_IN -j DROP

# FORWARD chain: Zero cross-interface egress/ingress across host interfaces; only intra-bridge L2 allowed
iptables -A V2_VIRBR1_FWD -i "$BRIDGE" -o "$BRIDGE" -j ACCEPT
iptables -A V2_VIRBR1_FWD -m limit --limit 10/sec --limit-burst 20 -j LOG --log-prefix "$LOG_PREFIX" --log-level 4
iptables -A V2_VIRBR1_FWD -j DROP

iptables -I INPUT 1 -i "$BRIDGE" -j V2_VIRBR1_IN
iptables -I FORWARD 1 -i "$BRIDGE" -j V2_VIRBR1_FWD
iptables -I FORWARD 2 -o "$BRIDGE" -j V2_VIRBR1_FWD

echo "[+] Applied strict default-DROP policy on $BRIDGE."
echo "[*] Note: On Arch Linux, save with: sudo iptables-save > /etc/iptables/iptables.rules && sudo systemctl enable --now iptables.service"
iptables -L V2_VIRBR1_IN -v -n
iptables -L V2_VIRBR1_FWD -v -n
