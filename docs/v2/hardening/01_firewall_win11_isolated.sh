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
LOG_PREFIX6="[V2-VIRBR1-DROP6] "

usage() {
    cat <<'EOF'
Usage: sudo ./01_firewall_win11_isolated.sh [--apply | --status | --nft-print]
  --apply      Replace permissive v1 ACCEPT rules on virbr1 with default-DROP IPv4+IPv6 detonation policy.
  --status     Show active iptables and ip6tables rules mentioning virbr1.
  --nft-print  Print equivalent standalone nftables policy (do not apply).
EOF
}

MODE="${1:---apply}"
case "$MODE" in
    --status)
        echo "=== iptables -S INPUT (head) / FORWARD (head) & virbr1|V2_VIRBR1 ==="
        iptables -S INPUT 2>/dev/null | head -n 10 || true
        iptables -S FORWARD 2>/dev/null | head -n 10 || true
        iptables -S | grep -E "virbr1|V2_VIRBR1" || true
        for uch in ufw-user-input ufw-user-output ufw-user-forward; do
            iptables -S "$uch" 2>/dev/null | grep -E "virbr1" || true
        done
        echo "=== ip6tables -S INPUT (head) / FORWARD (head) & virbr1|V2_VIRBR1 ==="
        ip6tables -S INPUT 2>/dev/null | head -n 10 || true
        ip6tables -S FORWARD 2>/dev/null | head -n 10 || true
        ip6tables -S 2>/dev/null | grep -E "virbr1|V2_VIRBR1" || true
        for uch6 in ufw6-user-input ufw6-user-output ufw6-user-forward; do
            ip6tables -S "$uch6" 2>/dev/null | grep -E "virbr1" || true
        done
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

if [[ "${EUID:-$(id -u)}" -ne 0 && "${SKIP_ROOT_CHECK:-0}" != "1" ]]; then
    echo "ERROR: Run with sudo as operator when applying iptables/ip6tables changes." >&2
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

echo "[*] Removing UFW ufw-user-* ACCEPT rules referencing $BRIDGE if present..."
for uch in ufw-user-input ufw-user-output ufw-user-forward; do
    if iptables -L "$uch" -n >/dev/null 2>&1; then
        for dir_flag in "-i" "-o"; do
            while iptables -C "$uch" "$dir_flag" "$BRIDGE" -j ACCEPT 2>/dev/null; do
                iptables -D "$uch" "$dir_flag" "$BRIDGE" -j ACCEPT
            done
        done
        while read -r rule_spec; do
            [[ -z "$rule_spec" ]] && continue
            # shellcheck disable=SC2086
            iptables -D $rule_spec 2>/dev/null || true
        done < <(
            iptables -S "$uch" 2>/dev/null \
                | grep -E "(^|[[:space:]])(-i|-o)[[:space:]]+${BRIDGE}([[:space:]]|$)" \
                | grep -E -- "-j[[:space:]]+ACCEPT([[:space:]]|$)" \
                | sed 's/^-A //' \
                || true
        )
    fi
done

echo "[*] Flushing any previous V2_VIRBR1_IN / V2_VIRBR1_FWD chains..."
for ch in V2_VIRBR1_IN V2_VIRBR1_FWD; do
    while iptables -C INPUT -i "$BRIDGE" -j "$ch" 2>/dev/null; do
        iptables -D INPUT -i "$BRIDGE" -j "$ch"
    done
    while iptables -C FORWARD -i "$BRIDGE" -j "$ch" 2>/dev/null; do
        iptables -D FORWARD -i "$BRIDGE" -j "$ch"
    done
    while iptables -C FORWARD -o "$BRIDGE" -j "$ch" 2>/dev/null; do
        iptables -D FORWARD -o "$BRIDGE" -j "$ch"
    done
    if iptables -L "$ch" -n >/dev/null 2>&1; then
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

echo "[+] Applied strict IPv4 default-DROP policy on $BRIDGE."
iptables -L V2_VIRBR1_IN -v -n
iptables -L V2_VIRBR1_FWD -v -n

if ! command -v ip6tables >/dev/null 2>&1; then
    echo "ERROR: ip6tables binary not found; refusing partial IPv4-only firewall state." >&2
    exit 1
fi

echo "[*] Removing legacy IPv6 virbr1 ACCEPT rules if present..."
for pair6 in \
    "INPUT -i $BRIDGE -j ACCEPT" \
    "FORWARD -i $BRIDGE -j ACCEPT" \
    "FORWARD -o $BRIDGE -j ACCEPT" \
    "INPUT -i $BRIDGE -m state --state RELATED,ESTABLISHED -j ACCEPT"; do
    # shellcheck disable=SC2086
    while ip6tables -C $pair6 2>/dev/null; do
        # shellcheck disable=SC2086
        ip6tables -D $pair6
    done
done

echo "[*] Removing UFW ufw6-user-* ACCEPT rules referencing $BRIDGE if present..."
for uch6 in ufw6-user-input ufw6-user-output ufw6-user-forward; do
    if ip6tables -L "$uch6" -n >/dev/null 2>&1; then
        for dir_flag in "-i" "-o"; do
            while ip6tables -C "$uch6" "$dir_flag" "$BRIDGE" -j ACCEPT 2>/dev/null; do
                ip6tables -D "$uch6" "$dir_flag" "$BRIDGE" -j ACCEPT
            done
        done
        while read -r rule_spec6; do
            [[ -z "$rule_spec6" ]] && continue
            # shellcheck disable=SC2086
            ip6tables -D $rule_spec6 2>/dev/null || true
        done < <(
            ip6tables -S "$uch6" 2>/dev/null \
                | grep -E "(^|[[:space:]])(-i|-o)[[:space:]]+${BRIDGE}([[:space:]]|$)" \
                | grep -E -- "-j[[:space:]]+ACCEPT([[:space:]]|$)" \
                | sed 's/^-A //' \
                || true
        )
    fi
done

echo "[*] Flushing any previous V2_VIRBR1_IN6 / V2_VIRBR1_FWD6 chains..."
for ch6 in V2_VIRBR1_IN6 V2_VIRBR1_FWD6; do
    while ip6tables -C INPUT -i "$BRIDGE" -j "$ch6" 2>/dev/null; do
        ip6tables -D INPUT -i "$BRIDGE" -j "$ch6"
    done
    while ip6tables -C FORWARD -i "$BRIDGE" -j "$ch6" 2>/dev/null; do
        ip6tables -D FORWARD -i "$BRIDGE" -j "$ch6"
    done
    while ip6tables -C FORWARD -o "$BRIDGE" -j "$ch6" 2>/dev/null; do
        ip6tables -D FORWARD -o "$BRIDGE" -j "$ch6"
    done
    if ip6tables -L "$ch6" -n >/dev/null 2>&1; then
        ip6tables -F "$ch6"
        ip6tables -X "$ch6"
    fi
done

echo "[*] Creating strict IPv6 default-DROP chains for $BRIDGE..."
ip6tables -N V2_VIRBR1_IN6
ip6tables -N V2_VIRBR1_FWD6

# IPv6 INPUT chain: Host stays inaccessible from win11 / inetsim guests
ip6tables -A V2_VIRBR1_IN6 -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
ip6tables -A V2_VIRBR1_IN6 -m limit --limit 10/sec --limit-burst 20 -j LOG --log-prefix "$LOG_PREFIX6" --log-level 4
ip6tables -A V2_VIRBR1_IN6 -j DROP

# IPv6 FORWARD chain: Zero cross-interface IPv6 egress/ingress; intra-bridge L2 only
ip6tables -A V2_VIRBR1_FWD6 -i "$BRIDGE" -o "$BRIDGE" -j ACCEPT
ip6tables -A V2_VIRBR1_FWD6 -m limit --limit 10/sec --limit-burst 20 -j LOG --log-prefix "$LOG_PREFIX6" --log-level 4
ip6tables -A V2_VIRBR1_FWD6 -j DROP

ip6tables -I INPUT 1 -i "$BRIDGE" -j V2_VIRBR1_IN6
ip6tables -I FORWARD 1 -i "$BRIDGE" -j V2_VIRBR1_FWD6
ip6tables -I FORWARD 2 -o "$BRIDGE" -j V2_VIRBR1_FWD6

echo "[+] Applied strict IPv4+IPv6 default-DROP policy on $BRIDGE."
echo "[*] Persist via systemd unit: sudo cp docs/v2/hardening/v2-virbr1-firewall.service /etc/systemd/system/ && sudo systemctl daemon-reload && sudo systemctl enable --now v2-virbr1-firewall.service"
ip6tables -L V2_VIRBR1_IN6 -v -n
ip6tables -L V2_VIRBR1_FWD6 -v -n
