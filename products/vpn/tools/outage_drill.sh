#!/usr/bin/env bash
# Outage drill for Acxelin VPN's outage grace: partitions or slows the key agreement port (default 7443) between two real Linux
# machines and prints a timestamped timeline of the tunnel. Run as root on the gateway VM and on the client VM; see
# docs/outage-drill.md. NOT RUN by its authors: it needs two machines. Checked only with `bash -n`.
set -euo pipefail

CMD="${1:-}"
[ $# -gt 0 ] && shift
PORT=7443 STEP=5 ROLE="" IFACE="" PEER_IP="" WGIF="" TARGET="" MINUTES="" BASELINE=1 AFTER=5 DELAY_MS="" LOSS=0
REVOKE_SERIAL="" REVOKE_AT="" CA_DIR="" RESTART_CMD="" STATUS_URL="http://127.0.0.1:9101/status" YES=0
VPN="${ACXELIN_VPN:-acxelin-vpn}"
UNDO=()

usage() {
    cat <<'EOF'
usage: outage_drill.sh COMMAND [options]      (as root; nothing is changed until you answer yes)

  watch    only print the timeline (changes nothing)
  block    drop TCP port PORT between this machine and --peer-ip, both directions, for --minutes
  slow     delay (and optionally lose) packets of that port towards --peer-ip, for --minutes
  restart  run --restart-cmd, then print the timeline for --after-min

options
  --role gateway|client      which timeline to print                            (required)
  --wg-interface NAME        the WireGuard interface, such as wg0               (required)
  --target IP                client role: a tunnel address to ping, such as the gateway's 10.99.0.1
  --status-url URL           gateway role: its /status (default http://127.0.0.1:9101/status)
  --interface NIC            block, slow: the network card that carries the key agreement traffic, such as eth0
  --peer-ip IP               block, slow: the other machine's real address
  --port N                   key agreement port (default 7443)
  --minutes N                block, slow: how long the outage lasts
  --delay-ms N --loss PCT    slow: added delay and packet loss on that port
  --baseline-min N           minutes of timeline before the outage (default 1)
  --after-min N              minutes of timeline after it ends (default 5)
  --revoke-serial HEX --ca-dir DIR --revoke-at-min N
                             block, gateway only: revoke that certificate N minutes into the outage with `acxelin-vpn ca revoke`
                             (needs ACXELIN_VPN_CA_PASSPHRASE if the CA key is encrypted)
  --restart-cmd 'CMD'        restart: the command that restarts the gateway, e.g. 'systemctl restart acxelin-vpn-wireguard'
  --step N                   seconds between timeline lines (default 5)
  --yes                      do not ask for confirmation
EOF
}

die() { echo "error: $*" >&2; exit 2; }
now() { date -u +%H:%M:%S; }
say() { echo "$(now) $*"; }

while [ $# -gt 0 ]; do
    case "$1" in
        --role) ROLE="$2" ;; --wg-interface) WGIF="$2" ;; --target) TARGET="$2" ;; --status-url) STATUS_URL="$2" ;;
        --interface) IFACE="$2" ;; --peer-ip) PEER_IP="$2" ;; --port) PORT="$2" ;; --minutes) MINUTES="$2" ;;
        --delay-ms) DELAY_MS="$2" ;; --loss) LOSS="$2" ;; --baseline-min) BASELINE="$2" ;; --after-min) AFTER="$2" ;;
        --revoke-serial) REVOKE_SERIAL="$2" ;; --ca-dir) CA_DIR="$2" ;; --revoke-at-min) REVOKE_AT="$2" ;;
        --restart-cmd) RESTART_CMD="$2" ;; --step) STEP="$2" ;;
        --yes) YES=1; shift; continue ;;
        -h|--help) usage; exit 0 ;;
        *) usage >&2; die "unknown option $1" ;;
    esac
    [ $# -ge 2 ] || die "$1 needs a value"
    shift 2
done

number() { [[ "$2" =~ ^[0-9]+([.][0-9]+)?$ ]] || die "$1 must be a number, not '$2'"; }
[ "$(id -u)" = 0 ] || die "run as root"
[ -n "$CMD" ] || { usage >&2; exit 2; }
case "$ROLE" in gateway|client) ;; *) die "--role gateway or client is required" ;; esac
[ -n "$WGIF" ] || die "--wg-interface is required"
[ "$ROLE" = client ] && [ -z "$TARGET" ] && die "--target is required for --role client"
for n in "$PORT:--port" "$STEP:--step" "$BASELINE:--baseline-min" "$AFTER:--after-min" "$LOSS:--loss"; do number "${n#*:}" "${n%%:*}"; done

timeline_line() {
    if [ "$ROLE" = client ]; then
        local hs age ping st
        hs=$(wg show "$WGIF" latest-handshakes 2>/dev/null | awk 'NR==1{print $2}' || true)
        if [ -z "${hs:-}" ] || [ "$hs" = 0 ]; then age="none"; else age="$(($(date +%s) - hs))s"; fi
        if ping -c1 -W2 "$TARGET" >/dev/null 2>&1; then ping=up; else ping=DOWN; fi
        st=$("$VPN" status --interface "$WGIF" 2>&1 | head -1 || true)
        echo "$(now) client  wg-handshake-age=$age  ping-through-tunnel=$ping  status: ${st:-none}"
    else
        local peers body
        peers=$(wg show "$WGIF" latest-handshakes 2>/dev/null | awk -v n="$(date +%s)" '{a=($2==0)?"none":(n-$2)"s"; printf "%s..=%s ", substr($1,1,6), a}' || true)
        body=$(curl -fsS --max-time 3 "$STATUS_URL" 2>/dev/null | python3 -c '
import json, sys
d = json.load(sys.stdin)
print(" ".join("%s[keys=%ss %s]" % (k, v.get("keys_age_s"), "IN GRACE %ss left" % v["grace_remaining_s"] if v.get("in_grace") else "no grace")
               for k, v in d.items() if not k.startswith("_")) or "no peers")' 2>/dev/null || echo "status unreachable")
        echo "$(now) gateway wg-handshake-age: ${peers:-none}  |  $body"
    fi
}

watch_for() { # seconds
    local end=$((SECONDS + $1))
    while [ "$SECONDS" -lt "$end" ]; do timeline_line; sleep "$STEP"; done
}

cleanup() {
    trap - EXIT INT TERM
    local i
    for ((i = ${#UNDO[@]} - 1; i >= 0; i--)); do
        # shellcheck disable=SC2086
        ${UNDO[$i]} 2>/dev/null || true
    done
    [ ${#UNDO[@]} -eq 0 ] || say "removed every rule this script added"
}
trap cleanup EXIT
trap 'cleanup; exit 130' INT TERM

confirm() {
    echo "This will change this machine:"
    printf '  %s\n' "$@"
    echo "Every change is removed when the script ends or is interrupted (Ctrl-C)."
    [ "$YES" = 1 ] && return
    read -r -p "Type yes to continue: " answer
    [ "$answer" = yes ] || die "not confirmed; nothing changed"
}

need_net() {
    [ -n "$IFACE" ] || die "--interface is required"
    [ -n "$PEER_IP" ] || die "--peer-ip is required"
    [ -n "$MINUTES" ] || die "--minutes is required"
    number --minutes "$MINUTES"
    [[ "$PEER_IP" =~ ^[0-9.]+$ ]] || die "--peer-ip must be an IPv4 address"
    ip link show "$IFACE" >/dev/null 2>&1 || die "no network interface $IFACE"
    ip -4 route get "$PEER_IP" 2>/dev/null | grep -q "dev $IFACE" || die "$PEER_IP is not reached through $IFACE here"
    [ "$PEER_IP" != 127.0.0.1 ] || die "--peer-ip must be the other machine's address"
}

phase() { # name seconds
    say "=== $1 ==="
    watch_for "$2"
}

case "$CMD" in
    watch)
        say "timeline for the $ROLE (Ctrl-C to stop)"
        while true; do timeline_line; sleep "$STEP"; done
        ;;
    block)
        need_net
        command -v iptables >/dev/null || die "iptables is required"
        confirm "iptables: DROP TCP port $PORT to and from $PEER_IP on $IFACE (4 rules, tagged acxelin-drill), for $MINUTES minutes" \
                "nothing else: WireGuard's UDP data traffic is not touched"
        phase "baseline: the tunnel as it is" "$(awk "BEGIN{print int($BASELINE*60)}")"
        for rule in "INPUT -i $IFACE -s $PEER_IP -p tcp --dport $PORT" "INPUT -i $IFACE -s $PEER_IP -p tcp --sport $PORT" \
                    "OUTPUT -o $IFACE -d $PEER_IP -p tcp --dport $PORT" "OUTPUT -o $IFACE -d $PEER_IP -p tcp --sport $PORT"; do
            # shellcheck disable=SC2086
            iptables -w -I $rule -m comment --comment acxelin-drill -j DROP
            # shellcheck disable=SC2086
            UNDO+=("iptables -w -D $rule -m comment --comment acxelin-drill -j DROP")
        done
        say "=== KEY AGREEMENT PARTITIONED (port $PORT dropped both ways) for $MINUTES minutes ==="
        end=$((SECONDS + $(awk "BEGIN{print int($MINUTES*60)}")))
        revoked=0
        began=$SECONDS
        revoke_after=$(awk "BEGIN{print int(${REVOKE_AT:-0}*60)}")
        while [ "$SECONDS" -lt "$end" ]; do
            if [ -n "$REVOKE_SERIAL" ] && [ "$revoked" = 0 ] && [ $((SECONDS - began)) -ge "$revoke_after" ]; then
                [ -n "$CA_DIR" ] || die "--ca-dir is required with --revoke-serial"
                say "=== REVOKING certificate $REVOKE_SERIAL now ==="
                "$VPN" ca revoke "$REVOKE_SERIAL" --dir "$CA_DIR" || say "revoke failed"
                revoked=1
            fi
            timeline_line
            sleep "$STEP"
        done
        cleanup
        UNDO=()
        phase "outage over: key agreement can reach the gateway again" "$(awk "BEGIN{print int($AFTER*60)}")"
        ;;
    slow)
        need_net
        number --delay-ms "${DELAY_MS:-x}"
        command -v tc >/dev/null || die "tc (iproute2) is required"
        tc qdisc show dev "$IFACE" root | grep -Eq 'noqueue|fq_codel|pfifo_fast|mq|fq' || die "$IFACE already has a custom queue discipline; not touching it"
        confirm "tc on $IFACE: replace the root queue with a 2-band prio queue; band 2 adds ${DELAY_MS} ms delay and ${LOSS}% loss" \
                "tc filters: only TCP port $PORT packets to $PEER_IP go to band 2; all other traffic is untouched" \
                "for $MINUTES minutes (removing it restores the default queue)"
        phase "baseline: the tunnel as it is" "$(awk "BEGIN{print int($BASELINE*60)}")"
        tc qdisc replace dev "$IFACE" root handle 1: prio bands 2 priomap 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0
        UNDO+=("tc qdisc del dev $IFACE root")
        tc qdisc add dev "$IFACE" parent 1:2 handle 20: netem delay "${DELAY_MS}ms" loss "${LOSS}%"
        for m in sport dport; do
            tc filter add dev "$IFACE" parent 1: protocol ip prio 1 u32 match ip protocol 6 0xff match ip dst "$PEER_IP/32" match ip "$m" "$PORT" 0xffff flowid 1:2
        done
        phase "KEY AGREEMENT SLOWED (+${DELAY_MS}ms, ${LOSS}% loss on port $PORT)" "$(awk "BEGIN{print int($MINUTES*60)}")"
        cleanup
        UNDO=()
        phase "back to normal" "$(awk "BEGIN{print int($AFTER*60)}")"
        ;;
    restart)
        [ -n "$RESTART_CMD" ] || die "--restart-cmd is required"
        confirm "run: $RESTART_CMD" "a gateway restart forgets every connected computer until it agrees keys again (the outage grace does not cover it)"
        phase "baseline: the tunnel as it is" "$(awk "BEGIN{print int($BASELINE*60)}")"
        say "=== RESTARTING: $RESTART_CMD ==="
        bash -c "$RESTART_CMD" || say "the restart command failed"
        phase "after the restart" "$(awk "BEGIN{print int($AFTER*60)}")"
        ;;
    *) usage >&2; die "unknown command $CMD" ;;
esac
