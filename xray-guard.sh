#!/usr/bin/env bash

set -u
set -o pipefail

PATH="/usr/sbin:/usr/bin:/sbin:/bin"

PORT="${PORT:-443}"
INTERVAL="${INTERVAL:-5}"

CPU_THRESHOLD="${CPU_THRESHOLD:-200}"
GLOBAL_SYN_THRESHOLD="${GLOBAL_SYN_THRESHOLD:-150}"
GLOBAL_EST_THRESHOLD="${GLOBAL_EST_THRESHOLD:-3000}"

PER_IP_SYN_BAN_THRESHOLD="${PER_IP_SYN_BAN_THRESHOLD:-12}"
PER_IP_EST_BAN_THRESHOLD="${PER_IP_EST_BAN_THRESHOLD:-20}"

NFT_CONN_LIMIT="${NFT_CONN_LIMIT:-20}"
NFT_RATE="${NFT_RATE:-8/second}"
NFT_BURST="${NFT_BURST:-12}"

BAN_TIMEOUT="${BAN_TIMEOUT:-2h}"
RUN_ONCE="${RUN_ONCE:-0}"

TOP_LIMIT="${TOP_LIMIT:-10}"
NFT_TABLE="${NFT_TABLE:-xrayguard}"
LOG_FILE="${LOG_FILE:-/var/log/xray-guard.log}"

PROC_REGEX="${PROC_REGEX:-xray|rw-core|sing-box|v2ray}"

mkdir -p "$(dirname "$LOG_FILE")"
touch "$LOG_FILE" 2>/dev/null || true

log() {
  echo "$(date '+%F %T') $*" >> "$LOG_FILE"
}

trim() {
  awk '{$1=$1; print}'
}

float_gt() {
  local a="${1:-0}"
  local b="${2:-0}"
  awk -v a="$a" -v b="$b" 'BEGIN { exit !(a > b) }'
}

is_ipv4() {
  [[ "${1:-}" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]
}

is_ignored_ip() {
  local ip="${1:-}"
  [[ -z "$ip" ]] && return 0

  if is_ipv4 "$ip"; then
    local o1 o2 o3 o4
    IFS='.' read -r o1 o2 o3 o4 <<< "$ip"

    [[ "$o1" == "10" ]] && return 0
    [[ "$o1" == "127" ]] && return 0
    [[ "$o1" == "169" && "$o2" == "254" ]] && return 0
    [[ "$o1" == "192" && "$o2" == "168" ]] && return 0
    if [[ "$o1" == "172" ]] && (( o2 >= 16 && o2 <= 31 )); then
      return 0
    fi
    return 1
  fi

  case "$ip" in
    ::1|fe80:*|fc*|fd*)
      return 0
      ;;
  esac

  return 1
}

get_pid() {
  pgrep -o -f "$PROC_REGEX" 2>/dev/null | head -n1
}

get_cpu() {
  local pid="${1:-}"
  [[ -z "$pid" ]] && { echo "0"; return; }
  ps -p "$pid" -o %cpu= 2>/dev/null | head -n1 | trim
}

ensure_nftables() {
  nft add table inet "$NFT_TABLE" 2>/dev/null || true

  nft add set inet "$NFT_TABLE" deny4 '{ type ipv4_addr; flags timeout; }' 2>/dev/null || true
  nft add set inet "$NFT_TABLE" deny6 '{ type ipv6_addr; flags timeout; }' 2>/dev/null || true

  nft add set inet "$NFT_TABLE" conn4 '{ type ipv4_addr; size 65535; flags dynamic; }' 2>/dev/null || true
  nft add set inet "$NFT_TABLE" conn6 '{ type ipv6_addr; size 65535; flags dynamic; }' 2>/dev/null || true

  nft add set inet "$NFT_TABLE" rate4 '{ type ipv4_addr; size 65535; flags dynamic,timeout; timeout 1m; }' 2>/dev/null || true
  nft add set inet "$NFT_TABLE" rate6 '{ type ipv6_addr; size 65535; flags dynamic,timeout; timeout 1m; }' 2>/dev/null || true

  nft add chain inet "$NFT_TABLE" input '{ type filter hook input priority filter - 10; policy accept; }' 2>/dev/null || true
  nft flush chain inet "$NFT_TABLE" input 2>/dev/null || true

  nft add rule inet "$NFT_TABLE" input 'iifname "lo" return'
  nft add rule inet "$NFT_TABLE" input "tcp dport $PORT ip saddr @deny4 drop"
  nft add rule inet "$NFT_TABLE" input "tcp dport $PORT ip6 saddr @deny6 drop"
  nft add rule inet "$NFT_TABLE" input "udp dport $PORT ip saddr @deny4 drop"
  nft add rule inet "$NFT_TABLE" input "udp dport $PORT ip6 saddr @deny6 drop"

  nft add rule inet "$NFT_TABLE" input "tcp dport $PORT ct state new add @conn4 { ip saddr ct count over $NFT_CONN_LIMIT } counter drop"
  nft add rule inet "$NFT_TABLE" input "tcp dport $PORT ct state new add @conn6 { ip6 saddr ct count over $NFT_CONN_LIMIT } counter drop"

  nft add rule inet "$NFT_TABLE" input "tcp dport $PORT ct state new update @rate4 { ip saddr limit rate over $NFT_RATE burst $NFT_BURST packets } counter drop"
  nft add rule inet "$NFT_TABLE" input "tcp dport $PORT ct state new update @rate6 { ip6 saddr limit rate over $NFT_RATE burst $NFT_BURST packets } counter drop"
}

ss_filtered_by_state() {
  local state="${1:-}"
  ss -Htan state "$state" "( sport = :$PORT )" 2>/dev/null || true
}

count_state() {
  local state="${1:-}"
  ss_filtered_by_state "$state" | wc -l | tr -d ' '
}

top_peers_by_state() {
  local state="${1:-}"
  local limit="${2:-1000}"

  ss_filtered_by_state "$state" | awk '
    function endpoint_ip(ep, ip) {
      ip = ep

      if (ip == "" || ip == "*" || ip == "-") return ""

      if (ip ~ /^\[/) {
        sub(/^\[/, "", ip)
        sub(/\]:[0-9]+$/, "", ip)
      } else {
        sub(/:[0-9]+$/, "", ip)
      }

      if (ip ~ /^::ffff:[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/) {
        sub(/^::ffff:/, "", ip)
      }

      return ip
    }
    {
      peer = endpoint_ip($NF)
      if (peer != "") c[peer]++
    }
    END {
      for (ip in c) print c[ip], ip
    }
  ' | sort -rn -k1,1 | head -n "$limit"
}

format_top_state() {
  local state="${1:-}"
  local limit="${2:-10}"

  top_peers_by_state "$state" "$limit" | awk '
    NF >= 2 {
      if (NR > 1) printf ", "
      printf "%s %s", $1, $2
    }
    END {
      if (NR > 0) print ""
    }
  ' | sed 's/[[:space:]]*$//'
}

has_ip_in_set() {
  local setname="${1:-}"
  local ip="${2:-}"
  [[ -z "$setname" || -z "$ip" ]] && return 1
  nft list set inet "$NFT_TABLE" "$setname" 2>/dev/null | grep -Fq "$ip"
}

ban_ip() {
  local ip="${1:-}"
  local reason="${2:-}"

  [[ -z "$ip" ]] && return 0
  is_ignored_ip "$ip" && return 0

  if is_ipv4 "$ip"; then
    has_ip_in_set "deny4" "$ip" && return 0
    if nft add element inet "$NFT_TABLE" deny4 "{ $ip timeout $BAN_TIMEOUT }" 2>/dev/null; then
      log "BAN ip=$ip family=ipv4 timeout=$BAN_TIMEOUT reason=\"$reason\""
    fi
  else
    has_ip_in_set "deny6" "$ip" && return 0
    if nft add element inet "$NFT_TABLE" deny6 "{ $ip timeout $BAN_TIMEOUT }" 2>/dev/null; then
      log "BAN ip=$ip family=ipv6 timeout=$BAN_TIMEOUT reason=\"$reason\""
    fi
  fi
}

main_loop() {
  while :; do
    local pid cpu syn_recv established
    local top_syn top_est overloaded

    pid="$(get_pid || true)"
    cpu="0"

    if [[ -n "$pid" ]]; then
      cpu="$(get_cpu "$pid")"
      cpu="$(trim <<< "$cpu")"
      [[ -z "$cpu" ]] && cpu="0"
    fi

    syn_recv="$(count_state syn-recv)"
    established="$(count_state established)"

    top_syn="$(format_top_state syn-recv "$TOP_LIMIT")"
    top_est="$(format_top_state established "$TOP_LIMIT")"

    log "CHECK pid=${pid:-none} cpu=${cpu}% syn_recv=$syn_recv established=$established port=$PORT top_syn=[${top_syn}] top_est=[${top_est}]"

    overloaded=0

    if [[ -n "$pid" ]] && float_gt "$cpu" "$CPU_THRESHOLD"; then
      overloaded=1
    fi
    if (( syn_recv > GLOBAL_SYN_THRESHOLD )); then
      overloaded=1
    fi
    if (( established > GLOBAL_EST_THRESHOLD )); then
      overloaded=1
    fi

    if (( overloaded == 1 )); then
      while read -r cnt ip; do
        [[ -z "${cnt:-}" || -z "${ip:-}" ]] && continue
        if (( cnt >= PER_IP_SYN_BAN_THRESHOLD )); then
          ban_ip "$ip" "state=syn-recv count=$cnt cpu=${cpu}% global_syn=$syn_recv global_est=$established"
        fi
      done < <(top_peers_by_state syn-recv 1000)

      while read -r cnt ip; do
        [[ -z "${cnt:-}" || -z "${ip:-}" ]] && continue
        if (( cnt >= PER_IP_EST_BAN_THRESHOLD )); then
          ban_ip "$ip" "state=established count=$cnt cpu=${cpu}% global_syn=$syn_recv global_est=$established"
        fi
      done < <(top_peers_by_state established 1000)
    fi

    [[ "$RUN_ONCE" == "1" ]] && break
    sleep "$INTERVAL"
  done
}

main() {
  ensure_nftables

  log "START port=$PORT interval=${INTERVAL}s cpu_threshold=${CPU_THRESHOLD}% global_syn=$GLOBAL_SYN_THRESHOLD global_est=$GLOBAL_EST_THRESHOLD per_ip_syn=$PER_IP_SYN_BAN_THRESHOLD per_ip_est=$PER_IP_EST_BAN_THRESHOLD nft_conn_limit=$NFT_CONN_LIMIT nft_rate=$NFT_RATE burst=$NFT_BURST ban_timeout=$BAN_TIMEOUT"

  main_loop
}

main "$@"
