#!/usr/bin/env bash
set -euo pipefail

oracle_home="/opt/oracle/product/26ai/dbhomeFree"
tcps_port="2484"
out_pcap="/tmp/oracle_plain_tcps.pcap"
max_packets=""

usage() {
  cat <<'USAGE'
Usage: run_ebpf_capture.sh [-H ORACLE_HOME] [-p TCPS_PORT] [-o OUT_PCAP] [-n MAX_PACKETS] [-A]

Runs the eBPF uprobe plaintext TCPS/TNS capture PoC.
USAGE
}

ack_data=""

while getopts ":H:p:o:n:Ah" opt; do
  case "$opt" in
    H) oracle_home="$OPTARG" ;;
    p) tcps_port="$OPTARG" ;;
    o) out_pcap="$OPTARG" ;;
    n) max_packets="$OPTARG" ;;
    A) ack_data="1" ;;
    h) usage; exit 0 ;;
    *) usage >&2; exit 2 ;;
  esac
done

bin="./build/oracle_tcps_plaincap_ebpf"
if [[ ! -x "$bin" ]]; then
  echo "missing $bin; run ./scripts/build.sh first" >&2
  exit 1
fi

args=(-H "$oracle_home" -p "$tcps_port" -o "$out_pcap")
if [[ -n "$max_packets" ]]; then
  args+=(-n "$max_packets")
fi
if [[ -n "$ack_data" ]]; then
  args+=(-A)
fi

exec "$bin" "${args[@]}"
