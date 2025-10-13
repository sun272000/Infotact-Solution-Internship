#!/usr/bin/env bash
# run_nids_tests.sh - Attacker-side NIDS test script
# Usage: sudo ./run_nids_tests.sh TARGET_IP [IFACE]
# Default TARGET_IP = 192.168.56.102

set -u
TARGET=${1:-192.168.56.105}
IFACE=${2:-$(ip route get "$TARGET" 2>/dev/null | awk '/dev/ {print $5; exit}')}

PCAP="/tmp/nids_test_${TARGET//./_}.pcap"
TCPDUMP_PID_FILE="/tmp/tcpdump_nids_test.pid"

echo "[*] Target: $TARGET"
if [[ -z "$IFACE" || "$IFACE" == "0.0.0.0" ]]; then
  echo "[!] Interface autodetect failed. List your interfaces with: ip -br addr"
  echo "    Re-run the script with the interface as second argument, e.g.:"
  echo "    sudo ./run_nids_tests.sh $TARGET eth1"
  exit 2
fi
echo "[*] Interface: $IFACE"
echo "[*] PCAP file: $PCAP"
echo

# require sudo
if [[ $EUID -ne 0 ]]; then
  echo "[!] Please run with sudo. Exiting."
  exit 3
fi

# Check for required commands and warn (we won't attempt to install)
for cmd in tcpdump nmap curl ssh; do
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "[!] Warning: '$cmd' not found. Some tests may be skipped."
  fi
done

# start tcpdump capturing traffic between attacker and target (if tcpdump exists)
if command -v tcpdump >/dev/null 2>&1; then
  echo "[*] Starting tcpdump..."
  tcpdump -i "$IFACE" host "$TARGET" -w "$PCAP" 2>/dev/null &
  TCPDUMP_PID=$!
  echo $TCPDUMP_PID > "$TCPDUMP_PID_FILE"
  sleep 1
  echo "[*] tcpdump started (pid $TCPDUMP_PID)."
else
  echo "[!] tcpdump not installed — continuing without pcap capture."
fi

# 1) Nmap tests (if nmap installed)
if command -v nmap >/dev/null 2>&1; then
  echo
  echo "==== [Nmap SYN scan] ===="
  nmap -sS -Pn "$TARGET" -oN /tmp/nmap_syn_scan_${TARGET}.txt || true
  sleep 2

  echo
  echo "==== [Nmap FIN scan] ===="
  nmap -sF -Pn "$TARGET" -oN /tmp/nmap_fin_scan_${TARGET}.txt || true
  sleep 2

  echo
  echo "==== [Nmap XMAS scan] ===="
  nmap -sX -Pn "$TARGET" -oN /tmp/nmap_xmas_scan_${TARGET}.txt || true
  sleep 2
else
  echo "[!] nmap not installed; skipping Nmap tests."
fi

# 2) SSH brute-force (quick) - simple connect attempts
if command -v ssh >/dev/null 2>&1; then
  echo
  echo "==== [SSH brute attempts x6] ===="
  for i in {1..6}; do
    ssh -o ConnectTimeout=2 -o StrictHostKeyChecking=no invaliduser@"$TARGET" 2>/dev/null || true
    sleep 1
  done
  sleep 2
else
  echo "[!] ssh client not installed; skipping SSH tests."
fi

# 3) FTP attempts (simple TCP connects) - uses bash TCP socket, always available on modern bash
echo
echo "==== [FTP connect attempts x12] ===="
for i in {1..12}; do
  timeout 3 bash -c "echo > /dev/tcp/$TARGET/21" 2>/dev/null || true
  sleep 1
done
sleep 2

# 4) HTTP beacon simulation - 5 quick GETs to /update.php
if command -v curl >/dev/null 2>&1; then
  echo
  echo "==== [HTTP beacon: GET /update.php x5] ===="
  for i in {1..5}; do
    curl -s -I "http://$TARGET/update.php" >/dev/null 2>&1 || true
    sleep 1
  done
else
  echo "[!] curl not installed; skipping HTTP beacon."
fi

# cleanup tcpdump
if [[ -f "$TCPDUMP_PID_FILE" ]]; then
  TCPDUMP_PID=$(cat "$TCPDUMP_PID_FILE" 2>/dev/null || echo "")
  if [[ -n "$TCPDUMP_PID" ]]; then
    echo
    echo "[*] Stopping tcpdump (pid $TCPDUMP_PID)..."
    kill "$TCPDUMP_PID" 2>/dev/null || true
    sleep 1
  fi
  rm -f "$TCPDUMP_PID_FILE"
fi

echo
echo "[*] Tests finished."
if [[ -f "$PCAP" ]]; then
  echo "[*] PCAP saved to: $PCAP"
else
  echo "[!] No PCAP was captured (tcpdump missing or failed)."
fi
echo "[*] Nmap outputs (if run): /tmp/nmap_syn_scan_${TARGET}.txt /tmp/nmap_fin_scan_${TARGET}.txt /tmp/nmap_xmas_scan_${TARGET}.txt"
echo
echo "On the TARGET (NIDS host) check alerts with:"
echo "  sudo tail -n 200 /var/log/snort/alert"
echo
