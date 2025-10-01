#!/bin/bash
set -e

IFACE=$1
if [ -z "$IFACE" ]; then
    echo "Usage: $0 <iface>"
    exit 1
fi

echo "[1] Cleanup old clsact & pins..."
sudo tc qdisc del dev $IFACE clsact 2>/dev/null || true
sudo rm -f /sys/fs/bpf/retis_id_to_fp /sys/fs/bpf/retis_rb

echo "[2] Attach ingress/egress directly..."
sudo tc qdisc add dev $IFACE clsact
sudo tc filter add dev $IFACE ingress bpf da obj bpf/tag_kern.o sec tc/ingress
sudo tc filter add dev $IFACE egress  bpf da obj bpf/tag_kern.o sec tc/egress

echo "[3] Find and pin maps..."
ID_TO_FP=$(bpftool map show | grep id_to_fp | awk '{print $1}' | sed 's/://' | tail -n1)
RB=$(bpftool map show | grep -w "rb" | awk '{print $1}' | sed 's/://' | tail -n1)

if [ -z "$ID_TO_FP" ] || [ -z "$RB" ]; then
    echo "Error: Could not find maps id_to_fp / rb"
    exit 1
fi

sudo bpftool map pin id $ID_TO_FP /sys/fs/bpf/retis_id_to_fp
sudo bpftool map pin id $RB       /sys/fs/bpf/retis_rb

echo "[OK] Setup done!"
ls -l /sys/fs/bpf/retis_*
