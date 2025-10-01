#!/bin/bash
set -e

IFACE=$1
if [ -z "$IFACE" ]; then
    echo "Usage: $0 <iface>"
    exit 1
fi

echo "[1] Cleanup old qdisc..."
sudo tc qdisc del dev $IFACE clsact 2>/dev/null || true

echo "[2] Setup clsact..."
sudo tc qdisc add dev $IFACE clsact

echo "[3] Attach ingress/egress..."
sudo tc filter add dev $IFACE ingress bpf da obj bpf/tag_kern.o sec tc/ingress
sudo tc filter add dev $IFACE egress  bpf da obj bpf/tag_kern.o sec tc/egress

echo "[4] Pin maps..."
ID_TO_FP=$(bpftool map show | grep id_to_fp | awk '{print $1}' | sed 's/://')
RB=$(bpftool map show | grep -w rb | awk '{print $1}' | sed 's/://')

sudo mkdir -p /sys/fs/bpf/retis
sudo bpftool map pin id $ID_TO_FP /sys/fs/bpf/retis/id_to_fp
sudo bpftool map pin id $RB       /sys/fs/bpf/retis/rb

echo "[OK] Done!"
