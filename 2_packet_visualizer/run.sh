#!/bin/bash
set -e

IFACE=$1
if [ -z "$IFACE" ]; then
    echo "Usage: $0 <iface>"
    exit 1
fi

echo "[1] Cleanup old clsact & pins..."
sudo tc qdisc del dev $IFACE clsact 2>/dev/null || true
sudo rm -f /sys/fs/bpf/retis_percpu_ctr \
           /sys/fs/bpf/retis_id_to_fp \
           /sys/fs/bpf/retis_rb

echo "[2] Attach ingress/egress..."
sudo tc qdisc add dev $IFACE clsact
sudo tc filter add dev $IFACE ingress bpf da obj bpf/tag_kern.o sec tc/ingress
sudo tc filter add dev $IFACE egress  bpf da obj bpf/tag_kern.o sec tc/egress

echo "[3] Find and pin latest maps..."
for MAP in percpu_ctr id_to_fp rb; do
    ID=$(bpftool map show | grep -w "$MAP" | awk '{print $1}' | sed 's/://' | tail -n1)
    if [ -n "$ID" ]; then
        sudo bpftool map pin id $ID /sys/fs/bpf/retis_$MAP
        echo "Pinned $MAP (id=$ID)"
    else
        echo "Map $MAP not found!"
    fi
done

echo "[OK] Setup done!"
ls -l /sys/fs/bpf/retis_*
