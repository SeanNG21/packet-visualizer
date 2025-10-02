#!/bin/bash
# cleanup.sh - Remove all BPF programs and filters

INTERFACE=${1}

if [ -z "$INTERFACE" ]; then
    echo "Usage: $0 <interface>"
    echo "Example: $0 wlo1"
    exit 1
fi

if [ "$EUID" -ne 0 ]; then
    echo "Please run as root: sudo $0 $INTERFACE"
    exit 1
fi

echo "Cleaning up $INTERFACE..."
echo ""

# Remove TC filters and qdisc
echo "Removing TC filters..."
tc filter del dev "$INTERFACE" ingress 2>/dev/null && echo "✅ Removed ingress filter" || echo "  (no ingress filter)"
tc filter del dev "$INTERFACE" egress 2>/dev/null && echo "✅ Removed egress filter" || echo "  (no egress filter)"
tc qdisc del dev "$INTERFACE" clsact 2>/dev/null && echo "✅ Removed clsact qdisc" || echo "  (no clsact qdisc)"
echo ""

# Unpin ring buffer
echo "Unpinning ring buffer..."
rm -f /sys/fs/bpf/retis_rb && echo "✅ Removed /sys/fs/bpf/retis_rb" || echo "  (already removed)"
echo ""

echo "✅ Cleanup complete for $INTERFACE"