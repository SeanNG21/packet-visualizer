#!/bin/bash
# setup.sh - Complete setup script

set -e

INTERFACE=${1}

if [ -z "$INTERFACE" ]; then
    echo "Usage: $0 <interface>"
    echo ""
    echo "Available interfaces:"
    ip link show | grep -E "^[0-9]+:" | awk '{print "  " $2}' | tr -d ':'
    exit 1
fi

if [ "$EUID" -ne 0 ]; then
    echo "Please run as root: sudo $0 $INTERFACE"
    exit 1
fi

echo "═══════════════════════════════════════════"
echo "  Packet Visualizer Setup"
echo "═══════════════════════════════════════════"
echo "Interface: $INTERFACE"
echo ""

# Step 1: Compile BPF program
echo "[1/6] Compiling BPF program..."
if [ ! -f "bpf/tag_kern.c" ]; then
    echo "❌ bpf/tag_kern.c not found!"
    exit 1
fi

clang -O2 -g -target bpf \
    -D__TARGET_ARCH_x86 \
    -D__BPF_TRACING__ \
    -I/usr/include \
    -I/usr/include/x86_64-linux-gnu \
    -c bpf/tag_kern.c -o bpf/tag_kern.o

if [ $? -eq 0 ]; then
    echo "✅ Compiled bpf/tag_kern.o"
else
    echo "❌ Compilation failed"
    exit 1
fi
echo ""

# Step 2: Clean old setup
echo "[2/6] Cleaning old setup..."
tc filter del dev "$INTERFACE" ingress 2>/dev/null || true
tc filter del dev "$INTERFACE" egress 2>/dev/null || true
tc qdisc del dev "$INTERFACE" clsact 2>/dev/null || true
rm -f /sys/fs/bpf/retis_rb 2>/dev/null || true
echo "✅ Cleaned"
echo ""

# Step 3: Check interface
echo "[3/6] Verifying interface..."
if ! ip link show "$INTERFACE" &>/dev/null; then
    echo "❌ Interface $INTERFACE does not exist!"
    exit 1
fi
echo "✅ Interface exists"
echo ""

# Step 4: Load BPF programs
echo "[4/6] Loading BPF programs..."
tc qdisc add dev "$INTERFACE" clsact
tc filter add dev "$INTERFACE" ingress \
    bpf obj bpf/tag_kern.o sec tc/ingress direct-action
tc filter add dev "$INTERFACE" egress \
    bpf obj bpf/tag_kern.o sec tc/egress direct-action
echo "✅ Programs loaded"
echo ""

# Step 5: Pin ring buffer
echo "[5/6] Pinning ring buffer..."
sleep 2

RB_ID=$(bpftool map list | grep "ringbuf.*name rb" | tail -1 | awk '{print $1}' | tr -d ':')

if [ -z "$RB_ID" ]; then
    echo "❌ No ring buffer found!"
    echo "Debug: All maps:"
    bpftool map list
    exit 1
fi

echo "  Found ring buffer ID: $RB_ID"
bpftool map pin id "$RB_ID" /sys/fs/bpf/retis_rb
echo "✅ Ring buffer pinned"
echo ""

# Step 6: Compile reader
echo "[6/6] Compiling reader..."
if [ ! -f "user/rb_reader.c" ]; then
    echo "❌ user/rb_reader.c not found!"
    exit 1
fi

gcc -Wall -O2 -o user/rb_reader user/rb_reader.c -lbpf -lelf -lz

if [ $? -eq 0 ]; then
    echo "✅ Reader compiled"
else
    echo "❌ Reader compilation failed"
    exit 1
fi
echo ""

# Verification
echo "═══════════════════════════════════════════"
echo "  Verification"
echo "═══════════════════════════════════════════"
echo ""
echo "TC Filters:"
tc filter show dev "$INTERFACE" ingress | grep -E "filter|tag_ingress" | head -2
echo ""
echo "BPF Programs:"
bpftool prog list | grep -E "tag_ingress|tag_egress" | head -2
echo ""
echo "Ring Buffer:"
bpftool map show pinned /sys/fs/bpf/retis_rb
echo ""

# Success
echo "═══════════════════════════════════════════"
echo "✅ SETUP COMPLETE!"
echo "═══════════════════════════════════════════"
echo ""
echo "To capture packets:"
echo "  Terminal 1: sudo ./user/rb_reader"
echo "  Terminal 2: ping -c 10 8.8.8.8"
echo ""
echo "To cleanup:"
echo "  sudo ./cleanup.sh $INTERFACE"
echo "═══════════════════════════════════════════"