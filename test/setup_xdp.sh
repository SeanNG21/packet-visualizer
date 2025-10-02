#!/bin/bash
# setup_xdp.sh - Use XDP instead of TC for better packet capture

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
echo "  Packet Visualizer Setup (XDP)"
echo "═══════════════════════════════════════════"
echo "Interface: $INTERFACE"
echo ""

# Step 1: Compile XDP program
echo "[1/5] Compiling XDP program..."
if [ ! -f "bpf/tag_kern_xdp.c" ]; then
    echo "❌ bpf/tag_kern_xdp.c not found!"
    exit 1
fi

clang -O2 -g -target bpf \
    -D__TARGET_ARCH_x86 \
    -D__BPF_TRACING__ \
    -I/usr/include \
    -I/usr/include/x86_64-linux-gnu \
    -c bpf/tag_kern_xdp.c -o bpf/tag_kern_xdp.o

if [ $? -eq 0 ]; then
    echo "✅ Compiled bpf/tag_kern_xdp.o"
else
    echo "❌ Compilation failed"
    exit 1
fi
echo ""

# Step 2: Clean old setup
echo "[2/5] Cleaning old setup..."
ip link set dev "$INTERFACE" xdp off 2>/dev/null || true
tc qdisc del dev "$INTERFACE" clsact 2>/dev/null || true
rm -f /sys/fs/bpf/retis_rb 2>/dev/null || true
echo "✅ Cleaned"
echo ""

# Step 3: Verify interface
echo "[3/5] Verifying interface..."
if ! ip link show "$INTERFACE" &>/dev/null; then
    echo "❌ Interface $INTERFACE does not exist!"
    exit 1
fi
echo "✅ Interface exists"
echo ""

# Step 4: Load XDP program
echo "[4/5] Loading XDP program..."
ip link set dev "$INTERFACE" xdp obj bpf/tag_kern_xdp.o sec xdp

if [ $? -eq 0 ]; then
    echo "✅ XDP program loaded"
else
    echo "❌ Failed to load XDP program"
    echo ""
    echo "Try with generic XDP (slower but more compatible):"
    echo "  ip link set dev $INTERFACE xdpgeneric obj bpf/tag_kern_xdp.o sec xdp"
    exit 1
fi
echo ""

# Step 5: Pin ring buffer
echo "[5/5] Pinning ring buffer..."
sleep 2

RB_ID=$(bpftool map list | grep "ringbuf.*name rb" | tail -1 | awk '{print $1}' | tr -d ':')

if [ -z "$RB_ID" ]; then
    echo "❌ No ring buffer found!"
    exit 1
fi

echo "  Found ring buffer ID: $RB_ID"
bpftool map pin id "$RB_ID" /sys/fs/bpf/retis_rb
echo "✅ Ring buffer pinned"
echo ""

# Verification
echo "═══════════════════════════════════════════"
echo "  Verification"
echo "═══════════════════════════════════════════"
echo ""
echo "XDP Program:"
ip link show "$INTERFACE" | grep xdp
echo ""
echo "BPF Programs:"
bpftool prog list | grep xdp_prog | head -2
echo ""
echo "Ring Buffer:"
bpftool map show pinned /sys/fs/bpf/retis_rb
echo ""

# Success
echo "═══════════════════════════════════════════"
echo "✅ SETUP COMPLETE (XDP MODE)"
echo "═══════════════════════════════════════════"
echo ""
echo "XDP captures ALL packets entering $INTERFACE"
echo ""
echo "To capture packets:"
echo "  Terminal 1: sudo ./user/rb_reader"
echo "  Terminal 2: ping -c 10 8.8.8.8"
echo ""
echo "To cleanup:"
echo "  sudo ip link set dev $INTERFACE xdp off"
echo "  sudo rm /sys/fs/bpf/retis_rb"
echo "═══════════════════════════════════════════"