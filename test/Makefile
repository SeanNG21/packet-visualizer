# Simple Makefile

.PHONY: all clean bpf user

all: bpf user

bpf:
	@echo "Compiling BPF program..."
	clang -O2 -g -target bpf \
		-D__TARGET_ARCH_x86 \
		-D__BPF_TRACING__ \
		-I/usr/include \
		-I/usr/include/x86_64-linux-gnu \
		-c bpf/tag_kern.c -o bpf/tag_kern.o
	@echo "Done: bpf/tag_kern.o"

user:
	@echo "Compiling user program..."
	gcc -Wall -O2 -o user/rb_reader user/rb_reader.c -lbpf -lelf -lz
	@echo "Done: user/rb_reader"

clean:
	rm -f bpf/*.o user/rb_reader

help:
	@echo "Packet Visualizer Makefile"
	@echo ""
	@echo "Targets:"
	@echo "  make all    - Compile everything"
	@echo "  make bpf    - Compile BPF program only"
	@echo "  make user   - Compile user program only"
	@echo "  make clean  - Remove compiled files"
	@echo ""
	@echo "After compiling, run:"
	@echo "  sudo ./setup.sh <interface>"
	@echo ""
	@echo "Example:"
	@echo "  sudo ./setup.sh wlo1"