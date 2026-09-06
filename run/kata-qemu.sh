#!/usr/bin/env bash
# Boot Kata's guest kernel directly in QEMU with the probe as PID 1.
#
# This deliberately skips the whole Kata orchestration: no kata-agent, no
# containerd, no Kubernetes. It answers "what does the guest kernel provide",
# which is the question this repository asks — and nothing beyond that. See
# LIMITATIONS.md.
#
# Usage: run/kata-qemu.sh /path/to/extracted/kata-static
#   where the argument contains opt/kata/{bin,share}, i.e. the layout of
#   kata-static-<version>-amd64.tar.zst after extraction.
set -euo pipefail

BUNDLE=${1:?usage: kata-qemu.sh /path/to/extracted/kata-static}
K="$BUNDLE/opt/kata"
HERE=$(cd "$(dirname "$0")/.." && pwd)

QEMU="$K/bin/qemu-system-x86_64"
BIOS="$K/share/kata-qemu/qemu"
KERNEL=$(ls "$K"/share/kata-containers/vmlinux-*[0-9] 2>/dev/null | grep -v debug | head -1)

for f in "$QEMU" "$KERNEL"; do
	[ -e "$f" ] || { echo "not found: $f" >&2; exit 1; }
done

cd "$HERE"
make probe
rm -rf ramfs && mkdir -p ramfs && cp probe ramfs/init
(cd ramfs && find . -print0 | cpio --null -o -H newc 2>/dev/null | gzip -9 > ../initrd.gz)

echo "guest kernel: $KERNEL"
timeout 120 "$QEMU" \
	-L "$BIOS" \
	-machine q35,accel=kvm -cpu host \
	-m 512 -smp 1 -nographic -no-reboot -nic none \
	-kernel "$KERNEL" -initrd initrd.gz \
	-append "console=ttyS0 panic=-1" 2>&1 |
	sed -n '/^kernel reported/,/^PROBE-DONE/p'
