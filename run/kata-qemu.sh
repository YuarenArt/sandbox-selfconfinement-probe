#!/usr/bin/env bash
# Boot Kata's guest kernel directly in QEMU with the probe as PID 1.
#
# This deliberately skips the whole Kata orchestration: no kata-agent, no
# containerd, no Kubernetes. It answers "what does the guest kernel provide",
# which is the question this repository asks, and nothing beyond it. The guest
# here is also far more privileged than any pod: PID 1, full capability set, no
# seccomp, no LSM policy. See LIMITATIONS.md.
#
# Usage: run/kata-qemu.sh /path/to/extracted/kata-static
#   The argument is a directory containing opt/kata/{bin,share}, i.e. the layout
#   of kata-static-<version>-amd64.tar.zst after `tar -I zstd -xf`.
set -euo pipefail

BUNDLE=${1:?usage: kata-qemu.sh /path/to/extracted/kata-static}
K="$BUNDLE/opt/kata"
HERE=$(cd "$(dirname "$0")/.." && pwd)
OUT=${OUT:-$HERE/results}

need() { command -v "$1" >/dev/null 2>&1 || { echo "missing dependency: $1" >&2; exit 1; }; }
for t in make gcc cpio gzip find; do need "$t"; done

QEMU="$K/bin/qemu-system-x86_64"
BIOS="$K/share/kata-qemu/qemu"
KERNEL=$(ls "$K"/share/kata-containers/vmlinux-*[0-9] 2>/dev/null | grep -v debug | head -1 || true)

[ -x "$QEMU" ] || { echo "qemu not found or not executable: $QEMU" >&2; exit 1; }
[ -d "$BIOS" ] || { echo "qemu data directory not found: $BIOS" >&2; exit 1; }
[ -n "$KERNEL" ] && [ -r "$KERNEL" ] || { echo "no guest kernel under $K/share/kata-containers" >&2; exit 1; }
[ -r /dev/kvm ] && [ -w /dev/kvm ] || {
	echo "/dev/kvm is not readable and writable by this user." >&2
	echo "Add yourself to the kvm group, or run with accel=tcg by editing this script." >&2
	exit 1
}

cd "$HERE"
make probe

# -R 0:0 matters: cpio would otherwise record the building user as the owner of
# the guest root, and then anything the probe does inside a user namespace hits
# an unmapped owner and fails with EACCES for reasons that have nothing to do
# with the kernel under test.
STAGE=$(mktemp -d)
trap 'rm -rf "$STAGE"' EXIT
cp probe "$STAGE/init"
(cd "$STAGE" && find . -print0 | cpio --null -o -H newc -R 0:0 2>/dev/null | gzip -9 > "$HERE/initrd.gz")

mkdir -p "$OUT"
date=$(date +%F)
log=$(mktemp)
set +e
timeout 120 "$QEMU" \
	-L "$BIOS" \
	-machine q35,accel=kvm -cpu host \
	-m 512 -smp 1 -nographic -no-reboot -nic none \
	-kernel "$KERNEL" -initrd initrd.gz \
	-append "console=ttyS0 panic=-1" > "$log" 2>&1
rc=$?
set -e
if ! grep -q PROBE-DONE "$log"; then
	echo "the probe did not finish (qemu exit $rc); full console log follows:" >&2
	cat "$log" >&2
	exit 1
fi

{
	echo "# Kata guest kernel booted directly in QEMU, probe as PID 1"
	echo "# NOT the full Kata path: no kata-agent, no containerd, no Kubernetes"
	echo "# date: $date"
	echo "# kata bundle $(cat "$K/VERSION" 2>/dev/null || echo unknown), kernel $(basename "$KERNEL")"
	echo "# $("$QEMU" --version | head -1)"
	echo "# host kernel $(uname -r)"
	echo
	sed -n '/^kernel reported/,/^PROBE-DONE/p' "$log" | tr -d '\r'
} > "$OUT/$date-kata-guest-kernel-qemu.txt"
rm -f "$log"

cat "$OUT/$date-kata-guest-kernel-qemu.txt"
echo
echo "wrote $OUT/$date-kata-guest-kernel-qemu.txt"
