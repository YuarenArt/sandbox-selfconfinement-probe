#!/usr/bin/env bash
# Create a kind cluster with a real gVisor runtime and run the probe under both
# runc and runsc, in a minimal pod and in a hardened one.
#
# The RuntimeClass is named "gvisor" and its handler is "runsc". A RuntimeClass
# named gvisor whose handler is runc is a common misconfiguration and would make
# the whole comparison meaningless, so the probe prints uname and the output
# itself shows which kernel answered.
set -euo pipefail

CLUSTER=${CLUSTER:-selfconfinement-probe}
NODE_IMAGE=${NODE_IMAGE:-kindest/node:v1.32.2}
# Pinned on purpose: the "latest" channel moves, and what it points at is not
# always the newest release. The capability surface really does change between
# releases: openat2 returns ENOSYS on 20260817.0 and works on 20260831.0. An
# unpinned run produces a table that cannot be compared with anything.
RUNSC_RELEASE=${RUNSC_RELEASE:-20260831.0}
RUNSC_URL="https://storage.googleapis.com/gvisor/releases/release/${RUNSC_RELEASE}/x86_64"
HERE=$(cd "$(dirname "$0")/.." && pwd)
OUT=${OUT:-$HERE/results}

need() { command -v "$1" >/dev/null 2>&1 || { echo "missing dependency: $1" >&2; exit 1; }; }
for t in docker kind kubectl curl make gcc sha512sum; do need "$t"; done

# Releases up to 20260817.0 publish bare binaries with a .sha512 beside each;
# later ones publish only gvisor.tar.*. Both layouts are handled so that a
# pinned older release keeps working.
fetch_runsc() {
	[ -x runsc ] && [ -x containerd-shim-runsc-v1 ] && return 0
	if curl -fsSL -o runsc.tmp "$RUNSC_URL/runsc" 2>/dev/null; then
		curl -fsSL -o runsc.sha512 "$RUNSC_URL/runsc.sha512"
		mv runsc.tmp runsc
		sha512sum -c runsc.sha512
		curl -fsSL -o containerd-shim-runsc-v1.tmp "$RUNSC_URL/containerd-shim-runsc-v1"
		curl -fsSL -o containerd-shim-runsc-v1.sha512 "$RUNSC_URL/containerd-shim-runsc-v1.sha512"
		mv containerd-shim-runsc-v1.tmp containerd-shim-runsc-v1
		sha512sum -c containerd-shim-runsc-v1.sha512
	else
		need zstd
		rm -f runsc.tmp
		curl -fsSL -o gvisor.tar.zstd "$RUNSC_URL/gvisor.tar.zstd"
		tar -I zstd -xf gvisor.tar.zstd runsc containerd-shim-runsc-v1
		rm -f gvisor.tar.zstd
	fi
	chmod +x runsc containerd-shim-runsc-v1
}

cd "$HERE"
make image

fetch_runsc

if ! kind get clusters | grep -qx "$CLUSTER"; then
	kind create cluster --name "$CLUSTER" --image "$NODE_IMAGE"
fi
NODE="${CLUSTER}-control-plane"

docker cp runsc "$NODE:/usr/local/bin/runsc"
docker cp containerd-shim-runsc-v1 "$NODE:/usr/local/bin/containerd-shim-runsc-v1"
docker exec "$NODE" sh -c '
	chmod 755 /usr/local/bin/runsc /usr/local/bin/containerd-shim-runsc-v1
	if ! grep -q "runtimes.runsc" /etc/containerd/config.toml; then
		cat >> /etc/containerd/config.toml <<EOF

[plugins."io.containerd.grpc.v1.cri".containerd.runtimes.runsc]
  runtime_type = "io.containerd.runsc.v1"
EOF
		systemctl restart containerd
	fi'
sleep 5

kind load docker-image sandbox-probe:local --name "$CLUSTER"

KC="kubectl --context kind-${CLUSTER}"
$KC apply -f - <<'EOF'
apiVersion: node.k8s.io/v1
kind: RuntimeClass
metadata: {name: gvisor}
handler: runsc
EOF

# The work directory is an emptyDir so the probe never touches anything the
# runtime mounted in from the node, and so the hardened pod, which runs as a
# non-root user, still has somewhere to write.
pod() {
	local name=$1 runtime=$2 hardened=$3
	local rc="" sc=""
	[ "$runtime" = gvisor ] && rc="  runtimeClassName: gvisor"
	if [ "$hardened" = yes ]; then
		sc='  securityContext: {runAsNonRoot: true, runAsUser: 1000, runAsGroup: 1000, fsGroup: 1000}'
	fi
	cat <<EOF
apiVersion: v1
kind: Pod
metadata: {name: $name}
spec:
  restartPolicy: Never
$rc
$sc
  volumes: [{name: work, emptyDir: {}}]
  containers:
  - name: p
    image: sandbox-probe:local
    imagePullPolicy: Never
    env: [{name: PROBE_WORKDIR, value: /work}]
    volumeMounts: [{name: work, mountPath: /work}]
$( [ "$hardened" = yes ] && echo '    securityContext: {allowPrivilegeEscalation: false, capabilities: {drop: [ALL]}, seccompProfile: {type: RuntimeDefault}}' )
EOF
}

names="probe-runc probe-gvisor probe-runc-hardened probe-gvisor-hardened"
$KC delete pod $names --ignore-not-found --wait=true >/dev/null
{
	pod probe-runc runc no;            echo "---"
	pod probe-gvisor gvisor no;        echo "---"
	pod probe-runc-hardened runc yes;  echo "---"
	pod probe-gvisor-hardened gvisor yes
} | $KC apply -f -

for n in $names; do
	$KC wait --for=jsonpath='{.status.phase}'=Succeeded "pod/$n" --timeout=180s
done

mkdir -p "$OUT"
date=$(date +%F)
runsc_version=$(docker exec "$NODE" runsc --version | head -1)
kind_version=$(kind version | head -1)
for n in $names; do
	case "$n" in
	*gvisor*) rt="gVisor (RuntimeClass gvisor -> handler runsc), platform systrap (default)";;
	*)        rt="runc (default runtime)";;
	esac
	case "$n" in
	*hardened) spec="hardened: runAsNonRoot uid 1000, capabilities drop ALL, seccompProfile RuntimeDefault";;
	*)         spec="minimal: no securityContext";;
	esac
	{
		echo "# Kubernetes pod, runtime: $rt"
		echo "# pod spec: $spec"
		echo "# date: $date"
		echo "# $runsc_version"
		echo "# $kind_version, node image $NODE_IMAGE, host kernel $(uname -r)"
		echo
		$KC logs "$n"
	} > "$OUT/$date-$n.txt"
	echo "wrote $OUT/$date-$n.txt"
done

echo
echo "cleanup when done: kind delete cluster --name $CLUSTER"
