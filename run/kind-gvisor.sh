#!/usr/bin/env bash
# Create a kind cluster with a real gVisor runtime and run the probe under both
# runc and runsc. The RuntimeClass is named "gvisor" and its handler is "runsc" —
# a RuntimeClass named gvisor whose handler is runc is a common misconfiguration
# and would make the comparison meaningless. The probe prints uname, so the
# output itself shows which kernel answered.
set -euo pipefail

CLUSTER=${CLUSTER:-selfconfinement-probe}
NODE_IMAGE=${NODE_IMAGE:-kindest/node:v1.32.2}
RUNSC_URL=${RUNSC_URL:-https://storage.googleapis.com/gvisor/releases/release/latest/x86_64}
HERE=$(cd "$(dirname "$0")/.." && pwd)

cd "$HERE"
make probe
docker build -q -t sandbox-probe:local . >/dev/null

if ! kind get clusters | grep -qx "$CLUSTER"; then
	kind create cluster --name "$CLUSTER" --image "$NODE_IMAGE"
fi
NODE="${CLUSTER}-control-plane"

if [ ! -f runsc ]; then
	curl -fsSL -o runsc "$RUNSC_URL/runsc"
	curl -fsSL -o containerd-shim-runsc-v1 "$RUNSC_URL/containerd-shim-runsc-v1"
	chmod +x runsc containerd-shim-runsc-v1
fi

docker cp runsc "$NODE:/usr/local/bin/runsc"
docker cp containerd-shim-runsc-v1 "$NODE:/usr/local/bin/containerd-shim-runsc-v1"
docker exec "$NODE" sh -c '
	chmod 755 /usr/local/bin/runsc /usr/local/bin/containerd-shim-runsc-v1
	grep -q "runtimes.runsc" /etc/containerd/config.toml || cat >> /etc/containerd/config.toml <<EOF

[plugins."io.containerd.grpc.v1.cri".containerd.runtimes.runsc]
  runtime_type = "io.containerd.runsc.v1"
EOF
	systemctl restart containerd'
sleep 6

kind load docker-image sandbox-probe:local --name "$CLUSTER"

KC="kubectl --context kind-${CLUSTER}"
$KC apply -f - <<'EOF'
apiVersion: node.k8s.io/v1
kind: RuntimeClass
metadata: {name: gvisor}
handler: runsc
EOF
$KC delete pod probe-runc probe-gvisor --ignore-not-found --wait=true >/dev/null
$KC apply -f - <<'EOF'
apiVersion: v1
kind: Pod
metadata: {name: probe-runc}
spec:
  restartPolicy: Never
  containers: [{name: p, image: "sandbox-probe:local", imagePullPolicy: Never}]
---
apiVersion: v1
kind: Pod
metadata: {name: probe-gvisor}
spec:
  runtimeClassName: gvisor
  restartPolicy: Never
  containers: [{name: p, image: "sandbox-probe:local", imagePullPolicy: Never}]
EOF

echo "waiting for both pods to finish..."
sleep 25
echo "########## runc ##########"
$KC logs probe-runc
echo
echo "########## gVisor ##########"
$KC logs probe-gvisor
echo
echo "runsc version on the node:"
docker exec "$NODE" runsc --version | head -2
