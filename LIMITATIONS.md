# Limitations

What this measurement does not show. Read before citing any row.

## The Kata column is a guest kernel, not Kata

The Kata result was produced by booting Kata's shipped guest kernel directly in QEMU
with the probe as PID 1. There is no `kata-agent`, no containerd, no Kubernetes.

Running the probe through the full Kata path was attempted and abandoned: inside a kind
node the runtime first failed on systemd/dbus for cgroups, and after that was fixed it
failed on network setup (`failed to handle network / get entity from netns`). Those are
artifacts of running Kata inside a container, not statements about Kata.

So the column answers "what does Kata's guest kernel provide", which is the question
that matters here, but it does **not** answer "what does a Kata container provide".
The agent may restrict things further — the shipped `runtime-rs` config has
`disable_guest_seccomp = true`, which concerns delivery of the container's OCI seccomp
profile into the guest and not the application's ability to filter itself, but the
distinction has not been verified end to end.

## The userns row is a property of the pod, not of the runtime

`unshare(CLONE_NEWUSER)` succeeds inside the pod, but the subsequent bind mount fails
with `EINVAL` — identically under runc and under gVisor. The standard `unshare(1)` tool
fails the same way in the same pod, so this is not a bug in the probe.

Two earlier versions of this check were wrong: the first did not make the mount
namespace root private, the second did not write `uid_map`. Both are fixed; the result
did not change.

More importantly, this row says nothing about the mechanism Kubernetes actually
provides for this. `hostUsers: false` is enabled by default since Kubernetes 1.33 and
went GA in 1.36. The cluster used here is 1.32.2, which predates that default. An
attempt to test `hostUsers: false` on a 1.33 cluster failed at pod creation with
`error mounting "sysfs" to rootfs at "/sys": operation not permitted`, which is a kind
limitation: a kind node is itself a container, and a nested user namespace there cannot
mount sysfs. Settling this row requires a real node.

## kind is not a node

Every Kubernetes row was measured inside a kind node, which is a Docker container. The
"pod / runc" column is therefore container-in-container. The bias is unfavourable in a
subtle way: kind nodes are privileged, so the environment is *more* permissive than a
production node is likely to be. Some `yes` results here may be `EPERM` on a real node
with a restrictive `seccompProfile`, a reduced capability set, or a non-root uid.

The pod spec used is minimal — no `securityContext`, no seccomp profile, default
capabilities. Results under a hardened pod spec will differ.

## Single point on every other axis

One runsc release, one platform (systrap; the KVM platform was not tested), one host
kernel, one architecture (x86-64), one run per configuration. Nothing here is a
statistical claim.

## Presence, not semantics

The probe checks that a primitive exists and, where cheap, that it has an observable
effect. It does not test conformance. "Landlock works" here means an empty ruleset
denied one `open()`; it does not mean the implementation matches Linux semantics for
reparenting, truncation, ioctl restriction, or scoping. For that, gVisor's own merged
`landlock_v1..v6` tests are the right instrument, and they have not been run.

## Not verified against source

`ENOSYS` and `EINVAL` are what the kernel returned. Whether the cause is what one would
guess from reading gVisor's syscall table has not been checked against the source for
every row.
