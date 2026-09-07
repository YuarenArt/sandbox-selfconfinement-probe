# Limitations

What this measurement does not show. Read before citing any row.

## The columns are not equally privileged

Four different privilege levels appear in one table, and several rows differ
because of that rather than because of the runtime:

- **host** runs as the invoking unprivileged user. `chroot`, `OPEN_TREE_CLONE`
  and `fanotify_init` want capabilities a normal user does not have, so they fail
  there and that says nothing about the host kernel.
- **pod / runc** and **pod / gVisor** run as uid 0 with the default container
  capability set and no seccomp profile.
- **hardened** pods run as uid 1000 with `capabilities: drop: [ALL]`,
  `allowPrivilegeEscalation: false` and `seccompProfile: RuntimeDefault`.
- **Kata guest** is the most privileged environment of all: PID 1 in an
  initramfs, full capability set, no seccomp, no LSM policy, no OCI config.

Comparing a row across columns is only meaningful when the privilege level is the
same. The two hardened columns are the pair to read side by side.

## The Kata column is a guest kernel, not Kata

It was produced by booting Kata's shipped guest kernel directly in QEMU with the
probe as PID 1. There is no `kata-agent`, no containerd, no Kubernetes.

Running the probe through the full Kata path was attempted and abandoned: inside
a kind node it first failed on systemd/dbus for cgroups, and after that was fixed
it failed on network setup. Those are artifacts of running Kata inside a
container, not statements about Kata.

So the column answers "what does Kata's guest kernel provide", which is the
question this repository asks, but it does **not** answer "what does a Kata
container provide". The agent may restrict things further; the shipped
`runtime-rs` config has `disable_guest_seccomp = true`, which concerns delivery of
the container's OCI seccomp profile into the guest rather than the application's
ability to filter itself, but that distinction has not been verified end to end.

The `pivot_root` failure in that column is likewise environmental: `pivot_root`
refuses to operate when the current root is an initramfs. Every preceding step of
the jail succeeded, including the recursive binds and the read-only remount.

## kind is not a node

Every Kubernetes row was measured inside a kind node, which is itself a Docker
container. The bias is unfavourable in a subtle way: kind nodes are privileged, so
the environment is *more* permissive than a production node is likely to be. Some
`yes` results here may be `EPERM` on a real node under a different container
runtime, LSM policy or kernel.

## One point on every other axis

One host kernel, one architecture (x86-64 — the probe refuses to build elsewhere),
one gVisor platform (systrap; the KVM platform was not tested), one run per
configuration. Two gVisor releases were compared, and they already differ. Nothing
here is a statistical claim.

## Presence, not conformance

The probe checks that a primitive exists and that it has an observable effect. It
does not test conformance. "Landlock works" means an empty ruleset denied one
`open` with `EACCES`; it does not mean the implementation matches Linux semantics
for reparenting, truncation, ioctl restriction or scoping. gVisor's own merged
`landlock_v1..v6` tests are the right instrument for that, and they have not been
run here.

Two rows are narrower than their names suggest. `seccomp_user_notif` only checks
that a listener fd can be obtained, not that notifications can be received and
answered. `SECCOMP_RET_TRAP` mediation is demonstrated against a cooperative
single-threaded workload; the handler lives in the workload's own address space,
so it confines generated code that misbehaves, not an adversary that is trying to
escape.

## What the jail does not do

`pivot_root` does not invalidate file descriptors opened before the jail was
entered: a directory fd captured earlier still resolves. Landlock does not revoke
open descriptors either, so this is a property of the whole class rather than of
the substitute, but a harness relying on either has to close them itself.

## Three bugs this probe had, and what they cost

Recorded because each of them produced a confident, wrong row, and the same
classes of error are easy to repeat:

1. **No `MS_PRIVATE` on the new mount namespace.** Bind mounts failed with
   `EINVAL`, which was read as a property of the pod.
2. **No `uid_map` written after `unshare(CLONE_NEWUSER)`.** Mounting stayed
   refused, which was read the same way.
3. **A non-recursive bind of `/etc`.** Every `/etc` in a container has three bind
   mounts under it (`hosts`, `hostname`, `resolv.conf`); after `unshare` they are
   locked, and a non-recursive bind of a source with locked children returns
   `EINVAL`. The control that was supposed to catch this — running `unshare(1)`
   by hand — used `mount --bind`, so it reproduced the same bug instead of
   testing for it. With `mount --rbind` the operation succeeds under both
   runtimes.

The lesson that generalises: an `errno` reproduced by a second tool is not a
control if the second tool makes the same mistake.

## Not verified against source

`ENOSYS` and `EINVAL` are what the runtime returned. For the Landlock, seccomp and
`PR_SET_SYSCALL_USER_DISPATCH` rows the cause was confirmed by reading gVisor's
syscall table and handlers. For the remaining rows it was not.
