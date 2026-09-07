# Self-confinement primitives inside sandboxed runtimes

Which primitives can an application use to restrict **itself**, once it is already
running inside a sandbox — under `runc`, under gVisor, and inside a Kata guest kernel.

This matters for AI agent harnesses. A harness that runs model-generated code holds
credentials that code should not reach, so it wants to drop privileges for the
duration of a step. Tools such as OpenAI Codex and [`nono`](https://github.com/stacklok/nono)
use Landlock for exactly this, and [google/gvisor#13439](https://github.com/google/gvisor/issues/13439)
exists because it does not work inside gVisor.

Everything here probes open-source software on one laptop. No proprietary data.

## Results

Measured **2026-09-07**. Raw output for every column is in [`results/`](results/).

| Primitive | host | pod / runc | pod / runc hardened | pod / gVisor | pod / gVisor hardened | Kata guest |
|---|---|---|---|---|---|---|
| `landlock_create_ruleset` (ABI) | 4 | 4 | 4 | **ENOSYS** | **ENOSYS** | 7 |
| Landlock denies a readable file | yes | yes | yes | **ENOSYS** | **ENOSYS** | yes |
| `seccomp-bpf` filter on self | yes | yes | yes | yes | yes | yes |
| `SECCOMP_GET_NOTIF_SIZES` | yes | yes | yes | **EINVAL** | **EINVAL** | yes |
| `SECCOMP_FILTER_FLAG_NEW_LISTENER` | yes | yes | yes | **EINVAL** | **EINVAL** | yes |
| `SECCOMP_RET_TRAP` mediation | yes | yes | yes | **yes** | **yes** | yes |
| `pidfd_open` + `pidfd_getfd` | yes | yes | EPERM | yes | yes | yes |
| `ptrace` syscall-stop + registers | yes | yes | yes | yes | yes | yes |
| userns + rbind + `pivot_root` jail | yes | yes | **EPERM** | **yes** | **yes** | EINVAL¹ |
| `chroot` | EPERM | yes | EPERM | yes | EPERM | yes |
| `open_tree(OPEN_TREE_CLONE)` | EPERM | EPERM | EPERM | EPERM | EPERM | yes |
| `openat2` + `RESOLVE_BENEATH` | yes | yes | yes | **yes**² | yes | yes |
| `inotify` | yes | yes | yes | yes | yes | yes |
| `fanotify_init` | EPERM | EPERM | EPERM | **ENOSYS** | **ENOSYS** | yes |
| `PR_SET_SECUREBITS` | EPERM | yes | EPERM | yes | EPERM | yes |
| `PR_SET_SYSCALL_USER_DISPATCH` | yes | yes | yes | **EINVAL** | **EINVAL** | yes |

¹ Every step of the jail succeeds and `pivot_root` then returns `EINVAL`: the guest
root here is an initramfs, and `pivot_root` refuses that by design. This is a
property of how the guest is booted, not of the kernel.
² `ENOSYS` on `release-20260817.0`, works on `release-20260831.0` — see below.

## What this does and does not say about gVisor

**What is missing.** Landlock is not implemented: syscalls 444–446 are absent from
the amd64 table in `pkg/sentry/syscalls/linux/linux64.go`, which ends at
`441: epoll_pwait2`, and unregistered numbers go through `Missing` to `ENOSYS`.
seccomp user notification is not implemented either: `sys_seccomp.go` accepts only
`SECCOMP_SET_MODE_FILTER` and only the `TSYNC` flag, and the action switch in
`kernel/seccomp.go` has no `SECCOMP_RET_USER_NOTIF` case. `PR_SET_SYSCALL_USER_DISPATCH`
is not handled by `sys_prctl.go` and falls into a `default` that returns `EINVAL`.
So the two mechanisms an agent harness would reach for first, and the obvious
third, are all unavailable.

**What is not missing, contrary to what an earlier version of this README claimed.**
Path confinement is entirely possible under gVisor. A bubblewrap-style jail — user
namespace, private mount tree, recursive read-write and read-only binds,
`pivot_root`, capability bounding set dropped — builds and holds, unprivileged, and
`openat2` with `RESOLVE_BENEATH` gives kernel-enforced, TOCTOU-safe path
restriction on the newer release. Dynamic mediation is possible too and it is not
expensive: the `SECCOMP_RET_TRAP` filter cannot dereference the path pointer, but
the `SIGSYS` handler it hands control to runs in the same address space and can.

So the defensible claim is narrow:

> gVisor has no **Landlock equivalent** — no unprivileged, composable, per-step,
> kernel-revocable path policy. The substitutes work, but each costs a one-time
> rebuild of the mount namespace, none can be tightened per step without a new
> process, and none revokes file descriptors opened before the jail. And there is
> no synchronous mediation whose verdict lives outside the workload's own address
> space, which is what `SECCOMP_RET_USER_NOTIF` would give.

## Two findings that are easy to miss

**The pod's security context decides more than the runtime does.** In the hardened
pod the jail route fails under `runc` — `unshare(CLONE_NEWUSER)` returns `EPERM`,
because the `RuntimeDefault` seccomp profile blocks it — and succeeds under gVisor
in the same spec. runsc does not apply the pod's seccomp profile by default. Read
the two hardened columns side by side before concluding anything about a runtime.

**The surface moves between releases.** `openat2` with `RESOLVE_BENEATH` returns
`ENOSYS` on `release-20260817.0` and works on `release-20260831.0`, two weeks apart.
Both runs are in `results/`, and the diff between them is exactly that one line.
Any table like this one is a dated observation, not a property.

## Versions

| | |
|---|---|
| host kernel | 6.8.0-138-generic, Ubuntu 22.04, `CONFIG_SECURITY_LANDLOCK=y` |
| gVisor | `runsc release-20260831.0`, platform systrap (default); `release-20260817.0` kept for comparison |
| Kata | kata-static 4.1.0, guest kernel `vmlinux-6.18.35-202`, qemu 11.0.1 |
| Kubernetes | kind v0.27.0, node image `kindest/node:v1.32.2` |
| compiler | gcc 11.4.0, static build |

Landlock ABI is a function of the kernel version, not of the runtime: ABI 4 is
6.7+, ABI 7 is 6.15+, ABI 8 arrives in 7.0. The host reports 4 because it runs
6.8; the Kata guest reports 7 because it runs 6.18. That the guest can be *newer*
than the host is the interesting part, and it is a consequence of the guest kernel
being independent — not of Kata being "stronger". Landlock is in Kata's guest
because it was turned on deliberately, in
[kata-containers#13087](https://github.com/kata-containers/kata-containers/pull/13087),
released in 3.32.0.

## Reproducing

```sh
./run/host.sh                     # host baseline, as your normal user
./run/kind-gvisor.sh              # kind cluster + pinned runsc, four pods
./run/kata-qemu.sh /path/to/kata  # Kata guest kernel with the probe as PID 1
```

The Kata bundle is `kata-static-4.1.0-amd64.tar.zst` from the
[kata-containers releases](https://github.com/kata-containers/kata-containers/releases);
extract it with `tar -I zstd -xf`, and pass the directory that contains `opt/kata`.
It needs read-write access to `/dev/kvm`.

The probe prints `uname` first, and that is the check that the runtime is what it
claims to be: gVisor reports `4.19.0-gvisor`. A `RuntimeClass` named `gvisor` whose
handler is actually `runc` is a common and silent misconfiguration, and it makes
every row of a table like this meaningless.

## What the probe checks

Raw syscalls only, no kernel headers, one static binary for every environment.
Each check names the step that failed and its `errno`, because the step matters: a
Landlock ruleset that installs but does not deny is worse than none.

Where a check proves a denial it first proves the same operation succeeds without
the restriction. Otherwise a missing file passes for a working policy — which is a
real failure mode, not a hypothetical one.

Run as PID 1 with no `/proc` mounted, the probe mounts `/proc`, prints, and powers
off. That is how the Kata guest kernel is measured with no orchestration around it.
It deliberately does **not** take that path merely because its pid is 1, which is
also true inside every container.

## Not done yet

Running gVisor's own merged `landlock_v1..v6` tests with `SKIP_IF(IsRunningOnGvisor())`
removed would be better evidence than this probe for the Landlock rows, and it
reports in a form upstream already accepts.

No timings are measured here. "ptrace is more expensive than a trap handler" is
true and stated elsewhere in the literature, but this repository does not measure
it, so it is not claimed as a result.

## License

MIT.
