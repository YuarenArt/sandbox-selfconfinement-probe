# Self-confinement primitives inside sandboxed runtimes

What can a process use to restrict **itself**, once it is already inside a sandbox?
Measured under `runc`, under gVisor, and inside a Kata guest kernel.

The question comes from AI agent harnesses. A harness that runs model-generated code
holds credentials that code must not reach, so it wants to drop privileges for the
duration of one step. Tools like OpenAI Codex and [`nono`](https://github.com/stacklok/nono)
use Landlock for this, and [google/gvisor#13439](https://github.com/google/gvisor/issues/13439)
exists because Landlock does not work inside gVisor.

Everything here probes open-source software on one laptop. No proprietary data.

## Results

Measured **2026-09-08**. Raw output for each column is in [`results/`](results/).

**Restricting which paths the process may reach**

| | host | runc | runc hardened | gVisor | gVisor hardened | Kata guest |
|---|---|---|---|---|---|---|
| `landlock_create_ruleset` (ABI) | 4 | 4 | 4 | **ENOSYS** | **ENOSYS** | 7 |
| Landlock denies a readable file | yes | yes | yes | **ENOSYS** | **ENOSYS** | yes |
| userns + rbind + `pivot_root` jail | yes | yes | **EPERM** | **yes** | **yes** | EINVAL¹ |
| `chroot` | EPERM | yes | EPERM | yes | EPERM | yes |
| `openat2` + `RESOLVE_BENEATH` | yes | yes | yes | **yes**² | yes | yes |
| `open_tree(OPEN_TREE_CLONE)` | EPERM | EPERM | EPERM | EPERM | EPERM | yes |

**Mediating syscalls as they happen**

| | host | runc | runc hardened | gVisor | gVisor hardened | Kata guest |
|---|---|---|---|---|---|---|
| `seccomp-bpf` filter on self | yes | yes | yes | yes | yes | yes |
| `SECCOMP_GET_NOTIF_SIZES` | yes | yes | yes | **EINVAL** | **EINVAL** | yes |
| `SECCOMP_FILTER_FLAG_NEW_LISTENER` | yes | yes | yes | **EINVAL** | **EINVAL** | yes |
| `SECCOMP_RET_TRAP` mediation | yes | yes | yes | **yes** | **yes** | yes |
| `ptrace` syscall-stop + registers | yes | yes | yes | yes | yes | yes |
| `pidfd_open` + `pidfd_getfd` | yes | yes | EPERM | yes | yes | yes |

**Observing, and dropping privilege**

| | host | runc | runc hardened | gVisor | gVisor hardened | Kata guest |
|---|---|---|---|---|---|---|
| `inotify` | yes | yes | yes | yes | yes | yes |
| `fanotify_init` | EPERM | EPERM | EPERM | **ENOSYS** | **ENOSYS** | yes |
| `PR_SET_SECUREBITS` | EPERM | yes | EPERM | yes | EPERM | yes |
| `PR_SET_SYSCALL_USER_DISPATCH` | yes | yes | yes | **EINVAL** | **EINVAL** | yes |

¹ Every step of the jail succeeds and `pivot_root` then returns `EINVAL`: the guest
root here is an initramfs, which `pivot_root` refuses by design. That is a property
of how the guest boots, not of the kernel.
² `ENOSYS` on `release-20260817.0`, works on `release-20260831.0`. See below.

## What this says about gVisor

**Three mechanisms are missing, and the source says why.** Landlock: syscalls 444–446
are absent from the amd64 table in `pkg/sentry/syscalls/linux/linux64.go`, which ends
at `441: epoll_pwait2`; unregistered numbers reach `Missing` and return `ENOSYS`.
seccomp user notification: `sys_seccomp.go` accepts only `SECCOMP_SET_MODE_FILTER`
and only the `TSYNC` flag, and the action switch in `kernel/seccomp.go` has no
`SECCOMP_RET_USER_NOTIF` case. Syscall user dispatch: `sys_prctl.go` does not handle
`PR_SET_SYSCALL_USER_DISPATCH`, so it falls into a `default` returning `EINVAL`.
Those are the first two things an agent harness reaches for, and the obvious third.

**Path confinement, however, works.** An earlier version of this README claimed it
did not. That was wrong. A bubblewrap-style jail — user namespace, private mount
tree, recursive read-write and read-only binds, `pivot_root`, capability bounding set
dropped — builds and holds, unprivileged. `openat2` with `RESOLVE_BENEATH` gives
kernel-enforced, TOCTOU-safe path restriction on the newer release.

**Dynamic mediation works too, and it is not expensive.** A `SECCOMP_RET_TRAP` filter
cannot dereference the path pointer, but the `SIGSYS` handler it hands control to runs
in the same address space and can. That handler confines generated code that
misbehaves; it is not a boundary against an adversary sharing its memory.

So the defensible claim is narrow:

> gVisor has no **Landlock equivalent** — no unprivileged, composable, per-step,
> kernel-revocable path policy. The substitutes work, but each costs a one-time
> rebuild of the mount namespace, none tightens per step without a new process, and
> none revokes descriptors opened before the jail. Nor is there synchronous mediation
> whose verdict lives outside the workload's own address space, which is what
> `SECCOMP_RET_USER_NOTIF` would give.

## Two things that are easy to miss

**The pod's security context decides more than the runtime does.** In the hardened
pod the jail fails under `runc` — `unshare(CLONE_NEWUSER)` returns `EPERM`, because
the `RuntimeDefault` seccomp profile blocks it — and succeeds under gVisor in the very
same spec, because runsc does not apply the pod's seccomp profile by default. Read the
two hardened columns together before concluding anything about a runtime.

**The surface moves between releases.** `openat2` with `RESOLVE_BENEATH` returns
`ENOSYS` on `release-20260817.0` and works on `release-20260831.0`, two weeks apart.
Both runs are in `results/`, and the diff between them is that one line. A table like
this is a dated observation, not a property.

## Versions

| | |
|---|---|
| host kernel | 6.8.0-138-generic, Ubuntu 22.04, `CONFIG_SECURITY_LANDLOCK=y` |
| gVisor | `runsc release-20260831.0`, platform systrap; `release-20260817.0` kept for comparison |
| Kata | kata-static 4.1.0, guest kernel `vmlinux-6.18.35-202`, qemu 11.0.1 |
| Kubernetes | kind v0.27.0, node image `kindest/node:v1.32.2` |
| compiler | gcc 11.4.0, static build |

The Landlock ABI number tracks the kernel version, not the runtime: ABI 4 is 6.7+,
ABI 7 is 6.15+, ABI 8 arrives in 7.0. The host reports 4 because it runs 6.8; the Kata
guest reports 7 because it runs 6.18. That a guest can be *newer* than its host is the
interesting part, and it follows from the guest kernel being independent — not from
Kata being "stronger". Landlock is in that guest because it was switched on
deliberately, in [kata-containers#13087](https://github.com/kata-containers/kata-containers/pull/13087),
released in 3.32.0.

## Reproducing

```sh
./run/host.sh                     # host baseline, as your normal user
./run/kind-gvisor.sh              # kind cluster + pinned runsc, four pods
./run/kata-qemu.sh /path/to/kata  # Kata guest kernel, probe as PID 1
```

The Kata bundle is `kata-static-4.1.0-amd64.tar.zst` from the
[kata-containers releases](https://github.com/kata-containers/kata-containers/releases);
extract it with `tar -I zstd -xf` and pass the directory containing `opt/kata`. It
needs read-write access to `/dev/kvm`.

The probe prints `uname` first, and that is the check that the runtime is what it
claims to be: gVisor reports `4.19.0-gvisor`. A `RuntimeClass` named `gvisor` whose
handler is actually `runc` is a common and silent misconfiguration, and it makes every
row of a table like this meaningless.

## How the probe is built

Raw syscalls only, no kernel headers, one static binary for every environment. Each
check names the step that failed and its `errno`, because the step is the finding: a
Landlock ruleset that installs but does not deny is worse than none.

Where a check proves a denial, it first proves the same operation succeeds without the
restriction. Otherwise a missing file passes for a working policy — a failure mode this
probe actually had.

Run as PID 1 with no `/proc` mounted, it mounts `/proc`, prints, and powers off. That
is how the Kata guest kernel is measured with no orchestration around it. It
deliberately does not take that path merely because its pid is 1, which is also true
inside every container.

## Not done here

Running gVisor's own merged `landlock_v1..v6` tests with `SKIP_IF(IsRunningOnGvisor())`
removed would be stronger evidence for the Landlock rows than this probe, and it
reports in a form upstream already accepts.

Nothing is timed. That ptrace costs more than a trap handler is true and documented
elsewhere; this repository does not measure it, so it is not claimed here.

## License

MIT.
