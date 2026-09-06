# Self-confinement primitives inside sandboxed runtimes

Which primitives can an application use to **restrict itself** once it is already
running inside a sandbox — under `runc`, under gVisor, and under a Kata guest kernel.

This matters for AI agent harnesses. A harness that runs model-generated code holds
credentials the generated code should not reach, so it wants to drop privileges for
the duration of a step. Tools such as OpenAI Codex and `nono` use Landlock for exactly
this. Inside gVisor that mechanism does not exist, and neither does the obvious
fallback.

Everything here is a probe of open-source software on a laptop. No proprietary data.

## Results

Measured **2026-09-06**. Raw output in [`results/`](results/).

| Primitive | host | pod / runc | pod / **gVisor** | **Kata** guest kernel |
|---|---|---|---|---|
| `landlock_create_ruleset` (ABI query) | ABI 4 | ABI 4 | **ENOSYS** | ABI 7 |
| Landlock actually denies `open()` | yes | yes | **ENOSYS** | yes |
| `seccomp-bpf` filter applied to self | yes | yes | yes | yes |
| `SECCOMP_GET_NOTIF_SIZES` | yes | yes | **EINVAL** | yes |
| `SECCOMP_FILTER_FLAG_NEW_LISTENER` | yes | yes | **EINVAL** | yes |
| `pidfd_open` + `pidfd_getfd` | yes | yes | yes | yes |
| `ptrace` syscall-stop + register read | yes | yes | yes | yes |
| `chroot` | — | yes | yes | yes |
| `open_tree` (new mount API) | — | yes | yes | yes |
| `inotify` init + add_watch | — | yes | yes | yes |
| userns + `MS_BIND` + `chroot` | — | **EINVAL** | **EINVAL** | n/a |

Two observations, stated as narrowly as the data allows:

**Under gVisor there is no path-based self-confinement, and no cheap dynamic
mediation either.** Landlock is not implemented; `seccomp-bpf` is available but by
design cannot dereference pointer arguments, so it cannot express "this step may read
only this directory". The mechanism that would let an application build its own
supervisor — seccomp user notification — is also absent. `ptrace` works, but it is
both slower and not TOCTOU-safe for pointer arguments, so it is not an equivalent
substitute.

**This is a property of re-implementing the guest ABI, not of sandbox strength.**
gVisor implements a subset of Linux in user space, so what is missing is missing.
A Kata guest runs a real kernel and therefore exposes the full set — including a
*newer* Landlock ABI than the host, since the guest kernel version is independent of
the host's. Note that Landlock is present in Kata's guest because it was enabled
deliberately (kata-containers PR #13087, release 3.32.0), not as an automatic
consequence of the architecture.

The `userns` row is **not** a runtime difference: it fails identically under both
runtimes and is a property of the pod. See [LIMITATIONS.md](LIMITATIONS.md).

## Versions

| | |
|---|---|
| host kernel | 6.8.0-138-generic, `CONFIG_SECURITY_LANDLOCK=y` |
| gVisor | `runsc release-20260817.0`, platform systrap (default) |
| Kata | kata-static 4.1.0, guest kernel `vmlinux-6.18.35-202`, qemu 11.0.1 |
| Kubernetes | kind v0.27.0, node image `kindest/node:v1.32.2` |

The gVisor result is expected to change: [google/gvisor#13439](https://github.com/google/gvisor/issues/13439)
tracks guest Landlock support, upstream syscall tests are already merged (currently
guarded by `SKIP_IF(IsRunningOnGvisor())`), and implementation work has been claimed.
Treat the table as dated, not as a standing property.

## Reproducing

```sh
make probe                 # static binary, no kernel headers needed
./probe                    # host baseline

./run/kind-gvisor.sh       # kind cluster + real runsc + RuntimeClass, both pods
./run/kata-qemu.sh /path/to/kata   # boot the Kata guest kernel with the probe as PID 1
```

The probe prints `uname` first. That is the check that the runtime is what it claims
to be: gVisor reports `4.19.0-gvisor`. A `RuntimeClass` named `gvisor` whose handler is
actually `runc` is a common and silent misconfiguration, and it makes every row of a
table like this meaningless.

## What the probe checks

Raw syscalls only, no kernel headers, so one static binary runs everywhere.

1. Landlock ABI query, and whether an empty ruleset actually denies `open()`
2. `seccomp-bpf` filter applied to self, verified by the filtered call returning `EPERM`
3. `SECCOMP_GET_NOTIF_SIZES`
4. `SECCOMP_FILTER_FLAG_NEW_LISTENER` (the supervisor fd)
5. `pidfd_open` + `pidfd_getfd` (acting on behalf of a confined process)
6. `ptrace`: syscall-stop reached and registers readable
7. unprivileged userns + `MS_PRIVATE` + bind mount + `chroot`
8. `chroot` alone
9. `open_tree`
10. `inotify`

Each check reports the failing step and `errno`, not just pass/fail, because the step
matters: a Landlock ruleset that installs but does not deny is worse than none.

Run as PID 1 the probe mounts `/proc`, prints, and powers off — that is how the Kata
guest kernel is measured without any orchestration around it.

## Not done yet

Running gVisor's own merged `landlock_v1..v6` tests with `SKIP_IF(IsRunningOnGvisor())`
removed would be stronger evidence than this probe for the Landlock rows, and it
reports in a form upstream already accepts. It has not been done here.

## License

MIT.
