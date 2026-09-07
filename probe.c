// Which primitives can an application use to restrict *itself* once it is
// already inside a sandbox. Raw syscalls only, no kernel headers, so one static
// binary runs on the host, in a pod under any runtime, and as PID 1 in a guest
// kernel booted directly in QEMU.
//
// Every check reports the step that failed and its errno. Where a check proves
// a denial, it first proves the same operation succeeds without the restriction
// — otherwise a missing file is indistinguishable from a working policy.
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <sched.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/prctl.h>
#include <sys/ptrace.h>
#include <sys/reboot.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/user.h>
#include <sys/utsname.h>
#include <sys/wait.h>
#include <ucontext.h>
#include <unistd.h>

#if !defined(__x86_64__)
#error "x86-64 only: syscall numbers and user_regs_struct.orig_rax are arch-specific"
#endif

#define NR_landlock_create_ruleset 444
#define NR_landlock_restrict_self  446
#define NR_seccomp                 317
#define NR_pidfd_open              434
#define NR_pidfd_getfd             438
#define NR_openat2                 437
#define NR_open_tree               428
#define NR_move_mount              429
#define NR_pivot_root              155
#define NR_fanotify_init           300

#define LANDLOCK_CREATE_RULESET_VERSION (1U << 0)
#define LANDLOCK_ACCESS_FS_READ_FILE    (1ULL << 2)

#define SECCOMP_SET_MODE_FILTER          1
#define SECCOMP_GET_NOTIF_SIZES          3
#define SECCOMP_FILTER_FLAG_NEW_LISTENER (1UL << 3)
#define SECCOMP_RET_ERRNO                0x00050000U
#define SECCOMP_RET_TRAP                 0x00030000U
#define SECCOMP_RET_USER_NOTIF           0x7fc00000U
#define SECCOMP_RET_ALLOW                0x7fff0000U

#define RESOLVE_BENEATH         0x08
#define OPEN_TREE_CLONE         1
#define MOVE_MOUNT_F_EMPTY_PATH 0x00000004

#define PR_SET_SECUREBITS_            28
#define PR_SET_SYSCALL_USER_DISPATCH_ 59

struct landlock_ruleset_attr {
	uint64_t handled_access_fs;
};

struct open_how {
	uint64_t flags;
	uint64_t mode;
	uint64_t resolve;
};

struct sock_filter {
	uint16_t code;
	uint8_t jt;
	uint8_t jf;
	uint32_t k;
};

struct sock_fprog {
	unsigned short len;
	struct sock_filter *filter;
};

struct notif_sizes {
	uint16_t seccomp_notif;
	uint16_t seccomp_notif_resp;
	uint16_t seccomp_data;
};

static void ok(const char *name, const char *detail) {
	printf("%-24s PASS   %s\n", name, detail);
}

static void fail(const char *name, const char *detail) {
	printf("%-24s FAIL   %s\n", name, detail);
}

static void section(const char *title) {
	printf("\n-- %s --\n", title);
}

static const char *errname(int e) {
	switch (e) {
	case ENOSYS: return "ENOSYS (not implemented)";
	case EPERM: return "EPERM";
	case EACCES: return "EACCES";
	case EINVAL: return "EINVAL";
	case ENOENT: return "ENOENT";
	case EOPNOTSUPP: return "EOPNOTSUPP";
	case EXDEV: return "EXDEV";
	case ELOOP: return "ELOOP";
	case EROFS: return "EROFS";
	case EBADF: return "EBADF";
	default: return strerror(e);
	}
}

// Child verdicts travel through the exit code: 0 means the property held,
// 1 means the mechanism ran but did not confine, and 2+n names the step that
// failed. errno is not encoded, because values above 127 would not survive.
#define ENC_OK       0
#define ENC_NEGATIVE 1
#define ENC_STAGE(n) (2 + (n))

static int child_status(pid_t pid, int *code) {
	int st = 0;
	if (waitpid(pid, &st, 0) != pid) return -1;
	if (WIFSIGNALED(st)) { *code = -WTERMSIG(st); return 0; }
	if (!WIFEXITED(st)) return -1;
	*code = WEXITSTATUS(st);
	return 0;
}

static void report_child(const char *name, pid_t pid, const char *pass_detail,
			 const char *neg_detail, const char *const *stages, int nstages) {
	int code = 0;
	char buf[192];
	if (child_status(pid, &code) < 0) { fail(name, "waitpid failed"); return; }
	if (code < 0) {
		snprintf(buf, sizeof(buf), "child killed by signal %d", -code);
		fail(name, buf);
	} else if (code == ENC_OK) {
		ok(name, pass_detail);
	} else if (code == ENC_NEGATIVE) {
		fail(name, neg_detail);
	} else if (code >= 40) {
		// Codes above 40 are outcomes, not steps: the mechanism ran to the
		// end and the property it was supposed to give did not hold.
		int s = code - 40;
		fail(name, (s >= 0 && s < nstages) ? stages[s] : "unknown outcome");
	} else {
		int s = code - 2;
		snprintf(buf, sizeof(buf), "%s failed",
			 (s >= 0 && s < nstages) ? stages[s] : "unknown stage");
		fail(name, buf);
	}
}

static int write_file(const char *path, const char *val) {
	int fd = open(path, O_WRONLY);
	if (fd < 0) return -1;
	ssize_t n = write(fd, val, strlen(val));
	close(fd);
	return (n == (ssize_t)strlen(val)) ? 0 : -1;
}

static int make_file(const char *path, const char *content) {
	int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
	if (fd < 0) return -1;
	ssize_t n = write(fd, content, strlen(content));
	close(fd);
	return n < 0 ? -1 : 0;
}

// Everything happens in a work directory the probe chdir's into, so the checks
// use relative paths and do not depend on where that directory ended up. The
// control file is the exception: after pivot_root a relative name would resolve
// inside the new root, and the point of that check is that it must not.
static char ctrl_path[256];
static char workdir_abs[160];

static int enter_userns(void) {
	uid_t u = getuid();
	gid_t g = getgid();
	char map[64];
	if (unshare(CLONE_NEWUSER) != 0) return 1;
	if (write_file("/proc/self/setgroups", "deny") != 0) return 2;
	snprintf(map, sizeof(map), "0 %u 1", u);
	if (write_file("/proc/self/uid_map", map) != 0) return 2;
	snprintf(map, sizeof(map), "0 %u 1", g);
	if (write_file("/proc/self/gid_map", map) != 0) return 2;
	return 0;
}

// 1. Landlock ABI query.
static void probe_landlock_abi(void) {
	long r = syscall(NR_landlock_create_ruleset, NULL, 0, LANDLOCK_CREATE_RULESET_VERSION);
	char buf[128];
	if (r >= 0) {
		snprintf(buf, sizeof(buf), "ABI version %ld", r);
		ok("landlock_abi", buf);
	} else {
		snprintf(buf, sizeof(buf), "errno=%s", errname(errno));
		fail("landlock_abi", buf);
	}
}

// 2. Landlock enforcing. The denial must be EACCES specifically.
static void probe_landlock_enforce(void) {
	static const char *stages[] = { "control open", "create_ruleset", "no_new_privs", "restrict_self" };
	pid_t pid = fork();
	if (pid < 0) { fail("landlock_enforce", "fork failed"); return; }
	if (pid == 0) {
		int c = open(ctrl_path, O_RDONLY);
		if (c < 0) _exit(ENC_STAGE(0));
		close(c);
		struct landlock_ruleset_attr attr = { .handled_access_fs = LANDLOCK_ACCESS_FS_READ_FILE };
		long fd = syscall(NR_landlock_create_ruleset, &attr, sizeof(attr), 0);
		if (fd < 0) _exit(ENC_STAGE(1));
		if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0) _exit(ENC_STAGE(2));
		if (syscall(NR_landlock_restrict_self, (int)fd, 0) != 0) _exit(ENC_STAGE(3));
		errno = 0;
		int f = open(ctrl_path, O_RDONLY);
		_exit((f < 0 && errno == EACCES) ? ENC_OK : ENC_NEGATIVE);
	}
	report_child("landlock_enforce", pid, "empty ruleset denied a readable file with EACCES",
		     "ruleset installed but the file stayed readable", stages, 4);
}

// 3. A seccomp filter the workload applies to itself. An unfiltered call is
// checked too, so a blanket EPERM from elsewhere cannot pass for selectivity.
static void probe_seccomp_filter(void) {
	static const char *stages[] = { "no_new_privs", "seccomp(SET_MODE_FILTER)" };
	pid_t pid = fork();
	if (pid < 0) { fail("seccomp_filter", "fork failed"); return; }
	if (pid == 0) {
		struct sock_filter code[] = {
			{ 0x20, 0, 0, 0x00000000 },
			{ 0x15, 0, 1, __NR_getpid },
			{ 0x06, 0, 0, SECCOMP_RET_ERRNO | 1 },
			{ 0x06, 0, 0, SECCOMP_RET_ALLOW },
		};
		struct sock_fprog prog = { .len = 4, .filter = code };
		if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0) _exit(ENC_STAGE(0));
		if (syscall(NR_seccomp, SECCOMP_SET_MODE_FILTER, 0, &prog) != 0) _exit(ENC_STAGE(1));
		errno = 0;
		long filtered = syscall(__NR_getpid);
		int filtered_ok = (filtered < 0 && errno == EPERM);
		long allowed = syscall(__NR_getppid);
		_exit((filtered_ok && allowed > 0) ? ENC_OK : ENC_NEGATIVE);
	}
	report_child("seccomp_filter", pid, "getpid filtered to EPERM, getppid still allowed",
		     "filter installed but not selectively enforced", stages, 2);
}

// 4. Cheap probe of user-notification support; needs no privileges.
static void probe_notif_sizes(void) {
	struct notif_sizes sizes;
	memset(&sizes, 0, sizeof(sizes));
	long r = syscall(NR_seccomp, SECCOMP_GET_NOTIF_SIZES, 0, &sizes);
	char buf[160];
	if (r == 0) {
		snprintf(buf, sizeof(buf), "notif=%u resp=%u data=%u",
			 sizes.seccomp_notif, sizes.seccomp_notif_resp, sizes.seccomp_data);
		ok("seccomp_notif_sizes", buf);
	} else {
		snprintf(buf, sizeof(buf), "errno=%s", errname(errno));
		fail("seccomp_notif_sizes", buf);
	}
}

// 5. The supervisor fd. A plain filter goes in first, so "this flag is
// unsupported" is distinguishable from "no filter installs at all".
static void probe_notif_listener(void) {
	int pipefd[2];
	if (pipe(pipefd) != 0) { fail("seccomp_user_notif", "pipe failed"); return; }
	pid_t pid = fork();
	if (pid < 0) { fail("seccomp_user_notif", "fork failed"); return; }
	if (pid == 0) {
		close(pipefd[0]);
		struct sock_filter plain[] = {
			{ 0x20, 0, 0, 0x00000000 },
			{ 0x06, 0, 0, SECCOMP_RET_ALLOW },
		};
		struct sock_filter notif[] = {
			{ 0x20, 0, 0, 0x00000000 },
			{ 0x15, 0, 1, __NR_getpid },
			{ 0x06, 0, 0, SECCOMP_RET_USER_NOTIF },
			{ 0x06, 0, 0, SECCOMP_RET_ALLOW },
		};
		struct sock_fprog plain_prog = { .len = 2, .filter = plain };
		struct sock_fprog notif_prog = { .len = 4, .filter = notif };
		int res;
		prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
		if (syscall(NR_seccomp, SECCOMP_SET_MODE_FILTER, 0, &plain_prog) != 0) {
			res = -1;
		} else {
			long fd = syscall(NR_seccomp, SECCOMP_SET_MODE_FILTER,
					  SECCOMP_FILTER_FLAG_NEW_LISTENER, &notif_prog);
			res = (fd >= 0) ? 0 : errno;
		}
		ssize_t n = write(pipefd[1], &res, sizeof(res));
		(void)n;
		_exit(0);
	}
	close(pipefd[1]);
	int res = -2;
	ssize_t n = read(pipefd[0], &res, sizeof(res));
	close(pipefd[0]);
	waitpid(pid, NULL, 0);
	char buf[160];
	if (n != sizeof(res)) fail("seccomp_user_notif", "child produced no result");
	else if (res == 0) ok("seccomp_user_notif", "listener fd obtained");
	else if (res == -1) fail("seccomp_user_notif", "no filter could be installed at all");
	else {
		snprintf(buf, sizeof(buf), "plain filter ok, NEW_LISTENER errno=%s", errname(res));
		fail("seccomp_user_notif", buf);
	}
}

// 6. SECCOMP_RET_TRAP. The filter itself cannot dereference the path pointer,
// but the SIGSYS handler it hands control to runs in the same address space and
// can. Allowed opens are performed with openat2, which the filter does not
// trap, so the handler does not re-enter itself.
static volatile int trap_hits;

static void sigsys_handler(int sig, siginfo_t *si, void *ucv) {
	(void)sig; (void)si;
	ucontext_t *uc = (ucontext_t *)ucv;
	const char *path = (const char *)uc->uc_mcontext.gregs[REG_RSI];
	trap_hits++;
	if (path && strstr(path, "allowed")) {
		// Performed with open(2), a different syscall number, so the handler
		// does not trip the filter that brought it here. openat2 would be the
		// better choice, but it is not implemented everywhere this runs.
		long fd = syscall(2 /* open */, path, O_RDONLY, 0);
		uc->uc_mcontext.gregs[REG_RAX] = fd;
	} else {
		uc->uc_mcontext.gregs[REG_RAX] = -EACCES;
	}
}

static void probe_seccomp_trap(void) {
	static const char *stages[] = { "prepare files", "sigaction", "no_new_privs", "seccomp" };
	pid_t pid = fork();
	if (pid < 0) { fail("seccomp_ret_trap", "fork failed"); return; }
	if (pid == 0) {
		if (make_file("allowed", "a\n") != 0 ||
		    make_file("denied", "d\n") != 0) _exit(ENC_STAGE(0));
		struct sigaction sa;
		memset(&sa, 0, sizeof(sa));
		sa.sa_sigaction = sigsys_handler;
		sa.sa_flags = SA_SIGINFO | SA_NODEFER;
		if (sigaction(SIGSYS, &sa, NULL) != 0) _exit(ENC_STAGE(1));
		struct sock_filter code[] = {
			{ 0x20, 0, 0, 0x00000000 },
			{ 0x15, 0, 1, __NR_openat },
			{ 0x06, 0, 0, SECCOMP_RET_TRAP },
			{ 0x06, 0, 0, SECCOMP_RET_ALLOW },
		};
		struct sock_fprog prog = { .len = 4, .filter = code };
		if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0) _exit(ENC_STAGE(2));
		if (syscall(NR_seccomp, SECCOMP_SET_MODE_FILTER, 0, &prog) != 0) _exit(ENC_STAGE(3));
		int allowed = open("allowed", O_RDONLY);
		errno = 0;
		int denied = open("denied", O_RDONLY);
		int denied_ok = (denied < 0 && errno == EACCES);
		_exit((allowed >= 0 && denied_ok && trap_hits >= 2) ? ENC_OK : ENC_NEGATIVE);
	}
	report_child("seccomp_ret_trap", pid,
		     "SIGSYS handler read the path and mediated open per path",
		     "trap installed but mediation did not take effect", stages, 4);
}

// 7. Acting on behalf of a confined process. The fd is taken from a child, not
// from self: a process always passes the ptrace access check on itself.
static void probe_pidfd(void) {
	int ready[2], done[2];
	if (pipe(ready) != 0 || pipe(done) != 0) { fail("pidfd", "pipe failed"); return; }
	pid_t pid = fork();
	if (pid < 0) { fail("pidfd", "fork failed"); return; }
	if (pid == 0) {
		char c = 1, w;
		ssize_t n = write(ready[1], &c, 1);
		n = read(done[0], &w, 1);
		(void)n;
		_exit(0);
	}
	close(ready[1]);
	char c;
	ssize_t rn = read(ready[0], &c, 1);
	(void)rn;
	char buf[160];
	long pfd = syscall(NR_pidfd_open, pid, 0);
	if (pfd < 0) {
		snprintf(buf, sizeof(buf), "pidfd_open errno=%s", errname(errno));
		fail("pidfd", buf);
	} else {
		errno = 0;
		long got = syscall(NR_pidfd_getfd, (int)pfd, 1, 0);
		if (got >= 0) {
			ok("pidfd", "pidfd_open + pidfd_getfd against another process work");
			close((int)got);
		} else {
			snprintf(buf, sizeof(buf), "pidfd_open ok, pidfd_getfd errno=%s", errname(errno));
			fail("pidfd", buf);
		}
		close((int)pfd);
	}
	char w = 1;
	ssize_t wn = write(done[1], &w, 1);
	(void)wn;
	waitpid(pid, NULL, 0);
	close(ready[0]); close(done[0]); close(done[1]);
}

// 8. ptrace as an interception point. The stop must be a syscall-stop for the
// expected call, not merely any stop with a readable register set.
static void probe_ptrace_supervisor(void) {
	pid_t pid = fork();
	if (pid < 0) { fail("ptrace_supervisor", "fork failed"); return; }
	if (pid == 0) {
		if (ptrace(PTRACE_TRACEME, 0, NULL, NULL) != 0) _exit(80);
		raise(SIGSTOP);
		syscall(__NR_getpid);
		_exit(0);
	}
	int st = 0;
	char buf[192];
	if (waitpid(pid, &st, 0) < 0) { fail("ptrace_supervisor", "waitpid failed"); return; }
	if (WIFEXITED(st) && WEXITSTATUS(st) == 80) {
		fail("ptrace_supervisor", "PTRACE_TRACEME refused");
		return;
	}
	if (!WIFSTOPPED(st)) { fail("ptrace_supervisor", "child never stopped"); goto reap; }
	if (ptrace(PTRACE_SYSCALL, pid, NULL, NULL) != 0) {
		snprintf(buf, sizeof(buf), "PTRACE_SYSCALL errno=%s", errname(errno));
		fail("ptrace_supervisor", buf);
		goto reap;
	}
	if (waitpid(pid, &st, 0) < 0 || !WIFSTOPPED(st) || WSTOPSIG(st) != SIGTRAP) {
		fail("ptrace_supervisor", "no syscall-stop delivered");
		goto reap;
	}
	struct user_regs_struct regs;
	memset(&regs, 0, sizeof(regs));
	if (ptrace(PTRACE_GETREGS, pid, NULL, &regs) != 0) {
		snprintf(buf, sizeof(buf), "PTRACE_GETREGS errno=%s", errname(errno));
		fail("ptrace_supervisor", buf);
	} else if ((long)regs.orig_rax != __NR_getpid) {
		snprintf(buf, sizeof(buf), "stopped on nr=%lld, expected getpid",
			 (long long)regs.orig_rax);
		fail("ptrace_supervisor", buf);
	} else {
		ok("ptrace_supervisor", "syscall-stop on the expected call, registers readable");
	}
reap:
	kill(pid, SIGKILL);
	waitpid(pid, NULL, 0);
}

// 9. The bubblewrap-style route: user namespace, private tree, a read-write and
// a read-only bind, pivot_root, then capabilities dropped.
//
// Binds are recursive on purpose. A non-recursive bind of a source that has
// locked children fails with EINVAL, and every /etc in a container has three
// (hosts, hostname, resolv.conf), so a non-recursive probe measures the choice
// of source rather than the sandbox.
static void probe_jail(void) {
	static const char *stages[] = {
		"unshare(CLONE_NEWUSER)", "write id maps", "unshare(CLONE_NEWNS)",
		"mount(/, MS_PRIVATE)", "mount(tmpfs)", "build jail tree",
		"bind rw", "bind ro", "remount ro", "bind newroot",
		"pivot_root", "umount oldroot", "no_new_privs",
		"confinement: the outside tree stayed reachable",
		"confinement: the read-only bind was unreadable",
		"confinement: the read-only bind accepted a write",
		"confinement: the read-write bind refused a write",
	};
	// The step that fails is reported with its errno on stderr: pivot_root, for
	// one, is refused outright when the current root is an initramfs, and that
	// is a property of the root filesystem rather than of the sandbox.
#define JAIL_STEP(cond, n)                                                            \
	do {                                                                          \
		if (cond) {                                                           \
			fprintf(stderr, "  userns_jail: %s: %s\n", stages[n],          \
				strerror(errno));                                     \
			_exit(ENC_STAGE(n));                                          \
		}                                                                     \
	} while (0)

	pid_t pid = fork();
	if (pid < 0) { fail("userns_jail", "fork failed"); return; }
	if (pid == 0) {
		int s = enter_userns();
		JAIL_STEP(s != 0, s - 1);
		JAIL_STEP(unshare(CLONE_NEWNS) != 0, 2);
		JAIL_STEP(mount(NULL, "/", NULL, MS_REC | MS_PRIVATE, NULL) != 0, 3);
		// Mounting over the current directory leaves cwd on the old inode,
		// so step back in by absolute path to work inside the tmpfs and
		// leave nothing on the real filesystem.
		JAIL_STEP(mount("none", workdir_abs, "tmpfs", 0, NULL) != 0, 4);
		JAIL_STEP(chdir(workdir_abs) != 0, 4);
		JAIL_STEP(mkdir("root", 0755) != 0 || mkdir("rw", 0755) != 0 ||
			  mkdir("ro", 0755) != 0 || mkdir("root/rw", 0755) != 0 ||
			  mkdir("root/ro", 0755) != 0 || mkdir("root/old", 0755) != 0 ||
			  make_file("ro/marker", "ro\n") != 0, 5);
		// The new root has to become a mount point before anything is bound
		// inside it: a bind takes a snapshot of the tree at that moment, so
		// sub-mounts created earlier would not travel with it.
		JAIL_STEP(mount("root", "root", NULL, MS_BIND, NULL) != 0, 9);
		JAIL_STEP(mount("rw", "root/rw", NULL, MS_BIND | MS_REC, NULL) != 0, 6);
		JAIL_STEP(mount("ro", "root/ro", NULL, MS_BIND | MS_REC, NULL) != 0, 7);
		JAIL_STEP(mount(NULL, "root/ro", NULL, MS_BIND | MS_REMOUNT | MS_RDONLY, NULL) != 0, 8);
		JAIL_STEP(chdir("root") != 0, 9);
		JAIL_STEP(syscall(NR_pivot_root, ".", "old") != 0, 10);
		JAIL_STEP(chdir("/") != 0 || umount2("/old", MNT_DETACH) != 0, 11);
		for (int c = 0; c <= 40; c++) prctl(PR_CAPBSET_DROP, c, 0, 0, 0);
		JAIL_STEP(prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0, 12);
#undef JAIL_STEP

		int outside = open(ctrl_path, O_RDONLY);
		if (outside >= 0) { close(outside); _exit(40 + 13); }
		int romark = open("/ro/marker", O_RDONLY);
		if (romark < 0) {
			fprintf(stderr, "  userns_jail: open(/ro/marker) errno=%s\n", strerror(errno));
			_exit(40 + 14);
		}
		close(romark);
		if (make_file("/ro/should_fail", "x") == 0) _exit(40 + 15);
		if (make_file("/rw/ok", "x") != 0) _exit(40 + 16);
		_exit(ENC_OK);
	}
	report_child("userns_jail", pid,
		     "userns + recursive binds + pivot_root hold: outside gone, ro refuses writes",
		     "jail was built but did not confine", stages, 17);
}

// 10. chroot on its own, with a control on both sides.
static void probe_chroot(void) {
	static const char *stages[] = { "control open", "mkdir", "chroot", "chdir" };
	pid_t pid = fork();
	if (pid < 0) { fail("chroot", "fork failed"); return; }
	if (pid == 0) {
		int c = open(ctrl_path, O_RDONLY);
		if (c < 0) _exit(ENC_STAGE(0));
		close(c);
		if (mkdir("chrootdir", 0755) != 0 && errno != EEXIST) _exit(ENC_STAGE(1));
		if (chroot("chrootdir") != 0) _exit(ENC_STAGE(2));
		if (chdir("/") != 0) _exit(ENC_STAGE(3));
		errno = 0;
		int f = open(ctrl_path, O_RDONLY);
		_exit((f < 0 && errno == ENOENT) ? ENC_OK : ENC_NEGATIVE);
	}
	report_child("chroot", pid, "root changed, the old tree is no longer reachable",
		     "chroot returned success but the old tree stayed visible", stages, 4);
}

// 11. The new mount API. open_tree(flags=0) is little more than an O_PATH open;
// detaching a tree with OPEN_TREE_CLONE is the actual capability.
static void probe_mount_api(void) {
	char buf[160];
	long fd = syscall(NR_open_tree, AT_FDCWD, ".", OPEN_TREE_CLONE);
	if (fd < 0) {
		snprintf(buf, sizeof(buf), "OPEN_TREE_CLONE errno=%s", errname(errno));
		fail("open_tree_clone", buf);
		return;
	}
	if (mkdir("mnt", 0755) != 0 && errno != EEXIST) {
		close((int)fd);
		fail("open_tree_clone", "mkdir for move_mount failed");
		return;
	}
	long r = syscall(NR_move_mount, (int)fd, "", AT_FDCWD, "mnt",
			 MOVE_MOUNT_F_EMPTY_PATH);
	if (r == 0) {
		ok("open_tree_clone", "detached tree cloned and attached with move_mount");
		umount2("mnt", MNT_DETACH);
	} else {
		snprintf(buf, sizeof(buf), "open_tree ok, move_mount errno=%s", errname(errno));
		fail("open_tree_clone", buf);
	}
	close((int)fd);
}

// 12. openat2 resolve flags: a path restriction the kernel enforces on every
// resolution, and the one mechanism here that is TOCTOU-safe by construction.
static void probe_openat2(void) {
	struct open_how how;
	char buf[192];
	int dir = open(".", O_RDONLY | O_DIRECTORY);
	if (dir < 0) { fail("openat2_beneath", "cannot open the work directory"); return; }
	memset(&how, 0, sizeof(how));
	how.flags = O_RDONLY;
	how.resolve = RESOLVE_BENEATH;

	long inside = syscall(NR_openat2, dir, "ctrl", &how, sizeof(how));
	if (inside < 0) {
		snprintf(buf, sizeof(buf), "in-tree open refused, errno=%s", errname(errno));
		fail("openat2_beneath", buf);
		close(dir);
		return;
	}
	close((int)inside);

	errno = 0;
	long escape = syscall(NR_openat2, dir, "../etc/hostname", &how, sizeof(how));
	if (escape >= 0) {
		close((int)escape);
		fail("openat2_beneath", "RESOLVE_BENEATH did not stop an escaping path");
	} else {
		snprintf(buf, sizeof(buf), "in-tree open ok, escape refused with %s", errname(errno));
		ok("openat2_beneath", buf);
	}
	close(dir);
}

// 13. Watching what the workload does, rather than stopping it.
static void probe_observation(void) {
	char buf[160];

	int ifd = (int)syscall(__NR_inotify_init1, 0);
	if (ifd < 0) {
		snprintf(buf, sizeof(buf), "inotify_init1 errno=%s", errname(errno));
		fail("inotify", buf);
	} else {
		int wd = (int)syscall(__NR_inotify_add_watch, ifd, ".", 0x00000002);
		if (wd < 0) {
			snprintf(buf, sizeof(buf), "add_watch errno=%s", errname(errno));
			fail("inotify", buf);
		} else {
			ok("inotify", "init + add_watch work");
		}
		close(ifd);
	}

	long ffd = syscall(NR_fanotify_init, 0x00000001 /* FAN_CLOEXEC */, O_RDONLY);
	if (ffd >= 0) {
		ok("fanotify", "fanotify_init succeeded");
		close((int)ffd);
	} else {
		snprintf(buf, sizeof(buf), "errno=%s", errname(errno));
		fail("fanotify", buf);
	}
}

// 14. Giving up privilege permanently, and the third route to mediation.
static void probe_privilege(void) {
	char buf[160];

	pid_t pid = fork();
	if (pid == 0) _exit(prctl(PR_SET_SECUREBITS_, 0, 0, 0, 0) == 0 ? ENC_OK : ENC_NEGATIVE);
	if (pid > 0) {
		int code = 0;
		if (child_status(pid, &code) == 0 && code == ENC_OK)
			ok("securebits", "PR_SET_SECUREBITS accepted");
		else
			fail("securebits", "PR_SET_SECUREBITS refused");
	}

	errno = 0;
	if (prctl(PR_SET_SYSCALL_USER_DISPATCH_, 0 /* PR_SYS_DISPATCH_OFF */, 0, 0, 0) == 0) {
		ok("syscall_user_dispatch", "PR_SET_SYSCALL_USER_DISPATCH accepted");
	} else {
		snprintf(buf, sizeof(buf), "errno=%s", errname(errno));
		fail("syscall_user_dispatch", buf);
	}
}

int main(void) {
	struct utsname u;
	// An initramfs has no /proc yet; PID 1 in a container does. Gating on the
	// pid alone would run the init path inside every container, where reboot()
	// is refused and the process would never exit.
	int as_init = (getpid() == 1) && (access("/proc/self/status", F_OK) != 0);
	if (as_init) {
		mkdir("/proc", 0755);
		mount("proc", "/proc", "proc", 0, NULL);
		setvbuf(stdout, NULL, _IONBF, 0);
	}

	// PROBE_WORKDIR wins; otherwise / is writable in a container but usually
	// not on a host for an unprivileged user, so fall back to /tmp.
	const char *candidates[3];
	int ncand = 0;
	const char *env = getenv("PROBE_WORKDIR");
	if (env) candidates[ncand++] = env;
	candidates[ncand++] = "/probe_work";
	candidates[ncand++] = "/tmp/probe_work";

	int have_dir = 0;
	for (int i = 0; i < ncand && !have_dir; i++) {
		if ((mkdir(candidates[i], 0755) == 0 || errno == EEXIST) && chdir(candidates[i]) == 0)
			have_dir = 1;
	}
	if (!have_dir) {
		fprintf(stderr, "no writable work directory (last error: %s)\n", strerror(errno));
		return 1;
	}
	if (getcwd(workdir_abs, sizeof(workdir_abs)) == NULL) {
		fprintf(stderr, "getcwd failed: %s\n", strerror(errno));
		return 1;
	}
	snprintf(ctrl_path, sizeof(ctrl_path), "%s/ctrl", workdir_abs);
	if (make_file("ctrl", "control\n") != 0) {
		fprintf(stderr, "cannot create the control file: %s\n", strerror(errno));
		return 1;
	}

	if (uname(&u) == 0)
		printf("kernel reported: %s %s\n", u.sysname, u.release);
	printf("uid=%d euid=%d\n", getuid(), geteuid());

	// Grouped by what a harness would use them for, so the output reads in the
	// same order as the table it feeds.
	section("restricting which paths this process may reach");
	probe_landlock_abi();
	probe_landlock_enforce();
	probe_jail();
	probe_chroot();
	probe_openat2();
	probe_mount_api();

	section("mediating syscalls as they happen");
	probe_seccomp_filter();
	probe_notif_sizes();
	probe_notif_listener();
	probe_seccomp_trap();
	probe_ptrace_supervisor();
	probe_pidfd();

	section("observing and dropping privilege");
	probe_observation();
	probe_privilege();

	printf("\nPROBE-DONE\n");
	if (as_init) {
		sync();
		reboot(RB_POWER_OFF);
	}
	return 0;
}
