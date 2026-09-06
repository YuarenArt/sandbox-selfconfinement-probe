// Probe: which in-sandbox confinement primitives are available to the workload itself.
// Raw syscalls only, no kernel headers, so the same binary runs anywhere.
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sched.h>
#include <signal.h>
#include <sys/mount.h>
#include <sys/ptrace.h>
#include <sys/reboot.h>
#include <sys/user.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/utsname.h>
#include <sys/wait.h>
#include <unistd.h>

#define NR_landlock_create_ruleset 444
#define NR_landlock_add_rule       445
#define NR_landlock_restrict_self  446
#define NR_seccomp                 317
#define NR_pidfd_open              434
#define NR_pidfd_getfd             438

#define LANDLOCK_CREATE_RULESET_VERSION (1U << 0)
#define LANDLOCK_ACCESS_FS_READ_FILE    (1ULL << 2)

#define SECCOMP_SET_MODE_FILTER         1
#define SECCOMP_GET_NOTIF_SIZES         3
#define SECCOMP_FILTER_FLAG_NEW_LISTENER (1UL << 3)
#define SECCOMP_RET_ERRNO               0x00050000U
#define SECCOMP_RET_ALLOW               0x7fff0000U

struct landlock_ruleset_attr {
	uint64_t handled_access_fs;
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
	printf("%-28s PASS   %s\n", name, detail);
}

static void fail(const char *name, const char *detail) {
	printf("%-28s FAIL   %s\n", name, detail);
}

static const char *errname(int e) {
	switch (e) {
	case ENOSYS: return "ENOSYS (syscall not implemented)";
	case EPERM: return "EPERM";
	case EACCES: return "EACCES";
	case EINVAL: return "EINVAL";
	case EOPNOTSUPP: return "EOPNOTSUPP";
	case ENOTTY: return "ENOTTY";
	case EBADF: return "EBADF";
	default: return strerror(e);
	}
}

// 1. Landlock ABI version. This is the cheapest existence check: the kernel
// answers with the ABI number and touches nothing.
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

// 2. Landlock actually enforcing: empty ruleset over READ_FILE must make a
// plain open() fail. A ruleset that installs but does not deny is worse than
// none, so the check is the denial, not the syscall return.
static void probe_landlock_enforce(void) {
	pid_t pid = fork();
	if (pid == 0) {
		struct landlock_ruleset_attr attr = { .handled_access_fs = LANDLOCK_ACCESS_FS_READ_FILE };
		long fd = syscall(NR_landlock_create_ruleset, &attr, sizeof(attr), 0);
		if (fd < 0) _exit(100 + (errno & 0x7f));
		if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0) _exit(90);
		if (syscall(NR_landlock_restrict_self, (int)fd, 0) != 0) _exit(100 + (errno & 0x7f));
		int f = open("/etc/hostname", O_RDONLY);
		_exit(f < 0 ? 0 : 1);  // 0 = denied as expected, 1 = ruleset ignored
	}
	int st = 0;
	waitpid(pid, &st, 0);
	int code = WIFEXITED(st) ? WEXITSTATUS(st) : -1;
	char buf[128];
	if (code == 0) {
		ok("landlock_enforce", "empty ruleset denied open() as expected");
	} else if (code == 1) {
		fail("landlock_enforce", "ruleset installed but open() still succeeded");
	} else if (code >= 100) {
		snprintf(buf, sizeof(buf), "errno=%s", errname(code - 100));
		fail("landlock_enforce", buf);
	} else {
		snprintf(buf, sizeof(buf), "child exit %d", code);
		fail("landlock_enforce", buf);
	}
}

// 3. Classic seccomp-bpf filter applied by the workload to itself.
static void probe_seccomp_filter(void) {
	pid_t pid = fork();
	if (pid == 0) {
		struct sock_filter code[] = {
			{ 0x20, 0, 0, 0x00000000 },              // ld  [0]  -> nr
			{ 0x15, 0, 1, __NR_getpid },             // jeq getpid ? next : +1
			{ 0x06, 0, 0, SECCOMP_RET_ERRNO | 1 },   // ret ERRNO(EPERM)
			{ 0x06, 0, 0, SECCOMP_RET_ALLOW },       // ret ALLOW
		};
		struct sock_fprog prog = { .len = 4, .filter = code };
		if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0) _exit(90);
		if (syscall(NR_seccomp, SECCOMP_SET_MODE_FILTER, 0, &prog) != 0) _exit(100 + (errno & 0x7f));
		errno = 0;
		long r = syscall(__NR_getpid);
		_exit((r < 0 && errno == EPERM) ? 0 : 1);
	}
	int st = 0;
	waitpid(pid, &st, 0);
	int code = WIFEXITED(st) ? WEXITSTATUS(st) : -1;
	char buf[128];
	if (code == 0) {
		ok("seccomp_filter", "filter installed and enforced (getpid -> EPERM)");
	} else if (code == 1) {
		fail("seccomp_filter", "filter installed but not enforced");
	} else if (code >= 100) {
		snprintf(buf, sizeof(buf), "errno=%s", errname(code - 100));
		fail("seccomp_filter", buf);
	} else {
		snprintf(buf, sizeof(buf), "child exit %d", code);
		fail("seccomp_filter", buf);
	}
}

// 4. SECCOMP_GET_NOTIF_SIZES: cheap probe of user-notification support,
// needs no privileges.
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

// 5. The mechanism Sandlock's runtime decisions rest on: a supervisor fd for
// syscalls the static policy cannot decide.
static void probe_notif_listener(void) {
	int pipefd[2];
	if (pipe(pipefd) != 0) {
		fail("seccomp_user_notif", "pipe failed");
		return;
	}
	pid_t pid = fork();
	if (pid == 0) {
		close(pipefd[0]);
		struct sock_filter code[] = {
			{ 0x20, 0, 0, 0x00000000 },
			{ 0x15, 0, 1, __NR_getpid },
			{ 0x06, 0, 0, 0x7fc00000U },             // ret USER_NOTIF
			{ 0x06, 0, 0, SECCOMP_RET_ALLOW },
		};
		struct sock_fprog prog = { .len = 4, .filter = code };
		prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
		long fd = syscall(NR_seccomp, SECCOMP_SET_MODE_FILTER,
				  SECCOMP_FILTER_FLAG_NEW_LISTENER, &prog);
		int res = (fd >= 0) ? 0 : (100 + (errno & 0x7f));
		ssize_t n = write(pipefd[1], &res, sizeof(res));
		(void)n;
		_exit(0);
	}
	close(pipefd[1]);
	int res = -1;
	ssize_t n = read(pipefd[0], &res, sizeof(res));
	close(pipefd[0]);
	waitpid(pid, NULL, 0);
	char buf[128];
	if (n != sizeof(res)) {
		fail("seccomp_user_notif", "child produced no result");
	} else if (res == 0) {
		ok("seccomp_user_notif", "listener fd obtained");
	} else {
		snprintf(buf, sizeof(buf), "errno=%s", errname(res - 100));
		fail("seccomp_user_notif", buf);
	}
}

// 6. pidfd_open / pidfd_getfd: how a supervisor acts on behalf of the confined
// process. ENOSYS here removes the on-behalf half of the design.
static void probe_pidfd(void) {
	long pfd = syscall(NR_pidfd_open, getpid(), 0);
	char buf[128];
	if (pfd < 0) {
		snprintf(buf, sizeof(buf), "pidfd_open errno=%s", errname(errno));
		fail("pidfd", buf);
		return;
	}
	errno = 0;
	long got = syscall(NR_pidfd_getfd, (int)pfd, 1, 0);
	if (got >= 0) {
		ok("pidfd", "pidfd_open + pidfd_getfd work");
		close((int)got);
	} else if (errno == ENOSYS) {
		fail("pidfd", "pidfd_open works, pidfd_getfd ENOSYS");
	} else {
		snprintf(buf, sizeof(buf), "pidfd_open works, pidfd_getfd errno=%s", errname(errno));
		ok("pidfd", buf);
	}
	close((int)pfd);
}

static int write_file(const char *path, const char *val) {
	int fd = open(path, O_WRONLY);
	if (fd < 0) return -1;
	ssize_t n = write(fd, val, strlen(val));
	close(fd);
	return (n == (ssize_t)strlen(val)) ? 0 : -1;
}

// 7. The pre-Landlock route: unprivileged user namespace plus mount namespace,
// bind mount and chroot. If this works, filesystem confinement is still
// reachable inside the sandbox, only at the old price.
static void probe_namespaces(void) {
	int pipefd[2];
	if (pipe(pipefd) != 0) {
		fail("userns_mountns", "pipe failed");
		return;
	}
	uid_t outer_uid = getuid();
	gid_t outer_gid = getgid();
	pid_t pid = fork();
	if (pid == 0) {
		close(pipefd[0]);
		int stage = 0;
		char map[64];
		if (unshare(CLONE_NEWUSER) != 0) { stage = 1; goto out; }
		// Mounting inside a user namespace stays refused until the id maps
		// are written, so this step is part of the mechanism, not setup.
		if (write_file("/proc/self/setgroups", "deny") != 0) { stage = 2; goto out; }
		snprintf(map, sizeof(map), "0 %u 1", outer_uid);
		if (write_file("/proc/self/uid_map", map) != 0) { stage = 2; goto out; }
		snprintf(map, sizeof(map), "0 %u 1", outer_gid);
		if (write_file("/proc/self/gid_map", map) != 0) { stage = 2; goto out; }
		if (unshare(CLONE_NEWNS) != 0) { stage = 3; goto out; }
		// A fresh mount namespace inherits shared propagation; bind mounts
		// fail with EINVAL until the root is made private.
		if (mount(NULL, "/", NULL, MS_REC | MS_PRIVATE, NULL) != 0) { stage = 4; goto out; }
		if (mkdir("/probe_jail", 0755) != 0 && errno != EEXIST) { stage = 5; goto out; }
		if (mount("/etc", "/probe_jail", NULL, MS_BIND, NULL) != 0) { stage = 6; goto out; }
		if (chroot("/probe_jail") != 0) { stage = 7; goto out; }
		stage = 100;
	out:;
		int res = (stage == 100) ? 0 : (stage * 1000 + (errno & 0x7f));
		ssize_t n = write(pipefd[1], &res, sizeof(res));
		(void)n;
		_exit(0);
	}
	close(pipefd[1]);
	int res = -1;
	ssize_t n = read(pipefd[0], &res, sizeof(res));
	close(pipefd[0]);
	waitpid(pid, NULL, 0);
	char buf[160];
	if (n != sizeof(res)) {
		fail("userns_mountns", "child produced no result");
		return;
	}
	if (res == 0) {
		ok("userns_mountns", "userns + mountns + bind + chroot all work");
		return;
	}
	static const char *stages[] = { "", "unshare(CLONE_NEWUSER)", "write id maps",
					"unshare(CLONE_NEWNS)", "mount(/, MS_PRIVATE)",
					"mkdir", "mount(MS_BIND)", "chroot" };
	int stage = res / 1000;
	snprintf(buf, sizeof(buf), "%s failed, errno=%s",
		 (stage >= 1 && stage <= 7) ? stages[stage] : "?", errname(res % 1000));
	fail("userns_mountns", buf);
}

// 8. ptrace as the fallback interception mechanism: if user notification is
// absent, a supervisor inside the sandbox can only be built on ptrace, and
// only if syscall-stops and register reads work.
static void probe_ptrace_supervisor(void) {
	pid_t pid = fork();
	if (pid == 0) {
		if (ptrace(PTRACE_TRACEME, 0, NULL, NULL) != 0) _exit(80);
		raise(SIGSTOP);
		syscall(__NR_getpid);
		_exit(0);
	}
	int st = 0;
	char buf[160];
	if (waitpid(pid, &st, 0) < 0 || !WIFSTOPPED(st)) {
		fail("ptrace_supervisor", "child never reached a stop");
		kill(pid, SIGKILL);
		return;
	}
	if (ptrace(PTRACE_SYSCALL, pid, NULL, NULL) != 0) {
		snprintf(buf, sizeof(buf), "PTRACE_SYSCALL errno=%s", errname(errno));
		fail("ptrace_supervisor", buf);
		kill(pid, SIGKILL);
		waitpid(pid, NULL, 0);
		return;
	}
	if (waitpid(pid, &st, 0) < 0 || !WIFSTOPPED(st)) {
		fail("ptrace_supervisor", "no syscall-stop delivered");
		kill(pid, SIGKILL);
		return;
	}
	struct user_regs_struct regs;
	memset(&regs, 0, sizeof(regs));
	if (ptrace(PTRACE_GETREGS, pid, NULL, &regs) != 0) {
		snprintf(buf, sizeof(buf), "PTRACE_GETREGS errno=%s", errname(errno));
		fail("ptrace_supervisor", buf);
	} else {
		snprintf(buf, sizeof(buf), "syscall-stop seen, nr=%llu readable",
			 (unsigned long long)regs.orig_rax);
		ok("ptrace_supervisor", buf);
	}
	kill(pid, SIGKILL);
	waitpid(pid, NULL, 0);
}

// 9. chroot alone: the crudest jail, not a boundary against root but the last
// remaining way to narrow the visible tree.
static void probe_chroot(void) {
	pid_t pid = fork();
	if (pid == 0) {
		if (mkdir("/probe_chroot", 0755) != 0 && errno != EEXIST) _exit(100 + (errno & 0x7f));
		if (chroot("/probe_chroot") != 0) _exit(100 + (errno & 0x7f));
		if (chdir("/") != 0) _exit(90);
		int f = open("/etc/hostname", O_RDONLY);
		_exit(f < 0 ? 0 : 1);  // 0 = old tree hidden, 1 = chroot ineffective
	}
	int st = 0;
	waitpid(pid, &st, 0);
	int code = WIFEXITED(st) ? WEXITSTATUS(st) : -1;
	char buf[128];
	if (code == 0) {
		ok("chroot", "chroot applied, old tree no longer visible");
	} else if (code == 1) {
		fail("chroot", "chroot returned success but tree still visible");
	} else if (code >= 100) {
		snprintf(buf, sizeof(buf), "errno=%s", errname(code - 100));
		fail("chroot", buf);
	} else {
		snprintf(buf, sizeof(buf), "child exit %d", code);
		fail("chroot", buf);
	}
}

// 10. The modern mount API and inotify: the other two ways to shape or observe
// the file namespace from inside.
static void probe_mount_api_and_inotify(void) {
	long fd = syscall(428 /* open_tree */, AT_FDCWD, "/etc", 0);
	char buf[128];
	if (fd >= 0) {
		ok("open_tree", "new mount API available");
		close((int)fd);
	} else {
		snprintf(buf, sizeof(buf), "errno=%s", errname(errno));
		fail("open_tree", buf);
	}

	int ifd = (int)syscall(__NR_inotify_init1, 0);
	if (ifd < 0) {
		snprintf(buf, sizeof(buf), "inotify_init1 errno=%s", errname(errno));
		fail("inotify", buf);
		return;
	}
	int wd = (int)syscall(__NR_inotify_add_watch, ifd, "/etc", 0x00000002 /* IN_MODIFY */);
	if (wd < 0) {
		snprintf(buf, sizeof(buf), "add_watch errno=%s", errname(errno));
		fail("inotify", buf);
	} else {
		ok("inotify", "init + add_watch work");
	}
	close(ifd);
}

int main(void) {
	struct utsname u;
	// Also usable as PID 1 in an initramfs, to probe a guest kernel directly
	// without the orchestration around it.
	int as_init = (getpid() == 1);
	if (as_init) {
		mkdir("/proc", 0755);
		mkdir("/etc", 0755);
		mount("proc", "/proc", "proc", 0, NULL);
		int f = open("/etc/hostname", O_WRONLY | O_CREAT | O_TRUNC, 0644);
		if (f >= 0) { ssize_t n = write(f, "guest\n", 6); (void)n; close(f); }
		setvbuf(stdout, NULL, _IONBF, 0);
	}

	if (uname(&u) == 0)
		printf("kernel reported: %s %s\n", u.sysname, u.release);
	printf("uid=%d euid=%d\n\n", getuid(), geteuid());

	probe_landlock_abi();
	probe_landlock_enforce();
	probe_seccomp_filter();
	probe_notif_sizes();
	probe_notif_listener();
	probe_pidfd();
	probe_namespaces();
	probe_ptrace_supervisor();
	probe_chroot();
	probe_mount_api_and_inotify();

	printf("\nPROBE-DONE\n");
	if (as_init) {
		sync();
		reboot(RB_POWER_OFF);
		for (;;) pause();
	}
	return 0;
}
