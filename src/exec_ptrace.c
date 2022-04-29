/*
 * Copyright (c) 2022 Todd C. Miller <Todd.Miller@sudo.ws>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

/*
 * This is an open source non-commercial project. Dear PVS-Studio, please check it.
 * PVS-Studio Static Code Analyzer for C, C++ and C#: http://www.viva64.com
 */

#include <config.h>

#include <sys/types.h>
#include <sys/uio.h>
#include <sys/wait.h>

#include <errno.h>
#include <limits.h>
#include <signal.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "sudo.h"
#include "sudo_exec.h"

#ifdef HAVE_PTRACE_INTERCEPT
# include <elf.h>
# include <sys/prctl.h>
# include <sys/ptrace.h>
# include <sys/user.h>
# include <asm/unistd.h>
# include <linux/ptrace.h>
# include <linux/seccomp.h>
# include <linux/filter.h>

/*
 * See syscall(2) for a list of registers used in system calls.
 * For example code, see tools/testing/selftests/seccomp/seccomp_bpf.c
 *
 * The structs and registers vary among the different platforms.
 * We define user_regs_struct as the struct to use for the
 * PTRACE_GETREGSET/PTRACE_SETREGSET command and define accessor
 * macros to get/set the struct members.
 */
#if defined(__amd64__)
# define user_pt_regs		user_regs_struct
# define reg_syscall(x)		(x).orig_rax
# define reg_retval(x)		(x).rax
# define reg_arg1(x)		(x).rdi
# define reg_arg2(x)		(x).rsi
# define reg_arg3(x)		(x).rdx
# define reg_arg4(x)		(x).r10
#elif defined(__aarch64__)
# define reg_syscall(x)		(x).regs[8]	/* w8 */
# define reg_retval(x)		(x).regs[0]	/* x0 */
# define reg_arg1(x)		(x).regs[0]	/* x0 */
# define reg_arg2(x)		(x).regs[1]	/* x1 */
# define reg_arg3(x)		(x).regs[2]	/* x2 */
# define reg_arg4(x)		(x).regs[3]	/* x3 */
#elif defined(__arm__)
/* Note: assumes arm EABI, not OABI */
/* Untested */
# define user_pt_regs		pt_regs
# define reg_syscall(x)		(x).ARM_r7
# define reg_retval(x)		(x).ARM_r0
# define reg_arg1(x)		(x).ARM_r0
# define reg_arg2(x)		(x).ARM_r1
# define reg_arg3(x)		(x).ARM_r2
# define reg_arg4(x)		(x).ARM_r3
#elif defined (__hppa__)
/* Untested */
# define user_pt_regs		user_regs_struct
# define reg_syscall(x)		(x).gr[20]	/* r20 */
# define reg_retval(x)		(x).gr[28]	/* r28 */
# define reg_arg1(x)		(x).gr[26]	/* r26 */
# define reg_arg2(x)		(x).gr[25]	/* r25 */
# define reg_arg3(x)		(x).gr[24]	/* r24 */
# define reg_arg4(x)		(x).gr[23]	/* r23 */
#elif defined(__i386__)
# define user_pt_regs		user_regs_struct
# define reg_syscall(x)		(x).orig_eax
# define reg_retval(x)		(x).eax
# define reg_arg1(x)		(x).ebx
# define reg_arg2(x)		(x).ecx
# define reg_arg3(x)		(x).edx
# define reg_arg4(x)		(x).esi
#elif defined(__powerpc64__)
/* Untested */
# define user_pt_regs		pt_regs
# define reg_syscall(x)		(x).gpr[0]	/* r0 */
# define reg_retval(x)		(x).gpr[3]	/* r3 */
# define reg_arg1(x)		(x).gpr[3]	/* r3 */
# define reg_arg2(x)		(x).gpr[4]	/* r4 */
# define reg_arg3(x)		(x).gpr[5]	/* r5 */
# define reg_arg4(x)		(x).gpr[6]	/* r6 */
#elif defined(__powerpc__)
/* Untested */
# define user_pt_regs		pt_regs
# define reg_syscall(x)		(x).gpr[0]	/* r0 */
# define reg_retval(x)		(x).gpr[3]	/* r3 */
# define reg_arg1(x)		(x).gpr[3]	/* r3 */
# define reg_arg2(x)		(x).gpr[4]	/* r4 */
# define reg_arg3(x)		(x).gpr[5]	/* r5 */
# define reg_arg4(x)		(x).gpr[6]	/* r6 */
#elif defined(__riscv) && __riscv_xlen == 64
/* Untested */
# define user_pt_regs		user_regs_struct
# define reg_syscall(x)		(x).a7
# define reg_retval(x)		(x).a0
# define reg_arg1(x)		(x).a0
# define reg_arg2(x)		(x).a1
# define reg_arg3(x)		(x).a2
# define reg_arg4(x)		(x).a3
#elif defined(__s390__)
/* Untested */
# define user_pt_regs		s390_regs
# define reg_syscall(x)		(x).gprs[1]	/* r1 */
# define reg_retval(x)		(x).gprs[2]	/* r2 */
# define reg_arg1(x)		(x).gprs[2]	/* r2 */
# define reg_arg2(x)		(x).gprs[3]	/* r3 */
# define reg_arg3(x)		(x).gprs[4]	/* r4 */
# define reg_arg4(x)		(x).gprs[5]	/* r6 */
#else
# error "Do not know how to find your architecture's registers"
#endif

/*
 * Read the string at addr and store in buf.
 * Returns the number of bytes stored, including the NUL.
 */
static size_t
ptrace_read_string(pid_t pid, long addr, char *buf, size_t bufsize)
{
    const char *buf0 = buf;
    const char *cp;
    long word;
    unsigned int i;
    debug_decl(ptrace_read_string, SUDO_DEBUG_EXEC);

    /* Read the string via ptrace(2) one word at a time. */
    for (;;) {
	word = ptrace(PTRACE_PEEKTEXT, pid, addr, NULL);
	if (word == -1) {
	    sudo_warn("ptrace(PTRACE_PEEKTEXT, %d, %ld, NULL)", pid, addr);
	    debug_return_ssize_t(-1);
	}

	/* XXX - this could be optimized. */
	cp = (char *)&word;
	for (i = 0; i < sizeof(long); i++) {
	    if (bufsize == 0) {
		sudo_debug_printf(SUDO_DEBUG_ERROR,
		    "%s: %d: out of space reading string", __func__, (int)pid);
		debug_return_ssize_t(-1);
	    }
	    *buf = cp[i];
	    if (*buf++ == '\0')
		debug_return_ssize_t(buf - buf0);
	    bufsize--;
	}
	addr += sizeof(long);
    }
}

/*
 * Read the string vector at addr and store in vec, which must have
 * sufficient space.  Strings are stored in buf.
 * Returns the number of bytes in buf consumed (including NULs).
 */
static size_t
ptrace_read_vec(pid_t pid, long addr, char **vec, char *buf, size_t bufsize)
{
    char *buf0 = buf;
    int len = 0;
    size_t slen;
    debug_decl(ptrace_read_vec, SUDO_DEBUG_EXEC);

    /* Fill in vector. */
    for (;;) {
	long word = ptrace(PTRACE_PEEKTEXT, pid, addr, NULL);
	switch (word) {
	case -1:
	    sudo_warn("ptrace(PTRACE_PEEKTEXT, %d, %ld, NULL)", pid, addr);
	    goto bad;
	case 0:
	    vec[len] = NULL;
	    debug_return_size_t(buf - buf0);
	default:
	    slen = ptrace_read_string(pid, word, buf, bufsize);
	    if (slen == (size_t)-1)
		goto bad;
	    vec[len++] = buf;
	    buf += slen + 1;
	    bufsize -= slen + 1;
	    addr += sizeof(word);
	    continue;
	}
    }
bad:
    while (len > 0) {
	free(vec[len]);
	len--;
    }
    debug_return_size_t(-1);
}

/*
 * Return the length of the string vector at addr or -1 on error.
 */
static int
ptrace_get_vec_len(pid_t pid, long addr)
{
    int len = 0;
    debug_decl(ptrace_get_vec_len, SUDO_DEBUG_EXEC);

    for (;;) {
	long word = ptrace(PTRACE_PEEKTEXT, pid, addr, NULL);
	switch (word) {
	case -1:
	    sudo_warn("ptrace(PTRACE_PEEKTEXT, %d, %ld, NULL)", pid, addr);
	    debug_return_int(-1);
	case 0:
	    debug_return_int(len);
	default:
	    len++;
	    addr += sizeof(word);
	    continue;
	}
    }
}

/*
 * Read the filename, argv and envp of the execve(2) system call.
 * Returns a dynamically allocated buffer the parent is responsible for.
 */
static char *
get_execve_args(pid_t pid, char **pathname_out, char ***argv_out, char ***envp_out)
{
    char *argbuf, *strtab, *pathname, **argv, **envp;
    long path_addr, argv_addr, envp_addr, syscallno;
    struct user_pt_regs regs;
    struct iovec iov;
    int argc, envc;
    size_t bufsize, len;
    debug_decl(get_execve_args, SUDO_DEBUG_EXEC);

    bufsize = sysconf(_SC_ARG_MAX) + PATH_MAX;
    argbuf = malloc(bufsize);
    if (argbuf == NULL)
	sudo_fatalx(U_("%s: %s"), __func__, U_("unable to allocate memory"));

    /* XXX - for amd64 and i386 use PTRACE_GETREGS/PTRACE_SETREGS instead. */
    iov.iov_base = &regs;
    iov.iov_len = sizeof(regs);
    if (ptrace(PTRACE_GETREGSET, pid, (long)NT_PRSTATUS, &iov) == -1) {
	sudo_warn(U_("unable to get registers for process %d"), (int)pid);
	goto bad;
    }

    /* System call number is stored in the lower 32-bits on 64-bit platforms. */
    syscallno = reg_syscall(regs) & 0xffffffff;
    if (syscallno != __NR_execve) {
	sudo_warnx("%s: unexpected system call %ld", __func__, syscallno);
	goto bad;
    }

    /* execve(2) takes three arguments: pathname, argv, envp. */
    path_addr = reg_arg1(regs);
    argv_addr = reg_arg2(regs);
    envp_addr = reg_arg3(regs);

#ifdef notyet
    /* Cause the syscall to fail by changing its number to -1. */
    reg_syscall(regs) |= 0xffffffff;
    if (ptrace(PTRACE_SETREGSET, pid, (long)NT_PRSTATUS, &iov) == -1) {
	sudo_warn("unable to set registers");
	goto bad;
    }

    /* Allow the syscall to complete and change return value to EACCES. */
    ptrace(PTRACE_SYSCALL, pid, NULL, NULL);
    waitpid(pid, NULL, 0);
    reg_retval(regs) = -EACCES;
    if (ptrace(PTRACE_SETREGSET, pid, (long)NT_PRSTATUS, &iov) == -1) {
	sudo_warn("unable to set registers");
	goto bad;
    }
#endif

    /* Count argv and envp */
    argc = ptrace_get_vec_len(pid, argv_addr);
    envc = ptrace_get_vec_len(pid, envp_addr);
    if (argc == -1 || envc == -1)
	goto bad;

    /* Reserve argv and envp at the start of argbuf so they are alined. */
    if ((argc + 1 + envc + 1) * sizeof(long) >= bufsize) {
	sudo_warnx("%s", U_("insufficent space for argv and envp"));
	goto bad;
    }
    argv = (char **)argbuf;
    envp = argv + argc + 1;
    strtab = (char *)(envp + envc + 1);
    bufsize -= strtab - argbuf;

    /* Read argv */
    len = ptrace_read_vec(pid, argv_addr, argv, strtab, bufsize);
    if (len == (size_t)-1) {
	sudo_warn(U_("unable to read execve argv for process %d"), (int)pid);
	goto bad;
    }
    strtab += len;
    bufsize -= len;

    /* Read envp */
    len = ptrace_read_vec(pid, envp_addr, envp, strtab, bufsize);
    if (len == (size_t)-1) {
	sudo_warn(U_("unable to read execve envp for process %d"), (int)pid);
	goto bad;
    }
    strtab += len;
    bufsize -= len;

    /* Read the pathname. */
    len = ptrace_read_string(pid, path_addr, strtab, bufsize);
    if (len == (size_t)-1) {
	sudo_warn(U_("unable to read execve pathname for process %d"), (int)pid);
	goto bad;
    }
    pathname = strtab;
    strtab += len;
    bufsize -= len;

    sudo_debug_execve(SUDO_DEBUG_INFO, pathname, argv, envp);

    *pathname_out = pathname;
    *argv_out = argv;
    *envp_out = envp;

    debug_return_ptr(argbuf);
bad:
    free(argbuf);
    debug_return_ptr(NULL);
}

/*
 * Check whether seccomp(2) filtering supports ptrace(2) traps.
 * Only supported by Linux 4.14 and higher.
 */
bool
have_seccomp_action(const char *action)
{
    char line[LINE_MAX];
    bool ret = false;
    FILE *fp;
    debug_decl(have_seccomp_action, SUDO_DEBUG_EXEC);

    fp = fopen("/proc/sys/kernel/seccomp/actions_avail", "r");
    if (fp != NULL) {
	if (fgets(line, sizeof(line), fp) != NULL) {
	    char *cp, *last;

	    for ((cp = strtok_r(line, " \t\n", &last)); cp != NULL;
		(cp = strtok_r(NULL, " \t\n", &last))) {
		if (strcmp(cp, action) == 0) {
		    ret = true;
		    break;
		}
	    }
	}
	fclose(fp);
    }
    debug_return_bool(ret);
}

/*
 * Intercept execve(2) using seccomp(2) and ptrace(2).
 * If no tracer is present, execve(2) will fail with ENOSYS.
 * Must be called with CAP_SYS_ADMIN, before privs are dropped.
 */
bool
set_exec_filter(void)
{
    struct sock_filter exec_filter[] = {
	/* Load syscall number into the accumulator */
	BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),
	/* Jump to trace for execve(2), else allow. */
	BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_execve, 0, 1),
	/* Trace execve(2) syscall */
	BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_TRACE),
	/* Allow non-matching syscalls */
	BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW)
    };
    const struct sock_fprog exec_fprog = {
	nitems(exec_filter),
	exec_filter
    };
    debug_decl(set_exec_filter, SUDO_DEBUG_UTIL);

    /* We must set SECCOMP_MODE_FILTER before dropping privileges. */
    if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &exec_fprog) == -1) {
	sudo_warn("%s", U_("unable to set seccomp filter"));
	debug_return_bool(false);
    }
    debug_return_bool(true);
}

/*
 * Seize control of the specified child process which must be in
 * ptrace wait.  Returns true on success and false on failure.
 */
bool
exec_ptrace_seize(pid_t child)
{
    const long ptrace_opts = PTRACE_O_TRACESECCOMP|PTRACE_O_TRACECLONE|
			     PTRACE_O_TRACEFORK|PTRACE_O_TRACEVFORK;
    int status;
    pid_t pid;
    debug_decl(exec_ptrace_seize, SUDO_DEBUG_UTIL);

    /* Seize control of the child process. */
    if (ptrace(PTRACE_SEIZE, child, NULL, ptrace_opts) == -1) {
	sudo_warn("ptrace(PTRACE_SEIZE, %d, NULL, 0x%lx)", (int)child,
	    ptrace_opts);
	debug_return_bool(false);
    }

    /* The child will stop itself immediately before execve(2). */
    do {
	pid = waitpid(child, &status, WUNTRACED);
    } while (pid == -1 && errno == EINTR);
    if (pid == -1) {
	sudo_warn(U_("%s: %s"), __func__, "waitpid");
	debug_return_bool(false);
    }
    if (!WIFSTOPPED(status)) {
	sudo_warnx(U_("process %d exited unexpectedly"), (int)child);
	debug_return_bool(false);
    }
    if (ptrace(PTRACE_CONT, child, NULL, NULL) == -1) {
	sudo_warn("ptrace(PTRACE_CONT, %d, NULL, NULL)", (int)child);
	debug_return_bool(false);
    }

    debug_return_bool(true);
}

/*
 * Handle a process stopped due to ptrace.
 * Returns true if the signal was suppressed and false if it was delivered.
 */
bool
exec_ptrace_handled(pid_t pid, int status)
{
    const int stopsig = WSTOPSIG(status);
    const int sigtrap = status >> 8;
    long signo = 0;
    bool group_stop = false;
    debug_decl(exec_ptrace_handled, SUDO_DEBUG_EXEC);

    if (sigtrap == (SIGTRAP | (PTRACE_EVENT_SECCOMP << 8))) {
	char *pathname, **argv, **envp, *buf;

	/* Trapped child exec. */
	sudo_debug_printf(SUDO_DEBUG_INFO, "%s: %d called exec",
	    __func__, (int)pid);

	/*
	 * Get the exec arguments and perform a policy check either over
	 * the socketpair (pty case) or via a direct function call (no pty).
	 * XXX
	 */
	 buf = get_execve_args(pid, &pathname, &argv, &envp);
	 if (buf == NULL) {
	    sudo_debug_printf(SUDO_DEBUG_ERROR,
		"%s: %d: unable to get exec args", __func__, (int)pid);
	}
    } else if (sigtrap == (SIGTRAP | (PTRACE_EVENT_CLONE << 8)) ||
	sigtrap == (SIGTRAP | (PTRACE_EVENT_VFORK << 8)) ||
	sigtrap == (SIGTRAP | (PTRACE_EVENT_FORK << 8))) {
	unsigned long new_pid;

	/* New child process, it will inherit the parent's trace flags. */
	if (sudo_debug_needed(SUDO_DEBUG_INFO)) {
	    if (ptrace(PTRACE_GETEVENTMSG, pid, NULL, &new_pid) != -1) {
		sudo_debug_printf(SUDO_DEBUG_INFO,
		    "%s: %d forked new child %lu", __func__, (int)pid, new_pid);
	    } else {
		sudo_debug_printf(
		    SUDO_DEBUG_ERROR|SUDO_DEBUG_LINENO|SUDO_DEBUG_ERRNO,
		    "ptrace(PTRACE_GETEVENTMSG, %d, NULL, %p)", (int)pid,
		    &new_pid);
	    }
	}
    } else {
	switch (stopsig) {
	case SIGSTOP:
	case SIGTSTP:
	case SIGTTIN:
	case SIGTTOU:
	    /* Is this a group-stop? */
	    if (status >> 16 == PTRACE_EVENT_STOP) {
		/* Group-stop, do not deliver signal. */
		sudo_debug_printf(SUDO_DEBUG_INFO,
		    "%s: %d: group-stop signal %d",
		    __func__, (int)pid, stopsig);
		group_stop = true;
	    } else {
		/* Signal-delivery-stop, deliver signal. */
		sudo_debug_printf(SUDO_DEBUG_INFO,
		    "%s: %d: signal-delivery-stop signal %d",
		    __func__, (int)pid, stopsig);
		signo = stopsig;
	    }
	    break;
	default:
	    /* Not a stop signal so not a group-stop. */
	    sudo_debug_printf(SUDO_DEBUG_INFO,
		"%s: %d: signal %d", __func__, (int)pid, stopsig);
	    break;
	}
    }

    /* Continue child. */
    /* XXX - handle ptrace returning ESRCH if process dies */
    if (group_stop) {
	/*
	 * Restart child but prevent it from executing
	 * until SIGCONT is received (simulate SIGSTOP, etc).
	 */
	if (ptrace(PTRACE_LISTEN, pid, NULL, 0L) == -1)
	    sudo_warn("ptrace(PTRACE_LISTEN,, %d, NULL, %d", pid, stopsig);
    } else {
	/* Restart child. */
	if (ptrace(PTRACE_CONT, pid, NULL, signo) == -1)
	    sudo_warn("ptrace(PTRACE_CONT, %d, NULL, %d", pid, stopsig);
    }

    debug_return_bool(signo == 0);
}
#else
/* STUB */
void
exec_ptrace_enable(void)
{
    return;
}

/* STUB */
bool
have_seccomp_action(const char *action)
{
    return false;
}

/* STUB */
bool
exec_ptrace_handled(pid_t pid, int status)
{
    return false;
}

/* STUB */
bool
exec_ptrace_seize(pid_t child)
{
    return true;
}
#endif /* HAVE_PTRACE_INTERCEPT */
