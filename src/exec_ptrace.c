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
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "sudo.h"
#include "sudo_exec.h"
#include "exec_intercept.h"

#ifdef HAVE_PTRACE_INTERCEPT
# include <elf.h>
# include <sys/prctl.h>
# include <sys/ptrace.h>
# include <sys/user.h>
# include <asm/unistd.h>
# include <linux/audit.h>
# include <linux/ptrace.h>
# include <linux/seccomp.h>
# include <linux/filter.h>

/* Older systems may not support execveat(2). */
#ifndef __NR_execveat
# define __NR_execveat	-1
#endif

/* Align address to a word boundary. */
#define WORDALIGN(_a)	(((_a) + (sizeof(long) - 1L)) & ~(sizeof(long) - 1L))

/*
 * See syscall(2) for a list of registers used in system calls.
 * For example code, see tools/testing/selftests/seccomp/seccomp_bpf.c
 *
 * The structs and registers vary among the different platforms.
 * We define user_regs_struct as the struct to use for the
 * PTRACE_GETREGSET/PTRACE_SETREGSET command and define accessor
 * macros to get/set the struct members.
 *
 * The value of SECCOMP_AUDIT_ARCH is used when matching the architecture
 * in the seccomp(2) filter.
 */
#if defined(__amd64__)
# define SECCOMP_AUDIT_ARCH	AUDIT_ARCH_X86_64
# define user_pt_regs		user_regs_struct
# define reg_syscall(x)		(x)->orig_rax
# define reg_retval(x)		(x)->rax
# define reg_sp(x)		(x)->rsp
# define reg_arg1(x)		(x)->rdi
# define reg_arg2(x)		(x)->rsi
# define reg_arg3(x)		(x)->rdx
# define reg_arg4(x)		(x)->r10
#elif defined(__aarch64__)
# define SECCOMP_AUDIT_ARCH	AUDIT_ARCH_AARCH64
# define reg_syscall(x)		(x)->regs[8]	/* w8 */
# define reg_retval(x)		(x)->regs[0]	/* x0 */
# define reg_sp(x)		(x)->sp		/* sp */
# define reg_arg1(x)		(x)->regs[0]	/* x0 */
# define reg_arg2(x)		(x)->regs[1]	/* x1 */
# define reg_arg3(x)		(x)->regs[2]	/* x2 */
# define reg_arg4(x)		(x)->regs[3]	/* x3 */
#elif defined(__arm__)
/* Note: assumes arm EABI, not OABI */
/* Untested */
# define SECCOMP_AUDIT_ARCH	AUDIT_ARCH_ARM
# define user_pt_regs		pt_regs
# define reg_syscall(x)		(x)->ARM_r7
# define reg_retval(x)		(x)->ARM_r0
# define reg_sp(x)		(x)->ARM_sp
# define reg_arg1(x)		(x)->ARM_r0
# define reg_arg2(x)		(x)->ARM_r1
# define reg_arg3(x)		(x)->ARM_r2
# define reg_arg4(x)		(x)->ARM_r3
#elif defined (__hppa__)
/* Untested (should also support hppa64) */
# define SECCOMP_AUDIT_ARCH	AUDIT_ARCH_PARISC
# define user_pt_regs		user_regs_struct
# define reg_syscall(x)		(x)->gr[20]	/* r20 */
# define reg_retval(x)		(x)->gr[28]	/* r28 */
# define reg_sp(x)		(x)->gr[30]	/* r30 */
# define reg_arg1(x)		(x)->gr[26]	/* r26 */
# define reg_arg2(x)		(x)->gr[25]	/* r25 */
# define reg_arg3(x)		(x)->gr[24]	/* r24 */
# define reg_arg4(x)		(x)->gr[23]	/* r23 */
#elif defined(__i386__)
# define SECCOMP_AUDIT_ARCH	AUDIT_ARCH_I386
# define user_pt_regs		user_regs_struct
# define reg_syscall(x)		(x)->orig_eax
# define reg_retval(x)		(x)->eax
# define reg_sp(x)		(x)->esp
# define reg_arg1(x)		(x)->ebx
# define reg_arg2(x)		(x)->ecx
# define reg_arg3(x)		(x)->edx
# define reg_arg4(x)		(x)->esi
#elif defined(__powerpc64__)
/* Untested */
# if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
#  define SECCOMP_AUDIT_ARCH	AUDIT_ARCH_PPC64LE
# else
#  define SECCOMP_AUDIT_ARCH	AUDIT_ARCH_PPC64
# endif
# define user_pt_regs		pt_regs
# define reg_syscall(x)		(x)->gpr[0]	/* r0 */
# define reg_retval(x)		(x)->gpr[3]	/* r3 */
# define reg_sp(x)		(x)->gpr[1]	/* r1 */
# define reg_arg1(x)		(x)->gpr[3]	/* r3 */
# define reg_arg2(x)		(x)->gpr[4]	/* r4 */
# define reg_arg3(x)		(x)->gpr[5]	/* r5 */
# define reg_arg4(x)		(x)->gpr[6]	/* r6 */
#elif defined(__powerpc__)
/* Untested */
# define SECCOMP_AUDIT_ARCH	AUDIT_ARCH_PPC
# define user_pt_regs		pt_regs
# define reg_syscall(x)		(x)->gpr[0]	/* r0 */
# define reg_retval(x)		(x)->gpr[3]	/* r3 */
# define reg_sp(x)		(x)->gpr[1]	/* r1 */
# define reg_arg1(x)		(x)->gpr[3]	/* r3 */
# define reg_arg2(x)		(x)->gpr[4]	/* r4 */
# define reg_arg3(x)		(x)->gpr[5]	/* r5 */
# define reg_arg4(x)		(x)->gpr[6]	/* r6 */
#elif defined(__riscv) && __riscv_xlen == 64
/* Untested */
# define SECCOMP_AUDIT_ARCH	AUDIT_ARCH_RISCV64
# define user_pt_regs		user_regs_struct
# define reg_syscall(x)		(x)->a7
# define reg_retval(x)		(x)->a0
# define reg_sp(x)		(x)->sp
# define reg_arg1(x)		(x)->a0
# define reg_arg2(x)		(x)->a1
# define reg_arg3(x)		(x)->a2
# define reg_arg4(x)		(x)->a3
#elif defined(__s390x__)
# define SECCOMP_AUDIT_ARCH	AUDIT_ARCH_S390X
# define user_pt_regs		s390_regs
# define reg_syscall(x)		(x)->gprs[1]	/* r1 */
# define reg_retval(x)		(x)->gprs[2]	/* r2 */
# define reg_sp(x)		(x)->gprs[15]	/* r15 */
# define reg_arg1(x)		(x)->gprs[2]	/* r2 */
# define reg_arg2(x)		(x)->gprs[3]	/* r3 */
# define reg_arg3(x)		(x)->gprs[4]	/* r4 */
# define reg_arg4(x)		(x)->gprs[5]	/* r6 */
#elif defined(__s390__)
# define SECCOMP_AUDIT_ARCH	AUDIT_ARCH_S390
# define user_pt_regs		s390_regs
# define reg_syscall(x)		(x)->gprs[1]	/* r1 */
# define reg_retval(x)		(x)->gprs[2]	/* r2 */
# define reg_sp(x)		(x)->gprs[15]	/* r15 */
# define reg_arg1(x)		(x)->gprs[2]	/* r2 */
# define reg_arg2(x)		(x)->gprs[3]	/* r3 */
# define reg_arg3(x)		(x)->gprs[4]	/* r4 */
# define reg_arg4(x)		(x)->gprs[5]	/* r6 */
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
	word = ptrace(PTRACE_PEEKDATA, pid, addr, NULL);
	if (word == -1) {
	    sudo_warn("ptrace(PTRACE_PEEKDATA, %d, 0x%lx, NULL)",
		(int)pid, addr);
	    debug_return_ssize_t(-1);
	}

	/* XXX - this could be optimized. */
	cp = (char *)&word;
	for (i = 0; i < sizeof(long); i++) {
	    if (bufsize == 0) {
		sudo_debug_printf(SUDO_DEBUG_ERROR,
		    "%s: %d: out of space reading string", __func__, (int)pid);
		debug_return_size_t(-1);
	    }
	    *buf = cp[i];
	    if (*buf++ == '\0')
		debug_return_size_t(buf - buf0);
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
	long word = ptrace(PTRACE_PEEKDATA, pid, addr, NULL);
	switch (word) {
	case -1:
	    sudo_warn("ptrace(PTRACE_PEEKDATA, %d, 0x%lx, NULL)",
		(int)pid, addr);
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
	long word = ptrace(PTRACE_PEEKDATA, pid, addr, NULL);
	switch (word) {
	case -1:
	    sudo_warn("ptrace(PTRACE_PEEKDATA, %d, 0x%lx, NULL)",
		(int)pid, addr);
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
 * Write the NUL-terminated string str to addr in the tracee.
 * The number of bytes written will be rounded up to the nearest
 * word, with extra bytes set to NUL.
 * Returns the number of bytes written, including trailing NULs.
 */
static size_t
ptrace_write_string(pid_t pid, long addr, const char *str)
{
    long start_addr = addr;
    unsigned int i;
    union {
	long word;
	char buf[sizeof(long)];
    } u;
    debug_decl(ptrace_write_string, SUDO_DEBUG_EXEC);

    /* Write the string via ptrace(2) one word at a time. */
    for (;;) {
	for (i = 0; i < sizeof(u.buf); i++) {
	    if (*str == '\0') {
		u.buf[i] = '\0';
	    } else {
		u.buf[i] = *str++;
	    }
	}
	if (ptrace(PTRACE_POKEDATA, pid, addr, u.word) == -1) {
	    sudo_warn("ptrace(PTRACE_POKEDATA, %d, 0x%lx, %.*s)",
		(int)pid, addr, (int)sizeof(u.buf), u.buf);
	    debug_return_size_t(-1);
	}
	addr += sizeof(long);
	if (*str == '\0')
	    debug_return_size_t(addr - start_addr);
    }
}

/*
 * Use /proc/PID/cwd to determine the current working directory.
 */
static bool
getcwd_by_pid(pid_t pid, char *buf, size_t bufsize)
{
    size_t len;
    char path[PATH_MAX];
    debug_decl(getcwd_by_pid, SUDO_DEBUG_EXEC);

    len = snprintf(path, sizeof(path), "/proc/%d/cwd", (int)pid);
    if (len < sizeof(path)) {
	len = readlink(path, buf, bufsize);
	if (len != (size_t)-1) {
	    /* Check for truncation. */
	    if (len >= bufsize)
		buf[bufsize - 1] = '\0';
	    debug_return_bool(true);
	}
    }
    debug_return_bool(false);
}

/*
 * Read the filename, argv and envp of the execve(2) system call.
 * Returns a dynamically allocated buffer the parent is responsible for.
 */
static char *
get_execve_info(pid_t pid, struct user_pt_regs *regs, char **pathname_out,
    int *argc_out, char ***argv_out, int *envc_out, char ***envp_out)
{
    char *argbuf, *strtab, *pathname, **argv, **envp;
    long path_addr, argv_addr, envp_addr;
    int argc, envc;
    size_t bufsize, len;
    debug_decl(get_execve_info, SUDO_DEBUG_EXEC);

    bufsize = sysconf(_SC_ARG_MAX) + PATH_MAX;
    argbuf = malloc(bufsize);
    if (argbuf == NULL)
	sudo_fatalx(U_("%s: %s"), __func__, U_("unable to allocate memory"));

    /* execve(2) takes three arguments: pathname, argv, envp. */
    path_addr = reg_arg1(regs);
    argv_addr = reg_arg2(regs);
    envp_addr = reg_arg3(regs);

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
    *argc_out = argc;
    *argv_out = argv;
    *envc_out = envc;
    *envp_out = envp;

    debug_return_ptr(argbuf);
bad:
    free(argbuf);
    debug_return_ptr(NULL);
}

/*
 * Cause the current syscall to fail and set the error value to ecode.
 */
static bool
ptrace_fail_syscall(pid_t pid, struct user_pt_regs *regs, int ecode)
{
    struct iovec iov;
    sigset_t chldmask;
    bool ret = false;
    int status;
    debug_decl(ptrace_fail_syscall, SUDO_DEBUG_EXEC);

    iov.iov_base = regs;
    iov.iov_len = sizeof(*regs);

    /* Cause the syscall to fail by changing its number to -1. */
    reg_syscall(regs) |= 0xffffffff;
    if (ptrace(PTRACE_SETREGSET, pid, (long)NT_PRSTATUS, &iov) == -1) {
	sudo_warn(U_("unable to set registers for process %d"), (int)pid);
	debug_return_bool(false);
    }

    /* Block SIGCHLD for the critical section (waitpid). */
    sigemptyset(&chldmask);
    sigaddset(&chldmask, SIGCHLD);
    sigprocmask(SIG_BLOCK, &chldmask, NULL);

    /* Allow the syscall to continue and change return value to ecode. */
    ptrace(PTRACE_SYSCALL, pid, NULL, NULL);
    for (;;) {
	if (waitpid(pid, &status, __WALL) != -1)
	    break;
	if (errno == EINTR)
	    continue;
	sudo_warn(U_("%s: %s"), __func__, "waitpid");
	goto done;
    }
    if (!WIFSTOPPED(status)) {
	sudo_warnx(U_("process %d exited unexpectedly"), (int)pid);
	goto done;
    }
    reg_retval(regs) = -ecode;
    if (ptrace(PTRACE_SETREGSET, pid, (long)NT_PRSTATUS, &iov) == -1) {
	sudo_warn(U_("unable to set registers for process %d"), (int)pid);
	goto done;
    }

    ret = true;

done:
    sigprocmask(SIG_UNBLOCK, &chldmask, NULL);

    debug_return_bool(ret);
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
 * Intercept execve(2) and execveat(2) using seccomp(2) and ptrace(2).
 * If no tracer is present, execve(2) and execveat(2) will fail with ENOSYS.
 * Must be called with CAP_SYS_ADMIN, before privs are dropped.
 */
bool
set_exec_filter(void)
{
    struct sock_filter exec_filter[] = {
	/* Load architecture value (AUDIT_ARCH_*) into the accumulator. */
	BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, arch)),
	/* Jump to the end unless the architecture matches. */
	BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SECCOMP_AUDIT_ARCH, 0, 4),
	/* Load syscall number into the accumulator. */
	BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),
	/* Jump to trace for execve(2)/execveat(2), else allow. */
	BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_execve, 1, 0),
	BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_execveat, 0, 1),
	/* Trace execve(2)/execveat(2) syscalls */
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
    debug_decl(exec_ptrace_seize, SUDO_DEBUG_UTIL);

    /* Seize control of the child process. */
    if (ptrace(PTRACE_SEIZE, child, NULL, ptrace_opts) == -1) {
	sudo_warn("ptrace(PTRACE_SEIZE, %d, NULL, 0x%lx)", (int)child,
	    ptrace_opts);
	debug_return_bool(false);
    }
    /* The child is suspended waiting for SIGUSR1, wake it up. */
    if (kill(child, SIGUSR1) == -1) {
	sudo_warn("kill(%d, SIGUSR1)", child);
	debug_return_bool(false);
    }

    /* Wait for the child to enter trace stop and continue it. */
    for (;;) {
	if (waitpid(child, &status, __WALL) != -1)
	    break;
	if (errno == EINTR)
	    continue;
	sudo_warn(U_("%s: %s"), __func__, "waitpid");
	debug_return_bool(false);
    }
    if (!WIFSTOPPED(status)) {
	sudo_warnx(U_("process %d exited unexpectedly"), (int)child);
	debug_return_bool(false);
    }
    if (ptrace(PTRACE_CONT, child, NULL, (long)SIGUSR1) == -1) {
	sudo_warn("ptrace(PTRACE_CONT, %d, NULL, SIGUSR1)", (int)child);
	debug_return_bool(false);
    }

    debug_return_bool(true);
}

/*
 * Intercept execve(2) and perform a policy check.
 * Reads current registers and execve(2) arguments.
 * If the command is not allowed by policy, fail with EACCES.
 * If the command is allowed, update argv if needed before continuing.
 * Returns true on success and false on error.
 */
static bool
ptrace_intercept_execve(pid_t pid, struct intercept_closure *closure)
{
    char *pathname, **argv, **envp, *buf;
    int argc, envc, syscallno;
    struct user_pt_regs regs;
    char cwd[PATH_MAX];
    struct iovec iov;
    bool ret = false;
    debug_decl(ptrace_intercept_execve, SUDO_DEBUG_UTIL);

    /* Do not check the policy if we are executing the initial command. */
    if (closure->initial_command != 0) {
	closure->initial_command--;
	debug_return_bool(true);
    }

    /* Get the registers. */
    /* XXX - for amd64 and i386 use PTRACE_GETREGS/PTRACE_SETREGS instead. */
    iov.iov_base = &regs;
    iov.iov_len = sizeof(regs);
    if (ptrace(PTRACE_GETREGSET, pid, (long)NT_PRSTATUS, &iov) == -1) {
	sudo_warn(U_("unable to get registers for process %d"), (int)pid);
	debug_return_bool(false);
    }

    /* System call number is stored in the lower 32-bits on 64-bit platforms. */
    syscallno = reg_syscall(&regs) & 0xffffffff;
    switch (syscallno) {
    case __NR_execve:
	/* Handled below. */
	break;
    case __NR_execveat:
	/* We don't currently check execveat(2). */
	debug_return_bool(true);
	break;
    default:
	sudo_warnx("%s: unexpected system call %d", __func__, syscallno);
	debug_return_bool(false);
    }

    /* Get the current working directory and execve info. */
    if (!getcwd_by_pid(pid, cwd, sizeof(cwd)))
	(void)strlcpy(cwd, "unknown", sizeof(cwd));
    buf = get_execve_info(pid, &regs, &pathname, &argc, &argv, &envc, &envp);
    if (buf == NULL) {
	sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_ERRNO,
	    "%s: %d: unable to get execve info", __func__, (int)pid);

	/* Unrecoverable error, kill the process if it still exists. */
	if (errno != ESRCH)
	    kill(pid, SIGKILL);
	debug_return_bool(false);
    }

    /* Perform a policy check. */
    sudo_debug_printf(SUDO_DEBUG_INFO, "%s: %d: checking policy for %s",
	__func__, (int)pid, pathname);

    argv[0] = pathname;
    if (!intercept_check_policy(pathname, argc, argv, envc, envp, cwd,
	    closure)) {
	sudo_warnx("%s", U_(closure->errstr));
    }

    if (closure->state == POLICY_ACCEPT) {
	/*
	 * Update argv if the policy modified it.
	 * We don't currently ever modify envp.
	 */
	int i;
	bool match = strcmp(pathname, closure->command) == 0;
	if (match) {
	    for (i = 0; closure->run_argv[i] != NULL && argv[i] != NULL; i++) {
		if (strcmp(closure->run_argv[i], argv[i]) != 0) {
		    match = false;
		    break;
		}
	    }
	}
	if (!match) {
	    /*
	     * Need to replace argv with run_argv.  We can use space below
	     * the stack pointer to store the new copy of argv.
	     * On amd64 there is a 128 byte red zone that must be avoided.
	     * Note: on pa-risc the stack grows up, not down.
	     */
	    long sp = reg_sp(&regs) - 128;
	    long new_argv, strtab;
	    struct iovec iov;
	    size_t len;

	    /* Calculate the amount of space required for argv + strings. */
	    size_t argv_size = sizeof(long);
	    for (argc = 0; closure->run_argv[argc] != NULL; argc++) {
		/* Align length to word boundary to simplify writes. */
		len = WORDALIGN(strlen(closure->run_argv[argc]) + 1);
	    	argv_size += sizeof(long) + len;
	    }

	    /* Reserve stack space for argv (w/ NULL) and its strings. */
	    sp -= argv_size;
	    new_argv = sp;
	    strtab = sp + ((argc + 1) * sizeof(long));

	    /* Copy new argv into tracee one word at a time. */
	    for (i = 0; i < argc; i++) {
		/* Store string address as new_argv[i]. */
		if (ptrace(PTRACE_POKEDATA, pid, sp, strtab) == -1) {
		    sudo_warn("ptrace(PTRACE_POKEDATA, %d, 0x%lx, 0x%lx)",
			(int)pid, sp, strtab);
		    goto done;
		}
		sp += sizeof(long);

		/* Write new_argv[i] to the string table. */
		len = ptrace_write_string(pid, strtab, closure->run_argv[i]);
		if (len == (size_t)-1)
		    goto done;
		strtab += len;
	    }

	    /* Write terminating NULL pointer. */
	    if (ptrace(PTRACE_POKEDATA, pid, sp, NULL) == -1) {
		sudo_warn("ptrace(PTRACE_POKEDATA, %d, 0x%lx, NULL)",
		    (int)pid, sp);
		goto done;
	    }

	    /* Update argv address in the tracee to our new value. */
	    iov.iov_base = &regs;
	    iov.iov_len = sizeof(regs);
	    reg_arg2(&regs) = new_argv;
	    if (ptrace(PTRACE_SETREGSET, pid, (long)NT_PRSTATUS, &iov) == -1) {
		sudo_warn(U_("unable to set registers for process %d"),
		    (int)pid);
		goto done;
	    }
	}
    } else {
	/* If denied, fake the syscall and set return to EACCES */
	ptrace_fail_syscall(pid, &regs, EACCES);
    }

    ret = true;

done:
    intercept_closure_reset(closure);

    debug_return_bool(ret);
}

/*
 * Handle a process stopped due to ptrace.
 * Returns true if the signal was suppressed and false if it was delivered.
 */
bool
exec_ptrace_handled(pid_t pid, int status, void *intercept)
{
    struct intercept_closure *closure = intercept;
    const int stopsig = WSTOPSIG(status);
    const int sigtrap = status >> 8;
    long signo = 0;
    bool group_stop = false;
    debug_decl(exec_ptrace_handled, SUDO_DEBUG_EXEC);

    if (sigtrap == (SIGTRAP | (PTRACE_EVENT_SECCOMP << 8))) {
	if (!ptrace_intercept_execve(pid, closure))
	    debug_return_bool(true);
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
	    sudo_warn("ptrace(PTRACE_LISTEN, %d, NULL, %d)", (int)pid, stopsig);
    } else {
	/* Restart child. */
	if (ptrace(PTRACE_CONT, pid, NULL, signo) == -1)
	    sudo_warn("ptrace(PTRACE_CONT, %d, NULL, %d)", (int)pid, stopsig);
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
exec_ptrace_handled(pid_t pid, int status, void *intercept)
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
