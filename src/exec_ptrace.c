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

#include <sys/stat.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/wait.h>

#include <errno.h>
#include <limits.h>
#include <signal.h>
#if defined(HAVE_STDINT_H)
# include <stdint.h>
#elif defined(HAVE_INTTYPES_H)
# include <inttypes.h>
#endif
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#if defined(HAVE_ENDIAN_H)
# include <endian.h>
#elif defined(HAVE_SYS_ENDIAN_H)
# include <sys/endian.h>
#elif defined(HAVE_MACHINE_ENDIAN_H)
# include <machine/endian.h>
#else
# include "compat/endian.h"
#endif

#include "sudo.h"
#include "sudo_exec.h"

#ifdef HAVE_PTRACE_INTERCEPT
# include "exec_intercept.h"
# include "exec_ptrace.h"

/* We need to take care when ptracing 32-bit binaries on 64-bit kernels. */
# ifdef __LP64__
#  define COMPAT_FLAG 0x01
# else
#  define COMPAT_FLAG 0x00
# endif

static int seccomp_trap_supported = -1;

/* Register getters and setters. */
# ifdef SECCOMP_AUDIT_ARCH_COMPAT
static inline unsigned long
get_stack_pointer(struct sudo_ptrace_regs *regs)
{
    if (regs->compat) {
	return compat_reg_sp(regs->u.compat);
    } else {
	return reg_sp(regs->u.native);
    }
}

static inline void
set_sc_retval(struct sudo_ptrace_regs *regs, int retval)
{
    if (regs->compat) {
	compat_reg_set_retval(regs->u.compat, retval);
    } else {
	reg_set_retval(regs->u.native, retval);
    }
}

static inline int
get_syscallno(struct sudo_ptrace_regs *regs)
{
    if (regs->compat) {
	return compat_reg_syscall(regs->u.compat);
    } else {
	return reg_syscall(regs->u.native);
    }
}

static inline void
set_syscallno(pid_t pid, struct sudo_ptrace_regs *regs, int syscallno)
{
    if (regs->compat) {
	compat_reg_set_syscall(regs->u.compat, syscallno);
    } else {
	reg_set_syscall(regs->u.native, syscallno);
    }
}

static inline unsigned long
get_sc_arg1(struct sudo_ptrace_regs *regs)
{
    if (regs->compat) {
	return compat_reg_arg1(regs->u.compat);
    } else {
	return reg_arg1(regs->u.native);
    }
}

static inline void
set_sc_arg1(struct sudo_ptrace_regs *regs, unsigned long addr)
{
    if (regs->compat) {
	compat_reg_set_arg1(regs->u.compat, addr);
    } else {
	reg_set_arg1(regs->u.native, addr);
    }
}

static inline unsigned long
get_sc_arg2(struct sudo_ptrace_regs *regs)
{
    if (regs->compat) {
	return compat_reg_arg2(regs->u.compat);
    } else {
	return reg_arg2(regs->u.native);
    }
}

static inline void
set_sc_arg2(struct sudo_ptrace_regs *regs, unsigned long addr)
{
    if (regs->compat) {
	compat_reg_set_arg2(regs->u.compat, addr);
    } else {
	reg_set_arg2(regs->u.native, addr);
    }
}

static inline unsigned long
get_sc_arg3(struct sudo_ptrace_regs *regs)
{
    if (regs->compat) {
	return compat_reg_arg3(regs->u.compat);
    } else {
	return reg_arg3(regs->u.native);
    }
}

#  ifdef notyet
static inline void
set_sc_arg3(struct sudo_ptrace_regs *regs, unsigned long addr)
{
    if (regs->compat) {
	compat_reg_set_arg3(regs->u.compat, addr);
    } else {
	reg_set_arg3(regs->u.native, addr);
    }
}

static inline unsigned long
get_sc_arg4(struct sudo_ptrace_regs *regs)
{
    if (regs->compat) {
	return compat_reg_arg4(regs->u.compat);
    } else {
	return reg_arg4(regs->u.native);
    }
}

static inline void
set_sc_arg4(struct sudo_ptrace_regs *regs, unsigned long addr)
{
    if (regs->compat) {
	compat_reg_set_arg4(regs->u.compat, addr);
    } else {
	reg_set_arg4(regs->u.native, addr);
    }
}
#  endif /* notyet */

# else /* SECCOMP_AUDIT_ARCH_COMPAT */

static inline unsigned long
get_stack_pointer(struct sudo_ptrace_regs *regs)
{
    return reg_sp(regs->u.native);
}

static inline void
set_sc_retval(struct sudo_ptrace_regs *regs, int retval)
{
    reg_set_retval(regs->u.native, retval);
}

static inline int
get_syscallno(struct sudo_ptrace_regs *regs)
{
    return reg_syscall(regs->u.native);
}

static inline void
set_syscallno(pid_t pid, struct sudo_ptrace_regs *regs, int syscallno)
{
    reg_set_syscall(regs->u.native, syscallno);
}

static inline unsigned long
get_sc_arg1(struct sudo_ptrace_regs *regs)
{
    return reg_arg1(regs->u.native);
}

static inline void
set_sc_arg1(struct sudo_ptrace_regs *regs, unsigned long addr)
{
    reg_set_arg1(regs->u.native, addr);
}

static inline unsigned long
get_sc_arg2(struct sudo_ptrace_regs *regs)
{
    return reg_arg2(regs->u.native);
}

static inline void
set_sc_arg2(struct sudo_ptrace_regs *regs, unsigned long addr)
{
    reg_set_arg2(regs->u.native, addr);
}

static inline unsigned long
get_sc_arg3(struct sudo_ptrace_regs *regs)
{
    return reg_arg3(regs->u.native);
}

#  ifdef notyet
static inline void
set_sc_arg3(struct sudo_ptrace_regs *regs, unsigned long addr)
{
    reg_set_arg3(regs->u.native, addr);
}

static inline unsigned long
get_sc_arg4(struct sudo_ptrace_regs *regs)
{
    return reg_arg4(regs->u.native);
}

static inline void
set_sc_arg4(struct sudo_ptrace_regs *regs, unsigned long addr)
{
    reg_set_arg4(regs->u.native, addr);
}
#  endif /* notyet */
# endif /* SECCOMP_AUDIT_ARCH_COMPAT */

/*
 * Get the registers for the given process and store in regs, which
 * must be large enough.  If the compat flag is set, pid is expected
 * to refer to a 32-bit process and the md parameters will be filled
 * in accordingly.
 * Returns true on success, else false.
 */
static bool
ptrace_getregs(int pid, struct sudo_ptrace_regs *regs, bool compat)
{
    debug_decl(ptrace_getregs, SUDO_DEBUG_EXEC);

# ifdef __mips__
    /* PTRACE_GETREGSET has bugs with the MIPS o32 ABI at least. */
    if (ptrace(PTRACE_GETREGS, pid, NULL, &regs->u) == -1)
	debug_return_bool(false);
# else
    struct iovec iov;
    iov.iov_base = &regs->u;
    iov.iov_len = sizeof(regs->u);
    if (ptrace(PTRACE_GETREGSET, pid, (void *)NT_PRSTATUS, &iov) == -1)
	debug_return_bool(false);
# endif /* __mips__ */

    /* Machine-dependent parameters to support compat binaries. */
    if (compat) {
	regs->compat = true;
	regs->wordsize = sizeof(int);
    } else {
	regs->compat = false;
	regs->wordsize = sizeof(unsigned long);
    }

    debug_return_bool(true);
}

/*
 * Set the registers, specified by regs, for the given process.
 * Returns true on success, else false.
 */
static bool
ptrace_setregs(int pid, struct sudo_ptrace_regs *regs)
{
    debug_decl(ptrace_setregs, SUDO_DEBUG_EXEC);

# ifdef __mips__
    /* PTRACE_SETREGSET has bugs with the MIPS o32 ABI at least. */
    if (ptrace(PTRACE_SETREGS, pid, NULL, &regs->u) == -1)
	debug_return_bool(false);
# else
    struct iovec iov;
    iov.iov_base = &regs->u;
    iov.iov_len = sizeof(regs->u);
    if (ptrace(PTRACE_SETREGSET, pid, (void *)NT_PRSTATUS, &iov) == -1)
	debug_return_bool(false);
# endif /* __mips__ */

    debug_return_bool(true);
}

/*
 * Read the string at addr and store in buf.
 * Returns the number of bytes stored, including the NUL.
 */
static size_t
ptrace_read_string(pid_t pid, unsigned long addr, char *buf, size_t bufsize)
{
    const char *buf0 = buf;
    const char *cp;
    unsigned long word;
    unsigned int i;
    debug_decl(ptrace_read_string, SUDO_DEBUG_EXEC);

    /*
     * Read the string via ptrace(2) one (native) word at a time.
     * We use the native word size even in compat mode because that
     * is the unit ptrace(2) uses.
     */
    for (;;) {
	word = ptrace(PTRACE_PEEKDATA, pid, addr, NULL);
	if (word == (unsigned long)-1) {
	    sudo_warn("%s: ptrace(PTRACE_PEEKDATA, %d, 0x%lx, NULL)",
		__func__, (int)pid, addr);
	    debug_return_ssize_t(-1);
	}

	cp = (char *)&word;
	for (i = 0; i < sizeof(unsigned long); i++) {
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
	addr += sizeof(unsigned long);
    }
}

/*
 * Read the string vector at addr and store in vec, which must have
 * sufficient space.  Strings are stored in buf.
 * Returns the number of bytes in buf consumed (including NULs).
 */
static size_t
ptrace_read_vec(pid_t pid, struct sudo_ptrace_regs *regs, unsigned long addr,
    char **vec, char *buf, size_t bufsize)
{
# ifdef SECCOMP_AUDIT_ARCH_COMPAT
    unsigned long next_word = -1;
# endif
    unsigned long word;
    char *buf0 = buf;
    int len = 0;
    size_t slen;
    debug_decl(ptrace_read_vec, SUDO_DEBUG_EXEC);

    /* Fill in vector. */
    for (;;) {
# ifdef SECCOMP_AUDIT_ARCH_COMPAT
	if (next_word == (unsigned long)-1) {
	    word = ptrace(PTRACE_PEEKDATA, pid, addr, NULL);
	    if (regs->compat) {
		/* Stash the next compat word in next_word. */
#  if BYTE_ORDER == BIG_ENDIAN
		next_word = word & 0xffffffffU;
		word >>= 32;
#  else
		next_word = word >> 32;
		word &= 0xffffffffU;
#  endif
	    }
	} else {
	    /* Use the stashed value of the next word. */
	    word = next_word;
	    next_word = (unsigned long)-1;
	}
# else /* SECCOMP_AUDIT_ARCH_COMPAT */
	word = ptrace(PTRACE_PEEKDATA, pid, addr, NULL);
# endif /* SECCOMP_AUDIT_ARCH_COMPAT */
	switch (word) {
	case -1:
	    sudo_warn("%s: ptrace(PTRACE_PEEKDATA, %d, 0x%lx, NULL)",
		__func__, (int)pid, addr);
	    debug_return_size_t(-1);
	case 0:
	    vec[len] = NULL;
	    debug_return_size_t(buf - buf0);
	default:
	    slen = ptrace_read_string(pid, word, buf, bufsize);
	    if (slen == (size_t)-1)
		debug_return_size_t(-1);
	    vec[len++] = buf;
	    buf += slen + 1;
	    bufsize -= slen + 1;
	    addr += regs->wordsize;
	    continue;
	}
    }
}

/*
 * Return the length of the string vector at addr or -1 on error.
 */
static int
ptrace_get_vec_len(pid_t pid, struct sudo_ptrace_regs *regs, unsigned long addr)
{
# ifdef SECCOMP_AUDIT_ARCH_COMPAT
    unsigned long next_word = -1;
# endif
    unsigned long word;
    int len = 0;
    debug_decl(ptrace_get_vec_len, SUDO_DEBUG_EXEC);

    for (;;) {
# ifdef SECCOMP_AUDIT_ARCH_COMPAT
	if (next_word == (unsigned long)-1) {
	    word = ptrace(PTRACE_PEEKDATA, pid, addr, NULL);
	    if (regs->compat) {
		/* Stash the next compat word in next_word. */
#  if BYTE_ORDER == BIG_ENDIAN
		next_word = word & 0xffffffffU;
		word >>= 32;
#  else
		next_word = word >> 32;
		word &= 0xffffffffU;
#  endif
	    }
	} else {
	    /* Use the stashed value of the next word. */
	    word = next_word;
	    next_word = (unsigned long)-1;
	}
# else /* SECCOMP_AUDIT_ARCH_COMPAT */
	word = ptrace(PTRACE_PEEKDATA, pid, addr, NULL);
# endif /* SECCOMP_AUDIT_ARCH_COMPAT */
	switch (word) {
	case -1:
	    sudo_warn("%s: ptrace(PTRACE_PEEKDATA, %d, 0x%lx, NULL)",
		__func__, (int)pid, addr);
	    debug_return_int(-1);
	case 0:
	    debug_return_int(len);
	default:
	    len++;
	    addr += regs->wordsize;
	    continue;
	}
    }
}

/*
 * Write the NUL-terminated string str to addr in the tracee.
 * Returns the number of bytes written, including trailing NUL.
 */
static size_t
ptrace_write_string(pid_t pid, unsigned long addr, const char *str)
{
    const char *str0 = str;
    unsigned int i;
    union {
	unsigned long word;
	char buf[sizeof(unsigned long)];
    } u;
    debug_decl(ptrace_write_string, SUDO_DEBUG_EXEC);

    /*
     * Write the string via ptrace(2) one (native) word at a time.
     * We use the native word size even in compat mode because that
     * is the unit ptrace(2) writes in terms of.
     */
    for (;;) {
	for (i = 0; i < sizeof(u.buf); i++) {
	    if (*str == '\0') {
		/* NUL-pad buf to sizeof(unsigned long). */
		u.buf[i] = '\0';
		continue;
	    }
	    u.buf[i] = *str++;
	}
	if (ptrace(PTRACE_POKEDATA, pid, addr, u.word) == -1) {
	    sudo_warn("%s: ptrace(PTRACE_POKEDATA, %d, 0x%lx, %.*s)",
		__func__, (int)pid, addr, (int)sizeof(u.buf), u.buf);
	    debug_return_size_t(-1);
	}
	if ((u.word & 0xff) == 0) {
	    /* If the last byte we wrote is a NUL we are done. */
	    debug_return_size_t(str - str0 + 1);
	}
	addr += sizeof(unsigned long);
    }
}

/*
 * Write the string vector vec to addr in the tracee which must have
 * sufficient space.  Strings are written to strtab.
 * Returns the number of bytes used in strtab (including NULs).
 */
static size_t
ptrace_write_vec(pid_t pid, struct sudo_ptrace_regs *regs, char **vec,
    unsigned long addr, unsigned long strtab)
{
    const unsigned long strtab0 = strtab;
    size_t i, len;
    debug_decl(ptrace_write_vec, SUDO_DEBUG_EXEC);

    /* Copy string vector into tracee one word at a time. */
    for (i = 0; vec[i] != NULL; i++) {
	unsigned long word = strtab;

	/* First write the actual string to tracee's string table. */
	len = ptrace_write_string(pid, strtab, vec[i]);
	if (len == (size_t)-1)
	    debug_return_int(-1);
	strtab += len;

# ifdef SECCOMP_AUDIT_ARCH_COMPAT
	if (regs->compat) {
	    /*
	     * For compat binaries we need to pack two 32-bit string addresses
	     * into a single 64-bit word.  If this is the last string, NULL
	     * will be written as the second 32-bit address.
	     */
	    if ((i & 1) == 1) {
		/* Wrote this string address last iteration. */
		continue;
	    }
#  if BYTE_ORDER == BIG_ENDIAN
	    word <<= 32;
	    if (vec[i + 1] != NULL)
		word |= strtab;
#  else
	    if (vec[i + 1] != NULL)
		word |= strtab << 32;
#  endif
	}
# endif
	/* Next write the string address to tracee at addr. */
	if (ptrace(PTRACE_POKEDATA, pid, addr, word) == -1) {
	    sudo_warn("%s: ptrace(PTRACE_POKEDATA, %d, 0x%lx, 0x%lx)",
		__func__, (int)pid, addr, word);
	    debug_return_int(-1);
	}
	addr += sizeof(unsigned long);
    }

    /* Finally, write the terminating NULL to tracee if needed. */
    if (!regs->compat || (i & 1) == 0) {
	if (ptrace(PTRACE_POKEDATA, pid, addr, NULL) == -1) {
	    sudo_warn("%s: ptrace(PTRACE_POKEDATA, %d, 0x%lx, NULL)",
		__func__, (int)pid, addr);
	    debug_return_int(-1);
	}
    }

    debug_return_size_t(strtab - strtab0);
}

/*
 * Use /proc/PID/cwd to determine the current working directory.
 * Returns true on success, else false.
 */
static bool
getcwd_by_pid(pid_t pid, char *buf, size_t bufsize)
{
    size_t len;
    char path[PATH_MAX];
    debug_decl(getcwd_by_pid, SUDO_DEBUG_EXEC);

    len = snprintf(path, sizeof(path), "/proc/%d/cwd", (int)pid);
    if (len < sizeof(path)) {
	len = readlink(path, buf, bufsize - 1);
	if (len != (size_t)-1) {
	    /* readlink(2) does not add the NUL for us. */
	    buf[len] = '\0';
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
get_execve_info(pid_t pid, struct sudo_ptrace_regs *regs, char **pathname_out,
    int *argc_out, char ***argv_out, int *envc_out, char ***envp_out)
{
    char *argbuf, *strtab, *pathname, **argv, **envp;
    unsigned long path_addr, argv_addr, envp_addr;
    int argc, envc;
    size_t bufsize, len;
    debug_decl(get_execve_info, SUDO_DEBUG_EXEC);

    bufsize = sysconf(_SC_ARG_MAX) + PATH_MAX;
    argbuf = malloc(bufsize);
    if (argbuf == NULL)
	sudo_fatalx(U_("%s: %s"), __func__, U_("unable to allocate memory"));

    /* execve(2) takes three arguments: pathname, argv, envp. */
    path_addr = get_sc_arg1(regs);
    argv_addr = get_sc_arg2(regs);
    envp_addr = get_sc_arg3(regs);

    /* Count argv and envp */
    argc = ptrace_get_vec_len(pid, regs, argv_addr);
    envc = ptrace_get_vec_len(pid, regs, envp_addr);
    if (argc == -1 || envc == -1)
	goto bad;

    /* Reserve argv and envp at the start of argbuf so they are aligned. */
    if ((argc + 1 + envc + 1) * sizeof(unsigned long) >= bufsize) {
	sudo_warnx("%s", U_("insufficient space for execve arguments"));
	goto bad;
    }
    argv = (char **)argbuf;
    envp = argv + argc + 1;
    strtab = (char *)(envp + envc + 1);
    bufsize -= strtab - argbuf;

    /* Read argv */
    len = ptrace_read_vec(pid, regs, argv_addr, argv, strtab, bufsize);
    if (len == (size_t)-1) {
	sudo_warn(U_("unable to read execve %s for process %d"),
	    "argv", (int)pid);
	goto bad;
    }
    strtab += len;
    bufsize -= len;

    /* Read envp */
    len = ptrace_read_vec(pid, regs, envp_addr, envp, strtab, bufsize);
    if (len == (size_t)-1) {
	sudo_warn(U_("unable to read execve %s for process %d"),
	    "envp", (int)pid);
	goto bad;
    }
    strtab += len;
    bufsize -= len;

    /* Read the pathname. */
    len = ptrace_read_string(pid, path_addr, strtab, bufsize);
    if (len == (size_t)-1) {
	sudo_warn(U_("unable to read execve %s for process %d"),
	    "pathname", (int)pid);
	goto bad;
    }
    pathname = strtab;

    sudo_debug_execve(SUDO_DEBUG_DIAG, pathname, argv, envp);

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
ptrace_fail_syscall(pid_t pid, struct sudo_ptrace_regs *regs, int ecode)
{
    sigset_t chldmask;
    bool ret = false;
    int status;
    debug_decl(ptrace_fail_syscall, SUDO_DEBUG_EXEC);

    /* Cause the syscall to fail by changing its number to -1. */
    set_syscallno(pid, regs, -1);
    if (!ptrace_setregs(pid, regs)) {
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
    set_sc_retval(regs, -ecode);
    if (!ptrace_setregs(pid, regs)) {
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
static bool
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
# ifdef SECCOMP_AUDIT_ARCH_COMPAT2
	/* Match on the compat2 architecture or jump to the compat check. */
	BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SECCOMP_AUDIT_ARCH_COMPAT2, 0, 4),
	/* Load syscall number into the accumulator. */
	BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),
	/* Jump to trace for compat2 execve(2)/execveat(2), else allow. */
	BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, COMPAT2_execve, 1, 0),
	BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, COMPAT2_execveat, 0, 13),
	/* Trace execve(2)/execveat(2) syscalls (w/ compat flag) */
	BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_TRACE | COMPAT_FLAG),
# endif /* SECCOMP_AUDIT_ARCH_COMPAT2 */
# ifdef SECCOMP_AUDIT_ARCH_COMPAT
	/* Match on the compat architecture or jump to the native arch check. */
	BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SECCOMP_AUDIT_ARCH_COMPAT, 0, 4),
	/* Load syscall number into the accumulator. */
	BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),
	/* Jump to trace for compat execve(2)/execveat(2), else allow. */
	BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, COMPAT_execve, 1, 0),
	BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, COMPAT_execveat, 0, 8),
	/* Trace execve(2)/execveat(2) syscalls (w/ compat flag) */
	BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_TRACE | COMPAT_FLAG),
# endif /* SECCOMP_AUDIT_ARCH_COMPAT */
	/* Jump to the end unless the architecture matches. */
	BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SECCOMP_AUDIT_ARCH, 0, 6),
	/* Load syscall number into the accumulator. */
	BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),
	/* Jump to trace for execve(2)/execveat(2), else allow. */
# ifdef X32_execve
	BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, X32_execve, 3, 0),
	BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, X32_execveat, 2, 0),
# else
	/* No x32 support, check native system call numbers. */
	BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_execve, 3, 0),
	BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_execveat, 2, 3),
# endif /* X32_execve */
	/* If no x32 support, these two instructions are never reached. */
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
    debug_decl(set_exec_filter, SUDO_DEBUG_EXEC);

    /* We must set SECCOMP_MODE_FILTER before dropping privileges. */
    if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &exec_fprog) == -1) {
	sudo_warn("%s", U_("unable to set seccomp filter"));
	debug_return_bool(false);
    }
    debug_return_bool(true);
}

/*
 * Seize control of the specified child process which must be in
 * ptrace wait.  Returns true on success, false if child is already
 * being traced and -1 on error.
 */
int
exec_ptrace_seize(pid_t child)
{
    const long ptrace_opts = PTRACE_O_TRACESECCOMP|PTRACE_O_TRACECLONE|
			     PTRACE_O_TRACEFORK|PTRACE_O_TRACEVFORK;
    int ret = -1;
    int status;
    debug_decl(exec_ptrace_seize, SUDO_DEBUG_EXEC);

    /* Seize control of the child process. */
    if (ptrace(PTRACE_SEIZE, child, NULL, ptrace_opts) == -1) {
	/*
	 * If the process is already being traced, we will get EPERM.
	 * We don't treat that as a fatal error since we want it to be
	 * possible to run sudo inside a sudo shell with intercept enabled.
	 */
	if (errno != EPERM) {
	    sudo_warn("%s: ptrace(PTRACE_SEIZE, %d, NULL, 0x%lx)",
		__func__, (int)child, ptrace_opts);
	    goto done;
	}
	sudo_debug_printf(SUDO_DEBUG_WARN,
	    "%s: unable to trace process %d, already being traced?",
		__func__, (int)child);
	ret = false;
    }

    /* The child is suspended waiting for SIGUSR1, wake it up. */
    if (kill(child, SIGUSR1) == -1) {
	sudo_warn("kill(%d, SIGUSR1)", (int)child);
	goto done;
    }
    if (!ret)
	goto done;

    /* Wait for the child to enter trace stop and continue it. */
    for (;;) {
	if (waitpid(child, &status, __WALL) != -1)
	    break;
	if (errno == EINTR)
	    continue;
	sudo_warn(U_("%s: %s"), __func__, "waitpid");
	goto done;
    }
    if (!WIFSTOPPED(status)) {
	sudo_warnx(U_("process %d exited unexpectedly"), (int)child);
	goto done;
    }
    if (ptrace(PTRACE_CONT, child, NULL, (void *)SIGUSR1) == -1) {
	sudo_warn("%s: ptrace(PTRACE_CONT, %d, NULL, SIGUSR1)",
	    __func__, (int)child);
	goto done;
    }

    ret = true;

done:
    debug_return_int(ret);
}

/*
 * Verify that the execve(2) argument we wrote match the contents of closure.
 * Returns true if they match, else false.
 */
static bool
verify_execve_info(pid_t pid, struct sudo_ptrace_regs *regs,
    struct intercept_closure *closure)
{
    char *pathname, **argv, **envp, *buf;
    int argc, envc, i;
    bool ret = true;
    debug_decl(verify_execve_info, SUDO_DEBUG_EXEC);

    buf = get_execve_info(pid, regs, &pathname, &argc, &argv,
	&envc, &envp);
    if (buf == NULL)
	debug_return_bool(false);

    if (pathname == NULL || strcmp(pathname, closure->command) != 0) {
	sudo_warn(
	    U_("pathname mismatch, expected \"%s\", got \"%s\""),
	    closure->command, pathname ? pathname : "(NULL)");
	ret = false;
    }
    for (i = 0; i < argc; i++) {
	if (closure->run_argv[i] == NULL) {
	    ret = false;
	    sudo_warn(
		U_("%s[%d] mismatch, expected \"%s\", got \"%s\""),
		"argv", i, "(NULL)", argv[i] ? argv[i] : "(NULL)");
	    break;
	} else if (argv[i] == NULL) {
	    ret = false;
	    sudo_warn(
		U_("%s[%d] mismatch, expected \"%s\", got \"%s\""),
		"argv", i, closure->run_argv[i], "(NULL)");
	    break;
	} else if (strcmp(argv[i], closure->run_argv[i]) != 0) {
	    ret = false;
	    sudo_warn(
		U_("%s[%d] mismatch, expected \"%s\", got \"%s\""),
		"argv", i, closure->run_argv[i], argv[i]);
	}
    }
    for (i = 0; i < envc; i++) {
	if (closure->run_envp[i] == NULL) {
	    ret = false;
	    sudo_warn(
		U_("%s[%d] mismatch, expected \"%s\", got \"%s\""),
		"envp", i, "(NULL)", envp[i] ? envp[i] : "(NULL)");
	    break;
	} else if (envp[i] == NULL) {
	    ret = false;
	    sudo_warn(
		U_("%s[%d] mismatch, expected \"%s\", got \"%s\""),
		"envp", i, closure->run_envp[i], "(NULL)");
	    break;
	} else if (strcmp(envp[i], closure->run_envp[i]) != 0) {
	    ret = false;
	    sudo_warn(
		U_("%s[%d] mismatch, expected \"%s\", got \"%s\""),
		"envp", i, closure->run_envp[i], envp[i]);
	}
    }
    free(buf);

    debug_return_bool(ret);
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
    struct sudo_ptrace_regs regs;
    bool path_mismatch = false;
    bool argv_mismatch = false;
    char cwd[PATH_MAX];
    unsigned long msg;
    bool ret = false;
    struct stat sb;
    int i;
    debug_decl(ptrace_intercept_execve, SUDO_DEBUG_EXEC);

    /* Do not check the policy if we are executing the initial command. */
    if (closure->initial_command != 0) {
	closure->initial_command--;
	debug_return_bool(true);
    }

    /* Get compat flag. */
    if (ptrace(PTRACE_GETEVENTMSG, pid, NULL, &msg) == -1) {
	sudo_warn(U_("unable to get event message for process %d"), (int)pid);
	debug_return_bool(false);
    }

    /* Get the registers. */
    if (!ptrace_getregs(pid, &regs, msg)) {
	sudo_warn(U_("unable to get registers for process %d"), (int)pid);
	debug_return_bool(false);
    }

# ifdef SECCOMP_AUDIT_ARCH_COMPAT
    if (regs.compat) {
	syscallno = get_syscallno(&regs);
	switch (syscallno) {
	case COMPAT_execve:
	    /* Handled below. */
	    break;
	case COMPAT_execveat:
	    /* We don't currently check execveat(2). */
	    debug_return_bool(true);
	    break;
	default:
	    sudo_warnx("%s: unexpected compat system call %d",
		__func__, syscallno);
	    debug_return_bool(false);
	}
    } else
# endif /* SECCOMP_AUDIT_ARCH_COMPAT */
    {
	syscallno = get_syscallno(&regs);
	switch (syscallno) {
# ifdef X32_execve
	case X32_execve:
# endif
	case __NR_execve:
	    /* Handled below. */
	    break;
# ifdef X32_execveat
	case X32_execveat:
# endif
	case __NR_execveat:
	    /* We don't currently check execveat(2). */
	    debug_return_bool(true);
	    break;
	default:
	    sudo_warnx("%s: unexpected system call %d", __func__, syscallno);
	    debug_return_bool(false);
	}
    }

    /* Get the current working directory and execve info. */
    if (!getcwd_by_pid(pid, cwd, sizeof(cwd)))
	(void)strlcpy(cwd, "unknown", sizeof(cwd));
    buf = get_execve_info(pid, &regs, &pathname, &argc, &argv,
	&envc, &envp);
    if (buf == NULL) {
	sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_ERRNO,
	    "%s: %d: unable to get execve info", __func__, (int)pid);

	/* Unrecoverable error, kill the process if it still exists. */
	if (errno != ESRCH)
	    kill(pid, SIGKILL);
	debug_return_bool(false);
    }

    /*
     * Short-circuit the policy check if the command doesn't exist.
     * Otherwise, both sudo and the shell will report the error.
     */
    if (stat(pathname, &sb) == -1) {
	ptrace_fail_syscall(pid, &regs, errno);
	ret = true;
	goto done;
    }

    /* Perform a policy check. */
    sudo_debug_printf(SUDO_DEBUG_INFO, "%s: %d: checking policy for %s",
	__func__, (int)pid, pathname);
    argv[0] = pathname;
    if (!intercept_check_policy(pathname, argc, argv, envc, envp, cwd,
	    closure)) {
	sudo_warnx("%s", U_(closure->errstr));
    }

    switch (closure->state) {
    case POLICY_TEST:
	path_mismatch = true;
	argv_mismatch = true;
	if (closure->command == NULL)
	    closure->command = pathname;
	if (closure->run_argv == NULL)
	    closure->run_argv = argv;
	if (closure->run_envp == NULL)
	    closure->run_envp = envp;
	FALLTHROUGH;
    case POLICY_ACCEPT:
	/*
	 * Update pathname and argv if the policy modified it.
	 * We don't currently ever modify envp.
	 */
	if (strcmp(pathname, closure->command) != 0)
	    path_mismatch = true;
	for (i = 0; closure->run_argv[i] != NULL && argv[i] != NULL; i++) {
	    if (strcmp(closure->run_argv[i], argv[i]) != 0) {
		argv_mismatch = true;
		break;
	    }
	}

	if (path_mismatch || argv_mismatch) {
	    /*
	     * Need to rewrite pathname and/or argv.
	     * We can use space below the stack pointer to store the data.
	     * On amd64 there is a 128 byte red zone that must be avoided.
	     * Note: on pa-risc the stack grows up, not down.
	     */
	    unsigned long sp = get_stack_pointer(&regs) - 128;
	    unsigned long strtab;
	    size_t len, space = 0;

	    sudo_debug_execve(SUDO_DEBUG_DIAG, closure->command,
		closure->run_argv, envp);

	    /*
	     * Calculate the amount of space required for pointers + strings.
	     * Since ptrace(2) always writes in sizeof(long) increments we
	     * need to be careful to avoid overwriting what we have already
	     * written for compat binaries (where the word size doesn't match).
	     *
	     * This is mostly a problem for the string table since we do
	     * interleaved writes of the argument vector pointers and the
	     * strings they refer to.  For native binaries, it is sufficient
	     * to align the string table on a word boundary.  For compat
	     * binaries, if argc is odd, writing the last pointer will overlap
	     * the first string so leave an extra word in between them.
	     */
	    if (argv_mismatch) {
		/* argv pointers */
		space += (argc + 1 + regs.compat) * regs.wordsize;

		/* argv strings */
		for (argc = 0; closure->run_argv[argc] != NULL; argc++) {
		    space += strlen(closure->run_argv[argc]) + 1;
		}
	    }
	    if (path_mismatch) {
		/* pathname string */
		space += strlen(closure->command) + 1;
	    }

	    /* Reserve stack space for path, argv (w/ NULL) and its strings. */
	    sp -= WORDALIGN(space, regs);
	    strtab = sp;

	    if (argv_mismatch) {
		/* Update argv address in the tracee to our new value. */
		set_sc_arg2(&regs, sp);

		/* Skip over argv pointers (plus NULL) for string table. */
		strtab += (argc + 1 + regs.compat) * regs.wordsize;

		len = ptrace_write_vec(pid, &regs, closure->run_argv,
		    sp, strtab);
		if (len == (size_t)-1)
		    goto done;
		strtab += len;
	    }
	    if (path_mismatch) {
		/* Update pathname address in the tracee to our new value. */
		set_sc_arg1(&regs, strtab);

		/* Write pathname to the string table. */
		len = ptrace_write_string(pid, strtab, closure->command);
		if (len == (size_t)-1)
		    goto done;
	    }

	    /* Update args in the tracee to the new values. */
	    if (!ptrace_setregs(pid, &regs)) {
		sudo_warn(U_("unable to set registers for process %d"),
		    (int)pid);
		goto done;
	    }

	    if (closure->state == POLICY_TEST) {
		/* Verify the contents of what we just wrote. */
		if (!verify_execve_info(pid, &regs, closure)) {
		    sudo_debug_printf(SUDO_DEBUG_ERROR,
			"%s: new execve args don't match closure", __func__);
		}
	    }
	}
	break;
    default:
	/* If rejected, fake the syscall and set return to EACCES */
	ptrace_fail_syscall(pid, &regs, EACCES);
	break;
    }

    ret = true;

done:
    free(buf);
    intercept_closure_reset(closure);

    debug_return_bool(ret);
}

/*
 * Handle a process stopped due to ptrace.
 * Restarts the tracee with PTRACE_LISTEN (for a group-stop)
 * or PTRACE_CONT (for signal-delivery-stop).
 * Returns true if stopped by a group-stop, else false.
 */
bool
exec_ptrace_stopped(pid_t pid, int status, void *intercept)
{
    struct intercept_closure *closure = intercept;
    const int stopsig = WSTOPSIG(status);
    const int sigtrap = status >> 8;
    long signo = 0;
    bool group_stop = false;
    debug_decl(exec_ptrace_stopped, SUDO_DEBUG_EXEC);

    if (sigtrap == (SIGTRAP | (PTRACE_EVENT_SECCOMP << 8))) {
	if (!ptrace_intercept_execve(pid, closure)) {
	    sudo_debug_printf(SUDO_DEBUG_ERROR,
		"%s: %d failed to intercept execve", __func__, (int)pid);
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
		break;
	    }
	    FALLTHROUGH;
	default:
	    /* Signal-delivery-stop, deliver signal. */
	    sudo_debug_printf(SUDO_DEBUG_INFO,
		"%s: %d: signal-delivery-stop signal %d",
		__func__, (int)pid, stopsig);
	    signo = stopsig;
	    break;
	}
    }

    if (group_stop) {
	/*
	 * Restart child but prevent it from executing
	 * until SIGCONT is received (simulate SIGSTOP, etc).
	 */
	if (ptrace(PTRACE_LISTEN, pid, NULL, 0L) == -1 && errno != ESRCH)
	    sudo_warn("%s: ptrace(PTRACE_LISTEN, %d, NULL, 0L)",
		__func__, (int)pid);
    } else {
	/* Restart child immediately. */
	if (ptrace(PTRACE_CONT, pid, NULL, signo) == -1 && errno != ESRCH)
	    sudo_warn("%s: ptrace(PTRACE_CONT, %d, NULL, %ld)",
		__func__, (int)pid, signo);
    }

    debug_return_bool(group_stop);
}

bool
exec_ptrace_intercept_supported(void)
{
# ifdef __mips__
    /* MIPS doesn't support changing the syscall return value. */
    return false;
# else
    if (seccomp_trap_supported == -1)
	seccomp_trap_supported = have_seccomp_action("trap");

    return seccomp_trap_supported == true;
# endif
}

bool
exec_ptrace_subcmds_supported(void)
{
    if (seccomp_trap_supported == -1)
	seccomp_trap_supported = have_seccomp_action("trap");

    return seccomp_trap_supported == true;
}
#else
/* STUB */
bool
exec_ptrace_stopped(pid_t pid, int status, void *intercept)
{
    return true;
}

/* STUB */
int
exec_ptrace_seize(pid_t child)
{
    return true;
}

/* STUB */
bool
exec_ptrace_intercept_supported(void)
{
    return false;
}

/* STUB */
bool
exec_ptrace_subcmds_supported(void)
{
    return false;
}
#endif /* HAVE_PTRACE_INTERCEPT */

/*
 * Adjust flags based on the availability of ptrace support.
 */
void
exec_ptrace_fix_flags(struct command_details *details)
{
    debug_decl(exec_ptrace_fix_flags, SUDO_DEBUG_EXEC);

    if (ISSET(details->flags, CD_USE_PTRACE)) {
	/* If both CD_INTERCEPT and CD_LOG_SUBCMDS set, CD_INTERCEPT wins. */
	if (ISSET(details->flags, CD_INTERCEPT)) {
	    if (!exec_ptrace_intercept_supported())
		CLR(details->flags, CD_USE_PTRACE);
	} else if (ISSET(details->flags, CD_LOG_SUBCMDS)) {
	    if (!exec_ptrace_subcmds_supported())
		CLR(details->flags, CD_USE_PTRACE);
	} else {
	    CLR(details->flags, CD_USE_PTRACE);
	}
    }
    debug_return;
}
