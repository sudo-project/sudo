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

#include <sys/wait.h>
#include <errno.h>
#include <limits.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>

#include "sudo.h"
#include "sudo_exec.h"

#ifdef HAVE_PTRACE_INTERCEPT
# include <sys/prctl.h>
# include <sys/ptrace.h>
# include <sys/user.h>
# include <asm/unistd.h>
# include <linux/ptrace.h>
# include <linux/seccomp.h>
# include <linux/filter.h>

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

    if (sigtrap == (SIGTRAP | (PTRACE_EVENT_EXEC << 8))) {
	/* Trapped child exec. */
	sudo_debug_printf(SUDO_DEBUG_INFO, "%s: %d called exec",
	    __func__, (int)pid);
	/*
	 * XXX
	 * Get the exec arguments and perform a policy check either over
	 * the socketpair (pty case) or via a direct function call (no pty).
	 */
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
