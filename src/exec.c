/*
 * SPDX-License-Identifier: ISC
 *
 * Copyright (c) 2009-2021 Todd C. Miller <Todd.Miller@sudo.ws>
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

#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/uio.h>
#if defined(HAVE_STDINT_H)
# include <stdint.h>
#elif defined(HAVE_INTTYPES_H)
# include <inttypes.h>
#endif
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <pwd.h>
#include <signal.h>
#ifdef HAVE_LOGIN_CAP_H
# include <login_cap.h>
# ifndef LOGIN_SETENV
#  define LOGIN_SETENV  0
# endif
#endif
#ifdef HAVE_PROJECT_H
# include <project.h>
# include <sys/task.h>
#endif

#include "sudo.h"
#include "sudo_exec.h"
#include "sudo_plugin.h"
#include "sudo_plugin_int.h"
#include "intercept.pb-c.h"

static void intercept_cb(int fd, int what, void *v);

static void
close_fds(struct command_details *details, int errfd, int intercept_fd)
{
    int fd, maxfd;
    unsigned char *debug_fds;
    debug_decl(close_fds, SUDO_DEBUG_EXEC);

    if (details->closefrom < 0)
	debug_return;

    /* Preserve debug fds and error pipe as needed. */
    maxfd = sudo_debug_get_fds(&debug_fds);
    for (fd = 0; fd <= maxfd; fd++) {
	if (sudo_isset(debug_fds, fd))
	    add_preserved_fd(&details->preserved_fds, fd);
    }
    if (errfd != -1)
	add_preserved_fd(&details->preserved_fds, errfd);
    if (intercept_fd != -1)
	add_preserved_fd(&details->preserved_fds, intercept_fd);

    /* Close all fds except those explicitly preserved. */
    closefrom_except(details->closefrom, &details->preserved_fds);

    debug_return;
}

/*
 * Setup the execution environment immediately prior to the call to execve().
 * Group setup is performed by policy_init_session(), called earlier.
 * Returns true on success and false on failure.
 */
static bool
exec_setup(struct command_details *details, int intercept_fd, int errfd)
{
    bool ret = false;
    debug_decl(exec_setup, SUDO_DEBUG_EXEC);

    if (details->pw != NULL) {
#ifdef HAVE_PROJECT_H
	set_project(details->pw);
#endif
#ifdef HAVE_PRIV_SET
	if (details->privs != NULL) {
	    if (setppriv(PRIV_SET, PRIV_INHERITABLE, details->privs) != 0) {
		sudo_warn("unable to set privileges");
		goto done;
	    }
	}
	if (details->limitprivs != NULL) {
	    if (setppriv(PRIV_SET, PRIV_LIMIT, details->limitprivs) != 0) {
		sudo_warn("unable to set limit privileges");
		goto done;
	    }
	} else if (details->privs != NULL) {
	    if (setppriv(PRIV_SET, PRIV_LIMIT, details->privs) != 0) {
		sudo_warn("unable to set limit privileges");
		goto done;
	    }
	}
#endif /* HAVE_PRIV_SET */

#ifdef HAVE_GETUSERATTR
	if (aix_prep_user(details->pw->pw_name, details->tty) != 0) {
	    /* error message displayed by aix_prep_user */
	    goto done;
	}
#endif
#ifdef HAVE_LOGIN_CAP_H
	if (details->login_class) {
	    int flags;
	    login_cap_t *lc;

	    /*
	     * We only use setusercontext() to set the nice value, rlimits
	     * and umask unless this is a login shell (sudo -i).
	     */
	    lc = login_getclass((char *)details->login_class);
	    if (!lc) {
		sudo_warnx(U_("unknown login class %s"), details->login_class);
		errno = ENOENT;
		goto done;
	    }
	    if (ISSET(details->flags, CD_LOGIN_SHELL)) {
		/* Set everything except user, group and login name. */
		flags = LOGIN_SETALL;
		CLR(flags, LOGIN_SETGROUP|LOGIN_SETLOGIN|LOGIN_SETUSER|LOGIN_SETENV|LOGIN_SETPATH);
	    } else {
		flags = LOGIN_SETRESOURCES|LOGIN_SETPRIORITY|LOGIN_SETUMASK;
	    }
	    if (setusercontext(lc, details->pw, details->pw->pw_uid, flags)) {
		sudo_warn("%s", U_("unable to set user context"));
		if (details->pw->pw_uid != ROOT_UID)
		    goto done;
	    }
	}
#endif /* HAVE_LOGIN_CAP_H */
    }

    if (ISSET(details->flags, CD_SET_GROUPS)) {
	/* set_user_groups() prints error message on failure. */
	if (!set_user_groups(details))
	    goto done;
    }

    if (ISSET(details->flags, CD_SET_PRIORITY)) {
	if (setpriority(PRIO_PROCESS, 0, details->priority) != 0) {
	    sudo_warn("%s", U_("unable to set process priority"));
	    goto done;
	}
    }

    /* Policy may override umask in PAM or login.conf. */
    if (ISSET(details->flags, CD_OVERRIDE_UMASK))
	(void) umask(details->umask);

    /* Close fds before chroot (need /dev) or uid change (prlimit on Linux). */
    close_fds(details, errfd, intercept_fd);

    if (details->chroot) {
	if (chroot(details->chroot) != 0 || chdir("/") != 0) {
	    sudo_warn(U_("unable to change root to %s"), details->chroot);
	    goto done;
	}
    }

    /*
     * Unlimit the number of processes since Linux's setuid() will
     * return EAGAIN if RLIMIT_NPROC would be exceeded by the uid switch.
     */
    unlimit_nproc();

#if defined(HAVE_SETRESUID)
    if (setresuid(details->cred.uid, details->cred.euid, details->cred.euid) != 0) {
	sudo_warn(U_("unable to change to runas uid (%u, %u)"),
	    (unsigned int)details->cred.uid, (unsigned int)details->cred.euid);
	goto done;
    }
#elif defined(HAVE_SETREUID)
    if (setreuid(details->cred.uid, details->cred.euid) != 0) {
	sudo_warn(U_("unable to change to runas uid (%u, %u)"),
	    (unsigned int)details->cred.uid, (unsigned int)details->cred.euid);
	goto done;
    }
#else
    /* Cannot support real user-ID that is different from effective user-ID. */
    if (setuid(details->cred.euid) != 0) {
	sudo_warn(U_("unable to change to runas uid (%u, %u)"),
	    (unsigned int)details->cred.euid, (unsigned int)details->cred.euid);
	goto done;
    }
#endif /* !HAVE_SETRESUID && !HAVE_SETREUID */

    /* Restore previous value of RLIMIT_NPROC. */
    restore_nproc();

    /*
     * Only change cwd if we have chroot()ed or the policy modules
     * specifies a different cwd.  Must be done after uid change.
     */
    if (details->cwd != NULL) {
	if (details->chroot != NULL || user_details.cwd == NULL ||
	    strcmp(details->cwd, user_details.cwd) != 0) {
	    /* Note: cwd is relative to the new root, if any. */
	    if (chdir(details->cwd) == -1) {
		sudo_warn(U_("unable to change directory to %s"), details->cwd);
		if (!details->cwd_optional)
		    goto done;
		if (details->chroot != NULL)
		    sudo_warnx(U_("starting from %s"), "/");
	    }
	}
    }

    ret = true;

done:
    debug_return_bool(ret);
}

/*
 * Setup the execution environment and execute the command.
 * If SELinux is enabled, run the command via sesh, otherwise
 * execute it directly.
 * If the exec fails, cstat is filled in with the value of errno.
 */
void
exec_cmnd(struct command_details *details, int intercept_fd, int errfd)
{
    debug_decl(exec_cmnd, SUDO_DEBUG_EXEC);

    restore_signals();
    if (exec_setup(details, intercept_fd, errfd) == true) {
	/* headed for execve() */
#ifdef HAVE_SELINUX
	if (ISSET(details->flags, CD_RBAC_ENABLED)) {
	    selinux_execve(details->execfd, details->command, details->argv,
		details->envp, ISSET(details->flags, CD_NOEXEC));
	} else
#endif
	{
	    sudo_execve(details->execfd, details->command, details->argv,
		details->envp, intercept_fd, details->flags);
	}
    }
    sudo_debug_printf(SUDO_DEBUG_ERROR, "unable to exec %s: %s",
	details->command, strerror(errno));
    debug_return;
}

/*
 * Check for caught signals sent to sudo before command execution.
 * Also suspends the process if SIGTSTP was caught.
 * Returns true if we should terminate, else false.
 */
bool
sudo_terminated(struct command_status *cstat)
{
    int signo;
    bool sigtstp = false;
    debug_decl(sudo_terminated, SUDO_DEBUG_EXEC);

    for (signo = 0; signo < NSIG; signo++) {
	if (signal_pending(signo)) {
	    switch (signo) {
	    case SIGCHLD:
		/* Ignore. */
		break;
	    case SIGTSTP:
		/* Suspend below if not terminated. */
		sigtstp = true;
		break;
	    default:
		/* Terminal signal, do not exec command. */
		cstat->type = CMD_WSTATUS;
		cstat->val = signo + 128;
		debug_return_bool(true);
		break;
	    }
	}
    }
    if (sigtstp) {
	struct sigaction sa;
	sigset_t set, oset;

	/* Send SIGTSTP to ourselves, unblocking it if needed. */
	memset(&sa, 0, sizeof(sa));
	sigemptyset(&sa.sa_mask);
	sa.sa_flags = SA_RESTART;
	sa.sa_handler = SIG_DFL;
	if (sudo_sigaction(SIGTSTP, &sa, NULL) != 0)
	    sudo_warn(U_("unable to set handler for signal %d"), SIGTSTP);
	sigemptyset(&set);
	sigaddset(&set, SIGTSTP);
	sigprocmask(SIG_UNBLOCK, &set, &oset);
	if (kill(getpid(), SIGTSTP) != 0)
	    sudo_warn("kill(%d, SIGTSTP)", (int)getpid());
	sigprocmask(SIG_SETMASK, &oset, NULL);
	/* No need to restore old SIGTSTP handler. */
    }
    debug_return_bool(false);
}

#if SUDO_API_VERSION != SUDO_API_MKVERSION(1, 17)
# error "Update sudo_needs_pty() after changing the plugin API"
#endif
static bool
sudo_needs_pty(struct command_details *details)
{
    struct plugin_container *plugin;

    if (ISSET(details->flags, CD_USE_PTY|CD_INTERCEPT|CD_LOG_CHILDREN))
	return true;

    TAILQ_FOREACH(plugin, &io_plugins, entries) {
	if (plugin->u.io->log_ttyin != NULL ||
	    plugin->u.io->log_ttyout != NULL ||
	    plugin->u.io->log_stdin != NULL ||
	    plugin->u.io->log_stdout != NULL ||
	    plugin->u.io->log_stderr != NULL ||
	    plugin->u.io->change_winsize != NULL ||
	    plugin->u.io->log_suspend != NULL)
	    return true;
    }
    return false;
}

/*
 * If we are not running the command in a pty, we were not invoked as
 * sudoedit, there is no command timeout and there is no close function,
 * sudo can exec the command directly (and not wait).
 */
static bool
direct_exec_allowed(struct command_details *details)
{
    struct plugin_container *plugin;
    debug_decl(direct_exec_allowed, SUDO_DEBUG_EXEC);

    /* Assumes sudo_needs_pty() was already checked. */
    if (ISSET(details->flags, CD_RBAC_ENABLED|CD_SET_TIMEOUT|CD_SUDOEDIT) ||
	    policy_plugin.u.policy->close != NULL)
	debug_return_bool(false);

    TAILQ_FOREACH(plugin, &audit_plugins, entries) {
	if (plugin->u.audit->close != NULL)
	    debug_return_bool(false);
    }

    debug_return_bool(true);
}

/*
 * Execute a command, potentially in a pty with I/O logging, and
 * wait for it to finish.
 * This is a little bit tricky due to how POSIX job control works and
 * we fact that we have two different controlling terminals to deal with.
 */
int
sudo_execute(struct command_details *details, struct command_status *cstat)
{
    debug_decl(sudo_execute, SUDO_DEBUG_EXEC);

    /* If running in background mode, fork and exit. */
    if (ISSET(details->flags, CD_BACKGROUND)) {
	switch (sudo_debug_fork()) {
	    case -1:
		cstat->type = CMD_ERRNO;
		cstat->val = errno;
		debug_return_int(-1);
	    case 0:
		/* child continues without controlling terminal */
		(void)setpgid(0, 0);
		break;
	    default:
		/* parent exits (but does not flush buffers) */
		sudo_debug_exit_int(__func__, __FILE__, __LINE__,
		    sudo_debug_subsys, 0);
		_exit(EXIT_SUCCESS);
	}
    }

    /*
     * Restore resource limits before running.
     * We must do this *before* calling the PAM session module.
     */
    restore_limits();

    /*
     * Run the command in a new pty if there is an I/O plugin or the policy
     * has requested a pty.  If /dev/tty is unavailable and no I/O plugin
     * is configured, this returns false and we run the command without a pty.
     */
    if (sudo_needs_pty(details)) {
	if (exec_pty(details, cstat))
	    goto done;
    }

    /*
     * If we are not running the command in a pty, we may be able to
     * exec directly, depending on the plugins used.
     */
    if (direct_exec_allowed(details)) {
	if (!sudo_terminated(cstat)) {
	    exec_cmnd(details, -1, -1);
	    cstat->type = CMD_ERRNO;
	    cstat->val = errno;
	}
	goto done;
    }

    /*
     * Run the command in the existing tty (if any) and wait for it to finish.
     */
    exec_nopty(details, cstat);

done:
    /* The caller will run any plugin close functions. */
    debug_return_int(cstat->type == CMD_ERRNO ? -1 : 0);
}

/*
 * Kill command with increasing urgency.
 */
void
terminate_command(pid_t pid, bool use_pgrp)
{
    debug_decl(terminate_command, SUDO_DEBUG_EXEC);

    /* Avoid killing more than a single process or process group. */
    if (pid <= 0)
	debug_return;

    /*
     * Note that SIGCHLD will interrupt the sleep()
     */
    if (use_pgrp) {
	sudo_debug_printf(SUDO_DEBUG_INFO, "killpg %d SIGHUP", (int)pid);
	killpg(pid, SIGHUP);
	sudo_debug_printf(SUDO_DEBUG_INFO, "killpg %d SIGTERM", (int)pid);
	killpg(pid, SIGTERM);
	sleep(2);
	sudo_debug_printf(SUDO_DEBUG_INFO, "killpg %d SIGKILL", (int)pid);
	killpg(pid, SIGKILL);
    } else {
	sudo_debug_printf(SUDO_DEBUG_INFO, "kill %d SIGHUP", (int)pid);
	kill(pid, SIGHUP);
	sudo_debug_printf(SUDO_DEBUG_INFO, "kill %d SIGTERM", (int)pid);
	kill(pid, SIGTERM);
	sleep(2);
	sudo_debug_printf(SUDO_DEBUG_INFO, "kill %d SIGKILL", (int)pid);
	kill(pid, SIGKILL);
    }

    debug_return;
}

struct intercept_closure {
    struct sudo_event ev;
    const char *errstr;
    char *command;		/* dynamically allocated */
    char **run_argv;		/* owned by plugin */
    char **run_envp;		/* dynamically allocated */
    uint8_t *buf;		/* dynamically allocated */
    size_t len;
    int policy_result;
};

/*
 * Reset intercept closure for re-use.
 */
static void
intercept_closure_reset(struct intercept_closure *closure)
{
    size_t n;
    debug_decl(intercept_closure_reset, SUDO_DEBUG_EXEC);

    free(closure->buf);
    free(closure->command);
    if (closure->run_argv != NULL) {
	for (n = 0; closure->run_argv[n] != NULL; n++)
	    free(closure->run_argv[n]);
	free(closure->run_argv);
    }
    if (closure->run_envp != NULL) {
	for (n = 0; closure->run_envp[n] != NULL; n++)
	    free(closure->run_envp[n]);
	free(closure->run_envp);
    }
    sudo_ev_del(NULL, &closure->ev);

    /* Reset all but the event (which we may reuse). */
    closure->errstr = NULL;
    closure->command = NULL;
    closure->run_argv = NULL;
    closure->run_envp = NULL;
    closure->buf = NULL;
    closure->len = 0;
    closure->policy_result = -1;

    debug_return;
}

/*
 * Close intercept fd and free closure.
 * Called on EOF from sudo_intercept.so due to program exit.
 */
static void
intercept_close(int fd, struct intercept_closure *closure)
{
    debug_decl(intercept_close, SUDO_DEBUG_EXEC);

    intercept_closure_reset(closure);
    free(closure);
    close(fd);

    debug_return;
}

static int
intercept_check_policy(PolicyCheckRequest *req,
    struct intercept_closure *closure, const char **errstr)
{
    char **command_info = NULL;
    char **user_env_out = NULL;
    char **argv, **run_argv = NULL;
    size_t n;
    int ok;
    debug_decl(intercept_check_policy, SUDO_DEBUG_EXEC);

    if (req->command == NULL || req->n_argv == 0 || req->n_envp == 0) {
	*errstr = N_("invalid PolicyCheckRequest");
	goto error;
    }

    if (sudo_debug_needed(SUDO_DEBUG_INFO)) {
	sudo_debug_printf(SUDO_DEBUG_INFO|SUDO_DEBUG_LINENO,
	    "req_command: %s", req->command);
	for (n = 0; n < req->n_argv; n++) {
	    sudo_debug_printf(SUDO_DEBUG_INFO|SUDO_DEBUG_LINENO,
	    "req_argv[%zu]: %s", n, req->argv[n]);
	}
    }

    /* Rebuild argv from PolicyCheckReq so it is NULL-terminated. */
    argv = reallocarray(NULL, req->n_argv + 1, sizeof(char *));
    if (argv == NULL) {
	*errstr = N_("unable to allocate memory");
	goto error;
    }
    for (n = 0; n < req->n_argv; n++) {
	argv[n] = req->argv[n];
    }
    argv[n] = NULL;

    /* We don't currently have a good way to validate the environment. */
    /* TODO: make sure LD_PRELOAD is preserved in environment */
    sudo_debug_set_active_instance(policy_plugin.debug_instance);
    ok = policy_plugin.u.policy->check_policy(n, argv, NULL,
	&command_info, &run_argv, &user_env_out, errstr);
    sudo_debug_set_active_instance(sudo_debug_instance);
    free(argv);

    switch (ok) {
    case 1:
	/* Extract command path from command_info[] */
	if (command_info != NULL) {
	    for (n = 0; command_info[n] != NULL; n++) {
		const char *cp = command_info[n];
		if (strncmp(cp, "command=", sizeof("command=") - 1) == 0) {
		    closure->command = strdup(cp + sizeof("command=") - 1);
		    if (closure->command == NULL) {
			*errstr = N_("unable to allocate memory");
			goto error;
		    }
		    break;
		}
	    }
	}

	if (sudo_debug_needed(SUDO_DEBUG_INFO)) {
	    sudo_debug_printf(SUDO_DEBUG_INFO|SUDO_DEBUG_LINENO,
	       "run_command: %s", closure->command);
	    for (n = 0; run_argv[n] != NULL; n++) {
		sudo_debug_printf(SUDO_DEBUG_INFO|SUDO_DEBUG_LINENO,
		    "run_argv[%zu]: %s", n, run_argv[n]);
	    }
	}

	/* run_argv strings may be part of PolicyCheckReq, make a copy. */
	for (n = 0; run_argv[n] != NULL; n++)
	    continue;
	closure->run_argv = reallocarray(NULL, n + 1, sizeof(char *));
	if (closure->run_argv == NULL) {
	    *errstr = N_("unable to allocate memory");
	    goto error;
	}
	for (n = 0; run_argv[n] != NULL; n++) {
	    closure->run_argv[n] = strdup(run_argv[n]);
	    if (closure->run_argv[n] == NULL) {
		*errstr = N_("unable to allocate memory");
		goto error;
	    }
	}
	closure->run_argv[n] = NULL;

	/* envp strings are part of PolicyCheckReq, make a copy. */
	closure->run_envp = reallocarray(NULL, req->n_envp + 1, sizeof(char *));
	if (closure->run_envp == NULL) {
	    *errstr = N_("unable to allocate memory");
	    goto error;
	}
	for (n = 0; n < req->n_envp; n++) {
	    closure->run_envp[n] = strdup(req->envp[n]);
	    if (closure->run_envp[n] == NULL) {
		*errstr = N_("unable to allocate memory");
		goto error;
	    }
	}
	closure->run_envp[n] = NULL;

	audit_accept(policy_plugin.name, SUDO_POLICY_PLUGIN, command_info,
		closure->run_argv, closure->run_envp);

	/* Call approval plugins and audit the result. */
	if (!approval_check(command_info, closure->run_argv, closure->run_envp))
	    debug_return_int(0);

	/* Audit the event again for the sudo front-end. */
	audit_accept("sudo", SUDO_FRONT_END, command_info, closure->run_argv,
	    closure->run_envp);
	debug_return_int(1);
    case 0:
	if (*errstr == NULL)
	    *errstr = N_("command rejected by policy");
	audit_reject(policy_plugin.name, SUDO_POLICY_PLUGIN, *errstr,
	    command_info);
	debug_return_int(0);
    default:
    error:
	if (*errstr == NULL)
	    *errstr = N_("policy plugin error");
	audit_error(policy_plugin.name, SUDO_POLICY_PLUGIN, *errstr,
	    command_info);
	debug_return_int(-1);
    }
}

/*
 * Read a single message from sudo_intercept.so.
 */
static bool
intercept_read(int fd, struct intercept_closure *closure)
{
    struct sudo_event_base *base = sudo_ev_get_base(&closure->ev);
    InterceptMessage *msg = NULL;
    uint8_t *cp, *buf = NULL;
    uint32_t msg_len;
    ssize_t nread;
    bool ret = false;
    debug_decl(intercept_read, SUDO_DEBUG_EXEC);

    /* Read message size (uint32_t in host byte order). */
    nread = read(fd, &msg_len, sizeof(msg_len));
    if (nread != sizeof(msg_len)) {
	if (nread != 0)
	    sudo_warn("read");
	goto done;
    }

    if (msg_len > MESSAGE_SIZE_MAX) {
	sudo_warnx(U_("client message too large: %zu"), (size_t)msg_len);
	goto done;
    }

    if (msg_len > 0) {
	size_t rem = msg_len;

	if ((buf = malloc(msg_len)) == NULL) {
	    sudo_warnx("%s", U_("unable to allocate memory"));
	    goto done;
	}
	cp = buf;
	do {
	    nread = read(fd, cp, rem);
	    switch (nread) {
	    case 0:
		/* EOF, other side must have exited. */
		goto done;
	    case -1:
		sudo_warn("read");
		goto done;
	    default:
		rem -= nread;
		cp += nread;
		break;
	    }
	} while (rem > 0);
    }

    msg = intercept_message__unpack(NULL, msg_len, buf);
    if (msg == NULL) {
	sudo_warnx("unable to unpack %s size %zu", "InterceptMessage",
	    (size_t)msg_len);
	goto done;
    }
    if (msg->type_case != INTERCEPT_MESSAGE__TYPE_POLICY_CHECK_REQ) {
	sudo_warnx(U_("unexpected type_case value %d in %s from %s"),
	    msg->type_case, "InterceptMessage", "sudo_intercept.so");
	goto done;
    }

    closure->policy_result = intercept_check_policy(msg->u.policy_check_req,
	closure, &closure->errstr);

    /* Switch event to write mode for the reply. */
    if (sudo_ev_set(&closure->ev, fd, SUDO_EV_WRITE, intercept_cb, closure) == -1) {
	/* This cannot (currently) fail. */
	sudo_warn("%s", U_("unable to add event to queue"));
	goto done;
    }
    if (sudo_ev_add(base, &closure->ev, NULL, false) == -1) {
	sudo_warn("%s", U_("unable to add event to queue"));
	goto done;
    }

    ret = true;

done:
    intercept_message__free_unpacked(msg, NULL);
    free(buf);
    debug_return_bool(ret);
}

static bool
fmt_policy_check_result(PolicyCheckResult *msg, struct intercept_closure *closure)
{
    uint32_t msg_len;
    bool ret = false;
    debug_decl(fmt_policy_check_result, SUDO_DEBUG_EXEC);

    closure->len = policy_check_result__get_packed_size(msg);
    if (closure->len > MESSAGE_SIZE_MAX) {
	sudo_warnx(U_("server message too large: %zu"), closure->len);
	goto done;
    }

    /* Wire message size is used for length encoding, precedes message. */
    msg_len = closure->len;
    closure->len += sizeof(msg_len);

    sudo_debug_printf(SUDO_DEBUG_INFO|SUDO_DEBUG_LINENO,
	"size + PolicyCheckResult %zu bytes", closure->len);

    if ((closure->buf = malloc(closure->len)) == NULL) {
	sudo_warnx("%s", U_("unable to allocate memory"));
	goto done;
    }
    memcpy(closure->buf, &msg_len, sizeof(msg_len));
    policy_check_result__pack(msg, closure->buf + sizeof(msg_len));

    ret = true;

done:
    debug_return_bool(ret);
}

static bool
fmt_accept_message(struct intercept_closure *closure)
{
    PolicyAcceptMessage msg = POLICY_ACCEPT_MESSAGE__INIT;
    PolicyCheckResult res = POLICY_CHECK_RESULT__INIT;
    size_t n;
    debug_decl(fmt_accept_message, SUDO_DEBUG_EXEC);

    msg.run_command = closure->command;
    msg.run_argv = closure->run_argv;
    for (n = 0; closure->run_argv[n] != NULL; n++)
	continue;
    msg.n_run_argv = n;
    msg.run_envp = closure->run_envp;
    for (n = 0; closure->run_envp[n] != NULL; n++)
	continue;
    msg.n_run_envp = n;

    res.u.accept_msg = &msg;
    res.type_case = POLICY_CHECK_RESULT__TYPE_ACCEPT_MSG;

    debug_return_bool(fmt_policy_check_result(&res, closure));
}

static bool
fmt_reject_message(struct intercept_closure *closure)
{
    PolicyRejectMessage msg = POLICY_REJECT_MESSAGE__INIT;
    PolicyCheckResult res = POLICY_CHECK_RESULT__INIT;
    debug_decl(fmt_reject_message, SUDO_DEBUG_EXEC);

    msg.reject_message = (char *)closure->errstr;

    res.u.reject_msg = &msg;
    res.type_case = POLICY_CHECK_RESULT__TYPE_REJECT_MSG;

    debug_return_bool(fmt_policy_check_result(&res, closure));
}

static bool
fmt_error_message(struct intercept_closure *closure)
{
    PolicyErrorMessage msg = POLICY_ERROR_MESSAGE__INIT;
    PolicyCheckResult res = POLICY_CHECK_RESULT__INIT;
    debug_decl(fmt_error_message, SUDO_DEBUG_EXEC);

    msg.error_message = (char *)closure->errstr;

    res.u.error_msg = &msg;
    res.type_case = POLICY_CHECK_RESULT__TYPE_ERROR_MSG;

    debug_return_bool(fmt_policy_check_result(&res, closure));
}

/*
 * Write a response to sudo_intercept.so.
 */
static bool
intercept_write(int fd, struct intercept_closure *closure)
{
    size_t rem;
    uint8_t *cp;
    ssize_t nwritten;
    bool ret = false;
    debug_decl(intercept_write, SUDO_DEBUG_EXEC);

    switch (closure->policy_result) {
	case 1:
	    if (!fmt_accept_message(closure))
		goto done;
	    break;
	case 0:
	    if (!fmt_reject_message(closure))
		goto done;
	    break;
	default:
	    if (!fmt_error_message(closure))
		goto done;
	    break;
    }

    cp = closure->buf;
    rem = closure->len;
    do {
	nwritten = write(fd, cp, rem);
	if (nwritten == -1) {
	    sudo_warn("write");
	    goto done;
	}
	cp += nwritten;
	rem -= nwritten;
    } while (rem > 0);

    ret = true;

done:
    debug_return_bool(ret);
}

static void
intercept_cb(int fd, int what, void *v)
{
    struct intercept_closure *closure = v;
    bool success = false;
    debug_decl(intercept_cb, SUDO_DEBUG_EXEC);

    switch (what) {
    case SUDO_EV_READ:
	success = intercept_read(fd, closure);
	break;
    case SUDO_EV_WRITE:
	success = intercept_write(fd, closure);
	break;
    default:
	sudo_warnx("%s: unexpected event type %d", __func__, what);
	break;
    }

    if (!success || what == SUDO_EV_WRITE) {
	intercept_close(fd, closure);
    }

    debug_return;
}

/*
 * Accept a single fd passed from the child to use for policy checks.
 * This acts a bit like accept() in reverse since the client allocates
 * the socketpair() that is used for the actual communication.
 */
void
intercept_fd_cb(int fd, int what, void *v)
{
    struct intercept_closure *closure = NULL;
    struct sudo_event_base *base = v;
    struct msghdr msg;
    union {
	struct cmsghdr hdr;
	char buf[CMSG_SPACE(sizeof(int))];
    } cmsgbuf;
    struct cmsghdr *cmsg;
    struct iovec iov[1];
    int newfd = -1;
    char ch;
    debug_decl(intercept_fd_cb, SUDO_DEBUG_EXEC);

    closure = calloc(1, sizeof(*closure));
    if (closure == NULL) {
	sudo_warnx("%s", U_("unable to allocate memory"));
	goto bad;
    }

    /*
     * We send a single byte of data along with the fd; some systems
     * don't support sending file descriptors without data.
     * Note that the intercept fd is *blocking*.
     */
    iov[0].iov_base = &ch;
    iov[0].iov_len = 1;
    memset(&msg, 0, sizeof(msg));
    memset(&cmsgbuf, 0, sizeof(cmsgbuf));
    msg.msg_iov = iov;
    msg.msg_iovlen = 1;
    msg.msg_control = &cmsgbuf.buf;
    msg.msg_controllen = sizeof(cmsgbuf.buf);

    switch (recvmsg(fd, &msg, 0)) {
    case -1:
	if (errno != EAGAIN && errno != EINTR)
	    sudo_warn("recvmsg");
	goto bad;
    case 0:
	/* EOF */
	goto bad;
    default:
	break;
    }

    cmsg = CMSG_FIRSTHDR(&msg);
    if (cmsg == NULL) {
	sudo_warnx(U_("%s: missing message header"), __func__);
	goto bad;
    }

    if (cmsg->cmsg_type != SCM_RIGHTS) {
	sudo_warnx(U_("%s: expected message type %d, got %d"), __func__,
	    SCM_RIGHTS, cmsg->cmsg_type);
	goto bad;
    }

    newfd = (*(int *)CMSG_DATA(cmsg));
    if (sudo_ev_set(&closure->ev, newfd, SUDO_EV_READ, intercept_cb, closure) == -1) {
	sudo_warn("%s", U_("unable to add event to queue"));
	goto bad;
    }
    if (sudo_ev_add(base, &closure->ev, NULL, false) == -1) {
	sudo_warn("%s", U_("unable to add event to queue"));
	goto bad;
    }

    debug_return;
bad:
    if (newfd != -1)
	close(newfd);
    free(closure);
    debug_return;
}
