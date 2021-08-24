/*
 * SPDX-License-Identifier: ISC
 *
 * Copyright (c) 2021 Todd C. Miller <Todd.Miller@sudo.ws>
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

#include <sys/socket.h>
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
#include <termios.h>

#include "sudo.h"
#include "sudo_exec.h"
#include "sudo_plugin.h"
#include "sudo_plugin_int.h"
#include "intercept.pb-c.h"

/* TCSASOFT is a BSD extension that ignores control flags and speed. */
#ifndef TCSASOFT
# define TCSASOFT	0
#endif

static void intercept_cb(int fd, int what, void *v);

/* Must match start of exec_closure_nopty and monitor_closure.  */
struct intercept_fd_closure {
    uint64_t secret;
    struct command_details *details;
    struct sudo_event_base *evbase;
};

/* Closure for intercept_cb() */
struct intercept_closure {
    struct command_details *details;
    struct sudo_event ev;
    const char *errstr;
    char *command;		/* dynamically allocated */
    char **run_argv;		/* owned by plugin */
    char **run_envp;		/* dynamically allocated */
    uint8_t *buf;		/* dynamically allocated */
    uint64_t secret;
    size_t len;
    int policy_result;
};

/*
 * Close intercept fd and free closure.
 * Called on EOF from sudo_intercept.so due to program exit.
 */
static void
intercept_close(int fd, struct intercept_closure *closure)
{
    size_t n;
    debug_decl(intercept_close, SUDO_DEBUG_EXEC);

    sudo_ev_del(NULL, &closure->ev);
    close(fd);

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
    free(closure);

    debug_return;
}

static int
intercept_check_policy(PolicyCheckRequest *req,
    struct intercept_closure *closure, const char **errstr)
{
    char **command_info = NULL;
    char **user_env_out = NULL;
    char **argv = NULL, **run_argv = NULL;
    int ret = 1;
    size_t n;
    debug_decl(intercept_check_policy, SUDO_DEBUG_EXEC);

    if (req->command == NULL || req->n_argv == 0 || req->n_envp == 0) {
	*errstr = N_("invalid PolicyCheckRequest");
	goto bad;
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
	goto bad;
    }
    argv[0] = req->command;
    for (n = 1; n < req->n_argv; n++) {
	argv[n] = req->argv[n];
    }
    argv[n] = NULL;

    if (ISSET(closure->details->flags, CD_INTERCEPT)) {
	/* We don't currently have a good way to validate the environment. */
	sudo_debug_set_active_instance(policy_plugin.debug_instance);
	ret = policy_plugin.u.policy->check_policy(n, argv, NULL,
	    &command_info, &run_argv, &user_env_out, errstr);
	sudo_debug_set_active_instance(sudo_debug_instance);
	sudo_debug_printf(SUDO_DEBUG_INFO|SUDO_DEBUG_LINENO,
	    "check_policy returns %d", ret);

	switch (ret) {
	case 1:
	    /* Extract command path from command_info[] */
	    if (command_info != NULL) {
		for (n = 0; command_info[n] != NULL; n++) {
		    const char *cp = command_info[n];
		    if (strncmp(cp, "command=", sizeof("command=") - 1) == 0) {
			closure->command = strdup(cp + sizeof("command=") - 1);
			if (closure->command == NULL) {
			    *errstr = N_("unable to allocate memory");
			    goto bad;
			}
			break;
		    }
		}
	    }
	    break;
	case 0:
	    if (*errstr == NULL)
		*errstr = N_("command rejected by policy");
	    audit_reject(policy_plugin.name, SUDO_POLICY_PLUGIN, *errstr,
		command_info);
	    goto done;
	default:
	    goto bad;
	}
    } else {
	/* No actual policy check, just logging child processes. */
	sudo_debug_printf(SUDO_DEBUG_INFO|SUDO_DEBUG_LINENO,
	    "not checking policy, audit only");
	closure->command = strdup(req->command);
	if (closure->command == NULL) {
	    *errstr = N_("unable to allocate memory");
	    goto bad;
	}
	command_info = (char **)closure->details->info;
	run_argv = argv;
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
	goto bad;
    }
    for (n = 0; run_argv[n] != NULL; n++) {
	closure->run_argv[n] = strdup(run_argv[n]);
	if (closure->run_argv[n] == NULL) {
	    *errstr = N_("unable to allocate memory");
	    goto bad;
	}
    }
    closure->run_argv[n] = NULL;

    /* envp strings are part of PolicyCheckReq, make a copy. */
    closure->run_envp = reallocarray(NULL, req->n_envp + 1, sizeof(char *));
    if (closure->run_envp == NULL) {
	*errstr = N_("unable to allocate memory");
	goto bad;
    }
    for (n = 0; n < req->n_envp; n++) {
	closure->run_envp[n] = strdup(req->envp[n]);
	if (closure->run_envp[n] == NULL) {
	    *errstr = N_("unable to allocate memory");
	    goto bad;
	}
    }
    closure->run_envp[n] = NULL;

    if (ISSET(closure->details->flags, CD_INTERCEPT)) {
	audit_accept(policy_plugin.name, SUDO_POLICY_PLUGIN, command_info,
		closure->run_argv, closure->run_envp);

	/* Call approval plugins and audit the result. */
	if (!approval_check(command_info, closure->run_argv, closure->run_envp))
	    debug_return_int(0);
    }

    /* Audit the event again for the sudo front-end. */
    audit_accept("sudo", SUDO_FRONT_END, command_info, closure->run_argv,
	closure->run_envp);

done:
    free(argv);
    debug_return_int(ret);

bad:
    free(argv);
    if (*errstr == NULL)
	*errstr = N_("policy plugin error");
    audit_error(policy_plugin.name, SUDO_POLICY_PLUGIN, *errstr,
	command_info);
    debug_return_int(ret);
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
    pid_t saved_pgrp = -1;
    struct termios oterm;
    uint32_t msg_len;
    bool ret = false;
    int ttyfd = -1;
    ssize_t nread;
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

    /* Take back control of the tty, if necessary, for the policy check. */
    ttyfd = open(_PATH_TTY, O_RDWR);
    if (ttyfd != -1) {
	saved_pgrp = tcgetpgrp(ttyfd);
	if (saved_pgrp == -1 || tcsetpgrp(ttyfd, getpgid(0)) == -1 ||
		tcgetattr(ttyfd, &oterm) == -1) {
	    close(ttyfd);
	    ttyfd = -1;
	}
    }

    closure->policy_result = intercept_check_policy(msg->u.policy_check_req,
	closure, &closure->errstr);

    if (ttyfd != -1) {
	(void)tcsetattr(ttyfd, TCSASOFT|TCSAFLUSH, &oterm);
	(void)tcsetpgrp(ttyfd, saved_pgrp);
    }

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
    if (ttyfd != -1)
	close(ttyfd);
    intercept_message__free_unpacked(msg, NULL);
    free(buf);
    debug_return_bool(ret);
}

static bool
fmt_policy_check_result(PolicyCheckResult *res, struct intercept_closure *closure)
{
    uint32_t msg_len;
    bool ret = false;
    debug_decl(fmt_policy_check_result, SUDO_DEBUG_EXEC);

    res->secret = closure->secret;
    closure->len = policy_check_result__get_packed_size(res);
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
    policy_check_result__pack(res, closure->buf + sizeof(msg_len));

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
    struct intercept_fd_closure *fdc = v;
    struct msghdr msg;
#if defined(HAVE_STRUCT_MSGHDR_MSG_CONTROL) && HAVE_STRUCT_MSGHDR_MSG_CONTROL == 1
    union {
	struct cmsghdr hdr;
	char buf[CMSG_SPACE(sizeof(int))];
    } cmsgbuf;
    struct cmsghdr *cmsg;
#endif
    struct iovec iov[1];
    int newfd = -1;
    char ch;
    debug_decl(intercept_fd_cb, SUDO_DEBUG_EXEC);

    /*
     * We send a single byte of data along with the fd; some systems
     * don't support sending file descriptors without data.
     * Note that the intercept fd is *blocking*.
     */
    iov[0].iov_base = &ch;
    iov[0].iov_len = 1;
    memset(&msg, 0, sizeof(msg));
    msg.msg_iov = iov;
    msg.msg_iovlen = 1;
#if defined(HAVE_STRUCT_MSGHDR_MSG_CONTROL) && HAVE_STRUCT_MSGHDR_MSG_CONTROL == 1
    memset(&cmsgbuf, 0, sizeof(cmsgbuf));
    msg.msg_control = &cmsgbuf.buf;
    msg.msg_controllen = sizeof(cmsgbuf.buf);
#else
    msg.msg_accrights = (caddr_t)&newfd;
    msg.msg_accrightslen = sizeof(newfd);
#endif /* HAVE_STRUCT_MSGHDR_MSG_CONTROL */

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

    if (ch == INTERCEPT_REQ_SEC) {
	/* Client requested secret from ctor, no fd is present. */
	if (write(fd, &fdc->secret, sizeof(fdc->secret)) != sizeof(fdc->secret))
	    goto bad;
	debug_return;
    }

#if defined(HAVE_STRUCT_MSGHDR_MSG_CONTROL) && HAVE_STRUCT_MSGHDR_MSG_CONTROL == 1
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
    memcpy(&newfd, CMSG_DATA(cmsg), sizeof(newfd));
#else
    if (msg.msg_accrightslen != sizeof(newfd)) {
	sudo_warnx(U_("%s: missing message header"), __func__);
	goto bad;
    }
#endif /* HAVE_STRUCT_MSGHDR_MSG_CONTROL */

    closure = calloc(1, sizeof(*closure));
    if (closure == NULL) {
	sudo_warnx("%s", U_("unable to allocate memory"));
	goto bad;
    }
    closure->secret = fdc->secret;
    closure->details = fdc->details;

    if (sudo_ev_set(&closure->ev, newfd, SUDO_EV_READ, intercept_cb, closure) == -1) {
	sudo_warn("%s", U_("unable to add event to queue"));
	goto bad;
    }
    if (sudo_ev_add(fdc->evbase, &closure->ev, NULL, false) == -1) {
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
