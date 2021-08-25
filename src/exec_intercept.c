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
#include <netinet/in.h>

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
#include "sudo_rand.h"
#include "intercept.pb-c.h"

/* TCSASOFT is a BSD extension that ignores control flags and speed. */
#ifndef TCSASOFT
# define TCSASOFT	0
#endif

/* Closure for intercept_cb() */
struct intercept_closure {
    struct command_details *details;
    struct sudo_event ev;
    const char *errstr;
    char *command;		/* dynamically allocated */
    char **run_argv;		/* owned by plugin */
    char **run_envp;		/* dynamically allocated */
    uint8_t *buf;		/* dynamically allocated */
    size_t len;
    int listen_sock;
    int policy_result;
};

static uint64_t intercept_secret;
static in_port_t intercept_listen_port;
static void intercept_accept_cb(int fd, int what, void *v);
static void intercept_cb(int fd, int what, void *v);

bool
intercept_setup(int fd, struct sudo_event_base *evbase,
    struct command_details *details)
{
    struct intercept_closure *closure;
    debug_decl(intercept_setup, SUDO_DEBUG_EXEC);

    sudo_debug_printf(SUDO_DEBUG_INFO|SUDO_DEBUG_LINENO,
	"intercept fd %d\n", fd);

    closure = calloc(1, sizeof(*closure));
    if (closure == NULL) {
	sudo_warnx("%s", U_("unable to allocate memory"));
	goto bad;
    }

    closure->details = details;
    /* XXX - add proper state variable */
    closure->policy_result = intercept_secret ? -1 : 1;
    closure->listen_sock = -1;

    if (sudo_ev_set(&closure->ev, fd, SUDO_EV_READ, intercept_cb, closure) == -1) {
	/* This cannot (currently) fail. */
	sudo_warn("%s", U_("unable to add event to queue"));
	goto bad;
    }
    if (sudo_ev_add(evbase, &closure->ev, NULL, false) == -1) {
	sudo_warn("%s", U_("unable to add event to queue"));
	goto bad;
    }

    debug_return_bool(true);

bad:
    free(closure);
    debug_return_bool(false);
}

/*
 * Close intercept socket and free closure when we are done with
 * the connection.
 */
static void
intercept_connection_close(int fd, struct intercept_closure *closure)
{
    size_t n;
    debug_decl(intercept_connection_close, SUDO_DEBUG_EXEC);

    sudo_ev_del(NULL, &closure->ev);
    close(fd);
    if (closure->listen_sock != -1)
	close(closure->listen_sock);

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

/*
 * Prepare to listen on localhost using an ephemeral port.
 * Sets intercept_secret and intercept_listen_port as side effects.
 */
static bool
prepare_listener(struct intercept_closure *closure)
{
    struct sockaddr_in sin;
    socklen_t sin_len = sizeof(sin);
    int sock;
    debug_decl(prepare_listener, SUDO_DEBUG_EXEC);

    /* Secret must be non-zero. */
    do {
	intercept_secret = arc4random() | ((uint64_t)arc4random() << 32);
    } while (intercept_secret == 0);

    /* Create localhost listener socket (currently AF_INET only). */
    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock == -1) {
	sudo_warn("socket");
	goto bad;
    }
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    sin.sin_port = 0;
    if (bind(sock, (struct sockaddr *)&sin, sizeof(sin)) == -1) {
	sudo_warn("bind");
	goto bad;
    }
    if (getsockname(sock, (struct sockaddr *)&sin, &sin_len) == -1) {
	sudo_warn("getsockname");
	goto bad;
    }
    if (listen(sock, SOMAXCONN) == -1) {
	sudo_warn("listen");
	goto bad;
    }

    closure->listen_sock = sock;
    intercept_listen_port = ntohs(sin.sin_port);
    sudo_debug_printf(SUDO_DEBUG_INFO|SUDO_DEBUG_LINENO,
	"%s: listening on port %hu", __func__, intercept_listen_port);

    debug_return_bool(true);

bad:
    if (sock != -1)
	close(sock);
    debug_return_bool(false);
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
    if (req->secret != intercept_secret) {
	*errstr = N_("invalid PolicyCheckRequest");
	sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_LINENO,
	    "secret mismatch: got %" PRIu64 ", expected %" PRIu64, req->secret,
	    intercept_secret);
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
 * Read a single message from sudo_intercept.so and unpack it.
 * Assumes fd is in blocking mode.
 */
static InterceptRequest *
intercept_recv_request(int fd)
{
    InterceptRequest *req = NULL;
    uint8_t *cp, *buf = NULL;
    uint32_t req_len;
    ssize_t nread;
    debug_decl(intercept_recv_request, SUDO_DEBUG_EXEC);

    /* Read message size (uint32_t in host byte order). */
    nread = recv(fd, &req_len, sizeof(req_len), 0);
    if (nread != sizeof(req_len)) {
	if (nread != 0)
	    sudo_warn("read");
	goto done;
    }

    if (req_len > MESSAGE_SIZE_MAX) {
	sudo_warnx(U_("client request too large: %zu"), (size_t)req_len);
	goto done;
    }

    if (req_len > 0) {
	size_t rem = req_len;

	if ((buf = malloc(req_len)) == NULL) {
	    sudo_warnx("%s", U_("unable to allocate memory"));
	    goto done;
	}
	cp = buf;
	do {
	    nread = recv(fd, cp, rem, 0);
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

    req = intercept_request__unpack(NULL, req_len, buf);
    if (req == NULL) {
	sudo_warnx("unable to unpack %s size %zu", "InterceptRequest",
	    (size_t)req_len);
	goto done;
    }

done:
    free(buf);
    debug_return_ptr(req);
}

/*
 * Read a message from sudo_intercept.so and act on it.
 */
static bool
intercept_read(int fd, struct intercept_closure *closure)
{
    struct sudo_event_base *base = sudo_ev_get_base(&closure->ev);
    InterceptRequest *req;
    pid_t saved_pgrp = -1;
    struct termios oterm;
    bool ret = false;
    int ttyfd = -1;
    debug_decl(intercept_read, SUDO_DEBUG_EXEC);

    req = intercept_recv_request(fd);
    if (req == NULL)
	goto done;

    switch (req->type_case) {
    case INTERCEPT_REQUEST__TYPE_POLICY_CHECK_REQ:
	if (closure->policy_result != -1) {
	    /* Only a single policy check request is allowed. */
	    sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_LINENO,
		"got another PolicyCheckRequest on the socket (%d)",
		closure->policy_result);
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

	closure->policy_result = intercept_check_policy(req->u.policy_check_req,
	    closure, &closure->errstr);

	if (ttyfd != -1) {
	    (void)tcsetattr(ttyfd, TCSASOFT|TCSAFLUSH, &oterm);
	    (void)tcsetpgrp(ttyfd, saved_pgrp);
	}
	break;
    case INTERCEPT_REQUEST__TYPE_HELLO:
	if (closure->policy_result != 1) {
	    /* Only accept hello on a socket with an accepted command. */
	    sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_LINENO,
		"got ClientHello without an accepted command");
	    goto done;
	}

	/* Start listener after first Hello. */
	if (intercept_secret == 0 && !prepare_listener(closure))
	    goto done;

	closure->policy_result = 2; /* XXX */
	break;
    default:
	sudo_warnx(U_("unexpected type_case value %d in %s from %s"),
	    req->type_case, "InterceptRequest", "sudo_intercept.so");
	goto done;
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
    intercept_request__free_unpacked(req, NULL);
    debug_return_bool(ret);
}

static bool
fmt_intercept_response(InterceptResponse *resp,
    struct intercept_closure *closure)
{
    uint32_t resp_len;
    bool ret = false;
    debug_decl(fmt_intercept_response, SUDO_DEBUG_EXEC);

    closure->len = intercept_response__get_packed_size(resp);
    if (closure->len > MESSAGE_SIZE_MAX) {
	sudo_warnx(U_("server message too large: %zu"), closure->len);
	goto done;
    }

    /* Wire message size is used for length encoding, precedes message. */
    resp_len = closure->len;
    closure->len += sizeof(resp_len);

    sudo_debug_printf(SUDO_DEBUG_INFO|SUDO_DEBUG_LINENO,
	"size + InterceptResponse %zu bytes", closure->len);

    if ((closure->buf = malloc(closure->len)) == NULL) {
	sudo_warnx("%s", U_("unable to allocate memory"));
	goto done;
    }
    memcpy(closure->buf, &resp_len, sizeof(resp_len));
    intercept_response__pack(resp, closure->buf + sizeof(resp_len));

    ret = true;

done:
    debug_return_bool(ret);
}

static bool
fmt_hello_response(struct intercept_closure *closure)
{
    HelloResponse hello_resp = HELLO_RESPONSE__INIT;
    InterceptResponse resp = INTERCEPT_RESPONSE__INIT;
    debug_decl(fmt_hello_response, SUDO_DEBUG_EXEC);

    hello_resp.portno = intercept_listen_port;
    hello_resp.secret = intercept_secret;

    resp.u.hello_resp = &hello_resp;
    resp.type_case = INTERCEPT_RESPONSE__TYPE_HELLO_RESP;

    debug_return_bool(fmt_intercept_response(&resp, closure));
}

static bool
fmt_accept_message(struct intercept_closure *closure)
{
    PolicyAcceptMessage msg = POLICY_ACCEPT_MESSAGE__INIT;
    InterceptResponse resp = INTERCEPT_RESPONSE__INIT;
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

    resp.u.accept_msg = &msg;
    resp.type_case = INTERCEPT_RESPONSE__TYPE_ACCEPT_MSG;

    debug_return_bool(fmt_intercept_response(&resp, closure));
}

static bool
fmt_reject_message(struct intercept_closure *closure)
{
    PolicyRejectMessage msg = POLICY_REJECT_MESSAGE__INIT;
    InterceptResponse resp = INTERCEPT_RESPONSE__INIT;
    debug_decl(fmt_reject_message, SUDO_DEBUG_EXEC);

    msg.reject_message = (char *)closure->errstr;

    resp.u.reject_msg = &msg;
    resp.type_case = INTERCEPT_RESPONSE__TYPE_REJECT_MSG;

    debug_return_bool(fmt_intercept_response(&resp, closure));
}

static bool
fmt_error_message(struct intercept_closure *closure)
{
    PolicyErrorMessage msg = POLICY_ERROR_MESSAGE__INIT;
    InterceptResponse resp = INTERCEPT_RESPONSE__INIT;
    debug_decl(fmt_error_message, SUDO_DEBUG_EXEC);

    msg.error_message = (char *)closure->errstr;

    resp.u.error_msg = &msg;
    resp.type_case = INTERCEPT_RESPONSE__TYPE_ERROR_MSG;

    debug_return_bool(fmt_intercept_response(&resp, closure));
}

/*
 * Write a response to sudo_intercept.so.
 */
static bool
intercept_write(int fd, struct intercept_closure *closure)
{
    struct sudo_event_base *evbase = sudo_ev_get_base(&closure->ev);
    ssize_t nwritten;
    bool ret = false;
    uint8_t *cp;
    size_t rem;
    debug_decl(intercept_write, SUDO_DEBUG_EXEC);

    /* XXX - proper state variable */
    switch (closure->policy_result) {
	case 2:
	    if (!fmt_hello_response(closure))
		goto done;
	    break;
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
	nwritten = send(fd, cp, rem, 0);
	if (nwritten == -1) {
	    sudo_warn("send");
	    goto done;
	}
	cp += nwritten;
	rem -= nwritten;
    } while (rem > 0);

    switch (closure->policy_result) {
    case 1:
	/* Switch event to read mode for sudo_intercept.so ctor. */
	if (sudo_ev_set(&closure->ev, fd, SUDO_EV_READ, intercept_cb, closure) == -1) {
	    /* This cannot (currently) fail. */
	    sudo_warn("%s", U_("unable to add event to queue"));
	    goto done;
	}
	if (sudo_ev_add(evbase, &closure->ev, NULL, false) == -1) {
	    sudo_warn("%s", U_("unable to add event to queue"));
	    goto done;
	}
	break;
    case 2:
	if (closure->listen_sock != -1) {
	    /* Re-use intercept_event for the listener. */
	    if (sudo_ev_set(&closure->ev, closure->listen_sock, SUDO_EV_READ|SUDO_EV_PERSIST, intercept_accept_cb, closure) == -1) {
		/* This cannot (currently) fail. */
		sudo_warn("%s", U_("unable to add event to queue"));
		goto done;
	    }
	    if (sudo_ev_add(evbase, &closure->ev, NULL, false) == -1) {
		sudo_warn("%s", U_("unable to add event to queue"));
		goto done;
	    }
	    close(fd);

	    /* Reset bits of closure we used for Hello. */
	    free(closure->buf);
	    closure->buf = NULL;
	    closure->len = 0;
	    closure->listen_sock = -1;
	    break;
	}
	FALLTHROUGH;
    default:
	/* Done with this connection. */
	intercept_connection_close(fd, closure);
    }

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

    if (!success)
	intercept_connection_close(fd, closure);

    debug_return;
}

/*
 * Accept a new connection from the client and fill in a client closure.
 * Registers a new event for the connection.
 */
static void
intercept_accept_cb(int fd, int what, void *v)
{
    struct intercept_closure *closure = v;
    struct sudo_event_base *evbase = sudo_ev_get_base(&closure->ev);
    struct sockaddr_in sin;
    socklen_t sin_len = sizeof(sin);
    int client_sock;
    debug_decl(intercept_accept_cb, SUDO_DEBUG_EXEC);

    client_sock = accept(fd, (struct sockaddr *)&sin, &sin_len);
    if (client_sock == -1) {
	sudo_warn("accept");
	goto bad;
    }

    if (!intercept_setup(client_sock, evbase, closure->details)) {
	goto bad;
    }

    debug_return;

bad:
    if (client_sock != -1)
	close(client_sock);
    debug_return;
}
