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

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>

#if defined(HAVE_STDINT_H)
# include <stdint.h>
#elif defined(HAVE_INTTYPES_H)
# include <inttypes.h>
#endif
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#ifdef HAVE_STDBOOL_H
# include <stdbool.h>
#else
# include "compat/stdbool.h"
#endif /* HAVE_STDBOOL_H */

#include "sudo_compat.h"
#include "sudo_conf.h"
#include "sudo_debug.h"
#include "sudo_fatal.h"
#include "sudo_exec.h"
#include "sudo_gettext.h"
#include "sudo_util.h"
#include "intercept.pb-c.h"

extern char **environ;

static union sudo_token_un intercept_token;
static in_port_t intercept_port;

/* Send entire request to sudo (blocking). */
static bool
send_req(int sock, const void *buf, size_t len)
{
    const uint8_t *cp = buf;
    ssize_t nwritten;
    debug_decl(send_req, SUDO_DEBUG_EXEC);

    do {
	nwritten = send(sock, cp, len, 0);
	if (nwritten == -1) {
	    if (errno == EINTR)
		continue;
	    debug_return_bool(false);
	}
	len -= nwritten;
	cp += nwritten;
    } while (len > 0);

    debug_return_bool(true);
}

static bool
send_client_hello(int sock)
{
    InterceptRequest msg = INTERCEPT_REQUEST__INIT;
    InterceptHello hello = INTERCEPT_HELLO__INIT;
    uint8_t *buf = NULL;
    uint32_t msg_len;
    size_t len;
    bool ret = false;
    debug_decl(send_client_hello, SUDO_DEBUG_EXEC);

    /* Setup client hello. */
    hello.pid = getpid();
    msg.type_case = INTERCEPT_REQUEST__TYPE_HELLO;;
    msg.u.hello = &hello;

    len = intercept_request__get_packed_size(&msg);
    if (len > MESSAGE_SIZE_MAX) {
	sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_LINENO,
	    "InterceptRequest too large: %zu", len);
	goto done;
    }
    /* Wire message size is used for length encoding, precedes message. */
    msg_len = len;
    len += sizeof(msg_len);

    if ((buf = malloc(len)) == NULL) {
	sudo_warnx(U_("%s: %s"), __func__, U_("unable to allocate memory"));
	goto done;
    }
    memcpy(buf, &msg_len, sizeof(msg_len));
    intercept_request__pack(&msg, buf + sizeof(msg_len));

    ret = send_req(sock, buf, len);

done:
    free(buf);
    debug_return_bool(ret);
}

/*
 * Receive InterceptResponse from sudo over fd.
 */
InterceptResponse *
recv_intercept_response(int fd)
{
    InterceptResponse *res = NULL;
    ssize_t nread;
    uint32_t rem, res_len;
    uint8_t *cp, *buf = NULL;
    debug_decl(recv_intercept_response, SUDO_DEBUG_EXEC);

    /* Read message size (uint32_t in host byte order). */
    nread = recv(fd, &res_len, sizeof(res_len), 0);
    if ((size_t)nread != sizeof(res_len)) {
        if (nread == 0) {
	    sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_LINENO,
		"unexpected EOF reading response size");
	} else {
	    sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_LINENO|SUDO_DEBUG_ERRNO,
		"error reading response size");
	}
        goto done;
    }
    if (res_len > MESSAGE_SIZE_MAX) {
	sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_LINENO,
	    "InterceptResponse too large: %u", res_len);
        goto done;
    }

    /* Read response from sudo (blocking). */
    if ((buf = malloc(res_len)) == NULL) {
	goto done;
    }
    cp = buf;
    rem = res_len;
    do {
	nread = recv(fd, cp, rem, 0);
	switch (nread) {
	case 0:
	    sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_LINENO,
		"unexpected EOF reading response");
	    goto done;
	case -1:
	    if (errno == EINTR)
		continue;
	    sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_LINENO|SUDO_DEBUG_ERRNO,
		"error reading response");
	    goto done;
	default:
	    rem -= nread;
	    cp += nread;
	    break;
	}
    } while (rem > 0);
    res = intercept_response__unpack(NULL, res_len, buf);
    if (res == NULL) {
	sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_LINENO,
	    "unable to unpack %s size %u", "InterceptResponse", res_len);
        goto done;
    }

done:
    free(buf);
    debug_return_ptr(res);
}

/*
 * Look up SUDO_INTERCEPT_FD in the environment.
 * This function is run when the shared library is loaded.
 */
__attribute__((constructor)) static void
sudo_interposer_init(void)
{
    InterceptResponse *res = NULL;
    static bool initialized;
    int fd = -1;
    char **p;
    debug_decl(sudo_interposer_init, SUDO_DEBUG_EXEC);

    if (initialized)
	debug_return;
    initialized = true;

    /* Read debug section of sudo.conf and init debugging. */
    if (sudo_conf_read(NULL, SUDO_CONF_DEBUG) != -1) {
	sudo_debug_register("sudo_intercept.so", NULL, NULL,
	    sudo_conf_debug_files("sudo_intercept.so"), INTERCEPT_FD_MIN);
    }
    sudo_debug_enter(__func__, __FILE__, __LINE__, sudo_debug_subsys);

    /*
     * Missing SUDO_INTERCEPT_FD will result in execve() failure.
     * Note that we cannot use getenv(3) here on Linux at least.
     */
    for (p = environ; *p != NULL; p++) {
	if (strncmp(*p, "SUDO_INTERCEPT_FD=", sizeof("SUDO_INTERCEPT_FD=") -1) == 0) {
	    const char *fdstr = *p + sizeof("SUDO_INTERCEPT_FD=") - 1;
	    const char *errstr;

	    sudo_debug_printf(SUDO_DEBUG_INFO|SUDO_DEBUG_LINENO, "%s", *p);

	    fd = sudo_strtonum(fdstr, 0, INT_MAX, &errstr);
	    if (errstr != NULL) {
		sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_LINENO,
		    "invalid SUDO_INTERCEPT_FD: %s: %s", fdstr, errstr);
		goto done;
	    }
	}
    }
    if (fd == -1) {
	sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_LINENO,
	    "SUDO_INTERCEPT_FD not found in environment");
	goto done;
    }

    /*
     * Send InterceptHello message to over the fd.
     */
    if (!send_client_hello(fd))
	goto done;

    res = recv_intercept_response(fd);
    if (res != NULL) {
	if (res->type_case == INTERCEPT_RESPONSE__TYPE_HELLO_RESP) {
	    intercept_token.u64[0] = res->u.hello_resp->token_lo;
	    intercept_token.u64[1] = res->u.hello_resp->token_hi;
	    intercept_port = res->u.hello_resp->portno;
	} else {
	    sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_LINENO,
		"unexpected type_case value %d in %s from %s",
		res->type_case, "InterceptResponse", "sudo");
	}
	intercept_response__free_unpacked(res, NULL);
    }

done:
    if (fd != -1)
	close(fd);

    debug_return;
}

static bool
send_policy_check_req(int sock, const char *cmnd, char * const argv[],
    char * const envp[])
{
    InterceptRequest msg = INTERCEPT_REQUEST__INIT;
    PolicyCheckRequest req = POLICY_CHECK_REQUEST__INIT;
    char cwdbuf[PATH_MAX];
    uint8_t *buf = NULL;
    bool ret = false;
    uint32_t msg_len;
    size_t len;
    debug_decl(fmt_policy_check_req, SUDO_DEBUG_EXEC);

    /* Send token first (out of band) to initiate connection. */
    if (!send_req(sock, &intercept_token, sizeof(intercept_token))) {
	sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_LINENO,
	    "unable to send token back to sudo");
	goto done;
    }

    /* Setup policy check request. */
    req.intercept_fd = sock;
    req.command = (char *)cmnd;
    req.argv = (char **)argv;
    for (len = 0; argv[len] != NULL; len++)
	continue;
    req.n_argv = len;
    req.envp = (char **)envp;
    for (len = 0; envp[len] != NULL; len++)
	continue;
    req.n_envp = len;
    if (getcwd(cwdbuf, sizeof(cwdbuf)) != NULL) {
	req.cwd = cwdbuf;
    }
    msg.type_case = INTERCEPT_REQUEST__TYPE_POLICY_CHECK_REQ;
    msg.u.policy_check_req = &req;

    len = intercept_request__get_packed_size(&msg);
    if (len > MESSAGE_SIZE_MAX) {
	sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_LINENO,
	    "InterceptRequest too large: %zu", len);
	goto done;
    }
    /* Wire message size is used for length encoding, precedes message. */
    msg_len = len;
    len += sizeof(msg_len);

    if ((buf = malloc(len)) == NULL) {
	sudo_warnx(U_("%s: %s"), __func__, U_("unable to allocate memory"));
	goto done;
    }
    memcpy(buf, &msg_len, sizeof(msg_len));
    intercept_request__pack(&msg, buf + sizeof(msg_len));

    ret = send_req(sock, buf, len);

done:
    free(buf);
    debug_return_bool(ret);
}

/* 
 * Connect back to sudo process at localhost:intercept_port
 */
static int
intercept_connect(void)
{
    int sock = -1;
    struct sockaddr_in sin;
    debug_decl(command_allowed, SUDO_DEBUG_EXEC);

    if (intercept_port == 0) {
	sudo_warnx(U_("intercept port not set"));
	goto done;
    }

    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    sin.sin_port = htons(intercept_port);

    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock == -1) {
	sudo_warn("socket");
	goto done;
    }

    if (connect(sock, (struct sockaddr *)&sin, sizeof(sin)) == -1) {
	sudo_warn("connect");
	close(sock);
	sock = -1;
	goto done;
    }

done:
    debug_return_int(sock);
}

bool
command_allowed(const char *cmnd, char * const argv[],
    char * const envp[], char **ncmndp, char ***nargvp, char ***nenvpp)
{
    char *ncmnd = NULL, **nargv = NULL, **nenvp = NULL;
    InterceptResponse *res = NULL;
    bool ret = false;
    size_t idx, len = 0;
    int sock;
    debug_decl(command_allowed, SUDO_DEBUG_EXEC);

    if (sudo_debug_needed(SUDO_DEBUG_INFO)) {
	sudo_debug_printf(SUDO_DEBUG_INFO|SUDO_DEBUG_LINENO,
	    "req_command: %s", cmnd);
	for (idx = 0; argv[idx] != NULL; idx++) {
	    sudo_debug_printf(SUDO_DEBUG_INFO|SUDO_DEBUG_LINENO,
		"req_argv[%zu]: %s", idx, argv[idx]);
	}
    }

    sock = intercept_connect();
    if (sock == -1)
	goto done;

    if (!send_policy_check_req(sock, cmnd, argv, envp))
	goto done;

    res = recv_intercept_response(sock);
    if (res == NULL)
	goto done;

    switch (res->type_case) {
    case INTERCEPT_RESPONSE__TYPE_ACCEPT_MSG:
	if (sudo_debug_needed(SUDO_DEBUG_INFO)) {
	    sudo_debug_printf(SUDO_DEBUG_INFO|SUDO_DEBUG_LINENO,
		"run_command: %s", res->u.accept_msg->run_command);
	    for (idx = 0; idx < res->u.accept_msg->n_run_argv; idx++) {
		sudo_debug_printf(SUDO_DEBUG_INFO|SUDO_DEBUG_LINENO,
		    "run_argv[%zu]: %s", idx, res->u.accept_msg->run_argv[idx]);
	    }
	}
	ncmnd = strdup(res->u.accept_msg->run_command);
	if (ncmnd == NULL)
	    goto oom;
	nargv = reallocarray(NULL, res->u.accept_msg->n_run_argv + 1,
	    sizeof(char *));
	if (nargv == NULL)
	    goto oom;
	for (len = 0; len < res->u.accept_msg->n_run_argv; len++) {
	    nargv[len] = strdup(res->u.accept_msg->run_argv[len]);
	    if (nargv[len] == NULL)
		goto oom;
	}
	nargv[len] = NULL;
	// XXX - bogus cast
	nenvp = sudo_preload_dso((char **)envp, sudo_conf_intercept_path(),
	    sock);
	if (nenvp == NULL)
	    goto oom;
	*ncmndp = ncmnd;
	*nargvp = nargv;
	*nenvpp = nenvp;
	ret = true;
	goto done;
    case INTERCEPT_RESPONSE__TYPE_REJECT_MSG:
	/* Policy module displayed reject message but we are in raw mode. */
	fputc('\r', stderr);
	goto done;
    case INTERCEPT_RESPONSE__TYPE_ERROR_MSG:
	/* Policy module may display error message but we are in raw mode. */
	fputc('\r', stderr);
	sudo_warnx("%s", res->u.error_msg->error_message);
	goto done;
    default:
	sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_LINENO,
	    "unexpected type_case value %d in %s from %s",
            res->type_case, "InterceptResponse", "sudo");
	goto done;
    }

oom:
    free(ncmnd);
    while (len > 0)
	free(nargv[--len]);
    free(nargv);

done:
    /* Keep socket open for ctor when we execute the command. */
    if (!ret && sock != -1)
	close(sock);
    intercept_response__free_unpacked(res, NULL);

    debug_return_bool(ret);
}
