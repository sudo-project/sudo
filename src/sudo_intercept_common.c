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

static int intercept_sock = -1;
static uint64_t secret;

/*
 * Look up SUDO_INTERCEPT_FD in the environment.
 * This function is run when the shared library is loaded.
 */
__attribute__((constructor)) static void
sudo_interposer_init(void)
{
    static bool initialized;
    char **p;
    debug_decl(sudo_interposer_init, SUDO_DEBUG_EXEC);

    if (!initialized) {
        initialized = true;

	/* Read debug section of sudo.conf and init debugging. */
	if (sudo_conf_read(NULL, SUDO_CONF_DEBUG) != -1) {
	    sudo_debug_register("sudo_intercept.so", NULL, NULL,
		sudo_conf_debug_files("sudo_intercept.so"));
	}

        /*
         * Missing SUDO_INTERCEPT_FD will result in execve() failure.
         * Note that we cannot use getenv(3) here on Linux at least.
         */
        for (p = environ; *p != NULL; p++) {
            if (strncmp(*p, "SUDO_INTERCEPT_FD=", sizeof("SUDO_INTERCEPT_FD=") -1) == 0) {
                const char *fdstr = *p + sizeof("SUDO_INTERCEPT_FD=") - 1;
		const char *errstr;
		char ch = INTERCEPT_REQ_SEC;
                int fd;

		fd = sudo_strtonum(fdstr, 0, INT_MAX, &errstr);
		if (errstr != NULL) {
		    sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_LINENO,
			"invalid SUDO_INTERCEPT_FD: %s: %s", fdstr, errstr);
                    break;
                }

		/* Request secret from parent. */
		if (send(fd, &ch, sizeof(ch), 0) != sizeof(ch)) {
		    sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_LINENO,
			"unable to request secret: %s", strerror(errno));
                    break;
		}
		if (recv(fd, &secret, sizeof(secret), 0) != sizeof(secret)) {
		    sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_LINENO,
			"unable to read secret: %s", strerror(errno));
                    break;
		}

                intercept_sock = fd;
                break;
            }
        }
	if (intercept_sock == -1) {
	    sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_LINENO,
		"SUDO_INTERCEPT_FD not found in environment");
	}
    }
    debug_return;
}

static uint8_t *
fmt_policy_check_req(const char *cmnd, char * const argv[], char * const envp[],
    size_t *buflen)
{
    InterceptMessage msg = INTERCEPT_MESSAGE__INIT;
    PolicyCheckRequest req = POLICY_CHECK_REQUEST__INIT;
    uint8_t *buf = NULL;
    uint32_t msg_len;
    size_t len;
    debug_decl(sudo_interposer_init, SUDO_DEBUG_EXEC);

    /* Setup policy check request. */
    req.command = (char *)cmnd;
    req.argv = (char **)argv;
    for (len = 0; argv[len] != NULL; len++)
	continue;
    req.n_argv = len;
    req.envp = (char **)envp;
    for (len = 0; envp[len] != NULL; len++)
	continue;
    req.n_envp = len;
    msg.type_case = INTERCEPT_MESSAGE__TYPE_POLICY_CHECK_REQ;
    msg.u.policy_check_req = &req;

    len = intercept_message__get_packed_size(&msg);
    if (len > MESSAGE_SIZE_MAX) {
	sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_LINENO,
	    "InterceptMessage too large: %zu", len);
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
    intercept_message__pack(&msg, buf + sizeof(msg_len));
    *buflen = len;

done:
    debug_return_ptr(buf);
}

/* Send fd over a unix domain socket. */
static bool
intercept_send_fd(int sock, int fd)
{
    struct msghdr msg;
#if defined(HAVE_STRUCT_MSGHDR_MSG_CONTROL) && HAVE_STRUCT_MSGHDR_MSG_CONTROL == 1
    union {
	struct cmsghdr hdr;
	char buf[CMSG_SPACE(sizeof(int))];
    } cmsgbuf;
    struct cmsghdr *cmsg;
#endif
    struct iovec iov[1];
    char ch = '\0';
    ssize_t nsent;
    debug_decl(intercept_send_fd, SUDO_DEBUG_EXEC);

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
    cmsg = CMSG_FIRSTHDR(&msg);
    cmsg->cmsg_len = CMSG_LEN(sizeof(int));
    cmsg->cmsg_level = SOL_SOCKET;
    cmsg->cmsg_type = SCM_RIGHTS;
    memcpy(CMSG_DATA(cmsg), &fd, sizeof(fd));
#else
    msg.msg_accrights = (caddr_t)&fd;
    msg.msg_accrightslen = sizeof(fd);
#endif /* HAVE_STRUCT_MSGHDR_MSG_CONTROL */

    for (;;) {
	nsent = sendmsg(sock, &msg, 0);
	if (nsent != -1)
	    debug_return_bool(true);
	if (errno != EAGAIN && errno != EINTR)
	    break;
    }
    sudo_warn("sendmsg");
    debug_return_bool(false);
}

bool
command_allowed(const char *cmnd, char * const argv[], char * const envp[],
    char **ncmndp, char ***nargvp, char ***nenvpp)
{
    char *ncmnd = NULL, **nargv = NULL, **nenvp = NULL;
    PolicyCheckResult *res = NULL;
    int sv[2] = { -1, -1 };
    ssize_t nread, nwritten;
    uint8_t *cp, *buf = NULL;
    bool ret = false;
    uint32_t res_len;
    size_t idx, len;
    debug_decl(intercept_send_fd, SUDO_DEBUG_EXEC);

    if (sudo_debug_needed(SUDO_DEBUG_INFO)) {
	sudo_debug_printf(SUDO_DEBUG_INFO|SUDO_DEBUG_LINENO,
	    "req_command: %s", cmnd);
	for (idx = 0; argv[idx] != NULL; idx++) {
	    sudo_debug_printf(SUDO_DEBUG_INFO|SUDO_DEBUG_LINENO,
		"req_argv[%zu]: %s", idx, argv[idx]);
	}
    }

    if (intercept_sock < INTERCEPT_FD_MIN) {
	sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_LINENO,
	    "invalid intercept fd: %d", intercept_sock);
        errno = EINVAL;
        goto done;
    }
    if (fcntl(intercept_sock, F_GETFD, 0) == -1) {
	sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_LINENO,
	    "intercept fd %d not open", intercept_sock);
        errno = EINVAL;
        goto done;
    }

    /*
     * We communicate with the main sudo process over a socket pair
     * which is passed over the intercept_sock.  The reason for not
     * using intercept_sock directly is that multiple processes
     * could be trying to use it at once.  Sending an fd like this
     * is atomic but regular communication is not.
     */
    if (socketpair(PF_UNIX, SOCK_STREAM, 0, sv) == -1) {
	sudo_warn("socketpair");
	goto done;
    }
    if (!intercept_send_fd(intercept_sock, sv[1]))
	goto done;
    close(sv[1]);
    sv[1] = -1;

    buf = fmt_policy_check_req(cmnd, argv, envp, &len);
    if (buf == NULL)
	goto done;

    /* Send request to sudo (blocking). */
    cp = buf;
    do {
	nwritten = write(sv[0], cp, len);
	if (nwritten == -1) {
	    goto done;
	}
	len -= nwritten;
	cp += nwritten;
    } while (len > 0);
    free(buf);
    buf = NULL;

    /* Read message size (uint32_t in host byte order). */
    nread = read(sv[0], &res_len, sizeof(res_len));
    if ((size_t)nread != sizeof(res_len)) {
        if (nread == 0) {
	    sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_LINENO,
		"unexpected EOF reading result size");
	} else {
	    sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_LINENO|SUDO_DEBUG_ERRNO,
		"error reading result size");
	}
        goto done;
    }
    if (res_len > MESSAGE_SIZE_MAX) {
	sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_LINENO,
	    "PolicyCheckResult too large: %zu", len);
        goto done;
    }

    /* Read result from sudo (blocking). */
    if ((buf = malloc(res_len)) == NULL) {
	goto done;
    }
    nread = read(sv[0], buf, res_len);
    if ((size_t)nread != res_len) {
        if (nread == 0) {
	    sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_LINENO,
		"unexpected EOF reading result");
        } else {
	    sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_LINENO|SUDO_DEBUG_ERRNO,
		"error reading result");
	}
        goto done;
    }
    res = policy_check_result__unpack(NULL, res_len, buf);
    if (res == NULL) {
	sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_LINENO,
	    "unable to unpack %s size %u", "PolicyCheckResult", res_len);
        goto done;
    }
    if (res->secret != secret) {
	sudo_warnx("secret mismatch\r");
	goto done;
    }
    switch (res->type_case) {
    case POLICY_CHECK_RESULT__TYPE_ACCEPT_MSG:
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
	    intercept_sock);
	if (nenvp == NULL)
	    goto oom;
	*ncmndp = ncmnd;
	*nargvp = nargv;
	*nenvpp = nenvp;
	ret = true;
	goto done;
    case POLICY_CHECK_RESULT__TYPE_REJECT_MSG:
	/* Policy module displayed reject message but we are in raw mode. */
	fputc('\r', stderr);
	goto done;
    case POLICY_CHECK_RESULT__TYPE_ERROR_MSG:
	/* Policy module may display error message but we are in raw mode. */
	fputc('\r', stderr);
	sudo_warnx("%s", res->u.error_msg->error_message);
	goto done;
    default:
	sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_LINENO,
	    "unexpected type_case value %d in %s from %s",
            res->type_case, "PolicyCheckResult", "sudo");
	goto done;
    }

oom:
    free(ncmnd);
    while (len > 0)
	free(nargv[--len]);

done:
    policy_check_result__free_unpacked(res, NULL);
    if (sv[0] != -1)
	close(sv[0]);
    if (sv[1] != -1)
	close(sv[1]);
    free(buf);

    debug_return_bool(ret);
}
