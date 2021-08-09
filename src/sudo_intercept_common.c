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

#define SUDO_ERROR_WRAP 0

#include "sudo_compat.h"
#include "sudo_fatal.h"
#include "sudo_exec.h"
#include "sudo_gettext.h"
#include "intercept.pb-c.h"

extern char **environ;

static pid_t mainpid = -1;
static int intercept_sock = -1;

/*
 * Look up SUDO_INTERCEPT_FD in the environment.
 * This function is run when the shared library is loaded.
 */
__attribute__((constructor)) static void
sudo_interposer_init(void)
{
    static bool initialized;
    char **p;

    if (!initialized) {
        initialized = true;
        mainpid = getpid();

        /*
         * Missing SUDO_INTERCEPT_FD will result in execve() failure.
         * Note that we cannot use getenv(3) here on Linux at least.
         */
        for (p = environ; *p != NULL; p++) {
            if (strncmp(*p, "SUDO_INTERCEPT_FD=", sizeof("SUDO_INTERCEPT_FD=") -1) == 0) {
                const char *fdstr = *p + sizeof("SUDO_INTERCEPT_FD=") - 1;
                char *ep;
                long ulval;

		/* XXX - debugging */
                ulval = strtoul(fdstr, &ep, 10);
                if (*fdstr == '\0' || *ep != '\0' || ulval > INT_MAX) {
		    sudo_warnx(U_("invalid SUDO_INTERCEPT_FD: %s"), fdstr);
                    break;
                }
                intercept_sock = ulval;
                break;
            }
        }
    }
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
	sudo_warnx(U_("client message too large: %zu"), len);
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
    return buf;
}

/* Send fd over a unix domain socket. */
static bool
intercept_send_fd(int sock, int fd)
{
    struct msghdr msg;
    union {
	struct cmsghdr hdr;
	char buf[CMSG_SPACE(sizeof(int))];
    } cmsgbuf;
    struct cmsghdr *cmsg;
    struct iovec iov[1];
    char ch = '\0';
    ssize_t nsent;

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

    cmsg = CMSG_FIRSTHDR(&msg);
    cmsg->cmsg_len = CMSG_LEN(sizeof(int));
    cmsg->cmsg_level = SOL_SOCKET;
    cmsg->cmsg_type = SCM_RIGHTS;
    *(int *)CMSG_DATA(cmsg) = fd;

    for (;;) {
	nsent = sendmsg(sock, &msg, 0);
	if (nsent != -1)
	    return true;
	if (errno != EAGAIN && errno != EINTR)
	    break;
    }
    sudo_warn("sendmsg");
    return false;
}

bool
command_allowed(const char *cmnd, char * const argv[], char * const envp[],
    char **ncmnd, char ***nargv, char ***nenvp)
{
    PolicyCheckResult *res = NULL;
    int sv[2] = { -1, -1 };
    ssize_t nread, nwritten;
    uint8_t *cp, *buf = NULL;
    bool ret = false;
    uint32_t res_len;
    size_t len;

    if (intercept_sock < INTERCEPT_FD_MIN) {
	sudo_warnx("invalid intercept fd: %d", intercept_sock); // XXX debugging
        errno = EINVAL;
        goto done;
    }
    if (fcntl(intercept_sock, F_GETFD, 0) == -1) {
	sudo_warnx("intercept fd %d not open", intercept_sock); // XXX debugging
        errno = EINVAL;
        goto done;
    }

    /* Don't allow the original process to be replaced. */
    if (getpid() == mainpid) {
	sudo_warnx("shell overwrite denied"); // XXX
	// XXX debugging
        errno = EACCES;
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
        if (nread == 0)
            sudo_warnx("unexpected EOF reading message size"); // XXX
	else
            sudo_warn("read");
        goto done;
    }
    if (res_len > MESSAGE_SIZE_MAX) {
        sudo_warnx(U_("server message too large: %zu"), (size_t)res_len);
        goto done;
    }

    /* Read response from sudo (blocking). */
    if ((buf = malloc(res_len)) == NULL) {
	goto done;
    }
    nread = read(sv[0], buf, res_len);
    if ((size_t)nread != res_len) {
        if (nread == 0)
            sudo_warnx("unexpected EOF reading response"); // XXX
        else
            sudo_warn("read");
        goto done;
    }
    res = policy_check_result__unpack(NULL, res_len, buf);
    if (res == NULL) {
        sudo_warnx("unable to unpack %s size %zu", "PolicyCheckResult",
            (size_t)res_len);
        goto done;
    }
    switch (res->type_case) {
    case POLICY_CHECK_RESULT__TYPE_ACCEPT_MSG:
	// XXX - return value
	*ncmnd = strdup(res->u.accept_msg->run_command);
	*nargv = reallocarray(NULL, res->u.accept_msg->n_run_argv + 1, sizeof(char *));
	for (len = 0; len < res->u.accept_msg->n_run_argv; len++) {
	    (*nargv)[len] = strdup(res->u.accept_msg->run_argv[len]);
	}
	(*nargv)[len] = NULL;
	/* XXX - add SUDO_INTERCEPT_FD to environment as needed. */
	*nenvp = (char **)envp;
	ret = true;
	break;
    case POLICY_CHECK_RESULT__TYPE_REJECT_MSG:
	/* XXX - display reject message */
	break;
    case POLICY_CHECK_RESULT__TYPE_ERROR_MSG:
	/* XXX - display error message */
	break;
    default:
        sudo_warnx(U_("unexpected type_case value %d in %s from %s"),
            res->type_case, "PolicyCheckResult", "sudo");
	break;
    }

done:
    policy_check_result__free_unpacked(res, NULL);
    if (sv[0] != -1)
	close(sv[0]);
    if (sv[1] != -1)
	close(sv[1]);
    free(buf);

    return ret;
}
