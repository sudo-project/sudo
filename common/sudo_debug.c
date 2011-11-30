/*
 * Copyright (c) 2011 Todd C. Miller <Todd.Miller@courtesan.com>
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

#include <config.h>

#include <sys/types.h>
#include <sys/param.h>
#include <sys/stat.h>
#include <sys/uio.h>
#include <stdio.h>
#ifdef STDC_HEADERS
# include <stdlib.h>
# include <stddef.h>
#else
# ifdef HAVE_STDLIB_H
#  include <stdlib.h>
# endif
#endif /* STDC_HEADERS */
#ifdef HAVE_STRING_H
# include <string.h>
#endif /* HAVE_STRING_H */
#ifdef HAVE_STRINGS_H
# include <strings.h>
#endif /* HAVE_STRINGS_H */
#ifdef HAVE_UNISTD_H
# include <unistd.h>
#endif /* HAVE_UNISTD_H */
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <time.h>

#include "missing.h"
#include "alloc.h"
#include "error.h"
#include "gettext.h"
#include "sudo_plugin.h"
#include "sudo_debug.h"

/*
 * The debug priorities and subsystems are currently hard-coded.
 * In the future we might consider allowing plugins to register their
 * own subsystems and provide direct access to the debugging API.
 */

/* Note: this must match the order in sudo_debug.h */
const char *const sudo_debug_priorities[] = {
    "crit",
    "err",
    "warn",
    "notice",
    "diag",
    "info",
    "trace",
    "debug",
    NULL
};

/* Note: this must match the order in sudo_debug.h */
const char *const sudo_debug_subsystems[] = {
    "main",
    "memory",
    "args",
    "exec",
    "pty",
    "utmp",
    "conv",
    "pcomm",
    "util",
    "list",
    "netif",
    "audit",
    "edit",
    "selinux",
    "ldap",
    "match",
    "parser",
    "alias",
    "defaults",
    "auth",
    "env",
    "logging",
    "nss",
    "rbtree",
    "perms",
    "plugin",
    NULL
};

#define NUM_SUBSYSTEMS	(sizeof(sudo_debug_subsystems) / sizeof(sudo_debug_subsystems[0]) - 1)

static int sudo_debug_settings[NUM_SUBSYSTEMS];
static int sudo_debug_fd = -1;

extern sudo_conv_t sudo_conv;

/*
 * Parse settings string from sudo.conf and open debugfile.
 * Returns 1 on success, 0 if cannot open debugfile.
 * Unsupported subsystems and priorities are silently ignored.
 */
int sudo_debug_init(const char *debugfile, const char *settings)
{
    char *buf, *cp, *subsys, *pri;
    int i, j;

    /* Init per-subsystems settings to -1 since 0 is a valid priority. */
    for (i = 0; i < NUM_SUBSYSTEMS; i++)
	sudo_debug_settings[i] = -1;

    /* Open debug file if specified. */
    if (debugfile != NULL) {
	if (sudo_debug_fd != -1)
	    close(sudo_debug_fd);
	sudo_debug_fd = open(debugfile, O_WRONLY|O_APPEND|O_CREAT,
	    S_IRUSR|S_IWUSR);
	if (sudo_debug_fd == -1)
	    return 0;
	(void)fcntl(sudo_debug_fd, F_SETFD, FD_CLOEXEC);
    }

    /* Parse settings string. */
    buf = estrdup(settings);
    for ((cp = strtok(buf, ",")); cp != NULL; (cp = strtok(NULL, ","))) {
	/* Should be in the form subsys@pri. */
	subsys = cp;
	if ((pri = strchr(cp, '@')) == NULL)
	    continue;
	*pri++ = '\0';

	/* Look up priority and subsystem, fill in sudo_debug_settings[]. */
	for (i = 0; sudo_debug_priorities[i] != NULL; i++) {
	    if (strcasecmp(pri, sudo_debug_priorities[i]) == 0) {
		for (j = 0; sudo_debug_subsystems[j] != NULL; j++) {
		    if (strcasecmp(subsys, "all") == 0) {
			sudo_debug_settings[j] = i;
			continue;
		    }
		    if (strcasecmp(subsys, sudo_debug_subsystems[j]) == 0) {
			sudo_debug_settings[j] = i;
			break;
		    }
		}
		break;
	    }
	}
    }
    efree(buf);

    return 1;
}

void
sudo_debug_enter(const char *func, const char *file, int line,
    int subsys)
{
    sudo_debug_printf2(subsys | SUDO_DEBUG_TRACE, "-> %s @ %s:%d", func,
	file, line);
}

void sudo_debug_exit(const char *func, const char *file, int line,
    int subsys)
{
    sudo_debug_printf2(subsys | SUDO_DEBUG_TRACE, "<- %s @ %s:%d", func,
	file, line);
}

void sudo_debug_exit_int(const char *func, const char *file, int line,
    int subsys, int rval)
{
    sudo_debug_printf2(subsys | SUDO_DEBUG_TRACE, "<- %s @ %s:%d := %d", func,
	file, line, rval);
}

void sudo_debug_exit_long(const char *func, const char *file, int line,
    int subsys, long rval)
{
    sudo_debug_printf2(subsys | SUDO_DEBUG_TRACE, "<- %s @ %s:%d := %ld", func,
	file, line, rval);
}

void sudo_debug_exit_size_t(const char *func, const char *file, int line,
    int subsys, size_t rval)
{
    /* XXX - should use %zu but snprintf.c doesn't support it */
    sudo_debug_printf2(subsys | SUDO_DEBUG_TRACE, "<- %s @ %s:%d := %lu", func,
	file, line, (unsigned long)rval);
}

void sudo_debug_exit_bool(const char *func, const char *file, int line,
    int subsys, int rval)
{
    if (rval == 0 || rval == 1) {
	sudo_debug_printf2(subsys | SUDO_DEBUG_TRACE, "<- %s @ %s:%d := %s",
	    func, file, line, rval ? "true" : "false");
    } else {
	sudo_debug_printf2(subsys | SUDO_DEBUG_TRACE, "<- %s @ %s:%d := %d",
	    func, file, line, rval);
    }
}

void sudo_debug_exit_str(const char *func, const char *file, int line,
    int subsys, const char *rval)
{
    sudo_debug_printf2(subsys | SUDO_DEBUG_TRACE, "<- %s @ %s:%d := %s", func,
	file, line, rval ? rval : "(null)");
}

void sudo_debug_exit_str_masked(const char *func, const char *file, int line,
    int subsys, const char *rval)
{
    static const char stars[] = "********************************************************************************";
    int len = rval ? strlen(rval) : sizeof("(null)") - 1;

    sudo_debug_printf2(subsys | SUDO_DEBUG_TRACE, "<- %s @ %s:%d := %.*s", func,
	file, line, len, rval ? stars : "(null)");
}

void sudo_debug_exit_ptr(const char *func, const char *file, int line,
    int subsys, const void *rval)
{
    sudo_debug_printf2(subsys | SUDO_DEBUG_TRACE, "<- %s @ %s:%d := %p", func,
	file, line, rval);
}

void
sudo_debug_write(const char *str, int len)
{
    char *timestr;
    time_t now;
    ssize_t n;
    struct iovec iov[5];
    int iovcnt = 4;

    if (len <= 0)
	return;

    if (sudo_debug_fd == -1) {
	/* Use conversation function if no debug fd. */
	if (sudo_conv == NULL)
	    return;

	struct sudo_conv_message msg;
	struct sudo_conv_reply repl;

	/* Call conversation function */
	memset(&msg, 0, sizeof(msg));
	memset(&repl, 0, sizeof(repl));
	msg.msg_type = SUDO_CONV_DEBUG_MSG;
	msg.msg = str;
	sudo_conv(1, &msg, &repl);
	return;
    }

    /* Prepend program name with trailing space. */
    iov[1].iov_base = (char *)getprogname();
    iov[1].iov_len = strlen(iov[1].iov_base);
    iov[2].iov_base = " ";
    iov[2].iov_len = 1;

    /* Add string along with newline if it doesn't have one. */
    iov[3].iov_base = (char *)str;
    iov[3].iov_len = len;
    if (str[len - 1] != '\n') {
	/* force newline */
	iov[4].iov_base = "\n";
	iov[4].iov_len = 1;
	iovcnt++;
    }

    /* Do timestamp last due to ctime's static buffer. */
    now = time(NULL);
    timestr = ctime(&now) + 4;
    timestr[15] = ' ';	/* replace year with a space */
    timestr[16] = '\0';
    iov[0].iov_base = timestr;
    iov[0].iov_len = 16;

    /* Write message in a single syscall */
    n = writev(sudo_debug_fd, iov, iovcnt);
}

void
sudo_debug_printf2(int level, const char *fmt, ...)
{
    int buflen, pri, subsys;
    va_list ap;
    char *buf;

    if (sudo_debug_fd == -1 && sudo_conv == NULL)
	return;

    /* Extract pri and subsystem from level. */
    pri = SUDO_DEBUG_PRI(level);
    subsys = SUDO_DEBUG_SUBSYS(level);

    /* Make sure we want debug info at this level. */
    if (subsys >= NUM_SUBSYSTEMS || sudo_debug_settings[subsys] < pri)
	return;

    va_start(ap, fmt);
    buflen = vasprintf(&buf, fmt, ap);
    va_end(ap);
    if (buflen != -1) {
	sudo_debug_write(buf, buflen);
	free(buf);
    }
}

void
sudo_debug_execve2(int level, const char *path, char *const argv[], char *const envp[])
{
    char * const *av;
    char *buf, *cp;
    int buflen, pri, subsys, log_envp = 0;
    size_t plen;

    if (sudo_debug_fd == -1 && sudo_conv == NULL)
	return;

    /* Extract pri and subsystem from level. */
    pri = SUDO_DEBUG_PRI(level);
    subsys = SUDO_DEBUG_SUBSYS(level);

    /* Make sure we want debug info at this level. */
    if (subsys >= NUM_SUBSYSTEMS || sudo_debug_settings[subsys] < pri)
	return;

    /* Log envp for debug level "debug". */
    if (sudo_debug_settings[subsys] >= SUDO_DEBUG_DEBUG - 1 && envp[0] != NULL)
	log_envp = 1;

#define EXEC_PREFIX "exec "

    /* Alloc and build up buffer. */
    plen = strlen(path);
    buflen = sizeof(EXEC_PREFIX) -1 + plen;
    if (argv[0] != NULL) {
	buflen += sizeof(" []") - 1;
	for (av = argv; *av; av++)
	    buflen += strlen(*av) + 1;
	buflen--;
    }
    if (log_envp) {
	buflen += sizeof(" []") - 1;
	for (av = envp; *av; av++)
	    buflen += strlen(*av) + 1;
	buflen--;
    }
    buf = malloc(buflen + 1);
    if (buf == NULL)
	return;

    /* Copy prefix and command. */
    memcpy(buf, EXEC_PREFIX, sizeof(EXEC_PREFIX) - 1);
    cp = buf + sizeof(EXEC_PREFIX) - 1;
    memcpy(cp, path, plen);
    cp += plen;

    /* Copy argv. */
    if (argv[0] != NULL) {
	*cp++ = ' ';
	*cp++ = '[';
	for (av = argv; *av; av++) {
	    size_t avlen = strlen(*av);
	    memcpy(cp, *av, avlen);
	    cp += avlen;
	    *cp++ = ' ';
	}
	cp[-1] = ']';
    }

    if (log_envp) {
	*cp++ = ' ';
	*cp++ = '[';
	for (av = envp; *av; av++) {
	    size_t avlen = strlen(*av);
	    memcpy(cp, *av, avlen);
	    cp += avlen;
	    *cp++ = ' ';
	}
	cp[-1] = ']';
    }

    *cp = '\0';

    sudo_debug_write(buf, buflen);
    free(buf);
}

/*
 * Dup sudo_debug_fd to the specified value so we don't
 * close it when calling closefrom().
 */
int
sudo_debug_fd_set(int fd)
{
    if (sudo_debug_fd != -1 && fd != sudo_debug_fd) {
	if (dup2(sudo_debug_fd, fd) == -1)
	    return -1;
	(void)fcntl(fd, F_SETFD, FD_CLOEXEC);
	close(sudo_debug_fd);
	sudo_debug_fd = fd;
    }
    return sudo_debug_fd;
}
