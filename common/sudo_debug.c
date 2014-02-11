/*
 * Copyright (c) 2011-2013 Todd C. Miller <Todd.Miller@courtesan.com>
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
#ifdef HAVE_STDBOOL_H
# include <stdbool.h>
#else
# include "compat/stdbool.h"
#endif
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

#define DEFAULT_TEXT_DOMAIN	"sudo"
#include "gettext.h"		/* must be included before missing.h */

#include "missing.h"
#include "alloc.h"
#include "fatal.h"
#include "sudo_plugin.h"
#include "sudo_debug.h"
#include "sudo_util.h"

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
    "args",
    "exec",
    "pty",
    "utmp",
    "conv",
    "pcomm",
    "util",
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
    "hooks",
    "sssd",
    "event",
    NULL
};

#define NUM_SUBSYSTEMS	(sizeof(sudo_debug_subsystems) / sizeof(sudo_debug_subsystems[0]) - 1)

/* Values for sudo_debug_mode */
#define SUDO_DEBUG_MODE_DISABLED	0
#define SUDO_DEBUG_MODE_FILE		1
#define SUDO_DEBUG_MODE_CONV		2

static int sudo_debug_settings[NUM_SUBSYSTEMS];
static int sudo_debug_fd = -1;
static int sudo_debug_mode;
static char sudo_debug_pidstr[(((sizeof(int) * 8) + 2) / 3) + 3];
static size_t sudo_debug_pidlen;
static const int num_subsystems = NUM_SUBSYSTEMS;

/*
 * Parse settings string from sudo.conf and open debugfile.
 * Returns 1 on success, 0 if cannot open debugfile.
 * Unsupported subsystems and priorities are silently ignored.
 */
int sudo_debug_init(const char *debugfile, const char *settings)
{
    char *buf, *cp, *subsys, *pri;
    int i, j;

    /* Make sure we are not already initialized. */
    if (sudo_debug_mode != SUDO_DEBUG_MODE_DISABLED)
	return 1;

    /* Init per-subsystems settings to -1 since 0 is a valid priority. */
    for (i = 0; i < num_subsystems; i++)
	sudo_debug_settings[i] = -1;

    /* Open debug file if specified. */
    if (debugfile != NULL) {
	if (sudo_debug_fd != -1)
	    close(sudo_debug_fd);
	sudo_debug_fd = open(debugfile, O_WRONLY|O_APPEND, S_IRUSR|S_IWUSR);
	if (sudo_debug_fd == -1) {
	    /* Create debug file as needed and set group ownership. */
	    if (errno == ENOENT) {
		sudo_debug_fd = open(debugfile, O_WRONLY|O_APPEND|O_CREAT,
		    S_IRUSR|S_IWUSR);
	    }
	    if (sudo_debug_fd == -1)
		return 0;
	    ignore_result(fchown(sudo_debug_fd, (uid_t)-1, 0));
	}
	(void)fcntl(sudo_debug_fd, F_SETFD, FD_CLOEXEC);
	sudo_debug_mode = SUDO_DEBUG_MODE_FILE;
    } else {
	/* Called from the plugin, no debug file. */
	sudo_debug_mode = SUDO_DEBUG_MODE_CONV;
    }

    /* Stash the pid string so we only have to format it once. */
    (void)snprintf(sudo_debug_pidstr, sizeof(sudo_debug_pidstr), "[%d] ",
	(int)getpid());
    sudo_debug_pidlen = strlen(sudo_debug_pidstr);

    /* Parse settings string. */
    if ((buf = strdup(settings)) == NULL)
	return 0;
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
    free(buf);

    return 1;
}

pid_t
sudo_debug_fork(void)
{
    pid_t pid;

    if ((pid = fork()) == 0) {
	(void)snprintf(sudo_debug_pidstr, sizeof(sudo_debug_pidstr), "[%d] ",
	    (int)getpid());
	sudo_debug_pidlen = strlen(sudo_debug_pidstr);
    }

    return pid;
}

void
sudo_debug_enter(const char *func, const char *file, int line,
    int subsys)
{
    sudo_debug_printf2(NULL, NULL, 0, subsys | SUDO_DEBUG_TRACE,
	"-> %s @ %s:%d", func, file, line);
}

void
sudo_debug_exit(const char *func, const char *file, int line,
    int subsys)
{
    sudo_debug_printf2(NULL, NULL, 0, subsys | SUDO_DEBUG_TRACE,
	"<- %s @ %s:%d", func, file, line);
}

void
sudo_debug_exit_int(const char *func, const char *file, int line,
    int subsys, int rval)
{
    sudo_debug_printf2(NULL, NULL, 0, subsys | SUDO_DEBUG_TRACE,
	"<- %s @ %s:%d := %d", func, file, line, rval);
}

void
sudo_debug_exit_long(const char *func, const char *file, int line,
    int subsys, long rval)
{
    sudo_debug_printf2(NULL, NULL, 0, subsys | SUDO_DEBUG_TRACE,
	"<- %s @ %s:%d := %ld", func, file, line, rval);
}

void
sudo_debug_exit_size_t(const char *func, const char *file, int line,
    int subsys, size_t rval)
{
    /* XXX - should use %zu but our snprintf.c doesn't support it */
    sudo_debug_printf2(NULL, NULL, 0, subsys | SUDO_DEBUG_TRACE,
	"<- %s @ %s:%d := %lu", func, file, line, (unsigned long)rval);
}

/* We use int, not bool, here for functions that return -1 on error. */
void
sudo_debug_exit_bool(const char *func, const char *file, int line,
    int subsys, int rval)
{
    if (rval == true || rval == false) {
	sudo_debug_printf2(NULL, NULL, 0, subsys | SUDO_DEBUG_TRACE,
	    "<- %s @ %s:%d := %s", func, file, line, rval ? "true" : "false");
    } else {
	sudo_debug_printf2(NULL, NULL, 0, subsys | SUDO_DEBUG_TRACE,
	    "<- %s @ %s:%d := %d", func, file, line, rval);
    }
}

void
sudo_debug_exit_str(const char *func, const char *file, int line,
    int subsys, const char *rval)
{
    sudo_debug_printf2(NULL, NULL, 0, subsys | SUDO_DEBUG_TRACE,
	"<- %s @ %s:%d := %s", func, file, line, rval ? rval : "(null)");
}

void
sudo_debug_exit_str_masked(const char *func, const char *file, int line,
    int subsys, const char *rval)
{
    static const char stars[] = "********************************************************************************";
    int len = rval ? strlen(rval) : sizeof("(null)") - 1;

    sudo_debug_printf2(NULL, NULL, 0, subsys | SUDO_DEBUG_TRACE,
	"<- %s @ %s:%d := %.*s", func, file, line, len, rval ? stars : "(null)");
}

void
sudo_debug_exit_ptr(const char *func, const char *file, int line,
    int subsys, const void *rval)
{
    sudo_debug_printf2(NULL, NULL, 0, subsys | SUDO_DEBUG_TRACE,
	"<- %s @ %s:%d := %p", func, file, line, rval);
}

static void
sudo_debug_write_conv(const char *func, const char *file, int lineno,
    const char *str, int len, int errno_val)
{
    /* Remove trailing newlines. */
    while (len > 0 && str[len - 1] == '\n')
	len--;

    if (len > 0) {
	if (func != NULL && file != NULL) {
	    if (errno_val) {
		sudo_printf(SUDO_CONV_DEBUG_MSG, "%.*s: %s @ %s() %s:%d",
		    len, str, strerror(errno_val), func, file, lineno);
	    } else {
		sudo_printf(SUDO_CONV_DEBUG_MSG, "%.*s @ %s() %s:%d",
		    len, str, func, file, lineno);
	    }
	} else {
	    if (errno_val) {
		sudo_printf(SUDO_CONV_DEBUG_MSG, "%.*s: %s",
		    len, str, strerror(errno_val));
	    } else {
		sudo_printf(SUDO_CONV_DEBUG_MSG, "%.*s", len, str);
	    }
	}
    } else if (errno_val) {
	/* Only print error string. */
	if (func != NULL && file != NULL) {
	    sudo_printf(SUDO_CONV_DEBUG_MSG, "%s @ %s() %s:%d",
		strerror(errno_val), func, file, lineno);
	} else {
	    sudo_printf(SUDO_CONV_DEBUG_MSG, "%s", strerror(errno_val));
	}
    }
}

static void
sudo_debug_write_file(const char *func, const char *file, int lineno,
    const char *str, int len, int errno_val)
{
    char *timestr, numbuf[(((sizeof(int) * 8) + 2) / 3) + 2];
    time_t now;
    struct iovec iov[12];
    int iovcnt = 3;

    /* Prepend program name and pid with a trailing space. */
    iov[1].iov_base = (char *)getprogname();
    iov[1].iov_len = strlen(iov[1].iov_base);
    iov[2].iov_base = sudo_debug_pidstr;
    iov[2].iov_len = sudo_debug_pidlen;

    /* Add string, trimming any trailing newlines. */
    while (len > 0 && str[len - 1] == '\n')
	len--;
    if (len > 0) {
	iov[iovcnt].iov_base = (char *)str;
	iov[iovcnt].iov_len = len;
	iovcnt++;
    }

    /* Append error string if errno is specified. */
    if (errno_val) {
	if (len > 0) {
	    iov[iovcnt].iov_base = ": ";
	    iov[iovcnt].iov_len = 2;
	    iovcnt++;
	}
	iov[iovcnt].iov_base = strerror(errno_val);
	iov[iovcnt].iov_len = strlen(iov[iovcnt].iov_base);
	iovcnt++;
    }

    /* If function, file and lineno are specified, append them. */
    if (func != NULL && file != NULL && lineno != 0) {
	iov[iovcnt].iov_base = " @ ";
	iov[iovcnt].iov_len = 3;
	iovcnt++;

	iov[iovcnt].iov_base = (char *)func;
	iov[iovcnt].iov_len = strlen(func);
	iovcnt++;

	iov[iovcnt].iov_base = "() ";
	iov[iovcnt].iov_len = 3;
	iovcnt++;

	iov[iovcnt].iov_base = (char *)file;
	iov[iovcnt].iov_len = strlen(file);
	iovcnt++;

	(void)snprintf(numbuf, sizeof(numbuf), ":%d", lineno);
	iov[iovcnt].iov_base = numbuf;
	iov[iovcnt].iov_len = strlen(numbuf);
	iovcnt++;
    }

    /* Append newline. */
    iov[iovcnt].iov_base = "\n";
    iov[iovcnt].iov_len = 1;
    iovcnt++;

    /* Do timestamp last due to ctime's static buffer. */
    time(&now);
    timestr = ctime(&now) + 4;
    timestr[15] = ' ';	/* replace year with a space */
    timestr[16] = '\0';
    iov[0].iov_base = timestr;
    iov[0].iov_len = 16;

    /* Write message in a single syscall */
    ignore_result(writev(sudo_debug_fd, iov, iovcnt));
}

void
sudo_debug_write2(const char *func, const char *file, int lineno,
    const char *str, int len, int errno_val)
{
    switch (sudo_debug_mode) {
    case SUDO_DEBUG_MODE_CONV:
	sudo_debug_write_conv(func, file, lineno, str, len, errno_val);
	break;
    case SUDO_DEBUG_MODE_FILE:
	sudo_debug_write_file(func, file, lineno, str, len, errno_val);
	break;
    }
}

/* XXX - turn into a macro */
void
sudo_debug_write(const char *str, int len, int errno_val)
{
    sudo_debug_write2(NULL, NULL, 0, str, len, errno_val);
}

void
sudo_debug_vprintf2(const char *func, const char *file, int lineno, int level,
    const char *fmt, va_list ap)
{
    int buflen, pri, subsys, saved_errno = errno;
    char *buf = NULL;

    if (!sudo_debug_mode)
	return;

    /* Extract pri and subsystem from level. */
    pri = SUDO_DEBUG_PRI(level);
    subsys = SUDO_DEBUG_SUBSYS(level);

    /* Make sure we want debug info at this level. */
    if (subsys < num_subsystems && sudo_debug_settings[subsys] >= pri) {
	buflen = fmt ? vasprintf(&buf, fmt, ap) : 0;
	if (buflen != -1) {
	    int errcode = ISSET(level, SUDO_DEBUG_ERRNO) ? saved_errno : 0;
	    if (ISSET(level, SUDO_DEBUG_LINENO))
		sudo_debug_write2(func, file, lineno, buf, buflen, errcode);
	    else
		sudo_debug_write2(NULL, NULL, 0, buf, buflen, errcode);
	    free(buf);
	}
    }

    errno = saved_errno;
}

#ifdef NO_VARIADIC_MACROS
void
sudo_debug_printf_nvm(int pri, const char *fmt, ...)
{
    va_list ap;

    va_start(ap, fmt);
    sudo_debug_vprintf2(NULL, NULL, 0, pri, fmt, ap);
    va_end(ap);
}
#endif /* NO_VARIADIC_MACROS */

void
sudo_debug_printf2(const char *func, const char *file, int lineno, int level,
    const char *fmt, ...)
{
    va_list ap;

    va_start(ap, fmt);
    sudo_debug_vprintf2(func, file, lineno, level, fmt, ap);
    va_end(ap);
}

void
sudo_debug_execve2(int level, const char *path, char *const argv[], char *const envp[])
{
    char * const *av;
    char *buf, *cp;
    int buflen, pri, subsys, log_envp = 0;
    size_t plen;

    if (!sudo_debug_mode)
	return;

    /* Extract pri and subsystem from level. */
    pri = SUDO_DEBUG_PRI(level);
    subsys = SUDO_DEBUG_SUBSYS(level);

    /* Make sure we want debug info at this level. */
    if (subsys >= num_subsystems || sudo_debug_settings[subsys] < pri)
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

    sudo_debug_write(buf, buflen, 0);
    free(buf);
}

/*
 * Getter for the debug descriptor.
 */
int
sudo_debug_fd_get(void)
{
    return sudo_debug_fd;
}

/*
 * Setter for the debug descriptor.
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
