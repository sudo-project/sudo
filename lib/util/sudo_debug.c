/*
 * SPDX-License-Identifier: ISC
 *
 * Copyright (c) 2011-2017 Todd C. Miller <Todd.Miller@sudo.ws>
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
#include <sys/stat.h>
#include <sys/uio.h>
#include <stdio.h>
#include <stdlib.h>
#ifdef HAVE_STRING_H
# include <string.h>
#endif /* HAVE_STRING_H */
#ifdef HAVE_STRINGS_H
# include <strings.h>
#endif /* HAVE_STRINGS_H */
#include <unistd.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <time.h>

#define DEFAULT_TEXT_DOMAIN	"sudo"
#include "sudo_gettext.h"	/* must be included before sudo_compat.h */

#include "sudo_compat.h"
#include "sudo_fatal.h"
#include "sudo_plugin.h"
#include "sudo_debug.h"
#include "sudo_conf.h"
#include "sudo_util.h"

/*
 * The debug priorities and subsystems are currently hard-coded.
 * In the future we might consider allowing plugins to register their
 * own subsystems and provide direct access to the debugging API.
 */

/* Note: this must match the order in sudo_debug.h */
static const char *const sudo_debug_priorities[] = {
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
static const char *const sudo_debug_default_subsystems[] = {
    "args",
    "conv",
    "edit",
    "event",
    "exec",
    "hooks",
    "main",
    "netif",
    "pcomm",
    "plugin",
    "pty",
    "selinux",
    "util",
    "utmp",
    NULL
};

#define NUM_DEF_SUBSYSTEMS	(nitems(sudo_debug_default_subsystems) - 1)

/*
 * For multiple programs/plugins there is a per-program instance
 * and one or more outputs (files).
 */
struct sudo_debug_output {
    SLIST_ENTRY(sudo_debug_output) entries;
    char *filename;
    int *settings;
    int fd;
};
SLIST_HEAD(sudo_debug_output_list, sudo_debug_output);
struct sudo_debug_instance {
    char *program;
    const char *const *subsystems;
    const unsigned int *subsystem_ids;
    unsigned int max_subsystem;
    unsigned int refcnt;
    struct sudo_debug_output_list outputs;
};

/* Support up to 10 instances. */
#define SUDO_DEBUG_INSTANCE_MAX 10
static struct sudo_debug_instance *sudo_debug_instances[SUDO_DEBUG_INSTANCE_MAX];
static int sudo_debug_last_instance = -1;

static char sudo_debug_pidstr[(((sizeof(int) * 8) + 2) / 3) + 3];
static size_t sudo_debug_pidlen;

#define round_nfds(_n)	(((_n) + (4 * NBBY) - 1) & ~((4 * NBBY) - 1))
static int sudo_debug_fds_size;
static unsigned char *sudo_debug_fds;
static int sudo_debug_max_fd = -1;

/* Default instance index to use for common utility functions. */
static int sudo_debug_active_instance = -1;

/*
 * Free the specified output structure.
 */
static void
sudo_debug_free_output(struct sudo_debug_output *output)
{
    free(output->filename);
    free(output->settings);
    if (output->fd != -1)
	close(output->fd);
    free(output);
}

/*
 * Create a new output file for the specified debug instance.
 * Returns NULL if the file cannot be opened or memory cannot be allocated.
 */
static struct sudo_debug_output *
sudo_debug_new_output(struct sudo_debug_instance *instance,
    struct sudo_debug_file *debug_file)
{
    char *buf, *cp, *last, *subsys, *pri;
    struct sudo_debug_output *output;
    unsigned int j;
    int i;

    /* Create new output for the instance. */
    /* XXX - reuse fd for existing filename? */
    output = calloc(1, sizeof(*output));
    if (output == NULL)
	goto oom;
    output->fd = -1;
    output->settings = reallocarray(NULL, instance->max_subsystem + 1,
	sizeof(int));
    if (output->settings == NULL)
	goto oom;
    output->filename = strdup(debug_file->debug_file);
    if (output->filename == NULL)
	goto oom;
    output->fd = -1;

    /* Init per-subsystems settings to -1 since 0 is a valid priority. */
    for (j = 0; j <= instance->max_subsystem; j++)
	output->settings[j] = -1;

    /* Open debug file. */
    output->fd = open(output->filename, O_WRONLY|O_APPEND, S_IRUSR|S_IWUSR);
    if (output->fd == -1) {
	/* Create debug file as needed and set group ownership. */
	if (errno == ENOENT) {
	    output->fd = open(output->filename, O_WRONLY|O_APPEND|O_CREAT,
		S_IRUSR|S_IWUSR);
	}
	if (output->fd == -1) {
	    sudo_warn_nodebug("%s", output->filename);
	    goto bad;
	}
	ignore_result(fchown(output->fd, (uid_t)-1, 0));
    }
    (void)fcntl(output->fd, F_SETFD, FD_CLOEXEC);
    if (sudo_debug_fds_size < output->fd) {
	/* Bump fds size to the next multiple of 4 * NBBY. */
	const int old_size = sudo_debug_fds_size / NBBY;
	const int new_size = round_nfds(output->fd + 1) / NBBY;
	unsigned char *new_fds;

	new_fds = realloc(sudo_debug_fds, new_size);
	if (new_fds == NULL)
	    goto oom;
	memset(new_fds + old_size, 0, new_size - old_size);
	sudo_debug_fds = new_fds;
	sudo_debug_fds_size = new_size * NBBY;
    }
    sudo_setbit(sudo_debug_fds, output->fd);
    if (output->fd > sudo_debug_max_fd)
	sudo_debug_max_fd = output->fd;

    /* Parse Debug conf string. */
    buf = strdup(debug_file->debug_flags);
    if (buf == NULL)
	goto oom;
    for ((cp = strtok_r(buf, ",", &last)); cp != NULL; (cp = strtok_r(NULL, ",", &last))) {
	/* Should be in the form subsys@pri. */
	subsys = cp;
	if ((pri = strchr(cp, '@')) == NULL)
	    continue;
	*pri++ = '\0';

	/* Look up priority and subsystem, fill in sudo_debug_settings[]. */
	for (i = 0; sudo_debug_priorities[i] != NULL; i++) {
	    if (strcasecmp(pri, sudo_debug_priorities[i]) == 0) {
		for (j = 0; instance->subsystems[j] != NULL; j++) {
		    if (strcasecmp(subsys, "all") == 0) {
			const unsigned int idx = instance->subsystem_ids ?
			    SUDO_DEBUG_SUBSYS(instance->subsystem_ids[j]) : j;
			if (i > output->settings[idx])
			    output->settings[idx] = i;
			continue;
		    }
		    if (strcasecmp(subsys, instance->subsystems[j]) == 0) {
			const unsigned int idx = instance->subsystem_ids ?
			    SUDO_DEBUG_SUBSYS(instance->subsystem_ids[j]) : j;
			if (i > output->settings[idx])
			    output->settings[idx] = i;
			break;
		    }
		}
		break;
	    }
	}
    }
    free(buf);

    return output;
oom:
    sudo_warn_nodebug(NULL);
bad:
    if (output != NULL)
	sudo_debug_free_output(output);
    return NULL;
}

/*
 * Register a program/plugin with the debug framework,
 * parses settings string from sudo.conf and opens debug_files.
 * If subsystem names are specified they override the default values.
 * NOTE: subsystems must not be freed by caller unless deregistered.
 * Sets the active instance to the newly registered instance.
 * Returns instance index on success, SUDO_DEBUG_INSTANCE_INITIALIZER
 * if no debug files are specified and SUDO_DEBUG_INSTANCE_ERROR
 * on error.
 */
int
sudo_debug_register_v1(const char *program, const char *const subsystems[],
    unsigned int ids[], struct sudo_conf_debug_file_list *debug_files)
{
    struct sudo_debug_instance *instance = NULL;
    struct sudo_debug_output *output;
    struct sudo_debug_file *debug_file;
    int idx, free_idx = -1;
    debug_decl_func(sudo_debug_register);

    if (debug_files == NULL)
	return SUDO_DEBUG_INSTANCE_INITIALIZER;

    /* Use default subsystem names if none are provided. */
    if (subsystems == NULL) {
	subsystems = sudo_debug_default_subsystems;
    } else if (ids == NULL) {
	/* If subsystems are specified we must have ids[] too. */
	return SUDO_DEBUG_INSTANCE_ERROR;
    }

    /* Search for existing instance. */
    for (idx = 0; idx <= sudo_debug_last_instance; idx++) {
	if (sudo_debug_instances[idx] == NULL) {
	    free_idx = idx;
	    continue;
	}
	if (sudo_debug_instances[idx]->subsystems == subsystems &&
	    strcmp(sudo_debug_instances[idx]->program, program) == 0) {
	    instance = sudo_debug_instances[idx];
	    break;
	}
    }

    if (instance == NULL) {
	unsigned int i, j, max_id = NUM_DEF_SUBSYSTEMS - 1;

	/* Fill in subsystem name -> id mapping as needed. */
	if (ids != NULL) {
	    for (i = 0; subsystems[i] != NULL; i++) {
		/* Check default subsystems. */
		for (j = 0; j < NUM_DEF_SUBSYSTEMS; j++) {
		    if (strcmp(subsystems[i], sudo_debug_default_subsystems[j]) == 0)
			break;
		}
		if (j == NUM_DEF_SUBSYSTEMS)
		    j = ++max_id;
		ids[i] = ((j + 1) << 6);
	    }
	}

	if (free_idx != -1)
	    idx = free_idx;
	if (idx == SUDO_DEBUG_INSTANCE_MAX) {
	    /* XXX - realloc? */
	    sudo_warnx_nodebug("too many debug instances (max %d)", SUDO_DEBUG_INSTANCE_MAX);
	    return SUDO_DEBUG_INSTANCE_ERROR;
	}
	if (idx != sudo_debug_last_instance + 1 && idx != free_idx) {
	    sudo_warnx_nodebug("%s: instance number mismatch: expected %d or %d, got %d", __func__, sudo_debug_last_instance + 1, free_idx, idx);
	    return SUDO_DEBUG_INSTANCE_ERROR;
	}
	if ((instance = malloc(sizeof(*instance))) == NULL)
	    return SUDO_DEBUG_INSTANCE_ERROR;
	if ((instance->program = strdup(program)) == NULL) {
	    free(instance);
	    return SUDO_DEBUG_INSTANCE_ERROR;
	}
	instance->subsystems = subsystems;
	instance->subsystem_ids = ids;
	instance->max_subsystem = max_id;
	instance->refcnt = 1;
	SLIST_INIT(&instance->outputs);
	sudo_debug_instances[idx] = instance;
	if (idx != free_idx)
	    sudo_debug_last_instance++;
    } else {
	/* Check for matching instance but different ids[]. */
	if (ids != NULL && instance->subsystem_ids != ids) {
	    unsigned int i;

	    for (i = 0; subsystems[i] != NULL; i++)
		ids[i] = instance->subsystem_ids[i];
	}
	instance->refcnt++;
    }

    TAILQ_FOREACH(debug_file, debug_files, entries) {
	output = sudo_debug_new_output(instance, debug_file);
	if (output != NULL)
	    SLIST_INSERT_HEAD(&instance->outputs, output, entries);
    }

    /* Set active instance. */
    sudo_debug_active_instance = idx;

    /* Stash the pid string so we only have to format it once. */
    if (sudo_debug_pidlen == 0) {
	(void)snprintf(sudo_debug_pidstr, sizeof(sudo_debug_pidstr), "[%d] ",
	    (int)getpid());
	sudo_debug_pidlen = strlen(sudo_debug_pidstr);
    }

    return idx;
}

/*
 * De-register the specified instance from the debug subsystem
 * and free up any associated data structures.
 * Returns the number of remaining references for the instance or -1 on error.
 */
int
sudo_debug_deregister_v1(int idx)
{
    struct sudo_debug_instance *instance;
    struct sudo_debug_output *output, *next;
    debug_decl_func(sudo_debug_deregister);

    if (idx < 0 || idx > sudo_debug_last_instance) {
	sudo_warnx_nodebug("%s: invalid instance ID %d, max %d",
	    __func__, idx, sudo_debug_last_instance);
	return -1;
    }
    /* Reset active instance as needed. */
    if (sudo_debug_active_instance == idx)
	sudo_debug_active_instance = -1;

    instance = sudo_debug_instances[idx];
    if (instance == NULL)
	return -1;			/* already deregistered */

    if (--instance->refcnt != 0)
	return instance->refcnt;	/* ref held by other caller */

    /* Free up instance data, note that subsystems[] is owned by caller. */
    sudo_debug_instances[idx] = NULL;
    SLIST_FOREACH_SAFE(output, &instance->outputs, entries, next) {
	close(output->fd);
	free(output->filename);
	free(output->settings);
	free(output);
    }
    free(instance->program);
    free(instance);

    if (idx == sudo_debug_last_instance)
	sudo_debug_last_instance--;

    return 0;
}

int
sudo_debug_get_instance_v1(const char *program)
{
    int idx;

    for (idx = 0; idx <= sudo_debug_last_instance; idx++) {
	if (sudo_debug_instances[idx] == NULL)
	    continue;
	if (strcmp(sudo_debug_instances[idx]->program, program) == 0)
	    return idx;
    }
    return SUDO_DEBUG_INSTANCE_INITIALIZER;
}

pid_t
sudo_debug_fork_v1(void)
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
sudo_debug_enter_v1(const char *func, const char *file, int line,
    int subsys)
{
    sudo_debug_printf2(NULL, NULL, 0, subsys | SUDO_DEBUG_TRACE,
	"-> %s @ %s:%d", func, file, line);
}

void
sudo_debug_exit_v1(const char *func, const char *file, int line,
    int subsys)
{
    sudo_debug_printf2(NULL, NULL, 0, subsys | SUDO_DEBUG_TRACE,
	"<- %s @ %s:%d", func, file, line);
}

void
sudo_debug_exit_int_v1(const char *func, const char *file, int line,
    int subsys, int ret)
{
    sudo_debug_printf2(NULL, NULL, 0, subsys | SUDO_DEBUG_TRACE,
	"<- %s @ %s:%d := %d", func, file, line, ret);
}

void
sudo_debug_exit_long_v1(const char *func, const char *file, int line,
    int subsys, long ret)
{
    sudo_debug_printf2(NULL, NULL, 0, subsys | SUDO_DEBUG_TRACE,
	"<- %s @ %s:%d := %ld", func, file, line, ret);
}

void
sudo_debug_exit_id_t_v1(const char *func, const char *file, int line,
    int subsys, id_t ret)
{
#if SIZEOF_ID_T == 8
    sudo_debug_printf2(NULL, NULL, 0, subsys | SUDO_DEBUG_TRACE,
	"<- %s @ %s:%d := %lld", func, file, line, (long long)ret);
#else
    sudo_debug_printf2(NULL, NULL, 0, subsys | SUDO_DEBUG_TRACE,
	"<- %s @ %s:%d := %d", func, file, line, (int)ret);
#endif
}

void
sudo_debug_exit_size_t_v1(const char *func, const char *file, int line,
    int subsys, size_t ret)
{
    sudo_debug_printf2(NULL, NULL, 0, subsys | SUDO_DEBUG_TRACE,
	"<- %s @ %s:%d := %zu", func, file, line, ret);
}

void
sudo_debug_exit_ssize_t_v1(const char *func, const char *file, int line,
    int subsys, ssize_t ret)
{
    sudo_debug_printf2(NULL, NULL, 0, subsys | SUDO_DEBUG_TRACE,
	"<- %s @ %s:%d := %zd", func, file, line, ret);
}

void
sudo_debug_exit_time_t_v1(const char *func, const char *file, int line,
    int subsys, time_t ret)
{
#if SIZEOF_TIME_T == 8
    sudo_debug_printf2(NULL, NULL, 0, subsys | SUDO_DEBUG_TRACE,
	"<- %s @ %s:%d := %lld", func, file, line, (long long)ret);
#else
    sudo_debug_printf2(NULL, NULL, 0, subsys | SUDO_DEBUG_TRACE,
	"<- %s @ %s:%d := %d", func, file, line, (int)ret);
#endif
}

void
sudo_debug_exit_bool_v1(const char *func, const char *file, int line,
    int subsys, bool ret)
{
    sudo_debug_printf2(NULL, NULL, 0, subsys | SUDO_DEBUG_TRACE,
	"<- %s @ %s:%d := %s", func, file, line, ret ? "true" : "false");
}

void
sudo_debug_exit_str_v1(const char *func, const char *file, int line,
    int subsys, const char *ret)
{
    sudo_debug_printf2(NULL, NULL, 0, subsys | SUDO_DEBUG_TRACE,
	"<- %s @ %s:%d := %s", func, file, line, ret ? ret : "(null)");
}

void
sudo_debug_exit_str_masked_v1(const char *func, const char *file, int line,
    int subsys, const char *ret)
{
    static const char stars[] = "********************************************************************************";
    int len = ret ? strlen(ret) : sizeof("(null)") - 1;

    sudo_debug_printf2(NULL, NULL, 0, subsys | SUDO_DEBUG_TRACE,
	"<- %s @ %s:%d := %.*s", func, file, line, len, ret ? stars : "(null)");
}

void
sudo_debug_exit_ptr_v1(const char *func, const char *file, int line,
    int subsys, const void *ret)
{
    sudo_debug_printf2(NULL, NULL, 0, subsys | SUDO_DEBUG_TRACE,
	"<- %s @ %s:%d := %p", func, file, line, ret);
}

void
sudo_debug_write2_v1(int fd, const char *func, const char *file, int lineno,
    const char *str, int len, int errnum)
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
    if (errnum) {
	if (len > 0) {
	    iov[iovcnt].iov_base = ": ";
	    iov[iovcnt].iov_len = 2;
	    iovcnt++;
	}
	iov[iovcnt].iov_base = strerror(errnum);
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
    ignore_result(writev(fd, iov, iovcnt));
}

bool
sudo_debug_needed_v1(int level)
{
    unsigned int subsys;
    int pri;
    struct sudo_debug_instance *instance;
    struct sudo_debug_output *output;
    bool result = false;

    if (sudo_debug_active_instance == -1)
        goto out;

    /* Extract priority and subsystem from level. */
    pri = SUDO_DEBUG_PRI(level);
    subsys = (unsigned int)SUDO_DEBUG_SUBSYS(level);

    if (sudo_debug_active_instance > sudo_debug_last_instance)
        goto out;

    instance = sudo_debug_instances[sudo_debug_active_instance];
    if (instance == NULL)
        goto out;

    if (subsys <= instance->max_subsystem) {
        SLIST_FOREACH(output, &instance->outputs, entries) {
            if (output->settings[subsys] >= pri) {
                result = true;
                break;
            }
        }
    }
out:
    return result;
}

void
sudo_debug_vprintf2_v1(const char *func, const char *file, int lineno, int level,
    const char *fmt, va_list ap)
{
    int buflen, pri, saved_errno = errno;
    unsigned int subsys;
    char static_buf[1024], *buf = static_buf;
    struct sudo_debug_instance *instance;
    struct sudo_debug_output *output;
    debug_decl_func(sudo_debug_vprintf2);

    if (sudo_debug_active_instance == -1)
	goto out;

    /* Extract priority and subsystem from level. */
    pri = SUDO_DEBUG_PRI(level);
    subsys = SUDO_DEBUG_SUBSYS(level);

    /* Find matching instance. */
    if (sudo_debug_active_instance > sudo_debug_last_instance) {
	sudo_warnx_nodebug("%s: invalid instance ID %d, max %d",
	    __func__, sudo_debug_active_instance, sudo_debug_last_instance);
	goto out;
    }
    instance = sudo_debug_instances[sudo_debug_active_instance];
    if (instance == NULL) {
	sudo_warnx_nodebug("%s: unregistered instance index %d", __func__,
	    sudo_debug_active_instance);
	goto out;
    }

    SLIST_FOREACH(output, &instance->outputs, entries) {
	/* Make sure we want debug info at this level. */
	if (subsys <= instance->max_subsystem && output->settings[subsys] >= pri) {
	    va_list ap2;

	    /* Operate on a copy of ap to support multiple outputs. */
	    va_copy(ap2, ap);
	    buflen = fmt ? vsnprintf(static_buf, sizeof(static_buf), fmt, ap2) : 0;
	    va_end(ap2);
	    if (buflen >= ssizeof(static_buf)) {
		va_list ap3;

		/* Not enough room in static buf, allocate dynamically. */
		va_copy(ap3, ap);
		buflen = vasprintf(&buf, fmt, ap3);
		va_end(ap3);
	    }
	    if (buflen != -1) {
		int errcode = ISSET(level, SUDO_DEBUG_ERRNO) ? saved_errno : 0;
		if (ISSET(level, SUDO_DEBUG_LINENO))
		    sudo_debug_write2(output->fd, func, file, lineno, buf, buflen, errcode);
		else
		    sudo_debug_write2(output->fd, NULL, NULL, 0, buf, buflen, errcode);
		if (buf != static_buf) {
		    free(buf);
		    buf = static_buf;
		}
	    }
	}
    }
out:
    errno = saved_errno;
}

#ifdef NO_VARIADIC_MACROS
void
sudo_debug_printf_nvm_v1(int pri, const char *fmt, ...)
{
    va_list ap;

    va_start(ap, fmt);
    sudo_debug_vprintf2(NULL, NULL, 0, pri, fmt, ap);
    va_end(ap);
}
#endif /* NO_VARIADIC_MACROS */

void
sudo_debug_printf2_v1(const char *func, const char *file, int lineno, int level,
    const char *fmt, ...)
{
    va_list ap;

    va_start(ap, fmt);
    sudo_debug_vprintf2(func, file, lineno, level, fmt, ap);
    va_end(ap);
}

#define EXEC_PREFIX "exec "

void
sudo_debug_execve2_v1(int level, const char *path, char *const argv[], char *const envp[])
{
    int buflen, pri, saved_errno = errno;
    unsigned int subsys;
    struct sudo_debug_instance *instance;
    struct sudo_debug_output *output;
    char * const *av;
    char *cp, static_buf[4096], *buf = static_buf;
    size_t plen;
    debug_decl_func(sudo_debug_execve2);

    if (sudo_debug_active_instance == -1)
	goto out;

    /* Extract priority and subsystem from level. */
    pri = SUDO_DEBUG_PRI(level);
    subsys = SUDO_DEBUG_SUBSYS(level);

    /* Find matching instance. */
    if (sudo_debug_active_instance > sudo_debug_last_instance) {
	sudo_warnx_nodebug("%s: invalid instance ID %d, max %d",
	    __func__, sudo_debug_active_instance, sudo_debug_last_instance);
	goto out;
    }
    instance = sudo_debug_instances[sudo_debug_active_instance];
    if (instance == NULL) {
	sudo_warnx_nodebug("%s: unregistered instance index %d", __func__,
	    sudo_debug_active_instance);
	goto out;
    }
    if (subsys > instance->max_subsystem)
	goto out;

    SLIST_FOREACH(output, &instance->outputs, entries) {
	bool log_envp = false;

	/* Make sure we want debug info at this level. */
	if (output->settings[subsys] < pri)
	    continue;

	/* Log envp for debug level "debug". */
	if (output->settings[subsys] >= SUDO_DEBUG_DEBUG - 1 && envp[0] != NULL)
	    log_envp = true;

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
	if (buflen >= ssizeof(static_buf)) {
	    buf = malloc(buflen + 1);
	    if (buf == NULL)
		goto out;
	}

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

	sudo_debug_write(output->fd, buf, buflen, 0);
	if (buf != static_buf) {
	    free(buf);
	    buf = static_buf;
	}
    }
out:
    errno = saved_errno;
}

/*
 * Returns the active instance or SUDO_DEBUG_INSTANCE_INITIALIZER
 * if no instance is active.
 */
int
sudo_debug_get_active_instance_v1(void)
{
    return sudo_debug_active_instance;
}

/*
 * Sets a new active instance, returning the old one.
 * Note that the old instance may be SUDO_DEBUG_INSTANCE_INITIALIZER
 * if this is the only instance.
 */
int
sudo_debug_set_active_instance_v1(int idx)
{
    const int old_idx = sudo_debug_active_instance;

    if (idx >= -1 && idx <= sudo_debug_last_instance)
	sudo_debug_active_instance = idx;
    return old_idx;
}

/*
 * Replace the ofd with nfd in all outputs if present.
 * Also updates sudo_debug_fds.
 */
void
sudo_debug_update_fd_v1(int ofd, int nfd)
{
    int idx;

    if (ofd <= sudo_debug_max_fd && sudo_isset(sudo_debug_fds, ofd)) {
	/* Update sudo_debug_fds. */
	sudo_clrbit(sudo_debug_fds, ofd);
	sudo_setbit(sudo_debug_fds, nfd);

	/* Update the outputs. */
	for (idx = 0; idx <= sudo_debug_last_instance; idx++) {
	    struct sudo_debug_instance *instance;
	    struct sudo_debug_output *output;

	    instance = sudo_debug_instances[idx];
	    if (instance == NULL)
		continue;
	    SLIST_FOREACH(output, &instance->outputs, entries) {
		if (output->fd == ofd)
		    output->fd = nfd;
	    }
	}
    }
}

/*
 * Returns the highest debug output fd or -1 if no debug files open.
 * Fills in fds with the value of sudo_debug_fds.
 */
int
sudo_debug_get_fds_v1(unsigned char **fds)
{
    *fds = sudo_debug_fds;
    return sudo_debug_max_fd;
}
