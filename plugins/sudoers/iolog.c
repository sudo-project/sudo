/*
 * SPDX-License-Identifier: ISC
 *
 * Copyright (c) 2009-2019 Todd C. Miller <Todd.Miller@sudo.ws>
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
#include <stdio.h>
#include <stdlib.h>
#ifdef HAVE_STRING_H
# include <string.h>
#endif /* HAVE_STRING_H */
#ifdef HAVE_STRINGS_H
# include <strings.h>
#endif /* HAVE_STRINGS_H */
#include <unistd.h>
#include <time.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <pwd.h>
#include <grp.h>

#include "sudoers.h"
#include "sudo_iolog.h"

/* XXX - separate sudoers.h and iolog.h? */
#undef runas_pw
#undef runas_gr

struct iolog_details {
    const char *cwd;
    const char *tty;
    const char *user;
    const char *command;
    const char *iolog_path;
    struct passwd *runas_pw;
    struct group *runas_gr;
    int lines;
    int cols;
    bool ignore_iolog_errors;
};

static struct iolog_file iolog_files[] = {
    { false },	/* IOFD_STDIN */
    { false },	/* IOFD_STDOUT */
    { false },	/* IOFD_STDERR */
    { false },	/* IOFD_TTYIN  */
    { false },	/* IOFD_TTYOUT */
    { true, },	/* IOFD_TIMING */
};

static struct iolog_details iolog_details;
static bool warned = false;
static struct timespec last_time;

/* sudoers_io is declared at the end of this file. */
extern __dso_public struct io_plugin sudoers_io;

/*
 * Sudoers callback for maxseq Defaults setting.
 */
bool
cb_maxseq(const union sudo_defs_val *sd_un)
{
    return iolog_set_maxseq(sd_un->str);
}

/*
 * Sudoers callback for iolog_user Defaults setting.
 */
bool
cb_iolog_user(const union sudo_defs_val *sd_un)
{
    const char *name = sd_un->str;
    struct passwd *pw = NULL;
    bool ret;
    debug_decl(cb_iolog_user, SUDOERS_DEBUG_UTIL)

    /* NULL name means reset to default. */
    if (name != NULL) {
	if ((pw = sudo_getpwnam(name)) == NULL) {
	    log_warningx(SLOG_SEND_MAIL, N_("unknown user: %s"), name);
	    debug_return_bool(false);
	}
    }
    ret = iolog_set_user(pw);
    if (pw != NULL)
	sudo_pw_delref(pw);

    debug_return_bool(ret);
}

/*
 * Look up I/O log group-ID from group name.
 */
bool
cb_iolog_group(const union sudo_defs_val *sd_un)
{
    const char *name = sd_un->str;
    struct group *gr = NULL;
    bool ret;
    debug_decl(cb_iolog_group, SUDOERS_DEBUG_UTIL)

    /* NULL name means reset to default. */
    if (name != NULL) {
	if ((gr = sudo_getgrnam(name)) == NULL) {
	    log_warningx(SLOG_SEND_MAIL, N_("unknown group: %s"), name);
	    debug_return_bool(false);
	}
    }
    ret = iolog_set_group(gr);
    if (gr != NULL)
	sudo_gr_delref(gr);

    debug_return_bool(ret);
}

/*
 * Sudoers callback for iolog_mode Defaults setting.
 */
bool
cb_iolog_mode(const union sudo_defs_val *sd_un)
{
    return iolog_set_mode(sd_un->mode);
}

/*
 * Pull out I/O log related data from user_info and command_info arrays.
 * Returns true if I/O logging is enabled, else false.
 */
static bool
iolog_deserialize_info(struct iolog_details *details, char * const user_info[],
    char * const command_info[])
{
    const char *runas_uid_str = "0", *runas_euid_str = NULL;
    const char *runas_gid_str = "0", *runas_egid_str = NULL;
    const char *errstr;
    char idbuf[MAX_UID_T_LEN + 2];
    char * const *cur;
    id_t id;
    uid_t runas_uid = 0;
    gid_t runas_gid = 0;
    debug_decl(iolog_deserialize_info, SUDOERS_DEBUG_UTIL)

    details->lines = 24;
    details->cols = 80;

    for (cur = user_info; *cur != NULL; cur++) {
	switch (**cur) {
	case 'c':
	    if (strncmp(*cur, "cols=", sizeof("cols=") - 1) == 0) {
		int n = sudo_strtonum(*cur + sizeof("cols=") - 1, 1, INT_MAX,
		    NULL);
		if (n > 0)
		    details->cols = n;
		continue;
	    }
	    if (strncmp(*cur, "cwd=", sizeof("cwd=") - 1) == 0) {
		details->cwd = *cur + sizeof("cwd=") - 1;
		continue;
	    }
	    break;
	case 'l':
	    if (strncmp(*cur, "lines=", sizeof("lines=") - 1) == 0) {
		int n = sudo_strtonum(*cur + sizeof("lines=") - 1, 1, INT_MAX,
		    NULL);
		if (n > 0)
		    details->lines = n;
		continue;
	    }
	    break;
	case 't':
	    if (strncmp(*cur, "tty=", sizeof("tty=") - 1) == 0) {
		details->tty = *cur + sizeof("tty=") - 1;
		continue;
	    }
	    break;
	case 'u':
	    if (strncmp(*cur, "user=", sizeof("user=") - 1) == 0) {
		details->user = *cur + sizeof("user=") - 1;
		continue;
	    }
	    break;
	}
    }

    for (cur = command_info; *cur != NULL; cur++) {
	switch (**cur) {
	case 'c':
	    if (strncmp(*cur, "command=", sizeof("command=") - 1) == 0) {
		details->command = *cur + sizeof("command=") - 1;
		continue;
	    }
	    break;
	case 'i':
	    if (strncmp(*cur, "ignore_iolog_errors=", sizeof("ignore_iolog_errors=") - 1) == 0) {
		if (sudo_strtobool(*cur + sizeof("ignore_iolog_errors=") - 1) == true)
		    details->ignore_iolog_errors = true;
		continue;
	    }
	    if (strncmp(*cur, "iolog_path=", sizeof("iolog_path=") - 1) == 0) {
		details->iolog_path = *cur + sizeof("iolog_path=") - 1;
		continue;
	    }
	    if (strncmp(*cur, "iolog_stdin=", sizeof("iolog_stdin=") - 1) == 0) {
		if (sudo_strtobool(*cur + sizeof("iolog_stdin=") - 1) == true)
		    iolog_files[IOFD_STDIN].enabled = true;
		continue;
	    }
	    if (strncmp(*cur, "iolog_stdout=", sizeof("iolog_stdout=") - 1) == 0) {
		if (sudo_strtobool(*cur + sizeof("iolog_stdout=") - 1) == true)
		    iolog_files[IOFD_STDOUT].enabled = true;
		continue;
	    }
	    if (strncmp(*cur, "iolog_stderr=", sizeof("iolog_stderr=") - 1) == 0) {
		if (sudo_strtobool(*cur + sizeof("iolog_stderr=") - 1) == true)
		    iolog_files[IOFD_STDERR].enabled = true;
		continue;
	    }
	    if (strncmp(*cur, "iolog_ttyin=", sizeof("iolog_ttyin=") - 1) == 0) {
		if (sudo_strtobool(*cur + sizeof("iolog_ttyin=") - 1) == true)
		    iolog_files[IOFD_TTYIN].enabled = true;
		continue;
	    }
	    if (strncmp(*cur, "iolog_ttyout=", sizeof("iolog_ttyout=") - 1) == 0) {
		if (sudo_strtobool(*cur + sizeof("iolog_ttyout=") - 1) == true)
		    iolog_files[IOFD_TTYOUT].enabled = true;
		continue;
	    }
	    if (strncmp(*cur, "iolog_compress=", sizeof("iolog_compress=") - 1) == 0) {
		if (!iolog_set_compress(*cur + sizeof("iolog_compress=") - 1)) {
		    sudo_debug_printf(SUDO_DEBUG_WARN,
			"%s: unable to parse %s", __func__, *cur);
		}
		continue;
	    }
	    if (strncmp(*cur, "iolog_flush=", sizeof("iolog_flush=") - 1) == 0) {
		if (!iolog_set_flush(*cur + sizeof("iolog_flush=") - 1)) {
		    sudo_debug_printf(SUDO_DEBUG_WARN,
			"%s: unable to parse %s", __func__, *cur);
		}
		continue;
	    }
	    if (strncmp(*cur, "iolog_mode=", sizeof("iolog_mode=") - 1) == 0) {
		mode_t mode = sudo_strtomode(*cur + sizeof("iolog_mode=") - 1, &errstr);
		if (errstr == NULL) {
		    iolog_set_mode(mode);
		} else {
		    sudo_debug_printf(SUDO_DEBUG_WARN,
			"%s: unable to parse %s", __func__, *cur);
		}
		continue;
	    }
	    if (strncmp(*cur, "iolog_group=", sizeof("iolog_group=") - 1) == 0) {
		struct group *gr =
		    sudo_getgrnam(*cur + sizeof("iolog_group=") - 1);
		if (gr == NULL) {
		    sudo_debug_printf(SUDO_DEBUG_WARN, "%s: unknown group %s",
			__func__, *cur + sizeof("iolog_group=") - 1);
		} else {
		    iolog_set_group(gr);
		    sudo_gr_delref(gr);
		}
		continue;
	    }
	    if (strncmp(*cur, "iolog_user=", sizeof("iolog_user=") - 1) == 0) {
		struct passwd *pw =
		    sudo_getpwnam(*cur + sizeof("iolog_user=") - 1);
		if (pw == NULL) {
		    sudo_debug_printf(SUDO_DEBUG_WARN, "%s: unknown user %s",
			__func__, *cur + sizeof("iolog_user=") - 1);
		} else {
		    iolog_set_user(pw);
		    sudo_pw_delref(pw);
		}
		continue;
	    }
	    break;
	case 'm':
	    if (strncmp(*cur, "maxseq=", sizeof("maxseq=") - 1) == 0) {
		iolog_set_maxseq(*cur + sizeof("maxseq=") - 1);
		continue;
	    }
	    break;
	case 'r':
	    if (strncmp(*cur, "runas_gid=", sizeof("runas_gid=") - 1) == 0) {
		runas_gid_str = *cur + sizeof("runas_gid=") - 1;
		continue;
	    }
	    if (strncmp(*cur, "runas_egid=", sizeof("runas_egid=") - 1) == 0) {
		runas_egid_str = *cur + sizeof("runas_egid=") - 1;
		continue;
	    }
	    if (strncmp(*cur, "runas_uid=", sizeof("runas_uid=") - 1) == 0) {
		runas_uid_str = *cur + sizeof("runas_uid=") - 1;
		continue;
	    }
	    if (strncmp(*cur, "runas_euid=", sizeof("runas_euid=") - 1) == 0) {
		runas_euid_str = *cur + sizeof("runas_euid=") - 1;
		continue;
	    }
	    break;
	}
    }

    /*
     * Lookup runas user and group, preferring effective over real uid/gid.
     */
    if (runas_euid_str != NULL)
	runas_uid_str = runas_euid_str;
    if (runas_uid_str != NULL) {
	id = sudo_strtoid(runas_uid_str, &errstr);
	if (errstr != NULL)
	    sudo_warnx("runas uid %s: %s", runas_uid_str, U_(errstr));
	else
	    runas_uid = (uid_t)id;
    }
    if (runas_egid_str != NULL)
	runas_gid_str = runas_egid_str;
    if (runas_gid_str != NULL) {
	id = sudo_strtoid(runas_gid_str, &errstr);
	if (errstr != NULL)
	    sudo_warnx("runas gid %s: %s", runas_gid_str, U_(errstr));
	else
	    runas_gid = (gid_t)id;
    }

    details->runas_pw = sudo_getpwuid(runas_uid);
    if (details->runas_pw == NULL) {
	idbuf[0] = '#';
	strlcpy(&idbuf[1], runas_uid_str, sizeof(idbuf) - 1);
	details->runas_pw = sudo_fakepwnam(idbuf, runas_gid);
    }

    if (runas_gid != details->runas_pw->pw_gid) {
	details->runas_gr = sudo_getgrgid(runas_gid);
	if (details->runas_gr == NULL) {
	    idbuf[0] = '#';
	    strlcpy(&idbuf[1], runas_gid_str, sizeof(idbuf) - 1);
	    details->runas_gr = sudo_fakegrnam(idbuf);
	}
    }
    debug_return_bool(
	iolog_files[IOFD_STDIN].enabled || iolog_files[IOFD_STDOUT].enabled ||
	iolog_files[IOFD_STDERR].enabled || iolog_files[IOFD_TTYIN].enabled ||
	iolog_files[IOFD_TTYOUT].enabled);
}

/*
 * Write the "/log" file that contains the user and command info.
 * This file is not compressed.
 */
static bool
write_info_log(char *pathbuf, size_t len, struct iolog_details *details,
    char * const argv[])
{
    struct iolog_info iolog_info;
    debug_decl(write_info_log, SUDOERS_DEBUG_UTIL)

    /* XXX - just use iolog_info in the first place? */
    time(&iolog_info.tstamp);
    iolog_info.user = (char *)details->user;
    iolog_info.runas_user = details->runas_pw->pw_name;
    iolog_info.runas_group = details->runas_gr ? details->runas_gr->gr_name: NULL;
    iolog_info.tty = (char *)details->tty;
    iolog_info.cwd = (char *)details->cwd;
    iolog_info.cmd = (char *)details->command;
    iolog_info.lines = details->lines;
    iolog_info.cols = details->cols;
    pathbuf[len] = '\0';

    if (!iolog_write_info_file(pathbuf, &iolog_info, argv)) {
	log_warning(SLOG_SEND_MAIL,
	    N_("unable to write to I/O log file: %s"), strerror(errno));
	warned = true;
	debug_return_bool(false);
    }
    debug_return_bool(true);
}

static int
sudoers_io_open(unsigned int version, sudo_conv_t conversation,
    sudo_printf_t plugin_printf, char * const settings[],
    char * const user_info[], char * const command_info[],
    int argc, char * const argv[], char * const user_env[], char * const args[])
{
    struct sudo_conf_debug_file_list debug_files = TAILQ_HEAD_INITIALIZER(debug_files);
    char pathbuf[PATH_MAX], sessid[7];
    char *tofree = NULL;
    char * const *cur;
    const char *cp, *plugin_path = NULL;
    size_t len;
    int i, ret = -1;
    debug_decl(sudoers_io_open, SUDOERS_DEBUG_PLUGIN)

    sudo_conv = conversation;
    sudo_printf = plugin_printf;

    /* If we have no command (because -V was specified) just return. */
    if (argc == 0)
	debug_return_int(true);

    bindtextdomain("sudoers", LOCALEDIR);

    /* Initialize the debug subsystem.  */
    for (cur = settings; (cp = *cur) != NULL; cur++) {
	if (strncmp(cp, "debug_flags=", sizeof("debug_flags=") - 1) == 0) {
	    cp += sizeof("debug_flags=") - 1;
	    if (!sudoers_debug_parse_flags(&debug_files, cp))
		debug_return_int(-1);
	    continue;
	}
	if (strncmp(cp, "plugin_path=", sizeof("plugin_path=") - 1) == 0) {
	    plugin_path = cp + sizeof("plugin_path=") - 1;
	    continue;
	}
    }

    if (!sudoers_debug_register(plugin_path, &debug_files)) {
	ret = -1;
	goto done;
    }

    /*
     * Pull iolog settings out of command_info.
     */
    if (!iolog_deserialize_info(&iolog_details, user_info, command_info)) {
	ret = false;
	goto done;
    }

    /* If no I/O log path defined we need to figure it out ourselves. */
    if (iolog_details.iolog_path == NULL) {
	/* Get next session ID and convert it into a path. */
	tofree = malloc(sizeof(_PATH_SUDO_IO_LOGDIR) + sizeof(sessid) + 2);
	if (tofree == NULL) {
	    sudo_warnx(U_("%s: %s"), __func__, U_("unable to allocate memory"));
	    goto done;
	}
	memcpy(tofree, _PATH_SUDO_IO_LOGDIR, sizeof(_PATH_SUDO_IO_LOGDIR));
	if (!iolog_nextid(tofree, sessid)) {
	    log_warning(SLOG_SEND_MAIL, N_("unable to update sequence file"));
	    ret = false;
	    goto done;
	}
	(void)snprintf(tofree + sizeof(_PATH_SUDO_IO_LOGDIR),
	    sizeof(sessid) + 2, "%c%c/%c%c/%c%c", sessid[0], sessid[1],
	    sessid[2], sessid[3], sessid[4], sessid[5]);
	iolog_details.iolog_path = tofree;
    }

    /*
     * Make local copy of I/O log path and create it, along with any
     * intermediate subdirs.  Calls mkdtemp() if iolog_path ends in XXXXXX.
     */
    len = mkdir_iopath(iolog_details.iolog_path, pathbuf, sizeof(pathbuf));
    if (len >= sizeof(pathbuf)) {
	log_warning(SLOG_SEND_MAIL, "%s", iolog_details.iolog_path);
	goto done;
    }

    /* Write log file with user and command details. */
    if (!write_info_log(pathbuf, len, &iolog_details, argv))
	goto done;

    /* Create the timing and I/O log files. */
    for (i = 0; i < IOFD_MAX; i++) {
	pathbuf[len] = '/';
	pathbuf[len + 1] = '\0';
	if (strlcat(pathbuf, iolog_fd_to_name(i), sizeof(pathbuf)) >= sizeof(pathbuf)) {
	    errno = ENAMETOOLONG;
	    log_warning(SLOG_SEND_MAIL, N_("unable to create %s"), pathbuf);
	    goto done;
	}
	if (!iolog_open(&iolog_files[i], pathbuf, "w")) {
	    log_warning(SLOG_SEND_MAIL, N_("unable to create %s"), pathbuf);
	    goto done;
	}
    }

    /*
     * Clear I/O log function pointers for disabled log functions.
     */
    if (!iolog_files[IOFD_STDIN].enabled)
	sudoers_io.log_stdin = NULL;
    if (!iolog_files[IOFD_STDOUT].enabled)
	sudoers_io.log_stdout = NULL;
    if (!iolog_files[IOFD_STDERR].enabled)
	sudoers_io.log_stderr = NULL;
    if (!iolog_files[IOFD_TTYIN].enabled)
	sudoers_io.log_ttyin = NULL;
    if (!iolog_files[IOFD_TTYOUT].enabled)
	sudoers_io.log_ttyout = NULL;

    if (sudo_gettime_awake(&last_time) == -1) {
	sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_ERRNO,
	    "%s: unable to get time of day", __func__);
	goto done;
    }

    ret = true;

done:
    free(tofree);
    if (iolog_details.runas_pw)
	sudo_pw_delref(iolog_details.runas_pw);
    if (iolog_details.runas_gr)
	sudo_gr_delref(iolog_details.runas_gr);
    sudo_freepwcache();
    sudo_freegrcache();

    /* Ignore errors if they occur if the policy says so. */
    if (ret == -1 && iolog_details.ignore_iolog_errors)
	ret = 0;

    debug_return_int(ret);
}

static void
sudoers_io_close(int exit_status, int error)
{
    const char *errstr = NULL;
    int i;
    debug_decl(sudoers_io_close, SUDOERS_DEBUG_PLUGIN)

    for (i = 0; i < IOFD_MAX; i++) {
	if (iolog_files[i].fd.v == NULL)
	    continue;
	iolog_close(&iolog_files[i], &errstr);
    }

    if (errstr != NULL && !warned) {
	/* Only warn about I/O log file errors once. */
	log_warning(SLOG_SEND_MAIL,
	    N_("unable to write to I/O log file: %s"), errstr);
	warned = true;
    }

    sudoers_debug_deregister();

    return;
}

static int
sudoers_io_version(int verbose)
{
    debug_decl(sudoers_io_version, SUDOERS_DEBUG_PLUGIN)

    sudo_printf(SUDO_CONV_INFO_MSG, "Sudoers I/O plugin version %s\n",
	PACKAGE_VERSION);

    debug_return_int(true);
}

/*
 * Generic I/O logging function.  Called by the I/O logging entry points.
 * Returns 1 on success and -1 on error.
 */
static int
sudoers_io_log(struct iolog_file *iol, const char *buf, unsigned int len,
    int event)
{
    struct timespec now, delay;
    char tbuf[1024];
    const char *errstr = NULL;
    int ret = -1;
    debug_decl(sudoers_io_log, SUDOERS_DEBUG_PLUGIN)

    if (!iol->enabled) {
	sudo_warnx(U_("%s: internal error, I/O log file for event %d not open"),
	    __func__, event);
	debug_return_int(-1);
    }

    if (sudo_gettime_awake(&now) == -1) {
	sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_ERRNO,
	    "%s: unable to get time of day", __func__);
	errstr = strerror(errno);
	goto bad;
    }

    /* Write I/O log file entry. */
    if (iolog_write(iol, buf, len, &errstr) == -1)
	goto done;

    /* Write timing file entry. */
    sudo_timespecsub(&now, &last_time, &delay);
    len = (unsigned int)snprintf(tbuf, sizeof(tbuf), "%d %lld.%09ld %u\n",
	event, (long long)delay.tv_sec, delay.tv_nsec, len);
    if (len >= sizeof(tbuf)) {
	/* Not actually possible due to the size of tbuf[]. */
	errstr = strerror(EOVERFLOW);
	goto done;
    }
    if (iolog_write(&iolog_files[IOFD_TIMING], tbuf, len, &errstr) == -1)
	goto done;

    /* Success. */
    ret = 1;

done:
    last_time.tv_sec = now.tv_sec;
    last_time.tv_nsec = now.tv_nsec;

bad:
    if (ret == -1) {
	if (errstr != NULL && !warned) {
	    /* Only warn about I/O log file errors once. */
	    log_warning(SLOG_SEND_MAIL,
		N_("unable to write to I/O log file: %s"), errstr);
	    warned = true;
	}

	/* Ignore errors if they occur if the policy says so. */
	if (iolog_details.ignore_iolog_errors)
	    ret = 1;
    }

    debug_return_int(ret);
}

static int
sudoers_io_log_stdin(const char *buf, unsigned int len)
{
    return sudoers_io_log(&iolog_files[IOFD_STDIN], buf, len, IO_EVENT_STDIN);
}

static int
sudoers_io_log_stdout(const char *buf, unsigned int len)
{
    return sudoers_io_log(&iolog_files[IOFD_STDOUT], buf, len, IO_EVENT_STDOUT);
}

static int
sudoers_io_log_stderr(const char *buf, unsigned int len)
{
    return sudoers_io_log(&iolog_files[IOFD_STDERR], buf, len, IO_EVENT_STDERR);
}

static int
sudoers_io_log_ttyin(const char *buf, unsigned int len)
{
    return sudoers_io_log(&iolog_files[IOFD_TTYIN], buf, len, IO_EVENT_TTYIN);
}

static int
sudoers_io_log_ttyout(const char *buf, unsigned int len)
{
    return sudoers_io_log(&iolog_files[IOFD_TTYOUT], buf, len, IO_EVENT_TTYOUT);
}

static int
sudoers_io_change_winsize(unsigned int lines, unsigned int cols)
{
    struct timespec now, delay;
    unsigned int len;
    char tbuf[1024];
    const char *errstr = NULL;
    int ret = -1;
    debug_decl(sudoers_io_change_winsize, SUDOERS_DEBUG_PLUGIN)

    if (sudo_gettime_awake(&now) == -1) {
	sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_ERRNO,
	    "%s: unable to get time of day", __func__);
	errstr = strerror(errno);
	goto bad;
    }

    /* Write window change event to the timing file. */
    sudo_timespecsub(&now, &last_time, &delay);
    len = (unsigned int)snprintf(tbuf, sizeof(tbuf), "%d %lld.%09ld %u %u\n",
	IO_EVENT_WINSIZE, (long long)delay.tv_sec, delay.tv_nsec, lines, cols);
    if (len >= sizeof(tbuf)) {
	/* Not actually possible due to the size of tbuf[]. */
	errstr = strerror(EOVERFLOW);
	goto done;
    }
    if (iolog_write(&iolog_files[IOFD_TIMING], tbuf, len, &errstr) == -1)
	goto done;

    /* Success. */
    ret = 1;

done:
    last_time.tv_sec = now.tv_sec;
    last_time.tv_nsec = now.tv_nsec;

bad:
    if (ret == -1) {
	if (errstr != NULL && !warned) {
	    /* Only warn about I/O log file errors once. */
	    log_warning(SLOG_SEND_MAIL,
		N_("unable to write to I/O log file: %s"), errstr);
	    warned = true;
	}

	/* Ignore errors if they occur if the policy says so. */
	if (iolog_details.ignore_iolog_errors)
	    ret = 1;
    }

    debug_return_int(ret);
}

static int
sudoers_io_suspend(int signo)
{
    struct timespec now, delay;
    unsigned int len;
    char signame[SIG2STR_MAX];
    char tbuf[1024];
    const char *errstr = NULL;
    int ret = -1;
    debug_decl(sudoers_io_suspend, SUDOERS_DEBUG_PLUGIN)

    if (signo <= 0 || sig2str(signo, signame) == -1) {
	sudo_warnx(U_("%s: internal error, invalid signal %d"),
	    __func__, signo);
	debug_return_int(-1);
    }

    if (sudo_gettime_awake(&now) == -1) {
	sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_ERRNO,
	    "%s: unable to get time of day", __func__);
	errstr = strerror(errno);
	goto bad;
    }

    /* Write suspend event to the timing file. */
    sudo_timespecsub(&now, &last_time, &delay);
    len = (unsigned int)snprintf(tbuf, sizeof(tbuf), "%d %lld.%09ld %s\n",
	IO_EVENT_SUSPEND, (long long)delay.tv_sec, delay.tv_nsec, signame);
    if (len >= sizeof(tbuf)) {
	/* Not actually possible due to the size of tbuf[]. */
	errstr = strerror(EOVERFLOW);
	goto done;
    }
    if (iolog_write(&iolog_files[IOFD_TIMING], tbuf, len, &errstr) == -1)
	goto done;

    /* Success. */
    ret = 1;

done:
    last_time.tv_sec = now.tv_sec;
    last_time.tv_nsec = now.tv_nsec;

bad:
    if (ret == -1) {
	if (errstr != NULL && !warned) {
	    /* Only warn about I/O log file errors once. */
	    log_warning(SLOG_SEND_MAIL,
		N_("unable to write to I/O log file: %s"), errstr);
	    warned = true;
	}

	/* Ignore errors if they occur if the policy says so. */
	if (iolog_details.ignore_iolog_errors)
	    ret = 1;
    }

    debug_return_int(ret);
}

__dso_public struct io_plugin sudoers_io = {
    SUDO_IO_PLUGIN,
    SUDO_API_VERSION,
    sudoers_io_open,
    sudoers_io_close,
    sudoers_io_version,
    sudoers_io_log_ttyin,
    sudoers_io_log_ttyout,
    sudoers_io_log_stdin,
    sudoers_io_log_stdout,
    sudoers_io_log_stderr,
    NULL, /* register_hooks */
    NULL, /* deregister_hooks */
    sudoers_io_change_winsize,
    sudoers_io_suspend
};
