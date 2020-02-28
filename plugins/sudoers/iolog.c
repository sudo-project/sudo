/*
 * SPDX-License-Identifier: ISC
 *
 * Copyright (c) 2009-2020 Todd C. Miller <Todd.Miller@sudo.ws>
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
#include <arpa/inet.h>
#include <netinet/in.h>

#include "sudoers.h"
#include "sudo_iolog.h"
#include "iolog_plugin.h"

static struct iolog_file iolog_files[] = {
    { false },	/* IOFD_STDIN */
    { false },	/* IOFD_STDOUT */
    { false },	/* IOFD_STDERR */
    { false },	/* IOFD_TTYIN  */
    { false },	/* IOFD_TTYOUT */
    { true, },	/* IOFD_TIMING */
};

static struct sudoers_io_operations {
    int (*open)(struct timespec *now);
    void (*close)(int exit_status, int error, const char **errstr);
    int (*log)(int event, const char *buf, unsigned int len,
	struct timespec *delay, const char **errstr);
    int (*change_winsize)(unsigned int lines, unsigned int cols,
	struct timespec *delay, const char **errstr);
    int (*suspend)(const char *signame, struct timespec *delay,
	const char **errstr);
} io_operations;

#ifdef SUDOERS_IOLOG_CLIENT
static struct client_closure client_closure = CLIENT_CLOSURE_INITIALIZER(client_closure);
#endif
static struct iolog_details iolog_details;
static bool warned = false;
static struct timespec last_time;
static void sudoers_io_setops(void);

/* sudoers_io is declared at the end of this file. */
extern __dso_public struct io_plugin sudoers_io;

/*
 * Sudoers callback for maxseq Defaults setting.
 */
bool
cb_maxseq(const union sudo_defs_val *sd_un)
{
    const char *errstr;
    unsigned int value;
    debug_decl(cb_maxseq, SUDOERS_DEBUG_UTIL);

    value = sudo_strtonum(sd_un->str, 0, SESSID_MAX, &errstr);
    if (errstr != NULL) {
        if (errno != ERANGE) {
            sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_LINENO,
                "bad maxseq: %s: %s", sd_un->str, errstr);
            debug_return_bool(false);
        }
        /* Out of range, clamp to SESSID_MAX as documented. */
        value = SESSID_MAX;
    }
    iolog_set_maxseq(value);
    debug_return_bool(true);
}

/*
 * Sudoers callback for iolog_user Defaults setting.
 */
bool
cb_iolog_user(const union sudo_defs_val *sd_un)
{
    const char *name = sd_un->str;
    struct passwd *pw;
    debug_decl(cb_iolog_user, SUDOERS_DEBUG_UTIL);

    /* NULL name means reset to default. */
    if (name == NULL) {
	iolog_set_owner(ROOT_UID, ROOT_GID);
    } else {
	if ((pw = sudo_getpwnam(name)) == NULL) {
	    log_warningx(SLOG_SEND_MAIL, N_("unknown user: %s"), name);
	    debug_return_bool(false);
	}
	iolog_set_owner(pw->pw_uid, pw->pw_gid);
	sudo_pw_delref(pw);
    }

    debug_return_bool(true);
}

/*
 * Look up I/O log group-ID from group name.
 */
bool
cb_iolog_group(const union sudo_defs_val *sd_un)
{
    const char *name = sd_un->str;
    struct group *gr;
    debug_decl(cb_iolog_group, SUDOERS_DEBUG_UTIL);

    /* NULL name means reset to default. */
    if (name == NULL) {
	iolog_set_gid(ROOT_GID);
    } else {
	if ((gr = sudo_getgrnam(name)) == NULL) {
	    log_warningx(SLOG_SEND_MAIL, N_("unknown group: %s"), name);
	    debug_return_bool(false);
	}
	iolog_set_gid(gr->gr_gid);
	sudo_gr_delref(gr);
    }

    debug_return_bool(true);
}

/*
 * Sudoers callback for iolog_mode Defaults setting.
 */
bool
cb_iolog_mode(const union sudo_defs_val *sd_un)
{
    iolog_set_mode(sd_un->mode);
    return true;
}

/*
 * Convert a comma-separated list to a string list.
 */
static struct sudoers_str_list *
deserialize_stringlist(const char *s)
{
    struct sudoers_str_list *strlist;
    struct sudoers_string *str;
    const char *s_end = s + strlen(s);
    const char *cp, *ep;
    debug_decl(deserialize_stringlist, SUDOERS_DEBUG_UTIL);

    if ((strlist = str_list_alloc()) == NULL)
	debug_return_ptr(NULL);

    for (cp = sudo_strsplit(s, s_end, ",", &ep); cp != NULL;
	    cp = sudo_strsplit(NULL, s_end, ",", &ep)) {
	if (cp == ep)
	    continue;
	if ((str = malloc(sizeof(*str))) == NULL)
	    goto bad;
	if ((str->str = strndup(cp, (ep - cp))) == NULL) {
	    free(str);
	    goto bad;
	}
	STAILQ_INSERT_TAIL(strlist, str, entries);
    }
    if (STAILQ_EMPTY(strlist))
	goto bad;

    debug_return_ptr(strlist);

bad:
    str_list_free(strlist);
    debug_return_ptr(NULL);
}

/*
 * Pull out I/O log related data from user_info and command_info arrays.
 * Returns true if I/O logging is enabled, false if not and -1 on error.
 */
static int
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
    debug_decl(iolog_deserialize_info, SUDOERS_DEBUG_UTIL);

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
	case 'h':
	    if (strncmp(*cur, "host=", sizeof("host=") - 1) == 0) {
		details->host = *cur + sizeof("host=") - 1;
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
		int val = sudo_strtobool(*cur + sizeof("iolog_compress=") - 1);
		if (val != -1) {
		    iolog_set_compress(val);
		} else {
		    sudo_debug_printf(SUDO_DEBUG_WARN,
			"%s: unable to parse %s", __func__, *cur);
		}
		continue;
	    }
	    if (strncmp(*cur, "iolog_flush=", sizeof("iolog_flush=") - 1) == 0) {
		int val = sudo_strtobool(*cur + sizeof("iolog_flush=") - 1);
		if (val != -1) {
		    iolog_set_flush(val);
		} else {
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
		    iolog_set_gid(gr->gr_gid);
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
		    iolog_set_owner(pw->pw_uid, pw->pw_gid);
		    sudo_pw_delref(pw);
		}
		continue;
	    }
	    break;
	case 'l':
	    if (strncmp(*cur, "log_servers=", sizeof("log_servers=") - 1) == 0) {
		details->log_servers =
		    deserialize_stringlist(*cur + sizeof("log_servers=") - 1);
		if (!details->log_servers)
		    goto oom;
		continue;
	    }
	    if (strncmp(*cur, "log_server_timeout=", sizeof("log_server_timeout=") - 1) == 0) {
		details->server_timeout.tv_sec =
		    sudo_strtonum(*cur + sizeof("log_server_timeout=") - 1, 1,
		    TIME_T_MAX, NULL);
		continue;
	    }
        if (strncmp(*cur, "log_server_keepalive=", sizeof("log_server_keepalive=") - 1) == 0) {
            int val = sudo_strtobool(*cur + sizeof("log_server_keepalive=") - 1);
            if (val != -1) {
                details->tcp_keepalive = val;
            } else {
                details->tcp_keepalive = true;
            }
            continue;
        }
#if defined(HAVE_OPENSSL)
	    if (strncmp(*cur, "log_server_cabundle=", sizeof("log_server_cabundle=") - 1) == 0) {
            details->ca_bundle = *cur + sizeof("log_server_cabundle=") - 1;
            continue;
        }
	    if (strncmp(*cur, "log_server_peer_cert=", sizeof("log_server_peer_cert=") - 1) == 0) {
            details->cert_file = *cur + sizeof("log_server_peer_cert=") - 1;
            continue;
        }
	    if (strncmp(*cur, "log_server_peer_key=", sizeof("log_server_peer_key=") - 1) == 0) {
            details->key_file = *cur + sizeof("log_server_peer_key=") - 1;
            continue;
        }
#endif /* HAVE_OPENSSL */
	    break;
	case 'm':
	    if (strncmp(*cur, "maxseq=", sizeof("maxseq=") - 1) == 0) {
		union sudo_defs_val sd_un;
		sd_un.str = *cur + sizeof("maxseq=") - 1;
		cb_maxseq(&sd_un);
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
    debug_return_int(
	iolog_files[IOFD_STDIN].enabled || iolog_files[IOFD_STDOUT].enabled ||
	iolog_files[IOFD_STDERR].enabled || iolog_files[IOFD_TTYIN].enabled ||
	iolog_files[IOFD_TTYOUT].enabled);
oom:
    sudo_warnx(U_("%s: %s"), __func__, U_("unable to allocate memory"));
    str_list_free(details->log_servers);
    debug_return_int(-1);
}

/*
 * Write the "log" file that contains the user and command info.
 * This file is not compressed.
 */
static bool
write_info_log(int dfd, char *iolog_dir, struct iolog_details *details)
{
    struct iolog_info iolog_info;
    debug_decl(write_info_log, SUDOERS_DEBUG_UTIL);

    /* XXX - just use iolog_info in the first place? */
    memset(&iolog_info, 0, sizeof(iolog_info));
    time(&iolog_info.tstamp);
    iolog_info.user = (char *)details->user;
    iolog_info.runas_user = details->runas_pw->pw_name;
    iolog_info.runas_group = details->runas_gr ? details->runas_gr->gr_name: NULL;
    iolog_info.tty = (char *)details->tty;
    iolog_info.cwd = (char *)details->cwd;
    iolog_info.cmd = (char *)details->command;
    iolog_info.lines = details->lines;
    iolog_info.cols = details->cols;

    if (!iolog_write_info_file(dfd, iolog_dir, &iolog_info, details->argv)) {
	log_warning(SLOG_SEND_MAIL,
	    N_("unable to write to I/O log file: %s"), strerror(errno));
	warned = true;
	debug_return_bool(false);
    }
    debug_return_bool(true);
}

/*
 * Make a shallow copy of a NULL-terminated argument or environment vector.
 * Only the outer array is allocated, the pointers inside are copied.
 * The caller is responsible for freeing the returned copy.
 */
static char **
copy_vector_shallow(char * const *vec)
{
    char **copy;
    size_t len;
    debug_decl(copy_vector, SUDOERS_DEBUG_UTIL);

    for (len = 0; vec[len] != NULL; len++)
	continue;

    if ((copy = reallocarray(NULL, len + 1, sizeof(char *))) != NULL) {
	for (len = 0; vec[len] != NULL; len++)
	    copy[len] = vec[len];
	copy[len] = NULL;
    }

    debug_return_ptr(copy);
}

static int
sudoers_io_open_local(struct timespec *now)
{
    char iolog_path[PATH_MAX], sessid[7];
    size_t len;
    int iolog_dir_fd = -1;
    int i, ret = -1;
    debug_decl(sudoers_io_open_local, SUDOERS_DEBUG_PLUGIN);

    /* If no I/O log path defined we need to figure it out ourselves. */
    if (iolog_details.iolog_path == NULL) {
	/* Get next session ID and convert it into a path. */
	len = strlcpy(iolog_path, _PATH_SUDO_IO_LOGDIR, sizeof(iolog_path));
	if (len + strlen("/00/00/00") >= sizeof(iolog_path)) {
	    sudo_warnx(U_("internal error, %s overflow"), __func__);
	    ret = false;
	    goto done;
	}
	if (!iolog_nextid(iolog_path, sessid)) {
	    log_warning(SLOG_SEND_MAIL, N_("unable to update sequence file"));
	    ret = false;
	    goto done;
	}
	(void)snprintf(iolog_path + sizeof(_PATH_SUDO_IO_LOGDIR),
	    sizeof(iolog_path) - sizeof(_PATH_SUDO_IO_LOGDIR),
	    "/%c%c/%c%c/%c%c", sessid[0], sessid[1], sessid[2],
	    sessid[3], sessid[4], sessid[5]);
    } else {
	len = strlcpy(iolog_path, iolog_details.iolog_path, sizeof(iolog_path));
	if (len >= sizeof(iolog_path)) {
	    sudo_warnx(U_("internal error, %s overflow"), __func__);
	    ret = false;
	    goto done;
	}
    }

    /*
     * Create I/O log path along with any * intermediate subdirs.
     * Calls mkdtemp() if iolog_path ends in XXXXXX.
     */
    if (!iolog_mkpath(iolog_path)) {
	log_warning(SLOG_SEND_MAIL, "%s", iolog_path);
	goto done;
    }

    iolog_dir_fd = iolog_openat(AT_FDCWD, iolog_path, O_RDONLY);
    if (iolog_dir_fd == -1) {
	log_warning(SLOG_SEND_MAIL, "%s", iolog_path);
	goto done;
    }

    /* Write log file with user and command details. */
    if (!write_info_log(iolog_dir_fd, iolog_path, &iolog_details))
	goto done;

    /* Create the timing and I/O log files. */
    for (i = 0; i < IOFD_MAX; i++) {
	if (!iolog_open(&iolog_files[i], iolog_dir_fd, i, "w")) {
	    log_warning(SLOG_SEND_MAIL, N_("unable to create %s/%s"),
		iolog_path, iolog_fd_to_name(i));
	    goto done;
	}
    }

    ret = true;

done:
    if (iolog_dir_fd != -1)
	close(iolog_dir_fd);

    debug_return_int(ret);
}

#ifdef SUDOERS_IOLOG_CLIENT
static int
sudoers_io_open_remote(struct timespec *now)
{
    int sock, ret = -1;
    struct sudoers_string *connected_server = NULL;
    debug_decl(sudoers_io_open_remote, SUDOERS_DEBUG_PLUGIN);

    /* Connect to log server. */
    sock = log_server_connect(iolog_details.log_servers, iolog_details.tcp_keepalive,
	&iolog_details.server_timeout, &connected_server);
    if (sock == -1) {
	/* TODO: support offline logs if server unreachable */
	sudo_warnx(U_("unable to connect to log server"));
	goto done;
    }

    if (!client_closure_fill(&client_closure, sock, connected_server, now,
	    &iolog_details, &sudoers_io)) {
	close(sock);
	goto done;
    }

    /* Read ServerHello and perform TLS handshake (optional). */
    if (read_server_hello(sock, &client_closure))
	ret = 1;

done:
    if (ret != 1)
	client_closure_free(&client_closure);
    debug_return_int(ret);
}
#endif /* SUDOERS_IOLOG_CLIENT */

static int
sudoers_io_open(unsigned int version, sudo_conv_t conversation,
    sudo_printf_t plugin_printf, char * const settings[],
    char * const user_info[], char * const command_info[],
    int argc, char * const argv[], char * const user_env[], char * const args[],
    const char **errstr)
{
    struct sudo_conf_debug_file_list debug_files = TAILQ_HEAD_INITIALIZER(debug_files);
    char * const *cur;
    const char *cp, *plugin_path = NULL;
    int ret = -1;
    debug_decl(sudoers_io_open, SUDOERS_DEBUG_PLUGIN);

    sudo_conv = conversation;
    sudo_printf = plugin_printf;

    /* Initialize io_operations. */
    sudoers_io_setops();

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
    ret = iolog_deserialize_info(&iolog_details, user_info, command_info);
    if (ret != true)
	goto done;
    iolog_details.argv = argv;
    iolog_details.argc = argc;

    /*
     * Copy user_env, it may be reallocated during policy session init.
     */
    if (user_env != NULL) {
	iolog_details.user_env = copy_vector_shallow(user_env);
	if (iolog_details.user_env ==  NULL) {
	    ret = -1;
	    goto done;
	}
    }

    if (sudo_gettime_awake(&last_time) == -1) {
	sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_ERRNO,
	    "%s: unable to get time of day", __func__);
	goto done;
    }

    /*
     * Create local I/O log file or connect to remote log server.
     */
    if ((ret = io_operations.open(&last_time)) != true)
	goto done;

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

done:
    if (ret != true) {
	sudo_freepwcache();
	sudo_freegrcache();
    }

    /* Ignore errors if they occur if the policy says so. */
    if (ret == -1 && iolog_details.ignore_iolog_errors)
	ret = 0;

    debug_return_int(ret);
}

static void
sudoers_io_close_local(int exit_status, int error, const char **errstr)
{
    int i;
    debug_decl(sudoers_io_close_local, SUDOERS_DEBUG_PLUGIN);

    for (i = 0; i < IOFD_MAX; i++) {
	if (iolog_files[i].fd.v == NULL)
	    continue;
	iolog_close(&iolog_files[i], errstr);
    }

    debug_return;
}

#ifdef SUDOERS_IOLOG_CLIENT
static void
sudoers_io_close_remote(int exit_status, int error, const char **errstr)
{
    debug_decl(sudoers_io_close_remote, SUDOERS_DEBUG_PLUGIN);

    client_close(&client_closure, exit_status, error);

    debug_return;
}
#endif

static void
sudoers_io_close(int exit_status, int error)
{
    const char *errstr = NULL;
    debug_decl(sudoers_io_close, SUDOERS_DEBUG_PLUGIN);

    io_operations.close(exit_status, error, &errstr);

    sudo_freepwcache();
    sudo_freegrcache();

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
    debug_decl(sudoers_io_version, SUDOERS_DEBUG_PLUGIN);

    sudo_printf(SUDO_CONV_INFO_MSG, "Sudoers I/O plugin version %s\n",
	PACKAGE_VERSION);

    debug_return_int(true);
}

/*
 * Write an I/O log entry to the local file system.
 * Returns 1 on success and -1 on error.
 * Fills in errstr on error.
 */
static int
sudoers_io_log_local(int event, const char *buf, unsigned int len,
    struct timespec *delay, const char **errstr)
{
    struct iolog_file *iol;
    char tbuf[1024];
    int ret = -1;
    debug_decl(sudoers_io_log_local, SUDOERS_DEBUG_PLUGIN);

    if (event < 0 || event >= IOFD_MAX) {
	*errstr = NULL;
	sudo_warnx(U_("unexpected I/O event %d"), event);
	debug_return_int(-1);
    }
    iol = &iolog_files[event];
    if (!iol->enabled) {
	*errstr = NULL;
	sudo_warnx(U_("%s: internal error, I/O log file for event %d not open"),
	    __func__, event);
	debug_return_int(-1);
    }

    /* Write I/O log file entry. */
    if (iolog_write(iol, buf, len, errstr) == -1)
	goto done;

    /* Write timing file entry. */
    len = (unsigned int)snprintf(tbuf, sizeof(tbuf), "%d %lld.%09ld %u\n",
	event, (long long)delay->tv_sec, delay->tv_nsec, len);
    if (len >= sizeof(tbuf)) {
	/* Not actually possible due to the size of tbuf[]. */
	*errstr = strerror(EOVERFLOW);
	goto done;
    }
    if (iolog_write(&iolog_files[IOFD_TIMING], tbuf, len, errstr) == -1)
	goto done;

    /* Success. */
    ret = 1;

done:
    debug_return_int(ret);
}

#ifdef SUDOERS_IOLOG_CLIENT
/*
 * Schedule an I/O log entry to be written to the log server.
 * Returns 1 on success and -1 on error.
 * Fills in errstr on error.
 */
static int
sudoers_io_log_remote(int event, const char *buf, unsigned int len,
    struct timespec *delay, const char **errstr)
{
    int type, ret = -1;
    debug_decl(sudoers_io_log_remote, SUDOERS_DEBUG_PLUGIN);

    if (client_closure.disabled)
	debug_return_int(1);

    /* Track elapsed time for comparison with commit points. */
    sudo_timespecadd(delay, &client_closure.elapsed, &client_closure.elapsed);

    switch (event) {
    case IO_EVENT_STDIN:
	type = CLIENT_MESSAGE__TYPE_STDIN_BUF;
	break;
    case IO_EVENT_STDOUT:
	type = CLIENT_MESSAGE__TYPE_STDOUT_BUF;
	break;
    case IO_EVENT_STDERR:
	type = CLIENT_MESSAGE__TYPE_STDERR_BUF;
	break;
    case IO_EVENT_TTYIN:
	type = CLIENT_MESSAGE__TYPE_TTYIN_BUF;
	break;
    case IO_EVENT_TTYOUT:
	type = CLIENT_MESSAGE__TYPE_TTYOUT_BUF;
	break;
    default:
	sudo_warnx(U_("unexpected I/O event %d"), event);
	goto done;
    }
    if (fmt_io_buf(&client_closure, type, buf, len, delay)) {
	ret = client_closure.write_ev->add(client_closure.write_ev,
	    &iolog_details.server_timeout);
	if (ret == -1)
	    sudo_warn(U_("unable to add event to queue"));
    }

done:
    debug_return_int(ret);
}
#endif /* SUDOERS_IOLOG_CLIENT */

/*
 * Generic I/O logging function.  Called by the I/O logging entry points.
 * Returns 1 on success and -1 on error.
 */
static int
sudoers_io_log(const char *buf, unsigned int len, int event, const char **errstr)
{
    struct timespec now, delay;
    const char *ioerror = NULL;
    int ret = -1;
    debug_decl(sudoers_io_log, SUDOERS_DEBUG_PLUGIN);

    if (sudo_gettime_awake(&now) == -1) {
	sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_ERRNO,
	    "%s: unable to get time of day", __func__);
	ioerror = N_("unable to read the clock");
	goto bad;
    }
    sudo_timespecsub(&now, &last_time, &delay);

    ret = io_operations.log(event, buf, len, &delay, &ioerror);

    last_time.tv_sec = now.tv_sec;
    last_time.tv_nsec = now.tv_nsec;

bad:
    if (ret == -1) {
	if (ioerror != NULL) {
	    char *cp;

	    if (asprintf(&cp, N_("unable to write to I/O log file: %s"),
		    ioerror) != -1) {
		*errstr = cp;
	    }
	    if (!warned) {
		/* Only warn about I/O log file errors once. */
		log_warning(SLOG_SEND_MAIL,
		    N_("unable to write to I/O log file: %s"), ioerror);
		warned = true;
	    }
	}

	/* Ignore errors if they occur if the policy says so. */
	if (iolog_details.ignore_iolog_errors)
	    ret = 1;
    }

    debug_return_int(ret);
}

static int
sudoers_io_log_stdin(const char *buf, unsigned int len, const char **errstr)
{
    return sudoers_io_log(buf, len, IO_EVENT_STDIN, errstr);
}

static int
sudoers_io_log_stdout(const char *buf, unsigned int len, const char **errstr)
{
    return sudoers_io_log(buf, len, IO_EVENT_STDOUT, errstr);
}

static int
sudoers_io_log_stderr(const char *buf, unsigned int len, const char **errstr)
{
    return sudoers_io_log(buf, len, IO_EVENT_STDERR, errstr);
}

static int
sudoers_io_log_ttyin(const char *buf, unsigned int len, const char **errstr)
{
    return sudoers_io_log(buf, len, IO_EVENT_TTYIN, errstr);
}

static int
sudoers_io_log_ttyout(const char *buf, unsigned int len, const char **errstr)
{
    return sudoers_io_log(buf, len, IO_EVENT_TTYOUT, errstr);
}

static int
sudoers_io_change_winsize_local(unsigned int lines, unsigned int cols,
    struct timespec *delay, const char **errstr)
{
    char tbuf[1024];
    int len, ret = -1;
    debug_decl(sudoers_io_change_winsize_local, SUDOERS_DEBUG_PLUGIN);

    /* Write window change event to the timing file. */
    len = snprintf(tbuf, sizeof(tbuf), "%d %lld.%09ld %u %u\n",
	IO_EVENT_WINSIZE, (long long)delay->tv_sec, delay->tv_nsec,
	lines, cols);
    if (len < 0 || len >= ssizeof(tbuf)) {
	/* Not actually possible due to the size of tbuf[]. */
	*errstr = strerror(EOVERFLOW);
	goto done;
    }
    if (iolog_write(&iolog_files[IOFD_TIMING], tbuf, len, errstr) == -1)
	goto done;

    /* Success. */
    ret = 1;

done:
    debug_return_int(ret);
}

#ifdef SUDOERS_IOLOG_CLIENT
static int
sudoers_io_change_winsize_remote(unsigned int lines, unsigned int cols,
    struct timespec *delay, const char **errstr)
{
    int ret = -1;
    debug_decl(sudoers_io_change_winsize_remote, SUDOERS_DEBUG_PLUGIN);

    if (client_closure.disabled)
	debug_return_int(1);

    /* Track elapsed time for comparison with commit points. */
    sudo_timespecadd(delay, &client_closure.elapsed, &client_closure.elapsed);

    if (fmt_winsize(&client_closure, lines, cols, delay)) {
	ret = client_closure.write_ev->add(client_closure.write_ev,
	    &iolog_details.server_timeout);
	if (ret == -1)
	    sudo_warn(U_("unable to add event to queue"));
    }

    debug_return_int(ret);
}
#endif /* SUDOERS_IOLOG_CLIENT */

static int
sudoers_io_change_winsize(unsigned int lines, unsigned int cols, const char **errstr)
{
    struct timespec now, delay;
    const char *ioerror = NULL;
    int ret = -1;
    debug_decl(sudoers_io_change_winsize, SUDOERS_DEBUG_PLUGIN);

    if (sudo_gettime_awake(&now) == -1) {
	sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_ERRNO,
	    "%s: unable to get time of day", __func__);
	ioerror = N_("unable to read the clock");
	goto bad;
    }
    sudo_timespecsub(&now, &last_time, &delay);

    ret = io_operations.change_winsize(lines, cols, &delay, &ioerror);

    last_time.tv_sec = now.tv_sec;
    last_time.tv_nsec = now.tv_nsec;

bad:
    if (ret == -1) {
	if (ioerror != NULL && !warned) {
	    char *cp;

	    if (asprintf(&cp, N_("unable to write to I/O log file: %s"),
		    ioerror) != -1) {
		*errstr = cp;
	    }
	    if (!warned) {
		/* Only warn about I/O log file errors once. */
		log_warning(SLOG_SEND_MAIL,
		    N_("unable to write to I/O log file: %s"), ioerror);
		warned = true;
	    }
	}

	/* Ignore errors if they occur if the policy says so. */
	if (iolog_details.ignore_iolog_errors)
	    ret = 1;
    }

    debug_return_int(ret);
}

static int
sudoers_io_suspend_local(const char *signame, struct timespec *delay,
    const char **errstr)
{
    unsigned int len;
    char tbuf[1024];
    int ret = -1;
    debug_decl(sudoers_io_suspend_local, SUDOERS_DEBUG_PLUGIN);

    /* Write suspend event to the timing file. */
    len = (unsigned int)snprintf(tbuf, sizeof(tbuf), "%d %lld.%09ld %s\n",
	IO_EVENT_SUSPEND, (long long)delay->tv_sec, delay->tv_nsec, signame);
    if (len >= sizeof(tbuf)) {
	/* Not actually possible due to the size of tbuf[]. */
	*errstr = strerror(EOVERFLOW);
	goto done;
    }
    if (iolog_write(&iolog_files[IOFD_TIMING], tbuf, len, errstr) == -1)
	goto done;

    /* Success. */
    ret = 1;

done:
    debug_return_int(ret);
}

#ifdef SUDOERS_IOLOG_CLIENT
static int
sudoers_io_suspend_remote(const char *signame, struct timespec *delay,
    const char **errstr)
{
    int ret = -1;
    debug_decl(sudoers_io_suspend_remote, SUDOERS_DEBUG_PLUGIN);

    if (client_closure.disabled)
	debug_return_int(1);

    /* Track elapsed time for comparison with commit points. */
    sudo_timespecadd(delay, &client_closure.elapsed, &client_closure.elapsed);

    if (fmt_suspend(&client_closure, signame, delay)) {
	ret = client_closure.write_ev->add(client_closure.write_ev,
	    &iolog_details.server_timeout);
	if (ret == -1)
	    sudo_warn(U_("unable to add event to queue"));
    }

    debug_return_int(ret);
}
#endif /* SUDOERS_IOLOG_CLIENT */

static int
sudoers_io_suspend(int signo, const char **errstr)
{
    struct timespec now, delay;
    char signame[SIG2STR_MAX];
    const char *ioerror = NULL;
    int ret = -1;
    debug_decl(sudoers_io_suspend, SUDOERS_DEBUG_PLUGIN);

    if (signo <= 0 || sig2str(signo, signame) == -1) {
	sudo_warnx(U_("%s: internal error, invalid signal %d"),
	    __func__, signo);
	debug_return_int(-1);
    }

    if (sudo_gettime_awake(&now) == -1) {
	sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_ERRNO,
	    "%s: unable to get time of day", __func__);
	ioerror = N_("unable to read the clock");
	goto bad;
    }
    sudo_timespecsub(&now, &last_time, &delay);

    /* Write suspend event to the timing file. */
    ret = io_operations.suspend(signame, &delay, &ioerror);

    last_time.tv_sec = now.tv_sec;
    last_time.tv_nsec = now.tv_nsec;

bad:
    if (ret == -1) {
	if (ioerror != NULL && !warned) {
	    char *cp;

	    if (asprintf(&cp, N_("unable to write to I/O log file: %s"),
		    ioerror) != -1) {
		*errstr = cp;
	    }
	    if (!warned) {
		/* Only warn about I/O log file errors once. */
		log_warning(SLOG_SEND_MAIL,
		    N_("unable to write to I/O log file: %s"), ioerror);
		warned = true;
	    }
	}

	/* Ignore errors if they occur if the policy says so. */
	if (iolog_details.ignore_iolog_errors)
	    ret = 1;
    }

    debug_return_int(ret);
}

/*
 * Fill in the contents of io_operations, either local or remote.
 */
static void
sudoers_io_setops(void)
{
    debug_decl(sudoers_io_setops, SUDOERS_DEBUG_PLUGIN);

#ifdef SUDOERS_IOLOG_CLIENT
    if (sudoers_io.event_alloc != NULL && iolog_details.log_servers != NULL) {
	io_operations.open = sudoers_io_open_remote;
	io_operations.close = sudoers_io_close_remote;
	io_operations.log = sudoers_io_log_remote;
	io_operations.change_winsize = sudoers_io_change_winsize_remote;
	io_operations.suspend = sudoers_io_suspend_remote;
    } else
#endif /* SUDOERS_IOLOG_CLIENT */
    {
	io_operations.open = sudoers_io_open_local;
	io_operations.close = sudoers_io_close_local;
	io_operations.log = sudoers_io_log_local;
	io_operations.change_winsize = sudoers_io_change_winsize_local;
	io_operations.suspend = sudoers_io_suspend_local;
    }

    debug_return;
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
    sudoers_io_suspend,
    NULL /* event_alloc() filled in by sudo */
};
