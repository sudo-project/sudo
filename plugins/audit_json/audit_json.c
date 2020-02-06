/*
 * SPDX-License-Identifier: ISC
 *
 * Copyright (c) 2020 Todd C. Miller <Todd.Miller@sudo.ws>
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
#include <sys/wait.h>

#include <stdio.h>
#include <stdlib.h>
#ifdef HAVE_STDBOOL_H
# include <stdbool.h>
#else
# include "compat/stdbool.h"
#endif /* HAVE_STDBOOL_H */
#ifdef HAVE_STRING_H
# include <string.h>
#endif /* HAVE_STRING_H */
#ifdef HAVE_STRINGS_H
# include <strings.h>
#endif /* HAVE_STRINGS_H */
#include <signal.h>
#include <unistd.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <time.h>

#include "sudo_gettext.h"	/* must be included before sudo_compat.h */

#include "sudo_compat.h"
#include "sudo_conf.h"
#include "sudo_debug.h"
#include "sudo_dso.h"
#include "sudo_fatal.h"
#include "sudo_json.h"
#include "sudo_plugin.h"
#include "sudo_util.h"
#include "pathnames.h"

#ifndef HAVE_FSEEKO
# define fseeko(f, o, w)	fseek((f), (o), (w))
# define ftello(f)		ftell(f)
#endif

static int audit_debug_instance = SUDO_DEBUG_INSTANCE_INITIALIZER;
static sudo_conv_t audit_conv;
static sudo_printf_t audit_printf;

static struct audit_state {
    int submit_optind;
    char uuid_str[37];
    bool accepted;
    FILE *log_fp;
    char *logfile;
    char * const * settings;
    char * const * user_info;
    char * const * submit_argv;
    char * const * submit_envp;
} state = { -1 };

/* Filter out entries in settings[] that are not really options. */
char * const settings_filter[] = {
    "debug_flags",
    "max_groups",
    "network_addrs",
    "plugin_dir",
    "plugin_path",
    "progname",
    NULL
};

/*
 * Parse the "filename flags,..." debug_flags entry and insert a new
 * sudo_debug_file struct into debug_files.
 * XXX - move to libsudoutil
 */
static bool
sudo_debug_parse_flags(struct sudo_conf_debug_file_list *debug_files,
    const char *entry)
{
    struct sudo_debug_file *debug_file;
    const char *filename, *flags;
    size_t namelen;

    /* Only process new-style debug flags: filename flags,... */
    filename = entry;
    if (*filename != '/' || (flags = strpbrk(filename, " \t")) == NULL)
	return true;
    namelen = (size_t)(flags - filename);
    while (isblank((unsigned char)*flags))
	flags++;
    if (*flags != '\0') {
	if ((debug_file = calloc(1, sizeof(*debug_file))) == NULL)
	    goto oom;
	if ((debug_file->debug_file = strndup(filename, namelen)) == NULL)
	    goto oom;
	if ((debug_file->debug_flags = strdup(flags)) == NULL)
	    goto oom;
	TAILQ_INSERT_TAIL(debug_files, debug_file, entries);
    }
    return true;
oom:
    if (debug_file != NULL) {
	free(debug_file->debug_file);
	free(debug_file->debug_flags);
	free(debug_file);
    }
    return false;
}

static int
audit_open(unsigned int version, sudo_conv_t conversation,
    sudo_printf_t plugin_printf, char * const settings[],
    char * const user_info[], int submit_optind, char * const submit_argv[],
    char * const submit_envp[], char * const plugin_options[],
    const char **errstr)
{
    struct sudo_conf_debug_file_list debug_files =
	TAILQ_HEAD_INITIALIZER(debug_files);
    struct sudo_debug_file *debug_file;
    const char *cp, *plugin_path = NULL;
    unsigned char uuid[16];
    char * const *cur;
    mode_t oldmask;
    int fd, ret = -1;
    debug_decl(audit_open, SUDO_DEBUG_PLUGIN);

    audit_conv = conversation;
    audit_printf = plugin_printf;

    /*
     * Stash initial values.
     */
    state.submit_optind = submit_optind;
    state.settings = settings;
    state.user_info = user_info;
    state.submit_argv = submit_argv;
    state.submit_envp = submit_envp;

    /* Initialize the debug subsystem.  */
    for (cur = settings; (cp = *cur) != NULL; cur++) {
        if (strncmp(cp, "debug_flags=", sizeof("debug_flags=") - 1) == 0) {
            cp += sizeof("debug_flags=") - 1;
            if (!sudo_debug_parse_flags(&debug_files, cp)) {
                goto oom;
	    }
            continue;
        }
        if (strncmp(cp, "plugin_path=", sizeof("plugin_path=") - 1) == 0) {
            plugin_path = cp + sizeof("plugin_path=") - 1;
            continue;
        }
    }
    if (plugin_path != NULL && !TAILQ_EMPTY(&debug_files)) {
	audit_debug_instance =
	    sudo_debug_register(plugin_path, NULL, NULL, &debug_files);
	if (audit_debug_instance == SUDO_DEBUG_INSTANCE_ERROR) {
	    *errstr = U_("unable to initialize debugging");
	    goto bad;
	}
    }

    /* Create a UUID for this command for use with audit records. */
    sudo_uuid_create(uuid);
    if (sudo_uuid_to_string(uuid, state.uuid_str, sizeof(state.uuid_str)) == NULL) {
	*errstr = U_("unable to generate UUID");
	goto bad;
    }

    /* Parse plugin_options to check for logfile option. */
    if (plugin_options != NULL) {
	for (cur = plugin_options; (cp = *cur) != NULL; cur++) {
	    if (strncmp(cp, "logfile=", sizeof("logfile=") - 1) == 0) {
		state.logfile = strdup(cp + sizeof("logfile=") - 1);
		if (state.logfile == NULL)
		    goto oom;
	    }
	}
    }
    if (state.logfile == NULL) {
	if (asprintf(&state.logfile, "%s/sudo_audit.json", _PATH_SUDO_LOGDIR) == -1)
	    goto oom;
    }

    /* open log file */
    /* TODO: suport pipe */
    oldmask = umask(S_IRWXG|S_IRWXO);
    fd = open(state.logfile, O_RDWR|O_CREAT, S_IRUSR|S_IWUSR);
    (void)umask(oldmask);
    if (fd == -1 || (state.log_fp = fdopen(fd, "w")) == NULL) {
	*errstr = U_("unable to open audit system");
	if (fd != -1)
	    close(fd);
	goto bad;
    }

    ret = 1;
    goto done;

oom:
    sudo_warnx(U_("%s: %s"), __func__, U_("unable to allocate memory"));
    *errstr = U_("unable to allocate memory");

bad:
    if (state.log_fp != NULL) {
	fclose(state.log_fp);
	state.log_fp = NULL;
    }

done:
    while ((debug_file = TAILQ_FIRST(&debug_files))) {
	TAILQ_REMOVE(&debug_files, debug_file, entries);
	free(debug_file->debug_file);
	free(debug_file->debug_flags);
	free(debug_file);
    }

    debug_return_int(ret);
}

static bool
print_key_value(struct json_container *json, const char *str)
{
    struct json_value json_value;
    const char *cp, *errstr;
    char name[256];
    size_t len;
    debug_decl(print_key_value, SUDO_DEBUG_PLUGIN);

    if ((cp = strchr(str, '=')) == NULL) {
	sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_LINENO,
	    "ignoring bad command info string \"%s\"", str);
	debug_return_bool(false);
    }
    len = (size_t)(cp - str);
    cp++;

    /* Variable name currently limited to 256 chars */
    if (len >= sizeof(name)) {
	sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_LINENO,
	    "ignoring long command info name \"%.*s\"", (int)len, str);
	debug_return_bool(false);
    }
    memcpy(name, str, len);
    name[len] = '\0';

    /* Check for bool or number. */
    json_value.type = JSON_NULL;
    switch (*cp) {
    case '+': case '-': case '0': case '1': case '2': case '3':
    case '4': case '5': case '6': case '7': case '8': case '9':
	json_value.u.number = sudo_strtonum(cp, INT_MIN, INT_MAX, &errstr);
	if (errstr == NULL)
	    json_value.type = JSON_NUMBER;
	break;
    case 't':
	if (strcmp(cp, "true") == 0) {
	    json_value.type = JSON_BOOL;
	    json_value.u.boolean = true;
	}
	break;
    case 'f':
	if (strcmp(cp, "false") == 0) {
	    json_value.type = JSON_BOOL;
	    json_value.u.boolean = false;
	}
	break;
    }

    /* Default to string type. */
    if (json_value.type == JSON_NULL) {
	json_value.type = JSON_STRING;
	json_value.u.string = cp;
    }

    sudo_json_add_value(json, name, &json_value);

    debug_return_bool(true);
}

static void
print_array(struct json_container *json, const char *name, char * const * array)
{
    struct json_value json_value;
    debug_decl(print_array, SUDO_DEBUG_PLUGIN);

    json_value.type = JSON_ARRAY;
    json_value.u.array = array;
    sudo_json_add_value(json, name, &json_value);

    debug_return;
}

static bool
filter_key_value(const char *kv, char * const * filter)
{
    char * const *cur;
    const char *cp;
    size_t namelen;

    if (filter != NULL) {
	namelen = strcspn(kv, "=");
	for (cur = filter; (cp = *cur) != NULL; cur++) {
	    if (strncmp(kv, cp, namelen) == 0 && cp[namelen] == '\0')
		return true;
	}
    }
    return false;
}

static void
print_key_value_object(struct json_container *json, const char *name,
	char * const * array, char * const * filter)
{
    char * const *cur;
    const char *cp;
    bool empty = false;
    debug_decl(print_key_value_object, SUDO_DEBUG_PLUGIN);

    if (filter != NULL) {
	/* Avoid printing an empty object if everything is filtered. */
	empty = true;
	for (cur = array; (cp = *cur) != NULL; cur++) {
	    if (!filter_key_value(cp, filter)) {
		empty = false;
		break;
	    }
	}
    }
    if (!empty) {
	sudo_json_open_object(json, name);
	for (cur = array; (cp = *cur) != NULL; cur++) {
	    if (filter_key_value(cp, filter))
		continue;
	    print_key_value(json, cp);
	}
	sudo_json_close_object(json);
    }

    debug_return;
}

static bool
print_timestamp(struct json_container *json, struct timespec *ts)
{
    struct json_value json_value;
    time_t secs = ts->tv_sec;
    char timebuf[1024];
    struct tm *tm;
    debug_decl(print_timestamp, SUDO_DEBUG_PLUGIN);

    if ((tm = gmtime(&secs)) == NULL)
	debug_return_bool(false);

    sudo_json_open_object(json, "timestamp");

    json_value.type = JSON_NUMBER;
    json_value.u.number = ts->tv_sec;
    sudo_json_add_value(json, "seconds", &json_value);

    json_value.type = JSON_NUMBER;
    json_value.u.number = ts->tv_nsec;
    sudo_json_add_value(json, "nanoseconds", &json_value);

    strftime(timebuf, sizeof(timebuf), "%Y%m%d%H%M%SZ", tm);
    json_value.type = JSON_STRING;
    json_value.u.string = timebuf;
    sudo_json_add_value(json, "iso8601", &json_value);

    strftime(timebuf, sizeof(timebuf), "%a %b %e %H:%M:%S %Z %Y", tm);
    json_value.type = JSON_STRING;
    json_value.u.string = timebuf;
    sudo_json_add_value(json, "localtime", &json_value);

    sudo_json_close_object(json);

    debug_return_bool(true);
}

static int
audit_write_exit_record(int exit_status, int error)
{
    struct timespec now;
    struct json_container json;
    struct json_value json_value;
    int ret = -1;
    debug_decl(audit_write_exit_record, SUDO_DEBUG_PLUGIN);

    if (sudo_gettime_real(&now) == -1) {
	sudo_warn(U_("unable to read the clock"));
	goto done;
    }

    if (!sudo_lock_file(fileno(state.log_fp), SUDO_LOCK)) {
	sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_LINENO,
	    "unable to lock %s", state.logfile);
	goto done;
    }

    /* Note: assumes file ends in "\n}\n" */
    fseeko(state.log_fp, 0, SEEK_END);
    if (ftello(state.log_fp) == 0) {
	/* New file */
	putc('{', state.log_fp);
    } else {
	/* Continue file, overwrite the final "\n}\n" */
	fseeko(state.log_fp, -3, SEEK_END);
	putc(',', state.log_fp);
    }

    sudo_json_init(&json, state.log_fp, 4);
    sudo_json_open_object(&json, "exit");

    /* Write UUID */
    json_value.type = JSON_STRING;
    json_value.u.string = state.uuid_str;
    sudo_json_add_value(&json, "uuid", &json_value);

    /* Write time stamp */
    if (!print_timestamp(&json, &now))
	sudo_warnx(U_("unable to format timestamp"));

    if (error != 0) {
	/* Error executing command */
	json_value.type = JSON_STRING;
	json_value.u.string = strerror(error);
	sudo_json_add_value(&json, "error", &json_value);
    } else {
        if (WIFEXITED(exit_status)) {
	    /* Command exited normally. */
	    json_value.type = JSON_NUMBER;
	    json_value.u.number = WEXITSTATUS(exit_status);
	    sudo_json_add_value(&json, "exit_value", &json_value);
        } else if (WIFSIGNALED(exit_status)) {
	    /* Command killed by signal. */
	    char signame[SIG2STR_MAX];
            int signo = WTERMSIG(exit_status);
            if (signo <= 0 || sig2str(signo, signame) == -1) {
		json_value.type = JSON_NUMBER;
		json_value.u.number = signo;
		sudo_json_add_value(&json, "signal", &json_value);
            } else {
		json_value.type = JSON_STRING;
		json_value.u.string = signame;
		sudo_json_add_value(&json, "signal", &json_value);
	    }
	    /* Core dump? */
	    json_value.type = JSON_BOOL;
	    json_value.u.boolean = WCOREDUMP(exit_status);
	    sudo_json_add_value(&json, "dumped_core", &json_value);
	    /* Exit value */
	    json_value.type = JSON_NUMBER;
	    json_value.u.number = WTERMSIG(exit_status) | 128;
	    sudo_json_add_value(&json, "exit_value", &json_value);
        }
    }

    sudo_json_close_object(&json);	/* close record */
    fputs("\n}\n", state.log_fp);	/* close JSON */
    fflush(state.log_fp);

    (void)sudo_lock_file(fileno(state.log_fp), SUDO_UNLOCK);

    ret = true;
done:
    debug_return_int(ret);
}

static int
audit_write_record(const char *audit_str, const char *plugin_name,
    unsigned int plugin_type, const char *reason, char * const command_info[],
    char * const run_argv[], char * const run_envp[])
{
    struct timespec now;
    struct json_container json;
    struct json_value json_value;
    int ret = -1;
    debug_decl(audit_write_record, SUDO_DEBUG_PLUGIN);

    if (sudo_gettime_real(&now) == -1) {
	sudo_warn(U_("unable to read the clock"));
	goto done;
    }

    if (!sudo_lock_file(fileno(state.log_fp), SUDO_LOCK)) {
	sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_LINENO,
	    "unable to lock %s", state.logfile);
	goto done;
    }

    /* Note: assumes file ends in "\n}\n" */
    fseeko(state.log_fp, 0, SEEK_END);
    if (ftello(state.log_fp) == 0) {
	/* New file */
	putc('{', state.log_fp);
    } else {
	/* Continue file, overwrite the final "\n}\n" */
	fseeko(state.log_fp, -3, SEEK_END);
	putc(',', state.log_fp);
    }

    sudo_json_init(&json, state.log_fp, 4);
    sudo_json_open_object(&json, audit_str);

    json_value.type = JSON_STRING;
    json_value.u.string = plugin_name;
    sudo_json_add_value(&json, "plugin_name", &json_value);

    switch (plugin_type) {
    case 0:
	json_value.u.string = "front-end";
	break;
    case SUDO_POLICY_PLUGIN:
	json_value.u.string = "policy";
	break;
    case SUDO_IO_PLUGIN:
	json_value.u.string = "io";
	break;
    case SUDO_APPROVAL_PLUGIN:
	json_value.u.string = "approval";
	break;
    case SUDO_AUDIT_PLUGIN:
	json_value.u.string = "audit";
	break;
    default:
	json_value.u.string = "unknown";
	break;
    }
    json_value.type = JSON_STRING;
    sudo_json_add_value(&json, "plugin_type", &json_value);

    /* error and reject audit events usually contain a reason. */
    if (reason != NULL) {
	json_value.type = JSON_STRING;
	json_value.u.string = reason;
	sudo_json_add_value(&json, "reason", &json_value);
    }

    json_value.type = JSON_STRING;
    json_value.u.string = state.uuid_str;
    sudo_json_add_value(&json, "uuid", &json_value);

    if (!print_timestamp(&json, &now))
	sudo_warnx(U_("unable to format timestamp"));

    /* Write key=value objects. */
    print_key_value_object(&json, "options", state.settings, settings_filter);
    print_key_value_object(&json, "user_info", state.user_info, NULL);
    if (command_info != NULL)
	print_key_value_object(&json, "command_info", command_info, NULL);

    /* Write submit_optind before submit_argv */
    json_value.type = JSON_NUMBER;
    json_value.u.number = state.submit_optind;
    sudo_json_add_value(&json, "submit_optind", &json_value);

    print_array(&json, "submit_argv", state.submit_argv);
    print_array(&json, "submit_envp", state.submit_envp);
    if (run_argv != NULL)
	print_array(&json, "run_argv", run_argv);
    if (run_envp != NULL)
	print_array(&json, "run_envp", run_envp);

    sudo_json_close_object(&json);	/* close audit_str */
    fputs("\n}\n", state.log_fp);	/* close JSON */
    fflush(state.log_fp);

    (void)sudo_lock_file(fileno(state.log_fp), SUDO_UNLOCK);

    ret = true;
done:
    debug_return_int(ret);
}

static int
audit_accept(const char *plugin_name, unsigned int plugin_type,
    char * const command_info[], char * const run_argv[],
    char * const run_envp[], const char **errstr)
{
    int ret;
    debug_decl(audit_accept, SUDO_DEBUG_PLUGIN);

    state.accepted = true;

    ret = audit_write_record("accept", plugin_name, plugin_type, NULL,
	command_info, run_argv, run_envp);

    debug_return_int(ret);
}

static int
audit_reject(const char *plugin_name, unsigned int plugin_type,
    const char *reason, char * const command_info[], const char **errstr)
{
    int ret;
    debug_decl(audit_reject, SUDO_DEBUG_PLUGIN);

    ret = audit_write_record("reject", plugin_name, plugin_type,
	reason, command_info, NULL, NULL);

    debug_return_int(ret);
}

static int
audit_error(const char *plugin_name, unsigned int plugin_type,
    const char *reason, char * const command_info[], const char **errstr)
{
    int ret;
    debug_decl(audit_error, SUDO_DEBUG_PLUGIN);

    ret = audit_write_record("error", plugin_name, plugin_type,
	reason, command_info, NULL, NULL);

    debug_return_int(ret);
}

static void
audit_close(int status_type, int status)
{
    debug_decl(audit_close, SUDO_DEBUG_PLUGIN);

    switch (status_type) {
    case SUDO_PLUGIN_NO_STATUS:
	break;
    case SUDO_PLUGIN_WAIT_STATUS:
	audit_write_exit_record(status, 0);
	break;
    case SUDO_PLUGIN_EXEC_ERROR:
	audit_write_exit_record(0, status);
	break;
    case SUDO_PLUGIN_SUDO_ERROR:
	audit_write_record("error", "sudo", 0, strerror(status),
	    NULL, NULL, NULL);
	break;
    default:
	sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_LINENO,
	    "unexpected status type %d, value %d", status_type, status);
	break;
    }

    free(state.logfile);
    if (state.log_fp != NULL)
	fclose(state.log_fp);

    debug_return;
}

static int
audit_show_version(int verbose)
{
    debug_decl(audit_show_version, SUDO_DEBUG_PLUGIN);

    audit_printf(SUDO_CONV_INFO_MSG, "JSON audit plugin version %s\n",
        PACKAGE_VERSION);

    debug_return_int(true);
}

__dso_public struct audit_plugin audit_json = {
    SUDO_AUDIT_PLUGIN,
    SUDO_API_VERSION,
    audit_open,
    audit_close,
    audit_accept,
    audit_reject,
    audit_error,
    audit_show_version,
    NULL, /* register_hooks */
    NULL /* deregister_hooks */
};
