/*
 * Copyright (c) 2021-2022 Todd C. Miller <Todd.Miller@sudo.ws>
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
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#if defined(HAVE_STDINT_H)
# include <stdint.h>
#elif defined(HAVE_INTTYPES_H)
# include <inttypes.h>
#endif
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <unistd.h>
#include <string.h>
#ifndef HAVE_GETADDRINFO
# include "compat/getaddrinfo.h"
#endif

#include "sudoers.h"
#include "sudo_iolog.h"
#include "interfaces.h"
#include "check.h"

extern char **environ;
extern sudo_dso_public struct policy_plugin sudoers_policy;

const char *path_plugin_dir = _PATH_SUDO_PLUGIN_DIR;
char *audit_msg;

static int pass;

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

static FILE *
open_data(const uint8_t *data, size_t size)
{
#ifdef HAVE_FMEMOPEN
    /* Operate in-memory. */
    return fmemopen((void *)data, size, "r");
#else
    char tempfile[] = "/tmp/sudoers.XXXXXX";
    size_t nwritten;
    int fd;

    /* Use (unlinked) temporary file. */
    fd = mkstemp(tempfile);
    if (fd == -1)
	return NULL;
    unlink(tempfile);
    nwritten = write(fd, data, size);
    if (nwritten != size) {
	close(fd);
	return NULL;
    }
    lseek(fd, 0, SEEK_SET);
    return fdopen(fd, "r");
#endif
}

/*
 * Array that gets resized as needed.
 */
struct dynamic_array {
    char **entries;
    size_t len;
    size_t size;
};

static void
free_strvec(char **vec)
{
    int i;

    for (i = 0; vec[i] != NULL; i++)
	free(vec[i]);
}

static void
free_dynamic_array(struct dynamic_array *arr)
{
    if (arr->entries != NULL) {
	free_strvec(arr->entries);
	free(arr->entries);
    }
    memset(arr, 0, sizeof(*arr));
}

static bool
push(struct dynamic_array *arr, const char *entry)
{
    char *copy = NULL;

    if (entry != NULL) {
	if ((copy = strdup(entry)) == NULL)
	    return false;
    }

    if (arr->len + (entry != NULL) >= arr->size) {
	char **tmp = reallocarray(arr->entries, arr->size + 1024, sizeof(char *));
	if (tmp == NULL) {
	    free(copy);
	    return false;
	}
	arr->entries = tmp;
	arr->size += 1024;
    }
    if (copy != NULL)
	arr->entries[arr->len++] = copy;
    arr->entries[arr->len] = NULL;

    return true;
}

static int
fuzz_conversation(int num_msgs, const struct sudo_conv_message msgs[],
    struct sudo_conv_reply replies[], struct sudo_conv_callback *callback)
{
    int n;

    for (n = 0; n < num_msgs; n++) {
	const struct sudo_conv_message *msg = &msgs[n];

	switch (msg->msg_type & 0xff) {
	    case SUDO_CONV_PROMPT_ECHO_ON:
	    case SUDO_CONV_PROMPT_MASK:
	    case SUDO_CONV_PROMPT_ECHO_OFF:
		/* input not supported */
		return -1;
	    case SUDO_CONV_ERROR_MSG:
	    case SUDO_CONV_INFO_MSG:
		/* no output for fuzzers */
		break;
	    default:
		return -1;
	}
    }
    return 0;
}

static int
fuzz_printf(int msg_type, const char *fmt, ...)
{
    return 0;
}

static int
fuzz_hook_stub(struct sudo_hook *hook)
{
    return 0;
}

/*
 * The fuzzing environment may not have DNS available, this may result
 * in long delays that cause a timeout when fuzzing.  This getaddrinfo()
 * can look up "localhost" and returns an error for anything else.
 */
#ifdef FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION
/* Avoid compilation errors if getaddrinfo() or freeaddrinfo() are macros. */
# undef getaddrinfo
# undef freeaddrinfo

int
# ifdef HAVE_GETADDRINFO
getaddrinfo(
# else
sudo_getaddrinfo(
# endif
    const char *nodename, const char *servname,
    const struct addrinfo *hints, struct addrinfo **res)
{
    struct addrinfo *ai;
    struct in_addr addr;

    /* Stub getaddrinfo(3) to avoid a DNS timeout in CIfuzz. */
    if (strcmp(nodename, "localhost") != 0 || servname != NULL)
	return EAI_FAIL;

    /* Hard-code localhost. */
    ai = calloc(1, sizeof(*ai) + sizeof(struct sockaddr_in));
    if (ai == NULL)
	return EAI_MEMORY;
    ai->ai_canonname = strdup("localhost");
    if (ai == NULL) {
	free(ai);
	return EAI_MEMORY;
    }
    ai->ai_family = AF_INET;
    ai->ai_protocol = IPPROTO_TCP;
    ai->ai_addrlen = sizeof(struct sockaddr_in);
    ai->ai_addr = (struct sockaddr *)(ai + 1);
    inet_pton(AF_INET, "127.0.0.1", &addr);
    ((struct sockaddr_in *)ai->ai_addr)->sin_family = AF_INET;
    ((struct sockaddr_in *)ai->ai_addr)->sin_addr = addr;
    *res = ai;
    return 0;
}

void
# ifdef HAVE_GETADDRINFO
freeaddrinfo(struct addrinfo *ai)
# else
sudo_freeaddrinfo(struct addrinfo *ai)
# endif
{
    struct addrinfo *next;

    while (ai != NULL) {
	next = ai->ai_next;
	free(ai->ai_canonname);
	free(ai);
	ai = next;
    }
}
#endif /* FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION */

enum fuzz_policy_pass {
    PASS_NONE,
    PASS_VERSION,
    PASS_CHECK_LOG_LOCAL,
    PASS_CHECK_LOG_REMOTE,
    PASS_CHECK_NOT_FOUND,
    PASS_CHECK_NOT_FOUND_DOT,
    PASS_LIST,
    PASS_LIST_OTHER,
    PASS_LIST_CHECK,
    PASS_VALIDATE,
    PASS_INVALIDATE
};

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    struct dynamic_array plugin_args = { NULL };
    struct dynamic_array settings = { NULL };
    struct dynamic_array user_info = { NULL };
    struct dynamic_array argv = { NULL };
    struct dynamic_array env_add = { NULL };
    char **command_info = NULL, **argv_out = NULL, **user_env_out = NULL;
    const char *errstr = NULL;
    const int num_passes = 10;
    char *line = NULL;
    size_t linesize = 0;
    ssize_t linelen;
    int res = 1;
    FILE *fp;

    fp = open_data(data, size);
    if (fp == NULL)
        return 0;

    initprogname("fuzz_policy");
    sudoers_debug_register(getprogname(), NULL);
    if (getenv("SUDO_FUZZ_VERBOSE") == NULL)
	sudo_warn_set_conversation(fuzz_conversation);

    /* user_info and settings must be non-NULL (even if empty). */
    push(&user_info, NULL);
    push(&settings, NULL);

    /* Iterate over each line of data. */
    while ((linelen = getdelim(&line, &linesize, '\n', fp)) != -1) {
	if (line[linelen - 1] == '\n')
	    line[linelen - 1] = '\0';

	/* Skip comments and blank lines. */
	if (line[0] == '#' || line[0] == '\0')
	    continue;

	/* plugin args */
	if (strncmp(line, "error_recovery=", sizeof("error_recovery=") - 1) == 0) {
	    push(&plugin_args, line);
	    continue;
	}
	if (strncmp(line, "sudoers_file=", sizeof("sudoers_file=") - 1) == 0) {
	    push(&plugin_args, line);
	    continue;
	}
	if (strncmp(line, "sudoers_mode=", sizeof("sudoers_mode=") - 1) == 0) {
	    push(&plugin_args, line);
	    continue;
	}
	if (strncmp(line, "sudoers_gid=", sizeof("sudoers_gid=") - 1) == 0) {
	    push(&plugin_args, line);
	    continue;
	}
	if (strncmp(line, "sudoers_uid=", sizeof("sudoers_uid=") - 1) == 0) {
	    push(&plugin_args, line);
	    continue;
	}
	if (strncmp(line, "ldap_conf=", sizeof("ldap_conf=") - 1) == 0) {
	    push(&plugin_args, line);
	    continue;
	}
	if (strncmp(line, "ldap_secret=", sizeof("ldap_secret=") - 1) == 0) {
	    push(&plugin_args, line);
	    continue;
	}

	/* user info */
	if (strncmp(line, "user=", sizeof("user=") - 1) == 0) {
	    push(&user_info, line);
	    continue;
	}
	if (strncmp(line, "uid=", sizeof("uid=") - 1) == 0) {
	    push(&user_info, line);
	    continue;
	}
	if (strncmp(line, "gid=", sizeof("gid=") - 1) == 0) {
	    push(&user_info, line);
	    continue;
	}
	if (strncmp(line, "groups=", sizeof("groups=") - 1) == 0) {
	    push(&user_info, line);
	    continue;
	}
	if (strncmp(line, "cwd=", sizeof("cwd=") - 1) == 0) {
	    push(&user_info, line);
	    continue;
	}
	if (strncmp(line, "tty=", sizeof("tty=") - 1) == 0) {
	    push(&user_info, line);
	    continue;
	}
	if (strncmp(line, "host=", sizeof("host=") - 1) == 0) {
	    push(&user_info, line);
	    continue;
	}
	if (strncmp(line, "lines=", sizeof("lines=") - 1) == 0) {
	    push(&user_info, line);
	    continue;
	}
	if (strncmp(line, "cols=", sizeof("cols=") - 1) == 0) {
	    push(&user_info, line);
	    continue;
	}
	if (strncmp(line, "sid=", sizeof("sid=") - 1) == 0) {
	    push(&user_info, line);
	    continue;
	}
	if (strncmp(line, "umask=", sizeof("umask=") - 1) == 0) {
	    push(&user_info, line);
	    continue;
	}
	if (strncmp(line, "rlimit_", sizeof("rlimit_") - 1) == 0) {
	    push(&user_info, line);
	    continue;
	}

	/* First argv entry is the command, the rest are args. */
	if (strncmp(line, "argv=", sizeof("argv=") - 1) == 0) {
	    push(&argv, line);
	    continue;
	}

	/* Additional environment variables to add. */
	if (strncmp(line, "env=", sizeof("env=") - 1) == 0) {
	    const char *cp = line + sizeof("env=") - 1;
	    if (strchr(cp, '=') != NULL)
		push(&env_add, cp);
	    continue;
	}

	/* Treat anything else as a setting. */
	push(&settings, line);
    }
    fclose(fp);
    free(line);
    line = NULL;

    /* Exercise code paths that use KRB5CCNAME and SUDO_PROMPT. */
    putenv((char *)"KRB5CCNAME=/tmp/krb5cc_123456");
    putenv((char *)"SUDO_PROMPT=[sudo] password for %p: ");

    sudoers_policy.register_hooks(SUDO_API_VERSION, fuzz_hook_stub);

    for (pass = 1; res == 1 && pass <= num_passes; pass++) {
	/* Call policy open function */
	res = sudoers_policy.open(SUDO_API_VERSION, fuzz_conversation,
	    fuzz_printf, settings.entries, user_info.entries, environ,
	    plugin_args.entries, &errstr);
	if (res == 1) {
	    if (argv.len == 0) {
		/* Must have a command to check. */
		push(&argv, "/usr/bin/id");
	    }

	    switch (pass) {
	    case PASS_NONE:
		break;
	    case PASS_VERSION:
		/* sudo -V */
		sudoers_policy.show_version(true);
		break;
	    case PASS_CHECK_LOG_LOCAL: {
		/* sudo command w/ local I/O logging (MODE_RUN) */
		sudoers_policy.check_policy(argv.len, argv.entries,
		    env_add.entries, &command_info, &argv_out, &user_env_out,
		    &errstr);
		/* call check_policy() again to check for leaks. */
		sudoers_policy.check_policy(argv.len, argv.entries,
		    env_add.entries, &command_info, &argv_out, &user_env_out,
		    &errstr);
		/* sudo_auth_begin_session() is stubbed out below. */
		sudoers_policy.init_session(NULL, NULL, NULL);
		break;
	    }
	    case PASS_CHECK_LOG_REMOTE:
		/* sudo command w/ remote I/O logging (MODE_RUN) */
		sudoers_policy.check_policy(argv.len, argv.entries,
		    env_add.entries, &command_info, &argv_out, &user_env_out,
		    &errstr);
		/* call check_policy() again to check for leaks. */
		sudoers_policy.check_policy(argv.len, argv.entries,
		    env_add.entries, &command_info, &argv_out, &user_env_out,
		    &errstr);
		/* sudo_auth_begin_session() is stubbed out below. */
		sudoers_policy.init_session(NULL, NULL, NULL);
		break;
	    case PASS_CHECK_NOT_FOUND:
		/* sudo command (not found) */
		sudoers_policy.check_policy(argv.len, argv.entries,
		    env_add.entries, &command_info, &argv_out, &user_env_out,
		    &errstr);
		/* sudo_auth_begin_session() is stubbed out below. */
		sudoers_policy.init_session(NULL, NULL, NULL);
		break;
	    case PASS_CHECK_NOT_FOUND_DOT:
		/* sudo command (found but in cwd) */
		sudoers_policy.check_policy(argv.len, argv.entries,
		    env_add.entries, &command_info, &argv_out, &user_env_out,
		    &errstr);
		/* call check_policy() again to check for leaks. */
		sudoers_policy.check_policy(argv.len, argv.entries,
		    env_add.entries, &command_info, &argv_out, &user_env_out,
		    &errstr);
		/* sudo_auth_begin_session() is stubbed out below. */
		sudoers_policy.init_session(NULL, NULL, NULL);
		break;
	    case PASS_LIST:
		/* sudo -l (MODE_LIST) */
		sudoers_policy.list(0, NULL, false, NULL, &errstr);
		/* call list() again to check for leaks. */
		sudoers_policy.list(0, NULL, false, NULL, &errstr);
		break;
	    case PASS_LIST_OTHER:
		/* sudo -l -U root (MODE_LIST) */
		sudoers_policy.list(0, NULL, false, "root", &errstr);
		/* call list() again to check for leaks. */
		sudoers_policy.list(0, NULL, false, "root", &errstr);
		break;
	    case PASS_LIST_CHECK:
		/* sudo -l command (MODE_CHECK) */
		sudoers_policy.list(argv.len, argv.entries, false, NULL,
		    &errstr);
		/* call list() again to check for leaks. */
		sudoers_policy.list(argv.len, argv.entries, false, NULL,
		    &errstr);
		break;
	    case PASS_VALIDATE:
		/* sudo -v (MODE_VALIDATE) */
		sudoers_policy.validate(&errstr);
		/* call validate() again to check for leaks. */
		sudoers_policy.validate(&errstr);
		break;
	    case PASS_INVALIDATE:
		/* sudo -k */
		sudoers_policy.invalidate(false);
		/* call invalidate() again to check for leaks. */
		sudoers_policy.invalidate(false);
		break;
	    }
	}

	/* Free resources. */
	if (sudoers_policy.close != NULL)
	    sudoers_policy.close(0, 0);
	else
	    sudoers_cleanup();

	/* Call a second time to free old env pointer. */
	env_init(NULL);
    }

    sudoers_policy.deregister_hooks(SUDO_API_VERSION, fuzz_hook_stub);
    sudoers_gc_run();

    free_dynamic_array(&plugin_args);
    free_dynamic_array(&settings);
    free_dynamic_array(&user_info);
    free_dynamic_array(&argv);
    free_dynamic_array(&env_add);

    sudoers_debug_deregister();

    fflush(stdout);

    return 0;
}

/* STUB */
bool
user_is_exempt(void)
{
    return false;
}

/* STUB */
bool
set_interfaces(const char *ai)
{
    return true;
}

/* STUB */
void
dump_interfaces(const char *ai)
{
    return;
}

/* STUB */
void
dump_auth_methods(void)
{
    return;
}

/* STUB */
int
sudo_auth_begin_session(struct passwd *pw, char **user_env[])
{
    return 1;
}

/* STUB */
int
sudo_auth_end_session(struct passwd *pw)
{
    return 1;
}

/* STUB */
bool
sudo_auth_needs_end_session(void)
{
    return false;
}

/* STUB */
int
timestamp_remove(bool unlink_it)
{
    return true;
}

/* STUB */
int
create_admin_success_flag(void)
{
    return true;
}

/* STUB */
static int
sudo_file_open(struct sudo_nss *nss)
{
    return 0;
}

/* STUB */
static int
sudo_file_close(struct sudo_nss *nss)
{
    return 0;
}

/* STUB */
static struct sudoers_parse_tree *
sudo_file_parse(struct sudo_nss *nss)
{
    static struct sudoers_parse_tree parse_tree;

    return &parse_tree;
}

/* STUB */
static int
sudo_file_query(struct sudo_nss *nss, struct passwd *pw)
{
    return 0;
}

/* STUB */
static int
sudo_file_getdefs(struct sudo_nss *nss)
{
    /* Set some Defaults */
    set_default("log_input", NULL, true, "sudoers", 1, 1, false);
    set_default("log_output", NULL, true, "sudoers", 1, 1, false);
    set_default("env_file", "/dev/null", true, "sudoers", 1, 1, false);
    set_default("restricted_env_file", "/dev/null", true, "sudoers", 1, 1, false);
    set_default("exempt_group", "sudo", true, "sudoers", 1, 1, false);
    set_default("runchroot", "/", true, "sudoers", 1, 1, false);
    set_default("runcwd", "~", true, "sudoers", 1, 1, false);
    set_default("fqdn", NULL, true, "sudoers", 1, 1, false);
    set_default("runas_default", "root", true, "sudoers", 1, 1, false);
    set_default("tty_tickets", NULL, true, "sudoers", 1, 1, false);
    set_default("umask", "022", true, "sudoers", 1, 1, false);
    set_default("logfile", "/var/log/sudo", true, "sudoers", 1, 1, false);
    set_default("syslog", "auth", true, "sudoers", 1, 1, false);
    set_default("syslog_goodpri", "notice", true, "sudoers", 1, 1, false);
    set_default("syslog_badpri", "alert", true, "sudoers", 1, 1, false);
    set_default("syslog_maxlen", "2048", true, "sudoers", 1, 1, false);
    set_default("loglinelen", "0", true, "sudoers", 1, 1, false);
    set_default("log_year", NULL, true, "sudoers", 1, 1, false);
    set_default("log_host", NULL, true, "sudoers", 1, 1, false);
    set_default("mailerpath", NULL, false, "sudoers", 1, 1, false);
    set_default("mailerflags", "-t", true, "sudoers", 1, 1, false);
    set_default("mailto", "root@localhost", true, "sudoers", 1, 1, false);
    set_default("mailfrom", "sudo@sudo.ws", true, "sudoers", 1, 1, false);
    set_default("mailsub", "Someone has been naughty on %h", true, "sudoers", 1, 1, false);
    set_default("timestampowner", "#0", true, "sudoers", 1, 1, false);
    set_default("compress_io", NULL, true, "sudoers", 1, 1, false);
    set_default("iolog_flush", NULL, true, "sudoers", 1, 1, false);
    set_default("iolog_flush", NULL, true, "sudoers", 1, 1, false);
    set_default("maxseq", "2176782336", true, "sudoers", 1, 1, false);
    set_default("sudoedit_checkdir", NULL, false, "sudoers", 1, 1, false);
    set_default("sudoedit_follow", NULL, true, "sudoers", 1, 1, false);
    set_default("ignore_iolog_errors", NULL, true, "sudoers", 1, 1, false);
    set_default("ignore_iolog_errors", NULL, true, "sudoers", 1, 1, false);
    set_default("noexec", NULL, true, "sudoers", 1, 1, false);
    set_default("exec_background", NULL, true, "sudoers", 1, 1, false);
    set_default("use_pty", NULL, true, "sudoers", 1, 1, false);
    set_default("utmp_runas", NULL, true, "sudoers", 1, 1, false);
    set_default("iolog_mode", "0640", true, "sudoers", 1, 1, false);
    set_default("iolog_user", NULL, false, "sudoers", 1, 1, false);
    set_default("iolog_group", NULL, false, "sudoers", 1, 1, false);
    if (pass != PASS_CHECK_LOG_LOCAL) {
	set_default("log_servers", "localhost", true, "sudoers", 1, 1, false);
	set_default("log_server_timeout", "30", true, "sudoers", 1, 1, false);
	set_default("log_server_cabundle", "/etc/ssl/cacert.pem", true, "sudoers", 1, 1, false);
	set_default("log_server_peer_cert", "/etc/ssl/localhost.crt", true, "sudoers", 1, 1, false);
	set_default("log_server_peer_key", "/etc/ssl/private/localhost.key", true, "sudoers", 1, 1, false);
    }

    return 0;
}

static struct sudo_nss sudo_nss_file = {
    { NULL, NULL },
    "sudoers",
    sudo_file_open,
    sudo_file_close,
    sudo_file_parse,
    sudo_file_query,
    sudo_file_getdefs
};

struct sudo_nss_list *
sudo_read_nss(void)
{
    static struct sudo_nss_list snl = TAILQ_HEAD_INITIALIZER(snl);

    if (TAILQ_EMPTY(&snl))
	TAILQ_INSERT_TAIL(&snl, &sudo_nss_file, entries);

    return &snl;
}

/* STUB */
int
check_user(int validated, int mode)
{
    return true;
}

/* STUB */
bool
check_user_shell(const struct passwd *pw)
{
    return true;
}

/* STUB */
void
group_plugin_unload(void)
{
    return;
}

/* STUB */
bool
log_warning(int flags, const char *fmt, ...)
{
    return true;
}

/* STUB */
bool
log_warningx(int flags, const char *fmt, ...)
{
    return true;
}

/* STUB */
bool
gai_log_warning(int flags, int errnum, const char *fmt, ...)
{
    return true;
}

/* STUB */
bool
log_denial(int status, bool inform_user)
{
    return true;
}

/* STUB */
bool
log_failure(int status, int flags)
{
    return true;
}

/* STUB */
bool
log_exit_status(int exit_status)
{
    return true;
}

/* STUB */
bool
mail_parse_errors(void)
{
    return true;
}

/* STUB */
bool
log_parse_error(const char *file, int line, int column, const char *fmt,
    va_list args)
{
    return true;
}

/* STUB */
int
audit_failure(char *const argv[], char const *const fmt, ...)
{
    return 0;
}

/* STUB */
int
sudoers_lookup(struct sudo_nss_list *snl, struct passwd *pw, int *cmnd_status,
    int pwflag)
{
    return VALIDATE_SUCCESS;
}

/* STUB */
int
display_cmnd(struct sudo_nss_list *snl, struct passwd *pw)
{
    return true;
}

/* STUB */
int
display_privs(struct sudo_nss_list *snl, struct passwd *pw, bool verbose)
{
    return true;
}

/* STUB */
int
find_path(const char *infile, char **outfile, struct stat *sbp,
    const char *path, const char *runchroot, int ignore_dot,
    char * const *allowlist)
{
    switch (pass) {
    case PASS_CHECK_NOT_FOUND:
	return NOT_FOUND;
    case PASS_CHECK_NOT_FOUND_DOT:
	return NOT_FOUND_DOT;
    default:
	if (infile[0] == '/') {
	    *outfile = strdup(infile);
	} else {
	    if (asprintf(outfile, "/usr/bin/%s", infile) == -1)
		*outfile = NULL;
	}
	if (*outfile == NULL)
	    return NOT_FOUND_ERROR;
	return FOUND;
    }
}

/* STUB */
bool
expand_iolog_path(const char *inpath, char *path, size_t pathlen,
    const struct iolog_path_escape *escapes, void *closure)
{
    return strlcpy(path, inpath, pathlen) < pathlen;
}

/* STUB */
bool
iolog_nextid(const char *iolog_dir, char sessid[7])
{
    strlcpy(sessid, "000001", 7);
    return true;
}

/* STUB */
bool
cb_maxseq(const char *file, int line, int column,
    const union sudo_defs_val *sd_un, int op)
{
    return true;
}

/* STUB */
bool
cb_iolog_user(const char *file, int line, int column,
    const union sudo_defs_val *sd_un, int op)
{
    return true;
}

/* STUB */
bool
cb_iolog_group(const char *file, int line, int column,
    const union sudo_defs_val *sd_un, int op)
{
    return true;
}

/* STUB */
bool
cb_iolog_mode(const char *file, int line, int column,
    const union sudo_defs_val *sd_un, int op)
{
    return true;
}

/* STUB */
bool
cb_group_plugin(const char *file, int line, int column,
    const union sudo_defs_val *sd_un, int op)
{
    return true;
}
