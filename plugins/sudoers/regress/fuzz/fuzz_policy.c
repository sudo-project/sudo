/*
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

#include <config.h>

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
#include <unistd.h>
#include <string.h>

#include "sudoers.h"
#include "interfaces.h"

extern char **environ;
extern sudo_dso_public struct policy_plugin sudoers_policy;

const char *path_plugin_dir = _PATH_SUDO_PLUGIN_DIR;
char *audit_msg;

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
	char **tmp = reallocarray(arr->entries, arr->size + 128, sizeof(char *));
	if (tmp == NULL) {
	    free(copy);
	    return false;
	}
	arr->entries = tmp;
	arr->size += 128;
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
    return 0;
}

static int
fuzz_printf(int msg_type, const char *fmt, ...)
{
    return 0;
}

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
    const int num_checks = 4;
    char *line = NULL;
    size_t linesize = 0;
    ssize_t linelen;
    int i, res;
    FILE *fp;

    setprogname("fuzz_policy");

    fp = open_data(data, size);
    if (fp == NULL)
        return 0;

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
	    push(&env_add, line);
	    continue;
	}

	/* Treat anything else as a setting. */
	push(&settings, line);
    }
    fclose(fp);
    free(line);
    line = NULL;

    for (i = 0; i < num_checks; i++) {
	/* Call policy open function */
	res = sudoers_policy.open(SUDO_API_VERSION, fuzz_conversation, fuzz_printf,
	    settings.entries, user_info.entries, environ, plugin_args.entries,
	    &errstr);

	switch (res) {
	case 1:
	    /* success */
	    if (argv.len == 0) {
		/* Must have a command to check. */
		push(&argv, "/usr/bin/id");
	    }

	    switch (i) {
	    case 0:
		sudoers_policy.check_policy(argv.len, argv.entries,
		    env_add.entries, &command_info, &argv_out, &user_env_out,
		    &errstr);
		break;
	    case 1:
		sudoers_policy.list(argv.len, argv.entries, false, NULL,
		    &errstr);
		break;
	    case 2:
		sudoers_policy.validate(&errstr);
		break;
	    case 3:
		sudoers_policy.invalidate(false);
		break;
	    }
	    break;
	default:
	    /* failure or error, skip remaining checks (counts by 4) */
	    i = ((i + num_checks) & ~(num_checks - 1)) - 1;
	    break;
	}

	/* Free resources. */
	if (sudoers_policy.close != NULL)
	    sudoers_policy.close(0, 0);
	else
	    sudoers_cleanup();

	/* Call a second time to free old env pointer. */
	env_init(NULL);
    }

    sudoers_gc_run();

    free_dynamic_array(&plugin_args);
    free_dynamic_array(&settings);
    free_dynamic_array(&user_info);
    free_dynamic_array(&argv);
    free_dynamic_array(&env_add);

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
    return 0;
}

static struct sudo_nss sudo_nss_file = {
    { NULL, NULL },
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

bool
log_warning(int flags, const char *fmt, ...)
{
    va_list ap;

    /* Just display on stderr. */
    va_start(ap, fmt);
    sudo_vwarn_nodebug(fmt, ap);
    va_end(ap);

    return true;
}

bool
log_warningx(int flags, const char *fmt, ...)
{
    va_list ap;

    /* Just display on stderr. */
    va_start(ap, fmt);
    sudo_vwarnx_nodebug(fmt, ap);
    va_end(ap);

    return true;
}

bool
gai_log_warning(int flags, int errnum, const char *fmt, ...)
{
    va_list ap;

    /* Note: ignores errnum */
    va_start(ap, fmt);
    sudo_vwarnx_nodebug(fmt, ap);
    va_end(ap);

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
    if (infile[0] == '/') {
	*outfile = strdup(infile);
    } else {
	if (asprintf(outfile, "/usr/bin/%s", infile) == -1)
	    *outfile = NULL;
    }
    return *outfile ? FOUND : NOT_FOUND_ERROR;
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
iolog_nextid(char *iolog_dir, char sessid[7])
{
    strlcpy(sessid, "000001", 7);
    return true;
}

/* STUB */
bool
cb_maxseq(const union sudo_defs_val *sd_un)
{
    return true;
}

/* STUB */
bool
cb_iolog_user(const union sudo_defs_val *sd_un)
{
    return true;
}

/* STUB */
bool
cb_iolog_group(const union sudo_defs_val *sd_un)
{
    return true;
}

/* STUB */
bool
cb_iolog_mode(const union sudo_defs_val *sd_un)
{
    return true;
}

/* STUB */
bool
cb_group_plugin(const union sudo_defs_val *sd_un)
{
    return true;
}
