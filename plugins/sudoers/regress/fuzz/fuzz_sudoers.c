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

#include <sys/socket.h>

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <pwd.h>
#include <unistd.h>
#if defined(HAVE_STDINT_H)
# include <stdint.h>
#elif defined(HAVE_INTTYPES_H)
# include <inttypes.h>
#endif
#include <netinet/in.h>
#include <arpa/inet.h>
#ifdef NEED_RESOLV_H
# include <arpa/nameser.h>
# include <resolv.h>
#endif /* NEED_RESOLV_H */
#include <netdb.h>

#include "sudoers.h"
#include "interfaces.h"

static int fuzz_conversation(int num_msgs, const struct sudo_conv_message msgs[], struct sudo_conv_reply replies[], struct sudo_conv_callback *callback);
static int fuzz_printf(int msg_type, const char * restrict fmt, ...);
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

/* For set_cmnd_path() */
static const char *orig_cmnd;

/* Required to link with parser. */
struct sudoers_user_context user_ctx;
struct sudoers_runas_context runas_ctx;
sudo_conv_t sudo_conv = fuzz_conversation;
sudo_printf_t sudo_printf = fuzz_printf;
unsigned int sudo_mode;

FILE *
open_sudoers(const char *file, char **outfile, bool doedit, bool *keepopen)
{
    /*
     * If we allow the fuzzer to choose include paths it will
     * include random files in the file system.
     * This leads to bug reports that cannot be reproduced.
     */
    return NULL;
}

static int
fuzz_printf(int msg_type, const char * restrict fmt, ...)
{
    return 0;
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

bool
init_envtables(void)
{
    return true;
}

int
set_cmnd_path(const char *runchroot)
{
    /* Reallocate user_ctx.cmnd to catch bugs in command_matches(). */
    char *new_cmnd = strdup(orig_cmnd);
    if (new_cmnd == NULL)
        return NOT_FOUND_ERROR;
    free(user_ctx.cmnd);
    user_ctx.cmnd = new_cmnd;
    return FOUND;
}

/* STUB */
bool
mail_parse_errors(void)
{
    return true;
}

/* STUB */
bool
log_warningx(unsigned int flags, const char * restrict fmt, ...)
{
    return true;
}

static int
sudo_fuzz_query(const struct sudo_nss *nss, struct passwd *pw)
{
    return 0;
}

static int
cb_unused(struct sudoers_parse_tree *parse_tree, struct alias *a, void *v)
{
    return 0;
}

bool
cb_log_input(const char *file, int line, int column,
    const union sudo_defs_val *sd_un, int op)
{
    return 0;
}

bool
cb_log_output(const char *file, int line, int column,
    const union sudo_defs_val *sd_un, int op)
{
    return 0;
}

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

static struct user_data {
    const char *user;
    const char *runuser;
    const char *rungroup;
} user_data[] = {
    { "root", NULL, NULL },
    { "millert", "operator", NULL },
    { "millert", NULL, "wheel" },
    { "operator", NULL, NULL },
    { NULL }
};

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    struct user_data *ud;
    struct sudo_nss sudo_nss_fuzz;
    struct sudo_nss_list snl = TAILQ_HEAD_INITIALIZER(snl);
    struct sudoers_parse_tree parse_tree;
    struct interface_list *interfaces;
    struct passwd *pw;
    struct group *gr;
    const char *gids[10];
    time_t now;
    FILE *fp;

    /* Don't waste time fuzzing tiny inputs. */
    if (size < 5)
        return 0;

    fp = open_data(data, size);
    if (fp == NULL)
        return 0;

    initprogname("fuzz_sudoers");
    sudoers_debug_register(getprogname(), NULL);
    if (getenv("SUDO_FUZZ_VERBOSE") == NULL)
	sudo_warn_set_conversation(fuzz_conversation);

    /* Sudoers locale setup. */
    sudoers_initlocale(setlocale(LC_ALL, ""), "C");
    sudo_warn_set_locale_func(sudoers_warn_setlocale);
    bindtextdomain("sudoers", LOCALEDIR);
    textdomain("sudoers");

    /* Use the sudoers locale for everything. */
    sudoers_setlocale(SUDOERS_LOCALE_SUDOERS, NULL);

    /* Prime the group cache */
    gr = sudo_mkgrent("wheel", 0, "millert", "root", (char *)NULL);
    if (gr == NULL)
	goto done;
    sudo_gr_delref(gr);

    gr = sudo_mkgrent("operator", 5, "operator", "root", "millert", (char *)NULL);
    if (gr == NULL)
	goto done;
    sudo_gr_delref(gr);

    gr = sudo_mkgrent("staff", 20, "root", "millert", (char *)NULL);
    if (gr == NULL)
	goto done;
    sudo_gr_delref(gr);

    gr = sudo_mkgrent("sudo", 100, "root", "millert", (char *)NULL);
    if (gr == NULL)
	goto done;
    sudo_gr_delref(gr);

    /* Prime the passwd cache */
    pw = sudo_mkpwent("root", 0, 0, "/", "/bin/sh");
    if (pw == NULL)
	goto done;
    gids[0] = "0";
    gids[1] = "20";
    gids[2] = "5";
    gids[3] = NULL;
    if (sudo_set_gidlist(pw, (char **)gids, ENTRY_TYPE_FRONTEND) == -1)
	goto done;
    sudo_pw_delref(pw);

    pw = sudo_mkpwent("operator", 2, 5, "/operator", "/sbin/nologin");
    if (pw == NULL)
	goto done;
    gids[0] = "5";
    gids[1] = NULL;
    if (sudo_set_gidlist(pw, (char **)gids, ENTRY_TYPE_FRONTEND) == -1)
	goto done;
    sudo_pw_delref(pw);

    pw = sudo_mkpwent("millert", 8036, 20, "/home/millert", "/bin/tcsh");
    if (pw == NULL)
	goto done;
    gids[0] = "0";
    gids[1] = "20";
    gids[2] = "5";
    gids[3] = "100";
    gids[4] = NULL;
    if (sudo_set_gidlist(pw, (char **)gids, ENTRY_TYPE_FRONTEND) == -1)
	goto done;
    sudo_pw_delref(pw);

    /* The minimum needed to perform matching (cmnd must be dynamic). */
    user_ctx.host = user_ctx.shost = runas_ctx.host = runas_ctx.shost =
	(char *)"localhost";
    orig_cmnd = (char *)"/usr/bin/id";
    user_ctx.cmnd = strdup(orig_cmnd);
    if (user_ctx.cmnd == NULL)
	goto done;
    user_ctx.cmnd_args = (char *)"-u";
    user_ctx.cmnd_base = sudo_basename(user_ctx.cmnd);
    time(&now);

    /* Add a fake network interfaces. */
    interfaces = get_interfaces();
    if (SLIST_EMPTY(interfaces)) {
	static struct interface interface;

	interface.family = AF_INET;
	inet_pton(AF_INET, "128.138.243.151", &interface.addr.ip4);
	inet_pton(AF_INET, "255.255.255.0", &interface.netmask.ip4);
	SLIST_INSERT_HEAD(interfaces, &interface, entries);
    }

    /* Only one sudoers source, the sudoers file itself. */
    init_parse_tree(&parse_tree, NULL, NULL, NULL);
    memset(&sudo_nss_fuzz, 0, sizeof(sudo_nss_fuzz));
    sudo_nss_fuzz.parse_tree = &parse_tree;
    sudo_nss_fuzz.query = sudo_fuzz_query;
    TAILQ_INSERT_TAIL(&snl, &sudo_nss_fuzz, entries);

    /* Initialize defaults and parse sudoers. */
    init_defaults();
    init_parser("sudoers", NULL);
    sudoersrestart(fp);
    sudoersparse();
    reparent_parse_tree(&parse_tree);

    if (!parse_error) {
	/* Match user/host/command against parsed policy. */
	for (ud = user_data; ud->user != NULL; ud++) {
	    int cmnd_status;

	    /* Invoking user. */
	    user_ctx.name = (char *)ud->user;
	    if (user_ctx.pw != NULL)
		sudo_pw_delref(user_ctx.pw);
	    user_ctx.pw = sudo_getpwnam(user_ctx.name);
	    if (user_ctx.pw == NULL) {
		sudo_warnx_nodebug("unknown user %s", user_ctx.name);
		continue;
	    }

	    /* Run user. */
	    if (runas_ctx.pw != NULL)
		sudo_pw_delref(runas_ctx.pw);
	    if (ud->runuser != NULL) {
		runas_ctx.user = (char *)ud->runuser;
		SET(runas_ctx.flags, RUNAS_USER_SPECIFIED);
		runas_ctx.pw = sudo_getpwnam(runas_ctx.user);
	    } else {
		runas_ctx.user = NULL;
		CLR(runas_ctx.flags, RUNAS_USER_SPECIFIED);
		runas_ctx.pw = sudo_getpwnam("root");
	    }
	    if (runas_ctx.pw == NULL) {
		sudo_warnx_nodebug("unknown run user %s", runas_ctx.user);
		continue;
	    }

	    /* Run group. */
	    if (runas_ctx.gr != NULL)
		sudo_gr_delref(runas_ctx.gr);
	    if (ud->rungroup != NULL) {
		runas_ctx.group = (char *)ud->rungroup;
		SET(runas_ctx.flags, RUNAS_GROUP_SPECIFIED);
		runas_ctx.gr = sudo_getgrnam(runas_ctx.group);
		if (runas_ctx.gr == NULL) {
		    sudo_warnx_nodebug("unknown run group %s",
			runas_ctx.group);
		    continue;
		}
	    } else {
		runas_ctx.group = NULL;
		CLR(runas_ctx.flags, RUNAS_GROUP_SPECIFIED);
		runas_ctx.gr = NULL;
	    }

	    update_defaults(&parse_tree, NULL, SETDEF_ALL, false);

	    sudoers_lookup(&snl, user_ctx.pw, now, NULL, NULL, &cmnd_status,
		false);

	    /* Match again as a pseudo-command (list, validate, etc). */
	    sudoers_lookup(&snl, user_ctx.pw, now, NULL, NULL, &cmnd_status,
		true);

	    /* Display privileges. */
	    display_privs(&snl, user_ctx.pw, false);
	    display_privs(&snl, user_ctx.pw, true);
	}

	/* Expand tildes in runcwd and runchroot. */
	if (runas_ctx.pw != NULL) {
	    if (def_runcwd != NULL && strcmp(def_runcwd, "*") != 0) {
		expand_tilde(&def_runcwd, runas_ctx.pw->pw_name);
	    }
	    if (def_runchroot != NULL && strcmp(def_runchroot, "*") != 0) {
		expand_tilde(&def_runchroot, runas_ctx.pw->pw_name);
	    }
	}

	/* Check Defaults and aliases. */
	check_defaults(&parse_tree, false);
	check_aliases(&parse_tree, true, false, cb_unused);
    }

done:
    /* Cleanup. */
    fclose(fp);
    free_parse_tree(&parse_tree);
    reset_parser();
    if (user_ctx.pw != NULL)
	sudo_pw_delref(user_ctx.pw);
    if (runas_ctx.pw != NULL)
	sudo_pw_delref(runas_ctx.pw);
    if (runas_ctx.gr != NULL)
	sudo_gr_delref(runas_ctx.gr);
    sudo_freepwcache();
    sudo_freegrcache();
    free(user_ctx.cmnd);
    free(runas_ctx.cmnd);
    free(user_ctx.cmnd_list);
    memset(&user_ctx, 0, sizeof(user_ctx));
    memset(&runas_ctx, 0, sizeof(runas_ctx));
    sudoers_setlocale(SUDOERS_LOCALE_USER, NULL);
    sudoers_debug_deregister();
    fflush(stdout);

    return 0;
}
