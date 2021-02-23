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

/* Required to link with parser. */
struct sudo_user sudo_user;
struct passwd *list_pw;
sudo_conv_t sudo_conv = fuzz_conversation;
bool sudoers_recovery = true;

FILE *
open_sudoers(const char *file, bool doedit, bool *keepopen)
{
    /*
     * If we allow the fuzzer to choose include paths it will
     * include random files in the file system.
     * This leads to bug reports that cannot be reproduced.
     */
    return NULL;
}

static int
fuzz_conversation(int num_msgs, const struct sudo_conv_message msgs[],
    struct sudo_conv_reply replies[], struct sudo_conv_callback *callback)
{
    int n;

    for (n = 0; n < num_msgs; n++) {
	const struct sudo_conv_message *msg = &msgs[n];
	FILE *fp = stdout;

	switch (msg->msg_type & 0xff) {
	    case SUDO_CONV_PROMPT_ECHO_ON:
	    case SUDO_CONV_PROMPT_MASK:
	    case SUDO_CONV_PROMPT_ECHO_OFF:
		/* input not supported */
		return -1;
	    case SUDO_CONV_ERROR_MSG:
		fp = stderr;
		FALLTHROUGH;
	    case SUDO_CONV_INFO_MSG:
		if (msg->msg != NULL) {
		    size_t len = strlen(msg->msg);

		    if (len == 0)
			break;

		    if (fwrite(msg->msg, 1, len, fp) == 0 || fputc('\n', fp) == EOF)
			return -1;
		}
		break;
	    default:
		return -1;
	}
    }
    return 0;
}

bool
set_perms(int perm)
{
    return true;
}

bool
restore_perms(void)
{
    return true;
}

bool
sudo_nss_can_continue(struct sudo_nss *nss, int match)
{
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

extern struct sudo_nss sudo_nss_file;

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    char **u, *users[] = { "root", "millert", "operator", NULL };
    struct sudo_nss_list snl = TAILQ_HEAD_INITIALIZER(snl);
    struct sudoers_parse_tree parse_tree;
    struct interface_list *interfaces;
    struct passwd *pw;
    struct group *gr;
    char *gids[10];
    FILE *fp;

    /* Don't waste time fuzzing tiny inputs. */
    if (size < 5)
        return 0;

    fp = open_data(data, size);
    if (fp == NULL)
        return 0;

    /* Prime the group cache */
    gr = sudo_mkgrent("wheel", 0, "millert", "root", NULL);
    if (gr == NULL)
	goto done;
    sudo_gr_delref(gr);

    gr = sudo_mkgrent("operator", 5, "operator", "root", "millert", NULL);
    if (gr == NULL)
	goto done;
    sudo_gr_delref(gr);

    gr = sudo_mkgrent("staff", 20, "root", "millert", NULL);
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
    if (sudo_set_gidlist(pw, gids, ENTRY_TYPE_FRONTEND) == -1)
	goto done;
    sudo_pw_delref(pw);

    pw = sudo_mkpwent("operator", 2, 5, "/operator", "/sbin/nologin");
    if (pw == NULL)
	goto done;
    gids[0] = "5";
    gids[1] = NULL;
    if (sudo_set_gidlist(pw, gids, ENTRY_TYPE_FRONTEND) == -1)
	goto done;
    sudo_pw_delref(pw);

    pw = sudo_mkpwent("millert", 8036, 20, "/home/millert", "/bin/tcsh");
    if (pw == NULL)
	goto done;
    gids[0] = "0";
    gids[1] = "20";
    gids[2] = "5";
    gids[3] = NULL;
    if (sudo_set_gidlist(pw, gids, ENTRY_TYPE_FRONTEND) == -1)
	goto done;
    sudo_pw_delref(pw);

    /* The minimum needed to perform matching (user_cmnd must be dynamic). */
    user_host = user_shost = user_runhost = user_srunhost = "localhost";
    user_cmnd = strdup("/usr/bin/id");
    user_args = "-u";
    user_base = "id";
    runas_pw = sudo_getpwnam("root");
    if (user_cmnd == NULL || runas_pw == NULL)
	goto done;

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
    TAILQ_INSERT_TAIL(&snl, &sudo_nss_file, entries);
    init_parse_tree(&parse_tree, user_host, user_shost);
    sudo_nss_file.parse_tree = &parse_tree;

    /* Initialize defaults and parse sudoers. */
    init_defaults();
    init_parser("sudoers", false, true);
    sudoersrestart(fp);
    sudoersparse();
    reparent_parse_tree(&parse_tree);

    if (!parse_error) {
	/* Match user/host/command against parsed policy. */
	for (u = users; (user_name = *u) != NULL; u++) {
	    int cmnd_status;

	    sudo_user.pw = sudo_getpwnam(user_name);
	    if (sudo_user.pw == NULL)
		goto done;

	    sudoers_lookup(&snl, sudo_user.pw, &cmnd_status, false);

	    /* Match again as a pseudo-command (list, validate, etc). */
	    sudoers_lookup(&snl, sudo_user.pw, &cmnd_status, true);

	    /* Display privileges. */
	    display_privs(&snl, sudo_user.pw, false);
	    display_privs(&snl, sudo_user.pw, true);

	    sudo_pw_delref(sudo_user.pw);
	    sudo_user.pw = NULL;
	}
    }

done:
    /* Cleanup. */
    fclose(fp);
    free_parse_tree(&parse_tree);
    init_parser(NULL, false, true);
    if (sudo_user.pw != NULL)
	sudo_pw_delref(sudo_user.pw);
    if (runas_pw != NULL)
	sudo_pw_delref(runas_pw);
    sudo_freepwcache();
    sudo_freegrcache();
    free(user_cmnd);
    free(safe_cmnd);
    memset(&sudo_user, 0, sizeof(sudo_user));

    return 0;
}
