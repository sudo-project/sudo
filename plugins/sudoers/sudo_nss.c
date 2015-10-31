/*
 * Copyright (c) 2007-2015 Todd C. Miller <Todd.Miller@courtesan.com>
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

#include <stdio.h>
#include <stdlib.h>
#ifdef HAVE_STRING_H
# include <string.h>
#endif /* HAVE_STRING_H */
#ifdef HAVE_STRINGS_H
# include <strings.h>
#endif /* HAVE_STRINGS_H */
#include <unistd.h>
#include <pwd.h>
#include <grp.h>
#include <ctype.h>

#include "sudoers.h"
#include "sudo_lbuf.h"

extern struct sudo_nss sudo_nss_file;
#ifdef HAVE_LDAP
extern struct sudo_nss sudo_nss_ldap;
#endif
#ifdef HAVE_SSSD
extern struct sudo_nss sudo_nss_sss;
#endif

/* Make sure we have not already inserted the nss entry. */
#define SUDO_NSS_CHECK_UNUSED(nss, tag)					       \
    if (nss.entries.tqe_next != NULL || nss.entries.tqe_prev != NULL) {      \
	sudo_warnx("internal error: nsswitch entry \"%s\" already in use",     \
	    tag);							       \
	continue;							       \
    }

#if (defined(HAVE_LDAP) || defined(HAVE_SSSD)) && defined(_PATH_NSSWITCH_CONF)
/*
 * Read in /etc/nsswitch.conf
 * Returns a tail queue of matches.
 */
struct sudo_nss_list *
sudo_read_nss(void)
{
    FILE *fp;
    char *line = NULL;
    size_t linesize = 0;
#ifdef HAVE_SSSD
    bool saw_sss = false;
#endif
#ifdef HAVE_LDAP
    bool saw_ldap = false;
#endif
    bool saw_files = false;
    bool got_match = false;
    static struct sudo_nss_list snl = TAILQ_HEAD_INITIALIZER(snl);
    debug_decl(sudo_read_nss, SUDOERS_DEBUG_NSS)

    if ((fp = fopen(_PATH_NSSWITCH_CONF, "r")) == NULL)
	goto nomatch;

    while (sudo_parseln(&line, &linesize, NULL, fp) != -1) {
	char *cp, *last;

	/* Skip blank or comment lines */
	if (*line == '\0')
	    continue;

	/* Look for a line starting with "sudoers:" */
	if (strncasecmp(line, "sudoers:", 8) != 0)
	    continue;

	/* Parse line */
	for ((cp = strtok_r(line + 8, " \t", &last)); cp != NULL; (cp = strtok_r(NULL, " \t", &last))) {
	    if (strcasecmp(cp, "files") == 0 && !saw_files) {
		SUDO_NSS_CHECK_UNUSED(sudo_nss_file, "files");
		TAILQ_INSERT_TAIL(&snl, &sudo_nss_file, entries);
		got_match = saw_files = true;
#ifdef HAVE_LDAP
	    } else if (strcasecmp(cp, "ldap") == 0 && !saw_ldap) {
		SUDO_NSS_CHECK_UNUSED(sudo_nss_ldap, "ldap");
		TAILQ_INSERT_TAIL(&snl, &sudo_nss_ldap, entries);
		got_match = saw_ldap = true;
#endif
#ifdef HAVE_SSSD
	    } else if (strcasecmp(cp, "sss") == 0 && !saw_sss) {
		SUDO_NSS_CHECK_UNUSED(sudo_nss_sss, "sss");
		TAILQ_INSERT_TAIL(&snl, &sudo_nss_sss, entries);
		got_match = saw_sss = true;
#endif
	    } else if (strcasecmp(cp, "[NOTFOUND=return]") == 0 && got_match) {
		/* NOTFOUND affects the most recent entry */
		TAILQ_LAST(&snl, sudo_nss_list)->ret_if_notfound = true;
		got_match = false;
	    } else if (strcasecmp(cp, "[SUCCESS=return]") == 0 && got_match) {
		/* SUCCESS affects the most recent entry */
		TAILQ_LAST(&snl, sudo_nss_list)->ret_if_found = true;
		got_match = false;
	    } else
		got_match = false;
	}
	/* Only parse the first "sudoers:" line */
	break;
    }
    free(line);
    fclose(fp);

nomatch:
    /* Default to files only if no matches */
    if (TAILQ_EMPTY(&snl))
	TAILQ_INSERT_TAIL(&snl, &sudo_nss_file, entries);

    debug_return_ptr(&snl);
}

#else /* (HAVE_LDAP || HAVE_SSSD) && _PATH_NSSWITCH_CONF */

# if (defined(HAVE_LDAP) || defined(HAVE_SSSD)) && defined(_PATH_NETSVC_CONF)

/*
 * Read in /etc/netsvc.conf (like nsswitch.conf on AIX)
 * Returns a tail queue of matches.
 */
struct sudo_nss_list *
sudo_read_nss(void)
{
    FILE *fp;
    char *cp, *ep, *last, *line = NULL;
    size_t linesize = 0;
#ifdef HAVE_SSSD
    bool saw_sss = false;
#endif
    bool saw_files = false;
    bool saw_ldap = false;
    bool got_match = false;
    static struct sudo_nss_list snl = TAILQ_HEAD_INITIALIZER(snl);
    debug_decl(sudo_read_nss, SUDOERS_DEBUG_NSS)

    if ((fp = fopen(_PATH_NETSVC_CONF, "r")) == NULL)
	goto nomatch;

    while (sudo_parseln(&line, &linesize, NULL, fp) != -1) {
	/* Skip blank or comment lines */
	if (*(cp = line) == '\0')
	    continue;

	/* Look for a line starting with "sudoers = " */
	if (strncasecmp(cp, "sudoers", 7) != 0)
	    continue;
	cp += 7;
	while (isspace((unsigned char)*cp))
	    cp++;
	if (*cp++ != '=')
	    continue;

	/* Parse line */
	for ((cp = strtok_r(cp, ",", &last)); cp != NULL; (cp = strtok_r(NULL, ",", &last))) {
	    /* Trim leading whitespace. */
	    while (isspace((unsigned char)*cp))
		cp++;

	    if (!saw_files && strncasecmp(cp, "files", 5) == 0 &&
		(isspace((unsigned char)cp[5]) || cp[5] == '\0')) {
		TAILQ_INSERT_TAIL(&snl, &sudo_nss_file, entries);
		got_match = saw_files = true;
		ep = &cp[5];
#ifdef HAVE_LDAP
	    } else if (!saw_ldap && strncasecmp(cp, "ldap", 4) == 0 &&
		(isspace((unsigned char)cp[4]) || cp[4] == '\0')) {
		TAILQ_INSERT_TAIL(&snl, &sudo_nss_ldap, entries);
		got_match = saw_ldap = true;
		ep = &cp[4];
#endif
#ifdef HAVE_SSSD
	    } else if (!saw_sss && strncasecmp(cp, "sss", 3) == 0 &&
		(isspace((unsigned char)cp[3]) || cp[3] == '\0')) {
		TAILQ_INSERT_TAIL(&snl, &sudo_nss_sss, entries);
		got_match = saw_sss = true;
		ep = &cp[3];
#endif
	    } else {
		got_match = false;
	    }

	    /* check for = auth qualifier */
	    if (got_match && *ep) {
		cp = ep;
		while (isspace((unsigned char)*cp) || *cp == '=')
		    cp++;
		if (strncasecmp(cp, "auth", 4) == 0 &&
		    (isspace((unsigned char)cp[4]) || cp[4] == '\0')) {
		    TAILQ_LAST(&snl, sudo_nss_list)->ret_if_found = true;
		}
	    }
	}
	/* Only parse the first "sudoers" line */
	break;
    }
    fclose(fp);

nomatch:
    /* Default to files only if no matches */
    if (TAILQ_EMPTY(&snl))
	TAILQ_INSERT_TAIL(&snl, &sudo_nss_file, entries);

    debug_return_ptr(&snl);
}

# else /* !_PATH_NETSVC_CONF && !_PATH_NSSWITCH_CONF */

/*
 * Non-nsswitch.conf version with hard-coded order.
 */
struct sudo_nss_list *
sudo_read_nss(void)
{
    static struct sudo_nss_list snl = TAILQ_HEAD_INITIALIZER(snl);
    debug_decl(sudo_read_nss, SUDOERS_DEBUG_NSS)

#  ifdef HAVE_SSSD
    TAILQ_INSERT_TAIL(&snl, &sudo_nss_sss, entries);
#  endif
#  ifdef HAVE_LDAP
    TAILQ_INSERT_TAIL(&snl, &sudo_nss_ldap, entries);
#  endif
    TAILQ_INSERT_TAIL(&snl, &sudo_nss_file, entries);

    debug_return_ptr(&snl);
}

# endif /* !HAVE_LDAP || !_PATH_NETSVC_CONF */

#endif /* HAVE_LDAP && _PATH_NSSWITCH_CONF */

static int
output(const char *buf)
{
    struct sudo_conv_message msg;
    struct sudo_conv_reply repl;
    debug_decl(output, SUDOERS_DEBUG_NSS)

    /* Call conversation function */
    memset(&msg, 0, sizeof(msg));
    msg.msg_type = SUDO_CONV_INFO_MSG;
    msg.msg = buf;
    memset(&repl, 0, sizeof(repl));
    if (sudo_conv(1, &msg, &repl, NULL) == -1)
	debug_return_int(0);
    debug_return_int(strlen(buf));
}

/*
 * Print out privileges for the specified user.
 * Returns true if the user is allowed to run commands, false if not
 * or -1 on error.
 */
int
display_privs(struct sudo_nss_list *snl, struct passwd *pw)
{
    struct sudo_nss *nss;
    struct sudo_lbuf defs, privs;
    struct stat sb;
    int cols, count, olen;
    debug_decl(display_privs, SUDOERS_DEBUG_NSS)

    cols = sudo_user.cols;
    if (fstat(STDOUT_FILENO, &sb) == 0 && S_ISFIFO(sb.st_mode))
	cols = 0;
    sudo_lbuf_init(&defs, output, 4, NULL, cols);
    sudo_lbuf_init(&privs, output, 8, NULL, cols);

    /* Display defaults from all sources. */
    sudo_lbuf_append(&defs, _("Matching Defaults entries for %s on %s:\n"),
	pw->pw_name, user_srunhost);
    count = 0;
    TAILQ_FOREACH(nss, snl, entries) {
	const int n = nss->display_defaults(nss, pw, &defs);
	if (n == -1)
	    goto bad;
	count += n;
    }
    if (count) {
	sudo_lbuf_append(&defs, "\n\n");
    } else {
	/* Undo Defaults header. */
	defs.len = 0;
    }

    /* Display Runas and Cmnd-specific defaults from all sources. */
    olen = defs.len;
    sudo_lbuf_append(&defs, _("Runas and Command-specific defaults for %s:\n"),
	pw->pw_name);
    count = 0;
    TAILQ_FOREACH(nss, snl, entries) {
	const int n = nss->display_bound_defaults(nss, pw, &defs);
	if (n == -1)
	    goto bad;
	count += n;
    }
    if (count) {
	sudo_lbuf_append(&defs, "\n\n");
    } else {
	/* Undo Defaults header. */
	defs.len = olen;
    }

    /* Display privileges from all sources. */
    sudo_lbuf_append(&privs,
	_("User %s may run the following commands on %s:\n"),
	pw->pw_name, user_srunhost);
    count = 0;
    TAILQ_FOREACH(nss, snl, entries) {
	const int n = nss->display_privs(nss, pw, &privs);
	if (n == -1)
	    goto bad;
	count += n;
    }
    if (count == 0) {
	defs.len = 0;
	privs.len = 0;
	sudo_lbuf_append(&privs,
	    _("User %s is not allowed to run sudo on %s.\n"),
	    pw->pw_name, user_shost);
    }
    if (sudo_lbuf_error(&defs) || sudo_lbuf_error(&privs))
	goto bad;

    sudo_lbuf_print(&defs);
    sudo_lbuf_print(&privs);

    sudo_lbuf_destroy(&defs);
    sudo_lbuf_destroy(&privs);

    debug_return_int(count > 0);
bad:
    sudo_lbuf_destroy(&defs);
    sudo_lbuf_destroy(&privs);

    debug_return_int(-1);
}

/*
 * Check user_cmnd against sudoers and print the matching entry if the
 * command is allowed.
 * Returns true if the command is allowed, false if not or -1 on error.
 */
int
display_cmnd(struct sudo_nss_list *snl, struct passwd *pw)
{
    struct sudo_nss *nss;
    debug_decl(display_cmnd, SUDOERS_DEBUG_NSS)

    /* XXX - display_cmnd return value is backwards */
    /* XXX - doesn't handle commands allowed by one backend denied by another. */
    TAILQ_FOREACH(nss, snl, entries) {
	switch (nss->display_cmnd(nss, pw)) {
	    case 0:
		debug_return_int(true);
	    case -1:
		debug_return_int(-1);
	}
    }
    debug_return_int(false);
}
