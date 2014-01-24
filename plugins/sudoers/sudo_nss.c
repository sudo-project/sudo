/*
 * Copyright (c) 2007-2013 Todd C. Miller <Todd.Miller@courtesan.com>
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
#ifdef STDC_HEADERS
# include <stdlib.h>
# include <stddef.h>
#else
# ifdef HAVE_STDLIB_H
#  include <stdlib.h>
# endif
#endif /* STDC_HEADERS */
#ifdef HAVE_STRING_H
# include <string.h>
#endif /* HAVE_STRING_H */
#ifdef HAVE_STRINGS_H
# include <strings.h>
#endif /* HAVE_STRINGS_H */
#ifdef HAVE_UNISTD_H
# include <unistd.h>
#endif /* HAVE_UNISTD_H */
#include <pwd.h>
#include <grp.h>
#include <ctype.h>

#include "sudoers.h"
#include "lbuf.h"

extern struct sudo_nss sudo_nss_file;
#ifdef HAVE_LDAP
extern struct sudo_nss sudo_nss_ldap;
#endif
#ifdef HAVE_SSSD
extern struct sudo_nss sudo_nss_sss;
#endif

#if (defined(HAVE_LDAP) || defined(HAVE_SSSD)) && defined(_PATH_NSSWITCH_CONF)
/*
 * Read in /etc/nsswitch.conf
 * Returns a tail queue of matches.
 */
struct sudo_nss_list *
sudo_read_nss(void)
{
    FILE *fp;
    char *cp, *line = NULL;
    size_t linesize = 0;
#ifdef HAVE_SSSD
    bool saw_sss = false;
#endif
    bool saw_files = false;
    bool saw_ldap = false;
    bool got_match = false;
    static struct sudo_nss_list snl = TAILQ_HEAD_INITIALIZER(snl);
    debug_decl(sudo_read_nss, SUDO_DEBUG_NSS)

    if ((fp = fopen(_PATH_NSSWITCH_CONF, "r")) == NULL)
	goto nomatch;

    while (sudo_parseln(&line, &linesize, NULL, fp) != -1) {
	/* Skip blank or comment lines */
	if (*line == '\0')
	    continue;

	/* Look for a line starting with "sudoers:" */
	if (strncasecmp(line, "sudoers:", 8) != 0)
	    continue;

	/* Parse line */
	for ((cp = strtok(line + 8, " \t")); cp != NULL; (cp = strtok(NULL, " \t"))) {
	    if (strcasecmp(cp, "files") == 0 && !saw_files) {
		TAILQ_INSERT_TAIL(&snl, &sudo_nss_file, entries);
		got_match = true;
#ifdef HAVE_LDAP
	    } else if (strcasecmp(cp, "ldap") == 0 && !saw_ldap) {
		TAILQ_INSERT_TAIL(&snl, &sudo_nss_ldap, entries);
		got_match = true;
#endif
#ifdef HAVE_SSSD
	    } else if (strcasecmp(cp, "sss") == 0 && !saw_sss) {
		TAILQ_INSERT_TAIL(&snl, &sudo_nss_sss, entries);
		got_match = true;
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
    char *cp, *ep, *line = NULL;
    size_t linesize = 0;
#ifdef HAVE_SSSD
    bool saw_sss = false;
#endif
    bool saw_files = false;
    bool saw_ldap = false;
    bool got_match = false;
    static struct sudo_nss_list snl = TAILQ_HEAD_INITIALIZER(snl);
    debug_decl(sudo_read_nss, SUDO_DEBUG_NSS)

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
	for ((cp = strtok(cp, ",")); cp != NULL; (cp = strtok(NULL, ","))) {
	    /* Trim leading whitespace. */
	    while (isspace((unsigned char)*cp))
		cp++;

	    if (!saw_files && strncasecmp(cp, "files", 5) == 0 &&
		(isspace((unsigned char)cp[5]) || cp[5] == '\0')) {
		TAILQ_INSERT_TAIL(&snl, &sudo_nss_file, entries);
		got_match = true;
		ep = &cp[5];
#ifdef HAVE_LDAP
	    } else if (!saw_ldap && strncasecmp(cp, "ldap", 4) == 0 &&
		(isspace((unsigned char)cp[4]) || cp[4] == '\0')) {
		TAILQ_INSERT_TAIL(&snl, &sudo_nss_ldap, entries);
		got_match = true;
		ep = &cp[4];
#endif
#ifdef HAVE_SSSD
	    } else if (!saw_sss && strncasecmp(cp, "sss", 3) == 0 &&
		(isspace((unsigned char)cp[3]) || cp[3] == '\0')) {
		TAILQ_INSERT_TAIL(&snl, &sudo_nss_sss, entries);
		got_match = true;
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
    debug_decl(sudo_read_nss, SUDO_DEBUG_NSS)

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
    debug_decl(output, SUDO_DEBUG_NSS)

    /* Call conversation function */
    memset(&msg, 0, sizeof(msg));
    msg.msg_type = SUDO_CONV_INFO_MSG;
    msg.msg = buf;
    memset(&repl, 0, sizeof(repl));
    if (sudo_conv(1, &msg, &repl) == -1)
	debug_return_int(0);
    debug_return_int(strlen(buf));
}

/*
 * Print out privileges for the specified user.
 * We only get here if the user is allowed to run something.
 */
void
display_privs(struct sudo_nss_list *snl, struct passwd *pw)
{
    struct sudo_nss *nss;
    struct lbuf defs, privs;
    struct stat sb;
    int cols, count, olen;
    debug_decl(display_privs, SUDO_DEBUG_NSS)

    cols = sudo_user.cols;
    if (fstat(STDOUT_FILENO, &sb) == 0 && S_ISFIFO(sb.st_mode))
	cols = 0;
    lbuf_init(&defs, output, 4, NULL, cols);
    lbuf_init(&privs, output, 8, NULL, cols);

    /* Display defaults from all sources. */
    lbuf_append(&defs, _("Matching Defaults entries for %s on %s:\n"),
	pw->pw_name, user_srunhost);
    count = 0;
    TAILQ_FOREACH(nss, snl, entries) {
	count += nss->display_defaults(nss, pw, &defs);
    }
    if (count)
	lbuf_append(&defs, "\n\n");
    else
	defs.len = 0;

    /* Display Runas and Cmnd-specific defaults from all sources. */
    olen = defs.len;
    lbuf_append(&defs, _("Runas and Command-specific defaults for %s:\n"),
	pw->pw_name);
    count = 0;
    TAILQ_FOREACH(nss, snl, entries) {
	count += nss->display_bound_defaults(nss, pw, &defs);
    }
    if (count)
	lbuf_append(&defs, "\n\n");
    else
	defs.len = olen;

    /* Display privileges from all sources. */
    lbuf_append(&privs,
	_("User %s may run the following commands on %s:\n"),
	pw->pw_name, user_srunhost);
    count = 0;
    TAILQ_FOREACH(nss, snl, entries) {
	count += nss->display_privs(nss, pw, &privs);
    }
    if (count == 0) {
	defs.len = 0;
	privs.len = 0;
	lbuf_append(&privs, _("User %s is not allowed to run sudo on %s.\n"),
	    pw->pw_name, user_shost);
    }
    lbuf_print(&defs);
    lbuf_print(&privs);

    lbuf_destroy(&defs);
    lbuf_destroy(&privs);

    debug_return;
}

/*
 * Check user_cmnd against sudoers and print the matching entry if the
 * command is allowed.
 * Returns true if the command is allowed, else false.
 */
bool
display_cmnd(struct sudo_nss_list *snl, struct passwd *pw)
{
    struct sudo_nss *nss;
    debug_decl(display_cmnd, SUDO_DEBUG_NSS)

    TAILQ_FOREACH(nss, snl, entries) {
	if (nss->display_cmnd(nss, pw) == 0)
	    debug_return_bool(true);
    }
    debug_return_bool(false);
}
