/*
 * Copyright (c) 2013 Todd C. Miller <Todd.Miller@courtesan.com>
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

#ifndef _SUDO_UTIL_H
#define _SUDO_UTIL_H

#ifdef HAVE_STDBOOL_H
# include <stdbool.h>
#else
# include "compat/stdbool.h"
#endif /* HAVE_STDBOOL_H */

/* aix.c */
void aix_prep_user(char *user, const char *tty);
void aix_restoreauthdb(void);
void aix_setauthdb(char *user);

/* atobool.c */
int atobool(const char *str);

/* atoid.c */
id_t atoid(const char *str, const char *sep, char **endp, const char **errstr);

/* atomode.c */
int atomode(const char *cp, const char **errstr);

/* fmt_string.h */
char *fmt_string(const char *var, const char *value);

/* gidlist.c */
int parse_gid_list(const char *gidstr, const gid_t *basegid, GETGROUPS_T **gidsp);

/* progname.c */
void initprogname(const char *);

/* setgroups.c */
int sudo_setgroups(int ngids, const GETGROUPS_T *gids);

/* term.c */
int term_cbreak(int);
int term_copy(int, int);
int term_noecho(int);
int term_raw(int, int);
int term_restore(int, int);

/* ttysize.c */
void get_ttysize(int *rowp, int *colp);

#endif /* _SUDO_UTIL_H */
