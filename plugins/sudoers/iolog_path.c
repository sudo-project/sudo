/*
 * Copyright (c) 2011 Todd C. Miller <Todd.Miller@courtesan.com>
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
# if defined(HAVE_MEMORY_H) && !defined(STDC_HEADERS)
#  include <memory.h>
# endif
# include <string.h>
#endif /* HAVE_STRING_H */
#ifdef HAVE_STRINGS_H
# include <strings.h>
#endif /* HAVE_STRINGS_H */
#ifdef HAVE_SETLOCALE
# include <locale.h>
#endif
#include <pwd.h>
#include <grp.h>
#include <time.h>

#include "sudoers.h"

struct path_escape {
    const char *name;
    size_t (*copy_fn)(char *, size_t);
};

static size_t fill_seq(char *, size_t);
static size_t fill_user(char *, size_t);
static size_t fill_group(char *, size_t);
static size_t fill_runas_user(char *, size_t);
static size_t fill_runas_group(char *, size_t);
static size_t fill_hostname(char *, size_t);
static size_t fill_command(char *, size_t);

static struct path_escape escapes[] = {
    { "seq", fill_seq },
    { "user", fill_user },
    { "group", fill_group },
    { "runas_user", fill_runas_user },
    { "runas_group", fill_runas_group },
    { "hostname", fill_hostname },
    { "command", fill_command },
    { NULL, NULL }
};

static size_t
fill_seq(char *str, size_t strsize)
{
    int len;

    /* Path is of the form /var/log/sudo-io/00/00/01. */
    len = snprintf(str, strsize, "%c%c/%c%c/%c%c", sudo_user.sessid[0],
	sudo_user.sessid[1], sudo_user.sessid[2], sudo_user.sessid[3],
	sudo_user.sessid[4], sudo_user.sessid[5]);
    if (len < 0)
	return strsize;	/* handle non-standard snprintf() */
    return (size_t)len;
}

static size_t
fill_user(char *str, size_t strsize)
{
    return strlcpy(str, user_name, strsize);
}

static size_t
fill_group(char *str, size_t strsize)
{
    struct group *grp;
    size_t len;

    if ((grp = sudo_getgrgid(user_gid)) != NULL) {
	len = strlcpy(str, grp->gr_name, strsize);
	gr_delref(grp);
    } else {
	len = strlen(str);
	len = snprintf(str + len, strsize - len, "#%u",
	    (unsigned int) user_gid);
    }
    return len;
}

static size_t
fill_runas_user(char *str, size_t strsize)
{
    return strlcpy(str, runas_pw->pw_name, strsize);
}

static size_t
fill_runas_group(char *str, size_t strsize)
{
    struct group *grp;
    size_t len;

    if (runas_gr != NULL) {
	len = strlcpy(str, runas_gr->gr_name, strsize);
    } else {
	if ((grp = sudo_getgrgid(runas_pw->pw_gid)) != NULL) {
	    len = strlcpy(str, grp->gr_name, strsize);
	    gr_delref(grp);
	} else {
	    len = strlen(str);
	    len = snprintf(str + len, strsize - len, "#%u",
		(unsigned int) runas_pw->pw_gid);
	}
    }
    return len;
}

static size_t
fill_hostname(char *str, size_t strsize)
{
    return strlcpy(str, user_shost, strsize);
}

static size_t
fill_command(char *str, size_t strsize)
{
    return strlcpy(str, user_base, strsize);
}

char *
expand_iolog_path(const char *prefix, const char *dir, const char *file,
    char **slashp)
{
    size_t plen = 0, psize = 1024;
    char *path, *dst;
    const char *src = dir, *ep;
    int pass, strfit = FALSE;

    /* Concatenate dir + file -> path, expanding any escape sequences. */
    dst = path = emalloc(psize);
    *path = '\0';

    /* Trim leading slashes from file component. */
    while (*file == '/')
	file++;

    if (prefix != NULL) {
	plen = strlcpy(path, prefix, psize);
	dst += plen;
    }
    for (pass = 0; pass < 3; pass++) {
	switch (pass) {
	case 0:
	    src = dir;
	    break;
	case 1:
	    /* Trim trailing slashes from dir component. */
	    while (dst > path && dst[-1] == '/')
		dst--;
	    if (slashp)
		*slashp = dst;
	    src = "/";
	    break;
	case 2:
	    src = file;
	    break;
	}
	for (; *src != '\0'; src++) {
	    if (src[0] == '%') {
		if (src[1] == '{') {
		    ep = strchr(src + 2, '}');
		    if (ep != NULL) {
			struct path_escape *esc;
			size_t len = (size_t)(ep - src - 2);
			for (esc = escapes; esc->name != NULL; esc++) {
			    if (strncmp(src + 2, esc->name, len) == 0 &&
				esc->name[len] == '\0')
				break;
			}
			for (;;) {
			    len = esc->copy_fn(dst, psize - (dst - path));
			    if (len < psize - (dst - path))
				break;
			    path = erealloc3(path, 2, psize);
			    psize *= 2;
			    dst = path + plen;
			}
			dst += len;
			plen += len;
			src = ep;
			continue;
		    }
		} else {
		    /* May need strftime() */
		    strfit = 1;
		}
	    }
	    /* Need at least 2 chars, including the NUL terminator. */
	    if (plen + 2 >= psize) {
		path = erealloc3(path, 2, psize);
		psize *= 2;
		dst = path + plen;
	    }
	    *dst++ = *src;
	    plen++;
	}
    }
    *dst = '\0';

    if (strfit) {
	time_t now;
	struct tm *timeptr;
	char *buf = NULL;

	time(&now);
	timeptr = localtime(&now);

#ifdef HAVE_SETLOCALE
	if (!setlocale(LC_ALL, def_sudoers_locale)) {
	    warningx("unable to set locale to \"%s\", using \"C\"",
		def_sudoers_locale);
	    setlocale(LC_ALL, "C");
	}
#endif
	/* Double the size of the buffer until it is big enough to expand. */
	do {
	    psize *= 2;
	    buf = erealloc(buf, psize);
	    buf[psize - 1] = '\0';
	} while (!strftime(buf, psize, path, timeptr) || buf[psize - 1] != '\0');
#ifdef HAVE_SETLOCALE
	setlocale(LC_ALL, "");
#endif
	if (slashp)
	    *slashp = buf + (*slashp - path);
	efree(path);
	path = buf;
    }

    return path;
}
