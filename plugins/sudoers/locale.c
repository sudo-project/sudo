/*
 * Copyright (c) 2012-2014 Todd C. Miller <Todd.Miller@courtesan.com>
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
#include <stdlib.h>
#ifdef HAVE_STRING_H
# include <string.h>
#endif /* HAVE_STRING_H */
#ifdef HAVE_STRINGS_H
# include <strings.h>
#endif /* HAVE_STRINGS_H */
#ifdef HAVE_STDBOOL_H
# include <stdbool.h>
#else
# include "compat/stdbool.h"
#endif /* HAVE_STDBOOL_H */

#define DEFAULT_TEXT_DOMAIN	"sudoers"
#include "sudo_gettext.h"	/* must be included before sudo_compat.h */

#include "sudo_compat.h"
#include "sudo_fatal.h"
#include "logging.h"

static int current_locale = SUDOERS_LOCALE_USER;
static char *user_locale;
static char *sudoers_locale;

int
sudoers_getlocale(void)
{
    return current_locale;
}

bool
sudoers_initlocale(const char *ulocale, const char *slocale)
{
    if (ulocale != NULL) {
	free(user_locale);
	if ((user_locale = strdup(ulocale)) == NULL)
	    return false;
    }
    if (slocale != NULL) {
	free(sudoers_locale);
	if ((sudoers_locale = strdup(slocale)) == NULL)
	    return false;
    }
    return true;
}

/*
 * Set locale to user or sudoers value.
 * Returns true on success and false on failure,
 * If prevlocale is non-NULL it will be filled in with the
 * old SUDOERS_LOCALE_* value.
 */
bool
sudoers_setlocale(int newlocale, int *prevlocale)
{
    char *res = NULL;

    switch (newlocale) {
	case SUDOERS_LOCALE_USER:
	    if (prevlocale)
		*prevlocale = current_locale;
	    if (current_locale != SUDOERS_LOCALE_USER) {
		current_locale = SUDOERS_LOCALE_USER;
		res = setlocale(LC_ALL, user_locale ? user_locale : "");
		if (res != NULL && user_locale == NULL) {
		    user_locale = setlocale(LC_ALL, NULL);
		    if (user_locale != NULL)
			user_locale = strdup(user_locale);
		    if (user_locale == NULL)
			res = NULL;
		}
	    }
	    break;
	case SUDOERS_LOCALE_SUDOERS:
	    if (prevlocale)
		*prevlocale = current_locale;
	    if (current_locale != SUDOERS_LOCALE_SUDOERS) {
		current_locale = SUDOERS_LOCALE_SUDOERS;
		res = setlocale(LC_ALL, sudoers_locale ? sudoers_locale : "C");
		if (res == NULL && sudoers_locale != NULL) {
		    if (strcmp(sudoers_locale, "C") != 0) {
			free(sudoers_locale);
			sudoers_locale = strdup("C");
			if (sudoers_locale != NULL)
			    res = setlocale(LC_ALL, "C");
		    }
		}
	    }
	    break;
    }
    return res ? true : false;
}

bool
sudoers_warn_setlocale(bool restore, int *cookie)
{
    if (restore)
	return sudoers_setlocale(*cookie, NULL);
    return sudoers_setlocale(SUDOERS_LOCALE_USER, cookie);
}
