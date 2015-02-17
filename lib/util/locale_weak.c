/*
 * Copyright (c) 2013-2015 Todd C. Miller <Todd.Miller@courtesan.com>
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

#ifdef HAVE_SYS_WEAK_ALIAS

#include <stdio.h>
#include <stdlib.h>
#ifdef HAVE_STRING_H
# include <string.h>
#endif /* HAVE_STRING_H */
#ifdef HAVE_STRINGS_H
# include <strings.h>
#endif /* HAVE_STRINGS_H */

#define DEFAULT_TEXT_DOMAIN	"sudo"
#include "sudo_gettext.h"	/* must be included before sudo_compat.h */

#include "sudo_compat.h"
#include "sudo_fatal.h"

/*
 * Weak symbols for sudo_warn_gettext_v1() and sudo_warn_strerror_v1().
 * These stubs are provided to make libsudo_util link with no undefined
 * symbols.
 */

# ifdef HAVE_LIBINTL_H
/* We only need to swap locales in the plugin. */
char *
sudo_warn_gettext_weak(const char *msgid)
{
    return gettext(msgid);
}
#  if defined(HAVE_SYS_WEAK_ALIAS_ATTRIBUTE)
char *sudo_warn_gettext_v1(const char *msgid)
    __attribute__((weak, alias("sudo_warn_gettext_weak")));
#  elif defined(HAVE_SYS_WEAK_ALIAS_PRAGMA)
#   pragma weak sudo_warn_gettext_v1 = sudo_warn_gettext_weak
#  elif defined(HAVE_SYS_WEAK_ALIAS_HPSECONDARY)
#   pragma _HP_SECONDARY_DEF sudo_warn_gettext_weak sudo_warn_gettext_v1
#  elif defined(HAVE_SYS_WEAK_ALIAS_CRIDUPLICATE)
#   pragma _CRI duplicate sudo_warn_gettext_v1 as sudo_warn_gettext_weak
#  endif
# endif /* HAVE_LIBINTL_H */

/* We only need to swap locales in the plugin. */
char *
sudo_warn_strerror_weak(int errnum)
{
    return strerror(errnum);
}
# if defined(HAVE_SYS_WEAK_ALIAS_ATTRIBUTE)
char *sudo_warn_strerror_v1(int errnum)
    __attribute__((weak, alias("sudo_warn_strerror_weak")));
# elif defined(HAVE_SYS_WEAK_ALIAS_PRAGMA)
#  pragma weak sudo_warn_strerror_v1 = sudo_warn_strerror_weak
# elif defined(HAVE_SYS_WEAK_ALIAS_HPSECONDARY)
#  pragma _HP_SECONDARY_DEF sudo_warn_strerror_weak sudo_warn_strerror_v1
# elif defined(HAVE_SYS_WEAK_ALIAS_CRIDUPLICATE)
#  pragma _CRI duplicate sudo_warn_strerror_v1 as sudo_warn_strerror_weak
# endif

#endif /* HAVE_SYS_WEAK_ALIAS */
