/*
 * Copyright (c) 1996, 1998-2005, 2007-2013
 *	Todd C. Miller <Todd.Miller@courtesan.com>
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
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
 * OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
 * ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * Sponsored in part by the Defense Advanced Research Projects
 * Agency (DARPA) and Air Force Research Laboratory, Air Force
 * Materiel Command, USAF, under agreement number F39502-99-1-0512.
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
# include <string.h>
#endif /* HAVE_STRING_H */
#ifdef HAVE_STRINGS_H
# include <strings.h>
#endif /* HAVE_STRINGS_H */
#ifdef HAVE_UNISTD_H
# include <unistd.h>
#endif /* HAVE_UNISTD_H */
#if defined(HAVE_MALLOC_H) && !defined(STDC_HEADERS)
# include <malloc.h>
#endif /* HAVE_MALLOC_H && !STDC_HEADERS */
#include <ctype.h>
#include <errno.h>

#include "sudoers.h"
#include "parse.h"
#include "toke.h"
#include <gram.h>

static int arg_len = 0;
static int arg_size = 0;

bool
fill_txt(const char *src, int len, int olen)
{
    char *dst;
    debug_decl(fill_txt, SUDO_DEBUG_PARSER)

    dst = olen ? realloc(sudoerslval.string, olen + len + 1) : malloc(len + 1);
    if (dst == NULL) {
	warning(NULL);
	sudoerserror(NULL);
	debug_return_bool(false);
    }
    sudoerslval.string = dst;

    /* Copy the string and collapse any escaped characters. */
    dst += olen;
    while (len--) {
	if (*src == '\\' && len) {
	    if (src[1] == 'x' && len >= 3 && 
		isxdigit((unsigned char) src[2]) &&
		isxdigit((unsigned char) src[3])) {
		*dst++ = hexchar(src + 2);
		src += 4;
		len -= 3;
	    } else {
		src++;
		len--;
		*dst++ = *src++;
	    }
	} else {
	    *dst++ = *src++;
	}
    }
    *dst = '\0';
    debug_return_bool(true);
}

bool
append(const char *src, int len)
{
    int olen = 0;
    debug_decl(append, SUDO_DEBUG_PARSER)

    if (sudoerslval.string != NULL)
	olen = strlen(sudoerslval.string);

    debug_return_bool(fill_txt(src, len, olen));
}

#define SPECIAL(c) \
    ((c) == ',' || (c) == ':' || (c) == '=' || (c) == ' ' || (c) == '\t' || (c) == '#')

bool
fill_cmnd(const char *src, int len)
{
    char *dst;
    int i;
    debug_decl(fill_cmnd, SUDO_DEBUG_PARSER)

    arg_len = arg_size = 0;

    dst = sudoerslval.command.cmnd = (char *) malloc(len + 1);
    if (sudoerslval.command.cmnd == NULL) {
	warning(NULL);
	sudoerserror(NULL);
	debug_return_bool(false);
    }

    /* Copy the string and collapse any escaped sudo-specific characters. */
    for (i = 0; i < len; i++) {
	if (src[i] == '\\' && i != len - 1 && SPECIAL(src[i + 1]))
	    *dst++ = src[++i];
	else
	    *dst++ = src[i];
    }
    *dst = '\0';

    sudoerslval.command.args = NULL;
    debug_return_bool(true);
}

bool
fill_args(const char *s, int len, int addspace)
{
    int new_len;
    char *p;
    debug_decl(fill_args, SUDO_DEBUG_PARSER)

    if (sudoerslval.command.args == NULL) {
	addspace = 0;
	new_len = len;
    } else
	new_len = arg_len + len + addspace;

    if (new_len >= arg_size) {
	/* Allocate more space than we need for subsequent args */
	while (new_len >= (arg_size += COMMANDARGINC))
	    ;

	p = sudoerslval.command.args ?
	    (char *) realloc(sudoerslval.command.args, arg_size) :
	    (char *) malloc(arg_size);
	if (p == NULL) {
	    efree(sudoerslval.command.args);
	    warning(NULL);
	    sudoerserror(NULL);
	    debug_return_bool(false);
	} else
	    sudoerslval.command.args = p;
    }

    /* Efficiently append the arg (with a leading space if needed). */
    p = sudoerslval.command.args + arg_len;
    if (addspace)
	*p++ = ' ';
    if (strlcpy(p, s, arg_size - (p - sudoerslval.command.args)) != (size_t)len) {
	warningx(U_("fill_args: buffer overflow"));	/* paranoia */
	sudoerserror(NULL);
	debug_return_bool(false);
    }
    arg_len = new_len;
    debug_return_bool(true);
}

/*
 * Check to make sure an IPv6 address does not contain multiple instances
 * of the string "::".  Assumes strlen(s) >= 1.
 * Returns true if address is valid else false.
 */
bool
ipv6_valid(const char *s)
{
    int nmatch = 0;
    debug_decl(ipv6_valid, SUDO_DEBUG_PARSER)

    for (; *s != '\0'; s++) {
	if (s[0] == ':' && s[1] == ':') {
	    if (++nmatch > 1)
		break;
	}
	if (s[0] == '/')
	    nmatch = 0;			/* reset if we hit netmask */
    }

    debug_return_bool(nmatch <= 1);
}
