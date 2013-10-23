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
 * OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
 * ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
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
#ifdef HAVE_UNISTD_H
# include <unistd.h>
#endif /* HAVE_UNISTD_H */
#include <ctype.h>

#include "missing.h"
#include "alloc.h"
#include "fatal.h"
#include "lbuf.h"
#include "sudo_debug.h"

void
lbuf_init(struct lbuf *lbuf, int (*output)(const char *),
    int indent, const char *continuation, int cols)
{
    debug_decl(lbuf_init, SUDO_DEBUG_UTIL)

    lbuf->output = output;
    lbuf->continuation = continuation;
    lbuf->indent = indent;
    lbuf->cols = cols;
    lbuf->len = 0;
    lbuf->size = 0;
    lbuf->buf = NULL;

    debug_return;
}

void
lbuf_destroy(struct lbuf *lbuf)
{
    debug_decl(lbuf_destroy, SUDO_DEBUG_UTIL)

    efree(lbuf->buf);
    lbuf->buf = NULL;

    debug_return;
}

static void
lbuf_expand(struct lbuf *lbuf, int extra)
{
    if (lbuf->len + extra + 1 >= lbuf->size) {
	do {
	    lbuf->size += 256;
	} while (lbuf->len + extra + 1 >= lbuf->size);
	lbuf->buf = erealloc(lbuf->buf, lbuf->size);
    }
}

/*
 * Parse the format and append strings, only %s and %% escapes are supported.
 * Any characters in set are quoted with a backslash.
 */
void
lbuf_append_quoted(struct lbuf *lbuf, const char *set, const char *fmt, ...)
{
    va_list ap;
    int len;
    char *cp, *s;
    debug_decl(lbuf_append_quoted, SUDO_DEBUG_UTIL)

    va_start(ap, fmt);
    while (*fmt != '\0') {
	if (fmt[0] == '%' && fmt[1] == 's') {
	    if ((s = va_arg(ap, char *)) == NULL)
		goto done;
	    while ((cp = strpbrk(s, set)) != NULL) {
		len = (int)(cp - s);
		lbuf_expand(lbuf, len + 2);
		memcpy(lbuf->buf + lbuf->len, s, len);
		lbuf->len += len;
		lbuf->buf[lbuf->len++] = '\\';
		lbuf->buf[lbuf->len++] = *cp;
		s = cp + 1;
	    }
	    if (*s != '\0') {
		len = strlen(s);
		lbuf_expand(lbuf, len);
		memcpy(lbuf->buf + lbuf->len, s, len);
		lbuf->len += len;
	    }
	    fmt += 2;
	    continue;
	}
	lbuf_expand(lbuf, 2);
	if (strchr(set, *fmt) != NULL)
	    lbuf->buf[lbuf->len++] = '\\';
	lbuf->buf[lbuf->len++] = *fmt++;
    }
done:
    if (lbuf->size != 0)
	lbuf->buf[lbuf->len] = '\0';
    va_end(ap);

    debug_return;
}

/*
 * Parse the format and append strings, only %s and %% escapes are supported.
 */
void
lbuf_append(struct lbuf *lbuf, const char *fmt, ...)
{
    va_list ap;
    int len;
    char *s;
    debug_decl(lbuf_append, SUDO_DEBUG_UTIL)

    va_start(ap, fmt);
    while (*fmt != '\0') {
	if (fmt[0] == '%' && fmt[1] == 's') {
	    if ((s = va_arg(ap, char *)) == NULL)
		goto done;
	    len = strlen(s);
	    lbuf_expand(lbuf, len);
	    memcpy(lbuf->buf + lbuf->len, s, len);
	    lbuf->len += len;
	    fmt += 2;
	    continue;
	}
	lbuf_expand(lbuf, 1);
	lbuf->buf[lbuf->len++] = *fmt++;
    }
done:
    if (lbuf->size != 0)
	lbuf->buf[lbuf->len] = '\0';
    va_end(ap);

    debug_return;
}

static void
lbuf_println(struct lbuf *lbuf, char *line, int len)
{
    char *cp, save;
    int i, have, contlen;
    debug_decl(lbuf_println, SUDO_DEBUG_UTIL)

    contlen = lbuf->continuation ? strlen(lbuf->continuation) : 0;

    /*
     * Print the buffer, splitting the line as needed on a word
     * boundary.
     */
    cp = line;
    have = lbuf->cols;
    while (cp != NULL && *cp != '\0') {
	char *ep = NULL;
	int need = len - (int)(cp - line);

	if (need > have) {
	    have -= contlen;		/* subtract for continuation char */
	    if ((ep = memrchr(cp, ' ', have)) == NULL)
		ep = memchr(cp + have, ' ', need - have);
	    if (ep != NULL)
		need = (int)(ep - cp);
	}
	if (cp != line) {
	    /* indent continued lines */
	    /* XXX - build up string instead? */
	    for (i = 0; i < lbuf->indent; i++)
		lbuf->output(" ");
	}
	/* NUL-terminate cp for the output function and restore afterwards */
	save = cp[need];
	cp[need] = '\0';
	lbuf->output(cp);
	cp[need] = save;
	cp = ep;

	/*
	 * If there is more to print, reset have, incremement cp past
	 * the whitespace, and print a line continuaton char if needed.
	 */
	if (cp != NULL) {
	    have = lbuf->cols - lbuf->indent;
	    ep = line + len;
	    while (cp < ep && isblank((unsigned char)*cp)) {
		cp++;
	    }
	    if (contlen)
		lbuf->output(lbuf->continuation);
	}
	lbuf->output("\n");
    }

    debug_return;
}

/*
 * Print the buffer with word wrap based on the tty width.
 * The lbuf is reset on return.
 */
void
lbuf_print(struct lbuf *lbuf)
{
    char *cp, *ep;
    int len;
    debug_decl(lbuf_print, SUDO_DEBUG_UTIL)

    if (lbuf->buf == NULL || lbuf->len == 0)
	goto done;

    /* For very small widths just give up... */
    len = lbuf->continuation ? strlen(lbuf->continuation) : 0;
    if (lbuf->cols <= lbuf->indent + len + 20) {
	if (lbuf->len > 0) {
	    lbuf->buf[lbuf->len] = '\0';
	    lbuf->output(lbuf->buf);
	    if (lbuf->buf[lbuf->len - 1] != '\n')
		lbuf->output("\n");
	}
	goto done;
    }

    /* Print each line in the buffer */
    for (cp = lbuf->buf; cp != NULL && *cp != '\0'; ) {
	if (*cp == '\n') {
	    lbuf->output("\n");
	    cp++;
	} else {
	    len = lbuf->len - (cp - lbuf->buf);
	    if ((ep = memchr(cp, '\n', len)) != NULL)
		len = (int)(ep - cp);
	    if (len)
		lbuf_println(lbuf, cp, len);
	    cp = ep ? ep + 1 : NULL;
	}
    }

done:
    lbuf->len = 0;		/* reset the buffer for re-use. */

    debug_return;
}
