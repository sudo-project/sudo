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
# include <string.h>
#endif /* HAVE_STRING_H */
#ifdef HAVE_STRINGS_H
# include <strings.h>
#endif /* HAVE_STRINGS_H */

#include "missing.h"
#include "sudo_debug.h"

/*
 * Decode a NUL-terminated string in base64 format and store the
 * result in dst.
 */
size_t
base64_decode(const char *str, unsigned char *dst, size_t dsize)
{
    static const char b64[] =
	"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    const unsigned char *dst0 = dst;
    const unsigned char *dend = dst + dsize;
    unsigned char ch[4];
    char *pos;
    int i;
    debug_decl(base64_decode, SUDO_DEBUG_MATCH)

    /*
     * Convert from base64 to binary.  Each base64 char holds 6 bits of data
     * so 4 base64 chars equals 3 chars of data.
     * Padding (with the '=' char) may or may not be present.
     */
    while (*str != '\0') {
	for (i = 0; i < 4; i++) {
	    switch (*str) {
	    case '=':
		str++;
		/* FALLTHROUGH */
	    case '\0':
		ch[i] = '=';
		break;
	    default:
		if ((pos = strchr(b64, *str++)) == NULL)
		    debug_return_size_t((size_t)-1);
		ch[i] = (unsigned char)(pos - b64);
		break;
	    }
	}
	if (ch[0] == '=' || ch[1] == '=' || dst == dend)
	    break;
	*dst++ = (ch[0] << 2) | ((ch[1] & 0x30) >> 4);
	if (ch[2] == '=' || dst == dend)
	    break;
	*dst++ = ((ch[1] & 0x0f) << 4) | ((ch[2] & 0x3c) >> 2);
	if (ch[3] == '=' || dst == dend)
	    break;
	*dst++ = ((ch[2] & 0x03) << 6) | ch[3];
    }
    debug_return_size_t((size_t)(dst - dst0));
}
