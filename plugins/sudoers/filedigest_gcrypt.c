/*
 * Copyright (c) 2017 Todd C. Miller <Todd.Miller@courtesan.com>
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
#include <stdlib.h>
#ifdef HAVE_STRING_H
# include <string.h>
#endif /* HAVE_STRING_H */
#ifdef HAVE_STRINGS_H
# include <strings.h>
#endif /* HAVE_STRINGS_H */
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>

#include <gcrypt.h>

#include "sudoers.h"
#include "parse.h"

unsigned char *
sudo_filedigest(int fd, const char *file, int digest_type, size_t *digest_lenp)
{
    unsigned char *file_digest = NULL;
    unsigned char buf[32 * 1024];
    int fd2, gcry_digest_type;
    size_t digest_len, nread;
    gcry_error_t error;
    gcry_md_hd_t ctx;
    FILE *fp = NULL;
    debug_decl(sudo_filedigest, SUDOERS_DEBUG_UTIL)

    switch (digest_type) {
    case SUDO_DIGEST_SHA224:
	gcry_digest_type = GCRY_MD_SHA224;
	break;
    case SUDO_DIGEST_SHA256:
	gcry_digest_type = GCRY_MD_SHA256;
	break;
    case SUDO_DIGEST_SHA384:
	gcry_digest_type = GCRY_MD_SHA384;
	break;
    case SUDO_DIGEST_SHA512:
	gcry_digest_type = GCRY_MD_SHA512;
	break;
    default:
	sudo_warnx(U_("unsupported digest type %d for %s"), digest_type, file);
	debug_return_ptr(NULL);
    }

    error = gcry_md_open(&ctx, gcry_digest_type, 0);
    if (error != 0) {
	sudo_warnx(U_("%s: %s"), digest_type_to_name(digest_type),
	    gcry_strerror(error));
	goto bad;
    }
    digest_len = gcry_md_get_algo_dlen(gcry_digest_type);

    if ((fd2 = dup(fd)) == -1) {
	sudo_debug_printf(SUDO_DEBUG_INFO, "unable to dup %s: %s",
	    file, strerror(errno));
	goto bad;
    }
    if ((fp = fdopen(fd2, "r")) == NULL) {
	sudo_debug_printf(SUDO_DEBUG_INFO, "unable to fdopen %s: %s",
	    file, strerror(errno));
	close(fd2);
	goto bad;
    }
    if ((file_digest = malloc(digest_len)) == NULL) {
	sudo_warnx(U_("%s: %s"), __func__, U_("unable to allocate memory"));
	goto bad;
    }

    while ((nread = fread(buf, 1, sizeof(buf), fp)) != 0) {
	gcry_md_write(ctx, buf, nread);
    }
    if (ferror(fp)) {
	sudo_warnx(U_("%s: read error"), file);
	goto bad;
    }
    gcry_md_final(ctx);
    fclose(fp);

    memcpy(file_digest, gcry_md_read(ctx, 0), digest_len);
    *digest_lenp = digest_len;
    debug_return_ptr(file_digest);
bad:
    free(file_digest);
    gcry_md_close(ctx);
    if (fp != NULL)
	fclose(fp);
    debug_return_ptr(NULL);
}
