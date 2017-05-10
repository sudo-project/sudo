/*
 * Copyright (c) 2013-2017 Todd C. Miller <Todd.Miller@courtesan.com>
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
#if defined(HAVE_STDINT_H)
# include <stdint.h>
#elif defined(HAVE_INTTYPES_H)
# include <inttypes.h>
#endif
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>

#include "sudoers.h"
#include "parse.h"

#ifdef HAVE_SHA224UPDATE
# include <sha2.h>
#else
# include "compat/sha2.h"
#endif

static struct digest_function {
    const unsigned int digest_len;
    void (*init)(SHA2_CTX *);
#ifdef SHA2_VOID_PTR
    void (*update)(SHA2_CTX *, const void *, size_t);
    void (*final)(void *, SHA2_CTX *);
#else
    void (*update)(SHA2_CTX *, const unsigned char *, size_t);
    void (*final)(unsigned char *, SHA2_CTX *);
#endif
} digest_functions[] = {
    {
	SHA224_DIGEST_LENGTH,
	SHA224Init,
	SHA224Update,
	SHA224Final
    }, {
	SHA256_DIGEST_LENGTH,
	SHA256Init,
	SHA256Update,
	SHA256Final
    }, {
	SHA384_DIGEST_LENGTH,
	SHA384Init,
	SHA384Update,
	SHA384Final
    }, {
	SHA512_DIGEST_LENGTH,
	SHA512Init,
	SHA512Update,
	SHA512Final
    }, {
	0
    }
};

unsigned char *
sudo_filedigest(int fd, const char *file, int digest_type, size_t *digest_len)
{
    struct digest_function *func = NULL;
    unsigned char *file_digest = NULL;
    unsigned char buf[32 * 1024];
    size_t nread;
    SHA2_CTX ctx;
    int i, fd2;
    FILE *fp = NULL;
    debug_decl(sudo_filedigest, SUDOERS_DEBUG_UTIL)

    for (i = 0; digest_functions[i].digest_len != 0; i++) {
	if (digest_type == i) {
	    func = &digest_functions[i];
	    break;
	}
    }
    if (func == NULL) {
	sudo_warnx(U_("unsupported digest type %d for %s"), digest_type, file);
	goto bad;
    }

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
    if ((file_digest = malloc(func->digest_len)) == NULL) {
	sudo_warnx(U_("%s: %s"), __func__, U_("unable to allocate memory"));
	goto bad;
    }

    func->init(&ctx);
    while ((nread = fread(buf, 1, sizeof(buf), fp)) != 0) {
	func->update(&ctx, buf, nread);
    }
    if (ferror(fp)) {
	sudo_warnx(U_("%s: read error"), file);
	goto bad;
    }
    func->final(file_digest, &ctx);
    fclose(fp);

    *digest_len = func->digest_len;
    debug_return_ptr(file_digest);
bad:
    free(file_digest);
    if (fp != NULL)
	fclose(fp);
    debug_return_ptr(NULL);
}
