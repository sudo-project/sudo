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
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>

#include <openssl/sha.h>

#include "sudoers.h"
#include "parse.h"

union ANY_CTX {
    SHA256_CTX sha256;
    SHA512_CTX sha512;
};

static struct digest_function {
    const unsigned int digest_len;
    int (*init)(union ANY_CTX *);
    int (*update)(union ANY_CTX *, const void *, size_t);
    int (*final)(unsigned char *, union ANY_CTX *);
} digest_functions[] = {
    {
	SHA224_DIGEST_LENGTH,
	(int (*)(union ANY_CTX *))SHA224_Init,
	(int (*)(union ANY_CTX *, const void *, size_t))SHA224_Update,
	(int (*)(unsigned char *, union ANY_CTX *))SHA224_Final
    }, {
	SHA256_DIGEST_LENGTH,
	(int (*)(union ANY_CTX *))SHA256_Init,
	(int (*)(union ANY_CTX *, const void *, size_t))SHA256_Update,
	(int (*)(unsigned char *, union ANY_CTX *))SHA256_Final
    }, {
	SHA384_DIGEST_LENGTH,
	(int (*)(union ANY_CTX *))SHA384_Init,
	(int (*)(union ANY_CTX *, const void *, size_t))SHA384_Update,
	(int (*)(unsigned char *, union ANY_CTX *))SHA384_Final
    }, {
	SHA512_DIGEST_LENGTH,
	(int (*)(union ANY_CTX *))SHA512_Init,
	(int (*)(union ANY_CTX *, const void *, size_t))SHA512_Update,
	(int (*)(unsigned char *, union ANY_CTX *))SHA512_Final
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
    union ANY_CTX ctx;
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
