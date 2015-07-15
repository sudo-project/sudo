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

#include "sudo_compat.h"

#ifdef HAVE_SHA224UPDATE
# include <sha2.h>
#else
# include "compat/sha2.h"
#endif

__dso_public int main(int argc, char *argv[]);

static struct digest_function {
    const char *digest_name;
    const int digest_len;
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
	"SHA224",
	SHA224_DIGEST_LENGTH,
	SHA224Init,
	SHA224Update,
	SHA224Final
    }, {
	"SHA256",
	SHA256_DIGEST_LENGTH,
	SHA256Init,
	SHA256Update,
	SHA256Final
    }, {
	"SHA384",
	SHA384_DIGEST_LENGTH,
	SHA384Init,
	SHA384Update,
	SHA384Final
    }, {
	"SHA512",
	SHA512_DIGEST_LENGTH,
	SHA512Init,
	SHA512Update,
	SHA512Final
    }, {
	NULL
    }
};

#define NUM_TESTS	8
static const char *test_strings[NUM_TESTS] = {
    "",
    "a",
    "abc",
    "message digest",
    "abcdefghijklmnopqrstuvwxyz",
    "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
    "12345678901234567890123456789012345678901234567890123456789"
	"012345678901234567890",
};

int
main(int argc, char *argv[])
{
    SHA2_CTX ctx;
    int i, j;
    struct digest_function *func;
    unsigned char digest[SHA512_DIGEST_LENGTH];
    static const char hex[] = "0123456789abcdef";
    unsigned char buf[1000];

    for (func = digest_functions; func->digest_name != NULL; func++) {
	for (i = 0; i < NUM_TESTS; i++) {
	    func->init(&ctx);
	    func->update(&ctx, (unsigned char *)test_strings[i],
		strlen(test_strings[i]));
	    func->final(digest, &ctx);
	    printf("%s (\"%s\") = ", func->digest_name, test_strings[i]);
	    for (j = 0; j < func->digest_len; j++) {
		putchar(hex[digest[j] >> 4]);
		putchar(hex[digest[j] & 0x0f]);
	    }
	    putchar('\n');
	}

	/* Simulate a string of a million 'a' characters. */
	memset(buf, 'a', sizeof(buf));
	func->init(&ctx);
	for (i = 0; i < 1000; i++) {
	    func->update(&ctx, buf, sizeof(buf));
	}
	func->final(digest, &ctx);
	printf("%s (one million 'a' characters) = ", func->digest_name);
	for (j = 0; j < func->digest_len; j++) {
	    putchar(hex[digest[j] >> 4]);
	    putchar(hex[digest[j] & 0x0f]);
	}
	putchar('\n');
    }
    exit(0);
}
