/*
 * Copyright (c) 1998-2005, 2010-2013 Todd C. Miller <Todd.Miller@courtesan.com>
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
#include <pwd.h>
#ifdef __hpux
#  undef MAXINT
#  include <hpsecurity.h>
#else
#  include <sys/security.h>
#endif /* __hpux */
#include <prot.h>

#include "sudoers.h"
#include "sudo_auth.h"

int
sudo_secureware_init(struct passwd *pw, sudo_auth *auth)
{
#ifdef __alpha
    extern int crypt_type;
    debug_decl(sudo_secureware_init, SUDO_DEBUG_AUTH)

    if (crypt_type == INT_MAX)
	debug_return_int(AUTH_FAILURE);			/* no shadow */
#else
    debug_decl(secureware_init, SUDO_DEBUG_AUTH)
#endif
    sudo_setspent();
    auth->data = sudo_getepw(pw);
    sudo_endspent();
    debug_return_int(AUTH_SUCCESS);
}

int
sudo_secureware_verify(struct passwd *pw, char *pass, sudo_auth *auth)
{
    char *pw_epasswd = auth->data;
    char *epass = NULL;
    debug_decl(sudo_secureware_verify, SUDO_DEBUG_AUTH)
#ifdef __alpha
    {
	extern int crypt_type;

# ifdef HAVE_DISPCRYPT
	epass = dispcrypt(pass, pw_epasswd, crypt_type);
# else
	if (crypt_type == AUTH_CRYPT_BIGCRYPT)
	    epass = bigcrypt(pass, pw_epasswd);
	else if (crypt_type == AUTH_CRYPT_CRYPT16)
	    epass = crypt(pass, pw_epasswd);
# endif /* HAVE_DISPCRYPT */
    }
#elif defined(HAVE_BIGCRYPT)
    epass = bigcrypt(pass, pw_epasswd);
#endif /* __alpha */

    if (epass != NULL && strcmp(pw_epasswd, epass) == 0)
	debug_return_int(AUTH_SUCCESS);
    debug_return_int(AUTH_FAILURE);
}

int
sudo_secureware_cleanup(pw, auth)
    struct passwd *pw;
    sudo_auth *auth;
{
    char *pw_epasswd = auth->data;
    debug_decl(sudo_secureware_cleanup, SUDO_DEBUG_AUTH)

    if (pw_epasswd != NULL) {
	memset_s(pw_epasswd, SUDO_CONV_REPL_MAX, 0, strlen(pw_epasswd));
	efree(pw_epasswd);
    }
    debug_return_int(AUTH_SUCCESS);
}
