/*
 * Copyright (c) 1999-2005, 2007-2013 Todd C. Miller <Todd.Miller@courtesan.com>
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
#endif /* HAVE_STRING_H */
#ifdef HAVE_UNISTD_H
# include <unistd.h>
#endif /* HAVE_UNISTD_H */
#include <pwd.h>
#include <usersec.h>

#include "sudoers.h"
#include "sudo_auth.h"

/*
 * For a description of the AIX authentication API, see
 * http://publib16.boulder.ibm.com/doc_link/en_US/a_doc_lib/libs/basetrf1/authenticate.htm
 */
int
sudo_aix_verify(struct passwd *pw, char *prompt, sudo_auth *auth)
{
    char *pass, *message = NULL;
    int result = 1, reenter = 0;
    int rval = AUTH_SUCCESS;
    debug_decl(sudo_aix_verify, SUDO_DEBUG_AUTH)

    do {
	pass = auth_getpass(prompt, def_passwd_timeout * 60,
	    SUDO_CONV_PROMPT_ECHO_OFF);
	if (pass == NULL)
	    break;
	efree(message);
	message = NULL;
	result = authenticate(pw->pw_name, pass, &reenter, &message);
	memset_s(pass, SUDO_CONV_REPL_MAX, 0, strlen(pass));
	prompt = message;
    } while (reenter);

    if (result != 0) {
	/* Display error message, if any. */
	if (message != NULL) {
	    struct sudo_conv_message msg;
	    struct sudo_conv_reply repl;

	    memset(&msg, 0, sizeof(msg));
	    msg.msg_type = SUDO_CONV_ERROR_MSG;
	    msg.msg = message;
	    memset(&repl, 0, sizeof(repl));
	    sudo_conv(1, &msg, &repl);
	}
	rval = pass ? AUTH_FAILURE : AUTH_INTR;
    }
    efree(message);
    debug_return_int(rval);
}

int
sudo_aix_cleanup(struct passwd *pw, sudo_auth *auth)
{
    debug_decl(sudo_aix_cleanup, SUDO_DEBUG_AUTH)

    /* Unset AUTHSTATE as it may not be correct for the runas user. */
    sudo_unsetenv("AUTHSTATE");

    debug_return_int(AUTH_SUCCESS);
}
