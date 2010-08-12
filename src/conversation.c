/*
 * Copyright (c) 1999-2005, 2007-2010 Todd C. Miller <Todd.Miller@courtesan.com>
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
#include <sys/param.h>
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
#include <errno.h>

#include "sudo.h"
#include "sudo_plugin.h"

extern int tgetpass_flags; /* XXX */

/*
 * Sudo conversation function.
 */
int
sudo_conversation(int num_msgs, const struct sudo_conv_message msgs[],
    struct sudo_conv_reply replies[])
{
    struct sudo_conv_reply *repl;
    const struct sudo_conv_message *msg;
    char *pass;
    int n, flags = tgetpass_flags;

    for (n = 0; n < num_msgs; n++) {
	msg = &msgs[n];
	repl = &replies[n];
	switch (msg->msg_type & 0xff) {
	    case SUDO_CONV_PROMPT_ECHO_ON:
	    case SUDO_CONV_PROMPT_MASK:
		if (msg->msg_type == SUDO_CONV_PROMPT_ECHO_ON)
		    SET(flags, TGP_ECHO);
		else
		    SET(flags, TGP_MASK);
		/* FALLTHROUGH */
	    case SUDO_CONV_PROMPT_ECHO_OFF:
		if (ISSET(msg->msg_type, SUDO_CONV_PROMPT_ECHO_OK))
		    SET(flags, TGP_NOECHO_TRY);
		/* Read the password unless interrupted. */
		pass = tgetpass(msg->msg, msg->timeout, flags);
		if (pass == NULL)
		    goto err;
		repl->reply = estrdup(pass);
		zero_bytes(pass, strlen(pass));
		break;
	    case SUDO_CONV_INFO_MSG:
		if (msg->msg)
		    (void) fputs(msg->msg, stdout);
		break;
	    case SUDO_CONV_ERROR_MSG:
		if (msg->msg)
		    (void) fputs(msg->msg, stderr);
		break;
	    default:
		goto err;
	}
    }

    return 0;

err:
    /* Zero and free allocated memory and return an error. */
    do {
	repl = &replies[n];
	if (repl->reply != NULL) {
	    zero_bytes(repl->reply, strlen(repl->reply));
	    free(repl->reply);
	    repl->reply = NULL;
	}
    } while (n--);

    return -1;
}

int
_sudo_printf(int msg_type, const char *fmt, ...)
{
    va_list ap;
    FILE *fp;
    int len;

    switch (msg_type) {
    case SUDO_CONV_INFO_MSG:
	fp = stdout;
	break;
    case SUDO_CONV_ERROR_MSG:
	fp = stderr;
	break;
    default:
	errno = EINVAL;
	return -1;
    }

    va_start(ap, fmt);
    len = vfprintf(fp, fmt, ap);
    va_end(ap);

    return len;
}
