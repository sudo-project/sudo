/*
 * SPDX-License-Identifier: ISC
 *
 * Copyright (c) 1999-2005, 2007-2012 Todd C. Miller <Todd.Miller@sudo.ws>
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

/*
 * This is an open source non-commercial project. Dear PVS-Studio, please check it.
 * PVS-Studio Static Code Analyzer for C, C++ and C#: http://www.viva64.com
 */

#include <config.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>

#include "sudo.h"
#include "sudo_plugin.h"
#include "sudo_plugin_int.h"

extern int tgetpass_flags; /* XXX */

/*
 * Sudo conversation function.
 */
int
sudo_conversation(int num_msgs, const struct sudo_conv_message msgs[],
    struct sudo_conv_reply replies[], struct sudo_conv_callback *callback)
{
    char *pass;
    int n;
    const int conv_debug_instance = sudo_debug_get_active_instance();

    sudo_debug_set_active_instance(sudo_debug_instance);

    for (n = 0; n < num_msgs; n++) {
	const struct sudo_conv_message *msg = &msgs[n];
	int flags = tgetpass_flags;
	FILE *fp = stdout;

	switch (msg->msg_type & 0xff) {
	    case SUDO_CONV_PROMPT_ECHO_ON:
		SET(flags, TGP_ECHO);
		goto read_pass;
	    case SUDO_CONV_PROMPT_MASK:
		SET(flags, TGP_MASK);
		FALLTHROUGH;
	    case SUDO_CONV_PROMPT_ECHO_OFF:
		if (ISSET(msg->msg_type, SUDO_CONV_PROMPT_ECHO_OK))
		    SET(flags, TGP_NOECHO_TRY);
	    read_pass:
		/* Read the password unless interrupted. */
		if (replies == NULL)
		    goto err;
		pass = tgetpass(msg->msg, msg->timeout, flags, callback);
		if (pass == NULL)
		    goto err;
		replies[n].reply = strdup(pass);
		if (replies[n].reply == NULL) {
		    sudo_fatalx_nodebug(U_("%s: %s"), "sudo_conversation",
			U_("unable to allocate memory"));
		}
		explicit_bzero(pass, strlen(pass));
		break;
	    case SUDO_CONV_ERROR_MSG:
		fp = stderr;
		FALLTHROUGH;
	    case SUDO_CONV_INFO_MSG:
		if (msg->msg != NULL) {
		    size_t len = strlen(msg->msg);
		    const char *crnl = NULL;
		    bool written = false;
		    int ttyfd = -1;

		    if (ISSET(msg->msg_type, SUDO_CONV_PREFER_TTY) &&
			    !ISSET(tgetpass_flags, TGP_STDIN))
			ttyfd = open(_PATH_TTY, O_WRONLY);
		    if (len != 0 && (ttyfd != -1 || isatty(fileno(fp)))) {
			/* Convert nl -> cr nl in case tty is in raw mode. */
			if (msg->msg[len - 1] == '\n') {
			    if (len == 1 || msg->msg[len - 2] != '\r') {
				len--;
				crnl = "\r\n";
			    }
			}
		    }
		    if (ttyfd != -1) {
			/* Try writing to tty but fall back to fp on error. */
			if ((len == 0 || write(ttyfd, msg->msg, len) != -1) &&
				(crnl == NULL || write(ttyfd, crnl, 2) != -1)) {
			    written = true;
			}
			close(ttyfd);
		    }
		    if (!written) {
			if (len != 0 && fwrite(msg->msg, 1, len, fp) == 0)
			    goto err;
			if (crnl != NULL && fwrite(crnl, 1, 2, fp) == 0)
			    goto err;
		    }
		}
		break;
	    default:
		goto err;
	}
    }

    sudo_debug_set_active_instance(conv_debug_instance);
    return 0;

err:
    /* Zero and free allocated memory and return an error. */
    if (replies != NULL) {
	do {
	    struct sudo_conv_reply *repl = &replies[n];
	    if (repl->reply == NULL)
		continue;
	    freezero(repl->reply, strlen(repl->reply));
	    repl->reply = NULL;
	} while (n--);
    }

    sudo_debug_set_active_instance(conv_debug_instance);
    return -1;
}

int
sudo_conversation_1_7(int num_msgs, const struct sudo_conv_message msgs[],
    struct sudo_conv_reply replies[])
{
    return sudo_conversation(num_msgs, msgs, replies, NULL);
}

int
sudo_conversation_printf(int msg_type, const char *fmt, ...)
{
    FILE *fp = stdout;
    FILE *ttyfp = NULL;
    va_list ap;
    int len;
    const int conv_debug_instance = sudo_debug_get_active_instance();

    sudo_debug_set_active_instance(sudo_debug_instance);

    if (ISSET(msg_type, SUDO_CONV_PREFER_TTY) &&
	    !ISSET(tgetpass_flags, TGP_STDIN)) {
	/* Try writing to /dev/tty first. */
	ttyfp = fopen(_PATH_TTY, "w");
    }

    switch (msg_type & 0xff) {
    case SUDO_CONV_ERROR_MSG:
	fp = stderr;
	FALLTHROUGH;
    case SUDO_CONV_INFO_MSG:
	va_start(ap, fmt);
	len = vfprintf(ttyfp ? ttyfp : fp, fmt, ap);
	va_end(ap);
	break;
    default:
	len = -1;
	errno = EINVAL;
	break;
    }

    if (ttyfp != NULL)
	fclose(ttyfp);

    sudo_debug_set_active_instance(conv_debug_instance);
    return len;
}
