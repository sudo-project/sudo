/*
 * Copyright (c) 2009-2018 Todd C. Miller <Todd.Miller@sudo.ws>
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
#if defined(HAVE_STDINT_H)
# include <stdint.h>
#elif defined(HAVE_INTTYPES_H)
# include <inttypes.h>
#endif
#ifdef HAVE_STRING_H
# include <string.h>
#endif /* HAVE_STRING_H */
#ifdef HAVE_STRINGS_H
# include <strings.h>
#endif /* HAVE_STRINGS_H */
#include <unistd.h>
#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <fcntl.h>
#ifdef HAVE_STDBOOL_H
# include <stdbool.h>
#else
# include "compat/stdbool.h"
#endif /* HAVE_STDBOOL_H */

#include "sudo_gettext.h"	/* must be included before sudo_compat.h */

#include "sudo_compat.h"
#include "sudo_fatal.h"
#include "sudo_debug.h"
#include "sudo_util.h"
#include "iolog_util.h"

static int timing_idx_adj;

struct log_info *
parse_logfile(const char *logfile)
{
    FILE *fp;
    char *buf = NULL, *cp, *ep;
    const char *errstr;
    size_t bufsize = 0, cwdsize = 0, cmdsize = 0;
    struct log_info *li = NULL;
    debug_decl(parse_logfile, SUDO_DEBUG_UTIL)

    fp = fopen(logfile, "r");
    if (fp == NULL) {
	sudo_warn(U_("unable to open %s"), logfile);
	goto bad;
    }

    /*
     * ID file has three lines:
     *  1) a log info line
     *  2) cwd
     *  3) command with args
     */
    if ((li = calloc(1, sizeof(*li))) == NULL)
	sudo_fatalx(U_("%s: %s"), __func__, U_("unable to allocate memory"));
    if (getline(&buf, &bufsize, fp) == -1 ||
	getline(&li->cwd, &cwdsize, fp) == -1 ||
	getline(&li->cmd, &cmdsize, fp) == -1) {
	sudo_warn(U_("%s: invalid log file"), logfile);
	goto bad;
    }

    /* Strip the newline from the cwd and command. */
    li->cwd[strcspn(li->cwd, "\n")] = '\0';
    li->cmd[strcspn(li->cmd, "\n")] = '\0';

    /*
     * Crack the log line (rows and cols not present in old versions).
     *	timestamp:user:runas_user:runas_group:tty:rows:cols
     * XXX - probably better to use strtok and switch on the state.
     */
    buf[strcspn(buf, "\n")] = '\0';
    cp = buf;

    /* timestamp */
    if ((ep = strchr(cp, ':')) == NULL) {
	sudo_warn(U_("%s: time stamp field is missing"), logfile);
	goto bad;
    }
    *ep = '\0';
    li->tstamp = sizeof(time_t) == 4 ? strtonum(cp, INT_MIN, INT_MAX, &errstr) :
	strtonum(cp, LLONG_MIN, LLONG_MAX, &errstr);
    if (errstr != NULL) {
	sudo_warn(U_("%s: time stamp %s: %s"), logfile, cp, errstr);
	goto bad;
    }

    /* user */
    cp = ep + 1;
    if ((ep = strchr(cp, ':')) == NULL) {
	sudo_warn(U_("%s: user field is missing"), logfile);
	goto bad;
    }
    if ((li->user = strndup(cp, (size_t)(ep - cp))) == NULL)
	sudo_fatalx(U_("%s: %s"), __func__, U_("unable to allocate memory"));

    /* runas user */
    cp = ep + 1;
    if ((ep = strchr(cp, ':')) == NULL) {
	sudo_warn(U_("%s: runas user field is missing"), logfile);
	goto bad;
    }
    if ((li->runas_user = strndup(cp, (size_t)(ep - cp))) == NULL)
	sudo_fatalx(U_("%s: %s"), __func__, U_("unable to allocate memory"));

    /* runas group */
    cp = ep + 1;
    if ((ep = strchr(cp, ':')) == NULL) {
	sudo_warn(U_("%s: runas group field is missing"), logfile);
	goto bad;
    }
    if (cp != ep) {
	if ((li->runas_group = strndup(cp, (size_t)(ep - cp))) == NULL)
	    sudo_fatalx(U_("%s: %s"), __func__, U_("unable to allocate memory"));
    }

    /* tty, followed by optional rows + columns */
    cp = ep + 1;
    if ((ep = strchr(cp, ':')) == NULL) {
	/* just the tty */
	if ((li->tty = strdup(cp)) == NULL)
	    sudo_fatalx(U_("%s: %s"), __func__, U_("unable to allocate memory"));
    } else {
	/* tty followed by rows + columns */
	if ((li->tty = strndup(cp, (size_t)(ep - cp))) == NULL)
	    sudo_fatalx(U_("%s: %s"), __func__, U_("unable to allocate memory"));
	cp = ep + 1;
	/* need to NULL out separator to use strtonum() */
	if ((ep = strchr(cp, ':')) != NULL) {
	    *ep = '\0';
	}
	li->rows = strtonum(cp, 1, INT_MAX, &errstr);
	if (errstr != NULL) {
	    sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_LINENO,
		"%s: tty rows %s: %s", logfile, cp, errstr);
	}
	if (ep != NULL) {
	    cp = ep + 1;
	    li->cols = strtonum(cp, 1, INT_MAX, &errstr);
	    if (errstr != NULL) {
		sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_LINENO,
		    "%s: tty cols %s: %s", logfile, cp, errstr);
	    }
	}
    }
    fclose(fp);
    free(buf);
    debug_return_ptr(li);

bad:
    if (fp != NULL)
	fclose(fp);
    free(buf);
    free_log_info(li);
    debug_return_ptr(NULL);
}

/*
 * Parse a timing line, which is formatted as:
 *	index sleep_time num_bytes
 * Where index is IOFD_*, sleep_time is the number of seconds to sleep
 * before writing the data and num_bytes is the number of bytes to output.
 * Returns true on success and false on failure.
 */
bool
parse_timing(const char *buf, double *seconds, struct timing_closure *timing)
{
    unsigned long ul;
    long l;
    double d, fract = 0;
    char *cp, *ep;
    debug_decl(parse_timing, SUDO_DEBUG_UTIL)

    /* Parse index */
    ul = strtoul(buf, &ep, 10);
    if (ep == buf || !isspace((unsigned char) *ep))
	goto bad;
    if (ul >= IOFD_MAX) {
	if (ul != 6)
	    goto bad;
	/* work around a bug in timing files generated by sudo 1.8.7 */
	timing_idx_adj = 2;
    }
    timing->idx = (int)ul - timing_idx_adj;
    for (cp = ep + 1; isspace((unsigned char) *cp); cp++)
	continue;

    /*
     * Parse number of seconds.  Sudo logs timing data in the C locale
     * but this may not match the current locale so we cannot use strtod().
     * Furthermore, sudo < 1.7.4 logged with the user's locale so we need
     * to be able to parse those logs too.
     */
    errno = 0;
    l = strtol(cp, &ep, 10);
    if (ep == cp || (*ep != '.' && strncmp(ep, timing->decimal, strlen(timing->decimal)) != 0))
	goto bad;
    if (l < 0 || l > INT_MAX || (errno == ERANGE && l == LONG_MAX))
	goto bad;
    *seconds = (double)l;
    cp = ep + (*ep == '.' ? 1 : strlen(timing->decimal));
    d = 10.0;
    while (isdigit((unsigned char) *cp)) {
	fract += (*cp - '0') / d;
	d *= 10;
	cp++;
    }
    *seconds += fract;
    while (isspace((unsigned char) *cp))
	cp++;

    if (timing->idx == IOFD_TIMING) {
	errno = 0;
	ul = strtoul(cp, &ep, 10);
	if (ep == cp || !isspace((unsigned char) *ep))
	    goto bad;
	if (ul > INT_MAX || (errno == ERANGE && ul == ULONG_MAX))
	    goto bad;
	timing->u.winsize.rows = (int)ul;
	for (cp = ep + 1; isspace((unsigned char) *cp); cp++)
	    continue;

	errno = 0;
	ul = strtoul(cp, &ep, 10);
	if (ep == cp || *ep != '\0')
	    goto bad;
	if (ul > INT_MAX || (errno == ERANGE && ul == ULONG_MAX))
	    goto bad;
	timing->u.winsize.cols = (int)ul;
    } else {
	errno = 0;
	ul = strtoul(cp, &ep, 10);
	if (ep == cp || *ep != '\0')
	    goto bad;
	if (ul > SIZE_MAX || (errno == ERANGE && ul == ULONG_MAX))
	    goto bad;
	timing->u.nbytes = (size_t)ul;
    }

    debug_return_bool(true);
bad:
    debug_return_bool(false);
}

void
free_log_info(struct log_info *li)
{
    if (li != NULL) {
	free(li->cwd);
	free(li->user);
	free(li->runas_user);
	free(li->runas_group);
	free(li->tty);
	free(li->cmd);
	free(li);
    }
}
