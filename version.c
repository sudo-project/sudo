/*
 * Copyright (c) 1996, 1998, 1999 Todd C. Miller <Todd.Miller@courtesan.com>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * 3. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission.
 *
 * 4. Products derived from this software may not be called "Sudo" nor
 *    may "Sudo" appear in their names without specific prior written
 *    permission from the author.
 *
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES,
 * INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY
 * AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL
 * THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS;
 * OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
 * OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
 * ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "config.h"

#include <stdio.h>
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif /* HAVE_UNISTD_H */
#ifdef HAVE_STRING_H
#include <string.h>
#endif /* HAVE_STRING_H */
#ifdef HAVE_STRINGS_H
#include <strings.h>
#endif /* HAVE_STRINGS_H */
#include <sys/types.h>
#include <sys/param.h>

/* XXX - configure needs to check for the tables */
/* XXX   most OS's don't have the tables! */
#define SYSLOG_NAMES

#include "sudo.h"
#include "version.h"

#ifndef lint
static const char rcsid[] = "$Sudo$";
#endif /* lint */

#if (LOGGING & SLOG_SYSLOG) && defined(HAVE_SYSLOG_NAMES)
static char *num_to_name __P((int, CODE *));
#endif /* SLOG_SYSLOG && HAVE_SYSLOG_NAMES */

/*
 * Print version and configure info.
 */
void
print_version()
{

    (void) printf("Sudo version %s\n", version);

    /*
     * Print compile-time options if root.
     */
    if (getuid() == 0) {
	(void) fputs("\nLogging:\n", stdout);
#if (LOGGING & SLOG_SYSLOG)
# ifdef HAVE_SYSLOG_NAMES
	printf("    syslog: facility %s, failures to %s, success to %s\n",
	    num_to_name(LOGFAC, facilitynames),
	    num_to_name(PRI_FAILURE, prioritynames),
	    num_to_name(PRI_SUCCESS, prioritynames));
# else
	printf("    syslog: facility %d, failures to %d, success to %d\n",
	    LOGFAC, PRI_FAILURE, PRI_SUCCESS);
# endif /* HAVE_SYSLOG_NAMES */
#endif /* SLOG_SYSLOG */
#if (LOGGING & SLOG_FILE)
	printf("    log file: %s", _PATH_SUDO_LOGFILE);
# ifdef HOST_IN_LOG
	fputs(", host in log", stdout);
# endif
# ifdef WRAP_LOG
	printf(", lines wrap after %d characters", MAXLOGFILELEN);
# endif
	putchar('\n');
#endif /* SLOG_FILE */

    /* XXX - add more */

    }
}

#if (LOGGING & SLOG_SYSLOG) && defined(HAVE_SYSLOG_NAMES)
static char *
num_to_name(num, table)
    int num;
    CODE *table;
{
    CODE *t;

    for (t = table; t->c_name; t++)
	if (t->c_val == num)
	    return(t->c_name);

    return("unknown");
}
#endif /* SLOG_SYSLOG && HAVE_SYSLOG_NAMES */
