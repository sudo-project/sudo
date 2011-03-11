/*
 * Copyright (c) 2011 Todd C. Miller <Todd.Miller@courtesan.com>
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
#include <sys/param.h>
#include <sys/time.h>
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
#if TIME_WITH_SYS_TIME
# include <time.h>
#endif
#if defined(HAVE_GETUTXID)
# include <utmpx.h>
#elif defined(HAVE_GETUTID)
# include <utmp.h>
#elif defined(HAVE_UTIL_H)
# include <util.h>
# include <utmp.h>
#endif

#include "sudo.h"
#include "sudo_exec.h"

#if defined(HAVE_GETUTXID) || defined(HAVE_GETUTID)
/*
 * Create ut_id from tty line and the id from the entry we are cloning.
 */
static void
utmp_setid(const char *line, const char *old_id, char *new_id, size_t idsize)
{
    size_t idlen;

    /* Skip over "tty" in the id if old entry did too. */
    if (strncmp(line, "tty", 3) == 0 &&
	strncmp(old_id, "tty", idsize < 3 ? idsize : 3) != 0)
	line += 3;
    
    /* Store as much as will fit, skipping parts of the beginning as needed. */
    idlen = strlen(line);
    if (idlen > idsize) {
	line += (idlen - idsize);
	idlen = idsize;
    }
    strncpy(new_id, line, idlen);
}
#endif /* HAVE_GETUTXID || HAVE_GETUTID */

/*
 * Clone a utmp entry, updating the line, id, pid and time.
 * XXX - if no existing entry, make a new one
 */
static int
utmp_doclone(const char *from_line, const char *to_line)
{
    int rval = FALSE;
#ifdef HAVE_GETUTXID
    struct utmpx *ut_old, ut_new;

    memset(&ut_new, 0, sizeof(ut_new));
    strncpy(ut_new.ut_line, from_line, sizeof(ut_new.ut_line));
    setutxent();
    if ((ut_old = getutxid(&ut_new)) != NULL) {
	if (ut_old != &ut_new)
	    memcpy(&ut_new, ut_old, sizeof(ut_new));
	strncpy(ut_new.ut_line, to_line, sizeof(ut_new.ut_line));
	utmp_setid(to_line, ut_old->ut_id, ut_new.ut_id, sizeof(ut_new.ut_id));
	ut_new.ut_pid = getpid();
	gettimeofday(&ut_new.ut_tv, NULL);
	ut_new.ut_type = USER_PROCESS;

	if (pututxline(&ut_new) != NULL)
	    rval = TRUE;
    }
    endutxent();
#elif HAVE_GETUTID
    struct utmp *ut_old, ut_new;

    memset(&ut_new, 0, sizeof(ut_new));
    strncpy(ut_new.ut_line, from_line, sizeof(ut_new.ut_line));
    setutent();
    if ((ut_old = getutid(&ut_new)) != NULL) {
	if (ut_old != &ut_new)
	    memcpy(&ut_new, ut_old, sizeof(ut_new));
	strncpy(ut_new.ut_line, to_line, sizeof(ut_new.ut_line));
	utmp_setid(to_line, ut_old->ut_id, ut_new.ut_id, sizeof(ut_new.ut_id));
	ut_new.ut_pid = getpid();
	ut_new.ut_time = time(NULL);
	ut_new.ut_type = USER_PROCESS;

	if (pututline(&ut_new) != NULL)
	    rval = TRUE;
    }
    endutent();
#elif HAVE_LOGIN
    FILE *fp;
    struct utmp ut;

    /* Find existing entry, update line and add as new. */
    if ((fp = fopen(_PATH_UTMP, "r")) != NULL) {
	while (fread(&ut, sizeof(ut), 1, fp) == 1) {
	    if (ut.ut_name[0] &&
		strncmp(ut.ut_line, from_line, sizeof(ut.ut_line)) == 0) {
		strncpy(ut.ut_line, to_line, sizeof(ut.ut_line));
		login(&ut);
		rval = TRUE;
		break;
	    }
	}
	fclose(fp);
    }
#endif
    return rval;
}

int
utmp_clone(const char *from_line, const char *to_line)
{
    /* Strip off /dev/ prefix from to/from line as needed. */
    if (strncmp(from_line, _PATH_DEV, sizeof(_PATH_DEV) - 1) == 0)
	from_line += sizeof(_PATH_DEV) - 1;
    if (strncmp(to_line, _PATH_DEV, sizeof(_PATH_DEV) - 1) == 0)
	to_line += sizeof(_PATH_DEV) - 1;
   
    return utmp_doclone(from_line, to_line);
}

/*
 * Remove (zero out) the utmp entry for a line.
 */
static int
utmp_doremove(const char *line)
{
    int rval = FALSE;
#ifdef HAVE_GETUTXID
    struct utmpx *ut, key;
   
    memset(&key, 0, sizeof(key));
    strncpy(key.ut_line, line, sizeof(key.ut_line));
    setutxent();
    if ((ut = getutxid(&key)) != NULL) {
	ut->ut_type = DEAD_PROCESS;
	(void)gettimeofday(&ut->ut_tv, NULL);
	if (pututxline(ut) != NULL)
	    rval = TRUE;
    }
    endutxent();
#elif HAVE_GETUTID
    struct utmp *ut, key;
   
    memset(&key, 0, sizeof(key));
    strncpy(key.ut_line, line, sizeof(key.ut_line));
    setutent();
    if ((ut = getutid(&key)) != NULL) {
	ut->ut_type = DEAD_PROCESS;
	ut->ut_time = time(NULL);
	if (pututline(ut) != NULL)
	    rval = TRUE;
    }
    endutent();
#elif HAVE_LOGIN
    if (logout(line) != 0)
	rval = TRUE;
#endif /* HAVE_GETUTXID */
    return rval;
}

int
utmp_remove(const char *line)
{
    /* Strip off /dev/ prefix from to/from line as needed. */
    if (strncmp(line, _PATH_DEV, sizeof(_PATH_DEV) - 1) == 0)
	line += sizeof(_PATH_DEV) - 1;

    return utmp_doremove(line);
}
