/*
 * Copyright (c) 1994-1996,1998-2000 Todd C. Miller <Todd.Miller@courtesan.com>
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
#ifdef STDC_HEADERS
#include <stdlib.h>
#endif /* STDC_HEADERS */
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif /* HAVE_UNISTD_H */
#ifdef HAVE_STRING_H
#include <string.h>
#endif /* HAVE_STRING_H */
#ifdef HAVE_STRINGS_H
#include <strings.h>
#endif /* HAVE_STRINGS_H */
#include <pwd.h>
#include <errno.h>
#include <grp.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/param.h>
#ifdef HAVE_LOGIN_CAP_H
# include <login_cap.h>
#endif

#include "sudo.h"

#ifndef lint
static const char rcsid[] = "$Sudo$";
#endif /* lint */

/*
 * It might be better to use sysconf(_SC_SAVED_IDS) instead but
 * I'm * not aware of any system where this would be necessary.
 */
#ifdef _POSIX_SAVED_IDS
# define TOGGLE_ROOT							\
	if (seteuid(0)) {						\
	    log_error(NO_MAIL|USE_ERRNO|MSG_ONLY,			\
		"seteuid(0)");						\
	}
# define TOGGLE_USER							\
	if (seteuid(user_uid)) {					\
	    log_error(NO_MAIL|USE_ERRNO|MSG_ONLY,			\
		"seteuid(%ld)", (long) user_uid);			\
	}
#else
# ifdef HAVE_SETREUID
#  define TOGGLE_ROOT							\
	if (setreuid(user_uid, 0)) {					\
	    log_error(NO_MAIL|USE_ERRNO|MSG_ONLY,			\
		"setreuid(%ld, 0)", (long) user_uid);			\
	}
#  define TOGGLE_USER							\
	if (setreuid(0, user_uid)) {					\
	    log_error(NO_MAIL|USE_ERRNO|MSG_ONLY,			\
		"setreuid(0, %ld)", (long) user_uid);			\
	}
# else /* !_POSIX_SAVED_IDS && !HAVE_SETREUID */
#  define TOGGLE_ROOT							\
	;
# define TOGGLE_USER							\
	if (seteuid(user_uid)) {					\
	    log_error(NO_MAIL|USE_ERRNO|MSG_ONLY,			\
		"seteuid(%ld)", (long) user_uid);			\
	}
# endif /* HAVE_SETREUID */
#endif /* _POSIX_SAVED_IDS */

/*
 * Set real and effective uids and gids based on perm.
 * If we have POSIX saved IDs or setreuid(2) we can get away with only
 * toggling the effective uid/gid unless we are headed for an exec().
 */
void
set_perms(perm, sudo_mode)
    int perm;
    int sudo_mode;
{
    struct passwd *pw;
    int error;
#ifdef HAVE_LOGIN_CAP_H
    extern login_cap_t *lc;
#endif
    extern char *runas_homedir;

    /*
     * If we only have setuid() and seteuid() we have to set both to root
     * initially.
     */
#if !defined(_POSIX_SAVED_IDS) && !defined(HAVE_SETREUID)
    if (setuid(0)) {
	perror("setuid(0)");
	exit(1);
    }
#endif

    switch (perm) {
	case PERM_ROOT:
				TOGGLE_ROOT;
			      	break;
	case PERM_USER:
    	    	    	        (void) setegid(user_gid);
				TOGGLE_USER;
			      	break;
				
	case PERM_FULL_USER:
				/* headed for exec() */
    	    	    	        (void) setgid(user_gid);
				if (setuid(user_uid)) {
				    perror("setuid(user_uid)");
				    exit(1);
				}
			      	break;

	case PERM_RUNAS:
				/* headed for exec(), assume euid == 0 */
				/* XXX - add group/gid support */
				if (**user_runas == '#') {
				    if (def_flag(I_STAY_SETUID))
					error = seteuid(atoi(*user_runas + 1));
				    else
					error = setuid(atoi(*user_runas + 1));
				    if (error)
					log_error(NO_MAIL|USE_ERRNO|MSG_ONLY,
					    "cannot set uid to %s", *user_runas);
				} else {
				    if (!(pw = getpwnam(*user_runas)))
					log_error(NO_MAIL|MSG_ONLY,
					    "no passwd entry for %s!",
					    *user_runas);

				    /* Set $USER and $LOGNAME to target user */
				    if (def_flag(I_LOGNAME)) {
					sudo_setenv("USER", pw->pw_name);
					sudo_setenv("LOGNAME", pw->pw_name);
				    }

#ifdef HAVE_LOGIN_CAP_H
				    if (def_flag(I_LOGINCLASS)) {
					/*
					 * We don't have setusercontext()
					 * set the user since we may only
					 * want to set the effective uid.
					 */
					error = setusercontext(lc, pw, pw->pw_uid,
					    LOGIN_SETGROUP|LOGIN_SETRESOURCES|LOGIN_SETPRIORITY);
					if (error)
					    log_error(NO_MAIL|USE_ERRNO|MSG_ONLY,
						"setusercontext() failed for login class %s",
						login_class);
				    } else
#endif /* HAVE_LOGIN_CAP_H */
				    {
					if (setgid(pw->pw_gid))
					    log_error(NO_MAIL|USE_ERRNO|MSG_ONLY,
						"cannot set gid to %ld: %s",
						(long) pw->pw_gid);
#ifdef HAVE_INITGROUPS
					/*
					 * Initialize group vector only if are
					 * going to run as a non-root user.
					 */
					if (strcmp(*user_runas, "root") != 0 &&
					    initgroups(*user_runas, pw->pw_gid) < 0)
					    log_error(NO_MAIL|USE_ERRNO|MSG_ONLY,
						"cannot set group vector");
#endif /* HAVE_INITGROUPS */
				    }
				    if (def_flag(I_STAY_SETUID))
					error = seteuid(pw->pw_uid);
				    else
					error = setuid(pw->pw_uid);
				    if (error)
					log_error(NO_MAIL|USE_ERRNO|MSG_ONLY,
					    "cannot set uid to %ld",
					    (long) pw->pw_uid);
				    if (sudo_mode & MODE_RESET_HOME)
					runas_homedir = pw->pw_dir;
				}
				break;

	case PERM_SUDOERS:
				/* assume euid == 0, ruid == user */
				if (setegid(SUDOERS_GID))
				    log_error(NO_MAIL|USE_ERRNO|MSG_ONLY,
					"setegid(SUDOERS_GID)");

				/*
				 * If SUDOERS_UID == 0 and SUDOERS_MODE
				 * is group readable we use a non-zero
				 * uid in order to avoid NFS lossage.
				 * Using uid 1 is a bit bogus but should
				 * work on all OS's.
				 */
#if defined(HAVE_SETREUID) && !defined(_POSIX_SAVED_IDS)
				if (SUDOERS_UID == 0) {
				    if ((SUDOERS_MODE & 040) && setreuid(0, 1))
					log_error(NO_MAIL|USE_ERRNO|MSG_ONLY,
					    "setreuid(0, 1)");
				} else {
				    if (setreuid(0, SUDOERS_UID))
					log_error(NO_MAIL|USE_ERRNO|MSG_ONLY,
					    "setreuid(0, SUDOERS_UID)");
				}
#else
				if (SUDOERS_UID == 0) {
				    if ((SUDOERS_MODE & 040) && seteuid(1))
					log_error(NO_MAIL|USE_ERRNO|MSG_ONLY,
					    "seteuid(1)");
				} else {
				    if (seteuid(SUDOERS_UID))
					log_error(NO_MAIL|USE_ERRNO|MSG_ONLY,
					    "seteuid(SUDOERS_UID)");
				}
#endif /* HAVE_SETREUID && !_POSIX_SAVED_IDS */
			      	break;
    }
}
