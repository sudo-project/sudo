/*
 *  CU sudo version 1.5.7
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 1, or (at your option)
 *  any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 *
 *  Please send bugs, changes, problems to sudo-bugs@courtesan.com
 *
 *******************************************************************
 *
 *  This module contains sudo_getpwuid(), a function that
 *  Makes a dynamic copy of the struct passwd returned by
 *  getpwuid() and substitutes the shadow password if
 *  necesary.
 *
 *  Todd C. Miller  Mon Nov 20 13:53:06 MST 1995
 */

#ifndef lint
static char rcsid[] = "$Id$";
#endif /* lint */

#include "config.h"

#include <stdio.h>
#ifdef STDC_HEADERS
#include <stdlib.h>
#endif /* STDC_HEADERS */
#if defined(HAVE_MALLOC_H) && !defined(STDC_HEADERS)
#include <malloc.h>   
#endif /* HAVE_MALLOC_H && !STDC_HEADERS */
#ifdef HAVE_STRING_H
#include <string.h>
#endif /* HAVE_STRING_H */
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif /* HAVE_UNISTD_H */
#include <sys/types.h>
#include <sys/param.h>
#include <netinet/in.h>
#include <pwd.h>
#ifdef HAVE_GETSPNAM
#  include <shadow.h>
#endif /* HAVE_GETSPNAM */
#ifdef HAVE_GETPRPWNAM
#  ifdef __hpux
#    include <hpsecurity.h>
#  else
#    include <sys/security.h>
#  endif /* __hpux */
#  include <prot.h>
#endif /* HAVE_GETPRPWNAM */
#ifdef HAVE_GETPWANAM
#  include <sys/label.h>
#  include <sys/audit.h>
#  include <pwdadj.h>
#endif /* HAVE_GETPWANAM */
#ifdef HAVE_GETAUTHUID
#  include <auth.h>
#endif /* HAVE_GETAUTHUID */

#include "sudo.h"

#ifndef STDC_HEADERS
#ifndef __GNUC__                /* gcc has its own malloc */
extern char *malloc     __P((size_t));
#endif /* __GNUC__ */
extern char *getenv     __P((const char *));
#ifdef HAVE_STRDUP
extern char *strdup     __P((const char *));
#endif /* HAVE_STRDUP */
#endif /* !STDC_HEADERS */

/*
 * Global variables (yuck)
 */
#if defined(HAVE_GETPRPWNAM) && defined(__alpha)
int crypt_type = -1;
#endif /* HAVE_GETPRPWNAM && __alpha */


/*
 * Local functions not visible outside getspwuid.c
 */
static char *sudo_getshell	__P((struct passwd *));
static char *sudo_getepw	__P((struct passwd *));



/**********************************************************************
 *
 * sudo_getshell()
 *
 *  This function returns the user's shell based on either the
 *  SHELL evariable or the passwd(5) entry (in that order).
 */

static char *sudo_getshell(pw_ent)
    struct passwd *pw_ent;
{
    char *pw_shell;

    if ((pw_shell = getenv("SHELL")) == NULL)
	pw_shell = pw_ent -> pw_shell;

#ifdef _PATH_BSHELL
    /* empty string "" means bourne shell */
    if (*pw_shell == '\0')
	pw_shell = _PATH_BSHELL;
#endif /* _PATH_BSHELL */

    return(pw_shell);
}


/**********************************************************************
 *
 *  sudo_getepw()
 *
 *  This function returns the encrypted password for the user described
 *  by pw_ent.  If there is a shadow password it is returned, else the
 *  normal UN*X password is returned instead.
 */

static char *sudo_getepw(pw_ent)
    struct passwd *pw_ent;
{
#ifdef HAVE_GETPRPWNAM
    {
	struct pr_passwd *spw_ent;

	spw_ent = getprpwnam(pw_ent->pw_name);
	if (spw_ent != NULL && spw_ent->ufld.fd_encrypt != NULL) {
#  ifdef __alpha
	    crypt_type = spw_ent -> ufld.fd_oldcrypt;
#  endif /* __alpha */
	    return(spw_ent -> ufld.fd_encrypt);
	}
    }
#endif /* HAVE_GETPRPWNAM */
#ifdef HAVE_GETSPNAM
    {
	struct spwd *spw_ent;

	if ((spw_ent = getspnam(pw_ent -> pw_name)) && spw_ent -> sp_pwdp)
	    return(spw_ent -> sp_pwdp);
    }
#endif /* HAVE_GETSPNAM */
#ifdef HAVE_GETSPWUID
    {
	struct s_passwd *spw_ent;

	if ((spw_ent = getspwuid(pw_ent -> pw_uid)) && spw_ent -> pw_passwd)
	    return(spw_ent -> pw_passwd);
    }
#endif /* HAVE_GETSPWUID */
#ifdef HAVE_GETPWANAM
    {
	struct passwd_adjunct *spw_ent;

	if ((spw_ent = getpwanam(pw_ent -> pw_name)) && spw_ent -> pwa_passwd)
	    return(spw_ent -> pwa_passwd);
    }
#endif /* HAVE_GETPWANAM */
#ifdef HAVE_GETAUTHUID
    {
	AUTHORIZATION *spw_ent;

	if ((spw_ent = getauthuid(pw_ent -> pw_uid)) && spw_ent -> a_password)
	    return(spw_ent -> a_password);
    }
#endif /* HAVE_GETAUTHUID */

    /* Fall back on normal passwd */
    return(pw_ent->pw_passwd);
}


/**********************************************************************
 *
 *  sudo_getpwuid()
 *
 *  This function dynamically allocates space for a struct password
 *  and the constituent parts that we care about.  If shadow passwords
 *  are in use, it substitutes the shadow password for pw_passwd.
 */

struct passwd *sudo_getpwuid(uid)
    uid_t uid;
{
    struct passwd *pw_ent, *local_pw_ent;

    if ((pw_ent = getpwuid(uid)) == NULL)
	return(NULL);

    /* allocate space for a local copy of pw_ent */
    local_pw_ent = (struct passwd *) malloc(sizeof(struct passwd));
    if (local_pw_ent == NULL) {
	perror("malloc");
	(void) fprintf(stderr, "%s: cannot allocate memory!\n", Argv[0]);
	exit(1);
    }

    /*
     * Copy the struct passwd and the interesting strings...
     */
    (void) memcpy(local_pw_ent, pw_ent, sizeof(struct passwd));

    local_pw_ent->pw_name = (char *) strdup(pw_ent->pw_name);
    if (local_pw_ent->pw_name == NULL) {
	perror("malloc");
	(void) fprintf(stderr, "%s: cannot allocate memory!\n", Argv[0]);
	exit(1);
    }

    local_pw_ent->pw_dir = (char *) strdup(pw_ent->pw_dir);
    if (local_pw_ent->pw_dir == NULL) {
	perror("malloc");
	(void) fprintf(stderr, "%s: cannot allocate memory!\n", Argv[0]);
	exit(1);
    }

    /* pw_shell is a special case since we overide with $SHELL */
    local_pw_ent->pw_shell = (char *) strdup(sudo_getshell(pw_ent));
    if (local_pw_ent->pw_shell == NULL) {
	perror("malloc");
	(void) fprintf(stderr, "%s: cannot allocate memory!\n", Argv[0]);
	exit(1);
    }

    /* pw_passwd gets a shadow password if applicable */
    local_pw_ent->pw_passwd = (char *) strdup(sudo_getepw(pw_ent));
    if (local_pw_ent->pw_passwd == NULL) {
	perror("malloc");
	(void) fprintf(stderr, "%s: cannot allocate memory!\n", Argv[0]);
	exit(1);
    }

    return(local_pw_ent);
}
