/*
 * CU sudo version 1.3.1 (based on Root Group sudo version 1.1)
 *
 * This software comes with no waranty whatsoever, use at your own risk.
 *
 * Please send bugs, changes, problems to sudo-bugs@cs.colorado.edu
 *
 */

/*
 *  sudo version 1.1 allows users to execute commands as root
 *  Copyright (C) 1991  The Root Group, Inc.
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
 **************************************************************************
 *
 *   sudo.c
 *
 *   This is the main() routine for sudo
 *
 *   sudo is a program to allow users to execute commands 
 *   as root.  The commands are defined in a global network-
 *   wide file and can be distributed.
 *
 *   sudo has been hacked far and wide.  Too many people to
 *   know about.  It's about time to come up with a secure
 *   version that will work well in a network.
 *
 *   This most recent version is done by:
 *
 *              Jeff Nieusma <nieusma@rootgroup.com>
 *              Dave Hieb    <davehieb@rootgroup.com>
 *
 *   However, due to the fact that both of the above are no longer
 *   working at Root Group, I am maintaining the "CU version" of
 *   sudo.
 *		Todd Miller  <millert@cs.colorado.edu>
 */

#ifndef lint
static char rcsid[] = "$Id$";
#endif /* lint */

#define MAIN

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
#ifdef HAVE_MALLOC_H 
#include <malloc.h>   
#endif /* HAVE_MALLOC_H */ 
#include <pwd.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/param.h>
#include <netinet/in.h>
#if defined(__osf__) && defined(HAVE_C2_SECURITY)
#include <sys/security.h>
#include <prot.h>
#endif /* __osf__ && HAVE_C2_SECURITY */

#include "sudo.h"
#include "options.h"
#include "version.h"

#ifndef STDC_HEADERS
#ifndef __GNUC__		/* gcc has its own malloc */
extern char *malloc	__P((size_t));
#endif /* __GNUC__ */
#ifdef HAVE_STRDUP
extern char *strdup	__P((const char *));
#endif /* HAVE_STRDUP */
#endif /* STDC_HEADERS */


/*
 * Local type declarations
 */
struct env_table {
    char *name;
    int len;
};


/*
 * local functions not visible outside sudo.c
 */
static int  parse_args		__P((void));
static void usage		__P((int));
static void load_globals	__P((void));
static int check_sudoers	__P((void));
static void load_cmnd		__P((void));
static void add_env		__P((void));
static void clean_env		__P((char **, struct env_table *));
extern int user_is_exempt	__P((void));

/*
 * Globals
 */
int Argc;
char **Argv;
char *cmnd = NULL;
char *user = NULL;
char *epasswd = NULL;
char *prompt = PASSPROMPT;
char host[MAXHOSTNAMELEN + 1];
char cwd[MAXPATHLEN + 1];
uid_t uid = (uid_t)-2;
struct stat cmnd_st;
extern struct interface *interfaces;
extern int num_interfaces;
extern int printmatches;

/*
 * Table of "bad" envariables to remove and len for strncmp()
 */
struct env_table badenv_table[] = {
    { "LD_", 3 },
#ifdef __hpux
    { "SHLIB_PATH=", 11 },
#endif /* __hpux */
#ifdef _AIX
    { "LIBPATH=", 8 },
#endif /* _AIX */
#if defined (__osf__) && defined(__alpha)
    { "_RLD_", 5 },
#endif /* __alpha && __alpha */
    { "IFS=", 4 },
    { (char *) NULL, 0 }
};


/********************************************************************
 *
 *  main ()
 *
 *  the driving force behind sudo...
 */

main(argc, argv)
    int argc;
    char **argv;
{
    int rtn;
    int sudo_mode = MODE_RUN;
    extern char ** environ;

#if defined(SHADOW_TYPE) && (SHADOW_TYPE == SPW_SECUREWARE)
    (void) set_auth_parameters(argc, argv);
#endif /* SHADOW_TYPE && SPW_SECUREWARE */

    Argv = argv;
    Argc = argc;

    if (geteuid() != 0) {
	(void) fprintf(stderr, "Sorry, %s must be setuid root.\n", Argv[0]);
	exit(1);
    }

    /*
     * parse our arguments
     */
    sudo_mode = parse_args();

    switch(sudo_mode) {
	case MODE_VERSION :
	case MODE_HELP :
	    (void) printf("CU Sudo version %s\n", version);
	    if (sudo_mode == MODE_VERSION)
		exit(0);
	    else
		usage(0);
	    break;
	case MODE_VALIDATE :
	    cmnd = "validate";
	    break;
	case MODE_LIST :
	    cmnd = "list";
	    printmatches = 1;
	    break;
	case MODE_BACKGROUND :
	    if (Argc == 1)
		usage(1);
	    break;
    }

    /*
     * Close all file descriptors to make sure we have a nice
     * clean slate from which to work.  
     */
#ifdef HAVE_SYSCONF
    for (rtn = sysconf(_SC_OPEN_MAX) - 1; rtn > 3; rtn--)
	(void) close(rtn);
#else
    for (rtn = getdtablesize() - 1; rtn > 3; rtn--)
	(void) close(rtn);
#endif /* HAVE_SYSCONF */

    clean_env(environ, badenv_table);

    load_globals();		/* load the user host cmnd and uid variables */

    rtn = check_sudoers();	/* check mode/owner on _PATH_SUDO_SUDOERS */
    if (rtn != ALL_SYSTEMS_GO) {
	log_error(rtn);
	set_perms(PERM_FULL_USER);
	inform_user(rtn);
	exit(1);
    }

    if (sudo_mode == MODE_RUN || sudo_mode == MODE_BACKGROUND) {
	load_cmnd();		/* load the cmnd global variable */
    } else if (sudo_mode == MODE_KILL) {
	remove_timestamp();	/* remove the timestamp ticket file */
	exit(0);
    } else if (sudo_mode == MODE_LIST) {
	check_user();
	log_error(ALL_SYSTEMS_GO);
	(void) validate(FALSE);
	exit(0);
    }

    add_env();			/* add in SUDO_* envariables */

    /* validate the user but don't search for "validate" */
    rtn = validate(sudo_mode != MODE_VALIDATE);
    switch (rtn) {

	case VALIDATE_OK:
	    check_user();
	    log_error(ALL_SYSTEMS_GO);
	    if (sudo_mode == MODE_VALIDATE)
		exit(0);
	    set_perms(PERM_FULL_ROOT);
#ifndef GPROF
	    if (sudo_mode == MODE_BACKGROUND && fork() > 0) {
		exit(0);
	    } else {
		/*
		 * Make sure we are not being spoofed.  The stat should
		 * be cheap enough to make this almost bulletproof.
		 */
		if (cmnd_st.st_dev) {
		    struct stat st;

		    if (stat(cmnd, &st) < 0) {
			fprintf(stderr, "%s: unable to stat %s:", Argv[0],
					cmnd);
			perror("");
			exit(1);
		    }

		    if (st.st_dev != cmnd_st.st_dev ||
			st.st_ino != cmnd_st.st_ino) {
			/* log and send mail, then bitch */
			log_error(SPOOF_ATTEMPT);
			inform_user(SPOOF_ATTEMPT);
			exit(1);
		    }
		}

		EXEC(cmnd, &Argv[1]);
	    }
#else
	    exit(0);
#endif /* GPROF */
	    perror(cmnd);		/* exec failed! */
	    exit(-1);
	    break;

	case VALIDATE_NO_USER:
	case VALIDATE_NOT_OK:
	case VALIDATE_ERROR:
	default:
	    log_error(rtn);
	    set_perms(PERM_FULL_USER);
	    inform_user(rtn);
	    exit(1);
	    break;
    }
}



/**********************************************************************
 *
 *  load_globals()
 *
 *  This function primes these important global variables:
 *  user, host, cwd, uid
 */

static void load_globals()
{
    struct passwd *pw_ent;
#ifdef FQDN
    struct hostent *h_ent;
#endif /* FQDN */
    char *p;

    uid = getuid();		/* we need to tuck this away for safe keeping */

#ifdef HAVE_TZSET
    (void) tzset();		/* set the timezone if applicable */
#endif /* HAVE_TZSET */

    /*
     * loading the user & epasswd global variable from the passwd file
     * (must be done as root to get real passwd on some systems)
     */
    set_perms(PERM_ROOT);
    if ((pw_ent = getpwuid(uid)) == NULL) {
	set_perms(PERM_USER);
	if ((user = (char *)malloc(MAX_UID_T_LEN + 1)) == NULL) {
	    perror("malloc");
	    (void) fprintf(stderr, "%s: cannot allocate memory!\n", Argv[0]);
	    exit(1);
	}
	(void) sprintf(user, "%ld", uid);
	log_error(GLOBAL_NO_PW_ENT);
	inform_user(GLOBAL_NO_PW_ENT);
	exit(1);
    }

    user = strdup(pw_ent -> pw_name);
    epasswd = strdup(pw_ent -> pw_passwd);
    if (user == NULL || epasswd == NULL) {
	perror("malloc");
	(void) fprintf(stderr, "%s: cannot allocate memory!\n", Argv[0]);
	exit(1);
    }

    /*
     * We only want to be root when we absolutely need it.
     * Since we set euid and ruid to 0 above, this will set the euid
     * to the * uid of the caller so (ruid, euid) == (0, user's uid).
     */
    set_perms(PERM_USER);

#ifdef UMASK
    (void) umask((mode_t)UMASK);
#endif /* UMASK */

    /*
     * so we know where we are... (do as user)
     */
    if (!getwd(cwd)) {
    	(void) fprintf(stderr, "%s:  Can't get working directory!\n", Argv[0]);
	exit(1);
    }

#ifdef NO_ROOT_SUDO
    if (uid == 0) {
	(void) fprintf(stderr, "You are already root, you don't need to use sudo.\n");
	exit(1);
    }
#endif

    /*
     * load the host global variable from gethostname()
     * and use gethostbyname() if we want it to be fully qualified.
     */
    if ((gethostname(host, MAXHOSTNAMELEN))) {
	strcpy(host, "localhost");
	log_error(GLOBAL_NO_HOSTNAME);
	inform_user(GLOBAL_NO_HOSTNAME);
#ifdef FQDN
    } else {
	if ((h_ent = gethostbyname(host)) == NULL)
	    log_error(GLOBAL_HOST_UNREGISTERED);
	else
	    strcpy(host, h_ent -> h_name);
    }
#else
    }

    /*
     * load a list of ip addresses and netmasks into
     * the interfaces array.
     */
    load_interfaces();

    /*
     * We don't want to return the fully quallified name unless FQDN is set
     */
    if ((p = strchr(host, '.')))
	*p = '\0';
#endif /* FQDN */
}



/**********************************************************************
 *
 * parse_args()
 *
 *  this function parses the arguments to sudo
 */

static int parse_args()
{
    int ret = MODE_RUN;			/* what mode is suod to be run in? */
    int excl = 0;			/* exclusive arg, no others allowed */
    char *progname = Argv[0];		/* so we can save Argv[0] */
    int i;

    if (Argc < 2)			/* no options and no command */
	usage(1);

    while (Argc > 1 && Argv[1][0] == '-') {
	if (Argv[1][1] != '\0' && Argv[1][2] != '\0') {
	    (void) fprintf(stderr, "%s: Please use single character options\n",
		progname);
	    usage(1);
	}

	if (excl)
	    usage(1);			/* only one -? option allowed */

	switch (Argv[1][1]) {
	    case 'p':
		if (Argc < 4)
		    usage(1);

		prompt = Argv[2];

		/* shift Argv over and adjust Argc */
		Argc--;
		Argv++;
		break;
	    case 'b':
		ret = MODE_BACKGROUND;
		break;
	    case 'v':
		ret = MODE_VALIDATE;
		excl++;
		break;
	    case 'k':
		ret = MODE_KILL;
		excl++;
		break;
	    case 'l':
		ret = MODE_LIST;
		excl++;
		break;
	    case 'V':
		ret = MODE_VERSION;
		excl++;
		break;
	    case 'h':
		ret = MODE_HELP;
		excl++;
		break;
	    case '\0':
		(void) fprintf(stderr, "%s: '-' requires an argument\n",
		    progname);
		usage(1);
	    default:
		(void) fprintf(stderr, "%s: Illegal option %s\n", progname,
		    Argv[1]);
		usage(1);
	}
	Argc--;
	Argv++;
	Argv[0] = progname;
    }

    return(ret);
}



/**********************************************************************
 *
 * usage()
 *
 *  this function just gives you instructions and exits
 */

static void usage(exit_val)
    int exit_val;
{
    (void) fprintf(stderr, "usage: %s -V | -h | -l | -b | -v | -k | [-p prompt] <command>\n", Argv[0]);
    exit(exit_val);
}



/**********************************************************************
 *
 * add_env()
 *
 *  this function adds sudo-specific variables into the environment
 */

static void add_env()
{
    char idstr[MAX_UID_T_LEN + 1];

#ifdef SECURE_PATH
    /* replace the PATH envariable with a secure one */
    if (!user_is_exempt())
	sudo_setenv("PATH", SECURE_PATH);
#endif /* SECURE_PATH */

    /* add the SUDO_COMMAND envariable */
    if (sudo_setenv("SUDO_COMMAND", cmnd)) {
	perror("malloc");
	(void) fprintf(stderr, "%s: cannot allocate memory!\n", Argv[0]);
	exit(1);
    }

    /* add the SUDO_USER envariable */
    if (sudo_setenv("SUDO_USER", user)) {
	perror("malloc");
	(void) fprintf(stderr, "%s: cannot allocate memory!\n", Argv[0]);
	exit(1);
    }

    /* add the SUDO_UID envariable */
    (void) sprintf(idstr, "%ld", (long) uid);
    if (sudo_setenv("SUDO_UID", idstr)) {
	perror("malloc");
	(void) fprintf(stderr, "%s: cannot allocate memory!\n", Argv[0]);
	exit(1);
    }

    /* add the SUDO_GID envariable */
    (void) sprintf(idstr, "%ld", (long) getegid());
    if (sudo_setenv("SUDO_GID", idstr)) {
	perror("malloc");
	(void) fprintf(stderr, "%s: cannot allocate memory!\n", Argv[0]);
	exit(1);
    }
}



/**********************************************************************
 *
 *  load_cmnd()
 *
 *  This function sets the cmnd global variable based on Argv[1]
 */

static void load_cmnd()
{
    if (strlen(Argv[1]) > MAXPATHLEN) {
	errno = ENAMETOOLONG;
	(void) fprintf(stderr, "%s: %s: Pathname too long\n", Argv[0], Argv[1]);
	exit(1);
    }

    /*
     * Resolve the path
     */
    if ((cmnd = find_path(Argv[1])) == NULL) {
	(void) fprintf(stderr, "%s: %s: command not found\n", Argv[0], Argv[1]);
	exit(1);
    }
}



/**********************************************************************
 *
 *  check_sudoers()
 *
 *  This function check to see that the sudoers file is owned by
 *  SUDOERS_OWNER and not writable by anyone else.
 */

static int check_sudoers()
{
    struct stat statbuf;
    struct passwd *pw_ent;

    if (!(pw_ent = getpwnam(SUDOERS_OWNER)))
	return(SUDOERS_NO_OWNER);

    if (lstat(_PATH_SUDO_SUDOERS, &statbuf))
	return(NO_SUDOERS_FILE);
    else if (!S_ISREG(statbuf.st_mode))
	return(SUDOERS_NOT_FILE);
    else if (statbuf.st_uid != pw_ent -> pw_uid)
        return(SUDOERS_WRONG_OWNER);
    else if ((statbuf.st_mode & 0000066))
        return(SUDOERS_RW_OTHER); 

    return(ALL_SYSTEMS_GO);
}



/**********************************************************************
 *
 * set_perms()
 *
 *  this function sets real and effective uids and gids based on perm.
 */

void set_perms(perm)
    int perm;
{
    struct passwd *pw_ent;

    switch(perm) {
	case        PERM_ROOT :
				if (setuid(0)) {
				    perror("setuid(0)");
				    exit(1);
				}
			      	break;

	case   PERM_FULL_ROOT :
				if (setuid(0)) {  
				    perror("setuid(0)");
				    exit(1);
				}

				if (!(pw_ent = getpwuid(0))) {
				    perror("getpwuid(0)");
				} else if (setgid(pw_ent->pw_gid)) {
				    perror("setgid");
    	    	    	    	}
			      	break;

	case        PERM_USER : 
    	    	    	        if (seteuid(uid)) {
    	    	    	            perror("seteuid(uid)");
    	    	    	            exit(1); 
    	    	    	        }
			      	break;
				
	case   PERM_FULL_USER : 
				if (setuid(0)) {
				    perror("setuid(0)");
				    exit(1);
				}

				if (setuid(uid)) {
				    perror("setuid(uid)");
				    exit(1);
				}

			      	break;

	case   PERM_SUDOERS : 
				if (setuid(0)) {
				    perror("setuid(0)");
				    exit(1);
				}

				if (!(pw_ent = getpwnam(SUDOERS_OWNER))) {
				    (void) fprintf(stderr, "%s: no passwd entry for sudoers file owner (%s)\n", Argv[0], SUDOERS_OWNER);
				    exit(1);
				} else if (seteuid(pw_ent->pw_uid)) {
				    (void) fprintf(stderr, "%s: ",
							   SUDOERS_OWNER);
				    perror("");
				    exit(1);
    	    	    	    	}

			      	break;
    }
}



/**********************************************************************
 *
 * clean_env()
 *
 *  This function removes things from the environment that match the
 *  entries in badenv_table.  It would be nice to add in the SUDO_*
 *  variables here as well but cmnd has not been defined at this point.
 */

static void clean_env(envp, badenv_table)
    char **envp;
    struct env_table *badenv_table;
{
    struct env_table *bad;
    char **cur;

    /*
     * Remove any envars that match entries in badenv_table
     */
    for (cur = envp; *cur; cur++) {
	for (bad = badenv_table; bad -> name; bad++) {
	    if (strncmp(*cur, bad -> name, bad -> len) == 0) {
		/* got a match so remove it */
		char **move;

		for (move = cur; *move; move++)
		    *move = *(move + 1);

		cur--;

		break;
	    }
	}
    }
}
