/*
 * CU sudo version 1.4 (based on Root Group sudo version 1.1)
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
 *		Todd Miller  <Todd.Miller@cs.colorado.edu>
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
#if defined(HAVE_MALLOC_H) && !defined(STDC_HEADERS)
#include <malloc.h>   
#endif /* HAVE_MALLOC_H && !STDC_HEADERS */
#include <pwd.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/param.h>
#include <netinet/in.h>
#include <netdb.h>
#if defined(__osf__) && defined(HAVE_C2_SECURITY)
#include <sys/security.h>
#include <prot.h>
#endif /* __osf__ && HAVE_C2_SECURITY */
#ifdef HAVE_DCE
#include <pthread.h>
#endif /* HAVE_DCE */

#include "sudo.h"
#include <options.h>
#include "version.h"

#ifndef STDC_HEADERS
#ifndef __GNUC__		/* gcc has its own malloc */
extern char *malloc	__P((size_t));
#endif /* __GNUC__ */
#ifdef HAVE_STRDUP
extern char *strdup	__P((const char *));
#endif /* HAVE_STRDUP */
extern char *getenv	__P((char *));
#endif /* STDC_HEADERS */


/*
 * Local type declarations
 */
struct env_table {
    char *name;
    int len;
};


/*
 * Prototypes
 */
static int  parse_args			__P((void));
static void usage			__P((int));
static void load_globals		__P((int));
static int check_sudoers		__P((void));
static void load_cmnd			__P((int));
static void add_env			__P((void));
static void clean_env			__P((char **, struct env_table *));
extern int user_is_exempt		__P((void));
extern struct passwd *sudo_getpwuid	__P((uid_t));

/*
 * Globals
 */
int Argc;
char **Argv;
int NewArgc = 0;
char **NewArgv = NULL;
struct passwd *user_pw_ent;
char *cmnd = NULL;
char *tty = NULL;
char *prompt = PASSPROMPT;
char host[MAXHOSTNAMELEN + 1];
#ifdef FQDN
char shost[MAXHOSTNAMELEN + 1];
#endif /*FQDN */
char cwd[MAXPATHLEN + 1];
struct stat cmnd_st;
extern struct interface *interfaces;
extern int num_interfaces;
extern int printmatches;

/*
 * Table of "bad" envariables to remove and len for strncmp()
 */
struct env_table badenv_table[] = {
    { "IFS=", 4 },
    { "LD_", 3 },
    { "_RLD_", 5 },
#ifdef __hpux
    { "SHLIB_PATH=", 11 },
#endif /* __hpux */
#ifdef _AIX
    { "LIBPATH=", 8 },
#endif /* _AIX */
#ifdef HAVE_KERB4
    { "KRB_CONF", 8 },
#endif
    { (char *) NULL, 0 }
};


/********************************************************************
 *
 *  main()
 *
 *  the driving force behind sudo...
 */

int main(argc, argv)
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
    	case MODE_KILL :
	    cmnd = "kill";
	    break;
	case MODE_LIST :
	    cmnd = "list";
	    printmatches = 1;
	    break;
    }

    /* must have a command to run unless got -s */
    if (cmnd == NULL && NewArgc == 0 && !(sudo_mode & MODE_SHELL))
	usage(1);

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

    load_globals(sudo_mode);	/* load global variables used throughout sudo */

    /*
     * If we got the '-s' option (run shell) we need to redo NewArgv
     * and NewArgc.  This can only be done after load_globals().
     */
    if ((sudo_mode & MODE_SHELL)) {
	char **dst, **src = NewArgv;

	NewArgv = (char **) malloc (sizeof(char *) * (++NewArgc));
	if (NewArgv == NULL) {
	    perror("malloc");
	    (void) fprintf(stderr, "%s: cannot allocate memory!\n", Argv[0]);
	    exit(1);
	}

	/* add the shell as argv[0] */
	if (user_shell && *user_shell) {
	    if ((NewArgv[0] = strrchr(user_shell, '/') + 1) == (char *) 1)
		NewArgv[0] = user_shell;
	} else {
	    (void) fprintf(stderr, "%s: Unable to determine shell.", Argv[0]);
	    exit(1);
	}

	/* copy the args from Argv */
	dst = NewArgv + 1;
	*dst = (char *) NULL;
	while (*src) {
	    *dst++ = *src++;
	}
    }

    rtn = check_sudoers();	/* check mode/owner on _PATH_SUDO_SUDOERS */
    if (rtn != ALL_SYSTEMS_GO) {
	log_error(rtn);
	set_perms(PERM_FULL_USER);
	inform_user(rtn);
	exit(1);
    }

#ifdef SECURE_PATH
    /* replace the PATH envariable with a secure one */
    if (!user_is_exempt())
	sudo_setenv("PATH", SECURE_PATH);
#endif /* SECURE_PATH */

    if ((sudo_mode & MODE_RUN)) {
	load_cmnd(sudo_mode);	/* load the cmnd global variable */
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
    rtn = validate((sudo_mode != MODE_VALIDATE));
    switch (rtn) {

	case VALIDATE_OK:
	    check_user();
	    log_error(ALL_SYSTEMS_GO);
	    if (sudo_mode == MODE_VALIDATE)
		exit(0);
	    set_perms(PERM_FULL_ROOT);
#ifndef PROFILING
	    if ((sudo_mode & MODE_BACKGROUND) && fork() > 0) {
		exit(0);
	    } else {
		/*
		 * Make sure we are not being spoofed.  The stat should
		 * be cheap enough to make this almost bulletproof.
		 */
		if (cmnd_st.st_dev) {
		    struct stat st;

		    if (stat(cmnd, &st) < 0) {
			(void) fprintf(stderr, "%s: unable to stat %s: ",
					Argv[0], cmnd);
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

		EXEC(cmnd, NewArgv);	/* run the command */
	    }
#else
	    exit(0);
#endif /* PROFILING */
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
 *  user_pw_ent, host, cwd, interfaces.
 */

static void load_globals(sudo_mode)
    int sudo_mode;
{
    char *p;
    struct passwd *pw_ent;
#ifdef FQDN
    struct hostent *h_ent;
#endif /* FQDN */

    /*
     * Get a local copy of the user's struct passwd with the shadow password
     * if necesary.  It is assumed that euid is 0 at this point so we
     * can read the shadow passwd file if necesary.
     */
    user_pw_ent = sudo_getpwuid(getuid());
    set_perms(PERM_ROOT);
    set_perms(PERM_USER);
    if (user_pw_ent == NULL) {
	/* need to make a fake user_pw_ent */
	struct passwd pw_ent;
	char pw_name[MAX_UID_T_LEN+1];

	/* fill in uid and name fields with the uid */
	pw_ent.pw_uid = getuid();
	(void) sprintf(pw_name, "%ld", pw_ent.pw_uid);
	pw_ent.pw_name = pw_name;
	user_pw_ent = &pw_ent;

	/* complain, log, and die */
	log_error(GLOBAL_NO_PW_ENT);
	inform_user(GLOBAL_NO_PW_ENT);
	exit(1);
    }

#ifdef HAVE_TZSET
    (void) tzset();		/* set the timezone if applicable */
#endif /* HAVE_TZSET */

    /*
     * Need to get tty early since it's used for logging
     */
    if ((tty = (char *) ttyname(0)) || (tty = (char *) ttyname(1))) {
	if (strncmp(tty, _PATH_DEV, sizeof(_PATH_DEV) - 1) == 0)
	    tty += sizeof(_PATH_DEV) - 1;
	if ((tty = (char *) strdup(tty)) == NULL) {
	    perror("malloc");
	    (void) fprintf(stderr, "%s: cannot allocate memory!\n", Argv[0]);
	    exit(1);
	}
    } else
	tty = "none";

#ifdef UMASK
    (void) umask((mode_t)UMASK);
#endif /* UMASK */

#ifdef NO_ROOT_SUDO
    if (user_uid == 0) {
	(void) fprintf(stderr,
		       "You are already root, you don't need to use sudo.\n");
	exit(1);
    }
#endif

    /*
     * so we know where we are... (do as user)
     */
    if (!getwd(cwd)) {
	/* try as root... */
	set_perms(PERM_ROOT);
	if (!getwd(cwd)) {
	    (void) fprintf(stderr, "%s:  Can't get working directory!\n",
			   Argv[0]);
	    (void) strcpy(cwd, "unknown");
	}
	set_perms(PERM_USER);
    }

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
	if ((h_ent = gethostbyname(host)) == NULL) {
	    log_error(GLOBAL_HOST_UNREGISTERED);
	} else {
	    strcpy(host, h_ent -> h_name);
	    if ((p = strchr(host, '.'))) {
		*p = '\0';
		strcpy(shost, host);
		*p = '.';
	    } else {
		strcpy(shost, host);
	    }
	}    
    }
#else
    }

    /*
     * We don't want to return the fully quallified name unless FQDN is set
     */
    if ((p = strchr(host, '.')))
	*p = '\0';
#endif /* FQDN */

    /*
     * load a list of ip addresses and netmasks into
     * the interfaces array.
     */
    load_interfaces();
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

#ifdef SHELL_IF_NO_ARGS
    if (Argc < 2) {			/* no options and no command */
	ret |= MODE_SHELL;
	return(ret);
    }
#else
    if (Argc < 2)			/* no options and no command */
	usage(1);
#endif /* SHELL_IF_NO_ARGS */

    NewArgv = Argv + 1;
    NewArgc = Argc - 1;
    while (NewArgc > 0 && NewArgv[0][0] == '-') {
	if (NewArgv[0][1] != '\0' && NewArgv[0][2] != '\0') {
	    (void) fprintf(stderr, "%s: Please use single character options\n",
		Argv[0]);
	    usage(1);
	}

	if (excl)
	    usage(1);			/* only one -? option allowed */

	switch (NewArgv[0][1]) {
	    case 'p':
		/* must have an associated prompt */
		if (NewArgv[1] == NULL)
		    usage(1);

		prompt = NewArgv[1];

		/* shift Argv over and adjust Argc */
		NewArgc--;
		NewArgv++;
		break;
	    case 'b':
		ret |= MODE_BACKGROUND;
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
	    case 's':
		ret |= MODE_SHELL;
		break;
	    case '-':
		NewArgc--;
		NewArgv++;
#ifdef SHELL_IF_NO_ARGS
		if (ret == MODE_RUN)
		    ret |= MODE_SHELL;
#endif /* SHELL_IF_NO_ARGS */
		return(ret);
	    case '\0':
		(void) fprintf(stderr, "%s: '-' requires an argument\n",
		    Argv[0]);
		usage(1);
	    default:
		(void) fprintf(stderr, "%s: Illegal option %s\n", Argv[0],
		    NewArgv[0]);
		usage(1);
	}
	NewArgc--;
	NewArgv++;
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
    (void) fprintf(stderr, "usage: %s -V | -h | -l | -v | -k | [-b] [-p prompt] -s | <command>\n", Argv[0]);
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

    /* add the SUDO_COMMAND envariable */
    if (sudo_setenv("SUDO_COMMAND", cmnd)) {
	perror("malloc");
	(void) fprintf(stderr, "%s: cannot allocate memory!\n", Argv[0]);
	exit(1);
    }

    /* add the SUDO_USER envariable */
    if (sudo_setenv("SUDO_USER", user_name)) {
	perror("malloc");
	(void) fprintf(stderr, "%s: cannot allocate memory!\n", Argv[0]);
	exit(1);
    }

    /* add the SUDO_UID envariable */
    (void) sprintf(idstr, "%ld", (long) user_uid);
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
 *  This function sets the cmnd global variable based on Argv
 */

static void load_cmnd(sudo_mode)
    int sudo_mode;
{
    if (strlen(NewArgv[0]) > MAXPATHLEN) {
	errno = ENAMETOOLONG;
	(void) fprintf(stderr, "%s: %s: Pathname too long\n", Argv[0],
		       NewArgv[0]);
	exit(1);
    }

    /*
     * Resolve the path
     */
    if ((cmnd = find_path(NewArgv[0])) == NULL) {
	(void) fprintf(stderr, "%s: %s: command not found\n", Argv[0],
		       NewArgv[0]);
	exit(1);
    }
}



/**********************************************************************
 *
 *  check_sudoers()
 *
 *  This function check to see that the sudoers file is readable,
 *  owned by SUDOERS_OWNER, and not writable by anyone else.
 */

static int check_sudoers()
{
    struct stat statbuf;
    struct passwd *pw_ent;
    int fd;
    char c;
    int rtn = ALL_SYSTEMS_GO;

    if (!(pw_ent = getpwnam(SUDOERS_OWNER)))
	return(SUDOERS_NO_OWNER);

    set_perms(PERM_SUDOERS);

    if ((fd = open(_PATH_SUDO_SUDOERS, O_RDONLY)) < 0 || read(fd, &c, 1) == -1)
	rtn = NO_SUDOERS_FILE;
    else if (lstat(_PATH_SUDO_SUDOERS, &statbuf))
	rtn = NO_SUDOERS_FILE;
    else if (!S_ISREG(statbuf.st_mode))
	rtn = SUDOERS_NOT_FILE;
    else if (statbuf.st_uid != pw_ent -> pw_uid)
	rtn = SUDOERS_WRONG_OWNER;
    else if ((statbuf.st_mode & 0000066))
	rtn = SUDOERS_RW_OTHER;

    (void) close(fd);

    set_perms(PERM_ROOT);
    set_perms(PERM_USER);

    return(rtn);
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
    	    	    	        if (seteuid(user_uid)) {
    	    	    	            perror("seteuid(user_uid)");
    	    	    	            exit(1); 
    	    	    	        }
			      	break;
				
	case   PERM_FULL_USER : 
				if (setuid(0)) {
				    perror("setuid(0)");
				    exit(1);
				}

				if (setuid(user_uid)) {
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
