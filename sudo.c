/*
 * CU sudo version 1.3.1 (based on Root Group sudo version 1.1)
 *
 * This software comes with no waranty whatsoever, use at your own risk.
 *
 * Please send bugs, changes, problems to sudo-bugs.cs.colorado.edu
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
#include <netdb.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/socket.h>
#ifdef HAVE_SYS_SOCKIO_H
#include <sys/sockio.h>
#else
#include <sys/ioctl.h>
#endif /* HAVE_SYS_SOCKIO_H */
#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <sys/param.h>
#ifdef _AIX
#include <sys/id.h>
#endif /* _AIX */

#include "sudo.h"
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
 * local functions not visible outside sudo.c
 */
static int  parse_args		__P((void));
static void usage		__P((int));
static void load_globals	__P((void));
static void load_interfaces	__P((void));
static void load_cmnd		__P((void));
static void add_env		__P((void));
static void rmenv		__P((char **, char *, int));
static void clean_env		__P((char **));

/*
 * Globals
 */
int Argc;
char **Argv;
char *cmnd;
char *user;
char *epasswd;
char host[MAXHOSTNAMELEN + 1];
struct interface *interfaces;
int num_interfaces;
char cwd[MAXPATHLEN + 1];
uid_t uid = -2;


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

    Argv = argv;
    Argc = argc;

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

    clean_env(environ);		/* clean up the environment (no LD_*) */

    load_globals();		/* load the user host cmnd and uid variables */

    if (sudo_mode == MODE_RUN) {
	load_cmnd();		/* load the cmnd global variable */
    } else if (sudo_mode == MODE_KILL) {
	remove_timestamp();	/* remove the timestamp ticket file */
	exit(0);
    }

    add_env();			/* add in SUDO_* envariables */

    rtn = validate();		/* validate the user */
    switch (rtn) {

	case VALIDATE_OK:
	    check_user();
	    log_error(ALL_SYSTEMS_GO);
	    if (sudo_mode == MODE_VALIDATE)
		exit(0);
	    be_root();
	    EXEC(cmnd, &Argv[1]);
	    perror(cmnd);		/* exec failed! */
	    exit(-1);
	    break;

	case VALIDATE_NO_USER:
	case VALIDATE_NOT_OK:
	case VALIDATE_ERROR:
	default:
	    log_error(rtn);
	    be_full_user();
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
    struct hostent *h_ent;
    char *p;

    uid = getuid();		/* we need to tuck this away for safe keeping */

#ifdef HAVE_TZSET
    (void) tzset();		/* set the timezone if applicable */
#endif /* HAVE_TZSET */

    /*
     * loading the user & epasswd global variable from the passwd file
     * (must be done as root to get real passwd on some systems)
     */
    if ((pw_ent = getpwuid(uid)) == NULL) {
	(void) sprintf(user, "%u", uid);
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
     * This will effectively do setreuid(0, uid) but for portability...
     */
    be_root();
    be_user();

#ifdef UMASK
    (void) umask((mode_t)UMASK);
#endif /* UMASK */

    /*
     * so we know where we are... (do as user)
     */
    if (!getcwd(cwd, (size_t) sizeof(cwd))) {
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
    int ret=MODE_RUN;			/* what mode is suod to be run in? */

    if (Argc < 2)			/* no options and no command */
	usage(1);

    if (Argv[1][0] == '-') {
	if (Argc > 2)			/* only one -? option allowed */
	    usage(1);

	if (Argv[1][1] != '\0' && Argv[1][2] != '\0') {
	    fprintf(stderr, "%s: Please use single character options\n", Argv[0]);
	    usage(1);
	}

	switch (Argv[1][1]) {
	    case 'v':
		ret = MODE_VALIDATE;
		break;
	    case 'k':
		ret = MODE_KILL;
		break;
	    case 'V':
		ret = MODE_VERSION;
		break;
	    case 'h':
		ret = MODE_HELP;
		break;
	    case '\0':
		fprintf(stderr, "%s: '-' requires an argument\n", Argv[0]);
		usage(1);
	    default:
		fprintf(stderr, "%s: Illegal option %s\n", Argv[0], Argv[1]);
		usage(1);
	}
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
    (void) fprintf(stderr, "usage: %s -V | -h | -v | -k | <command>\n", Argv[0]);
    exit(exit_val);
}



/**********************************************************************
 *
 *  clean_env()
 *
 *  This function builds cleans up the environ pointer so that all execv*()'s
 *  omit LD_* variables and hard-code PATH if SECURE_PATH is defined.
 */

static void clean_env(envp)
    char **envp;
{
    /*
     * omit all LD_* environmental vars
     */
    rmenv(envp, "LD_", 3);
#ifdef __hpux
    rmenv(envp, "SHLIB_PATH", 10);
#endif /* __hpux */
#ifdef _AIX
    rmenv(envp, "LIBPATH", 7);
#endif /* _AIX */
#ifdef __alpha
    rmenv(envp, "_RLD_", 5);
#endif /* __alpha */

#ifdef SECURE_PATH
    sudo_setenv("PATH", SECURE_PATH);
#endif /* SECURE_PATH */
}



/**********************************************************************
 *
 * be_root()
 *
 *  this function sets the real and effective uids to 0
 */

void be_root()
{
    if (setuid(0)) {
        perror("setuid(0)");
        exit(1); 
    }
}



/**********************************************************************
 *
 * be_user()
 *
 *  this function sets the effective uid to the value of uid.
 *  Naturally, we need to do something completely different for AIX.
 */

#ifdef _AIX
void be_user()
{
    if (setuidx(ID_EFFECTIVE|ID_REAL, uid)) {
        perror("setuidx(ID_EFFECTIVE|ID_REAL, uid)");
        exit(1); 
    }
}
#else /* _AIX */
void be_user()
{
    if (seteuid(uid)) {
        perror("seteuid(uid)");
        exit(1); 
    }
}
#endif /* _AIX */



/**********************************************************************
 *
 * be_full_user()
 *
 *  this function sets the real and effective uids to the value of uid
 *  since our euid is probably already uid we need to setuid(0) first
 */

void be_full_user()
{
    if (setuid(0)) {
        perror("setuid(0)");
        exit(1); 
    }
    if (setuid(uid)) {
        perror("setuid(uid)");
        exit(1); 
    }
}



/**********************************************************************
 *
 * rmenv()
 *
 *  this function removes things from the environment that match the
 *  string "s" up to length len [ie: with strncmp()].
 */

static void rmenv(envp, s, len)
    char ** envp;				/* pointer to environment */
    char * s;					/* string to search for */
    int len;					/* how much of it to check */
{
    char ** tenvp;				/* temp env pointer */
    char ** move;				/* used to move around */

    /*
     * cycle through the environment and purge strings that match s
     */
    for (tenvp=envp; *tenvp; tenvp++) {
	if (!strncmp(*tenvp, s, len)) {
	    /* matched: remove by shifting everything below one up */
	    for (move=tenvp; *move; move++)
		*move = *(move+1);
	    tenvp--;
	}
    }
}



/**********************************************************************
 *
 * add_env()
 *
 *  this function adds sudo-specific variables into the environment
 */

static void add_env()
{
    char *uidstr;
    int len, n;

    /* add the SUDO_USER envariable */
    if (sudo_setenv("SUDO_USER", user)) {
	perror("malloc");
	(void) fprintf(stderr, "%s: cannot allocate memory!\n", Argv[0]);
	exit(1);
    }

    /* add the SUDO_UID envariable */
    for (len = 1 + (uid < 0), n = (int)uid; (n = n / 10) != 0; )
	++len;
    
    uidstr = (char *) malloc(len+1);
    if (uidstr == NULL) {
	perror("malloc");
	(void) fprintf(stderr, "%s: cannot allocate memory!\n", Argv[0]);
	exit(1);
    }

    (void) sprintf(uidstr, "%d", (int)uid);
    if (sudo_setenv("SUDO_UID", uidstr)) {
	perror("malloc");
	(void) fprintf(stderr, "%s: cannot allocate memory!\n", Argv[0]);
	exit(1);
    }
    (void) free(uidstr);
}



/**********************************************************************
 *
 *  load_cmnd()
 *
 *  This function sets the cmnd global variable based on Argv[1]
 */

static void load_cmnd()
{
    char path[MAXPATHLEN + 1];

    strncpy(path, Argv[1], MAXPATHLEN)[MAXPATHLEN] = 0;

    cmnd = find_path(path);	/* get the absolute path */
    if (cmnd == NULL) {
	(void) fprintf(stderr, "%s: %s: command not found\n", Argv[0], Argv[1]);
	exit(1);
    }
}



/**********************************************************************
 *
 *  load_interfaces()
 *
 *  This function sets the interfaces global variable
 *  and sets the constituent ip addrs and netmasks.
 */

static void load_interfaces()
{
    struct ifconf ifconf;
    struct ifreq ifreq;
    struct in_addr *inptr;
    char buf[BUFSIZ];
    int sock, len;
    int i, j;

    sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
	perror("socket");
	exit(1);
    }

    /*
     * get interface configuration or return (leaving interfaces NULL)
     */
    ifconf.ifc_len = sizeof(buf);
    ifconf.ifc_buf = buf;
    if (ioctl(sock, SIOCGIFCONF, (char *)(&ifconf)) < 0) {
	/* networking probably not installed in kernel */
	return;
    }

    /*
     * find out how many interfaces exist, skipping bogus ones.
     */
    len = num_interfaces = ifconf.ifc_len / sizeof(struct ifreq);
    for (i = 0; i < len; i++) {
	inptr = &(((struct sockaddr_in *)&ifconf.ifc_req[i].ifr_addr)->sin_addr);
	if (inptr->s_addr == inet_addr("127.0.0.1") ||
	    inptr->s_addr == inet_addr("255.255.255.255") ||
	    inptr->s_addr == inet_addr("0.0.0.0"))
	    --num_interfaces;
    }

    /*
     * malloc() space for interfaces array
     */
    interfaces = (struct interface *) malloc(sizeof(struct interface) *
	num_interfaces);
    if (interfaces == NULL) {
	perror("malloc");
	(void) fprintf(stderr, "%s: cannot allocate memory!\n", Argv[0]);
	exit(1);
    }

    /*
     * for each interface, get the ip address and netmask
     */
    for (i = 0, j = 0; i < len; i++) {

	inptr = &(((struct sockaddr_in *)&ifconf.ifc_req[i].ifr_addr)->sin_addr);

	/* get the ip address */
	if (inptr->s_addr == inet_addr("127.0.0.1") ||
	    inptr->s_addr == inet_addr("255.255.255.255") ||
	    inptr->s_addr == inet_addr("0.0.0.0"))
	    continue;

	(void) memcpy(&interfaces[j].addr, inptr, sizeof(struct in_addr));

	/* get the netmask */
#ifdef SIOCGIFNETMASK
	(void) strcpy(ifreq.ifr_name, ifconf.ifc_req[i].ifr_name);
	if (ioctl(sock, SIOCGIFNETMASK, (char *)(&ifreq)) >= 0) {
	    (void) memcpy(&interfaces[j].netmask,
			  &(((struct sockaddr_in *)&ifreq.ifr_addr)->sin_addr),
			  sizeof(struct in_addr));
	} else {
#else
	{
#endif /* SIOCGIFNETMASK */
	    if (IN_CLASSC(interfaces[j].addr.s_addr))
		interfaces[j].netmask.s_addr = htonl(IN_CLASSC_NET);
	    else if (IN_CLASSB(interfaces[j].addr.s_addr))
		interfaces[j].netmask.s_addr = htonl(IN_CLASSB_NET);
	    else
		interfaces[j].netmask.s_addr = htonl(IN_CLASSA_NET);
	}
	++j;
    }
}
