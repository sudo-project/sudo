#include <stdio.h>
#include <strings.h>
#include <sys/param.h>
#include <sys/stat.h>
#include "sudo.h"

/*
 * qualify() takes a path and makes it fully qualified and resolves
 * all symbolic links, returning the fully qualfied path.
 */

char * qualify(n)
    char * n;				/* name to make fully qualified */
{
    char * beg = NULL;			/* begining of a path component */
    char * end;				/* end of a path component */
    char * tmp;				/* temporary pointer */
    char name[MAXPATHLEN+1];		/* local copy of n */
    char full[MAXPATHLEN+1];		/* the fully qualified name */
    struct stat statbuf;		/* for lstat() */
    /* for lint and gcc -Wall */
#ifdef USE_CWD
    char * getcwd();
#else
    char * getwd();
#endif
    int fprintf();
    int readlink();
    int stat();
    int lstat();
    char * strdup();

    if (stat(n, &statbuf))		/* is it a bogus path? */
	return(NULL);

    /* if n is relative, fill full with working dir */
    if (*n != '/')
    {
#ifdef USE_CWD
	if (!getcwd(full, (size_t)(MAXPATHLEN+1)))
#else
	if (!getwd(full))
#endif
	{
	    fprintf(stderr, "Can't get working dir!  Quitting\n");
	    exit(-1);
	}
    }
    else
	full[0] = '\0';

    strcpy(name, n);			/* working copy... */

    do					/* while (end) */
    {
	if (beg)
	    beg = end + 1;		/* skip past the NULL */
	else
	    beg = name;			/* just starting out... */

	/* find and terminate end of path component */
	if ((end = index(beg, '/')))
	    *end = '\0';

	if (beg == end)
	    continue;
	else if (!strcmp(beg, "."))
	    ;				/* ignore "." */
	else if (!strcmp(beg, ".."))
	{
	    tmp = rindex(full, '/');
	    if (tmp && tmp != &full[0])
		*tmp = '\0';
	}
	else
	{
	    strcat(full, "/");
	    strcat(full, beg);		/* copy in new component */
	}

	/* check for symbolic links */
	lstat(full, &statbuf);
	if ((statbuf.st_mode & S_IFMT) == S_IFLNK)
	{
	    char newname[MAXPATHLEN+1];
	    int linklen;

	    linklen = readlink(full, newname, sizeof(newname));
	    newname[linklen] = '\0';
	    
	    /* check to make sure we don't go past MAXPATHLEN */
	    ++end;
	    if (end != (char *)1)
	    {
		if (linklen + strlen(end) >= MAXPATHLEN)
		{
		    fprintf(stderr, "Symbolic link too long!  Quitting\n");
		    exit(-1);
		}

		strcat(newname, "/");
		strcat(newname, end);	/* copy what's left of end */
	    }

	    if (newname[0] == '/')	/* reset full if necesary */
		full[0] = '\0';
	    else
		if ((tmp = rindex(full, '/')))	/* remove component from full */
		    *tmp = '\0';

	    strcpy(name, newname);	/* reset name with new path */
	    beg = NULL;			/* since we have a new name */
	}
    }
    while (end);

    return(strdup(full));		/* malloc space for return path */
}

/******************************************************************
 *
 *  strdup()
 *
 *  this function returns a pointer a string copied into 
 *  a malloc()ed buffer
 */

char * strdup(s1)
    char *s1;
{
    char * s;
    char * strcpy();
    char * malloc();

    if ((s = (char *) malloc(strlen(s1) + 1)) == NULL)
	return (NULL);

    (void)strcpy(s, s1);
    return(s);
}

extern char *malloc();
extern char *getenv();

extern char **Argv;
char *find_path();
char *strdup();



/*******************************************************************
 *
 * find_path()
 *
 * this function finds the full pathname for a command
 */

char *find_path(file)
char *file;
{
    register char *n;
    char *path=NULL;
    char fn[MAXPATHLEN+1];
    char *cmd;
    struct stat statbuf;		/* for stat() */

    if ( strlen ( file ) > MAXPATHLEN ) {
	fprintf ( stderr, "%s:  path too long:  %s\n", Argv[0], file );
	exit (1);
    }
	
    /* do we need to search the path? */
    if ( index(file, '/') )
	return (qualify(file));

    /* grab PATH out of environment and make a local copy */
    if ( ( path = getenv("PATH") ) == NULL )
	return ( NULL ) ;

    if ( ( path=strdup(path) ) == NULL ) {
	perror ( "find_path:  malloc" );
	exit (1);
    }

    while ( n = index ( path, ':' ) ) {
	*n='\0';
	strcpy(fn, path);
	strcat(fn, "/");
	strcat(fn, file);

	/* stat the file to make sure it exists and is executable */
	if (!stat(fn, &statbuf) && (statbuf.st_mode & 0000111))
	    return (qualify(fn));
	else
	    path=n+1;
    }
    return(NULL);
}
