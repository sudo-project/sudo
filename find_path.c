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
 *  If you make modifications to the source, we would be happy to have
 *  them to include in future releases.  Feel free to send them to:
 *      Jeff Nieusma                       nieusma@rootgroup.com
 *      3959 Arbol CT                      (303) 447-8093
 *      Boulder, CO 80301-1752             
 *
 *******************************************************************
 *
 *  This module contains the find_path() command that returns
 *  a pointer to a static area with the absolute path of the 
 *  command or NULL if the command is not found in the path
 *
 *  I also added the strdup() function in here after I found most
 *  systems don't have it...
 *
 *  Jeff Nieusma  Thu Mar 21 23:11:23 MST 1991
 */

#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/param.h>
#include <string.h>
#include <strings.h>
extern char *malloc();
extern char *getenv();

extern char **Argv;
char *find_path();
static char *do_stat();
static char *check_link();
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
char *cmd;

if ( strlen ( file ) > MAXPATHLEN ) {
    fprintf ( stderr, "%s:  path too long:  %s\n", Argv[0], file );
    exit (1);
    }
    
if ( *file == '.' && *(file+1) == '/' || *file == '/' ) 
    return ( do_stat ( NULL, file ) );

if ( ( path=getenv("PATH") ) == NULL ) return ( NULL ) ;
if ( ( path=strdup(path) ) == NULL ) {
    perror ( "find_path:  malloc" );
    exit (1);
    }

while ( n = index ( path, ':' ) ) {
    *n='\0';
    if ( cmd = do_stat ( path, file ) ) return ( cmd );
    path=n+1;
    }

if ( cmd = do_stat ( path, file ) ) 
    return ( cmd );
else
    return ( NULL );
	
}




/**********************************************************************
 * 
 * check_link()
 * 
 * this function makes sure the argument is not a symbolic link.
 * it returns the pathname of the binary or NULL
 */

static char *check_link(path)
char *path;
{
char buf1[MAXPATHLEN+1];    /* is the link */
char *s, *buf;
register int rtn;

/* the recursive buck stops here */
if ( path == NULL ) return NULL ;

/* I'd rather play with pointers than arrays... */
buf = buf1;

/* If this is NOT a sym link, return */
if ( ( rtn=readlink(path, buf, MAXPATHLEN)) < 0 )
    return (path);

/* if it is a sym link, NULL terminate the string */
buf[rtn]='\0';

/* if the link points to an absolute path, start again... */
if ( *buf == '/' ) return ( do_stat( NULL, buf ) );

/* if the link points to ./something or something/ we need to 
 * strip off the filename portion of the current path */
if ( ( s=rindex(path,'/') ) == NULL ) {
    fprintf( stderr, "check_link:  This path is very wierd: %s \n", path );
    exit (1);
    }
else
    *s='\0';

/* as long as the link has ./ or ../ in it, get rid of it... */
while ( *buf == '.' ) {

    if ( strncmp(buf, "../", 3) == 0 ) {
	if ( ( s=rindex(path, '/')) ) {
            *s='\0';
	    if ( *path == '\0' ) strcpy ( path, "/" );
	    }
	buf += 3; 
	continue;
	}
    else if ( strncmp(buf, "./", 2) == 0 ) {
	buf += 2;
	continue;
	}
    else 
	break;

    }

/* we have to copy the path buffer since do_stat() will bzero() it */
if ( ( s = strdup ( path ) ) == NULL ) {
    perror ( "check_link:  malloc" );
    exit (1);
    }

return ( do_stat ( s, buf ) );
}



/******************************************************************
 *
 *   do_stat()
 *
 *    This function takes a path and a file and stat()s the file
 *    If the file exists and is executable, the full path to that
 *    file is returned otherwise NULL is returned.
 */

static char *do_stat( path, file )
char *path, *file;
{
static char buf[MAXPATHLEN+1];
struct stat s;
register char type;


if ( *file == '.' && *(file+1) == '/' ) 
    type=1;
else  if ( *file == '/' )
    type=2;
else  if ( path == NULL )
    type=2;
else  if ( *path == '.' && *(path+1) == (char)NULL )
    type=3;
else
    type=0;


switch ( type ) {
    case 1:
        file += 2;
    case 3:
	if ( (path=(char *)malloc(MAXPATHLEN+1)) == NULL ) {
	    perror ("do_stat:  malloc");
	    exit (1);
	    }
#ifdef hpux
	if ( ! getcwd ( path, (size_t)(MAXPATHLEN+1) ) ) {
	    perror ("do_stat:  getcwd");
	    exit (1);
	    }
#else
	if ( ! getwd ( path ) ) {
	    perror ("do_stat:  getwd");
	    exit (1);
	    }
#endif
        break;
    case 2:
    default:
        break;
    }
    
    
if ( ( ( path? strlen(path) : 0 ) + strlen (file) ) > MAXPATHLEN - 1 ) {
    fprintf ( stderr, "%s:  path too long:  %s/%s\n", Argv[0], path, file );
    exit (1);
    }

bzero ( buf, MAXPATHLEN+1 );
if ( path ) strcat ( buf, path );
if ( *file != '/' && path [strlen(path)-1] != '/' ) strcat ( buf, "/" );
strcat ( buf, file );
if ( ! stat ( buf, &s ) && (s.st_mode & 0000111) >= 0000001 )
    return ( check_link ( buf ) );
else
    return ( NULL );

}




/******************************************************************
 *
 *  strdup()
 *
 *  this function returns a pointer a string copied into 
 *  a malloc()ed buffer
 */

char *strdup(s1)
char *s1;
{
char *s;
if ( ( s=(char *)malloc(strlen(s1)+1)) == NULL )
    return (NULL);
strcpy(s,s1);
return (s);
}
