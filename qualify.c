#include <stdio.h>
#include <strings.h>
#include <sys/param.h>

char * mfq (p)
    char * p;			/* path to make fully qualified */
{
    char * tmp1, * tmp2;
    static char path[MAXPATHLEN+1];
    int done = 0;

    if ( *p == '/' )		/* starts at root */
    {
	path[0] = '\0';
	++p;
    }
    else
#ifdef hpux
	getcwd(path, (size_t)(MAXPATHLEN+1));
#else
	getwd(path);
#endif

    while ((tmp1 = index(p, '/')) || !done)
    {
	if (tmp1)
    	    *tmp1 = '\0';		/* only want up to '/' */
	else
	    done = 1;

	if (!strcmp(p, ".."))
	{
	    tmp2 = rindex(path, '/');
	    if (tmp2)
		*tmp2 = '\0';	/* nuke last component if it exists */
	}
	else if (strcmp(p, "."))	/* not .. or . */
	{
	    strcat(path, "/");		/* add a '/' */
	    strcat(path, p);		/* add component form p */
	}

	if (tmp1)
	{
	    *tmp1 = '/';		/* leave p as we found it */
	    p = tmp1 + 1;
	}
    }

    return((char *)path);
}
