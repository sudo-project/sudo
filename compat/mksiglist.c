#include <config.h>

#include <stdio.h>
#ifdef STDC_HEADERS
# include <stdlib.h>
# include <stddef.h>
#else
# ifdef HAVE_STDLIB_H
#  include <stdlib.h>
# endif
#endif /* STDC_HEADERS */
#include <signal.h>

#include "compat.h"

#if !defined(NSIG)
# if defined(_NSIG)
#  define NSIG _NSIG
# elif defined(__NSIG)
#  define NSIG __NSIG
# else
#  error one of NSIG, _NSIG, or __NSIG must be defined
# endif
#endif

int
main(int argc, char *argv[])
{
    static char *my_sys_siglist[NSIG];
    int i;

#include "mksiglist.h"

    printf("#include <config.h>\n");
    printf("#include <signal.h>\n");
    printf("#include <compat.h>\n\n");
    printf("const char *const my_sys_siglist[NSIG] = {\n");
    for (i = 0; i < NSIG; i++) {
	if (my_sys_siglist[i] != NULL) {
	    printf("    \"%s\",\n", my_sys_siglist[i]);
	} else {
	    printf("    \"Signal %d\",\n", i);
	}
    }
    printf("};\n");

    exit(0);
}
