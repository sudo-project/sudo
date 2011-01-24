/*	$OpenBSD: globtest.c,v 1.1 2008/10/01 23:04:36 millert Exp $	*/

/*
 * Public domain, 2008, Todd C. Miller <Todd.Miller@courtesan.com>
 */

#include <config.h>

#include <stdio.h>
#include <stdlib.h>
#ifdef HAVE_STRING_H
# include <string.h>
#endif /* HAVE_STRING_H */
#ifdef HAVE_STRINGS_H
# include <strings.h>
#endif /* HAVE_STRINGS_H */
#ifdef HAVE_GLOB
# include <glob.h>
#else
# include "compat/glob.h"
#endif

#define MAX_RESULTS	256

struct gl_entry {
	int flags;
	int nresults;
	char pattern[1024];
	char *results[MAX_RESULTS];
};

int test_glob(struct gl_entry *);

int
main(int argc, char **argv)
{
	FILE *fp = stdin;
	char *buf, *cp;
	int errors = 0, tests = 0, lineno;
	struct gl_entry entry;
	size_t len;

	if (argc > 1) {
		if ((fp = fopen(argv[1], "r")) == NULL) {
			perror(argv[1]);
			exit(1);
		}
	}

	/*
	 * Read in test file, which is formatted thusly:
	 *
	 * [pattern] <flags>
	 * result1
	 * result2
	 * result3
	 * ...
	 *
	 */
	lineno = 0;
	memset(&entry, 0, sizeof(entry));
	while ((buf = fgetln(fp, &len)) != NULL) {
		lineno++;
		if (buf[len - 1] != '\n') {
			fprintf(stderr, "globtest: missing newline at EOF\n");
			exit(1);
		}
		buf[--len] = '\0';
		if (len == 0)
			continue; /* blank line */

		if (buf[0] == '[') {
			/* check previous pattern */
			if (entry.pattern[0]) {
				errors += test_glob(&entry);
				tests++;
			}

			/* start new entry */
			if ((cp = strrchr(buf + 1, ']')) == NULL) {
				fprintf(stderr,
				    "globtest: invalid entry on line %d\n",
				    lineno);
				exit(1);
			}
			len = cp - buf - 1;
			if (len >= sizeof(entry.pattern)) {
				fprintf(stderr,
				    "globtest: pattern too big on line %d\n",
				    lineno);
				exit(1);
			}
			memcpy(entry.pattern, buf + 1, len);
			entry.pattern[len] = '\0';

			buf = cp + 2;
			if (*buf++ != '<') {
				fprintf(stderr,
				    "globtest: invalid entry on line %d\n",
				    lineno);
				exit(1);
			}
			if ((cp = strchr(buf, '>')) == NULL) {
				fprintf(stderr,
				    "globtest: invalid entry on line %d\n",
				    lineno);
				exit(1);
			}
			entry.flags = (int)strtol(buf, &cp, 0);
			if (*cp != '>' || entry.flags < 0 || entry.flags > 0x2000) {
				fprintf(stderr,
				    "globtest: invalid flags: %s\n", buf);
				exit(1);
			}
			entry.nresults = 0;
			continue;
		}
		if (!entry.pattern[0]) {
			fprintf(stderr, "globtest: missing entry on line %d\n",
			    lineno);
			exit(1);
		}

		if (entry.nresults + 1 > MAX_RESULTS) {
			fprintf(stderr,
			    "globtest: too many results for %s, max %d\n",
			    entry.pattern, MAX_RESULTS);
			exit(1);
		}
		entry.results[entry.nresults++] = strdup(buf);
	}
	if (entry.pattern[0]) {
		errors += test_glob(&entry); /* test last pattern */
		tests++;
	}
        if (tests != 0) {
		printf("glob: %d test%s run, %d errors, %d%% success rate\n",
		    tests, tests == 1 ? "" : "s", errors,
		    (tests - errors) * 100 / tests);
        }
	exit(errors);
}

int test_glob(struct gl_entry *entry)
{
	glob_t gl;
	int i = 0;

	if (glob(entry->pattern, entry->flags, NULL, &gl) != 0) {
		fprintf(stderr, "glob failed: %s", entry->pattern);
		exit(1);
	}

	if (gl.gl_matchc != entry->nresults)
		goto mismatch;

	for (i = 0; i < gl.gl_matchc; i++) {
		if (strcmp(gl.gl_pathv[i], entry->results[i]) != 0)
			goto mismatch;
		free(entry->results[i]);
	}
	return 0;
 mismatch:
	fprintf(stderr, "globtest: mismatch for pattern %s, flags 0x%x "
	    "(found \"%s\", expected \"%s\")\n", entry->pattern, entry->flags,
	    gl.gl_pathv[i], entry->results[i]);
	while (i < gl.gl_matchc) {
		free(entry->results[i++]);
	}
	return 1;
}
