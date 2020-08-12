/*
 * SPDX-License-Identifier: ISC
 *
 * Copyright (c) 2020 Todd C. Miller <Todd.Miller@sudo.ws>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include <config.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <unistd.h>

#define SUDO_ERROR_WRAP 0

#include "sudo_compat.h"
#include "sudo_util.h"
#include "sudo_fatal.h"

#include "iolog_json.h"

sudo_dso_public int main(int argc, char *argv[]);

bool
json_print_object(struct json_container *json, struct json_object *object)
{
    struct json_item *item;
    struct json_value json_value;
    bool ret = false;

    TAILQ_FOREACH(item, &object->items, entries) {
	switch (item->type) {
	case JSON_STRING:
	    json_value.type = JSON_STRING;
	    json_value.u.string = item->u.string;
	    if (!sudo_json_add_value(json, item->name, &json_value))
		goto oom;
	    break;
	case JSON_NUMBER:
	    json_value.type = JSON_NUMBER;
	    json_value.u.number = item->u.number;
	    if (!sudo_json_add_value(json, item->name, &json_value))
		goto oom;
	    break;
	case JSON_OBJECT:
	    if (!sudo_json_open_object(json, item->name))
		goto oom;
	    if (!json_print_object(json, &item->u.child))
		goto done;
	    if (!sudo_json_close_object(json))
		goto oom;
	    break;
	case JSON_ARRAY:
	    if (!sudo_json_open_array(json, item->name))
		goto oom;
	    if (!json_print_object(json, &item->u.child))
		goto done;
	    if (!sudo_json_close_array(json))
		goto oom;
	    break;
	case JSON_BOOL:
	    json_value.type = JSON_BOOL;
	    json_value.u.boolean = item->u.boolean;
	    if (!sudo_json_add_value(json, item->name, &json_value))
		goto oom;
	    break;
	case JSON_NULL:
	    json_value.type = JSON_NULL;
	    if (!sudo_json_add_value(json, item->name, &json_value))
		goto oom;
	    break;
	default:
	    sudo_warnx("unsupported JSON type %d", item->type);
	    goto done;
	}
    }

    ret = true;
    goto done;

oom:
    sudo_warnx("%s: %s", __func__, "unable to allocate memory");
done:
    return ret;
}

static bool
json_format(struct json_container *json, struct json_object *object)
{
    struct json_item *item;
    bool ret = false;

    /* First object holds all the actual data. */
    item = TAILQ_FIRST(&object->items);
    if (item->type != JSON_OBJECT) {
	sudo_warnx("expected JSON_OBJECT, got %d", item->type);
	goto done;
    }
    object = &item->u.child;

    if (!json_print_object(json, object))
	goto done;

    ret = true;

done:
    return ret;
}

static void
usage(void)
{
    fprintf(stderr, "usage: %s [-c] input_file ...\n",
	getprogname());
    exit(EXIT_FAILURE);
}

static bool
compare(FILE *fp, const char *infile, struct json_container *json)
{
    const char *cp;
    unsigned int lineno = 0;
    size_t linesize = 0;
    char *line = NULL;
    ssize_t len;

    cp = sudo_json_get_buf(json);

    while ((len = getdelim(&line, &linesize, '\n', fp)) != -1) {
	lineno++;

	/* skip open/close brace, not present in formatted output */
	if (lineno == 1 && strcmp(line, "{\n") == 0)
	    continue;
	if (*cp == '\0' && strcmp(line, "}\n") == 0)
	    continue;

	/* Ignore newlines in output to make comparison easier. */
	if (*cp == '\n')
	    cp++;
	if (line[len - 1] == '\n')
	    len--;

	if (strncmp(line, cp, len) != 0) {
	    fprintf(stderr, "%s: mismatch on line %u\n", infile, lineno);
	    fprintf(stderr, "expected: %s", line);
	    fprintf(stderr, "got     : %.*s\n", (int)len, cp);
	    return false;
	}
	cp += len;
    }
    free(line);

    return true;
}

int
main(int argc, char *argv[])
{
    struct json_object root;
    int ch, i, tests = 0, errors = 0;
    bool cat = false;

    initprogname(argc > 0 ? argv[0] : "check_iolog_json");

    while ((ch = getopt(argc, argv, "c")) != -1) {
	switch (ch) {
	    case 'c':
		cat = true;
		break;
	    default:
		usage();
	}
    }
    argc -= optind;
    argv += optind;

    if (argc < 1)
	usage();

    for (i = 0; i < argc; i++) {
	struct json_container json;
	const char *infile = argv[i];
	const char *outfile = argv[i];
	const char *cp;
	char pathbuf[PATH_MAX];
	FILE *infp = NULL;
	FILE *outfp = NULL;

	tests++;

	if (!sudo_json_init(&json, 4, false, true)) {
	    errors++;
	    continue;
	}

	/* Parse input file. */
	if ((infp = fopen(infile, "r")) == NULL) {
	    sudo_warn("%s", argv[1]);
	    errors++;
	    goto next;
	}
	if (!iolog_parse_json(infp, infile, &root)) {
	    errors++;
	    goto next;
	}

	/* Format as pretty-printed JSON */
	if (!json_format(&json, &root)) {
	    errors++;
	    goto next;
	}

	/* Check for a .out.ok file in the same location as the .in file. */
	cp = strrchr(infile, '.');
	if (cp != NULL && strcmp(cp, ".in") == 0) {
	    snprintf(pathbuf, sizeof(pathbuf), "%.*s.out.ok",
		(int)(cp - infile), infile);
	    if ((outfp = fopen(pathbuf, "r")) != NULL)
		outfile = pathbuf;
	}
	if (outfp == NULL)
	    outfp = infp;

	/* Compare output to expected output. */
	rewind(outfp);
	if (!compare(outfp, outfile, &json))
	    errors++;

	/* Write the formatted output to stdout for -c (cat) */
	if (cat) {
	    fprintf(stdout, "{%s\n}\n", sudo_json_get_buf(&json));
	    fflush(stdout);
	}

next:
	free_json_items(&root.items);
	sudo_json_free(&json);
	if (infp != NULL)
	    fclose(infp);
	if (outfp != NULL && outfp != infp)
	    fclose(outfp);
    }

    if (tests != 0) {
	printf("iolog_json: %d test%s run, %d errors, %d%% success rate\n",
	    tests, tests == 1 ? "" : "s", errors,
	    (tests - errors) * 100 / tests);
    }

    exit(errors);
}
