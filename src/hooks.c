/*
 * Copyright (c) 2012 Todd C. Miller <Todd.Miller@courtesan.com>
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

#include <sys/types.h>
#include <stdio.h>
#ifdef STDC_HEADERS
# include <stdlib.h>
# include <stddef.h>
#else
# ifdef HAVE_STDLIB_H
#  include <stdlib.h>
# endif
#endif /* STDC_HEADERS */
#ifdef HAVE_STRING_H
# include <string.h>
#endif /* HAVE_STRING_H */
#ifdef HAVE_STRINGS_H
# include <strings.h>
#endif /* HAVE_STRINGS_H */
#ifdef HAVE_UNISTD_H
# include <unistd.h>
#endif /* HAVE_UNISTD_H */

#include "sudo.h"
#include "sudo_plugin.h"
#include "sudo_plugin_int.h"
#include "sudo_debug.h"

/* XXX - autogen from config file? */
/* XXX - implement deregister_hook */

/* HOOK: setenv */

static struct sudo_hook_setenv {
    struct sudo_hook_setenv *next;
    sudo_hook_fn_setenv_t hook_fn;
    void *closure;
} *sudo_hook_setenv_list;

static void
register_hook_setenv(int (*hook_fn)(), void *closure)
{
    struct sudo_hook_setenv *hook;
    debug_decl(add_hook_setenv, SUDO_DEBUG_HOOKS)

    hook = emalloc(sizeof(*hook));
    hook->hook_fn = (sudo_hook_fn_setenv_t)hook_fn;
    hook->closure = closure;
    hook->next = sudo_hook_setenv_list;
    sudo_hook_setenv_list = hook;

    debug_return;
}

int
process_hooks_setenv(const char *name, const char *value, int overwrite)
{
    struct sudo_hook_setenv *hook;
    int rc = SUDO_HOOK_RET_NEXT;
    debug_decl(process_hooks_setenv, SUDO_DEBUG_HOOKS)

    /* First process the hooks. */
    for (hook = sudo_hook_setenv_list; hook != NULL; hook = hook->next) {
	rc = hook->hook_fn(name, value, overwrite, hook->closure);
	switch (rc) {
	    case SUDO_HOOK_RET_NEXT:
		break;
	    case SUDO_HOOK_RET_ERROR:
	    case SUDO_HOOK_RET_STOP:
		goto done;
	    default:
		warningx("invalid setenv hook return value: %d", rc);
		break;
	}
    }
done:
    debug_return_int(rc);
}

/* HOOK: putenv */

static struct sudo_hook_putenv {
    struct sudo_hook_putenv *next;
    sudo_hook_fn_putenv_t hook_fn;
    void *closure;
} *sudo_hook_putenv_list;

static void
register_hook_putenv(int (*hook_fn)(), void *closure)
{
    struct sudo_hook_putenv *hook;
    debug_decl(add_hook_putenv, SUDO_DEBUG_HOOKS)

    hook = emalloc(sizeof(*hook));
    hook->hook_fn = (sudo_hook_fn_putenv_t)hook_fn;
    hook->closure = closure;
    hook->next = sudo_hook_putenv_list;
    sudo_hook_putenv_list = hook;

    debug_return;
}

int
process_hooks_putenv(char *string)
{
    struct sudo_hook_putenv *hook;
    int rc = SUDO_HOOK_RET_NEXT;
    debug_decl(process_hooks_putenv, SUDO_DEBUG_HOOKS)

    /* First process the hooks. */
    for (hook = sudo_hook_putenv_list; hook != NULL; hook = hook->next) {
	rc = hook->hook_fn(string, hook->closure);
	switch (rc) {
	    case SUDO_HOOK_RET_NEXT:
		break;
	    case SUDO_HOOK_RET_ERROR:
	    case SUDO_HOOK_RET_STOP:
		goto done;
	    default:
		warningx("invalid putenv hook return value: %d", rc);
		break;
	}
    }
done:
    debug_return_int(rc);
}

/* HOOK: getenv */

static struct sudo_hook_getenv {
    struct sudo_hook_getenv *next;
    sudo_hook_fn_getenv_t hook_fn;
    void *closure;
} *sudo_hook_getenv_list;

static void
register_hook_getenv(int (*hook_fn)(), void *closure)
{
    struct sudo_hook_getenv *hook;
    debug_decl(add_hook_putenv, SUDO_DEBUG_HOOKS)

    hook = emalloc(sizeof(*hook));
    hook->hook_fn = (sudo_hook_fn_getenv_t)hook_fn;
    hook->closure = closure;
    hook->next = sudo_hook_getenv_list;
    sudo_hook_getenv_list = hook;

    debug_return;
}

int
process_hooks_getenv(const char *name, char **value)
{
    struct sudo_hook_getenv *hook;
    char *val = NULL;
    int rc = SUDO_HOOK_RET_NEXT;
    debug_decl(process_hooks_getenv, SUDO_DEBUG_HOOKS)

    /* First process the hooks. */
    for (hook = sudo_hook_getenv_list; hook != NULL; hook = hook->next) {
	rc = hook->hook_fn(name, &val, hook->closure);
	switch (rc) {
	    case SUDO_HOOK_RET_NEXT:
		break;
	    case SUDO_HOOK_RET_ERROR:
	    case SUDO_HOOK_RET_STOP:
		goto done;
	    default:
		warningx("invalid getenv hook return value: %d", rc);
		break;
	}
    }
done:
    if (val != NULL)
	*value = val;
    debug_return_int(rc);
}

/* HOOK: unsetenv */

static struct sudo_hook_unsetenv {
    struct sudo_hook_unsetenv *next;
    sudo_hook_fn_unsetenv_t hook_fn;
    void *closure;
} *sudo_hook_unsetenv_list;

static void
register_hook_unsetenv(int (*hook_fn)(), void *closure)
{
    struct sudo_hook_unsetenv *hook;
    debug_decl(add_hook_unsetenv, SUDO_DEBUG_HOOKS)

    hook = emalloc(sizeof(*hook));
    hook->hook_fn = (sudo_hook_fn_unsetenv_t)hook_fn;
    hook->closure = closure;
    hook->next = sudo_hook_unsetenv_list;
    sudo_hook_unsetenv_list = hook;

    debug_return;
}

int
process_hooks_unsetenv(const char *name)
{
    struct sudo_hook_unsetenv *hook;
    int rc = SUDO_HOOK_RET_NEXT;
    debug_decl(process_hooks_unsetenv, SUDO_DEBUG_HOOKS)

    /* First process the hooks. */
    for (hook = sudo_hook_unsetenv_list; hook != NULL; hook = hook->next) {
	rc = hook->hook_fn(name, hook->closure);
	switch (rc) {
	    case SUDO_HOOK_RET_NEXT:
		break;
	    case SUDO_HOOK_RET_ERROR:
	    case SUDO_HOOK_RET_STOP:
		goto done;
	    default:
		warningx("invalid unsetenv hook return value: %d", rc);
		break;
	}
    }
done:
    debug_return_int(rc);
}

/* Register the specified hook. */
int
register_hook(struct sudo_hook *hook)
{
    int rval = 0;
    debug_decl(register_hook, SUDO_DEBUG_HOOKS)

    if (SUDO_HOOK_VERSION_GET_MAJOR(hook->hook_version) != SUDO_HOOK_VERSION_MAJOR) {
	/* Major versions must match. */
	rval = -1;
    } else {
	switch (hook->hook_type) {
	    case SUDO_HOOK_GETENV:
		register_hook_getenv(hook->hook_fn, hook->closure);
		break;
	    case SUDO_HOOK_PUTENV:
		register_hook_putenv(hook->hook_fn, hook->closure);
		break;
	    case SUDO_HOOK_SETENV:
		register_hook_setenv(hook->hook_fn, hook->closure);
		break;
	    case SUDO_HOOK_UNSETENV:
		register_hook_unsetenv(hook->hook_fn, hook->closure);
		break;
	    default:
		/* XXX - use define for unknown value */
		rval = 1;
		break;
	}
    }

    debug_return_int(rval);
}
