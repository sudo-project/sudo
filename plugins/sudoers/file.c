/*
 * Copyright (c) 2004-2005, 2007-2018 Todd C. Miller <Todd.Miller@sudo.ws>
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
 * OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
 * ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <config.h>

#include <sys/types.h>
#include <stdio.h>
#include <stdlib.h>
#ifdef HAVE_STRING_H
# include <string.h>
#endif /* HAVE_STRING_H */
#ifdef HAVE_STRINGS_H
# include <strings.h>
#endif /* HAVE_STRINGS_H */
#include <unistd.h>
#include <ctype.h>
#include <grp.h>
#include <pwd.h>
#include <time.h>

#include "sudoers.h"
#include "parse.h"
#include "sudo_lbuf.h"
#include <gram.h>

struct sudo_file_handle {
    FILE *fp;
    struct defaults_list defaults;
    struct userspec_list userspecs;
};

static int
sudo_file_close(struct sudo_nss *nss)
{
    debug_decl(sudo_file_close, SUDOERS_DEBUG_NSS)
    struct sudo_file_handle *handle = nss->handle;

    if (handle != NULL) {
	fclose(handle->fp);
	sudoersin = NULL;

	free_userspecs(&handle->userspecs);
	free_defaults(&handle->defaults);

	free(handle);
	nss->handle = NULL;
    }

    debug_return_int(0);
}

static int
sudo_file_open(struct sudo_nss *nss)
{
    debug_decl(sudo_file_open, SUDOERS_DEBUG_NSS)
    struct sudo_file_handle *handle;

    if (def_ignore_local_sudoers)
	debug_return_int(-1);

    if (nss->handle != NULL) {
	sudo_debug_printf(SUDO_DEBUG_ERROR,
	    "%s: called with non-NULL handle %p", __func__, nss->handle);
	sudo_file_close(nss);
    }

    handle = malloc(sizeof(*handle));
    if (handle != NULL) {
	handle->fp = open_sudoers(sudoers_file, false, NULL);
	if (handle->fp != NULL) {
	    TAILQ_INIT(&handle->userspecs);
	    TAILQ_INIT(&handle->defaults);
	} else {
	    free(handle);
	    handle = NULL;
	}
    }
    nss->handle = handle;
    debug_return_int(nss->handle ? 0 : -1);
}

/*
 * Parse the specified sudoers file.
 */
static int
sudo_file_parse(struct sudo_nss *nss)
{
    debug_decl(sudo_file_close, SUDOERS_DEBUG_NSS)
    struct sudo_file_handle *handle = nss->handle;

    if (handle == NULL || handle->fp == NULL) {
	sudo_debug_printf(SUDO_DEBUG_ERROR, "%s: called with NULL %s",
	    __func__, handle ? "file pointer" : "handle");
	debug_return_int(-1);
    }

    sudoersin = handle->fp;
    if (sudoersparse() != 0 || parse_error) {
	if (errorlineno != -1) {
	    log_warningx(SLOG_SEND_MAIL, N_("parse error in %s near line %d"),
		errorfile, errorlineno);
	} else {
	    log_warningx(SLOG_SEND_MAIL, N_("parse error in %s"), errorfile);
	}
	debug_return_int(-1);
    }

    /* Move parsed userspecs and defaults to nss structure. */
    TAILQ_CONCAT(&handle->userspecs, &userspecs, entries);
    TAILQ_CONCAT(&handle->defaults, &defaults, entries);

    debug_return_int(0);
}

/*
 * We return all cached userspecs, the parse functions will
 * perform matching against pw for us.
 */
static struct userspec_list *
sudo_file_query(struct sudo_nss *nss, struct passwd *pw)
{
    struct sudo_file_handle *handle = nss->handle;
    debug_decl(sudo_file_query, SUDOERS_DEBUG_NSS)

    if (handle == NULL) {
	sudo_debug_printf(SUDO_DEBUG_ERROR,
	    "%s: called with NULL handle", __func__);
	debug_return_ptr(NULL);
    }
    debug_return_ptr(&handle->userspecs);
}

/*
 * Return cached defaults entries.
 */
static struct defaults_list *
sudo_file_getdefs(struct sudo_nss *nss)
{
    debug_decl(sudo_file_getdefs, SUDOERS_DEBUG_NSS)
    struct sudo_file_handle *handle = nss->handle;

    if (handle == NULL) {
	sudo_debug_printf(SUDO_DEBUG_ERROR,
	    "%s: called with NULL handle", __func__);
	debug_return_ptr(NULL);
    }
    debug_return_ptr(&handle->defaults);
}

/* sudo_nss implementation */
struct sudo_nss sudo_nss_file = {
    { NULL, NULL },
    sudo_file_open,
    sudo_file_close,
    sudo_file_parse,
    sudo_file_query,
    sudo_file_getdefs
};
