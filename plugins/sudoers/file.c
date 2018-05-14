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

/*
 * Local prototypes.
 */
static int sudo_file_close(struct sudo_nss *);
static int sudo_file_open(struct sudo_nss *);
static int sudo_file_parse(struct sudo_nss *);
static int sudo_file_query(struct sudo_nss *, struct passwd *pw);
static int sudo_file_getdefs(struct sudo_nss *);

/* sudo_nss implementation */
struct sudo_nss sudo_nss_file = {
    { NULL, NULL },
    sudo_file_open,
    sudo_file_close,
    sudo_file_parse,
    sudo_file_query,
    sudo_file_getdefs
};

static int
sudo_file_open(struct sudo_nss *nss)
{
    debug_decl(sudo_file_open, SUDOERS_DEBUG_NSS)

    if (def_ignore_local_sudoers)
	debug_return_int(-1);
    nss->handle = open_sudoers(sudoers_file, false, NULL);
    debug_return_int(nss->handle ? 0 : -1);
}

static int
sudo_file_close(struct sudo_nss *nss)
{
    struct member_list *prev_binding = NULL;
    struct defaults *def;
    struct userspec *us;
    debug_decl(sudo_file_close, SUDOERS_DEBUG_NSS)

    if (nss->handle != NULL) {
	fclose(nss->handle);
	nss->handle = NULL;
	sudoersin = NULL;

	/* XXX - do in main module? */
	while ((us = TAILQ_FIRST(&nss->userspecs)) != NULL) {
	    TAILQ_REMOVE(&nss->userspecs, us, entries);
	    free_userspec(us);
	}
	while ((def = TAILQ_FIRST(&nss->defaults)) != NULL) {
	    TAILQ_REMOVE(&nss->defaults, def, entries);
	    free_default(def, &prev_binding);
	}
    }

    debug_return_int(0);
}

/*
 * Parse the specified sudoers file.
 */
static int
sudo_file_parse(struct sudo_nss *nss)
{
    debug_decl(sudo_file_close, SUDOERS_DEBUG_NSS)

    if (nss->handle == NULL)
	debug_return_int(-1);

    sudoersin = nss->handle;
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
    TAILQ_CONCAT(&nss->userspecs, &userspecs, entries);
    TAILQ_CONCAT(&nss->defaults, &defaults, entries);

    debug_return_int(0);
}

/*
 * No need for explicit queries for sudoers file, we have it all in memory.
 */
static int
sudo_file_query(struct sudo_nss *nss, struct passwd *pw)
{
    debug_decl(sudo_file_query, SUDOERS_DEBUG_NSS)
    debug_return_int(0);
}

/*
 * No need to get defaults for sudoers file, the parse function handled it.
 */
static int
sudo_file_getdefs(struct sudo_nss *nss)
{
    debug_decl(sudo_file_getdefs, SUDOERS_DEBUG_NSS)
    debug_return_int(0);
}
