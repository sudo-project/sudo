/*
 * Copyright (c) 1999-2005, 2007, 2010-2015
 *	Todd C. Miller <Todd.Miller@courtesan.com>
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
 *
 * Sponsored in part by the Defense Advanced Research Projects
 * Agency (DARPA) and Air Force Research Laboratory, Air Force
 * Materiel Command, USAF, under agreement number F39502-99-1-0512.
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
#include <pwd.h>
#include <signal.h>
#include <siad.h>

#include "sudoers.h"
#include "sudo_auth.h"

static int sudo_collect(int, int, uchar_t *, int, prompt_t *);

static char *def_prompt;
static char **sudo_argv;
static int sudo_argc;

#define PROMPT_IS_PASSWORD(_p) \
    (strncmp((_p), "Password:", 9) == 0 && \
	((_p)[9] == '\0' || ((_p)[9] == ' ' && (_p)[10] == '\0')))

/*
 * Collection routine (callback) for limiting the timeouts in SIA
 * prompts and (possibly) setting a custom prompt.
 */
static int
sudo_collect(int timeout, int rendition, uchar_t *title, int nprompts,
    prompt_t *prompts)
{
    int rval;
    sigset_t mask, omask;
    debug_decl(sudo_collect, SUDOERS_DEBUG_AUTH)

    switch (rendition) {
	case SIAFORM:
	case SIAONELINER:
	    if (timeout <= 0 || timeout > def_passwd_timeout * 60)
		timeout = def_passwd_timeout * 60;
	    /*
	     * Substitute custom prompt if a) the sudo prompt is not "Password:"
	     * and b) the SIA prompt is "Password:" (so we know it is safe).
	     * This keeps us from overwriting things like S/Key challenges.
	     */
	    if (!PROMPT_IS_PASSWORD(def_prompt) &&
		PROMPT_IS_PASSWORD((char *)prompts[0].prompt))
		prompts[0].prompt = (unsigned char *)def_prompt;
	    break;
	default:
	    break;
    }

    /* Unblock SIGINT and SIGQUIT during password entry. */
    sigemptyset(&mask);
    sigaddset(&mask, SIGINT);
    sigaddset(&mask, SIGQUIT);
    sigprocmask(SIG_UNBLOCK, &mask, &omask);

    rval = sia_collect_trm(timeout, rendition, title, nprompts, prompts);

    /* Restore previous signal mask. */
    sigprocmask(SIG_SETMASK, &omask, NULL);

    debug_return_int(rval);
}

int
sudo_sia_setup(struct passwd *pw, char **promptp, sudo_auth *auth)
{
    SIAENTITY *siah = NULL;
    int i;
    debug_decl(sudo_sia_setup, SUDOERS_DEBUG_AUTH)

    /* Rebuild argv for sia_ses_init() */
    sudo_argc = NewArgc + 1;
    sudo_argv = sudo_emallocarray(sudo_argc + 1, sizeof(char *));
    sudo_argv[0] = "sudo";
    for (i = 0; i < NewArgc; i++)
	sudo_argv[i + 1] = NewArgv[i];
    sudo_argv[sudo_argc] = NULL;

    if (sia_ses_init(&siah, sudo_argc, sudo_argv, NULL, pw->pw_name, user_ttypath, 1, NULL) != SIASUCCESS) {

	log_warning(0, N_("unable to initialize SIA session"));
	debug_return_int(AUTH_FATAL);
    }

    auth->data = (void *) siah;
    debug_return_int(AUTH_SUCCESS);
}

int
sudo_sia_verify(struct passwd *pw, char *prompt, sudo_auth *auth)
{
    SIAENTITY *siah = (SIAENTITY *) auth->data;
    debug_decl(sudo_sia_verify, SUDOERS_DEBUG_AUTH)

    def_prompt = prompt;		/* for sudo_collect */

    /* XXX - need a way to detect user hitting ^C or EOF at prompt */
    if (sia_ses_reauthent(sudo_collect, siah) == SIASUCCESS)
	debug_return_int(AUTH_SUCCESS);
    else
	debug_return_int(AUTH_FAILURE);
}

int
sudo_sia_cleanup(struct passwd *pw, sudo_auth *auth)
{
    SIAENTITY *siah = (SIAENTITY *) auth->data;
    debug_decl(sudo_sia_cleanup, SUDOERS_DEBUG_AUTH)

    (void) sia_ses_release(&siah);
    sudo_efree(sudo_argv);
    debug_return_int(AUTH_SUCCESS);
}
