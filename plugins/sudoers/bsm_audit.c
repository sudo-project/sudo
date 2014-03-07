/*
 * Copyright (c) 2009-2013 Todd C. Miller <Todd.Miller@courtesan.com>
 * Copyright (c) 2009 Christian S.J. Peron
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

#include <bsm/audit.h>
#include <bsm/libbsm.h>
#include <bsm/audit_uevents.h>

#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include <pwd.h>
#include <errno.h>
#include <unistd.h>

#define DEFAULT_TEXT_DOMAIN	"sudoers"
#include "gettext.h"		/* must be included before missing.h */

#include "missing.h"
#include "fatal.h"
#include "sudo_debug.h"
#include "bsm_audit.h"

/*
 * Solaris auditon() returns EINVAL if BSM audit not configured.
 * OpenBSM returns ENOSYS for unimplemented options.
 */
#ifdef __sun
# define AUDIT_NOT_CONFIGURED	EINVAL
#else
# define AUDIT_NOT_CONFIGURED	ENOSYS
#endif

static int
audit_sudo_selected(int sf)
{
	auditinfo_addr_t ainfo_addr;
	struct au_mask *mask;
	auditinfo_t ainfo;
	int rc, sorf;
	debug_decl(audit_sudo_selected, SUDO_DEBUG_AUDIT)

	if (getaudit_addr(&ainfo_addr, sizeof(ainfo_addr)) < 0) {
		if (errno == ENOSYS) {
			if (getaudit(&ainfo) < 0)
				fatal("getaudit");
			mask = &ainfo.ai_mask;
		} else
			fatal("getaudit");
        } else
		mask = &ainfo_addr.ai_mask;
	sorf = (sf == 0) ? AU_PRS_SUCCESS : AU_PRS_FAILURE;
	rc = au_preselect(AUE_sudo, mask, sorf, AU_PRS_REREAD);
        debug_return_int(rc);
}

void
bsm_audit_success(char **exec_args)
{
	auditinfo_addr_t ainfo_addr;
	auditinfo_t ainfo;
	token_t *tok;
	au_id_t auid;
	long au_cond;
	int aufd;
	pid_t pid;
	debug_decl(bsm_audit_success, SUDO_DEBUG_AUDIT)

	pid = getpid();
	/*
	 * If we are not auditing, don't cut an audit record; just return.
	 */
	if (auditon(A_GETCOND, (caddr_t)&au_cond, sizeof(long)) < 0) {
		if (errno == AUDIT_NOT_CONFIGURED)
			return;
		fatal(U_("Could not determine audit condition"));
	}
	if (au_cond == AUC_NOAUDIT)
		debug_return;
	/*
	 * Check to see if the preselection masks are interested in seeing
	 * this event.
	 */
	if (!audit_sudo_selected(0))
		debug_return;
	if (getauid(&auid) < 0)
		fatal("getauid");
	if ((aufd = au_open()) == -1)
		fatal("au_open");
	if (getaudit_addr(&ainfo_addr, sizeof(ainfo_addr)) == 0) {
		tok = au_to_subject_ex(auid, geteuid(), getegid(), getuid(),
		    getuid(), pid, pid, &ainfo_addr.ai_termid);
	} else if (errno == ENOSYS) {
		/*
		 * NB: We should probably watch out for ERANGE here.
		 */
		if (getaudit(&ainfo) < 0)
			fatal("getaudit");
		tok = au_to_subject(auid, geteuid(), getegid(), getuid(),
		    getuid(), pid, pid, &ainfo.ai_termid);
	} else
		fatal("getaudit");
	if (tok == NULL)
		fatal("au_to_subject");
	au_write(aufd, tok);
	tok = au_to_exec_args(exec_args);
	if (tok == NULL)
		fatal("au_to_exec_args");
	au_write(aufd, tok);
	tok = au_to_return32(0, 0);
	if (tok == NULL)
		fatal("au_to_return32");
	au_write(aufd, tok);
#ifdef __sun
	if (au_close(aufd, 1, AUE_sudo, 0) == -1)
#else
	if (au_close(aufd, 1, AUE_sudo) == -1)
#endif
		fatal(U_("unable to commit audit record"));
	debug_return;
}

void
bsm_audit_failure(char **exec_args, char const *const fmt, va_list ap)
{
	auditinfo_addr_t ainfo_addr;
	auditinfo_t ainfo;
	char text[256];
	token_t *tok;
	long au_cond;
	au_id_t auid;
	pid_t pid;
	int aufd;
	debug_decl(bsm_audit_success, SUDO_DEBUG_AUDIT)

	pid = getpid();
	/*
	 * If we are not auditing, don't cut an audit record; just return.
	 */
	if (auditon(A_GETCOND, (caddr_t)&au_cond, sizeof(long)) < 0) {
		if (errno == AUDIT_NOT_CONFIGURED)
			debug_return;
		fatal(U_("Could not determine audit condition"));
	}
	if (au_cond == AUC_NOAUDIT)
		debug_return;
	if (!audit_sudo_selected(1))
		debug_return;
	if (getauid(&auid) < 0)
		fatal("getauid");
	if ((aufd = au_open()) == -1)
		fatal("au_open");
	if (getaudit_addr(&ainfo_addr, sizeof(ainfo_addr)) == 0) { 
		tok = au_to_subject_ex(auid, geteuid(), getegid(), getuid(),
		    getuid(), pid, pid, &ainfo_addr.ai_termid);
	} else if (errno == ENOSYS) {
		if (getaudit(&ainfo) < 0) 
			fatal("getaudit");
		tok = au_to_subject(auid, geteuid(), getegid(), getuid(),
		    getuid(), pid, pid, &ainfo.ai_termid);
	} else
		fatal("getaudit");
	if (tok == NULL)
		fatal("au_to_subject");
	au_write(aufd, tok);
	tok = au_to_exec_args(exec_args);
	if (tok == NULL)
		fatal("au_to_exec_args");
	au_write(aufd, tok);
	(void) vsnprintf(text, sizeof(text), fmt, ap);
	tok = au_to_text(text);
	if (tok == NULL)
		fatal("au_to_text");
	au_write(aufd, tok);
	tok = au_to_return32(EPERM, 1);
	if (tok == NULL)
		fatal("au_to_return32");
	au_write(aufd, tok);
#ifdef __sun
	if (au_close(aufd, 1, AUE_sudo, PAD_FAILURE) == -1)
#else
	if (au_close(aufd, 1, AUE_sudo) == -1)
#endif
		fatal(U_("unable to commit audit record"));
	debug_return;
}
