/*
 * Copyright (c) 1999 Todd C. Miller <Todd.Miller@courtesan.com>
 * All rights reserved.
 *
 * This code is derived from software contributed by Frank Cusack
 * <fcusack@iconnet.net>.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES,
 * INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY
 * AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL
 * THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS;
 * OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
 * OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
 * ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "config.h"

#include <stdio.h>
#ifdef STDC_HEADERS
#include <stdlib.h>
#endif /* STDC_HEADERS */
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif /* HAVE_UNISTD_H */
#ifdef HAVE_STRING_H
#include <string.h>
#endif /* HAVE_STRING_H */
#ifdef HAVE_STRINGS_H
#include <strings.h>
#endif /* HAVE_STRINGS_H */
#include <sys/param.h>
#include <sys/types.h>
#include <pwd.h>
#include <krb5.h>

#include "sudo.h"
#include "sudo_auth.h"

#ifndef lint
static const char rcsid[] = "$Sudo$";
#endif /* lint */

char *realm = NULL;
static int xrealm = 0;
static krb5_context sudo_context = NULL;

static int verify_krb_v5_tgt __P((krb5_ccache));

int
kerb5_init(pw, promptp, data)
    struct passwd *pw;
    char **promptp;
    void **data;
{
    char *lrealm;
    krb5_error_code retval;
    extern int arg_prompt;

    /* XXX - make these errors non-fatal for better fallback? */
    if (retval = krb5_init_context(&sudo_context)) {
	/* XXX - how to map retval to error string? */
	log_error(NO_EXIT|NO_MAIL, 
	    "unable to initialize Kerberos V context");
	return(AUTH_FATAL);
    }
    *data = (void *) &sudo_context;	/* save a pointer to the context */

    krb5_init_ets(sudo_context);

    if (retval = krb5_get_default_realm(sudo_context, &lrealm)) {
	set_perms(PERM_USER, 0);
	log_error(NO_EXIT|NO_MAIL, 
	    "unable to get default Kerberos V realm");
	return(AUTH_FATAL);
    }

    if (realm) {
	if (strcmp(realm, lrealm) != 0)
	    xrealm = 1; /* User supplied realm is not the system default */
	free(lrealm);
    } else
	realm = lrealm;

    /* Only rewrite prompt if user didn't specify their own. */
    if (!strcmp(prompt, PASSPROMPT))
	easprintf(promptp, "Password for %s@%s: ", pw->pw_name, realm);
    return(AUTH_SUCCESS);
}

int
kerb5_verify(pw, pass, data)
    struct passwd *pw;
    char *pass;
    void **data;
{
    krb5_error_code	retval;
    krb5_principal	princ;
    krb5_creds		creds;
    krb5_ccache		ccache;
    char		cache_name[64];
    char		*princ_name;
    krb5_get_init_creds_opt opts;

    /* Initialize */
    krb5_get_init_creds_opt_init(&opts);

    princ_name = emalloc(strlen(pw->pw_name) + strlen(realm) + 2);
    (void) sprintf(princ_name, "%s@%s", pw->pw_name, realm);
    if (krb5_parse_name(sudo_context, princ_name, &princ))
	return(AUTH_FAILURE);

    /* Set the ticket file to be in /tmp so we don't need to change perms. */
    /* XXX - potential /tmp race */
    (void) snprintf(cache_name, sizeof(cache_name), "FILE:/tmp/sudocc_%ld",
	(long) getpid());
    if (krb5_cc_resolve(sudo_context, cache_name, &ccache)
	return(AUTH_FAILURE);

    if (krb5_get_init_creds_password(sudo_context, &creds, princ, pass,
	krb5_prompter_posix, NULL, 0, NULL, &opts))
	return(AUTH_FAILURE);

    /* Stash the TGT so we can verify it. */
    if (krb5_cc_initialize(sudo_context, ccache, princ))
	return(AUTH_FAILURE);
    if (krb5_cc_store_cred(sudo_context, ccache, &creds)) {
	(void) krb5_cc_destroy(sudo_context, ccache);
	return(AUTH_FAILURE);
    }

    retval = verify_krb_v5_tgt(ccache);
    (void) krb5_cc_destroy(sudo_context, ccache);
    return (retval ? AUTH_FAILURE : AUTH_SUCCESS);
}

/*
 * This routine with some modification is from the MIT V5B6 appl/bsd/login.c
 *
 * Verify the Kerberos ticket-granting ticket just retrieved for the
 * user.  If the Kerberos server doesn't respond, assume the user is
 * trying to fake us out (since we DID just get a TGT from what is
 * supposedly our KDC).  If the host/<host> service is unknown (i.e.,
 * the local keytab doesn't have it), let her in.
 *
 * Returns 1 for confirmation, -1 for failure, 0 for uncertainty.
 */
static int
verify_krb_v5_tgt(ccache)
    krb5_ccache		ccache;
{
    char		phost[BUFSIZ];
    krb5_error_code	retval;
    krb5_principal	princ;
    krb5_keyblock *	keyblock = 0;
    krb5_data		packet;
    krb5_auth_context	auth_context = NULL;

    packet.data = 0;

    /*
     * Get the server principal for the local host.
     * (Use defaults of "host" and canonicalized local name.)
     */
    if (krb5_sname_to_principal(sudo_context, NULL, NULL,
				KRB5_NT_SRV_HST, &princ))
	return -1;

    /* Extract the name directly. */
    strncpy(phost, krb5_princ_component(c, princ, 1)->data, BUFSIZ);
    phost[BUFSIZ - 1] = '\0';

    /*
     * Do we have host/<host> keys?
     * (use default keytab, kvno IGNORE_VNO to get the first match,
     * and enctype is currently ignored anyhow.)
     */
    if (retval = krb5_kt_read_service_key(sudo_context, NULL, princ, 0,
					  ENCTYPE_DES_CBC_MD5, &keyblock)) {
	/* Keytab or service key does not exist */
	if (xrealm)
	    retval = -1;
	else
	    retval = 0;
	goto cleanup;
    }
    if (keyblock)
	krb5_free_keyblock(sudo_context, keyblock);

    /* Talk to the kdc and construct the ticket. */
    retval = krb5_mk_req(sudo_context, &auth_context, 0, "host", phost,
			 NULL, ccache, &packet);
    if (auth_context) {
	krb5_auth_con_free(sudo_context, auth_context);
	auth_context = NULL; /* setup for rd_req */
    }
    if (retval) {
	retval = -1;
	goto cleanup;
    }

    /* Try to use the ticket. */
    retval = krb5_rd_req(sudo_context, &auth_context, &packet, princ,
			 NULL, NULL, NULL);
    if (retval) {
	retval = -1;
    } else {
	retval = 1;
    }

cleanup:
    if (packet.data)
	krb5_free_data_contents(sudo_context, &packet);
    krb5_free_principal(sudo_context, princ);
    return retval;

}
