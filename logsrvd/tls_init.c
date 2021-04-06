/*
 * SPDX-License-Identifier: ISC
 *
 * Copyright (c) 2019-2021 Todd C. Miller <Todd.Miller@sudo.ws>
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

#include "config.h"

#ifdef HAVE_STDBOOL_H
# include <stdbool.h>
#else
# include "compat/stdbool.h"
#endif /* HAVE_STDBOOL_H */
#if defined(HAVE_STDINT_H)
# include <stdint.h>
#elif defined(HAVE_INTTYPES_H)
# include <inttypes.h>
#endif
#include <stdio.h>
#include <stdlib.h>

#if defined(HAVE_OPENSSL)
# include <openssl/ssl.h>
# include <openssl/err.h>
#endif

#include "sudo_compat.h"
#include "sudo_debug.h"
#include "sudo_event.h"
#include "sudo_fatal.h"
#include "sudo_gettext.h"

#include "hostcheck.h"
#include "tls_common.h"

#define DEFAULT_CIPHER_LST12 "HIGH:!aNULL"
#define DEFAULT_CIPHER_LST13 "TLS_AES_256_GCM_SHA384"

#if defined(HAVE_OPENSSL)

static bool
verify_cert_chain(SSL_CTX *ctx, const char *cert_file)
{
#ifdef HAVE_SSL_CTX_GET0_CERTIFICATE
    bool ret = false;
    X509_STORE_CTX *store_ctx = NULL;
    X509_STORE *ca_store;
    STACK_OF(X509) *chain_certs;
    X509 *x509;
    debug_decl(verify_cert_chain, SUDO_DEBUG_UTIL);

    if ((x509 = SSL_CTX_get0_certificate(ctx)) == NULL) {
        sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_LINENO,
            "unable to get X509 object from SSL_CTX: %s",
            ERR_error_string(ERR_peek_error(), NULL));
        goto done;
    }

    if ((store_ctx = X509_STORE_CTX_new()) == NULL) {
        sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_LINENO,
            "unable to allocate X509_STORE_CTX object: %s",
            ERR_error_string(ERR_peek_error(), NULL));
        goto done;
    }

    if (!SSL_CTX_get0_chain_certs(ctx, &chain_certs)) {
        sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_LINENO,
            "unable to get chain certs: %s",
            ERR_error_string(ERR_peek_error(), NULL));
        goto done;
    }

    if ((ca_store = SSL_CTX_get_cert_store(ctx)) != NULL)
        X509_STORE_set_flags(ca_store, X509_V_FLAG_X509_STRICT);

    if (!X509_STORE_CTX_init(store_ctx, ca_store, x509, chain_certs)) {
        sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_LINENO,
            "unable to initialize X509_STORE_CTX object: %s",
            ERR_error_string(ERR_peek_error(), NULL));
        goto done;
    }

    if (X509_verify_cert(store_ctx) <= 0) {
        sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_LINENO,
            "unable to verify cert %s: %s", cert_file,
            ERR_error_string(ERR_peek_error(), NULL));
        goto done;
    }

    ret = true;
done:
    X509_STORE_CTX_free(store_ctx);

    debug_return_bool(ret);
#else
    /* TODO: verify server cert with old OpenSSL */
    return true;
#endif /* HAVE_SSL_CTX_GET0_CERTIFICATE */
}

static bool
init_tls_ciphersuites(SSL_CTX *ctx, const char *ciphers_v12,
    const char *ciphers_v13)
{
    const char *errstr;
    int success = 0;
    debug_decl(init_tls_ciphersuites, SUDO_DEBUG_UTIL);

    if (ciphers_v12 != NULL) {
	/* try to set TLS v1.2 ciphersuite list from config if given */
        success = SSL_CTX_set_cipher_list(ctx, ciphers_v12);
	if (success) {
            sudo_debug_printf(SUDO_DEBUG_INFO|SUDO_DEBUG_LINENO,
                "TLS 1.2 ciphersuite list set to %s", ciphers_v12);
        } else {
	    errstr = ERR_reason_error_string(ERR_get_error());
	    sudo_warnx(U_("unable to set TLS 1.2 ciphersuite to %s: %s"),
		ciphers_v12, errstr);
        }
    }
    if (!success) {
	/* fallback to default ciphersuites for TLS v1.2 */
        if (SSL_CTX_set_cipher_list(ctx, DEFAULT_CIPHER_LST12) <= 0) {
	    errstr = ERR_reason_error_string(ERR_get_error());
	    sudo_warnx(U_("unable to set TLS 1.2 ciphersuite to %s: %s"),
		DEFAULT_CIPHER_LST12, errstr);
            debug_return_bool(false);
        } else {
            sudo_debug_printf(SUDO_DEBUG_INFO|SUDO_DEBUG_LINENO,
                "TLS v1.2 ciphersuite list set to %s (default)",
                DEFAULT_CIPHER_LST12);
        }
    }

# if defined(HAVE_SSL_CTX_SET_CIPHERSUITES)
    success = 0;
    if (ciphers_v13 != NULL) {
	/* try to set TLSv1.3 ciphersuite list from config */
        success = SSL_CTX_set_ciphersuites(ctx, ciphers_v13);
	if (success) {
            sudo_debug_printf(SUDO_DEBUG_INFO|SUDO_DEBUG_LINENO,
                "TLS v1.3 ciphersuite list set to %s", ciphers_v13);
        } else {
	    errstr = ERR_reason_error_string(ERR_get_error());
	    sudo_warnx(U_("unable to set TLS 1.3 ciphersuite to %s: %s"),
		ciphers_v13, errstr);
        }
    }
    if (!success) {
	/* fallback to default ciphersuites for TLS v1.3 */
        if (SSL_CTX_set_ciphersuites(ctx, DEFAULT_CIPHER_LST13) <= 0) {
	    errstr = ERR_reason_error_string(ERR_get_error());
	    sudo_warnx(U_("unable to set TLS 1.3 ciphersuite to %s: %s"),
		DEFAULT_CIPHER_LST13, errstr);
            debug_return_bool(false);
        } else {
            sudo_debug_printf(SUDO_DEBUG_INFO|SUDO_DEBUG_LINENO,
                "TLS v1.3 ciphersuite list set to %s (default)",
                DEFAULT_CIPHER_LST13);
        }
    }
# endif

    debug_return_bool(true);
}

SSL_CTX *
init_tls_context(const char *ca_bundle_file, const char *cert_file,
    const char *key_file, const char *dhparam_file, const char *ciphers_v12,
    const char *ciphers_v13, bool verify_cert)
{
    SSL_CTX *ctx = NULL;
    const char *errstr;
    debug_decl(init_tls_context, SUDO_DEBUG_UTIL);

    SSL_library_init();
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();

    /* Create the ssl context and enforce TLS 1.2 or higher. */
    if ((ctx = SSL_CTX_new(TLS_client_method())) == NULL) {
	errstr = ERR_reason_error_string(ERR_get_error());
	sudo_warnx(U_("unable to create TLS context: %s"), errstr);
        goto bad;
    }
#ifdef HAVE_SSL_CTX_SET_MIN_PROTO_VERSION
    if (!SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION)) {
	errstr = ERR_reason_error_string(ERR_get_error());
	sudo_warnx(U_("unable to set minimum protocol version to TLS 1.2: %s"),
	    errstr);
        goto bad;
    }
#else
    SSL_CTX_set_options(ctx,
        SSL_OP_NO_SSLv2|SSL_OP_NO_SSLv3|SSL_OP_NO_TLSv1|SSL_OP_NO_TLSv1_1);
#endif

    if (ca_bundle_file != NULL) {
	STACK_OF(X509_NAME) *cacerts =
	    SSL_load_client_CA_file(ca_bundle_file);

	if (cacerts == NULL) {
	    errstr = ERR_reason_error_string(ERR_get_error());
	    sudo_warnx(U_("%s: %s"), ca_bundle_file, errstr);
	    goto bad;
	}
	SSL_CTX_set_client_CA_list(ctx, cacerts);

	if (SSL_CTX_load_verify_locations(ctx, ca_bundle_file, NULL) <= 0) {
	    errstr = ERR_reason_error_string(ERR_get_error());
	    sudo_warnx("SSL_CTX_load_verify_locations: %s", errstr);
	    goto bad;
	}
    } else {
	if (!SSL_CTX_set_default_verify_paths(ctx)) {
	    errstr = ERR_reason_error_string(ERR_get_error());
	    sudo_warnx("SSL_CTX_set_default_verify_paths: %s", errstr);
	    goto bad;
	}
    }

    if (cert_file != NULL) {
        if (!SSL_CTX_use_certificate_chain_file(ctx, cert_file)) {
	    errstr = ERR_reason_error_string(ERR_get_error());
	    sudo_warnx(U_("%s: %s"), cert_file, errstr);
            goto bad;
        }
	if (key_file == NULL) {
	    /* No explicit key file set, try to use the cert file. */
	    key_file = cert_file;
	}
        if (!SSL_CTX_use_PrivateKey_file(ctx, key_file, X509_FILETYPE_PEM) ||
		!SSL_CTX_check_private_key(ctx)) {
	    errstr = ERR_reason_error_string(ERR_get_error());
	    sudo_warnx(U_("%s: %s"), key_file, errstr);
            goto bad;
        }

	/* Optionally verify the certificate we are using. */
	if (verify_cert) {
	    if (!verify_cert_chain(ctx, cert_file))
		goto bad;
	} else {
	    sudo_debug_printf(SUDO_DEBUG_INFO|SUDO_DEBUG_LINENO,
		"skipping local cert check");
	}
    }

    /* Initialize TLS 1.2 1.3 ciphersuites. */
    if (!init_tls_ciphersuites(ctx, ciphers_v12, ciphers_v13)) {
	goto bad;
    }

    /*
     * Load diffie-hellman parameters from a file if specified.
     * Failure to open the file is not a fatal error.
     */
    if (dhparam_file != NULL) {
	FILE *fp = fopen(dhparam_file, "r");
	if (fp != NULL) {
	    DH *dhparams = PEM_read_DHparams(fp, NULL, NULL, NULL);
	    if (dhparams != NULL) {
		if (!SSL_CTX_set_tmp_dh(ctx, dhparams)) {
		    errstr = ERR_reason_error_string(ERR_get_error());
		    sudo_warnx(U_("unable to set diffie-hellman parameters: %s"),
			errstr);
		    DH_free(dhparams);
		} else {
		    sudo_debug_printf(SUDO_DEBUG_INFO|SUDO_DEBUG_LINENO,
			"loaded diffie-hellman parameters from %s", dhparam_file);
		}
	    } else {
		errstr = ERR_reason_error_string(ERR_get_error());
		sudo_warnx(U_("unable to read diffie-hellman parameters: %s"),
		    errstr);
	    }
	    fclose(fp);
	} else {
	    sudo_warn(U_("unable to open %s"), dhparam_file);
	}
    } else {
	sudo_debug_printf(SUDO_DEBUG_INFO|SUDO_DEBUG_LINENO,
	    "dhparam file not specified, using default parameters");
    }

    goto done;

bad:
    SSL_CTX_free(ctx);
    ctx = NULL;

done:
    debug_return_ptr(ctx);
}
#endif /* HAVE_OPENSSL */
