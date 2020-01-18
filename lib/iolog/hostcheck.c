/*
 * Copyright (c) 2020 Laszlo Orban <laszlo.orban@oneidentity.com>
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

#if defined(HAVE_OPENSSL)
# include <string.h>
# include <netdb.h>
# include <sys/socket.h>
# include <arpa/inet.h>
# include <openssl/x509v3.h>

# include  "hostcheck.h"

/**
 * @brief Checks if given hostname resolves to the given IP address.
 *
 * @param hostname  hostname to be resolved
 * @param ipaddr    ip address to be checked
 * 
 * @return  1 if hostname resolves to the given IP address
 *          0 otherwise
 */
static int
forward_lookup_match(const char *hostname, const char *ipaddr)
{
    int ret = 0;
    struct addrinfo *res = NULL, *p;
    void *addr;
    struct sockaddr_in *ipv4;
#if defined(HAVE_STRUCT_IN6_ADDR)
    struct sockaddr_in6 *ipv6;
    char ipstr[INET6_ADDRSTRLEN];
#else
    char ipstr[INET_ADDRSTRLEN];
#endif

    if (getaddrinfo(hostname, NULL, NULL, &res) != 0) {
        goto exit;
    }

    for(p = res ;p != NULL; p = p->ai_next) {
        if(p->ai_family == AF_INET) {
            ipv4 = (struct sockaddr_in *)p->ai_addr;
            addr = &(ipv4->sin_addr);
#if defined(HAVE_STRUCT_IN6_ADDR)
        } else if(p->ai_family == AF_INET6) {
            ipv6 = (struct sockaddr_in6 *)p->ai_addr;
            addr = &(ipv6->sin6_addr);
#endif
        } else {
            goto exit;
        }

        if (inet_ntop(p->ai_family, addr, ipstr, sizeof(ipstr)) != 0) {
            if (strcmp(ipaddr, ipstr) == 0) {
                ret = 1;
                break;
            }
        }
    }

exit:
    if (res != NULL) {
        freeaddrinfo(res);
    }
    return ret;
}

/**
 * @brief Compares the given hostname with a DNS entry in a certificate.
 *
 * The certificate DNS name can contain wildcards in the left-most label.
 * A wildcard can match only one label.
 * Accepted names:
 *  - foo.bar.example.com
 *  - *.example.com
 *  - *.bar.example.com
 * 
 * @param hostname          peer's name
 * @param certname_asn1     hostname in the certificate
 * 
 * @return  MatchFound
 *          MatchNotFound
 */
static HostnameValidationResult
validate_name(const char *hostname, ASN1_STRING *certname_asn1) {
	char *certname_s = (char *) ASN1_STRING_get0_data(certname_asn1);
	int certname_len = ASN1_STRING_length(certname_asn1);
    int hostname_len = strlen(hostname);

	/* remove last '.' from hostname if exists */
	if (hostname_len != 0 && hostname[hostname_len - 1] == '.') {
		--hostname_len;
    }

	/* skip the first label if wildcard */
	if (certname_len > 2 && certname_s[0] == '*' && certname_s[1] == '.') {
		if (hostname_len != 0) {
			do {
				--hostname_len;
				if (*hostname++ == '.') {
					break;
                }
			} while (hostname_len != 0);
		}
		certname_s += 2;
		certname_len -= 2;
	}
	/* Compare expected hostname with the DNS name */
	if (certname_len != hostname_len) {
		return MatchNotFound;
	}
    if (strncasecmp(hostname, certname_s, hostname_len) != 0) {
        return MatchNotFound;
    }

    return MatchFound;
}

/**
 * @brief Matches a hostname with the cert's CN.
 * 
 * @param hostname  peer's name
 *                  on client side: it is the name where the client is connected to
 *                  on server side, it is in fact an IP address of the remote client
 * @param ipaddr    peer's IP address
 * @param cert      peer's X509 certificate
 * @param resolve   if the value is not 0, the function checks that the value of the CN
 *                  resolves to the given ipaddr or not.
 * 
 * @return  MatchFound
 *          MatchNotFound
 *          MalformedCertificate
 *          Error
 */
static HostnameValidationResult
matches_common_name(const char *hostname, const char *ipaddr, const X509 *cert, int resolve)
{
	X509_NAME_ENTRY *common_name_entry = NULL;
	ASN1_STRING *common_name_asn1 = NULL;
 	int common_name_loc = -1;

	/* Find the position of the CN field in the Subject field of the certificate */
	common_name_loc = X509_NAME_get_index_by_NID(X509_get_subject_name((X509 *) cert), NID_commonName, -1);
	if (common_name_loc < 0) {
		return Error;
	}

	/* Extract the CN field */
	common_name_entry = X509_NAME_get_entry(X509_get_subject_name((X509 *) cert), common_name_loc);
	if (common_name_entry == NULL) {
		return Error;
	}

	/* Convert the CN field to a C string */
	common_name_asn1 = X509_NAME_ENTRY_get_data(common_name_entry);
	if (common_name_asn1 == NULL) {
		return Error;
	}			
	const unsigned char *common_name_str = ASN1_STRING_get0_data(common_name_asn1);

	/* Make sure there isn't an embedded NUL character in the CN */
    if (memchr(common_name_str, '\0', ASN1_STRING_length(common_name_asn1)) != NULL) {
		return MalformedCertificate;
	}

	/* Compare expected hostname with the CN */
    if (validate_name(hostname, common_name_asn1) == MatchFound) {
		return MatchFound;
	}

    int common_name_length = ASN1_STRING_length(common_name_asn1);
    unsigned char *nullterm_common_name = malloc(common_name_length + 1);

    if (nullterm_common_name == NULL) {
        return Error;
    }

    memcpy(nullterm_common_name, common_name_str, common_name_length);
    nullterm_common_name[common_name_length] = '\0';


    /* check if hostname in the CN field resolves to the given ip address */
    if (resolve && forward_lookup_match(nullterm_common_name, ipaddr)) {
        free(nullterm_common_name);
		return MatchFound;
    }

    free(nullterm_common_name);
    return MatchNotFound;
}

/**
 * @brief Matches a hostname or ipaddr with the cert's corresponding SAN field.
 *
 * SAN can have different fields. For hostname matching, the GEN_DNS field is used,
 * for IP address matching, the GEN_IPADD field is used.
 * Since SAN is an X503 v3 extension, it can happen that the cert does
 * not contain SAN at all.
 * 
 * @param hostname  remote peer's name
 *                  on client side: it is the name where the client is connected to
 *                  on server side, it is in fact an IP address of the remote client
 * @param ipaddr    remote peer's IP address
 * @param cert      peer's X509 certificate
 * @param resolve   if the value is not 0, the function checks that the value of the
 *                  SAN GEN_DNS resolves to the given ipaddr or not.
 * 
 * @return  MatchFound
 *          MatchNotFound
 *          NoSANPresent
 *          MalformedCertificate
 *          Error
 */
static HostnameValidationResult
matches_subject_alternative_name(const char *hostname, const char *ipaddr, const X509 *cert, int resolve)
{
    HostnameValidationResult result = MatchNotFound;
    int i;
    int san_names_nb = -1;
    STACK_OF(GENERAL_NAME) *san_names = NULL;

    /* Try to extract the names within the SAN extension from the certificate */
    san_names = X509_get_ext_d2i((X509 *) cert, NID_subject_alt_name, NULL, NULL);
    if (san_names == NULL) {
        return NoSANPresent;
    }
    san_names_nb = sk_GENERAL_NAME_num(san_names);

    /* Check each name within the extension */
    for (i=0; i<san_names_nb; i++) {
        const GENERAL_NAME *current_name = sk_GENERAL_NAME_value(san_names, i);

        if (current_name->type == GEN_DNS) {
            const unsigned char *dns_name = ASN1_STRING_get0_data(current_name->d.dNSName);

            /* Make sure there isn't an embedded NUL character in the DNS name */
            if (memchr(dns_name, '\0', ASN1_STRING_length(current_name->d.dNSName)) != NULL) {
                result = MalformedCertificate;
                break;
            } else {
                /* Compare expected hostname with the DNS name */
                if (validate_name(hostname, current_name->d.dNSName) == MatchFound) {
                    result = MatchFound;
                    break;
                }

                int dns_name_length = ASN1_STRING_length(current_name->d.dNSName);
                unsigned char *nullterm_dns_name = malloc(dns_name_length + 1);

                if (nullterm_dns_name == NULL) {
                    return Error;
                }

                memcpy(nullterm_dns_name, dns_name, dns_name_length);
                nullterm_dns_name[dns_name_length] = '\0';

                if (resolve && forward_lookup_match(nullterm_dns_name, ipaddr)) {
                    free(nullterm_dns_name);
                    result = MatchFound;
                    break;
                }
                free(nullterm_dns_name);
            }
        } else if (current_name->type == GEN_IPADD) {
            const unsigned char *san_ip = ASN1_STRING_get0_data(current_name->d.iPAddress);
#if defined(HAVE_STRUCT_IN6_ADDR)
            char san_ip_str[INET6_ADDRSTRLEN];
#else
            char san_ip_str[INET_ADDRSTRLEN];
#endif

            /* IPV4 address */
            if(current_name->d.iPAddress->length == 4) {
                if (inet_ntop(AF_INET, san_ip, san_ip_str, INET_ADDRSTRLEN) == NULL) {
                    result = MalformedCertificate;
                    break;
                }
#if defined(HAVE_STRUCT_IN6_ADDR)
            /* IPV6 address */
            } else if (current_name->d.iPAddress->length == 16) {
                if (inet_ntop(AF_INET6, san_ip, san_ip_str, INET6_ADDRSTRLEN) == NULL) {
                    result = MalformedCertificate;
                    break;
                }
# endif
            } else {
                result = MalformedCertificate;
                break;
            }

            if (strcasecmp(ipaddr, san_ip_str) == 0) {
                result = MatchFound;
                break;
            }
        }
    }
    sk_GENERAL_NAME_pop_free(san_names, GENERAL_NAME_free);

    return result;
}

/**
 * @brief Do hostname/IP validation on the given X509 certificate.
 *
 * According to RFC 6125 section 6.4.4, first the certificate's SAN field
 * has to be checked. If there is no SAN field, the certificate's CN field
 * has to be checked.
 * 
 * @param cert      X509 certificate
 * @param hostname  remote peer's name
 *                  on client side: it is the name where the client is connected to
 *                  on server side, it is in fact an IP address of the remote client
 * @param ipaddr    remote peer's IP address
 * @param resolve   if the value is not 0, the function checks that the value of the
 *                  SAN GEN_DNS or the value of CN resolves to the given ipaddr or not.
 * 
 * @return  MatchFound
 *          MatchNotFound
 *          MalformedCertificate
 *          Error
 */
HostnameValidationResult
validate_hostname(const X509 *cert, const char *hostname, const char *ipaddr, int resolve)
{
    HostnameValidationResult res = MatchFound;

    /* hostname can be also an ip address, if client connects
     * to ip instead of FQDN
     */
    if((ipaddr == NULL) || (cert == NULL)) {
        return Error;
    }

    /* check SAN first if exists */
    res = matches_subject_alternative_name(hostname, ipaddr, cert, resolve);

    /* According to RFC 6125 section 6.4.4, check CN only,
     * if no SAN name was provided
     */
    if (res == NoSANPresent) {
        res = matches_common_name(hostname, ipaddr, cert, resolve);
    }

    return res;
}
#endif /* HAVE_OPENSSL */