/* Copyright (c) 2017 - 2022 LiteSpeed Technologies Inc.  See LICENSE. */
#include <assert.h>
#include <stddef.h>
#include <string.h>

#ifdef HAVE_BORINGSSL
#include <openssl/hkdf.h>
#else
#include <openssl/kdf.h>
#include <openssl/core_names.h>
#endif

#include "lsquic_hkdf.h"


/* [draft-ietf-quic-tls-17] Section 5 */
void
lsquic_qhkdf_expand (const EVP_MD *md, const unsigned char *secret,
            unsigned secret_len, const char *label, uint8_t label_len,
            unsigned char *out, uint16_t out_len)
{
#ifndef NDEBUG
    int s;
#endif
    const size_t len = 2 + 1 + 6 + label_len + 1;
#ifndef WIN32
    unsigned char info[ 2 + 1 + 6 + label_len + 1];
#else
    unsigned char info[ 2 + 1 + 6 + UINT8_MAX + 1];
#endif

#ifdef HAVE_OPENSSL
    char *md_sn = EVP_MD_get0_name(md);
    int kdf_mode = EVP_KDF_HKDF_MODE_EXPAND_ONLY;
    EVP_KDF *kdf = EVP_KDF_fetch(NULL, "HKDF", NULL);
    EVP_KDF_CTX *kctx = EVP_KDF_CTX_new(kdf);
    OSSL_PARAM params[5], *pp = params;

    EVP_KDF_free(kdf);
#endif

    info[0] = out_len >> 8;
    info[1] = out_len;
    info[2] = label_len + 6;
    info[3] = 't';
    info[4] = 'l';
    info[5] = 's';
    info[6] = '1';
    info[7] = '3';
    info[8] = ' ';
    memcpy(info + 9, label, label_len);
    info[9 + label_len] = 0;

#ifdef HAVE_BORINGSSL
#ifndef NDEBUG
    s =
#else
    (void)
#endif
    HKDF_expand(out, out_len, md, secret, secret_len, info, len);
#else

    *pp++ = OSSL_PARAM_construct_int(OSSL_KDF_PARAM_MODE, &kdf_mode);

    *pp++ = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST, md_sn, strlen(md_sn));

    *pp++ = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_KEY, (uint8_t *)secret, secret_len);

    *pp++ = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_INFO, (uint8_t *)info, len);

    *pp = OSSL_PARAM_construct_end();

    s = EVP_KDF_derive(kctx, out, out_len, params);

    EVP_KDF_CTX_free(kctx);
#endif
    assert(s >= 0);
}
