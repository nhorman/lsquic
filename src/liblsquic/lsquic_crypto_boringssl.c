/* Copyright (c) 2025 LiteSpeed Technologies Inc.  See LICENSE. */
#include <assert.h>
#include <string.h>

#include <openssl/ssl.h>
#include <openssl/crypto.h>
#include <openssl/stack.h>
#include <openssl/x509.h>
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/hmac.h>

#include "lsquic_types.h"
#include "lsquic_crypto.h"
#include "lsquic_parse.h"
#include "lsquic_util.h"
#include "lsquic_str.h"

#define LSQUIC_LOGGER_MODULE LSQLM_CRYPTO
#include "lsquic_logger.h"


void *lsquic_aead_ctx_alloc(void *aead, uint8_t *key, size_t key_len, size_t tag_len, unsigned dir)
{
    EVP_AEAD_CTX *new;
    EVP_AEAD *_aead = (EVP_AEAD *)aead;
    enum evp_aead_direction_t mydir;

    new = EVP_AEAD_CTX_new(_aead, key, key_len, tag_len);

    if (new != NULL && dir != 2) {
        mydir = (dir == 0) ? evp_aead_open : evp_aead_seal;
        EVP_AEAD_CTX_cleanup(new);
        if (!EVP_AEAD_CTX_init_with_direction(new, _aead, key,
                                              key_len, tag_len, mydir)) {
           EVP_AEAD_CTX_free(new);
           new = NULL;
        }
    }

    return (void *)new;
}

void lsquic_aead_ctx_free(void *ctx)
{
    EVP_AEAD_CTX *key = (EVP_AEAD_CTX *)ctx;
    EVP_AEAD_CTX_free(key);
}

int lsquic_aead_seal(void *ctx, uint8_t *out, size_t *out_len,
                     size_t max_out_len, uint8_t *nonce,
                     size_t nonce_len, uint8_t *in, size_t in_len,
                     const uint8_t *ad, size_t ad_len)
{
    EVP_AEAD_CTX *key = (EVP_AEAD_CTX *)ctx;

    return EVP_AEAD_CTX_seal(key, out, out_len, max_out_len, nonce,
                             nonce_len, in, in_len, ad, ad_len);
}


int lsquic_aead_open(void *ctx, uint8_t *out, size_t *out_len,
                     size_t max_out_len, const uint8_t *nonce,
                     size_t nonce_len, const uint8_t *in, size_t in_len,
                     const uint8_t *ad, size_t ad_len)
{
    EVP_AEAD_CTX *key = (EVP_AEAD_CTX *)ctx;

    return EVP_AEAD_CTX_open(key, out, out_len, max_out_len, nonce,
                             nonce_len, in, in_len, ad, ad_len);
}


