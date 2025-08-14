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

    return EVP_AEAD_CTX_open(ctx, out, out_len, max_out_len, nonce,
                             nonce_len, in, in_len, ad, ad_len);
}


