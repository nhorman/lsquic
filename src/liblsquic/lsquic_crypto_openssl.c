/* Copyright (c) 2025 LiteSpeed Technologies Inc.  See LICENSE. */
#include <assert.h>
#include <string.h>

#include <openssl/crypto.h>
#include <openssl/evp.h>

#include "lsquic_types.h"
#include "lsquic_crypto.h"
#include "lsquic_parse.h"
#include "lsquic_util.h"
#include "lsquic_str.h"

#define LSQUIC_LOGGER_MODULE LSQLM_CRYPTO
#include "lsquic_logger.h"


void *lsquic_aead_ctx_alloc(void *aead, uint8_t *key, size_t key_len, size_t tag_len, unsigned dir)
{
    EVP_CIPHER_CTX *new;
    EVP_CIPHER *_aead = (EVP_CIPHER *)aead;

    new = EVP_CIPHER_CTX_new();

    if (new != NULL) {
        if (!EVP_EncryptInit_ex(new, _aead, NULL, key, NULL)) {
            EVP_CIPHER_CTX_free(new);
            new = NULL;
        }
    }

    return (void *)new;
}

void lsquic_aead_ctx_free(void *ctx)
{
    EVP_CIPHER_CTX *key = (EVP_CIPHER_CTX *)ctx;
    EVP_CIPHER_CTX_free(key);
}

int lsquic_aead_seal(void *myctx, uint8_t *out, size_t *out_len,
                     size_t max_out_len, uint8_t *nonce,
                     size_t nonce_len, uint8_t *in, size_t in_len,
                     const uint8_t *ad, size_t ad_len)
{
    int tmp_len = 0;
    EVP_CIPHER_CTX *ctx = (EVP_CIPHER_CTX *)myctx;
    int tag_len = EVP_CIPHER_CTX_get_tag_length(ctx);

    /*
     * Initalize with existing key/iv/cipher
     */
    if (!EVP_EncryptInit_ex(ctx, NULL, NULL, NULL, NULL)) {
        return 0;
    }

    /*
     * Set the requested nonce length
     */
    if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, nonce_len, NULL)) {
        return 0;
    }

    /*
     * Set the requested iv
     */
    if (!EVP_EncryptInit_ex(ctx, NULL, NULL, NULL, nonce)) {
        return 0;
    }

    /*
     * Feed in associated data
     */
    if (ad != NULL) {
        if (!EVP_EncryptUpdate(ctx, NULL, &tmp_len, ad, ad_len)) {
            return 0;
        }
    }

    /*
     * Encrypt the message body
     */
    if (!EVP_EncryptUpdate(ctx, out, &tmp_len, in, in_len)) {
        return 0;
    }

    /*
     * Record our body encrypted length
     */
    *out_len = tmp_len;

    /*
     * Finalize the encryption
     */
    if (!EVP_EncryptFinal_ex(ctx, out + tmp_len, &tmp_len)) {
        return 0;
    }

    /*
     * Append any extra length
     */
    *out_len += tmp_len;

    /*
     * Append our tag to the end of the output
     */
    if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, tag_len, out + *out_len)) {
        return 0;
    }

    *out_len += tag_len;

    return 1;
}


int lsquic_aead_open(LSQ_AEAD_CTX *myctx, uint8_t *out, size_t *out_len,
                     size_t max_out_len, const uint8_t *nonce,
                     size_t nonce_len, const uint8_t *in, size_t in_len,
                     const uint8_t *ad, size_t ad_len)
{
    int tmp_len = 0;
    EVP_CIPHER_CTX *ctx = (EVP_CIPHER_CTX *)myctx;
    int tag_len = EVP_CIPHER_CTX_get_tag_length(ctx);
    int tagless_in_len = in_len - tag_len;
    const uint8_t *tagptr = in + tagless_in_len;

    /*
     * Set the context up for decryption
     */
    if (!EVP_DecryptInit_ex(ctx, NULL, NULL, NULL, NULL)) {
        return 0;
    }

    /*
     * Set our iv len
     */
    if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, nonce_len, NULL)) {
        return 0;
    }

    /*
     * Install our iv
     */
    if (!EVP_DecryptInit_ex(ctx, NULL, NULL, NULL, nonce)) {
        return 0;
    }

    /*
     * Feed in our aad data
     */
    if (ad != NULL) {
        if (!EVP_DecryptUpdate(ctx, NULL, &tmp_len, ad, ad_len)) {
            return 0;
        }
    }

    /*
     * Feed in our body data, minus the tag
     */
    if (!EVP_DecryptUpdate(ctx, out, &tmp_len, in, tagless_in_len)) {
        return 0;
    }

    *out_len = tmp_len;

    /*
     * set our tag value at the end of our input
     */
    if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, tag_len, tagptr)) {
        return 0;
    }

    /*
     * And finalize the decryption to confirm the tag matches
     */
    if (!EVP_DecryptFinal_ex(ctx, in + tmp_len, &tmp_len)) {
        return 0;
    }

    *out_len += tmp_len;

    return 1;
}


