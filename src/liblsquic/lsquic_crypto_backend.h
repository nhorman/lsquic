/* Copyright (c) 2025 LiteSpeed Technologies Inc.  See LICENSE. */
#ifndef __LSQUIC_CRYPTO_BACKEND_H__
#define __LSQUIC_CRYPTO_BACKEND_H__

typedef void LSQ_AEAD_CTX;
typedef void LSQ_AEAD;

LSQ_AEAD_CTX *lsquic_aead_ctx_alloc(LSQ_AEAD *aead, uint8_t *key, size_t key_len, size_t tag_len, unsigned dir);

void lsquic_aead_ctx_free(LSQ_AEAD_CTX *ctx);

int lsquic_aead_seal(LSQ_AEAD_CTX *ctx, uint8_t *out, size_t *out_len,
                     size_t max_out_len, uint8_t *nonce,
                     size_t nonce_len, uint8_t *in, size_t in_len,
                     const uint8_t *ad, size_t ad_len);

int lsquic_aead_open(LSQ_AEAD_CTX *ctx, uint8_t *out, size_t *out_len,
                     size_t max_out_len, const uint8_t *nonce,
                     size_t nonce_len, const uint8_t *in, size_t in_len,
                     const uint8_t *ad, size_t ad_len);
#endif
