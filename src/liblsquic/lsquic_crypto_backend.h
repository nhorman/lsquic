/* Copyright (c) 2025 LiteSpeed Technologies Inc.  See LICENSE. */
#ifndef __LSQUIC_CRYPTO_BACKEND_H__
#define __LSQUIC_CRYPTO_BACKEND_H__


int lsquic_aead_seal(void *ctx, uint8_t *out, size_t *out_len,
                     size_t max_out_len, uint8_t *nonce,
                     size_t nonce_len, uint8_t *in, size_t in_len,
                     const uint8_t *ad, size_t ad_len);

int lsquic_aead_open(void *ctx, uint8_t *out, size_t *out_len,
                     size_t max_out_len, const uint8_t *nonce,
                     size_t nonce_len, const uint8_t *in, size_t in_len,
                     const uint8_t *ad, size_t ad_len);
#endif
