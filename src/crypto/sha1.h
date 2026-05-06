/*
 * Copyright (C) 2025 Recep Aslantas
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */

#ifndef zipy_crypto_sha1_h
#define zipy_crypto_sha1_h

#include <stddef.h>
#include <stdint.h>

#define SHA1_SIZE       20u
#define SHA1_BLOCK_SIZE 64u

typedef struct sha1_t {
  uint32_t h[5];
  uint64_t len;
  uint8_t  buf[SHA1_BLOCK_SIZE];
  size_t   buf_len;
} sha1_t;

typedef struct hmac_sha1_t {
  sha1_t inner;
  sha1_t outer;
} hmac_sha1_t;

void
sha1_init(sha1_t *ctx);

void
sha1_update(sha1_t *ctx, const uint8_t *data, size_t len);

void
sha1_final(sha1_t *ctx, uint8_t out[SHA1_SIZE]);

void
hmac_sha1_init(hmac_sha1_t *ctx, const uint8_t *key, size_t key_len);

void
hmac_sha1_update(hmac_sha1_t *ctx, const uint8_t *data, size_t len);

void
hmac_sha1_final(hmac_sha1_t *ctx, uint8_t out[SHA1_SIZE]);

int
pbkdf2_hmac_sha1(const uint8_t *password,
                 size_t password_len,
                 const uint8_t *salt,
                 size_t salt_len,
                 uint32_t iterations,
                 uint8_t *out,
                 size_t out_len);

#endif /* zipy_crypto_sha1_h */
