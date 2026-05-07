/*
 * Copyright (C) 2025 Recep Aslantas
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */

#ifndef CRYPTO_AES_WG_H
#define CRYPTO_AES_WG_H

#include "sha1.h"

#include <stddef.h>
#include <stdint.h>

#define AES_WG_BLOCK_SIZE        16u
#define AES_WG_MAX_KEY_SIZE      32u
#define AES_WG_MAX_SALT_SIZE     16u
#define AES_WG_VERIFY_SIZE       2u
#define AES_WG_AUTH_SIZE         10u
#define AES_WG_KEYING_ITERATIONS 1000u

typedef struct aes_key_t {
  uint8_t round_key[240];
  uint8_t rounds;
} aes_key_t;

typedef struct aes_wg_t {
  aes_key_t   key;
  hmac_sha1_t hmac;
  uint8_t     nonce[AES_WG_BLOCK_SIZE];
  uint8_t     stream[AES_WG_BLOCK_SIZE];
  size_t      stream_pos;
} aes_wg_t;

size_t
aes_wg_salt_size(uint8_t strength);

size_t
aes_wg_key_size(uint8_t strength);

int
aes_wg_open(aes_wg_t *ctx,
            const char *password,
            uint8_t strength,
            const uint8_t *salt,
            const uint8_t verify[AES_WG_VERIFY_SIZE]);

void
aes_wg_decrypt(aes_wg_t *ctx, uint8_t *buf, size_t len);

int
aes_wg_auth(aes_wg_t *ctx, const uint8_t auth[AES_WG_AUTH_SIZE]);

#endif /* CRYPTO_AES_WG_H */
