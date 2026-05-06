/*
 * Copyright (C) 2025 Recep Aslantas
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */

#ifndef zipy_crypto_dec_h
#define zipy_crypto_dec_h

#include <stddef.h>
#include <stdint.h>

#define ZIPCRYPTO_HEADER_SIZE 12u

typedef struct zipcrypto_t {
  uint32_t keys[3];
} zipcrypto_t;

void
zipcrypto_init(zipcrypto_t *ctx, const char *password);

void
zipcrypto_decrypt(zipcrypto_t *ctx, uint8_t *buf, size_t len);

int
zipcrypto_open(zipcrypto_t *ctx,
               const char *password,
               uint8_t header[ZIPCRYPTO_HEADER_SIZE],
               uint8_t verify);

#endif /* zipy_crypto_dec_h */
