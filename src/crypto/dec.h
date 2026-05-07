/*
 * Copyright (C) 2025 Recep Aslantas
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */

#ifndef CRYPTO_DEC_H
#define CRYPTO_DEC_H

#include "aes_wg.h"

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

#include <zipy/zip.h>

#define ZIPCRYPTO_HEADER_SIZE 12u

typedef struct zipcrypto_t {
  uint32_t keys[3];
} zipcrypto_t;

typedef enum dec_kind_t {
  DEC_NONE = 0,
  DEC_ZIPCRYPTO,
  DEC_AES_WG
} dec_kind_t;

typedef struct dec_t {
  dec_kind_t kind;
  union {
    zipcrypto_t zipcrypto;
    aes_wg_t    aes_wg;
  } u;
} dec_t;

void
zipcrypto_init(zipcrypto_t *ctx, const char *password);

void
zipcrypto_decrypt(zipcrypto_t *ctx, uint8_t *buf, size_t len);

int
zipcrypto_open(zipcrypto_t *ctx,
               const char *password,
               uint8_t header[ZIPCRYPTO_HEADER_SIZE],
               uint8_t verify);

void
dec_init(dec_t *dec);

int
dec_open_zipcrypto(dec_t *dec,
                   FILE *fp,
                   const char *password,
                   uint8_t verify,
                   uint64_t *compressed_size);

int
dec_open_aes_wg(dec_t *dec,
                FILE *fp,
                const char *password,
                uint8_t strength,
                uint64_t *compressed_size);

void
dec_decrypt(dec_t *dec, uint8_t *buf, size_t len);

int
dec_finish(dec_t *dec, FILE *fp);

#endif /* CRYPTO_DEC_H */
