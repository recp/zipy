/*
 * Copyright (C) 2025 Recep Aslantas
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */

#include "dec.h"

#include <string.h>

static uint32_t
zipcrypto_crc32(uint32_t crc, uint8_t value) {
  static const uint32_t table[16] = {
    0x00000000u, 0x1DB71064u, 0x3B6E20C8u, 0x26D930ACu,
    0x76DC4190u, 0x6B6B51F4u, 0x4DB26158u, 0x5005713Cu,
    0xEDB88320u, 0xF00F9344u, 0xD6D6A3E8u, 0xCB61B38Cu,
    0x9B64C2B0u, 0x86D3D2D4u, 0xA00AE278u, 0xBDBDF21Cu
  };

  crc ^= value;
  crc = (crc >> 4) ^ table[crc & 0x0Fu];
  crc = (crc >> 4) ^ table[crc & 0x0Fu];
  return crc;
}

static void
zipcrypto_update(zipcrypto_t *ctx, uint8_t value) {
  ctx->keys[0] = zipcrypto_crc32(ctx->keys[0], value);
  ctx->keys[1] = ctx->keys[1] + (ctx->keys[0] & 0xffu);
  ctx->keys[1] = ctx->keys[1] * 134775813u + 1u;
  ctx->keys[2] = zipcrypto_crc32(ctx->keys[2], (uint8_t)(ctx->keys[1] >> 24));
}

static uint8_t
zipcrypto_byte(const zipcrypto_t *ctx) {
  uint32_t temp = ctx->keys[2] | 2u;

  return (uint8_t)((temp * (temp ^ 1u)) >> 8);
}

void
zipcrypto_init(zipcrypto_t *ctx, const char *password) {
  ctx->keys[0] = 0x12345678u;
  ctx->keys[1] = 0x23456789u;
  ctx->keys[2] = 0x34567890u;

  if (!password)
    return;

  while (*password)
    zipcrypto_update(ctx, (uint8_t)*password++);
}

void
zipcrypto_decrypt(zipcrypto_t *ctx, uint8_t *buf, size_t len) {
  size_t i;

  for (i = 0; i < len; i++) {
    uint8_t plain = (uint8_t)(buf[i] ^ zipcrypto_byte(ctx));
    zipcrypto_update(ctx, plain);
    buf[i] = plain;
  }
}

int
zipcrypto_open(zipcrypto_t *ctx,
               const char *password,
               uint8_t header[ZIPCRYPTO_HEADER_SIZE],
               uint8_t verify) {
  if (!password)
    return 0;

  zipcrypto_init(ctx, password);
  zipcrypto_decrypt(ctx, header, ZIPCRYPTO_HEADER_SIZE);
  return header[ZIPCRYPTO_HEADER_SIZE - 1] == verify;
}

void
dec_init(dec_t *dec) {
  if (dec)
    dec->kind = DEC_NONE;
}

int
dec_open_zipcrypto(dec_t *dec,
                   FILE *fp,
                   const char *password,
                   uint8_t verify,
                   uint64_t *compressed_size) {
  uint8_t header[ZIPCRYPTO_HEADER_SIZE];

  if (!dec || !fp || !compressed_size)
    return ZIPY_ZIP_ERR;
  if (!password)
    return ZIPY_ZIP_EPASS;
  if (*compressed_size < ZIPCRYPTO_HEADER_SIZE)
    return ZIPY_ZIP_ESIZE;
  if (fread(header, 1, sizeof(header), fp) != sizeof(header))
    return ZIPY_ZIP_EFILE;
  if (!zipcrypto_open(&dec->u.zipcrypto, password, header, verify))
    return ZIPY_ZIP_EPASS;

  *compressed_size -= ZIPCRYPTO_HEADER_SIZE;
  dec->kind = DEC_ZIPCRYPTO;
  return ZIPY_ZIP_OK;
}

int
dec_open_aes_wg(dec_t *dec,
                FILE *fp,
                const char *password,
                uint8_t strength,
                uint64_t *compressed_size) {
  uint8_t salt[AES_WG_MAX_SALT_SIZE];
  uint8_t verify[AES_WG_VERIFY_SIZE];
  size_t salt_size;
  uint64_t overhead;

  if (!dec || !fp || !compressed_size)
    return ZIPY_ZIP_ERR;
  if (!password)
    return ZIPY_ZIP_EPASS;

  salt_size = aes_wg_salt_size(strength);
  if (salt_size == 0)
    return ZIPY_ZIP_EUNSUP;

  overhead = (uint64_t)salt_size + AES_WG_VERIFY_SIZE + AES_WG_AUTH_SIZE;
  if (*compressed_size < overhead)
    return ZIPY_ZIP_ESIZE;

  if (fread(salt, 1, salt_size, fp) != salt_size
      || fread(verify, 1, sizeof(verify), fp) != sizeof(verify))
    return ZIPY_ZIP_EFILE;

  if (!aes_wg_open(&dec->u.aes_wg, password, strength, salt, verify))
    return ZIPY_ZIP_EPASS;

  *compressed_size -= overhead;
  dec->kind = DEC_AES_WG;
  return ZIPY_ZIP_OK;
}

void
dec_decrypt(dec_t *dec, uint8_t *buf, size_t len) {
  if (!dec || !buf || len == 0)
    return;

  if (dec->kind == DEC_ZIPCRYPTO) {
    zipcrypto_decrypt(&dec->u.zipcrypto, buf, len);
  } else if (dec->kind == DEC_AES_WG) {
    aes_wg_decrypt(&dec->u.aes_wg, buf, len);
  }
}

int
dec_finish(dec_t *dec, FILE *fp) {
  uint8_t auth[AES_WG_AUTH_SIZE];

  if (!dec)
    return ZIPY_ZIP_OK;
  if (dec->kind != DEC_AES_WG) {
    dec->kind = DEC_NONE;
    return ZIPY_ZIP_OK;
  }
  if (!fp)
    return ZIPY_ZIP_ERR;

  if (fread(auth, 1, sizeof(auth), fp) != sizeof(auth))
    return ZIPY_ZIP_EFILE;

  dec->kind = DEC_NONE;
  return aes_wg_auth(&dec->u.aes_wg, auth)
       ? ZIPY_ZIP_OK
       : ZIPY_ZIP_EAUTH;
}
