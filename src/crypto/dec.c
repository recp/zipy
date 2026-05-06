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
  if (!password || !*password)
    return 0;

  zipcrypto_init(ctx, password);
  zipcrypto_decrypt(ctx, header, ZIPCRYPTO_HEADER_SIZE);
  return header[ZIPCRYPTO_HEADER_SIZE - 1] == verify;
}
