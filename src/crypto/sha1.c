/*
 * Copyright (C) 2025 Recep Aslantas
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */

#include "sha1.h"

#include <string.h>

static uint32_t
rol32(uint32_t x, unsigned n) {
  return (x << n) | (x >> (32u - n));
}

static uint32_t
load_be32(const uint8_t *p) {
  return ((uint32_t)p[0] << 24)
       | ((uint32_t)p[1] << 16)
       | ((uint32_t)p[2] << 8)
       | ((uint32_t)p[3]);
}

static void
store_be32(uint8_t *p, uint32_t x) {
  p[0] = (uint8_t)(x >> 24);
  p[1] = (uint8_t)(x >> 16);
  p[2] = (uint8_t)(x >> 8);
  p[3] = (uint8_t)x;
}

static void
store_be64(uint8_t *p, uint64_t x) {
  p[0] = (uint8_t)(x >> 56);
  p[1] = (uint8_t)(x >> 48);
  p[2] = (uint8_t)(x >> 40);
  p[3] = (uint8_t)(x >> 32);
  p[4] = (uint8_t)(x >> 24);
  p[5] = (uint8_t)(x >> 16);
  p[6] = (uint8_t)(x >> 8);
  p[7] = (uint8_t)x;
}

static void
sha1_compress(sha1_t *ctx, const uint8_t block[SHA1_BLOCK_SIZE]) {
  uint32_t w[80];
  uint32_t a, b, c, d, e;
  unsigned i;

  for (i = 0; i < 16; i++)
    w[i] = load_be32(block + i * 4u);
  for (; i < 80; i++)
    w[i] = rol32(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1);

  a = ctx->h[0];
  b = ctx->h[1];
  c = ctx->h[2];
  d = ctx->h[3];
  e = ctx->h[4];

  for (i = 0; i < 80; i++) {
    uint32_t f, k, tmp;

    if (i < 20) {
      f = (b & c) | (~b & d);
      k = 0x5A827999u;
    } else if (i < 40) {
      f = b ^ c ^ d;
      k = 0x6ED9EBA1u;
    } else if (i < 60) {
      f = (b & c) | (b & d) | (c & d);
      k = 0x8F1BBCDCu;
    } else {
      f = b ^ c ^ d;
      k = 0xCA62C1D6u;
    }

    tmp = rol32(a, 5) + f + e + k + w[i];
    e = d;
    d = c;
    c = rol32(b, 30);
    b = a;
    a = tmp;
  }

  ctx->h[0] += a;
  ctx->h[1] += b;
  ctx->h[2] += c;
  ctx->h[3] += d;
  ctx->h[4] += e;
}

void
sha1_init(sha1_t *ctx) {
  ctx->h[0] = 0x67452301u;
  ctx->h[1] = 0xEFCDAB89u;
  ctx->h[2] = 0x98BADCFEu;
  ctx->h[3] = 0x10325476u;
  ctx->h[4] = 0xC3D2E1F0u;
  ctx->len = 0;
  ctx->buf_len = 0;
}

void
sha1_update(sha1_t *ctx, const uint8_t *data, size_t len) {
  ctx->len += len;

  if (ctx->buf_len > 0) {
    size_t n = SHA1_BLOCK_SIZE - ctx->buf_len;
    if (n > len)
      n = len;
    memcpy(ctx->buf + ctx->buf_len, data, n);
    ctx->buf_len += n;
    data += n;
    len -= n;

    if (ctx->buf_len == SHA1_BLOCK_SIZE) {
      sha1_compress(ctx, ctx->buf);
      ctx->buf_len = 0;
    }
  }

  while (len >= SHA1_BLOCK_SIZE) {
    sha1_compress(ctx, data);
    data += SHA1_BLOCK_SIZE;
    len -= SHA1_BLOCK_SIZE;
  }

  if (len > 0) {
    memcpy(ctx->buf, data, len);
    ctx->buf_len = len;
  }
}

void
sha1_final(sha1_t *ctx, uint8_t out[SHA1_SIZE]) {
  uint64_t bits = ctx->len * 8u;
  uint8_t lenbuf[8];
  unsigned i;

  ctx->buf[ctx->buf_len++] = 0x80u;

  if (ctx->buf_len > 56u) {
    memset(ctx->buf + ctx->buf_len, 0, SHA1_BLOCK_SIZE - ctx->buf_len);
    sha1_compress(ctx, ctx->buf);
    ctx->buf_len = 0;
  }

  memset(ctx->buf + ctx->buf_len, 0, 56u - ctx->buf_len);
  store_be64(lenbuf, bits);
  memcpy(ctx->buf + 56u, lenbuf, sizeof(lenbuf));
  sha1_compress(ctx, ctx->buf);

  for (i = 0; i < 5; i++)
    store_be32(out + i * 4u, ctx->h[i]);
}

void
hmac_sha1_init(hmac_sha1_t *ctx, const uint8_t *key, size_t key_len) {
  uint8_t key_hash[SHA1_SIZE];
  uint8_t ipad[SHA1_BLOCK_SIZE];
  uint8_t opad[SHA1_BLOCK_SIZE];
  size_t i;

  if (key_len > SHA1_BLOCK_SIZE) {
    sha1_t tmp;

    sha1_init(&tmp);
    sha1_update(&tmp, key, key_len);
    sha1_final(&tmp, key_hash);
    key = key_hash;
    key_len = SHA1_SIZE;
  }

  memset(ipad, 0x36, sizeof(ipad));
  memset(opad, 0x5c, sizeof(opad));
  for (i = 0; i < key_len; i++) {
    ipad[i] ^= key[i];
    opad[i] ^= key[i];
  }

  sha1_init(&ctx->inner);
  sha1_update(&ctx->inner, ipad, sizeof(ipad));
  sha1_init(&ctx->outer);
  sha1_update(&ctx->outer, opad, sizeof(opad));
}

void
hmac_sha1_update(hmac_sha1_t *ctx, const uint8_t *data, size_t len) {
  sha1_update(&ctx->inner, data, len);
}

void
hmac_sha1_final(hmac_sha1_t *ctx, uint8_t out[SHA1_SIZE]) {
  uint8_t inner[SHA1_SIZE];

  sha1_final(&ctx->inner, inner);
  sha1_update(&ctx->outer, inner, sizeof(inner));
  sha1_final(&ctx->outer, out);
}

int
pbkdf2_hmac_sha1(const uint8_t *password,
                 size_t password_len,
                 const uint8_t *salt,
                 size_t salt_len,
                 uint32_t iterations,
                 uint8_t *out,
                 size_t out_len) {
  uint8_t u[SHA1_SIZE];
  uint8_t t[SHA1_SIZE];
  uint8_t counter[4];
  uint32_t block = 1;
  size_t done = 0;

  if (!out || iterations == 0)
    return 0;

  while (done < out_len) {
    hmac_sha1_t hmac;
    size_t n, i;
    uint32_t iter;

    counter[0] = (uint8_t)(block >> 24);
    counter[1] = (uint8_t)(block >> 16);
    counter[2] = (uint8_t)(block >> 8);
    counter[3] = (uint8_t)block;

    hmac_sha1_init(&hmac, password, password_len);
    hmac_sha1_update(&hmac, salt, salt_len);
    hmac_sha1_update(&hmac, counter, sizeof(counter));
    hmac_sha1_final(&hmac, u);
    memcpy(t, u, sizeof(t));

    for (iter = 1; iter < iterations; iter++) {
      hmac_sha1_init(&hmac, password, password_len);
      hmac_sha1_update(&hmac, u, sizeof(u));
      hmac_sha1_final(&hmac, u);
      for (i = 0; i < sizeof(t); i++)
        t[i] ^= u[i];
    }

    n = out_len - done;
    if (n > sizeof(t))
      n = sizeof(t);
    memcpy(out + done, t, n);
    done += n;
    block++;
  }

  return 1;
}
