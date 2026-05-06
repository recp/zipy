/*
 * Copyright (C) 2025 Recep Aslantas
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */

#include "aes_wg.h"

#include <string.h>

static const uint8_t sbox[256] = {
  0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
  0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
  0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
  0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
  0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
  0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
  0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
  0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
  0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
  0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
  0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
  0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
  0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
  0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
  0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
  0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16
};

static uint8_t
xtime(uint8_t x) {
  return (uint8_t)((x << 1) ^ ((x >> 7) * 0x1bu));
}

static uint8_t
ct_equal(const uint8_t *a, const uint8_t *b, size_t len) {
  uint8_t diff = 0;
  size_t i;

  for (i = 0; i < len; i++)
    diff |= (uint8_t)(a[i] ^ b[i]);

  return diff == 0;
}

static void
sub_word(uint8_t w[4]) {
  w[0] = sbox[w[0]];
  w[1] = sbox[w[1]];
  w[2] = sbox[w[2]];
  w[3] = sbox[w[3]];
}

static int
aes_set_encrypt_key(aes_key_t *ctx, const uint8_t *key, size_t key_len) {
  unsigned nk, nr, words, i;
  uint8_t rcon = 1;

  if (key_len != 16u && key_len != 24u && key_len != 32u)
    return 0;

  nk = (unsigned)(key_len / 4u);
  nr = nk + 6u;
  words = 4u * (nr + 1u);
  ctx->rounds = (uint8_t)nr;
  memcpy(ctx->round_key, key, key_len);

  for (i = nk; i < words; i++) {
    uint8_t tmp[4];
    unsigned j;

    memcpy(tmp, ctx->round_key + (i - 1u) * 4u, sizeof(tmp));
    if (i % nk == 0) {
      uint8_t t = tmp[0];
      tmp[0] = tmp[1];
      tmp[1] = tmp[2];
      tmp[2] = tmp[3];
      tmp[3] = t;
      sub_word(tmp);
      tmp[0] ^= rcon;
      rcon = xtime(rcon);
    } else if (nk > 6u && i % nk == 4u) {
      sub_word(tmp);
    }

    for (j = 0; j < 4; j++) {
      ctx->round_key[i * 4u + j] =
        (uint8_t)(ctx->round_key[(i - nk) * 4u + j] ^ tmp[j]);
    }
  }

  return 1;
}

static void
add_round_key(uint8_t s[16], const uint8_t *rk) {
  unsigned i;

  for (i = 0; i < 16; i++)
    s[i] ^= rk[i];
}

static void
sub_bytes(uint8_t s[16]) {
  unsigned i;

  for (i = 0; i < 16; i++)
    s[i] = sbox[s[i]];
}

static void
shift_rows(uint8_t s[16]) {
  uint8_t t;

  t = s[1];
  s[1] = s[5];
  s[5] = s[9];
  s[9] = s[13];
  s[13] = t;

  t = s[2];
  s[2] = s[10];
  s[10] = t;
  t = s[6];
  s[6] = s[14];
  s[14] = t;

  t = s[15];
  s[15] = s[11];
  s[11] = s[7];
  s[7] = s[3];
  s[3] = t;
}

static void
mix_columns(uint8_t s[16]) {
  unsigned c;

  for (c = 0; c < 4; c++) {
    uint8_t *p = s + c * 4u;
    uint8_t a0 = p[0];
    uint8_t a1 = p[1];
    uint8_t a2 = p[2];
    uint8_t a3 = p[3];
    uint8_t t = (uint8_t)(a0 ^ a1 ^ a2 ^ a3);

    p[0] ^= (uint8_t)(t ^ xtime((uint8_t)(a0 ^ a1)));
    p[1] ^= (uint8_t)(t ^ xtime((uint8_t)(a1 ^ a2)));
    p[2] ^= (uint8_t)(t ^ xtime((uint8_t)(a2 ^ a3)));
    p[3] ^= (uint8_t)(t ^ xtime((uint8_t)(a3 ^ a0)));
  }
}

static void
aes_encrypt_block(const aes_key_t *ctx,
                  const uint8_t in[AES_WG_BLOCK_SIZE],
                  uint8_t out[AES_WG_BLOCK_SIZE]) {
  uint8_t s[AES_WG_BLOCK_SIZE];
  unsigned round;

  memcpy(s, in, sizeof(s));
  add_round_key(s, ctx->round_key);

  for (round = 1; round < ctx->rounds; round++) {
    sub_bytes(s);
    shift_rows(s);
    mix_columns(s);
    add_round_key(s, ctx->round_key + round * AES_WG_BLOCK_SIZE);
  }

  sub_bytes(s);
  shift_rows(s);
  add_round_key(s, ctx->round_key + ctx->rounds * AES_WG_BLOCK_SIZE);
  memcpy(out, s, sizeof(s));
}

size_t
aes_wg_salt_size(uint8_t strength) {
  if (strength < 1u || strength > 3u)
    return 0;

  return (size_t)(4u * (strength & 3u) + 4u);
}

size_t
aes_wg_key_size(uint8_t strength) {
  if (strength < 1u || strength > 3u)
    return 0;

  return (size_t)(8u * (strength & 3u) + 8u);
}

int
aes_wg_open(aes_wg_t *ctx,
            const char *password,
            uint8_t strength,
            const uint8_t *salt,
            const uint8_t verify[AES_WG_VERIFY_SIZE]) {
  uint8_t keybuf[2u * AES_WG_MAX_KEY_SIZE + AES_WG_VERIFY_SIZE];
  size_t key_len = aes_wg_key_size(strength);
  size_t salt_len = aes_wg_salt_size(strength);
  size_t password_len;

  if (!ctx || !password || !salt || !verify || key_len == 0 || salt_len == 0)
    return 0;

  password_len = strlen(password);
  if (!pbkdf2_hmac_sha1((const uint8_t *)password,
                        password_len,
                        salt,
                        salt_len,
                        AES_WG_KEYING_ITERATIONS,
                        keybuf,
                        2u * key_len + AES_WG_VERIFY_SIZE))
    return 0;

  if (!ct_equal(keybuf + 2u * key_len, verify, AES_WG_VERIFY_SIZE))
    return 0;

  if (!aes_set_encrypt_key(&ctx->key, keybuf, key_len))
    return 0;

  hmac_sha1_init(&ctx->hmac, keybuf + key_len, key_len);
  memset(ctx->nonce, 0, sizeof(ctx->nonce));
  memset(ctx->stream, 0, sizeof(ctx->stream));
  ctx->stream_pos = AES_WG_BLOCK_SIZE;
  return 1;
}

static void
aes_wg_next_stream(aes_wg_t *ctx) {
  unsigned i;

  for (i = 0; i < 8u; i++) {
    ctx->nonce[i]++;
    if (ctx->nonce[i] != 0)
      break;
  }

  aes_encrypt_block(&ctx->key, ctx->nonce, ctx->stream);
  ctx->stream_pos = 0;
}

void
aes_wg_decrypt(aes_wg_t *ctx, uint8_t *buf, size_t len) {
  size_t i;

  if (!ctx || !buf || len == 0)
    return;

  hmac_sha1_update(&ctx->hmac, buf, len);
  for (i = 0; i < len; i++) {
    if (ctx->stream_pos == AES_WG_BLOCK_SIZE)
      aes_wg_next_stream(ctx);
    buf[i] ^= ctx->stream[ctx->stream_pos++];
  }
}

int
aes_wg_auth(aes_wg_t *ctx, const uint8_t auth[AES_WG_AUTH_SIZE]) {
  uint8_t digest[SHA1_SIZE];

  if (!ctx || !auth)
    return 0;

  hmac_sha1_final(&ctx->hmac, digest);
  return ct_equal(digest, auth, AES_WG_AUTH_SIZE);
}
