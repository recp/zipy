/*
 * Copyright (C) 2022 Recep Aslantas
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef infl_huff_h
#define infl_huff_h

#include "../common.h"
#include <assert.h>

/* Resources:
   [0]: https://www.hanshq.net/zip.html
 */

#define MAX_HUFFMAN_SYMBOLS 288      /* Deflate uses max 288 symbols.      */
#define MAX_HUFFMAN_BITS 16          /* Implode uses max 16-bit codewords. */
#define HUFFMAN_LOOKUP_TABLE_BITS 8  /* Seems a good trade-off.            */

typedef struct huff_dec_t {
  /* Lookup table for fast decoding of short codewords. */
  struct {
    uint16_t sym: 9;  /* Wide enough to fit the max symbol nbr. */
    uint16_t len: 7;  /* 0 means no symbol.                     */
  } table[1U << HUFFMAN_LOOKUP_TABLE_BITS];

  /* "Sentinel bits" value for each codeword length. */
  uint32_t sentinel_bits[MAX_HUFFMAN_BITS + 1];

  /* First symbol index minus first codeword mod 2**16 for each length. */
  uint16_t offset_first_sym_idx[MAX_HUFFMAN_BITS + 1];

  /* Map from symbol index to symbol. */
  uint16_t syms[MAX_HUFFMAN_SYMBOLS];

#ifndef NDEBUG
  size_t num_syms;
#endif
} huff_dec_t;

/* Get the n least significant bits of x. */
static inline uint64_t lsb(uint64_t x, size_t n) {
  assert(n <= 63);
  return x & (((uint64_t)1 << n) - 1);
}

/* Reverse the n least significant bits of x.
 The (16 - n) most significant bits of the result will be zero. */
static inline uint16_t reverse16(uint16_t x, int n) {
  uint16_t lo, hi;
  uint16_t reversed;
  
  assert(n > 0);
  assert(n <= 16);
  
  lo = x & 0xff;
  hi = x >> 8;
  
//  reversed = (uint16_t)((reverse8_tbl[lo] << 8) | reverse8_tbl[hi]);
  reversed = reverse_bit16(x);
  
  return reversed >> (16 - n);
}


/* Use the decoder d to decode a symbol from the LSB-first zero-padded bits.
 * Returns the decoded symbol number or -1 if no symbol could be decoded.
 * *num_used_bits will be set to the number of bits used to decode the symbol,
 * or zero if no symbol could be decoded. */
UNZ_INLINE
uint16_t
fixed_huff_decode(const huff_dec_t *d,
                  uint16_t          bits,
                  size_t           *num_used_bits) {
  uint64_t lookup_bits;
  size_t l;
  size_t sym_idx;

  /* First try the lookup table. */
  lookup_bits = lsb(bits, HUFFMAN_LOOKUP_TABLE_BITS);

  assert(lookup_bits < sizeof(d->table) / sizeof(d->table[0]));

  if (d->table[lookup_bits].len != 0) {
    assert(d->table[lookup_bits].len <= HUFFMAN_LOOKUP_TABLE_BITS);
    assert(d->table[lookup_bits].sym < d->num_syms);

    *num_used_bits = d->table[lookup_bits].len;
    return d->table[lookup_bits].sym;
  }

  /* Then do canonical decoding with the bits in MSB-first order. */
  bits = reverse16(bits, MAX_HUFFMAN_BITS);
  for (l = HUFFMAN_LOOKUP_TABLE_BITS + 1; l <= MAX_HUFFMAN_BITS; l++) {
    if (bits < d->sentinel_bits[l]) {
      bits >>= MAX_HUFFMAN_BITS - l;

      sym_idx = (uint16_t)(d->offset_first_sym_idx[l] + bits);
      assert(sym_idx < d->num_syms);

      *num_used_bits = l;
      return d->syms[sym_idx];
    }
  }

  *num_used_bits = 0;
  return -1;
}

#endif /* infl_huff_h */
