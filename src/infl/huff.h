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

UNZ_INLINE
void
table_insert(huff_dec_t *d, size_t sym, int len,
                         uint16_t codeword)
{
  int pad_len;
  uint16_t padding, index;
  
  assert(len <= HUFFMAN_LOOKUP_TABLE_BITS);
  
  codeword = reverse16(codeword, len); /* Make it LSB-first. */
  pad_len = HUFFMAN_LOOKUP_TABLE_BITS - len;
  
  /* Pad the pad_len upper bits with all bit combinations. */
  for (padding = 0; padding < (1U << pad_len); padding++) {
    index = (uint16_t)(codeword | (padding << len));
    d->table[index].sym = (uint16_t)sym;
    d->table[index].len = (uint16_t)len;
    
    assert(d->table[index].sym == sym && "Fits in bitfield.");
    assert(d->table[index].len == len && "Fits in bitfield.");
  }
}

UNZ_INLINE
bool
huff_dec_init(huff_dec_t *d, const uint8_t *lengths,
                          size_t n)
{
  size_t i;
  uint16_t count[MAX_HUFFMAN_BITS + 1] = {0};
  uint16_t code[MAX_HUFFMAN_BITS + 1];
  uint32_t s;
  uint16_t sym_idx[MAX_HUFFMAN_BITS + 1];
  int l;
  
#ifndef NDEBUG
  assert(n <= MAX_HUFFMAN_SYMBOLS);
  d->num_syms = n;
#endif
  
  /* Zero-initialize the lookup table. */
  for (i = 0; i < sizeof(d->table) / sizeof(d->table[0]); i++) {
    d->table[i].len = 0;
  }
  
  /* Count the number of codewords of each length. */
  for (i = 0; i < n; i++) {
    assert(lengths[i] <= MAX_HUFFMAN_BITS);
    count[lengths[i]]++;
  }
  count[0] = 0;  /* Ignore zero-length codewords. */
  
  /* Compute sentinel_bits and offset_first_sym_idx for each length. */
  code[0] = 0;
  sym_idx[0] = 0;
  for (l = 1; l <= MAX_HUFFMAN_BITS; l++) {
    /* First canonical codeword of this length. */
    code[l] = (uint16_t)((code[l - 1] + count[l - 1]) << 1);
    
    if (count[l] != 0 && code[l] + count[l] - 1 > (1 << l) - 1) {
      /* The last codeword is longer than l bits. */
      return false;
    }
    
    s = (uint32_t)((code[l] + count[l]) << (MAX_HUFFMAN_BITS - l));
    d->sentinel_bits[l] = s;
    assert(d->sentinel_bits[l] >= code[l] && "No overflow!");
    
    sym_idx[l] = sym_idx[l - 1] + count[l - 1];
    d->offset_first_sym_idx[l] = sym_idx[l] - code[l];
  }
  
  /* Build mapping from index to symbol and populate the lookup table. */
  for (i = 0; i < n; i++) {
    l = lengths[i];
    if (l == 0) {
      continue;
    }
    
    d->syms[sym_idx[l]] = (uint16_t)i;
    sym_idx[l]++;
    
    if (l <= HUFFMAN_LOOKUP_TABLE_BITS) {
      table_insert(d, i, l, code[l]);
      code[l]++;
    }
  }
  
  return true;
}


#endif /* infl_huff_h */
