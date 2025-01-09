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

#include "infl.h"
#include "../endian.h"

#include <math.h>

#define LITLEN_EOB 256
#define LITLEN_MAX 285
#define LITLEN_TBL_OFFSET 257
#define MIN_LEN 3
#define MAX_LEN 258

#define MIN(a,b) (((a)<(b))?(a):(b))
#define MAX(a,b) (((a)>(b))?(a):(b))

#define MIN_CODELEN_LENS 4
#define MAX_CODELEN_LENS 19

#define MIN_LITLEN_LENS 257
#define MAX_LITLEN_LENS 288

#define MIN_DIST_LENS   1
#define MAX_DIST_LENS   32

#define CODELEN_MAX_LIT 15

#define CODELEN_COPY 16
#define CODELEN_COPY_MIN 3
#define CODELEN_COPY_MAX 6

#define CODELEN_ZEROS 17
#define CODELEN_ZEROS_MIN 3
#define CODELEN_ZEROS_MAX 10

#define CODELEN_ZEROS2 18
#define CODELEN_ZEROS2_MIN 11
#define CODELEN_ZEROS2_MAX 138

#define MAX_CODELEN_CODES 19   // Maximum number of code length codes
#define MAX_LITLEN_CODES 288   // Maximum number of literal/length codes
#define MAX_DIST_CODES 32      // Maximum number of distance codes

typedef struct {uint_fast16_t base;uint_fast8_t bits;} hval_t;

static const hval_t lvals[] = {
  {3, 0},{4, 0},{5, 0},{6,  0},{7,  0},{8,  0},{9,  0},{10, 0},{11, 1},{13, 1},
  {15,1},{17,1},{19,2},{23, 2},{27, 2},{31, 2},{35, 3},{43, 3},{51, 3},{59, 3},
  {67,4},{83,4},{99,4},{115,4},{131,5},{163,5},{195,5},{227,5},{258,0}
};

static const hval_t dvals[] = {
  {1,0},{2,0},{3,0},{4,0},{5,1},{7,1},{9, 2},{13,  2},{17,    3},
  {25,3},{33,4},{49,4},{65,5},{97,5},{129,6},{193, 6},{257,   7},
  {385,7},{513,8},{769,8},{1025,9},{1537,9},{2049,10},{3073, 10},
  {4097,11},{6145,11},{8193,12},{12289,12},{16385,13},{24577,13}
};

static const uint_fast8_t
  l_orders[19] = {16,17,18,0,8,7,9,6,10,5,11,4,12,3,13,2,14,1,15},
  f_ldist[32]  = {[0 ...31]=5},
  f_llitl[288] = {[0 ...143]=8,[144 ...255]=9,[256 ...279]=7,[280 ...287]=8
};

static inline uint_fast8_t min8(uint_fast8_t a, uint_fast8_t b) { return a < b ? a : b; }

#define INITBITS() bits    = pbits;                                           \
                   nbits   = min8(sizeof(bits)*8, npbits);                    \
                   pbits   = nbits < npbits ? pbits >> nbits : 0;             \
                   npbits -= nbits;                                           \

#define EXTRACT_BITS(B,C) ((B) & (((bitstream_t)1 << (C)) - 1))
#define CONSUME_BITS(N)   bits >>= (N); nbits -= (N);
#define RESTORE_BITS()    npbits=chunk->npbits;pbits=chunk->pbits;INITBITS();
#define DONATE_BITS()     chunk->pbits=(pbits<<nbits)|bits;chunk->npbits=npbits+nbits;bits=0;nbits=0;

#define REFILL_BITS(req)                                                      \
  if (nbits < (req)) {                                                        \
    if (!npbits) {                                                            \
      if ((chunk->p >= chunk->end)                                            \
          && (!(chunk = chunk->next) || (!chunk->p || chunk->len == 0))) {    \
        return UNZ_ERR;                                                       \
      }                                                                       \
      pbits = huff_read(&chunk->p, &chunk->bitpos, &npbits, chunk->end);      \
      if (!npbits) { return UNZ_ERR;  }                                       \
    }                                                                         \
                                                                              \
    if (!nbits) { INITBITS(); } else {                                        \
      uint8_t nt = min8(sizeof(bits)*8 - nbits, npbits);                      \
      bits      |= EXTRACT_BITS(pbits, nt) << nbits;                          \
      pbits    >>= nt; nbits += nt; npbits -= nt;                             \
    }                                                                         \
  }                                                                           \

UNZ_INLINE
UnzResult
infl_block(defl_stream_t      * __restrict stream,
           defl_chunk_t       * __restrict chunk,
           const huff_table_t * __restrict tlit,
           const huff_table_t * __restrict tdist) {
  uint8_t * __restrict dst;
  size_t  * __restrict dst_pos;
  size_t      dst_cap, dpos;
  bitstream_t bits, pbits;
  uint32_t    len,  dist;
  uint16_t    lsym, dsym;
  uint8_t     nbits, npbits, used;
  hval_t      val;

  dst     = stream->dst;
  dst_cap = stream->dstlen;
  dst_pos = &stream->dstpos;
  dpos    = *dst_pos;

  RESTORE_BITS()

  while (true) {
    /* decode literal/length symbol */
    REFILL_BITS(15);
    lsym = huff_decode_lsb(tlit, bits, 15, &used);
    if (!used || lsym > 285)
      return UNZ_ERR; /* invalid symbol */

    CONSUME_BITS(used);

    if (lsym < 256) {
      /* literal byte */
      if (dpos >= dst_cap)
        return UNZ_EFULL;
      dst[dpos++] = (uint8_t)lsym;
      continue;
    } else if (lsym == 256) {
      /* eof */
      break;
    }

    /* back-reference length */
    val = lvals[lsym - 257];
    len = val.base;

    if (val.bits) {
      REFILL_BITS(val.bits);
      len += EXTRACT_BITS(bits, val.bits);
      CONSUME_BITS(val.bits);
    }

    /* decode distance symbol */
    REFILL_BITS(15);
    dsym = huff_decode_lsb(tdist, bits, 15, &used);
    if (!used)
      return UNZ_ERR; /* invalid symbol */
    CONSUME_BITS(used);

    val  = dvals[dsym];
    dist = val.base;
    if (val.bits) {
      REFILL_BITS(val.bits);
      dist += EXTRACT_BITS(bits, val.bits);
      CONSUME_BITS(val.bits);
    }

    /* validate distance */
    if (dist > dpos)
      return UNZ_ERR; /* invalid distance */

    if ((dpos + len) > dst_cap)
      return UNZ_EFULL;

    /* output back-reference */
    while (len--) {
      dst[dpos] = dst[dpos - dist];
      dpos++;
    }
  }

  *dst_pos = dpos;

  DONATE_BITS();

  return UNZ_OK;
}

UNZ_HIDE
int
infl(defl_stream_t  * __restrict stream,
     defl_chunk_t  ** __restrict chunkref) {
  static huff_table_t tlitl = {0}, tdist = {0};

  unz_chunk_t   *chunk;
  bitstream_t    bits, pbits;
  uint8_t        bfinal, btype, nbits, npbits;

  bfinal = 0;
  chunk  = *chunkref;

  /* initilize static tables */
  if (!tlitl.syms) {
    huff_init_lsb(&tlitl, f_llitl, NULL, ARRAY_LEN(f_llitl));
    huff_init_lsb(&tdist, f_ldist, NULL, ARRAY_LEN(f_ldist));
  }

  while (!bfinal && chunk) {
    RESTORE_BITS();

    REFILL_BITS(3);
    bfinal = bits & 0x1;
    btype  = (bits >> 1) & 0x3;
    CONSUME_BITS(3);

#if DEBUG
    printf("defl: bfinal: %d, btype: %d\n\n\n\n", (int)bfinal, (int)btype);
#endif

    switch (btype) {
      case 0: {
        uint16_t len, nlen, leftover_bits;

        leftover_bits = nbits % 8;
        if (leftover_bits > 0)
          CONSUME_BITS(leftover_bits);

        REFILL_BITS(32);

        len  = EXTRACT_BITS(bits, 16); CONSUME_BITS(16);
        nlen = EXTRACT_BITS(bits, 16); CONSUME_BITS(16);

        if (unlikely(len != ~nlen)) { goto err; }

        memcpy(stream->dst, chunk->p, len);
        stream->dstpos += len;
      } continue;
      case 1:
        DONATE_BITS();
        if (infl_block(stream, chunk, &tlitl, &tdist) != UNZ_OK) {
          goto err;
        }
        break;
      case 2: {
        uint16_t hclen, hlit, hdist;
        uint8_t code_lengths[MAX_CODELEN_CODES] = {0};
        uint8_t lens[MAX_LITLEN_CODES + MAX_DIST_CODES] = {0};
        huff_table_t dyn_tlitl = {0}, dyn_dist = {0}, codelen_table = {0};
        size_t i = 0;

        REFILL_BITS(14);
        hlit  = (bits & 0x1F) + 257;
        hdist = ((bits >> 5) & 0x1F) + 1;
        hclen = ((bits >> 10) & 0xF) + 4;
        CONSUME_BITS(14);

        if (hlit + hdist > MAX_LITLEN_CODES + MAX_DIST_CODES)
          return UNZ_ERR;

        memset(code_lengths, 0, sizeof(code_lengths));

        for (i = 0; i < hclen; i++) {
          REFILL_BITS(3);
          code_lengths[l_orders[i]] = bits & 0x7;
          CONSUME_BITS(3);
        }

        if (!huff_init_lsb(&codelen_table, code_lengths, NULL, MAX_CODELEN_CODES))
          return UNZ_ERR;

        i = 0;
        while (i < (hlit + hdist)) {
          uint8_t used_bits;
          REFILL_BITS(15);
          int symbol = huff_decode_lsb(&codelen_table, bits, 15, &used_bits);
          if (symbol < 0 || used_bits == 0)
            return UNZ_ERR;
          CONSUME_BITS(used_bits);

          if (symbol <= 15) {
            lens[i++] = symbol;
          } else if (symbol == 16) {
            REFILL_BITS(2);
            uint8_t repeat = 3 + (bits & 0x3);
            CONSUME_BITS(2);

            if (i == 0)
              return UNZ_ERR;

            uint8_t prev = lens[i - 1];

            if (i + repeat > (hlit + hdist))
              return UNZ_ERR;

            while (repeat--) lens[i++] = prev;
          } else if (symbol == 17) {
            REFILL_BITS(3);
            uint8_t repeat = 3 + (bits & 0x7);
            CONSUME_BITS(3);

            if (i + repeat > (hlit + hdist))
              return UNZ_ERR;

            memset(&lens[i], 0, repeat);
            i += repeat;
          } else if (symbol == 18) {
            REFILL_BITS(7);
            uint8_t repeat = 11 + (bits & 0x7F);
            CONSUME_BITS(7);

            if (i + repeat > (hlit + hdist))
              return UNZ_ERR;

            memset(&lens[i], 0, repeat);
            i += repeat;
          } else {
            return UNZ_ERR;
          }
        }

        if (!huff_init_lsb(&dyn_tlitl, lens,        NULL, hlit))  return UNZ_ERR;
        if (!huff_init_lsb(&dyn_dist,  lens + hlit, NULL, hdist)) return UNZ_ERR;

        DONATE_BITS();

        if (infl_block(stream, chunk, &dyn_tlitl, &dyn_dist) != UNZ_OK) {
          goto err;
        }
      } break;
      default:
        goto err;
    }
  }

  return UNZ_OK;
err:
  return UNZ_ERR;
}
