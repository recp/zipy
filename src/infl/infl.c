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

#define MAX_CODELEN_CODES 19
#define MAX_LITLEN_CODES  288
#define MAX_DIST_CODES    32

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
  f_llitl[288] = {[0 ...143]=8,[144 ...255]=9,[256 ...279]=7,[280 ...287]=8},
  f_ldist[32]  = {[0 ...31]=5}
;

static inline uint_fast8_t   min8(uint_fast8_t  a, uint_fast8_t  b) { return a < b ? a : b; }
static inline uint_fast16_t min16(uint_fast16_t a, uint_fast16_t b) { return a < b ? a : b; }

#define EXTRACT_BITS(B,C) ((B) & (((bitstream_t)1 << (C)) - 1))
#define CONSUME_BITS(N)   bst.bits >>= (N);bst.nbits -= (N);
#define RESTORE_BITS()    bst=stream->bst;
#define DONATE_BITS()     stream->bst=bst;memset(&bst,0,sizeof(bst));

#define REFILL_BITS(req)                                                      \
  while (bst.nbits < (req)) {                                                 \
    if (!bst.npbits) {                                                        \
      if ((bst.chunk->p >= bst.chunk->end)                                    \
          && (!(bst.chunk = bst.chunk->next) || !bst.chunk->p)) {             \
        return UNZ_ERR;                                                       \
      }                                                                       \
      bst.pbits = huff_read(&bst.chunk->p, &bst.chunk->bitpos,                \
                            &bst.npbits, bst.chunk->end);                     \
      if (!bst.npbits) { return UNZ_ERR;  }                                   \
    }                                                                         \
                                                                              \
    if (!bst.nbits) {                                                         \
      bst.bits   = bst.pbits;                                                 \
      bst.nbits  = min8(sizeof(bst.bits)*8,bst.npbits);                       \
      bst.pbits  = bst.nbits<bst.npbits?bst.pbits>>bst.nbits:0;               \
      bst.npbits = bst.nbits<bst.npbits?bst.npbits-bst.nbits:0;               \
   } else {                                                                   \
      uint16_t nt = min8(sizeof(bst.bits)*8-bst.nbits,bst.npbits);            \
      bst.bits   |= EXTRACT_BITS(bst.pbits,nt) << bst.nbits;                  \
      bst.pbits >>= nt; bst.nbits += nt; bst.npbits -= nt;                    \
    }                                                                         \
  }                                                                           \

UNZ_INLINE
UnzResult
infl_block(defl_stream_t      * __restrict stream,
           const huff_table_t * __restrict tlit,
           const huff_table_t * __restrict tdist) {
  uint8_t   * __restrict dst;
  size_t    * __restrict dst_pos;
  unz__bitstate_t bst;
  size_t          dst_cap, dpos;
  uint_fast32_t   len,  dist;
  uint_fast16_t   lsym, dsym;
  hval_t          val;
  uint_fast8_t    used;

  dst     = stream->dst;
  dst_cap = stream->dstlen;
  dst_pos = &stream->dstpos;
  dpos    = *dst_pos;

  RESTORE_BITS()

  while (true) {
    /* decode literal/length symbol */
    REFILL_BITS(15);
    lsym = huff_decode_lsb(tlit, bst.bits, 15, &used);
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
      len += EXTRACT_BITS(bst.bits, val.bits);
      CONSUME_BITS(val.bits);
    }

    /* decode distance symbol */
    REFILL_BITS(15);
    dsym = huff_decode_lsb(tdist, bst.bits, 15, &used);
    if (!used)
      return UNZ_ERR; /* invalid symbol */
    CONSUME_BITS(used);

    val  = dvals[dsym];
    dist = val.base;
    if (val.bits) {
      REFILL_BITS(val.bits);
      dist += EXTRACT_BITS(bst.bits, val.bits);
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
infl(defl_stream_t * __restrict stream,
     defl_chunk_t ** __restrict chunkref) {
  static huff_table_t tlitl={0}, tdist={0};

  unz__bitstate_t bst;
  uint_fast8_t    used, btype, bfinal = 0;

  if (!stream->bst.chunk)
    stream->bst.chunk = *chunkref;

  /* initilize static tables */
  if (!tlitl.syms) {
    huff_init_lsb(&tlitl, f_llitl, NULL, ARRAY_LEN(f_llitl));
    huff_init_lsb(&tdist, f_ldist, NULL, ARRAY_LEN(f_ldist));
  }

  RESTORE_BITS();

  while (!bfinal && bst.chunk) {
    REFILL_BITS(3);
    bfinal = bst.bits & 0x1;
    btype  = (bst.bits >> 1) & 0x3;
    CONSUME_BITS(3);

    switch (btype) {
      case 0: {
        size_t        remlen, chunkrem;
        uint_fast16_t len, nlen, padbits, to_copy;
        uint_fast8_t  cached;

        padbits = bst.nbits % 8;
        if (padbits > 0)
          CONSUME_BITS(padbits);

        REFILL_BITS(32);

        len  = EXTRACT_BITS(bst.bits, 16); CONSUME_BITS(16);
        nlen = EXTRACT_BITS(bst.bits, 16); CONSUME_BITS(16);

        if (unlikely(len != (uint16_t)~nlen)) { goto err; } /* invalid block */

        /* flush cached bits (bst.bits) to the output buffer */
        while (bst.nbits >= 8) {
          cached = EXTRACT_BITS(bst.bits, 8);
          /* output buffer overflow */
          if (stream->dstpos >= stream->dstlen) { goto err; }
          stream->dst[stream->dstpos++] = cached;
          CONSUME_BITS(8);
        }

        /* flush remaining bits in bst.pbits to the output buffer */
        while (bst.npbits >= 8) {
          cached = EXTRACT_BITS(bst.pbits, 8);
          /* output buffer overflow */
          if (stream->dstpos >= stream->dstlen) { goto err; }
          stream->dst[stream->dstpos++] = cached;
          bst.pbits >>= 8;
          bst.npbits -= 8;
        }

        /* copy LEN bytes of literal data, handling multiple chunks */
        remlen = len;
        while (remlen > 0) {
          if ((chunkrem = bst.chunk->end - bst.chunk->p) == 0) {
            /* invalid stream or insufficient data */
            if (!(bst.chunk = bst.chunk->next)|| !bst.chunk->p) { goto err; }
            continue;
          }

          /* validate output buffer overflow */
          to_copy = min16(chunkrem, remlen);
          if (stream->dstpos + to_copy > stream->dstlen) { goto err; }

          /* copy data */
          memcpy(stream->dst + stream->dstpos, bst.chunk->p, to_copy);
          stream->dstpos += to_copy;
          bst.chunk->p   += to_copy;
          remlen         -= to_copy;
        }

        // DONATE_BITS() /* TODO: reduce donate / restore */
      } continue;
      case 1:
        DONATE_BITS();
        if (infl_block(stream, &tlitl, &tdist) != UNZ_OK) {
          goto err;
        }
        RESTORE_BITS();
        break;
      case 2: {
        uint_fast8_t  codelens[MAX_CODELEN_CODES]={0};
        uint_fast8_t  lens[MAX_LITLEN_CODES + MAX_DIST_CODES]={0};
        huff_table_t  dyn_tlitl={0}, dyn_tdist={0}, tcodelen={0};
        size_t        i;
        uint_fast32_t n;
        uint_fast16_t sym, hclen, hlit, hdist;
        uint_fast8_t  repeat, prev;

        REFILL_BITS(14);
        hlit  = (bst.bits & 0x1F) + 257;
        hdist = ((bst.bits >> 5) & 0x1F) + 1;
        hclen = ((bst.bits >> 10) & 0xF) + 4;
        n     = hlit + hdist;
        CONSUME_BITS(14);

        if (hlit + hdist > MAX_LITLEN_CODES + MAX_DIST_CODES)
          goto err;

        memset(codelens, 0, sizeof(codelens));
        for (i = 0; i < hclen; i++) {
          REFILL_BITS(3);
          codelens[l_orders[i]] = bst.bits & 0x7;
          CONSUME_BITS(3);
        }

        if (!huff_init_lsb(&tcodelen, codelens, NULL, MAX_CODELEN_CODES))
          goto err;

        i = 0;
        while (i < n) {
          REFILL_BITS(15);
          sym = huff_decode_lsb(&tcodelen, bst.bits, 15, &used);
          if (!used) goto err;
          CONSUME_BITS(used);

          if (sym <= 15) {
            lens[i++] = sym;
          } else if (sym == 16) {
            REFILL_BITS(2);
            repeat = 3 + (bst.bits & 0x3);
            CONSUME_BITS(2);

            if (i == 0 || i + repeat > (hlit + hdist))
              goto err;

            prev = lens[i - 1];
            while (repeat--) lens[i++] = prev;
          } else if (sym == 17) {
            REFILL_BITS(3);
            repeat = 3 + (bst.bits & 0x7);
            CONSUME_BITS(3);

            if (i + repeat > (hlit + hdist))
              goto err;

            memset(&lens[i], 0, repeat);
            i += repeat;
          } else if (sym == 18) {
            REFILL_BITS(7);
            repeat = 11 + (bst.bits & 0x7F);
            CONSUME_BITS(7);

            if (i + repeat > (hlit + hdist))
              goto err;

            memset(&lens[i], 0, repeat);
            i += repeat;
          } else {
            goto err;
          }
        }

        if (!huff_init_lsb(&dyn_tlitl, lens,      NULL, hlit))  goto err;
        if (!huff_init_lsb(&dyn_tdist, lens+hlit, NULL, hdist)) goto err;

        DONATE_BITS();
        if (infl_block(stream, &dyn_tlitl, &dyn_tdist) != UNZ_OK) {
          goto err;
        }
        RESTORE_BITS();
      } break;
      default:
        goto err;
    }
  }

  *chunkref = bst.chunk;
  DONATE_BITS();
  return UNZ_OK;
err:
  return UNZ_ERR;
}
