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
#include "huff.h"
#include "../endian.h"

static const uint8_t hufxd_len_litl[288] = {
  8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,
  8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,
  8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,
  8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,
  9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,
  9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,
  9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,
  9,9,9,9,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,8,8,8,8,8,8,8,8
};

static const uint8_t hufxd_len_dist[32] = {
  5,5,5,5,5,5,5,5,5,5,5,5,5,5,5,5,5,5,5,5,5,5,5,5,5,5,5,5,5,5,5,5
};

UNZ_INLINE
UnzipResult
infl_block(unzip_t          * __restrict stream,
           uint8_t          * __restrict dst,
           size_t                        dst_cap,
           size_t           * __restrict dst_pos,
           const huff_dec_t * __restrict litlen_dec,
           const huff_dec_t * __restrict dist_dec) {
  return UNZ_OK;
}

UNZ_HIDE
int
infl(unzip_t * __restrict stream, const uint8_t * __restrict p, uint32_t len) {
  const uint8_t *end;
  uint8_t        bfinal, btype;
  huff_dec_t     hufxd_litl, hufxd_dist;

  end = p + len;

  /* initilize static tables */
  huff_dec_init(&hufxd_litl, hufxd_len_litl, ARRAY_LEN(hufxd_len_litl));
  huff_dec_init(&hufxd_dist, hufxd_len_dist, ARRAY_LEN(hufxd_len_dist));

  /* TODO: option to check enough input / output memory */
  do {
    bfinal  = *p++;
    btype   = bfinal & 0x6;
    bfinal &= 0x1;

    switch (btype) {
      case 0x0: {
        /* no compression */
        uint16_t len, nlen;

        be_16(len,  p);
        be_16(nlen, p);

        /* TODO: option to skip this or different error code? */
        if (unlikely(len != ~nlen)) { goto err; }

        memcpy(stream->dst, p, len);
        continue;
      }
      case 0x2: {
        /* static huffman */
      
        break;
      }
      case 0x4:
        /* dynamic huffman */
        break;
      default:
        /* unkown btype */
        goto err;
    }
  } while (p < end);

  return 0;

err:
  return -1;
}
