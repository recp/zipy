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

UNZ_HIDE
int
infl(unzip_t * __restrict stream, const uint8_t * __restrict p, uint32_t len) {
  const uint8_t *end;
  uint8_t        bfinal, btype;

  end = p + len;

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

        /* TODO: option to skip this */
        if (unlikely(len != ~nlen)) { return -2; }

        memcpy(stream->dst, p, len);
        continue;
      }
      case 0x2:
        /* static huffman */
        break;
      case 0x4:
        /* dynamic huffman */
        break;
      default:
        /* unkown btype */
        return -1;
    }
  } while (p < end);

  return 0;
}
