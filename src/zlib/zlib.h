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

#ifndef unz_zlib_h
#define unz_zlib_h

#include "../common.h"

UNZ_INLINE
const uint8_t*
zlib_header(unzip_t * __restrict stream, unz_chunk_t * __restrict ch) {
  const uint8_t *p;
  uint8_t        cm, cinfo, fcheck, fdict, flevel;

  p       = ch->p;
  cinfo   = *p++;
  cm      = cinfo & 0xf;
  cinfo >>= 4;

  flevel  = *p++;
  fcheck  = flevel & 0xf;
  fdict   = (flevel & 0x10) >> 4;
  flevel  = (flevel & 0xe0) >> 5;

  if (fdict) { p += 4; }

  ch->p       = p;
  ch->bitpos  = 0;
  ch->pbits   = 0;
  ch->npbits  = 0;
  ch->hasbits = ch->end > p;

  return p;
}

#endif /* unz_zlib_h */
