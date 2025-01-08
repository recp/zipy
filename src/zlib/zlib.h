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
zlib_header(unzip_t *__restrict stream, unz_chunk_t *__restrict ch, bool nodict) {
  const uint8_t *p;
  uint8_t       cm, cinfo, fcheck, fdict, flevel, flags;

  /**
   * nodict: PNG spec doesnt allow dict so give a chance to skip fdict and fdict
   *         errors.
   */

  p = ch->p;
  cinfo = *p++;                 // Read CMF
  cm = cinfo & 0xf;             // Bits 0-3: CM
  cinfo >>= 4;                  // Bits 4-7: CINFO

  flags = *p++;                 // Read FLG
  fcheck = flags & 0xf;         // Bits 0-3: FCHECK
  fdict = (flags & 0x10) >> 4;  // Bit 4: FDICT
  flevel = (flags & 0xe0) >> 5; // Bits 5-7: FLEVEL

  // Debugging output
#if DEBUG
  printf("CMF: 0x%x, FLG: 0x%x\n", cinfo, flags);
  printf("Checksum validation: ((CMF << 8) + FLG) %% 31 = %d\n",
         ((cinfo << 8) + flags) % 31);
#endif

  /* validate compression method, 8: DEFLATE */
  if (cm != 8) {
#if DEBUG
    printf("Error: Unsupported compression method (CM = %d)\n", cm);
#endif
    return NULL;
  }

  /* validate header checksum (CMF + FLG) % 31 == 0 */
  if (((cinfo << 8) + flags) % 31 != 0) {
#if DEBUG
    printf("Error: Invalid header checksum\n");
#endif

    if (!nodict)
      return NULL;
  }

  /* Handle preset dictionaries */
  if (!nodict && fdict) {
    uint32_t dict_id = (p[0] << 24) | (p[1] << 16) | (p[2] << 8) | p[3];
#if DEBUG
    printf("FDICT set. Dictionary ID: 0x%x\n", dict_id);
#endif
    p += 4;  // Skip dictionary ID
  }

  /* update chunk state */
  ch->p       = p;
  ch->bitpos  = 0;
  ch->pbits   = 0;
  ch->npbits  = 0;

  return p;
}

#endif /* unz_zlib_h */
