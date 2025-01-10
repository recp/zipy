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

#include "common.h"
#include "zlib/zlib.h"
#include "infl/infl.h"

UNZ_EXPORT
unz_t *
unz_init_mem(const void * __restrict dst, uint32_t dstlen) {
  unz_t *zip;
  
  zip          = calloc(1, sizeof(*zip));
  zip->dst     = (uint8_t *)dst;
  zip->dstlen  = dstlen;

  zip->malloc  = malloc;
  zip->realloc = realloc;
  zip->free    = free;

  return zip;
}

UNZ_EXPORT
void
unz_include_fchunk(unz_t    * __restrict stream,
                   FILE       * __restrict file,
                   uint32_t                off,
                   uint32_t                len) {
  unz_chunk_t *chk;

  chk          = calloc(1, sizeof(*chk));
  chk->file    = file;
  chk->off     = off;
  chk->len     = len;
  chk->ismmap  = false;

  if (!stream->start) { stream->start     = chk; }
  else                { stream->end->next = chk; }

  stream->end = chk;
}

UNZ_EXPORT
void
defl_include(unz_t    * __restrict stream,
             const void * __restrict ptr,
             uint32_t                len) {
  unz_chunk_t *chk;

  chk          = calloc(1, sizeof(*chk));
  chk->p       = ptr;
  chk->len     = len;
  chk->end     = ptr + len;
  chk->ismmap  = true;

  if (!stream->start) { stream->start     = chk; }
  else                { stream->end->next = chk; }

  stream->end     = chk;
  stream->srclen += len;
}

UNZ_EXPORT
UnzResult
unzip(unz_t * __restrict stream) {
  unz_chunk_t *chk;

  if (!(chk = stream->start)) { return UNZ_NOOP; }

  /* TODO: currently only zlib is implemented */

  if (unlikely(!stream->header)) {
    zlib_header(stream, &chk, true);
    stream->it = chk;
  }

  if (infl(stream) < 0) {
    goto err;
  }

err:
  return UNZ_ERR;
}

UNZ_EXPORT
void
unz_cleanup(unz_t * __restrict stream) {
  unz_chunk_t *chk, *tofree;

  if (!stream) return;

  if ((chk = stream->start)) {
    do {
      tofree = chk;
      chk    = chk->next;
      free(tofree);
    } while (chk);
  }

  free(stream);
}
