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
unzip_t *
unzip_init_mem(const void * __restrict dst, uint32_t dstlen) {
  unzip_t *zip;
  
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
unzip_include_fchunk(unzip_t    * __restrict stream,
                     FILE       * __restrict file,
                     uint32_t                off,
                     uint32_t                len) {
  unzip_chunk_t *chk;

  chk         = calloc(1, sizeof(*chk));
  chk->file   = file;
  chk->off    = off;
  chk->len    = len;
  chk->ismmap = false;

  if (!stream->chunks_first) { stream->chunks_first      = chk; }
  else                       { stream->chunks_last->next = chk; }
  
  stream->chunks_last = chk;
}

UNZ_EXPORT
void
unzip_include_chunk(unzip_t    * __restrict stream,
                    const void * __restrict ptr,
                    uint32_t                len) {
  unzip_chunk_t *chk;

  chk         = calloc(1, sizeof(*chk));
  chk->p      = ptr;
  chk->len    = len;
  chk->ismmap = true;

  if (!stream->chunks_first) { stream->chunks_first      = chk; }
  else                       { stream->chunks_last->next = chk; }

  stream->chunks_last = chk;
}

UNZ_EXPORT
UnzipResult
unzip(unzip_t * __restrict stream) {
  unzip_chunk_t *chk;
  const uint8_t *p;

  if (!(chk = stream->chunks_first)) { return UNZ_NOOP; }

  /* TODO: currently only zlib is implemented */

  do {
    if (likely(stream->header)) { p = chk->p;                   }
    else                        { p = zlib_header(stream, chk); }

    if (infl(stream, p, chk->len) < 0) {
      goto err;
    }
  } while ((chk = chk->next));

  return UNZ_OK;

err:
  return UNZ_ERR;
}

UNZ_EXPORT
void
unzip_cleanup(unzip_t * __restrict stream) {
  unzip_chunk_t *chk, *tofree;

  if (!stream) return;

  if ((chk = stream->chunks_first)) {
    do {
      tofree = chk;
      chk    = chk->next;
      free(tofree);
    } while (chk);
  }

  free(stream);
}
