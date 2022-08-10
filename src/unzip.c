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

UNZ_EXPORT
unzip_t *
unzip_init_mem(const void * __restrict dst, uint32_t dstlen) {
  unzip_t *zip;
  
  zip          = calloc(1, sizeof(*zip));
  zip->dst     = dst;
  zip->dstlen  = dstlen;

  zip->malloc  = malloc;
  zip->realloc = realloc;
  zip->free    = free;

  return zip;
}

UNZ_EXPORT
void
unzip_include_chunk(unzip_t    * __restrict stream,
                    const void * __restrict chkptr,
                    uint32_t                chklen) {
  unzip_chunk_t *chk;
  
  chk      = calloc(1, sizeof(*chk));
  chk->p   = chkptr;
  chk->len = chklen;

  if (!stream->chunks_first) { stream->chunks_first      = chk; }
  else                       { stream->chunks_last->next = chk; }

  stream->chunks_last = chk;
}

UNZ_EXPORT
UnzipResult
unzip(unzip_t * __restrict stream) {
  
  return UNZ_OK;
}

UNZ_EXPORT
UnzipResult
unzip_chunk(unzip_t * __restrict stream, const void * __restrict ptr, size_t len) {
  return UNZ_OK;
}

UNZ_EXPORT
void
unzip_cleanup(unzip_t * __restrict stream) {
  unzip_chunk_t *chk, *tofree;

  if ((chk = stream->chunks_first)) {
    tofree = chk;
    chk    = chk->next;
    free(tofree);
  }

  free(stream);
}
