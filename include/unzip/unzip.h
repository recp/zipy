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

#ifndef unzip_h
#define unzip_h
#ifdef __cplusplus
extern "C" {
#endif

#include "common.h"

typedef struct unzip_t unzip_t;

/*!
 * @brief initialize zip for memory, the destination must be a known-size memory addr
 *
 * @param[in]     dst       uncompressed data (memory addr to unzip)
 * @param[in]     dstlen    size of uncompressed data in bytes
 *
 * @returns zip stream to use later
 */
UNZ_EXPORT
unzip_t *
unzip_init_mem(const void * __restrict dst, uint32_t dstlen);

/*!
 * @brief appends a chunk to unzip stream to uncompress, the chunks may be separated from each other
 *        but can be uncompressed together
 *
 *  this appends uncopressed data into src which specified with unzip_init(), the subsequent calls
 *  will assume that the chunk that include  zip header already included
 *
 * @param[in,out] stream    zip stream: NULL to get created one, stream to continue unzipping.
 * @param[in]     ptr           compressed data (memory addr to unzip)
 * @param[in]     len           size of chunk
 */
UNZ_EXPORT
void
unzip_include_chunk(unzip_t    * __restrict stream,
                    const void * __restrict ptr,
                    uint32_t                len);

/*!
 * @brief appends a chunk to unzip stream to uncompress, the chunks may be separated from each other
 *        but can be uncompressed together
 *
 *  this appends uncopressed data into src which specified with unzip_init(), the subsequent calls
 *  will assume that the chunk that include  zip header already included
 *
 * @param[in,out] stream    zip stream: NULL to get created one, stream to continue unzipping.
 * @param[in]     file        compressed data's file
 * @param[in]     off          offset of chunk
 * @param[in]     len          size of chunk
 */
UNZ_EXPORT
void
unzip_include_fchunk(unzip_t    * __restrict stream,
                     FILE       * __restrict file,
                     uint32_t                off,
                     uint32_t                len);

/*!
 * @brief unzip the contents memory addr, for files they must be open and passed to as memory addr
 *        the api doesn't maintain file management[s]
 *
 * @param[in,out] stream  zip stream: NULL to get created one, stream to continue unzipping.
 */
UNZ_EXPORT
UnzipResult
unzip(unzip_t * __restrict stream);

/*!
 * @brief cleanup
 */
UNZ_EXPORT
void
unzip_cleanup(unzip_t * __restrict stream);

#ifdef __cplusplus
}
#endif
#endif /* unzip_h */
