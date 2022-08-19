/*
 * Copyright (C) 2020 Recep Aslantas
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

#ifndef src_common_h
#define src_common_h

#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <math.h>

#include "../include/unzip/common.h"
#include "../include/unzip/unzip.h"

#ifdef __GNUC__
#  define unlikely(expr) __builtin_expect(!!(expr), 0)
#  define likely(expr)   __builtin_expect(!!(expr), 1)
#else
#  define unlikely(expr) (expr)
#  define likely(expr)   (expr)
#endif

typedef struct unzip_chunk_t {
  struct unzip_chunk_t *next;
  FILE                 *file;
  const uint8_t        *p;
  uint32_t              len;
  uint32_t              off;
  bool                  ismmap;
} unzip_chunk_t;

typedef struct unzip_t {
  unzip_chunk_t  *chunks_first;
  unzip_chunk_t  *chunks_last;
  
  void           *header;

  void          *(*malloc)(size_t);
  void          *(*realloc)(void *, size_t);
  void           (*free)(void *);

  uint8_t       *dst;
  uint32_t       dstlen;
} unzip_t;

#endif /* src_io_common_h */
