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
#include <huff/huff.h>

#include "../include/unzip/common.h"
#include "../include/unzip/unzip.h"

#ifdef __GNUC__
#  define unlikely(expr) __builtin_expect(!!(expr), 0)
#  define likely(expr)   __builtin_expect(!!(expr), 1)
#else
#  define unlikely(expr) (expr)
#  define likely(expr)   (expr)
#endif

#define ARRAY_LEN(ARR) (sizeof(ARR) / sizeof(ARR[0]))

typedef struct unz__chunk_t  unz_chunk_t;
typedef struct unz__chunk_t  defl_chunk_t;
typedef struct unz__stream_t defl_stream_t;

struct unz__chunk_t {
  struct unz__chunk_t *next;
  FILE                *file;
  const uint8_t       *p;
  const uint8_t       *end;
  uint32_t             len;
  uint32_t             off;
  size_t               bitpos;
  uint64_t             bitlen;
  bitstream_t          pbits;
  uint8_t              npbits;
  bool                 ismmap;
  bool                 hasbits;
};

struct unz__stream_t {
  unz_chunk_t   *chunks_first;
  unz_chunk_t   *chunks_last;
  unz_chunk_t   *it;

  void          *header;

  void          *(*malloc)(size_t);
  void          *(*realloc)(void *, size_t);
  void           (*free)(void *);

  size_t         bitpos; /* bit position in all */
  uint8_t       *dst;
  uint32_t       dstlen;
  uintptr_t      dstpos;
  size_t         srclen; /* sum_of(chunk->len)  */
};

UNZ_INLINE uint32_t revbits32(uint32_t x) {
#if defined(__arm__) || defined(__aarch64__)
  __asm__( "rbit %0, %1" : "=r" ( x ) : "r" ( x ) );
  return x;
#endif

  // Flip pairwise
  x = ( ( x & 0x55555555 ) << 1 ) | ( ( x & 0xAAAAAAAA ) >> 1 );
  // Flip pairs
  x = ( ( x & 0x33333333 ) << 2 ) | ( ( x & 0xCCCCCCCC ) >> 2 );
  // Flip nibbles
  x = ( ( x & 0x0F0F0F0F ) << 4 ) | ( ( x & 0xF0F0F0F0 ) >> 4 );
  
  // Flip bytes. CPUs have an instruction for that, pretty fast one.
#ifdef _MSC_VER
  return _byteswap_ulong( x );
#elif defined(__INTEL_COMPILER)
  return (uint32_t)_bswap( (int)x );
#else
  // Assuming gcc or clang
  return __builtin_bswap32( x );
#endif
}

UNZ_INLINE unsigned char reverse_bit8(unsigned char x)
{
  x = ((x & 0x55) << 1) | ((x & 0xAA) >> 1);
  x = ((x & 0x33) << 2) | ((x & 0xCC) >> 2);
  return (x << 4) | (x >> 4);
}

UNZ_INLINE unsigned short reverse_bit16(unsigned short x)
{
  x = ((x & 0x5555) << 1) | ((x & 0xAAAA) >> 1);
  x = ((x & 0x3333) << 2) | ((x & 0xCCCC) >> 2);
  x = ((x & 0x0F0F) << 4) | ((x & 0xF0F0) >> 4);
  return (x << 8) | (x >> 8);
}

UNZ_INLINE unsigned int reverse_bit32(unsigned int x)
{
  x = ((x & 0x55555555) << 1) | ((x & 0xAAAAAAAA) >> 1);
  x = ((x & 0x33333333) << 2) | ((x & 0xCCCCCCCC) >> 2);
  x = ((x & 0x0F0F0F0F) << 4) | ((x & 0xF0F0F0F0) >> 4);
  x = ((x & 0x00FF00FF) << 8) | ((x & 0xFF00FF00) >> 8);
  return (x << 16) | (x >> 16);
}

#endif /* src_io_common_h */
