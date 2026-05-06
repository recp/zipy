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

#ifndef zipy_common_h
#define zipy_common_h
#ifdef __cplusplus
extern "C" {
#endif

#ifndef _USE_MATH_DEFINES
#  define _USE_MATH_DEFINES       /* for windows */
#endif

#ifndef _CRT_SECURE_NO_WARNINGS
#  define _CRT_SECURE_NO_WARNINGS /* for windows */
#endif

#ifndef _CRT_NONSTDC_NO_DEPRECATE
#  define _CRT_NONSTDC_NO_DEPRECATE /* for windows */
#endif

/* since C99 or compiler ext */
#include <stdint.h>
#include <stddef.h>
#include <float.h>
#include <stdbool.h>
#include <errno.h>
#include <stdlib.h>

#ifdef DEBUG
#  include <assert.h>
#  include <stdio.h>
#endif

#if defined(_MSC_VER) || defined(__MINGW32__) || defined(__MINGW64__)
#  define ZIPY_WINAPI
#  pragma warning (disable : 4068) /* disable unknown pragma warnings */
#endif

#if defined(_MSC_VER) || defined(__MINGW32__) || defined(__MINGW64__)
#  ifdef ZIPY_STATIC
#    define ZIPY_EXPORT
#  elif defined(ZIPY_EXPORTS)
#    define ZIPY_EXPORT __declspec(dllexport)
#  else
#    define ZIPY_EXPORT __declspec(dllimport)
#  endif
#  define ZIPY_HIDE
#else
#  define ZIPY_EXPORT   __attribute__((visibility("default")))
#  define ZIPY_HIDE     __attribute__((visibility("hidden")))
#endif

#if defined(_MSC_VER)
#  define ZIPY_INLINE      __forceinline
#  define ZIPY_ALIGN(X)    __declspec(align(X))
#  define ZIPY_HOT
#  define ZIPY_HOT_INLINE  __forceinline
#else
#  define ZIPY_INLINE      static inline __attribute__((always_inline))
#  define ZIPY_ALIGN(X)    __attribute__((aligned(X)))
#  define ZIPY_HOT         __attribute__((hot))
#  define ZIPY_HOT_INLINE  static inline __attribute__((hot, always_inline))
#endif

#ifndef __has_builtin
#  define __has_builtin(x) 0
#endif

typedef enum ZipyResult {
  ZIPY_UNFINISHED =  2,       /* need more data for streaming */
  ZIPY_NOOP       =  1,       /* no operation needed */
  ZIPY_OK         =  0,
  ZIPY_ERR        = -1,       /* UKNOWN ERR */
  ZIPY_EFOUND     = -1000,
  ZIPY_ENOMEM     = -ENOMEM,
  ZIPY_EPERM      = -EPERM,
  ZIPY_EBADF      = -EBADF,   /* file couldn't parsed / loaded */
  ZIPY_EFULL      = -ENOBUFS  /* no space ENOBUFS vs ENOSPC    */
} ZipyResult;

#ifdef __cplusplus
}
#endif
#endif /* zipy_common_h */
