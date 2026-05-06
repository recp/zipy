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

#ifndef zap_common_h
#define zap_common_h
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
#  define ZAP_WINAPI
#  pragma warning (disable : 4068) /* disable unknown pragma warnings */
#endif

#if defined(_MSC_VER) || defined(__MINGW32__) || defined(__MINGW64__)
#  ifdef ZAP_STATIC
#    define ZAP_EXPORT
#  elif defined(ZAP_EXPORTS)
#    define ZAP_EXPORT __declspec(dllexport)
#  else
#    define ZAP_EXPORT __declspec(dllimport)
#  endif
#  define ZAP_HIDE
#else
#  define ZAP_EXPORT   __attribute__((visibility("default")))
#  define ZAP_HIDE     __attribute__((visibility("hidden")))
#endif

#if defined(_MSC_VER)
#  define ZAP_INLINE      __forceinline
#  define ZAP_ALIGN(X)    __declspec(align(X))
#  define ZAP_HOT
#  define ZAP_HOT_INLINE  __forceinline
#else
#  define ZAP_INLINE      static inline __attribute__((always_inline))
#  define ZAP_ALIGN(X)    __attribute__((aligned(X)))
#  define ZAP_HOT         __attribute__((hot))
#  define ZAP_HOT_INLINE  static inline __attribute__((hot, always_inline))
#endif

#ifndef __has_builtin
#  define __has_builtin(x) 0
#endif

typedef enum ZapResult {
  ZAP_UNFINISHED =  2,       /* need more data for streaming */
  ZAP_NOOP       =  1,       /* no operation needed */
  ZAP_OK         =  0,
  ZAP_ERR        = -1,       /* UKNOWN ERR */
  ZAP_EFOUND     = -1000,
  ZAP_ENOMEM     = -ENOMEM,
  ZAP_EPERM      = -EPERM,
  ZAP_EBADF      = -EBADF,   /* file couldn't parsed / loaded */
  ZAP_EFULL      = -ENOBUFS  /* no space ENOBUFS vs ENOSPC    */
} ZapResult;

#ifdef __cplusplus
}
#endif
#endif /* zap_common_h */
