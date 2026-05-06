/*
 * Copyright (C) 2025 Recep Aslantas
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */

#ifndef zap_zip_h
#define zap_zip_h

#include "common.h"
#include <stdbool.h>

typedef struct ZapArchive ZapArchive;

typedef enum ZapZipResult {
  ZAP_ZIP_OK       =  0,
  ZAP_ZIP_ERR      = -1,
  ZAP_ZIP_EINFLATE = -2,
  ZAP_ZIP_ESIZE    = -3,
  ZAP_ZIP_ECRC     = -4,
  ZAP_ZIP_EFILE    = -5,
  ZAP_ZIP_EUNSUP   = -6
} ZapZipResult;

typedef enum ZapZipMethod {
  ZAP_ZIP_STORE   = 0,
  ZAP_ZIP_DEFLATE = 8
} ZapZipMethod;

typedef struct ZapEntry {
  const char *name;
  uint64_t    compressedSize;
  uint64_t    uncompressedSize;
  uint32_t    crc32;
  uint16_t    method;
  bool        isDirectory;
} ZapEntry;

ZAP_EXPORT ZapArchive *
zap_open(const char *path);

ZAP_EXPORT size_t
zap_count(const ZapArchive *zap);

ZAP_EXPORT const ZapEntry *
zap_entry(const ZapArchive *zap, size_t index);

ZAP_EXPORT int
zap_extract(ZapArchive *zap, size_t index, const char *destpath);

ZAP_EXPORT int
zap_extract_named(ZapArchive *zap, const char *name, const char *destpath);

ZAP_EXPORT int
zap_extract_all(ZapArchive *zap, const char *destdir);

ZAP_EXPORT void
zap_close(ZapArchive *zap);

#endif /* zap_zip_h */
