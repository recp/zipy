/*
 * Copyright (C) 2025 Recep Aslantas
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */

#ifndef zipy_zip_h
#define zipy_zip_h

#include "common.h"
#include <stdbool.h>

typedef struct ZipyArchive ZipyArchive;

typedef enum ZipyZipResult {
  ZIPY_ZIP_OK       =  0,
  ZIPY_ZIP_SAVED    =  1,
  ZIPY_ZIP_SKIPPED  =  2,
  ZIPY_ZIP_ERR      = -1,
  ZIPY_ZIP_EINFLATE = -2,
  ZIPY_ZIP_ESIZE    = -3,
  ZIPY_ZIP_ECRC     = -4,
  ZIPY_ZIP_EFILE    = -5,
  ZIPY_ZIP_EUNSUP   = -6,
  ZIPY_ZIP_EEXIST   = -7
} ZipyZipResult;

typedef enum ZipyZipMethod {
  ZIPY_ZIP_STORE   = 0,
  ZIPY_ZIP_DEFLATE = 8
} ZipyZipMethod;

typedef enum ZipySaveLocation {
  ZIPY_SAVE_TARGET = 0,
  ZIPY_SAVE_HOME   = 1,
  ZIPY_SAVE_TRASH  = 2
} ZipySaveLocation;

typedef enum ZipyConflictPolicy {
  ZIPY_CONFLICT_SAVE      = 0,
  ZIPY_CONFLICT_OVERWRITE = 1,
  ZIPY_CONFLICT_SKIP      = 2,
  ZIPY_CONFLICT_FAIL      = 3
} ZipyConflictPolicy;

typedef struct ZipyExtractOptions {
  ZipyConflictPolicy onConflict;
  ZipySaveLocation saveTo;
  const char       *saveDir;
} ZipyExtractOptions;

typedef struct ZipyEntry {
  const char *name;
  uint64_t    compressedSize;
  uint64_t    uncompressedSize;
  uint32_t    crc32;
  uint16_t    method;
  bool        isDirectory;
} ZipyEntry;

ZIPY_EXPORT ZipyArchive *
zipy_open(const char *path);

ZIPY_EXPORT size_t
zipy_count(const ZipyArchive *zipy);

ZIPY_EXPORT const ZipyEntry *
zipy_entry(const ZipyArchive *zipy, size_t index);

ZIPY_EXPORT int
zipy_extract(ZipyArchive *zipy, size_t index, const char *destpath);

ZIPY_EXPORT int
zipy_extract_to(ZipyArchive *zipy,
                size_t index,
                const char *destdir,
                const ZipyExtractOptions *options);

ZIPY_EXPORT int
zipy_extract_named(ZipyArchive *zipy, const char *name, const char *destpath);

ZIPY_EXPORT int
zipy_extract_all(ZipyArchive *zipy, const char *destdir);

ZIPY_EXPORT int
zipy_extract_all_options(ZipyArchive *zipy,
                         const char *destdir,
                         const ZipyExtractOptions *options);

ZIPY_EXPORT void
zipy_close(ZipyArchive *zipy);

#endif /* zipy_zip_h */
