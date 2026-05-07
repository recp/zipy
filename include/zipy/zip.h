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

typedef struct zipy_archive_t zipy_archive_t;

typedef enum zipy_zip_result_t {
  ZIPY_ZIP_OK       =  0,
  ZIPY_ZIP_SAVED    =  1,
  ZIPY_ZIP_SKIPPED  =  2,
  ZIPY_ZIP_ERR      = -1,
  ZIPY_ZIP_EINFLATE = -2,
  ZIPY_ZIP_ESIZE    = -3,
  ZIPY_ZIP_ECRC     = -4,
  ZIPY_ZIP_EFILE    = -5,
  ZIPY_ZIP_EUNSUP   = -6,
  ZIPY_ZIP_EEXIST   = -7,
  ZIPY_ZIP_EPASS    = -8,
  ZIPY_ZIP_EAUTH    = -9
} zipy_zip_result_t;

typedef enum zipy_zip_method_t {
  ZIPY_ZIP_STORE   = 0,
  ZIPY_ZIP_DEFLATE = 8
} zipy_zip_method_t;

typedef enum zipy_save_location_t {
  ZIPY_SAVE_TARGET = 0,
  ZIPY_SAVE_HOME   = 1,
  ZIPY_SAVE_TRASH  = 2
} zipy_save_location_t;

typedef enum zipy_conflict_policy_t {
  ZIPY_CONFLICT_SAVE      = 0,
  ZIPY_CONFLICT_OVERWRITE = 1,
  ZIPY_CONFLICT_SKIP      = 2,
  ZIPY_CONFLICT_FAIL      = 3
} zipy_conflict_policy_t;

typedef enum zipy_extract_flags_t {
  ZIPY_EXTRACT_DEFAULT = 0,
  ZIPY_EXTRACT_NO_CRC  = 1u << 0
} zipy_extract_flags_t;

typedef struct zipy_extract_options_t {
  zipy_conflict_policy_t on_conflict;
  zipy_save_location_t save_to;
  const char       *save_dir;
  uint32_t          flags;
  const char       *password;
} zipy_extract_options_t;

typedef struct zipy_entry_t {
  const char *name;
  size_t      name_len;
  uint64_t    compressed_size;
  uint64_t    uncompressed_size;
  uint32_t    crc32;
  uint16_t    method;
  bool        is_directory;
  bool        encrypted;
} zipy_entry_t;

ZIPY_EXPORT zipy_archive_t *
zipy_open(const char *path);

ZIPY_EXPORT size_t
zipy_count(const zipy_archive_t *zipy);

ZIPY_EXPORT const zipy_entry_t *
zipy_entry(const zipy_archive_t *zipy, size_t index);

ZIPY_EXPORT int
zipy_extract(zipy_archive_t *zipy, size_t index, const char *destpath);

ZIPY_EXPORT int
zipy_extract_to(zipy_archive_t *zipy,
                size_t index,
                const char *destdir,
                const zipy_extract_options_t *options);

ZIPY_EXPORT int
zipy_extract_named(zipy_archive_t *zipy, const char *name, const char *destpath);

ZIPY_EXPORT int
zipy_extract_all(zipy_archive_t *zipy, const char *destdir);

ZIPY_EXPORT int
zipy_extract_all_options(zipy_archive_t *zipy,
                         const char *destdir,
                         const zipy_extract_options_t *options);

ZIPY_EXPORT void
zipy_close(zipy_archive_t *zipy);

#endif /* zipy_zip_h */
