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
#include <stdio.h>

/* ZIP signatures */
#define ZIP_SIGN_LOCAL_FILE    0x04034B50
#define ZIP_SIGN_CENTRAL_DIR   0x02014B50
#define ZIP_SIGN_END_CENTRAL   0x06054B50
#define ZIP_SIGN_DATA_DESC     0x08074B50

/* ZIP64 signatures */
#define ZIP_SIGN_ZIP64_END     0x06064B50
#define ZIP_SIGN_ZIP64_LOCATOR 0x07064B50

/* ZIP64 magic values that indicate ZIP64 fields are used */
#define ZIP64_MAGIC_UINT16     0xFFFF
#define ZIP64_MAGIC_UINT32     0xFFFFFFFF

/* Compression methods */
#define ZIP_METHOD_STORE        0
#define ZIP_METHOD_DEFLATE      8

/* Error codes */
#define ZIP_OK            0
#define ZIP_ERR_GENERAL  -1
#define ZIP_ERR_INFLATE  -2
#define ZIP_ERR_SIZE     -3
#define ZIP_ERR_CRC      -4
#define ZIP_ERR_FILE     -5
#define ZIP_ERR_UNSUP    -6

typedef struct ZapFileInfo {
  char    *filename;
  uint64_t compressedSize;
  uint64_t uncompressedSize;
  uint64_t localHeaderOffset;
  uint16_t method;
  uint16_t flags;
  uint32_t crc32;
  uint32_t externalAttr;
  bool     isDirectory;
} ZapFileInfo;

typedef struct ZapArchive {
  FILE        *fp;
  ZapFileInfo *files;
  size_t       fileCount;
  uint64_t     fileSize;
} ZapArchive;

ZAP_EXPORT ZapArchive*
zap_open(const char *path);

ZAP_EXPORT int
zap_extract_file(ZapArchive *zap, 
                 const char *filename,
                 const char *destpath);

ZAP_EXPORT void
zap_close(ZapArchive *zap);

#endif /* zap_zip_h */
