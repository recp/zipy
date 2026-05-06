/*
 * Copyright (C) 2025 Recep Aslantas
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */

#define _FILE_OFFSET_BITS 64
#define _LARGEFILE_SOURCE

#include <defl/infl.h>
#include <zap/zip.h>

#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if defined(_WIN32)
#  include <direct.h>
#  include <io.h>
#else
#  include <sys/stat.h>
#  include <sys/types.h>
#endif

#define ZIP_SIGN_LOCAL_FILE    0x04034B50u
#define ZIP_SIGN_CENTRAL_DIR   0x02014B50u
#define ZIP_SIGN_END_CENTRAL   0x06054B50u
#define ZIP_SIGN_ZIP64_END     0x06064B50u
#define ZIP_SIGN_ZIP64_LOCATOR 0x07064B50u

#define ZIP64_MAGIC_UINT16     0xFFFFu
#define ZIP64_MAGIC_UINT32     0xFFFFFFFFu

#define ZIP_LOCAL_FIXED       30u
#define ZIP_CENTRAL_FIXED     46u
#define ZIP_EOCD_FIXED        22u
#define ZIP64_EOCD_FIXED      56u
#define ZIP64_LOCATOR_FIXED   20u
#define ZIP_MAX_EOCD_SEARCH   (ZIP_EOCD_FIXED + 65535u)
#define ZIP_IO_CHUNK          (256u * 1024u)

#define ZIP_EXTRA_ZIP64       0x0001u
#define ZIP_FLAG_ENCRYPTED    0x0001u
#define ZIP_FLAG_STRONG_ENC   0x0040u

typedef struct ZapFile {
  ZapEntry entry;
  uint64_t localHeaderOffset;
  uint16_t flags;
  uint32_t externalAttr;
} ZapFile;

struct ZapArchive {
  FILE    *fp;
  ZapFile *files;
  size_t   fileCount;
  uint64_t fileSize;
};

typedef struct ZapDirInfo {
  uint64_t fileSize;
  uint64_t eocdOffset;
  uint64_t centralDirOffset;
  uint64_t centralDirSize;
  uint64_t entries;
} ZapDirInfo;

static uint16_t
zap_le16(const uint8_t *p) {
  return (uint16_t)((uint16_t)p[0] | ((uint16_t)p[1] << 8));
}

static uint32_t
zap_le32(const uint8_t *p) {
  return ((uint32_t)p[0])
       | ((uint32_t)p[1] << 8)
       | ((uint32_t)p[2] << 16)
       | ((uint32_t)p[3] << 24);
}

static uint64_t
zap_le64(const uint8_t *p) {
  return ((uint64_t)zap_le32(p)) | ((uint64_t)zap_le32(p + 4) << 32);
}

static int
zap_read(FILE *fp, void *buf, size_t len) {
  return len == 0 || fread(buf, 1, len, fp) == len;
}

static int
zap_seek_set(FILE *fp, uint64_t off) {
#if defined(_WIN32)
  if (off > (uint64_t)INT64_MAX)
    return -1;
  return _fseeki64(fp, (__int64)off, SEEK_SET);
#else
  if (off > (uint64_t)INT64_MAX)
    return -1;
  return fseeko(fp, (off_t)off, SEEK_SET);
#endif
}

static int
zap_tell(FILE *fp, uint64_t *pos) {
#if defined(_WIN32)
  __int64 p = _ftelli64(fp);
  if (p < 0)
    return -1;
  *pos = (uint64_t)p;
#else
  off_t p = ftello(fp);
  if (p < 0)
    return -1;
  *pos = (uint64_t)p;
#endif
  return 0;
}

static int
zap_skip(FILE *fp, uint64_t len) {
  uint64_t pos;

  if (zap_tell(fp, &pos) != 0 || UINT64_MAX - pos < len)
    return -1;

  return zap_seek_set(fp, pos + len);
}

static int
zap_file_size(FILE *fp, uint64_t *size) {
#if defined(_WIN32)
  if (_fseeki64(fp, 0, SEEK_END) != 0)
    return -1;
#else
  if (fseeko(fp, 0, SEEK_END) != 0)
    return -1;
#endif

  return zap_tell(fp, size);
}

static int
zap_u64_to_size(uint64_t value, size_t *out) {
  if (value > (uint64_t)SIZE_MAX)
    return 0;

  *out = (size_t)value;
  return 1;
}

static char *
zap_strndup(const uint8_t *src, size_t len) {
  char *dst;

  if (memchr(src, '\0', len))
    return NULL;

  dst = malloc(len + 1);
  if (!dst)
    return NULL;

  memcpy(dst, src, len);
  dst[len] = '\0';
  return dst;
}

static int
zap_read_zip64_eocd(FILE *fp, ZapDirInfo *dir) {
  uint8_t locator[ZIP64_LOCATOR_FIXED];
  uint8_t eocd[ZIP64_EOCD_FIXED];
  uint64_t zip64Off, entriesDisk;

  if (dir->eocdOffset < ZIP64_LOCATOR_FIXED)
    return 0;

  if (zap_seek_set(fp, dir->eocdOffset - ZIP64_LOCATOR_FIXED) != 0
      || !zap_read(fp, locator, sizeof(locator)))
    return 0;

  if (zap_le32(locator) != ZIP_SIGN_ZIP64_LOCATOR)
    return 0;

  if (zap_le32(locator + 4) != 0 || zap_le32(locator + 16) != 1)
    return 0;

  zip64Off = zap_le64(locator + 8);
  if (dir->fileSize < ZIP64_EOCD_FIXED
      || zip64Off > dir->fileSize - ZIP64_EOCD_FIXED)
    return 0;

  if (zap_seek_set(fp, zip64Off) != 0 || !zap_read(fp, eocd, sizeof(eocd)))
    return 0;

  if (zap_le32(eocd) != ZIP_SIGN_ZIP64_END || zap_le64(eocd + 4) < 44)
    return 0;

  if (zap_le32(eocd + 16) != 0 || zap_le32(eocd + 20) != 0)
    return 0;

  entriesDisk = zap_le64(eocd + 24);
  dir->entries = zap_le64(eocd + 32);
  if (entriesDisk != dir->entries)
    return 0;

  dir->centralDirSize = zap_le64(eocd + 40);
  dir->centralDirOffset = zap_le64(eocd + 48);
  return 1;
}

static int
zap_find_eocd(FILE *fp, ZapDirInfo *dir) {
  uint8_t *tail;
  uint64_t tailOff, fileSize;
  size_t tailSize, i;

  memset(dir, 0, sizeof(*dir));

  if (zap_file_size(fp, &fileSize) != 0 || fileSize < ZIP_EOCD_FIXED)
    return 0;

  tailSize = fileSize < ZIP_MAX_EOCD_SEARCH
           ? (size_t)fileSize
           : (size_t)ZIP_MAX_EOCD_SEARCH;
  tailOff = fileSize - tailSize;

  tail = malloc(tailSize);
  if (!tail)
    return 0;

  if (zap_seek_set(fp, tailOff) != 0 || !zap_read(fp, tail, tailSize)) {
    free(tail);
    return 0;
  }

  i = tailSize - ZIP_EOCD_FIXED;
  for (;;) {
    const uint8_t *p = tail + i;

    if (zap_le32(p) == ZIP_SIGN_END_CENTRAL) {
      uint16_t disk = zap_le16(p + 4);
      uint16_t cdDisk = zap_le16(p + 6);
      uint16_t entriesDisk = zap_le16(p + 8);
      uint16_t entries = zap_le16(p + 10);
      uint16_t commentLen = zap_le16(p + 20);
      int needsZip64;

      if (i + ZIP_EOCD_FIXED + commentLen != tailSize)
        goto next;

      dir->fileSize = fileSize;
      dir->eocdOffset = tailOff + i;
      dir->entries = entries;
      dir->centralDirSize = zap_le32(p + 12);
      dir->centralDirOffset = zap_le32(p + 16);

      needsZip64 = disk == ZIP64_MAGIC_UINT16
                || cdDisk == ZIP64_MAGIC_UINT16
                || entriesDisk == ZIP64_MAGIC_UINT16
                || entries == ZIP64_MAGIC_UINT16
                || dir->centralDirSize == ZIP64_MAGIC_UINT32
                || dir->centralDirOffset == ZIP64_MAGIC_UINT32;

      if (needsZip64) {
        if (!zap_read_zip64_eocd(fp, dir))
          break;
      } else if (disk != 0 || cdDisk != 0 || entriesDisk != entries) {
        break;
      }

      free(tail);
      if (UINT64_MAX - dir->centralDirOffset < dir->centralDirSize)
        return 0;
      return dir->centralDirOffset + dir->centralDirSize <= dir->eocdOffset;
    }

next:
    if (i == 0)
      break;
    i--;
  }

  free(tail);
  return 0;
}

static int
zap_parse_zip64_extra(ZapFile *info,
                      const uint8_t *extra,
                      size_t len,
                      uint32_t comp32,
                      uint32_t uncomp32,
                      uint32_t offset32,
                      uint16_t disk32) {
  size_t pos = 0;
  uint32_t disk = disk32;

  while (len - pos >= 4) {
    uint16_t id = zap_le16(extra + pos);
    uint16_t size = zap_le16(extra + pos + 2);
    const uint8_t *p = extra + pos + 4;
    size_t rem;

    pos += 4;
    if (size > len - pos)
      return 0;

    rem = size;
    if (id == ZIP_EXTRA_ZIP64) {
      if (uncomp32 == ZIP64_MAGIC_UINT32) {
        if (rem < 8)
          return 0;
        info->entry.uncompressedSize = zap_le64(p);
        p += 8;
        rem -= 8;
      }

      if (comp32 == ZIP64_MAGIC_UINT32) {
        if (rem < 8)
          return 0;
        info->entry.compressedSize = zap_le64(p);
        p += 8;
        rem -= 8;
      }

      if (offset32 == ZIP64_MAGIC_UINT32) {
        if (rem < 8)
          return 0;
        info->localHeaderOffset = zap_le64(p);
        p += 8;
        rem -= 8;
      }

      if (disk32 == ZIP64_MAGIC_UINT16) {
        if (rem < 4)
          return 0;
        disk = zap_le32(p);
      }
    }

    pos += size;
  }

  return pos == len
      && disk == 0
      && (comp32 != ZIP64_MAGIC_UINT32
          || info->entry.compressedSize != ZIP64_MAGIC_UINT32)
      && (uncomp32 != ZIP64_MAGIC_UINT32
          || info->entry.uncompressedSize != ZIP64_MAGIC_UINT32)
      && (offset32 != ZIP64_MAGIC_UINT32
          || info->localHeaderOffset != ZIP64_MAGIC_UINT32);
}

static bool
zap_is_zip_sep(char c) {
  return c == '/' || c == '\\';
}

static bool
zap_is_fs_sep(char c) {
#if defined(_WIN32)
  return c == '/' || c == '\\';
#else
  return c == '/';
#endif
}

static bool
zap_is_safe_member_name(const char *path) {
  const char *seg;
  const char *p;

  if (!path || !*path || zap_is_zip_sep(path[0]))
    return false;

  if (isalpha((unsigned char)path[0]) && path[1] == ':')
    return false;

  seg = path;
  for (p = path; ; p++) {
    unsigned char c = (unsigned char)*p;

    if (c != '\0' && (c < 32 || c == '<' || c == '>' || c == '|'
        || c == '"'))
      return false;

    if (c == '\0' || zap_is_zip_sep((char)c)) {
      size_t len = (size_t)(p - seg);
      if (len == 2 && seg[0] == '.' && seg[1] == '.')
        return false;

      if (c == '\0')
        break;

      seg = p + 1;
    }
  }

  return true;
}

static bool
zap_is_dir_name(const char *path) {
  size_t len = strlen(path);
  return len > 0 && zap_is_zip_sep(path[len - 1]);
}

static int
zap_mkdir_one(const char *path) {
  if (!path || !*path)
    return 1;

#if defined(_WIN32)
  if (_mkdir(path) == 0 || errno == EEXIST)
    return 1;
#else
  if (mkdir(path, 0755) == 0 || errno == EEXIST)
    return 1;
#endif

  return 0;
}

static int
zap_mkdirs(const char *path) {
  char *tmp, *p;
  int ok = 1;

  if (!path || !*path)
    return 1;

  tmp = malloc(strlen(path) + 1);
  if (!tmp)
    return 0;
  strcpy(tmp, path);

  p = tmp;
#if defined(_WIN32)
  if (isalpha((unsigned char)p[0]) && p[1] == ':')
    p += 2;
#endif
  while (zap_is_fs_sep(*p))
    p++;

  for (; *p; p++) {
    if (!zap_is_fs_sep(*p))
      continue;

    *p = '\0';
    ok = zap_mkdir_one(tmp);
    *p = '/';
    if (!ok)
      break;

    while (zap_is_fs_sep(p[1]))
      p++;
  }

  if (ok)
    ok = zap_mkdir_one(tmp);

  free(tmp);
  return ok;
}

static int
zap_mkdir_parent(const char *path) {
  char *tmp, *p, *last = NULL;
  int ok;

  if (!path || !*path)
    return 0;

  tmp = malloc(strlen(path) + 1);
  if (!tmp)
    return 0;
  strcpy(tmp, path);

  for (p = tmp; *p; p++) {
    if (zap_is_fs_sep(*p))
      last = p;
  }

  if (!last) {
    free(tmp);
    return 1;
  }

  if (last == tmp && zap_is_fs_sep(tmp[0])) {
    tmp[1] = '\0';
  } else {
    *last = '\0';
  }

  ok = zap_mkdirs(tmp);
  free(tmp);
  return ok;
}

static ZapFile *
zap_find_file(ZapArchive *zap, const char *filename) {
  size_t i;

  for (i = 0; i < zap->fileCount; i++) {
    if (strcmp(zap->files[i].entry.name, filename) == 0)
      return &zap->files[i];
  }

  return NULL;
}

static void
zap_free_files(ZapArchive *zap) {
  size_t i;

  if (!zap || !zap->files)
    return;

  for (i = 0; i < zap->fileCount; i++)
    free((char *)zap->files[i].entry.name);

  free(zap->files);
  zap->files = NULL;
}

static size_t
zap_chunk_size(uint64_t remaining) {
  return remaining > ZIP_IO_CHUNK ? ZIP_IO_CHUNK : (size_t)remaining;
}

static uint32_t
zap_crc32_update(uint32_t crc, const uint8_t *buf, size_t len) {
  static const uint32_t table[16] = {
    0x00000000u, 0x1DB71064u, 0x3B6E20C8u, 0x26D930ACu,
    0x76DC4190u, 0x6B6B51F4u, 0x4DB26158u, 0x5005713Cu,
    0xEDB88320u, 0xF00F9344u, 0xD6D6A3E8u, 0xCB61B38Cu,
    0x9B64C2B0u, 0x86D3D2D4u, 0xA00AE278u, 0xBDBDF21Cu
  };

  crc = ~crc;
  while (len--) {
    crc ^= *buf++;
    crc = (crc >> 4) ^ table[crc & 0x0Fu];
    crc = (crc >> 4) ^ table[crc & 0x0Fu];
  }
  return ~crc;
}

static int
zap_write_chunk(FILE *out,
                const uint8_t *buf,
                size_t len,
                uint32_t *crc,
                uint64_t *written) {
  if (len == 0)
    return ZAP_ZIP_OK;

  if (fwrite(buf, 1, len, out) != len)
    return ZAP_ZIP_EFILE;

  *crc = zap_crc32_update(*crc, buf, len);
  *written += len;
  return ZAP_ZIP_OK;
}

static int
zap_copy_store(FILE *fp, FILE *out, uint64_t len, uint32_t expectedCrc) {
  uint8_t *buf;
  uint64_t remaining = len, written = 0;
  uint32_t crc;
  int ret = ZAP_ZIP_OK;

  buf = malloc(ZIP_IO_CHUNK);
  if (!buf)
    return ZAP_ZIP_ERR;

  crc = 0;
  while (remaining > 0) {
    size_t n = zap_chunk_size(remaining);

    if (fread(buf, 1, n, fp) != n) {
      ret = ZAP_ZIP_EFILE;
      goto done;
    }

    ret = zap_write_chunk(out, buf, n, &crc, &written);
    if (ret != ZAP_ZIP_OK)
      goto done;

    remaining -= n;
  }

  if (written != len)
    ret = ZAP_ZIP_ESIZE;
  else if ((uint32_t)crc != expectedCrc)
    ret = ZAP_ZIP_ECRC;

done:
  free(buf);
  return ret;
}

static int
zap_inflate_raw(FILE *fp,
                FILE *out,
                uint64_t compressedSize,
                uint64_t uncompressedSize,
                uint32_t expectedCrc) {
  uint8_t *inbuf = NULL;
  uint8_t *outbuf = NULL;
  size_t inlen, outlen;
  uint32_t crc;
  int ret;

  if (compressedSize > UINT32_MAX || uncompressedSize > UINT32_MAX)
    return ZAP_ZIP_EUNSUP;

  inlen = compressedSize > 0 ? (size_t)compressedSize : 1;
  outlen = uncompressedSize > 0 ? (size_t)uncompressedSize : 1;

  inbuf = malloc(inlen);
  outbuf = malloc(outlen);
  if (!inbuf || !outbuf) {
    ret = ZAP_ZIP_ERR;
    goto done;
  }

  if (compressedSize > 0 && fread(inbuf, 1, (size_t)compressedSize, fp) != (size_t)compressedSize) {
    ret = ZAP_ZIP_EFILE;
    goto done;
  }

  if (infl_buf(inbuf,
               (uint32_t)compressedSize,
               outbuf,
               (uint32_t)uncompressedSize,
               0) != UNZ_OK) {
    ret = ZAP_ZIP_EINFLATE;
    goto done;
  }

  crc = zap_crc32_update(0, outbuf, (size_t)uncompressedSize);
  if (crc != expectedCrc) {
    ret = ZAP_ZIP_ECRC;
    goto done;
  }

  if (uncompressedSize > 0
      && fwrite(outbuf, 1, (size_t)uncompressedSize, out) != (size_t)uncompressedSize) {
    ret = ZAP_ZIP_EFILE;
    goto done;
  }

  ret = ZAP_ZIP_OK;

done:
  free(outbuf);
  free(inbuf);
  return ret;
}

static char *
zap_extract_path(const char *dir, const char *name) {
  size_t dirLen, nameLen, i;
  char *path;

  if (!dir || !name)
    return NULL;

  dirLen = strlen(dir);
  nameLen = strlen(name);
  path = malloc(dirLen + nameLen + 2);
  if (!path)
    return NULL;

  memcpy(path, dir, dirLen);
  if (dirLen > 0 && !zap_is_fs_sep(dir[dirLen - 1]))
    path[dirLen++] = '/';

  for (i = 0; i < nameLen; i++)
    path[dirLen + i] = zap_is_zip_sep(name[i]) ? '/' : name[i];
  path[dirLen + nameLen] = '\0';

  return path;
}

ZAP_EXPORT
ZapArchive *
zap_open(const char *path) {
  ZapArchive *zap = NULL;
  ZapDirInfo dir;
  FILE *fp;
  size_t i, count;

  if (!path || !(fp = fopen(path, "rb")))
    return NULL;

  if (!zap_find_eocd(fp, &dir))
    goto err;

  if (!zap_u64_to_size(dir.entries, &count))
    goto err;

  zap = calloc(1, sizeof(*zap));
  if (!zap)
    goto err;

  zap->fp = fp;
  zap->fileCount = count;
  zap->fileSize = dir.fileSize;

  if (count > 0) {
    zap->files = calloc(count, sizeof(*zap->files));
    if (!zap->files)
      goto err;
  }

  if (zap_seek_set(fp, dir.centralDirOffset) != 0)
    goto err;

  for (i = 0; i < count; i++) {
    uint8_t hdr[ZIP_CENTRAL_FIXED];
    uint8_t *name = NULL, *extra = NULL;
    ZapFile *info = &zap->files[i];
    uint16_t nameLen, extraLen, commentLen, diskStart;
    uint32_t comp32, uncomp32, offset32;

    if (!zap_read(fp, hdr, sizeof(hdr)) || zap_le32(hdr) != ZIP_SIGN_CENTRAL_DIR)
      goto err;

    info->flags = zap_le16(hdr + 8);
    info->entry.method = zap_le16(hdr + 10);
    info->entry.crc32 = zap_le32(hdr + 16);
    comp32 = zap_le32(hdr + 20);
    uncomp32 = zap_le32(hdr + 24);
    nameLen = zap_le16(hdr + 28);
    extraLen = zap_le16(hdr + 30);
    commentLen = zap_le16(hdr + 32);
    diskStart = zap_le16(hdr + 34);
    info->externalAttr = zap_le32(hdr + 38);
    offset32 = zap_le32(hdr + 42);

    if (nameLen == 0
        || (diskStart != 0 && diskStart != ZIP64_MAGIC_UINT16))
      goto err;

    name = malloc(nameLen);
    if (!name || !zap_read(fp, name, nameLen))
      goto err;

    info->entry.name = zap_strndup(name, nameLen);
    free(name);
    name = NULL;
    if (!info->entry.name)
      goto err;

    info->entry.compressedSize = comp32;
    info->entry.uncompressedSize = uncomp32;
    info->localHeaderOffset = offset32;
    info->entry.isDirectory = zap_is_dir_name(info->entry.name);

    if (extraLen > 0) {
      extra = malloc(extraLen);
      if (!extra || !zap_read(fp, extra, extraLen))
        goto err;

      if (!zap_parse_zip64_extra(info, extra, extraLen,
                                 comp32, uncomp32, offset32, diskStart))
        goto err;
      free(extra);
      extra = NULL;
    } else if (comp32 == ZIP64_MAGIC_UINT32
               || uncomp32 == ZIP64_MAGIC_UINT32
               || offset32 == ZIP64_MAGIC_UINT32) {
      goto err;
    }

    if (info->localHeaderOffset >= dir.centralDirOffset
        || info->entry.compressedSize > zap->fileSize
        || UINT64_MAX - info->localHeaderOffset < ZIP_LOCAL_FIXED)
      goto err;

    if (commentLen > 0 && zap_skip(fp, commentLen) != 0)
      goto err;
  }

  return zap;

err:
  if (zap) {
    zap_free_files(zap);
    free(zap);
  }
  fclose(fp);
  return NULL;
}

static int
zap_extract_entry(ZapArchive *zap, ZapFile *info, const char *destpath) {
  uint8_t local[ZIP_LOCAL_FIXED];
  uint16_t flags, method, nameLen, extraLen;
  uint64_t dataOffset;
  FILE *outfp;
  int ret = ZAP_ZIP_ERR;

  if (!zap || !zap->fp || !info || !destpath)
    return ZAP_ZIP_ERR;

  if (!zap_is_safe_member_name(info->entry.name))
    return ZAP_ZIP_EFILE;

  if (info->flags & (ZIP_FLAG_ENCRYPTED | ZIP_FLAG_STRONG_ENC))
    return ZAP_ZIP_EUNSUP;

  if (info->entry.isDirectory)
    return zap_mkdirs(destpath) ? ZAP_ZIP_OK : ZAP_ZIP_EFILE;

  if (info->entry.method != ZAP_ZIP_STORE && info->entry.method != ZAP_ZIP_DEFLATE)
    return ZAP_ZIP_EUNSUP;

  if (zap_seek_set(zap->fp, info->localHeaderOffset) != 0
      || !zap_read(zap->fp, local, sizeof(local))
      || zap_le32(local) != ZIP_SIGN_LOCAL_FILE)
    return ZAP_ZIP_EFILE;

  flags = zap_le16(local + 6);
  method = zap_le16(local + 8);
  nameLen = zap_le16(local + 26);
  extraLen = zap_le16(local + 28);

  if (method != info->entry.method || (flags & (ZIP_FLAG_ENCRYPTED | ZIP_FLAG_STRONG_ENC)))
    return ZAP_ZIP_EUNSUP;

  if (UINT64_MAX - info->localHeaderOffset
      < ZIP_LOCAL_FIXED + (uint64_t)nameLen + (uint64_t)extraLen)
    return ZAP_ZIP_ESIZE;

  dataOffset = info->localHeaderOffset + ZIP_LOCAL_FIXED + nameLen + extraLen;
  if (dataOffset > zap->fileSize || info->entry.compressedSize > zap->fileSize - dataOffset)
    return ZAP_ZIP_ESIZE;

  if (zap_seek_set(zap->fp, dataOffset) != 0)
    return ZAP_ZIP_EFILE;

  if (!zap_mkdir_parent(destpath)) {
    ret = ZAP_ZIP_EFILE;
    return ret;
  }

  outfp = fopen(destpath, "wb");
  if (!outfp) {
    ret = ZAP_ZIP_EFILE;
    return ret;
  }

  if (info->entry.method == ZAP_ZIP_STORE) {
    if (info->entry.compressedSize != info->entry.uncompressedSize)
      ret = ZAP_ZIP_ESIZE;
    else
      ret = zap_copy_store(zap->fp, outfp,
                           info->entry.uncompressedSize,
                           info->entry.crc32);
  } else {
    ret = zap_inflate_raw(zap->fp, outfp,
                          info->entry.compressedSize,
                          info->entry.uncompressedSize,
                          info->entry.crc32);
  }

  if (fclose(outfp) != 0 && ret == ZAP_ZIP_OK)
    ret = ZAP_ZIP_EFILE;

  return ret;
}

ZAP_EXPORT
size_t
zap_count(const ZapArchive *zap) {
  return zap ? zap->fileCount : 0;
}

ZAP_EXPORT
const ZapEntry *
zap_entry(const ZapArchive *zap, size_t index) {
  if (!zap || index >= zap->fileCount)
    return NULL;

  return &zap->files[index].entry;
}

ZAP_EXPORT
int
zap_extract(ZapArchive *zap, size_t index, const char *destpath) {
  if (!zap || index >= zap->fileCount)
    return ZAP_ZIP_EFILE;

  return zap_extract_entry(zap, &zap->files[index], destpath);
}

ZAP_EXPORT
int
zap_extract_named(ZapArchive *zap, const char *name, const char *destpath) {
  ZapFile *info;

  if (!zap || !name)
    return ZAP_ZIP_ERR;

  info = zap_find_file(zap, name);
  if (!info)
    return ZAP_ZIP_EFILE;

  return zap_extract_entry(zap, info, destpath);
}

ZAP_EXPORT
int
zap_extract_all(ZapArchive *zap, const char *destdir) {
  size_t i;

  if (!zap || !destdir)
    return ZAP_ZIP_ERR;

  for (i = 0; i < zap->fileCount; i++) {
    char *path;
    int ret;

    path = zap_extract_path(destdir, zap->files[i].entry.name);
    if (!path)
      return ZAP_ZIP_ERR;

    ret = zap_extract_entry(zap, &zap->files[i], path);
    free(path);
    if (ret != ZAP_ZIP_OK)
      return ret;
  }

  return ZAP_ZIP_OK;
}

ZAP_EXPORT
void
zap_close(ZapArchive *zap) {
  if (!zap)
    return;

  zap_free_files(zap);
  if (zap->fp)
    fclose(zap->fp);
  free(zap);
}
