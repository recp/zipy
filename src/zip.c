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

#include "thread/thread.h"

#include <defl/infl.h>
#include <zipy/zip.h>

#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#if defined(_WIN32)
#  include <direct.h>
#  include <io.h>
#  include <sys/stat.h>
#  define zipy_getcwd _getcwd
#else
#  include <sys/stat.h>
#  include <sys/types.h>
#  include <unistd.h>
#  define zipy_getcwd getcwd
#endif

#ifndef PATH_MAX
#  define PATH_MAX 4096
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

#if defined(_WIN32)
#  define ZIPY_PATH_SEP '\\'
#else
#  define ZIPY_PATH_SEP '/'
#endif

typedef struct ZipyFile {
  ZipyEntry entry;
  uint64_t localHeaderOffset;
  uint16_t flags;
  uint32_t externalAttr;
} ZipyFile;

struct ZipyArchive {
  FILE    *fp;
  char    *path;
  ZipyFile *files;
  size_t   fileCount;
  uint64_t fileSize;
};

typedef struct ZipyDirInfo {
  uint64_t fileSize;
  uint64_t eocdOffset;
  uint64_t centralDirOffset;
  uint64_t centralDirSize;
  uint64_t entries;
} ZipyDirInfo;

static uint16_t
zipy_le16(const uint8_t *p) {
  return (uint16_t)((uint16_t)p[0] | ((uint16_t)p[1] << 8));
}

static uint32_t
zipy_le32(const uint8_t *p) {
  return ((uint32_t)p[0])
       | ((uint32_t)p[1] << 8)
       | ((uint32_t)p[2] << 16)
       | ((uint32_t)p[3] << 24);
}

static uint64_t
zipy_le64(const uint8_t *p) {
  return ((uint64_t)zipy_le32(p)) | ((uint64_t)zipy_le32(p + 4) << 32);
}

static int
zipy_read(FILE *fp, void *buf, size_t len) {
  return len == 0 || fread(buf, 1, len, fp) == len;
}

static int
zipy_seek_set(FILE *fp, uint64_t off) {
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
zipy_tell(FILE *fp, uint64_t *pos) {
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
zipy_skip(FILE *fp, uint64_t len) {
  uint64_t pos;

  if (zipy_tell(fp, &pos) != 0 || UINT64_MAX - pos < len)
    return -1;

  return zipy_seek_set(fp, pos + len);
}

static int
zipy_file_size(FILE *fp, uint64_t *size) {
#if defined(_WIN32)
  if (_fseeki64(fp, 0, SEEK_END) != 0)
    return -1;
#else
  if (fseeko(fp, 0, SEEK_END) != 0)
    return -1;
#endif

  return zipy_tell(fp, size);
}

static int
zipy_u64_to_size(uint64_t value, size_t *out) {
  if (value > (uint64_t)SIZE_MAX)
    return 0;

  *out = (size_t)value;
  return 1;
}

static char *
zipy_strdup(const char *src) {
  size_t len;
  char *dst;

  if (!src)
    return NULL;

  len = strlen(src);
  dst = malloc(len + 1);
  if (!dst)
    return NULL;

  memcpy(dst, src, len + 1);
  return dst;
}

static char *
zipy_strndup(const uint8_t *src, size_t len) {
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
zipy_read_zip64_eocd(FILE *fp, ZipyDirInfo *dir) {
  uint8_t locator[ZIP64_LOCATOR_FIXED];
  uint8_t eocd[ZIP64_EOCD_FIXED];
  uint64_t zip64Off, entriesDisk;

  if (dir->eocdOffset < ZIP64_LOCATOR_FIXED)
    return 0;

  if (zipy_seek_set(fp, dir->eocdOffset - ZIP64_LOCATOR_FIXED) != 0
      || !zipy_read(fp, locator, sizeof(locator)))
    return 0;

  if (zipy_le32(locator) != ZIP_SIGN_ZIP64_LOCATOR)
    return 0;

  if (zipy_le32(locator + 4) != 0 || zipy_le32(locator + 16) != 1)
    return 0;

  zip64Off = zipy_le64(locator + 8);
  if (dir->fileSize < ZIP64_EOCD_FIXED
      || zip64Off > dir->fileSize - ZIP64_EOCD_FIXED)
    return 0;

  if (zipy_seek_set(fp, zip64Off) != 0 || !zipy_read(fp, eocd, sizeof(eocd)))
    return 0;

  if (zipy_le32(eocd) != ZIP_SIGN_ZIP64_END || zipy_le64(eocd + 4) < 44)
    return 0;

  if (zipy_le32(eocd + 16) != 0 || zipy_le32(eocd + 20) != 0)
    return 0;

  entriesDisk = zipy_le64(eocd + 24);
  dir->entries = zipy_le64(eocd + 32);
  if (entriesDisk != dir->entries)
    return 0;

  dir->centralDirSize = zipy_le64(eocd + 40);
  dir->centralDirOffset = zipy_le64(eocd + 48);
  return 1;
}

static int
zipy_find_eocd(FILE *fp, ZipyDirInfo *dir) {
  uint8_t *tail;
  uint64_t tailOff, fileSize;
  size_t tailSize, i;

  memset(dir, 0, sizeof(*dir));

  if (zipy_file_size(fp, &fileSize) != 0 || fileSize < ZIP_EOCD_FIXED)
    return 0;

  tailSize = fileSize < ZIP_MAX_EOCD_SEARCH
           ? (size_t)fileSize
           : (size_t)ZIP_MAX_EOCD_SEARCH;
  tailOff = fileSize - tailSize;

  tail = malloc(tailSize);
  if (!tail)
    return 0;

  if (zipy_seek_set(fp, tailOff) != 0 || !zipy_read(fp, tail, tailSize)) {
    free(tail);
    return 0;
  }

  i = tailSize - ZIP_EOCD_FIXED;
  for (;;) {
    const uint8_t *p = tail + i;

    if (zipy_le32(p) == ZIP_SIGN_END_CENTRAL) {
      uint16_t disk = zipy_le16(p + 4);
      uint16_t cdDisk = zipy_le16(p + 6);
      uint16_t entriesDisk = zipy_le16(p + 8);
      uint16_t entries = zipy_le16(p + 10);
      uint16_t commentLen = zipy_le16(p + 20);
      int needsZip64;

      if (i + ZIP_EOCD_FIXED + commentLen != tailSize)
        goto next;

      dir->fileSize = fileSize;
      dir->eocdOffset = tailOff + i;
      dir->entries = entries;
      dir->centralDirSize = zipy_le32(p + 12);
      dir->centralDirOffset = zipy_le32(p + 16);

      needsZip64 = disk == ZIP64_MAGIC_UINT16
                || cdDisk == ZIP64_MAGIC_UINT16
                || entriesDisk == ZIP64_MAGIC_UINT16
                || entries == ZIP64_MAGIC_UINT16
                || dir->centralDirSize == ZIP64_MAGIC_UINT32
                || dir->centralDirOffset == ZIP64_MAGIC_UINT32;

      if (needsZip64) {
        if (!zipy_read_zip64_eocd(fp, dir))
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
zipy_parse_zip64_extra(ZipyFile *info,
                      const uint8_t *extra,
                      size_t len,
                      uint32_t comp32,
                      uint32_t uncomp32,
                      uint32_t offset32,
                      uint16_t disk32) {
  size_t pos = 0;
  uint32_t disk = disk32;

  while (len - pos >= 4) {
    uint16_t id = zipy_le16(extra + pos);
    uint16_t size = zipy_le16(extra + pos + 2);
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
        info->entry.uncompressedSize = zipy_le64(p);
        p += 8;
        rem -= 8;
      }

      if (comp32 == ZIP64_MAGIC_UINT32) {
        if (rem < 8)
          return 0;
        info->entry.compressedSize = zipy_le64(p);
        p += 8;
        rem -= 8;
      }

      if (offset32 == ZIP64_MAGIC_UINT32) {
        if (rem < 8)
          return 0;
        info->localHeaderOffset = zipy_le64(p);
        p += 8;
        rem -= 8;
      }

      if (disk32 == ZIP64_MAGIC_UINT16) {
        if (rem < 4)
          return 0;
        disk = zipy_le32(p);
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
zipy_is_zip_sep(char c) {
  return c == '/' || c == '\\';
}

static bool
zipy_is_fs_sep(char c) {
#if defined(_WIN32)
  return c == '/' || c == '\\';
#else
  return c == '/';
#endif
}

static bool
zipy_is_safe_member_name(const char *path) {
  const char *seg;
  const char *p;

  if (!path || !*path || zipy_is_zip_sep(path[0]))
    return false;

  if (isalpha((unsigned char)path[0]) && path[1] == ':')
    return false;

  seg = path;
  for (p = path; ; p++) {
    unsigned char c = (unsigned char)*p;

    if (c != '\0' && (c < 32 || c == '<' || c == '>' || c == '|'
        || c == '"'))
      return false;

    if (c == '\0' || zipy_is_zip_sep((char)c)) {
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
zipy_is_dir_name(const char *path) {
  size_t len = strlen(path);
  return len > 0 && zipy_is_zip_sep(path[len - 1]);
}

static int
zipy_path_info(const char *path, int *exists, int *isDir) {
#if defined(_WIN32)
  struct _stat64 st;

  if (_stat64(path, &st) != 0) {
#else
  struct stat st;

  if (stat(path, &st) != 0) {
#endif
    if (errno == ENOENT || errno == ENOTDIR) {
      if (exists)
        *exists = 0;
      if (isDir)
        *isDir = 0;
      return 1;
    }
    return 0;
  }

  if (exists)
    *exists = 1;
  if (isDir) {
#if defined(_WIN32)
    *isDir = (st.st_mode & _S_IFDIR) != 0;
#else
    *isDir = S_ISDIR(st.st_mode);
#endif
  }
  return 1;
}

static int
zipy_path_is_dir(const char *path) {
  int exists, isDir;

  if (!zipy_path_info(path, &exists, &isDir))
    return 0;
  return exists && isDir;
}

static int
zipy_mkdir_one(const char *path) {
  if (!path || !*path)
    return 1;

#if defined(_WIN32)
  if (_mkdir(path) == 0)
    return 1;
#else
  if (mkdir(path, 0755) == 0)
    return 1;
#endif

  if (errno == EEXIST)
    return zipy_path_is_dir(path);

  return 0;
}

static int
zipy_mkdirs(const char *path) {
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
  while (zipy_is_fs_sep(*p))
    p++;

  for (; *p; p++) {
    if (!zipy_is_fs_sep(*p))
      continue;

    *p = '\0';
    ok = zipy_mkdir_one(tmp);
    *p = '/';
    if (!ok)
      break;

    while (zipy_is_fs_sep(p[1]))
      p++;
  }

  if (ok)
    ok = zipy_mkdir_one(tmp);

  free(tmp);
  return ok;
}

static int
zipy_mkdir_parent(const char *path) {
  char *tmp, *p, *last = NULL;
  int ok;

  if (!path || !*path)
    return 0;

  tmp = malloc(strlen(path) + 1);
  if (!tmp)
    return 0;
  strcpy(tmp, path);

  for (p = tmp; *p; p++) {
    if (zipy_is_fs_sep(*p))
      last = p;
  }

  if (!last) {
    free(tmp);
    return 1;
  }

  if (last == tmp && zipy_is_fs_sep(tmp[0])) {
    tmp[1] = '\0';
  } else {
    *last = '\0';
  }

  ok = zipy_mkdirs(tmp);
  free(tmp);
  return ok;
}

static ZipyFile *
zipy_find_file(ZipyArchive *zipy, const char *filename) {
  size_t i;

  for (i = 0; i < zipy->fileCount; i++) {
    if (strcmp(zipy->files[i].entry.name, filename) == 0)
      return &zipy->files[i];
  }

  return NULL;
}

static void
zipy_free_files(ZipyArchive *zipy) {
  size_t i;

  if (!zipy || !zipy->files)
    return;

  for (i = 0; i < zipy->fileCount; i++)
    free((char *)zipy->files[i].entry.name);

  free(zipy->files);
  zipy->files = NULL;
}

static size_t
zipy_chunk_size(uint64_t remaining) {
  return remaining > ZIP_IO_CHUNK ? ZIP_IO_CHUNK : (size_t)remaining;
}

static uint32_t
zipy_crc32_update(uint32_t crc, const uint8_t *buf, size_t len) {
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
zipy_write_chunk(FILE *out,
                const uint8_t *buf,
                size_t len,
                uint32_t *crc,
                uint64_t *written) {
  if (len == 0)
    return ZIPY_ZIP_OK;

  if (fwrite(buf, 1, len, out) != len)
    return ZIPY_ZIP_EFILE;

  *crc = zipy_crc32_update(*crc, buf, len);
  *written += len;
  return ZIPY_ZIP_OK;
}

static int
zipy_copy_store(FILE *fp, FILE *out, uint64_t len, uint32_t expectedCrc) {
  uint8_t *buf;
  uint64_t remaining = len, written = 0;
  uint32_t crc;
  int ret = ZIPY_ZIP_OK;

  buf = malloc(ZIP_IO_CHUNK);
  if (!buf)
    return ZIPY_ZIP_ERR;

  crc = 0;
  while (remaining > 0) {
    size_t n = zipy_chunk_size(remaining);

    if (fread(buf, 1, n, fp) != n) {
      ret = ZIPY_ZIP_EFILE;
      goto done;
    }

    ret = zipy_write_chunk(out, buf, n, &crc, &written);
    if (ret != ZIPY_ZIP_OK)
      goto done;

    remaining -= n;
  }

  if (written != len)
    ret = ZIPY_ZIP_ESIZE;
  else if ((uint32_t)crc != expectedCrc)
    ret = ZIPY_ZIP_ECRC;

done:
  free(buf);
  return ret;
}

static int
zipy_inflate_raw(FILE *fp,
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
    return ZIPY_ZIP_EUNSUP;

  inlen = compressedSize > 0 ? (size_t)compressedSize : 1;
  outlen = uncompressedSize > 0 ? (size_t)uncompressedSize : 1;

  inbuf = malloc(inlen);
  outbuf = malloc(outlen);
  if (!inbuf || !outbuf) {
    ret = ZIPY_ZIP_ERR;
    goto done;
  }

  if (compressedSize > 0 && fread(inbuf, 1, (size_t)compressedSize, fp) != (size_t)compressedSize) {
    ret = ZIPY_ZIP_EFILE;
    goto done;
  }

  if (infl_buf(inbuf,
               (uint32_t)compressedSize,
               outbuf,
               (uint32_t)uncompressedSize,
               0) != UNZ_OK) {
    ret = ZIPY_ZIP_EINFLATE;
    goto done;
  }

  crc = zipy_crc32_update(0, outbuf, (size_t)uncompressedSize);
  if (crc != expectedCrc) {
    ret = ZIPY_ZIP_ECRC;
    goto done;
  }

  if (uncompressedSize > 0
      && fwrite(outbuf, 1, (size_t)uncompressedSize, out) != (size_t)uncompressedSize) {
    ret = ZIPY_ZIP_EFILE;
    goto done;
  }

  ret = ZIPY_ZIP_OK;

done:
  free(outbuf);
  free(inbuf);
  return ret;
}

static char *
zipy_extract_path(const char *dir, const char *name) {
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
  if (dirLen > 0 && !zipy_is_fs_sep(dir[dirLen - 1]))
    path[dirLen++] = '/';

  for (i = 0; i < nameLen; i++)
    path[dirLen + i] = zipy_is_zip_sep(name[i]) ? '/' : name[i];
  path[dirLen + nameLen] = '\0';

  return path;
}

static char *
zipy_join_path(const char *dir, const char *name) {
  size_t dirLen, nameLen;
  char *path;

  if (!dir || !name)
    return NULL;

  dirLen = strlen(dir);
  nameLen = strlen(name);
  path = malloc(dirLen + nameLen + 2);
  if (!path)
    return NULL;

  memcpy(path, dir, dirLen);
  if (dirLen > 0 && !zipy_is_fs_sep(dir[dirLen - 1]))
    path[dirLen++] = ZIPY_PATH_SEP;
  memcpy(path + dirLen, name, nameLen + 1);
  return path;
}

static int
zipy_is_abs_path(const char *path) {
  if (!path || !*path)
    return 0;

#if defined(_WIN32)
  if (isalpha((unsigned char)path[0]) && path[1] == ':')
    return 1;
#endif

  return zipy_is_fs_sep(path[0]);
}

static char *
zipy_abs_path(const char *path) {
  char cwd[PATH_MAX];

  if (!path)
    return NULL;

  if (zipy_is_abs_path(path))
    return zipy_strdup(path);

  if (!zipy_getcwd(cwd, sizeof(cwd)))
    return zipy_strdup(path);

  return zipy_join_path(cwd, path);
}

static char *
zipy_trim_trailing_seps(const char *path) {
  char *out;
  size_t len;

  if (!path)
    return NULL;

  len = strlen(path);
  while (len > 1 && zipy_is_fs_sep(path[len - 1])) {
#if defined(_WIN32)
    if (len == 3 && isalpha((unsigned char)path[0]) && path[1] == ':')
      break;
#endif
    len--;
  }

  out = malloc(len + 1);
  if (!out)
    return NULL;

  memcpy(out, path, len);
  out[len] = '\0';
  return out;
}

static const char *
zipy_home_dir(void) {
  const char *home;

#if defined(_WIN32)
  home = getenv("USERPROFILE");
  if (!home || !*home)
    home = getenv("HOME");
#else
  home = getenv("HOME");
#endif

  return home && *home ? home : NULL;
}

static char *
zipy_trash_dir(void) {
  const char *home = zipy_home_dir();

  if (!home)
    return NULL;

#if defined(_WIN32)
  return zipy_join_path(home, "AppData\\Local\\Microsoft\\Windows\\Recycle Bin");
#elif defined(__APPLE__)
  return zipy_join_path(home, ".Trash");
#else
  return zipy_join_path(home, ".local/share/Trash/files");
#endif
}

static void
zipy_saved_name(char *buf, size_t len) {
  time_t now;
  struct tm tmv;

  now = time(NULL);
#if defined(_WIN32)
  localtime_s(&tmv, &now);
#else
  localtime_r(&now, &tmv);
#endif

  strftime(buf, len, "zipy %Y-%m-%d %H-%M-%S saved", &tmv);
}

static char *
zipy_create_save_dir(const char *destdir, ZipySaveLocation saveTo) {
  char name[64], numbered[96];
  const char *base = destdir;
  char *ownedBase = NULL;
  char *path = NULL;
  unsigned i;

  if (saveTo == ZIPY_SAVE_HOME) {
    base = zipy_home_dir();
  } else if (saveTo == ZIPY_SAVE_TRASH) {
    ownedBase = zipy_trash_dir();
    base = ownedBase;
  }

  if (!base || !*base)
    goto done;

  if (!zipy_mkdirs(base))
    goto done;

  zipy_saved_name(name, sizeof(name));
  for (i = 0; i < 1000; i++) {
    free(path);
    if (i == 0) {
      path = zipy_join_path(base, name);
    } else {
      snprintf(numbered, sizeof(numbered), "%s %u", name, i + 1);
      path = zipy_join_path(base, numbered);
    }

    if (!path)
      goto done;

#if defined(_WIN32)
    if (_mkdir(path) == 0)
      goto done;
#else
    if (mkdir(path, 0755) == 0)
      goto done;
#endif

    if (errno != EEXIST) {
      free(path);
      path = NULL;
      goto done;
    }
  }

  free(path);
  path = NULL;

done:
  free(ownedBase);
  return path;
}

static int
zipy_append_saved_manifest(const char *saveDir,
                           const char *originalPath,
                           const char *savedPath) {
  char *manifest;
  FILE *fp;

  manifest = zipy_join_path(saveDir, "zipy_saved_original_paths.txt");
  if (!manifest)
    return 0;

  fp = fopen(manifest, "ab");
  free(manifest);
  if (!fp)
    return 0;

  fprintf(fp, "%s -> %s\n", originalPath, savedPath);
  if (fclose(fp) != 0)
    return 0;

  return 1;
}

static ZipyExtractOptions
zipy_default_extract_options(const ZipyExtractOptions *options) {
  ZipyExtractOptions out;

  out.onConflict = ZIPY_CONFLICT_SAVE;
  out.saveTo = ZIPY_SAVE_TARGET;
  out.saveDir = NULL;

  if (!options)
    return out;

  out = *options;
  if (out.onConflict < ZIPY_CONFLICT_SAVE
      || out.onConflict > ZIPY_CONFLICT_FAIL)
    out.onConflict = ZIPY_CONFLICT_SAVE;
  if (out.saveTo < ZIPY_SAVE_TARGET || out.saveTo > ZIPY_SAVE_TRASH)
    out.saveTo = ZIPY_SAVE_TARGET;

  return out;
}

static int
zipy_prepare_conflict(const char *destdir,
                      const ZipyEntry *entry,
                      const char *destpath,
                      const ZipyExtractOptions *options,
                      char **saveDir) {
  int exists, isDir;
  char *savePath = NULL;
  char *cleanDestPath = NULL;
  char *cleanSavePath = NULL;
  char *originalAbs = NULL;
  char *savedAbs = NULL;
  int ret = ZIPY_ZIP_OK;

  cleanDestPath = zipy_trim_trailing_seps(destpath);
  if (!cleanDestPath)
    return ZIPY_ZIP_ERR;

  if (!zipy_path_info(cleanDestPath, &exists, &isDir)) {
    ret = ZIPY_ZIP_EFILE;
    goto done;
  }
  if (!exists) {
    ret = ZIPY_ZIP_OK;
    goto done;
  }
  if (entry->isDirectory && isDir) {
    ret = ZIPY_ZIP_OK;
    goto done;
  }

  if (options->onConflict == ZIPY_CONFLICT_OVERWRITE) {
    ret = ZIPY_ZIP_OK;
    goto done;
  }
  if (options->onConflict == ZIPY_CONFLICT_SKIP) {
    ret = ZIPY_ZIP_SKIPPED;
    goto done;
  }
  if (options->onConflict == ZIPY_CONFLICT_FAIL) {
    ret = ZIPY_ZIP_EEXIST;
    goto done;
  }

  if (!*saveDir) {
    if (options->saveDir) {
      *saveDir = zipy_strdup(options->saveDir);
      if (*saveDir && !zipy_mkdirs(*saveDir)) {
        free(*saveDir);
        *saveDir = NULL;
      }
    } else {
      *saveDir = zipy_create_save_dir(destdir, options->saveTo);
    }
  }
  if (!*saveDir) {
    ret = ZIPY_ZIP_EFILE;
    goto done;
  }

  savePath = zipy_extract_path(*saveDir, entry->name);
  if (!savePath) {
    ret = ZIPY_ZIP_ERR;
    goto done;
  }

  cleanSavePath = zipy_trim_trailing_seps(savePath);
  if (!cleanSavePath) {
    ret = ZIPY_ZIP_ERR;
    goto done;
  }
  if (!zipy_mkdir_parent(cleanSavePath)) {
    ret = ZIPY_ZIP_EFILE;
    goto done;
  }

  originalAbs = zipy_abs_path(cleanDestPath);
  if (rename(cleanDestPath, cleanSavePath) != 0) {
    int nowExists, nowIsDir;

    if (zipy_path_info(cleanDestPath, &nowExists, &nowIsDir)
        && (!nowExists || (entry->isDirectory && nowIsDir))) {
      ret = ZIPY_ZIP_OK;
      goto done;
    }

    ret = ZIPY_ZIP_EFILE;
    goto done;
  }

  savedAbs = zipy_abs_path(cleanSavePath);
  if (!originalAbs || !savedAbs
      || !zipy_append_saved_manifest(*saveDir, originalAbs, savedAbs)) {
    ret = ZIPY_ZIP_EFILE;
    goto done;
  }

  ret = ZIPY_ZIP_SAVED;

done:
  free(savedAbs);
  free(originalAbs);
  free(cleanSavePath);
  free(cleanDestPath);
  free(savePath);
  return ret;
}

static int
zipy_prepare_parent_conflicts(const char *destdir,
                              const ZipyEntry *entry,
                              const ZipyExtractOptions *options,
                              char **saveDir) {
  ZipyEntry parentEntry;
  char *rel = NULL;
  char *path = NULL;
  size_t len, i, j;
  int result = ZIPY_ZIP_OK;

  if (!entry || !entry->name)
    return ZIPY_ZIP_ERR;

  len = strlen(entry->name);
  rel = malloc(len + 1);
  if (!rel)
    return ZIPY_ZIP_ERR;

  parentEntry = *entry;
  parentEntry.name = rel;
  parentEntry.isDirectory = false;

  for (i = 0; i < len; i++) {
    int exists, isDir;

    if (!zipy_is_zip_sep(entry->name[i]) || i == 0)
      continue;

    for (j = 0; j < i; j++)
      rel[j] = zipy_is_zip_sep(entry->name[j]) ? '/' : entry->name[j];
    rel[i] = '\0';

    free(path);
    path = zipy_extract_path(destdir, rel);
    if (!path) {
      result = ZIPY_ZIP_ERR;
      break;
    }

    if (!zipy_path_info(path, &exists, &isDir)) {
      result = ZIPY_ZIP_EFILE;
      break;
    }

    if (!exists || isDir)
      continue;

    result = zipy_prepare_conflict(destdir,
                                   &parentEntry,
                                   path,
                                   options,
                                   saveDir);
    if (result != ZIPY_ZIP_OK && result != ZIPY_ZIP_SAVED)
      break;
  }

  free(path);
  free(rel);
  return result;
}

static int
zipy_prepare_entry_conflict(const char *destdir,
                            const ZipyEntry *entry,
                            const char *destpath,
                            const ZipyExtractOptions *options,
                            char **saveDir) {
  int parentRet, ret;

  parentRet = zipy_prepare_parent_conflicts(destdir, entry, options, saveDir);
  if (parentRet != ZIPY_ZIP_OK && parentRet != ZIPY_ZIP_SAVED)
    return parentRet;

  ret = zipy_prepare_conflict(destdir, entry, destpath, options, saveDir);
  if (ret == ZIPY_ZIP_OK && parentRet == ZIPY_ZIP_SAVED)
    return ZIPY_ZIP_SAVED;

  return ret;
}

ZIPY_EXPORT
ZipyArchive *
zipy_open(const char *path) {
  ZipyArchive *zipy = NULL;
  ZipyDirInfo dir;
  FILE *fp;
  size_t i, count;

  if (!path || !(fp = fopen(path, "rb")))
    return NULL;

  if (!zipy_find_eocd(fp, &dir))
    goto err;

  if (!zipy_u64_to_size(dir.entries, &count))
    goto err;

  zipy = calloc(1, sizeof(*zipy));
  if (!zipy)
    goto err;

  zipy->fp = fp;
  zipy->path = zipy_strdup(path);
  if (!zipy->path)
    goto err;

  zipy->fileCount = count;
  zipy->fileSize = dir.fileSize;

  if (count > 0) {
    zipy->files = calloc(count, sizeof(*zipy->files));
    if (!zipy->files)
      goto err;
  }

  if (zipy_seek_set(fp, dir.centralDirOffset) != 0)
    goto err;

  for (i = 0; i < count; i++) {
    uint8_t hdr[ZIP_CENTRAL_FIXED];
    uint8_t *name = NULL, *extra = NULL;
    ZipyFile *info = &zipy->files[i];
    uint16_t nameLen, extraLen, commentLen, diskStart;
    uint32_t comp32, uncomp32, offset32;

    if (!zipy_read(fp, hdr, sizeof(hdr)) || zipy_le32(hdr) != ZIP_SIGN_CENTRAL_DIR)
      goto err;

    info->flags = zipy_le16(hdr + 8);
    info->entry.method = zipy_le16(hdr + 10);
    info->entry.crc32 = zipy_le32(hdr + 16);
    comp32 = zipy_le32(hdr + 20);
    uncomp32 = zipy_le32(hdr + 24);
    nameLen = zipy_le16(hdr + 28);
    extraLen = zipy_le16(hdr + 30);
    commentLen = zipy_le16(hdr + 32);
    diskStart = zipy_le16(hdr + 34);
    info->externalAttr = zipy_le32(hdr + 38);
    offset32 = zipy_le32(hdr + 42);

    if (nameLen == 0
        || (diskStart != 0 && diskStart != ZIP64_MAGIC_UINT16))
      goto err;

    name = malloc(nameLen);
    if (!name || !zipy_read(fp, name, nameLen))
      goto err;

    info->entry.name = zipy_strndup(name, nameLen);
    free(name);
    name = NULL;
    if (!info->entry.name)
      goto err;

    info->entry.compressedSize = comp32;
    info->entry.uncompressedSize = uncomp32;
    info->localHeaderOffset = offset32;
    info->entry.isDirectory = zipy_is_dir_name(info->entry.name);

    if (extraLen > 0) {
      extra = malloc(extraLen);
      if (!extra || !zipy_read(fp, extra, extraLen))
        goto err;

      if (!zipy_parse_zip64_extra(info, extra, extraLen,
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
        || info->entry.compressedSize > zipy->fileSize
        || UINT64_MAX - info->localHeaderOffset < ZIP_LOCAL_FIXED)
      goto err;

    if (commentLen > 0 && zipy_skip(fp, commentLen) != 0)
      goto err;
  }

  return zipy;

err:
  if (zipy) {
    zipy_free_files(zipy);
    free(zipy->path);
    free(zipy);
  }
  fclose(fp);
  return NULL;
}

static int
zipy_extract_entry(ZipyArchive *zipy, ZipyFile *info, const char *destpath) {
  uint8_t local[ZIP_LOCAL_FIXED];
  uint16_t flags, method, nameLen, extraLen;
  uint64_t dataOffset;
  FILE *outfp;
  int ret = ZIPY_ZIP_ERR;

  if (!zipy || !zipy->fp || !info || !destpath)
    return ZIPY_ZIP_ERR;

  if (!zipy_is_safe_member_name(info->entry.name))
    return ZIPY_ZIP_EFILE;

  if (info->flags & (ZIP_FLAG_ENCRYPTED | ZIP_FLAG_STRONG_ENC))
    return ZIPY_ZIP_EUNSUP;

  if (info->entry.isDirectory)
    return zipy_mkdirs(destpath) ? ZIPY_ZIP_OK : ZIPY_ZIP_EFILE;

  if (info->entry.method != ZIPY_ZIP_STORE && info->entry.method != ZIPY_ZIP_DEFLATE)
    return ZIPY_ZIP_EUNSUP;

  if (zipy_seek_set(zipy->fp, info->localHeaderOffset) != 0
      || !zipy_read(zipy->fp, local, sizeof(local))
      || zipy_le32(local) != ZIP_SIGN_LOCAL_FILE)
    return ZIPY_ZIP_EFILE;

  flags = zipy_le16(local + 6);
  method = zipy_le16(local + 8);
  nameLen = zipy_le16(local + 26);
  extraLen = zipy_le16(local + 28);

  if (method != info->entry.method || (flags & (ZIP_FLAG_ENCRYPTED | ZIP_FLAG_STRONG_ENC)))
    return ZIPY_ZIP_EUNSUP;

  if (UINT64_MAX - info->localHeaderOffset
      < ZIP_LOCAL_FIXED + (uint64_t)nameLen + (uint64_t)extraLen)
    return ZIPY_ZIP_ESIZE;

  dataOffset = info->localHeaderOffset + ZIP_LOCAL_FIXED + nameLen + extraLen;
  if (dataOffset > zipy->fileSize || info->entry.compressedSize > zipy->fileSize - dataOffset)
    return ZIPY_ZIP_ESIZE;

  if (zipy_seek_set(zipy->fp, dataOffset) != 0)
    return ZIPY_ZIP_EFILE;

  if (!zipy_mkdir_parent(destpath)) {
    ret = ZIPY_ZIP_EFILE;
    return ret;
  }

  outfp = fopen(destpath, "wb");
  if (!outfp) {
    ret = ZIPY_ZIP_EFILE;
    return ret;
  }

  if (info->entry.method == ZIPY_ZIP_STORE) {
    if (info->entry.compressedSize != info->entry.uncompressedSize)
      ret = ZIPY_ZIP_ESIZE;
    else
      ret = zipy_copy_store(zipy->fp, outfp,
                           info->entry.uncompressedSize,
                           info->entry.crc32);
  } else {
    ret = zipy_inflate_raw(zipy->fp, outfp,
                          info->entry.compressedSize,
                          info->entry.uncompressedSize,
                          info->entry.crc32);
  }

  if (fclose(outfp) != 0 && ret == ZIPY_ZIP_OK)
    ret = ZIPY_ZIP_EFILE;

  return ret;
}

ZIPY_EXPORT
size_t
zipy_count(const ZipyArchive *zipy) {
  return zipy ? zipy->fileCount : 0;
}

ZIPY_EXPORT
const ZipyEntry *
zipy_entry(const ZipyArchive *zipy, size_t index) {
  if (!zipy || index >= zipy->fileCount)
    return NULL;

  return &zipy->files[index].entry;
}

ZIPY_EXPORT
int
zipy_extract(ZipyArchive *zipy, size_t index, const char *destpath) {
  if (!zipy || index >= zipy->fileCount)
    return ZIPY_ZIP_EFILE;

  return zipy_extract_entry(zipy, &zipy->files[index], destpath);
}

ZIPY_EXPORT
int
zipy_extract_to(ZipyArchive *zipy,
                size_t index,
                const char *destdir,
                const ZipyExtractOptions *options) {
  ZipyExtractOptions opts;
  char *destpath;
  char *saveDir = NULL;
  int ret, conflictRet;

  if (!zipy || index >= zipy->fileCount || !destdir)
    return ZIPY_ZIP_EFILE;

  opts = zipy_default_extract_options(options);
  destpath = zipy_extract_path(destdir, zipy->files[index].entry.name);
  if (!destpath)
    return ZIPY_ZIP_ERR;

  conflictRet = zipy_prepare_entry_conflict(destdir,
                                            &zipy->files[index].entry,
                                            destpath,
                                            &opts,
                                            &saveDir);
  if (conflictRet == ZIPY_ZIP_SKIPPED) {
    ret = ZIPY_ZIP_SKIPPED;
    goto done;
  }
  if (conflictRet < ZIPY_ZIP_OK) {
    ret = conflictRet;
    goto done;
  }

  ret = zipy_extract_entry(zipy, &zipy->files[index], destpath);
  if (ret == ZIPY_ZIP_OK && conflictRet == ZIPY_ZIP_SAVED)
    ret = ZIPY_ZIP_SAVED;

done:
  free(saveDir);
  free(destpath);
  return ret;
}

ZIPY_EXPORT
int
zipy_extract_named(ZipyArchive *zipy, const char *name, const char *destpath) {
  ZipyFile *info;

  if (!zipy || !name)
    return ZIPY_ZIP_ERR;

  info = zipy_find_file(zipy, name);
  if (!info)
    return ZIPY_ZIP_EFILE;

  return zipy_extract_entry(zipy, info, destpath);
}

typedef struct ZipyExtractAllContext {
  const char *zipPath;
  const char *destdir;
  const unsigned char *skip;
  ZipyMutex    lock;
  size_t      count;
  size_t      next;
  int         result;
} ZipyExtractAllContext;

static size_t
zipy_extract_default_jobs(size_t count) {
  size_t jobs;

  if (count <= 1)
    return 1;

  jobs = zipy_cpu_count();
  if (jobs < 1)
    jobs = 1;
  if (jobs > count)
    jobs = count;

  return jobs;
}

static int
zipy_extract_all_serial(ZipyArchive *zipy,
                        const char *destdir,
                        const unsigned char *skip) {
  size_t i;

  for (i = 0; i < zipy->fileCount; i++) {
    char *path;
    int ret;

    if (skip && skip[i])
      continue;

    path = zipy_extract_path(destdir, zipy->files[i].entry.name);
    if (!path)
      return ZIPY_ZIP_ERR;

    ret = zipy_extract_entry(zipy, &zipy->files[i], path);
    free(path);
    if (ret < ZIPY_ZIP_OK)
      return ret;
  }

  return ZIPY_ZIP_OK;
}

static void
zipy_extract_all_worker(void *arg) {
  ZipyExtractAllContext *ctx;
  ZipyArchive *zipy;
  size_t index;

  ctx = arg;
  zipy = zipy_open(ctx->zipPath);
  if (!zipy) {
    zipy_lock(&ctx->lock);
    if (ctx->result == ZIPY_ZIP_OK)
      ctx->result = ZIPY_ZIP_EFILE;
    zipy_unlock(&ctx->lock);
    return;
  }

  for (;;) {
    const ZipyEntry *entry;
    char *path;
    int ret;

    zipy_lock(&ctx->lock);
    if (ctx->result != ZIPY_ZIP_OK || ctx->next >= ctx->count) {
      zipy_unlock(&ctx->lock);
      break;
    }
    index = ctx->next++;
    zipy_unlock(&ctx->lock);

    if (ctx->skip && ctx->skip[index])
      continue;

    entry = zipy_entry(zipy, index);
    if (!entry) {
      ret = ZIPY_ZIP_EFILE;
      goto fail;
    }

    path = zipy_extract_path(ctx->destdir, entry->name);
    if (!path) {
      ret = ZIPY_ZIP_ERR;
      goto fail;
    }

    ret = zipy_extract(zipy, index, path);
    free(path);
    if (ret >= ZIPY_ZIP_OK)
      continue;

  fail:
    zipy_lock(&ctx->lock);
    if (ctx->result == ZIPY_ZIP_OK)
      ctx->result = ret;
    zipy_unlock(&ctx->lock);
    break;
  }

  zipy_close(zipy);
}

static int
zipy_extract_all_parallel(ZipyArchive *zipy,
                          const char *destdir,
                          size_t jobs,
                          const unsigned char *skip) {
  ZipyExtractAllContext ctx;
  ZipyThread *threads;
  size_t i, started;
  int result;

  if (!zipy->path || jobs <= 1)
    return zipy_extract_all_serial(zipy, destdir, skip);

  threads = calloc(jobs, sizeof(*threads));
  if (!threads)
    return zipy_extract_all_serial(zipy, destdir, skip);

  memset(&ctx, 0, sizeof(ctx));
  ctx.zipPath = zipy->path;
  ctx.destdir = destdir;
  ctx.skip = skip;
  ctx.count = zipy->fileCount;
  ctx.result = ZIPY_ZIP_OK;
  zipy_mutex_init(&ctx.lock);

  started = 0;
  for (i = 0; i < jobs; i++) {
    if (zipy_thread_start(&threads[i], zipy_extract_all_worker, &ctx) != 0)
      break;
    started++;
  }

  if (started == 0) {
    zipy_mutex_destroy(&ctx.lock);
    free(threads);
    return zipy_extract_all_serial(zipy, destdir, skip);
  }

  for (i = 0; i < started; i++)
    zipy_thread_join(&threads[i]);

  result = ctx.result;
  zipy_mutex_destroy(&ctx.lock);
  free(threads);
  return result;
}

static int
zipy_prepare_extract_all(ZipyArchive *zipy,
                         const char *destdir,
                         const ZipyExtractOptions *options,
                         unsigned char **skipOut) {
  char *saveDir = NULL;
  size_t i;
  int result = ZIPY_ZIP_OK;

  *skipOut = NULL;

  if (options->onConflict == ZIPY_CONFLICT_OVERWRITE)
    return ZIPY_ZIP_OK;

  for (i = 0; i < zipy->fileCount; i++) {
    char *path;
    int ret;

    path = zipy_extract_path(destdir, zipy->files[i].entry.name);
    if (!path) {
      result = ZIPY_ZIP_ERR;
      break;
    }

    ret = zipy_prepare_entry_conflict(destdir,
                                      &zipy->files[i].entry,
                                      path,
                                      options,
                                      &saveDir);
    free(path);

    if (ret == ZIPY_ZIP_SKIPPED) {
      if (!*skipOut) {
        *skipOut = calloc(zipy->fileCount, sizeof(**skipOut));
        if (!*skipOut) {
          result = ZIPY_ZIP_ERR;
          break;
        }
      }
      (*skipOut)[i] = 1;
      continue;
    }

    if (ret < ZIPY_ZIP_OK) {
      result = ret;
      break;
    }
  }

  free(saveDir);
  return result;
}

ZIPY_EXPORT
int
zipy_extract_all(ZipyArchive *zipy, const char *destdir) {
  return zipy_extract_all_options(zipy, destdir, NULL);
}

ZIPY_EXPORT
int
zipy_extract_all_options(ZipyArchive *zipy,
                         const char *destdir,
                         const ZipyExtractOptions *options) {
  ZipyExtractOptions opts;
  unsigned char *skip = NULL;
  int ret;

  if (!zipy || !destdir)
    return ZIPY_ZIP_ERR;

  opts = zipy_default_extract_options(options);
  ret = zipy_prepare_extract_all(zipy, destdir, &opts, &skip);
  if (ret >= ZIPY_ZIP_OK)
    ret = zipy_extract_all_parallel(zipy,
                                    destdir,
                                    zipy_extract_default_jobs(zipy->fileCount),
                                    skip);

  free(skip);
  return ret;
}

ZIPY_EXPORT
void
zipy_close(ZipyArchive *zipy) {
  if (!zipy)
    return;

  zipy_free_files(zipy);
  free(zipy->path);
  if (zipy->fp)
    fclose(zipy->fp);
  free(zipy);
}
