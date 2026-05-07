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

#include "crypto/dec.h"
#include "thread/thread.h"
#include "zip_private.h"

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
#  include <sys/utime.h>
#  include <windows.h>
#  define os_getcwd _getcwd
#else
#  include <dirent.h>
#  include <fcntl.h>
#  include <sys/mman.h>
#  include <sys/stat.h>
#  include <sys/types.h>
#  include <utime.h>
#  include <unistd.h>
#  define os_getcwd getcwd
#endif

#ifndef PATH_MAX
#  define PATH_MAX 4096
#endif

#define ZIP_SIGN_LOCAL_FILE    0x04034B50u
#define ZIP_SIGN_CENTRAL_DIR   0x02014B50u
#define ZIP_SIGN_END_CENTRAL   0x06054B50u
#define ZIP_SIGN_DATA_DESC     0x08074B50u
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
#define ZIP_INFLATE_STREAM_CHUNK (1024u * 1024u)
#define ZIP_MAPPED_WRITE_CHUNK (16u * 1024u * 1024u)
#define ZIP_FAST_WRITE_CHUNK  (128u * 1024u * 1024u)
#define ZIP_OUTPUT_MMAP_MIN   (8u * 1024u * 1024u)
#define ZIP_PATH_STACK        512u
#define ZIP_PARALLEL_MIN_ENTRIES 8u
#define ZIP_PARALLEL_MIN_BYTES (8u * 1024u * 1024u)
#define ZIP_PARALLEL_MIN_STORE_ENTRIES 16u
#define ZIP_PARALLEL_MIN_STORE_BYTES (64u * 1024u * 1024u)
#define ZIP_STACK_THREADS     64u
#define ZIP_WORK_BATCH        8u

#define ZIP_EXTRA_ZIP64       0x0001u
#define ZIP_EXTRA_EXT_TIME    0x5455u
#define ZIP_EXTRA_AES         0x9901u
#define ZIP_FLAG_ENCRYPTED    0x0001u
#define ZIP_FLAG_DATA_DESC    0x0008u
#define ZIP_FLAG_STRONG_ENC   0x0040u
#define ZIP_METHOD_AES        99u
#define EXTRACT_DELAY_DIR_METADATA (1u << 31)

#if defined(_WIN32)
#  define PATH_SEP '\\'
#else
#  define PATH_SEP '/'
#endif
#if defined(_WIN32) \
    || defined(__LITTLE_ENDIAN__) \
    || (defined(__BYTE_ORDER__) && __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__)
#  define HOST_LITTLE_ENDIAN 1
#endif

typedef struct entry_info_t {
  zipy_entry_t entry;
  uint64_t local_header_offset;
  uint64_t data_offset;
  uint16_t flags;
  uint16_t local_flags;
  uint16_t mod_time;
  uint16_t mod_date;
  uint16_t name_parent_len;
  uint32_t external_attr;
  uint32_t unix_mode;
  time_t   mtime;
  uint16_t zip_method;
  uint16_t aes_vendor_version;
  uint8_t  aes_strength;
  uint8_t  has_mtime;
  uint8_t  is_symlink;
  uint8_t  safe_name;
  uint8_t  has_data_offset;
  uint8_t  name_has_backslash;
} entry_info_t;

typedef struct path_buf_t {
  char  *data;
  size_t cap;
  char   stack[ZIP_PATH_STACK];
} path_buf_t;

typedef struct name_chunk_t {
  struct name_chunk_t *next;
  size_t used;
  size_t cap;
  char data[];
} name_chunk_t;

struct zipy_archive_t {
  FILE    *fp;
  char    *path;
  entry_info_t *files;
  name_chunk_t *name_chunks;
  size_t   file_count;
  size_t   extract_file_count;
  size_t   extract_work_file_count;
  size_t   directory_count;
  uint64_t extract_work_size;
  uint64_t extract_uncompressed_size;
  uint64_t file_size;
  const uint8_t *map;
  size_t   map_size;
  int      owns_files;
  int      owns_map;
  int      has_encrypted;
  int      has_symlink;
  int      has_unsupported_method;
  int      has_root_zipy;
  uint16_t unsupported_method;
  path_buf_t path_buf;
  path_buf_t parent_buf;
  path_buf_t parent_cache;
  path_buf_t part_buf;
  path_buf_t state_buf;
  size_t   path_prefix_len;
  size_t   path_prefix_dir_len;
  size_t   parent_cache_len;
  int      path_prefix_valid;
  int      parent_cache_valid;
  int      parent_cache_has_symlink;
  uint8_t *copy_buf;
  uint8_t *inflate_in;
  uint8_t *inflate_out;
  size_t   copy_cap;
  size_t   inflate_in_cap;
  size_t   inflate_out_cap;
  infl_stream_t *inflate_stream;
#if defined(_WIN32)
  HANDLE   map_handle;
#endif
};

typedef struct dir_info_t {
  uint64_t file_size;
  uint64_t eocd_offset;
  uint64_t central_dir_offset;
  uint64_t central_dir_size;
  uint64_t entries;
} dir_info_t;

typedef struct out_map_t {
  uint8_t *data;
  size_t   len;
#if defined(_WIN32)
  HANDLE   handle;
#endif
} out_map_t;

typedef struct out_file_t {
#if defined(_WIN32)
  FILE *fp;
#else
  int fd;
#endif
} out_file_t;

typedef struct progress_state_t {
  const zipy_extract_options_t *options;
  const zipy_entry_t *entry;
  mutex_handle_t *lock;
  uint64_t *done;
  uint64_t total;
  uint64_t entry_done;
  int *result;
} progress_state_t;

static int
progress_advance(progress_state_t *progress, uint64_t amount);

static int
stream_incomplete_result(zipy_archive_t * __restrict zipy, int ret) {
  if ((ret == ZIPY_ZIP_EFILE
       || ret == ZIPY_ZIP_ESIZE
       || ret == ZIPY_ZIP_EINFLATE)
      && zipy
      && zipy->fp
      && feof(zipy->fp))
    return ZIPY_ZIP_EINCOMPLETE;

  return ret;
}

static uint16_t
le16(const uint8_t * __restrict p) {
  return (uint16_t)((uint16_t)p[0] | ((uint16_t)p[1] << 8));
}

static uint32_t
le32(const uint8_t * __restrict p) {
  return ((uint32_t)p[0])
       | ((uint32_t)p[1] << 8)
       | ((uint32_t)p[2] << 16)
       | ((uint32_t)p[3] << 24);
}

static uint64_t
le64(const uint8_t * __restrict p) {
  return ((uint64_t)le32(p)) | ((uint64_t)le32(p + 4) << 32);
}

static uint64_t
load_le64(const uint8_t * __restrict p) {
#if HOST_LITTLE_ENDIAN
  uint64_t value;

  memcpy(&value, p, sizeof(value));
  return value;
#else
  return le64(p);
#endif
}

static void
path_buf_free(path_buf_t *buf) {
  if (!buf)
    return;

  if (buf->data && buf->data != buf->stack)
    free(buf->data);
  buf->data = NULL;
  buf->cap = 0;
}

static void
free_name_chunks(zipy_archive_t *zipy) {
  name_chunk_t *chunk;

  if (!zipy)
    return;

  chunk = zipy->name_chunks;
  while (chunk) {
    name_chunk_t *next = chunk->next;

    free(chunk);
    chunk = next;
  }

  zipy->name_chunks = NULL;
}

static char *
alloc_name(zipy_archive_t *zipy, size_t len) {
  name_chunk_t *chunk;
  size_t cap;

  if (!zipy || len == 0)
    return NULL;

  chunk = zipy->name_chunks;
  if (!chunk || len > chunk->cap - chunk->used) {
    cap = len > 4096u ? len : 4096u;
    chunk = malloc(sizeof(*chunk) + cap);
    if (!chunk)
      return NULL;

    chunk->next = zipy->name_chunks;
    chunk->used = 0;
    chunk->cap = cap;
    zipy->name_chunks = chunk;
  }

  chunk->used += len;
  return chunk->data + chunk->used - len;
}

static int
prealloc_name_slab(zipy_archive_t *zipy,
                        const uint8_t *central,
                        size_t central_size,
                        size_t count) {
  name_chunk_t *chunk;
  size_t i, pos = 0, total = 0;

  if (!zipy || !central || count == 0)
    return 1;

  for (i = 0; i < count; i++) {
    const uint8_t *hdr;
    uint16_t nameLen, extraLen, commentLen;
    size_t record_len;

    if (pos > central_size || central_size - pos < ZIP_CENTRAL_FIXED)
      return 0;

    hdr = central + pos;
    if (le32(hdr) != ZIP_SIGN_CENTRAL_DIR)
      return 0;

    nameLen = le16(hdr + 28);
    extraLen = le16(hdr + 30);
    commentLen = le16(hdr + 32);
    if (nameLen == 0)
      return 0;

    record_len = ZIP_CENTRAL_FIXED
               + (size_t)nameLen
               + (size_t)extraLen
               + (size_t)commentLen;
    if (record_len > central_size - pos
        || total > SIZE_MAX - (size_t)nameLen - 1u)
      return 0;

    total += (size_t)nameLen + 1u;
    pos += record_len;
  }

  if (pos != central_size || total == 0)
    return pos == central_size;

  chunk = malloc(sizeof(*chunk) + total);
  if (!chunk)
    return 0;

  chunk->next = zipy->name_chunks;
  chunk->used = 0;
  chunk->cap = total;
  zipy->name_chunks = chunk;
  return 1;
}

static int
path_buf_reserve(path_buf_t *buf, size_t len) {
  char *data;
  size_t cap;

  if (!buf || len == SIZE_MAX)
    return 0;
  if (len <= buf->cap)
    return 1;
  if (!buf->data && len <= sizeof(buf->stack)) {
    buf->data = buf->stack;
    buf->cap = sizeof(buf->stack);
    return 1;
  }

  cap = buf->cap ? buf->cap : sizeof(buf->stack);
  while (cap < len) {
    if (cap > SIZE_MAX / 2u) {
      cap = len;
      break;
    }
    cap *= 2u;
  }

  if (buf->data == buf->stack) {
    data = malloc(cap);
    if (data)
      memcpy(data, buf->stack, sizeof(buf->stack));
  } else {
    data = realloc(buf->data, cap);
  }
  if (!data)
    return 0;

  buf->data = data;
  buf->cap = cap;
  return 1;
}

static int
reserve_bytes(uint8_t **buf, size_t *cap, size_t len) {
  uint8_t *data;
  size_t next;

  if (!buf || !cap)
    return 0;
  if (len == 0)
    len = 1;
  if (len <= *cap)
    return 1;

  next = *cap ? *cap : ZIP_IO_CHUNK;
  while (next < len) {
    if (next > SIZE_MAX / 2u) {
      next = len;
      break;
    }
    next *= 2u;
  }

  data = realloc(*buf, next);
  if (!data)
    return 0;

  *buf = data;
  *cap = next;
  return 1;
}

static int
read_exact(FILE * __restrict fp, void * __restrict buf, size_t len) {
  return len == 0 || fread(buf, 1, len, fp) == len;
}

static int
file_error_result(void) {
  return errno == ENOSPC ? ZIPY_ZIP_ENOSPC : ZIPY_ZIP_EFILE;
}

static int
write_file(out_file_t * __restrict out,
                const void * __restrict buf,
                size_t len) {
#if defined(_WIN32)
  if (len == 0)
    return ZIPY_ZIP_OK;
  if (!out || !out->fp)
    return ZIPY_ZIP_EFILE;
  errno = 0;
  return fwrite(buf, 1, len, out->fp) == len
       ? ZIPY_ZIP_OK
       : file_error_result();
#else
  const uint8_t *p = buf;

  if (len == 0)
    return ZIPY_ZIP_OK;
  if (!out || out->fd < 0)
    return ZIPY_ZIP_EFILE;

  while (len > 0) {
    ssize_t n = write(out->fd, p, len);

    if (n < 0) {
      if (errno == EINTR)
        continue;
      return file_error_result();
    }
    if (n == 0)
      return ZIPY_ZIP_EFILE;

    p += (size_t)n;
    len -= (size_t)n;
  }

  return ZIPY_ZIP_OK;
#endif
}

static int
flush_output(out_file_t *out) {
#if defined(_WIN32)
  return out && out->fp && fflush(out->fp) == 0;
#else
  (void)out;
  return 1;
#endif
}

static int
seek_set(FILE * __restrict fp, uint64_t off) {
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
tell_pos(FILE * __restrict fp, uint64_t * __restrict pos) {
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
set_output_size(out_file_t *out, uint64_t size) {
#if defined(_WIN32)
  if (!out || !out->fp)
    return -1;
  if (size > (uint64_t)INT64_MAX)
    return -1;
  return _chsize_s(_fileno(out->fp), (__int64)size);
#else
  if (!out || out->fd < 0)
    return -1;
  if (size > (uint64_t)INT64_MAX)
    return -1;
  return ftruncate(out->fd, (off_t)size);
#endif
}

static int
skip_bytes(FILE *fp, uint64_t len) {
  uint64_t pos;

  if (tell_pos(fp, &pos) != 0 || UINT64_MAX - pos < len)
    return -1;

  return seek_set(fp, pos + len);
}

static int
skip_data_descriptor(zipy_archive_t * __restrict zipy,
                     const entry_info_t * __restrict info,
                     int zip64_descriptor,
                     int check_crc,
                     uint32_t * __restrict crc_out) {
  uint8_t desc[24];
  const uint8_t *p;
  uint64_t compressed_size;
  uint64_t uncompressed_size;
  uint32_t first;
  uint32_t crc;
  size_t rest;
  int ret;

  if (!zipy || !zipy->fp || !info)
    return ZIPY_ZIP_ERR;

  if (!read_exact(zipy->fp, desc, 4u))
    return ZIPY_ZIP_EFILE;

  first = le32(desc);
  rest = first == ZIP_SIGN_DATA_DESC
       ? (zip64_descriptor ? 20u : 12u)
       : (zip64_descriptor ? 16u : 8u);
  if (!read_exact(zipy->fp, desc + 4u, rest))
    return ZIPY_ZIP_EFILE;

  p = first == ZIP_SIGN_DATA_DESC ? desc + 4u : desc;
  crc = le32(p);
  p += 4u;
  if (zip64_descriptor) {
    compressed_size = le64(p);
    uncompressed_size = le64(p + 8u);
  } else {
    compressed_size = le32(p);
    uncompressed_size = le32(p + 4u);
  }

  if (check_crc && crc != info->entry.crc32)
    ret = ZIPY_ZIP_ECRC;
  else if (compressed_size != info->entry.compressed_size
           || uncompressed_size != info->entry.uncompressed_size)
    ret = ZIPY_ZIP_ESIZE;
  else {
    if (crc_out)
      *crc_out = crc;
    return ZIPY_ZIP_OK;
  }

  if (first == ZIP_SIGN_DATA_DESC) {
    uint64_t pos;

    p = desc;
    crc = le32(p);
    p += 4u;
    if (zip64_descriptor) {
      compressed_size = le64(p);
      uncompressed_size = le64(p + 8u);
    } else {
      compressed_size = le32(p);
      uncompressed_size = le32(p + 4u);
    }

    if ((!check_crc || crc == info->entry.crc32)
        && compressed_size == info->entry.compressed_size
        && uncompressed_size == info->entry.uncompressed_size) {
      if (tell_pos(zipy->fp, &pos) != 0
          || pos < 4u
          || seek_set(zipy->fp, pos - 4u) != 0)
        return ZIPY_ZIP_EFILE;
      if (crc_out)
        *crc_out = crc;
      return ZIPY_ZIP_OK;
    }
  }

  return ret;
}

static int
is_record_signature(uint32_t sig) {
  return sig == ZIP_SIGN_LOCAL_FILE
      || sig == ZIP_SIGN_CENTRAL_DIR
      || sig == ZIP_SIGN_END_CENTRAL
      || sig == ZIP_SIGN_ZIP64_END
      || sig == ZIP_SIGN_ZIP64_LOCATOR;
}

static int
match_signed_store_descriptor(zipy_archive_t * __restrict zipy,
                              entry_info_t * __restrict info,
                              uint64_t descriptor_offset,
                              uint64_t data_len,
                              uint32_t data_crc,
                              int zip64_descriptor) {
  uint8_t desc[24];
  uint8_t next[4];
  uint64_t compressed_size;
  uint64_t uncompressed_size;
  uint64_t descriptor_len;
  const uint8_t *p;
  uint32_t crc;

  if (!zipy || !zipy->fp || !info)
    return ZIPY_ZIP_ERR;

  descriptor_len = zip64_descriptor ? 24u : 16u;
  if (descriptor_offset > zipy->file_size
      || descriptor_len > zipy->file_size - descriptor_offset
      || zipy->file_size - descriptor_offset - descriptor_len < 4u)
    return ZIPY_ZIP_SKIPPED;

  if (seek_set(zipy->fp, descriptor_offset) != 0
      || !read_exact(zipy->fp, desc, (size_t)descriptor_len)
      || !read_exact(zipy->fp, next, sizeof(next)))
    return ZIPY_ZIP_EFILE;

  if (le32(desc) != ZIP_SIGN_DATA_DESC)
    return ZIPY_ZIP_SKIPPED;

  p = desc + 4u;
  crc = le32(p);
  p += 4u;
  if (zip64_descriptor) {
    compressed_size = le64(p);
    uncompressed_size = le64(p + 8u);
  } else {
    compressed_size = le32(p);
    uncompressed_size = le32(p + 4u);
  }

  if (crc != data_crc
      || compressed_size != data_len
      || uncompressed_size != data_len
      || !is_record_signature(le32(next)))
    return ZIPY_ZIP_SKIPPED;

  info->entry.crc32 = crc;
  info->entry.compressed_size = compressed_size;
  info->entry.uncompressed_size = uncompressed_size;

  return seek_set(zipy->fp, descriptor_offset + descriptor_len) == 0
       ? ZIPY_ZIP_OK
       : ZIPY_ZIP_EFILE;
}

static int
match_unsigned_store_descriptor(zipy_archive_t * __restrict zipy,
                                entry_info_t * __restrict info,
                                uint64_t descriptor_offset,
                                uint64_t data_len,
                                uint32_t data_crc,
                                int zip64_descriptor) {
  uint8_t desc[24];
  uint8_t next[4];
  uint64_t compressed_size;
  uint64_t uncompressed_size;
  uint64_t descriptor_len;
  const uint8_t *p;
  uint32_t crc;

  if (!zipy || !zipy->fp || !info)
    return ZIPY_ZIP_ERR;

  descriptor_len = zip64_descriptor ? 20u : 12u;
  if (descriptor_offset > zipy->file_size
      || descriptor_len > zipy->file_size - descriptor_offset
      || zipy->file_size - descriptor_offset - descriptor_len < 4u)
    return ZIPY_ZIP_SKIPPED;

  if (seek_set(zipy->fp, descriptor_offset) != 0
      || !read_exact(zipy->fp, desc, (size_t)descriptor_len)
      || !read_exact(zipy->fp, next, sizeof(next)))
    return ZIPY_ZIP_EFILE;

  p = desc;
  crc = le32(p);
  p += 4u;
  if (zip64_descriptor) {
    compressed_size = le64(p);
    uncompressed_size = le64(p + 8u);
  } else {
    compressed_size = le32(p);
    uncompressed_size = le32(p + 4u);
  }

  if (crc != data_crc
      || compressed_size != data_len
      || uncompressed_size != data_len
      || !is_record_signature(le32(next)))
    return ZIPY_ZIP_SKIPPED;

  info->entry.crc32 = crc;
  info->entry.compressed_size = compressed_size;
  info->entry.uncompressed_size = uncompressed_size;

  return seek_set(zipy->fp, descriptor_offset + descriptor_len) == 0
       ? ZIPY_ZIP_OK
       : ZIPY_ZIP_EFILE;
}

static int
get_file_size(FILE *fp, uint64_t *size) {
#if defined(_WIN32)
  if (_fseeki64(fp, 0, SEEK_END) != 0)
    return -1;
#else
  if (fseeko(fp, 0, SEEK_END) != 0)
    return -1;
#endif

  return tell_pos(fp, size);
}

static void
map_archive(zipy_archive_t *zipy) {
  if (!zipy || !zipy->fp || zipy->file_size == 0
      || zipy->file_size > (uint64_t)SIZE_MAX)
    return;

#if defined(_WIN32)
  {
    HANDLE file;
    HANDLE mapping;
    void *view;

    file = (HANDLE)_get_osfhandle(_fileno(zipy->fp));
    if (file == INVALID_HANDLE_VALUE)
      return;

    mapping = CreateFileMapping(file, NULL, PAGE_READONLY, 0, 0, NULL);
    if (!mapping)
      return;

    view = MapViewOfFile(mapping, FILE_MAP_READ, 0, 0, 0);
    if (!view) {
      CloseHandle(mapping);
      return;
    }

    zipy->map = view;
    zipy->map_size = (size_t)zipy->file_size;
    zipy->map_handle = mapping;
    zipy->owns_map = 1;
  }
#else
  {
    void *view;

    view = mmap(NULL,
                (size_t)zipy->file_size,
                PROT_READ,
                MAP_PRIVATE,
                fileno(zipy->fp),
                0);
    if (view == MAP_FAILED)
      return;

    zipy->map = view;
    zipy->map_size = (size_t)zipy->file_size;
    zipy->owns_map = 1;
  }
#endif
}

static void
unmap_archive(zipy_archive_t *zipy) {
  if (!zipy || !zipy->map)
    return;

  if (!zipy->owns_map) {
    zipy->map = NULL;
    zipy->map_size = 0;
    return;
  }

#if defined(_WIN32)
  UnmapViewOfFile(zipy->map);
  if (zipy->map_handle)
    CloseHandle(zipy->map_handle);
  zipy->map_handle = NULL;
#else
  munmap((void *)zipy->map, zipy->map_size);
#endif

  zipy->map = NULL;
  zipy->map_size = 0;
  zipy->owns_map = 0;
}

static const uint8_t *
mapped_range(const zipy_archive_t *zipy, uint64_t offset, uint64_t len) {
  if (!zipy || !zipy->map || offset > (uint64_t)zipy->map_size
      || len > (uint64_t)zipy->map_size - offset)
    return NULL;

  return zipy->map + (size_t)offset;
}

static int
map_output(out_file_t *out, uint64_t len, out_map_t *map) {
  if (!out || !map || len == 0 || len > (uint64_t)SIZE_MAX)
    return 0;
  memset(map, 0, sizeof(*map));
  map->len = (size_t)len;

  if (set_output_size(out, len) != 0)
    return 0;

#if defined(_WIN32)
  {
    HANDLE file;

    file = (HANDLE)_get_osfhandle(_fileno(out->fp));
    if (file == INVALID_HANDLE_VALUE)
      return 0;

    map->handle = CreateFileMapping(file, NULL, PAGE_READWRITE, 0, 0, NULL);
    if (!map->handle)
      return 0;

    map->data = MapViewOfFile(map->handle, FILE_MAP_WRITE, 0, 0, map->len);
    if (!map->data) {
      CloseHandle(map->handle);
      map->handle = NULL;
      map->len = 0;
      return 0;
    }
  }
#else
  {
    void *view;

    view = mmap(NULL,
                map->len,
                PROT_READ | PROT_WRITE,
                MAP_SHARED,
                out->fd,
                0);
    if (view == MAP_FAILED) {
      map->data = NULL;
      map->len = 0;
      return 0;
    }
    map->data = view;
  }
#endif

  return 1;
}

static void
unmap_output(out_map_t *map) {
  if (!map || !map->data)
    return;

#if defined(_WIN32)
  UnmapViewOfFile(map->data);
  if (map->handle)
    CloseHandle(map->handle);
  map->handle = NULL;
#else
  munmap(map->data, map->len);
#endif

  map->data = NULL;
  map->len = 0;
}

static int
u64_to_size(uint64_t value, size_t *out) {
  if (value > (uint64_t)SIZE_MAX)
    return 0;

  *out = (size_t)value;
  return 1;
}

static char *
dup_text(const char *src) {
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

static time_t
dos_time(uint16_t date, uint16_t timev) {
  struct tm tmv;

  memset(&tmv, 0, sizeof(tmv));
  tmv.tm_sec = (timev & 0x1fu) * 2;
  tmv.tm_min = (timev >> 5) & 0x3f;
  tmv.tm_hour = (timev >> 11) & 0x1f;
  tmv.tm_mday = date & 0x1f;
  tmv.tm_mon = ((date >> 5) & 0x0f) - 1;
  tmv.tm_year = ((date >> 9) & 0x7f) + 80;
  tmv.tm_isdst = -1;

  if (tmv.tm_mday == 0 || tmv.tm_mon < 0)
    return (time_t)0;

  return mktime(&tmv);
}

static int
read_zip64_eocd(FILE *fp, dir_info_t *dir) {
  uint8_t locator[ZIP64_LOCATOR_FIXED];
  uint8_t eocd[ZIP64_EOCD_FIXED];
  uint64_t zip64Off, entriesDisk;

  if (dir->eocd_offset < ZIP64_LOCATOR_FIXED)
    return 0;

  if (seek_set(fp, dir->eocd_offset - ZIP64_LOCATOR_FIXED) != 0
      || !read_exact(fp, locator, sizeof(locator)))
    return 0;

  if (le32(locator) != ZIP_SIGN_ZIP64_LOCATOR)
    return 0;

  if (le32(locator + 4) != 0 || le32(locator + 16) != 1)
    return 0;

  zip64Off = le64(locator + 8);
  if (dir->file_size < ZIP64_EOCD_FIXED
      || zip64Off > dir->file_size - ZIP64_EOCD_FIXED)
    return 0;

  if (seek_set(fp, zip64Off) != 0 || !read_exact(fp, eocd, sizeof(eocd)))
    return 0;

  if (le32(eocd) != ZIP_SIGN_ZIP64_END || le64(eocd + 4) < 44)
    return 0;

  if (le32(eocd + 16) != 0 || le32(eocd + 20) != 0)
    return 0;

  entriesDisk = le64(eocd + 24);
  dir->entries = le64(eocd + 32);
  if (entriesDisk != dir->entries)
    return 0;

  dir->central_dir_size = le64(eocd + 40);
  dir->central_dir_offset = le64(eocd + 48);
  return 1;
}

static int
read_zip64_eocd_mapped(const uint8_t *map,
                            uint64_t file_size,
                            dir_info_t *dir) {
  const uint8_t *locator, *eocd;
  uint64_t zip64Off, entriesDisk;

  if (!map || dir->eocd_offset < ZIP64_LOCATOR_FIXED)
    return 0;

  locator = map + (size_t)(dir->eocd_offset - ZIP64_LOCATOR_FIXED);
  if (le32(locator) != ZIP_SIGN_ZIP64_LOCATOR)
    return 0;

  if (le32(locator + 4) != 0 || le32(locator + 16) != 1)
    return 0;

  zip64Off = le64(locator + 8);
  if (file_size < ZIP64_EOCD_FIXED
      || zip64Off > file_size - ZIP64_EOCD_FIXED)
    return 0;

  eocd = map + (size_t)zip64Off;
  if (le32(eocd) != ZIP_SIGN_ZIP64_END || le64(eocd + 4) < 44)
    return 0;

  if (le32(eocd + 16) != 0 || le32(eocd + 20) != 0)
    return 0;

  entriesDisk = le64(eocd + 24);
  dir->entries = le64(eocd + 32);
  if (entriesDisk != dir->entries)
    return 0;

  dir->central_dir_size = le64(eocd + 40);
  dir->central_dir_offset = le64(eocd + 48);
  return 1;
}

static int
find_eocd_mapped(const uint8_t *map,
                      uint64_t file_size,
                      dir_info_t *dir) {
  uint64_t tailOff;
  size_t tailSize, i;

  memset(dir, 0, sizeof(*dir));

  if (!map || file_size < ZIP_EOCD_FIXED || file_size > (uint64_t)SIZE_MAX)
    return 0;

  tailSize = file_size < ZIP_MAX_EOCD_SEARCH
           ? (size_t)file_size
           : (size_t)ZIP_MAX_EOCD_SEARCH;
  tailOff = file_size - tailSize;

  i = tailSize - ZIP_EOCD_FIXED;
  for (;;) {
    const uint8_t *p = map + (size_t)tailOff + i;

    if (le32(p) == ZIP_SIGN_END_CENTRAL) {
      uint16_t disk = le16(p + 4);
      uint16_t cdDisk = le16(p + 6);
      uint16_t entriesDisk = le16(p + 8);
      uint16_t entries = le16(p + 10);
      uint16_t commentLen = le16(p + 20);
      int needsZip64;

      if (i + ZIP_EOCD_FIXED + commentLen != tailSize)
        goto next;

      dir->file_size = file_size;
      dir->eocd_offset = tailOff + i;
      dir->entries = entries;
      dir->central_dir_size = le32(p + 12);
      dir->central_dir_offset = le32(p + 16);

      needsZip64 = disk == ZIP64_MAGIC_UINT16
                || cdDisk == ZIP64_MAGIC_UINT16
                || entriesDisk == ZIP64_MAGIC_UINT16
                || entries == ZIP64_MAGIC_UINT16
                || dir->central_dir_size == ZIP64_MAGIC_UINT32
                || dir->central_dir_offset == ZIP64_MAGIC_UINT32;

      if (needsZip64) {
        if (!read_zip64_eocd_mapped(map, file_size, dir))
          break;
      } else if (disk != 0 || cdDisk != 0 || entriesDisk != entries) {
        break;
      }

      if (UINT64_MAX - dir->central_dir_offset < dir->central_dir_size)
        return 0;
      return dir->central_dir_offset + dir->central_dir_size <= dir->eocd_offset;
    }

next:
    if (i == 0)
      break;
    i--;
  }

  return 0;
}

static int
find_eocd(FILE *fp, dir_info_t *dir) {
  uint8_t *tail;
  uint64_t tailOff, file_size;
  size_t tailSize, i;

  memset(dir, 0, sizeof(*dir));

  if (get_file_size(fp, &file_size) != 0 || file_size < ZIP_EOCD_FIXED)
    return 0;

  tailSize = file_size < ZIP_MAX_EOCD_SEARCH
           ? (size_t)file_size
           : (size_t)ZIP_MAX_EOCD_SEARCH;
  tailOff = file_size - tailSize;

  tail = malloc(tailSize);
  if (!tail)
    return 0;

  if (seek_set(fp, tailOff) != 0 || !read_exact(fp, tail, tailSize)) {
    free(tail);
    return 0;
  }

  i = tailSize - ZIP_EOCD_FIXED;
  for (;;) {
    const uint8_t *p = tail + i;

    if (le32(p) == ZIP_SIGN_END_CENTRAL) {
      uint16_t disk = le16(p + 4);
      uint16_t cdDisk = le16(p + 6);
      uint16_t entriesDisk = le16(p + 8);
      uint16_t entries = le16(p + 10);
      uint16_t commentLen = le16(p + 20);
      int needsZip64;

      if (i + ZIP_EOCD_FIXED + commentLen != tailSize)
        goto next;

      dir->file_size = file_size;
      dir->eocd_offset = tailOff + i;
      dir->entries = entries;
      dir->central_dir_size = le32(p + 12);
      dir->central_dir_offset = le32(p + 16);

      needsZip64 = disk == ZIP64_MAGIC_UINT16
                || cdDisk == ZIP64_MAGIC_UINT16
                || entriesDisk == ZIP64_MAGIC_UINT16
                || entries == ZIP64_MAGIC_UINT16
                || dir->central_dir_size == ZIP64_MAGIC_UINT32
                || dir->central_dir_offset == ZIP64_MAGIC_UINT32;

      if (needsZip64) {
        if (!read_zip64_eocd(fp, dir))
          break;
      } else if (disk != 0 || cdDisk != 0 || entriesDisk != entries) {
        break;
      }

      free(tail);
      if (UINT64_MAX - dir->central_dir_offset < dir->central_dir_size)
        return 0;
      return dir->central_dir_offset + dir->central_dir_size <= dir->eocd_offset;
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
parse_zip64_extra(entry_info_t *info,
                      const uint8_t *extra,
                      size_t len,
                      uint32_t comp32,
                      uint32_t uncomp32,
                      uint32_t offset32,
                      uint16_t disk32) {
  size_t pos = 0;
  uint32_t disk = disk32;

  while (len - pos >= 4) {
    uint16_t id = le16(extra + pos);
    uint16_t size = le16(extra + pos + 2);
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
        info->entry.uncompressed_size = le64(p);
        p += 8;
        rem -= 8;
      }

      if (comp32 == ZIP64_MAGIC_UINT32) {
        if (rem < 8)
          return 0;
        info->entry.compressed_size = le64(p);
        p += 8;
        rem -= 8;
      }

      if (offset32 == ZIP64_MAGIC_UINT32) {
        if (rem < 8)
          return 0;
        info->local_header_offset = le64(p);
        p += 8;
        rem -= 8;
      }

      if (disk32 == ZIP64_MAGIC_UINT16) {
        if (rem < 4)
          return 0;
        disk = le32(p);
      }
    }

    pos += size;
  }

  return pos == len
      && disk == 0
      && (comp32 != ZIP64_MAGIC_UINT32
          || info->entry.compressed_size != ZIP64_MAGIC_UINT32)
      && (uncomp32 != ZIP64_MAGIC_UINT32
          || info->entry.uncompressed_size != ZIP64_MAGIC_UINT32)
      && (offset32 != ZIP64_MAGIC_UINT32
          || info->local_header_offset != ZIP64_MAGIC_UINT32);
}

static int
parse_aes_extra(entry_info_t *info, const uint8_t *extra, size_t len) {
  size_t pos = 0;

  while (len - pos >= 4) {
    uint16_t id = le16(extra + pos);
    uint16_t size = le16(extra + pos + 2);
    const uint8_t *p = extra + pos + 4;

    pos += 4;
    if (size > len - pos)
      return 0;

    if (id == ZIP_EXTRA_AES) {
      uint16_t actual_method;

      if (size < 7
          || p[2] != 'A'
          || p[3] != 'E'
          || p[4] < 1
          || p[4] > 3)
        return 0;

      info->aes_vendor_version = le16(p);
      if (info->aes_vendor_version != 1 && info->aes_vendor_version != 2)
        return 0;

      actual_method = le16(p + 5);
      info->aes_strength = p[4];
      info->entry.method = actual_method;
    }

    pos += size;
  }

  return pos == len;
}

static int
parse_ext_time_extra(entry_info_t *info, const uint8_t *extra, size_t len) {
  size_t pos = 0;

  while (len - pos >= 4) {
    uint16_t id = le16(extra + pos);
    uint16_t size = le16(extra + pos + 2);
    const uint8_t *p = extra + pos + 4;

    pos += 4;
    if (size > len - pos)
      return 0;

    if (id == ZIP_EXTRA_EXT_TIME && size >= 5 && (p[0] & 1u)) {
      info->mtime = (time_t)le32(p + 1);
      info->has_mtime = 1;
    }

    pos += size;
  }

  return pos == len;
}

static int
verify_local_aes_extra(zipy_archive_t * __restrict zipy,
                            const entry_info_t * __restrict info,
                            uint64_t extra_offset,
                            uint16_t extra_len) {
  uint8_t stack_extra[512];
  uint8_t *heap_extra = NULL;
  const uint8_t *extra;
  entry_info_t local;
  int ok;

  if (!zipy || !zipy->fp || !info || extra_len == 0)
    return 0;

  extra = mapped_range(zipy, extra_offset, extra_len);
  if (!extra) {
    if (extra_len <= sizeof(stack_extra)) {
      extra = stack_extra;
    } else {
      heap_extra = malloc(extra_len);
      if (!heap_extra)
        return 0;
      extra = heap_extra;
    }

    if (seek_set(zipy->fp, extra_offset) != 0
        || !read_exact(zipy->fp, (void *)extra, extra_len)) {
      free(heap_extra);
      return 0;
    }
  }

  memset(&local, 0, sizeof(local));
  local.entry.method = ZIP_METHOD_AES;
  local.zip_method = ZIP_METHOD_AES;

  ok = parse_aes_extra(&local, extra, extra_len)
    && local.aes_vendor_version == info->aes_vendor_version
    && local.aes_strength == info->aes_strength
    && local.entry.method == info->entry.method;

  free(heap_extra);
  return ok;
}

static void
cache_local_header(zipy_archive_t * __restrict zipy,
                        entry_info_t * __restrict info) {
  const uint8_t *localp;
  uint16_t flags, method, nameLen, extraLen;
  uint64_t dataOffset;

  if (!zipy || !info)
    return;

  localp = mapped_range(zipy, info->local_header_offset, ZIP_LOCAL_FIXED);
  if (!localp || le32(localp) != ZIP_SIGN_LOCAL_FILE)
    return;

  flags = le16(localp + 6);
  method = le16(localp + 8);
  nameLen = le16(localp + 26);
  extraLen = le16(localp + 28);

  if (method != info->zip_method || (flags & ZIP_FLAG_STRONG_ENC))
    return;
  if (UINT64_MAX - info->local_header_offset
      < ZIP_LOCAL_FIXED + (uint64_t)nameLen + (uint64_t)extraLen)
    return;

  dataOffset = info->local_header_offset + ZIP_LOCAL_FIXED + nameLen + extraLen;
  if (dataOffset > zipy->file_size
      || info->entry.compressed_size > zipy->file_size - dataOffset)
    return;

  info->data_offset = dataOffset;
  info->local_flags = flags;
  info->has_data_offset = 1;
}

static bool
is_zip_sep(char c) {
  return c == '/' || c == '\\';
}

static void
record_extract_metrics(zipy_archive_t * __restrict zipy,
                            const entry_info_t * __restrict info) {
  if (!zipy || !info)
    return;
  if (info->entry.is_directory) {
    zipy->directory_count++;
    return;
  }

  zipy->extract_file_count++;
  if (UINT64_MAX - zipy->extract_uncompressed_size < info->entry.uncompressed_size)
    zipy->extract_uncompressed_size = UINT64_MAX;
  else
    zipy->extract_uncompressed_size += info->entry.uncompressed_size;
  if (info->entry.method == ZIPY_ZIP_STORE && !(info->flags & ZIP_FLAG_ENCRYPTED))
    return;

  zipy->extract_work_file_count++;
  if (zipy->extract_work_size < ZIP_PARALLEL_MIN_BYTES) {
    if (info->entry.uncompressed_size > ZIP_PARALLEL_MIN_BYTES - zipy->extract_work_size)
      zipy->extract_work_size = ZIP_PARALLEL_MIN_BYTES;
    else
      zipy->extract_work_size += info->entry.uncompressed_size;
  }
}

static bool
is_fs_sep(char c) {
#if defined(_WIN32)
  return c == '/' || c == '\\';
#else
  return c == '/';
#endif
}

static bool
is_dir_name_len(const char *path, size_t len) {
  return path && len > 0 && is_zip_sep(path[len - 1]);
}

static int
scan_member_name(const char * __restrict path,
                      size_t len,
                      uint8_t * __restrict safe,
                      uint8_t * __restrict has_backslash,
                      uint16_t * __restrict parent_len) {
  size_t i, seg = 0, parent = 0;
  int is_safe;

  if (!path || !safe || !has_backslash || !parent_len)
    return 0;

  is_safe = len > 0 && !is_zip_sep(path[0]);
  if (len > 1 && isalpha((unsigned char)path[0]) && path[1] == ':')
    is_safe = 0;
  *has_backslash = 0;

  for (i = 0; i < len; i++) {
    unsigned char c = (unsigned char)path[i];

    if (c == '\0')
      return 0;
    if (c < 32 || c == '<' || c == '>' || c == '|' || c == '"')
      is_safe = 0;
    if (c == '\\')
      *has_backslash = 1;
    if (is_zip_sep((char)c)) {
      size_t seg_len = i - seg;

      parent = i;
      if (seg_len == 2 && path[seg] == '.' && path[seg + 1] == '.')
        is_safe = 0;
      seg = i + 1u;
    }
  }

  if (len - seg == 2 && path[seg] == '.' && path[seg + 1] == '.')
    is_safe = 0;

  *safe = (uint8_t)is_safe;
  *parent_len = parent > UINT16_MAX ? UINT16_MAX : (uint16_t)parent;
  return 1;
}

static size_t
segment_len(const char *name, size_t len, size_t pos) {
  size_t i;

  if (!name || pos >= len)
    return 0;

  for (i = pos; i < len; i++) {
    if (is_zip_sep(name[i]))
      break;
  }

  return i - pos;
}

static int
segment_eq(const char *name, size_t len, const char *lit) {
  size_t i;

  if (!name || !lit)
    return 0;

  for (i = 0; i < len; i++) {
    if (!lit[i]
        || tolower((unsigned char)name[i]) != tolower((unsigned char)lit[i]))
      return 0;
  }

  return lit[i] == '\0';
}

static int
prefix_eq(const char *name, size_t len, const char *prefix) {
  size_t i;

  if (!name || !prefix)
    return 0;

  for (i = 0; prefix[i]; i++) {
    if (i >= len
        || tolower((unsigned char)name[i]) != tolower((unsigned char)prefix[i]))
      return 0;
  }

  return 1;
}

static int
has_root_zipy_segment(const char *name, size_t len) {
  return segment_eq(name, segment_len(name, len, 0), ".zipy");
}

static int
is_internal_state_name(const char *name, size_t len) {
  size_t firstLen, pos, secondLen, restLen;

  if (!name || len < 7u)
    return 0;

  firstLen = segment_len(name, len, 0);
  if (!segment_eq(name, firstLen, ".zipy"))
    return 0;
  if (firstLen >= len || !is_zip_sep(name[firstLen]))
    return 0;

  pos = firstLen + 1u;
  secondLen = segment_len(name, len, pos);
  if (segment_eq(name + pos, secondLen, "parts"))
    return 1;

  restLen = len - pos;
  if (segment_eq(name + pos, restLen, "resume_state.txt")
      || segment_eq(name + pos, restLen, "resume_options.txt"))
    return 1;
  if (prefix_eq(name + pos, restLen, "resume_state.txt.tmp"))
    return 1;

  return 0;
}

static int
path_info(const char *path, int *exists, int *isDir) {
#if defined(_WIN32)
  struct _stat64 st;

  if (_stat64(path, &st) != 0) {
#else
  struct stat st;

  if (lstat(path, &st) != 0) {
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
regular_file_size(const char *path, int *exists, uint64_t *size) {
#if defined(_WIN32)
  struct _stat64 st;

  if (_stat64(path, &st) != 0) {
#else
  struct stat st;

  if (lstat(path, &st) != 0) {
#endif
    if (errno == ENOENT || errno == ENOTDIR) {
      if (exists)
        *exists = 0;
      if (size)
        *size = 0;
      return 1;
    }
    return 0;
  }

  if (exists)
    *exists = 1;
#if defined(_WIN32)
  if ((st.st_mode & _S_IFDIR) != 0)
    return 0;
#else
  if (!S_ISREG(st.st_mode))
    return 0;
#endif

  if (st.st_size < 0)
    return 0;
  if (size)
    *size = (uint64_t)st.st_size;
  return 1;
}

static int
path_is_dir(const char *path) {
  int exists, isDir;

  if (!path_info(path, &exists, &isDir))
    return 0;
  return exists && isDir;
}

static char *
join_path(const char *dir, const char *name);

static int
target_empty_or_missing(const char *path, int *emptyOrMissing) {
  int exists, isDir;

  *emptyOrMissing = 0;
  if (!path_info(path, &exists, &isDir))
    return 0;
  if (!exists) {
    *emptyOrMissing = 1;
    return 1;
  }
  if (!isDir)
    return 1;

#if defined(_WIN32)
  {
    char *pattern;
    WIN32_FIND_DATAA data;
    HANDLE handle;

    pattern = join_path(path, "*");
    if (!pattern)
      return 0;

    handle = FindFirstFileA(pattern, &data);
    free(pattern);
    if (handle == INVALID_HANDLE_VALUE) {
      if (GetLastError() == ERROR_FILE_NOT_FOUND) {
        *emptyOrMissing = 1;
        return 1;
      }
      return 0;
    }

    do {
      if (strcmp(data.cFileName, ".") != 0 && strcmp(data.cFileName, "..") != 0) {
        FindClose(handle);
        return 1;
      }
    } while (FindNextFileA(handle, &data));

    FindClose(handle);
    *emptyOrMissing = 1;
  }
#else
  {
    DIR *dir;
    struct dirent *entry;

    dir = opendir(path);
    if (!dir)
      return 0;

    while ((entry = readdir(dir))) {
      if (strcmp(entry->d_name, ".") != 0 && strcmp(entry->d_name, "..") != 0) {
        closedir(dir);
        return 1;
      }
    }

    closedir(dir);
    *emptyOrMissing = 1;
  }
#endif

  return 1;
}

static int
mkdir_one(const char *path) {
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
    return path_is_dir(path);

  return 0;
}

static int
mkdirs_mut(char *tmp) {
  char *p;
  int ok = 1;

  if (!tmp || !*tmp)
    return 1;

  p = tmp;
#if defined(_WIN32)
  if (isalpha((unsigned char)p[0]) && p[1] == ':')
    p += 2;
#endif
  while (is_fs_sep(*p))
    p++;

  for (; *p; p++) {
    if (!is_fs_sep(*p))
      continue;

    *p = '\0';
    ok = mkdir_one(tmp);
    *p = '/';
    if (!ok)
      break;

    while (is_fs_sep(p[1]))
      p++;
  }

  if (ok)
    ok = mkdir_one(tmp);

  return ok;
}

static int
mkdirs(const char *path) {
  char *tmp;
  int ok;

  if (!path || !*path)
    return 1;

  tmp = malloc(strlen(path) + 1);
  if (!tmp)
    return 0;
  strcpy(tmp, path);

  ok = mkdirs_mut(tmp);
  free(tmp);
  return ok;
}

static int
mkdirs_buf(const char *path, path_buf_t *buf) {
  size_t len;

  if (!path || !*path)
    return 1;

  len = strlen(path);
  if (!path_buf_reserve(buf, len + 1u))
    return 0;
  memcpy(buf->data, path, len + 1u);
  return mkdirs_mut(buf->data);
}

static uint32_t
unix_mode(const entry_info_t *info) {
  return info ? info->unix_mode : 0;
}

static int
path_is_symlink(const char *path) {
#if !defined(_WIN32) && defined(S_IFLNK)
  struct stat st;

  if (!path || lstat(path, &st) != 0)
    return 0;

  return S_ISLNK(st.st_mode);
#else
  (void)path;
  return 0;
#endif
}

#if defined(_WIN32) || !defined(O_NOFOLLOW)
static int
unlink_symlink(const char *path) {
  if (!path_is_symlink(path))
    return 1;

#if defined(_WIN32)
  return 1;
#else
  return unlink(path) == 0;
#endif
}
#endif

static int
open_output_file_seek(const char *path,
                      out_file_t *out,
                      int *ret,
                      uint64_t offset,
                      int truncate_file) {
  if (ret)
    *ret = ZIPY_ZIP_EFILE;
  if (!out)
    return 0;

#if !defined(_WIN32) && defined(O_NOFOLLOW)
  {
    int fd;
    int flags = O_RDWR | O_CREAT | O_NOFOLLOW;

    if (truncate_file)
      flags |= O_TRUNC;

#  if defined(O_CLOEXEC)
    flags |= O_CLOEXEC;
#  endif

    fd = open(path, flags, 0666);
    if (fd < 0 && errno == ELOOP) {
      if (!truncate_file)
        return 0;
      if (unlink(path) != 0)
        return 0;
      fd = open(path, flags, 0666);
    }
    if (fd < 0)
      return 0;
    if (offset > 0) {
      if (offset > (uint64_t)INT64_MAX
          || lseek(fd, (off_t)offset, SEEK_SET) < 0) {
        close(fd);
        return 0;
      }
    }

    out->fd = fd;
    if (ret)
      *ret = ZIPY_ZIP_OK;
    return 1;
  }
#else
  if (truncate_file) {
    if (!unlink_symlink(path))
      return 0;
  } else if (path_is_symlink(path)) {
    return 0;
  }

  out->fp = fopen(path, truncate_file ? "wb" : "r+b");
  if (!out->fp && !truncate_file)
    out->fp = fopen(path, "w+b");
  if (!out->fp)
    return 0;
  if (offset > 0 && seek_set(out->fp, offset) != 0) {
    fclose(out->fp);
    out->fp = NULL;
    return 0;
  }

  if (ret)
    *ret = ZIPY_ZIP_OK;
  return 1;
#endif
}

static int
close_output_file(out_file_t *out) {
#if defined(_WIN32)
  if (!out || !out->fp)
    return 0;
  return fclose(out->fp) == 0;
#else
  if (!out || out->fd < 0)
    return 0;
  return close(out->fd) == 0;
#endif
}

static void
remove_file(const char *path) {
  if (!path)
    return;
#if defined(_WIN32)
  (void)_unlink(path);
#else
  (void)unlink(path);
#endif
}

static int
replace_file(const char *src, const char *dst) {
  if (!src || !dst)
    return 0;

#if defined(_WIN32)
  (void)_unlink(dst);
#endif

  if (rename(src, dst) == 0)
    return 1;

#if !defined(_WIN32)
  if (errno == EEXIST) {
    (void)unlink(dst);
    return rename(src, dst) == 0;
  }
#endif

  return 0;
}

static void
remove_empty_dir(const char *path) {
  if (!path || !*path)
    return;

#if defined(_WIN32)
  (void)_rmdir(path);
#else
  (void)rmdir(path);
#endif
}

static int
path_buf_set_dir(path_buf_t * __restrict buf,
                 const char * __restrict dir,
                 size_t * __restrict prefixLen);

static const char *
path_buf_append_name(path_buf_t * __restrict buf,
                     size_t prefixLen,
                     const char * __restrict name,
                     size_t nameLen,
                     int nameHasBackslash);

static const char *
path_buf_append_suffix(path_buf_t * __restrict buf,
                       const char * __restrict suffix);

static void
state_write_text(FILE *fp, const char *text) {
  const unsigned char *p = (const unsigned char *)text;

  if (!fp || !text)
    return;

  while (*p) {
    unsigned char c = *p++;

    if (c == '\\' || c == '\n' || c == '\r') {
      fputc('\\', fp);
      fputc(c == '\n' ? 'n' : c == '\r' ? 'r' : '\\', fp);
    } else if (c < 32) {
      fputc('?', fp);
    } else {
      fputc((int)c, fp);
    }
  }
}

static const char *
resume_state_path(zipy_archive_t * __restrict zipy,
                  const char * __restrict destdir) {
  size_t prefixLen;

  if (!zipy || !destdir)
    return NULL;
  if (!path_buf_set_dir(&zipy->state_buf, destdir, &prefixLen))
    return NULL;
  if (!path_buf_append_name(&zipy->state_buf,
                            prefixLen,
                            ".zipy",
                            5u,
                            0))
    return NULL;
  if (!mkdirs_buf(zipy->state_buf.data, &zipy->parent_buf))
    return NULL;
  if (!path_buf_append_suffix(&zipy->state_buf, "/resume_state.txt"))
    return NULL;

  return zipy->state_buf.data;
}

static const char *
resume_part_path(zipy_archive_t * __restrict zipy,
                 const char * __restrict destdir,
                 const entry_info_t * __restrict info) {
  size_t prefixLen;

  if (!zipy || !destdir || !info)
    return NULL;
  if (!path_buf_set_dir(&zipy->part_buf, destdir, &prefixLen))
    return NULL;
  if (!path_buf_append_name(&zipy->part_buf,
                            prefixLen,
                            ".zipy/parts",
                            11u,
                            0))
    return NULL;
  if (!mkdirs_buf(zipy->part_buf.data, &zipy->parent_buf))
    return NULL;
  if (!path_buf_append_suffix(&zipy->part_buf, "/"))
    return NULL;

  prefixLen = strlen(zipy->part_buf.data);
  if (!path_buf_append_name(&zipy->part_buf,
                            prefixLen,
                            info->entry.name,
                            info->entry.name_len,
                            info->name_has_backslash))
    return NULL;
  if (!path_buf_append_suffix(&zipy->part_buf, ".part"))
    return NULL;

  return zipy->part_buf.data;
}

static void
cleanup_empty_parts_dirs(zipy_archive_t * __restrict zipy,
                         const char * __restrict destdir,
                         const char * __restrict partpath) {
  char *p, *last;
  size_t stopLen, len;

  if (!zipy || !destdir || !partpath)
    return;
  if (!path_buf_set_dir(&zipy->state_buf, destdir, &stopLen))
    return;
  if (zipy->has_root_zipy) {
    if (!path_buf_append_name(&zipy->state_buf,
                              stopLen,
                              ".zipy",
                              5u,
                              0))
      return;
    stopLen = strlen(zipy->state_buf.data);
  }

  len = strlen(partpath);
  if (len <= stopLen || strncmp(partpath, zipy->state_buf.data, stopLen) != 0)
    return;
  if (!path_buf_reserve(&zipy->parent_buf, len + 1u))
    return;

  memcpy(zipy->parent_buf.data, partpath, len + 1u);
  for (;;) {
    last = NULL;
    for (p = zipy->parent_buf.data; *p; p++) {
      if (is_fs_sep(*p))
        last = p;
    }
    if (!last)
      return;

    *last = '\0';
    len = strlen(zipy->parent_buf.data);
    if (len <= stopLen)
      return;

    remove_empty_dir(zipy->parent_buf.data);
  }
}

static void
write_resume_state(const char *state_path,
                   const zipy_archive_t *zipy,
                   const entry_info_t *info,
                   const char *destpath,
                   const char *partpath,
                   uint64_t offset,
                   uint32_t flags,
                   const char *status) {
  char tmp[PATH_MAX];
  FILE *fp;
  int n;

  if (!state_path || !*state_path || !info)
    return;

  n = snprintf(tmp, sizeof(tmp), "%s.tmp.%p", state_path, (const void *)info);
  if (n < 0 || (size_t)n >= sizeof(tmp))
    return;

  fp = fopen(tmp, "wb");
  if (!fp)
    return;

  fputs("version = 1\n", fp);
  fputs("status = ", fp);
  state_write_text(fp, status ? status : "extracting");
  fputc('\n', fp);

  fputs("archive = ", fp);
  state_write_text(fp, zipy ? zipy->path : NULL);
  fputc('\n', fp);

  fputs("entry = ", fp);
  state_write_text(fp, info->entry.name);
  fputc('\n', fp);

  fputs("target = ", fp);
  state_write_text(fp, destpath);
  fputc('\n', fp);

  fputs("part = ", fp);
  state_write_text(fp, partpath);
  fputc('\n', fp);

  fprintf(fp,
          "method = %u\n"
          "encrypted = %u\n"
          "resume_offset = %llu\n"
          "compressed_size = %llu\n"
          "uncompressed_size = %llu\n"
          "crc32 = %08x\n"
          "flags = 0x%08x\n",
          (unsigned)info->entry.method,
          info->entry.encrypted ? 1u : 0u,
          (unsigned long long)offset,
          (unsigned long long)info->entry.compressed_size,
          (unsigned long long)info->entry.uncompressed_size,
          (unsigned)info->entry.crc32,
          (unsigned)(flags & ~EXTRACT_DELAY_DIR_METADATA));

  if (fclose(fp) != 0) {
    remove_file(tmp);
    return;
  }

  (void)replace_file(tmp, state_path);
}

static void
write_resume_run_state(const char *state_path,
                       const zipy_archive_t *zipy,
                       const char *status,
                       int result) {
  char tmp[PATH_MAX];
  FILE *fp;
  size_t len;

  if (!state_path || !*state_path)
    return;

  len = strlen(state_path);
  if (len > sizeof(tmp) - 5u)
    return;

  memcpy(tmp, state_path, len);
  memcpy(tmp + len, ".tmp", 5u);

  fp = fopen(tmp, "wb");
  if (!fp)
    return;

  fputs("version = 1\n", fp);
  fputs("status = ", fp);
  state_write_text(fp, status ? status : "complete");
  fputc('\n', fp);

  fputs("archive = ", fp);
  state_write_text(fp, zipy ? zipy->path : NULL);
  fputc('\n', fp);
  fprintf(fp, "result = %d\n", result);

  if (fclose(fp) != 0) {
    remove_file(tmp);
    return;
  }

  (void)replace_file(tmp, state_path);
}

static int
parent_has_symlink(const char *path) {
#if defined(_WIN32)
  (void)path;
  return 0;
#else
  char *tmp, *p, *last = NULL;
  int found = 0;

  if (!path || !*path)
    return 0;

  tmp = dup_text(path);
  if (!tmp)
    return 1;

  for (p = tmp; *p; p++) {
    if (is_fs_sep(*p))
      last = p;
  }

  if (!last) {
    free(tmp);
    return 0;
  }

  if (last == tmp && is_fs_sep(tmp[0])) {
    tmp[1] = '\0';
  } else {
    *last = '\0';
  }

  p = tmp;
  while (is_fs_sep(*p))
    p++;

  for (; *p; p++) {
    if (!is_fs_sep(*p))
      continue;

    *p = '\0';
    if (*tmp && path_is_symlink(tmp)) {
      found = 1;
      *p = '/';
      break;
    }
    *p = '/';

    while (is_fs_sep(p[1]))
      p++;
  }

  if (!found && *tmp && !(strlen(tmp) == 1 && is_fs_sep(tmp[0])))
    found = path_is_symlink(tmp);

  free(tmp);
  return found;
#endif
}

static int
parent_has_symlink_buf(const char *path, path_buf_t *buf) {
#if defined(_WIN32)
  (void)path;
  (void)buf;
  return 0;
#else
  char *p, *last = NULL;
  size_t len;
  int found = 0;

  if (!path || !*path)
    return 0;

  len = strlen(path);
  if (!path_buf_reserve(buf, len + 1u))
    return 1;

  memcpy(buf->data, path, len + 1u);

  for (p = buf->data; *p; p++) {
    if (is_fs_sep(*p))
      last = p;
  }

  if (!last)
    return 0;

  if (last == buf->data && is_fs_sep(buf->data[0])) {
    buf->data[1] = '\0';
  } else {
    *last = '\0';
  }

  p = buf->data;
  while (is_fs_sep(*p))
    p++;

  for (; *p; p++) {
    if (!is_fs_sep(*p))
      continue;

    *p = '\0';
    if (*buf->data && path_is_symlink(buf->data)) {
      found = 1;
      *p = '/';
      break;
    }
    *p = '/';

    while (is_fs_sep(p[1]))
      p++;
  }

  if (!found
      && *buf->data
      && !(strlen(buf->data) == 1 && is_fs_sep(buf->data[0])))
    found = path_is_symlink(buf->data);

  return found;
#endif
}

static int
is_symlink(const entry_info_t *info) {
#if !defined(_WIN32) && defined(S_IFLNK)
  return info && info->is_symlink;
#else
  (void)info;
  return 0;
#endif
}

static int
apply_attrs(const char *path, const entry_info_t *info) {
  uint32_t mode = unix_mode(info);

  if (!path || !info || mode == 0 || is_symlink(info))
    return 1;

#if defined(_WIN32)
  return _chmod(path, (int)(mode & 0777u)) == 0 || errno == ENOENT;
#else
  return chmod(path, (mode_t)(mode & 07777u)) == 0 || errno == ENOENT;
#endif
}

static int
apply_time(const char *path, const entry_info_t *info) {
  if (!path || !info || !info->has_mtime)
    return 1;

#if defined(_WIN32)
  {
    struct _utimbuf times;
    times.actime = info->mtime;
    times.modtime = info->mtime;
    return _utime(path, &times) == 0 || errno == ENOENT;
  }
#elif defined(AT_SYMLINK_NOFOLLOW)
  {
    struct timespec times[2];
    times[0].tv_sec = info->mtime;
    times[0].tv_nsec = 0;
    times[1].tv_sec = info->mtime;
    times[1].tv_nsec = 0;
    return utimensat(AT_FDCWD,
                     path,
                     times,
                     is_symlink(info) ? AT_SYMLINK_NOFOLLOW : 0) == 0
        || errno == ENOENT;
  }
#else
  if (is_symlink(info))
    return 1;
  {
    struct utimbuf times;
    times.actime = info->mtime;
    times.modtime = info->mtime;
    return utime(path, &times) == 0 || errno == ENOENT;
  }
#endif
}

static int
apply_entry_metadata(const char *path, const entry_info_t *info) {
  return apply_attrs(path, info) && apply_time(path, info);
}

static int
apply_open_file_metadata(out_file_t *out, const entry_info_t *info) {
#if defined(_WIN32)
  (void)out;
  (void)info;
  return 0;
#else
  uint32_t mode = unix_mode(info);

  if (!out || out->fd < 0 || !info || is_symlink(info))
    return 0;

  if (mode != 0 && fchmod(out->fd, (mode_t)(mode & 07777u)) != 0)
    return 0;

  if (info->has_mtime) {
    struct timespec times[2];

    times[0].tv_sec = info->mtime;
    times[0].tv_nsec = 0;
    times[1].tv_sec = info->mtime;
    times[1].tv_nsec = 0;
    if (futimens(out->fd, times) != 0)
      return 0;
  }

  return 1;
#endif
}

static int
mkdir_parent(const char *path) {
  char *tmp, *p, *last = NULL;
  int ok;

  if (!path || !*path)
    return 0;

  tmp = malloc(strlen(path) + 1);
  if (!tmp)
    return 0;
  strcpy(tmp, path);

  for (p = tmp; *p; p++) {
    if (is_fs_sep(*p))
      last = p;
  }

  if (!last) {
    free(tmp);
    return 1;
  }

  if (last == tmp && is_fs_sep(tmp[0])) {
    tmp[1] = '\0';
  } else {
    *last = '\0';
  }

  ok = mkdirs(tmp);
  free(tmp);
  return ok;
}

static int
prepare_parent_dir_len(zipy_archive_t * __restrict zipy,
                            const char * __restrict path,
                            size_t parent_len) {
  int has_symlink;

  if (!zipy || !path || !*path)
    return 0;
  if (parent_len == 0)
    return 1;

  if (zipy->parent_cache_valid
      && zipy->parent_cache_len == parent_len
      && memcmp(zipy->parent_cache.data, path, parent_len) == 0) {
    return !zipy->parent_cache_has_symlink;
  }

  if (!path_buf_reserve(&zipy->parent_buf, parent_len + 1u))
    return 0;
  memcpy(zipy->parent_buf.data, path, parent_len);
  zipy->parent_buf.data[parent_len] = '\0';

  if (!mkdirs_mut(zipy->parent_buf.data))
    return 0;

  has_symlink = parent_has_symlink_buf(path, &zipy->parent_buf);
  if (has_symlink)
    return 0;
  if (!path_buf_reserve(&zipy->parent_cache, parent_len + 1u))
    return 0;

  memcpy(zipy->parent_cache.data, path, parent_len);
  zipy->parent_cache.data[parent_len] = '\0';
  zipy->parent_cache_len = parent_len;
  zipy->parent_cache_valid = 1;
  zipy->parent_cache_has_symlink = has_symlink;

  return !has_symlink;
}

static int
prepare_parent_dir(zipy_archive_t * __restrict zipy,
                        const char * __restrict path) {
  const char *p, *last = NULL;
  size_t parent_len;

  if (!zipy || !path || !*path)
    return 0;

  for (p = path; *p; p++) {
    if (is_fs_sep(*p))
      last = p;
  }

  if (!last)
    return 1;

  parent_len = (size_t)(last - path);
  if (last == path && is_fs_sep(path[0]))
    parent_len = 1;

  return prepare_parent_dir_len(zipy, path, parent_len);
}

static entry_info_t *
find_file(zipy_archive_t *zipy, const char *filename) {
  size_t i;

  for (i = 0; i < zipy->file_count; i++) {
    if (strcmp(zipy->files[i].entry.name, filename) == 0)
      return &zipy->files[i];
  }

  return NULL;
}

static void
free_files(zipy_archive_t *zipy) {
  size_t i;

  if (!zipy || !zipy->files)
    return;

  if (!zipy->owns_files) {
    zipy->files = NULL;
    zipy->file_count = 0;
    return;
  }

  if (zipy->name_chunks) {
    free_name_chunks(zipy);
  } else {
    for (i = 0; i < zipy->file_count; i++)
      free((char *)zipy->files[i].entry.name);
  }

  free(zipy->files);
  zipy->files = NULL;
}

static void
archive_cleanup(zipy_archive_t *zipy) {
  if (!zipy)
    return;

  free_files(zipy);
  free_name_chunks(zipy);
  free(zipy->path);
  zipy->path = NULL;
  path_buf_free(&zipy->path_buf);
  path_buf_free(&zipy->parent_buf);
  path_buf_free(&zipy->parent_cache);
  path_buf_free(&zipy->part_buf);
  path_buf_free(&zipy->state_buf);
  free(zipy->copy_buf);
  zipy->copy_buf = NULL;
  free(zipy->inflate_in);
  zipy->inflate_in = NULL;
  free(zipy->inflate_out);
  zipy->inflate_out = NULL;
  if (zipy->inflate_stream) {
    infl_destroy(zipy->inflate_stream);
    zipy->inflate_stream = NULL;
  }
  unmap_archive(zipy);
  if (zipy->fp) {
    fclose(zipy->fp);
    zipy->fp = NULL;
  }
}

static size_t
chunk_size(uint64_t remaining) {
  return remaining > ZIP_IO_CHUNK ? ZIP_IO_CHUNK : (size_t)remaining;
}

static size_t
mapped_write_chunk_size(uint64_t remaining) {
  return remaining > ZIP_MAPPED_WRITE_CHUNK
       ? ZIP_MAPPED_WRITE_CHUNK
       : (size_t)remaining;
}

static size_t
fast_write_chunk_size(uint64_t remaining) {
  return remaining > ZIP_FAST_WRITE_CHUNK
       ? ZIP_FAST_WRITE_CHUNK
       : (size_t)remaining;
}

static const uint32_t crc32_base_table[256] = {
    0x00000000u, 0x77073096u, 0xEE0E612Cu, 0x990951BAu,
    0x076DC419u, 0x706AF48Fu, 0xE963A535u, 0x9E6495A3u,
    0x0EDB8832u, 0x79DCB8A4u, 0xE0D5E91Eu, 0x97D2D988u,
    0x09B64C2Bu, 0x7EB17CBDu, 0xE7B82D07u, 0x90BF1D91u,
    0x1DB71064u, 0x6AB020F2u, 0xF3B97148u, 0x84BE41DEu,
    0x1ADAD47Du, 0x6DDDE4EBu, 0xF4D4B551u, 0x83D385C7u,
    0x136C9856u, 0x646BA8C0u, 0xFD62F97Au, 0x8A65C9ECu,
    0x14015C4Fu, 0x63066CD9u, 0xFA0F3D63u, 0x8D080DF5u,
    0x3B6E20C8u, 0x4C69105Eu, 0xD56041E4u, 0xA2677172u,
    0x3C03E4D1u, 0x4B04D447u, 0xD20D85FDu, 0xA50AB56Bu,
    0x35B5A8FAu, 0x42B2986Cu, 0xDBBBC9D6u, 0xACBCF940u,
    0x32D86CE3u, 0x45DF5C75u, 0xDCD60DCFu, 0xABD13D59u,
    0x26D930ACu, 0x51DE003Au, 0xC8D75180u, 0xBFD06116u,
    0x21B4F4B5u, 0x56B3C423u, 0xCFBA9599u, 0xB8BDA50Fu,
    0x2802B89Eu, 0x5F058808u, 0xC60CD9B2u, 0xB10BE924u,
    0x2F6F7C87u, 0x58684C11u, 0xC1611DABu, 0xB6662D3Du,
    0x76DC4190u, 0x01DB7106u, 0x98D220BCu, 0xEFD5102Au,
    0x71B18589u, 0x06B6B51Fu, 0x9FBFE4A5u, 0xE8B8D433u,
    0x7807C9A2u, 0x0F00F934u, 0x9609A88Eu, 0xE10E9818u,
    0x7F6A0DBBu, 0x086D3D2Du, 0x91646C97u, 0xE6635C01u,
    0x6B6B51F4u, 0x1C6C6162u, 0x856530D8u, 0xF262004Eu,
    0x6C0695EDu, 0x1B01A57Bu, 0x8208F4C1u, 0xF50FC457u,
    0x65B0D9C6u, 0x12B7E950u, 0x8BBEB8EAu, 0xFCB9887Cu,
    0x62DD1DDFu, 0x15DA2D49u, 0x8CD37CF3u, 0xFBD44C65u,
    0x4DB26158u, 0x3AB551CEu, 0xA3BC0074u, 0xD4BB30E2u,
    0x4ADFA541u, 0x3DD895D7u, 0xA4D1C46Du, 0xD3D6F4FBu,
    0x4369E96Au, 0x346ED9FCu, 0xAD678846u, 0xDA60B8D0u,
    0x44042D73u, 0x33031DE5u, 0xAA0A4C5Fu, 0xDD0D7CC9u,
    0x5005713Cu, 0x270241AAu, 0xBE0B1010u, 0xC90C2086u,
    0x5768B525u, 0x206F85B3u, 0xB966D409u, 0xCE61E49Fu,
    0x5EDEF90Eu, 0x29D9C998u, 0xB0D09822u, 0xC7D7A8B4u,
    0x59B33D17u, 0x2EB40D81u, 0xB7BD5C3Bu, 0xC0BA6CADu,
    0xEDB88320u, 0x9ABFB3B6u, 0x03B6E20Cu, 0x74B1D29Au,
    0xEAD54739u, 0x9DD277AFu, 0x04DB2615u, 0x73DC1683u,
    0xE3630B12u, 0x94643B84u, 0x0D6D6A3Eu, 0x7A6A5AA8u,
    0xE40ECF0Bu, 0x9309FF9Du, 0x0A00AE27u, 0x7D079EB1u,
    0xF00F9344u, 0x8708A3D2u, 0x1E01F268u, 0x6906C2FEu,
    0xF762575Du, 0x806567CBu, 0x196C3671u, 0x6E6B06E7u,
    0xFED41B76u, 0x89D32BE0u, 0x10DA7A5Au, 0x67DD4ACCu,
    0xF9B9DF6Fu, 0x8EBEEFF9u, 0x17B7BE43u, 0x60B08ED5u,
    0xD6D6A3E8u, 0xA1D1937Eu, 0x38D8C2C4u, 0x4FDFF252u,
    0xD1BB67F1u, 0xA6BC5767u, 0x3FB506DDu, 0x48B2364Bu,
    0xD80D2BDAu, 0xAF0A1B4Cu, 0x36034AF6u, 0x41047A60u,
    0xDF60EFC3u, 0xA867DF55u, 0x316E8EEFu, 0x4669BE79u,
    0xCB61B38Cu, 0xBC66831Au, 0x256FD2A0u, 0x5268E236u,
    0xCC0C7795u, 0xBB0B4703u, 0x220216B9u, 0x5505262Fu,
    0xC5BA3BBEu, 0xB2BD0B28u, 0x2BB45A92u, 0x5CB36A04u,
    0xC2D7FFA7u, 0xB5D0CF31u, 0x2CD99E8Bu, 0x5BDEAE1Du,
    0x9B64C2B0u, 0xEC63F226u, 0x756AA39Cu, 0x026D930Au,
    0x9C0906A9u, 0xEB0E363Fu, 0x72076785u, 0x05005713u,
    0x95BF4A82u, 0xE2B87A14u, 0x7BB12BAEu, 0x0CB61B38u,
    0x92D28E9Bu, 0xE5D5BE0Du, 0x7CDCEFB7u, 0x0BDBDF21u,
    0x86D3D2D4u, 0xF1D4E242u, 0x68DDB3F8u, 0x1FDA836Eu,
    0x81BE16CDu, 0xF6B9265Bu, 0x6FB077E1u, 0x18B74777u,
    0x88085AE6u, 0xFF0F6A70u, 0x66063BCAu, 0x11010B5Cu,
    0x8F659EFFu, 0xF862AE69u, 0x616BFFD3u, 0x166CCF45u,
    0xA00AE278u, 0xD70DD2EEu, 0x4E048354u, 0x3903B3C2u,
    0xA7672661u, 0xD06016F7u, 0x4969474Du, 0x3E6E77DBu,
    0xAED16A4Au, 0xD9D65ADCu, 0x40DF0B66u, 0x37D83BF0u,
    0xA9BCAE53u, 0xDEBB9EC5u, 0x47B2CF7Fu, 0x30B5FFE9u,
    0xBDBDF21Cu, 0xCABAC28Au, 0x53B39330u, 0x24B4A3A6u,
    0xBAD03605u, 0xCDD70693u, 0x54DE5729u, 0x23D967BFu,
    0xB3667A2Eu, 0xC4614AB8u, 0x5D681B02u, 0x2A6F2B94u,
    0xB40BBE37u, 0xC30C8EA1u, 0x5A05DF1Bu, 0x2D02EF8Du
  };

static uint32_t crc32_tables[16][256];

static void
crc32_make_tables(void) {
  size_t i, j;

  memcpy(crc32_tables[0],
         crc32_base_table,
         sizeof(crc32_base_table));

  for (i = 0; i < 256u; i++) {
    uint32_t crc = crc32_tables[0][i];

    for (j = 1; j < 16u; j++) {
      crc = crc32_tables[0][crc & 0xFFu] ^ (crc >> 8);
      crc32_tables[j][i] = crc;
    }
  }
}

#if defined(_WIN32)
static INIT_ONCE crc32_once = INIT_ONCE_STATIC_INIT;

static BOOL CALLBACK
crc32_init_once(PINIT_ONCE once, PVOID param, PVOID *context) {
  (void)once;
  (void)param;
  (void)context;
  crc32_make_tables();
  return TRUE;
}

static void
crc32_init_tables(void) {
  InitOnceExecuteOnce(&crc32_once, crc32_init_once, NULL, NULL);
}
#else
static pthread_once_t crc32_once = PTHREAD_ONCE_INIT;

static void
crc32_init_tables(void) {
  (void)pthread_once(&crc32_once, crc32_make_tables);
}
#endif

static uint32_t
crc32_update(uint32_t crc,
                  const uint8_t * __restrict buf,
                  size_t len) {
  const uint32_t (*table)[256] = crc32_tables;

  crc32_init_tables();

  crc = ~crc;
  while (len >= 16u) {
    uint64_t word0 = load_le64(buf) ^ crc;
    uint64_t word1 = load_le64(buf + 8u);

    crc = table[15][ word0        & 0xFFu]
        ^ table[14][(word0 >>  8) & 0xFFu]
        ^ table[13][(word0 >> 16) & 0xFFu]
        ^ table[12][(word0 >> 24) & 0xFFu]
        ^ table[11][(word0 >> 32) & 0xFFu]
        ^ table[10][(word0 >> 40) & 0xFFu]
        ^ table[ 9][(word0 >> 48) & 0xFFu]
        ^ table[ 8][(word0 >> 56) & 0xFFu]
        ^ table[ 7][ word1        & 0xFFu]
        ^ table[ 6][(word1 >>  8) & 0xFFu]
        ^ table[ 5][(word1 >> 16) & 0xFFu]
        ^ table[ 4][(word1 >> 24) & 0xFFu]
        ^ table[ 3][(word1 >> 32) & 0xFFu]
        ^ table[ 2][(word1 >> 40) & 0xFFu]
        ^ table[ 1][(word1 >> 48) & 0xFFu]
        ^ table[ 0][(word1 >> 56) & 0xFFu];
    buf += 16u;
    len -= 16u;
  }

  while (len >= 8u) {
    uint64_t word = load_le64(buf) ^ crc;

    crc = table[7][ word        & 0xFFu]
        ^ table[6][(word >>  8) & 0xFFu]
        ^ table[5][(word >> 16) & 0xFFu]
        ^ table[4][(word >> 24) & 0xFFu]
        ^ table[3][(word >> 32) & 0xFFu]
        ^ table[2][(word >> 40) & 0xFFu]
        ^ table[1][(word >> 48) & 0xFFu]
        ^ table[0][(word >> 56) & 0xFFu];
    buf += 8;
    len -= 8u;
  }

  while (len--)
    crc = (crc >> 8) ^ table[0][(crc ^ *buf++) & 0xFFu];
  return ~crc;
}

static int
crc32_file_prefix(zipy_archive_t * __restrict zipy,
                  const char * __restrict path,
                  uint64_t len,
                  uint32_t * __restrict crcOut) {
  FILE *fp;
  uint64_t remaining;
  uint32_t crc = 0;

  if (!zipy || !path || !crcOut)
    return ZIPY_ZIP_ERR;
  if (!reserve_bytes(&zipy->copy_buf, &zipy->copy_cap, ZIP_IO_CHUNK))
    return ZIPY_ZIP_ERR;

  fp = fopen(path, "rb");
  if (!fp)
    return ZIPY_ZIP_EFILE;

  remaining = len;
  while (remaining > 0) {
    size_t n = chunk_size(remaining);

    if (fread(zipy->copy_buf, 1, n, fp) != n) {
      fclose(fp);
      return ZIPY_ZIP_EFILE;
    }
    crc = crc32_update(crc, zipy->copy_buf, n);
    remaining -= n;
  }

  if (fclose(fp) != 0)
    return ZIPY_ZIP_EFILE;

  *crcOut = crc;
  return ZIPY_ZIP_OK;
}

static int
write_chunk(out_file_t * __restrict out,
                 uint8_t * __restrict buf,
                 size_t len,
                 uint32_t * __restrict crc,
                 int check_crc,
                 dec_t * __restrict dec,
                 uint64_t * __restrict written,
                 progress_state_t * __restrict progress) {
  int ret;

  if (len == 0)
    return ZIPY_ZIP_OK;

  if (dec)
    dec_decrypt(dec, buf, len);

  ret = write_file(out, buf, len);
  if (ret != ZIPY_ZIP_OK)
    return ret;

  if (check_crc)
    *crc = crc32_update(*crc, buf, len);
  *written += len;
  return progress_advance(progress, len);
}

static int
copy_store(zipy_archive_t * __restrict zipy,
                out_file_t * __restrict out,
                uint64_t len,
                uint32_t expectedCrc,
                int check_crc,
                dec_t * __restrict dec,
                uint64_t already_written,
                uint32_t initial_crc,
                progress_state_t * __restrict progress) {
  FILE *fp;
  uint8_t *buf;
  uint64_t remaining, written;
  uint32_t crc;
  int ret = ZIPY_ZIP_OK;

  if (!zipy || !zipy->fp)
    return ZIPY_ZIP_EFILE;
  if (already_written > len)
    return ZIPY_ZIP_ESIZE;
  if (!reserve_bytes(&zipy->copy_buf, &zipy->copy_cap, ZIP_IO_CHUNK))
    return ZIPY_ZIP_ERR;

  fp = zipy->fp;
  buf = zipy->copy_buf;
  remaining = len - already_written;
  written = already_written;
  crc = initial_crc;
  while (remaining > 0) {
    size_t n = chunk_size(remaining);

    if (fread(buf, 1, n, fp) != n) {
      ret = ZIPY_ZIP_EFILE;
      return ret;
    }

    ret = write_chunk(out, buf, n, &crc, check_crc, dec, &written, progress);
    if (ret != ZIPY_ZIP_OK)
      return ret;

    remaining -= n;
  }

  ret = dec_finish(dec, fp);
  if (ret != ZIPY_ZIP_OK)
    return ret;

  if (written != len)
    ret = ZIPY_ZIP_ESIZE;
  else if (check_crc && (uint32_t)crc != expectedCrc)
    ret = ZIPY_ZIP_ECRC;

  return ret;
}

static int
copy_store_mapped(out_file_t * __restrict out,
                       const uint8_t * __restrict src,
                       uint64_t len,
                       uint32_t expectedCrc,
                       int check_crc,
                       uint64_t already_written,
                       uint32_t initial_crc,
                       progress_state_t * __restrict progress) {
  uint64_t remaining;
  uint32_t crc = initial_crc;
  int ret;

  if (!src)
    return ZIPY_ZIP_EFILE;
  if (already_written > len)
    return ZIPY_ZIP_ESIZE;
  if (already_written > (uint64_t)SIZE_MAX)
    return ZIPY_ZIP_EUNSUP;

  src += (size_t)already_written;
  remaining = len - already_written;

  while (remaining > 0) {
    size_t n = check_crc
             ? mapped_write_chunk_size(remaining)
             : fast_write_chunk_size(remaining);

    ret = write_file(out, src, n);
    if (ret != ZIPY_ZIP_OK)
      return ret;

    if (check_crc)
      crc = crc32_update(crc, src, n);
    ret = progress_advance(progress, n);
    if (ret != ZIPY_ZIP_OK)
      return ret;

    src += n;
    remaining -= n;
  }

  if (check_crc && crc != expectedCrc)
    return ZIPY_ZIP_ECRC;

  return ZIPY_ZIP_OK;
}

static int
inflate_raw_streamed(zipy_archive_t * __restrict zipy,
                     out_file_t * __restrict out,
                     uint64_t compressed_size,
                     uint64_t uncompressed_size,
                     uint32_t expectedCrc,
                     int check_crc,
                     dec_t * __restrict dec,
                     progress_state_t * __restrict progress) {
  out_map_t outmap;
  uint8_t *outbuf;
  uint8_t *inbuf;
  uint64_t remaining;
  size_t outlen;
  uint32_t crc;
  uint32_t produced = 0;
  int mapped_out = 0;
  int zret = UNZ_UNFINISHED;
  int ret;

  if (!zipy || !zipy->fp)
    return ZIPY_ZIP_EFILE;
  if (compressed_size > UINT32_MAX || uncompressed_size > UINT32_MAX)
    return ZIPY_ZIP_EUNSUP;

  outlen = uncompressed_size > 0 ? (size_t)uncompressed_size : 1u;
  memset(&outmap, 0, sizeof(outmap));
  if (uncompressed_size >= ZIP_OUTPUT_MMAP_MIN
      && map_output(out, uncompressed_size, &outmap)) {
    outbuf = outmap.data;
    mapped_out = 1;
  } else {
    if (!reserve_bytes(&zipy->inflate_out, &zipy->inflate_out_cap, outlen))
      return ZIPY_ZIP_ERR;
    outbuf = zipy->inflate_out;
  }

  if (!reserve_bytes(&zipy->inflate_in,
                     &zipy->inflate_in_cap,
                     ZIP_INFLATE_STREAM_CHUNK)) {
    ret = ZIPY_ZIP_ERR;
    goto done;
  }
  inbuf = zipy->inflate_in;

  if (!zipy->inflate_stream) {
    zipy->inflate_stream = infl_init(outbuf, (uint32_t)uncompressed_size, 0);
    if (!zipy->inflate_stream) {
      ret = ZIPY_ZIP_ERR;
      goto done;
    }
  } else {
    infl_reset(zipy->inflate_stream, outbuf, (uint32_t)uncompressed_size, 0);
  }

  remaining = compressed_size;
  while (remaining > 0) {
    size_t n = remaining > ZIP_INFLATE_STREAM_CHUNK
             ? ZIP_INFLATE_STREAM_CHUNK
             : (size_t)remaining;

    if (fread(inbuf, 1, n, zipy->fp) != n) {
      ret = ZIPY_ZIP_EFILE;
      goto done;
    }
    if (dec)
      dec_decrypt(dec, inbuf, n);

    zret = infl_stream(zipy->inflate_stream, inbuf, (uint32_t)n);
    if (zret < UNZ_OK) {
      ret = ZIPY_ZIP_EINFLATE;
      goto done;
    }
    if (progress && progress->options && progress->options->progress) {
      uint32_t now = infl_output_pos(zipy->inflate_stream);

      if (now < produced) {
        ret = ZIPY_ZIP_ESIZE;
        goto done;
      }
      ret = progress_advance(progress, (uint64_t)(now - produced));
      if (ret != ZIPY_ZIP_OK)
        goto done;
      produced = now;
    }
    if (zret == UNZ_OK && remaining != n) {
      ret = ZIPY_ZIP_ESIZE;
      goto done;
    }

    remaining -= n;
  }

  if (zret == UNZ_UNFINISHED)
    zret = infl_stream(zipy->inflate_stream, NULL, 0);
  if (zret != UNZ_OK) {
    ret = ZIPY_ZIP_EINFLATE;
    goto done;
  }

  ret = dec_finish(dec, zipy->fp);
  if (ret != ZIPY_ZIP_OK)
    goto done;

  if (infl_output_pos(zipy->inflate_stream) != (uint32_t)uncompressed_size) {
    ret = ZIPY_ZIP_ESIZE;
    goto done;
  }
  if (infl_input_pos(zipy->inflate_stream) != (uint32_t)compressed_size) {
    ret = ZIPY_ZIP_ESIZE;
    goto done;
  }

  if (check_crc) {
    crc = crc32_update(0, outbuf, (size_t)uncompressed_size);
    if (crc != expectedCrc) {
      ret = ZIPY_ZIP_ECRC;
      goto done;
    }
  }

  if (!mapped_out && uncompressed_size > 0) {
    ret = write_file(out, outbuf, (size_t)uncompressed_size);
    if (ret != ZIPY_ZIP_OK)
      goto done;
  }

  ret = ZIPY_ZIP_OK;

done:
  unmap_output(&outmap);
  return ret;
}

static int
inflate_raw(zipy_archive_t * __restrict zipy,
                 out_file_t * __restrict out,
                 const uint8_t * __restrict mapped,
                 uint64_t compressed_size,
                 uint64_t uncompressed_size,
                 uint32_t expectedCrc,
                 int check_crc,
                 dec_t * __restrict dec,
                 progress_state_t * __restrict progress) {
  FILE *fp;
  uint8_t *inbuf = NULL;
  uint8_t *outbuf;
  out_map_t outmap;
  const uint8_t *src;
  size_t inlen, outlen;
  uint32_t crc;
  int mapped_out = 0;
  int zret;
  int ret;

  if (!zipy)
    return ZIPY_ZIP_EFILE;
  if (compressed_size > UINT32_MAX || uncompressed_size > UINT32_MAX)
    return ZIPY_ZIP_EUNSUP;
  if (!mapped)
    return inflate_raw_streamed(zipy,
                                out,
                                compressed_size,
                                uncompressed_size,
                                expectedCrc,
                                check_crc,
                                dec,
                                progress);

  inlen = compressed_size > 0 ? (size_t)compressed_size : 1;
  outlen = uncompressed_size > 0 ? (size_t)uncompressed_size : 1;

  memset(&outmap, 0, sizeof(outmap));
  fp = zipy->fp;
  if (uncompressed_size >= ZIP_OUTPUT_MMAP_MIN
      && map_output(out, uncompressed_size, &outmap)) {
    outbuf = outmap.data;
    mapped_out = 1;
  } else {
    if (!reserve_bytes(&zipy->inflate_out, &zipy->inflate_out_cap, outlen))
      return ZIPY_ZIP_ERR;
    outbuf = zipy->inflate_out;
  }

  src = mapped;
  if (mapped && progress && progress->options && progress->options->progress) {
    uint64_t remaining;
    uint32_t produced = 0;

    ret = dec_finish(dec, fp);
    if (ret != ZIPY_ZIP_OK)
      goto done;

    if (!zipy->inflate_stream) {
      zipy->inflate_stream = infl_init(outbuf, (uint32_t)uncompressed_size, 0);
      if (!zipy->inflate_stream) {
        ret = ZIPY_ZIP_ERR;
        goto done;
      }
    } else {
      infl_reset(zipy->inflate_stream, outbuf, (uint32_t)uncompressed_size, 0);
    }

    remaining = compressed_size;
    zret = UNZ_UNFINISHED;
    while (remaining > 0) {
      size_t n = remaining > ZIP_INFLATE_STREAM_CHUNK
               ? ZIP_INFLATE_STREAM_CHUNK
               : (size_t)remaining;

      zret = infl_stream(zipy->inflate_stream, src, (uint32_t)n);
      if (zret < UNZ_OK) {
        ret = ZIPY_ZIP_EINFLATE;
        goto done;
      }
      {
        uint32_t now = infl_output_pos(zipy->inflate_stream);

        if (now < produced) {
          ret = ZIPY_ZIP_ESIZE;
          goto done;
        }
        ret = progress_advance(progress, (uint64_t)(now - produced));
        if (ret != ZIPY_ZIP_OK)
          goto done;
        produced = now;
      }
      if (zret == UNZ_OK && remaining != n) {
        ret = ZIPY_ZIP_ESIZE;
        goto done;
      }

      src += n;
      remaining -= n;
    }

    if (zret == UNZ_UNFINISHED)
      zret = infl_stream(zipy->inflate_stream, NULL, 0);
    if (zret != UNZ_OK) {
      ret = ZIPY_ZIP_EINFLATE;
      goto done;
    }
    {
      uint32_t now = infl_output_pos(zipy->inflate_stream);

      if (now < produced) {
        ret = ZIPY_ZIP_ESIZE;
        goto done;
      }
      ret = progress_advance(progress, (uint64_t)(now - produced));
      if (ret != ZIPY_ZIP_OK)
        goto done;
    }

    if (infl_output_pos(zipy->inflate_stream) != (uint32_t)uncompressed_size
        || infl_input_pos(zipy->inflate_stream) != (uint32_t)compressed_size) {
      ret = ZIPY_ZIP_ESIZE;
      goto done;
    }

    if (check_crc) {
      crc = crc32_update(0, outbuf, (size_t)uncompressed_size);
      if (crc != expectedCrc) {
        ret = ZIPY_ZIP_ECRC;
        goto done;
      }
    }

    if (!mapped_out && uncompressed_size > 0) {
      ret = write_file(out, outbuf, (size_t)uncompressed_size);
      if (ret != ZIPY_ZIP_OK)
        goto done;
    }

    ret = ZIPY_ZIP_OK;
    goto done;
  }

  if (!src) {
    if (!fp) {
      ret = ZIPY_ZIP_EFILE;
      goto done;
    }
    if (!reserve_bytes(&zipy->inflate_in, &zipy->inflate_in_cap, inlen)) {
      ret = ZIPY_ZIP_ERR;
      goto done;
    }
    inbuf = zipy->inflate_in;

    if (compressed_size > 0
        && fread(inbuf, 1, (size_t)compressed_size, fp) != (size_t)compressed_size) {
      ret = ZIPY_ZIP_EFILE;
      goto done;
    }
    if (dec && compressed_size > 0)
      dec_decrypt(dec, inbuf, (size_t)compressed_size);
    src = inbuf;
  }

  ret = dec_finish(dec, fp);
  if (ret != ZIPY_ZIP_OK)
    goto done;

  if (!zipy->inflate_stream) {
    zipy->inflate_stream = infl_init(outbuf, (uint32_t)uncompressed_size, 0);
    if (!zipy->inflate_stream) {
      ret = ZIPY_ZIP_ERR;
      goto done;
    }
  } else {
    infl_reset(zipy->inflate_stream, outbuf, (uint32_t)uncompressed_size, 0);
  }

  infl_include(zipy->inflate_stream, src, (uint32_t)compressed_size);
  if (infl(zipy->inflate_stream) != UNZ_OK) {
    ret = ZIPY_ZIP_EINFLATE;
    goto done;
  }

  if (check_crc) {
    crc = crc32_update(0, outbuf, (size_t)uncompressed_size);
    if (crc != expectedCrc) {
      ret = ZIPY_ZIP_ECRC;
      goto done;
    }
  }

  if (!mapped_out && uncompressed_size > 0) {
    ret = write_file(out, outbuf, (size_t)uncompressed_size);
    if (ret != ZIPY_ZIP_OK)
      goto done;
  }

  ret = progress_advance(progress, uncompressed_size);
  if (ret != ZIPY_ZIP_OK)
    goto done;

  ret = ZIPY_ZIP_OK;

done:
  unmap_output(&outmap);
  return ret;
}

static int
read_store_mem(FILE *fp,
                    uint64_t len,
                    uint32_t expectedCrc,
                    int check_crc,
                    dec_t *dec,
                    uint8_t **out,
                    size_t *out_len) {
  uint8_t *buf;
  size_t size;
  int ret;

  *out = NULL;
  *out_len = 0;

  if (!u64_to_size(len, &size) || size == SIZE_MAX)
    return ZIPY_ZIP_EUNSUP;

  buf = malloc(size + 1u);
  if (!buf)
    return ZIPY_ZIP_ERR;

  if (size > 0 && fread(buf, 1, size, fp) != size) {
    free(buf);
    return ZIPY_ZIP_EFILE;
  }

  if (dec && size > 0)
    dec_decrypt(dec, buf, size);

  ret = dec_finish(dec, fp);
  if (ret != ZIPY_ZIP_OK) {
    free(buf);
    return ret;
  }

  if (check_crc && crc32_update(0, buf, size) != expectedCrc) {
    free(buf);
    return ZIPY_ZIP_ECRC;
  }

  buf[size] = '\0';
  *out = buf;
  *out_len = size;
  return ZIPY_ZIP_OK;
}

static int
inflate_raw_mem(FILE *fp,
                     uint64_t compressed_size,
                     uint64_t uncompressed_size,
                     uint32_t expectedCrc,
                     int check_crc,
                     dec_t *dec,
                     uint8_t **out,
                     size_t *out_len) {
  uint8_t *inbuf = NULL;
  uint8_t *outbuf = NULL;
  size_t inlen, outlen;
  int ret;

  *out = NULL;
  *out_len = 0;

  if (compressed_size > UINT32_MAX || uncompressed_size > UINT32_MAX)
    return ZIPY_ZIP_EUNSUP;
  if (!u64_to_size(compressed_size, &inlen)
      || !u64_to_size(uncompressed_size, &outlen)
      || outlen == SIZE_MAX)
    return ZIPY_ZIP_EUNSUP;

  inbuf = malloc(inlen > 0 ? inlen : 1u);
  outbuf = malloc(outlen + 1u);
  if (!inbuf || !outbuf) {
    ret = ZIPY_ZIP_ERR;
    goto done;
  }

  if (inlen > 0 && fread(inbuf, 1, inlen, fp) != inlen) {
    ret = ZIPY_ZIP_EFILE;
    goto done;
  }

  if (dec && inlen > 0)
    dec_decrypt(dec, inbuf, inlen);

  ret = dec_finish(dec, fp);
  if (ret != ZIPY_ZIP_OK)
    goto done;

  if (infl_buf(inbuf,
               (uint32_t)compressed_size,
               outbuf,
               (uint32_t)uncompressed_size,
               0) != UNZ_OK) {
    ret = ZIPY_ZIP_EINFLATE;
    goto done;
  }

  if (check_crc && crc32_update(0, outbuf, outlen) != expectedCrc) {
    ret = ZIPY_ZIP_ECRC;
    goto done;
  }

  outbuf[outlen] = '\0';
  *out = outbuf;
  *out_len = outlen;
  outbuf = NULL;
  ret = ZIPY_ZIP_OK;

done:
  free(outbuf);
  free(inbuf);
  return ret;
}

static int
create_symlink(const char *destpath,
                    const uint8_t *target,
                    size_t target_len,
                    const entry_info_t *info,
                    int apply_metadata) {
#if defined(_WIN32)
  (void)destpath;
  (void)target;
  (void)target_len;
  (void)info;
  (void)apply_metadata;
  return ZIPY_ZIP_EUNSUP;
#else
  if (!target || target_len == 0 || memchr(target, '\0', target_len))
    return ZIPY_ZIP_EFILE;
  if (parent_has_symlink(destpath))
    return ZIPY_ZIP_EFILE;
  if (!mkdir_parent(destpath))
    return ZIPY_ZIP_EFILE;

  if (symlink((const char *)target, destpath) != 0) {
    if (errno != EEXIST || unlink(destpath) != 0
        || symlink((const char *)target, destpath) != 0)
      return ZIPY_ZIP_EFILE;
  }

  if (apply_metadata && !apply_entry_metadata(destpath, info))
    return ZIPY_ZIP_EFILE;
  return ZIPY_ZIP_OK;
#endif
}

static char *
extract_path_len(const char *dir, const char *name, size_t nameLen) {
  size_t dirLen, i;
  char *path;

  if (!dir || !name)
    return NULL;

  dirLen = strlen(dir);
  path = malloc(dirLen + nameLen + 2);
  if (!path)
    return NULL;

  memcpy(path, dir, dirLen);
  if (dirLen > 0 && !is_fs_sep(dir[dirLen - 1]))
    path[dirLen++] = '/';

  if (memchr(name, '\\', nameLen)) {
    for (i = 0; i < nameLen; i++)
      path[dirLen + i] = is_zip_sep(name[i]) ? '/' : name[i];
  } else {
    memcpy(path + dirLen, name, nameLen);
  }
  path[dirLen + nameLen] = '\0';

  return path;
}

static char *
extract_path(const char *dir, const char *name) {
  return extract_path_len(dir, name, strlen(name));
}

static int
path_buf_set_dir(path_buf_t * __restrict buf,
                      const char * __restrict dir,
                      size_t * __restrict prefixLen) {
  size_t dirLen;

  if (!buf || !dir || !prefixLen)
    return 0;

  dirLen = strlen(dir);
  if (dirLen > SIZE_MAX - 2u)
    return 0;
  if (!path_buf_reserve(buf, dirLen + 2u))
    return 0;

  memcpy(buf->data, dir, dirLen);
  if (dirLen > 0 && !is_fs_sep(dir[dirLen - 1]))
    buf->data[dirLen++] = '/';
  buf->data[dirLen] = '\0';
  *prefixLen = dirLen;

  return 1;
}

static int
path_buf_set_archive_dir(zipy_archive_t * __restrict zipy,
                              const char * __restrict dir,
                              size_t * __restrict prefixLen) {
  size_t dirLen;

  if (!zipy || !dir || !prefixLen)
    return 0;

  dirLen = strlen(dir);
  if (zipy->path_prefix_valid
      && zipy->path_prefix_dir_len == dirLen
      && zipy->path_buf.data
      && memcmp(zipy->path_buf.data, dir, dirLen) == 0) {
    *prefixLen = zipy->path_prefix_len;
    return 1;
  }

  if (!path_buf_set_dir(&zipy->path_buf, dir, prefixLen))
    return 0;

  zipy->path_prefix_dir_len = dirLen;
  zipy->path_prefix_len = *prefixLen;
  zipy->path_prefix_valid = 1;
  return 1;
}

static const char *
path_buf_append_name(path_buf_t * __restrict buf,
                          size_t prefixLen,
                          const char * __restrict name,
                          size_t nameLen,
                          int nameHasBackslash) {
  size_t i;

  if (!buf || !buf->data || !name)
    return NULL;
  if (prefixLen > SIZE_MAX - nameLen - 1u)
    return NULL;
  if (!path_buf_reserve(buf, prefixLen + nameLen + 1u))
    return NULL;

  if (nameHasBackslash) {
    for (i = 0; i < nameLen; i++)
      buf->data[prefixLen + i] = is_zip_sep(name[i]) ? '/' : name[i];
  } else {
    memcpy(buf->data + prefixLen, name, nameLen);
  }
  buf->data[prefixLen + nameLen] = '\0';

  return buf->data;
}

static const char *
path_buf_set_suffix(path_buf_t * __restrict buf,
                    const char * __restrict path,
                    const char * __restrict suffix) {
  size_t pathLen, suffixLen;

  if (!buf || !path || !suffix)
    return NULL;

  pathLen = strlen(path);
  suffixLen = strlen(suffix);
  if (pathLen > SIZE_MAX - suffixLen - 1u)
    return NULL;
  if (!path_buf_reserve(buf, pathLen + suffixLen + 1u))
    return NULL;

  memcpy(buf->data, path, pathLen);
  memcpy(buf->data + pathLen, suffix, suffixLen + 1u);
  return buf->data;
}

static const char *
path_buf_append_suffix(path_buf_t * __restrict buf,
                       const char * __restrict suffix) {
  size_t len, suffixLen;

  if (!buf || !buf->data || !suffix)
    return NULL;

  len = strlen(buf->data);
  suffixLen = strlen(suffix);
  if (len > SIZE_MAX - suffixLen - 1u)
    return NULL;
  if (!path_buf_reserve(buf, len + suffixLen + 1u))
    return NULL;

  memcpy(buf->data + len, suffix, suffixLen + 1u);
  return buf->data;
}

static size_t
extract_parent_len(const entry_info_t * __restrict info,
                        size_t prefixLen) {
  if (info && info->name_parent_len > 0)
    return prefixLen + info->name_parent_len;
  return prefixLen > 1u ? prefixLen - 1u : prefixLen;
}

static char *
join_path(const char *dir, const char *name) {
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
  if (dirLen > 0 && !is_fs_sep(dir[dirLen - 1]))
    path[dirLen++] = PATH_SEP;
  memcpy(path + dirLen, name, nameLen + 1);
  return path;
}

static int
is_abs_path(const char *path) {
  if (!path || !*path)
    return 0;

#if defined(_WIN32)
  if (isalpha((unsigned char)path[0]) && path[1] == ':')
    return 1;
#endif

  return is_fs_sep(path[0]);
}

static char *
abs_path(const char *path) {
  char cwd[PATH_MAX];

  if (!path)
    return NULL;

  if (is_abs_path(path))
    return dup_text(path);

  if (!os_getcwd(cwd, sizeof(cwd)))
    return dup_text(path);

  return join_path(cwd, path);
}

static char *
trim_trailing_seps(const char *path) {
  char *out;
  size_t len;

  if (!path)
    return NULL;

  len = strlen(path);
  while (len > 1 && is_fs_sep(path[len - 1])) {
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
home_dir(void) {
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
trash_dir(void) {
  const char *home = home_dir();

  if (!home)
    return NULL;

#if defined(_WIN32)
  return join_path(home, "AppData\\Local\\Microsoft\\Windows\\Recycle Bin");
#elif defined(__APPLE__)
  return join_path(home, ".Trash");
#else
  return join_path(home, ".local/share/Trash/files");
#endif
}

static void
saved_name(char *buf, size_t len) {
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
create_save_dir(const char *destdir, zipy_save_location_t save_to) {
  char name[64], numbered[96];
  const char *base = destdir;
  char *ownedBase = NULL;
  char *path = NULL;
  unsigned i;

  if (save_to == ZIPY_SAVE_HOME) {
    base = home_dir();
  } else if (save_to == ZIPY_SAVE_TRASH) {
    ownedBase = trash_dir();
    base = ownedBase;
  }

  if (!base || !*base)
    goto done;

  if (!mkdirs(base))
    goto done;

  saved_name(name, sizeof(name));
  for (i = 0; i < 1000; i++) {
    free(path);
    if (i == 0) {
      path = join_path(base, name);
    } else {
      snprintf(numbered, sizeof(numbered), "%s %u", name, i + 1);
      path = join_path(base, numbered);
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
append_saved_manifest(const char *save_dir,
                           const char *savedRelativePath,
                           const char *originalPath) {
  char *manifest;
  FILE *fp;
  size_t len, i;

  manifest = join_path(save_dir, "zipy_saved_original_paths.txt");
  if (!manifest)
    return 0;

  len = strlen(savedRelativePath);
  while (len > 0 && is_zip_sep(savedRelativePath[len - 1]))
    len--;

  fp = fopen(manifest, "ab");
  free(manifest);
  if (!fp)
    return 0;

  for (i = 0; i < len; i++)
    fputc(is_zip_sep(savedRelativePath[i]) ? '/' : savedRelativePath[i], fp);
  fprintf(fp, " -> %s\n", originalPath);
  if (fclose(fp) != 0)
    return 0;

  return 1;
}

static zipy_extract_options_t
default_extract_options(const zipy_extract_options_t *options) {
  zipy_extract_options_t out;

  out.on_conflict = ZIPY_CONFLICT_SAVE;
  out.save_to = ZIPY_SAVE_TARGET;
  out.save_dir = NULL;
  out.flags = ZIPY_EXTRACT_DEFAULT;
  out.password = NULL;
  out.jobs = 0;
  out.progress = NULL;
  out.userdata = NULL;

  if (!options)
    return out;

  out = *options;
  if (out.on_conflict < ZIPY_CONFLICT_SAVE
      || out.on_conflict > ZIPY_CONFLICT_FAIL)
    out.on_conflict = ZIPY_CONFLICT_SAVE;
  if (out.save_to < ZIPY_SAVE_TARGET || out.save_to > ZIPY_SAVE_TRASH)
    out.save_to = ZIPY_SAVE_TARGET;
  out.flags &= ZIPY_EXTRACT_NO_CRC
             | ZIPY_EXTRACT_NO_METADATA
             | ZIPY_EXTRACT_ATOMIC
             | ZIPY_EXTRACT_RESUME;
  if (out.flags & ZIPY_EXTRACT_RESUME)
    out.on_conflict = ZIPY_CONFLICT_OVERWRITE;

  return out;
}

ZIPY_EXPORT
void
zipy_extract_options_init(zipy_extract_options_t * __restrict options) {
  if (options)
    *options = default_extract_options(NULL);
}

static uint64_t
entry_progress_size(const entry_info_t *info) {
  if (!info || info->entry.is_directory)
    return 0;
  return info->entry.uncompressed_size;
}

static int
report_progress(const zipy_extract_options_t *options,
                const zipy_entry_t *entry,
                uint64_t done,
                uint64_t total) {
  if (!options || !options->progress)
    return ZIPY_ZIP_OK;
  return options->progress(options->userdata, entry, done, total)
       ? ZIPY_ZIP_OK
       : ZIPY_ZIP_ECANCEL;
}

static int
progress_advance(progress_state_t *progress, uint64_t amount) {
  const zipy_extract_options_t *options;
  uint64_t done;
  uint64_t total;
  int ret;

  if (!progress
      || !progress->options
      || !progress->options->progress
      || amount == 0)
    return ZIPY_ZIP_OK;

  if (progress->lock)
    mutex_lock(progress->lock);

  if (UINT64_MAX - progress->entry_done < amount)
    progress->entry_done = UINT64_MAX;
  else
    progress->entry_done += amount;

  if (progress->done) {
    if (UINT64_MAX - *progress->done < amount)
      *progress->done = UINT64_MAX;
    else
      *progress->done += amount;
    done = *progress->done;
  } else {
    done = progress->entry_done;
  }
  total = progress->total;
  options = progress->options;

  ret = report_progress(options, progress->entry, done, total);
  if (ret < ZIPY_ZIP_OK && progress->result && *progress->result == ZIPY_ZIP_OK)
    *progress->result = ret;

  if (progress->lock)
    mutex_unlock(progress->lock);

  return ret;
}

static int
progress_finish_entry(progress_state_t *progress,
                      const entry_info_t *info) {
  uint64_t size;

  if (!progress
      || !progress->options
      || !progress->options->progress
      || !info
      || info->entry.is_directory)
    return ZIPY_ZIP_OK;

  size = entry_progress_size(info);
  if (size <= progress->entry_done)
    return ZIPY_ZIP_OK;

  return progress_advance(progress, size - progress->entry_done);
}

static void
progress_init_entry(progress_state_t *progress,
                    const zipy_extract_options_t *options,
                    const zipy_entry_t *entry,
                    uint64_t *done,
                    uint64_t total,
                    mutex_handle_t *lock,
                    int *result) {
  memset(progress, 0, sizeof(*progress));
  if (!options || !options->progress || !entry || entry->is_directory)
    return;

  progress->options = options;
  progress->entry = entry;
  progress->done = done;
  progress->total = total;
  progress->lock = lock;
  progress->result = result;
}

static int
prepare_conflict(const char *destdir,
                      const zipy_entry_t *entry,
                      const char *destpath,
                      const zipy_extract_options_t *options,
                      char **save_dir) {
  int exists, isDir;
  char *savePath = NULL;
  char *cleanDestPath = NULL;
  char *cleanSavePath = NULL;
  char *originalAbs = NULL;
  int ret = ZIPY_ZIP_OK;

  cleanDestPath = trim_trailing_seps(destpath);
  if (!cleanDestPath)
    return ZIPY_ZIP_ERR;

  if (!path_info(cleanDestPath, &exists, &isDir)) {
    ret = ZIPY_ZIP_EFILE;
    goto done;
  }
  if (!exists) {
    ret = ZIPY_ZIP_OK;
    goto done;
  }
  if (entry->is_directory && isDir) {
    ret = ZIPY_ZIP_OK;
    goto done;
  }

  if (options->on_conflict == ZIPY_CONFLICT_OVERWRITE) {
    ret = ZIPY_ZIP_OK;
    goto done;
  }
  if (options->on_conflict == ZIPY_CONFLICT_SKIP) {
    ret = ZIPY_ZIP_SKIPPED;
    goto done;
  }
  if (options->on_conflict == ZIPY_CONFLICT_FAIL) {
    ret = ZIPY_ZIP_EEXIST;
    goto done;
  }

  if (!*save_dir) {
    if (options->save_dir) {
      *save_dir = dup_text(options->save_dir);
      if (*save_dir && !mkdirs(*save_dir)) {
        free(*save_dir);
        *save_dir = NULL;
      }
    } else {
      *save_dir = create_save_dir(destdir, options->save_to);
    }
  }
  if (!*save_dir) {
    ret = ZIPY_ZIP_EFILE;
    goto done;
  }

  savePath = extract_path_len(*save_dir, entry->name, entry->name_len);
  if (!savePath) {
    ret = ZIPY_ZIP_ERR;
    goto done;
  }

  cleanSavePath = trim_trailing_seps(savePath);
  if (!cleanSavePath) {
    ret = ZIPY_ZIP_ERR;
    goto done;
  }
  if (!mkdir_parent(cleanSavePath)) {
    ret = ZIPY_ZIP_EFILE;
    goto done;
  }

  originalAbs = abs_path(cleanDestPath);
  if (rename(cleanDestPath, cleanSavePath) != 0) {
    int nowExists, nowIsDir;

    if (path_info(cleanDestPath, &nowExists, &nowIsDir)
        && (!nowExists || (entry->is_directory && nowIsDir))) {
      ret = ZIPY_ZIP_OK;
      goto done;
    }

    ret = ZIPY_ZIP_EFILE;
    goto done;
  }

  if (!originalAbs
      || !append_saved_manifest(*save_dir, entry->name, originalAbs)) {
    ret = ZIPY_ZIP_EFILE;
    goto done;
  }

  ret = ZIPY_ZIP_SAVED;

done:
  free(originalAbs);
  free(cleanSavePath);
  free(cleanDestPath);
  free(savePath);
  return ret;
}

static int
prepare_parent_conflicts(const char *destdir,
                              const zipy_entry_t *entry,
                              const zipy_extract_options_t *options,
                              char **save_dir) {
  zipy_entry_t parentEntry;
  char *rel = NULL;
  char *path = NULL;
  size_t len, i, j;
  int result = ZIPY_ZIP_OK;

  if (!entry || !entry->name)
    return ZIPY_ZIP_ERR;

  len = entry->name_len;
  rel = malloc(len + 1);
  if (!rel)
    return ZIPY_ZIP_ERR;

  parentEntry = *entry;
  parentEntry.name = rel;
  parentEntry.is_directory = false;

  for (i = 0; i < len; i++) {
    int exists, isDir;

    if (!is_zip_sep(entry->name[i]) || i == 0)
      continue;

    for (j = 0; j < i; j++)
      rel[j] = is_zip_sep(entry->name[j]) ? '/' : entry->name[j];
    rel[i] = '\0';

    free(path);
    path = extract_path(destdir, rel);
    if (!path) {
      result = ZIPY_ZIP_ERR;
      break;
    }

    if (!path_info(path, &exists, &isDir)) {
      result = ZIPY_ZIP_EFILE;
      break;
    }

    if (!exists || isDir)
      continue;

    result = prepare_conflict(destdir,
                                   &parentEntry,
                                   path,
                                   options,
                                   save_dir);
    if (result != ZIPY_ZIP_OK && result != ZIPY_ZIP_SAVED)
      break;
  }

  free(path);
  free(rel);
  return result;
}

static int
prepare_entry_conflict(const char *destdir,
                            const zipy_entry_t *entry,
                            const char *destpath,
                            const zipy_extract_options_t *options,
                            char **save_dir) {
  int parentRet, ret;

  if (options->on_conflict == ZIPY_CONFLICT_OVERWRITE)
    return ZIPY_ZIP_OK;

  parentRet = prepare_parent_conflicts(destdir, entry, options, save_dir);
  if (parentRet != ZIPY_ZIP_OK && parentRet != ZIPY_ZIP_SAVED)
    return parentRet;

  ret = prepare_conflict(destdir, entry, destpath, options, save_dir);
  if (ret == ZIPY_ZIP_OK && parentRet == ZIPY_ZIP_SAVED)
    return ZIPY_ZIP_SAVED;

  return ret;
}

ZIPY_EXPORT
zipy_archive_t *
zipy_open(const char * __restrict path) {
  zipy_archive_t *zipy = NULL;
  dir_info_t dir;
  FILE *fp;
  uint8_t extra_stack[512];
  uint8_t *extra_buf = NULL;
  size_t extra_cap = 0;
  const uint8_t *central;
  size_t cd_pos = 0;
  size_t i, count;

  if (!path || !(fp = fopen(path, "rb")))
    return NULL;

  zipy = calloc(1, sizeof(*zipy));
  if (!zipy)
    goto err;

  zipy->fp = fp;
  zipy->path = dup_text(path);
  if (!zipy->path)
    goto err;

  if (get_file_size(fp, &zipy->file_size) != 0)
    goto err;
  map_archive(zipy);

  if (zipy->map) {
    if (!find_eocd_mapped(zipy->map, zipy->file_size, &dir))
      goto err;
  } else if (!find_eocd(fp, &dir)) {
    goto err;
  } else {
    zipy->file_size = dir.file_size;
  }

  if (!u64_to_size(dir.entries, &count))
    goto err;

  zipy->file_count = count;
  central = mapped_range(zipy, dir.central_dir_offset, dir.central_dir_size);
  if (central
      && !prealloc_name_slab(zipy, central, (size_t)dir.central_dir_size, count))
    goto err;

  if (count > 0) {
    zipy->files = calloc(count, sizeof(*zipy->files));
    if (!zipy->files)
      goto err;
    zipy->owns_files = 1;
  }

  if (!central && seek_set(fp, dir.central_dir_offset) != 0)
    goto err;

  for (i = 0; i < count; i++) {
    uint8_t hdr[ZIP_CENTRAL_FIXED];
    const uint8_t *hdrp;
    const uint8_t *name_src = NULL;
    const uint8_t *extra = NULL;
    entry_info_t *info = &zipy->files[i];
    uint16_t nameLen, extraLen, commentLen, diskStart;
    uint32_t comp32, uncomp32, offset32;
    size_t record_len;

    if (central) {
      if (cd_pos > dir.central_dir_size
          || dir.central_dir_size - cd_pos < ZIP_CENTRAL_FIXED)
        goto err;
      hdrp = central + cd_pos;
    } else {
      if (!read_exact(fp, hdr, sizeof(hdr)))
        goto err;
      hdrp = hdr;
    }

    if (le32(hdrp) != ZIP_SIGN_CENTRAL_DIR)
      goto err;

    info->flags = le16(hdrp + 8);
    info->entry.method = le16(hdrp + 10);
    info->mod_time = le16(hdrp + 12);
    info->mod_date = le16(hdrp + 14);
    info->entry.crc32 = le32(hdrp + 16);
    comp32 = le32(hdrp + 20);
    uncomp32 = le32(hdrp + 24);
    nameLen = le16(hdrp + 28);
    extraLen = le16(hdrp + 30);
    commentLen = le16(hdrp + 32);
    diskStart = le16(hdrp + 34);
    info->external_attr = le32(hdrp + 38);
    info->unix_mode = info->external_attr >> 16;
#if !defined(_WIN32) && defined(S_IFLNK)
    info->is_symlink = (info->unix_mode & S_IFMT) == S_IFLNK;
#endif
    offset32 = le32(hdrp + 42);

    if (nameLen == 0
        || (diskStart != 0 && diskStart != ZIP64_MAGIC_UINT16))
      goto err;

    record_len = ZIP_CENTRAL_FIXED
               + (size_t)nameLen
               + (size_t)extraLen
               + (size_t)commentLen;
    if (central) {
      if (record_len > dir.central_dir_size - cd_pos)
        goto err;
      name_src = central + cd_pos + ZIP_CENTRAL_FIXED;
      extra = name_src + nameLen;
    }

    char *name = alloc_name(zipy, (size_t)nameLen + 1u);

    if (!name)
      goto err;
    if (central) {
      memcpy(name, name_src, nameLen);
    } else if (!read_exact(fp, name, nameLen)) {
      goto err;
    }
    name[nameLen] = '\0';
    info->entry.name = name;
    info->entry.name_len = nameLen;
    if (!scan_member_name(name,
                               nameLen,
                               &info->safe_name,
                               &info->name_has_backslash,
                               &info->name_parent_len))
      goto err;
    if (has_root_zipy_segment(name, nameLen))
      zipy->has_root_zipy = 1;

    info->zip_method = info->entry.method;
    info->entry.compressed_size = comp32;
    info->entry.uncompressed_size = uncomp32;
    info->local_header_offset = offset32;
    info->entry.is_directory = is_dir_name_len(info->entry.name,
                                                    info->entry.name_len);
    info->entry.encrypted = (info->flags & ZIP_FLAG_ENCRYPTED) != 0;
    if (info->entry.encrypted)
      zipy->has_encrypted = 1;
    if (info->is_symlink)
      zipy->has_symlink = 1;
    info->mtime = dos_time(info->mod_date, info->mod_time);
    info->has_mtime = info->mtime != (time_t)0;

    if (extraLen > 0) {
      if (!central) {
        if (extraLen <= sizeof(extra_stack)) {
          extra = extra_stack;
        } else {
          if (extraLen > extra_cap) {
            uint8_t *new_extra = realloc(extra_buf, extraLen);
            if (!new_extra)
              goto err;
            extra_buf = new_extra;
            extra_cap = extraLen;
          }
          extra = extra_buf;
        }

        if (!extra || !read_exact(fp, (void *)extra, extraLen))
          goto err;
      }

      if (!parse_zip64_extra(info, extra, extraLen,
                                 comp32, uncomp32, offset32, diskStart))
        goto err;
      if (!parse_aes_extra(info, extra, extraLen))
        goto err;
      if (!parse_ext_time_extra(info, extra, extraLen))
        goto err;
    } else if (comp32 == ZIP64_MAGIC_UINT32
               || uncomp32 == ZIP64_MAGIC_UINT32
               || offset32 == ZIP64_MAGIC_UINT32) {
      goto err;
    }

    if (info->zip_method == ZIP_METHOD_AES) {
      if (!info->entry.encrypted || info->aes_strength == 0)
        goto err;
    } else if (info->aes_strength != 0) {
      goto err;
    }
    if (!info->entry.is_directory
        && info->entry.method != ZIPY_ZIP_STORE
        && info->entry.method != ZIPY_ZIP_DEFLATE) {
      zipy->has_unsupported_method = 1;
      if (zipy->unsupported_method == 0)
        zipy->unsupported_method = info->entry.method;
    }

    record_extract_metrics(zipy, info);

    if (info->local_header_offset >= dir.central_dir_offset
        || info->entry.compressed_size > zipy->file_size
        || UINT64_MAX - info->local_header_offset < ZIP_LOCAL_FIXED)
      goto err;
    cache_local_header(zipy, info);

    if (central) {
      cd_pos += record_len;
    } else if (commentLen > 0 && skip_bytes(fp, commentLen) != 0) {
      goto err;
    }
  }

  if (central && cd_pos != dir.central_dir_size)
    goto err;

  free(extra_buf);
  return zipy;

err:
  free(extra_buf);
  if (zipy) {
    archive_cleanup(zipy);
    free(zipy);
  } else {
    fclose(fp);
  }
  return NULL;
}

static int
clone_init(zipy_archive_t * __restrict clone,
                zipy_archive_t * __restrict zipy) {
  int needs_fp;

  if (!clone || !zipy)
    return 0;
  memset(clone, 0, sizeof(*clone));

  needs_fp = !zipy->map || zipy->has_encrypted || zipy->has_symlink;
  if (needs_fp && (!zipy->path || !zipy->fp))
    return 0;

  if (needs_fp) {
    clone->fp = fopen(zipy->path, "rb");
    if (!clone->fp)
      goto err;
  }

  clone->files = zipy->files;
  clone->file_count = zipy->file_count;
  clone->extract_file_count = zipy->extract_file_count;
  clone->extract_work_file_count = zipy->extract_work_file_count;
  clone->directory_count = zipy->directory_count;
  clone->extract_work_size = zipy->extract_work_size;
  clone->extract_uncompressed_size = zipy->extract_uncompressed_size;
  clone->file_size = zipy->file_size;
  clone->owns_files = 0;
  clone->has_encrypted = zipy->has_encrypted;
  clone->has_symlink = zipy->has_symlink;
  clone->has_unsupported_method = zipy->has_unsupported_method;
  clone->has_root_zipy = zipy->has_root_zipy;
  clone->unsupported_method = zipy->unsupported_method;

  if (zipy->map) {
    clone->map = zipy->map;
    clone->map_size = zipy->map_size;
    clone->owns_map = 0;
  } else {
    map_archive(clone);
  }

  return 1;

err:
  archive_cleanup(clone);
  return 0;
}

zipy_archive_t *
archive_clone(zipy_archive_t * __restrict zipy) {
  zipy_archive_t *clone;

  clone = malloc(sizeof(*clone));
  if (!clone)
    return NULL;
  if (!clone_init(clone, zipy)) {
    free(clone);
    return NULL;
  }

  return clone;
}

int
archive_has_unsupported_method(const zipy_archive_t * __restrict zipy) {
  return zipy && zipy->has_unsupported_method;
}

uint16_t
archive_unsupported_method(const zipy_archive_t * __restrict zipy) {
  return zipy ? zipy->unsupported_method : 0u;
}

static int
extract_store_data_descriptor(zipy_archive_t * __restrict zipy,
                              entry_info_t * __restrict info,
                              const char * __restrict destpath,
                              size_t parent_len,
                              uint32_t extract_flags,
                              int zip64_descriptor,
                              const char * __restrict state_path,
                              const char * __restrict part_destdir,
                              progress_state_t * __restrict progress) {
  out_file_t outfile;
  uint8_t *buf;
  const char *part_path = NULL;
  uint8_t tail[15];
  size_t tail_len = 0;
  uint64_t base_len = 0;
  uint64_t resume_offset = 0;
  uint64_t remaining;
  size_t keep_tail = 15u;
  uint32_t crc = 0;
  uint32_t resume_crc = 0;
  int apply_metadata = (extract_flags & ZIPY_EXTRACT_NO_METADATA) == 0;
  int keep_part = (extract_flags & ZIPY_EXTRACT_RESUME) != 0;
  int metadata_done = 0;
  int ret = ZIPY_ZIP_ERR;

  memset(&outfile, 0, sizeof(outfile));
#if !defined(_WIN32)
  outfile.fd = -1;
#endif

  if (!zipy || !zipy->fp || !info || !destpath)
    return ZIPY_ZIP_ERR;
  if (zip64_descriptor
      || info->entry.encrypted
      || info->entry.method != ZIPY_ZIP_STORE)
    return ZIPY_ZIP_EUNSUP;
  if (info->data_offset > zipy->file_size)
    return ZIPY_ZIP_ESIZE;
  if (!reserve_bytes(&zipy->copy_buf, &zipy->copy_cap, ZIP_IO_CHUNK + keep_tail))
    return ZIPY_ZIP_ERR;
  buf = zipy->copy_buf;

  if (parent_len == SIZE_MAX) {
    if (!prepare_parent_dir(zipy, destpath))
      return ZIPY_ZIP_EFILE;
  } else if (!prepare_parent_dir_len(zipy, destpath, parent_len)) {
    return ZIPY_ZIP_EFILE;
  }

  part_path = keep_part && part_destdir
            ? resume_part_path(zipy, part_destdir, info)
            : path_buf_set_suffix(&zipy->part_buf, destpath, ".part");
  if (!part_path)
    return ZIPY_ZIP_ERR;
  if (!prepare_parent_dir(zipy, part_path))
    return ZIPY_ZIP_EFILE;

  if (keep_part) {
    int part_exists = 0;
    uint64_t part_size = 0;

    if (!regular_file_size(part_path, &part_exists, &part_size))
      return ZIPY_ZIP_EFILE;
    if (part_exists && part_size > 0) {
      if (part_size > zipy->file_size - info->data_offset) {
        remove_file(part_path);
      } else {
        ret = crc32_file_prefix(zipy, part_path, part_size, &resume_crc);
        if (ret != ZIPY_ZIP_OK)
          return ret;
        resume_offset = part_size;
        base_len = part_size;
        crc = resume_crc;
      }
    }
  } else {
    remove_file(part_path);
  }

  write_resume_state(state_path,
                     zipy,
                     info,
                     destpath,
                     part_path,
                     resume_offset,
                     extract_flags,
                     "extracting");

  if (!open_output_file_seek(part_path,
                             &outfile,
                             &ret,
                             resume_offset,
                             resume_offset == 0))
    return ret;
  if (seek_set(zipy->fp, info->data_offset + resume_offset) != 0) {
    ret = ZIPY_ZIP_EFILE;
    goto done;
  }

  remaining = zipy->file_size - info->data_offset - resume_offset;
  while (remaining > 0) {
    uint64_t read_end;
    size_t n = remaining > ZIP_IO_CHUNK ? ZIP_IO_CHUNK : (size_t)remaining;
    size_t scan_len;
    size_t i;

    if (tail_len > 0)
      memcpy(buf, tail, tail_len);
    if (fread(buf + tail_len, 1, n, zipy->fp) != n) {
      ret = ZIPY_ZIP_EFILE;
      goto done;
    }
    if (tell_pos(zipy->fp, &read_end) != 0) {
      ret = ZIPY_ZIP_EFILE;
      goto done;
    }

    remaining -= n;
    scan_len = tail_len + n;
    i = 0;
    while (i + 4u <= scan_len) {
      uint8_t *hit;
      uint32_t sig;

      hit = memchr(buf + i, 0x50, scan_len - 3u - i);
      if (!hit)
        break;

      i = (size_t)(hit - buf);
      sig = le32(buf + i);
      if (sig == ZIP_SIGN_DATA_DESC) {
        uint32_t candidate_crc = crc32_update(crc, buf, i);
        uint64_t data_len = base_len + i;
        uint64_t descriptor_offset = info->data_offset + data_len;

        ret = match_signed_store_descriptor(zipy,
                                            info,
                                            descriptor_offset,
                                            data_len,
                                            candidate_crc,
                                            zip64_descriptor);
        if (ret == ZIPY_ZIP_OK) {
          if (i > 0) {
            ret = write_file(&outfile, buf, i);
            if (ret != ZIPY_ZIP_OK)
              goto done;
            ret = progress_advance(progress, i);
            if (ret != ZIPY_ZIP_OK)
              goto done;
          }
          crc = candidate_crc;
          base_len = data_len;
          goto found;
        }
        if (ret < ZIPY_ZIP_OK)
          goto done;
      }
      if (is_record_signature(sig) && i >= keep_tail - 3u) {
        size_t data_in_buf = i - (keep_tail - 3u);
        uint32_t candidate_crc = crc32_update(crc, buf, data_in_buf);
        uint64_t data_len = base_len + data_in_buf;
        uint64_t descriptor_offset = info->data_offset + data_len;

        ret = match_unsigned_store_descriptor(zipy,
                                              info,
                                              descriptor_offset,
                                              data_len,
                                              candidate_crc,
                                              zip64_descriptor);
        if (ret == ZIPY_ZIP_OK) {
          if (data_in_buf > 0) {
            ret = write_file(&outfile, buf, data_in_buf);
            if (ret != ZIPY_ZIP_OK)
              goto done;
            ret = progress_advance(progress, data_in_buf);
            if (ret != ZIPY_ZIP_OK)
              goto done;
          }
          crc = candidate_crc;
          base_len = data_len;
          goto found;
        }
        if (ret < ZIPY_ZIP_OK)
          goto done;
      }

      i++;
    }

    if (scan_len > keep_tail) {
      size_t flush_len = scan_len - keep_tail;

      ret = write_file(&outfile, buf, flush_len);
      if (ret != ZIPY_ZIP_OK)
        goto done;
      ret = progress_advance(progress, flush_len);
      if (ret != ZIPY_ZIP_OK)
        goto done;
      crc = crc32_update(crc, buf, flush_len);
      base_len += flush_len;
      memcpy(tail, buf + flush_len, keep_tail);
      tail_len = keep_tail;
    } else {
      memcpy(tail, buf, scan_len);
      tail_len = scan_len;
    }

    if (seek_set(zipy->fp, read_end) != 0) {
      ret = ZIPY_ZIP_EFILE;
      goto done;
    }
  }

  ret = ZIPY_ZIP_EINCOMPLETE;
  goto done;

found:
  if (crc != info->entry.crc32
      || base_len != info->entry.uncompressed_size
      || base_len != info->entry.compressed_size) {
    ret = ZIPY_ZIP_ECRC;
    goto done;
  }
  if (!flush_output(&outfile)) {
    ret = ZIPY_ZIP_EFILE;
    goto done;
  }
  if (apply_metadata)
    metadata_done = apply_open_file_metadata(&outfile, info);
  if (!close_output_file(&outfile)) {
    ret = ZIPY_ZIP_EFILE;
  }
#if defined(_WIN32)
  outfile.fp = NULL;
#else
  outfile.fd = -1;
#endif
  if (ret != ZIPY_ZIP_OK)
    goto done;
  if (apply_metadata
      && !metadata_done
      && !apply_entry_metadata(part_path, info)) {
    ret = ZIPY_ZIP_EFILE;
    goto done;
  }
  if (!replace_file(part_path, destpath)) {
    ret = ZIPY_ZIP_EFILE;
    goto done;
  }

  ret = ZIPY_ZIP_OK;

done:
#if defined(_WIN32)
  if (outfile.fp) {
    if (!close_output_file(&outfile) && ret == ZIPY_ZIP_OK)
      ret = ZIPY_ZIP_EFILE;
    outfile.fp = NULL;
  }
#else
  if (outfile.fd >= 0) {
    if (!close_output_file(&outfile) && ret == ZIPY_ZIP_OK)
      ret = ZIPY_ZIP_EFILE;
    outfile.fd = -1;
  }
#endif
  write_resume_state(state_path,
                     zipy,
                     info,
                     destpath,
                     part_path,
                     base_len,
                     extract_flags,
                     ret == ZIPY_ZIP_OK ? "done"
                   : ret == ZIPY_ZIP_EINCOMPLETE ? "incomplete"
                   : "failed");
  if (ret != ZIPY_ZIP_OK && (!keep_part || ret != ZIPY_ZIP_EINCOMPLETE))
    remove_file(part_path);
  if (ret == ZIPY_ZIP_OK && keep_part && part_destdir)
    cleanup_empty_parts_dirs(zipy, part_destdir, part_path);
  return ret;
}

static int
extract_deflate_data_descriptor(zipy_archive_t * __restrict zipy,
                                entry_info_t * __restrict info,
                                const char * __restrict destpath,
                                size_t parent_len,
                                uint32_t extract_flags,
                                const char * __restrict password,
                                int zip64_descriptor,
                                progress_state_t * __restrict progress) {
  out_file_t outfile;
  out_map_t outmap;
  dec_t dec;
  dec_t *dec_ptr = NULL;
  dec_t chunk_dec;
  uint8_t *inbuf;
  uint8_t *plainbuf = NULL;
  const char *part_path;
  uint64_t remaining;
  uint64_t supplied = 0;
  uint64_t descriptor_offset;
  uint64_t encrypted_header_size = 0;
  uint64_t encrypted_footer_size = 0;
  uint32_t descriptor_crc = 0;
  uint32_t output_crc;
  uint32_t produced = 0;
  int check_crc = (extract_flags & ZIPY_EXTRACT_NO_CRC) == 0;
  int apply_metadata = (extract_flags & ZIPY_EXTRACT_NO_METADATA) == 0;
  int metadata_done = 0;
  int zret = UNZ_UNFINISHED;
  int ret = ZIPY_ZIP_ERR;

  memset(&outfile, 0, sizeof(outfile));
  memset(&outmap, 0, sizeof(outmap));
#if !defined(_WIN32)
  outfile.fd = -1;
#endif

  if (!zipy || !zipy->fp || !info || !destpath)
    return ZIPY_ZIP_ERR;
  if (zip64_descriptor
      || info->entry.method != ZIPY_ZIP_DEFLATE
      || (extract_flags & ZIPY_EXTRACT_RESUME))
    return ZIPY_ZIP_EUNSUP;
  if ((uint64_t)UINT32_MAX > (uint64_t)SIZE_MAX)
    return ZIPY_ZIP_EUNSUP;
  if (info->data_offset > zipy->file_size)
    return ZIPY_ZIP_ESIZE;

  remaining = zipy->file_size - info->data_offset;
  dec_init(&dec);
  if (info->entry.encrypted && info->zip_method != ZIP_METHOD_AES) {
    if (seek_set(zipy->fp, info->data_offset) != 0)
      return ZIPY_ZIP_EFILE;

    ret = dec_open_zipcrypto(&dec,
                             zipy->fp,
                             password,
                             (uint8_t)(info->mod_time >> 8),
                             &remaining);
    if (ret != ZIPY_ZIP_OK)
      return ret;
    encrypted_header_size = ZIPCRYPTO_HEADER_SIZE;
    dec_ptr = &dec;
  } else if (info->zip_method == ZIP_METHOD_AES) {
    if (seek_set(zipy->fp, info->data_offset) != 0)
      return ZIPY_ZIP_EFILE;

    ret = dec_open_aes_wg(&dec,
                          zipy->fp,
                          password,
                          info->aes_strength,
                          &remaining);
    if (ret != ZIPY_ZIP_OK)
      return ret;
    encrypted_header_size = aes_wg_salt_size(info->aes_strength)
                          + AES_WG_VERIFY_SIZE;
    encrypted_footer_size = AES_WG_AUTH_SIZE;
    dec_ptr = &dec;
    if (info->aes_vendor_version == 2)
      check_crc = 0;
  }

  if (parent_len == SIZE_MAX) {
    if (!prepare_parent_dir(zipy, destpath))
      return ZIPY_ZIP_EFILE;
  } else if (!prepare_parent_dir_len(zipy, destpath, parent_len)) {
    return ZIPY_ZIP_EFILE;
  }

  part_path = path_buf_set_suffix(&zipy->part_buf, destpath, ".part");
  if (!part_path)
    return ZIPY_ZIP_ERR;
  remove_file(part_path);

  if (!open_output_file_seek(part_path, &outfile, &ret, 0, 1))
    return ret;
  if (!map_output(&outfile, UINT32_MAX, &outmap)) {
    ret = ZIPY_ZIP_EUNSUP;
    goto done;
  }
  if (!reserve_bytes(&zipy->inflate_in,
                     &zipy->inflate_in_cap,
                     ZIP_INFLATE_STREAM_CHUNK)) {
    ret = ZIPY_ZIP_ERR;
    goto done;
  }
  inbuf = zipy->inflate_in;
  if (dec.kind == DEC_AES_WG) {
    if (!reserve_bytes(&zipy->copy_buf,
                       &zipy->copy_cap,
                       ZIP_INFLATE_STREAM_CHUNK)) {
      ret = ZIPY_ZIP_ERR;
      goto done;
    }
    plainbuf = zipy->copy_buf;
  }

  if (!zipy->inflate_stream) {
    zipy->inflate_stream = infl_init(outmap.data, UINT32_MAX, 0);
    if (!zipy->inflate_stream) {
      ret = ZIPY_ZIP_ERR;
      goto done;
    }
  } else {
    infl_reset(zipy->inflate_stream, outmap.data, UINT32_MAX, 0);
  }

  if (!dec_ptr && seek_set(zipy->fp, info->data_offset) != 0) {
    ret = ZIPY_ZIP_EFILE;
    goto done;
  }

  while (remaining > 0) {
    size_t n = remaining > ZIP_INFLATE_STREAM_CHUNK
             ? ZIP_INFLATE_STREAM_CHUNK
             : (size_t)remaining;
    uint64_t supplied_before = supplied;
    const uint8_t *feed = inbuf;
    uint32_t payload_consumed;

    if (fread(inbuf, 1, n, zipy->fp) != n) {
      ret = ZIPY_ZIP_EFILE;
      goto done;
    }

    supplied += n;
    remaining -= n;
    if (dec.kind == DEC_AES_WG) {
      chunk_dec = dec;
      memcpy(plainbuf, inbuf, n);
      dec_decrypt(&dec, plainbuf, n);
      feed = plainbuf;
    } else if (dec_ptr) {
      dec_decrypt(dec_ptr, inbuf, n);
    }

    zret = infl_stream(zipy->inflate_stream, feed, (uint32_t)n);
    if (zret < UNZ_OK) {
      ret = zret == UNZ_EFULL ? ZIPY_ZIP_EUNSUP : ZIPY_ZIP_EINFLATE;
      goto done;
    }
    if (progress && progress->options && progress->options->progress) {
      uint32_t now = infl_output_pos(zipy->inflate_stream);

      if (now < produced) {
        ret = ZIPY_ZIP_ESIZE;
        goto done;
      }
      ret = progress_advance(progress, (uint64_t)(now - produced));
      if (ret != ZIPY_ZIP_OK)
        goto done;
      produced = now;
    }
    if (zret == UNZ_OK) {
      if (dec.kind == DEC_AES_WG) {
        payload_consumed = infl_input_pos(zipy->inflate_stream);
        if ((uint64_t)payload_consumed < supplied_before
            || (uint64_t)payload_consumed > supplied) {
          ret = ZIPY_ZIP_ESIZE;
          goto done;
        }
        if ((uint64_t)payload_consumed < supplied) {
          size_t used = (size_t)((uint64_t)payload_consumed - supplied_before);

          dec = chunk_dec;
          if (used > 0) {
            memcpy(plainbuf, inbuf, used);
            dec_decrypt(&dec, plainbuf, used);
          }
        }
      }
      break;
    }
  }

  if (zret != UNZ_OK) {
    ret = ZIPY_ZIP_EFILE;
    goto done;
  }

  info->entry.compressed_size = encrypted_header_size
                              + infl_input_pos(zipy->inflate_stream)
                              + encrypted_footer_size;
  info->entry.uncompressed_size = infl_output_pos(zipy->inflate_stream);
  if (infl_input_pos(zipy->inflate_stream) > supplied) {
    ret = ZIPY_ZIP_ESIZE;
    goto done;
  }

  if (dec.kind == DEC_AES_WG) {
    descriptor_offset = info->data_offset
                      + encrypted_header_size
                      + infl_input_pos(zipy->inflate_stream);
    if (descriptor_offset > zipy->file_size
        || seek_set(zipy->fp, descriptor_offset) != 0) {
      ret = ZIPY_ZIP_EFILE;
      goto done;
    }
    ret = dec_finish(&dec, zipy->fp);
    if (ret != ZIPY_ZIP_OK)
      goto done;
  }

  descriptor_offset = info->data_offset + info->entry.compressed_size;
  if (descriptor_offset > zipy->file_size
      || seek_set(zipy->fp, descriptor_offset) != 0) {
    ret = ZIPY_ZIP_EFILE;
    goto done;
  }

  ret = skip_data_descriptor(zipy,
                             info,
                             zip64_descriptor,
                             0,
                             &descriptor_crc);
  if (ret != ZIPY_ZIP_OK)
    goto done;
  info->entry.crc32 = descriptor_crc;

  if (check_crc) {
    output_crc = crc32_update(0, outmap.data, (size_t)info->entry.uncompressed_size);
    if (output_crc != descriptor_crc) {
      ret = ZIPY_ZIP_ECRC;
      goto done;
    }
  }

  unmap_output(&outmap);
  if (set_output_size(&outfile, info->entry.uncompressed_size) != 0) {
    ret = ZIPY_ZIP_EFILE;
    goto done;
  }
  if (!flush_output(&outfile)) {
    ret = ZIPY_ZIP_EFILE;
    goto done;
  }
  if (apply_metadata)
    metadata_done = apply_open_file_metadata(&outfile, info);
  if (!close_output_file(&outfile)) {
    ret = ZIPY_ZIP_EFILE;
  }
#if defined(_WIN32)
  outfile.fp = NULL;
#else
  outfile.fd = -1;
#endif
  if (ret != ZIPY_ZIP_OK)
    goto done;
  if (apply_metadata
      && !metadata_done
      && !apply_entry_metadata(part_path, info)) {
    ret = ZIPY_ZIP_EFILE;
    goto done;
  }
  if (!replace_file(part_path, destpath)) {
    ret = ZIPY_ZIP_EFILE;
    goto done;
  }

  ret = ZIPY_ZIP_OK;

done:
  unmap_output(&outmap);
#if defined(_WIN32)
  if (outfile.fp) {
    if (!close_output_file(&outfile) && ret == ZIPY_ZIP_OK)
      ret = ZIPY_ZIP_EFILE;
    outfile.fp = NULL;
  }
#else
  if (outfile.fd >= 0) {
    if (!close_output_file(&outfile) && ret == ZIPY_ZIP_OK)
      ret = ZIPY_ZIP_EFILE;
    outfile.fd = -1;
  }
#endif
  if (ret != ZIPY_ZIP_OK)
    remove_file(part_path);
  return ret;
}

static int
extract_entry(zipy_archive_t * __restrict zipy,
                   entry_info_t * __restrict info,
                   const char * __restrict destpath,
                   size_t parent_len,
                   uint32_t extract_flags,
                   const char * __restrict password,
                   const char * __restrict state_path,
                   const char * __restrict part_destdir,
                   progress_state_t * __restrict progress) {
  uint8_t local[ZIP_LOCAL_FIXED];
  const uint8_t *localp;
  const uint8_t *mapped_data = NULL;
  uint16_t flags, method, nameLen, extraLen;
  uint64_t dataOffset;
  uint64_t compressed_size;
  dec_t dec;
  dec_t *dec_ptr = NULL;
  out_file_t outfile;
  const char *output_path = destpath;
  const char *part_path = NULL;
  uint64_t resume_offset = 0;
  uint32_t resume_crc = 0;
  int check_crc = (extract_flags & ZIPY_EXTRACT_NO_CRC) == 0;
  int apply_metadata = (extract_flags & ZIPY_EXTRACT_NO_METADATA) == 0;
  int use_part = (extract_flags & (ZIPY_EXTRACT_ATOMIC | ZIPY_EXTRACT_RESUME)) != 0;
  int keep_part = (extract_flags & ZIPY_EXTRACT_RESUME) != 0;
  int encrypted;
  int metadata_done = 0;
  int ret = ZIPY_ZIP_ERR;

  memset(&outfile, 0, sizeof(outfile));
#if !defined(_WIN32)
  outfile.fd = -1;
#endif

  if (!zipy || !info || !destpath)
    return ZIPY_ZIP_ERR;

  if (!info->safe_name)
    return ZIPY_ZIP_EFILE;

  if (info->flags & ZIP_FLAG_STRONG_ENC)
    return ZIPY_ZIP_EUNSUP;

  if (use_part
      && is_internal_state_name(info->entry.name, info->entry.name_len))
    return ZIPY_ZIP_EFILE;

  if (info->entry.is_directory) {
    if (!mkdirs_buf(destpath, &zipy->parent_buf))
      return ZIPY_ZIP_EFILE;
    if ((extract_flags & EXTRACT_DELAY_DIR_METADATA) || !apply_metadata)
      return ZIPY_ZIP_OK;
    return apply_entry_metadata(destpath, info) ? ZIPY_ZIP_OK : ZIPY_ZIP_EFILE;
  }

  if (info->entry.method != ZIPY_ZIP_STORE && info->entry.method != ZIPY_ZIP_DEFLATE)
    return ZIPY_ZIP_EUNSUP;

  if (info->has_data_offset && info->zip_method != ZIP_METHOD_AES) {
    flags = info->local_flags;
    method = info->zip_method;
    nameLen = 0;
    extraLen = 0;
    dataOffset = info->data_offset;
  } else {
    localp = mapped_range(zipy, info->local_header_offset, sizeof(local));
    if (!localp) {
      if (!zipy->fp
          || seek_set(zipy->fp, info->local_header_offset) != 0
          || !read_exact(zipy->fp, local, sizeof(local)))
        return ZIPY_ZIP_EFILE;
      localp = local;
    }

    if (le32(localp) != ZIP_SIGN_LOCAL_FILE)
      return ZIPY_ZIP_EFILE;

    flags = le16(localp + 6);
    method = le16(localp + 8);
    nameLen = le16(localp + 26);
    extraLen = le16(localp + 28);

    if (method != info->zip_method || (flags & ZIP_FLAG_STRONG_ENC))
      return ZIPY_ZIP_EUNSUP;

    if (UINT64_MAX - info->local_header_offset
        < ZIP_LOCAL_FIXED + (uint64_t)nameLen + (uint64_t)extraLen)
      return ZIPY_ZIP_ESIZE;

    dataOffset = info->local_header_offset + ZIP_LOCAL_FIXED + nameLen + extraLen;
    if (dataOffset > zipy->file_size
        || info->entry.compressed_size > zipy->file_size - dataOffset)
      return ZIPY_ZIP_ESIZE;

    if (method == ZIP_METHOD_AES
        && !verify_local_aes_extra(zipy,
                                        info,
                                        info->local_header_offset + ZIP_LOCAL_FIXED + nameLen,
                                        extraLen))
      return ZIPY_ZIP_EUNSUP;
  }

  compressed_size = info->entry.compressed_size;
  encrypted = ((flags | info->flags) & ZIP_FLAG_ENCRYPTED) != 0;
  if (!encrypted)
    mapped_data = mapped_range(zipy, dataOffset, compressed_size);
  if ((encrypted || !mapped_data)
      && (!zipy->fp || seek_set(zipy->fp, dataOffset) != 0))
    return ZIPY_ZIP_EFILE;

  dec_init(&dec);
  if (encrypted) {
    uint8_t verify = ((flags | info->flags) & ZIP_FLAG_DATA_DESC)
                   ? (uint8_t)(info->mod_time >> 8)
                   : (uint8_t)(info->entry.crc32 >> 24);

    if (method == ZIP_METHOD_AES) {
      ret = dec_open_aes_wg(&dec,
                            zipy->fp,
                            password,
                            info->aes_strength,
                            &compressed_size);
      if (ret != ZIPY_ZIP_OK)
        return ret;
      if (info->aes_vendor_version == 2)
        check_crc = 0;
    } else if (method == ZIPY_ZIP_STORE || method == ZIPY_ZIP_DEFLATE) {
      ret = dec_open_zipcrypto(&dec,
                               zipy->fp,
                               password,
                               verify,
                               &compressed_size);
      if (ret != ZIPY_ZIP_OK)
        return ret;
    } else {
      return ZIPY_ZIP_EUNSUP;
    }

    dec_ptr = &dec;
  }

  if (is_symlink(info)) {
    uint8_t *target = NULL;
    size_t target_len = 0;

    if (parent_len == SIZE_MAX) {
      if (!prepare_parent_dir(zipy, destpath))
        return ZIPY_ZIP_EFILE;
    } else if (!prepare_parent_dir_len(zipy, destpath, parent_len)) {
      return ZIPY_ZIP_EFILE;
    }

    if (mapped_data && seek_set(zipy->fp, dataOffset) != 0)
      return ZIPY_ZIP_EFILE;

    if (info->entry.method == ZIPY_ZIP_STORE) {
      if (compressed_size != info->entry.uncompressed_size)
        ret = ZIPY_ZIP_ESIZE;
      else
        ret = read_store_mem(zipy->fp,
                                  compressed_size,
                                  info->entry.crc32,
                                  check_crc,
                                  dec_ptr,
                                  &target,
                                  &target_len);
    } else {
      ret = inflate_raw_mem(zipy->fp,
                                 compressed_size,
                                 info->entry.uncompressed_size,
                                 info->entry.crc32,
                                 check_crc,
                                 dec_ptr,
                                 &target,
                                 &target_len);
    }

    if (ret == ZIPY_ZIP_OK)
      ret = create_symlink(destpath,
                                target,
                                target_len,
                                info,
                                apply_metadata);
    free(target);
    return ret;
  }

  if (parent_len == SIZE_MAX) {
    if (!prepare_parent_dir(zipy, destpath)) {
      ret = ZIPY_ZIP_EFILE;
      return ret;
    }
  } else if (!prepare_parent_dir_len(zipy, destpath, parent_len)) {
    ret = ZIPY_ZIP_EFILE;
    return ret;
  }

  if (use_part) {
    int final_exists = 0;
    uint64_t final_size = 0;
    int part_exists = 0;
    uint64_t part_size = 0;

    part_path = part_destdir
              ? resume_part_path(zipy, part_destdir, info)
              : path_buf_set_suffix(&zipy->part_buf, destpath, ".part");
    if (!part_path)
      return ZIPY_ZIP_ERR;
    output_path = part_path;

    if (keep_part
        && !regular_file_size(destpath, &final_exists, &final_size))
      return ZIPY_ZIP_EFILE;
    if (keep_part
        && final_exists
        && final_size == info->entry.uncompressed_size) {
      if (!check_crc) {
        write_resume_state(state_path,
                           zipy,
                           info,
                           destpath,
                           part_path,
                           0,
                           extract_flags,
                           "skipped");
        return ZIPY_ZIP_SKIPPED;
      } else {
        ret = crc32_file_prefix(zipy, destpath, final_size, &resume_crc);
        if (ret != ZIPY_ZIP_OK)
          return ret;
        if (resume_crc == info->entry.crc32) {
          write_resume_state(state_path,
                             zipy,
                             info,
                             destpath,
                             part_path,
                             0,
                             extract_flags,
                             "skipped");
          return ZIPY_ZIP_SKIPPED;
        }
      }
    }

    if (keep_part
        && !regular_file_size(part_path, &part_exists, &part_size))
      return ZIPY_ZIP_EFILE;

    if (keep_part && part_exists) {
      if (part_size == info->entry.uncompressed_size) {
        if (encrypted) {
          remove_file(part_path);
          part_exists = 0;
          part_size = 0;
        } else if (!check_crc && info->entry.method == ZIPY_ZIP_DEFLATE) {
          remove_file(part_path);
          part_exists = 0;
          part_size = 0;
        } else if (!check_crc) {
          if (!replace_file(part_path, destpath))
            return ZIPY_ZIP_EFILE;
          write_resume_state(state_path,
                             zipy,
                             info,
                             destpath,
                             part_path,
                             part_size,
                             extract_flags,
                             "done");
          return apply_metadata && !apply_entry_metadata(destpath, info)
               ? ZIPY_ZIP_EFILE
               : ZIPY_ZIP_OK;
        } else {
          ret = crc32_file_prefix(zipy, part_path, part_size, &resume_crc);
          if (ret != ZIPY_ZIP_OK)
            return ret;
          if (resume_crc == info->entry.crc32) {
            if (!replace_file(part_path, destpath))
              return ZIPY_ZIP_EFILE;
            write_resume_state(state_path,
                               zipy,
                               info,
                               destpath,
                               part_path,
                               part_size,
                               extract_flags,
                               "done");
            return apply_metadata && !apply_entry_metadata(destpath, info)
                 ? ZIPY_ZIP_EFILE
                 : ZIPY_ZIP_OK;
          }

          remove_file(part_path);
          part_exists = 0;
          part_size = 0;
        }
      } else if (part_size > info->entry.uncompressed_size) {
        remove_file(part_path);
        part_exists = 0;
        part_size = 0;
      }
    } else if (!keep_part) {
      remove_file(part_path);
    }

    if (keep_part
        && part_exists
        && part_size > 0
        && !encrypted
        && info->entry.method == ZIPY_ZIP_STORE
        && compressed_size == info->entry.uncompressed_size) {
      if (check_crc) {
        ret = crc32_file_prefix(zipy, part_path, part_size, &resume_crc);
        if (ret != ZIPY_ZIP_OK)
          return ret;
      }
      resume_offset = part_size;
    } else if (part_exists && part_size > 0) {
      remove_file(part_path);
    }

    write_resume_state(state_path,
                       zipy,
                       info,
                       destpath,
                       part_path,
                       resume_offset,
                       extract_flags,
                       "extracting");

    if (!prepare_parent_dir(zipy, output_path))
      return ZIPY_ZIP_EFILE;
  }

  if (!open_output_file_seek(output_path,
                             &outfile,
                             &ret,
                             resume_offset,
                             resume_offset == 0))
    return ret;

  if (info->entry.method == ZIPY_ZIP_STORE) {
    if (compressed_size != info->entry.uncompressed_size)
      ret = ZIPY_ZIP_ESIZE;
    else if (mapped_data)
      ret = copy_store_mapped(&outfile,
                              mapped_data,
                              info->entry.uncompressed_size,
                              info->entry.crc32,
                              check_crc,
                              resume_offset,
                              resume_crc,
                              progress);
    else {
      if (resume_offset > 0
          && (UINT64_MAX - dataOffset < resume_offset
              || seek_set(zipy->fp, dataOffset + resume_offset) != 0)) {
        ret = ZIPY_ZIP_EFILE;
      } else {
        ret = copy_store(zipy, &outfile,
                         info->entry.uncompressed_size,
                         info->entry.crc32,
                         check_crc,
                         dec_ptr,
                         resume_offset,
                         resume_crc,
                         progress);
      }
    }
  } else {
    if (resume_offset > 0) {
      ret = ZIPY_ZIP_EUNSUP;
    } else {
      ret = inflate_raw(zipy,
                        &outfile,
                        mapped_data,
                        compressed_size,
                        info->entry.uncompressed_size,
                        info->entry.crc32,
                        check_crc,
                        dec_ptr,
                        progress);
    }
  }

  if (ret == ZIPY_ZIP_OK) {
    if (!flush_output(&outfile))
      ret = ZIPY_ZIP_EFILE;
    else if (apply_metadata)
      metadata_done = apply_open_file_metadata(&outfile, info);
  }
  if (!close_output_file(&outfile) && ret == ZIPY_ZIP_OK)
    ret = ZIPY_ZIP_EFILE;
  if (ret == ZIPY_ZIP_OK
      && apply_metadata
      && !metadata_done
      && !apply_entry_metadata(output_path, info))
    ret = ZIPY_ZIP_EFILE;
  if (ret == ZIPY_ZIP_OK
      && use_part
      && !replace_file(output_path, destpath))
    ret = ZIPY_ZIP_EFILE;
  if (ret != ZIPY_ZIP_OK && use_part && !keep_part)
    remove_file(output_path);
  if (use_part)
    write_resume_state(state_path,
                       zipy,
                       info,
                       destpath,
                       part_path,
                       resume_offset,
                       extract_flags,
                       ret == ZIPY_ZIP_OK ? "done" : "failed");
  if (use_part && !keep_part && part_destdir)
    cleanup_empty_parts_dirs(zipy, part_destdir, output_path);

  return ret;
}

ZIPY_EXPORT
size_t
zipy_count(const zipy_archive_t * __restrict zipy) {
  return zipy ? zipy->file_count : 0;
}

ZIPY_EXPORT
size_t
zipy_file_count(const zipy_archive_t * __restrict zipy) {
  return zipy ? zipy->extract_file_count : 0;
}

ZIPY_EXPORT
uint64_t
zipy_uncompressed_size(const zipy_archive_t * __restrict zipy) {
  return zipy ? zipy->extract_uncompressed_size : 0;
}

ZIPY_EXPORT
const zipy_entry_t *
zipy_entry(const zipy_archive_t * __restrict zipy, size_t index) {
  if (!zipy || index >= zipy->file_count)
    return NULL;

  return &zipy->files[index].entry;
}

ZIPY_EXPORT
int
zipy_extract(zipy_archive_t * __restrict zipy,
             size_t index,
             const char * __restrict destpath) {
  if (!zipy || index >= zipy->file_count)
    return ZIPY_ZIP_EFILE;

  return extract_entry(zipy,
                            &zipy->files[index],
                            destpath,
                            SIZE_MAX,
                            ZIPY_EXTRACT_DEFAULT,
                            NULL,
                            NULL,
                            NULL,
                            NULL);
}

ZIPY_EXPORT
int
zipy_extract_to(zipy_archive_t * __restrict zipy,
                size_t index,
                const char * __restrict destdir,
                const zipy_extract_options_t * __restrict options) {
  zipy_extract_options_t opts;
  entry_info_t *info;
  const char *destpath;
  char *save_dir = NULL;
  progress_state_t progress;
  uint64_t done = 0;
  size_t prefixLen, parentLen;
  int ret, conflictRet;

  if (!zipy || index >= zipy->file_count || !destdir)
    return ZIPY_ZIP_EFILE;

  opts = default_extract_options(options);
  info = &zipy->files[index];
  progress_init_entry(&progress,
                      &opts,
                      &info->entry,
                      &done,
                      entry_progress_size(info),
                      NULL,
                      NULL);
  if (!path_buf_set_archive_dir(zipy, destdir, &prefixLen))
    return ZIPY_ZIP_ERR;
  destpath = path_buf_append_name(&zipy->path_buf,
                                       prefixLen,
                                       info->entry.name,
                                       info->entry.name_len,
                                       info->name_has_backslash);
  if (!destpath)
    return ZIPY_ZIP_ERR;
  parentLen = extract_parent_len(info, prefixLen);

  conflictRet = prepare_entry_conflict(destdir,
                                            &info->entry,
                                            destpath,
                                            &opts,
                                            &save_dir);
  if (conflictRet == ZIPY_ZIP_SKIPPED) {
    ret = ZIPY_ZIP_SKIPPED;
    goto report;
  }
  if (conflictRet < ZIPY_ZIP_OK) {
    ret = conflictRet;
    goto done;
  }

  ret = extract_entry(zipy,
                           info,
                           destpath,
                           parentLen,
                           opts.flags,
                           opts.password,
                           opts.flags & ZIPY_EXTRACT_RESUME
                         ? resume_state_path(zipy, destdir)
                         : NULL,
                           destdir,
                           opts.progress ? &progress : NULL);
  if (ret == ZIPY_ZIP_OK && conflictRet == ZIPY_ZIP_SAVED)
    ret = ZIPY_ZIP_SAVED;

report:
  if (ret >= ZIPY_ZIP_OK) {
    int progressRet = progress_finish_entry(&progress, info);

    if (progressRet < ZIPY_ZIP_OK)
      ret = progressRet;
  }

done:
  free(save_dir);
  return ret;
}

ZIPY_EXPORT
int
zipy_extract_named(zipy_archive_t * __restrict zipy,
                   const char * __restrict name,
                   const char * __restrict destpath) {
  entry_info_t *info;

  if (!zipy || !name)
    return ZIPY_ZIP_ERR;

  info = find_file(zipy, name);
  if (!info)
    return ZIPY_ZIP_EFILE;

  return extract_entry(zipy,
                            info,
                           destpath,
                           SIZE_MAX,
                           ZIPY_EXTRACT_DEFAULT,
                           NULL,
                           NULL,
                           NULL,
                           NULL);
}

typedef struct extract_all_context_t {
  zipy_archive_t *source;
  const char *destdir;
  const zipy_extract_options_t *options;
  const char *state_path;
  const unsigned char *skip;
  mutex_handle_t    lock;
  size_t      count;
  size_t      next;
  uint64_t    done;
  uint64_t    total;
  int         result;
} extract_all_context_t;

static size_t
extract_default_jobs(const zipy_archive_t *zipy) {
  size_t files, work_files;
  size_t jobs;

  if (!zipy)
    return 1;

  files = zipy->extract_file_count;
  work_files = zipy->extract_work_file_count;
  if (files <= 1)
    return 1;

  if (work_files > 1
      && (work_files >= ZIP_PARALLEL_MIN_ENTRIES
          || zipy->extract_work_size >= ZIP_PARALLEL_MIN_BYTES)) {
    jobs = cpu_count();
    if (jobs < 1)
      jobs = 1;
    if (jobs > work_files)
      jobs = work_files;
    return jobs;
  }

  if (files < ZIP_PARALLEL_MIN_STORE_ENTRIES
      || zipy->extract_uncompressed_size < ZIP_PARALLEL_MIN_STORE_BYTES)
    return 1;

  jobs = cpu_count();
  if (jobs < 1)
    jobs = 1;
  if (jobs > files)
    jobs = files;

  return jobs;
}

static size_t
extract_clamp_jobs(const zipy_archive_t *zipy, size_t jobs) {
  size_t count;

  if (!zipy || jobs <= 1)
    return 1;

  count = zipy->file_count;
  if (jobs > count)
    jobs = count;
  return jobs > 0 ? jobs : 1;
}

static int
extract_all_serial(zipy_archive_t *zipy,
                        const char *destdir,
                        const unsigned char *skip,
                        const zipy_extract_options_t *options,
                        const char *state_path) {
  size_t i, prefixLen;
  uint64_t done = 0;
  uint64_t total = zipy ? zipy->extract_uncompressed_size : 0;

  if (!path_buf_set_archive_dir(zipy, destdir, &prefixLen))
    return ZIPY_ZIP_ERR;

  for (i = 0; i < zipy->file_count; i++) {
    entry_info_t *info;
    progress_state_t progress;
    const char *path;
    int ret;

    info = &zipy->files[i];
    progress_init_entry(&progress,
                        options,
                        &info->entry,
                        &done,
                        total,
                        NULL,
                        NULL);
    if (skip && skip[i]) {
      ret = progress_finish_entry(&progress, info);
      if (ret < ZIPY_ZIP_OK)
        return ret;
      continue;
    }

    path = path_buf_append_name(&zipy->path_buf,
                                     prefixLen,
                                     info->entry.name,
                                     info->entry.name_len,
                                     info->name_has_backslash);
    if (!path)
      return ZIPY_ZIP_ERR;

    ret = extract_entry(zipy,
                             info,
                             path,
                             extract_parent_len(info, prefixLen),
                             options->flags | EXTRACT_DELAY_DIR_METADATA,
                             options->password,
                             state_path,
                             destdir,
                             options->progress ? &progress : NULL);
    if (ret < ZIPY_ZIP_OK)
      return ret;

    ret = progress_finish_entry(&progress, info);
    if (ret < ZIPY_ZIP_OK)
      return ret;
  }

  return ZIPY_ZIP_OK;
}

static void
extract_all_worker(void *arg) {
  extract_all_context_t *ctx;
  zipy_archive_t clone;
  zipy_archive_t *zipy = &clone;
  size_t index, prefixLen;

  ctx = arg;
  if (!clone_init(zipy, ctx->source)) {
    mutex_lock(&ctx->lock);
    if (ctx->result == ZIPY_ZIP_OK)
      ctx->result = ZIPY_ZIP_EFILE;
    mutex_unlock(&ctx->lock);
    return;
  }
  if (!path_buf_set_archive_dir(zipy, ctx->destdir, &prefixLen)) {
    mutex_lock(&ctx->lock);
    if (ctx->result == ZIPY_ZIP_OK)
      ctx->result = ZIPY_ZIP_ERR;
    mutex_unlock(&ctx->lock);
    archive_cleanup(zipy);
    return;
  }

  for (;;) {
    entry_info_t *info;
    const char *path;
    size_t end;
    int ret;

    mutex_lock(&ctx->lock);
    if (ctx->result != ZIPY_ZIP_OK || ctx->next >= ctx->count) {
      mutex_unlock(&ctx->lock);
      break;
    }
    index = ctx->next++;
    end = index + ZIP_WORK_BATCH;
    if (end > ctx->count)
      end = ctx->count;
    ctx->next = end;
    mutex_unlock(&ctx->lock);

    for (; index < end; index++) {
      progress_state_t progress;

      if (index >= zipy->file_count) {
        ret = ZIPY_ZIP_EFILE;
        goto fail;
      }
      info = &zipy->files[index];
      progress_init_entry(&progress,
                          ctx->options,
                          &info->entry,
                          &ctx->done,
                          ctx->total,
                          &ctx->lock,
                          &ctx->result);

      if (ctx->skip && ctx->skip[index]) {
        ret = progress_finish_entry(&progress, info);
        if (ret < ZIPY_ZIP_OK)
          goto fail;
        continue;
      }

      path = path_buf_append_name(&zipy->path_buf,
                                       prefixLen,
                                       info->entry.name,
                                       info->entry.name_len,
                                       info->name_has_backslash);
      if (!path) {
        ret = ZIPY_ZIP_ERR;
        goto fail;
      }

      ret = extract_entry(zipy,
                               info,
                               path,
                               extract_parent_len(info, prefixLen),
                               ctx->options->flags | EXTRACT_DELAY_DIR_METADATA,
                               ctx->options->password,
                               ctx->state_path,
                               ctx->destdir,
                               ctx->options->progress ? &progress : NULL);
      if (ret < ZIPY_ZIP_OK)
        goto fail;

      ret = progress_finish_entry(&progress, info);
      if (ret < ZIPY_ZIP_OK)
        goto fail;
    }

    continue;

  fail:
    mutex_lock(&ctx->lock);
    if (ctx->result == ZIPY_ZIP_OK)
      ctx->result = ret;
    mutex_unlock(&ctx->lock);
    break;
  }

  archive_cleanup(zipy);
}

static int
extract_all_parallel(zipy_archive_t *zipy,
                          const char *destdir,
                          size_t jobs,
                          const unsigned char *skip,
                          const zipy_extract_options_t *options,
                          const char *state_path) {
  extract_all_context_t ctx;
  thread_handle_t stack_threads[ZIP_STACK_THREADS];
  thread_handle_t *threads;
  size_t i, started;
  int result;

  if (!zipy->path || jobs <= 1)
    return extract_all_serial(zipy, destdir, skip, options, state_path);

  if (jobs <= ZIP_STACK_THREADS) {
    threads = stack_threads;
  } else {
    threads = calloc(jobs, sizeof(*threads));
    if (!threads)
      return extract_all_serial(zipy, destdir, skip, options, state_path);
  }

  memset(&ctx, 0, sizeof(ctx));
  ctx.source = zipy;
  ctx.destdir = destdir;
  ctx.options = options;
  ctx.state_path = state_path;
  ctx.skip = skip;
  ctx.count = zipy->file_count;
  ctx.total = zipy->extract_uncompressed_size;
  ctx.result = ZIPY_ZIP_OK;
  mutex_init(&ctx.lock);

  started = 0;
  for (i = 0; i < jobs; i++) {
    if (thread_start(&threads[i], extract_all_worker, &ctx) != 0)
      break;
    started++;
  }

  if (started == 0) {
    mutex_destroy(&ctx.lock);
    if (threads != stack_threads)
      free(threads);
    return extract_all_serial(zipy, destdir, skip, options, state_path);
  }

  for (i = 0; i < started; i++)
    thread_join(&threads[i]);

  result = ctx.result;
  mutex_destroy(&ctx.lock);
  if (threads != stack_threads)
    free(threads);
  return result;
}

static int
apply_directory_metadata(zipy_archive_t *zipy,
                              const char *destdir,
                              const unsigned char *skip) {
  size_t i, prefixLen;

  if (!zipy || zipy->directory_count == 0)
    return ZIPY_ZIP_OK;
  if (!path_buf_set_archive_dir(zipy, destdir, &prefixLen))
    return ZIPY_ZIP_ERR;

  for (i = zipy->file_count; i > 0; i--) {
    entry_info_t *info = &zipy->files[i - 1u];
    const char *path;
    int ok;

    if (!info->entry.is_directory || (skip && skip[i - 1u]))
      continue;

    path = path_buf_append_name(&zipy->path_buf,
                                     prefixLen,
                                     info->entry.name,
                                     info->entry.name_len,
                                     info->name_has_backslash);
    if (!path)
      return ZIPY_ZIP_ERR;

    ok = apply_entry_metadata(path, info);
    if (!ok)
      return ZIPY_ZIP_EFILE;
  }

  return ZIPY_ZIP_OK;
}

static int
prepare_extract_all(zipy_archive_t *zipy,
                         const char *destdir,
                         const zipy_extract_options_t *options,
                         unsigned char **skipOut) {
  char *save_dir = NULL;
  size_t i, prefixLen;
  int result = ZIPY_ZIP_OK;

  *skipOut = NULL;

  if (options->on_conflict == ZIPY_CONFLICT_OVERWRITE)
    return ZIPY_ZIP_OK;
  if (!path_buf_set_archive_dir(zipy, destdir, &prefixLen))
    return ZIPY_ZIP_ERR;

  for (i = 0; i < zipy->file_count; i++) {
    entry_info_t *info = &zipy->files[i];
    const char *path;
    int ret;

    path = path_buf_append_name(&zipy->path_buf,
                                     prefixLen,
                                     info->entry.name,
                                     info->entry.name_len,
                                     info->name_has_backslash);
    if (!path) {
      result = ZIPY_ZIP_ERR;
      break;
    }

    ret = prepare_entry_conflict(destdir,
                                      &info->entry,
                                      path,
                                      options,
                                      &save_dir);

    if (ret == ZIPY_ZIP_SKIPPED) {
      if (!*skipOut) {
        *skipOut = calloc(zipy->file_count, sizeof(**skipOut));
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

  free(save_dir);
  return result;
}

ZIPY_EXPORT
int
zipy_extract_all(zipy_archive_t * __restrict zipy,
                 const char * __restrict destdir,
                 const zipy_extract_options_t * __restrict options) {
  zipy_extract_options_t opts;
  unsigned char *skip = NULL;
  const char *state_path = NULL;
  size_t jobs;
  int ret;

  if (!zipy || !destdir)
    return ZIPY_ZIP_ERR;
  if (zipy->has_unsupported_method)
    return ZIPY_ZIP_EUNSUP;

  opts = default_extract_options(options);
  if (opts.on_conflict != ZIPY_CONFLICT_OVERWRITE) {
    int fastNoConflict = 0;

    if (target_empty_or_missing(destdir, &fastNoConflict) && fastNoConflict)
      opts.on_conflict = ZIPY_CONFLICT_OVERWRITE;
  }

  if (opts.flags & ZIPY_EXTRACT_RESUME)
    state_path = resume_state_path(zipy, destdir);

  ret = prepare_extract_all(zipy, destdir, &opts, &skip);
  if (ret >= ZIPY_ZIP_OK) {
    jobs = opts.jobs ? extract_clamp_jobs(zipy, opts.jobs)
                     : extract_default_jobs(zipy);
    ret = extract_all_parallel(zipy,
                               destdir,
                               jobs,
                               skip,
                               &opts,
                               state_path);
  }
  if (ret == ZIPY_ZIP_OK && !(opts.flags & ZIPY_EXTRACT_NO_METADATA))
    ret = apply_directory_metadata(zipy, destdir, skip);
  if (state_path)
    write_resume_run_state(state_path,
                           zipy,
                           ret == ZIPY_ZIP_OK ? "complete" : "failed",
                           ret);

  free(skip);
  return ret;
}

ZIPY_EXPORT
int
zipy_extract_stream(const char * __restrict path,
                    const char * __restrict destdir,
                    const zipy_extract_options_t * __restrict options) {
  zipy_archive_t zipy;
  zipy_extract_options_t opts;
  char extra_stack[512];
  char *save_dir = NULL;
  uint8_t *extra_buf = NULL;
  size_t extra_cap = 0;
  const char *state_path = NULL;
  uint64_t progress_done = 0;
  size_t prefixLen;
  int keep_entry_state = 0;
  int ret = ZIPY_ZIP_OK;

  memset(&zipy, 0, sizeof(zipy));
  if (!path || !destdir)
    return ZIPY_ZIP_ERR;

  zipy.fp = fopen(path, "rb");
  if (!zipy.fp)
    return ZIPY_ZIP_EFILE;
  zipy.path = dup_text(path);
  if (!zipy.path) {
    ret = ZIPY_ZIP_ERR;
    goto done;
  }
  if (get_file_size(zipy.fp, &zipy.file_size) != 0
      || seek_set(zipy.fp, 0) != 0) {
    ret = ZIPY_ZIP_EFILE;
    goto done;
  }

  opts = default_extract_options(options);
  if (opts.flags & ZIPY_EXTRACT_RESUME)
    state_path = resume_state_path(&zipy, destdir);
  if (!path_buf_set_archive_dir(&zipy, destdir, &prefixLen)) {
    ret = ZIPY_ZIP_ERR;
    goto done;
  }

  for (;;) {
    uint8_t hdr[ZIP_LOCAL_FIXED];
    entry_info_t info;
    char *name;
    const uint8_t *extra = NULL;
    const char *destpath;
    progress_state_t progress;
    uint64_t offset, dataOffset;
    uint32_t sig, comp32, uncomp32;
    uint16_t flags, method, nameLen, extraLen;
    size_t parentLen;
    int hasDataDesc, zip64Desc, unknownDataDesc;
    int conflictRet;

    if (tell_pos(zipy.fp, &offset) != 0) {
      ret = ZIPY_ZIP_EFILE;
      break;
    }

    if (fread(hdr, 1, sizeof(hdr), zipy.fp) != sizeof(hdr)) {
      ret = feof(zipy.fp) ? ZIPY_ZIP_EINCOMPLETE : ZIPY_ZIP_EFILE;
      break;
    }

    sig = le32(hdr);
    if (sig == ZIP_SIGN_CENTRAL_DIR
        || sig == ZIP_SIGN_END_CENTRAL
        || sig == ZIP_SIGN_ZIP64_END
        || sig == ZIP_SIGN_ZIP64_LOCATOR)
      break;
    if (sig != ZIP_SIGN_LOCAL_FILE) {
      ret = ZIPY_ZIP_EFILE;
      break;
    }

    flags = le16(hdr + 6);
    method = le16(hdr + 8);
    comp32 = le32(hdr + 18);
    uncomp32 = le32(hdr + 22);
    nameLen = le16(hdr + 26);
    extraLen = le16(hdr + 28);
    if (nameLen == 0 || (flags & ZIP_FLAG_STRONG_ENC)) {
      ret = ZIPY_ZIP_EUNSUP;
      break;
    }
    hasDataDesc = (flags & ZIP_FLAG_DATA_DESC) != 0;
    zip64Desc = comp32 == ZIP64_MAGIC_UINT32
             || uncomp32 == ZIP64_MAGIC_UINT32;

    memset(&info, 0, sizeof(info));
    info.flags = flags;
    info.local_flags = flags;
    info.mod_time = le16(hdr + 10);
    info.mod_date = le16(hdr + 12);
    info.entry.crc32 = le32(hdr + 14);
    info.entry.compressed_size = comp32;
    info.entry.uncompressed_size = uncomp32;
    info.entry.method = method;
    info.zip_method = method;
    info.local_header_offset = offset;

    name = alloc_name(&zipy, (size_t)nameLen + 1u);
    if (!name || !read_exact(zipy.fp, name, nameLen)) {
      ret = name
          ? stream_incomplete_result(&zipy, ZIPY_ZIP_EFILE)
          : ZIPY_ZIP_ERR;
      break;
    }
    name[nameLen] = '\0';
    info.entry.name = name;
    info.entry.name_len = nameLen;
    if (!scan_member_name(name,
                          nameLen,
                          &info.safe_name,
                          &info.name_has_backslash,
                          &info.name_parent_len)) {
      ret = ZIPY_ZIP_EFILE;
      break;
    }
    if (has_root_zipy_segment(name, nameLen))
      zipy.has_root_zipy = 1;

    if (extraLen > 0) {
      if (extraLen <= sizeof(extra_stack)) {
        extra = (const uint8_t *)extra_stack;
      } else {
        if (extraLen > extra_cap) {
          uint8_t *new_extra = realloc(extra_buf, extraLen);
          if (!new_extra) {
            ret = ZIPY_ZIP_ERR;
            break;
          }
          extra_buf = new_extra;
          extra_cap = extraLen;
        }
        extra = extra_buf;
      }
      if (!read_exact(zipy.fp, (void *)extra, extraLen)) {
        ret = stream_incomplete_result(&zipy, ZIPY_ZIP_EFILE);
        break;
      }
      if (!parse_zip64_extra(&info, extra, extraLen, comp32, uncomp32, 0, 0)
          || !parse_aes_extra(&info, extra, extraLen)
          || !parse_ext_time_extra(&info, extra, extraLen)) {
        ret = ZIPY_ZIP_EUNSUP;
        break;
      }
    } else if (comp32 == ZIP64_MAGIC_UINT32 || uncomp32 == ZIP64_MAGIC_UINT32) {
      ret = ZIPY_ZIP_EUNSUP;
      break;
    }

    if (info.zip_method == ZIP_METHOD_AES) {
      if (!(flags & ZIP_FLAG_ENCRYPTED) || info.aes_strength == 0) {
        ret = ZIPY_ZIP_EUNSUP;
        break;
      }
    } else if (info.aes_strength != 0) {
      ret = ZIPY_ZIP_EUNSUP;
      break;
    }

    info.entry.is_directory = is_dir_name_len(info.entry.name,
                                              info.entry.name_len);
    info.entry.encrypted = (flags & ZIP_FLAG_ENCRYPTED) != 0;
    info.mtime = dos_time(info.mod_date, info.mod_time);
    info.has_mtime = info.mtime != (time_t)0;
    unknownDataDesc = hasDataDesc
                   && !info.entry.is_directory
                   && info.entry.compressed_size == 0
                   && info.entry.uncompressed_size == 0;
    if (hasDataDesc
        && !info.entry.is_directory
        && unknownDataDesc
        && ((info.entry.method != ZIPY_ZIP_DEFLATE
             && info.entry.method != ZIPY_ZIP_STORE)
            || (info.entry.method == ZIPY_ZIP_STORE && info.entry.encrypted)
            || zip64Desc
            || ((opts.flags & ZIPY_EXTRACT_RESUME)
                && info.entry.method != ZIPY_ZIP_STORE))) {
      ret = ZIPY_ZIP_EUNSUP;
      break;
    }
    if (hasDataDesc
        && !info.entry.is_directory
        && !unknownDataDesc
        && (opts.flags & ZIPY_EXTRACT_NO_CRC) == 0
        && info.entry.crc32 == 0
        && info.entry.uncompressed_size != 0) {
      ret = ZIPY_ZIP_EUNSUP;
      break;
    }
    info.data_offset = offset + ZIP_LOCAL_FIXED + (uint64_t)nameLen + extraLen;
    info.has_data_offset = 1;
    dataOffset = info.data_offset;
    if (dataOffset > zipy.file_size
        || info.entry.compressed_size > zipy.file_size - dataOffset) {
      ret = ZIPY_ZIP_EINCOMPLETE;
      break;
    }
    if (!info.entry.is_directory
        && info.entry.method != ZIPY_ZIP_STORE
        && info.entry.method != ZIPY_ZIP_DEFLATE) {
      ret = ZIPY_ZIP_EUNSUP;
      break;
    }

    destpath = path_buf_append_name(&zipy.path_buf,
                                    prefixLen,
                                    info.entry.name,
                                    info.entry.name_len,
                                    info.name_has_backslash);
    if (!destpath) {
      ret = ZIPY_ZIP_ERR;
      break;
    }
    progress_init_entry(&progress,
                        &opts,
                        &info.entry,
                        &progress_done,
                        0,
                        NULL,
                        NULL);

    conflictRet = prepare_entry_conflict(destdir,
                                         &info.entry,
                                         destpath,
                                         &opts,
                                         &save_dir);
    if (conflictRet == ZIPY_ZIP_SKIPPED) {
      if (unknownDataDesc) {
        ret = ZIPY_ZIP_EUNSUP;
        break;
      }
      if (seek_set(zipy.fp, dataOffset + info.entry.compressed_size) != 0) {
        ret = ZIPY_ZIP_EFILE;
        break;
      }
      if (hasDataDesc) {
        ret = skip_data_descriptor(&zipy,
                                   &info,
                                   zip64Desc,
                                   (opts.flags & ZIPY_EXTRACT_NO_CRC) == 0
                                    && info.entry.crc32 != 0,
                                   NULL);
        if (ret < ZIPY_ZIP_OK) {
          ret = stream_incomplete_result(&zipy, ret);
          break;
        }
      }
      ret = progress_finish_entry(&progress, &info);
      if (ret < ZIPY_ZIP_OK)
        break;
      continue;
    }
    if (conflictRet < ZIPY_ZIP_OK) {
      ret = conflictRet;
      break;
    }

    parentLen = extract_parent_len(&info, prefixLen);
    if (unknownDataDesc) {
      if (info.entry.method == ZIPY_ZIP_STORE) {
        ret = extract_store_data_descriptor(&zipy,
                                            &info,
                                            destpath,
                                            parentLen,
                                            opts.flags | EXTRACT_DELAY_DIR_METADATA,
                                            zip64Desc,
                                            state_path,
                                            destdir,
                                            opts.progress ? &progress : NULL);
        if (ret < ZIPY_ZIP_OK && (opts.flags & ZIPY_EXTRACT_RESUME))
          keep_entry_state = 1;
      } else {
        ret = extract_deflate_data_descriptor(&zipy,
                                              &info,
                                              destpath,
                                              parentLen,
                                              opts.flags | EXTRACT_DELAY_DIR_METADATA,
                                              opts.password,
                                              zip64Desc,
                                              opts.progress ? &progress : NULL);
      }
    } else {
      ret = extract_entry(&zipy,
                          &info,
                          destpath,
                          parentLen,
                          opts.flags | EXTRACT_DELAY_DIR_METADATA,
                          opts.password,
                          state_path,
                          destdir,
                          opts.progress ? &progress : NULL);
    }
    if (ret < ZIPY_ZIP_OK) {
      ret = stream_incomplete_result(&zipy, ret);
      break;
    }
    ret = progress_finish_entry(&progress, &info);
    if (ret < ZIPY_ZIP_OK)
      break;
    if (unknownDataDesc)
      continue;
    if (info.entry.is_directory
        && info.entry.compressed_size > 0
        && skip_bytes(zipy.fp, info.entry.compressed_size) != 0) {
      ret = ZIPY_ZIP_EFILE;
      break;
    }
    if (hasDataDesc) {
      ret = skip_data_descriptor(&zipy,
                                 &info,
                                 zip64Desc,
                                 (opts.flags & ZIPY_EXTRACT_NO_CRC) == 0
                                  && info.entry.crc32 != 0,
                                 NULL);
      if (ret < ZIPY_ZIP_OK) {
        ret = stream_incomplete_result(&zipy, ret);
        break;
      }
    }
  }

done:
  if (state_path && !keep_entry_state)
    write_resume_run_state(state_path,
                           &zipy,
                           ret == ZIPY_ZIP_OK ? "complete"
                         : ret == ZIPY_ZIP_EINCOMPLETE ? "incomplete"
                         : "failed",
                           ret);
  free(extra_buf);
  free(save_dir);
  archive_cleanup(&zipy);
  return ret;
}

ZIPY_EXPORT
const char *
zipy_strerror(int result) {
  switch (result) {
    case ZIPY_ZIP_OK:          return "ok";
    case ZIPY_ZIP_SAVED:       return "saved existing file";
    case ZIPY_ZIP_SKIPPED:     return "skipped existing file";
    case ZIPY_ZIP_ERR:         return "zipy error";
    case ZIPY_ZIP_EINFLATE:    return "deflate decode failed";
    case ZIPY_ZIP_ESIZE:       return "zip size mismatch";
    case ZIPY_ZIP_ECRC:        return "crc check failed";
    case ZIPY_ZIP_EFILE:       return "file operation failed";
    case ZIPY_ZIP_EUNSUP:      return "unsupported zip feature";
    case ZIPY_ZIP_EEXIST:      return "target already exists";
    case ZIPY_ZIP_EPASS:       return "missing or incorrect password";
    case ZIPY_ZIP_EAUTH:       return "authentication failed";
    case ZIPY_ZIP_ENOSPC:      return "no space left";
    case ZIPY_ZIP_ECANCEL:     return "extraction cancelled";
    case ZIPY_ZIP_EINCOMPLETE: return "incomplete zip stream";
    default:                   return "unknown zipy result";
  }
}

ZIPY_EXPORT
void
zipy_close(zipy_archive_t * __restrict zipy) {
  if (!zipy)
    return;

  archive_cleanup(zipy);
  free(zipy);
}
