/*
 * Copyright (C) 2025 Recep Aslantas
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */

#include "thread/thread.h"

#include <zap/zip.h>
#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <stdint.h>

#if defined(_WIN32)
#  include <io.h>
#else
#  include <unistd.h>
#endif

typedef struct ZapProgress {
  FILE  *out;
  size_t count;
  size_t tick;
  int    tty;
  int    color;
} ZapProgress;

static void
print_usage(void) {
  printf("Usage: zap <zipfile> [-d extractdir]\n");
  printf("Options:\n");
  printf("  -d <dir>    Extract files into <dir>\n");
  printf("  -j <jobs>   Extract with jobs workers (default: cpu count)\n");
}

static int
file_is_tty(FILE *fp) {
  if (!fp)
    return 0;

#if defined(_WIN32)
  return _isatty(_fileno(fp));
#else
  return isatty(fileno(fp));
#endif
}

static int
use_color(int tty) {
  const char *term;

  if (!tty || getenv("NO_COLOR"))
    return 0;

  term = getenv("TERM");
  return !term || strcmp(term, "dumb") != 0;
}

static int
parse_jobs(const char *text, size_t *jobs) {
  char *end;
  unsigned long long value;

  if (!text || !*text)
    return 0;

  if (strcmp(text, "auto") == 0) {
    *jobs = 0;
    return 1;
  }

  errno = 0;
  value = strtoull(text, &end, 10);
  if (errno != 0 || *end != '\0' || value > (unsigned long long)SIZE_MAX)
    return 0;

  *jobs = (size_t)value;
  return 1;
}

static size_t
default_jobs(size_t count) {
  size_t jobs;

  if (count <= 1)
    return 1;

  jobs = zap_cpu_count();
  if (jobs < 1)
    jobs = 1;
  if (jobs > count)
    jobs = count;

  return jobs;
}

static size_t
clamp_jobs(size_t jobs, size_t count) {
  if (count <= 1)
    return 1;
  if (jobs == 0)
    jobs = default_jobs(count);
  if (jobs < 1)
    jobs = 1;
  if (jobs > count)
    jobs = count;
  return jobs;
}

static void
progress_init(ZapProgress *progress, FILE *out, size_t count) {
  progress->out = out;
  progress->count = count;
  progress->tick = 0;
  progress->tty = file_is_tty(out);
  progress->color = use_color(progress->tty);
}

static void
progress_clear(const ZapProgress *progress) {
  if (!progress->tty)
    return;

  fputs("\r\033[2K", progress->out);
  fflush(progress->out);
}

static void
progress_print_name(FILE *out, const char *name, size_t maxlen) {
  size_t len, i;

  if (!name || maxlen == 0)
    return;

  len = strlen(name);
  if (len > maxlen && maxlen > 3) {
    fputs("...", out);
    name += len - (maxlen - 3);
    maxlen -= 3;
    len = strlen(name);
  }

  for (i = 0; i < len && i < maxlen; i++) {
    unsigned char c = (unsigned char)name[i];
    fputc(isprint(c) ? c : '?', out);
  }
}

static void
progress_update(ZapProgress *progress, size_t current, const char *name) {
  static const char spinner[] = "-\\|/";
  unsigned percent;

  if (!progress->tty)
    return;

  percent = progress->count == 0
          ? 100u
          : (unsigned)((current * 100u) / progress->count);

  fputs("\r\033[2K", progress->out);
  if (progress->color) {
    fprintf(progress->out,
            "  \033[36m%c\033[0m \033[1m%zu/%zu\033[0m %3u%% ",
            spinner[progress->tick++ & 3u],
            current,
            progress->count,
            percent);
  } else {
    fprintf(progress->out,
            "  %c %zu/%zu %3u%% ",
            spinner[progress->tick++ & 3u],
            current,
            progress->count,
            percent);
  }

  progress_print_name(progress->out, name, 72);
  fflush(progress->out);
}

static char*
make_extract_path(const char *dir, const char *filename) {
  size_t dirlen, namelen;
  char *path;
  
  dirlen = strlen(dir);
  namelen = strlen(filename);
  
  /* +2 for possible slash and null terminator */
  path = malloc(dirlen + namelen + 2);
  if (!path) return NULL;
  
  strcpy(path, dir);
  
  /* Add trailing slash if needed */
  if (dirlen > 0 && dir[dirlen - 1] != '/' && dir[dirlen - 1] != '\\') {
    path[dirlen] = '/';
    dirlen++;
  }
  
  for (size_t i = 0; i < namelen; i++)
    path[dirlen + i] = filename[i] == '\\' ? '/' : filename[i];
  path[dirlen + namelen] = '\0';
  return path;
}

typedef struct ExtractContext {
  const char  *zipfile;
  const char  *extractdir;
  ZapArchive  *entries;
  ZapProgress *progress;
  ZapMutex     lock;
  size_t       count;
  size_t       next;
  size_t       done;
  size_t       extracted;
  int          failed;
} ExtractContext;

static void
extract_one(ExtractContext *ctx, ZapArchive *zip, size_t index) {
  const ZapEntry *entry;
  const char *name;
  char *destpath;
  int ret;

  entry = zap_entry(ctx->entries, index);
  if (!entry)
    return;

  name = entry->name;
  destpath = make_extract_path(ctx->extractdir, name);
  if (!destpath) {
    zap_lock(&ctx->lock);
    ctx->done++;
    ctx->failed = 1;
    progress_clear(ctx->progress);
    fprintf(stderr, "  Error: Failed to allocate path for '%s'\n", name);
    progress_update(ctx->progress, ctx->done, name);
    zap_unlock(&ctx->lock);
    return;
  }

  ret = zap_extract(zip, index, destpath);

  zap_lock(&ctx->lock);
  ctx->done++;
  if (ret == ZAP_ZIP_OK) {
    ctx->extracted++;
  } else {
    progress_clear(ctx->progress);
    fprintf(stderr, "  Error: Failed to extract '%s' (%d)\n", name, ret);
    ctx->failed = 1;
  }
  progress_update(ctx->progress, ctx->done, name);
  zap_unlock(&ctx->lock);

  free(destpath);
}

static void
extract_worker(void *arg) {
  ExtractContext *ctx;
  ZapArchive *zip;
  size_t index;

  ctx = arg;
  zip = zap_open(ctx->zipfile);
  if (!zip) {
    zap_lock(&ctx->lock);
    ctx->failed = 1;
    progress_clear(ctx->progress);
    fprintf(stderr, "  Error: Cannot open ZIP file '%s'\n", ctx->zipfile);
    zap_unlock(&ctx->lock);
    return;
  }

  for (;;) {
    zap_lock(&ctx->lock);
    if (ctx->next >= ctx->count) {
      zap_unlock(&ctx->lock);
      break;
    }
    index = ctx->next++;
    zap_unlock(&ctx->lock);

    extract_one(ctx, zip, index);
  }

  zap_close(zip);
}

static int
extract_serial(ZapArchive *zip,
               const char *extractdir,
               ZapProgress *progress,
               size_t count,
               size_t *extracted) {
  ExtractContext ctx;
  size_t i;

  memset(&ctx, 0, sizeof(ctx));
  ctx.extractdir = extractdir;
  ctx.entries = zip;
  ctx.progress = progress;
  ctx.count = count;
  zap_mutex_init(&ctx.lock);

  for (i = 0; i < count; i++)
    extract_one(&ctx, zip, i);

  zap_mutex_destroy(&ctx.lock);
  *extracted = ctx.extracted;
  return ctx.failed;
}

static int
extract_parallel(const char *zipfile,
                 ZapArchive *entries,
                 const char *extractdir,
                 ZapProgress *progress,
                 size_t count,
                 size_t jobs,
                 size_t *extracted) {
  ExtractContext ctx;
  ZapThread *threads;
  size_t i, started;

  memset(&ctx, 0, sizeof(ctx));
  ctx.zipfile = zipfile;
  ctx.extractdir = extractdir;
  ctx.entries = entries;
  ctx.progress = progress;
  ctx.count = count;
  zap_mutex_init(&ctx.lock);

  threads = calloc(jobs, sizeof(*threads));
  if (!threads) {
    zap_mutex_destroy(&ctx.lock);
    return extract_serial(entries, extractdir, progress, count, extracted);
  }

  started = 0;
  for (i = 0; i < jobs; i++) {
    if (zap_thread_start(&threads[i], extract_worker, &ctx) != 0)
      break;
    started++;
  }

  if (started == 0) {
    free(threads);
    zap_mutex_destroy(&ctx.lock);
    return extract_serial(entries, extractdir, progress, count, extracted);
  }

  for (i = 0; i < started; i++)
    zap_thread_join(&threads[i]);

  free(threads);
  zap_mutex_destroy(&ctx.lock);

  *extracted = ctx.extracted;
  return ctx.failed;
}

int
main(int argc, char *argv[]) {
  ZapArchive *zip;
  const char *zipfile = NULL;
  const char *extractdir = ".";  /* Default to current directory */
  size_t i;
  int success = 0;
  int summaryColor;
  int summaryTty;
  size_t jobs = 0;
  size_t count = 0, extracted = 0;
  ZapProgress progress;
  
  /* Parse command line arguments */
  for (i = 1; i < argc; i++) {
    if (strcmp(argv[i], "-d") == 0 && i + 1 < argc) {
      extractdir = argv[++i];
    } else if (strcmp(argv[i], "-j") == 0 && i + 1 < argc) {
      if (!parse_jobs(argv[++i], &jobs)) {
        print_usage();
        return 1;
      }
    } else if (!zipfile) {
      zipfile = argv[i];
    } else {
      print_usage();
      return 1;
    }
  }
  
  if (!zipfile) {
    print_usage();
    return 1;
  }
  
  /* Open ZIP file */
  zip = zap_open(zipfile);
  if (!zip) {
    fprintf(stderr, "Error: Cannot open ZIP file '%s'\n", zipfile);
    return 1;
  }
  
  summaryTty = file_is_tty(stdout);
  summaryColor = use_color(summaryTty);

  /* Extract all files */
  count = zap_count(zip);
  jobs = clamp_jobs(jobs, count);
  progress_init(&progress, stderr, count);
  if (jobs > 1)
    success = extract_parallel(zipfile, zip, extractdir, &progress, count, jobs, &extracted);
  else
    success = extract_serial(zip, extractdir, &progress, count, &extracted);

  progress_clear(&progress);
  if (success) {
    if (summaryColor)
      printf("  \033[31mextracted %zu/%zu %s to \033[35m%s\033[0m\n",
             extracted,
             count,
             count == 1 ? "file" : "files",
             extractdir);
    else
      printf("  extracted %zu/%zu %s to %s\n",
             extracted,
             count,
             count == 1 ? "file" : "files",
             extractdir);
  } else {
    if (summaryColor)
      printf("  \033[33m⚡\033[0m extracted %zu %s to \033[35m%s\033[0m\n",
             extracted,
             extracted == 1 ? "file" : "files",
             extractdir);
    else if (summaryTty)
      printf("  ⚡ extracted %zu %s to %s\n",
             extracted,
             extracted == 1 ? "file" : "files",
             extractdir);
    else
      printf("  extracted %zu %s to %s\n",
             extracted,
             extracted == 1 ? "file" : "files",
             extractdir);
  }
  
  zap_close(zip);
  return success;
}
