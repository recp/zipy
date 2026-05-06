/*
 * Copyright (C) 2025 Recep Aslantas
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */

#include <zap/zip.h>
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

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

int
main(int argc, char *argv[]) {
  ZapArchive *zip;
  const char *zipfile = NULL;
  const char *extractdir = ".";  /* Default to current directory */
  char *destpath;
  size_t i;
  int success = 0;
  int summaryColor;
  int summaryTty;
  size_t count = 0, extracted = 0;
  ZapProgress progress;
  
  /* Parse command line arguments */
  for (i = 1; i < argc; i++) {
    if (strcmp(argv[i], "-d") == 0 && i + 1 < argc) {
      extractdir = argv[++i];
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
  progress_init(&progress, stderr, count);
  for (i = 0; i < count; i++) {
    const ZapEntry *entry = zap_entry(zip, i);
    if (!entry) continue;

    destpath = make_extract_path(extractdir, entry->name);
    if (!destpath) continue;

    progress_update(&progress, i + 1, entry->name);
    
    int ret = zap_extract(zip, i, destpath);
    if (ret == 0) {
      extracted++;
    } else {
      progress_clear(&progress);
      fprintf(stderr, "  Error: Failed to extract '%s' (%d)\n",
              entry->name, ret);
      success = 1;
    }
    
    free(destpath);
  }

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
      printf("  \033[32m✓\033[0m extracted %zu %s to \033[35m%s\033[0m\n",
             extracted,
             extracted == 1 ? "file" : "files",
             extractdir);
    else if (summaryTty)
      printf("  ✓ extracted %zu %s to %s\n",
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
