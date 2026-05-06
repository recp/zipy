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

#include <zipy/zip.h>
#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <stdint.h>
#include <time.h>

#if defined(_WIN32)
#  include <direct.h>
#  include <io.h>
#  include <windows.h>
#  define zipy_getcwd _getcwd
#  define zipy_mkdir(path) _mkdir(path)
#  define zipy_rmdir(path) _rmdir(path)
#else
#  include <sys/stat.h>
#  include <sys/types.h>
#  include <unistd.h>
#  define zipy_getcwd getcwd
#  define zipy_mkdir(path) mkdir((path), 0755)
#  define zipy_rmdir(path) rmdir(path)
#endif

#ifndef PATH_MAX
#  define PATH_MAX 4096
#endif

typedef struct ZipyProgress {
  FILE  *out;
  size_t count;
  size_t tick;
  int    tty;
  int    color;
} ZipyProgress;

typedef struct ZipyConfig {
  ZipyExtractOptions options;
} ZipyConfig;

static void
print_usage(void) {
  printf("Usage: zipy <zipfile> [-d extractdir]\n");
  printf("Options:\n");
  printf("  -d <dir>    Extract files into <dir>\n");
  printf("  -j <jobs>   Extract with jobs workers (default: cpu count)\n");
  printf("  --on-conflict <save|overwrite|skip|fail>\n");
  printf("  --save-to <target|home|trash>\n");
  printf("  --config [key=value ...]  Show or update ~/.zipy/config\n");
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

static uint64_t
now_ms(void) {
#if defined(_WIN32)
  LARGE_INTEGER freq, counter;

  QueryPerformanceFrequency(&freq);
  QueryPerformanceCounter(&counter);
  return (uint64_t)((counter.QuadPart * 1000ull) / freq.QuadPart);
#else
  struct timespec ts;

  clock_gettime(CLOCK_MONOTONIC, &ts);
  return (uint64_t)ts.tv_sec * 1000ull + (uint64_t)ts.tv_nsec / 1000000ull;
#endif
}

static void
format_duration(char *buf, size_t len, uint64_t ms) {
  if (ms < 1000) {
    snprintf(buf, len, "%llums", (unsigned long long)ms);
  } else if (ms < 10000) {
    snprintf(buf, len, "%.2fs", (double)ms / 1000.0);
  } else if (ms < 100000) {
    snprintf(buf, len, "%.1fs", (double)ms / 1000.0);
  } else {
    snprintf(buf, len, "%llus", (unsigned long long)(ms / 1000));
  }
}

static const char *
conflict_name(ZipyConflictPolicy policy) {
  switch (policy) {
    case ZIPY_CONFLICT_OVERWRITE: return "overwrite";
    case ZIPY_CONFLICT_SKIP:      return "skip";
    case ZIPY_CONFLICT_FAIL:      return "fail";
    case ZIPY_CONFLICT_SAVE:
    default:                      return "save";
  }
}

static const char *
save_to_name(ZipySaveLocation saveTo) {
  switch (saveTo) {
    case ZIPY_SAVE_HOME:   return "home";
    case ZIPY_SAVE_TRASH:  return "trash";
    case ZIPY_SAVE_TARGET:
    default:               return "target";
  }
}

static char *
trim(char *text) {
  char *end;

  while (*text && isspace((unsigned char)*text))
    text++;

  end = text + strlen(text);
  while (end > text && isspace((unsigned char)end[-1]))
    *--end = '\0';

  return text;
}

static int
parse_conflict(const char *value, ZipyConflictPolicy *out) {
  if (strcmp(value, "save") == 0) {
    *out = ZIPY_CONFLICT_SAVE;
  } else if (strcmp(value, "overwrite") == 0) {
    *out = ZIPY_CONFLICT_OVERWRITE;
  } else if (strcmp(value, "skip") == 0) {
    *out = ZIPY_CONFLICT_SKIP;
  } else if (strcmp(value, "fail") == 0) {
    *out = ZIPY_CONFLICT_FAIL;
  } else {
    return 0;
  }

  return 1;
}

static int
parse_save_to(const char *value, ZipySaveLocation *out) {
  if (strcmp(value, "target") == 0) {
    *out = ZIPY_SAVE_TARGET;
  } else if (strcmp(value, "home") == 0) {
    *out = ZIPY_SAVE_HOME;
  } else if (strcmp(value, "trash") == 0) {
    *out = ZIPY_SAVE_TRASH;
  } else {
    return 0;
  }

  return 1;
}

static void
config_default(ZipyConfig *config) {
  config->options.onConflict = ZIPY_CONFLICT_SAVE;
  config->options.saveTo = ZIPY_SAVE_TARGET;
  config->options.saveDir = NULL;
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
dup_text(const char *text) {
  char *copy;
  size_t len;

  if (!text)
    return NULL;

  len = strlen(text);
  copy = malloc(len + 1);
  if (!copy)
    return NULL;

  memcpy(copy, text, len + 1);
  return copy;
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

  jobs = zipy_cpu_count();
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
progress_init(ZipyProgress *progress, FILE *out, size_t count) {
  progress->out = out;
  progress->count = count;
  progress->tick = 0;
  progress->tty = file_is_tty(out);
  progress->color = use_color(progress->tty);
}

static void
progress_clear(const ZipyProgress *progress) {
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
progress_update(ZipyProgress *progress, size_t current, const char *name) {
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

static int
mkdirs(const char *path) {
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
  while (*p == '/' || *p == '\\')
    p++;

  for (; *p; p++) {
    if (*p != '/' && *p != '\\')
      continue;

    *p = '\0';
    if (zipy_mkdir(tmp) != 0 && errno != EEXIST) {
      ok = 0;
      *p = '/';
      break;
    }
    *p = '/';

    while (p[1] == '/' || p[1] == '\\')
      p++;
  }

  if (ok && zipy_mkdir(tmp) != 0 && errno != EEXIST)
    ok = 0;

  free(tmp);
  return ok;
}

static char *
config_path(void) {
  char *dir, *path;
  const char *home = home_dir();
  const char *envPath = getenv("ZIPY_CONFIG");

  if (envPath && *envPath)
    return dup_text(envPath);

  if (!home)
    return NULL;

  dir = make_extract_path(home, ".zipy");
  if (!dir)
    return NULL;

  path = make_extract_path(dir, "config");
  free(dir);
  return path;
}

static int
mkdir_parent(const char *path) {
  char *tmp, *p, *last = NULL;
  int ok;

  if (!path || !*path)
    return 0;

  tmp = dup_text(path);
  if (!tmp)
    return 0;

  for (p = tmp; *p; p++) {
    if (*p == '/' || *p == '\\')
      last = p;
  }

  if (!last) {
    free(tmp);
    return 1;
  }

  if (last == tmp && (*last == '/' || *last == '\\')) {
    last[1] = '\0';
  } else {
    *last = '\0';
  }

  ok = mkdirs(tmp);
  free(tmp);
  return ok;
}

static int
apply_config_pair(ZipyConfig *config, const char *key, const char *value) {
  if (strcmp(key, "on_conflict") == 0)
    return parse_conflict(value, &config->options.onConflict);
  if (strcmp(key, "save_to") == 0)
    return parse_save_to(value, &config->options.saveTo);

  return 0;
}

static int
apply_config_assignment(ZipyConfig *config, char *text) {
  char *eq, *key, *value;

  eq = strchr(text, '=');
  if (!eq)
    return 0;

  *eq = '\0';
  key = trim(text);
  value = trim(eq + 1);
  return apply_config_pair(config, key, value);
}

static void
read_config(ZipyConfig *config) {
  char *path;
  FILE *fp;
  char line[256];

  config_default(config);
  path = config_path();
  if (!path)
    return;

  fp = fopen(path, "rb");
  free(path);
  if (!fp)
    return;

  while (fgets(line, sizeof(line), fp)) {
    char *hash = strchr(line, '#');
    char *text;

    if (hash)
      *hash = '\0';

    text = trim(line);
    if (*text)
      apply_config_assignment(config, text);
  }

  fclose(fp);
}

static int
apply_env_config(ZipyConfig *config) {
  const char *value;

  value = getenv("ZIPY_ON_CONFLICT");
  if (value && *value && !parse_conflict(value, &config->options.onConflict)) {
    fprintf(stderr, "Error: Invalid ZIPY_ON_CONFLICT '%s'\n", value);
    return 0;
  }

  value = getenv("ZIPY_SAVE_TO");
  if (value && *value && !parse_save_to(value, &config->options.saveTo)) {
    fprintf(stderr, "Error: Invalid ZIPY_SAVE_TO '%s'\n", value);
    return 0;
  }

  return 1;
}

static int
write_config(const ZipyConfig *config) {
  char *path;
  FILE *fp;
  int ok = 0;

  path = config_path();
  if (!path)
    return 0;

  if (!mkdir_parent(path)) {
    free(path);
    return 0;
  }

  fp = fopen(path, "wb");
  if (fp) {
    fprintf(fp, "on_conflict = %s\n", conflict_name(config->options.onConflict));
    fprintf(fp, "save_to = %s\n", save_to_name(config->options.saveTo));
    ok = fclose(fp) == 0;
  }

  free(path);
  return ok;
}

static void
print_config(const ZipyConfig *config) {
  char *path = config_path();

  printf("config: %s\n", path ? path : "(unavailable)");
  printf("on_conflict = %s\n", conflict_name(config->options.onConflict));
  printf("save_to = %s\n", save_to_name(config->options.saveTo));
  free(path);
}

static int
handle_config_command(int argc, char **argv) {
  ZipyConfig config;
  int i;

  read_config(&config);
  if (argc == 2) {
    if (!apply_env_config(&config))
      return 1;
    print_config(&config);
    return 0;
  }

  for (i = 2; i < argc; i++) {
    char *arg = malloc(strlen(argv[i]) + 1);
    int ok;

    if (!arg)
      return 1;
    strcpy(arg, argv[i]);
    ok = apply_config_assignment(&config, arg);
    free(arg);
    if (!ok) {
      fprintf(stderr, "Error: Invalid config assignment '%s'\n", argv[i]);
      return 1;
    }
  }

  if (!write_config(&config)) {
    fprintf(stderr, "Error: Failed to write config\n");
    return 1;
  }

  print_config(&config);
  return 0;
}

static char *
trash_dir(void) {
  const char *home = home_dir();

  if (!home)
    return NULL;

#if defined(_WIN32)
  return make_extract_path(home, "AppData\\Local\\Microsoft\\Windows\\Recycle Bin");
#elif defined(__APPLE__)
  return make_extract_path(home, ".Trash");
#else
  return make_extract_path(home, ".local/share/Trash/files");
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
create_save_dir(const char *extractdir, ZipySaveLocation saveTo) {
  char name[64], numbered[96];
  const char *base = extractdir;
  char *ownedBase = NULL;
  char *path = NULL;
  unsigned i;

  if (saveTo == ZIPY_SAVE_HOME) {
    base = home_dir();
  } else if (saveTo == ZIPY_SAVE_TRASH) {
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
      path = make_extract_path(base, name);
    } else {
      snprintf(numbered, sizeof(numbered), "%s %u", name, i + 1);
      path = make_extract_path(base, numbered);
    }

    if (!path)
      goto done;
    if (zipy_mkdir(path) == 0)
      goto done;
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

typedef struct ExtractContext {
  const char  *zipfile;
  const char  *extractdir;
  const ZipyExtractOptions *options;
  ZipyArchive  *entries;
  ZipyProgress *progress;
  ZipyMutex     lock;
  size_t       count;
  size_t       next;
  size_t       done;
  size_t       extracted;
  size_t       saved;
  size_t       skipped;
  int          failed;
} ExtractContext;

static void
extract_one(ExtractContext *ctx, ZipyArchive *zip, size_t index) {
  const ZipyEntry *entry;
  const char *name;
  int ret;

  entry = zipy_entry(ctx->entries, index);
  if (!entry)
    return;

  name = entry->name;
  ret = zipy_extract_to(zip, index, ctx->extractdir, ctx->options);

  zipy_lock(&ctx->lock);
  ctx->done++;
  if (ret == ZIPY_ZIP_SKIPPED) {
    ctx->skipped++;
  } else if (ret >= ZIPY_ZIP_OK) {
    ctx->extracted++;
    if (ret == ZIPY_ZIP_SAVED)
      ctx->saved++;
  } else {
    progress_clear(ctx->progress);
    fprintf(stderr, "  Error: Failed to extract '%s' (%d)\n", name, ret);
    ctx->failed = 1;
  }
  progress_update(ctx->progress, ctx->done, name);
  zipy_unlock(&ctx->lock);
}

static void
extract_worker(void *arg) {
  ExtractContext *ctx;
  ZipyArchive *zip;
  size_t index;

  ctx = arg;
  zip = zipy_open(ctx->zipfile);
  if (!zip) {
    zipy_lock(&ctx->lock);
    ctx->failed = 1;
    progress_clear(ctx->progress);
    fprintf(stderr, "  Error: Cannot open ZIP file '%s'\n", ctx->zipfile);
    zipy_unlock(&ctx->lock);
    return;
  }

  for (;;) {
    zipy_lock(&ctx->lock);
    if (ctx->next >= ctx->count) {
      zipy_unlock(&ctx->lock);
      break;
    }
    index = ctx->next++;
    zipy_unlock(&ctx->lock);

    extract_one(ctx, zip, index);
  }

  zipy_close(zip);
}

static int
extract_serial(ZipyArchive *zip,
               const char *extractdir,
               const ZipyExtractOptions *options,
               ZipyProgress *progress,
               size_t count,
               size_t *extracted,
               size_t *saved,
               size_t *skipped) {
  ExtractContext ctx;
  size_t i;

  memset(&ctx, 0, sizeof(ctx));
  ctx.extractdir = extractdir;
  ctx.options = options;
  ctx.entries = zip;
  ctx.progress = progress;
  ctx.count = count;
  zipy_mutex_init(&ctx.lock);

  for (i = 0; i < count; i++)
    extract_one(&ctx, zip, i);

  zipy_mutex_destroy(&ctx.lock);
  *extracted = ctx.extracted;
  *saved = ctx.saved;
  *skipped = ctx.skipped;
  return ctx.failed;
}

static int
extract_parallel(const char *zipfile,
                 ZipyArchive *entries,
                 const char *extractdir,
                 const ZipyExtractOptions *options,
                 ZipyProgress *progress,
                 size_t count,
                 size_t jobs,
                 size_t *extracted,
                 size_t *saved,
                 size_t *skipped) {
  ExtractContext ctx;
  ZipyThread *threads;
  size_t i, started;

  memset(&ctx, 0, sizeof(ctx));
  ctx.zipfile = zipfile;
  ctx.extractdir = extractdir;
  ctx.options = options;
  ctx.entries = entries;
  ctx.progress = progress;
  ctx.count = count;
  zipy_mutex_init(&ctx.lock);

  threads = calloc(jobs, sizeof(*threads));
  if (!threads) {
    zipy_mutex_destroy(&ctx.lock);
    return extract_serial(entries, extractdir, options, progress, count,
                          extracted, saved, skipped);
  }

  started = 0;
  for (i = 0; i < jobs; i++) {
    if (zipy_thread_start(&threads[i], extract_worker, &ctx) != 0)
      break;
    started++;
  }

  if (started == 0) {
    free(threads);
    zipy_mutex_destroy(&ctx.lock);
    return extract_serial(entries, extractdir, options, progress, count,
                          extracted, saved, skipped);
  }

  for (i = 0; i < started; i++)
    zipy_thread_join(&threads[i]);

  free(threads);
  zipy_mutex_destroy(&ctx.lock);

  *extracted = ctx.extracted;
  *saved = ctx.saved;
  *skipped = ctx.skipped;
  return ctx.failed;
}

int
main(int argc, char *argv[]) {
  ZipyArchive *zip;
  ZipyConfig config;
  const char *zipfile = NULL;
  const char *extractdir = ".";  /* Default to current directory */
  char *saveDir = NULL;
  size_t i;
  int success = 0;
  int summaryColor;
  int summaryTty;
  size_t jobs = 0;
  size_t count = 0, extracted = 0, saved = 0, skipped = 0;
  uint64_t startMs, elapsedMs;
  char elapsed[32];
  ZipyProgress progress;

  if (argc > 1 && strcmp(argv[1], "--config") == 0)
    return handle_config_command(argc, argv);

  read_config(&config);
  if (!apply_env_config(&config))
    return 1;
  
  /* Parse command line arguments */
  for (i = 1; i < argc; i++) {
    if (strcmp(argv[i], "-d") == 0 && i + 1 < argc) {
      extractdir = argv[++i];
    } else if (strcmp(argv[i], "-j") == 0 && i + 1 < argc) {
      if (!parse_jobs(argv[++i], &jobs)) {
        print_usage();
        return 1;
      }
    } else if (strcmp(argv[i], "--on-conflict") == 0 && i + 1 < argc) {
      if (!parse_conflict(argv[++i], &config.options.onConflict)) {
        print_usage();
        return 1;
      }
    } else if (strcmp(argv[i], "--save-to") == 0 && i + 1 < argc) {
      if (!parse_save_to(argv[++i], &config.options.saveTo)) {
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
  zip = zipy_open(zipfile);
  if (!zip) {
    fprintf(stderr, "Error: Cannot open ZIP file '%s'\n", zipfile);
    return 1;
  }
  
  summaryTty = file_is_tty(stdout);
  summaryColor = use_color(summaryTty);

  /* Extract all files */
  count = zipy_count(zip);
  jobs = clamp_jobs(jobs, count);
  progress_init(&progress, stderr, count);
  if (config.options.onConflict == ZIPY_CONFLICT_SAVE) {
    saveDir = create_save_dir(extractdir, config.options.saveTo);
    if (!saveDir) {
      fprintf(stderr, "Error: Failed to create saved folder\n");
      zipy_close(zip);
      return 1;
    }
    config.options.saveDir = saveDir;
  }

  startMs = now_ms();
  if (jobs > 1)
    success = extract_parallel(zipfile, zip, extractdir, &config.options,
                               &progress, count, jobs,
                               &extracted, &saved, &skipped);
  else
    success = extract_serial(zip, extractdir, &config.options, &progress,
                             count, &extracted, &saved, &skipped);

  elapsedMs = now_ms() - startMs;
  format_duration(elapsed, sizeof(elapsed), elapsedMs);
  progress_clear(&progress);
  if (saveDir && saved == 0) {
    zipy_rmdir(saveDir);
  }

  if (success) {
    if (summaryColor)
      printf("  \033[31mextracted %zu/%zu %s \033[2min %s\033[0m\n",
             extracted,
             count,
             count == 1 ? "file" : "files",
             elapsed);
    else
      printf("  extracted %zu/%zu %s in %s\n",
             extracted,
             count,
             count == 1 ? "file" : "files",
             elapsed);
  } else {
    if (summaryColor)
      printf("  \033[33m⚡\033[0m extracted %zu %s \033[2min %s\033[0m\n",
             extracted,
             extracted == 1 ? "file" : "files",
             elapsed);
    else if (summaryTty)
      printf("  ⚡ extracted %zu %s in %s\n",
             extracted,
             extracted == 1 ? "file" : "files",
             elapsed);
    else
      printf("  extracted %zu %s in %s\n",
             extracted,
             extracted == 1 ? "file" : "files",
             elapsed);
  }

  if (!success && skipped > 0) {
    if (summaryColor)
      printf("  skipped \033[1m%zu\033[0m existing %s\n",
             skipped,
             skipped == 1 ? "file" : "files");
    else
      printf("  skipped %zu existing %s\n",
             skipped,
             skipped == 1 ? "file" : "files");
  }

  if (!success && saved > 0 && saveDir) {
    if (summaryColor)
      printf("  saved existing files to \033[35m%s\033[0m\n", saveDir);
    else
      printf("  saved existing files to %s\n", saveDir);
  }
  
  zipy_close(zip);
  free(saveDir);
  return success;
}
