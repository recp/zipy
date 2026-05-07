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
#include "zip_private.h"

#include <zipy/zip.h>
#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <stdint.h>
#include <time.h>

#if defined(_WIN32)
#  include <conio.h>
#  include <direct.h>
#  include <io.h>
#  include <windows.h>
#  define zipy_getcwd _getcwd
#  define zipy_mkdir(path) _mkdir(path)
#  define zipy_rmdir(path) _rmdir(path)
#else
#  include <dirent.h>
#  include <sys/stat.h>
#  include <sys/types.h>
#  include <termios.h>
#  include <unistd.h>
#  define zipy_getcwd getcwd
#  define zipy_mkdir(path) mkdir((path), 0755)
#  define zipy_rmdir(path) rmdir(path)
#endif

#ifndef PATH_MAX
#  define PATH_MAX 4096
#endif

#define ZIPY_STACK_THREADS 64u
#define ZIPY_WORK_BATCH    8u
#define ZIPY_PARALLEL_MIN_ENTRIES 8u
#define ZIPY_PARALLEL_MIN_BYTES (8u * 1024u * 1024u)
#define ZIPY_PROGRESS_INTERVAL_MS 33u

typedef struct zipy_progress_t {
  FILE  *out;
  size_t count;
  size_t tick;
  uint64_t last_ms;
  int    tty;
  int    color;
} zipy_progress_t;

typedef enum zipy_cli_conflict_policy_t {
  ZIPY_CLI_CONFLICT_ASK = 0,
  ZIPY_CLI_CONFLICT_SAVE,
  ZIPY_CLI_CONFLICT_OVERWRITE,
  ZIPY_CLI_CONFLICT_SKIP,
  ZIPY_CLI_CONFLICT_FAIL
} zipy_cli_conflict_policy_t;

typedef struct zipy_config_t {
  zipy_cli_conflict_policy_t on_conflict;
  zipy_extract_options_t options;
} zipy_config_t;

static void
print_usage(void) {
  printf("Usage: zipy <zipfile> [-d extractdir]\n");
  printf("Options:\n");
  printf("  -h, --help  Show this help\n");
  printf("  -d <dir>    Extract files into <dir>\n");
  printf("  -j <jobs>   Extract with N workers, auto, or cpu (default: auto)\n");
  printf("  --on-conflict <ask|save|overwrite|skip|fail>\n");
  printf("  --save-to <target|home|trash>\n");
  printf("  -p, --password <password>\n");
  printf("  --no-crc    Skip CRC32 validation\n");
  printf("  --no-metadata  Skip mode and timestamp restoration\n");
  printf("  --no-progress  Disable interactive progress output\n");
  printf("  --fast      Alias for --no-crc --no-metadata --no-progress\n");
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

static void
print_error(const char *fmt, ...) {
  va_list args;
  int color = use_color(file_is_tty(stderr));

  if (color)
    fputs("\033[31m", stderr);

  va_start(args, fmt);
  vfprintf(stderr, fmt, args);
  va_end(args);

  if (color)
    fputs("\033[0m", stderr);
  fflush(stderr);
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
conflict_name(zipy_cli_conflict_policy_t policy) {
  switch (policy) {
    case ZIPY_CLI_CONFLICT_SAVE:      return "save";
    case ZIPY_CLI_CONFLICT_OVERWRITE: return "overwrite";
    case ZIPY_CLI_CONFLICT_SKIP:      return "skip";
    case ZIPY_CLI_CONFLICT_FAIL:      return "fail";
    case ZIPY_CLI_CONFLICT_ASK:
    default:                          return "ask";
  }
}

static const char *
save_to_name(zipy_save_location_t save_to) {
  switch (save_to) {
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
parse_conflict(const char *value, zipy_cli_conflict_policy_t *out) {
  if (strcmp(value, "ask") == 0) {
    *out = ZIPY_CLI_CONFLICT_ASK;
  } else if (strcmp(value, "save") == 0) {
    *out = ZIPY_CLI_CONFLICT_SAVE;
  } else if (strcmp(value, "overwrite") == 0) {
    *out = ZIPY_CLI_CONFLICT_OVERWRITE;
  } else if (strcmp(value, "skip") == 0) {
    *out = ZIPY_CLI_CONFLICT_SKIP;
  } else if (strcmp(value, "fail") == 0) {
    *out = ZIPY_CLI_CONFLICT_FAIL;
  } else {
    return 0;
  }

  return 1;
}

static int
parse_save_to(const char *value, zipy_save_location_t *out) {
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

static zipy_conflict_policy_t
cli_policy_to_extract(zipy_cli_conflict_policy_t policy) {
  switch (policy) {
    case ZIPY_CLI_CONFLICT_OVERWRITE: return ZIPY_CONFLICT_OVERWRITE;
    case ZIPY_CLI_CONFLICT_SKIP:      return ZIPY_CONFLICT_SKIP;
    case ZIPY_CLI_CONFLICT_FAIL:      return ZIPY_CONFLICT_FAIL;
    case ZIPY_CLI_CONFLICT_SAVE:
    case ZIPY_CLI_CONFLICT_ASK:
    default:                          return ZIPY_CONFLICT_SAVE;
  }
}

static void
config_default(zipy_config_t *config) {
  config->on_conflict = ZIPY_CLI_CONFLICT_ASK;
  config->options.on_conflict = ZIPY_CONFLICT_SAVE;
  config->options.save_to = ZIPY_SAVE_TARGET;
  config->options.save_dir = NULL;
  config->options.flags = ZIPY_EXTRACT_DEFAULT;
  config->options.password = NULL;
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
  if (strcmp(text, "cpu") == 0) {
    *jobs = SIZE_MAX;
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
cpu_jobs(size_t count) {
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
  if (count <= 1 || jobs <= 1)
    jobs = 1;
  else if (jobs == SIZE_MAX)
    jobs = cpu_jobs(count);
  if (jobs > count)
    jobs = count;
  return jobs;
}

static size_t
adaptive_jobs(zipy_archive_t *zip, size_t count) {
  uint64_t workSize = 0;
  size_t i, files = 0, workFiles = 0;
  size_t jobs;

  if (!zip || count <= 1)
    return 1;

  for (i = 0; i < count; i++) {
    const zipy_entry_t *entry = zipy_entry(zip, i);

    if (!entry || entry->is_directory)
      continue;

    files++;
    if (entry->method == ZIPY_ZIP_STORE && !entry->encrypted)
      continue;

    workFiles++;
    if (workSize < ZIPY_PARALLEL_MIN_BYTES)
      workSize += entry->uncompressed_size;
  }

  if (files <= 1
      || workFiles <= 1
      || (workFiles < ZIPY_PARALLEL_MIN_ENTRIES
          && workSize < ZIPY_PARALLEL_MIN_BYTES))
    return 1;

  jobs = cpu_jobs(workFiles);
  return jobs > 0 ? jobs : 1;
}

static size_t
file_count(zipy_archive_t *zip, size_t count) {
  size_t i, files = 0;

  if (!zip)
    return 0;

  for (i = 0; i < count; i++) {
    const zipy_entry_t *entry = zipy_entry(zip, i);

    if (entry && !entry->is_directory)
      files++;
  }

  return files;
}

static void
progress_init(zipy_progress_t *progress, FILE *out, size_t count) {
  progress->out = out;
  progress->count = count;
  progress->tick = 0;
  progress->last_ms = 0;
  progress->tty = file_is_tty(out);
  progress->color = use_color(progress->tty);
}

static void
progress_clear(const zipy_progress_t *progress) {
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
progress_update(zipy_progress_t *progress, size_t current, const char *name) {
  static const char spinner[] = "-\\|/";
  uint64_t now;
  unsigned percent;

  if (!progress->tty)
    return;
  now = now_ms();
  if (current < progress->count
      && progress->last_ms != 0
      && now - progress->last_ms < ZIPY_PROGRESS_INTERVAL_MS)
    return;
  progress->last_ms = now;

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
apply_config_pair(zipy_config_t *config, const char *key, const char *value) {
  if (strcmp(key, "on_conflict") == 0) {
    if (!parse_conflict(value, &config->on_conflict))
      return 0;
    config->options.on_conflict = cli_policy_to_extract(config->on_conflict);
    return 1;
  }
  if (strcmp(key, "save_to") == 0)
    return parse_save_to(value, &config->options.save_to);

  return 0;
}

static int
apply_config_assignment(zipy_config_t *config, char *text) {
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
read_config(zipy_config_t *config) {
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
apply_env_config(zipy_config_t *config) {
  const char *value;

  value = getenv("ZIPY_ON_CONFLICT");
  if (value && *value) {
    if (!parse_conflict(value, &config->on_conflict)) {
      print_error("Error: Invalid ZIPY_ON_CONFLICT '%s'\n", value);
      return 0;
    }
    config->options.on_conflict = cli_policy_to_extract(config->on_conflict);
  }

  value = getenv("ZIPY_SAVE_TO");
  if (value && *value && !parse_save_to(value, &config->options.save_to)) {
    print_error("Error: Invalid ZIPY_SAVE_TO '%s'\n", value);
    return 0;
  }

  return 1;
}

static int
write_config(const zipy_config_t *config) {
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
    fprintf(fp, "on_conflict = %s\n", conflict_name(config->on_conflict));
    fprintf(fp, "save_to = %s\n", save_to_name(config->options.save_to));
    ok = fclose(fp) == 0;
  }

  free(path);
  return ok;
}

static void
print_config(const zipy_config_t *config) {
  char *path = config_path();

  printf("config: %s\n", path ? path : "(unavailable)");
  printf("on_conflict = %s\n", conflict_name(config->on_conflict));
  printf("save_to = %s\n", save_to_name(config->options.save_to));
  free(path);
}

static int
handle_config_command(int argc, char **argv) {
  zipy_config_t config;
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
      print_error("Error: Invalid config assignment '%s'\n", argv[i]);
      return 1;
    }
  }

  if (!write_config(&config)) {
    print_error("Error: Failed to write config\n");
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
create_save_dir(const char *extractdir, zipy_save_location_t save_to) {
  char name[64], numbered[96];
  const char *base = extractdir;
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

static int
path_info(const char *path, int *exists, int *isDir) {
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
target_is_empty_or_missing(const char *path, int *emptyOrMissing) {
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

    pattern = make_extract_path(path, "*");
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

static char *
trim_trailing_seps_path(const char *path) {
  char *out;
  size_t len;

  if (!path)
    return NULL;

  len = strlen(path);
  while (len > 1 && (path[len - 1] == '/' || path[len - 1] == '\\')) {
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

static int
path_is_absolute(const char *path) {
  if (!path || !*path)
    return 0;

#if defined(_WIN32)
  if (isalpha((unsigned char)path[0]) && path[1] == ':')
    return 1;
#endif

  return path[0] == '/' || path[0] == '\\';
}

static char *
display_path(const char *path) {
  char cwd[PATH_MAX];
  size_t cwdLen;

  if (!path)
    return NULL;

  if (!path_is_absolute(path))
    return dup_text(path);

  if (!zipy_getcwd(cwd, sizeof(cwd)))
    return dup_text(path);

  cwdLen = strlen(cwd);
  if (strncmp(path, cwd, cwdLen) == 0
      && (path[cwdLen] == '/' || path[cwdLen] == '\\'))
    return dup_text(path + cwdLen + 1);

  return dup_text(path);
}

static void
print_choice_key(FILE *out, int color, char key) {
  if (color)
    fprintf(out, "[\033[36m%c\033[0m]", key);
  else
    fprintf(out, "[%c]", key);
}

static void
print_choice_option(FILE *out,
                    int color,
                    const char *prefix,
                    char key,
                    const char *suffix) {
  fputs(prefix, out);
  print_choice_key(out, color, key);
  fputs(suffix, out);
}

static void
print_conflict_choices(FILE *out, int color) {
  fputs("  ", out);
  print_choice_option(out, color, "", 's', "ave, ");
  print_choice_option(out, color, "", 'o', "verwrite, ");
  print_choice_option(out, color, "s", 'k', "ip, ");
  print_choice_option(out, color, "", 'f', "ail,\n  ");
  print_choice_option(out, color, "", 'S', "ave all, ");
  print_choice_option(out, color, "", 'O', "verwrite all, ");
  print_choice_option(out, color, "s", 'K', "ip all, ");
  print_choice_option(out, color, "", 'F', "ail all? ");
}

static int
read_choice_char(void) {
  char line[64];

  if (file_is_tty(stdin)) {
#if defined(_WIN32)
    int ch = _getch();

    if (ch == 0 || ch == 224) {
      (void)_getch();
      fputc('\n', stderr);
      return 0;
    }
    if (isprint((unsigned char)ch))
      fputc(ch, stderr);
    fputc('\n', stderr);
    return ch;
#else
    struct termios oldTerm, newTerm;
    int ch;

    if (tcgetattr(fileno(stdin), &oldTerm) == 0) {
      newTerm = oldTerm;
      newTerm.c_lflag &= (tcflag_t)~(ICANON | ECHO);
      newTerm.c_cc[VMIN] = 1;
      newTerm.c_cc[VTIME] = 0;

      if (tcsetattr(fileno(stdin), TCSANOW, &newTerm) == 0) {
        ch = fgetc(stdin);
        tcsetattr(fileno(stdin), TCSANOW, &oldTerm);
        if (ch != EOF) {
          if (isprint((unsigned char)ch))
            fputc(ch, stderr);
          fputc('\n', stderr);
          return ch;
        }
      }
    }
#endif
  }

  if (!fgets(line, sizeof(line), stdin))
    return EOF;

  return (unsigned char)line[0];
}

static int
entry_conflict_path(const char *extractdir,
                    const zipy_entry_t *entry,
                    char **conflictPath) {
  char *rel = NULL;
  char *path = NULL;
  char *clean = NULL;
  size_t len, i, j;
  int result = -1;

  *conflictPath = NULL;
  if (!entry || !entry->name)
    return -1;

  len = entry->name_len;
  rel = malloc(len + 1);
  if (!rel)
    return -1;

  for (i = 0; i < len; i++) {
    int exists, isDir;

    if ((entry->name[i] != '/' && entry->name[i] != '\\') || i == 0)
      continue;

    for (j = 0; j < i; j++)
      rel[j] = (entry->name[j] == '/' || entry->name[j] == '\\') ? '/' : entry->name[j];
    rel[i] = '\0';

    free(path);
    path = make_extract_path(extractdir, rel);
    if (!path)
      goto done;

    if (!path_info(path, &exists, &isDir))
      goto done;

    if (exists && !isDir) {
      *conflictPath = path;
      path = NULL;
      result = 1;
      goto done;
    }
  }

  free(path);
  path = make_extract_path(extractdir, entry->name);
  if (!path)
    goto done;

  clean = trim_trailing_seps_path(path);
  if (!clean)
    goto done;

  {
    int exists, isDir;

    if (!path_info(clean, &exists, &isDir))
      goto done;

    if (exists && !(entry->is_directory && isDir)) {
      *conflictPath = clean;
      clean = NULL;
      result = 1;
      goto done;
    }
  }

  result = 0;

done:
  free(clean);
  free(path);
  free(rel);
  return result;
}

static int
prompt_conflict_action(const zipy_entry_t *entry,
                       const char *path,
                       zipy_cli_conflict_policy_t *allPolicy,
                       zipy_conflict_policy_t *policy) {
  int color = use_color(file_is_tty(stderr));

  if (*allPolicy != ZIPY_CLI_CONFLICT_ASK) {
    *policy = cli_policy_to_extract(*allPolicy);
    return 1;
  }

  for (;;) {
    int ch;

    fprintf(stderr, "\n  %-9s %s\n  %-9s %s\n\n",
            "conflict:", entry->name,
            "exists:", path);
    print_conflict_choices(stderr, color);
    fflush(stderr);

    ch = read_choice_char();
    if (ch == EOF)
      return 0;

    switch (ch) {
      case 's':
        *policy = ZIPY_CONFLICT_SAVE;
        return 1;
      case 'S':
        *allPolicy = ZIPY_CLI_CONFLICT_SAVE;
        *policy = ZIPY_CONFLICT_SAVE;
        return 1;
      case 'o':
        *policy = ZIPY_CONFLICT_OVERWRITE;
        return 1;
      case 'O':
        *allPolicy = ZIPY_CLI_CONFLICT_OVERWRITE;
        *policy = ZIPY_CONFLICT_OVERWRITE;
        return 1;
      case 'k':
        *policy = ZIPY_CONFLICT_SKIP;
        return 1;
      case 'K':
        *allPolicy = ZIPY_CLI_CONFLICT_SKIP;
        *policy = ZIPY_CONFLICT_SKIP;
        return 1;
      case 'f':
      case 'q':
        return 0;
      case 'F':
      case 'Q':
        *allPolicy = ZIPY_CLI_CONFLICT_FAIL;
        return 0;
      default:
        fputs("  answer with s, o, k, f, S, O, K, or F\n", stderr);
        break;
    }
  }
}

static int
prepare_ask_plan(zipy_archive_t *zip,
                 const char *extractdir,
                 zipy_config_t *config,
                 zipy_conflict_policy_t **policiesOut,
                 int *needsSaveDir) {
  zipy_conflict_policy_t *policies = NULL;
  zipy_cli_conflict_policy_t allPolicy = ZIPY_CLI_CONFLICT_ASK;
  size_t count, i;
  int conflicts = 0;
  int fastNoConflict = 0;

  *policiesOut = NULL;
  *needsSaveDir = 0;

  config->options.on_conflict = cli_policy_to_extract(config->on_conflict);
  if (config->options.on_conflict == ZIPY_CONFLICT_OVERWRITE)
    return 1;

  if (target_is_empty_or_missing(extractdir, &fastNoConflict) && fastNoConflict) {
    config->options.on_conflict = ZIPY_CONFLICT_OVERWRITE;
    return 1;
  }

  if (config->on_conflict != ZIPY_CLI_CONFLICT_ASK) {
    *needsSaveDir = config->options.on_conflict == ZIPY_CONFLICT_SAVE;
    return 1;
  }

  if (!file_is_tty(stdin)) {
    config->options.on_conflict = ZIPY_CONFLICT_SAVE;
    *needsSaveDir = 1;
    return 1;
  }

  count = zipy_count(zip);
  policies = malloc(count * sizeof(*policies));
  if (!policies && count > 0)
    return 0;

  for (i = 0; i < count; i++) {
    const zipy_entry_t *entry = zipy_entry(zip, i);
    char *path = NULL;
    int ret;

    policies[i] = ZIPY_CONFLICT_OVERWRITE;
    if (!entry)
      continue;

    ret = entry_conflict_path(extractdir, entry, &path);
    if (ret < 0) {
      free(policies);
      return 0;
    }
    if (ret == 0)
      continue;

    conflicts++;
    if (!prompt_conflict_action(entry, path, &allPolicy, &policies[i])) {
      free(path);
      free(policies);
      return 0;
    }
    if (policies[i] == ZIPY_CONFLICT_SAVE)
      *needsSaveDir = 1;

    free(path);

    if (conflicts == 1 && allPolicy != ZIPY_CLI_CONFLICT_ASK) {
      config->on_conflict = allPolicy;
      config->options.on_conflict = cli_policy_to_extract(allPolicy);
      *needsSaveDir = config->options.on_conflict == ZIPY_CONFLICT_SAVE;
      free(policies);
      return 1;
    }
  }

  if (conflicts == 0) {
    config->options.on_conflict = ZIPY_CONFLICT_OVERWRITE;
    free(policies);
    return 1;
  }

  *policiesOut = policies;
  return 1;
}

typedef struct ExtractContext {
  const char  *zipfile;
  const char  *extractdir;
  const zipy_extract_options_t *options;
  const zipy_conflict_policy_t *policies;
  zipy_archive_t  *entries;
  zipy_progress_t *progress;
  zipy_mutex_t     lock;
  size_t       count;
  size_t       next;
  size_t       done;
  size_t       extracted;
  size_t       saved;
  size_t       skipped;
  int          failed;
} ExtractContext;

static void
extract_one(ExtractContext *ctx, zipy_archive_t *zip, size_t index) {
  const zipy_entry_t *entry;
  const char *name;
  int ret;

  entry = zipy_entry(ctx->entries, index);
  if (!entry)
    return;

  name = entry->name;
  if (entry->is_directory) {
    ret = ctx->policies && ctx->policies[index] == ZIPY_CONFLICT_SKIP
        ? ZIPY_ZIP_SKIPPED
        : ZIPY_ZIP_OK;
  } else if (ctx->policies) {
    zipy_extract_options_t options = *ctx->options;
    options.on_conflict = ctx->policies[index];
    ret = zipy_extract_to(zip, index, ctx->extractdir, &options);
  } else {
    ret = zipy_extract_to(zip, index, ctx->extractdir, ctx->options);
  }

  zipy_lock(&ctx->lock);
  ctx->done++;
  if (ret == ZIPY_ZIP_SKIPPED) {
    ctx->skipped++;
  } else if (ret >= ZIPY_ZIP_OK) {
    if (!entry->is_directory)
      ctx->extracted++;
    if (ret == ZIPY_ZIP_SAVED)
      ctx->saved++;
  } else {
    progress_clear(ctx->progress);
    if (ret == ZIPY_ZIP_EPASS)
      print_error("  Error: Missing or incorrect password for '%s'\n", name);
    else if (ret == ZIPY_ZIP_EAUTH)
      print_error("  Error: Authentication failed for '%s'\n", name);
    else
      print_error("  Error: Failed to extract '%s' (%d)\n", name, ret);
    ctx->failed = 1;
  }
  progress_update(ctx->progress, ctx->done, name);
  zipy_unlock(&ctx->lock);
}

static void
extract_worker(void *arg) {
  ExtractContext *ctx;
  zipy_archive_t *zip;
  size_t index;

  ctx = arg;
  zip = zipy_clone(ctx->entries);
  if (!zip) {
    zipy_lock(&ctx->lock);
    ctx->failed = 1;
    progress_clear(ctx->progress);
    print_error("  Error: Cannot open ZIP file '%s'\n", ctx->zipfile);
    zipy_unlock(&ctx->lock);
    return;
  }

  for (;;) {
    size_t end;

    zipy_lock(&ctx->lock);
    if (ctx->next >= ctx->count) {
      zipy_unlock(&ctx->lock);
      break;
    }
    index = ctx->next;
    end = index + ZIPY_WORK_BATCH;
    if (end > ctx->count)
      end = ctx->count;
    ctx->next = end;
    zipy_unlock(&ctx->lock);

    for (; index < end; index++)
      extract_one(ctx, zip, index);
  }

  zipy_close(zip);
}

static int
extract_serial(zipy_archive_t *zip,
               const char *extractdir,
               const zipy_extract_options_t *options,
               const zipy_conflict_policy_t *policies,
               zipy_progress_t *progress,
               size_t count,
               size_t *extracted,
               size_t *saved,
               size_t *skipped) {
  ExtractContext ctx;
  size_t i;

  memset(&ctx, 0, sizeof(ctx));
  ctx.extractdir = extractdir;
  ctx.options = options;
  ctx.policies = policies;
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
                 zipy_archive_t *entries,
                 const char *extractdir,
                 const zipy_extract_options_t *options,
                 const zipy_conflict_policy_t *policies,
                 zipy_progress_t *progress,
                 size_t count,
                 size_t jobs,
                 size_t *extracted,
                 size_t *saved,
                 size_t *skipped) {
  ExtractContext ctx;
  zipy_thread_t stack_threads[ZIPY_STACK_THREADS];
  zipy_thread_t *threads;
  size_t i, started;

  memset(&ctx, 0, sizeof(ctx));
  ctx.zipfile = zipfile;
  ctx.extractdir = extractdir;
  ctx.options = options;
  ctx.policies = policies;
  ctx.entries = entries;
  ctx.progress = progress;
  ctx.count = count;
  zipy_mutex_init(&ctx.lock);

  if (jobs <= ZIPY_STACK_THREADS) {
    threads = stack_threads;
  } else {
    threads = calloc(jobs, sizeof(*threads));
    if (!threads) {
      zipy_mutex_destroy(&ctx.lock);
      return extract_serial(entries, extractdir, options, policies, progress, count,
                            extracted, saved, skipped);
    }
  }

  started = 0;
  for (i = 0; i < jobs; i++) {
    if (zipy_thread_start(&threads[i], extract_worker, &ctx) != 0)
      break;
    started++;
  }

  if (started == 0) {
    if (threads != stack_threads)
      free(threads);
    zipy_mutex_destroy(&ctx.lock);
    return extract_serial(entries, extractdir, options, policies, progress, count,
                          extracted, saved, skipped);
  }

  for (i = 0; i < started; i++)
    zipy_thread_join(&threads[i]);

  if (threads != stack_threads)
    free(threads);
  zipy_mutex_destroy(&ctx.lock);

  *extracted = ctx.extracted;
  *saved = ctx.saved;
  *skipped = ctx.skipped;
  return ctx.failed;
}

static int
apply_directory_entries(zipy_archive_t *zip,
                        const char *extractdir,
                        const zipy_extract_options_t *options,
                        const zipy_conflict_policy_t *policies,
                        size_t count) {
  size_t i;

  for (i = count; i > 0; i--) {
    const zipy_entry_t *entry = zipy_entry(zip, i - 1u);
    zipy_extract_options_t dirOptions;
    int ret;

    if (!entry || !entry->is_directory)
      continue;
    if (policies && policies[i - 1u] == ZIPY_CONFLICT_SKIP)
      continue;

    dirOptions = *options;
    if (policies)
      dirOptions.on_conflict = policies[i - 1u];

    ret = zipy_extract_to(zip, i - 1u, extractdir, &dirOptions);
    if (ret < ZIPY_ZIP_OK)
      return 1;
  }

  return 0;
}

int
main(int argc, char *argv[]) {
  zipy_archive_t *zip;
  zipy_config_t config;
  const char *zipfile = NULL;
  const char *extractdir = ".";  /* Default to current directory */
  char *save_dir = NULL;
  zipy_conflict_policy_t *policies = NULL;
  size_t i;
  int success = 0;
  int summaryColor;
  int summaryTty;
  int needsSaveDir = 0;
  int noProgress = 0;
  int jobsSpecified = 0;
  size_t jobs = 0;
  size_t count = 0, files = 0, extracted = 0, saved = 0, skipped = 0;
  uint64_t startMs, elapsedMs;
  char elapsed[32];
  zipy_progress_t progress;
  int directExtract = 0;
  int directRet = ZIPY_ZIP_OK;

  if (argc > 1 && (strcmp(argv[1], "-h") == 0 || strcmp(argv[1], "--help") == 0)) {
    print_usage();
    return 0;
  }
  if (argc > 1 && strcmp(argv[1], "--config") == 0)
    return handle_config_command(argc, argv);

  read_config(&config);
  if (!apply_env_config(&config))
    return 1;
  
  /* Parse command line arguments */
  for (i = 1; i < argc; i++) {
    if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
      print_usage();
      return 0;
    } else if (strcmp(argv[i], "-d") == 0 && i + 1 < argc) {
      extractdir = argv[++i];
    } else if (strcmp(argv[i], "-j") == 0 && i + 1 < argc) {
      if (!parse_jobs(argv[++i], &jobs)) {
        print_usage();
        return 1;
      }
      jobsSpecified = 1;
    } else if (strcmp(argv[i], "--on-conflict") == 0 && i + 1 < argc) {
      if (!parse_conflict(argv[++i], &config.on_conflict)) {
        print_usage();
        return 1;
      }
      config.options.on_conflict = cli_policy_to_extract(config.on_conflict);
    } else if (strcmp(argv[i], "--save-to") == 0 && i + 1 < argc) {
      if (!parse_save_to(argv[++i], &config.options.save_to)) {
        print_usage();
        return 1;
      }
    } else if ((strcmp(argv[i], "-p") == 0 || strcmp(argv[i], "--password") == 0)
               && i + 1 < argc) {
      config.options.password = argv[++i];
    } else if (strcmp(argv[i], "--no-crc") == 0) {
      config.options.flags |= ZIPY_EXTRACT_NO_CRC;
    } else if (strcmp(argv[i], "--no-metadata") == 0
               || strcmp(argv[i], "--no-meta") == 0) {
      config.options.flags |= ZIPY_EXTRACT_NO_METADATA;
    } else if (strcmp(argv[i], "--no-progress") == 0) {
      noProgress = 1;
    } else if (strcmp(argv[i], "--fast") == 0) {
      config.options.flags |= ZIPY_EXTRACT_FAST;
      noProgress = 1;
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
    print_error("Error: Cannot open ZIP file '%s'\n", zipfile);
    return 1;
  }
  
  summaryTty = file_is_tty(stdout);
  summaryColor = use_color(summaryTty);

  /* Extract all files */
  count = zipy_count(zip);
  files = file_count(zip, count);
  if (jobsSpecified && jobs != 0) {
    jobs = clamp_jobs(jobs, count);
    config.options.jobs = jobs;
  } else {
    jobs = adaptive_jobs(zip, count);
    config.options.jobs = 0;
  }
  progress_init(&progress, noProgress ? NULL : stderr, count);
  if (!prepare_ask_plan(zip, extractdir, &config, &policies, &needsSaveDir)) {
    zipy_close(zip);
    free(policies);
    return 1;
  }

  if (needsSaveDir) {
    save_dir = create_save_dir(extractdir, config.options.save_to);
    if (!save_dir) {
      print_error("Error: Failed to create saved folder\n");
      zipy_close(zip);
      free(policies);
      return 1;
    }
    config.options.save_dir = save_dir;
  }

  startMs = now_ms();
  directExtract = noProgress
               && !policies
               && !save_dir
               && config.options.on_conflict == ZIPY_CONFLICT_OVERWRITE
               && !config.options.password
               && !zipy_has_encrypted(zip)
               && !zipy_has_symlink(zip);
  if (directExtract) {
    directRet = zipy_extract_all_options(zip, extractdir, &config.options);
    success = directRet < ZIPY_ZIP_OK;
    extracted = success ? 0 : files;
  } else if (jobs > 1) {
    success = extract_parallel(zipfile, zip, extractdir, &config.options, policies,
                               &progress, count, jobs,
                               &extracted, &saved, &skipped);
  } else {
    success = extract_serial(zip, extractdir, &config.options, policies, &progress,
                             count, &extracted, &saved, &skipped);
  }
  if (!success && !directExtract)
    success = apply_directory_entries(zip, extractdir, &config.options, policies, count);

  elapsedMs = now_ms() - startMs;
  format_duration(elapsed, sizeof(elapsed), elapsedMs);
  progress_clear(&progress);
  if (directExtract && success)
    print_error("  Error: Extraction failed (%d)\n", directRet);
  if (save_dir && saved == 0) {
    zipy_rmdir(save_dir);
  }

  if (success) {
    if (summaryColor)
      printf("  \033[31mextracted %zu/%zu %s \033[2min %s\033[0m\n",
             extracted,
             files,
             files == 1 ? "file" : "files",
             elapsed);
    else
      printf("  extracted %zu/%zu %s in %s\n",
             extracted,
             files,
             files == 1 ? "file" : "files",
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

  if (!success && saved > 0 && save_dir) {
    char *shownSaveDir = display_path(save_dir);
    const char *saveText = shownSaveDir ? shownSaveDir : save_dir;

    if (summaryColor)
      printf("  saved existing files to \033[35m%s\033[0m\n", saveText);
    else
      printf("  saved existing files to %s\n", saveText);

    free(shownSaveDir);
  }
  
  zipy_close(zip);
  free(policies);
  free(save_dir);
  return success;
}
