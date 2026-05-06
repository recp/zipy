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

typedef struct ZipyProgress {
  FILE  *out;
  size_t count;
  size_t tick;
  int    tty;
  int    color;
} ZipyProgress;

typedef enum ZipyCliConflictPolicy {
  ZIPY_CLI_CONFLICT_ASK = 0,
  ZIPY_CLI_CONFLICT_SAVE,
  ZIPY_CLI_CONFLICT_OVERWRITE,
  ZIPY_CLI_CONFLICT_SKIP,
  ZIPY_CLI_CONFLICT_FAIL
} ZipyCliConflictPolicy;

typedef struct ZipyConfig {
  ZipyCliConflictPolicy onConflict;
  ZipyExtractOptions options;
} ZipyConfig;

static void
print_usage(void) {
  printf("Usage: zipy <zipfile> [-d extractdir]\n");
  printf("Options:\n");
  printf("  -d <dir>    Extract files into <dir>\n");
  printf("  -j <jobs>   Extract with jobs workers (default: cpu count)\n");
  printf("  --on-conflict <ask|save|overwrite|skip|fail>\n");
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
conflict_name(ZipyCliConflictPolicy policy) {
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
parse_conflict(const char *value, ZipyCliConflictPolicy *out) {
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

static ZipyConflictPolicy
cli_policy_to_extract(ZipyCliConflictPolicy policy) {
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
config_default(ZipyConfig *config) {
  config->onConflict = ZIPY_CLI_CONFLICT_ASK;
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
  if (strcmp(key, "on_conflict") == 0) {
    if (!parse_conflict(value, &config->onConflict))
      return 0;
    config->options.onConflict = cli_policy_to_extract(config->onConflict);
    return 1;
  }
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
  if (value && *value) {
    if (!parse_conflict(value, &config->onConflict)) {
      fprintf(stderr, "Error: Invalid ZIPY_ON_CONFLICT '%s'\n", value);
      return 0;
    }
    config->options.onConflict = cli_policy_to_extract(config->onConflict);
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
    fprintf(fp, "on_conflict = %s\n", conflict_name(config->onConflict));
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
  printf("on_conflict = %s\n", conflict_name(config->onConflict));
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
                    const ZipyEntry *entry,
                    char **conflictPath) {
  char *rel = NULL;
  char *path = NULL;
  char *clean = NULL;
  size_t len, i, j;
  int result = -1;

  *conflictPath = NULL;
  if (!entry || !entry->name)
    return -1;

  len = strlen(entry->name);
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

    if (exists && !(entry->isDirectory && isDir)) {
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
prompt_conflict_action(const ZipyEntry *entry,
                       const char *path,
                       ZipyCliConflictPolicy *allPolicy,
                       ZipyConflictPolicy *policy) {
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
prepare_ask_plan(ZipyArchive *zip,
                 const char *extractdir,
                 ZipyConfig *config,
                 ZipyConflictPolicy **policiesOut,
                 int *needsSaveDir) {
  ZipyConflictPolicy *policies = NULL;
  ZipyCliConflictPolicy allPolicy = ZIPY_CLI_CONFLICT_ASK;
  size_t count, i;
  int conflicts = 0;
  int fastNoConflict = 0;

  *policiesOut = NULL;
  *needsSaveDir = 0;

  config->options.onConflict = cli_policy_to_extract(config->onConflict);

  if (config->onConflict == ZIPY_CLI_CONFLICT_ASK
      && target_is_empty_or_missing(extractdir, &fastNoConflict)
      && fastNoConflict) {
    config->options.onConflict = ZIPY_CONFLICT_OVERWRITE;
    return 1;
  }

  if (config->onConflict != ZIPY_CLI_CONFLICT_ASK) {
    *needsSaveDir = config->options.onConflict == ZIPY_CONFLICT_SAVE;
    return 1;
  }

  if (!file_is_tty(stdin)) {
    config->options.onConflict = ZIPY_CONFLICT_SAVE;
    *needsSaveDir = 1;
    return 1;
  }

  count = zipy_count(zip);
  policies = malloc(count * sizeof(*policies));
  if (!policies && count > 0)
    return 0;

  for (i = 0; i < count; i++) {
    const ZipyEntry *entry = zipy_entry(zip, i);
    char *path = NULL;
    int ret;

    policies[i] = ZIPY_CONFLICT_SAVE;
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
      config->onConflict = allPolicy;
      config->options.onConflict = cli_policy_to_extract(allPolicy);
      *needsSaveDir = config->options.onConflict == ZIPY_CONFLICT_SAVE;
      free(policies);
      return 1;
    }
  }

  if (conflicts == 0) {
    free(policies);
    return 1;
  }

  *policiesOut = policies;
  return 1;
}

typedef struct ExtractContext {
  const char  *zipfile;
  const char  *extractdir;
  const ZipyExtractOptions *options;
  const ZipyConflictPolicy *policies;
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
  if (ctx->policies) {
    ZipyExtractOptions options = *ctx->options;
    options.onConflict = ctx->policies[index];
    ret = zipy_extract_to(zip, index, ctx->extractdir, &options);
  } else {
    ret = zipy_extract_to(zip, index, ctx->extractdir, ctx->options);
  }

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
               const ZipyConflictPolicy *policies,
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
                 ZipyArchive *entries,
                 const char *extractdir,
                 const ZipyExtractOptions *options,
                 const ZipyConflictPolicy *policies,
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
  ctx.policies = policies;
  ctx.entries = entries;
  ctx.progress = progress;
  ctx.count = count;
  zipy_mutex_init(&ctx.lock);

  threads = calloc(jobs, sizeof(*threads));
  if (!threads) {
    zipy_mutex_destroy(&ctx.lock);
    return extract_serial(entries, extractdir, options, policies, progress, count,
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
    return extract_serial(entries, extractdir, options, policies, progress, count,
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
  ZipyConflictPolicy *policies = NULL;
  size_t i;
  int success = 0;
  int summaryColor;
  int summaryTty;
  int needsSaveDir = 0;
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
      if (!parse_conflict(argv[++i], &config.onConflict)) {
        print_usage();
        return 1;
      }
      config.options.onConflict = cli_policy_to_extract(config.onConflict);
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
  if (!prepare_ask_plan(zip, extractdir, &config, &policies, &needsSaveDir)) {
    zipy_close(zip);
    free(policies);
    return 1;
  }

  if (needsSaveDir) {
    saveDir = create_save_dir(extractdir, config.options.saveTo);
    if (!saveDir) {
      fprintf(stderr, "Error: Failed to create saved folder\n");
      zipy_close(zip);
      free(policies);
      return 1;
    }
    config.options.saveDir = saveDir;
  }

  startMs = now_ms();
  if (jobs > 1)
    success = extract_parallel(zipfile, zip, extractdir, &config.options, policies,
                               &progress, count, jobs,
                               &extracted, &saved, &skipped);
  else
    success = extract_serial(zip, extractdir, &config.options, policies, &progress,
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
    char *shownSaveDir = display_path(saveDir);
    const char *saveText = shownSaveDir ? shownSaveDir : saveDir;

    if (summaryColor)
      printf("  saved existing files to \033[35m%s\033[0m\n", saveText);
    else
      printf("  saved existing files to %s\n", saveText);

    free(shownSaveDir);
  }
  
  zipy_close(zip);
  free(policies);
  free(saveDir);
  return success;
}
