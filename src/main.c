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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void
print_usage(void) {
  printf("Usage: zap <zipfile> [-d extractdir]\n");
  printf("Options:\n");
  printf("  -d <dir>    Extract files into <dir>\n");
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
  int success = 0, count = 0;
  
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
  
  /* Extract all files */
  printf("Archive: %s\n", zipfile);
  
  for (i = 0; i < zip->fileCount; i++) {
    destpath = make_extract_path(extractdir, zip->files[i].filename);
    if (!destpath) continue;
    
    printf("  extracting: %s\n", zip->files[i].filename);
    
    int ret = zap_extract_file(zip, zip->files[i].filename, destpath);
    if (ret == 0) {
      count++;
    } else {
      fprintf(stderr, "Error: Failed to extract '%s' (%d)\n",
              zip->files[i].filename, ret);
      success = 1;
    }
    
    free(destpath);
  }
  
  printf("Successfully extracted %d file(s)\n", count);
  
  zap_close(zip);
  return success;
}
