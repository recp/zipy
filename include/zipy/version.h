/*
 * Copyright (C) 2025 Recep Aslantas
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */

#ifndef zipy_version_h
#define zipy_version_h

#define ZIPY_VERSION_MAJOR 0
#define ZIPY_VERSION_MINOR 1
#define ZIPY_VERSION_PATCH 1

#define ZIPY_VERSION_ENCODE(major, minor, patch) \
  (((major) * 10000) + ((minor) * 100) + (patch))

#define ZIPY_VERSION \
  ZIPY_VERSION_ENCODE(ZIPY_VERSION_MAJOR, ZIPY_VERSION_MINOR, ZIPY_VERSION_PATCH)

#define ZIPY_VERSION_STR2(x) #x
#define ZIPY_VERSION_STR(x) ZIPY_VERSION_STR2(x)
#define ZIPY_VERSION_STRING \
  ZIPY_VERSION_STR(ZIPY_VERSION_MAJOR) "." \
  ZIPY_VERSION_STR(ZIPY_VERSION_MINOR) "." \
  ZIPY_VERSION_STR(ZIPY_VERSION_PATCH)

#endif /* zipy_version_h */
