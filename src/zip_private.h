/*
 * Copyright (C) 2025 Recep Aslantas
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */

#ifndef zipy_private_h
#define zipy_private_h

#include <zipy/zip.h>

zipy_archive_t *
zipy_clone(zipy_archive_t * __restrict zipy);

int
zipy_has_encrypted(const zipy_archive_t * __restrict zipy);

int
zipy_has_symlink(const zipy_archive_t * __restrict zipy);

int
zipy_has_unsupported_method(const zipy_archive_t * __restrict zipy);

#endif /* zipy_private_h */
