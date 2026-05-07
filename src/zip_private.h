/*
 * Copyright (C) 2025 Recep Aslantas
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */

#ifndef ZIP_PRIVATE_H
#define ZIP_PRIVATE_H

#include <zipy/zip.h>

zipy_archive_t *
archive_clone(zipy_archive_t * __restrict zipy);

int
archive_has_encrypted(const zipy_archive_t * __restrict zipy);

int
archive_has_symlink(const zipy_archive_t * __restrict zipy);

int
archive_has_unsupported_method(const zipy_archive_t * __restrict zipy);

uint16_t
archive_unsupported_method(const zipy_archive_t * __restrict zipy);

#endif /* ZIP_PRIVATE_H */
