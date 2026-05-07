/*
 * Copyright (C) 2025 Recep Aslantas
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */

#ifndef THREAD_THREAD_H
#define THREAD_THREAD_H

#include <stddef.h>

#if defined(_WIN32)
#  include "../win/thread.h"
#else
#  include "../posix/thread.h"
#endif

#endif /* THREAD_THREAD_H */
