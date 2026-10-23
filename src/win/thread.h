/*
 * Copyright (C) 2025 Recep Aslantas
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef WIN_THREAD_H
#define WIN_THREAD_H

#include <stddef.h>
#include <windows.h>

typedef struct thread_handle_t {
  HANDLE id;
  void (*func)(void *);
  void *arg;
} thread_handle_t;

typedef struct mutex_handle_t {
  CRITICAL_SECTION mutex;
} mutex_handle_t;

int
thread_start(thread_handle_t *thread, void (*func)(void *), void *arg);

void
thread_join(thread_handle_t *thread);

void
mutex_init(mutex_handle_t *mutex);

void
mutex_destroy(mutex_handle_t *mutex);

void
mutex_lock(mutex_handle_t *mutex);

void
mutex_unlock(mutex_handle_t *mutex);

size_t
cpu_count(void);

#endif /* WIN_THREAD_H */
