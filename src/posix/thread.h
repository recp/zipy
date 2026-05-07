/*
 * Copyright (C) 2025 Recep Aslantas
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */

#ifndef zipy_posix_thread_h
#define zipy_posix_thread_h

#include <pthread.h>
#include <stddef.h>

typedef struct zipy_thread_t {
  pthread_t id;
  void (*func)(void *);
  void *arg;
} zipy_thread_t;

typedef struct zipy_mutex_t {
  pthread_mutex_t mutex;
} zipy_mutex_t;

int
zipy_thread_start(zipy_thread_t *thread, void (*func)(void *), void *arg);

void
zipy_thread_join(zipy_thread_t *thread);

void
zipy_mutex_init(zipy_mutex_t *mutex);

void
zipy_mutex_destroy(zipy_mutex_t *mutex);

void
zipy_lock(zipy_mutex_t *mutex);

void
zipy_unlock(zipy_mutex_t *mutex);

size_t
zipy_cpu_count(void);

#endif /* zipy_posix_thread_h */
