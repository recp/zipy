/*
 * Copyright (C) 2025 Recep Aslantas
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */

#ifndef POSIX_THREAD_H
#define POSIX_THREAD_H

#include <pthread.h>
#include <stddef.h>

typedef struct thread_handle_t {
  pthread_t id;
  void (*func)(void *);
  void *arg;
} thread_handle_t;

typedef struct mutex_handle_t {
  pthread_mutex_t mutex;
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

#endif /* POSIX_THREAD_H */
