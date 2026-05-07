/*
 * Copyright (C) 2025 Recep Aslantas
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */

#include "thread.h"

#include <unistd.h>

static void *
thread_entry(void *arg) {
  thread_handle_t *thread = arg;

  thread->func(thread->arg);
  return NULL;
}

int
thread_start(thread_handle_t *thread, void (*func)(void *), void *arg) {
  thread->func = func;
  thread->arg = arg;

  if (pthread_create(&thread->id, NULL, thread_entry, thread) != 0)
    return -1;

  return 0;
}

void
thread_join(thread_handle_t *thread) {
  pthread_join(thread->id, NULL);
}

void
mutex_init(mutex_handle_t *mutex) {
  pthread_mutex_init(&mutex->mutex, NULL);
}

void
mutex_destroy(mutex_handle_t *mutex) {
  pthread_mutex_destroy(&mutex->mutex);
}

void
mutex_lock(mutex_handle_t *mutex) {
  pthread_mutex_lock(&mutex->mutex);
}

void
mutex_unlock(mutex_handle_t *mutex) {
  pthread_mutex_unlock(&mutex->mutex);
}

size_t
cpu_count(void) {
  long n;

  n = sysconf(_SC_NPROCESSORS_ONLN);
  return n > 0 ? (size_t)n : 1u;
}
