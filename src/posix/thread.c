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

#include <stdlib.h>
#include <string.h>
#include <unistd.h>

typedef struct zipy_thread_entry_t {
  void (*func)(void *);
  void *arg;
} zipy_thread_entry_t;

static void *
zipy_thread_entry(void *arg) {
  zipy_thread_entry_t entry;

  memcpy(&entry, arg, sizeof(entry));
  free(arg);

  entry.func(entry.arg);
  return NULL;
}

int
zipy_thread_start(zipy_thread_t *thread, void (*func)(void *), void *arg) {
  zipy_thread_entry_t *entry;

  entry = calloc(1, sizeof(*entry));
  if (!entry)
    return -1;

  entry->func = func;
  entry->arg = arg;

  if (pthread_create(&thread->id, NULL, zipy_thread_entry, entry) != 0) {
    free(entry);
    return -1;
  }

  return 0;
}

void
zipy_thread_join(zipy_thread_t *thread) {
  pthread_join(thread->id, NULL);
}

void
zipy_mutex_init(zipy_mutex_t *mutex) {
  pthread_mutex_init(&mutex->mutex, NULL);
}

void
zipy_mutex_destroy(zipy_mutex_t *mutex) {
  pthread_mutex_destroy(&mutex->mutex);
}

void
zipy_lock(zipy_mutex_t *mutex) {
  pthread_mutex_lock(&mutex->mutex);
}

void
zipy_unlock(zipy_mutex_t *mutex) {
  pthread_mutex_unlock(&mutex->mutex);
}

size_t
zipy_cpu_count(void) {
  long n;

  n = sysconf(_SC_NPROCESSORS_ONLN);
  return n > 0 ? (size_t)n : 1u;
}
