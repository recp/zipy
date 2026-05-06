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

typedef struct ZipyThreadEntry {
  void (*func)(void *);
  void *arg;
} ZipyThreadEntry;

static void *
zipy_thread_entry(void *arg) {
  ZipyThreadEntry entry;

  memcpy(&entry, arg, sizeof(entry));
  free(arg);

  entry.func(entry.arg);
  return NULL;
}

int
zipy_thread_start(ZipyThread *thread, void (*func)(void *), void *arg) {
  ZipyThreadEntry *entry;

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
zipy_thread_join(ZipyThread *thread) {
  pthread_join(thread->id, NULL);
}

void
zipy_mutex_init(ZipyMutex *mutex) {
  pthread_mutex_init(&mutex->mutex, NULL);
}

void
zipy_mutex_destroy(ZipyMutex *mutex) {
  pthread_mutex_destroy(&mutex->mutex);
}

void
zipy_lock(ZipyMutex *mutex) {
  pthread_mutex_lock(&mutex->mutex);
}

void
zipy_unlock(ZipyMutex *mutex) {
  pthread_mutex_unlock(&mutex->mutex);
}

size_t
zipy_cpu_count(void) {
  long n;

  n = sysconf(_SC_NPROCESSORS_ONLN);
  return n > 0 ? (size_t)n : 1u;
}
