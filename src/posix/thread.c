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

typedef struct ZapThreadEntry {
  void (*func)(void *);
  void *arg;
} ZapThreadEntry;

static void *
zap_thread_entry(void *arg) {
  ZapThreadEntry entry;

  memcpy(&entry, arg, sizeof(entry));
  free(arg);

  entry.func(entry.arg);
  return NULL;
}

int
zap_thread_start(ZapThread *thread, void (*func)(void *), void *arg) {
  ZapThreadEntry *entry;

  entry = calloc(1, sizeof(*entry));
  if (!entry)
    return -1;

  entry->func = func;
  entry->arg = arg;

  if (pthread_create(&thread->id, NULL, zap_thread_entry, entry) != 0) {
    free(entry);
    return -1;
  }

  return 0;
}

void
zap_thread_join(ZapThread *thread) {
  pthread_join(thread->id, NULL);
}

void
zap_mutex_init(ZapMutex *mutex) {
  pthread_mutex_init(&mutex->mutex, NULL);
}

void
zap_mutex_destroy(ZapMutex *mutex) {
  pthread_mutex_destroy(&mutex->mutex);
}

void
zap_lock(ZapMutex *mutex) {
  pthread_mutex_lock(&mutex->mutex);
}

void
zap_unlock(ZapMutex *mutex) {
  pthread_mutex_unlock(&mutex->mutex);
}

size_t
zap_cpu_count(void) {
  long n;

  n = sysconf(_SC_NPROCESSORS_ONLN);
  return n > 0 ? (size_t)n : 1u;
}
