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

typedef struct ZipyThreadEntry {
  void (*func)(void *);
  void *arg;
} ZipyThreadEntry;

static DWORD WINAPI
zipy_thread_entry(void *arg) {
  ZipyThreadEntry entry;

  memcpy(&entry, arg, sizeof(entry));
  free(arg);

  entry.func(entry.arg);
  return 0;
}

int
zipy_thread_start(ZipyThread *thread, void (*func)(void *), void *arg) {
  ZipyThreadEntry *entry;

  entry = calloc(1, sizeof(*entry));
  if (!entry)
    return -1;

  entry->func = func;
  entry->arg = arg;

  thread->id = CreateThread(NULL, 0, zipy_thread_entry, entry, 0, NULL);
  if (!thread->id) {
    free(entry);
    return -1;
  }

  return 0;
}

void
zipy_thread_join(ZipyThread *thread) {
  WaitForSingleObject(thread->id, INFINITE);
  CloseHandle(thread->id);
}

void
zipy_mutex_init(ZipyMutex *mutex) {
  InitializeCriticalSection(&mutex->mutex);
}

void
zipy_mutex_destroy(ZipyMutex *mutex) {
  DeleteCriticalSection(&mutex->mutex);
}

void
zipy_lock(ZipyMutex *mutex) {
  EnterCriticalSection(&mutex->mutex);
}

void
zipy_unlock(ZipyMutex *mutex) {
  LeaveCriticalSection(&mutex->mutex);
}

size_t
zipy_cpu_count(void) {
  SYSTEM_INFO info;

  GetSystemInfo(&info);
  return info.dwNumberOfProcessors > 0 ? (size_t)info.dwNumberOfProcessors : 1u;
}
