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

typedef struct ZapThreadEntry {
  void (*func)(void *);
  void *arg;
} ZapThreadEntry;

static DWORD WINAPI
zap_thread_entry(void *arg) {
  ZapThreadEntry entry;

  memcpy(&entry, arg, sizeof(entry));
  free(arg);

  entry.func(entry.arg);
  return 0;
}

int
zap_thread_start(ZapThread *thread, void (*func)(void *), void *arg) {
  ZapThreadEntry *entry;

  entry = calloc(1, sizeof(*entry));
  if (!entry)
    return -1;

  entry->func = func;
  entry->arg = arg;

  thread->id = CreateThread(NULL, 0, zap_thread_entry, entry, 0, NULL);
  if (!thread->id) {
    free(entry);
    return -1;
  }

  return 0;
}

void
zap_thread_join(ZapThread *thread) {
  WaitForSingleObject(thread->id, INFINITE);
  CloseHandle(thread->id);
}

void
zap_mutex_init(ZapMutex *mutex) {
  InitializeCriticalSection(&mutex->mutex);
}

void
zap_mutex_destroy(ZapMutex *mutex) {
  DeleteCriticalSection(&mutex->mutex);
}

void
zap_lock(ZapMutex *mutex) {
  EnterCriticalSection(&mutex->mutex);
}

void
zap_unlock(ZapMutex *mutex) {
  LeaveCriticalSection(&mutex->mutex);
}

size_t
zap_cpu_count(void) {
  SYSTEM_INFO info;

  GetSystemInfo(&info);
  return info.dwNumberOfProcessors > 0 ? (size_t)info.dwNumberOfProcessors : 1u;
}
