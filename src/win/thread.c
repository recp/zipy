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

static DWORD WINAPI
zipy_thread_entry(void *arg) {
  zipy_thread_t *thread = arg;

  thread->func(thread->arg);
  return 0;
}

int
zipy_thread_start(zipy_thread_t *thread, void (*func)(void *), void *arg) {
  thread->func = func;
  thread->arg = arg;

  thread->id = CreateThread(NULL, 0, zipy_thread_entry, thread, 0, NULL);
  if (!thread->id)
    return -1;

  return 0;
}

void
zipy_thread_join(zipy_thread_t *thread) {
  WaitForSingleObject(thread->id, INFINITE);
  CloseHandle(thread->id);
}

void
zipy_mutex_init(zipy_mutex_t *mutex) {
  InitializeCriticalSection(&mutex->mutex);
}

void
zipy_mutex_destroy(zipy_mutex_t *mutex) {
  DeleteCriticalSection(&mutex->mutex);
}

void
zipy_lock(zipy_mutex_t *mutex) {
  EnterCriticalSection(&mutex->mutex);
}

void
zipy_unlock(zipy_mutex_t *mutex) {
  LeaveCriticalSection(&mutex->mutex);
}

size_t
zipy_cpu_count(void) {
  SYSTEM_INFO info;

  GetSystemInfo(&info);
  return info.dwNumberOfProcessors > 0 ? (size_t)info.dwNumberOfProcessors : 1u;
}
