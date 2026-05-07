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
thread_entry(void *arg) {
  thread_handle_t *thread = arg;

  thread->func(thread->arg);
  return 0;
}

int
thread_start(thread_handle_t *thread, void (*func)(void *), void *arg) {
  thread->func = func;
  thread->arg = arg;

  thread->id = CreateThread(NULL, 0, thread_entry, thread, 0, NULL);
  if (!thread->id)
    return -1;

  return 0;
}

void
thread_join(thread_handle_t *thread) {
  WaitForSingleObject(thread->id, INFINITE);
  CloseHandle(thread->id);
}

void
mutex_init(mutex_handle_t *mutex) {
  InitializeCriticalSection(&mutex->mutex);
}

void
mutex_destroy(mutex_handle_t *mutex) {
  DeleteCriticalSection(&mutex->mutex);
}

void
mutex_lock(mutex_handle_t *mutex) {
  EnterCriticalSection(&mutex->mutex);
}

void
mutex_unlock(mutex_handle_t *mutex) {
  LeaveCriticalSection(&mutex->mutex);
}

size_t
cpu_count(void) {
  SYSTEM_INFO info;

  GetSystemInfo(&info);
  return info.dwNumberOfProcessors > 0 ? (size_t)info.dwNumberOfProcessors : 1u;
}
