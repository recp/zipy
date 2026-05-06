/*
 * Copyright (C) 2025 Recep Aslantas
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */

#ifndef zap_win_thread_h
#define zap_win_thread_h

#include <stddef.h>
#include <windows.h>

typedef struct ZapThread {
  HANDLE id;
} ZapThread;

typedef struct ZapMutex {
  CRITICAL_SECTION mutex;
} ZapMutex;

int
zap_thread_start(ZapThread *thread, void (*func)(void *), void *arg);

void
zap_thread_join(ZapThread *thread);

void
zap_mutex_init(ZapMutex *mutex);

void
zap_mutex_destroy(ZapMutex *mutex);

void
zap_lock(ZapMutex *mutex);

void
zap_unlock(ZapMutex *mutex);

size_t
zap_cpu_count(void);

#endif /* zap_win_thread_h */
