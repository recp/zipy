/*
 * Copyright (C) 2025 Recep Aslantas
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */

#ifndef zap_posix_thread_h
#define zap_posix_thread_h

#include <pthread.h>
#include <stddef.h>

typedef struct ZapThread {
  pthread_t id;
} ZapThread;

typedef struct ZapMutex {
  pthread_mutex_t mutex;
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

#endif /* zap_posix_thread_h */
