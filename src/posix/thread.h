/*
 * Copyright (C) 2025 Recep Aslantas
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */

#ifndef zipy_posix_thread_h
#define zipy_posix_thread_h

#include <pthread.h>
#include <stddef.h>

typedef struct ZipyThread {
  pthread_t id;
} ZipyThread;

typedef struct ZipyMutex {
  pthread_mutex_t mutex;
} ZipyMutex;

int
zipy_thread_start(ZipyThread *thread, void (*func)(void *), void *arg);

void
zipy_thread_join(ZipyThread *thread);

void
zipy_mutex_init(ZipyMutex *mutex);

void
zipy_mutex_destroy(ZipyMutex *mutex);

void
zipy_lock(ZipyMutex *mutex);

void
zipy_unlock(ZipyMutex *mutex);

size_t
zipy_cpu_count(void);

#endif /* zipy_posix_thread_h */
