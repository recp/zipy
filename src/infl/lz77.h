/*
 * Copyright (C) 2022 Recep Aslantas
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef infl_lz77_h
#define infl_lz77_h

#include "../common.h"
#include <assert.h>

/* RFC 1951, 3.2.5 */
static struct {
  uint16_t litlen;
  uint16_t base_len;
  uint16_t ebits;
} litlen_tbl[29] = {
  { 257, 3,   0 },
  { 258, 4,   0 },
  { 259, 5,   0 },
  { 260, 6,   0 },
  { 261, 7,   0 },
  { 262, 8,   0 },
  { 263, 9,   0 },
  { 264, 10,  0 },
  { 265, 11,  1 },
  { 266, 13,  1 },
  { 267, 15,  1 },
  { 268, 17,  1 },
  { 269, 19,  2 },
  { 270, 23,  2 },
  { 271, 27,  2 },
  { 272, 31,  2 },
  { 273, 35,  3 },
  { 274, 43,  3 },
  { 275, 51,  3 },
  { 276, 59,  3 },
  { 277, 67,  4 },
  { 278, 83,  4 },
  { 279, 99,  4 },
  { 280, 115, 4 },
  { 281, 131, 5 },
  { 282, 163, 5 },
  { 283, 195, 5 },
  { 284, 227, 5 },
  { 285, 258, 0 }
};

/* RFC 1951, 3.2.5 */
static struct {
  uint16_t dist;
  uint16_t base_dist;
  uint16_t ebits;
} dist_tbl[30] = {
  { 0,  1,      0 },
  { 1,  2,      0 },
  { 2,  3,      0 },
  { 3,  4,      0 },
  { 4,  5,      1 },
  { 5,  7,      1 },
  { 6,  9,      2 },
  { 7,  13,     2 },
  { 8,  17,     3 },
  { 9,  25,     3 },
  { 10, 33,     4 },
  { 11, 49,     4 },
  { 12, 65,     5 },
  { 13, 97,     5 },
  { 14, 129,    6 },
  { 15, 193,    6 },
  { 16, 257,    7 },
  { 17, 385,    7 },
  { 18, 513,    8 },
  { 19, 769,    8 },
  { 20, 1025,   9 },
  { 21, 1537,   9 },
  { 22, 2049,  10 },
  { 23, 3073,  10 },
  { 24, 4097,  11 },
  { 25, 6145,  11 },
  { 26, 8193,  12 },
  { 27, 12289, 12 },
  { 28, 16385, 13 },
  { 29, 24577, 13 }
};

#endif /* infl_lz77_h */
