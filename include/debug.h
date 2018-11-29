/*
 * Copyright (c) Citrix Systems, Inc
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 *
 * Redistributions in binary form must reproduce the above copyright
 * notice, this list of conditions and the following disclaimer in the
 * documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED
 * TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
 * PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 * LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#ifndef  _DEBUG_H
#define  _DEBUG_H

enum log_level {
    LOG_LVL_ERROR,
    LOG_LVL_WARN,
    LOG_LVL_INFO,
    LOG_LVL_DEBUG,
};

extern const enum log_level log_level;

#define ERR(...)                                \
    do {                                        \
        if (log_level >= LOG_LVL_ERROR) {       \
            fprintf(stderr, "%s: ", __func__);  \
            fprintf(stderr, __VA_ARGS__);       \
            fflush(stderr);                     \
        }                                       \
    } while (0)

#define WARN(...)                               \
    do {                                        \
        if (log_level >= LOG_LVL_WARN) {        \
            fprintf(stderr, "%s: ", __func__);  \
            fprintf(stderr, __VA_ARGS__);       \
            fflush(stderr);                     \
        }                                       \
    } while (0)

#define INFO(...)                               \
    do {                                        \
        if (log_level >= LOG_LVL_INFO) {        \
            printf("%s: ", __func__);           \
            printf(__VA_ARGS__);                \
            fflush(stdout);                     \
        }                                       \
    } while (0)

#define DBG(...)                                \
    do {                                        \
        if (log_level >= LOG_LVL_DEBUG) {       \
            printf("%s: ", __func__);           \
            printf(__VA_ARGS__);                \
            fflush(stdout);                     \
        }                                       \
    } while (0)

#endif  /* _DEBUG_H */

