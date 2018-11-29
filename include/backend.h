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

#ifndef  BACKEND_H
#define  BACKEND_H

#include <stdbool.h>

enum backend_init_status {
    BACKEND_INIT_FAILURE,
    BACKEND_INIT_SUCCESS,
    BACKEND_INIT_FIRSTBOOT,
};

struct backend {
    /* Called to handle arguments specific to the backend. */
    bool (*parse_arg)(const char *name, const char *val);
    /* Called after argument parsing to verify arguments. */
    bool (*check_args)(void);
    /* Called at startup when not resuming to load the initial data. */
    enum backend_init_status (*init)(void);
    /* Called to save state when exiting. */
    bool (*save)(void);
    /* Called to resume from previously saved state. */
    bool (*resume)(void);
    /* Called when set_variable updates an NV variable. */
    bool (*set_variable)(void);
    /* Called when a Secure Boot verification failure occurs. */
    bool (*sb_notify)(void);
};

extern const struct backend *db;
extern const struct backend xapidb;
extern const struct backend xapidb_cmdline;

#endif
