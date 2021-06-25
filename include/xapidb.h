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

#ifndef XAPIDB_H
#define XAPIDB_H

#include <stdint.h>
#include <stdbool.h>

#include "backend.h"
#include "efi.h"

#define DB_MAGIC "VARS"
#define DB_VERSION 1
/* magic, version, count, data length */
#define DB_HEADER_LEN \
    (strlen(DB_MAGIC) + sizeof(UINT32) + sizeof(UINTN) + sizeof(UINTN))

#define MAX_FILE_SIZE (128 * 1024)

extern char *xapidb_arg_uuid;
extern char *xapidb_arg_socket;

bool xapidb_serialize_variables(uint8_t **out, size_t *out_len, bool only_nv);
bool xapidb_set_variable(void);
bool xapidb_parse_blob(uint8_t **buf, int len);
enum backend_init_status xapidb_init(void);
enum backend_init_status xapidb_file_init(void);
bool xapidb_sb_notify(void);

#endif
