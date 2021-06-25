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

#ifndef SERIALIZE_H
#define SERIALIZE_H

#include <stdint.h>
#include <string.h>

#include "efi.h"
#include "handler.h"

static inline enum command_t
unserialize_command(uint8_t **ptr)
{
    UINT32 data;

    memcpy(&data, *ptr, sizeof(data));
    *ptr += sizeof data;

    return (enum command_t)data;
}

static inline void
serialize_data(uint8_t **ptr, const uint8_t *data, UINTN data_len)
{
    memcpy(*ptr, &data_len, sizeof(data_len));
    *ptr += sizeof data_len;
    if (data_len) {
        memcpy(*ptr, data, data_len);
        *ptr += data_len;
    }
}

static inline void
serialize_result(uint8_t **ptr, EFI_STATUS status)
{
    memcpy(*ptr, &status, sizeof(status));
    *ptr += sizeof status;
}

static inline void
serialize_guid(uint8_t **ptr, const EFI_GUID *guid)
{
    memcpy(*ptr, guid, GUID_LEN);
    *ptr += GUID_LEN;
}

static inline void
serialize_timestamp(uint8_t **ptr, EFI_TIME *timestamp)
{
    memcpy(*ptr, timestamp, sizeof(*timestamp));
    *ptr += sizeof(*timestamp);
}

static inline void
serialize_uintn(uint8_t **ptr, UINTN var)
{
    memcpy(*ptr, &var, sizeof(var));
    *ptr += sizeof var;
}

static inline void
serialize_uint32(uint8_t **ptr, UINT32 var)
{
    memcpy(*ptr, &var, sizeof(var));
    *ptr += sizeof var;
}

static inline void
serialize_uint64(uint8_t **ptr, UINT64 var)
{
    memcpy(*ptr, &var, sizeof(var));
    *ptr += sizeof var;
}

static inline uint8_t *
unserialize_data(uint8_t **ptr, UINTN *len, UINTN limit)
{
    uint8_t *data;

    memcpy(len, *ptr, sizeof(*len));
    *ptr += sizeof *len;

    if (*len > limit || *len == 0)
        return NULL;

    data = malloc(*len);
    if (!data)
        return NULL;

    memcpy(data, *ptr, *len);
    *ptr += *len;

    return data;
}

static inline void
unserialize_guid(uint8_t **ptr, EFI_GUID *guid)
{
    memcpy(guid, *ptr, GUID_LEN);
    *ptr += GUID_LEN;
}

static inline void
unserialize_timestamp(uint8_t **ptr, EFI_TIME *timestamp)
{
    memcpy(timestamp, *ptr, sizeof(*timestamp));
    *ptr += sizeof(*timestamp);
}

static inline UINTN
unserialize_uintn(uint8_t **ptr)
{
    UINTN ret;

    memcpy(&ret, *ptr, sizeof(ret));
    *ptr += sizeof ret;

    return ret;
}

static inline BOOLEAN
unserialize_boolean(uint8_t **ptr)
{
    BOOLEAN ret;

    memcpy(&ret, *ptr, sizeof(ret));
    *ptr += sizeof ret;

    return ret;
}

static inline UINT32
unserialize_uint32(uint8_t **ptr)
{
    UINT32 ret;

    memcpy(&ret, *ptr, sizeof(ret));
    *ptr += sizeof ret;

    return ret;
}

#endif
