#ifndef SERIALIZE_H
#define SERIALIZE_H

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
    memcpy(*ptr, data, data_len);
    *ptr += data_len;
}

static inline void
serialize_result(uint8_t **ptr, EFI_STATUS status)
{
    memcpy(*ptr, &status, sizeof(status));
    *ptr += sizeof status;
}

static inline void
serialize_guid(uint8_t **ptr, const char *guid)
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
unserialize_guid(uint8_t **ptr, char *guid)
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
