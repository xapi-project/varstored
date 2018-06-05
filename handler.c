#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include <errno.h>

#include "debug.h"
#include "efi.h"
#include "handler.h"

#define GUID_LEN 16
#define NAME_LIMIT 4096 /* Maximum length of name */
#define DATA_LIMIT 57344 /* Maximum length of a single variable */
#define TOTAL_LIMIT 65536 /* Maximum total storage */
/*
 * A single variable takes up a minimum number of bytes.
 * This ensures a suitably low limit on the number of variables that can be
 * stored.
 */
#define VARIABLE_SIZE_MIN 64

enum command_t {
    COMMAND_GET_VARIABLE,
    COMMAND_SET_VARIABLE,
    COMMAND_GET_NEXT_VARIABLE,
    COMMAND_QUERY_VARIABLE_INFO,
};

struct efi_variable {
    uint8_t *name;
    UINTN name_len;
    uint8_t *data;
    UINTN data_len;
    char guid[GUID_LEN];
    UINT32 attributes;
    struct efi_variable *next;
};

static struct efi_variable *var_list;

static enum command_t
unserialize_command(uint8_t **ptr)
{
    UINT32 data;

    memcpy(&data, *ptr, sizeof data);
    *ptr += sizeof data;

    return (enum command_t)data;
}

static void
serialize_data(uint8_t **ptr, uint8_t *data, UINTN data_len)
{
    memcpy(*ptr, &data_len, sizeof data_len);
    *ptr += sizeof data_len;
    memcpy(*ptr, data, data_len);
    *ptr += data_len;
}

static void
serialize_result(uint8_t **ptr, EFI_STATUS status)
{
    memcpy(*ptr, &status, sizeof status);
    *ptr += sizeof status;
}

static void
serialize_guid(uint8_t **ptr, char *guid)
{
  memcpy(*ptr, guid, GUID_LEN);
  *ptr += GUID_LEN;
}

static void
serialize_uintn(uint8_t **ptr, UINTN var)
{
  memcpy(*ptr, &var, sizeof var);
  *ptr += sizeof var;
}

static void
serialize_uint32(uint8_t **ptr, UINT32 var)
{
  memcpy(*ptr, &var, sizeof var);
  *ptr += sizeof var;
}

static void
serialize_uint64(uint8_t **ptr, UINT64 var)
{
  memcpy(*ptr, &var, sizeof var);
  *ptr += sizeof var;
}

static uint8_t *
unserialize_data(uint8_t **ptr, UINTN *len, UINTN limit)
{
    uint8_t *data;

    memcpy(len, *ptr, sizeof *len);
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

static void
unserialize_guid(uint8_t **ptr, char *guid)
{
    memcpy(guid, *ptr, GUID_LEN);
    *ptr += GUID_LEN;
}

static UINTN
unserialize_uintn(uint8_t **ptr)
{
    UINTN ret;

    memcpy(&ret, *ptr, sizeof ret);
    *ptr += sizeof ret;

    return ret;
}

static BOOLEAN
unserialize_boolean(uint8_t **ptr)
{
    BOOLEAN ret;

    memcpy(&ret, *ptr, sizeof ret);
    *ptr += sizeof ret;

    return ret;
}

static UINT32
unserialize_uint32(uint8_t **ptr)
{
    UINT32 ret;

    memcpy(&ret, *ptr, sizeof ret);
    *ptr += sizeof ret;

    return ret;
}

extern char *save_name;

static void
save_list(void)
{
    struct efi_variable *l;
    FILE *f = fopen(save_name, "w");

    if (!f) {
        DBG("failed to open %s %s\n", save_name, strerror(errno));
        abort();
    }

    l = var_list;
    while (l) {
        if ((l->attributes & EFI_VARIABLE_NON_VOLATILE)) {
            DBG("write variable to file %lu %lu\n", l->name_len, l->data_len);
            fwrite(&l->name_len, sizeof l->name_len, 1, f);
            fwrite(l->name, 1, l->name_len, f);
            fwrite(&l->data_len, sizeof l->data_len, 1, f);
            fwrite(l->data, 1, l->data_len, f);
            fwrite(l->guid, 1, GUID_LEN, f);
            fwrite(&l->attributes, sizeof l->attributes, 1, f);
        }
        l = l->next;
    }

    fclose(f);
}

void
load_list(void)
{
    struct efi_variable *l;
    FILE *f = fopen(save_name, "r");

    if (!f) {
        DBG("failed to open %s : %s\n", save_name, strerror(errno));
        return;
    }

    DBG("opened %s\n", save_name);

    for (;;) {
        UINTN name_len;

        if (fread(&name_len, sizeof name_len, 1, f) != 1)
            break;

        l = malloc(sizeof *l);
        if (!l)
            abort(); /* XXX */

        l->name_len = name_len;
        l->name = malloc(l->name_len);
        fread(l->name, 1, l->name_len, f);
        fread(&l->data_len, sizeof l->data_len, 1, f);
        l->data = malloc(l->data_len);
        fread(l->data, 1, l->data_len, f);
        fread(l->guid, 1, GUID_LEN, f);
        fread(&l->attributes, 1, sizeof l->attributes, f);
        DBG("read variable from file: namelen %lu datalen %lu\n", l->name_len, l->data_len);
        l->next = var_list;
        var_list = l;
    }

    fclose(f);
}

static uint64_t
get_space_usage(void)
{
    struct efi_variable *l;
    uint64_t total = 0;

    l = var_list;
    while (l) {
        uint64_t amount = l->name_len + l->data_len;

        total += amount < VARIABLE_SIZE_MIN ? VARIABLE_SIZE_MIN : amount;
        l = l->next;
    }

    return total;
}

static void
do_get_variable(uint8_t *comm_buf)
{
    uint8_t *ptr, *name;
    char guid[GUID_LEN];
    UINTN name_len, data_len;
    BOOLEAN at_runtime;
    struct efi_variable *l;

    ptr = comm_buf;
    unserialize_uint32(&ptr); /* version */
    unserialize_command(&ptr);
    name = unserialize_data(&ptr, &name_len, NAME_LIMIT);
    if (!name) {
        serialize_result(&comm_buf, name_len == 0 ? EFI_NOT_FOUND : EFI_DEVICE_ERROR);
        return;
    }
    unserialize_guid(&ptr, guid);
    data_len = unserialize_uintn(&ptr);
    at_runtime = unserialize_boolean(&ptr);

    ptr = comm_buf;
    l = var_list;
    while (l) {
        if (l->name_len == name_len &&
                !memcmp(l->name, name, name_len) &&
                !memcmp(l->guid, guid, GUID_LEN)) {
            if (at_runtime && !(l->attributes & EFI_VARIABLE_RUNTIME_ACCESS)) {
                l = l->next;
                continue;
            }
            if (data_len < l->data_len) {
                serialize_result(&ptr, EFI_BUFFER_TOO_SMALL);
                serialize_uintn(&ptr, l->data_len);
            } else {
                serialize_result(&ptr, EFI_SUCCESS);
                serialize_uint32(&ptr, l->attributes);
                serialize_data(&ptr, l->data, l->data_len);
            }
            goto out;
        }
        l = l->next;
    }

    serialize_result(&ptr, EFI_NOT_FOUND);

out:
    free(name);
}

static void
do_set_variable(uint8_t *comm_buf)
{
    UINTN name_len, data_len;
    struct efi_variable *l, *prev = NULL;
    uint8_t *ptr, *name, *data;
    char guid[GUID_LEN];
    UINT32 attr;
    BOOLEAN at_runtime, append;

    ptr = comm_buf;
    unserialize_uint32(&ptr); /* version */
    unserialize_command(&ptr);
    name = unserialize_data(&ptr, &name_len, NAME_LIMIT);
    if (!name) {
        serialize_result(&comm_buf, name_len == 0 ? EFI_INVALID_PARAMETER : EFI_DEVICE_ERROR);
        return;
    }
    unserialize_guid(&ptr, guid);
    data = unserialize_data(&ptr, &data_len, DATA_LIMIT);
    if (!data && data_len) {
        serialize_result(&comm_buf, data_len > DATA_LIMIT ? EFI_OUT_OF_RESOURCES : EFI_DEVICE_ERROR);
        free(name);
        return;
    }
    attr = unserialize_uint32(&ptr);
    at_runtime = unserialize_boolean(&ptr);
    ptr = comm_buf;

    append = !!(attr & EFI_VARIABLE_APPEND_WRITE);
    attr &= ~EFI_VARIABLE_APPEND_WRITE;

    /* The hardware error record is not supported for now. */
    if (attr & EFI_VARIABLE_HARDWARE_ERROR_RECORD) {
        serialize_result(&ptr, EFI_INVALID_PARAMETER);
        goto err;
    }

    /* Authenticated variables are not supported for now. */
    if (attr & EFI_VARIABLE_AUTHENTICATED_WRITE_ACCESS ||
            attr & EFI_VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS) {
        serialize_result(&ptr, EFI_INVALID_PARAMETER);
        goto err;
    }

    /* If runtime access is set, bootservice access must also be set. */
    if ((attr & (EFI_VARIABLE_RUNTIME_ACCESS |
               EFI_VARIABLE_BOOTSERVICE_ACCESS)) == EFI_VARIABLE_RUNTIME_ACCESS) {
        serialize_result(&ptr, EFI_INVALID_PARAMETER);
        goto err;
    }

    l = var_list;
    while (l) {
        if (l->name_len == name_len &&
                !memcmp(l->name, name, name_len) &&
                !memcmp(l->guid, guid, GUID_LEN)) {
            bool should_save = !!(l->attributes & EFI_VARIABLE_NON_VOLATILE);

            /* Only runtime variables can be updated/deleted at runtime. */
            if (at_runtime && !(l->attributes & EFI_VARIABLE_RUNTIME_ACCESS)) {
                serialize_result(&ptr, EFI_INVALID_PARAMETER);
                goto err;
            }

            /* Only NV variables can be update/deleted at runtime. */
            if (at_runtime && !(l->attributes & EFI_VARIABLE_NON_VOLATILE)) {
                serialize_result(&ptr, EFI_WRITE_PROTECTED);
                goto err;
            }

            if ((data_len == 0 && !append) || !(attr & EFI_VAR_ACCESS)) {
                if (prev)
                    prev->next = l->next;
                else
                    var_list = l->next;
                free(l->name);
                free(l->data);
                free(l);
                free(data);
            } else {
                if (l->attributes != attr) {
                    serialize_result(&ptr, EFI_INVALID_PARAMETER);
                    goto err;
                }
                if (append) {
                    uint8_t *new_data;

                    if (get_space_usage() + data_len > TOTAL_LIMIT) {
                        serialize_result(&ptr, EFI_OUT_OF_RESOURCES);
                        goto err;
                    }
                    new_data = realloc(l->data, l->data_len + data_len);
                    if (!new_data) {
                        serialize_result(&ptr, EFI_DEVICE_ERROR);
                        goto err;
                    }
                    l->data = new_data;
                    memcpy(l->data + l->data_len, data, data_len);
                    free(data);
                    l->data_len += data_len;
                } else {
                    if (get_space_usage() - l->data_len + data_len > TOTAL_LIMIT) {
                        serialize_result(&ptr, EFI_OUT_OF_RESOURCES);
                        goto err;
                    }
                    free(l->data);
                    l->data = data;
                    l->data_len = data_len;
                }
            }
            free(name);
            serialize_result(&ptr, EFI_SUCCESS);
            if (should_save)
                save_list();
            return;
        }
        prev = l;
        l = l->next;
    }

    if (data_len == 0 || !(attr & EFI_VAR_ACCESS)) {
        serialize_result(&ptr, EFI_NOT_FOUND);
        goto err;
    } else {
        if (at_runtime && (!(attr & EFI_VARIABLE_RUNTIME_ACCESS) ||
                           !(attr & EFI_VARIABLE_NON_VOLATILE))) {
            serialize_result(&ptr, EFI_INVALID_PARAMETER);
            goto err;
        }

        if (get_space_usage() + name_len + data_len > TOTAL_LIMIT) {
            serialize_result(&ptr, EFI_OUT_OF_RESOURCES);
            goto err;
        }

        l = malloc(sizeof *l);
        if (!l) {
            serialize_result(&ptr, EFI_DEVICE_ERROR);
            goto err;
        }

        l->name = name;
        l->name_len = name_len;
        memcpy(l->guid, guid, GUID_LEN);
        l->data = data;
        l->data_len = data_len;
        l->attributes = attr;
        l->next = var_list;
        var_list = l;
        serialize_result(&ptr, EFI_SUCCESS);
        if ((attr & EFI_VARIABLE_NON_VOLATILE))
            save_list();
    }

    return;

err:
    free(name);
    free(data);
}

static void
do_get_next_variable(uint8_t *comm_buf)
{
    UINTN name_len, avail_len;
    uint8_t *ptr, *name;
    struct efi_variable *l;
    char guid[GUID_LEN];
    BOOLEAN at_runtime;

    ptr = comm_buf;
    unserialize_uint32(&ptr); /* version */
    unserialize_command(&ptr);
    avail_len = unserialize_uintn(&ptr);
    name = unserialize_data(&ptr, &name_len, NAME_LIMIT);
    if (!name && name_len) {
        serialize_result(&comm_buf, EFI_DEVICE_ERROR);
        return;
    }
    unserialize_guid(&ptr, guid);
    at_runtime = unserialize_boolean(&ptr);

    ptr = comm_buf;
    l = var_list;

    if (name_len) {
        while (l) {
            if (l->name_len == name_len &&
                    !memcmp(l->name, name, name_len) &&
                    !memcmp(l->guid, guid, GUID_LEN) &&
                    (!at_runtime || (l->attributes & EFI_VARIABLE_RUNTIME_ACCESS)))
                break;
            l = l->next;
        }
        if (!l) {
            /* Given name & guid didn't match an existing variable */
            serialize_result(&ptr, EFI_INVALID_PARAMETER);
            goto out;
        }
        l = l->next;
    }

    /* Find the next valid variable, if any. */
    while (at_runtime && l && !(l->attributes & EFI_VARIABLE_RUNTIME_ACCESS))
        l = l->next;

    if (l) {
        if (avail_len < l->name_len + sizeof(CHAR16)) {
            serialize_result(&ptr, EFI_BUFFER_TOO_SMALL);
            serialize_uintn(&ptr, l->name_len + sizeof(CHAR16));
        } else {
            serialize_result(&ptr, EFI_SUCCESS);
            serialize_data(&ptr, l->name, l->name_len);
            serialize_guid(&ptr, l->guid);
        }
    } else {
        serialize_result(&ptr, EFI_NOT_FOUND);
    }

out:
    free(name);
}

static void
do_query_variable_info(uint8_t *comm_buf)
{
    uint8_t *ptr;
    UINT32 attr;

    ptr = comm_buf;
    unserialize_uint32(&ptr); /* version */
    unserialize_command(&ptr);
    attr = unserialize_uint32(&ptr);

    ptr = comm_buf;

    if ((attr & EFI_VARIABLE_HARDWARE_ERROR_RECORD)) {
        serialize_result(&ptr, EFI_UNSUPPORTED);
        return;
    }

    /*
     * In this implementation, all variables share a common storage area, so
     * there is no need to check the attributes further.
     */
    serialize_result(&ptr, EFI_SUCCESS);
    serialize_uint64(&ptr, TOTAL_LIMIT);
    serialize_uint64(&ptr, TOTAL_LIMIT - get_space_usage());
    serialize_uint64(&ptr, DATA_LIMIT);
}

void dispatch_command(uint8_t *comm_buf)
{
    enum command_t command;
    UINT32 version;
    uint8_t *ptr = comm_buf;

    version = unserialize_uint32(&ptr);
    if (version != 1) {
        DBG("Unknown version: %u\n", version);
        return;
    }

    command = unserialize_command(&ptr);
    switch (command) {
    case COMMAND_GET_VARIABLE:
        DBG("COMMAND_GET_VARIABLE\n");
        do_get_variable(comm_buf);
        break;
    case COMMAND_SET_VARIABLE:
        DBG("COMMAND_SET_VARIABLE\n");
        do_set_variable(comm_buf);
        break;
    case COMMAND_GET_NEXT_VARIABLE:
        DBG("COMMAND_GET_NEXT_VARIABLE\n");
        do_get_next_variable(comm_buf);
        break;
    case COMMAND_QUERY_VARIABLE_INFO:
        DBG("COMMAND_QUERY_VARIABLE_INFO\n");
        do_query_variable_info(comm_buf);
        break;
    default:
        DBG("Unknown command\n");
        break;
    };
}
