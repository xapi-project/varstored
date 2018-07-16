#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#include "backend.h"
#include "debug.h"
#include "efi.h"
#include "handler.h"
#include "option.h"
#include "serialize.h"

#define DB_MAGIC "VARS"
#define DB_VERSION 1
/* magic, version, count, data length */
#define DB_HEADER_LEN \
    (strlen(DB_MAGIC) + sizeof(UINT32) + sizeof(UINTN) + sizeof(UINTN))

#define MAX_FILE_SIZE (1024 * 1024)

/* Path to the file containing the initial data from XAPI. */
static char *arg_init;
/* Path to the file used for saving / resuming. */
static char *arg_save;
/* The VM's uuid. Used for saving to the XAPI db. */
static char *arg_uuid;

static bool
xapidb_parse_arg(const char *name, const char *val)
{
    if (!strcmp(name, "init"))
        arg_init = strdup(val);
    else if (!strcmp(name, "save"))
        arg_save = strdup(val);
    else if (!strcmp(name, "uuid"))
        arg_uuid = strdup(val);
    else
        return false;

    return true;
}

static bool
xapidb_check_args(void)
{
    if (opt_resume && arg_init) {
        fprintf(stderr, "Backend arg 'init' is invalid when resuming\n");
        return false;
    }

    return true;
}

/*
 * Serializes the list of variables into a buffer. The buffer must be freed by
 * the caller. Returns the length of the buffer on success otherwise 0.
 */
static size_t
serialize_variables(uint8_t **out)
{
    struct efi_variable *l;
    uint8_t *buf, *ptr;
    size_t data_len = 0, count = 0;

    l = var_list;
    while (l) {
        data_len += sizeof(l->name_len) + l->name_len;
        data_len += sizeof(l->data_len) + l->data_len;
        data_len += GUID_LEN;
        data_len += sizeof(l->attributes);
        data_len += sizeof(l->timestamp);
        data_len += sizeof(l->cert);
        count++;
        l = l->next;
    }

    buf = malloc(data_len + DB_HEADER_LEN);
    if (!buf) {
        DBG("Failed to allocate memory\n");
        return 0;
    }

    ptr = buf;
    l = var_list;

    memcpy(ptr, DB_MAGIC, strlen(DB_MAGIC));
    ptr += strlen(DB_MAGIC);
    serialize_uint32(&ptr, DB_VERSION);
    serialize_uintn(&ptr, count);
    serialize_uintn(&ptr, data_len);

    while (l) {
        serialize_data(&ptr, l->name, l->name_len);
        serialize_data(&ptr, l->data, l->data_len);
        serialize_guid(&ptr, l->guid);
        serialize_uint32(&ptr, l->attributes);
        serialize_timestamp(&ptr, &l->timestamp);
        memcpy(ptr, l->cert, sizeof(l->cert));
        ptr += sizeof(l->cert);
        l = l->next;
    }

    *out = buf;
    return data_len + DB_HEADER_LEN;
}

static bool
unserialize_variables(uint8_t *buf, size_t count)
{
    struct efi_variable *l;
    size_t i;

    for (i = 0; i < count; i++) {
        l = malloc(sizeof(*l));
        if (!l) {
            DBG("Failed to allocate memory\n");
            return false;
        }

        l->name = unserialize_data(&buf, &l->name_len, NAME_LIMIT);
        if (!l->name) {
            DBG("Failed to allocate memory\n");
            free(l);
            return false;
        }
        l->data = unserialize_data(&buf, &l->data_len, DATA_LIMIT);
        if (!l->data) {
            DBG("Failed to allocate memory\n");
            free(l->name);
            free(l);
            return false;
        }
        unserialize_guid(&buf, l->guid);
        l->attributes = unserialize_uint32(&buf);
        unserialize_timestamp(&buf, &l->timestamp);
        memcpy(buf, l->cert, sizeof(l->cert));
        buf += sizeof(l->cert);

        l->next = var_list;
        var_list = l;
    }

    return true;
}

static bool
xapidb_init(void)
{
    /* Unimplemented */
    return 0;
}

static bool
xapidb_save(void)
{
    FILE *f;
    uint8_t *buf;
    size_t len;

    if (!arg_save)
        return true;

    len = serialize_variables(&buf);
    if (len == 0)
        return false;

    f = fopen(arg_save, "w");
    if (!f) {
        DBG("Failed to open '%s'\n", arg_save);
        return false;
    }
    if (fwrite(buf, 1, len, f) != len) {
        DBG("Failed to write to '%s': %s\n", arg_save, strerror(errno));
        fclose(f);
        free(buf);
        return false;
    }

    fclose(f);
    free(buf);
    return true;
}

static bool
xapidb_resume(void)
{
    FILE *f;
    struct stat st;
    uint8_t *buf, *ptr;
    uint32_t version;
    size_t count;

    if (!arg_save)
        return true;

    f = fopen(arg_save, "r");
    if (!f) {
        DBG("Failed to open '%s'\n", arg_save);
        return false;
    }

    if (fstat(fileno(f), &st) == -1 || st.st_size < DB_HEADER_LEN ||
            st.st_size > MAX_FILE_SIZE) {
        DBG("Save file size is invalid\n");
        fclose(f);
        return false;
    }

    buf = malloc(st.st_size);
    if (!buf) {
        DBG("Failed to allocate memory\n");
        fclose(f);
        return false;
    }
    if (fread(buf, 1, st.st_size, f) != st.st_size) {
        DBG("Failed to read from '%s'\n", arg_save);
        free(buf);
        fclose(f);
        return false;
    }
    fclose(f);

    ptr = buf;
    if (memcmp(ptr, DB_MAGIC, strlen(DB_MAGIC))) {
        DBG("Invalid db magic\n");
        free(buf);
        return false;
    }
    ptr += strlen(DB_MAGIC);

    version = unserialize_uint32(&ptr);
    if (version != DB_VERSION) {
        DBG("Unsupported save version\n");
        free(buf);
        return false;
    }

    count = unserialize_uintn(&ptr);
    unserialize_uintn(&ptr); /* data_len */

    unserialize_variables(ptr, count);
    free(buf);

    return true;
}

static bool
xapidb_set_variable(void)
{
    /* Unimplemented */
    return 0;
}

struct backend xapidb = {
    .parse_arg = xapidb_parse_arg,
    .check_args = xapidb_check_args,
    .init = xapidb_init,
    .save = xapidb_save,
    .resume = xapidb_resume,
    .set_variable = xapidb_set_variable,
};
