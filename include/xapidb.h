/*
 * Copyright (C) Citrix Systems, Inc
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

size_t xapidb_serialize_variables(uint8_t **out, bool only_nv);
bool xapidb_set_variable(void);
bool xapidb_parse_blob(uint8_t **buf, int len);
enum backend_init_status xapidb_init(void);
enum backend_init_status xapidb_file_init(void);

#endif
