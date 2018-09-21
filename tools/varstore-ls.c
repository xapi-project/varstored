/*
 * Copyright (C) Citrix Systems, Inc
 */

#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <ctype.h>

#include <backend.h>
#include <debug.h>
#include <serialize.h>

#include "tool-lib.h"

struct backend *db = &xapidb_cmdline;
enum log_level log_level = LOG_LVL_INFO;

static void
usage(const char *progname)
{
    printf("usage: %s [-h] <vm-uuid>\n", progname);
}

static void
print_guid(const EFI_GUID *guid)
{
    printf("%02x", guid->data[3]);
    printf("%02x", guid->data[2]);
    printf("%02x", guid->data[1]);
    printf("%02x", guid->data[0]);
    printf("-");
    printf("%02x", guid->data[5]);
    printf("%02x", guid->data[4]);
    printf("-");
    printf("%02x", guid->data[7]);
    printf("%02x", guid->data[6]);
    printf("-");
    printf("%02x", guid->data[8]);
    printf("%02x", guid->data[9]);
    printf("-");
    printf("%02x", guid->data[10]);
    printf("%02x", guid->data[11]);
    printf("%02x", guid->data[12]);
    printf("%02x", guid->data[13]);
    printf("%02x", guid->data[14]);
    printf("%02x", guid->data[15]);
}

static bool
do_ls(void)
{
    uint8_t buf[SHMEM_SIZE];
    uint8_t name[NAME_LIMIT] = {0};
    uint8_t *ptr;
    EFI_GUID guid = {{0}};
    UINTN size = 0;
    int i;
    EFI_STATUS status;

    for (;;) {
        ptr = buf;
        serialize_uint32(&ptr, 1); /* version */
        serialize_uint32(&ptr, COMMAND_GET_NEXT_VARIABLE);
        serialize_uintn(&ptr, NAME_LIMIT);
        serialize_data(&ptr, name, size);
        serialize_guid(&ptr, &guid);
        *ptr = 0;

        dispatch_command(buf);

        ptr = buf;
        status = unserialize_uintn(&ptr);
        if (status == EFI_NOT_FOUND)
            break;
        if (status != EFI_SUCCESS) {
            print_efi_error(status);
            return false;
        }

        size = unserialize_uintn(&ptr);
        memcpy(name, ptr, size);
        ptr += size;
        unserialize_guid(&ptr, &guid);

        print_guid(&guid);
        printf(" ");
        /* Only supports printing a limited subset of UTF-16 for now. */
        for (i = 0; i < size; i += 2) {
            if (isprint(name[i]))
                printf("%c", (char)name[i]);
        }
        printf("\n");
    }

    return true;
}

int main(int argc, char **argv)
{
    if (argc != 2) {
        usage(argv[0]);
        exit(1);
    }

    if (!strcmp(argv[1], "-h")) {
        usage(argv[0]);
        exit(0);
    }

    db->parse_arg("uuid", argv[1]);

    if (!tool_init())
        exit(1);

    return !do_ls();
}
