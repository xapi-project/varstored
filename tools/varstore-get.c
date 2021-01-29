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

#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>

#include <backend.h>
#include <debug.h>
#include <depriv.h>
#include <serialize.h>

#include "tool-lib.h"

const struct backend *db = &xapidb_cmdline;
const enum log_level log_level = LOG_LVL_INFO;

static void
usage(const char *progname)
{
    printf("usage: %s [-h] [depriv options] [-a] <vm-uuid> <guid> <name>\n\n",
           progname);
    printf("Writes out the contents of an EFI variable to stdout.\n"
           "If -a is given, writes out the variable attributes instead.\n");
    print_depriv_options();
}

#define print_attr(x) do { \
    if (attr & x) \
        printf(#x "\n"); \
    } while (0)

static bool
do_get(const char *guid_str, const char *name, bool show_attr)
{
    uint8_t buf[SHMEM_SIZE];
    uint8_t *ptr;
    uint8_t variable_name[NAME_LIMIT];
    EFI_GUID guid;
    EFI_STATUS status;
    UINT32 attr;
    size_t name_size;

    name_size = parse_name(name, variable_name);

    if (!parse_guid(&guid, guid_str)) {
        ERR("Failed to parse GUID\n");
        return false;
    }

    ptr = buf;
    serialize_uint32(&ptr, 1); /* version */
    serialize_uint32(&ptr, COMMAND_GET_VARIABLE);
    serialize_data(&ptr, variable_name, name_size);
    serialize_guid(&ptr, &guid);
    serialize_uintn(&ptr, DATA_LIMIT);
    *ptr = 0;

    dispatch_command(buf);

    ptr = buf;
    status = unserialize_uintn(&ptr);
    if (status != EFI_SUCCESS) {
        print_efi_error(status);
        return false;
    }

    attr = unserialize_uint32(&ptr);

    if (show_attr) {
        printf("Attributes = 0x%08x (%u)\n", attr, attr);

        print_attr(EFI_VARIABLE_NON_VOLATILE);
        print_attr(EFI_VARIABLE_BOOTSERVICE_ACCESS);
        print_attr(EFI_VARIABLE_RUNTIME_ACCESS);
        print_attr(EFI_VARIABLE_HARDWARE_ERROR_RECORD);
        print_attr(EFI_VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS);
        print_attr(EFI_VARIABLE_APPEND_WRITE);
        print_attr(EFI_VARIABLE_ENHANCED_AUTHENTICATED_ACCESS);
        print_attr(EFI_VARIABLE_AUTHENTICATED_WRITE_ACCESS);
    } else {
        uint8_t *data;
        UINTN data_len;

        data = unserialize_data(&ptr, &data_len, DATA_LIMIT);
        if (!data) {
            if (data_len == 0) {
                /* The variable is empty - nothing to write out. */
                return true;
            } else {
                ERR("Data too large: %lu > %u\n", data_len, DATA_LIMIT);
                return false;
            }
        }

        if (fwrite(data, 1, data_len, stdout) != data_len) {
            ERR("Failed to write out data\n");
            free(data);
            return false;
        }
        free(data);
    }

    return true;
}

int main(int argc, char **argv)
{
    bool show_attr = false;
    DEPRIV_VARS

    for (;;) {
        int c = getopt(argc, argv, "ah" DEPRIV_OPTS);

        if (c == -1)
            break;

        switch (c) {
        DEPRIV_CASES
        case 'a':
            show_attr = true;
            break;
        case 'h':
            usage(argv[0]);
            exit(0);
        default:
            usage(argv[0]);
            exit(1);
        }
    }

    if (argc - optind != 3) {
        usage(argv[0]);
        exit(1);
    }

    db->parse_arg("uuid", argv[optind]);

    if (opt_socket)
        db->parse_arg("socket", opt_socket);

    if (!drop_privileges(opt_chroot, opt_depriv, opt_gid, opt_uid))
        exit(1);

    if (!tool_init())
        exit(1);

    return !do_get(argv[optind + 1], argv[optind + 2], show_attr);
}
