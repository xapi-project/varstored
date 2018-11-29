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
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
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
    printf("usage: %s [-h] [depriv options] <vm-uuid> <guid> <name> <attributes> <data-file>\n\n",
           progname);
    printf("Sets/updates/appends/removes an EFI variable for a VM.\n"
           "attributes is a bitmask specified as a number. E.g. '7' for 'boot|runtime|nvram'.\n"
           "Variables can be appended by specifying 'append' in the attributes.\n"
           "Normal variables can be removed by providing an empty data-file or by\n"
           "specifying neither 'boot' nor 'runtime' in the attributes.\n"
           "Authenticated variables can be removed by providing a valid authentication\n"
           "descriptor with no data.\n");
    print_depriv_options();
}

static bool
do_set(const char *guid_str, const char *name, const char *attr_str,
       const char *path)
{
    uint8_t buf[SHMEM_SIZE];
    uint8_t *ptr, *data;
    uint8_t variable_name[NAME_LIMIT];
    EFI_GUID guid;
    EFI_STATUS status;
    UINT32 attr;
    size_t name_size;
    struct stat st;
    FILE *f;

    name_size = parse_name(name, variable_name);

    if (!parse_guid(&guid, guid_str)) {
        ERR("Failed to parse GUID\n");
        return false;
    }

    errno = 0;
    attr = strtoul(attr_str, NULL, 0);
    if (errno) {
        ERR("Failed to parse attributes\n");
        return false;
    }

    f = fopen(path, "r");
    if (!f) {
        ERR("Failed to open %s\n", path);
        return false;
    }
    if (fstat(fileno(f), &st) == -1 || st.st_size > DATA_LIMIT) {
        printf("Invalid file size\n");
        fclose(f);
        return false;
    }
    data = malloc(st.st_size);
    if (!data) {
        ERR("Failed to allocate memory\n");
        fclose(f);
        return false;
    }
    if (fread(data, 1, st.st_size, f) != st.st_size) {
        ERR("Failed to read from file\n");
        fclose(f);
        free(data);
        return false;
    }
    fclose(f);

    ptr = buf;
    serialize_uint32(&ptr, 1); /* version */
    serialize_uint32(&ptr, COMMAND_SET_VARIABLE);
    serialize_data(&ptr, variable_name, name_size);
    serialize_guid(&ptr, &guid);
    serialize_data(&ptr, data, st.st_size);
    free(data);
    serialize_uint32(&ptr, attr);
    *ptr = 0;

    dispatch_command(buf);

    ptr = buf;
    status = unserialize_uintn(&ptr);
    if (status != EFI_SUCCESS) {
        print_efi_error(status);
        return false;
    }

    return true;
}

int main(int argc, char **argv)
{
    DEPRIV_VARS

    for (;;) {
        int c = getopt(argc, argv, "h" DEPRIV_OPTS);

        if (c == -1)
            break;

        switch (c) {
        DEPRIV_CASES
        case 'h':
            usage(argv[0]);
            exit(0);
        default:
            usage(argv[0]);
            exit(1);
        }
    }

    if (argc - optind != 5) {
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

    return !do_set(argv[optind + 1], argv[optind + 2], argv[optind + 3],
                   argv[optind + 4]);
}
