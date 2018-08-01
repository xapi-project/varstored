#include <stdlib.h>
#include <stdio.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>

#include <backend.h>
#include <debug.h>
#include <guid.h>
#include <serialize.h>

#include "tool-lib.h"

struct backend *db = &xapidb_cmdline;
enum log_level log_level = LOG_LVL_INFO;

static void
usage(const char *progname)
{
    printf("usage: %s [-h] <vm-uuid> <guid> <name>\n", progname);
}

static bool
do_rm(const char *guid_str, const char *name)
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

    ptr = buf;
    serialize_uint32(&ptr, 1); /* version */
    serialize_uint32(&ptr, COMMAND_SET_VARIABLE);
    serialize_data(&ptr, variable_name, name_size);
    serialize_guid(&ptr, &guid);

    if (attr & EFI_VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS) {
        EFI_VARIABLE_AUTHENTICATION_2 d = {{0}};

        d.AuthInfo.Hdr.wCertificateType = WIN_CERT_TYPE_EFI_GUID;
        d.AuthInfo.Hdr.dwLength = offsetof(WIN_CERTIFICATE_UEFI_GUID, CertData);
        memcpy(&d.AuthInfo.CertType, &gEfiCertPkcs7Guid, GUID_LEN);
        serialize_data(&ptr, (uint8_t *)&d,
                       offsetof(EFI_VARIABLE_AUTHENTICATION_2, AuthInfo.CertData));
    } else {
        serialize_data(&ptr, NULL, 0);
    }
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
    if (argc != 4) {
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

    return !do_rm(argv[2], argv[3]);
}
