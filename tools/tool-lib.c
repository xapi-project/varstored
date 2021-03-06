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
#include <string.h>
#include <ctype.h>

#include <backend.h>
#include <handler.h>
#include <guid.h>
#include <serialize.h>

#include "tool-lib.h"

/*
 * Prepare a command-line tool for running by initializing state and loading
 * the VM's variables from the backend.
 */
bool
tool_init(void)
{
    enum backend_init_status status;

    secure_boot_enable = false;
    auth_enforce = false;

    if (!db->check_args())
        return false;

    status = db->init();

    if (status == BACKEND_INIT_FAILURE)
        return false;

    if (!setup_variables())
        return false;

    return true;
}

/*
 * Print out a useful message for an EFI_STATUS.
 */
void
print_efi_error(EFI_STATUS status)
{
    switch (status) {
    case EFI_SUCCESS:
        fprintf(stderr, "Success\n");
        break;
    case EFI_LOAD_ERROR:
        fprintf(stderr, "Load Error\n");
        break;
    case EFI_INVALID_PARAMETER:
        fprintf(stderr, "Invalid Parameter\n");
        break;
    case EFI_UNSUPPORTED:
        fprintf(stderr, "Unsupported\n");
        break;
    case EFI_BAD_BUFFER_SIZE:
        fprintf(stderr, "Bad Buffer Size\n");
        break;
    case EFI_BUFFER_TOO_SMALL:
        fprintf(stderr, "Buffer Too Small\n");
        break;
    case EFI_NOT_READY:
        fprintf(stderr, "Not Ready\n");
        break;
    case EFI_DEVICE_ERROR:
        fprintf(stderr, "Device Error\n");
        break;
    case EFI_WRITE_PROTECTED:
        fprintf(stderr, "Write Protected\n");
        break;
    case EFI_OUT_OF_RESOURCES:
        fprintf(stderr, "Out of Resources\n");
        break;
    case EFI_VOLUME_CORRUPTED:
        fprintf(stderr, "Volume Corrupt\n");
        break;
    case EFI_VOLUME_FULL:
        fprintf(stderr, "Volume Full\n");
        break;
    case EFI_NO_MEDIA:
        fprintf(stderr, "No Media\n");
        break;
    case EFI_MEDIA_CHANGED:
        fprintf(stderr, "Media Changed\n");
        break;
    case EFI_NOT_FOUND:
        fprintf(stderr, "Not Found\n");
        break;
    case EFI_ACCESS_DENIED:
        fprintf(stderr, "Access Denied\n");
        break;
    case EFI_NO_RESPONSE:
        fprintf(stderr, "No Response\n");
        break;
    case EFI_NO_MAPPING:
        fprintf(stderr, "No mapping\n");
        break;
    case EFI_TIMEOUT:
        fprintf(stderr, "Time out\n");
        break;
    case EFI_NOT_STARTED:
        fprintf(stderr, "Not started\n");
        break;
    case EFI_ALREADY_STARTED:
        fprintf(stderr, "Already started\n");
        break;
    case EFI_ABORTED:
        fprintf(stderr, "Aborted\n");
        break;
    case EFI_ICMP_ERROR:
        fprintf(stderr, "ICMP Error\n");
        break;
    case EFI_TFTP_ERROR:
        fprintf(stderr, "TFTP Error\n");
        break;
    case EFI_PROTOCOL_ERROR:
        fprintf(stderr, "Protocol Error\n");
        break;
    case EFI_INCOMPATIBLE_VERSION:
        fprintf(stderr, "Incompatible Version\n");
        break;
    case EFI_SECURITY_VIOLATION:
        fprintf(stderr, "Security Violation\n");
        break;
    case EFI_CRC_ERROR:
        fprintf(stderr, "CRC Error\n");
        break;
    case EFI_END_OF_MEDIA:
        fprintf(stderr, "End of Media\n");
        break;
    case EFI_END_OF_FILE:
        fprintf(stderr, "End of File\n");
        break;
    case EFI_INVALID_LANGUAGE:
        fprintf(stderr, "Invalid Language\n");
        break;
    case EFI_COMPROMISED_DATA:
        fprintf(stderr, "Compromised Data\n");
        break;
    case EFI_WARN_UNKNOWN_GLYPH:
        fprintf(stderr, "Warning Unknown Glyph\n");
        break;
    case EFI_WARN_DELETE_FAILURE:
        fprintf(stderr, "Warning Delete Failure\n");
        break;
    case EFI_WARN_WRITE_FAILURE:
        fprintf(stderr, "Warning Write Failure\n");
        break;
    case EFI_WARN_BUFFER_TOO_SMALL:
        fprintf(stderr, "Warning Buffer Too Small\n");
        break;
    case EFI_WARN_STALE_DATA:
        fprintf(stderr, "Warning Stale Data\n");
        break;
    default:
        fprintf(stderr, "Unknown error: 0x%016lx\n", status);
        break;
    }
}

/*
 * Convert a byte encoded as a hex string into an int.
 * Supports lower-case or upper-case.
 */
static int
hex_to_int(const char *str)
{
    int nibble1 = str[0] - 48, nibble2 = str[1] - 48;

    if (str[0] >= 'a' && str[0] <= 'f')
        nibble1 -= 39;
    else if (str[0] >= 'A' && str[0] <= 'F')
        nibble1 -= 17;

    if (str[1] >= 'a' && str[1] <= 'f')
        nibble2 -= 39;
    else if (str[1] >= 'A' && str[1] <= 'F')
        nibble2 -= 17;

    return nibble1 << 4 | nibble2;
}

/*
 * Convert a guid in string format to binary.
 * Returns true on success, false if the string is not a guid.
 */
bool
parse_guid(EFI_GUID *guid, const char *guid_str)
{
    size_t len;
    int i;

    len = strlen(guid_str);
    if (len != GUID_STR_LEN)
        return false;

    for (i = 0; i < len; i++) {
        switch (i) {
        case 8:
        case 13:
        case 18:
        case 23:
            if (guid_str[i] != '-')
                return false;
            break;
        default:
            if (!isxdigit(guid_str[i]))
                return false;
            break;
        }
    }

    guid->data[0] = hex_to_int(&guid_str[6]);
    guid->data[1] = hex_to_int(&guid_str[4]);
    guid->data[2] = hex_to_int(&guid_str[2]);
    guid->data[3] = hex_to_int(guid_str);
    guid->data[4] = hex_to_int(&guid_str[11]);
    guid->data[5] = hex_to_int(&guid_str[9]);
    guid->data[6] = hex_to_int(&guid_str[16]);
    guid->data[7] = hex_to_int(&guid_str[14]);
    guid->data[8] = hex_to_int(&guid_str[19]);
    guid->data[9] = hex_to_int(&guid_str[21]);
    guid->data[10] = hex_to_int(&guid_str[24]);
    guid->data[11] = hex_to_int(&guid_str[26]);
    guid->data[12] = hex_to_int(&guid_str[28]);
    guid->data[13] = hex_to_int(&guid_str[30]);
    guid->data[14] = hex_to_int(&guid_str[32]);
    guid->data[15] = hex_to_int(&guid_str[34]);

    return true;
}

/*
 * Converts from ASCII to something resembling UTF-16 (badly).
 */
size_t
parse_name(const char *in, uint8_t *name)
{
    int i;
    size_t len = strlen(in);

    for (i = 0; i < len; i++) {
        name[i * 2] = in[i];
        name[i * 2 + 1] = 0;
    }

    return len * 2;
}

void
print_depriv_options(void)
{
    printf("\nOptions to reduce privileges when running:\n"
           "  [-d] - reduce privileges\n"
           "  [-g] <gid> - change process group\n"
           "  [-r] <chroot> - enter a chroot\n"
           "  [-s] <path> - use given path to toolstack socket (this is relative to the chroot, if any)\n"
           "  [-u] <uid> - change process user\n");
}

bool
do_rm(const EFI_GUID *guid, const char *name)
{
    uint8_t buf[SHMEM_SIZE];
    uint8_t *ptr;
    uint8_t variable_name[NAME_LIMIT];
    EFI_STATUS status;
    UINT32 attr;
    size_t name_size;

    name_size = parse_name(name, variable_name);

    ptr = buf;
    serialize_uint32(&ptr, 1); /* version */
    serialize_uint32(&ptr, COMMAND_GET_VARIABLE);
    serialize_data(&ptr, variable_name, name_size);
    serialize_guid(&ptr, guid);
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
    serialize_guid(&ptr, guid);

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
