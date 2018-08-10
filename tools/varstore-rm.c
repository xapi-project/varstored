#include <stdlib.h>
#include <stdio.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>
#include <dirent.h>
#include <errno.h>

#include <backend.h>
#include <debug.h>
#include <guid.h>
#include <serialize.h>

#include "tool-lib.h"

#define CLONE_RM_DIR "/etc/xapi.d/efi-clone"

struct backend *db = &xapidb_cmdline;
enum log_level log_level = LOG_LVL_INFO;

static void
usage(const char *progname)
{
    printf("usage: %s [-c] [-h] <vm-uuid> [<guid> <name>]\n", progname);
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

static bool
clone_rm_one_file(const char *path)
{
    FILE *f;
    EFI_GUID guid;
    /* GUID string length + maximum length of a name + some whitespace */
    char line[GUID_STR_LEN + NAME_MAX + 16];
    char *ptr, *end;

    f = fopen(path, "r");
    if (!f) {
        fprintf(stderr, "Could not open '%s': %d, %s\n",
                path, errno, strerror(errno));
        return false;
    }

    while (fgets(line, sizeof(line), f)) {
        /* Strip newline */
        ptr = line + strlen(line) - 1;
        while (ptr >= line && (*ptr == '\r' || *ptr == '\n'))
            *ptr-- = '\0';

        /* Ignore comments and blank lines */
        if (strlen(line) == 0)
            continue;
        if (*line == '#')
            continue;

        /* Split GUID and name separated by some whitespace */
        end = line + strlen(line);
        ptr = line + GUID_STR_LEN;
        while (ptr < end) {
            if (isblank(*ptr))
                *ptr++ = '\0';
            else
                break;
        }

        if (ptr >= end || !parse_guid(&guid, line)) {
            fprintf(stderr, "Invalid format\n");
            fclose(f);
            return false;
        } else {
            printf("Removing: GUID: '%s' Name: '%s'\n", line, ptr);
            do_rm(line, ptr);
        }
    }
    fclose(f);

    return true;
}

static bool
do_clone_rm(void)
{
    DIR *dir;
    struct dirent *d;
    char path[PATH_MAX];
    bool ret = true;

    dir = opendir(CLONE_RM_DIR);
    if (!dir)
        return true;

    for (;;) {
        d = readdir(dir);

        if (!d)
            break;
        if (!strcmp(d->d_name, ".") || !strcmp(d->d_name, ".."))
            continue;

        if (snprintf(path, sizeof(path),
                     CLONE_RM_DIR "/%s", d->d_name) >= sizeof(path)) {
            fprintf(stderr, "Path too long\n");
            ret = false;
            goto out;
        }

        ret = clone_rm_one_file(path);
        if (!ret)
            goto out;
    }

out:
    closedir(dir);
    return ret;
}

int main(int argc, char **argv)
{
    bool clone_rm = false;

    for (;;) {
        int c = getopt(argc, argv, "ch");

        if (c == -1)
            break;

        switch (c) {
        case 'c':
            clone_rm = true;
            break;
        case 'h':
            usage(argv[0]);
            exit(0);
        default:
            usage(argv[0]);
            exit(1);
        }
    }

    if ((clone_rm && argc - optind != 1) || (!clone_rm && argc - optind != 3)) {
        usage(argv[0]);
        exit(1);
    }

    db->parse_arg("uuid", argv[optind]);

    if (!tool_init())
        exit(1);

    if (clone_rm)
        return !do_clone_rm();
    else
        return !do_rm(argv[optind + 1], argv[optind + 2]);
}
