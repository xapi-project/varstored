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
#include <serialize.h>

#include "tool-lib.h"

struct backend *db = &xapidb_cmdline;
enum log_level log_level = LOG_LVL_INFO;

static void
usage(const char *progname)
{
    printf("usage: %s [-h] <vm-uuid> <guid> <name> <attributes> <data-file>\n",
           progname);
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
    if (argc != 6) {
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

    return !do_set(argv[2], argv[3], argv[4], argv[5]);
}
