#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#include <backend.h>
#include <debug.h>
#include <xapidb.h>

#include "option.h"
#include "pci.h"

/* Path to the file used for resuming. */
static char *arg_resume;
/* Path to the file used for saving. */
static char *arg_save;

static bool
xapidb_parse_arg(const char *name, const char *val)
{
    if (!strcmp(name, "resume"))
        arg_resume = strdup(val);
    else if (!strcmp(name, "save"))
        arg_save = strdup(val);
    else if (!strcmp(name, "uuid"))
        xapidb_arg_uuid = strdup(val);
    else
        return false;

    return true;
}

static bool
xapidb_check_args(void)
{
    if (!xapidb_arg_uuid) {
        fprintf(stderr, "Backend arg 'uuid' is required\n");
        return false;
    }
    if (!opt_resume && arg_resume) {
        fprintf(stderr, "Backend arg 'resume' is invalid when not resuming\n");
        return false;
    }

    return true;
}

static bool
xapidb_save(void)
{
    FILE *f;
    uint8_t *buf;
    size_t len;

    if (!arg_save)
        return true;

    len = xapidb_serialize_variables(&buf, false);
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
    free(buf);

    if (fwrite(pci_config_ptr(), 1, PCI_CONFIG_SIZE, f) != PCI_CONFIG_SIZE) {
        DBG("Failed to write to '%s': %s\n", arg_save, strerror(errno));
        fclose(f);
        return false;
    }

    fclose(f);
    return true;
}

static bool
xapidb_resume(void)
{
    FILE *f;
    struct stat st;
    uint8_t *buf, *ptr;

    if (!arg_resume)
        return true;

    f = fopen(arg_resume, "r");
    if (!f) {
        DBG("Failed to open '%s'\n", arg_resume);
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
        DBG("Failed to read from '%s'\n", arg_resume);
        free(buf);
        fclose(f);
        return false;
    }
    fclose(f);

    ptr = buf;
    if (!xapidb_parse_blob(&ptr, st.st_size)) {
        free(buf);
        return false;
    }

    pci_config_resume(ptr);
    free(buf);

    return true;
}

struct backend xapidb = {
    .parse_arg = xapidb_parse_arg,
    .check_args = xapidb_check_args,
    .init = xapidb_init,
    .save = xapidb_save,
    .resume = xapidb_resume,
    .set_variable = xapidb_set_variable,
};
