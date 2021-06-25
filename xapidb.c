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
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>

#include <backend.h>
#include <debug.h>
#include <xapidb.h>

#include "option.h"

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
    else if (!strcmp(name, "socket"))
        xapidb_arg_socket = strdup(val);
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

    if (!xapidb_serialize_variables(&buf, &len, false))
        return false;

    f = fopen(arg_save, "w");
    if (!f) {
        DBG("Failed to open '%s'\n", arg_save);
        free(buf);
        return false;
    }
    if (fwrite(buf, 1, len, f) != len) {
        DBG("Failed to write to '%s': %s\n", arg_save, strerror(errno));
        fclose(f);
        free(buf);
        return false;
    }
    free(buf);

    fclose(f);
    return true;
}

static bool
xapidb_resume(void)
{
    FILE *f;
    struct stat st;
    uint8_t *buf, *ptr;
    bool ret;

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
    ret = xapidb_parse_blob(&ptr, st.st_size);
    free(buf);

    return ret;
}

const struct backend xapidb = {
    .parse_arg = xapidb_parse_arg,
    .check_args = xapidb_check_args,
    .init = xapidb_init,
    .save = xapidb_save,
    .resume = xapidb_resume,
    .set_variable = xapidb_set_variable,
    .sb_notify = xapidb_sb_notify,
};
